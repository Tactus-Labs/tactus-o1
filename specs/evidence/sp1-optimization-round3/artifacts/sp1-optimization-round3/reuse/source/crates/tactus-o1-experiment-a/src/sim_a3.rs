//! A3′ sharded lane-head simulation — Experiment A, churn arm (design §7.3;
//! spec §5.4, §14.6).
//!
//! `K` lanes each hold one live head cell; user ENQUEUEs consume only their
//! lane's head (parallel admission), while the builder's APPEND_BATCH consumes
//! the OrderingHead and must reference every lane head via read-only
//! `cell_deps`. Because a CellDep must resolve to a live Cell, a single lane
//! update invalidates every pending batch referencing the previous head —
//! the read-dependency amplification of spec §5.4. The epoch-sealed control
//! arm instead references immutable snapshots sealed every `seal_period`
//! ticks, trading processing latency for churn immunity.

use crate::RunMetrics;

/// Tuning parameters for the A3′ arm. The load model of design §3 is applied
/// by the caller through the arrival rates: L1 keeps per-lane arrival
/// constant as `lanes` grows; L2 keeps aggregate arrival constant; L3 is the
/// `adversary_rate`.
#[derive(Debug, Clone)]
pub struct A3Params {
    pub ticks: u64,
    pub lanes: usize,
    pub users: usize,
    pub user_arrival_prob: f64,
    pub signing_delay: u64,
    pub builder_period: u64,
    pub builder_fee: f64,
    pub user_fee_multiplier: f64,
    pub max_retries: u32,
    /// Per-tick probability of an adversarial enqueue that targets a lane
    /// referenced by the builder's pending batch (front-running the
    /// construction-to-commit window). L3.
    pub adversary_rate: f64,
    /// Reference immutable sealed snapshots instead of live lane heads.
    pub sealed: bool,
    pub seal_period: u64,
    pub wclose: u64,
    pub wfar: u64,
    pub reorg_prob: f64,
    pub seed: u64,
}

impl Default for A3Params {
    fn default() -> Self {
        Self {
            ticks: 2_000,
            lanes: 8,
            users: 5,
            user_arrival_prob: 0.10,
            signing_delay: 2,
            builder_period: 2,
            builder_fee: 1.0,
            user_fee_multiplier: 2.0,
            max_retries: 8,
            adversary_rate: 0.0,
            sealed: false,
            seal_period: 12,
            wclose: 2,
            wfar: 10,
            reorg_prob: 0.01,
            seed: 42,
        }
    }
}

/// Raw A3′ outcome counters.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct A3Stats {
    pub enqueue_attempts: u64,
    pub admissions: u64,
    pub admission_failures: u64,
    pub stale_before_broadcast: u64,
    pub superseded_after_broadcast: u64,
    pub admission_delays: Vec<u64>,
    /// Admission-to-containing-batch delays for admitted messages.
    pub processing_delays: Vec<u64>,
    pub batch_constructions: u64,
    pub batch_invalidations: u64,
    pub batches_committed: u64,
    pub lane_updates_by_users: u64,
    pub lane_updates_by_adversary: u64,
    pub reorgs: u64,
}

impl A3Stats {
    /// Share of constructed candidate batches that survived to commit.
    #[must_use]
    pub fn anchor_survival_rate(&self) -> f64 {
        if self.batch_constructions == 0 {
            f64::NAN
        } else {
            self.batches_committed as f64 / self.batch_constructions as f64
        }
    }

    #[must_use]
    pub fn invalidation_rate(&self) -> f64 {
        if self.batch_constructions == 0 {
            f64::NAN
        } else {
            self.batch_invalidations as f64 / self.batch_constructions as f64
        }
    }

    #[must_use]
    pub fn stale_rate(&self) -> f64 {
        let signings =
            self.stale_before_broadcast + self.superseded_after_broadcast + self.admissions;
        if signings == 0 {
            f64::NAN
        } else {
            self.stale_before_broadcast as f64 / signings as f64
        }
    }

    #[must_use]
    pub fn success_rate(&self) -> f64 {
        let done = self.admissions + self.admission_failures;
        if done == 0 {
            f64::NAN
        } else {
            self.admissions as f64 / done as f64
        }
    }

    #[must_use]
    pub fn percentile(values: &[u64], p: f64) -> f64 {
        if values.is_empty() {
            return f64::NAN;
        }
        let mut v = values.to_vec();
        v.sort_unstable();
        let idx = ((p / 100.0) * (v.len() - 1) as f64).round() as usize;
        v[idx] as f64
    }
}

struct Rng(u64);

impl Rng {
    fn next_f64(&mut self) -> f64 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        ((self.0 >> 11) as f64) / ((1u64 << 53) as f64)
    }
}

#[derive(Debug, Clone)]
enum UserState {
    Idle,
    Signing {
        lane: usize,
        head: u64,
        remaining: u64,
        attempts: u32,
        first_tick: u64,
    },
    Waiting {
        tx: u64,
        attempts: u32,
        first_tick: u64,
    },
}

#[derive(Debug, Clone)]
struct LaneTx {
    id: u64,
    lane: usize,
    head: u64,
    fee: f64,
    proposed: u64,
}

#[derive(Debug, Clone)]
struct PendingBatch {
    lane_refs: Vec<u64>,
    /// Tick of the seal this batch references (sealed arm), for processing
    /// accounting.
    seal_tick: Option<u64>,
    proposed: u64,
}

/// Runs one A3′ scenario and returns raw stats plus the mapped metrics record.
pub fn run_a3(params: &A3Params) -> (A3Stats, RunMetrics) {
    assert!(params.lanes >= 1, "at least one lane required");

    let mut rng = Rng(params.seed);
    let mut stats = A3Stats::default();

    let mut lane_heads = vec![0u64; params.lanes];
    let mut ordering_head = 0u64;
    let mut users: Vec<UserState> = vec![UserState::Idle; params.users];
    let mut mempool: Vec<LaneTx> = Vec::new();
    let mut next_tx_id = 0u64;
    let mut pending_batch: Option<PendingBatch> = None;
    let mut next_construction = 0u64;
    let mut seal: Option<(u64, Vec<u64>)> = if params.sealed {
        Some((0, lane_heads.clone()))
    } else {
        None
    };
    let mut adversary_target: Option<usize> = None;
    // Depth-1 rollback records.
    let mut last_lane_commit: Option<(usize, u64)> = None; // (lane, prev head)
    let mut last_batch_prev: Option<u64> = None;
    // Messages admitted but not yet contained in a committed batch.
    let mut open_processing: Vec<(u64, u64)> = Vec::new(); // (admitted_tick, id)

    for t in 0..params.ticks {
        // 1. Depth-1 reorganisation of the last committed transition.
        if rng.next_f64() < params.reorg_prob {
            if let Some((lane, prev)) = last_lane_commit {
                if lane_heads[lane] == prev + 1 {
                    lane_heads[lane] = prev;
                    stats.reorgs += 1;
                    mempool.retain(|tx| !(tx.lane == lane && tx.head > prev));
                    last_lane_commit = None;
                }
            } else if let Some(prev) = last_batch_prev {
                if ordering_head == prev + 1 {
                    ordering_head = prev;
                    stats.reorgs += 1;
                    if let Some(b) = pending_batch.take() {
                        stats.batch_invalidations += 1;
                        let _ = b;
                    }
                    last_batch_prev = None;
                }
            }
        }

        // 2. Builder constructs a candidate batch referencing every lane.
        if pending_batch.is_none() && t >= next_construction {
            let (lane_refs, seal_tick) = match &seal {
                Some((s_tick, snap)) => (snap.clone(), Some(*s_tick)),
                None => (lane_heads.clone(), None),
            };
            pending_batch = Some(PendingBatch {
                lane_refs,
                seal_tick,
                proposed: t,
            });
            stats.batch_constructions += 1;
        }

        // 3. Adversarial enqueue (L3): sign for one tick against a lane the
        //    pending batch references, then update it.
        if adversary_target.is_none() && rng.next_f64() < params.adversary_rate {
            let target = pending_batch
                .as_ref()
                .and_then(|b| {
                    (0..params.lanes)
                        .find(|&i| lane_heads[i] == b.lane_refs[i])
                        .or(Some(0))
                })
                .unwrap_or(0);
            adversary_target = Some(target);
        }
        if let Some(lane) = adversary_target.take() {
            if let Some(b) = &pending_batch {
                if lane_heads[lane] == b.lane_refs[lane] {
                    lane_heads[lane] += 1;
                    stats.lane_updates_by_adversary += 1;
                    last_lane_commit = Some((lane, lane_heads[lane] - 1));
                }
            }
        }

        // 4. Users: arrivals, signing, broadcast against a lane head.
        for user in users.iter_mut() {
            match user {
                UserState::Idle => {
                    if rng.next_f64() < params.user_arrival_prob {
                        let lane = (rng.next_f64() * params.lanes as f64) as usize % params.lanes;
                        *user = UserState::Signing {
                            lane,
                            head: lane_heads[lane],
                            remaining: params.signing_delay,
                            attempts: 1,
                            first_tick: t,
                        };
                        stats.enqueue_attempts += 1;
                    }
                }
                UserState::Signing {
                    lane,
                    head,
                    remaining,
                    attempts,
                    first_tick,
                } => {
                    *remaining -= 1;
                    if *remaining == 0 {
                        if lane_heads[*lane] == *head {
                            let id = next_tx_id;
                            next_tx_id += 1;
                            mempool.push(LaneTx {
                                id,
                                lane: *lane,
                                head: *head,
                                fee: params.builder_fee * params.user_fee_multiplier,
                                proposed: t,
                            });
                            *user = UserState::Waiting {
                                tx: id,
                                attempts: *attempts,
                                first_tick: *first_tick,
                            };
                        } else {
                            stats.stale_before_broadcast += 1;
                            restart_or_fail_counted(user, &lane_heads, t, params, &mut stats);
                        }
                    }
                }
                UserState::Waiting { .. } => {}
            }
        }

        // 5. Lane commits: one enqueue per lane per block (parallel cells).
        for (lane, lane_head) in lane_heads.iter_mut().enumerate() {
            let winner = mempool
                .iter()
                .filter(|tx| {
                    tx.lane == lane
                        && tx.head == *lane_head
                        && t - tx.proposed >= params.wclose
                        && t - tx.proposed <= params.wfar
                })
                .max_by(|a, b| {
                    a.fee
                        .partial_cmp(&b.fee)
                        .expect("finite")
                        .then(b.id.cmp(&a.id))
                })
                .cloned();
            if let Some(tx) = winner {
                *lane_head += 1;
                mempool.retain(|m| m.id != tx.id);
                stats.lane_updates_by_users += 1;
                last_lane_commit = Some((lane, *lane_head - 1));
                if let Some(user) = users
                    .iter_mut()
                    .find(|u| matches!(u, UserState::Waiting { tx: w, .. } if *w == tx.id))
                {
                    if let UserState::Waiting { first_tick, .. } = user {
                        stats.admission_delays.push(t - *first_tick);
                        open_processing.push((t, tx.id));
                    }
                    *user = UserState::Idle;
                }
                stats.admissions += 1;
            }
        }

        // 6. Batch commit or invalidation. A pending batch survives only if
        //    every referenced lane head is still live (unsealed arm).
        if let Some(batch) = &pending_batch {
            let age = t - batch.proposed;
            if age > params.wfar {
                stats.batch_invalidations += 1;
                pending_batch = None;
                next_construction = t + 1;
            } else if age >= params.wclose {
                let live_refs_ok =
                    params.sealed || lane_heads.iter().zip(&batch.lane_refs).all(|(h, r)| h == r);
                if live_refs_ok {
                    // Commit: flush every admitted message the batch covers.
                    let horizon = batch.seal_tick.unwrap_or(t);
                    open_processing.retain(|(adm, _)| {
                        if *adm <= horizon {
                            stats.processing_delays.push(t - adm);
                            false
                        } else {
                            true
                        }
                    });
                    stats.batches_committed += 1;
                    last_batch_prev = Some(ordering_head);
                    ordering_head += 1;
                    pending_batch = None;
                    next_construction = t + params.builder_period;
                }
                // Otherwise: still within the window; the invalidation is
                // detected when a referenced lane actually advances past the
                // reference, handled implicitly by the check above and the
                // wfar expiry above.
                else if !live_refs_ok
                    && lane_heads.iter().zip(&batch.lane_refs).any(|(h, r)| h != r)
                {
                    stats.batch_invalidations += 1;
                    pending_batch = None;
                    next_construction = t + 1;
                }
            }
        }

        // 7. Sealing: snapshot the live lane heads as the new immutable ref.
        if params.sealed && t % params.seal_period == 0 {
            seal = Some((t, lane_heads.clone()));
        }

        // 8. Supersession, expiry and stranded users.
        mempool.retain(|tx| {
            let superseded = tx.head < lane_heads[tx.lane];
            let expired = t - tx.proposed > params.wfar;
            if superseded {
                stats.superseded_after_broadcast += 1;
            }
            !(superseded || expired)
        });
        for user in users.iter_mut() {
            if let UserState::Waiting { tx, .. } = user {
                if !mempool.iter().any(|m| m.id == *tx) {
                    restart_or_fail_counted(user, &lane_heads, t, params, &mut stats);
                }
            }
        }
    }

    let metrics = map_metrics(&stats, params);
    (stats, metrics)
}

fn restart_or_fail_counted(
    user: &mut UserState,
    lane_heads: &[u64],
    t: u64,
    params: &A3Params,
    stats: &mut A3Stats,
) {
    let (attempts, first_tick) = match user {
        UserState::Signing {
            attempts,
            first_tick,
            ..
        }
        | UserState::Waiting {
            attempts,
            first_tick,
            ..
        } => (*attempts, *first_tick),
        UserState::Idle => return,
    };
    if attempts < params.max_retries {
        let lane = (t % lane_heads.len() as u64) as usize;
        *user = UserState::Signing {
            lane,
            head: lane_heads[lane],
            remaining: 1,
            attempts: attempts + 1,
            first_tick,
        };
    } else {
        stats.admission_failures += 1;
        *user = UserState::Idle;
    }
}

fn map_metrics(stats: &A3Stats, params: &A3Params) -> RunMetrics {
    RunMetrics {
        builder_batches_per_block: stats.batches_committed as f64 / params.ticks as f64,
        priority_admission_success_rate: stats.success_rate(),
        priority_admission_delay_blocks_p50: A3Stats::percentile(&stats.admission_delays, 50.0),
        priority_admission_delay_blocks_p95: A3Stats::percentile(&stats.admission_delays, 95.0),
        priority_processing_delay_batches_p50: A3Stats::percentile(&stats.processing_delays, 50.0),
        priority_processing_delay_batches_p95: A3Stats::percentile(&stats.processing_delays, 95.0),
        head_stale_before_broadcast_rate: stats.stale_rate(),
        retry_and_resign_count: stats.stale_before_broadcast + stats.superseded_after_broadcast,
        lane_head_churn_rate_per_lane: (stats.lane_updates_by_users
            + stats.lane_updates_by_adversary) as f64
            / params.ticks as f64
            / params.lanes as f64,
        batch_dependency_invalidation_rate: stats.invalidation_rate(),
        candidate_anchor_survival_rate: stats.anchor_survival_rate(),
        ckb_fee_paid_per_successful_priority_admission: params.builder_fee
            * params.user_fee_multiplier,
        reorg_recovery_and_checkpoint_dependency_results: vec![format!(
            "reorgs={} (depth-1 model)",
            stats.reorgs
        )],
        ..RunMetrics::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_churn_gives_full_anchor_survival() {
        let p = A3Params {
            user_arrival_prob: 0.0,
            adversary_rate: 0.0,
            reorg_prob: 0.0,
            ..A3Params::default()
        };
        let (s, m) = run_a3(&p);
        assert!((m.candidate_anchor_survival_rate - 1.0).abs() < 1e-9);
        assert!(
            s.batches_committed > 100,
            "progression should continue, got {}",
            s.batches_committed
        );
    }

    #[test]
    fn l1_more_lanes_worsen_invalidation() {
        // Design §3 L1: per-lane arrival held constant as lanes grow ⇒ the
        // aggregate churn a batch must survive grows with K.
        let base = A3Params {
            lanes: 2,
            users: 2,
            ..A3Params::default()
        };
        let wide = A3Params {
            lanes: 8,
            users: 8,
            ..A3Params::default()
        };
        let (s2, _) = run_a3(&base);
        let (s8, _) = run_a3(&wide);
        assert!(
            s8.anchor_survival_rate() < s2.anchor_survival_rate(),
            "L1: survival(K=8)={} should be below survival(K=2)={}",
            s8.anchor_survival_rate(),
            s2.anchor_survival_rate()
        );
    }

    #[test]
    fn l2_constant_aggregate_keeps_survival_stable() {
        // Design §3 L2: aggregate arrival fixed; more lanes only spread it.
        // Survival should stay within a comparable band rather than collapse.
        let narrow = A3Params {
            lanes: 2,
            users: 8,
            ..A3Params::default()
        };
        let wide = A3Params {
            lanes: 8,
            users: 8,
            ..A3Params::default()
        };
        let (s2, _) = run_a3(&narrow);
        let (s8, _) = run_a3(&wide);
        let diff = (s2.anchor_survival_rate() - s8.anchor_survival_rate()).abs();
        assert!(
            diff < 0.25,
            "L2: survival should be roughly K-neutral, diff={diff}"
        );
    }

    #[test]
    fn adversarial_churn_collapses_live_refs_but_not_sealed() {
        // L3: a front-running adversary invalidates live-head references;
        // the epoch-sealed control arm restores progression at latency cost.
        let live = A3Params {
            adversary_rate: 0.8,
            user_arrival_prob: 0.0,
            ..A3Params::default()
        };
        let sealed = A3Params {
            adversary_rate: 0.8,
            user_arrival_prob: 0.0,
            sealed: true,
            ..A3Params::default()
        };
        let (_s_live, m_live) = run_a3(&live);
        let (s_sealed, m_sealed) = run_a3(&sealed);
        assert!(
            m_live.candidate_anchor_survival_rate < 0.5,
            "adversary should collapse survival"
        );
        assert!(
            (m_sealed.candidate_anchor_survival_rate - 1.0).abs() < 1e-9,
            "sealed arm is churn-immune"
        );
        assert!(s_sealed.batches_committed > 100);
    }

    #[test]
    fn parallel_lanes_admit_users_better_than_singleton() {
        // The A3′ motivation: with the same total user load spread over 8
        // lanes, DOA is far below the A1 singleton baseline.
        let a3 = A3Params {
            lanes: 8,
            users: 5,
            signing_delay: 2,
            ..A3Params::default()
        };
        let (s3, _) = run_a3(&a3);
        let a1 = crate::sim::run_a1(&crate::sim::A1Params {
            signing_delay: 2,
            user_fee_multiplier: 2.0,
            ..crate::sim::A1Params::default()
        });
        assert!(
            s3.stale_rate() < a1.0.stale_rate(),
            "lanes should reduce DOA: {} vs {}",
            s3.stale_rate(),
            a1.0.stale_rate()
        );
    }
}
