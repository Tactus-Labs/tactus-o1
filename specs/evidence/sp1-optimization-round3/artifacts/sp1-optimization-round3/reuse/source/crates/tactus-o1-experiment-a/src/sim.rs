//! A1 atomic-OrderingHead admission simulation — Experiment A, test group 1
//! (fee-ratio versus dead-on-arrival; design §7.1, spec §14.2).
//!
//! Discrete-block model: one tick = one CKB block. Transactions enter the
//! mempool ("are proposed") at tick `t` and are commit-eligible while their
//! age lies within the RFC 0020 proposal window `[wclose, wfar]` (2..=10
//! blocks by default). A miner commits at most one OrderingHead spend per
//! block — single Cell consumption — choosing by fee density among
//! simultaneously eligible valid spends of the current live head; ties go to
//! the earlier proposal (the professional builder's pipelining advantage).
//!
//! Admission delay is measured from a user's **first** attempt (including all
//! re-signings), which is the user-perceived latency. Deliberate
//! simplifications, to be replaced by the devnet arm: reorganisation is
//! modelled as depth-1 rollbacks only; the A2 and A3′ arms are not simulated
//! yet.

use crate::RunMetrics;

/// Tuning parameters for the A1 admission experiment.
#[derive(Debug, Clone)]
pub struct A1Params {
    /// Simulated blocks.
    pub ticks: u64,
    /// Whether a dominant builder is active at all (false = uncontested arm).
    pub builder_enabled: bool,
    /// Dominant builder proposes one APPEND_BATCH every this many ticks.
    pub builder_period: u64,
    /// Builder fee density (numeraire).
    pub builder_fee: f64,
    /// Independent wallet users.
    pub users: usize,
    /// Per idle user per tick, probability of starting an ENQUEUE attempt.
    pub user_arrival_prob: f64,
    /// Wallet signing delay in blocks (the DOA variable).
    pub signing_delay: u64,
    /// ENQUEUE fee density = builder_fee × multiplier (the fee-ratio variable).
    pub user_fee_multiplier: f64,
    /// ENQUEUE attempts before the user gives up.
    pub max_retries: u32,
    /// Per-tick probability of a depth-1 reorganisation.
    pub reorg_prob: f64,
    pub seed: u64,
    /// RFC 0020 proposal window: minimum propose-to-commit distance.
    pub wclose: u64,
    /// RFC 0020 proposal window: maximum propose-to-commit distance.
    pub wfar: u64,
}

impl Default for A1Params {
    fn default() -> Self {
        Self {
            ticks: 2_000,
            builder_enabled: true,
            builder_period: 2,
            builder_fee: 1.0,
            users: 5,
            user_arrival_prob: 0.10,
            signing_delay: 2,
            user_fee_multiplier: 2.0,
            max_retries: 8,
            reorg_prob: 0.01,
            seed: 42,
            wclose: 2,
            wfar: 10,
        }
    }
}

/// Raw A1 outcome counters (superset view of the mapped [`RunMetrics`]).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct A1Stats {
    pub enqueue_attempts: u64,
    pub admissions: u64,
    pub admission_failures: u64,
    /// Signed against a head that had already advanced before broadcast.
    pub stale_before_broadcast: u64,
    /// Valid proposal superseded by a committed competing spend.
    pub superseded_after_broadcast: u64,
    pub batches_committed: u64,
    pub reorgs: u64,
    /// Per-admission delay in blocks, measured from the first attempt.
    pub admission_delays: Vec<u64>,
}

impl A1Stats {
    /// Fraction of completed attempts that resulted in admission.
    #[must_use]
    pub fn success_rate(&self) -> f64 {
        let done = self.admissions + self.admission_failures;
        if done == 0 {
            f64::NAN
        } else {
            self.admissions as f64 / done as f64
        }
    }

    /// DOA-before-broadcast rate over all signings (attempts + re-signings).
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

    /// `p`-th percentile of admission delay in blocks (0..=100).
    #[must_use]
    pub fn delay_percentile(&self, p: f64) -> f64 {
        if self.admission_delays.is_empty() {
            return f64::NAN;
        }
        let mut v = self.admission_delays.clone();
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
        target_head: u64,
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
struct MempoolTx {
    id: u64,
    enqueue: bool,
    head: u64,
    fee: f64,
    proposed: u64,
}

/// Runs one A1 scenario and returns the raw stats plus the mapped metrics record.
pub fn run_a1(params: &A1Params) -> (A1Stats, RunMetrics) {
    assert!(
        params.wclose >= 1 && params.wfar > params.wclose,
        "invalid proposal window"
    );
    assert!(
        params.signing_delay >= 1,
        "signing delay of at least one block models wallet latency"
    );

    let mut rng = Rng(params.seed);
    let mut stats = A1Stats::default();

    let mut head: u64 = 0; // live OrderingHead version
    let mut mempool: Vec<MempoolTx> = Vec::new();
    let mut next_tx_id: u64 = 0;
    let mut users = vec![UserState::Idle; params.users];
    let mut builder_pending: Option<u64> = None;
    let mut builder_next_proposal: u64 = 0;
    // Depth-1 reorg undo record: (committed tx id, previous head).
    let mut last_commit: Option<(u64, u64)> = None;

    for t in 0..params.ticks {
        // 1. Depth-1 reorganisation: roll back the last committed head
        //    transition; affected pending spends die and re-propose later.
        if let Some((_, prev_head)) = last_commit {
            if rng.next_f64() < params.reorg_prob {
                head = prev_head;
                stats.reorgs += 1;
                mempool.retain(|tx| tx.head <= head);
                last_commit = None;
                builder_next_proposal = builder_next_proposal.min(t + 1);
            }
        }

        // 2. Builder proposes a fresh APPEND_BATCH whenever idle.
        if params.builder_enabled && builder_pending.is_none() && t >= builder_next_proposal {
            let id = next_tx_id;
            next_tx_id += 1;
            mempool.push(MempoolTx {
                id,
                enqueue: false,
                head,
                fee: params.builder_fee,
                proposed: t,
            });
            builder_pending = Some(id);
        }

        // 3. Users: arrivals, signing countdown, broadcast.
        for user in users.iter_mut() {
            match user {
                UserState::Idle => {
                    if rng.next_f64() < params.user_arrival_prob {
                        *user = UserState::Signing {
                            target_head: head,
                            remaining: params.signing_delay,
                            attempts: 1,
                            first_tick: t,
                        };
                        stats.enqueue_attempts += 1;
                    }
                }
                UserState::Signing {
                    target_head,
                    remaining,
                    attempts,
                    first_tick,
                } => {
                    *remaining -= 1;
                    if *remaining == 0 {
                        if *target_head == head {
                            let id = next_tx_id;
                            next_tx_id += 1;
                            mempool.push(MempoolTx {
                                id,
                                enqueue: true,
                                head,
                                fee: params.builder_fee * params.user_fee_multiplier,
                                proposed: t,
                            });
                            *user = UserState::Waiting {
                                tx: id,
                                attempts: *attempts,
                                first_tick: *first_tick,
                            };
                        } else {
                            // Signed against a head that had already advanced:
                            // dead on arrival, never entered the mempool.
                            stats.stale_before_broadcast += 1;
                            restart_or_fail(user, head, params.max_retries, &mut stats);
                        }
                    }
                }
                UserState::Waiting { .. } => {}
            }
        }

        // 4. Commit phase: at most one spend of the live head per block,
        //    highest fee density wins; ties go to the earlier proposal.
        let winner = mempool
            .iter()
            .filter(|tx| {
                tx.head == head
                    && t - tx.proposed >= params.wclose
                    && t - tx.proposed <= params.wfar
            })
            .max_by(|a, b| {
                a.fee
                    .partial_cmp(&b.fee)
                    .expect("finite fees")
                    .then(b.id.cmp(&a.id)) // lower id = earlier proposal wins ties
            })
            .cloned();

        if let Some(tx) = winner {
            let prev_head = head;
            head += 1;
            mempool.retain(|m| m.id != tx.id);
            last_commit = Some((tx.id, prev_head));
            if tx.enqueue {
                if let Some(user) = users
                    .iter_mut()
                    .find(|u| matches!(u, UserState::Waiting { tx: w, .. } if *w == tx.id))
                {
                    if let UserState::Waiting { first_tick, .. } = user {
                        stats.admission_delays.push(t - *first_tick);
                    }
                    *user = UserState::Idle;
                }
                stats.admissions += 1;
            } else {
                stats.batches_committed += 1;
                builder_pending = None;
                builder_next_proposal = t.saturating_add(params.builder_period);
            }
        }

        // 5. Supersession and expiry: spendable-once means any tx targeting a
        //    dead head is invalid; anything past wfar must re-propose.
        mempool.retain(|tx| {
            let superseded = tx.head < head;
            let expired = t - tx.proposed > params.wfar;
            if tx.enqueue && superseded {
                stats.superseded_after_broadcast += 1;
            }
            !(superseded || expired)
        });
        if let Some(id) = builder_pending {
            if !mempool.iter().any(|tx| tx.id == id) {
                builder_pending = None;
                builder_next_proposal = builder_next_proposal.min(t + 1);
            }
        }

        // 6. Resolve users whose waiting transaction no longer exists
        //    (superseded, expired or reorged away): re-sign or give up.
        for user in users.iter_mut() {
            if let UserState::Waiting { tx, .. } = user {
                if !mempool.iter().any(|m| m.id == *tx) {
                    restart_or_fail(user, head, params.max_retries, &mut stats);
                }
            }
        }
    }

    let metrics = map_metrics(&stats, params);
    (stats, metrics)
}

fn restart_or_fail(user: &mut UserState, head: u64, max_retries: u32, stats: &mut A1Stats) {
    // Preserve the original first_tick: admission delay is user-perceived.
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
    if attempts < max_retries {
        *user = UserState::Signing {
            target_head: head,
            remaining: 1, // one-tick re-sign
            attempts: attempts + 1,
            first_tick,
        };
    } else {
        stats.admission_failures += 1;
        *user = UserState::Idle;
    }
}

fn map_metrics(stats: &A1Stats, params: &A1Params) -> RunMetrics {
    RunMetrics {
        builder_batches_per_block: stats.batches_committed as f64 / params.ticks as f64,
        priority_admission_success_rate: stats.success_rate(),
        priority_admission_delay_blocks_p50: stats.delay_percentile(50.0),
        priority_admission_delay_blocks_p95: stats.delay_percentile(95.0),
        priority_admission_delay_blocks_p99: stats.delay_percentile(99.0),
        head_stale_before_broadcast_rate: stats.stale_rate(),
        retry_and_resign_count: stats.stale_before_broadcast + stats.superseded_after_broadcast,
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
    fn uncontested_admission_meets_window_minimum() {
        // No builder pressure: a user signs for 1 tick and must wait out the
        // proposal window, so delay == signing + wclose, first try, no DOA.
        let p = A1Params {
            ticks: 500,
            builder_enabled: false,
            builder_period: u64::MAX,
            signing_delay: 1,
            user_arrival_prob: 1.0,
            users: 1,
            // Pure admission timing: reorg recovery is a separate model arm.
            reorg_prob: 0.0,
            ..A1Params::default()
        };
        let (s, _) = run_a1(&p);
        assert!(
            s.admissions > 50,
            "expected many admissions, got {}",
            s.admissions
        );
        assert_eq!(s.admission_failures, 0);
        assert_eq!(s.stale_before_broadcast, 0);
        assert!((s.delay_percentile(50.0) - (p.signing_delay + p.wclose) as f64).abs() < 0.5);
    }

    #[test]
    fn doa_rate_grows_with_signing_delay() {
        // The design's DOA variable: slower wallets sign against heads that
        // have already advanced. Higher delay ⇒ strictly higher DOA rate.
        let fast = A1Params {
            signing_delay: 1,
            ..A1Params::default()
        };
        let slow = A1Params {
            signing_delay: 3,
            ..A1Params::default()
        };
        let (s_fast, _) = run_a1(&fast);
        let (s_slow, _) = run_a1(&slow);
        assert!(s_slow.stale_rate() > s_fast.stale_rate());
        assert!(
            s_fast.stale_rate() > 0.0,
            "some DOA expected even at delay 1"
        );
    }

    #[test]
    fn fee_priority_only_helps_simultaneous_conflicts() {
        // Design §7.1: fee density decides only among simultaneously eligible
        // spends. With builder_period 1 and signing delay 1, user and builder
        // broadcasts become eligible in the same tick, so a 10× fee converts
        // lost conflicts into won ones — visible as fewer re-signings and
        // faster p95 admission, not necessarily different ultimate success.
        let base = A1Params {
            builder_period: 1,
            signing_delay: 1,
            user_arrival_prob: 1.0,
            users: 1,
            user_fee_multiplier: 1.0,
            ..A1Params::default()
        };
        let rich = A1Params {
            user_fee_multiplier: 10.0,
            ..base.clone()
        };
        let (s_base, _) = run_a1(&base);
        let (s_rich, _) = run_a1(&rich);
        let resign_base = s_base.stale_before_broadcast + s_base.superseded_after_broadcast;
        let resign_rich = s_rich.stale_before_broadcast + s_rich.superseded_after_broadcast;
        assert!(
            resign_rich < resign_base,
            "fee priority should reduce re-signings: {resign_rich} vs {resign_base}"
        );
    }
}
