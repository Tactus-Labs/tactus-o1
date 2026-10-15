//! A2 independent Priority Message Cells simulation — Experiment A, A2 arm
//! (design §7.2; spec §5.3).
//!
//! Users create independently funded Message Cells **without consuming any
//! shared head**: admission has no contention by construction (the A2
//! strength). The arm's open questions are processing and obligation
//! continuity — whether messages are actually processed before their
//! deadlines, and whether a challenge forces processing or merely exacts a
//! penalty. Both builder behaviours and both challenge semantics are
//! simulated; the decision rules of design §5 map the outcomes.

use crate::RunMetrics;

/// How the dominant builder treats pending messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BuilderBehavior {
    /// FIFO processing up to `max_messages_per_batch` per batch.
    HonestFifo,
    /// Processes nothing voluntarily; only forced inclusion (if enabled)
    /// ever progresses messages. Models the carry-forward-starvation attack.
    Lazy,
}

/// Tuning parameters for the A2 arm.
#[derive(Debug, Clone)]
pub struct A2Params {
    pub ticks: u64,
    pub users: usize,
    pub user_arrival_prob: f64,
    pub signing_delay: u64,
    /// Creation-transaction commit latency (proposal-window minimum).
    pub wclose: u64,
    /// Ticks after a message goes live before its processing deadline.
    pub deadline: u64,
    pub builder_period: u64,
    pub max_messages_per_batch: usize,
    pub builder_behavior: BuilderBehavior,
    /// Whether a successful challenge forces processing on the next batch
    /// (`true`) or only exacts a penalty (`false`).
    pub challenge_forces_processing: bool,
    /// Constant proving latency from batch commitment to proven settlement.
    pub proving_latency: u64,
    pub seed: u64,
}

impl Default for A2Params {
    fn default() -> Self {
        Self {
            ticks: 2_000,
            users: 5,
            user_arrival_prob: 0.10,
            signing_delay: 2,
            wclose: 2,
            deadline: 20,
            builder_period: 2,
            max_messages_per_batch: 3,
            builder_behavior: BuilderBehavior::HonestFifo,
            challenge_forces_processing: true,
            proving_latency: 6,
            seed: 42,
        }
    }
}

/// Raw A2 outcome counters.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct A2Stats {
    pub messages_admitted: u64,
    pub admission_delays: Vec<u64>,
    pub messages_processed: u64,
    /// Live-to-batch-commit delays for processed messages.
    pub processing_delays: Vec<u64>,
    /// Live-to-proven-settlement delays for processed messages.
    pub proven_delays: Vec<u64>,
    pub deadline_violations: u64,
    pub challenges_fired: u64,
    pub challenges_forced_processing: u64,
    pub batches_committed: u64,
}

impl A2Stats {
    #[must_use]
    pub fn deadline_violation_rate(&self) -> f64 {
        let done = self.messages_admitted;
        if done == 0 {
            f64::NAN
        } else {
            self.deadline_violations as f64 / done as f64
        }
    }

    /// Fraction of challenges that actually forced processing — design §5:
    /// retrospective liability is not forced inclusion.
    #[must_use]
    pub fn forced_fraction(&self) -> f64 {
        if self.challenges_fired == 0 {
            f64::NAN
        } else {
            self.challenges_forced_processing as f64 / self.challenges_fired as f64
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
    Signing { remaining: u64, first_tick: u64 },
    Confirming { live_tick: u64, first_tick: u64 },
}

#[derive(Debug, Clone)]
struct Message {
    live_tick: u64,
    deadline_tick: u64,
    /// Set when a challenge forces this message into the next batch.
    forced: bool,
}

/// Runs one A2 scenario and returns raw stats plus the mapped metrics record.
pub fn run_a2(params: &A2Params) -> (A2Stats, RunMetrics) {
    let mut rng = Rng(params.seed);
    let mut stats = A2Stats::default();

    let mut users = vec![UserState::Idle; params.users];
    // Messages live and not yet processed, FIFO by live_tick.
    let mut pending: Vec<Message> = Vec::new();
    let mut next_batch_tick = 0u64;

    for t in 0..params.ticks {
        // 1. User arrivals, signing, creation-transaction confirmation.
        for user in users.iter_mut() {
            match user {
                UserState::Idle => {
                    if rng.next_f64() < params.user_arrival_prob {
                        *user = UserState::Signing {
                            remaining: params.signing_delay,
                            first_tick: t,
                        };
                    }
                }
                UserState::Signing {
                    remaining,
                    first_tick,
                } => {
                    *remaining -= 1;
                    if *remaining == 0 {
                        // Creation tx proposes now, commits after wclose.
                        *user = UserState::Confirming {
                            live_tick: t + params.wclose,
                            first_tick: *first_tick,
                        };
                    }
                }
                UserState::Confirming { .. } => {}
            }
        }
        for user in users.iter_mut() {
            if let UserState::Confirming {
                live_tick,
                first_tick,
            } = user
            {
                if t == *live_tick {
                    // Cell is live: admission succeeded, with zero contention.
                    let msg = Message {
                        live_tick: t,
                        deadline_tick: t + params.deadline,
                        forced: false,
                    };
                    pending.push(msg);
                    stats.messages_admitted += 1;
                    stats.admission_delays.push(t - *first_tick);
                    *user = UserState::Idle;
                }
            }
        }

        // 2. Builder batch: commits every builder_period ticks, consuming the
        //    OrderingHead (uncontended in this arm) and up to N messages.
        if t >= next_batch_tick {
            let mut taken = 0usize;
            pending.retain(|m| {
                let wants = match params.builder_behavior {
                    BuilderBehavior::HonestFifo => taken < params.max_messages_per_batch,
                    BuilderBehavior::Lazy => m.forced && taken < params.max_messages_per_batch,
                };
                if wants {
                    taken += 1;
                    stats.messages_processed += 1;
                    stats.processing_delays.push(t - m.live_tick);
                    stats
                        .proven_delays
                        .push(t - m.live_tick + params.proving_latency);
                    false
                } else {
                    true
                }
            });
            stats.batches_committed += 1;
            next_batch_tick = t + params.builder_period;
        }

        // 3. Deadline expiry and challenges.
        pending.retain(|m| {
            if t > m.deadline_tick {
                stats.deadline_violations += 1;
                stats.challenges_fired += 1;
                if params.challenge_forces_processing {
                    // Forced inclusion: processed by the very next batch.
                    stats.challenges_forced_processing += 1;
                    stats.messages_processed += 1;
                    stats.processing_delays.push(t - m.live_tick);
                    stats
                        .proven_delays
                        .push(t - m.live_tick + params.proving_latency);
                    false
                } else {
                    // Penalty only: liability is recorded, the message is
                    // never processed. This is the §5 "G2 not passed" path.
                    false
                }
            } else {
                true
            }
        });
    }

    let metrics = RunMetrics {
        builder_batches_per_block: stats.batches_committed as f64 / params.ticks as f64,
        priority_admission_success_rate: 1.0, // admission is contention-free by construction
        priority_admission_delay_blocks_p50: A2Stats::percentile(&stats.admission_delays, 50.0),
        priority_admission_delay_blocks_p95: A2Stats::percentile(&stats.admission_delays, 95.0),
        priority_processing_delay_batches_p50: A2Stats::percentile(&stats.processing_delays, 50.0),
        priority_processing_delay_batches_p95: A2Stats::percentile(&stats.processing_delays, 95.0),
        priority_deadline_violation_rate: stats.deadline_violation_rate(),
        fraction_of_challenges_that_force_actual_processing: stats.forced_fraction(),
        ..RunMetrics::default()
    };
    (stats, metrics)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn honest_builder_processes_everything_before_deadline() {
        let p = A2Params {
            ticks: 2_000,
            ..A2Params::default()
        };
        let (s, _) = run_a2(&p);
        assert_eq!(
            s.deadline_violations, 0,
            "honest FIFO should never violate deadlines"
        );
        assert!(s.messages_processed > 100);
        assert!(s.challenges_fired == 0);
    }

    #[test]
    fn admission_is_contention_free() {
        // Even with a lazy builder ignoring every message, admission itself
        // always succeeds — the A2 strength, isolated.
        let p = A2Params {
            ticks: 1_000,
            builder_behavior: BuilderBehavior::Lazy,
            challenge_forces_processing: false,
            ..A2Params::default()
        };
        let (s, m) = run_a2(&p);
        assert!(s.messages_admitted > 50);
        assert!((m.priority_admission_success_rate - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn lazy_builder_penalty_only_fails_g2_evidence() {
        // Design §5: challenges that only exact a penalty leave messages
        // unprocessed — punishable censorship, not enforceable inclusion.
        let p = A2Params {
            ticks: 1_000,
            builder_behavior: BuilderBehavior::Lazy,
            challenge_forces_processing: false,
            ..A2Params::default()
        };
        let (s, m) = run_a2(&p);
        assert!(
            s.deadline_violation_rate() > 0.9,
            "lazy builder should violate deadlines"
        );
        assert_eq!(s.messages_processed, 0);
        assert!(
            (m.fraction_of_challenges_that_force_actual_processing).abs() < 1e-9,
            "penalty-only must not force processing"
        );
    }

    #[test]
    fn forced_inclusion_rescues_lazy_builder() {
        let p = A2Params {
            ticks: 1_000,
            builder_behavior: BuilderBehavior::Lazy,
            challenge_forces_processing: true,
            ..A2Params::default()
        };
        let (s, m) = run_a2(&p);
        assert!(s.messages_processed > 50);
        assert!((m.fraction_of_challenges_that_force_actual_processing - 1.0).abs() < 1e-9);
        assert!(
            s.deadline_violations > 0,
            "violations still occur before the challenge fires"
        );
    }
}
