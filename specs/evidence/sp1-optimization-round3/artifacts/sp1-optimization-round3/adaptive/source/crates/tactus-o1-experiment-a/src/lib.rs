//! Experiment A harness primitives: candidate arms, workload models and the
//! measurement record for the priority-admission comparison
//! (`specs/EXPERIMENT_A_DESIGN.md`; spec §14).
//!
//! The first implemented arm is the A1 simulation in [`sim`]: an
//! OrderingHead admission model under a dominant builder, exercising the
//! fee-ratio and dead-on-arrival variables of design §7.1.

pub mod decision;
pub mod sim;
pub mod sim_a2;
pub mod sim_a3;

/// Frozen architecture baseline this experiment runs against.
pub const SPEC_BASELINE: &str = "TACTUS_O1_ARCHITECTURE_SPEC_v0.2.6.md";

/// Experiment arms (design §2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Candidate {
    /// A1 atomic OrderingHead — correctness reference / oracle.
    A1AtomicHead,
    /// A2 independent Priority Message Cells — competitor.
    A2MessageCells,
    /// A3′ sharded lane heads — competitor.
    A3ShardedLanes,
    /// A3′ epoch-sealed snapshots — control arm.
    A3SealedSnapshot,
}

/// Workload regimes under which survival conclusions are interpreted
/// differently (design §3). Conclusions of the form "more lanes worsen
/// invalidation" hold **only** under [`LoadModel::FixedPerLane`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LoadModel {
    /// Fixed arrival rate `λ` per lane; lane count `K` grows:
    /// survival ≈ `e^(−KλΔt)` — more lanes do worsen invalidation.
    FixedPerLane,
    /// Fixed aggregate rate `Λ` spread over more lanes:
    /// survival ≈ `e^(−ΛΔt)` — K-neutral in the simple model; more lanes
    /// still cost more `cell_deps`, verification and construction complexity.
    FixedAggregate,
    /// Adversarially concentrated updates: the attacker chooses timing and
    /// lane targeting, breaking the independence assumption. No analytic
    /// form; must be measured regardless of the models above.
    AdversarialConcentrated,
}

/// Sensitivity model (spec §5.4; design §3). Approximates the probability
/// that all referenced lane heads remain unchanged across a
/// construction-to-commit interval `dt_secs`.
///
/// Returns `f64::NAN` for [`LoadModel::AdversarialConcentrated`]: there is no
/// analytic form, and reporting a number for it would understate the risk.
#[must_use]
pub fn survival_probability(dt_secs: f64, lane_rates: &[f64], model: LoadModel) -> f64 {
    match model {
        LoadModel::FixedPerLane | LoadModel::FixedAggregate => {
            let total: f64 = lane_rates.iter().sum();
            (-total * dt_secs).exp()
        }
        LoadModel::AdversarialConcentrated => f64::NAN,
    }
}

/// Result categories recorded for every run (design §4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ResultCategory {
    /// Duplicate consumption, mis-ordered processing, unauthenticated
    /// carry-forward or unauthenticated execution obligation.
    Safety,
    /// Dominant builder or malicious enqueuer blocking admission, processing
    /// or canonical batch progression.
    Liveness,
    /// Fees, cycles, rebuild cost and storage under the above guarantees.
    Economics,
}

/// Pre-committed decision rules (design §5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Decision {
    /// Safe, but wallets sustain dead-on-arrival admission: reference only.
    KeepA1AsReferenceOnly,
    /// Admission succeeds while forced processing remains unproven: G2 fail.
    G2NotPassed,
    /// Freshness correct but churn blocks batches: reject live-head strategy.
    RejectLiveHeadDependencyStrategy,
    /// Snapshots reduce invalidation but delay mandatory inclusion: reject
    /// the switching policy.
    RejectSnapshotSwitchingPolicy,
    /// Safe, recoverable, force-progressing, affordable.
    AdvanceToProductionReview,
    /// Passed only under an assumed or unexercised primitive — e.g.
    /// `challenge_forces_processing`, or a switching-policy gate whose delay
    /// path was never measured — that no CKB lock/type script yet implements.
    /// Not advanceable; revisited only with real script transitions and
    /// adversarial devnet tests.
    ConditionalEnforcementPrimitiveUnimplemented,
}

/// Measurement record — spec §14.4 including the v0.2.5 churn additions.
/// All rates are fractions in `[0, 1]` unless named otherwise.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct RunMetrics {
    pub builder_batches_per_block: f64,
    pub priority_admission_success_rate: f64,
    pub priority_admission_delay_blocks_p50: f64,
    pub priority_admission_delay_blocks_p95: f64,
    pub priority_admission_delay_blocks_p99: f64,
    pub priority_processing_delay_batches_p50: f64,
    pub priority_processing_delay_batches_p95: f64,
    pub priority_processing_delay_batches_p99: f64,
    pub priority_backlog_depth_over_time: Vec<f64>,
    pub priority_deadline_violation_rate: f64,
    pub time_to_recover_stability_after_overload_secs: f64,
    pub head_stale_before_broadcast_rate: f64,
    pub lane_head_churn_rate_per_lane: f64,
    pub batch_dependency_invalidation_rate: f64,
    pub candidate_anchor_survival_rate: f64,
    pub abandoned_anchor_rebuild_cost: f64,
    pub retry_and_resign_count: u64,
    pub ckb_fee_paid_per_successful_priority_admission: f64,
    /// (success rate, false-positive rate).
    pub challenge_success_and_false_positive_rate: (f64, f64),
    /// (required, exposed).
    pub liability_bond_required_and_exposed: (f64, f64),
    pub fraction_of_challenges_that_force_actual_processing: f64,
    /// (cycles, bytes).
    pub ckb_cycles_and_bytes_per_priority_operation: (f64, f64),
    pub reorg_recovery_and_checkpoint_dependency_results: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    const EPS: f64 = 1e-12;

    #[test]
    fn fixed_aggregate_survival_is_lane_count_neutral() {
        // L2: splitting the same aggregate rate across more lanes leaves the
        // survival probability unchanged in the simple model (design §3).
        let dt = 30.0;
        let aggregate = 0.4_f64; // updates per second, total
        let one_lane = [aggregate];
        let eight_lanes = [aggregate / 8.0; 8];
        let a = survival_probability(dt, &one_lane, LoadModel::FixedAggregate);
        let b = survival_probability(dt, &eight_lanes, LoadModel::FixedAggregate);
        assert!((a - b).abs() < EPS, "expected {a} ≈ {b}");
    }

    #[test]
    fn fixed_per_lane_survival_degrades_with_lane_count() {
        // L1: fixed per-lane rate λ; more lanes ⇒ strictly lower survival.
        let dt = 30.0;
        let lambda = 0.05_f64;
        let small = [lambda; 2];
        let large = [lambda; 16];
        let a = survival_probability(dt, &small, LoadModel::FixedPerLane);
        let b = survival_probability(dt, &large, LoadModel::FixedPerLane);
        assert!(b < a, "expected survival({large:?}) < survival({small:?})");
    }

    #[test]
    fn adversarial_model_has_no_analytic_answer() {
        let p = survival_probability(30.0, &[0.1; 4], LoadModel::AdversarialConcentrated);
        assert!(
            p.is_nan(),
            "adversarial regime must be measured, not modelled"
        );
    }
}
