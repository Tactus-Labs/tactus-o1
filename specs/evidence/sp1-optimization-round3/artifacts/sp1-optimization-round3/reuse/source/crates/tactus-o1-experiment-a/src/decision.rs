//! Pre-committed decision rules — design §5. Each arm's measured outcome maps
//! to a decision; thresholds are explicit and must not be weakened after the
//! fact ("revise the protocol, not the gate" — design §7).

use crate::sim::A1Stats;
use crate::sim_a2::A2Stats;
use crate::sim_a3::A3Stats;
use crate::Decision;

/// DOA rate above which A1 is deemed to starve wallet users.
pub const A1_DOA_STARVATION_THRESHOLD: f64 = 0.25;
/// Deadline-violation rate above which A2 processing is deemed failing.
pub const A2_VIOLATION_THRESHOLD: f64 = 0.10;
/// Fraction of challenges that must actually force processing for A2 to
/// claim enforceable inclusion rather than retrospective liability.
pub const A2_FORCED_FRACTION_THRESHOLD: f64 = 0.90;
/// Anchor invalidation rate above which the live-head reference strategy is
/// rejected.
pub const A3_INVALIDATION_THRESHOLD: f64 = 0.50;
/// p95 processing delay (blocks) above which a snapshot switching policy is
/// rejected for unbounded mandatory-inclusion latency.
pub const A3_SEALED_P95_LIMIT: f64 = 48.0;

/// A1: safe ordering, but sustained dead-on-arrival signings mean it stays a
/// correctness reference, not production admission.
#[must_use]
pub fn decide_a1(s: &A1Stats) -> Decision {
    if s.stale_rate() > A1_DOA_STARVATION_THRESHOLD {
        Decision::KeepA1AsReferenceOnly
    } else {
        Decision::AdvanceToProductionReview
    }
}

/// A2: admission is contention-free by construction; the gate is whether
/// challenges force actual processing before deadlines are materially missed.
/// At simulation tier this can never yield `AdvanceToProductionReview`:
/// `challenge_forces_processing` *assumes* the enforcement primitive — how a
/// legal CKB challenge makes a refusing builder process — which no CKB
/// lock/type script yet implements. A passing run is therefore conditional,
/// and "eventually processed" is not "processed within deadline".
#[must_use]
pub fn decide_a2(s: &A2Stats) -> Decision {
    let forced = if s.challenges_fired == 0 {
        1.0
    } else {
        s.forced_fraction()
    };
    if s.deadline_violation_rate() > A2_VIOLATION_THRESHOLD && forced < A2_FORCED_FRACTION_THRESHOLD
    {
        Decision::G2NotPassed
    } else {
        Decision::ConditionalEnforcementPrimitiveUnimplemented
    }
}

/// A3′: verifiable freshness must not come at the cost of batch-anchor
/// liveness; the sealed control arm must not trade it for unbounded delay.
#[must_use]
pub fn decide_a3(s: &A3Stats, sealed: bool) -> Decision {
    if sealed {
        let p95 = A3Stats::percentile(&s.processing_delays, 95.0);
        if p95.is_nan() {
            // The processing-delay path was never exercised in this run: an
            // unmeasured gate is untested, not satisfied (NaN comparisons
            // would otherwise pass every limit silently).
            Decision::ConditionalEnforcementPrimitiveUnimplemented
        } else if p95 > A3_SEALED_P95_LIMIT {
            Decision::RejectSnapshotSwitchingPolicy
        } else {
            Decision::ConditionalEnforcementPrimitiveUnimplemented
        }
    } else if s.invalidation_rate() > A3_INVALIDATION_THRESHOLD {
        Decision::RejectLiveHeadDependencyStrategy
    } else {
        Decision::AdvanceToProductionReview
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simulated_snapshot_latency_never_proves_unimplemented_enforcement() {
        let measured = A3Stats {
            processing_delays: vec![1, 2, 3],
            ..A3Stats::default()
        };
        assert_eq!(
            decide_a3(&measured, true),
            Decision::ConditionalEnforcementPrimitiveUnimplemented
        );
        let late = A3Stats {
            processing_delays: vec![49, 100],
            ..A3Stats::default()
        };
        assert_eq!(
            decide_a3(&late, true),
            Decision::RejectSnapshotSwitchingPolicy
        );
        assert_eq!(
            decide_a3(&A3Stats::default(), true),
            Decision::ConditionalEnforcementPrimitiveUnimplemented
        );
    }
}
