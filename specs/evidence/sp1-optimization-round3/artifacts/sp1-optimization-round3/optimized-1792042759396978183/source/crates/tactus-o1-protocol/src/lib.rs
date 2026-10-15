//! Tactus O1 protocol primitives.
//!
//! Illustrative field sets mirroring the architecture specification
//! (`specs/TACTUS_O1_ARCHITECTURE_SPEC_v0.2.6.md` §3.2). These types are
//! specification companions and test fixtures, **not** an approved canonical
//! encoding: the canonical wire format is defined under `specs/` with fixed
//! test vectors before any script or settlement logic may depend on it.
//!
//! Priority invariants (spec §5.1): PRI-1 identity, PRI-2 prefix/processing
//! integrity, PRI-3 freshness, PRI-4 deterministic outcome, PRI-5 recovery,
//! PRI-6 admission liveness (OPEN), PRI-7 enforceable inclusion (OPEN).

#![no_std]
extern crate alloc;

/// Canonical bounded batch inputs and inline-DA anchor state.
pub mod batch;
pub mod genesis;
pub mod priority;

/// 32-byte domain-separated digest.
pub type Hash32 = [u8; 32];

/// Canonical ordering state for the A1 reference construction (spec §4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrderingHead {
    /// Genesis-bound rollup identity.
    pub rollup_id: Hash32,
    pub protocol_version: u32,
    /// Next canonical batch number; APPEND_BATCH increments exactly once.
    pub next_batch_number: u64,
    /// Authenticated ordered batch accumulator (not unordered set membership).
    pub batch_accumulator_root: Hash32,
    /// Authenticated priority-queue root and cursors (A1 atomic admission).
    pub inbox_root: Hash32,
    pub inbox_tail: u64,
    pub processed_inbox_cursor: u64,
    /// Pinned Ethereum execution rules.
    pub execution_rules_hash: Hash32,
    /// Genesis-bound domain parameter; immutable under ordinary transitions
    /// (spec §10.2 — no per-batch DA switch over a global state).
    pub da_policy_id: Hash32,
}

/// The two permitted OrderingHead transitions (spec §4.1–4.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OrderingTransition {
    /// Append one authenticated priority message; batch counter and processed
    /// cursor unchanged; admission pricing and capacity accounting enforced.
    Enqueue,
    /// Extend the canonical batch accumulator and advance the processed
    /// priority cursor over an authenticated contiguous prefix.
    AppendBatch,
}

/// Candidate batch commitment (spec §3.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchManifest {
    pub rollup_id: Hash32,
    pub protocol_version: u32,
    pub batch_number: u64,
    pub parent_batch_commitment: Hash32,
    /// Binds the actual ordered transaction sequence.
    pub ordered_transactions_root: Hash32,
    pub inbox_cursor_before: u64,
    pub inbox_cursor_after: u64,
    pub data_commitment: Hash32,
    pub data_encoding_version: u32,
    pub da_policy_id: Hash32,
    pub execution_rules_hash: Hash32,
    pub gas_limit: u64,
    pub resource_limits_commitment: Hash32,
}

/// Immutable ordering evidence emitted by a valid APPEND_BATCH transition
/// (spec §6). Authenticity requires script-enforced provenance — a plausible
/// hash in arbitrary cell data is not a checkpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchCheckpoint {
    pub rollup_id: Hash32,
    pub batch_number: u64,
    pub cumulative_batch_root: Hash32,
    pub batch_commitment: Hash32,
    pub ordering_protocol_version: u32,
}

/// Verified settlement state (spec §5 of the spec's §3.2 reference set).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SettlementTip {
    pub rollup_id: Hash32,
    pub settlement_protocol_version: u32,
    /// Contiguous proven batch frontier.
    pub proven_batch_cursor: u64,
    pub ethereum_state_root: Hash32,
    pub withdrawal_root: Hash32,
    pub execution_rules_hash: Hash32,
    pub proof_system_id: Hash32,
    pub verification_key_commitment: Hash32,
}

pub mod sealed;

/// Candidate native custody profile; not enabled in the v1 proof guest.
#[cfg(feature = "native-bridge")]
pub mod native_bridge;
