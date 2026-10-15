//! State access shared by full-state replay and authenticated sparse execution.
//! Implementations are part of the proved guest, not prover-supplied behavior.
use alloy_primitives::B256;
use revm::{primitives::AddressMap, state::Account, Database};

pub trait StateBackend: Database {
    fn begin_batch(&mut self);
    fn accept_batch(&mut self);
    fn rollback_batch(&mut self);
    /// Missing or invalid witnesses must return an error, never a default value.
    fn commit_changes(&mut self, changes: AddressMap<Account>) -> Result<(), crate::Error>;
    fn calculate_state_root(&mut self) -> Result<B256, crate::Error>;
    fn cached_header_hash(&self, number: u64) -> Option<B256>;
    fn record_header(&mut self, number: u64, hash: B256);
}
