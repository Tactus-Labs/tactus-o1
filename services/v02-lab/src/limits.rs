//! Development retention ceilings, not consensus limits or a process-RSS bound.
use crate::{build::Cell, Result};
use serde_json::{json, Value};
use tactus_o1_execution::{v02::V02Executor, GenesisAccount};
pub const MAX_CLAIMS_PER_KIND: usize = 65_536;
pub const MAX_HEIGHT: u64 = 100_000;
pub const MAX_SCANNED_TRANSACTIONS: usize = 1_000_000;
pub const MAX_LIVE_CELLS: usize = 100_000;
pub const MAX_TRANSITIONS: usize = 100_000;
pub const MAX_OUTCOMES: usize = 65_536;
pub const MAX_FRAMES: usize = 10_000;
pub const MAX_LIVE_PAYLOAD: usize = 128 * 1024 * 1024;
pub const MAX_FRAME_PAYLOAD: usize = 24 * 1024 * 1024;
pub const MAX_STATE_PAYLOAD: usize = 128 * 1024 * 1024;
pub const MAX_STATE_ENTRIES: usize = 1_000_000;

pub struct Meter {
    used: usize,
    limit: usize,
    name: &'static str,
}
impl Meter {
    pub fn new(limit: usize, name: &'static str) -> Self {
        Self {
            used: 0,
            limit,
            name,
        }
    }
    pub fn add(&mut self, bytes: usize) -> Result<()> {
        let next = self
            .used
            .checked_add(bytes)
            .filter(|next| *next <= self.limit)
            .ok_or_else(|| format!("development {} retention limit exceeded", self.name))?;
        self.used = next;
        Ok(())
    }
    pub fn remove(&mut self, bytes: usize) -> Result<()> {
        self.used = self
            .used
            .checked_sub(bytes)
            .ok_or("retention accounting underflow")?;
        Ok(())
    }
    pub fn used(&self) -> usize {
        self.used
    }
}
pub fn cell_payload(cell: &Cell) -> Result<usize> {
    // Canonical outpoint, capacity, lock, optional type, data and length fields.
    [
        64,
        cell.output.lock.len(),
        cell.output.type_script.as_ref().map_or(0, Vec::len),
        cell.output.data.len(),
    ]
    .into_iter()
    .try_fold(0usize, |sum, n| {
        sum.checked_add(n)
            .ok_or_else(|| "cell payload overflow".into())
    })
}
fn measure_state(
    accounts: impl Iterator<Item = GenesisAccount>,
    max_bytes: usize,
    max_entries: usize,
) -> Result<(usize, usize)> {
    let mut bytes = Meter::new(max_bytes, "execution-state payload");
    let mut entries = Meter::new(max_entries, "execution-state entries");
    for account in accounts {
        entries.add(1)?;
        entries.add(account.storage.len())?;
        bytes.add(128)?;
        bytes.add(account.code.len())?;
        bytes.add(
            account
                .storage
                .len()
                .checked_mul(64)
                .ok_or("state payload overflow")?,
        )?;
    }
    Ok((bytes.used(), entries.used()))
}
pub fn state_usage(engine: &V02Executor) -> Result<(usize, usize)> {
    measure_state(
        engine.accounts().map(|(_, account)| account),
        MAX_STATE_PAYLOAD,
        MAX_STATE_ENTRIES,
    )
}
pub fn description() -> Value {
    json!({"maximum_claims_per_kind":MAX_CLAIMS_PER_KIND,"maximum_height":MAX_HEIGHT,"maximum_scanned_transactions":MAX_SCANNED_TRANSACTIONS,
        "maximum_live_cells":MAX_LIVE_CELLS,"maximum_transitions":MAX_TRANSITIONS,"maximum_frames":MAX_FRAMES,"maximum_reported_outcomes":MAX_OUTCOMES,
        "maximum_live_payload_bytes":MAX_LIVE_PAYLOAD,"maximum_frame_payload_bytes":MAX_FRAME_PAYLOAD,
        "maximum_execution_state_payload_bytes":MAX_STATE_PAYLOAD,"maximum_execution_state_entries":MAX_STATE_ENTRIES,
        "scope":"canonical cell/frame payload and visible live EVM state/count ceilings; deleted-account/code caches, allocator overhead, transient RPC/JSON buffers and execution working memory are additional",
        "on_limit":"abort refresh/export; never prune canonical rights or silently skip history"})
}
#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{Bytes, U256};
    use std::collections::BTreeMap;
    #[test]
    fn retained_payload_limit_releases_spent_data_and_rejects_overflow_atomically() {
        let mut meter = Meter::new(100, "fixture");
        meter.add(40).unwrap();
        meter.add(60).unwrap();
        assert!(meter.add(1).is_err());
        assert_eq!(meter.used(), 100);
        meter.remove(40).unwrap();
        meter.add(40).unwrap();
        assert!(meter.remove(101).is_err());
        assert_eq!(meter.used(), 100);
        let mut maximum = Meter::new(usize::MAX, "overflow fixture");
        maximum.add(usize::MAX).unwrap();
        assert!(maximum.add(1).is_err());
        assert_eq!(maximum.used(), usize::MAX);
    }
    #[test]
    fn replay_state_bounds_count_storage_and_code_not_only_addresses() {
        let account = GenesisAccount {
            code: Bytes::from(vec![0; 32]),
            storage: BTreeMap::from([
                (U256::from(1), U256::from(2)),
                (U256::from(3), U256::from(4)),
            ]),
            ..Default::default()
        };
        assert_eq!(
            measure_state(std::iter::once(account.clone()), 288, 3).unwrap(),
            (288, 3)
        );
        assert!(measure_state(std::iter::once(account.clone()), 287, 3).is_err());
        assert!(measure_state(std::iter::once(account), 288, 2).is_err());
    }
}
