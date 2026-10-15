//! Complete authenticated state checkpoints. This is the history-bounded first
//! stage, not a sparse witness. The caller must bind Boundary to a trusted prior
//! settlement/proof; a prover-chosen boundary provides no authority by itself.
use super::*;

pub const MAX_CHECKPOINT_BYTES: usize = 8 * 1024 * 1024;
const MAX_ACCOUNTS: usize = 16_384;
const MAX_STORAGE_SLOTS: usize = 131_072;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Boundary {
    pub anchor: AnchorState,
    pub state_root: B256,
    pub header_hash: B256,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Checkpoint {
    pub accounts: BTreeMap<Address, GenesisAccount>,
    /// Oldest first, exactly min(head.number + 1, 256) linked headers.
    pub recent_headers: Vec<Header>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CheckpointError {
    Encoding,
    Limit,
    Domain,
    Boundary,
    Header,
    State,
}

/// Authenticate the complete BLOCKHASH window against an externally bound tip.
/// This authenticates ancestry, not the authority of the supplied boundary.
pub fn authenticate_headers(
    headers: &[Header],
    boundary: &Boundary,
) -> Result<BTreeMap<u64, B256>, CheckpointError> {
    let head = headers.last().ok_or(CheckpointError::Header)?;
    if headers.len() > 256
        || head.number != boundary.anchor.last_block_number
        || head.timestamp != boundary.anchor.last_timestamp
        || head.state_root != boundary.state_root
        || head.hash_slow() != boundary.header_hash
        || headers.len() != head.number.min(255) as usize + 1
    {
        return Err(CheckpointError::Header);
    }
    let first_number = head.number - (headers.len() as u64 - 1);
    let mut previous = None;
    let mut hashes = BTreeMap::new();
    for (offset, header) in headers.iter().enumerate() {
        if header.number != first_number + offset as u64
            || previous.is_some_and(|hash| header.parent_hash != hash)
        {
            return Err(CheckpointError::Header);
        }
        let hash = header.hash_slow();
        hashes.insert(header.number, hash);
        previous = Some(hash);
    }
    Ok(hashes)
}

impl Checkpoint {
    pub fn decode(bytes: &[u8]) -> Result<Self, CheckpointError> {
        if bytes.len() > MAX_CHECKPOINT_BYTES {
            return Err(CheckpointError::Limit);
        }
        let value: Self = serde_json::from_slice(bytes).map_err(|_| CheckpointError::Encoding)?;
        value.check_limits()?;
        Ok(value)
    }
    pub fn encode(&self) -> Result<Vec<u8>, CheckpointError> {
        self.check_limits()?;
        let bytes = serde_json::to_vec(self).map_err(|_| CheckpointError::Encoding)?;
        if bytes.len() > MAX_CHECKPOINT_BYTES {
            return Err(CheckpointError::Limit);
        }
        Ok(bytes)
    }
    fn check_limits(&self) -> Result<(), CheckpointError> {
        if self.accounts.len() > MAX_ACCOUNTS
            || self.recent_headers.is_empty()
            || self.recent_headers.len() > 256
        {
            return Err(CheckpointError::Limit);
        }
        let mut slots = 0usize;
        for account in self.accounts.values() {
            slots = slots
                .checked_add(account.storage.len())
                .ok_or(CheckpointError::Limit)?;
            if slots > MAX_STORAGE_SLOTS
                || account.code.len() > tactus_o1_protocol::genesis::MAX_CODE_BYTES
            {
                return Err(CheckpointError::Limit);
            }
        }
        Ok(())
    }

    /// Restore only a continuation. Genesis must instead use the committed
    /// allocation and Executor::new; an arbitrary zero-height snapshot is invalid.
    pub fn restore(
        &self,
        rollup: B256,
        chain: u64,
        boundary: &Boundary,
    ) -> Result<Executor, CheckpointError> {
        self.check_limits()?;
        let anchor =
            AnchorState::decode(&boundary.anchor.encode()).map_err(|_| CheckpointError::Domain)?;
        if anchor.rollup_id != rollup.0
            || anchor.chain_id != chain
            || anchor.execution_rules_hash != rules_hash()
        {
            return Err(CheckpointError::Domain);
        }
        if anchor.next_batch_number == 0 || anchor.last_block_number < anchor.next_batch_number {
            return Err(CheckpointError::Boundary);
        }
        let head = self.recent_headers.last().ok_or(CheckpointError::Header)?;
        let mut db = JournalDb::default();
        for (number, hash) in authenticate_headers(&self.recent_headers, boundary)? {
            db.cache.block_hashes.insert(U256::from(number), hash);
        }
        let mut supply = U256::ZERO;
        for (address, account) in &self.accounts {
            supply = supply
                .checked_add(account.balance)
                .ok_or(CheckpointError::State)?;
            if supply > U256::from(u64::MAX)
                || (account.balance.is_zero() && account.nonce == 0 && account.code.is_empty())
                || account.storage.values().any(U256::is_zero)
            {
                return Err(CheckpointError::State);
            }
            let code = Bytecode::new_legacy(account.code.clone());
            db.insert_account_info(
                *address,
                AccountInfo::new(account.balance, account.nonce, code.hash_slow(), code),
            );
            for (key, value) in &account.storage {
                db.insert_account_storage(*address, *key, *value)
                    .expect("complete memory state");
            }
        }
        if state_root(&db) != boundary.state_root {
            return Err(CheckpointError::State);
        }
        Ok(Executor {
            db,
            anchor,
            head: head.clone(),
        })
    }

    #[cfg(not(target_os = "zkvm"))]
    pub fn capture(
        engine: &Executor,
        recent_headers: Vec<Header>,
    ) -> Result<(Boundary, Self), CheckpointError> {
        let boundary = Boundary {
            anchor: *engine.anchor(),
            state_root: engine.state_root(),
            header_hash: engine.head_hash(),
        };
        let snapshot = Self {
            accounts: engine.accounts().collect(),
            recent_headers,
        };
        snapshot.restore(
            engine.anchor.rollup_id.into(),
            engine.anchor.chain_id,
            &boundary,
        )?;
        Ok((boundary, snapshot))
    }
}
