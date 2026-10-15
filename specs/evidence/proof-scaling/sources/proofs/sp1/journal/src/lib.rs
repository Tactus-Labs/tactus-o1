//! Execution statement shared by the real zkVM guest and local verifier.
//! This is not a CKB settlement verifier or a custody authorization.
use tactus_o1_execution::{Executor, Genesis};
use tactus_o1_protocol::{
    batch::{self, AnchorState},
    genesis, Hash32,
};

pub const DOMAIN_LEN: usize = 136;
pub const JOURNAL_LEN: usize = 768;
const MAGIC: &[u8; 8] = b"TO1PRF01";

/// Public deployment context. A settlement verifier must compare these values
/// with its own authenticated configuration; a prover's choice is not authority.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Domain {
    pub ckb_genesis: Hash32,
    pub ordering_type_hash: Hash32,
    pub settlement_type_hash: Hash32,
    pub rollup_id: Hash32,
    pub chain_id: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Encoding,
    Domain,
    Range,
    Allocation,
    Execution,
}

impl Domain {
    pub fn encode(&self) -> [u8; DOMAIN_LEN] {
        let mut out = [0; DOMAIN_LEN];
        for (i, value) in [
            self.ckb_genesis,
            self.ordering_type_hash,
            self.settlement_type_hash,
            self.rollup_id,
        ]
        .iter()
        .enumerate()
        {
            out[i * 32..(i + 1) * 32].copy_from_slice(value);
        }
        out[128..].copy_from_slice(&self.chain_id.to_le_bytes());
        out
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != DOMAIN_LEN {
            return Err(Error::Encoding);
        }
        let domain = Self {
            ckb_genesis: bytes[..32].try_into().unwrap(),
            ordering_type_hash: bytes[32..64].try_into().unwrap(),
            settlement_type_hash: bytes[64..96].try_into().unwrap(),
            rollup_id: bytes[96..128].try_into().unwrap(),
            chain_id: u64::from_le_bytes(bytes[128..].try_into().unwrap()),
        };
        domain.validate()?;
        Ok(domain)
    }
    fn validate(&self) -> Result<(), Error> {
        if self.chain_id == 0
            || [
                self.ckb_genesis,
                self.ordering_type_hash,
                self.settlement_type_hash,
                self.rollup_id,
            ]
            .contains(&[0; 32])
        {
            return Err(Error::Domain);
        }
        Ok(())
    }
}

pub fn profile_id() -> Hash32 {
    batch::hash(b"tactus/o1/proof-profile/v1", b"TO1PRF01;replay-canonical-genesis-prefix;nonempty-contiguous-interval;ethereum-state-and-header;no-withdrawal-authorization")
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Journal {
    pub domain: Domain,
    pub allocation_commitment: Hash32,
    pub before: AnchorState,
    pub after: AnchorState,
    pub previous_state_root: Hash32,
    pub next_state_root: Hash32,
    pub previous_header_hash: Hash32,
    pub next_header_hash: Hash32,
    pub interval_digest: Hash32,
}

impl Journal {
    pub fn encode(&self) -> [u8; JOURNAL_LEN] {
        let mut out = [0; JOURNAL_LEN];
        out[..8].copy_from_slice(MAGIC);
        out[8..40].copy_from_slice(&profile_id());
        out[40..176].copy_from_slice(&self.domain.encode());
        out[176..208].copy_from_slice(&self.allocation_commitment);
        out[208..408].copy_from_slice(&self.before.encode());
        out[408..608].copy_from_slice(&self.after.encode());
        for (i, value) in [
            self.previous_state_root,
            self.next_state_root,
            self.previous_header_hash,
            self.next_header_hash,
            self.interval_digest,
        ]
        .iter()
        .enumerate()
        {
            out[608 + i * 32..640 + i * 32].copy_from_slice(value);
        }
        out
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != JOURNAL_LEN || &bytes[..8] != MAGIC || bytes[8..40] != profile_id() {
            return Err(Error::Encoding);
        }
        let before = AnchorState::decode(&bytes[208..408]).map_err(|_| Error::Encoding)?;
        let after = AnchorState::decode(&bytes[408..608]).map_err(|_| Error::Encoding)?;
        let domain = Domain::decode(&bytes[40..176])?;
        domain.validate()?;
        if before.next_batch_number >= after.next_batch_number {
            return Err(Error::Range);
        }
        if before.rollup_id != domain.rollup_id
            || before.chain_id != domain.chain_id
            || before.rollup_id != after.rollup_id
            || before.chain_id != after.chain_id
            || before.execution_rules_hash != after.execution_rules_hash
            || before.execution_rules_hash != tactus_o1_execution::rules_hash()
            || before.da_policy_id != after.da_policy_id
            || before.limits_hash != after.limits_hash
        {
            return Err(Error::Domain);
        }
        Ok(Self {
            domain,
            allocation_commitment: bytes[176..208].try_into().unwrap(),
            before,
            after,
            previous_state_root: bytes[608..640].try_into().unwrap(),
            next_state_root: bytes[640..672].try_into().unwrap(),
            previous_header_hash: bytes[672..704].try_into().unwrap(),
            next_header_hash: bytes[704..736].try_into().unwrap(),
            interval_digest: bytes[736..768].try_into().unwrap(),
        })
    }
}

/// Rebuild the prefix from canonical allocation bytes, then execute the requested
/// interval. This avoids trusting a caller-supplied state snapshot. Prefix replay
/// grows with history and still needs an authenticated checkpoint optimization.
pub fn execute(
    domain: Domain,
    allocation: &[u8],
    prefix_batches: u64,
    interval_batches: u64,
    mut next_batch: impl FnMut() -> Vec<u8>,
) -> Result<Journal, Error> {
    domain.validate()?;
    if interval_batches == 0 || prefix_batches.checked_add(interval_batches).is_none() {
        return Err(Error::Range);
    }
    let allocation_commitment = genesis::commitment(allocation).map_err(|_| Error::Allocation)?;
    let genesis = Genesis::from_allocation(domain.rollup_id.into(), domain.chain_id, allocation)
        .map_err(|_| Error::Allocation)?;
    let mut engine = Executor::new(&genesis).map_err(|_| Error::Execution)?;
    for _ in 0..prefix_batches {
        engine
            .apply_batch(&next_batch())
            .map_err(|_| Error::Execution)?;
    }
    let before = *engine.anchor();
    let previous_state_root = engine.state_root().0;
    let previous_header_hash = engine.head().hash_slow().0;
    let mut interval_digest = batch::hash(
        b"tactus/o1/proof-interval/v1",
        &interval_batches.to_le_bytes(),
    );
    for _ in 0..interval_batches {
        let bytes = next_batch();
        engine.apply_batch(&bytes).map_err(|_| Error::Execution)?;
        let mut entry = interval_digest.to_vec();
        entry.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
        entry.extend_from_slice(&bytes);
        interval_digest = batch::hash(b"tactus/o1/proof-interval-step/v1", &entry);
    }
    let journal = Journal {
        domain,
        allocation_commitment,
        before,
        after: *engine.anchor(),
        previous_state_root,
        next_state_root: engine.state_root().0,
        previous_header_hash,
        next_header_hash: engine.head().hash_slow().0,
        interval_digest,
    };
    // Keep construction and strict decoding in agreement.
    Journal::decode(&journal.encode())?;
    Ok(journal)
}
