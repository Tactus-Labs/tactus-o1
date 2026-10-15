//! A distinct execution-only sparse proof profile. Settlement must authenticate
//! its public starting boundary and published interval; it is not custody proof.
use tactus_o1_execution::{checkpoint::Boundary, Executor, Genesis};
pub use tactus_o1_proof_journal::{Domain, Error, Journal, JOURNAL_LEN};
use tactus_o1_protocol::{
    batch::{self, AnchorState},
    genesis, Hash32,
};
use tactus_o1_sparse_state::database::{SparseDb, Witness};

pub const MAGIC: &[u8; 8] = b"TO1SPF01";
pub const PROFILE_DESCRIPTION: &[u8] = b"TO1SPF01;genesis-allocation-or-authenticated-nonzero-boundary;ethereum-mpt-sparse-account-storage-code;missing-witness-fatal;linked-256-header-window;nonempty-contiguous-interval;no-withdrawal-authorization";
pub const BOUNDARY_LEN: usize = 264;
pub fn profile_id() -> Hash32 {
    batch::hash(b"tactus/o1/sparse-proof-profile/v1", PROFILE_DESCRIPTION)
}
pub fn encode_boundary(boundary: &Boundary) -> [u8; BOUNDARY_LEN] {
    let mut out = [0; BOUNDARY_LEN];
    out[..200].copy_from_slice(&boundary.anchor.encode());
    out[200..232].copy_from_slice(boundary.state_root.as_slice());
    out[232..].copy_from_slice(boundary.header_hash.as_slice());
    out
}
pub fn decode_boundary(bytes: &[u8]) -> Result<Boundary, Error> {
    if bytes.len() != BOUNDARY_LEN {
        return Err(Error::Encoding);
    }
    Ok(Boundary {
        anchor: AnchorState::decode(&bytes[..200]).map_err(|_| Error::Encoding)?,
        state_root: Hash32::try_from(&bytes[200..232]).unwrap().into(),
        header_hash: Hash32::try_from(&bytes[232..]).unwrap().into(),
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SparseJournal {
    pub transition: Journal,
}
impl SparseJournal {
    pub fn encode(&self) -> [u8; JOURNAL_LEN] {
        let mut out = self.transition.encode();
        out[..8].copy_from_slice(MAGIC);
        out[8..40].copy_from_slice(&profile_id());
        out
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != JOURNAL_LEN || &bytes[..8] != MAGIC || bytes[8..40] != profile_id() {
            return Err(Error::Encoding);
        }
        let mut replay = [0; JOURNAL_LEN];
        replay.copy_from_slice(bytes);
        replay[..8].copy_from_slice(b"TO1PRF01");
        replay[8..40].copy_from_slice(&tactus_o1_proof_journal::profile_id());
        let transition = Journal::decode(&replay)?;
        if transition.allocation_commitment == [0; 32]
            || transition.after.last_block_number <= transition.before.last_block_number
            || transition.after.last_timestamp < transition.before.last_timestamp
        {
            return Err(Error::Range);
        }
        Ok(Self { transition })
    }
    /// Structural continuity only; callers also verify the proof/key and bind
    /// the prior tip and canonical publication to authenticated chain state.
    pub fn follows(&self, previous: &Self) -> Result<(), Error> {
        let now = Self::decode(&self.encode())?.transition;
        let prior = Self::decode(&previous.encode())?.transition;
        if now.domain != prior.domain
            || now.allocation_commitment != prior.allocation_commitment
            || now.before != prior.after
            || now.previous_state_root != prior.next_state_root
            || now.previous_header_hash != prior.next_header_hash
        {
            return Err(Error::Domain);
        }
        Ok(())
    }
}

pub fn execute_genesis(
    domain: Domain,
    allocation: &[u8],
    witness_bytes: &[u8],
    interval_batches: u64,
    next_batch: impl FnMut() -> Vec<u8>,
) -> Result<SparseJournal, Error> {
    Domain::decode(&domain.encode())?;
    let allocation_commitment = genesis::commitment(allocation).map_err(|_| Error::Allocation)?;
    let genesis = Genesis::from_allocation(domain.rollup_id.into(), domain.chain_id, allocation)
        .map_err(|_| Error::Allocation)?;
    let engine = Executor::new(&genesis).map_err(|_| Error::Execution)?;
    let boundary = Boundary {
        anchor: *engine.anchor(),
        state_root: engine.state_root(),
        header_hash: engine.head_hash(),
    };
    let witness = Witness::decode(witness_bytes).map_err(|_| Error::Execution)?;
    let db = SparseDb::from_witness(&boundary, &witness).map_err(|_| Error::Execution)?;
    let engine = engine.with_backend(db).map_err(|_| Error::Execution)?;
    execute_interval(
        domain,
        allocation_commitment,
        engine,
        interval_batches,
        next_batch,
    )
}

pub fn execute_continuation(
    domain: Domain,
    allocation_commitment: Hash32,
    boundary: &Boundary,
    witness_bytes: &[u8],
    interval_batches: u64,
    next_batch: impl FnMut() -> Vec<u8>,
) -> Result<SparseJournal, Error> {
    Domain::decode(&domain.encode())?;
    if allocation_commitment == [0; 32]
        || boundary.anchor.rollup_id != domain.rollup_id
        || boundary.anchor.chain_id != domain.chain_id
    {
        return Err(Error::Domain);
    }
    let witness = Witness::decode(witness_bytes).map_err(|_| Error::Execution)?;
    let db = SparseDb::from_witness(boundary, &witness).map_err(|_| Error::Execution)?;
    let head = witness
        .recent_headers
        .last()
        .ok_or(Error::Execution)?
        .clone();
    let engine = Executor::from_state(db, boundary.anchor, head).map_err(|_| Error::Execution)?;
    execute_interval(
        domain,
        allocation_commitment,
        engine,
        interval_batches,
        next_batch,
    )
}

fn execute_interval(
    domain: Domain,
    allocation_commitment: Hash32,
    mut engine: Executor<SparseDb>,
    interval_batches: u64,
    mut next_batch: impl FnMut() -> Vec<u8>,
) -> Result<SparseJournal, Error> {
    if interval_batches == 0
        || engine
            .anchor()
            .next_batch_number
            .checked_add(interval_batches)
            .is_none()
    {
        return Err(Error::Range);
    }
    let before = *engine.anchor();
    let previous_state_root = engine.state_root().0;
    let previous_header_hash = engine.head_hash().0;
    let mut digest = batch::hash(
        b"tactus/o1/proof-interval/v1",
        &interval_batches.to_le_bytes(),
    );
    for _ in 0..interval_batches {
        let bytes = next_batch();
        engine.apply_batch(&bytes).map_err(|_| Error::Execution)?;
        let mut entry = digest.to_vec();
        entry.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
        entry.extend_from_slice(&bytes);
        digest = batch::hash(b"tactus/o1/proof-interval-step/v1", &entry);
    }
    let journal = SparseJournal {
        transition: Journal {
            domain,
            allocation_commitment,
            before,
            after: *engine.anchor(),
            previous_state_root,
            previous_header_hash,
            next_state_root: engine.state_root().0,
            next_header_hash: engine.head_hash().0,
            interval_digest: digest,
        },
    };
    SparseJournal::decode(&journal.encode())?;
    Ok(journal)
}
