//! Separate proof profile for genesis bootstrap or a bounded continuation from
//! authenticated state. Existing replay-profile verifiers deliberately reject it.
use super::{batch, Domain, Error, Hash32, Journal, JOURNAL_LEN};
use tactus_o1_execution::checkpoint::{Boundary, Checkpoint};

const MAGIC: &[u8; 8] = b"TO1CPF01";

pub fn profile_id() -> Hash32 {
    batch::hash(b"tactus/o1/checkpoint-proof-profile/v1", b"TO1CPF01;genesis-allocation-or-authenticated-nonzero-boundary;complete-state-checkpoint-8MiB;linked-256-header-window;nonempty-contiguous-interval;no-withdrawal-authorization")
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CheckpointJournal {
    pub transition: Journal,
}

impl CheckpointJournal {
    pub fn encode(&self) -> [u8; JOURNAL_LEN] {
        let mut bytes = self.transition.encode();
        bytes[..8].copy_from_slice(MAGIC);
        bytes[8..40].copy_from_slice(&profile_id());
        bytes
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != JOURNAL_LEN || &bytes[..8] != MAGIC || bytes[8..40] != profile_id() {
            return Err(Error::Encoding);
        }
        // Reuse the established domain, execution-rules and range validation.
        // Only the exact distinct checkpoint identifier is translated here.
        let mut replay_encoding = [0u8; JOURNAL_LEN];
        replay_encoding.copy_from_slice(bytes);
        replay_encoding[..8].copy_from_slice(super::MAGIC);
        replay_encoding[8..40].copy_from_slice(&super::profile_id());
        Ok(Self {
            transition: Journal::decode(&replay_encoding)?,
        })
    }

    /// Continuity check only. A caller still has to verify both the proof/key
    /// and canonical publication; an unverified predecessor is not authority.
    pub fn follows(&self, previous: &Self) -> Result<(), Error> {
        let current = Self::decode(&self.encode())?.transition;
        let prior = Self::decode(&previous.encode())?.transition;
        if current.domain != prior.domain
            || current.allocation_commitment != prior.allocation_commitment
            || current.before != prior.after
            || current.previous_state_root != prior.next_state_root
            || current.previous_header_hash != prior.next_header_hash
        {
            return Err(Error::Domain);
        }
        Ok(())
    }
}

pub fn execute_genesis(
    domain: Domain,
    allocation: &[u8],
    interval_batches: u64,
    next_batch: impl FnMut() -> Vec<u8>,
) -> Result<CheckpointJournal, Error> {
    let transition = super::execute(domain, allocation, 0, interval_batches, next_batch)?;
    Ok(CheckpointJournal { transition })
}

/// The boundary becomes public in the journal and MUST match the consumed
/// settlement tip. Merely producing this proof does not authenticate that tip.
pub fn execute_continuation(
    domain: Domain,
    allocation_commitment: Hash32,
    boundary: &Boundary,
    checkpoint_bytes: &[u8],
    interval_batches: u64,
    mut next_batch: impl FnMut() -> Vec<u8>,
) -> Result<CheckpointJournal, Error> {
    domain.validate()?;
    if interval_batches == 0
        || boundary
            .anchor
            .next_batch_number
            .checked_add(interval_batches)
            .is_none()
    {
        return Err(Error::Range);
    }
    if allocation_commitment == [0; 32] {
        return Err(Error::Allocation);
    }
    let snapshot = Checkpoint::decode(checkpoint_bytes).map_err(|_| Error::Execution)?;
    let mut engine = snapshot
        .restore(domain.rollup_id.into(), domain.chain_id, boundary)
        .map_err(|_| Error::Execution)?;
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
    let journal = CheckpointJournal {
        transition: Journal {
            domain,
            allocation_commitment,
            before: boundary.anchor,
            after: *engine.anchor(),
            previous_state_root: boundary.state_root.0,
            next_state_root: engine.state_root().0,
            previous_header_hash: boundary.header_hash.0,
            next_header_hash: engine.head_hash().0,
            interval_digest,
        },
    };
    CheckpointJournal::decode(&journal.encode())?;
    Ok(journal)
}
