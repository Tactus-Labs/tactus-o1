//! Complete 0.02 EVM replay statement. No supplied state root is trusted.
//! CKB independently authenticates the same publication boundaries and verifies
//! the actual proof; executing this library or the guest does not settle assets.
use tactus_o1_execution::{
    v02::{ExecutedBatch, V02Error, V02Executor},
    Genesis,
};
use tactus_o1_protocol::{
    genesis,
    v02::{hash, Config, Journal, NativeBatch, Policy, Reader, Snapshot, Wire},
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    Wire(tactus_o1_protocol::v02::Error),
    Allocation,
    Range,
    MissingInput,
    Execution(V02Error),
}
impl From<tactus_o1_protocol::v02::Error> for Error {
    fn from(value: tactus_o1_protocol::v02::Error) -> Self {
        Self::Wire(value)
    }
}
impl From<V02Error> for Error {
    fn from(value: V02Error) -> Self {
        Self::Execution(value)
    }
}

/// Canonical private input frame: complete snapshot followed by exact batch.
/// Snapshot hashes are already bound by the batch/publication input chain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Frame {
    pub snapshot: Snapshot,
    pub batch: NativeBatch,
}
impl Wire for Frame {
    const MAGIC: [u8; 8] = *b"T02FRM01";
    const MAX_BYTES: usize = 16 + Snapshot::MAX_BYTES + NativeBatch::MAX_BYTES;
    fn validate(&self) -> tactus_o1_protocol::v02::Result<()> {
        self.snapshot.validate()?;
        self.batch.validate()?;
        if self.snapshot.commitment()? != self.batch.snapshot {
            return Err(tactus_o1_protocol::v02::Error::Identity);
        }
        Ok(())
    }
    fn write_fields(&self, out: &mut Vec<u8>) {
        // Wire::encode validates both values before this infallible step.
        for bytes in [
            self.snapshot.encode().expect("validated snapshot"),
            self.batch.encode().expect("validated batch"),
        ] {
            out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
            out.extend_from_slice(&bytes);
        }
    }
    fn read_fields(r: &mut Reader<'_>) -> tactus_o1_protocol::v02::Result<Self> {
        Ok(Self {
            snapshot: Snapshot::decode(r.blob(Snapshot::MAX_BYTES)?)?,
            batch: NativeBatch::decode(r.blob(NativeBatch::MAX_BYTES)?)?,
        })
    }
}

fn outcomes(previous: [u8; 32], result: &ExecutedBatch) -> [u8; 32] {
    let mut bytes = previous.to_vec();
    bytes.extend_from_slice(&(result.deposits.len() as u32).to_le_bytes());
    for credit in &result.deposits {
        bytes.extend_from_slice(&credit.record.commitment().expect("executed receipt"));
        bytes.extend_from_slice(&credit.gas_used.to_le_bytes());
        bytes.extend_from_slice(&(credit.logs.len() as u32).to_le_bytes());
        for log in &credit.logs {
            bytes.extend_from_slice(log.address.as_slice());
            bytes.extend_from_slice(&(log.topics().len() as u32).to_le_bytes());
            for topic in log.topics() {
                bytes.extend_from_slice(topic.as_slice());
            }
            bytes.extend_from_slice(&(log.data.data.len() as u32).to_le_bytes());
            bytes.extend_from_slice(&log.data.data);
        }
    }
    bytes.extend_from_slice(&(result.blocks.len() as u32).to_le_bytes());
    for block in &result.blocks {
        // The header extra_data binds every accepted/rejected input outcome,
        // including the exact fixed rejection status, and the next boundary.
        bytes.extend_from_slice(&block.header.number.to_le_bytes());
        bytes.extend_from_slice(block.hash.as_slice());
    }
    hash(b"tactus/0.02/proof-outcomes-step", &bytes)
}

/// Reconstruct from immutable allocation through the entire canonical prefix.
/// Each callback must return exactly one bounded frame; errors are fatal and
/// cannot be classified as a valid user-transaction rejection.
pub fn execute(
    config: Config,
    policy: Policy,
    allocation: &[u8],
    prefix: u64,
    interval: u64,
    mut next_frame: impl FnMut() -> Result<Vec<u8>, Error>,
) -> Result<Journal, Error> {
    config.bind(&policy)?;
    if interval == 0
        || interval > policy.max_pending_batches
        || prefix.checked_add(interval).is_none()
    {
        return Err(Error::Range);
    }
    if genesis::commitment(allocation).map_err(|_| Error::Allocation)? != config.allocation {
        return Err(Error::Allocation);
    }
    let initial = Genesis::from_allocation(config.domain.into(), config.chain, allocation)
        .map_err(|_| Error::Allocation)?;
    let mut engine = V02Executor::new(&initial, config, policy)?;
    for _ in 0..prefix {
        let frame = Frame::decode(&next_frame()?)?;
        engine.apply_batch(&frame.batch.encode()?, &frame.snapshot)?;
    }
    let start = engine.control_candidate()?;
    let mut interval_inputs = hash(b"tactus/0.02/proof-inputs", &interval.to_le_bytes());
    let mut outcome_digest = hash(b"tactus/0.02/proof-outcomes", &interval.to_le_bytes());
    for _ in 0..interval {
        let raw = next_frame()?;
        let frame = Frame::decode(&raw)?;
        let result = engine.apply_batch(&frame.batch.encode()?, &frame.snapshot)?;
        let mut input = interval_inputs.to_vec();
        input.extend_from_slice(&(raw.len() as u64).to_le_bytes());
        input.extend_from_slice(&raw);
        interval_inputs = hash(b"tactus/0.02/proof-inputs-step", &input);
        outcome_digest = outcomes(outcome_digest, &result);
    }
    let journal = Journal {
        start,
        end: engine.control_candidate()?,
        outcomes: outcome_digest,
        interval_inputs,
    };
    journal.validate()?;
    Ok(journal)
}
