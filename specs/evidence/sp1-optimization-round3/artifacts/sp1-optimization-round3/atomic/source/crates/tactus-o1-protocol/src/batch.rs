//! Canonical input envelope; normative layout: specs/BATCH_INPUT_V1.md.
//! It authenticates bytes and boundaries, never claims that opaque bytes have
//! executed or that a validity proof exists.
use crate::Hash32;
use alloc::vec::Vec;

pub const ANCHOR_LEN: usize = 200;
pub const MAX_BATCH_BYTES: usize = 262_144;
pub const MAX_BLOCKS: usize = 16;
pub const MAX_TRANSACTIONS: usize = 1_024;
pub const MAX_BLOCK_TRANSACTIONS: usize = 256;
pub const MAX_TRANSACTION_BYTES: usize = 16_384;
pub const BLOCK_GAS_LIMIT: u64 = 1_000_000;
const BATCH_MAGIC: &[u8; 8] = b"TO1BAT01";
const ANCHOR_MAGIC: &[u8; 8] = b"TO1ANC01";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Encoding,
    Limit,
    Domain,
    Succession,
    Timestamp,
    Overflow,
    Genesis,
}

/// Domain-separated CKB-personalized digest, without allocating the preimage.
pub fn hash(domain: &[u8], bytes: &[u8]) -> Hash32 {
    let mut digest = [0; 32];
    let mut hasher = blake2b_ref::Blake2bBuilder::new(32)
        .personal(b"ckb-default-hash")
        .build();
    hasher.update(domain);
    hasher.update(bytes);
    hasher.finalize(&mut digest);
    digest
}

pub fn da_policy_id() -> Hash32 {
    hash(b"tactus/o1/da-policy/v1", b"inline-immutable-cell")
}

/// Commits the exact executable ceilings, including the fixed block gas limit.
pub fn limits_hash() -> Hash32 {
    let values = [
        MAX_BATCH_BYTES as u64,
        MAX_BLOCKS as u64,
        MAX_TRANSACTIONS as u64,
        MAX_BLOCK_TRANSACTIONS as u64,
        MAX_TRANSACTION_BYTES as u64,
        BLOCK_GAS_LIMIT,
    ];
    let mut bytes = [0; 48];
    for (index, value) in values.iter().enumerate() {
        bytes[index * 8..index * 8 + 8].copy_from_slice(&value.to_le_bytes());
    }
    hash(b"tactus/o1/admission-limits/v1", &bytes)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AnchorState {
    pub rollup_id: Hash32,
    pub next_batch_number: u64,
    pub last_batch_commitment: Hash32,
    pub last_block_number: u64,
    pub last_timestamp: u64,
    pub execution_rules_hash: Hash32,
    pub da_policy_id: Hash32,
    pub limits_hash: Hash32,
    pub chain_id: u64,
}

impl AnchorState {
    pub fn genesis(
        rollup_id: Hash32,
        execution_rules_hash: Hash32,
        chain_id: u64,
    ) -> Result<Self, Error> {
        let state = Self {
            rollup_id,
            next_batch_number: 0,
            last_batch_commitment: [0; 32],
            last_block_number: 0,
            last_timestamp: 0,
            execution_rules_hash,
            da_policy_id: da_policy_id(),
            limits_hash: limits_hash(),
            chain_id,
        };
        state.validate_genesis()?;
        Ok(state)
    }

    fn validate_domain(&self) -> Result<(), Error> {
        if self.chain_id == 0
            || self.execution_rules_hash == [0; 32]
            || self.da_policy_id != da_policy_id()
            || self.limits_hash != limits_hash()
        {
            return Err(Error::Domain);
        }
        Ok(())
    }

    pub fn validate_genesis(&self) -> Result<(), Error> {
        self.validate_domain()?;
        if self.next_batch_number != 0
            || self.last_batch_commitment != [0; 32]
            || self.last_block_number != 0
            || self.last_timestamp != 0
        {
            return Err(Error::Genesis);
        }
        Ok(())
    }

    pub fn encode(&self) -> [u8; ANCHOR_LEN] {
        let mut result = [0; ANCHOR_LEN];
        result[..8].copy_from_slice(ANCHOR_MAGIC);
        result[8..40].copy_from_slice(&self.rollup_id);
        result[40..48].copy_from_slice(&self.next_batch_number.to_le_bytes());
        result[48..80].copy_from_slice(&self.last_batch_commitment);
        result[80..88].copy_from_slice(&self.last_block_number.to_le_bytes());
        result[88..96].copy_from_slice(&self.last_timestamp.to_le_bytes());
        result[96..128].copy_from_slice(&self.execution_rules_hash);
        result[128..160].copy_from_slice(&self.da_policy_id);
        result[160..192].copy_from_slice(&self.limits_hash);
        result[192..200].copy_from_slice(&self.chain_id.to_le_bytes());
        result
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let mut reader = Reader::new(bytes);
        if reader.take(8)? != ANCHOR_MAGIC {
            return Err(Error::Encoding);
        }
        let state = Self {
            rollup_id: reader.array()?,
            next_batch_number: reader.u64()?,
            last_batch_commitment: reader.array()?,
            last_block_number: reader.u64()?,
            last_timestamp: reader.u64()?,
            execution_rules_hash: reader.array()?,
            da_policy_id: reader.array()?,
            limits_hash: reader.array()?,
            chain_id: reader.u64()?,
        };
        reader.finish()?;
        state.validate_domain()?;
        Ok(state)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockInput {
    pub timestamp: u64,
    pub fee_recipient: [u8; 20],
    pub transactions: Vec<Vec<u8>>,
}

/// An owned builder representation. The same streaming validator validates its
/// encoded result and CKB output bytes, keeping the wire contract authoritative.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BatchInput {
    pub parent: AnchorState,
    pub blocks: Vec<BlockInput>,
}

/// Fully validated view. Raw transactions borrow the immutable envelope;
/// allocations contain only bounded block metadata and slice references.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BatchView<'a> {
    pub blocks: Vec<BlockView<'a>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockView<'a> {
    pub timestamp: u64,
    pub fee_recipient: [u8; 20],
    pub transactions: Vec<&'a [u8]>,
}

impl<'a> BatchView<'a> {
    pub fn decode_with_summary(
        bytes: &'a [u8],
        parent: &AnchorState,
    ) -> Result<(Self, BatchSummary), Error> {
        let mut blocks: Vec<BlockView<'a>> = Vec::new();
        // The collector is private: nothing is returned or executed until the
        // complete envelope, including its suffix and successor, is valid.
        let summary = scan_events(bytes, parent, |event| match event {
            ScanEvent::Block {
                timestamp,
                recipient,
                count,
            } => blocks.push(BlockView {
                timestamp,
                fee_recipient: recipient,
                transactions: Vec::with_capacity(usize::from(count)),
            }),
            ScanEvent::Transaction { bytes, .. } => {
                blocks
                    .last_mut()
                    .expect("validated block header")
                    .transactions
                    .push(bytes);
            }
        })?;
        Ok((Self { blocks }, summary))
    }
}

impl BatchInput {
    /// Decode only after validating the entire envelope. Unlike the transaction
    /// visitor, this preserves empty blocks, which still advance execution time,
    /// block hashes and the base-fee schedule.
    pub fn decode(bytes: &[u8], parent: &AnchorState) -> Result<Self, Error> {
        Self::decode_with_summary(bytes, parent).map(|(input, _)| input)
    }

    /// Decode and return the summary from the same complete validation. This
    /// avoids callers hashing and validating the envelope a second time.
    /// No partially validated input escapes if any suffix or boundary is invalid.
    pub fn decode_with_summary(
        bytes: &[u8],
        parent: &AnchorState,
    ) -> Result<(Self, BatchSummary), Error> {
        let (view, summary) = BatchView::decode_with_summary(bytes, parent)?;
        let blocks = view
            .blocks
            .into_iter()
            .map(|block| BlockInput {
                timestamp: block.timestamp,
                fee_recipient: block.fee_recipient,
                transactions: block.transactions.into_iter().map(<[u8]>::to_vec).collect(),
            })
            .collect();
        Ok((
            Self {
                parent: *parent,
                blocks,
            },
            summary,
        ))
    }

    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        if self.blocks.is_empty() || self.blocks.len() > MAX_BLOCKS {
            return Err(Error::Limit);
        }
        let mut bytes = Vec::with_capacity(194);
        bytes.extend_from_slice(BATCH_MAGIC);
        bytes.extend_from_slice(&self.parent.rollup_id);
        bytes.extend_from_slice(&self.parent.chain_id.to_le_bytes());
        bytes.extend_from_slice(&self.parent.next_batch_number.to_le_bytes());
        bytes.extend_from_slice(&self.parent.last_batch_commitment);
        bytes.extend_from_slice(&self.parent.execution_rules_hash);
        bytes.extend_from_slice(&self.parent.da_policy_id);
        bytes.extend_from_slice(&self.parent.limits_hash);
        bytes.extend_from_slice(
            &self
                .parent
                .last_block_number
                .checked_add(1)
                .ok_or(Error::Overflow)?
                .to_le_bytes(),
        );
        bytes.extend_from_slice(&(self.blocks.len() as u16).to_le_bytes());
        for block in &self.blocks {
            if block.transactions.len() > MAX_BLOCK_TRANSACTIONS {
                return Err(Error::Limit);
            }
            bytes.extend_from_slice(&block.timestamp.to_le_bytes());
            bytes.extend_from_slice(&block.fee_recipient);
            bytes.extend_from_slice(&(block.transactions.len() as u16).to_le_bytes());
            for tx in &block.transactions {
                if tx.is_empty() || tx.len() > MAX_TRANSACTION_BYTES {
                    return Err(Error::Limit);
                }
                if bytes
                    .len()
                    .checked_add(4 + tx.len())
                    .ok_or(Error::Overflow)?
                    > MAX_BATCH_BYTES
                {
                    return Err(Error::Limit);
                }
                bytes.extend_from_slice(&(tx.len() as u32).to_le_bytes());
                bytes.extend_from_slice(tx);
            }
        }
        validate_batch(&bytes, &self.parent)?;
        Ok(bytes)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BatchSummary {
    pub next: AnchorState,
    pub blocks: u16,
    pub transactions: u32,
    pub bytes: u32,
    pub gas_ceiling: u64,
}

/// Validate a complete canonical envelope without copying or allocating from
/// attacker-controlled lengths. Every output field is derived from these bytes.
pub fn validate_batch(bytes: &[u8], parent: &AnchorState) -> Result<BatchSummary, Error> {
    scan_batch(bytes, parent, |_, _, _, _, _| {})
}

/// Visits raw inputs in execution order only after the complete envelope has
/// passed validation. A malformed suffix never causes partial visitor effects.
pub fn validate_and_visit(
    bytes: &[u8],
    parent: &AnchorState,
    visitor: impl FnMut(u64, u64, [u8; 20], usize, &[u8]),
) -> Result<BatchSummary, Error> {
    validate_batch(bytes, parent)?;
    scan_batch(bytes, parent, visitor)
}

fn scan_batch(
    bytes: &[u8],
    parent: &AnchorState,
    mut visitor: impl FnMut(u64, u64, [u8; 20], usize, &[u8]),
) -> Result<BatchSummary, Error> {
    scan_events(bytes, parent, |event| {
        if let ScanEvent::Transaction {
            number,
            timestamp,
            recipient,
            index,
            bytes,
        } = event
        {
            visitor(number, timestamp, recipient, index, bytes);
        }
    })
}

enum ScanEvent<'a> {
    Block {
        timestamp: u64,
        recipient: [u8; 20],
        count: u16,
    },
    Transaction {
        number: u64,
        timestamp: u64,
        recipient: [u8; 20],
        index: usize,
        bytes: &'a [u8],
    },
}

fn scan_events<'a>(
    bytes: &'a [u8],
    parent: &AnchorState,
    mut visitor: impl FnMut(ScanEvent<'a>),
) -> Result<BatchSummary, Error> {
    if bytes.len() > MAX_BATCH_BYTES {
        return Err(Error::Limit);
    }
    parent.validate_domain()?;
    let mut r = Reader::new(bytes);
    if r.take(8)? != BATCH_MAGIC {
        return Err(Error::Encoding);
    }
    let rollup_id: Hash32 = r.array()?;
    let chain_id = r.u64()?;
    let batch_number = r.u64()?;
    let prior_commitment: Hash32 = r.array()?;
    let execution_rules_hash: Hash32 = r.array()?;
    let da: Hash32 = r.array()?;
    let limits: Hash32 = r.array()?;
    let first = r.u64()?;
    let block_count = r.u16()?;
    if rollup_id != parent.rollup_id
        || chain_id != parent.chain_id
        || execution_rules_hash != parent.execution_rules_hash
        || da != parent.da_policy_id
        || limits != parent.limits_hash
    {
        return Err(Error::Domain);
    }
    if batch_number != parent.next_batch_number
        || prior_commitment != parent.last_batch_commitment
        || first
            != parent
                .last_block_number
                .checked_add(1)
                .ok_or(Error::Overflow)?
    {
        return Err(Error::Succession);
    }
    if block_count == 0 || usize::from(block_count) > MAX_BLOCKS {
        return Err(Error::Limit);
    }
    let mut timestamp = parent.last_timestamp;
    let mut total = 0u32;
    for index in 0..block_count {
        let next_timestamp = r.u64()?;
        if next_timestamp < timestamp {
            return Err(Error::Timestamp);
        }
        timestamp = next_timestamp;
        let recipient = r.array()?;
        let count = r.u16()?;
        total = total.checked_add(u32::from(count)).ok_or(Error::Overflow)?;
        if usize::from(count) > MAX_BLOCK_TRANSACTIONS || total as usize > MAX_TRANSACTIONS {
            return Err(Error::Limit);
        }
        let number = first.checked_add(u64::from(index)).ok_or(Error::Overflow)?;
        visitor(ScanEvent::Block {
            timestamp,
            recipient,
            count,
        });
        for tx_index in 0..count {
            let length = r.u32()? as usize;
            if length == 0 || length > MAX_TRANSACTION_BYTES {
                return Err(Error::Limit);
            }
            let tx = r.take(length)?;
            visitor(ScanEvent::Transaction {
                number,
                timestamp,
                recipient,
                index: usize::from(tx_index),
                bytes: tx,
            });
        }
    }
    r.finish()?;
    let next = AnchorState {
        next_batch_number: parent
            .next_batch_number
            .checked_add(1)
            .ok_or(Error::Overflow)?,
        last_batch_commitment: hash(b"tactus/o1/batch-input/v1", bytes),
        last_block_number: parent
            .last_block_number
            .checked_add(u64::from(block_count))
            .ok_or(Error::Overflow)?,
        last_timestamp: timestamp,
        ..*parent
    };
    Ok(BatchSummary {
        next,
        blocks: block_count,
        transactions: total,
        bytes: bytes.len() as u32,
        gas_ceiling: u64::from(block_count) * BLOCK_GAS_LIMIT,
    })
}

struct Reader<'a> {
    remaining: &'a [u8],
}
impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { remaining: bytes }
    }
    fn take(&mut self, len: usize) -> Result<&'a [u8], Error> {
        if len > self.remaining.len() {
            return Err(Error::Encoding);
        }
        let (value, rest) = self.remaining.split_at(len);
        self.remaining = rest;
        Ok(value)
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        self.take(N)?.try_into().map_err(|_| Error::Encoding)
    }
    fn u16(&mut self) -> Result<u16, Error> {
        Ok(u16::from_le_bytes(self.array()?))
    }
    fn u32(&mut self) -> Result<u32, Error> {
        Ok(u32::from_le_bytes(self.array()?))
    }
    fn u64(&mut self) -> Result<u64, Error> {
        Ok(u64::from_le_bytes(self.array()?))
    }
    fn finish(self) -> Result<(), Error> {
        if self.remaining.is_empty() {
            Ok(())
        } else {
            Err(Error::Encoding)
        }
    }
}
