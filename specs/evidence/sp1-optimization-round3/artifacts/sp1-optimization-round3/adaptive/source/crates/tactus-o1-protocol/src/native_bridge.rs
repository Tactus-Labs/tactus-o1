//! Native custody transcript shared by execution and future publication checks.
//! Arithmetic/hash validity alone does not authenticate a funded CKB receipt.
use crate::batch::{self, AnchorState, BatchInput};
use alloc::vec::Vec;

pub const CONFIG_BYTES: usize = 164;
pub const RECORD_BYTES: usize = 124;
pub const CURSOR_BYTES: usize = 56;
pub const ANCHOR_BYTES: usize = batch::ANCHOR_LEN + CURSOR_BYTES;
pub const MAX_DEPOSITS: usize = 32;
pub const MAX_BYTES: usize = batch::MAX_BATCH_BYTES;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Encoding,
    Domain,
    Limit,
    Succession,
    Arithmetic,
    Batch(batch::Error),
}
impl From<batch::Error> for Error {
    fn from(e: batch::Error) -> Self {
        Self::Batch(e)
    }
}
fn n(b: &[u8]) -> u64 {
    u64::from_le_bytes(b.try_into().unwrap())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Config {
    pub identity: [u8; 32],
    pub ckb_genesis: [u8; 32],
    pub rollup: [u8; 32],
    pub chain: u64,
    pub contract: [u8; 20],
    pub settlement: [u8; 32],
}
impl Config {
    pub fn decode(b: &[u8]) -> Result<Self, Error> {
        if b.len() != CONFIG_BYTES || &b[..8] != b"TO1VAU01" {
            return Err(Error::Encoding);
        }
        let c = Self {
            identity: b[8..40].try_into().unwrap(),
            ckb_genesis: b[40..72].try_into().unwrap(),
            rollup: b[72..104].try_into().unwrap(),
            chain: n(&b[104..112]),
            contract: b[112..132].try_into().unwrap(),
            settlement: b[132..164].try_into().unwrap(),
        };
        if [c.identity, c.ckb_genesis, c.rollup, c.settlement].contains(&[0; 32])
            || c.chain == 0
            || c.contract == [0; 20]
        {
            return Err(Error::Domain);
        }
        Ok(c)
    }
    pub fn encode(&self) -> [u8; CONFIG_BYTES] {
        let mut b = [0; CONFIG_BYTES];
        b[..8].copy_from_slice(b"TO1VAU01");
        b[8..40].copy_from_slice(&self.identity);
        b[40..72].copy_from_slice(&self.ckb_genesis);
        b[72..104].copy_from_slice(&self.rollup);
        b[104..112].copy_from_slice(&self.chain.to_le_bytes());
        b[112..132].copy_from_slice(&self.contract);
        b[132..].copy_from_slice(&self.settlement);
        b
    }
    pub fn deposit_id(&self, sequence: u64) -> [u8; 32] {
        batch::hash(
            b"tactus/o1/deposit/id/v1",
            &[self.encode().as_slice(), &sequence.to_le_bytes()].concat(),
        )
    }
    /// Molecule Script with Data1 code identity and the exact immutable config.
    pub fn vault_script(&self, code_hash: [u8; 32]) -> Vec<u8> {
        let mut b = Vec::with_capacity(217);
        for word in [217u32, 16, 48, 49] {
            b.extend_from_slice(&word.to_le_bytes());
        }
        b.extend_from_slice(&code_hash);
        b.push(2);
        b.extend_from_slice(&(CONFIG_BYTES as u32).to_le_bytes());
        b.extend_from_slice(&self.encode());
        b
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cursor {
    pub count: u64,
    pub cumulative: u128,
    pub accumulator: [u8; 32],
}
impl Cursor {
    pub fn genesis(c: &Config) -> Self {
        Self {
            count: 0,
            cumulative: 0,
            accumulator: batch::hash(b"tactus/o1/deposits/empty/v1", &c.encode()),
        }
    }
    pub fn encode(&self) -> [u8; CURSOR_BYTES] {
        let mut b = [0; CURSOR_BYTES];
        b[..8].copy_from_slice(&self.count.to_le_bytes());
        b[8..24].copy_from_slice(&self.cumulative.to_le_bytes());
        b[24..].copy_from_slice(&self.accumulator);
        b
    }
    pub fn decode(b: &[u8]) -> Result<Self, Error> {
        if b.len() != CURSOR_BYTES {
            return Err(Error::Encoding);
        }
        Ok(Self {
            count: n(&b[..8]),
            cumulative: u128::from_le_bytes(b[8..24].try_into().unwrap()),
            accumulator: b[24..].try_into().unwrap(),
        })
    }
    pub fn append(&self, c: &Config, r: &Record) -> Result<Self, Error> {
        if r.recipient == [0; 20] || r.recipient == c.contract || r.amount == 0 {
            return Err(Error::Domain);
        }
        let count = self.count.checked_add(1).ok_or(Error::Arithmetic)?;
        let cumulative = self
            .cumulative
            .checked_add(u128::from(r.amount))
            .ok_or(Error::Arithmetic)?;
        let accumulator = batch::hash(
            b"tactus/o1/deposits/append/v1",
            &[
                c.encode().as_slice(),
                &r.encode()[..76],
                &cumulative.to_le_bytes(),
            ]
            .concat(),
        );
        if r.sequence != count
            || r.cumulative != cumulative
            || r.before != self.accumulator
            || r.after != accumulator
        {
            return Err(Error::Succession);
        }
        Ok(Self {
            count,
            cumulative,
            accumulator,
        })
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    pub sequence: u64,
    pub recipient: [u8; 20],
    pub amount: u64,
    pub before: [u8; 32],
    pub after: [u8; 32],
    pub cumulative: u128,
}
impl Record {
    pub fn decode(b: &[u8]) -> Result<Self, Error> {
        if b.len() != RECORD_BYTES || &b[..8] != b"TO1DPR01" {
            return Err(Error::Encoding);
        }
        Ok(Self {
            sequence: n(&b[8..16]),
            recipient: b[16..36].try_into().unwrap(),
            amount: n(&b[36..44]),
            before: b[44..76].try_into().unwrap(),
            after: b[76..108].try_into().unwrap(),
            cumulative: u128::from_le_bytes(b[108..124].try_into().unwrap()),
        })
    }
    pub fn encode(&self) -> [u8; RECORD_BYTES] {
        let mut b = [0; RECORD_BYTES];
        b[..8].copy_from_slice(b"TO1DPR01");
        b[8..16].copy_from_slice(&self.sequence.to_le_bytes());
        b[16..36].copy_from_slice(&self.recipient);
        b[36..44].copy_from_slice(&self.amount.to_le_bytes());
        b[44..76].copy_from_slice(&self.before);
        b[76..108].copy_from_slice(&self.after);
        b[108..].copy_from_slice(&self.cumulative.to_le_bytes());
        b
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Anchor {
    pub ordering: AnchorState,
    pub deposits: Cursor,
}
impl Anchor {
    pub fn encode(&self) -> [u8; ANCHOR_BYTES] {
        let mut b = [0; ANCHOR_BYTES];
        b[..200].copy_from_slice(&self.ordering.encode());
        b[200..].copy_from_slice(&self.deposits.encode());
        b
    }
    pub fn decode(b: &[u8]) -> Result<Self, Error> {
        if b.len() != ANCHOR_BYTES {
            return Err(Error::Encoding);
        }
        Ok(Self {
            ordering: AnchorState::decode(&b[..200])?,
            deposits: Cursor::decode(&b[200..])?,
        })
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Batch {
    pub deposits: Vec<Record>,
    pub users: BatchInput,
}
impl Batch {
    pub fn encode(&self, c: &Config, parent: &Anchor) -> Result<Vec<u8>, Error> {
        if self.deposits.len() > MAX_DEPOSITS || self.users.parent != parent.ordering {
            return Err(Error::Limit);
        }
        let users = self.users.encode()?;
        let mut b = b"TO1BRG02".to_vec();
        b.extend_from_slice(&parent.deposits.encode());
        b.extend_from_slice(&(self.deposits.len() as u16).to_le_bytes());
        for r in &self.deposits {
            b.extend_from_slice(&r.encode());
        }
        b.extend_from_slice(&(users.len() as u32).to_le_bytes());
        b.extend_from_slice(&users);
        Self::decode(&b, c, parent)?;
        Ok(b)
    }
    /// Validates the transcript. Publication must additionally authenticate every
    /// record against its live immutable CKB receipt and trusted vault script.
    pub fn decode(b: &[u8], c: &Config, parent: &Anchor) -> Result<(Self, Anchor), Error> {
        if b.len() > MAX_BYTES {
            return Err(Error::Limit);
        }
        if b.len() < 70 || &b[..8] != b"TO1BRG02" {
            return Err(Error::Encoding);
        }
        Config::decode(&c.encode())?;
        if parent.ordering.rollup_id != c.rollup || parent.ordering.chain_id != c.chain {
            return Err(Error::Domain);
        }
        if Cursor::decode(&b[8..64])? != parent.deposits {
            return Err(Error::Succession);
        }
        let count = u16::from_le_bytes(b[64..66].try_into().unwrap()) as usize;
        if count > MAX_DEPOSITS {
            return Err(Error::Limit);
        }
        let end = 66 + count * RECORD_BYTES;
        if b.len() < end + 4 {
            return Err(Error::Encoding);
        }
        let size = u32::from_le_bytes(b[end..end + 4].try_into().unwrap()) as usize;
        if b.len() - end - 4 != size {
            return Err(Error::Encoding);
        }
        let mut cursor = parent.deposits;
        let mut deposits = Vec::with_capacity(count);
        for bytes in b[66..end].chunks_exact(RECORD_BYTES) {
            let record = Record::decode(bytes)?;
            cursor = cursor.append(c, &record)?;
            deposits.push(record);
        }
        let users = BatchInput::decode(&b[end + 4..], &parent.ordering)?;
        let mut ordering = batch::validate_batch(&b[end + 4..], &parent.ordering)?.next;
        ordering.last_batch_commitment = batch::hash(b"tactus/o1/native-batch/v2", b);
        Ok((
            Self { deposits, users },
            Anchor {
                ordering,
                deposits: cursor,
            },
        ))
    }
}
