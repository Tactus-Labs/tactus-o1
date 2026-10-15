//! Canonical, bounded genesis allocation publication (TO1GEN01).
//! Allocation bytes exclude deployment identity, avoiding a Type-ID cycle.
use crate::{batch::hash, Hash32};
use alloc::vec::Vec;
pub const MAX_BYTES: usize = 262_144;
pub const MAX_ACCOUNTS: usize = 1_024;
pub const MAX_CODE_BYTES: usize = 24_576;
pub const MAX_STORAGE_SLOTS: usize = 4_096;
const MAGIC: &[u8; 8] = b"TO1GEN01";
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Encoding,
    Limit,
    Order,
    EmptyAccount,
    ZeroStorage,
    Supply,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Account {
    pub address: [u8; 20],
    pub balance: [u8; 32],
    pub nonce: u64,
    pub code: Vec<u8>,
    pub storage: Vec<(Hash32, Hash32)>,
}
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Allocation {
    pub accounts: Vec<Account>,
}
struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}
impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        let end = self.offset.checked_add(n).ok_or(Error::Encoding)?;
        let bytes = self.bytes.get(self.offset..end).ok_or(Error::Encoding)?;
        self.offset = end;
        Ok(bytes)
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        self.take(N)?.try_into().map_err(|_| Error::Encoding)
    }
    fn u32(&mut self) -> Result<usize, Error> {
        Ok(u32::from_le_bytes(self.array()?) as usize)
    }
    fn u64(&mut self) -> Result<u64, Error> {
        Ok(u64::from_le_bytes(self.array()?))
    }
}
/// Streaming verification; no allocation proportional to attacker-supplied counts.
pub fn validate(bytes: &[u8]) -> Result<(), Error> {
    if bytes.len() > MAX_BYTES {
        return Err(Error::Limit);
    }
    let mut r = Reader { bytes, offset: 0 };
    if r.take(8)? != MAGIC {
        return Err(Error::Encoding);
    }
    let count = r.u32()?;
    if count > MAX_ACCOUNTS {
        return Err(Error::Limit);
    }
    let mut last = None;
    let mut supply = 0u64;
    for _ in 0..count {
        let address = r.array::<20>()?;
        if last.is_some_and(|p| p >= address) {
            return Err(Error::Order);
        }
        last = Some(address);
        let balance = r.array::<32>()?;
        // Execution-v1's explicit experimental supply ceiling. Removing it
        // requires a new execution profile, not a silent allocation reinterpretation.
        if balance[..24] != [0; 24] {
            return Err(Error::Supply);
        }
        let value = u64::from_be_bytes(balance[24..].try_into().unwrap());
        supply = supply.checked_add(value).ok_or(Error::Supply)?;
        let nonce = r.u64()?;
        let code_len = r.u32()?;
        if code_len > MAX_CODE_BYTES {
            return Err(Error::Limit);
        }
        r.take(code_len)?;
        if value == 0 && nonce == 0 && code_len == 0 {
            return Err(Error::EmptyAccount);
        }
        let slots = r.u32()?;
        if slots > MAX_STORAGE_SLOTS {
            return Err(Error::Limit);
        }
        let mut prior = None;
        for _ in 0..slots {
            let key = r.array::<32>()?;
            let value = r.array::<32>()?;
            if prior.is_some_and(|p| p >= key) {
                return Err(Error::Order);
            }
            prior = Some(key);
            if value == [0; 32] {
                return Err(Error::ZeroStorage);
            }
        }
    }
    if r.offset != bytes.len() {
        return Err(Error::Encoding);
    }
    Ok(())
}
pub fn commitment(bytes: &[u8]) -> Result<Hash32, Error> {
    validate(bytes)?;
    Ok(hash(b"tactus/o1/genesis-allocation/v1", bytes))
}
impl Allocation {
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        if self.accounts.len() > MAX_ACCOUNTS {
            return Err(Error::Limit);
        }
        let mut b = MAGIC.to_vec();
        b.extend_from_slice(&(self.accounts.len() as u32).to_le_bytes());
        for a in &self.accounts {
            if a.code.len() > MAX_CODE_BYTES || a.storage.len() > MAX_STORAGE_SLOTS {
                return Err(Error::Limit);
            }
            let size = 20 + 32 + 8 + 4 + a.code.len() + 4 + 64 * a.storage.len();
            if b.len() + size > MAX_BYTES {
                return Err(Error::Limit);
            }
            b.extend_from_slice(&a.address);
            b.extend_from_slice(&a.balance);
            b.extend_from_slice(&a.nonce.to_le_bytes());
            b.extend_from_slice(&(a.code.len() as u32).to_le_bytes());
            b.extend_from_slice(&a.code);
            b.extend_from_slice(&(a.storage.len() as u32).to_le_bytes());
            for (k, v) in &a.storage {
                b.extend_from_slice(k);
                b.extend_from_slice(v);
            }
        }
        validate(&b)?;
        Ok(b)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        validate(bytes)?;
        let mut r = Reader { bytes, offset: 8 };
        let count = r.u32()?;
        let mut accounts = Vec::with_capacity(count);
        for _ in 0..count {
            let address = r.array()?;
            let balance = r.array()?;
            let nonce = r.u64()?;
            let len = r.u32()?;
            let code = r.take(len)?.to_vec();
            let count = r.u32()?;
            let mut storage = Vec::with_capacity(count);
            for _ in 0..count {
                storage.push((r.array()?, r.array()?));
            }
            accounts.push(Account {
                address,
                balance,
                nonce,
                code,
                storage,
            });
        }
        Ok(Self { accounts })
    }
}
