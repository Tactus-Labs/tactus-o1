//! Exact little-endian codecs. No attacker-controlled allocation before bounds.
use super::{Error, Result};
use alloc::vec::Vec;

/// Bounded sequential decoder with explicit exact-consumption checks.
pub struct Reader<'a> {
    bytes: &'a [u8],
    position: usize,
}
impl<'a> Reader<'a> {
    pub fn new(bytes: &'a [u8], maximum: usize) -> Result<Self> {
        if bytes.len() > maximum {
            return Err(Error::Limit);
        }
        Ok(Self { bytes, position: 0 })
    }
    pub fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self.position.checked_add(n).ok_or(Error::Encoding)?;
        let value = self.bytes.get(self.position..end).ok_or(Error::Encoding)?;
        self.position = end;
        Ok(value)
    }
    pub fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        self.take(N)?.try_into().map_err(|_| Error::Encoding)
    }
    pub fn u8(&mut self) -> Result<u8> {
        Ok(self.array::<1>()?[0])
    }
    pub fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.array()?))
    }
    pub fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(self.array()?))
    }
    pub fn u128(&mut self) -> Result<u128> {
        Ok(u128::from_le_bytes(self.array()?))
    }
    pub fn lanes(&mut self) -> Result<[u64; 4]> {
        Ok([self.u64()?, self.u64()?, self.u64()?, self.u64()?])
    }
    pub fn blob(&mut self, maximum: usize) -> Result<&'a [u8]> {
        let size = usize::try_from(self.u32()?).map_err(|_| Error::Limit)?;
        if size > maximum {
            return Err(Error::Limit);
        }
        self.take(size)
    }
    pub fn finish(self) -> Result<()> {
        if self.position != self.bytes.len() {
            Err(Error::Encoding)
        } else {
            Ok(())
        }
    }
}

/// Versioned canonical objects. Encoders also validate caller-constructed values.
pub trait Wire: Sized {
    const MAGIC: [u8; 8];
    const MAX_BYTES: usize;
    fn validate(&self) -> Result<()>;
    fn write_fields(&self, out: &mut Vec<u8>);
    fn read_fields(r: &mut Reader<'_>) -> Result<Self>;
    fn encode(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut out = Vec::new();
        out.extend_from_slice(&Self::MAGIC);
        self.write_fields(&mut out);
        if out.len() > Self::MAX_BYTES {
            return Err(Error::Limit);
        }
        Ok(out)
    }
    fn decode(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes, Self::MAX_BYTES)?;
        if r.array::<8>()? != Self::MAGIC {
            return Err(Error::Encoding);
        }
        let result = Self::read_fields(&mut r)?;
        r.finish()?;
        result.validate()?;
        Ok(result)
    }
    /// Hash exact validated canonical bytes, including version tag.
    fn commitment(&self) -> Result<[u8; 32]> {
        Ok(super::hash(b"tactus/0.02/object", &self.encode()?))
    }
}

pub(crate) fn put_lanes(out: &mut Vec<u8>, values: &[u64; 4]) {
    for value in values {
        out.extend_from_slice(&value.to_le_bytes());
    }
}
