//! Full-width sparse nullifiers. Keys are never truncated to u64. A canonical
//! bitmap omits default siblings; verification computes both old and new roots.
use super::{hash, nonzero, ClaimKind, Error, Reader, Result, Wire};
use alloc::vec::Vec;

pub fn claim_key(config: &[u8; 32], kind: ClaimKind, identity: &[u8]) -> Result<[u8; 32]> {
    nonzero(config)?;
    let expected = if kind == ClaimKind::Escape { 20 } else { 8 };
    if identity.len() != expected || identity.iter().all(|byte| *byte == 0) {
        return Err(Error::Identity);
    }
    Ok(hash(
        b"tactus/0.02/claim/key",
        &[config.as_slice(), &[kind as u8], identity].concat(),
    ))
}
fn leaf(config: &[u8; 32], kind: ClaimKind, key: Option<&[u8; 32]>) -> [u8; 32] {
    let mut bytes = config.to_vec();
    bytes.push(kind as u8);
    match key {
        None => bytes.push(0),
        Some(key) => {
            bytes.push(1);
            bytes.extend_from_slice(key);
        }
    }
    hash(b"tactus/0.02/claim/leaf", &bytes)
}
fn branch(level: usize, left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    hash(
        b"tactus/0.02/claim/branch",
        &[&(level as u16).to_le_bytes()[..], left, right].concat(),
    )
}
pub fn empty_claim_root(config: &[u8; 32], kind: ClaimKind) -> Result<[u8; 32]> {
    nonzero(config)?;
    let mut root = leaf(config, kind, None);
    for level in 0..256 {
        root = branch(level, &root, &root);
    }
    Ok(root)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NullifierProof {
    /// Bit i marks a non-default sibling at level i, starting at the leaf.
    pub bitmap: [u8; 32],
    pub siblings: Vec<[u8; 32]>,
}
impl NullifierProof {
    pub fn empty() -> Self {
        Self {
            bitmap: [0; 32],
            siblings: Vec::new(),
        }
    }
    pub fn insert(
        &self,
        config: &[u8; 32],
        kind: ClaimKind,
        key: &[u8; 32],
        previous: &[u8; 32],
    ) -> Result<[u8; 32]> {
        self.validate()?;
        nonzero(config)?;
        nonzero(key)?;
        nonzero(previous)?;
        let mut default = leaf(config, kind, None);
        let mut old = default;
        let mut new = leaf(config, kind, Some(key));
        let mut index = 0;
        for level in 0..256 {
            let sibling = if self.bitmap[level / 8] & (1 << (level % 8)) != 0 {
                let sibling = self.siblings[index];
                index += 1;
                if sibling == default {
                    return Err(Error::Encoding);
                }
                sibling
            } else {
                default
            };
            let bit = 255 - level;
            if key[bit / 8] & (1 << (7 - bit % 8)) == 0 {
                old = branch(level, &old, &sibling);
                new = branch(level, &new, &sibling);
            } else {
                old = branch(level, &sibling, &old);
                new = branch(level, &sibling, &new);
            }
            default = branch(level, &default, &default);
        }
        if old != *previous {
            return Err(Error::Proof);
        }
        Ok(new)
    }
}
impl Wire for NullifierProof {
    const MAGIC: [u8; 8] = *b"T02NUL01";
    const MAX_BYTES: usize = 44 + 256 * 32;
    fn validate(&self) -> Result<()> {
        let count: u32 = self.bitmap.iter().map(|v| v.count_ones()).sum();
        if self.siblings.len() != count as usize {
            return Err(Error::Encoding);
        }
        Ok(())
    }
    fn write_fields(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.bitmap);
        out.extend_from_slice(&(self.siblings.len() as u32).to_le_bytes());
        for sibling in &self.siblings {
            out.extend_from_slice(sibling);
        }
    }
    fn read_fields(r: &mut Reader<'_>) -> Result<Self> {
        let bitmap: [u8; 32] = r.array()?;
        let count = r.u32()?;
        if count > 256 || count != bitmap.iter().map(|v| v.count_ones()).sum::<u32>() {
            return Err(Error::Limit);
        }
        let mut siblings = Vec::with_capacity(count as usize);
        for _ in 0..count {
            siblings.push(r.array()?);
        }
        Ok(Self { bitmap, siblings })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn replay_and_cross_domain_or_kind_paths_are_rejected() {
        let config = [31; 32];
        for kind in [ClaimKind::Release, ClaimKind::Refund, ClaimKind::Escape] {
            let identity = if kind == ClaimKind::Escape {
                &[1u8; 20][..]
            } else {
                &[1u8; 8][..]
            };
            let key = claim_key(&config, kind, identity).unwrap();
            let empty = empty_claim_root(&config, kind).unwrap();
            let proof = NullifierProof::empty();
            let spent = proof.insert(&config, kind, &key, &empty).unwrap();
            assert_ne!(spent, empty);
            assert_eq!(proof.insert(&config, kind, &key, &spent), Err(Error::Proof));
            assert_eq!(
                proof.insert(&[32; 32], kind, &key, &empty),
                Err(Error::Proof)
            );
            let other = if kind == ClaimKind::Release {
                ClaimKind::Refund
            } else {
                ClaimKind::Release
            };
            assert_eq!(
                proof.insert(&config, other, &key, &empty),
                Err(Error::Proof)
            );
        }
    }
    #[test]
    fn last_key_bit_is_distinct_and_noncanonical_defaults_fail() {
        let config = [31; 32];
        let kind = ClaimKind::Escape;
        let a = [42; 32];
        let mut b = a;
        b[31] ^= 1;
        let empty = empty_claim_root(&config, kind).unwrap();
        let spent = NullifierProof::empty()
            .insert(&config, kind, &a, &empty)
            .unwrap();
        let mut proof = NullifierProof::empty();
        proof.bitmap[0] = 1;
        proof.siblings.push(leaf(&config, kind, Some(&a)));
        let both = proof.insert(&config, kind, &b, &spent).unwrap();
        assert_ne!(both, spent);
        assert_eq!(proof.insert(&config, kind, &b, &both), Err(Error::Proof));
        assert_eq!(
            NullifierProof::decode(&proof.encode().unwrap()).unwrap(),
            proof
        );
        proof.siblings[0] = leaf(&config, kind, None);
        assert_eq!(
            proof.insert(&config, kind, &b, &empty),
            Err(Error::Encoding)
        );
        assert!(claim_key(&config, kind, &[0; 20]).is_err());
        assert!(claim_key(&config, kind, &[1; 8]).is_err());
    }
}
