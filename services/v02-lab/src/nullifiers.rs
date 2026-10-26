//! Reconstructible sparse claim tree. Only canonical, verified claims may be
//! inserted. Its root must match the current Vault before exporting any path.
use crate::{err, Result};
use std::collections::{BTreeMap, BTreeSet};
use tactus_o1_protocol::v02::{claim_key, hash, ClaimKind, NullifierProof};
#[derive(Clone)]
pub struct Tree {
    config: [u8; 32],
    kind: ClaimKind,
    spent: BTreeSet<[u8; 32]>,
}
fn branch(level: usize, left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    hash(
        b"tactus/0.02/claim/branch",
        &[&(level as u16).to_le_bytes()[..], left, right].concat(),
    )
}
fn parent(key: [u8; 32]) -> [u8; 32] {
    let mut next = [0; 32];
    let mut carry = 0;
    for (i, byte) in key.into_iter().enumerate() {
        next[i] = (byte >> 1) | carry;
        carry = (byte & 1) << 7;
    }
    next
}
impl Tree {
    pub fn new(config: [u8; 32], kind: ClaimKind) -> Self {
        Self {
            config,
            kind,
            spent: BTreeSet::new(),
        }
    }
    fn leaf(&self, key: Option<&[u8; 32]>) -> [u8; 32] {
        let mut b = self.config.to_vec();
        b.push(self.kind as u8);
        b.push(u8::from(key.is_some()));
        if let Some(k) = key {
            b.extend_from_slice(k);
        }
        hash(b"tactus/0.02/claim/leaf", &b)
    }
    fn calculate(&self, target: Option<[u8; 32]>) -> ([u8; 32], NullifierProof) {
        let mut nodes: BTreeMap<_, _> = self
            .spent
            .iter()
            .map(|k| (*k, self.leaf(Some(k))))
            .collect();
        let mut default = self.leaf(None);
        let mut target = target;
        let mut proof = NullifierProof::empty();
        for level in 0..256 {
            if let Some(key) = target {
                let mut sibling = key;
                sibling[31] ^= 1;
                if let Some(value) = nodes.get(&sibling).filter(|v| **v != default) {
                    proof.bitmap[level / 8] |= 1 << (level % 8);
                    proof.siblings.push(*value);
                }
                target = Some(parent(key));
            }
            let mut next = BTreeMap::new();
            for key in nodes.keys() {
                let p = parent(*key);
                if next.contains_key(&p) {
                    continue;
                }
                let mut left = *key;
                left[31] &= 0xfe;
                let mut right = left;
                right[31] |= 1;
                next.insert(
                    p,
                    branch(
                        level,
                        nodes.get(&left).unwrap_or(&default),
                        nodes.get(&right).unwrap_or(&default),
                    ),
                );
            }
            nodes = next;
            default = branch(level, &default, &default);
        }
        (nodes.get(&[0; 32]).copied().unwrap_or(default), proof)
    }
    pub fn root(&self) -> [u8; 32] {
        self.calculate(None).0
    }
    pub fn proof(&self, identity: &[u8], expected: [u8; 32]) -> Result<NullifierProof> {
        let key = claim_key(&self.config, self.kind, identity).map_err(err)?;
        if self.spent.contains(&key) {
            return Err("claim already spent".into());
        }
        let (root, proof) = self.calculate(Some(key));
        if root != expected {
            return Err("recovered nullifier root differs from Vault".into());
        }
        proof
            .insert(&self.config, self.kind, &key, &root)
            .map_err(err)?;
        Ok(proof)
    }
    pub fn record(&mut self, identity: &[u8]) -> Result<()> {
        if self.spent.len() >= crate::limits::MAX_CLAIMS_PER_KIND {
            return Err("development claim-index limit exceeded".into());
        }
        if !self
            .spent
            .insert(claim_key(&self.config, self.kind, identity).map_err(err)?)
        {
            return Err("duplicate canonical claim".into());
        }
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use tactus_o1_protocol::v02::empty_claim_root;
    #[test]
    fn paths_match_consensus_after_many_claims_and_reject_unknown_roots() {
        for kind in [ClaimKind::Release, ClaimKind::Refund, ClaimKind::Escape] {
            let mut tree = Tree::new([7; 32], kind);
            let mut root = empty_claim_root(&[7; 32], kind).unwrap();
            for n in 1u64..=16 {
                let id = if kind == ClaimKind::Escape {
                    [n.to_le_bytes().as_slice(), &[4; 12]].concat()
                } else {
                    n.to_le_bytes().to_vec()
                };
                assert!(tree.proof(&id, [9; 32]).is_err());
                let proof = tree.proof(&id, root).unwrap();
                root = proof
                    .insert(
                        &[7; 32],
                        kind,
                        &claim_key(&[7; 32], kind, &id).unwrap(),
                        &root,
                    )
                    .unwrap();
                tree.record(&id).unwrap();
                assert_eq!(tree.root(), root);
                assert!(tree.proof(&id, root).is_err());
            }
        }
    }
}
