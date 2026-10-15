//! Authenticated fixed-key Ethereum MPT reads and updates. Missing hashed nodes
//! are errors, including siblings needed to collapse a branch after deletion.
use alloy_primitives::{keccak256, B256};
use alloy_rlp::Decodable;
use alloy_trie::{
    nodes::{BranchNode, ExtensionNode, LeafNode, RlpNode, TrieNode},
    Nibbles, EMPTY_ROOT_HASH,
};
use std::collections::{BTreeMap, BTreeSet};

const MAX_NODE_BYTES: usize = 1024;
const MAX_WITNESS_BYTES: usize = 16 * 1024 * 1024;
const MAX_STORE_BYTES: usize = 64 * 1024 * 1024;
const MAX_NODES: usize = 262_144;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TrieError {
    MissingNode(B256),
    Encoding,
    InvalidPath,
    Limit,
}
impl std::fmt::Display for TrieError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for TrieError {}

#[derive(Clone, Debug, Default)]
pub struct NodeStore {
    nodes: BTreeMap<B256, Vec<u8>>,
    initial: BTreeSet<B256>,
    accessed: BTreeSet<B256>,
    bytes: usize,
}

#[derive(Clone, Debug)]
enum Node {
    Empty,
    Leaf(Vec<u8>, Vec<u8>),
    Extension(Vec<u8>, RlpNode),
    Branch(Box<[RlpNode; 16]>),
}

fn empty() -> RlpNode {
    RlpNode::from_raw(&[0x80]).unwrap()
}
fn is_empty(reference: &RlpNode) -> bool {
    reference.as_slice() == [0x80]
}
fn nibbles(key: B256) -> Vec<u8> {
    Nibbles::unpack(key.as_slice()).to_vec()
}

impl NodeStore {
    pub fn from_witness<N: AsRef<[u8]>>(nodes: &[N]) -> Result<Self, TrieError> {
        let mut store = Self::default();
        let mut bytes = 0usize;
        for node in nodes {
            let node = node.as_ref();
            bytes = bytes.checked_add(node.len()).ok_or(TrieError::Limit)?;
            if bytes > MAX_WITNESS_BYTES || nodes.len() > MAX_NODES {
                return Err(TrieError::Limit);
            }
            let hash = store.insert_encoded(node.to_vec())?;
            store.initial.insert(hash);
        }
        Ok(store)
    }

    /// Host witness construction uses a complete trie, then retains only nodes
    /// actually required by reads/updates. Newly computed nodes need no witness.
    pub fn mark_initial(&mut self) {
        self.initial = self.nodes.keys().copied().collect();
        self.accessed.clear();
    }
    pub fn accessed_witness(&self) -> Vec<Vec<u8>> {
        self.accessed
            .iter()
            .map(|h| self.nodes[h].clone())
            .collect()
    }
    pub fn all_nodes(&self) -> Vec<Vec<u8>> {
        self.nodes.values().cloned().collect()
    }

    fn insert_encoded(&mut self, encoded: Vec<u8>) -> Result<B256, TrieError> {
        if encoded.is_empty() || encoded.len() > MAX_NODE_BYTES {
            return Err(TrieError::Limit);
        }
        let hash = keccak256(&encoded);
        if !self.nodes.contains_key(&hash) {
            if self.nodes.len() >= MAX_NODES || self.bytes + encoded.len() > MAX_STORE_BYTES {
                return Err(TrieError::Limit);
            }
            self.bytes += encoded.len();
            self.nodes.insert(hash, encoded);
        }
        Ok(hash)
    }

    fn resolve(&mut self, reference: &RlpNode, root: bool) -> Result<Node, TrieError> {
        if is_empty(reference) {
            return Ok(Node::Empty);
        }
        let raw = if let Some(hash) = reference.as_hash() {
            if reference[0] != 0xa0 {
                return Err(TrieError::Encoding);
            }
            if root && hash == EMPTY_ROOT_HASH {
                return Ok(Node::Empty);
            }
            let raw = self.nodes.get(&hash).ok_or(TrieError::MissingNode(hash))?;
            if !root && raw.len() < 32 {
                return Err(TrieError::Encoding);
            }
            if self.initial.contains(&hash) {
                self.accessed.insert(hash);
            }
            raw.clone()
        } else {
            if reference.len() >= 32 {
                return Err(TrieError::Encoding);
            }
            reference.to_vec()
        };
        let mut input = raw.as_slice();
        let decoded = TrieNode::decode(&mut input).map_err(|_| TrieError::Encoding)?;
        if !input.is_empty() || alloy_rlp::encode(&decoded) != raw {
            return Err(TrieError::Encoding);
        }
        match decoded {
            TrieNode::EmptyRoot => Err(TrieError::Encoding),
            TrieNode::Leaf(leaf) => Ok(Node::Leaf(leaf.key.to_vec(), leaf.value)),
            TrieNode::Extension(extension) => {
                if extension.key.is_empty() || is_empty(&extension.child) {
                    return Err(TrieError::InvalidPath);
                }
                Ok(Node::Extension(extension.key.to_vec(), extension.child))
            }
            TrieNode::Branch(branch) => {
                if branch.state_mask.count_ones() < 2 {
                    return Err(TrieError::InvalidPath);
                }
                let mut children = Box::new(std::array::from_fn(|_| empty()));
                for (index, child) in branch.as_ref().children() {
                    if let Some(child) = child {
                        children[index as usize] = child.clone();
                    }
                }
                Ok(Node::Branch(children))
            }
        }
    }

    fn put(&mut self, node: Node) -> Result<RlpNode, TrieError> {
        let node = match node {
            Node::Empty => return Ok(empty()),
            Node::Leaf(path, value) => {
                TrieNode::Leaf(LeafNode::new(Nibbles::from_nibbles(path), value))
            }
            Node::Extension(path, child) => {
                if path.is_empty() {
                    return Ok(child);
                }
                TrieNode::Extension(ExtensionNode::new(Nibbles::from_nibbles(path), child))
            }
            Node::Branch(children) => {
                let mut branch = BranchNode::default();
                for (index, child) in (*children).into_iter().enumerate() {
                    if !is_empty(&child) {
                        branch.state_mask.set_bit(index as u8);
                        branch.stack.push(child);
                    }
                }
                TrieNode::Branch(branch)
            }
        };
        let bytes = alloy_rlp::encode(&node);
        // from_rlp would hash large nodes itself, then insert_encoded would hash
        // them again. Compute the content hash once and reuse it as the child
        // reference; short inline children retain their exact encoded bytes.
        let inline = (bytes.len() < 32).then(|| RlpNode::from_raw(&bytes).unwrap());
        let hash = self.insert_encoded(bytes)?;
        // A node recomputed inside this execution does not need to be supplied
        // later. Earlier accesses remain recorded if they needed the old node.
        self.initial.remove(&hash);
        Ok(inline.unwrap_or_else(|| RlpNode::word_rlp(&hash)))
    }

    pub fn get(&mut self, root: B256, key: B256) -> Result<Option<Vec<u8>>, TrieError> {
        let key = nibbles(key);
        let mut depth = 0;
        let mut reference = RlpNode::word_rlp(&root);
        loop {
            match self.resolve(&reference, depth == 0)? {
                Node::Empty => return Ok(None),
                Node::Leaf(path, value) => {
                    if path.len() != key.len() - depth {
                        return Err(TrieError::InvalidPath);
                    }
                    return Ok((key[depth..] == path).then_some(value));
                }
                Node::Extension(path, child) => {
                    if path.len() > key.len() - depth {
                        return Err(TrieError::InvalidPath);
                    }
                    if !key[depth..].starts_with(&path) {
                        return Ok(None);
                    }
                    depth += path.len();
                    reference = child;
                }
                Node::Branch(children) => {
                    let index = *key.get(depth).ok_or(TrieError::InvalidPath)? as usize;
                    reference = children[index].clone();
                    depth += 1;
                }
            }
        }
    }

    pub fn update(
        &mut self,
        root: B256,
        key: B256,
        value: Option<Vec<u8>>,
    ) -> Result<B256, TrieError> {
        let key = nibbles(key);
        let reference = self.update_at(RlpNode::word_rlp(&root), &key, value, true)?;
        if is_empty(&reference) {
            return Ok(EMPTY_ROOT_HASH);
        }
        if let Some(hash) = reference.as_hash() {
            Ok(hash)
        } else {
            Ok(keccak256(reference.as_slice()))
        }
    }

    fn prefix(&mut self, mut path: Vec<u8>, child: RlpNode) -> Result<RlpNode, TrieError> {
        if path.is_empty() {
            return Ok(child);
        }
        match self.resolve(&child, false)? {
            Node::Empty => Ok(empty()),
            Node::Leaf(tail, value) => {
                path.extend(tail);
                self.put(Node::Leaf(path, value))
            }
            Node::Extension(tail, grandchild) => {
                path.extend(tail);
                self.put(Node::Extension(path, grandchild))
            }
            Node::Branch(_) => self.put(Node::Extension(path, child)),
        }
    }
    fn collapse(&mut self, children: Box<[RlpNode; 16]>) -> Result<RlpNode, TrieError> {
        let present: Vec<_> = children
            .iter()
            .enumerate()
            .filter(|(_, c)| !is_empty(c))
            .collect();
        match present.len() {
            0 => Ok(empty()),
            1 => self.prefix(vec![present[0].0 as u8], present[0].1.clone()),
            _ => self.put(Node::Branch(children)),
        }
    }

    fn update_at(
        &mut self,
        reference: RlpNode,
        key: &[u8],
        value: Option<Vec<u8>>,
        root: bool,
    ) -> Result<RlpNode, TrieError> {
        match self.resolve(&reference, root)? {
            Node::Empty => match value {
                Some(value) => self.put(Node::Leaf(key.to_vec(), value)),
                None => Ok(reference),
            },
            Node::Leaf(path, prior) => {
                if path.len() != key.len() {
                    return Err(TrieError::InvalidPath);
                }
                let common = path.iter().zip(key).take_while(|(a, b)| a == b).count();
                if common == key.len() {
                    return match value {
                        Some(value) => self.put(Node::Leaf(path, value)),
                        None => Ok(empty()),
                    };
                }
                let Some(value) = value else {
                    return Ok(reference);
                };
                let mut children = Box::new(std::array::from_fn(|_| empty()));
                children[path[common] as usize] =
                    self.put(Node::Leaf(path[common + 1..].to_vec(), prior))?;
                children[key[common] as usize] =
                    self.put(Node::Leaf(key[common + 1..].to_vec(), value))?;
                let branch = self.put(Node::Branch(children))?;
                self.prefix(path[..common].to_vec(), branch)
            }
            Node::Extension(path, child) => {
                if path.len() > key.len() {
                    return Err(TrieError::InvalidPath);
                }
                let common = path.iter().zip(key).take_while(|(a, b)| a == b).count();
                if common == path.len() {
                    let child = self.update_at(child, &key[common..], value, false)?;
                    return self.prefix(path, child);
                }
                let Some(value) = value else {
                    return Ok(reference);
                };
                let mut children = Box::new(std::array::from_fn(|_| empty()));
                // The untouched old subtree can remain opaque on insertion.
                children[path[common] as usize] = if common + 1 == path.len() {
                    child
                } else {
                    self.put(Node::Extension(path[common + 1..].to_vec(), child))?
                };
                children[key[common] as usize] =
                    self.put(Node::Leaf(key[common + 1..].to_vec(), value))?;
                let branch = self.put(Node::Branch(children))?;
                self.prefix(path[..common].to_vec(), branch)
            }
            Node::Branch(mut children) => {
                let index = *key.first().ok_or(TrieError::InvalidPath)? as usize;
                children[index] =
                    self.update_at(children[index].clone(), &key[1..], value, false)?;
                self.collapse(children)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn reference(values: &BTreeMap<B256, Vec<u8>>) -> B256 {
        let mut builder = alloy_trie::HashBuilder::default();
        for (key, value) in values {
            builder.add_leaf(Nibbles::unpack(key.as_slice()), value);
        }
        builder.root()
    }
    #[test]
    fn sparse_insert_update_delete_matches_independent_full_hash_builder() {
        let mut store = NodeStore::default();
        let mut root = EMPTY_ROOT_HASH;
        let mut values = BTreeMap::new();
        let mut keys = Vec::new();
        for index in 0..160u64 {
            let key = if index < 80 {
                keccak256(index.to_le_bytes())
            } else {
                let mut key = [0x44; 32];
                key[30..].copy_from_slice(&(index as u16).to_be_bytes());
                B256::from(key)
            };
            keys.push(key);
            let value = vec![index as u8; if index % 2 == 0 { 1 } else { 80 }];
            values.insert(key, value.clone());
            root = store.update(root, key, Some(value)).unwrap();
            assert_eq!(root, reference(&values), "insert {index}");
        }
        for (index, key) in keys.iter().enumerate() {
            assert_eq!(store.get(root, *key).unwrap(), values.get(key).cloned());
            let value = vec![0xfe; 32];
            values.insert(*key, value.clone());
            root = store.update(root, *key, Some(value)).unwrap();
            assert_eq!(root, reference(&values), "update {index}");
        }
        for (index, key) in keys.iter().rev().enumerate() {
            values.remove(key);
            root = store.update(root, *key, None).unwrap();
            assert_eq!(root, reference(&values), "delete {index}");
            assert_eq!(store.get(root, *key).unwrap(), None);
        }
        assert_eq!(root, EMPTY_ROOT_HASH);
    }
    #[test]
    fn absent_keys_and_missing_witnesses_are_distinct_and_deletion_needs_sibling() {
        let mut full = NodeStore::default();
        let mut root = EMPTY_ROOT_HASH;
        let a = B256::repeat_byte(0x11);
        let b = B256::repeat_byte(0x22);
        let c = B256::repeat_byte(0x33);
        root = full.update(root, a, Some(vec![1; 40])).unwrap();
        root = full.update(root, b, Some(vec![2; 40])).unwrap();
        full.mark_initial();
        assert_eq!(full.get(root, a).unwrap(), Some(vec![1; 40]));
        let proof_a = full.accessed_witness();
        let mut partial = NodeStore::from_witness(&proof_a).unwrap();
        assert_eq!(partial.get(root, a).unwrap(), Some(vec![1; 40]));
        assert_eq!(partial.get(root, c).unwrap(), None);
        assert!(matches!(
            partial.get(root, b),
            Err(TrieError::MissingNode(_))
        ));
        assert!(matches!(
            partial.update(root, a, None),
            Err(TrieError::MissingNode(_))
        ));
        // Insertion into an empty branch need not open untouched siblings.
        let root_only = vec![full.nodes[&root].clone()];
        let mut partial = NodeStore::from_witness(&root_only).unwrap();
        let added = partial.update(root, c, Some(vec![3; 40])).unwrap();
        let expected = full.update(root, c, Some(vec![3; 40])).unwrap();
        assert_eq!(added, expected);
        assert_eq!(partial.update(added, c, None).unwrap(), root);
        let mut tampered = root_only;
        tampered[0][3] ^= 1;
        assert!(NodeStore::from_witness(&tampered)
            .unwrap()
            .get(root, a)
            .is_err());
    }
    #[test]
    fn root_leaf_and_inline_paths_roundtrip_through_witness() {
        let mut store = NodeStore::default();
        let mut root = EMPTY_ROOT_HASH;
        let keys = [B256::ZERO, B256::with_last_byte(1), B256::with_last_byte(2)];
        for (i, key) in keys.iter().enumerate() {
            root = store.update(root, *key, Some(vec![i as u8 + 1])).unwrap();
        }
        let mut from = NodeStore::from_witness(&store.all_nodes()).unwrap();
        for (i, key) in keys.iter().enumerate() {
            assert_eq!(from.get(root, *key).unwrap(), Some(vec![i as u8 + 1]));
        }
        for key in keys {
            root = from.update(root, key, None).unwrap();
        }
        assert_eq!(root, EMPTY_ROOT_HASH);
    }
}
