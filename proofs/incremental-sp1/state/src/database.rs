//! State access authenticated by Ethereum account/storage tries and code hashes.
//! A missing witness is fatal; only a verified absence can return a default.
use crate::trie::{
    NodeStore, TrieError, MAX_NODES, MAX_NODE_BYTES, MAX_WITNESS_BYTES as MAX_TRIE_BYTES,
};
use alloy_consensus::Header;
use alloy_primitives::{keccak256, Address, Bytes, B256, U256};
use alloy_rlp::{Decodable, Encodable};
use alloy_trie::{TrieAccount, EMPTY_ROOT_HASH};
use revm::{
    database_interface::DBErrorMarker,
    primitives::{AddressMap, KECCAK_EMPTY},
    state::{Account, AccountInfo, Bytecode},
    Database,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use tactus_o1_execution::{
    backend::StateBackend,
    checkpoint::{authenticate_headers, Boundary},
    Error, Executor,
};

const WITNESS_MAGIC: &[u8; 8] = b"TO1WIT01";
const MAX_WITNESS_BYTES: usize = 40 * 1024 * 1024;
const MAX_CODE_BYTES: usize = 8 * 1024 * 1024;
const MAX_CODES: usize = 16_384;
const MAX_HEADER_BYTES: usize = 2048;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Witness {
    pub nodes: Vec<Bytes>,
    pub codes: Vec<Bytes>,
    pub recent_headers: Vec<Header>,
}
impl Witness {
    /// Guest wire format: magic, length-prefixed node/code lists, then a bounded
    /// list of canonical RLP headers. JSON remains only a host artifact format.
    pub fn encode(&self) -> Result<Vec<u8>, StateError> {
        fn list(
            out: &mut Vec<u8>,
            items: &[Bytes],
            count: usize,
            each: usize,
            total: usize,
        ) -> Result<(), StateError> {
            if items.len() > count {
                return Err(StateError::Limit);
            }
            out.extend_from_slice(&(items.len() as u32).to_le_bytes());
            let mut size = 0usize;
            for item in items {
                size = size.checked_add(item.len()).ok_or(StateError::Limit)?;
                if item.len() > each || size > total {
                    return Err(StateError::Limit);
                }
                out.extend_from_slice(&(item.len() as u32).to_le_bytes());
                out.extend_from_slice(item);
            }
            Ok(())
        }
        let mut out = WITNESS_MAGIC.to_vec();
        list(
            &mut out,
            &self.nodes,
            MAX_NODES,
            MAX_NODE_BYTES,
            MAX_TRIE_BYTES,
        )?;
        list(
            &mut out,
            &self.codes,
            MAX_CODES,
            tactus_o1_protocol::genesis::MAX_CODE_BYTES,
            MAX_CODE_BYTES,
        )?;
        if self.recent_headers.is_empty() || self.recent_headers.len() > 256 {
            return Err(StateError::Limit);
        }
        out.extend_from_slice(&(self.recent_headers.len() as u32).to_le_bytes());
        for header in &self.recent_headers {
            let len = header.length();
            if len > MAX_HEADER_BYTES {
                return Err(StateError::Limit);
            }
            out.extend_from_slice(&(len as u32).to_le_bytes());
            header.encode(&mut out);
        }
        if out.len() > MAX_WITNESS_BYTES {
            return Err(StateError::Limit);
        }
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, StateError> {
        if bytes.len() > MAX_WITNESS_BYTES {
            return Err(StateError::Limit);
        }
        struct Reader<'a> {
            rest: &'a [u8],
        }
        impl<'a> Reader<'a> {
            fn take(&mut self, len: usize) -> Result<&'a [u8], StateError> {
                let value = self.rest.get(..len).ok_or(StateError::Encoding)?;
                self.rest = &self.rest[len..];
                Ok(value)
            }
            fn number(&mut self) -> Result<usize, StateError> {
                Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()) as usize)
            }
            fn blob(&mut self, cap: usize) -> Result<&'a [u8], StateError> {
                let len = self.number()?;
                if len > cap {
                    return Err(StateError::Limit);
                }
                self.take(len)
            }
            fn list(
                &mut self,
                count: usize,
                each: usize,
                total: usize,
            ) -> Result<Vec<Bytes>, StateError> {
                let len = self.number()?;
                if len > count {
                    return Err(StateError::Limit);
                }
                // Do not allocate the full claimed capacity before checking
                // that the corresponding length-prefixed data actually exists.
                let mut items = Vec::with_capacity(len.min(1024));
                let mut size = 0usize;
                for _ in 0..len {
                    let item = self.blob(each)?;
                    size = size.checked_add(item.len()).ok_or(StateError::Limit)?;
                    if size > total {
                        return Err(StateError::Limit);
                    }
                    items.push(Bytes::copy_from_slice(item));
                }
                Ok(items)
            }
        }
        let mut reader = Reader { rest: bytes };
        if reader.take(8)? != WITNESS_MAGIC {
            return Err(StateError::Encoding);
        }
        let nodes = reader.list(MAX_NODES, MAX_NODE_BYTES, MAX_TRIE_BYTES)?;
        let codes = reader.list(
            MAX_CODES,
            tactus_o1_protocol::genesis::MAX_CODE_BYTES,
            MAX_CODE_BYTES,
        )?;
        let len = reader.number()?;
        if len == 0 || len > 256 {
            return Err(StateError::Limit);
        }
        let mut recent_headers = Vec::with_capacity(len);
        for _ in 0..len {
            recent_headers.push(decode_canonical::<Header>(reader.blob(MAX_HEADER_BYTES)?)?);
        }
        if !reader.rest.is_empty() {
            return Err(StateError::Encoding);
        }
        Ok(Self {
            nodes,
            codes,
            recent_headers,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StateError {
    Trie(TrieError),
    Encoding,
    Limit,
    Header,
    MissingCode(B256),
    MissingHeader(u64),
    CodeHash,
}
impl std::fmt::Display for StateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for StateError {}
impl DBErrorMarker for StateError {}
impl From<TrieError> for StateError {
    fn from(e: TrieError) -> Self {
        Self::Trie(e)
    }
}
fn engine_error(error: StateError) -> Error {
    Error::Engine(error.to_string())
}
fn decode_canonical<T: Decodable + Encodable>(bytes: &[u8]) -> Result<T, StateError> {
    let mut rest = bytes;
    let value = T::decode(&mut rest).map_err(|_| StateError::Encoding)?;
    if !rest.is_empty() || alloy_rlp::encode(&value) != bytes {
        return Err(StateError::Encoding);
    }
    Ok(value)
}

#[derive(Clone, Debug)]
pub struct SparseDb {
    root: B256,
    nodes: NodeStore,
    accounts: BTreeMap<Address, Option<TrieAccount>>,
    // Transaction-visible writes since the last block root. Cached account
    // metadata is current; its storage_root still identifies the backing trie.
    // A present entry also marks an account with no storage writes as dirty.
    pending: BTreeMap<Address, BTreeMap<U256, U256>>,
    codes: BTreeMap<B256, Bytes>,
    initial_codes: BTreeSet<B256>,
    used_codes: BTreeSet<B256>,
    headers: BTreeMap<u64, B256>,
    undo: Option<(B256, BTreeMap<u64, B256>)>,
}
impl SparseDb {
    /// The caller must bind the boundary to a committed genesis or accepted tip.
    /// No authority is conferred by a self-consistent prover-chosen boundary.
    pub fn from_witness(boundary: &Boundary, witness: &Witness) -> Result<Self, StateError> {
        let headers = authenticate_headers(&witness.recent_headers, boundary)
            .map_err(|_| StateError::Header)?;
        let nodes = NodeStore::from_witness(&witness.nodes)?;
        let mut codes = BTreeMap::new();
        let mut size = 0usize;
        for code in &witness.codes {
            size = size.checked_add(code.len()).ok_or(StateError::Limit)?;
            if code.len() > tactus_o1_protocol::genesis::MAX_CODE_BYTES
                || size > MAX_CODE_BYTES
                || witness.codes.len() > MAX_CODES
            {
                return Err(StateError::Limit);
            }
            codes.insert(keccak256(code), code.clone());
        }
        Ok(Self {
            root: boundary.state_root,
            nodes,
            accounts: BTreeMap::new(),
            pending: BTreeMap::new(),
            initial_codes: codes.keys().copied().collect(),
            codes,
            used_codes: BTreeSet::new(),
            headers,
            undo: None,
        })
    }

    fn account(&mut self, address: Address) -> Result<Option<TrieAccount>, StateError> {
        if let Some(account) = self.accounts.get(&address) {
            return Ok(*account);
        }
        let account = self
            .nodes
            .get(self.root, keccak256(address))?
            .map(|bytes| decode_canonical::<TrieAccount>(&bytes))
            .transpose()?;
        if account
            .is_some_and(|a| a.nonce == 0 && a.balance.is_zero() && a.code_hash == KECCAK_EMPTY)
        {
            return Err(StateError::Encoding);
        }
        self.accounts.insert(address, account);
        Ok(account)
    }

    fn commit(&mut self, changes: AddressMap<Account>) -> Result<(), StateError> {
        // Stable ordering also makes host witness minimization reproducible.
        for (address, account) in changes.into_iter().collect::<BTreeMap<_, _>>() {
            if !account.is_touched() {
                continue;
            }
            if account.is_selfdestructed() {
                self.accounts.insert(address, None);
                self.pending.insert(address, BTreeMap::new());
                continue;
            }
            let prior = self.account(address)?;
            let created = account.is_created();
            let storage_root = if created {
                EMPTY_ROOT_HASH
            } else {
                prior.map_or(EMPTY_ROOT_HASH, |a| a.storage_root)
            };
            let mut hash = account.info.code_hash;
            if let Some(code) = &account.info.code {
                if !code.is_empty() {
                    let bytes = code.original_bytes();
                    let actual = keccak256(&bytes);
                    if hash != KECCAK_EMPTY && hash != actual {
                        return Err(StateError::CodeHash);
                    }
                    hash = actual;
                    self.codes.insert(hash, bytes);
                    self.initial_codes.remove(&hash);
                }
            }
            if hash == B256::ZERO {
                hash = KECCAK_EMPTY;
            }
            let slots = self.pending.entry(address).or_default();
            if created {
                // A new incarnation must not see writes from an earlier one,
                // including writes not yet incorporated into a block trie.
                slots.clear();
            }
            for (key, slot) in account.storage {
                if !created && !slot.is_changed() {
                    continue;
                }
                // Retain explicit zeroes: they override authenticated backing
                // values for later transactions and delete the slot on flush.
                slots.insert(key, slot.present_value());
            }
            let updated =
                TrieAccount::new(account.info.nonce, account.info.balance, storage_root, hash);
            let updated =
                (!(updated.nonce == 0 && updated.balance.is_zero() && hash == KECCAK_EMPTY))
                    .then_some(updated);
            if updated.is_none() {
                slots.clear();
            }
            self.accounts.insert(address, updated);
        }
        Ok(())
    }

    fn flush(&mut self) -> Result<B256, StateError> {
        // Publish no root/cache changes until all authenticated trie updates
        // succeed. Immutable computed nodes may remain after an error, but an
        // incomplete flush cannot become a state boundary.
        let mut root = self.root;
        let mut accounts = Vec::with_capacity(self.pending.len());
        for (address, slots) in &self.pending {
            let mut account = self.accounts[address];
            if let Some(info) = &mut account {
                for (key, value) in slots {
                    info.storage_root = self.nodes.update(
                        info.storage_root,
                        keccak256(key.to_be_bytes::<32>()),
                        (!value.is_zero()).then(|| alloy_rlp::encode(value)),
                    )?;
                }
            }
            root = self
                .nodes
                .update(root, keccak256(address), account.map(alloy_rlp::encode))?;
            accounts.push((*address, account));
        }
        self.root = root;
        self.accounts.extend(accounts);
        self.pending.clear();
        Ok(root)
    }

    pub fn required_witness(&self, recent_headers: Vec<Header>) -> Witness {
        assert!(
            self.pending.is_empty(),
            "witness requires completed block roots"
        );
        Witness {
            nodes: self
                .nodes
                .accessed_witness()
                .into_iter()
                .map(Bytes::from)
                .collect(),
            codes: self
                .used_codes
                .iter()
                .map(|h| self.codes[h].clone())
                .collect(),
            recent_headers,
        }
    }

    /// Host-only full-state constructor. Rebuilding is excluded from the guest;
    /// it is used to discover the exact authenticated paths an interval needs.
    #[cfg(not(target_os = "zkvm"))]
    pub fn from_complete(
        engine: &Executor,
        recent_headers: Vec<Header>,
    ) -> Result<Self, StateError> {
        let boundary = Boundary {
            anchor: *engine.anchor(),
            state_root: engine.state_root(),
            header_hash: engine.head_hash(),
        };
        let headers =
            authenticate_headers(&recent_headers, &boundary).map_err(|_| StateError::Header)?;
        let mut nodes = NodeStore::default();
        let mut root = EMPTY_ROOT_HASH;
        let mut codes = BTreeMap::new();
        for (address, account) in engine.accounts().collect::<BTreeMap<_, _>>() {
            let mut storage = EMPTY_ROOT_HASH;
            for (key, value) in account.storage {
                if !value.is_zero() {
                    storage = nodes.update(
                        storage,
                        keccak256(key.to_be_bytes::<32>()),
                        Some(alloy_rlp::encode(value)),
                    )?;
                }
            }
            let code_hash = keccak256(&account.code);
            if !account.code.is_empty() {
                codes.insert(code_hash, account.code);
            }
            root = nodes.update(
                root,
                keccak256(address),
                Some(alloy_rlp::encode(TrieAccount::new(
                    account.nonce,
                    account.balance,
                    storage,
                    code_hash,
                ))),
            )?;
        }
        if root != boundary.state_root {
            return Err(StateError::Encoding);
        }
        nodes.mark_initial();
        Ok(Self {
            root,
            nodes,
            accounts: BTreeMap::new(),
            pending: BTreeMap::new(),
            initial_codes: codes.keys().copied().collect(),
            codes,
            used_codes: BTreeSet::new(),
            headers,
            undo: None,
        })
    }
}

impl Database for SparseDb {
    type Error = StateError;
    fn basic(&mut self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        Ok(self.account(address)?.map(|a| AccountInfo {
            nonce: a.nonce,
            balance: a.balance,
            code_hash: a.code_hash,
            code: None,
            ..Default::default()
        }))
    }
    fn code_by_hash(&mut self, hash: B256) -> Result<Bytecode, Self::Error> {
        if hash == KECCAK_EMPTY {
            return Ok(Bytecode::default());
        }
        let code = self.codes.get(&hash).ok_or(StateError::MissingCode(hash))?;
        if self.initial_codes.contains(&hash) {
            self.used_codes.insert(hash);
        }
        Ok(Bytecode::new_legacy(code.clone()))
    }
    fn storage(&mut self, address: Address, key: U256) -> Result<U256, Self::Error> {
        let Some(account) = self.account(address)? else {
            return Ok(U256::ZERO);
        };
        if let Some(value) = self.pending.get(&address).and_then(|slots| slots.get(&key)) {
            return Ok(*value);
        }
        let Some(raw) = self
            .nodes
            .get(account.storage_root, keccak256(key.to_be_bytes::<32>()))?
        else {
            return Ok(U256::ZERO);
        };
        let value = decode_canonical::<U256>(&raw)?;
        if value.is_zero() {
            return Err(StateError::Encoding);
        }
        Ok(value)
    }
    fn block_hash(&mut self, number: u64) -> Result<B256, Self::Error> {
        self.headers
            .get(&number)
            .copied()
            .ok_or(StateError::MissingHeader(number))
    }
}
impl StateBackend for SparseDb {
    fn begin_batch(&mut self) {
        assert!(self.undo.is_none(), "nested batch");
        assert!(self.pending.is_empty(), "unflushed prior batch");
        self.undo = Some((self.root, self.headers.clone()));
    }
    fn accept_batch(&mut self) {
        assert!(self.pending.is_empty(), "unflushed accepted batch");
        assert!(self.undo.take().is_some(), "missing batch");
    }
    fn rollback_batch(&mut self) {
        let (root, headers) = self.undo.take().expect("active batch");
        self.root = root;
        self.headers = headers;
        self.accounts.clear();
        self.pending.clear();
        // New immutable nodes/code remain content-addressed and unreachable from
        // the restored root. They cannot replace any authenticated value.
    }
    fn commit_changes(&mut self, changes: AddressMap<Account>) -> Result<(), Error> {
        self.commit(changes).map_err(engine_error)
    }
    fn calculate_state_root(&mut self) -> Result<B256, Error> {
        self.flush().map_err(engine_error)
    }
    fn cached_header_hash(&self, number: u64) -> Option<B256> {
        self.headers.get(&number).copied()
    }
    fn record_header(&mut self, number: u64, hash: B256) {
        self.headers.insert(number, hash);
        self.headers.retain(|n, _| *n >= number.saturating_sub(255));
    }
}
