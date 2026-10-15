//! Batch rollback over the pinned complete in-memory state. Only first-written
//! accounts/code are retained; reads do not mutate the underlying cache. This
//! removes whole-database copies, but still copies a touched account's storage.
use alloy_primitives::{Address, B256, U256};
use revm::{
    database::{DbAccount, InMemoryDB},
    primitives::{AddressMap, B256Map, U256Map, KECCAK_EMPTY},
    state::{Account, AccountInfo, Bytecode},
    Database, DatabaseCommit, DatabaseRef,
};
use std::{
    convert::Infallible,
    ops::{Deref, DerefMut},
};

#[derive(Clone, Debug, Default)]
pub(super) struct JournalDb {
    inner: InMemoryDB,
    undo: Option<Rollback>,
}

#[derive(Clone, Debug)]
enum Rollback {
    // For tiny states, bounded copying avoids per-slot undo bookkeeping. The
    // large-state path never clones all accounts. Code bytes are shared Bytes.
    Small(Box<InMemoryDB>),
    Journal(Undo),
}

#[derive(Clone, Debug)]
struct Undo {
    accounts: AddressMap<Option<DbAccount>>,
    contracts: B256Map<Option<Bytecode>>,
    // The executor retains at most 256 recent hashes at every public boundary.
    block_hashes: U256Map<B256>,
}

impl JournalDb {
    pub(super) fn begin(&mut self) {
        assert!(self.undo.is_none(), "nested execution transaction");
        let small = self.inner.cache.accounts.len() <= 8
            && self.inner.cache.contracts.len() <= 8
            && self
                .inner
                .cache
                .accounts
                .values()
                .map(|a| a.storage.len())
                .sum::<usize>()
                <= 32;
        self.undo = Some(if small {
            Rollback::Small(Box::new(self.inner.clone()))
        } else {
            Rollback::Journal(Undo {
                accounts: AddressMap::default(),
                contracts: B256Map::default(),
                block_hashes: self.inner.cache.block_hashes.clone(),
            })
        });
    }
    pub(super) fn accept(&mut self) {
        assert!(self.undo.take().is_some(), "missing execution transaction");
    }
    pub(super) fn rollback(&mut self) {
        let undo = match self.undo.take().expect("active execution transaction") {
            Rollback::Small(snapshot) => {
                self.inner = *snapshot;
                return;
            }
            Rollback::Journal(undo) => undo,
        };
        for (address, account) in undo.accounts {
            match account {
                Some(account) => {
                    self.inner.cache.accounts.insert(address, account);
                }
                None => {
                    self.inner.cache.accounts.remove(&address);
                }
            }
        }
        for (hash, code) in undo.contracts {
            match code {
                Some(code) => {
                    self.inner.cache.contracts.insert(hash, code);
                }
                None => {
                    self.inner.cache.contracts.remove(&hash);
                }
            }
        }
        self.inner.cache.block_hashes = undo.block_hashes;
    }

    fn remember(&mut self, address: Address, account: &Account) {
        if !account.is_touched() {
            return;
        }
        if let Some(Rollback::Journal(undo)) = &mut self.undo {
            undo.accounts
                .entry(address)
                .or_insert_with(|| self.inner.cache.accounts.get(&address).cloned());
            if !account.is_selfdestructed() {
                if let Some(code) = account.info.code.as_ref().filter(|code| !code.is_empty()) {
                    // Match CacheDB::insert_contract's normalization exactly.
                    let hash = if account.info.code_hash == KECCAK_EMPTY {
                        code.hash_slow()
                    } else {
                        account.info.code_hash
                    };
                    undo.contracts
                        .entry(hash)
                        .or_insert_with(|| self.inner.cache.contracts.get(&hash).cloned());
                }
            }
        }
    }
}

// Direct mutable access is confined to genesis construction and the executor's
// bounded block-hash maintenance. EVM writes use DatabaseCommit below.
impl Deref for JournalDb {
    type Target = InMemoryDB;
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}
impl DerefMut for JournalDb {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}
impl Database for JournalDb {
    type Error = Infallible;
    fn basic(&mut self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        self.inner.basic_ref(address)
    }
    fn code_by_hash(&mut self, hash: B256) -> Result<Bytecode, Self::Error> {
        self.inner.code_by_hash_ref(hash)
    }
    fn storage(&mut self, address: Address, key: U256) -> Result<U256, Self::Error> {
        self.inner.storage_ref(address, key)
    }
    fn block_hash(&mut self, number: u64) -> Result<B256, Self::Error> {
        self.inner.block_hash_ref(number)
    }
}
impl DatabaseCommit for JournalDb {
    fn commit(&mut self, changes: AddressMap<Account>) {
        if matches!(self.undo, Some(Rollback::Journal(_))) {
            for (address, account) in &changes {
                self.remember(*address, account);
            }
        }
        self.inner.commit(changes);
    }
    fn commit_iter(&mut self, changes: &mut dyn Iterator<Item = (Address, Account)>) {
        for (address, account) in changes {
            self.remember(address, &account);
            self.inner
                .commit_iter(&mut std::iter::once((address, account)));
        }
    }
}

pub(super) struct ExecutionTransaction<'a> {
    engine: &'a mut super::Executor,
    old_head: super::Header,
    old_anchor: super::AnchorState,
    accepted: bool,
}
impl<'a> ExecutionTransaction<'a> {
    pub(super) fn new(engine: &'a mut super::Executor) -> Self {
        let old_head = engine.head.clone();
        let old_anchor = engine.anchor;
        engine.db.begin();
        Self {
            engine,
            old_head,
            old_anchor,
            accepted: false,
        }
    }
    pub(super) fn accept(mut self) {
        self.engine.db.accept();
        self.accepted = true;
    }
}
impl Deref for ExecutionTransaction<'_> {
    type Target = super::Executor;
    fn deref(&self) -> &Self::Target {
        self.engine
    }
}
impl DerefMut for ExecutionTransaction<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.engine
    }
}
impl Drop for ExecutionTransaction<'_> {
    fn drop(&mut self) {
        if !self.accepted {
            self.engine.db.rollback();
            self.engine.head = self.old_head.clone();
            self.engine.anchor = self.old_anchor;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Executor, Genesis, GenesisAccount};
    use revm::state::EvmStorageSlot;
    use std::collections::BTreeMap;

    fn engine() -> Executor {
        Executor::new(&Genesis {
            rollup_id: B256::repeat_byte(7),
            chain_id: 31337,
            accounts: BTreeMap::from([(
                Address::repeat_byte(1),
                GenesisAccount {
                    nonce: 1,
                    balance: U256::from(100),
                    code: vec![0x60, 0x01, 0x00].into(),
                    storage: BTreeMap::from([(U256::from(1), U256::from(42))]),
                },
            )]),
        })
        .unwrap()
    }

    fn changes(db: &JournalDb, fresh: bool) -> AddressMap<Account> {
        let address = Address::repeat_byte(if fresh { 2 } else { 1 });
        let info = if fresh {
            AccountInfo {
                balance: U256::from(3),
                nonce: 1,
                code_hash: KECCAK_EMPTY,
                code: Some(Bytecode::new_legacy(vec![0x60, 0x02, 0x00].into())),
                ..Default::default()
            }
        } else {
            db.inner.cache.accounts[&address].info.clone()
        };
        let mut account = Account::from(info);
        account.mark_touch();
        if fresh {
            account.mark_created();
        }
        account.info.balance += U256::from(1);
        account.storage.insert(
            U256::from(1),
            EvmStorageSlot::new_changed(U256::from(42), U256::from(99), Default::default()),
        );
        AddressMap::from_iter([(address, account)])
    }

    #[test]
    fn commit_matches_original_database_and_rollback_restores_all_boundaries() {
        let mut engine = engine();
        for marker in 10..20 {
            engine.db.insert_account_info(
                Address::repeat_byte(marker),
                AccountInfo {
                    balance: U256::from(1),
                    ..Default::default()
                },
            );
        }
        engine.head.state_root = crate::state_root(&engine.db);
        let hash = engine.head.hash_slow();
        engine.db.cache.block_hashes.insert(U256::ZERO, hash);
        let original = engine.clone();
        let mut reference = engine.db.inner.clone();
        {
            let mut transaction = ExecutionTransaction::new(&mut engine);
            for fresh in [false, false, true] {
                let changes = changes(&transaction.db, fresh);
                reference.commit(changes.clone());
                transaction.db.commit(changes);
            }
            assert_eq!(
                transaction.db.inner.pretty_print(),
                reference.pretty_print()
            );
            let Some(Rollback::Journal(undo)) = &transaction.db.undo else {
                panic!("large-state journal expected")
            };
            assert_eq!(undo.accounts.len(), 2);
            let mut destroyed = Account::from(
                transaction
                    .db
                    .basic(Address::repeat_byte(1))
                    .unwrap()
                    .unwrap(),
            );
            destroyed.mark_touch();
            destroyed.mark_selfdestruct();
            transaction.db.commit(AddressMap::from_iter([(
                Address::repeat_byte(1),
                destroyed,
            )]));
            transaction.db.cache.block_hashes.clear();
            transaction.head.number = 300;
            transaction.anchor.last_block_number = 300;
            // Dropping an unaccepted batch rolls back every committed slot.
        }
        assert_eq!(
            engine.db.inner.pretty_print(),
            original.db.inner.pretty_print()
        );
        assert_eq!(engine.head, original.head);
        assert_eq!(engine.anchor, original.anchor);
        assert_eq!(engine.state_root(), crate::state_root(&engine.db));
        assert_eq!(engine.head_hash(), engine.head.hash_slow());
        // A failed batch must not leave a stale undo journal or block retries.
        let mut transaction = ExecutionTransaction::new(&mut engine);
        let changes = changes(&transaction.db, true);
        transaction.db.commit(changes);
        transaction.accept();
        assert!(engine
            .db
            .cache
            .accounts
            .contains_key(&Address::repeat_byte(2)));
        assert!(engine.db.undo.is_none());
    }

    #[test]
    fn unwinding_rolls_back_and_reads_do_not_populate_unknown_state() {
        let mut engine = engine();
        let original = engine.db.inner.pretty_print();
        let failed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut transaction = ExecutionTransaction::new(&mut engine);
            assert!(transaction
                .db
                .basic(Address::repeat_byte(9))
                .unwrap()
                .is_none());
            assert_eq!(
                transaction
                    .db
                    .storage(Address::repeat_byte(1), U256::from(99))
                    .unwrap(),
                U256::ZERO
            );
            let changes = changes(&transaction.db, true);
            transaction.db.commit(changes);
            panic!("injected failure after commit");
        }));
        assert!(failed.is_err());
        assert_eq!(engine.db.inner.pretty_print(), original);
        assert_eq!(engine.state_root(), crate::state_root(&engine.db));
    }
}
