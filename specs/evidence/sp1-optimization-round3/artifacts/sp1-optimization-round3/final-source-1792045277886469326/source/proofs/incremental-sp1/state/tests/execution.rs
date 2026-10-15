use alloy_primitives::{Address, Bytes, TxKind, U256};
use revm::Database;
use tactus_o1_execution::{backend::StateBackend, checkpoint::Boundary, Executor, GenesisAccount};
use tactus_o1_protocol::batch::{BatchInput, BlockInput};
use tactus_o1_sparse_state::database::{SparseDb, StateError};

#[allow(dead_code)]
#[path = "../../../../crates/tactus-o1-execution/examples/execution-vectors.rs"]
mod vectors;

fn boundary(engine: &Executor) -> Boundary {
    Boundary {
        anchor: *engine.anchor(),
        state_root: engine.state_root(),
        header_hash: engine.head_hash(),
    }
}
fn input(engine: &Executor, transactions: Vec<Vec<u8>>) -> Vec<u8> {
    BatchInput {
        parent: *engine.anchor(),
        blocks: vec![BlockInput {
            timestamp: engine.head().timestamp + 1,
            fee_recipient: [3; 20],
            transactions,
        }],
    }
    .encode()
    .unwrap()
}

#[test]
fn sparse_execution_and_pruned_witness_match_complete_state_for_consecutive_batches() {
    let contract = Address::repeat_byte(0x55);
    let mut genesis = vectors::genesis();
    genesis.accounts.insert(
        contract,
        GenesisAccount {
            nonce: 1,
            // Write calldata[0] to slot zero, then emit LOG0.
            code: Bytes::from_static(&[0x5f, 0x35, 0x5f, 0x55, 0x5f, 0x5f, 0xa0, 0x00]),
            storage: std::collections::BTreeMap::from([
                (U256::ZERO, U256::from(99)),
                (U256::from(1), U256::from(77)),
            ]),
            ..Default::default()
        },
    );
    let mut complete = Executor::new(&genesis).unwrap();
    let mut headers = vec![complete.head().clone()];
    for nonce in 0..3 {
        let before = boundary(&complete);
        let original = complete.clone();
        let db = SparseDb::from_complete(&complete, headers.clone()).unwrap();
        let mut discovery = complete.clone().with_backend(db).unwrap();
        let mut tx = vectors::tx(nonce);
        tx.to = TxKind::Call(contract);
        tx.input = U256::from(if nonce == 1 { 0 } else { 42 })
            .to_be_bytes::<32>()
            .to_vec()
            .into();
        let batch = input(&complete, vec![vectors::sign(tx)]);
        let expected = complete.apply_batch(&batch).unwrap();
        assert_eq!(discovery.apply_batch(&batch).unwrap(), expected);
        let witness = discovery.backend().required_witness(headers.clone());
        let db = SparseDb::from_witness(&before, &witness).unwrap();
        let mut sparse = if nonce == 0 {
            original.clone().with_backend(db).unwrap()
        } else {
            Executor::from_state(db, before.anchor, original.head().clone()).unwrap()
        };
        assert_eq!(sparse.apply_batch(&batch).unwrap(), expected);
        assert_eq!(sparse.state_root(), complete.state_root());
        assert_eq!(sparse.anchor(), complete.anchor());
        // Every retained original node was required by the deterministic run.
        for index in 0..witness.nodes.len() {
            let mut missing = witness.clone();
            missing.nodes.remove(index);
            let db = SparseDb::from_witness(&before, &missing).unwrap();
            let mut rejected = original.clone().with_backend(db).unwrap();
            assert!(
                rejected.apply_batch(&batch).is_err(),
                "missing node {index}"
            );
            assert_eq!(rejected.state_root(), before.state_root);
            assert_eq!(rejected.head_hash(), before.header_hash);
            assert_eq!(rejected.anchor(), &before.anchor);
        }
        let mut wrong_code = witness.clone();
        assert!(!wrong_code.codes.is_empty());
        wrong_code.codes[0] = Bytes::from_static(&[0x00]);
        let db = SparseDb::from_witness(&before, &wrong_code).unwrap();
        assert!(original
            .with_backend(db)
            .unwrap()
            .apply_batch(&batch)
            .is_err());
        headers.extend(expected.into_iter().map(|b| b.header));
    }
}

#[test]
fn verified_absence_is_distinct_from_missing_witness_and_bad_headers() {
    let complete = Executor::new(&vectors::genesis()).unwrap();
    let before = boundary(&complete);
    let headers = vec![complete.head().clone()];
    let mut db = SparseDb::from_complete(&complete, headers.clone()).unwrap();
    let unknown = Address::repeat_byte(0xee);
    assert!(db.basic(unknown).unwrap().is_none());
    assert_eq!(db.storage(unknown, U256::ZERO).unwrap(), U256::ZERO);
    let mut witness = db.required_witness(headers);
    let mut verified = SparseDb::from_witness(&before, &witness).unwrap();
    assert!(verified.basic(unknown).unwrap().is_none());
    assert!(matches!(
        verified.block_hash(1),
        Err(StateError::MissingHeader(1))
    ));
    witness.nodes.clear();
    let mut missing = SparseDb::from_witness(&before, &witness).unwrap();
    assert!(missing.basic(unknown).is_err());
    witness.recent_headers[0].timestamp += 1;
    assert!(SparseDb::from_witness(&before, &witness).is_err());
}

#[test]
fn failed_sparse_commit_rolls_back_prior_successful_writes() {
    use revm::{primitives::AddressMap, state::Account};
    let complete = Executor::new(&vectors::genesis()).unwrap();
    let mut db = SparseDb::from_complete(&complete, vec![complete.head().clone()]).unwrap();
    let root = db.calculate_state_root().unwrap();
    db.begin_batch();
    let sender = vectors::sender();
    let mut changed = Account::from(db.basic(sender).unwrap().unwrap());
    changed.mark_touch();
    changed.info.balance -= U256::from(1);
    db.commit_changes(AddressMap::from_iter([(sender, changed)]))
        .unwrap();
    assert_ne!(db.calculate_state_root().unwrap(), root);
    db.record_header(1, alloy_primitives::B256::repeat_byte(1));
    db.rollback_batch();
    assert_eq!(db.calculate_state_root().unwrap(), root);
    assert_eq!(
        db.basic(sender).unwrap().unwrap().balance,
        complete.account(sender).unwrap().balance
    );
    assert_eq!(db.cached_header_hash(1), None);
    // Rollback permits a clean retry rather than retaining a stale transaction.
    db.begin_batch();
    db.accept_batch();
}

#[test]
fn sparse_blockhash_window_preserves_recent_oldest_and_out_of_range_reads() {
    let contract = Address::repeat_byte(0x88);
    let mut genesis = vectors::genesis();
    genesis.accounts.insert(
        contract,
        GenesisAccount {
            nonce: 1,
            code: Bytes::from_static(&[0x5f, 0x35, 0x40, 0x5f, 0x52, 0x60, 0x20, 0x5f, 0xf3]),
            ..Default::default()
        },
    );
    let mut full = Executor::new(&genesis).unwrap();
    let mut headers = vec![full.head().clone()];
    for _ in 0..260 {
        let batch = input(&full, vec![]);
        headers.extend(
            full.apply_batch(&batch)
                .unwrap()
                .into_iter()
                .map(|b| b.header),
        );
        if headers.len() > 256 {
            headers.remove(0);
        }
    }
    let before = boundary(&full);
    let expected_hashes = [
        headers[255].hash_slow(),
        headers[0].hash_slow(),
        alloy_primitives::B256::ZERO,
    ];
    let transactions = [260u64, 5, 4]
        .into_iter()
        .enumerate()
        .map(|(nonce, number)| {
            let mut tx = vectors::tx(nonce as u64);
            tx.to = TxKind::Call(contract);
            tx.input = U256::from(number).to_be_bytes::<32>().to_vec().into();
            vectors::sign(tx)
        })
        .collect();
    let batch = input(&full, transactions);
    let db = SparseDb::from_complete(&full, headers.clone()).unwrap();
    let mut discovery = full.clone().with_backend(db).unwrap();
    let expected = full.apply_batch(&batch).unwrap();
    assert_eq!(discovery.apply_batch(&batch).unwrap(), expected);
    let witness = discovery.backend().required_witness(headers);
    let db = SparseDb::from_witness(&before, &witness).unwrap();
    let mut sparse = Executor::from_state(
        db,
        before.anchor,
        witness.recent_headers.last().unwrap().clone(),
    )
    .unwrap();
    assert_eq!(sparse.apply_batch(&batch).unwrap(), expected);
    for (outcome, hash) in expected[0].outcomes.iter().zip(expected_hashes) {
        assert_eq!(outcome.status, tactus_o1_execution::Status::Success);
        assert_eq!(outcome.output.as_ref(), hash.as_slice());
    }
    let mut missing = witness.clone();
    missing.recent_headers.remove(0);
    assert!(SparseDb::from_witness(&before, &missing).is_err());
    let mut changed = witness;
    changed.recent_headers[0].timestamp += 1;
    assert!(SparseDb::from_witness(&before, &changed).is_err());
}

#[test]
fn transaction_reads_observe_pending_writes_and_each_block_gets_its_own_root() {
    let contract = Address::repeat_byte(0x77);
    let mut genesis = vectors::genesis();
    genesis.accounts.insert(
        contract,
        GenesisAccount {
            nonce: 1,
            // Increment slot zero and return the updated value.
            code: Bytes::from_static(&[
                0x5f, 0x54, 0x60, 0x01, 0x01, 0x80, 0x5f, 0x55, 0x5f, 0x52, 0x60, 0x20, 0x5f, 0xf3,
            ]),
            ..Default::default()
        },
    );
    let mut full = Executor::new(&genesis).unwrap();
    let original = full.clone();
    let before = boundary(&full);
    let headers = vec![full.head().clone()];
    let db = SparseDb::from_complete(&full, headers.clone()).unwrap();
    let mut discovery = full.clone().with_backend(db).unwrap();
    let transactions: Vec<_> = (0..10)
        .map(|nonce| {
            let mut tx = vectors::tx(nonce);
            tx.to = TxKind::Call(contract);
            vectors::sign(tx)
        })
        .collect();
    let batch = BatchInput {
        parent: *full.anchor(),
        blocks: vec![
            BlockInput {
                timestamp: 1,
                fee_recipient: [3; 20],
                transactions: transactions[..8].to_vec(),
            },
            BlockInput {
                timestamp: 2,
                fee_recipient: [3; 20],
                transactions: transactions[8..].to_vec(),
            },
        ],
    }
    .encode()
    .unwrap();
    let expected = full.apply_batch(&batch).unwrap();
    assert_ne!(expected[0].header.state_root, expected[1].header.state_root);
    for (index, outcome) in expected
        .iter()
        .flat_map(|block| &block.outcomes)
        .enumerate()
    {
        assert_eq!(outcome.status, tactus_o1_execution::Status::Success);
        assert_eq!(
            outcome.output.as_ref(),
            U256::from(index + 1).to_be_bytes::<32>()
        );
    }
    assert_eq!(discovery.apply_batch(&batch).unwrap(), expected);
    let witness = discovery.backend().required_witness(headers);
    let db = SparseDb::from_witness(&before, &witness).unwrap();
    let mut pruned = original.with_backend(db).unwrap();
    assert_eq!(pruned.apply_batch(&batch).unwrap(), expected);
    assert_eq!(pruned.state_root(), full.state_root());
}

#[test]
fn pending_zeroes_and_recreated_accounts_do_not_expose_old_storage() {
    use revm::{
        primitives::AddressMap,
        state::{Account, AccountInfo, Bytecode, EvmStorageSlot},
    };
    let contract = Address::repeat_byte(0x66);
    let code = Bytes::from_static(&[0x00]);
    let mut genesis = vectors::genesis();
    genesis.accounts.insert(
        contract,
        GenesisAccount {
            nonce: 1,
            code: code.clone(),
            storage: std::collections::BTreeMap::from([
                (U256::ZERO, U256::from(99)),
                (U256::from(2), U256::from(77)),
            ]),
            ..Default::default()
        },
    );
    let full = Executor::new(&genesis).unwrap();
    let mut db = SparseDb::from_complete(&full, vec![full.head().clone()]).unwrap();
    db.begin_batch();
    let mut clear = Account::from(db.basic(contract).unwrap().unwrap());
    clear.mark_touch();
    clear.storage.insert(
        U256::ZERO,
        EvmStorageSlot::new_changed(U256::from(99), U256::ZERO, revm::state::TransactionId::ZERO),
    );
    db.commit_changes(AddressMap::from_iter([(contract, clear)]))
        .unwrap();
    assert_eq!(db.storage(contract, U256::ZERO).unwrap(), U256::ZERO);
    assert_eq!(db.storage(contract, U256::from(2)).unwrap(), U256::from(77));
    let mut destroyed = Account::from(db.basic(contract).unwrap().unwrap());
    destroyed.mark_touch();
    destroyed.mark_selfdestruct();
    db.commit_changes(AddressMap::from_iter([(contract, destroyed)]))
        .unwrap();
    assert!(db.basic(contract).unwrap().is_none());
    assert_eq!(db.storage(contract, U256::from(2)).unwrap(), U256::ZERO);
    let runtime = Bytecode::new_legacy(code);
    let mut recreated = Account::from(AccountInfo::new(
        U256::ZERO,
        1,
        runtime.hash_slow(),
        runtime,
    ));
    recreated.mark_touch();
    recreated.mark_created();
    recreated.storage.insert(
        U256::from(1),
        EvmStorageSlot::new_changed(U256::ZERO, U256::from(42), revm::state::TransactionId::ZERO),
    );
    db.commit_changes(AddressMap::from_iter([(contract, recreated)]))
        .unwrap();
    assert_eq!(db.storage(contract, U256::ZERO).unwrap(), U256::ZERO);
    assert_eq!(db.storage(contract, U256::from(2)).unwrap(), U256::ZERO);
    assert_eq!(db.storage(contract, U256::from(1)).unwrap(), U256::from(42));
    // A fresh complete-state construction is independent of sparse update paths.
    genesis.accounts.get_mut(&contract).unwrap().storage =
        std::collections::BTreeMap::from([(U256::from(1), U256::from(42))]);
    let expected = Executor::new(&genesis).unwrap();
    assert_eq!(db.calculate_state_root().unwrap(), expected.state_root());
    assert_eq!(db.storage(contract, U256::from(2)).unwrap(), U256::ZERO);
    db.rollback_batch();
    assert_eq!(db.calculate_state_root().unwrap(), full.state_root());
    assert_eq!(db.storage(contract, U256::ZERO).unwrap(), U256::from(99));
    assert_eq!(db.storage(contract, U256::from(2)).unwrap(), U256::from(77));
}

#[test]
fn omitted_deletion_sibling_fails_at_flush_and_allows_rollback() {
    use revm::{primitives::AddressMap, state::Account};
    let mut genesis = vectors::genesis();
    let other = Address::repeat_byte(0xaa);
    genesis.accounts.insert(
        other,
        GenesisAccount {
            balance: U256::from(1),
            ..Default::default()
        },
    );
    let full = Executor::new(&genesis).unwrap();
    let before = boundary(&full);
    let headers = vec![full.head().clone()];
    let mut discovery = SparseDb::from_complete(&full, headers.clone()).unwrap();
    let sender = vectors::sender();
    discovery.basic(sender).unwrap();
    // This proves the sender read, but does not reveal the other account leaf
    // needed when deleting the sender collapses the two-account branch.
    let witness = discovery.required_witness(headers);
    let mut db = SparseDb::from_witness(&before, &witness).unwrap();
    db.begin_batch();
    let mut destroyed = Account::from(db.basic(sender).unwrap().unwrap());
    destroyed.mark_touch();
    destroyed.mark_selfdestruct();
    db.commit_changes(AddressMap::from_iter([(sender, destroyed)]))
        .unwrap();
    assert!(db.calculate_state_root().is_err());
    assert!(db.calculate_state_root().is_err());
    db.rollback_batch();
    assert_eq!(db.calculate_state_root().unwrap(), before.state_root);
    assert_eq!(
        db.basic(sender).unwrap().unwrap().balance,
        full.account(sender).unwrap().balance
    );
}

#[test]
fn binary_witness_rejects_truncation_trailing_data_noncanonical_headers_and_limits() {
    use tactus_o1_sparse_state::database::Witness;
    let full = Executor::new(&vectors::genesis()).unwrap();
    let witness = Witness {
        nodes: vec![],
        codes: vec![],
        recent_headers: vec![full.head().clone()],
    };
    let bytes = witness.encode().unwrap();
    assert_eq!(Witness::decode(&bytes).unwrap(), witness);
    for end in 0..bytes.len() {
        assert!(Witness::decode(&bytes[..end]).is_err(), "truncation {end}");
    }
    let mut changed = bytes.clone();
    changed.push(0);
    assert!(Witness::decode(&changed).is_err());
    let mut changed = bytes.clone();
    changed[0] ^= 1;
    assert!(Witness::decode(&changed).is_err());
    let mut changed = bytes.clone();
    changed[8..12].copy_from_slice(&u32::MAX.to_le_bytes());
    assert_eq!(Witness::decode(&changed), Err(StateError::Limit));
    for count in [0u32, 257] {
        let mut changed = bytes.clone();
        changed[16..20].copy_from_slice(&count.to_le_bytes());
        assert_eq!(Witness::decode(&changed), Err(StateError::Limit));
    }
    let mut changed = bytes.clone();
    changed[20..24].copy_from_slice(&u32::MAX.to_le_bytes());
    assert_eq!(Witness::decode(&changed), Err(StateError::Limit));
    // A long-list RLP length with an extra leading zero is noncanonical even
    // though it would describe the same header payload if accepted leniently.
    let header = &bytes[24..];
    assert!((0xf8..0xff).contains(&header[0]));
    let mut changed = bytes[..20].to_vec();
    changed.extend_from_slice(&((header.len() + 1) as u32).to_le_bytes());
    changed.push(header[0] + 1);
    changed.push(0);
    changed.extend_from_slice(&header[1..]);
    assert!(Witness::decode(&changed).is_err());
    let mut oversized = witness.clone();
    oversized.codes.push(Bytes::from(vec![
        0;
        tactus_o1_protocol::genesis::MAX_CODE_BYTES
            + 1
    ]));
    assert_eq!(oversized.encode(), Err(StateError::Limit));
    let mut oversized = witness.clone();
    oversized.nodes.push(Bytes::from(vec![0; 1025]));
    assert_eq!(oversized.encode(), Err(StateError::Limit));
    let mut oversized = witness;
    oversized.recent_headers[0].extra_data = Bytes::from(vec![0; 3000]);
    assert_eq!(oversized.encode(), Err(StateError::Limit));
}
