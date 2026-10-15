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
