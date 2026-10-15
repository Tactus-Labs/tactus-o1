use alloy_consensus::{SignableTransaction, TxEip1559, TxEip2930, TxEnvelope, TxLegacy};
use alloy_eips::{
    eip2718::Encodable2718,
    eip2930::{AccessList, AccessListItem},
};
use alloy_primitives::{address, b256, hex, Address, Bytes, Signature, TxKind, B256, U256};
use k256::ecdsa::SigningKey;
use std::collections::BTreeMap;
use tactus_o1_execution::{next_base_fee, Executor, Genesis, GenesisAccount, Status};
use tactus_o1_protocol::batch::{BatchInput, BlockInput, BLOCK_GAS_LIMIT};

const RECIPIENT: Address = address!("1111111111111111111111111111111111111111");
const BUILDER: Address = address!("2222222222222222222222222222222222222222");
const CONTRACT: Address = address!("3333333333333333333333333333333333333333");

#[test]
fn generated_rules_digest_matches_runtime_reference() {
    let mut descriptor = include_bytes!("../rules-v1.txt").to_vec();
    descriptor.extend_from_slice(include_bytes!("../../../Cargo.lock"));
    assert_eq!(
        tactus_o1_execution::rules_hash(),
        tactus_o1_protocol::batch::hash(b"tactus/o1/execution-rules/v1", &descriptor)
    );
}
fn key() -> SigningKey {
    SigningKey::from_bytes((&[0x21; 32]).into()).unwrap()
}
fn sender() -> Address {
    Address::from_public_key(key().verifying_key())
}
fn genesis() -> Genesis {
    Genesis {
        rollup_id: B256::repeat_byte(7),
        chain_id: 31337,
        accounts: BTreeMap::from([(
            sender(),
            GenesisAccount {
                balance: U256::from(10u64.pow(18)),
                ..Default::default()
            },
        )]),
    }
}
fn signature(tx: &impl SignableTransaction<Signature>) -> Signature {
    key()
        .sign_prehash_recoverable(tx.signature_hash().as_slice())
        .unwrap()
        .into()
}
fn tx(nonce: u64) -> TxEip1559 {
    TxEip1559 {
        chain_id: 31337,
        nonce,
        gas_limit: 100_000,
        max_fee_per_gas: 2_000_000_000,
        max_priority_fee_per_gas: 1_000_000_000,
        to: TxKind::Call(RECIPIENT),
        value: U256::from(123),
        ..Default::default()
    }
}
fn sign(tx: TxEip1559) -> Vec<u8> {
    let sig = signature(&tx);
    TxEnvelope::from(tx.into_signed(sig)).encoded_2718()
}
fn batch(engine: &Executor, blocks: Vec<Vec<Vec<u8>>>) -> Vec<u8> {
    BatchInput {
        parent: *engine.anchor(),
        blocks: blocks
            .into_iter()
            .map(|transactions| BlockInput {
                timestamp: 10.max(engine.head().timestamp),
                fee_recipient: BUILDER.0 .0,
                transactions,
            })
            .collect(),
    }
    .encode()
    .unwrap()
}
fn run(engine: &mut Executor, slots: Vec<Vec<u8>>) -> tactus_o1_execution::ExecutedBlock {
    let input = batch(engine, vec![slots]);
    engine.apply_batch(&input).unwrap().remove(0)
}
fn contract_genesis(code: &[u8]) -> Genesis {
    let mut config = genesis();
    config.accounts.insert(
        CONTRACT,
        GenesisAccount {
            nonce: 1,
            code: Bytes::copy_from_slice(code),
            ..Default::default()
        },
    );
    config
}

#[test]
fn malformed_nonce_and_balance_failures_do_not_poison_following_transfers() {
    let mut engine = Executor::new(&genesis()).unwrap();
    let mut too_expensive = tx(1);
    too_expensive.value = U256::MAX;
    let block = run(
        &mut engine,
        vec![
            vec![2, 1, 2],
            sign(tx(1)),
            sign(tx(0)),
            sign(tx(0)),
            sign(too_expensive),
            sign(tx(1)),
        ],
    );
    assert_eq!(
        block.outcomes.iter().map(|o| o.status).collect::<Vec<_>>(),
        vec![
            Status::Malformed,
            Status::InvalidTransaction,
            Status::Success,
            Status::InvalidTransaction,
            Status::InvalidTransaction,
            Status::Success
        ]
    );
    assert_eq!(block.header.gas_used, 42_000);
    assert_eq!(block.transactions.len(), 2);
    assert_eq!(
        block
            .receipts
            .iter()
            .map(|r| r.cumulative_gas_used())
            .collect::<Vec<_>>(),
        vec![21_000, 42_000]
    );
    assert_eq!(block.outcomes[5].transaction_index, Some(1));
    assert_eq!(engine.account(RECIPIENT).unwrap().balance, U256::from(246));
    let sender = engine.account(sender()).unwrap();
    assert_eq!(sender.nonce, 2);
    assert_eq!(
        sender.balance,
        U256::from(10u64.pow(18) - 42_000 * 1_875_000_000 - 246)
    );
    assert_eq!(
        engine.account(BUILDER).unwrap().balance,
        U256::from(42_000 * 1_000_000_000u64)
    );
}

#[test]
fn legacy_access_list_and_dynamic_fee_envelopes_make_matching_receipts() {
    let mut engine = Executor::new(&genesis()).unwrap();
    let legacy = TxLegacy {
        chain_id: Some(31337),
        nonce: 0,
        gas_price: 2_000_000_000,
        gas_limit: 21_000,
        to: TxKind::Call(RECIPIENT),
        value: U256::from(1),
        ..Default::default()
    };
    let sig = signature(&legacy);
    let legacy = TxEnvelope::from(legacy.into_signed(sig)).encoded_2718();
    let access = TxEip2930 {
        chain_id: 31337,
        nonce: 1,
        gas_price: 2_000_000_000,
        gas_limit: 30_000,
        to: TxKind::Call(RECIPIENT),
        value: U256::from(1),
        access_list: AccessList(vec![AccessListItem {
            address: CONTRACT,
            storage_keys: vec![B256::ZERO],
        }]),
        ..Default::default()
    };
    let sig = signature(&access);
    let access = TxEnvelope::from(access.into_signed(sig)).encoded_2718();
    let block = run(&mut engine, vec![legacy, access, sign(tx(2))]);
    assert!(block.outcomes.iter().all(|o| o.status == Status::Success));
    assert_eq!(
        block
            .outcomes
            .iter()
            .map(|o| o.gas_used)
            .collect::<Vec<_>>(),
        vec![21_000, 25_300, 21_000]
    );
    assert_eq!(
        block
            .receipts
            .iter()
            .map(|r| r.tx_type() as u8)
            .collect::<Vec<_>>(),
        vec![0, 1, 2]
    );
}

#[test]
fn signature_chain_canonical_encoding_and_type_rejections_are_total() {
    let mut engine = Executor::new(&genesis()).unwrap();
    let transaction = tx(0);
    let low = signature(&transaction);
    let curve_order = U256::from_be_bytes(hex!(
        "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"
    ));
    let high = Signature::new(low.r(), curve_order - low.s(), !low.v());
    let high = TxEnvelope::from(transaction.clone().into_signed(high)).encoded_2718();
    let zero =
        TxEnvelope::from(transaction.into_signed(Signature::new(U256::ZERO, U256::ZERO, false)))
            .encoded_2718();
    let mut wrong = tx(0);
    wrong.chain_id = 1;
    let unprotected = TxLegacy {
        chain_id: None,
        nonce: 0,
        gas_price: 2_000_000_000,
        gas_limit: 21_000,
        to: TxKind::Call(RECIPIENT),
        ..Default::default()
    };
    let sig = signature(&unprotected);
    let unprotected = TxEnvelope::from(unprotected.into_signed(sig)).encoded_2718();
    let mut trailing = sign(tx(0));
    trailing.push(0);
    let block = run(
        &mut engine,
        vec![
            high,
            zero,
            sign(wrong),
            unprotected,
            trailing,
            vec![3],
            vec![4],
            vec![0],
            sign(tx(0)),
        ],
    );
    assert_eq!(
        block.outcomes.iter().map(|o| o.status).collect::<Vec<_>>(),
        vec![
            Status::InvalidSignature,
            Status::InvalidSignature,
            Status::WrongChain,
            Status::WrongChain,
            Status::Malformed,
            Status::UnsupportedType,
            Status::UnsupportedType,
            Status::Malformed,
            Status::Success
        ]
    );
    assert_eq!(engine.account(sender()).unwrap().nonce, 1);
}

#[test]
fn deploy_then_write_storage_and_log_then_clear_slot() {
    let mut engine = Executor::new(&genesis()).unwrap();
    // Runtime: calldata word -> slot zero, then LOG0(empty). Uses Shanghai PUSH0.
    let runtime = hex!("5f355f555f5fa000");
    let mut init = hex!("6008600c60003960086000f3").to_vec();
    // Runtime begins immediately after the 12-byte constructor.
    init.extend(runtime);
    let mut create = tx(0);
    create.to = TxKind::Create;
    create.value = U256::ZERO;
    create.input = init.into();
    let created = sender().create(0);
    let mut write = tx(1);
    write.to = TxKind::Call(created);
    write.value = U256::ZERO;
    write.input = U256::from(42).to_be_bytes::<32>().to_vec().into();
    let block = run(&mut engine, vec![sign(create), sign(write)]);
    assert_eq!(block.outcomes[0].created_address, Some(created));
    assert_eq!(engine.account(created).unwrap().code.as_ref(), runtime);
    assert_eq!(
        engine.account(created).unwrap().storage.get(&U256::ZERO),
        Some(&U256::from(42))
    );
    assert_eq!(block.receipts[1].logs().len(), 1);
    assert_ne!(block.header.logs_bloom, alloy_primitives::Bloom::ZERO);
    let mut clear = tx(2);
    clear.to = TxKind::Call(created);
    clear.value = U256::ZERO;
    let clear_block = run(&mut engine, vec![sign(clear)]);
    assert_eq!(clear_block.outcomes[0].status, Status::Success);
    assert!(engine.account(created).unwrap().storage.is_empty());
    assert!(clear_block.outcomes[0].gas_used < block.outcomes[1].gas_used);
}

#[test]
fn revert_and_exception_charge_nonce_and_gas_but_revert_storage_and_logs() {
    for (code, status) in [
        (hex!("602a5f555f5fa05f5ffd").to_vec(), Status::Revert),
        (hex!("602a5f555f5fa0fe").to_vec(), Status::Halt),
    ] {
        let mut engine = Executor::new(&contract_genesis(&code)).unwrap();
        let mut call = tx(0);
        call.to = TxKind::Call(CONTRACT);
        call.value = U256::ZERO;
        let block = run(&mut engine, vec![sign(call), sign(tx(1))]);
        assert_eq!(block.outcomes[0].status, status);
        assert!(!block.receipts[0].status());
        assert!(block.receipts[0].logs().is_empty());
        assert!(engine.account(CONTRACT).unwrap().storage.is_empty());
        assert_eq!(engine.account(sender()).unwrap().nonce, 2);
        if status == Status::Halt {
            assert_eq!(block.outcomes[0].gas_used, 100_000);
        } else {
            assert!(block.outcomes[0].gas_used < 100_000);
        }
    }
}

#[test]
fn invalid_fee_intrinsic_gas_and_eoa_code_do_not_mutate_state() {
    let mut engine = Executor::new(&genesis()).unwrap();
    let initial = engine.state_root();
    let mut low_fee = tx(0);
    low_fee.max_fee_per_gas = 1;
    let mut priority = tx(0);
    priority.max_priority_fee_per_gas = 3_000_000_000;
    let mut intrinsic = tx(0);
    intrinsic.gas_limit = 20_999;
    let block = run(
        &mut engine,
        vec![sign(low_fee), sign(priority), sign(intrinsic)],
    );
    assert!(block
        .outcomes
        .iter()
        .all(|o| o.status == Status::InvalidTransaction));
    assert_eq!(engine.state_root(), initial);
    let mut config = genesis();
    config.accounts.get_mut(&sender()).unwrap().code = Bytes::from_static(&[0]);
    let mut engine = Executor::new(&config).unwrap();
    assert_eq!(
        run(&mut engine, vec![sign(tx(0))]).outcomes[0].status,
        Status::InvalidTransaction
    );
}

#[test]
fn remaining_block_gas_checks_declared_limit_without_stalling_next_slot() {
    let mut engine = Executor::new(&contract_genesis(&[0xfe])).unwrap();
    let mut exhaust = tx(0);
    exhaust.to = TxKind::Call(CONTRACT);
    exhaust.gas_limit = 980_000;
    let mut over = tx(1);
    over.gas_limit = 21_000;
    let block = run(&mut engine, vec![sign(exhaust), sign(over)]);
    assert_eq!(block.outcomes[0].status, Status::Halt);
    assert_eq!(block.outcomes[1].status, Status::BlockGas);
    assert_eq!(block.header.gas_used, 980_000);
    assert_eq!(
        run(&mut engine, vec![sign(tx(1))]).outcomes[0].status,
        Status::Success
    );
}

#[test]
fn block_context_parent_hash_and_empty_blocks_are_executed() {
    // NUMBER,TIMESTAMP,BASEFEE,COINBASE,CHAINID,PREVRANDAO,GASLIMIT,
    // BLOCKHASH(NUMBER-1), each to its own slot.
    let code = hex!("435f55426001554860025541600355466004554460055545600655600143034060075500");
    let config = contract_genesis(&code);
    let mut engine = Executor::new(&config).unwrap();
    let genesis_hash = engine.head().hash_slow();
    let mut call = tx(0);
    call.to = TxKind::Call(CONTRACT);
    call.value = U256::ZERO;
    call.gas_limit = 300_000;
    let bytes = batch(
        &engine,
        vec![
            vec![sign(call.clone())],
            vec![],
            vec![{
                call.nonce = 1;
                sign(call)
            }],
        ],
    );
    let blocks = engine.apply_batch(&bytes).unwrap();
    assert_eq!(blocks[0].header.parent_hash, genesis_hash);
    assert_eq!(blocks[1].header.parent_hash, blocks[0].hash);
    assert_eq!(blocks[1].header.gas_used, 0);
    assert_eq!(
        blocks[2].header.base_fee_per_gas,
        Some(next_base_fee(blocks[1].header.base_fee_per_gas.unwrap(), 0).unwrap())
    );
    let state = engine.account(CONTRACT).unwrap().storage;
    assert_eq!(state[&U256::ZERO], U256::from(3));
    assert_eq!(state[&U256::from(1)], U256::from(10));
    assert_eq!(
        state[&U256::from(2)],
        U256::from(blocks[2].header.base_fee_per_gas.unwrap())
    );
    assert_eq!(
        state[&U256::from(3)],
        U256::from_be_slice(BUILDER.as_slice())
    );
    assert_eq!(state[&U256::from(4)], U256::from(31337));
    assert!(!state.contains_key(&U256::from(5)));
    assert_eq!(state[&U256::from(6)], U256::from(BLOCK_GAS_LIMIT));
    assert_eq!(
        state[&U256::from(7)],
        U256::from_be_slice(blocks[1].hash.as_slice())
    );
    let mut replay = Executor::new(&config).unwrap();
    assert_eq!(replay.apply_batch(&bytes).unwrap(), blocks);
    assert_eq!(replay.state_root(), engine.state_root());
}

#[test]
fn precompiles_use_real_sha256_and_identity() {
    let mut engine = Executor::new(&genesis()).unwrap();
    let mut sha = tx(0);
    sha.to = TxKind::Call(Address::with_last_byte(2));
    sha.input = Bytes::from_static(b"abc");
    sha.value = U256::ZERO;
    let mut identity = sha.clone();
    identity.nonce = 1;
    identity.to = TxKind::Call(Address::with_last_byte(4));
    let block = run(&mut engine, vec![sign(sha), sign(identity)]);
    assert_eq!(
        block.outcomes[0].output.as_ref(),
        b256!("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad").as_slice()
    );
    assert_eq!(block.outcomes[1].output.as_ref(), b"abc");
}

#[test]
fn truncated_batch_wrong_domain_and_replay_do_not_leave_partial_execution() {
    let mut engine = Executor::new(&genesis()).unwrap();
    let input = batch(&engine, vec![vec![sign(tx(0))], vec![]]);
    let initial = (
        engine.anchor().encode(),
        engine.head().clone(),
        engine.state_root(),
    );
    for end in 0..input.len() {
        assert!(engine.apply_batch(&input[..end]).is_err());
        assert_eq!(
            (
                engine.anchor().encode(),
                engine.head().clone(),
                engine.state_root()
            ),
            initial
        );
    }
    let mut wrong = input.clone();
    wrong[88] ^= 1;
    assert!(engine.apply_batch(&wrong).is_err());
    let decoded = BatchInput::decode(&input, engine.anchor()).unwrap();
    assert_eq!(decoded.blocks.len(), 2);
    assert!(decoded.blocks[1].transactions.is_empty());
    engine.apply_batch(&input).unwrap();
    let done = engine.state_root();
    assert!(engine.apply_batch(&input).is_err());
    assert_eq!(engine.state_root(), done);
}

#[test]
fn rejected_slots_are_committed_even_when_ethereum_state_and_roots_match() {
    let mut a = Executor::new(&genesis()).unwrap();
    let mut b = a.clone();
    let block_a = run(&mut a, vec![vec![2, 1, 2]]);
    let block_b = run(&mut b, vec![vec![2, 1, 3]]);
    assert_eq!(block_a.header.state_root, block_b.header.state_root);
    assert_eq!(
        block_a.header.transactions_root,
        block_b.header.transactions_root
    );
    assert_eq!(block_a.header.receipts_root, block_b.header.receipts_root);
    assert_ne!(block_a.hash, block_b.hash);
}

#[test]
fn basefee_rounding_supply_bound_and_genesis_domain_are_explicit() {
    assert_eq!(next_base_fee(1_000_000_000, 0).unwrap(), 875_000_000);
    assert_eq!(
        next_base_fee(1_000_000_000, 500_000).unwrap(),
        1_000_000_000
    );
    assert_eq!(
        next_base_fee(1_000_000_000, 1_000_000).unwrap(),
        1_125_000_000
    );
    assert_eq!(next_base_fee(1, 500_001).unwrap(), 2);
    assert_eq!(next_base_fee(1, 0).unwrap(), 1);
    assert!(next_base_fee(u64::MAX, 1_000_000).is_err());
    let mut config = genesis();
    config.accounts.get_mut(&sender()).unwrap().balance = U256::MAX;
    assert!(Executor::new(&config).is_err());
    let mut a = genesis();
    let original = Executor::new(&a).unwrap();
    a.chain_id += 1;
    assert_ne!(
        original.head().hash_slow(),
        Executor::new(&a).unwrap().head().hash_slow()
    );
}
