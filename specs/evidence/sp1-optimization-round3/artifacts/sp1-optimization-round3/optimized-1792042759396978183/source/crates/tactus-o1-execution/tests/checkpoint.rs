use alloy_primitives::{Address, Bytes, B256, U256};
use std::collections::BTreeMap;
use tactus_o1_execution::{
    checkpoint::{Checkpoint, CheckpointError},
    Executor, Genesis, GenesisAccount,
};
use tactus_o1_protocol::batch::{BatchInput, BlockInput};
#[allow(dead_code)]
#[path = "../examples/execution-vectors.rs"]
mod vectors;

fn genesis() -> Genesis {
    Genesis {
        rollup_id: B256::repeat_byte(7),
        chain_id: 31337,
        accounts: BTreeMap::from([
            (
                Address::repeat_byte(1),
                GenesisAccount {
                    balance: U256::from(1000),
                    ..Default::default()
                },
            ),
            (
                Address::repeat_byte(2),
                GenesisAccount {
                    nonce: 1,
                    code: Bytes::from_static(&[0x60, 0x01, 0x00]),
                    storage: BTreeMap::from([(U256::from(5), U256::from(99))]),
                    ..Default::default()
                },
            ),
        ]),
    }
}
fn next(engine: &Executor) -> Vec<u8> {
    BatchInput {
        parent: *engine.anchor(),
        blocks: vec![BlockInput {
            timestamp: engine.head().timestamp + 1,
            fee_recipient: [3; 20],
            transactions: vec![],
        }],
    }
    .encode()
    .unwrap()
}

#[test]
fn checkpoint_continuation_matches_full_history_across_blockhash_window() {
    let genesis = genesis();
    let mut engine = Executor::new(&genesis).unwrap();
    let mut headers = vec![engine.head().clone()];
    for height in 1..=260 {
        let blocks = engine.apply_batch(&next(&engine)).unwrap();
        headers.push(blocks[0].header.clone());
        if headers.len() > 256 {
            headers.remove(0);
        }
        if [1, 255, 256, 260].contains(&height) {
            let (boundary, snapshot) = Checkpoint::capture(&engine, headers.clone()).unwrap();
            let bytes = snapshot.encode().unwrap();
            let decoded = Checkpoint::decode(&bytes).unwrap();
            let mut restored = decoded
                .restore(genesis.rollup_id, genesis.chain_id, &boundary)
                .unwrap();
            let mut replay = engine.clone();
            let input = next(&replay);
            assert_eq!(
                restored.apply_batch(&input).unwrap(),
                replay.apply_batch(&input).unwrap()
            );
            assert_eq!(restored.state_root(), replay.state_root());
            assert_eq!(restored.head_hash(), replay.head_hash());
            assert_eq!(restored.anchor(), replay.anchor());
            assert_eq!(
                restored
                    .accounts()
                    .collect::<Vec<_>>()
                    .into_iter()
                    .collect::<BTreeMap<_, _>>(),
                replay.accounts().collect::<BTreeMap<_, _>>()
            );
        }
    }
}

#[test]
fn forged_omitted_or_mismatched_checkpoint_material_is_rejected() {
    let genesis = genesis();
    let mut engine = Executor::new(&genesis).unwrap();
    assert!(Checkpoint::capture(&engine, vec![engine.head().clone()]).is_err());
    let mut headers = vec![engine.head().clone()];
    headers.extend(
        engine
            .apply_batch(&next(&engine))
            .unwrap()
            .into_iter()
            .map(|b| b.header),
    );
    let (boundary, snapshot) = Checkpoint::capture(&engine, headers).unwrap();
    let restore =
        |snapshot: &Checkpoint| snapshot.restore(genesis.rollup_id, genesis.chain_id, &boundary);
    for variant in 0..7 {
        let mut changed = snapshot.clone();
        match variant {
            0 => {
                changed.accounts.remove(&Address::repeat_byte(1));
            }
            1 => {
                changed
                    .accounts
                    .get_mut(&Address::repeat_byte(1))
                    .unwrap()
                    .balance += U256::from(1);
            }
            2 => {
                changed
                    .accounts
                    .get_mut(&Address::repeat_byte(2))
                    .unwrap()
                    .storage
                    .clear();
            }
            3 => {
                changed
                    .accounts
                    .get_mut(&Address::repeat_byte(2))
                    .unwrap()
                    .code = vec![0x00].into();
            }
            4 => {
                changed.recent_headers.remove(0);
            }
            5 => {
                changed.recent_headers[0].timestamp += 1;
            }
            6 => {
                changed.recent_headers[1].base_fee_per_gas = Some(42);
            }
            _ => unreachable!(),
        }
        assert!(restore(&changed).is_err(), "variant {variant}");
    }
    assert_eq!(
        snapshot
            .restore(B256::repeat_byte(8), genesis.chain_id, &boundary)
            .unwrap_err(),
        CheckpointError::Domain
    );
    let mut wrong = boundary.clone();
    wrong.header_hash = B256::ZERO;
    assert_eq!(
        snapshot
            .restore(genesis.rollup_id, genesis.chain_id, &wrong)
            .unwrap_err(),
        CheckpointError::Header
    );
    let mut wrong = boundary;
    wrong.state_root = B256::ZERO;
    assert!(snapshot
        .restore(genesis.rollup_id, genesis.chain_id, &wrong)
        .is_err());
    let mut encoded = snapshot.encode().unwrap();
    encoded.push(b'x');
    assert_eq!(
        Checkpoint::decode(&encoded).unwrap_err(),
        CheckpointError::Encoding
    );
}

#[test]
fn restored_recent_headers_preserve_blockhash_at_both_window_edges() {
    let contract = Address::repeat_byte(0x88);
    let mut genesis = vectors::genesis();
    genesis.accounts.insert(
        contract,
        GenesisAccount {
            nonce: 1,
            // Return BLOCKHASH(CALLDATALOAD(0)).
            code: Bytes::from_static(&[0x5f, 0x35, 0x40, 0x5f, 0x52, 0x60, 0x20, 0x5f, 0xf3]),
            ..Default::default()
        },
    );
    let mut engine = Executor::new(&genesis).unwrap();
    let mut headers = vec![engine.head().clone()];
    for _ in 0..260 {
        headers.extend(
            engine
                .apply_batch(&next(&engine))
                .unwrap()
                .into_iter()
                .map(|b| b.header),
        );
        if headers.len() > 256 {
            headers.remove(0);
        }
    }
    let wanted = [headers[255].hash_slow(), headers[0].hash_slow(), B256::ZERO];
    let (boundary, snapshot) = Checkpoint::capture(&engine, headers).unwrap();
    let mut restored = snapshot
        .restore(genesis.rollup_id, genesis.chain_id, &boundary)
        .unwrap();
    let transactions = [260u64, 5, 4]
        .into_iter()
        .enumerate()
        .map(|(nonce, number)| {
            let mut tx = vectors::tx(nonce as u64);
            tx.to = alloy_primitives::TxKind::Call(contract);
            tx.value = U256::ZERO;
            tx.input = U256::from(number).to_be_bytes::<32>().to_vec().into();
            vectors::sign(tx)
        })
        .collect();
    let input = BatchInput {
        parent: *engine.anchor(),
        blocks: vec![BlockInput {
            timestamp: 261,
            fee_recipient: [3; 20],
            transactions,
        }],
    }
    .encode()
    .unwrap();
    let blocks = restored.apply_batch(&input).unwrap();
    assert_eq!(blocks, engine.apply_batch(&input).unwrap());
    for (outcome, expected) in blocks[0].outcomes.iter().zip(wanted) {
        assert_eq!(outcome.status, tactus_o1_execution::Status::Success);
        assert_eq!(outcome.output.as_ref(), expected.as_slice());
    }
}
