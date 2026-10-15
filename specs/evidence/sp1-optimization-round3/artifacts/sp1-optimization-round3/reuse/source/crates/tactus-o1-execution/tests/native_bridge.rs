#![cfg(feature = "native-bridge")]
#[allow(dead_code)]
#[path = "../examples/support/native_bridge.rs"]
mod f;
use alloy_primitives::{hex, Address, B256, U256};
use f::token;
use tactus_o1_execution::{
    native_bridge::{self, NativeExecutor},
    Executor, GenesisAccount, Status,
};
use tactus_o1_protocol::{
    batch::{self, BatchInput, BlockInput},
    native_bridge::{Anchor, Batch, Config, Cursor, Record},
};

#[test]
fn generated_native_constants_match_original_artifact_expression() {
    let descriptor = [
        include_bytes!("../rules-native-v2.txt").as_slice(),
        include_bytes!("../rules-v1.txt").as_slice(),
        include_bytes!("../../../Cargo.lock").as_slice(),
        include_bytes!("../../../contracts/bridge/NativeCKB.json").as_slice(),
    ]
    .concat();
    assert_eq!(
        native_bridge::rules_hash(),
        batch::hash(b"tactus/o1/native-execution-rules/v2", &descriptor)
    );
    let artifact: serde_json::Value =
        serde_json::from_slice(include_bytes!("../../../contracts/bridge/NativeCKB.json")).unwrap();
    let deployed = &artifact["contract"]["evm"]["deployedBytecode"];
    let (original, _, _, _) = f::actual();
    for marker in [0, 1, 255] {
        let mut config = original.clone();
        config.identity = [marker; 32];
        let mut expected = hex::decode(deployed["object"].as_str().unwrap()).unwrap();
        for references in deployed["immutableReferences"]
            .as_object()
            .unwrap()
            .values()
        {
            for patch in references.as_array().unwrap() {
                let start = patch["start"].as_u64().unwrap() as usize;
                expected[start..start + 32]
                    .copy_from_slice(native_bridge::domain(&config).as_slice());
            }
        }
        assert_eq!(native_bridge::runtime(&config).as_ref(), expected);
    }
}

#[test]
fn actual_funded_records_preserve_domain_wire_and_credit_exact_balances() {
    let (c, code, records, report) = f::actual();
    let g = f::genesis(&c);
    let mut e = NativeExecutor::new(&g, c.clone(), code).unwrap();
    assert_ne!(
        e.anchor().ordering.execution_rules_hash,
        tactus_o1_execution::rules_hash()
    );
    assert_ne!(
        e.head().hash_slow(),
        Executor::new(&g).unwrap().head().hash_slow()
    );
    assert_eq!(
        format!("0x{}", hex::encode(c.vault_script(code))),
        report["vault_script"]
    );
    assert_eq!(Anchor::decode(&e.anchor().encode()).unwrap(), e.anchor());
    let encoded = f::encoded(&e, records.clone(), vec![]);
    let result = e.apply_batch(&encoded).unwrap();
    assert_eq!(result.deposits.len(), 2);
    assert_eq!(result.blocks.len(), 1);
    for (r, reported) in records.iter().zip(report["deposits"].as_array().unwrap()) {
        assert_eq!(
            format!("0x{}", hex::encode(c.deposit_id(r.sequence))),
            reported["deposit_id"]
        );
        assert_eq!(
            f::storage(&e, token::slot(token::address_word(r.recipient.into()), 3)),
            U256::from(r.amount)
        );
    }
    assert_eq!(f::storage(&e, U256::ZERO), U256::from(25_000_000_000u64));
    assert_eq!(e.anchor().deposits.cumulative, 25_000_000_000);
    assert!(e.account(Address::ZERO).is_none());
    assert!(result.blocks[0].transactions.is_empty());
    assert!(result.blocks[0].receipts.is_empty());
    assert!(result
        .deposits
        .iter()
        .all(|r| !r.logs.is_empty() && r.gas_used <= native_bridge::MAX_CREDIT_GAS));
    let old = e.clone();
    assert!(e.apply_batch(&encoded).is_err());
    assert_eq!(e.state_root(), old.state_root());
    assert_eq!(e.anchor(), old.anchor());
    let v1 = BatchInput {
        parent: Executor::new(&g).unwrap().anchor().to_owned(),
        blocks: vec![BlockInput {
            timestamp: 1,
            fee_recipient: [0x22; 20],
            transactions: vec![],
        }],
    }
    .encode()
    .unwrap();
    assert!(e.apply_batch(&v1).is_err());
    assert!(Executor::new(&g).unwrap().apply_batch(&encoded).is_err());
}

#[test]
fn credited_tokens_transfer_and_burn_in_real_signed_user_transactions() {
    let (c, code, _, _) = f::actual();
    let mut e = NativeExecutor::new(&f::genesis(&c), c.clone(), code).unwrap();
    let first = f::record(&c, e.anchor().deposits, token::user(0), 1000);
    let second = f::record(
        &c,
        e.anchor().deposits.append(&c, &first).unwrap(),
        token::user(1),
        500,
    );
    let transfer = f::signed_call(
        &e,
        0,
        "transfer(address,uint256)",
        &[token::address_word(token::user(1)), token::quantity(200)],
    );
    let r = e
        .apply_batch(&f::encoded(&e, vec![first, second], vec![transfer]))
        .unwrap();
    assert_eq!(r.blocks[0].outcomes[0].status, Status::Success);
    for (user, amount) in [(1, 700), (0, 800)] {
        let burn = f::signed_call(
            &e,
            user,
            "withdraw(uint64,bytes32)",
            &[token::quantity(amount), token::RECIPIENT],
        );
        let r = e.apply_batch(&f::encoded(&e, vec![], vec![burn])).unwrap();
        assert_eq!(r.blocks[0].outcomes[0].status, Status::Success);
    }
    assert_eq!(f::storage(&e, U256::ZERO), U256::ZERO);
    assert_eq!(f::storage(&e, U256::from(2)), U256::from(1500));
    assert_eq!(f::storage(&e, U256::from(6)), U256::from(2));
    let permanent = f::storage(&e, token::slot(token::quantity(1), 7));
    assert_ne!(permanent, U256::ZERO);
    let mint = f::signed_call(
        &e,
        0,
        "creditDeposit(bytes32,address,uint64)",
        &[
            B256::repeat_byte(1),
            token::address_word(token::user(0)),
            token::quantity(10),
        ],
    );
    let r = e.apply_batch(&f::encoded(&e, vec![], vec![mint])).unwrap();
    assert_eq!(r.blocks[0].outcomes[0].status, Status::Revert);
    assert_eq!(f::storage(&e, U256::ZERO), U256::ZERO);
    assert_eq!(
        f::storage(&e, token::slot(token::quantity(1), 7)),
        permanent
    );
}

#[test]
fn invalid_genesis_cannot_seed_tokens_or_impersonate_system_authority() {
    let (c, code, _, _) = f::actual();
    let g = f::genesis(&c);
    for mode in 0..8 {
        let mut g = g.clone();
        let mut c = c.clone();
        match mode {
            0 => {
                g.accounts.insert(
                    Address::ZERO,
                    GenesisAccount {
                        balance: U256::from(1),
                        ..Default::default()
                    },
                );
            }
            1 => {
                g.accounts
                    .get_mut(&Address::from(c.contract))
                    .unwrap()
                    .storage
                    .insert(U256::from(3), U256::from(1));
            }
            2 => g.accounts.get_mut(&Address::from(c.contract)).unwrap().code = vec![0].into(),
            3 => {
                g.accounts
                    .get_mut(&Address::from(c.contract))
                    .unwrap()
                    .nonce = 0
            }
            4 => {
                g.accounts
                    .get_mut(&Address::from(c.contract))
                    .unwrap()
                    .balance = U256::from(1)
            }
            5 => c.settlement = [0; 32],
            6 => c.chain += 1,
            _ => {
                c.contract = Address::from_word(B256::from(U256::from(1).to_be_bytes::<32>()))
                    .0
                     .0
            }
        }
        assert!(NativeExecutor::new(&g, c, code).is_err(), "case {mode}");
    }
    assert!(NativeExecutor::new(&g, c, [0; 32]).is_err());
}

#[test]
fn invalid_deposit_or_late_credit_failure_rolls_back_the_entire_batch() {
    let (c, code, _, _) = f::actual();
    let mut e = NativeExecutor::new(&f::genesis(&c), c.clone(), code).unwrap();
    let r = f::record(&c, e.anchor().deposits, token::user(0), 1000);
    let original = f::encoded(&e, vec![r], vec![]);
    let root = e.state_root();
    let head = e.head().clone();
    let anchor = e.anchor();
    for offset in [0, 8, 16, 40, 64, 66, 74, 82, 102, 110, 142, 174] {
        let mut bad = original.clone();
        bad[offset] ^= 1;
        assert!(e.apply_batch(&bad).is_err(), "offset {offset}");
        assert_eq!(e.state_root(), root);
        assert_eq!(e.head(), &head);
        assert_eq!(e.anchor(), anchor);
    }
    let first = f::record(&c, e.anchor().deposits, token::user(0), u64::MAX);
    let second = f::record(
        &c,
        e.anchor().deposits.append(&c, &first).unwrap(),
        token::user(1),
        1,
    );
    assert!(e
        .apply_batch(&f::encoded(&e, vec![first, second], vec![]))
        .is_err());
    assert_eq!(e.state_root(), root);
    assert_eq!(e.head(), &head);
    assert_eq!(e.anchor(), anchor);
    assert_eq!(f::storage(&e, U256::ZERO), U256::ZERO);
}

#[test]
fn transcript_rejects_duplicates_gaps_wrong_domains_and_unbounded_data() {
    let (c, code, actual, _) = f::actual();
    let e = NativeExecutor::new(&f::genesis(&c), c.clone(), code).unwrap();
    let a = e.anchor();
    let mut cursor = Cursor::genesis(&c);
    for r in &actual {
        cursor = cursor.append(&c, r).unwrap();
    }
    assert!(cursor.append(&c, &actual[1]).is_err());
    assert!(a.deposits.append(&c, &actual[1]).is_err());
    let mut wrong = c.clone();
    wrong.identity[0] ^= 1;
    assert!(a.deposits.append(&wrong, &actual[0]).is_err());
    let b = f::encoded(&e, actual.clone(), vec![]);
    for len in 0..b.len() {
        assert!(Batch::decode(&b[..len], &c, &a).is_err());
    }
    let mut extra = b.clone();
    extra.push(0);
    assert!(Batch::decode(&extra, &c, &a).is_err());
    assert!(Batch::decode(&vec![0; 262145], &c, &a).is_err());
    let mut too_many = b;
    too_many[64..66].copy_from_slice(&33u16.to_le_bytes());
    assert!(Batch::decode(&too_many, &c, &a).is_err());
    let mut seq = actual[0].clone();
    seq.sequence = 0;
    assert!(a.deposits.append(&c, &seq).is_err());
    for recipient in [[0; 20], c.contract] {
        seq = actual[0].clone();
        seq.recipient = recipient;
        assert!(a.deposits.append(&c, &seq).is_err());
    }
    let overflow = Cursor {
        count: u64::MAX,
        ..a.deposits
    };
    assert!(overflow.append(&c, &actual[0]).is_err());
    let overflow = Cursor {
        cumulative: u128::MAX,
        ..a.deposits
    };
    assert!(overflow.append(&c, &actual[0]).is_err());
    assert_eq!(Config::decode(&c.encode()).unwrap(), c);
    assert_eq!(Record::decode(&actual[0].encode()).unwrap(), actual[0]);
    assert_ne!(native_bridge::rules_hash(), batch::hash(b"", &[]));
}

#[test]
fn maximum_credit_batch_precedes_all_user_blocks_and_cumulative_can_exceed_u64() {
    let (c, code, _, _) = f::actual();
    let mut e = NativeExecutor::new(&f::genesis(&c), c.clone(), code).unwrap();
    let mut cursor = e.anchor().deposits;
    let mut records = vec![];
    for _ in 0..32 {
        let r = f::record(&c, cursor, token::user(0), 100);
        cursor = cursor.append(&c, &r).unwrap();
        records.push(r);
    }
    let burn = f::signed_call(
        &e,
        0,
        "withdraw(uint64,bytes32)",
        &[token::quantity(3200), token::RECIPIENT],
    );
    let b = Batch {
        deposits: records,
        users: BatchInput {
            parent: e.anchor().ordering,
            blocks: vec![
                BlockInput {
                    timestamp: 1,
                    fee_recipient: [0; 20],
                    transactions: vec![],
                },
                BlockInput {
                    timestamp: 2,
                    fee_recipient: [0; 20],
                    transactions: vec![burn],
                },
            ],
        },
    };
    let result = e.apply_batch(&b.encode(&c, &e.anchor()).unwrap()).unwrap();
    assert_eq!(result.deposits.len(), 32);
    assert_eq!(result.blocks.len(), 2);
    assert_eq!(result.blocks[1].header.parent_hash, result.blocks[0].hash);
    assert_eq!(result.blocks[1].outcomes[0].status, Status::Success);
    assert_eq!(e.anchor().deposits, cursor);
    assert_eq!(f::storage(&e, U256::ZERO), U256::ZERO);
    // Gross credited flow can exceed u64 after burns, while outstanding supply
    // remains bounded. These records are synthetic transcript tests, not L1 funds.
    for _ in 0..2 {
        let r = f::record(
            &c,
            e.anchor().deposits,
            token::user(0),
            u64::MAX - 39_000_000_000,
        );
        let burn = f::signed_call(
            &e,
            0,
            "withdraw(uint64,bytes32)",
            &[token::quantity(r.amount), token::RECIPIENT],
        );
        let result = e.apply_batch(&f::encoded(&e, vec![r], vec![burn])).unwrap();
        assert_eq!(result.blocks[0].outcomes[0].status, Status::Success);
    }
    assert!(e.anchor().deposits.cumulative > u128::from(u64::MAX));
    assert_eq!(
        f::storage(&e, U256::from(1)),
        U256::from(e.anchor().deposits.cumulative)
    );
    assert_eq!(f::storage(&e, U256::ZERO), U256::ZERO);
}
