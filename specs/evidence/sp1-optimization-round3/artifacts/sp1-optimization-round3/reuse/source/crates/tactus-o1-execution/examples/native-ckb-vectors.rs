//! Actual signed bridge user calls; seeded balances are not L1 deposits.
#[allow(dead_code)]
#[path = "support/native_ckb.rs"]
mod bridge;
use alloy_consensus::TxEnvelope;
use alloy_eips::eip2718::Decodable2718;
use alloy_primitives::{hex, Address, Bytes, TxKind, B256};
use bridge::*;
use serde_json::{json, Value};
use std::{collections::BTreeMap, fs, path::Path};
use tactus_o1_execution::{Executor, Genesis, Status};
use tactus_o1_protocol::batch::{BatchInput, BlockInput};

fn case(
    name: &str,
    genesis: Genesis,
    calls: Vec<(u8, TxKind, Bytes, u64, Status, &'static str)>,
) -> Value {
    let mut engine = Executor::new(&genesis).unwrap();
    let mut hashes = BTreeMap::from([("0x0".to_owned(), engine.head().hash_slow())]);
    let mut entries = Vec::new();
    let mut batches = Vec::new();
    for (index, to, input, value, status, label) in calls {
        let nonce = engine.account(user(index)).unwrap().nonce;
        let raw = signed(index, nonce, to, input, value);
        let source = BlockInput {
            timestamp: engine.head().timestamp + 1,
            fee_recipient: Address::repeat_byte(0x22).0 .0,
            transactions: vec![raw.clone()],
        };
        let encoded = BatchInput {
            parent: *engine.anchor(),
            blocks: vec![source.clone()],
        }
        .encode()
        .unwrap();
        let block = engine.apply_batch(&encoded).unwrap().remove(0);
        assert_eq!(block.outcomes[0].status, status, "{label}");
        conservation(&engine);
        let env = json!({"currentCoinbase":Address::repeat_byte(0x22),"currentGasLimit":"0xf4240","currentNumber":format!("0x{:x}",block.header.number),"currentTimestamp":format!("0x{:x}",block.header.timestamp),"currentRandom":B256::ZERO,"currentBaseFee":format!("0x{:x}",block.header.base_fee_per_gas.unwrap()),"withdrawals":[],"blockHashes":hashes});
        hashes.insert(format!("0x{:x}", block.header.number), block.hash);
        entries.push(json!({"label":label,"env":env,"txs":[TxEnvelope::decode_2718_exact(&raw).unwrap()],"expected":block}));
        batches.push(format!("0x{}", hex::encode(encoded)));
    }
    let alloc:BTreeMap<_,_>=genesis.accounts.iter().map(|(address,a)|{
        let storage:BTreeMap<_,_>=a.storage.iter().map(|(k,v)|(format!("0x{k:064x}"),format!("0x{v:064x}"))).collect();
        (address,json!({"balance":format!("0x{:x}",a.balance),"nonce":format!("0x{:x}",a.nonce),"code":a.code,"storage":storage}))
    }).collect();
    json!({"name":name,"genesis":genesis,"alloc":alloc,"batch":{"sequence":batches},"blocks":entries,"final_bridge_account":engine.account(CONTRACT).unwrap()})
}
fn main() {
    let directory = std::env::args()
        .nth(1)
        .expect("usage: native-ckb-vectors OUTPUT_DIRECTORY");
    let mut calls = Vec::new();
    let mut add = |index, signature, args: &[B256], status, label| {
        calls.push((
            index,
            TxKind::Call(CONTRACT),
            calldata(signature, args),
            0,
            status,
            label,
        ))
    };
    add(
        0,
        "creditDeposit(bytes32,address,uint64)",
        &[quantity(1), address_word(user(0)), quantity(100)],
        Status::Revert,
        "ordinary caller cannot mint",
    );
    add(
        0,
        "transfer(address,uint256)",
        &[address_word(user(1)), quantity(200)],
        Status::Success,
        "token transfer",
    );
    add(
        0,
        "approve(address,uint256)",
        &[address_word(user(1)), quantity(900)],
        Status::Success,
        "approve exact allowance",
    );
    add(
        1,
        "transferFrom(address,address,uint256)",
        &[address_word(user(0)), address_word(user(2)), quantity(801)],
        Status::Revert,
        "insufficient balance rolls back allowance",
    );
    add(
        1,
        "transferFrom(address,address,uint256)",
        &[address_word(user(0)), address_word(user(2)), quantity(100)],
        Status::Success,
        "allowance transfer after rollback",
    );
    add(
        1,
        "transferFrom(address,address,uint256)",
        &[address_word(user(0)), address_word(user(2)), quantity(801)],
        Status::Revert,
        "insufficient allowance",
    );
    add(
        2,
        "transfer(address,uint256)",
        &[address_word(user(2)), quantity(100)],
        Status::Success,
        "self transfer preserves balance",
    );
    add(
        2,
        "transfer(address,uint256)",
        &[address_word(user(0)), quantity(0)],
        Status::Success,
        "zero transfer emits event",
    );
    add(
        0,
        "transfer(address,uint256)",
        &[address_word(Address::ZERO), quantity(1)],
        Status::Revert,
        "no transfer to zero",
    );
    add(
        0,
        "transfer(address,uint256)",
        &[address_word(CONTRACT), quantity(1)],
        Status::Revert,
        "no stranded contract balance",
    );
    add(
        1,
        "withdraw(uint64,bytes32)",
        &[quantity(100), RECIPIENT],
        Status::Success,
        "first burn commitment",
    );
    add(
        2,
        "withdraw(uint64,bytes32)",
        &[quantity(101), RECIPIENT],
        Status::Revert,
        "no unowned token burn",
    );
    add(
        2,
        "withdraw(uint64,bytes32)",
        &[quantity(100), RECIPIENT],
        Status::Success,
        "second owner distinct commitment",
    );
    add(
        0,
        "withdraw(uint64,bytes32)",
        &[quantity(0), RECIPIENT],
        Status::Revert,
        "no zero withdrawal",
    );
    add(
        0,
        "withdraw(uint64,bytes32)",
        &[quantity(1), B256::ZERO],
        Status::Revert,
        "recipient hash required",
    );
    add(
        0,
        "withdraw(uint64,bytes32)",
        &[B256::repeat_byte(0xff), RECIPIENT],
        Status::Revert,
        "amount must fit uint64",
    );
    add(
        0,
        "withdraw(uint64,bytes32)",
        &[quantity(700), RECIPIENT],
        Status::Success,
        "exhaust holder balance",
    );
    add(
        0,
        "withdraw(uint64,bytes32)",
        &[quantity(1), RECIPIENT],
        Status::Revert,
        "no over-withdrawal",
    );
    add(
        1,
        "withdraw(uint64,bytes32)",
        &[quantity(100), RECIPIENT],
        Status::Success,
        "same owner recipient new ordinal",
    );
    add(
        1,
        "withdraw(uint64,bytes32)",
        &[quantity(1), RECIPIENT],
        Status::Revert,
        "exhausted final supply",
    );
    add(
        0,
        "withdrawals(uint64)",
        &[quantity(1)],
        Status::Success,
        "first commitment remains readable",
    );
    add(
        0,
        "totalSupply()",
        &[],
        Status::Success,
        "zero final supply",
    );
    calls.push((
        0,
        TxKind::Call(CONTRACT),
        Bytes::new(),
        1,
        Status::Revert,
        "no payable fallback",
    ));
    let seeded = case("seeded-native-ckb-user-calls", genesis(1000), calls);
    let g = genesis(0);
    let deployed = user(0).create(0);
    let deployment = case(
        "native-ckb-deployment",
        g,
        vec![
            (
                0,
                TxKind::Create,
                creation(BRIDGE),
                0,
                Status::Success,
                "ordinary constructor",
            ),
            (
                0,
                TxKind::Call(deployed),
                calldata("DOMAIN()", &[]),
                0,
                Status::Success,
                "deployed domain",
            ),
            (
                0,
                TxKind::Call(deployed),
                calldata(
                    "creditDeposit(bytes32,address,uint64)",
                    &[quantity(1), address_word(user(0)), quantity(100)],
                ),
                0,
                Status::Revert,
                "deployer has no mint privilege",
            ),
            (
                0,
                TxKind::Create,
                creation(B256::ZERO),
                0,
                Status::Revert,
                "zero domain rejected",
            ),
        ],
    );
    let candidate = json!({"schema":1,"rules_hash":format!("0x{}",hex::encode(tactus_o1_execution::rules_hash())),"cases":[seeded,deployment],"authenticated_l1_deposits":false,"custody_release":false,"production_ready":false});
    fs::create_dir_all(&directory).unwrap();
    fs::write(
        Path::new(&directory).join("candidates.json"),
        serde_json::to_string_pretty(&candidate).unwrap() + "\n",
    )
    .unwrap();
    println!("27 signed calls; no L1 deposit or vault release claim");
}
