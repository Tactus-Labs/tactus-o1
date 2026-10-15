//! Candidate execution vectors, not a proof or CKB settlement authorization.
#[allow(dead_code)]
#[path = "support/native_bridge.rs"]
mod f;
use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::{hex, B256};
use f::token;
use serde_json::{json, Value};
use tactus_o1_execution::native_bridge::{self, NativeExecutor};
use tactus_o1_protocol::native_bridge::Record;

fn step(e: &mut NativeExecutor, records: Vec<Record>, txs: Vec<Vec<u8>>) -> Value {
    let initial = f::encoded(e, records, txs.clone());
    let (mut input, _) =
        tactus_o1_protocol::native_bridge::Batch::decode(&initial, e.config(), &e.anchor())
            .unwrap();
    // Exercise credits after the zero system caller has received native fee
    // balances. A system call must preserve them and never increment its nonce.
    input.users.blocks[0].fee_recipient = [0; 20];
    let bytes = input.encode(e.config(), &e.anchor()).unwrap();
    let before = e.anchor();
    let parent = e.head().clone();
    let result = e.apply_batch(&bytes).unwrap();
    json!({"wrapper":format!("0x{}",hex::encode(bytes)),"before":hex::encode(before.encode()),"after":hex::encode(e.anchor().encode()),
        "parent":parent,"blocks":result.blocks.iter().map(|b|json!({"header":b.header,"hash":b.hash,"outcomes":b.outcomes,
            "transactions":b.transactions,"receipts":b.receipts.iter().map(|r|format!("0x{}",hex::encode(r.encoded_2718()))).collect::<Vec<_>>() })).collect::<Vec<_>>(),
        "deposits":result.deposits.iter().map(|d|json!({"record":hex::encode(d.record.encode()),"deposit_id":hex::encode(d.deposit_id),
            "calldata":native_bridge::credit_calldata(e.config(),&d.record),"gas_used":d.gas_used,"logs":d.logs})).collect::<Vec<_>>()})
}
fn main() {
    let (c, code, actual, _) = f::actual();
    let g = f::genesis(&c);
    let mut e = NativeExecutor::new(&g, c.clone(), code).unwrap();
    let genesis_head = e.head().clone();
    let rows = vec![
        step(&mut e, vec![actual[0].clone()], vec![]),
        step(&mut e, vec![actual[1].clone()], vec![]),
    ];
    let real = json!({"name":"actual-funded-record-bytes","genesis":g,"genesis_header":genesis_head,"steps":rows,"final_bridge":e.account(c.contract.into()).unwrap()});
    let mut e = NativeExecutor::new(&g, c.clone(), code).unwrap();
    let mut rows = vec![];
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
    rows.push(step(&mut e, vec![first, second], vec![transfer]));
    for (user, amount) in [(1, 700), (0, 800)] {
        let burn = f::signed_call(
            &e,
            user,
            "withdraw(uint64,bytes32)",
            &[token::quantity(amount), token::RECIPIENT],
        );
        rows.push(step(&mut e, vec![], vec![burn]));
    }
    let mint = f::signed_call(
        &e,
        0,
        "creditDeposit(bytes32,address,uint64)",
        &[
            B256::repeat_byte(1),
            token::address_word(token::user(0)),
            token::quantity(1),
        ],
    );
    rows.push(step(&mut e, vec![], vec![mint]));
    let refill = f::record(&c, e.anchor().deposits, token::user(0), 250);
    let burn = f::signed_call(
        &e,
        0,
        "withdraw(uint64,bytes32)",
        &[token::quantity(250), token::RECIPIENT],
    );
    rows.push(step(&mut e, vec![refill], vec![burn]));
    let synthetic = json!({"name":"synthetic-records-signed-transfer-burn-refill","genesis":g,"genesis_header":genesis_head,"steps":rows,"final_bridge":e.account(c.contract.into()).unwrap()});
    let report = json!({"schema":1,"profile":"native-custody-execution-v2-candidate","rules_hash":hex::encode(native_bridge::rules_hash()),"config":hex::encode(c.encode()),
        "vault_code_hash":hex::encode(code),"vault_type_hash":hex::encode(e.vault_type_hash()),"domain":native_bridge::domain(&c),
        "authenticated_publication":false,"proof_settled":false,"custody_release":false,"production_ready":false,"cases":[real,synthetic]});
    let path = std::env::args()
        .nth(1)
        .expect("usage: native-bridge-vectors OUTPUT_JSON");
    std::fs::write(path, serde_json::to_string_pretty(&report).unwrap() + "\n").unwrap();
}
