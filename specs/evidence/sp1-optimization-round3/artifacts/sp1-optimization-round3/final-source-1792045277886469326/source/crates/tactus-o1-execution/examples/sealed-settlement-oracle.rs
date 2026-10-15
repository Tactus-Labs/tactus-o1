//! Export an independent Geth comparison for a canonical A3 proving input.
//! Geth's JSON t8n interface cannot represent malformed wire envelopes. Retain
//! their raw slots explicitly; compare only decodable envelopes with Geth.
use alloy_consensus::TxEnvelope;
use alloy_eips::eip2718::Decodable2718;
use alloy_primitives::{hex, B256};
use serde_json::{json, Value};
use std::{collections::BTreeMap, fs, path::Path};
use tactus_o1_execution::{Executor, Genesis, Status};
use tactus_o1_protocol::batch::BatchInput;
fn decode(value: &Value) -> Vec<u8> {
    hex::decode(value.as_str().unwrap().strip_prefix("0x").unwrap()).unwrap()
}
fn main() {
    let args: Vec<_> = std::env::args().collect();
    assert_eq!(
        args.len(),
        3,
        "usage: sealed-settlement-oracle CANONICAL_INPUT OUTPUT_DIRECTORY"
    );
    let input: Value = serde_json::from_slice(&fs::read(&args[1]).unwrap()).unwrap();
    assert_eq!(input["schema"], 1);
    assert_eq!(input["prefix_batches"], 0);
    let domain = decode(&input["domain_hex"]);
    let chain = u64::from_le_bytes(domain[128..136].try_into().unwrap());
    assert_eq!(chain, 31337);
    let genesis = Genesis::from_allocation(
        B256::from_slice(&domain[96..128]),
        chain,
        &decode(&input["allocation_hex"]),
    )
    .unwrap();
    let mut engine = Executor::new(&genesis).unwrap();
    let mut combined = BatchInput {
        parent: *engine.anchor(),
        blocks: Vec::new(),
    };
    let mut hashes = BTreeMap::from([("0x0".to_owned(), engine.head().hash_slow())]);
    let mut entries = Vec::new();
    let mut excluded = 0;
    for raw in input["batches"].as_array().unwrap() {
        let bytes = decode(raw);
        let batch = BatchInput::decode(&bytes, engine.anchor()).unwrap();
        let executed = engine.apply_batch(&bytes).unwrap();
        for (block, source) in executed.into_iter().zip(&batch.blocks) {
            let env = json!({"currentCoinbase":format!("0x{}",hex::encode(source.fee_recipient)),"currentGasLimit":"0xf4240","currentNumber":format!("0x{:x}",block.header.number),"currentTimestamp":format!("0x{:x}",source.timestamp),"currentRandom":B256::ZERO,"currentBaseFee":format!("0x{:x}",block.header.base_fee_per_gas.unwrap()),"withdrawals":[],"blockHashes":hashes});
            hashes.insert(format!("0x{:x}", block.header.number), block.hash);
            let mut txs = Vec::new();
            let mut slots = Vec::new();
            let mut omitted = Vec::new();
            let mut outcomes = Vec::new();
            for (slot, (bytes, outcome)) in
                source.transactions.iter().zip(&block.outcomes).enumerate()
            {
                match TxEnvelope::decode_2718_exact(bytes) {
                    Ok(tx) => {
                        txs.push(tx);
                        slots.push(slot);
                        outcomes.push(outcome.clone());
                    }
                    Err(_) => {
                        assert_eq!(outcome.status, Status::Malformed);
                        assert_eq!(outcome.transaction_index, None);
                        assert_eq!(outcome.gas_used, 0);
                        omitted.push(json!({"input_slot":slot,"wire":format!("0x{}",hex::encode(bytes)),"reason":"malformed envelope is not representable by Geth t8n JSON; no independent Geth classification claimed"}));
                        excluded += 1;
                    }
                }
            }
            let mut expected = serde_json::to_value(&block).unwrap();
            expected["outcomes"] = json!(outcomes);
            entries.push(json!({"env":env,"txs":txs,"expected":expected,"canonical_execution":block,"source_input_slots":slots,"excluded_wire_inputs":omitted}));
        }
        combined.blocks.extend(batch.blocks);
    }
    assert_eq!(entries.len(), 9);
    assert_eq!(excluded, 1);
    let alloc:BTreeMap<_,_>=genesis.accounts.iter().map(|(address,a)| {
        let storage:BTreeMap<_,_>=a.storage.iter().map(|(k,v)|(format!("0x{k:064x}"),format!("0x{v:064x}"))).collect();
        (address,json!({"balance":format!("0x{:x}",a.balance),"nonce":format!("0x{:x}",a.nonce),"code":a.code,"storage":storage}))
    }).collect();
    let dir = Path::new(&args[2]);
    fs::create_dir_all(dir).unwrap();
    let candidate = json!({"schema":1,"rules_hash":format!("0x{}",hex::encode(tactus_o1_execution::rules_hash())),"cases":[{"name":"sealed-nine-batches","genesis":genesis,"alloc":alloc,"batch":format!("0x{}",hex::encode(combined.encode().unwrap())),"blocks":entries}],"excluded_malformed_wire_inputs":excluded,"independent_malformed_classification":false});
    fs::write(
        dir.join("candidates.json"),
        serde_json::to_string_pretty(&candidate).unwrap() + "\n",
    )
    .unwrap();
}
