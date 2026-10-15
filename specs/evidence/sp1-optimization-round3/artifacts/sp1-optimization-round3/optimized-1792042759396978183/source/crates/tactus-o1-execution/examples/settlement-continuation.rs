//! Prepare a signed, state-changing second publication and independent Geth input.
//! Fixed laboratory signer; this is not a wallet or production transaction builder.
use alloy_consensus::{SignableTransaction, TxEnvelope, TxLegacy};
use alloy_eips::eip2718::{Decodable2718, Encodable2718};
use alloy_primitives::{address, hex, Signature, TxKind, B256, U256};
use k256::ecdsa::SigningKey;
use serde_json::{json, Value};
use std::{collections::BTreeMap, fs, path::Path};
use tactus_o1_execution::{Executor, Genesis};
use tactus_o1_protocol::batch::{BatchInput, BlockInput};
fn decode(value: &Value) -> Vec<u8> {
    hex::decode(value.as_str().unwrap().strip_prefix("0x").unwrap()).unwrap()
}
fn main() {
    let args: Vec<_> = std::env::args().collect();
    assert_eq!(
        args.len(),
        3,
        "usage: settlement-continuation CANONICAL_INPUT_JSON OUTPUT_DIRECTORY"
    );
    let input: Value = serde_json::from_slice(&fs::read(&args[1]).unwrap()).unwrap();
    assert_eq!(input["schema"], 1);
    assert_eq!(input["prefix_batches"], 0);
    assert_eq!(input["batches"].as_array().unwrap().len(), 1);
    let domain = decode(&input["domain_hex"]);
    assert_eq!(domain.len(), 136);
    let chain = u64::from_le_bytes(domain[128..136].try_into().unwrap());
    assert_eq!(chain, 31337);
    let genesis = Genesis::from_allocation(
        B256::from_slice(&domain[96..128]),
        chain,
        &decode(&input["allocation_hex"]),
    )
    .unwrap();
    let mut engine = Executor::new(&genesis).unwrap();
    let first = decode(&input["batches"][0]);
    let first_batch = BatchInput::decode(&first, engine.anchor()).unwrap();
    let mut hashes = BTreeMap::from([("0x0".to_owned(), engine.head().hash_slow())]);
    let mut entries = Vec::new();
    let mut record = |blocks: Vec<tactus_o1_execution::ExecutedBlock>, inputs: &[BlockInput]| {
        for (block, raw) in blocks.into_iter().zip(inputs) {
            let env = json!({"currentCoinbase":format!("0x{}",hex::encode(raw.fee_recipient)),"currentGasLimit":"0xf4240","currentNumber":format!("0x{:x}",block.header.number),"currentTimestamp":format!("0x{:x}",raw.timestamp),"currentRandom":B256::ZERO,"currentBaseFee":format!("0x{:x}",block.header.base_fee_per_gas.unwrap()),"withdrawals":[],"blockHashes":hashes});
            hashes.insert(format!("0x{:x}", block.header.number), block.hash);
            entries.push(json!({"env":env,"txs":raw.transactions.iter().map(|t|TxEnvelope::decode_2718_exact(t).unwrap()).collect::<Vec<_>>(),"expected":block}));
        }
    };
    record(engine.apply_batch(&first).unwrap(), &first_batch.blocks);
    let before = *engine.anchor();
    let previous_state = engine.state_root();
    let previous_header = engine.head().hash_slow();
    let signer = SigningKey::from_bytes((&[0x21; 32]).into()).unwrap();
    let sender = alloy_primitives::Address::from_public_key(signer.verifying_key());
    assert_eq!(engine.account(sender).unwrap().nonce, 3);
    let transaction = TxLegacy {
        chain_id: Some(chain),
        nonce: 3,
        gas_price: 2_000_000_000,
        gas_limit: 21_000,
        to: TxKind::Call(address!("1111111111111111111111111111111111111111")),
        value: U256::from(321),
        ..Default::default()
    };
    let signature: Signature = signer
        .sign_prehash_recoverable(transaction.signature_hash().as_slice())
        .unwrap()
        .into();
    let signed = TxEnvelope::from(transaction.into_signed(signature)).encoded_2718();
    let second_batch = BatchInput {
        parent: before,
        blocks: vec![BlockInput {
            timestamp: 20,
            fee_recipient: [0x22; 20],
            transactions: vec![signed],
        }],
    };
    let second = second_batch.encode().unwrap();
    record(engine.apply_batch(&second).unwrap(), &second_batch.blocks);
    assert_eq!(engine.account(sender).unwrap().nonce, 4);
    assert_ne!(previous_state, engine.state_root());
    let mut combined = first_batch;
    combined.blocks.extend(second_batch.blocks);
    let alloc:BTreeMap<_,_>=genesis.accounts.iter().map(|(address,a)| {
        let storage:BTreeMap<_,_>=a.storage.iter().map(|(k,v)|(format!("0x{k:064x}"),format!("0x{v:064x}"))).collect();
        (address,json!({"balance":format!("0x{:x}",a.balance),"nonce":format!("0x{:x}",a.nonce),"code":a.code,"storage":storage}))
    }).collect();
    let dir = Path::new(&args[2]);
    fs::create_dir(dir).unwrap();
    let candidates = json!({"schema":1,"rules_hash":format!("0x{}",hex::encode(tactus_o1_execution::rules_hash())),"cases":[{"name":"two-settlement-intervals","genesis":genesis,"alloc":alloc,"batch":format!("0x{}",hex::encode(combined.encode().unwrap())),"blocks":entries}]});
    let continuation = json!({"schema":1,"description":"signed nonce-3 value transfer following canonical first three transfers","first_publication":input["batches"][0],"second_publication":format!("0x{}",hex::encode(second)),"before_anchor":format!("0x{}",hex::encode(before.encode())),"after_anchor":format!("0x{}",hex::encode(engine.anchor().encode())),"previous_state":previous_state,"next_state":engine.state_root(),"previous_header":previous_header,"next_header":engine.head().hash_slow(),"proof_generated":false,"settled":false});
    for (name, document) in [
        ("candidates.json", candidates),
        ("continuation.json", continuation),
    ] {
        fs::write(
            dir.join(name),
            serde_json::to_string_pretty(&document).unwrap() + "\n",
        )
        .unwrap();
    }
}
