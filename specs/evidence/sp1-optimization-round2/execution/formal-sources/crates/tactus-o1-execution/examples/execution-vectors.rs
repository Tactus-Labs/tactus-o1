//! Generates inputs and candidate outputs; Geth independently checks them.
use alloy_consensus::{SignableTransaction, TxEip1559, TxEip2930, TxEnvelope, TxLegacy};
use alloy_eips::{
    eip2718::{Decodable2718, Encodable2718},
    eip2930::{AccessList, AccessListItem},
};
use alloy_primitives::{address, hex, Address, Bytes, Signature, TxKind, B256, U256};
use k256::ecdsa::SigningKey;
use serde_json::{json, Value};
use std::{collections::BTreeMap, fs, path::Path};
use tactus_o1_execution::{Executor, Genesis, GenesisAccount};
use tactus_o1_protocol::batch::{BatchInput, BlockInput};
const TO: Address = address!("1111111111111111111111111111111111111111");
const BUILDER: Address = address!("2222222222222222222222222222222222222222");
const CONTRACT: Address = address!("3333333333333333333333333333333333333333");
pub(crate) fn key() -> SigningKey {
    SigningKey::from_bytes((&[0x21; 32]).into()).unwrap()
}
pub(crate) fn sender() -> Address {
    Address::from_public_key(key().verifying_key())
}
fn sig(tx: &impl SignableTransaction<Signature>) -> Signature {
    key()
        .sign_prehash_recoverable(tx.signature_hash().as_slice())
        .unwrap()
        .into()
}
pub(crate) fn tx(nonce: u64) -> TxEip1559 {
    TxEip1559 {
        chain_id: 31337,
        nonce,
        gas_limit: 300_000,
        max_fee_per_gas: 2_000_000_000,
        max_priority_fee_per_gas: 1_000_000_000,
        to: TxKind::Call(TO),
        value: U256::ZERO,
        ..Default::default()
    }
}
pub(crate) fn sign(tx: TxEip1559) -> Vec<u8> {
    let s = sig(&tx);
    TxEnvelope::from(tx.into_signed(s)).encoded_2718()
}
pub(crate) fn genesis() -> Genesis {
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
fn contract(code: &[u8]) -> Genesis {
    let mut g = genesis();
    g.accounts.insert(
        CONTRACT,
        GenesisAccount {
            nonce: 1,
            code: Bytes::copy_from_slice(code),
            ..Default::default()
        },
    );
    g
}
fn call(n: u64) -> TxEip1559 {
    let mut t = tx(n);
    t.to = TxKind::Call(CONTRACT);
    t
}
pub(crate) fn case(name: &str, genesis: Genesis, inputs: Vec<Vec<Vec<u8>>>) -> Value {
    let mut engine = Executor::new(&genesis).unwrap();
    let mut hashes = BTreeMap::from([("0x0".to_owned(), engine.head().hash_slow())]);
    let input = BatchInput {
        parent: *engine.anchor(),
        blocks: inputs
            .iter()
            .map(|txs| BlockInput {
                timestamp: 10,
                fee_recipient: BUILDER.0 .0,
                transactions: txs.clone(),
            })
            .collect(),
    }
    .encode()
    .unwrap();
    let blocks = engine.apply_batch(&input).unwrap();
    let mut entries = Vec::new();
    for (block, txs) in blocks.into_iter().zip(inputs) {
        let env = json!({"currentCoinbase":BUILDER,"currentGasLimit":"0xf4240","currentNumber":format!("0x{:x}",block.header.number),"currentTimestamp":"0xa","currentRandom":B256::ZERO,"currentBaseFee":format!("0x{:x}",block.header.base_fee_per_gas.unwrap()),"withdrawals":[],"blockHashes":hashes});
        hashes.insert(format!("0x{:x}", block.header.number), block.hash);
        entries.push(json!({"env":env,"txs":txs.iter().map(|raw|TxEnvelope::decode_2718_exact(raw).unwrap()).collect::<Vec<_>>(),"expected":block}));
    }
    let alloc: BTreeMap<_,_> = genesis.accounts.iter().map(|(address,a)| {
        let storage:BTreeMap<_,_>=a.storage.iter().map(|(k,v)|(format!("0x{k:064x}"),format!("0x{v:064x}"))).collect();
        (address,json!({"balance":format!("0x{:x}",a.balance),"nonce":format!("0x{:x}",a.nonce),"code":a.code,"storage":storage}))
    }).collect();
    json!({"name":name,"genesis":genesis,"batch":format!("0x{}",hex::encode(input)),"alloc":alloc,"blocks":entries})
}
fn main() {
    let dir = std::env::args()
        .nth(1)
        .expect("usage: execution-vectors OUTPUT_DIRECTORY");
    let mut cases = Vec::new();
    let mut transfer = tx(0);
    transfer.value = U256::from(123);
    let legacy = TxLegacy {
        chain_id: Some(31337),
        nonce: 1,
        gas_price: 2_000_000_000,
        gas_limit: 21_000,
        to: TxKind::Call(TO),
        value: U256::from(456),
        ..Default::default()
    };
    let legacy_sig = sig(&legacy);
    let access = TxEip2930 {
        chain_id: 31337,
        nonce: 2,
        gas_price: 2_000_000_000,
        gas_limit: 50_000,
        to: TxKind::Call(TO),
        value: U256::from(789),
        access_list: AccessList(vec![AccessListItem {
            address: CONTRACT,
            storage_keys: vec![B256::ZERO],
        }]),
        ..Default::default()
    };
    let access_sig = sig(&access);
    cases.push(case(
        "three-envelope-types",
        genesis(),
        vec![vec![
            sign(transfer),
            TxEnvelope::from(legacy.into_signed(legacy_sig)).encoded_2718(),
            TxEnvelope::from(access.into_signed(access_sig)).encoded_2718(),
        ]],
    ));
    let mut expensive = tx(0);
    expensive.value = U256::MAX;
    let mut intrinsic = tx(0);
    intrinsic.gas_limit = 20_999;
    let mut low_fee = tx(0);
    low_fee.max_fee_per_gas = 1;
    low_fee.max_priority_fee_per_gas = 0;
    cases.push(case(
        "invalid-slots-then-valid",
        genesis(),
        vec![vec![
            sign(tx(1)),
            sign(expensive),
            sign(intrinsic),
            sign(low_fee),
            sign(tx(0)),
            sign(tx(0)),
            sign(tx(1)),
        ]],
    ));
    let runtime = hex!("5f355f555f5fa000");
    let mut init = hex!("6008600c60003960086000f3").to_vec();
    init.extend(runtime);
    let mut create = tx(0);
    create.to = TxKind::Create;
    create.input = init.into();
    let mut write = tx(1);
    write.to = TxKind::Call(sender().create(0));
    write.input = U256::from(42).to_be_bytes::<32>().to_vec().into();
    let mut clear = write.clone();
    clear.nonce = 2;
    clear.input = Bytes::new();
    cases.push(case(
        "deploy-write-clear",
        genesis(),
        vec![vec![sign(create), sign(write)], vec![sign(clear)]],
    ));
    cases.push(case(
        "revert-after-store-log",
        contract(&hex!("602a5f555f5fa05f5ffd")),
        vec![vec![sign(call(0)), sign(tx(1))]],
    ));
    cases.push(case(
        "halt-after-store-log",
        contract(&hex!("602a5f555f5fa0fe")),
        vec![vec![sign(call(0)), sign(tx(1))]],
    ));
    let mut g = contract(&hex!("731111111111111111111111111111111111111111ff"));
    g.accounts.get_mut(&CONTRACT).unwrap().balance = U256::from(999);
    g.accounts
        .get_mut(&CONTRACT)
        .unwrap()
        .storage
        .insert(U256::ZERO, U256::from(42));
    cases.push(case(
        "shanghai-selfdestruct",
        g,
        vec![vec![sign(call(0))], vec![sign(call(1))]],
    ));
    let context = hex!("435f55426001554860025541600355466004554460055545600655600143034060075500");
    cases.push(case(
        "context-and-empty-block",
        contract(&context),
        vec![vec![sign(call(0))], vec![], vec![sign(call(1))]],
    ));
    let mut sha = tx(0);
    sha.to = TxKind::Call(Address::with_last_byte(2));
    sha.input = Bytes::from_static(b"abc");
    let mut identity = sha.clone();
    identity.nonce = 1;
    identity.to = TxKind::Call(Address::with_last_byte(4));
    cases.push(case(
        "sha256-identity-precompiles",
        genesis(),
        vec![vec![sign(sha), sign(identity)]],
    ));
    let mut halt = call(0);
    halt.gas_limit = 980_000;
    let mut over = tx(1);
    over.gas_limit = 21_000;
    cases.push(case(
        "block-gas-exhaustion",
        contract(&[0xfe]),
        vec![vec![sign(halt), sign(over)], vec![sign(tx(1))]],
    ));
    fs::create_dir_all(&dir).unwrap();
    let document = json!({"schema":1,"rules_hash":format!("0x{}",hex::encode(tactus_o1_execution::rules_hash())),"cases":cases});
    fs::write(
        Path::new(&dir).join("candidates.json"),
        serde_json::to_string_pretty(&document).unwrap() + "\n",
    )
    .unwrap();
}
