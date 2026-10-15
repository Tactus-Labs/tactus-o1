use alloy_primitives::{hex, Address, B256, U256};
use serde_json::Value;
use tactus_o1_execution::{
    native_bridge::{runtime, NativeExecutor},
    Genesis, GenesisAccount,
};
use tactus_o1_protocol::{
    batch::{self, BatchInput, BlockInput},
    native_bridge::{Batch, Config, Cursor, Record},
};
#[path = "native_ckb.rs"]
pub mod token;

pub fn actual() -> (Config, [u8; 32], Vec<Record>, Value) {
    let r: Value = serde_json::from_str(include_str!(
        "../../../../specs/evidence/native-vault-recovery/0.210.0/recovery.json"
    ))
    .unwrap();
    let r = r["cold_final"].clone();
    let script = hex::decode(r["vault_script"].as_str().unwrap()).unwrap();
    let c = Config::decode(&script[53..]).unwrap();
    let records = r["deposits"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| Record::decode(&hex::decode(r["record"].as_str().unwrap()).unwrap()).unwrap())
        .collect();
    (c, script[16..48].try_into().unwrap(), records, r)
}
pub fn genesis(c: &Config) -> Genesis {
    let mut g = token::genesis(0);
    g.rollup_id = c.rollup.into();
    g.chain_id = c.chain;
    g.accounts.remove(&token::CONTRACT);
    g.accounts.insert(
        c.contract.into(),
        GenesisAccount {
            nonce: 1,
            code: runtime(c),
            ..Default::default()
        },
    );
    g
}
pub fn record(c: &Config, cursor: Cursor, recipient: Address, amount: u64) -> Record {
    let mut r = Record {
        sequence: cursor.count + 1,
        recipient: recipient.0 .0,
        amount,
        before: cursor.accumulator,
        after: [0; 32],
        cumulative: cursor.cumulative + u128::from(amount),
    };
    r.after = batch::hash(
        b"tactus/o1/deposits/append/v1",
        &[
            c.encode().as_slice(),
            &r.encode()[..76],
            &r.cumulative.to_le_bytes(),
        ]
        .concat(),
    );
    r
}
pub fn encoded(e: &NativeExecutor, deposits: Vec<Record>, transactions: Vec<Vec<u8>>) -> Vec<u8> {
    Batch {
        deposits,
        users: BatchInput {
            parent: e.anchor().ordering,
            blocks: vec![BlockInput {
                timestamp: e.head().timestamp + 1,
                fee_recipient: Address::repeat_byte(0x22).0 .0,
                transactions,
            }],
        },
    }
    .encode(e.config(), &e.anchor())
    .unwrap()
}
pub fn signed_call(e: &NativeExecutor, user: u8, signature: &str, args: &[B256]) -> Vec<u8> {
    token::signed(
        user,
        e.account(token::user(user)).unwrap().nonce,
        alloy_primitives::TxKind::Call(e.config().contract.into()),
        token::calldata(signature, args),
        0,
    )
}
pub fn storage(e: &NativeExecutor, slot: U256) -> U256 {
    e.account(e.config().contract.into())
        .unwrap()
        .storage
        .get(&slot)
        .copied()
        .unwrap_or_default()
}
