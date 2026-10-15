//! Filled-block and ECRECOVER inputs for independent Geth and zkVM comparisons.
#[allow(dead_code)]
#[path = "execution-vectors.rs"]
mod vectors;

use alloy_primitives::{hex, Address, Bytes, TxKind, U256};
use serde_json::json;
use std::{fs, path::Path};

fn recovery_input() -> Vec<u8> {
    let message = [0x42; 32];
    let (sig, recid) = vectors::key().sign_prehash_recoverable(&message).unwrap();
    let mut data = vec![0; 128];
    data[..32].copy_from_slice(&message);
    data[63] = 27 + recid.to_byte();
    data[64..].copy_from_slice(&sig.to_bytes());
    data
}

fn main() {
    let directory = std::env::args()
        .nth(1)
        .expect("optimization-vectors NEW_DIR");
    let directory = Path::new(&directory);
    fs::create_dir(directory).unwrap();
    let mut cases = Vec::new();
    for count in [1usize, 8, 32, 128, 512] {
        let raw: Vec<_> = (0..count)
            .map(|nonce| {
                let mut tx = vectors::tx(nonce as u64);
                tx.gas_limit = 21_000;
                tx.value = U256::from(123);
                vectors::sign(tx)
            })
            .collect();
        cases.push(vectors::case(
            &format!("transfers-{count}"),
            vectors::genesis(),
            raw.chunks(32).map(|b| b.to_vec()).collect(),
        ));
    }
    for count in [1usize, 8] {
        let raw: Vec<_> = (0..count)
            .map(|nonce| {
                let mut tx = vectors::tx(nonce as u64);
                tx.to = TxKind::Call(Address::with_last_byte(1));
                tx.gas_limit = 50_000;
                tx.input = Bytes::from(recovery_input());
                vectors::sign(tx)
            })
            .collect();
        let case = vectors::case(&format!("ecrecover-{count}"), vectors::genesis(), vec![raw]);
        let wanted = format!("0x{}{}", "00".repeat(12), hex::encode(vectors::sender()));
        for outcome in case["blocks"][0]["expected"]["outcomes"]
            .as_array()
            .unwrap()
        {
            assert_eq!(outcome["output"], wanted);
            assert_eq!(outcome["status"], "Success");
        }
        cases.push(case);
    }
    let valid = recovery_input();
    let mut high_s = valid.clone();
    let order = U256::from_be_slice(
        &hex::decode("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141").unwrap(),
    );
    high_s[96..].copy_from_slice(&(order - U256::from_be_slice(&valid[96..])).to_be_bytes::<32>());
    high_s[63] = if valid[63] == 27 { 28 } else { 27 };
    let mut invalid_v = valid.clone();
    invalid_v[63] = 26;
    let mut v_padding = valid.clone();
    v_padding[32] = 1;
    let mut zero_r = valid.clone();
    zero_r[64..96].fill(0);
    let mut zero_s = valid.clone();
    zero_s[96..].fill(0);
    let mut overlong = valid.clone();
    overlong.extend_from_slice(&[9; 17]);
    let mut overflowing_s = valid.clone();
    overflowing_s[96..].copy_from_slice(&order.to_be_bytes::<32>());
    let inputs = [
        valid,
        high_s,
        invalid_v,
        v_padding,
        zero_r,
        zero_s,
        overlong,
        vec![],
        overflowing_s,
    ];
    let raw = inputs
        .into_iter()
        .enumerate()
        .map(|(nonce, data)| {
            let mut tx = vectors::tx(nonce as u64);
            tx.to = TxKind::Call(Address::with_last_byte(1));
            tx.gas_limit = 50_000;
            tx.input = data.into();
            vectors::sign(tx)
        })
        .collect();
    let case = vectors::case("ecrecover-edge-cases", vectors::genesis(), vec![raw]);
    let wanted = format!("0x{}{}", "00".repeat(12), hex::encode(vectors::sender()));
    for (index, outcome) in case["blocks"][0]["expected"]["outcomes"]
        .as_array()
        .unwrap()
        .iter()
        .enumerate()
    {
        assert_eq!(outcome["status"], "Success");
        assert_eq!(
            outcome["output"],
            if [0, 1, 6].contains(&index) {
                &wanted
            } else {
                "0x"
            }
        );
    }
    cases.push(case);
    fs::write(directory.join("candidates.json"), serde_json::to_vec_pretty(&json!({
        "schema": 1, "rules_hash": format!("0x{}", hex::encode(tactus_o1_execution::rules_hash())), "cases": cases
    })).unwrap()).unwrap();
}
