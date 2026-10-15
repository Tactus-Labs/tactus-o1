//! Workloads separating state size, touched state and empty-block costs.
#[allow(dead_code)]
#[path = "execution-vectors.rs"]
mod vectors;
use alloy_primitives::{Address, Bytes, TxKind, U256};
use std::{collections::BTreeMap, fs, path::Path};
use tactus_o1_execution::GenesisAccount;

fn main() {
    let directory = std::env::args()
        .nth(1)
        .expect("state-scaling-vectors NEW_DIR");
    let directory = Path::new(&directory);
    fs::create_dir(directory).unwrap();
    let mut cases = Vec::new();
    for count in [8usize, 128, 512] {
        let mut genesis = vectors::genesis();
        for index in 0..count {
            let mut address = [0x91; 20];
            address[12..].copy_from_slice(&(index as u64).to_be_bytes());
            genesis.accounts.insert(
                Address::from(address),
                GenesisAccount {
                    balance: U256::from(1),
                    ..Default::default()
                },
            );
        }
        let raw = (0..32)
            .map(|nonce| {
                let mut tx = vectors::tx(nonce);
                tx.gas_limit = 21_000;
                vectors::sign(tx)
            })
            .collect();
        cases.push(vectors::case(
            &format!("state-{count}-transfers-32"),
            genesis.clone(),
            vec![raw],
        ));
        cases.push(vectors::case(
            &format!("state-{count}-empty-16"),
            genesis,
            vec![vec![]; 16],
        ));
    }
    for slots in [32usize, 1024] {
        let mut genesis = vectors::genesis();
        let contract = Address::repeat_byte(0x88);
        genesis.accounts.insert(
            contract,
            GenesisAccount {
                nonce: 1,
                code: Bytes::from_static(&[0x60, 0x2a, 0x60, 0x00, 0x55, 0x00]),
                storage: (1..=slots)
                    .map(|i| (U256::from(i), U256::from(i)))
                    .collect::<BTreeMap<_, _>>(),
                ..Default::default()
            },
        );
        let raw = (0..8)
            .map(|nonce| {
                let mut tx = vectors::tx(nonce);
                tx.to = TxKind::Call(contract);
                tx.value = U256::ZERO;
                vectors::sign(tx)
            })
            .collect();
        cases.push(vectors::case(
            &format!("storage-{slots}-writes-8"),
            genesis,
            vec![raw],
        ));
    }
    fs::write(directory.join("candidates.json"), serde_json::to_vec_pretty(&serde_json::json!({
        "schema":1,"rules_hash":format!("0x{}",alloy_primitives::hex::encode(tactus_o1_execution::rules_hash())),"cases":cases
    })).unwrap()).unwrap();
}
