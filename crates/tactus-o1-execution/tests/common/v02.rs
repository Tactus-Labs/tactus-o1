//! Shared synthetic 0.02 workloads for native and zkVM execution checks.
use alloy_consensus::{SignableTransaction, TxEip1559, TxEnvelope};
use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::{keccak256, Address, Bytes, TxKind, B256, U256};
use k256::ecdsa::SigningKey;
use std::collections::BTreeMap;
use tactus_o1_execution::{
    v02::{self, V02Executor},
    Genesis, GenesisAccount,
};
use tactus_o1_protocol::{batch::BlockInput, v02::*};

fn key() -> SigningKey {
    SigningKey::from_bytes((&[0x21; 32]).into()).unwrap()
}
pub fn sender() -> Address {
    Address::from_public_key(key().verifying_key())
}
pub fn halt() -> Address {
    Address::repeat_byte(33)
}
pub fn fixture() -> (Genesis, Config, Policy) {
    let mut config = Config {
        domain: Config::domain_id(&[6; 44], 0),
        ckb_genesis: [7; 32],
        adapter_code_hash: [8; 32],
        head_lock_code_hash: [9; 32],
        policy: [10; 32],
        allocation: [11; 32],
        chain: 71402,
        bridge: [12; 20],
    };
    let code = v02::runtime(&config);
    let genesis = Genesis {
        rollup_id: B256::from(config.domain),
        chain_id: config.chain,
        accounts: BTreeMap::from([
            (
                sender(),
                GenesisAccount {
                    balance: U256::from(10u64.pow(18)),
                    ..Default::default()
                },
            ),
            (
                halt(),
                GenesisAccount {
                    nonce: 1,
                    code: Bytes::from_static(&[0xfe]),
                    ..Default::default()
                },
            ),
            (
                Address::repeat_byte(34),
                GenesisAccount {
                    nonce: 1,
                    code: Bytes::from_static(&[0x60, 0, 0x60, 0, 0xfd]),
                    ..Default::default()
                },
            ),
            (
                Address::from(config.bridge),
                GenesisAccount {
                    nonce: 1,
                    code: code.clone(),
                    ..Default::default()
                },
            ),
        ]),
    };
    let policy = Policy {
        lanes: 4,
        max_pending_batches: 32,
        max_pending_deposits: 32,
        stall_blocks: 120,
        priority_gas: 250000,
        credit_gas: 200000,
        rules: v02::rules_hash(),
        profile: v02::profile_hash(),
        guest_key: [13; 32],
        wrapper_key_hash: [14; 32],
        bridge_code_hash: keccak256(code).0,
    };
    config.policy = policy.commitment().unwrap();
    config.allocation =
        tactus_o1_protocol::genesis::commitment(&genesis.allocation_bytes().unwrap()).unwrap();
    (genesis, config, policy)
}
pub fn sign(nonce: u64, target: Address, gas: u64, data: Bytes, chain: u64) -> Vec<u8> {
    let tx = TxEip1559 {
        chain_id: chain,
        nonce,
        gas_limit: gas,
        max_fee_per_gas: 2_000_000_000,
        max_priority_fee_per_gas: 1_000_000_000,
        to: TxKind::Call(target),
        input: data,
        ..Default::default()
    };
    let sig = key()
        .sign_prehash_recoverable(tx.signature_hash().as_slice())
        .unwrap()
        .into();
    TxEnvelope::from(tx.into_signed(sig)).encoded_2718()
}
pub fn build(
    engine: &V02Executor,
    priority: Vec<Vec<u8>>,
    ordinary: Vec<Vec<u8>>,
    amounts: &[u64],
) -> (NativeBatch, Snapshot) {
    let control = engine.control_candidate().unwrap();
    assert_eq!(control.boundary.batches, 0);
    let mut vault = Vault::genesis(control.boundary.config, 1000).unwrap();
    let mut records = Vec::new();
    for amount in amounts {
        let (next, record) = vault
            .deposit(
                engine.config(),
                engine.policy(),
                &control,
                sender().0 .0,
                *amount,
                [24; 32],
            )
            .unwrap();
        vault = next;
        records.push(record);
    }
    let mut lanes: Vec<_> = (0..4)
        .map(|i| Lane::genesis(control.boundary.config, i).unwrap())
        .collect();
    for (index, payload) in priority.into_iter().enumerate() {
        lanes[index] = lanes[index]
            .enqueue(&control, engine.policy(), payload)
            .unwrap()
            .0;
    }
    let (schedule, snapshot, _) = Schedule::genesis(control.boundary.config)
        .unwrap()
        .seal(
            engine.config(),
            engine.policy(),
            &control,
            engine.boundary(),
            &lanes,
            &vault,
            None,
        )
        .unwrap();
    let priority = snapshot.users().unwrap();
    let mut transactions: Vec<_> = priority.iter().map(|p| p.message.payload.clone()).collect();
    transactions.extend(ordinary);
    (
        NativeBatch {
            parent: engine.boundary().clone(),
            snapshot: schedule.snapshot,
            priority,
            deposits: records,
            blocks: vec![BlockInput {
                timestamp: 100,
                fee_recipient: [29; 20],
                transactions,
            }],
        },
        snapshot,
    )
}

pub fn mixed(engine: &V02Executor) -> (NativeBatch, Snapshot) {
    let config = engine.config();
    let mut withdraw = keccak256(b"withdraw(uint64,bytes32)")[..4].to_vec();
    withdraw.extend_from_slice(&U256::from(7).to_be_bytes::<32>());
    withdraw.extend_from_slice(&[24; 32]);
    let recipient = Address::repeat_byte(23);
    let priority = vec![
        sign(0, halt(), 250000, Bytes::new(), config.chain),
        sign(1, recipient, 21000, Bytes::new(), config.chain),
        sign(2, recipient, 250001, Bytes::new(), config.chain),
        sign(
            2,
            Address::from(config.bridge),
            150000,
            withdraw.into(),
            config.chain,
        ),
    ];
    let invalid_signature = TxEnvelope::from(
        TxEip1559 {
            chain_id: config.chain,
            nonce: 5,
            gas_limit: 21000,
            max_fee_per_gas: 2_000_000_000,
            max_priority_fee_per_gas: 1_000_000_000,
            to: TxKind::Call(recipient),
            ..Default::default()
        }
        .into_signed(alloy_primitives::Signature::new(
            U256::ZERO,
            U256::ZERO,
            false,
        )),
    )
    .encoded_2718();
    let ordinary = vec![
        sign(3, recipient, 1000000, Bytes::new(), config.chain),
        vec![2, 1],
        sign(99, recipient, 21000, Bytes::new(), config.chain),
        sign(3, recipient, 21000, Bytes::new(), config.chain + 1),
        sign(3, recipient, 21000, Bytes::new(), config.chain),
        sign(
            4,
            Address::repeat_byte(34),
            22000,
            Bytes::new(),
            config.chain,
        ),
        invalid_signature,
    ];
    build(engine, priority, ordinary, &[100])
}
