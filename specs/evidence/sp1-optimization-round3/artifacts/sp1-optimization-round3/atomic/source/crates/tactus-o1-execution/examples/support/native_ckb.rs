//! Fixture helpers only. Seeded token balances are NOT authenticated CKB deposits.
use alloy_consensus::{SignableTransaction, TxEip1559, TxEnvelope};
use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::{hex, keccak256, Address, Bytes, TxKind, B256, U256};
use k256::ecdsa::SigningKey;
use serde_json::Value;
use std::collections::BTreeMap;
use tactus_o1_execution::{Executor, Genesis, GenesisAccount, SlotOutcome};
use tactus_o1_protocol::batch::{BatchInput, BlockInput};

pub const CONTRACT: Address = Address::repeat_byte(0x33);
pub const BRIDGE: B256 = B256::repeat_byte(0x44);
pub const RECIPIENT: B256 = B256::repeat_byte(0x55);
pub fn key(index: u8) -> SigningKey {
    SigningKey::from_bytes((&[0x21 + index; 32]).into()).unwrap()
}
pub fn user(index: u8) -> Address {
    Address::from_public_key(key(index).verifying_key())
}
pub fn artifact() -> Value {
    serde_json::from_str(include_str!("../../../../contracts/bridge/NativeCKB.json")).unwrap()
}
pub fn domain(contract: Address, chain: u64, bridge: B256) -> B256 {
    keccak256(
        [
            b"TO1BRDG1".as_slice(),
            bridge.as_slice(),
            &U256::from(chain).to_be_bytes::<32>(),
            contract.as_slice(),
        ]
        .concat(),
    )
}
pub fn runtime() -> Bytes {
    let artifact = artifact();
    let deployed = &artifact["contract"]["evm"]["deployedBytecode"];
    let mut bytes = hex::decode(deployed["object"].as_str().unwrap()).unwrap();
    for patches in deployed["immutableReferences"]
        .as_object()
        .unwrap()
        .values()
    {
        for patch in patches.as_array().unwrap() {
            assert_eq!(patch["length"], 32);
            let start = patch["start"].as_u64().unwrap() as usize;
            bytes[start..start + 32].copy_from_slice(domain(CONTRACT, 31337, BRIDGE).as_slice());
        }
    }
    bytes.into()
}
pub fn creation(bridge: B256) -> Bytes {
    let mut bytes = hex::decode(
        artifact()["contract"]["evm"]["bytecode"]["object"]
            .as_str()
            .unwrap(),
    )
    .unwrap();
    bytes.extend_from_slice(bridge.as_slice());
    bytes.into()
}
pub fn quantity(value: u64) -> B256 {
    B256::from(U256::from(value).to_be_bytes::<32>())
}
pub fn address_word(value: Address) -> B256 {
    let mut out = [0; 32];
    out[12..].copy_from_slice(value.as_slice());
    out.into()
}
pub fn slot(key: B256, position: u64) -> U256 {
    U256::from_be_bytes(keccak256([key.as_slice(), quantity(position).as_slice()].concat()).0)
}
pub fn calldata(signature: &str, args: &[B256]) -> Bytes {
    let mut out = keccak256(signature.as_bytes())[..4].to_vec();
    for arg in args {
        out.extend_from_slice(arg.as_slice());
    }
    out.into()
}
pub fn genesis(tokens: u64) -> Genesis {
    let mut accounts: BTreeMap<_, _> = (0..3)
        .map(|i| {
            (
                user(i),
                GenesisAccount {
                    balance: U256::from(1_000_000_000_000_000_000u64),
                    ..Default::default()
                },
            )
        })
        .collect();
    let mut storage = BTreeMap::new();
    if tokens != 0 {
        storage.insert(U256::ZERO, U256::from(tokens));
        storage.insert(U256::from(1), U256::from(tokens));
        storage.insert(slot(address_word(user(0)), 3), U256::from(tokens));
    }
    accounts.insert(
        CONTRACT,
        GenesisAccount {
            nonce: 1,
            code: runtime(),
            storage,
            ..Default::default()
        },
    );
    Genesis {
        rollup_id: B256::repeat_byte(7),
        chain_id: 31337,
        accounts,
    }
}
pub fn signed(index: u8, nonce: u64, to: TxKind, input: Bytes, value: u64) -> Vec<u8> {
    let tx = TxEip1559 {
        chain_id: 31337,
        nonce,
        gas_limit: 950_000,
        max_fee_per_gas: 2_000_000_000,
        max_priority_fee_per_gas: 1_000_000_000,
        to,
        input,
        value: U256::from(value),
        ..Default::default()
    };
    let sig = key(index)
        .sign_prehash_recoverable(tx.signature_hash().as_slice())
        .unwrap()
        .into();
    TxEnvelope::from(tx.into_signed(sig)).encoded_2718()
}
pub fn batch(engine: &Executor, tx: Vec<u8>) -> Vec<u8> {
    BatchInput {
        parent: *engine.anchor(),
        blocks: vec![BlockInput {
            timestamp: engine.head().timestamp + 1,
            fee_recipient: Address::repeat_byte(0x22).0 .0,
            transactions: vec![tx],
        }],
    }
    .encode()
    .unwrap()
}
pub fn call(engine: &mut Executor, index: u8, signature: &str, args: &[B256]) -> SlotOutcome {
    let nonce = engine.account(user(index)).unwrap().nonce;
    let raw = signed(
        index,
        nonce,
        TxKind::Call(CONTRACT),
        calldata(signature, args),
        0,
    );
    engine
        .apply_batch(&batch(engine, raw))
        .unwrap()
        .remove(0)
        .outcomes
        .remove(0)
}
pub fn storage(engine: &Executor, slot: U256) -> U256 {
    engine
        .account(CONTRACT)
        .unwrap()
        .storage
        .get(&slot)
        .copied()
        .unwrap_or_default()
}
pub fn balance(engine: &Executor, index: u8) -> U256 {
    storage(engine, slot(address_word(user(index)), 3))
}
pub fn claim(id: u64, amount: u64, recipient: B256, owner: Address) -> B256 {
    keccak256(
        [
            b"TO1EXIT1".as_slice(),
            domain(CONTRACT, 31337, BRIDGE).as_slice(),
            &id.to_be_bytes(),
            &amount.to_be_bytes(),
            recipient.as_slice(),
            owner.as_slice(),
        ]
        .concat(),
    )
}
pub fn conservation(engine: &Executor) {
    let supply = storage(engine, U256::ZERO);
    assert_eq!(supply, (0..3).map(|i| balance(engine, i)).sum::<U256>());
    assert_eq!(
        storage(engine, U256::from(1)),
        supply + storage(engine, U256::from(2))
    );
}
