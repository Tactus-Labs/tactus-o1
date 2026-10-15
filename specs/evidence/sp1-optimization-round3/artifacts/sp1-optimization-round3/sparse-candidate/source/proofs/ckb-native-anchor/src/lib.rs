//! Native deposit publication authority, independent from proof settlement.
#![cfg_attr(target_arch = "riscv64", no_std)]
extern crate alloc;
use alloc::vec::Vec;
use alloy_primitives::{keccak256, U256};
use tactus_o1_protocol::{
    batch, genesis,
    native_bridge::{Anchor, Config, Cursor},
};
include!(concat!(env!("OUT_DIR"), "/pinned.rs"));
pub const STATE_BYTES: usize = 428;
pub const MAX_CELLS: usize = 64;
pub const HEAD_LOCK: [u8; 32] = [
    0x1a, 0x79, 0xae, 0x4b, 0x82, 0xf5, 0x58, 0x8e, 0x07, 0xfc, 0x0b, 0x94, 0xa0, 0xe8, 0xfb, 0xcf,
    0x61, 0xf1, 0xad, 0xc0, 0x6d, 0x05, 0xd7, 0x53, 0xd1, 0x3e, 0x2e, 0x63, 0xee, 0xc7, 0x6d, 0xee,
];
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct State {
    pub config: Config,
    pub anchor: Anchor,
}
impl State {
    pub fn decode(b: &[u8]) -> Result<Self, i8> {
        if b.len() != STATE_BYTES || &b[..8] != b"TO1NAP02" {
            return Err(3);
        }
        let config = Config::decode(&b[8..172]).map_err(|_| 3)?;
        let anchor = Anchor::decode(&b[172..]).map_err(|_| 3)?;
        if anchor.ordering.rollup_id != config.rollup
            || anchor.ordering.chain_id != config.chain
            || anchor.ordering.execution_rules_hash != RULES
        {
            return Err(4);
        }
        Ok(Self { config, anchor })
    }
    pub fn encode(&self) -> [u8; STATE_BYTES] {
        let mut b = [0; STATE_BYTES];
        b[..8].copy_from_slice(b"TO1NAP02");
        b[8..172].copy_from_slice(&self.config.encode());
        b[172..].copy_from_slice(&self.anchor.encode());
        b
    }
    pub fn genesis(config: Config) -> Result<Self, i8> {
        Config::decode(&config.encode()).map_err(|_| 3)?;
        let ordering =
            batch::AnchorState::genesis(config.rollup, RULES, config.chain).map_err(|_| 4)?;
        let deposits = Cursor::genesis(&config);
        Ok(Self {
            config,
            anchor: Anchor { ordering, deposits },
        })
    }
    pub fn vault_script(&self) -> Vec<u8> {
        self.config.vault_script(VAULT_CODE)
    }
    pub fn vault_type_hash(&self) -> [u8; 32] {
        batch::hash(b"", &self.vault_script())
    }
}
pub fn runtime(c: &Config) -> Vec<u8> {
    let seed = keccak256(
        [
            b"TO1CKBD1".as_slice(),
            &c.ckb_genesis,
            &c.rollup,
            &c.identity,
        ]
        .concat(),
    );
    let domain = keccak256(
        [
            b"TO1BRDG1".as_slice(),
            seed.as_slice(),
            &U256::from(c.chain).to_be_bytes::<32>(),
            &c.contract,
        ]
        .concat(),
    );
    let mut bytes = RUNTIME.to_vec();
    for &p in PATCHES {
        bytes[p..p + 32].copy_from_slice(domain.as_slice());
    }
    bytes
}
pub fn validate_allocation(c: &Config, bytes: &[u8], expected: [u8; 32]) -> Result<(), i8> {
    if genesis::commitment(bytes).map_err(|_| 6)? != expected
        || U256::from_be_slice(&c.contract) <= U256::from(9)
    {
        return Err(6);
    }
    let a = genesis::Allocation::decode(bytes).map_err(|_| 6)?;
    let mut found = false;
    for account in a.accounts {
        if account.address == [0; 20] {
            return Err(6);
        }
        if account.address == c.contract {
            if account.nonce != 1
                || account.balance != [0; 32]
                || !account.storage.is_empty()
                || account.code != runtime(c)
            {
                return Err(6);
            }
            found = true;
        }
    }
    if !found {
        return Err(6);
    }
    Ok(())
}
#[cfg(all(target_arch = "riscv64", feature = "entry"))]
mod onchain;
