//! Native custody settlement: fixed guest identity, full-state checkpoints and
//! real Groth16 verification. A successful transition is withdrawal authority.
#![cfg_attr(target_arch = "riscv64", no_std)]
extern crate alloc;
use tactus_o1_native_anchor_script::State;
use tactus_o1_protocol::{
    batch,
    native_bridge::{Anchor, Config as VaultConfig},
};
pub const CONFIG_BYTES: usize = 136;
pub const TIP_BYTES: usize = 280;
pub const JOURNAL_BYTES: usize = 940;
pub const MAX_CELLS: usize = 64;
pub const MAX_WITNESS_BYTES: usize = 8192;
pub const MAX_PROOF_BYTES: usize = 4096;
pub const GUEST_KEY: &str = "0x00d159402000943b66d0df65c2c154592efbc8490b1ee44dfce8a181cd5e77e5";
pub const ANCHOR_CODE: [u8; 32] = [
    0x42, 0x9b, 0xa4, 0x62, 0x08, 0xc3, 0x9e, 0xd0, 0xb2, 0xb0, 0x01, 0x2d, 0x03, 0x14, 0x8b, 0x33,
    0x87, 0x08, 0x85, 0x85, 0x60, 0x43, 0xe3, 0x68, 0xc3, 0xbb, 0x42, 0xf9, 0xb2, 0x7a, 0x9a, 0x9b,
];
pub const CHECKPOINT_CODE: [u8; 32] = [
    0x3e, 0x9f, 0xaa, 0xf6, 0xe6, 0x25, 0x93, 0xe7, 0x56, 0xa2, 0x8f, 0x5c, 0x5b, 0xc2, 0xf1, 0xf3,
    0x0e, 0x49, 0x32, 0xd3, 0xf9, 0x9e, 0x07, 0x65, 0x83, 0xee, 0x99, 0x79, 0xc3, 0x41, 0x62, 0x18,
];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Config {
    pub ckb_genesis: [u8; 32],
    pub anchor_type_hash: [u8; 32],
    pub allocation_commitment: [u8; 32],
    pub vault_identity: [u8; 32],
}
impl Config {
    pub fn decode(bytes: &[u8]) -> Result<Self, i8> {
        if bytes.len() != CONFIG_BYTES || &bytes[..8] != b"TO1NSC02" {
            return Err(1);
        }
        let v = Self {
            ckb_genesis: bytes[8..40].try_into().unwrap(),
            anchor_type_hash: bytes[40..72].try_into().unwrap(),
            allocation_commitment: bytes[72..104].try_into().unwrap(),
            vault_identity: bytes[104..136].try_into().unwrap(),
        };
        if [
            v.ckb_genesis,
            v.anchor_type_hash,
            v.allocation_commitment,
            v.vault_identity,
        ]
        .contains(&[0; 32])
        {
            return Err(1);
        }
        Ok(v)
    }
    pub fn encode(&self) -> [u8; CONFIG_BYTES] {
        let mut b = [0; CONFIG_BYTES];
        b[..8].copy_from_slice(b"TO1NSC02");
        for (i, v) in [
            self.ckb_genesis,
            self.anchor_type_hash,
            self.allocation_commitment,
            self.vault_identity,
        ]
        .iter()
        .enumerate()
        {
            b[8 + i * 32..40 + i * 32].copy_from_slice(v);
        }
        b
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tip {
    pub initialized: bool,
    pub anchor: [u8; 200],
    pub state_root: [u8; 32],
    pub header_hash: [u8; 32],
}
fn number(bytes: &[u8]) -> u64 {
    u64::from_le_bytes(bytes.try_into().unwrap())
}
fn anchor_shape(bytes: &[u8; 200]) -> bool {
    &bytes[..8] == b"TO1ANC01"
        && bytes[8..40] != [0; 32]
        && number(&bytes[192..200]) != 0
        && bytes[96..128] != [0; 32]
}
impl Tip {
    pub fn initial(anchor: [u8; 200]) -> Result<Self, i8> {
        if !anchor_shape(&anchor) || anchor[40..96] != [0; 56] {
            return Err(4);
        }
        Ok(Self {
            initialized: false,
            anchor,
            state_root: [0; 32],
            header_hash: [0; 32],
        })
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, i8> {
        if bytes.len() != TIP_BYTES
            || &bytes[..8] != b"TO1TIP01"
            || bytes[8] > 1
            || bytes[9..16] != [0; 7]
        {
            return Err(3);
        }
        let tip = Self {
            initialized: bytes[8] == 1,
            anchor: bytes[16..216].try_into().unwrap(),
            state_root: bytes[216..248].try_into().unwrap(),
            header_hash: bytes[248..280].try_into().unwrap(),
        };
        if !anchor_shape(&tip.anchor) {
            return Err(3);
        }
        if !tip.initialized && Self::initial(tip.anchor)? != tip {
            return Err(3);
        }
        if tip.initialized && number(&tip.anchor[40..48]) == 0 {
            return Err(3);
        }
        Ok(tip)
    }
    pub fn encode(&self) -> [u8; TIP_BYTES] {
        let mut out = [0; TIP_BYTES];
        out[..8].copy_from_slice(b"TO1TIP01");
        out[8] = u8::from(self.initialized);
        out[16..216].copy_from_slice(&self.anchor);
        out[216..248].copy_from_slice(&self.state_root);
        out[248..].copy_from_slice(&self.header_hash);
        out
    }
}

pub fn profile_id() -> [u8; 32] {
    batch::hash(b"tactus/o1/native-proof-profile/v2",b"TO1NPR02;full-vault-config;fixed-vault-code;replay-canonical-genesis-prefix;authenticated-publication-required;nonempty-contiguous-interval;native-deposit-cursors;ethereum-state-and-header;ckb-settlement-required")
}
/// Full custody domain plus the fixed publisher and allocation. The vault type
/// hash is intentionally absent from args to avoid a settlement/vault hash cycle.
pub fn bind_state(c: &Config, own: &[u8; 32], state: &State) -> Result<(), i8> {
    Config::decode(&c.encode())?;
    State::decode(&state.encode()).map_err(|_| 6)?;
    if state.config.ckb_genesis != c.ckb_genesis
        || state.config.identity != c.vault_identity
        || state.config.settlement != *own
    {
        return Err(6);
    }
    let mut script = alloc::vec::Vec::new();
    for n in [117u32, 16, 48, 49] {
        script.extend_from_slice(&n.to_le_bytes());
    }
    script.extend_from_slice(&ANCHOR_CODE);
    script.push(2);
    script.extend_from_slice(&64u32.to_le_bytes());
    script.extend_from_slice(&state.config.rollup);
    script.extend_from_slice(&c.allocation_commitment);
    if batch::hash(b"", &script) != c.anchor_type_hash {
        return Err(6);
    }
    Ok(())
}
/// Structural checks only. On-chain callers additionally authenticate both full
/// boundaries (genesis or immutable checkpoints) and verify the actual proof.
pub fn transition(
    c: &Config,
    own: &[u8; 32],
    before: &Tip,
    after: &Tip,
    j: &[u8; JOURNAL_BYTES],
) -> Result<(State, State), i8> {
    Tip::decode(&before.encode())?;
    Tip::decode(&after.encode())?;
    if &j[..8] != b"TO1NPR02"
        || j[8..40] != profile_id()
        || j[204..236] != c.anchor_type_hash
        || j[236..268] != c.allocation_commitment
    {
        return Err(6);
    }
    let config = VaultConfig::decode(&j[40..204]).map_err(|_| 6)?;
    let b = State {
        config: config.clone(),
        anchor: Anchor::decode(&j[268..524]).map_err(|_| 6)?,
    };
    let a = State {
        config,
        anchor: Anchor::decode(&j[524..780]).map_err(|_| 6)?,
    };
    bind_state(c, own, &b)?;
    bind_state(c, own, &a)?;
    if !after.initialized
        || b.anchor.ordering.encode() != before.anchor
        || a.anchor.ordering.encode() != after.anchor
        || j[812..844] != after.state_root
        || j[876..908] != after.header_hash
        || (before.initialized
            && (j[780..812] != before.state_root || j[844..876] != before.header_hash))
        || (!before.initialized && b != State::genesis(b.config.clone()).map_err(|_| 7)?)
        || before.anchor[8..40] != after.anchor[8..40]
        || before.anchor[96..] != after.anchor[96..]
        || number(&before.anchor[40..48]) >= number(&after.anchor[40..48])
        || number(&before.anchor[80..88]) >= number(&after.anchor[80..88])
        || number(&before.anchor[88..96]) >= number(&after.anchor[88..96])
        || b.anchor.deposits.count > a.anchor.deposits.count
        || b.anchor.deposits.cumulative > a.anchor.deposits.cumulative
        || (b.anchor.deposits.count == a.anchor.deposits.count
            && b.anchor.deposits != a.anchor.deposits)
        || (b.anchor.deposits.count < a.anchor.deposits.count
            && b.anchor.deposits.cumulative == a.anchor.deposits.cumulative)
    {
        return Err(7);
    }
    Ok((b, a))
}
pub fn witness(bytes: &[u8]) -> Result<(&[u8; JOURNAL_BYTES], &[u8]), i8> {
    const PREFIX: usize = 8 + JOURNAL_BYTES + 4;
    if bytes.len() < PREFIX || &bytes[..8] != b"TO1NSW02" {
        return Err(5);
    }
    let len = u32::from_le_bytes(bytes[8 + JOURNAL_BYTES..PREFIX].try_into().unwrap()) as usize;
    if len == 0 || len > MAX_PROOF_BYTES || len != bytes.len() - PREFIX {
        return Err(5);
    }
    Ok((
        bytes[8..8 + JOURNAL_BYTES].try_into().unwrap(),
        &bytes[PREFIX..],
    ))
}

#[cfg(all(target_arch = "riscv64", feature = "entry"))]
mod onchain;
