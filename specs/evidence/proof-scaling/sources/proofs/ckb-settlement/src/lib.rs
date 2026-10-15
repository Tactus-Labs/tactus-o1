//! Proof-consuming SettlementTip prototype. No bridge/withdrawal authority.
#![cfg_attr(target_arch = "riscv64", no_std)]
#[cfg(target_arch = "riscv64")]
extern crate alloc;

pub const CONFIG_BYTES: usize = 168;
pub const TIP_BYTES: usize = 280;
pub const JOURNAL_BYTES: usize = 768;
pub const MAX_CELLS: usize = 64;
pub const MAX_WITNESS_BYTES: usize = 8192;
pub const MAX_PROOF_BYTES: usize = 4096;
// Exact TO1PRF01 execution profile committed by the pinned guest.
pub const PROFILE: [u8; 32] = [
    0xf0, 0xb9, 0x90, 0x68, 0x40, 0xf2, 0xa4, 0x42, 0x6a, 0x84, 0x07, 0x58, 0x41, 0xa3, 0x9f, 0xcb,
    0xbd, 0x9d, 0x3f, 0xce, 0xc0, 0x61, 0x7d, 0x0e, 0x7e, 0xb1, 0x99, 0x7f, 0x74, 0xaf, 0x1f, 0x38,
];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Config {
    pub ckb_genesis: [u8; 32],
    pub anchor_type_hash: [u8; 32],
    pub guest_key: [u8; 32],
    pub checkpoint_code_hash: [u8; 32],
    pub allocation_commitment: [u8; 32],
}
impl Config {
    pub fn decode(bytes: &[u8]) -> Result<Self, i8> {
        if bytes.len() != CONFIG_BYTES || &bytes[..8] != b"TO1CFG01" {
            return Err(1);
        }
        let value = Self {
            ckb_genesis: bytes[8..40].try_into().unwrap(),
            anchor_type_hash: bytes[40..72].try_into().unwrap(),
            guest_key: bytes[72..104].try_into().unwrap(),
            checkpoint_code_hash: bytes[104..136].try_into().unwrap(),
            allocation_commitment: bytes[136..168].try_into().unwrap(),
        };
        if [
            value.ckb_genesis,
            value.anchor_type_hash,
            value.guest_key,
            value.checkpoint_code_hash,
            value.allocation_commitment,
        ]
        .contains(&[0; 32])
        {
            return Err(1);
        }
        Ok(value)
    }
    pub fn encode(&self) -> [u8; CONFIG_BYTES] {
        let mut out = [0; CONFIG_BYTES];
        out[..8].copy_from_slice(b"TO1CFG01");
        for (i, field) in [
            self.ckb_genesis,
            self.anchor_type_hash,
            self.guest_key,
            self.checkpoint_code_hash,
            self.allocation_commitment,
        ]
        .iter()
        .enumerate()
        {
            out[8 + i * 32..40 + i * 32].copy_from_slice(field);
        }
        out
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

/// Structural binding only; callers must additionally authenticate the ending
/// checkpoint and verify the real Groth16 proof under Config.guest_key.
pub fn transition(
    config: &Config,
    own_type_hash: &[u8; 32],
    before: &Tip,
    after: &Tip,
    journal: &[u8; JOURNAL_BYTES],
) -> Result<(), i8> {
    Tip::decode(&before.encode())?;
    Tip::decode(&after.encode())?;
    if &journal[..8] != b"TO1PRF01"
        || journal[8..40] != PROFILE
        || journal[40..72] != config.ckb_genesis
        || journal[72..104] != config.anchor_type_hash
        || journal[104..136] != *own_type_hash
        || journal[176..208] != config.allocation_commitment
        || journal[136..168] != before.anchor[8..40]
        || journal[168..176] != before.anchor[192..200]
    {
        return Err(6);
    }
    if !after.initialized
        || journal[208..408] != before.anchor
        || journal[408..608] != after.anchor
        || journal[640..672] != after.state_root
        || journal[704..736] != after.header_hash
        || (before.initialized
            && (journal[608..640] != before.state_root || journal[672..704] != before.header_hash))
        || (!before.initialized && Tip::initial(before.anchor)? != *before)
        || before.anchor[8..40] != after.anchor[8..40]
        || before.anchor[96..] != after.anchor[96..]
        || number(&before.anchor[40..48]) >= number(&after.anchor[40..48])
        || number(&before.anchor[80..88]) >= number(&after.anchor[80..88])
        || number(&before.anchor[88..96]) >= number(&after.anchor[88..96])
    {
        return Err(7);
    }
    Ok(())
}

pub fn witness(bytes: &[u8]) -> Result<(&[u8; JOURNAL_BYTES], &[u8]), i8> {
    const PREFIX: usize = 8 + JOURNAL_BYTES + 4;
    if bytes.len() < PREFIX || &bytes[..8] != b"TO1SETW1" {
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

#[cfg(target_arch = "riscv64")]
mod onchain {
    use super::*;
    use alloc::vec;
    use ckb_std::{
        ckb_constants::Source,
        ckb_types::{
            packed::{Script, WitnessArgs},
            prelude::*,
        },
        error::SysError,
        high_level::*,
        syscalls,
    };
    ckb_std::default_alloc!();
    ckb_std::entry!(entrypoint);
    fn entrypoint() -> i8 {
        run().map_or_else(|e| e, |()| 0)
    }
    fn data<const N: usize>(index: usize, source: Source) -> Result<[u8; N], i8> {
        let mut bytes = [0; N];
        if syscalls::load_cell_data(&mut bytes, 0, index, source) != Ok(N) {
            return Err(3);
        }
        Ok(bytes)
    }
    fn matching(source: Source, identity: &[u8; 32]) -> Result<Option<usize>, i8> {
        let mut found = None;
        for index in 0..=MAX_CELLS {
            match load_cell_type_hash(index, source) {
                Err(SysError::IndexOutOfBound) => return Ok(found),
                Ok(value) if index < MAX_CELLS => {
                    if value == Some(*identity) && found.replace(index).is_some() {
                        return Err(4);
                    }
                }
                _ => return Err(4),
            }
        }
        Err(4)
    }
    fn checkpoint(config: &Config, anchor: &[u8; 200]) -> Result<(), i8> {
        let expected = Script::new_builder()
            .code_hash(config.checkpoint_code_hash.pack())
            .hash_type(2u8.into())
            .args(config.anchor_type_hash.to_vec().pack())
            .build();
        let mut found = false;
        for index in 0..=MAX_CELLS {
            match load_cell_type(index, Source::CellDep) {
                Err(SysError::IndexOutOfBound) => return if found { Ok(()) } else { Err(8) },
                Ok(Some(script)) if index < MAX_CELLS && script == expected => {
                    if data::<200>(index, Source::CellDep).map_err(|_| 8)? == *anchor {
                        found = true;
                    }
                }
                Ok(_) if index < MAX_CELLS => {}
                _ => return Err(8),
            }
        }
        Err(8)
    }
    fn run() -> Result<(), i8> {
        let script = load_script().map_err(|_| 1)?;
        let config = Config::decode(&script.args().raw_data())?;
        if load_cell_capacity(1, Source::GroupInput) != Err(SysError::IndexOutOfBound)
            || load_cell_capacity(1, Source::GroupOutput) != Err(SysError::IndexOutOfBound)
        {
            return Err(2);
        }
        let after = Tip::decode(&data::<TIP_BYTES>(0, Source::GroupOutput)?)?;
        if load_cell_capacity(0, Source::GroupInput) == Err(SysError::IndexOutOfBound) {
            if after != Tip::initial(after.anchor)?
                || matching(Source::Input, &config.anchor_type_hash)?.is_some()
            {
                return Err(4);
            }
            let index = matching(Source::Output, &config.anchor_type_hash)?.ok_or(4)?;
            if data::<200>(index, Source::Output)? != after.anchor {
                return Err(4);
            }
            let anchor_script = load_cell_type(index, Source::Output)
                .map_err(|_| 4)?
                .ok_or(4)?;
            let args = anchor_script.args().raw_data();
            if args.len() != 64
                || args[..32] != after.anchor[8..40]
                || args[32..] != config.allocation_commitment
            {
                return Err(4);
            }
            return Ok(());
        }
        let before = Tip::decode(&data::<TIP_BYTES>(0, Source::GroupInput)?)?;
        if load_cell_capacity(0, Source::GroupInput).map_err(|_| 10)?
            != load_cell_capacity(0, Source::GroupOutput).map_err(|_| 10)?
            || load_cell_lock_hash(0, Source::GroupInput).map_err(|_| 10)?
                != load_cell_lock_hash(0, Source::GroupOutput).map_err(|_| 10)?
        {
            return Err(10);
        }
        let len = match syscalls::load_witness(&mut [], 0, 0, Source::GroupInput) {
            Ok(n) | Err(SysError::LengthNotEnough(n)) => n,
            Err(_) => return Err(5),
        };
        if len > MAX_WITNESS_BYTES {
            return Err(5);
        }
        let mut bytes = vec![0; len];
        syscalls::load_witness(&mut bytes, 0, 0, Source::GroupInput).map_err(|_| 5)?;
        let parsed = WitnessArgs::from_slice(&bytes).map_err(|_| 5)?;
        let input = parsed.input_type().to_opt().ok_or(5)?.raw_data();
        let (journal, proof) = witness(&input)?;
        transition(
            &config,
            &load_script_hash().map_err(|_| 6)?,
            &before,
            &after,
            journal,
        )?;
        checkpoint(&config, &after.anchor)?;
        let mut key = [0u8; 66];
        key[..2].copy_from_slice(b"0x");
        for (i, byte) in config.guest_key.iter().enumerate() {
            key[2 + i * 2] = b"0123456789abcdef"[(byte >> 4) as usize];
            key[3 + i * 2] = b"0123456789abcdef"[(byte & 15) as usize];
        }
        sp1_verifier::Groth16Verifier::verify(
            proof,
            journal,
            core::str::from_utf8(&key).map_err(|_| 1)?,
            &sp1_verifier::GROTH16_VK_BYTES,
        )
        .map_err(|_| 9)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn retained_a3_groth16_and_every_public_domain_are_cryptographically_checked() {
        let proof =
            include_bytes!("../../../specs/evidence/sealed-chain-proof/proof/groth16-proof.bin");
        let journal =
            include_bytes!("../../../specs/evidence/sealed-chain-proof/proof/public-values.bin");
        let key = "0x00eb2677694b390a31db8883db49c1a828d73618173ce6f3e5790b7678958b14";
        let verify = |proof: &[u8], journal: &[u8], key: &str| {
            sp1_verifier::Groth16Verifier::verify(
                proof,
                journal,
                key,
                &sp1_verifier::GROTH16_VK_BYTES,
            )
        };
        assert!(verify(proof, journal, key).is_ok());
        for offset in [
            8, 40, 72, 104, 136, 168, 176, 208, 408, 608, 640, 672, 704, 736,
        ] {
            let mut altered = *journal;
            altered[offset] ^= 1;
            assert!(
                verify(proof, &altered, key).is_err(),
                "journal byte {offset}"
            );
        }
        assert!(verify(
            proof,
            journal,
            "0x01eb2677694b390a31db8883db49c1a828d73618173ce6f3e5790b7678958b14"
        )
        .is_err());
        let mut altered = *proof;
        altered[355] ^= 1;
        assert!(verify(&altered, journal, key).is_err());
    }

    fn fixture() -> (Config, [u8; 32], Tip, Tip, [u8; JOURNAL_BYTES]) {
        let text = include_str!("../../../specs/test-vectors/proof-v1/transfers-journal.hex")
            .trim()
            .trim_start_matches("0x");
        let mut journal = [0; JOURNAL_BYTES];
        for (i, out) in journal.iter_mut().enumerate() {
            *out = u8::from_str_radix(&text[i * 2..i * 2 + 2], 16).unwrap();
        }
        let config = Config {
            ckb_genesis: journal[40..72].try_into().unwrap(),
            anchor_type_hash: journal[72..104].try_into().unwrap(),
            guest_key: [4; 32],
            checkpoint_code_hash: [5; 32],
            allocation_commitment: journal[176..208].try_into().unwrap(),
        };
        let before = Tip::initial(journal[208..408].try_into().unwrap()).unwrap();
        let after = Tip {
            initialized: true,
            anchor: journal[408..608].try_into().unwrap(),
            state_root: journal[640..672].try_into().unwrap(),
            header_hash: journal[704..736].try_into().unwrap(),
        };
        (
            config,
            journal[104..136].try_into().unwrap(),
            before,
            after,
            journal,
        )
    }
    #[test]
    fn binds_fixture_journal_to_real_state_and_deployment_fields() {
        // Structural tests only: no mock cryptographic acceptance is installed.
        let (config, own, before, after, journal) = fixture();
        assert_eq!(transition(&config, &own, &before, &after, &journal), Ok(()));
        for offset in [
            0, 8, 40, 72, 104, 136, 168, 176, 208, 248, 408, 456, 640, 704,
        ] {
            let mut changed = journal;
            changed[offset] ^= 1;
            assert!(
                transition(&config, &own, &before, &after, &changed).is_err(),
                "offset {offset}"
            );
        }
        let mut changed = after.clone();
        changed.initialized = false;
        assert!(transition(&config, &own, &before, &changed, &journal).is_err());
        let mut changed = before.clone();
        changed.state_root[0] = 1;
        assert!(Tip::decode(&changed.encode()).is_err());
        let mut changed = config.clone();
        changed.ckb_genesis[0] ^= 1;
        assert!(transition(&changed, &own, &before, &after, &journal).is_err());
        let mut changed = own;
        changed[0] ^= 1;
        assert!(transition(&config, &changed, &before, &after, &journal).is_err());
    }
    #[test]
    fn later_intervals_require_both_predecessor_roots_and_strict_progress() {
        let (config, own, _, before, mut journal) = fixture();
        let mut after = before.clone();
        for range in [40..48, 80..88, 88..96] {
            let next = number(&after.anchor[range.clone()]) + 1;
            after.anchor[range].copy_from_slice(&next.to_le_bytes());
        }
        after.state_root = [6; 32];
        after.header_hash = [7; 32];
        journal[208..408].copy_from_slice(&before.anchor);
        journal[408..608].copy_from_slice(&after.anchor);
        journal[608..640].copy_from_slice(&before.state_root);
        journal[640..672].copy_from_slice(&after.state_root);
        journal[672..704].copy_from_slice(&before.header_hash);
        journal[704..736].copy_from_slice(&after.header_hash);
        assert_eq!(transition(&config, &own, &before, &after, &journal), Ok(()));
        for offset in [608, 640, 672, 704] {
            let mut changed = journal;
            changed[offset] ^= 1;
            assert_eq!(transition(&config, &own, &before, &after, &changed), Err(7));
        }
        for range in [40..48, 80..88, 88..96] {
            let mut stale = after.clone();
            stale.anchor[range.clone()].copy_from_slice(&before.anchor[range]);
            let mut changed = journal;
            changed[408..608].copy_from_slice(&stale.anchor);
            assert_eq!(transition(&config, &own, &before, &stale, &changed), Err(7));
        }
        let mut changed = journal;
        changed[208..408].copy_from_slice(&after.anchor);
        assert_eq!(transition(&config, &own, &before, &after, &changed), Err(7));
    }
    #[test]
    fn canonical_encodings_and_proof_framing_are_bounded() {
        let (config, _, before, after, journal) = fixture();
        assert_eq!(Config::decode(&config.encode()), Ok(config.clone()));
        for len in 0..CONFIG_BYTES {
            assert!(Config::decode(&config.encode()[..len]).is_err());
        }
        for offset in [8, 40, 72, 104, 136] {
            let mut bad = config.encode();
            bad[offset..offset + 32].fill(0);
            assert!(Config::decode(&bad).is_err());
        }
        for tip in [before, after] {
            assert_eq!(Tip::decode(&tip.encode()), Ok(tip.clone()));
            for len in 0..TIP_BYTES {
                assert!(Tip::decode(&tip.encode()[..len]).is_err());
            }
            for offset in 9..16 {
                let mut bad = tip.encode();
                bad[offset] = 1;
                assert!(Tip::decode(&bad).is_err());
            }
        }
        let mut encoded = b"TO1SETW1".to_vec();
        encoded.extend_from_slice(&journal);
        encoded.extend_from_slice(&1u32.to_le_bytes());
        encoded.push(42);
        assert_eq!(witness(&encoded), Ok((&journal, &[42][..])));
        for len in 0..encoded.len() {
            assert!(witness(&encoded[..len]).is_err());
        }
        encoded.push(0);
        assert!(witness(&encoded).is_err());
        encoded[776..780].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(witness(&encoded).is_err());
        encoded[776..780].copy_from_slice(&((MAX_PROOF_BYTES + 1) as u32).to_le_bytes());
        encoded.resize(780 + MAX_PROOF_BYTES + 1, 0);
        assert!(witness(&encoded).is_err());
    }
}
