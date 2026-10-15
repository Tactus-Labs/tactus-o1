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
use tactus_o1_protocol::native_bridge::{Batch, MAX_BYTES, RECORD_BYTES};
ckb_std::default_alloc!();
ckb_std::entry!(main);
fn main() -> i8 {
    run().map_or_else(|e| e, |()| 0)
}
fn data(index: usize, source: Source, limit: usize) -> Result<Vec<u8>, i8> {
    let n = match syscalls::load_cell_data(&mut [], 0, index, source) {
        Ok(n) | Err(SysError::LengthNotEnough(n)) => n,
        _ => return Err(3),
    };
    if n > limit {
        return Err(3);
    }
    let mut b = vec![0; n];
    if syscalls::load_cell_data(&mut b, 0, index, source) != Ok(n) {
        return Err(3);
    }
    Ok(b)
}
fn bounded(source: Source) -> Result<usize, i8> {
    for i in 0..=MAX_CELLS {
        match load_cell_capacity(i, source) {
            Err(SysError::IndexOutOfBound) => return Ok(i),
            Ok(_) if i < MAX_CELLS => {}
            _ => return Err(2),
        }
    }
    Err(2)
}
fn unique(hash: [u8; 32], source: Source) -> Result<usize, i8> {
    let mut found = None;
    for i in 0..bounded(source)? {
        if load_cell_type_hash(i, source).map_err(|_| 2)? == Some(hash)
            && found.replace(i).is_some()
        {
            return Err(2);
        }
    }
    found.ok_or(2)
}
fn immutable(script: &Script) -> Script {
    script
        .clone()
        .as_builder()
        .args(Vec::<u8>::new().pack())
        .build()
}
fn bind_genesis(script: &Script, next: &State, allocation: [u8; 32]) -> Result<(), i8> {
    if *next != State::genesis(next.config.clone())? {
        return Err(5);
    }
    let identity = load_script_hash().map_err(|_| 1)?;
    let index = unique(identity, Source::Output)?;
    let input = load_input(0, Source::Input).map_err(|_| 5)?;
    if batch::hash(
        b"",
        &[input.as_slice(), &(index as u64).to_le_bytes()].concat(),
    ) != next.config.rollup
    {
        return Err(5);
    }
    let header = load_header(0, Source::HeaderDep).map_err(|_| 7)?;
    if header.raw().number().unpack() != 0u64
        || batch::hash(b"", header.as_slice()) != next.config.ckb_genesis
    {
        return Err(7);
    }
    // The pinned native-vault type program executes in this very transaction.
    // A dependency alone cannot substitute for joint, empty vault creation.
    let vault = unique(next.vault_type_hash(), Source::Output).map_err(|_| 8)?;
    if load_cell_type(vault, Source::Output)
        .map_err(|_| 8)?
        .ok_or(8)?
        .as_slice()
        != next.vault_script()
    {
        return Err(8);
    }
    for i in 0..bounded(Source::Input)? {
        if load_cell_type_hash(i, Source::Input).map_err(|_| 8)? == Some(next.vault_type_hash()) {
            return Err(8);
        }
    }
    let mut found = false;
    for i in 0..bounded(Source::Output)? {
        if load_cell_type_hash(i, Source::Output)
            .map_err(|_| 6)?
            .is_none()
            && load_cell_lock(i, Source::Output).map_err(|_| 6)? == immutable(script)
        {
            let bytes = data(i, Source::Output, genesis::MAX_BYTES).map_err(|_| 6)?;
            if genesis::commitment(&bytes).map_err(|_| 6)? == allocation {
                validate_allocation(&next.config, &bytes, allocation)?;
                if found {
                    return Err(6);
                }
                found = true;
            }
        }
    }
    if !found {
        return Err(6);
    }
    Ok(())
}
fn run() -> Result<(), i8> {
    let script = load_script().map_err(|_| 1)?;
    let args = script.args().raw_data();
    if args.len() != 64 || script.hash_type() != 2u8.into() {
        return Err(1);
    }
    bounded(Source::Input)?;
    bounded(Source::Output)?;
    if load_cell_capacity(1, Source::GroupInput) != Err(SysError::IndexOutOfBound)
        || load_cell_capacity(1, Source::GroupOutput) != Err(SysError::IndexOutOfBound)
        || load_cell_capacity(0, Source::GroupOutput).is_err()
    {
        return Err(2);
    }
    let next = State::decode(&data(0, Source::GroupOutput, STATE_BYTES)?)?;
    if next.config.rollup != args[..32] {
        return Err(4);
    }
    let identity = load_script_hash().map_err(|_| 1)?;
    let lock = Script::new_builder()
        .code_hash(HEAD_LOCK.pack())
        .hash_type(2u8.into())
        .args(identity.to_vec().pack())
        .build();
    if load_cell_lock(0, Source::GroupOutput).map_err(|_| 9)? != lock {
        return Err(9);
    }
    if load_cell_capacity(0, Source::GroupInput) == Err(SysError::IndexOutOfBound) {
        if load_cell_capacity(0, Source::GroupOutput).map_err(|_| 9)?
            != load_cell_occupied_capacity(0, Source::GroupOutput).map_err(|_| 9)?
        {
            return Err(9);
        }
        return bind_genesis(&script, &next, args[32..].try_into().unwrap());
    }
    let current = State::decode(&data(0, Source::GroupInput, STATE_BYTES)?)?;
    if current.config != next.config {
        return Err(4);
    }
    if load_cell_lock(0, Source::GroupInput).map_err(|_| 9)? != lock
        || load_cell_capacity(0, Source::GroupInput).map_err(|_| 9)?
            != load_cell_capacity(0, Source::GroupOutput).map_err(|_| 9)?
    {
        return Err(9);
    }
    // Bounded WitnessArgs before allocating, including the untrusted lock field.
    let n = match syscalls::load_witness(&mut [], 0, 0, Source::GroupInput) {
        Ok(n) | Err(SysError::LengthNotEnough(n)) => n,
        _ => return Err(10),
    };
    if n > 4096 {
        return Err(10);
    }
    let mut raw = vec![0; n];
    if syscalls::load_witness(&mut raw, 0, 0, Source::GroupInput) != Ok(n) {
        return Err(10);
    }
    let witness = WitnessArgs::from_slice(&raw).map_err(|_| 10)?;
    let pointer = witness.input_type().to_opt().ok_or(10)?.raw_data();
    let i = u32::from_le_bytes(pointer.as_ref().try_into().map_err(|_| 10)?) as usize;
    if i >= MAX_CELLS
        || load_cell_type_hash(i, Source::Output)
            .map_err(|_| 10)?
            .is_some()
        || load_cell_lock(i, Source::Output).map_err(|_| 10)? != immutable(&script)
    {
        return Err(10);
    }
    let bytes = data(i, Source::Output, MAX_BYTES).map_err(|_| 11)?;
    let (batch, after) = Batch::decode(&bytes, &current.config, &current.anchor).map_err(|_| 11)?;
    if next.anchor != after {
        return Err(12);
    }
    let vault = Script::from_slice(&current.vault_script()).map_err(|_| 13)?;
    let receipt = vault
        .clone()
        .as_builder()
        .args(
            [b"TO1REC01".as_slice(), &current.vault_type_hash()]
                .concat()
                .pack(),
        )
        .build();
    let receipt_hash = batch::hash(b"", receipt.as_slice());
    let receipt_lock = immutable(&vault);
    let mut found = vec![false; batch.deposits.len()];
    for d in 0..bounded(Source::CellDep)? {
        if load_cell_type_hash(d, Source::CellDep).map_err(|_| 13)? != Some(receipt_hash) {
            continue;
        }
        if load_cell_lock(d, Source::CellDep).map_err(|_| 13)? != receipt_lock {
            return Err(13);
        }
        let bytes = data(d, Source::CellDep, RECORD_BYTES).map_err(|_| 13)?;
        for (i, record) in batch.deposits.iter().enumerate() {
            if bytes == record.encode() {
                if found[i] {
                    return Err(13);
                }
                found[i] = true;
            }
        }
    }
    if found.iter().any(|v| !*v) {
        return Err(14);
    }
    Ok(())
}
