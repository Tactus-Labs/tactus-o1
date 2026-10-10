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
use tactus_o1_native_anchor_script::{HEAD_LOCK, STATE_BYTES};
ckb_std::default_alloc!();
ckb_std::entry!(entrypoint);
fn entrypoint() -> i8 {
    run().map_or_else(|e| e, |()| 0)
}
fn data<const N: usize>(i: usize, s: Source) -> Result<[u8; N], i8> {
    let mut b = [0; N];
    if syscalls::load_cell_data(&mut b, 0, i, s) != Ok(N) {
        return Err(3);
    }
    Ok(b)
}
fn matching(s: Source, hash: &[u8; 32]) -> Result<Option<usize>, i8> {
    let mut found = None;
    for i in 0..=MAX_CELLS {
        match load_cell_type_hash(i, s) {
            Err(SysError::IndexOutOfBound) => return Ok(found),
            Ok(h) if i < MAX_CELLS => {
                if h == Some(*hash) && found.replace(i).is_some() {
                    return Err(4);
                }
            }
            _ => return Err(4),
        }
    }
    Err(4)
}
fn checkpoint(c: &Config, state: &State) -> Result<(), i8> {
    let expected = Script::new_builder()
        .code_hash(CHECKPOINT_CODE.pack())
        .hash_type(2u8.into())
        .args(
            [b"TO1NCP02".as_slice(), &c.anchor_type_hash]
                .concat()
                .pack(),
        )
        .build();
    let mut found = false;
    for i in 0..=MAX_CELLS {
        match load_cell_type(i, Source::CellDep) {
            Err(SysError::IndexOutOfBound) => return if found { Ok(()) } else { Err(8) },
            Ok(Some(script)) if i < MAX_CELLS && script == expected => {
                if data::<STATE_BYTES>(i, Source::CellDep).map_err(|_| 8)? == state.encode() {
                    if found {
                        return Err(8);
                    }
                    found = true;
                }
            }
            Ok(_) if i < MAX_CELLS => {}
            _ => return Err(8),
        }
    }
    Err(8)
}
fn run() -> Result<(), i8> {
    let script = load_script().map_err(|_| 1)?;
    if script.hash_type() != 2u8.into() {
        return Err(1);
    }
    let c = Config::decode(&script.args().raw_data())?;
    let own = load_script_hash().map_err(|_| 1)?;
    if load_cell_capacity(1, Source::GroupInput) != Err(SysError::IndexOutOfBound)
        || load_cell_capacity(1, Source::GroupOutput) != Err(SysError::IndexOutOfBound)
    {
        return Err(2);
    }
    let after = Tip::decode(&data::<TIP_BYTES>(0, Source::GroupOutput)?)?;
    let lock = Script::new_builder()
        .code_hash(HEAD_LOCK.pack())
        .hash_type(2u8.into())
        .args(own.to_vec().pack())
        .build();
    if load_cell_lock(0, Source::GroupOutput).map_err(|_| 10)? != lock {
        return Err(10);
    }
    if load_cell_capacity(0, Source::GroupInput) == Err(SysError::IndexOutOfBound) {
        if after != Tip::initial(after.anchor)?
            || matching(Source::Input, &c.anchor_type_hash)?.is_some()
        {
            return Err(4);
        }
        let i = matching(Source::Output, &c.anchor_type_hash)?.ok_or(4)?;
        let state = State::decode(&data::<STATE_BYTES>(i, Source::Output)?).map_err(|_| 4)?;
        bind_state(&c, &own, &state)?;
        if state != State::genesis(state.config.clone()).map_err(|_| 4)?
            || state.anchor.ordering.encode() != after.anchor
        {
            return Err(4);
        }
        if load_cell_capacity(0, Source::GroupOutput).map_err(|_| 10)?
            != load_cell_occupied_capacity(0, Source::GroupOutput).map_err(|_| 10)?
        {
            return Err(10);
        }
        return Ok(());
    }
    let before = Tip::decode(&data::<TIP_BYTES>(0, Source::GroupInput)?)?;
    if load_cell_capacity(0, Source::GroupInput).map_err(|_| 10)?
        != load_cell_capacity(0, Source::GroupOutput).map_err(|_| 10)?
        || load_cell_lock(0, Source::GroupInput).map_err(|_| 10)? != lock
    {
        return Err(10);
    }
    let len = match syscalls::load_witness(&mut [], 0, 0, Source::GroupInput) {
        Ok(n) | Err(SysError::LengthNotEnough(n)) => n,
        _ => return Err(5),
    };
    if len > MAX_WITNESS_BYTES {
        return Err(5);
    }
    let mut bytes = vec![0; len];
    if syscalls::load_witness(&mut bytes, 0, 0, Source::GroupInput) != Ok(len) {
        return Err(5);
    }
    let parsed = WitnessArgs::from_slice(&bytes).map_err(|_| 5)?;
    let input = parsed.input_type().to_opt().ok_or(5)?.raw_data();
    let (journal, proof) = witness(&input)?;
    let (b, a) = transition(&c, &own, &before, &after, journal)?;
    if before.initialized {
        checkpoint(&c, &b)?;
    }
    checkpoint(&c, &a)?;
    sp1_verifier::Groth16Verifier::verify(
        proof,
        journal,
        GUEST_KEY,
        &sp1_verifier::GROTH16_VK_BYTES,
    )
    .map_err(|_| 9)
}
