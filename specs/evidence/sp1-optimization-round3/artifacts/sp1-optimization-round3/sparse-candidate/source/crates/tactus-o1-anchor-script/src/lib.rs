//! CKB inline-DA anchor, distinct from the A1 bare-commitment fixture.
//! Empty args always fail, so the same code provides an immutable publication
//! lock without trusting an externally selected lock program.
#![cfg_attr(target_arch = "riscv64", no_std)]
#[cfg(target_arch = "riscv64")]
extern crate alloc;

#[cfg(target_arch = "riscv64")]
mod onchain {
    use alloc::{vec, vec::Vec};
    use ckb_std::{
        ckb_constants::Source, ckb_types::prelude::*, error::SysError, high_level::*, syscalls,
    };
    use tactus_o1_protocol::batch::{self, AnchorState, ANCHOR_LEN, MAX_BATCH_BYTES};
    use tactus_o1_protocol::genesis;
    ckb_std::default_alloc!();
    ckb_std::entry!(main);

    fn main() -> i8 {
        run().map_or_else(|error| error, |_| 0)
    }

    fn bounded_data(index: usize, source: Source, limit: usize) -> Result<Vec<u8>, i8> {
        let len = match syscalls::load_cell_data(&mut [], 0, index, source) {
            Ok(len) | Err(SysError::LengthNotEnough(len)) => len,
            Err(_) => return Err(8),
        };
        if len > limit {
            return Err(13);
        }
        let mut bytes = vec![0; len];
        if syscalls::load_cell_data(&mut bytes, 0, index, source).map_err(|_| 8)? != len {
            return Err(8);
        }
        Ok(bytes)
    }

    fn run() -> Result<(), i8> {
        let script = load_script().map_err(|_| 1)?;
        let args = script.args().raw_data();
        if args.len() != 64 {
            return Err(1);
        }
        let identity: [u8; 32] = args[..32].try_into().map_err(|_| 1)?;
        let allocation_hash: [u8; 32] = args[32..].try_into().map_err(|_| 1)?;
        if load_cell_capacity(1, Source::GroupInput) != Err(SysError::IndexOutOfBound)
            || load_cell_capacity(1, Source::GroupOutput) != Err(SysError::IndexOutOfBound)
            || load_cell_capacity(0, Source::GroupOutput).is_err()
        {
            return Err(2);
        }
        let output = bounded_data(0, Source::GroupOutput, ANCHOR_LEN)?;
        let next = AnchorState::decode(&output).map_err(|_| 3)?;
        if next.rollup_id != identity {
            return Err(4);
        }
        if load_cell_capacity(0, Source::GroupInput) == Err(SysError::IndexOutOfBound) {
            next.validate_genesis().map_err(|_| 5)?;
            let script_hash = load_script_hash().map_err(|_| 4)?;
            let mut index = 0;
            loop {
                if load_cell_type_hash(index, Source::Output).map_err(|_| 4)? == Some(script_hash) {
                    break;
                }
                index += 1;
            }
            let input = load_input(0, Source::Input).map_err(|_| 4)?;
            let mut seed = [0u8; 52];
            seed[..44].copy_from_slice(input.as_slice());
            seed[44..].copy_from_slice(&(index as u64).to_le_bytes());
            if batch::hash(b"", &seed) != identity {
                return Err(4);
            }
            let immutable = script
                .clone()
                .as_builder()
                .args(Vec::<u8>::new().pack())
                .build();
            let mut found = false;
            for i in 0..16 {
                match load_cell_capacity(i, Source::Output) {
                    Err(SysError::IndexOutOfBound) => break,
                    Err(_) => return Err(16),
                    Ok(_) => {}
                }
                if load_cell_type_hash(i, Source::Output)
                    .map_err(|_| 16)?
                    .is_none()
                    && load_cell_lock(i, Source::Output).map_err(|_| 16)? == immutable
                {
                    let bytes = bounded_data(i, Source::Output, genesis::MAX_BYTES)?;
                    if genesis::commitment(&bytes).map_err(|_| 16)? == allocation_hash {
                        found = true;
                    }
                }
            }
            if !found {
                return Err(16);
            }
            return Ok(());
        }
        let input = bounded_data(0, Source::GroupInput, ANCHOR_LEN)?;
        let current = AnchorState::decode(&input).map_err(|_| 3)?;
        if current.rollup_id != identity {
            return Err(4);
        }
        if load_cell_capacity(0, Source::GroupInput).map_err(|_| 6)?
            != load_cell_capacity(0, Source::GroupOutput).map_err(|_| 6)?
            || load_cell_lock_hash(0, Source::GroupInput).map_err(|_| 6)?
                != load_cell_lock_hash(0, Source::GroupOutput).map_err(|_| 6)?
        {
            return Err(6);
        }
        let witness = load_witness_args(0, Source::GroupInput).map_err(|_| 7)?;
        let pointer = witness.input_type().to_opt().ok_or(7)?.raw_data();
        let raw: [u8; 4] = pointer.as_ref().try_into().map_err(|_| 7)?;
        let data_index = u32::from_le_bytes(raw) as usize;
        if load_cell_type_hash(data_index, Source::Output)
            .map_err(|_| 8)?
            .is_some()
        {
            return Err(8);
        }
        // A lock executed with empty args returns code 1 unconditionally above.
        let immutable = script.as_builder().args(Vec::<u8>::new().pack()).build();
        if load_cell_lock(data_index, Source::Output).map_err(|_| 8)? != immutable {
            return Err(8);
        }
        let bytes = bounded_data(data_index, Source::Output, MAX_BATCH_BYTES)?;
        let summary = batch::validate_batch(&bytes, &current).map_err(|e| match e {
            batch::Error::Encoding => 9,
            batch::Error::Domain => 10,
            batch::Error::Succession => 11,
            batch::Error::Timestamp => 12,
            batch::Error::Limit => 13,
            batch::Error::Overflow => 14,
            batch::Error::Genesis => 5,
        })?;
        if next != summary.next {
            return Err(15);
        }
        Ok(())
    }
}
