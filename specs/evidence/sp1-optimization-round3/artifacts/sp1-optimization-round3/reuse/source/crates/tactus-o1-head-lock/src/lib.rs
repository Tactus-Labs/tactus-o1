//! Permissionless state-cell lock. Args bind the type script hash that must
//! execute for every input in this lock group. The type script enforces
//! singleton succession, capacity conservation and lock preservation.
#![cfg_attr(target_arch = "riscv64", no_std)]
#[cfg(target_arch = "riscv64")]
extern crate alloc;

#[cfg(target_arch = "riscv64")]
mod onchain {
    use ckb_std::{ckb_constants::Source, error::SysError, high_level::*};
    ckb_std::default_alloc!();
    ckb_std::entry!(run);

    fn run() -> i8 {
        let Ok(script) = load_script() else {
            return 1;
        };
        let args = script.args().raw_data();
        let Ok(expected) = <[u8; 32]>::try_from(args.as_ref()) else {
            return 1;
        };
        let mut index = 0;
        loop {
            match load_cell_type_hash(index, Source::GroupInput) {
                Ok(Some(hash)) if hash == expected => index += 1,
                Err(SysError::IndexOutOfBound) if index > 0 => return 0,
                _ => return 2,
            }
        }
    }
}
