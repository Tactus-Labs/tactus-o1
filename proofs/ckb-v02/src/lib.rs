//! 0.02 CKB authorization primitives. Cryptographic witnesses are checked here;
//! the transaction adapter must additionally authenticate unique live cells,
//! immutable receipt provenance, lock identities, capacities and payouts.
#![cfg_attr(target_arch = "riscv64", no_std)]
extern crate alloc;

pub mod adapter;
pub mod claims;

#[cfg(all(target_arch = "riscv64", feature = "entry"))]
mod onchain;
