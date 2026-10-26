//! Shared 0.02 consensus data and pure transitions.
//!
//! Decoding authenticates structure, not provenance. CKB adapters must verify
//! unique live types, capacity, counterpart operations and genuine receipts;
//! settlement additionally requires cryptographic proof verification. No method
//! here turns caller-supplied roots, journals or signatures into authority.

mod codec;
mod control;
mod custody;
mod nullifier;
mod ordering;
mod policy;
mod shape;

pub use crate::Hash32;
pub use codec::{Reader, Wire};
pub use control::{
    absolute_timestamp, relative_blocks, Boundary, Control, Journal, Mode, Watch, Work,
};
pub use custody::{ClaimKind, Deposit, DepositCursor, Vault};
pub use nullifier::{claim_key, empty_claim_root, NullifierProof};
pub use ordering::{Admission, Lane, Message, NativeBatch, Priority, Schedule, Snapshot};
pub use policy::{Config, Operation, Policy, Role};
pub use shape::{check_role_shape, RoleRef};

/// Maximum configured priority lanes. Unused vector entries must be zero.
pub const LANES: usize = 4;
/// Maximum messages admitted per active lane and epoch.
pub const LANE_MESSAGES: usize = 8;
/// Required priority messages and deposit credits per batch, independently.
pub const DUTY: usize = 4;
/// Batch transitions per epoch.
pub const EPOCH_BATCHES: u8 = 8;
/// Priority payload bound, separate from ordinary transaction size.
pub const PRIORITY_BYTES: usize = 1024;
/// Maximum whole native input envelope, not one allowance per nested object.
pub const BATCH_BYTES: usize = 262_144;

/// Stable protocol failures. Never serialize dependency exception strings.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Error {
    Encoding = 1,
    Limit = 2,
    Domain = 3,
    Arithmetic = 4,
    Continuity = 5,
    Mode = 6,
    Accounting = 7,
    Duty = 8,
    Maturity = 9,
    Identity = 10,
    Authorization = 11,
    Proof = 12,
    Resource = 13,
}

pub type Result<T> = core::result::Result<T, Error>;

#[cfg(test)]
mod tests;

/// CKB-personalized, explicitly domain-separated digest.
pub fn hash(domain: &[u8], bytes: &[u8]) -> Hash32 {
    crate::batch::hash(domain, bytes)
}

pub(crate) fn nonzero(h: &Hash32) -> Result<()> {
    if *h == [0; 32] {
        Err(Error::Domain)
    } else {
        Ok(())
    }
}

pub(crate) fn increment(n: u64) -> Result<u64> {
    n.checked_add(1).ok_or(Error::Arithmetic)
}

pub(crate) fn check_lanes(values: &[u64; LANES], lanes: u8) -> Result<()> {
    if lanes == 0
        || usize::from(lanes) > LANES
        || values[usize::from(lanes)..].iter().any(|n| *n != 0)
    {
        Err(Error::Limit)
    } else {
        Ok(())
    }
}
