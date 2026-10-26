//! Prepared, unexecuted arithmetic kernel. No balances, authorization or custody.
//! Both implementations use the full 256-bit input and wrap modulo 2^256.
#![no_std]
pub const MAX_STEPS: u32 = 4096;
pub const JOURNAL_MAGIC: [u8; 8] = *b"TARVR001";

pub fn kernel(seed: [u8; 32], steps: u32) -> (bool, [u8; 32]) {
    if steps > MAX_STEPS {
        return (false, seed);
    }
    // Four little-endian limbs, converted from the externally big-endian word.
    let mut limbs = [0u64; 4];
    for (i, limb) in limbs.iter_mut().enumerate() {
        let start = 24 - i * 8;
        *limb = u64::from_be_bytes(seed[start..start + 8].try_into().unwrap());
    }
    for _ in 0..steps {
        let mut carry = 1u128;
        for limb in &mut limbs {
            let next = u128::from(*limb) * 3 + carry;
            *limb = next as u64;
            carry = next >> 64;
        }
    }
    let mut result = [0u8; 32];
    for (i, limb) in limbs.iter().enumerate() {
        let start = 24 - i * 8;
        result[start..start + 8].copy_from_slice(&limb.to_be_bytes());
    }
    (true, result)
}

/// A research statement, deliberately incompatible with Tactus settlement.
/// Binds both request and result; no unchecked host-provided output is committed.
pub fn journal(seed: [u8; 32], steps: u32, success: bool, result: [u8; 32]) -> [u8; 77] {
    let mut bytes = [0; 77];
    bytes[..8].copy_from_slice(&JOURNAL_MAGIC);
    bytes[8..40].copy_from_slice(&seed);
    bytes[40..44].copy_from_slice(&steps.to_le_bytes());
    bytes[44] = u8::from(success);
    bytes[45..].copy_from_slice(&result);
    bytes
}
