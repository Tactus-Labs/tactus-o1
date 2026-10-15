//! Individual A2 obligation lifecycle. No global pending-set completeness or
//! forced processing is implied by a challenged marker or inclusion record.
use crate::{batch, Hash32};
use alloc::vec::Vec;

pub const MAX_PRIORITY_INPUTS: usize = 4;
pub const MAX_PAYLOAD_BYTES: usize = 4096;
pub const MAX_PRIORITY_BYTES: usize = 20_480;
pub const MAX_PRIORITY_SCRIPT_CYCLES: u64 = 12_000_000;
pub const MAX_PRIORITY_CYCLES: u64 = 2 * MAX_PRIORITY_INPUTS as u64 * MAX_PRIORITY_SCRIPT_CYCLES;
pub const MAX_PRIORITY_GAS: u64 = batch::BLOCK_GAS_LIMIT;
pub const MAX_INPUTS: usize = 12;
pub const MAX_OUTPUTS: usize = 16;
pub const MAX_WITNESSES: usize = 32;
pub const CHALLENGE_DELAY_BLOCKS: u64 = 12;
pub const CHALLENGE_SINCE: u64 = (1 << 63) | CHALLENGE_DELAY_BLOCKS;
pub const FIXED_BYTES: usize = 8 + 1 + 32 + 32 + 32 + 32 + 8 + 32 + 8 + 2 + 4;
pub const MAX_MESSAGE_BYTES: usize = FIXED_BYTES + MAX_PAYLOAD_BYTES;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Stage {
    Admitted = 0,
    Challenged = 1,
    Included = 2,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Message {
    pub stage: Stage,
    pub id: Hash32,
    pub rollup_id: Hash32,
    pub anchor_type_hash: Hash32,
    pub policy_hash: Hash32,
    pub batch_number: u64,
    pub batch_commitment: Hash32,
    pub block_number: u64,
    pub slot: u16,
    pub payload: Vec<u8>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Encoding,
    Limit,
    Domain,
    Stage,
    Identity,
    Inclusion,
}

pub fn policy_hash() -> Hash32 {
    let limits = [
        MAX_PRIORITY_INPUTS as u64,
        MAX_PAYLOAD_BYTES as u64,
        MAX_PRIORITY_BYTES as u64,
        MAX_PRIORITY_SCRIPT_CYCLES,
        MAX_PRIORITY_CYCLES,
        MAX_PRIORITY_GAS,
        MAX_INPUTS as u64,
        MAX_OUTPUTS as u64,
        MAX_WITNESSES as u64,
        CHALLENGE_DELAY_BLOCKS,
    ];
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"individual-obligation;challenge-marker-only;included-record-immutable;first-block-input-order-prefix;no-proven-transition");
    for value in limits {
        bytes.extend_from_slice(&value.to_le_bytes());
    }
    batch::hash(b"tactus/o1/priority-policy/v1", &bytes)
}
impl Message {
    pub fn admitted(
        id: Hash32,
        rollup_id: Hash32,
        anchor_type_hash: Hash32,
        payload: Vec<u8>,
    ) -> Result<Self, Error> {
        let value = Self {
            stage: Stage::Admitted,
            id,
            rollup_id,
            anchor_type_hash,
            policy_hash: policy_hash(),
            batch_number: 0,
            batch_commitment: [0; 32],
            block_number: 0,
            slot: 0,
            payload,
        };
        value.validate()?;
        Ok(value)
    }
    fn validate(&self) -> Result<(), Error> {
        if self.payload.is_empty() || self.payload.len() > MAX_PAYLOAD_BYTES {
            return Err(Error::Limit);
        }
        if self.id == [0; 32]
            || self.rollup_id == [0; 32]
            || self.anchor_type_hash == [0; 32]
            || self.policy_hash != policy_hash()
        {
            return Err(Error::Domain);
        }
        if self.stage == Stage::Included {
            if self.batch_commitment == [0; 32]
                || self.block_number == 0
                || usize::from(self.slot) >= MAX_PRIORITY_INPUTS
            {
                return Err(Error::Inclusion);
            }
        } else if self.batch_number != 0
            || self.batch_commitment != [0; 32]
            || self.block_number != 0
            || self.slot != 0
        {
            return Err(Error::Inclusion);
        }
        Ok(())
    }
    pub fn challenge(&self) -> Result<Self, Error> {
        if self.stage != Stage::Admitted {
            return Err(Error::Stage);
        }
        let mut next = self.clone();
        next.stage = Stage::Challenged;
        Ok(next)
    }
    pub fn include(
        &self,
        parent: &batch::AnchorState,
        next: &batch::AnchorState,
        slot: usize,
    ) -> Result<Self, Error> {
        if self.stage == Stage::Included {
            return Err(Error::Stage);
        }
        if self.rollup_id != parent.rollup_id || next.rollup_id != parent.rollup_id {
            return Err(Error::Domain);
        }
        let record = Self {
            stage: Stage::Included,
            batch_number: parent.next_batch_number,
            batch_commitment: next.last_batch_commitment,
            block_number: parent
                .last_block_number
                .checked_add(1)
                .ok_or(Error::Inclusion)?,
            slot: u16::try_from(slot).map_err(|_| Error::Limit)?,
            ..self.clone()
        };
        record.validate()?;
        Ok(record)
    }
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        self.validate()?;
        let mut bytes = Vec::with_capacity(FIXED_BYTES + self.payload.len());
        bytes.extend_from_slice(b"TO1PRI01");
        bytes.push(self.stage as u8);
        for hash in [
            &self.id,
            &self.rollup_id,
            &self.anchor_type_hash,
            &self.policy_hash,
        ] {
            bytes.extend_from_slice(hash);
        }
        bytes.extend_from_slice(&self.batch_number.to_le_bytes());
        bytes.extend_from_slice(&self.batch_commitment);
        bytes.extend_from_slice(&self.block_number.to_le_bytes());
        bytes.extend_from_slice(&self.slot.to_le_bytes());
        bytes.extend_from_slice(&(self.payload.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&self.payload);
        Ok(bytes)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() < FIXED_BYTES
            || bytes.len() > MAX_MESSAGE_BYTES
            || &bytes[..8] != b"TO1PRI01"
        {
            return Err(Error::Encoding);
        }
        let stage = match bytes[8] {
            0 => Stage::Admitted,
            1 => Stage::Challenged,
            2 => Stage::Included,
            _ => return Err(Error::Stage),
        };
        let length = u32::from_le_bytes(bytes[187..191].try_into().unwrap()) as usize;
        if bytes.len() != FIXED_BYTES + length {
            return Err(Error::Encoding);
        }
        let value = Self {
            stage,
            id: bytes[9..41].try_into().unwrap(),
            rollup_id: bytes[41..73].try_into().unwrap(),
            anchor_type_hash: bytes[73..105].try_into().unwrap(),
            policy_hash: bytes[105..137].try_into().unwrap(),
            batch_number: u64::from_le_bytes(bytes[137..145].try_into().unwrap()),
            batch_commitment: bytes[145..177].try_into().unwrap(),
            block_number: u64::from_le_bytes(bytes[177..185].try_into().unwrap()),
            slot: u16::from_le_bytes(bytes[185..187].try_into().unwrap()),
            payload: bytes[191..].to_vec(),
        };
        value.validate()?;
        Ok(value)
    }
}
