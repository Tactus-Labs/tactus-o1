use super::{hash, nonzero, Error, Reader, Result, Wire, LANES};
use alloc::vec::Vec;

/// One operation per protocol transaction; the adapter checks the full role set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Operation {
    Genesis = 0,
    Enqueue = 1,
    Deposit = 2,
    Seal = 3,
    Append = 4,
    Settle = 5,
    Release = 6,
    Watch = 7,
    CloseWatch = 8,
    Freeze = 9,
    Refund = 10,
    Escape = 11,
}
impl TryFrom<u8> for Operation {
    type Error = Error;
    fn try_from(v: u8) -> Result<Self> {
        Ok(match v {
            0 => Self::Genesis,
            1 => Self::Enqueue,
            2 => Self::Deposit,
            3 => Self::Seal,
            4 => Self::Append,
            5 => Self::Settle,
            6 => Self::Release,
            7 => Self::Watch,
            8 => Self::CloseWatch,
            9 => Self::Freeze,
            10 => Self::Refund,
            11 => Self::Escape,
            _ => return Err(Error::Encoding),
        })
    }
}

/// Roles share one versioned CKB adapter binary; role arguments separate types.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Role {
    Anchor = 0,
    Schedule = 1,
    Lane = 2,
    Vault = 3,
    Control = 4,
    Checkpoint = 5,
    DepositReceipt = 6,
    AdmissionReceipt = 7,
    Snapshot = 8,
    Watch = 9,
    Policy = 10,
    Allocation = 11,
    Batch = 12,
    Config = 13,
}
impl TryFrom<u8> for Role {
    type Error = Error;
    fn try_from(v: u8) -> Result<Self> {
        Ok(match v {
            0 => Self::Anchor,
            1 => Self::Schedule,
            2 => Self::Lane,
            3 => Self::Vault,
            4 => Self::Control,
            5 => Self::Checkpoint,
            6 => Self::DepositReceipt,
            7 => Self::AdmissionReceipt,
            8 => Self::Snapshot,
            9 => Self::Watch,
            10 => Self::Policy,
            11 => Self::Allocation,
            12 => Self::Batch,
            13 => Self::Config,
            _ => return Err(Error::Encoding),
        })
    }
}

/// New-instance policy. Values are developmental limits, not resource qualification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Policy {
    pub lanes: u8,
    pub max_pending_batches: u64,
    pub max_pending_deposits: u64,
    pub stall_blocks: u64,
    pub priority_gas: u64,
    pub credit_gas: u64,
    pub rules: [u8; 32],
    pub profile: [u8; 32],
    pub guest_key: [u8; 32],
    pub wrapper_key_hash: [u8; 32],
    pub bridge_code_hash: [u8; 32],
}
impl Wire for Policy {
    const MAGIC: [u8; 8] = *b"T02POL01";
    const MAX_BYTES: usize = 209;
    fn validate(&self) -> Result<()> {
        if self.lanes == 0
            || usize::from(self.lanes) > LANES
            || self.max_pending_batches == 0
            || self.max_pending_batches > 32
            || self.max_pending_deposits == 0
            || self.max_pending_deposits > 32
            || self.stall_blocks == 0
            || self.stall_blocks >= (1u64 << 56)
            || self.priority_gas == 0
            || self.priority_gas > 250_000
            || self.credit_gas != 200_000
        {
            return Err(Error::Limit);
        }
        for h in [
            &self.rules,
            &self.profile,
            &self.guest_key,
            &self.wrapper_key_hash,
            &self.bridge_code_hash,
        ] {
            nonzero(h)?;
        }
        Ok(())
    }
    fn write_fields(&self, out: &mut Vec<u8>) {
        out.push(self.lanes);
        for v in [
            self.max_pending_batches,
            self.max_pending_deposits,
            self.stall_blocks,
            self.priority_gas,
            self.credit_gas,
        ] {
            out.extend_from_slice(&v.to_le_bytes());
        }
        for h in [
            &self.rules,
            &self.profile,
            &self.guest_key,
            &self.wrapper_key_hash,
            &self.bridge_code_hash,
        ] {
            out.extend_from_slice(h);
        }
    }
    fn read_fields(r: &mut Reader<'_>) -> Result<Self> {
        Ok(Self {
            lanes: r.u8()?,
            max_pending_batches: r.u64()?,
            max_pending_deposits: r.u64()?,
            stall_blocks: r.u64()?,
            priority_gas: r.u64()?,
            credit_gas: r.u64()?,
            rules: r.array()?,
            profile: r.array()?,
            guest_key: r.array()?,
            wrapper_key_hash: r.array()?,
            bridge_code_hash: r.array()?,
        })
    }
}

/// Immutable joint-genesis configuration. No mutually recursive script hashes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Config {
    pub domain: [u8; 32],
    pub ckb_genesis: [u8; 32],
    pub adapter_code_hash: [u8; 32],
    pub head_lock_code_hash: [u8; 32],
    pub policy: [u8; 32],
    pub allocation: [u8; 32],
    pub chain: u64,
    pub bridge: [u8; 20],
}
impl Config {
    pub fn bind(&self, policy: &Policy) -> Result<()> {
        self.validate()?;
        if self.policy != policy.commitment()? {
            return Err(Error::Domain);
        }
        Ok(())
    }
    /// Derived before creating scripts; independent of policy and code hashes.
    pub fn domain_id(first_input: &[u8; 44], anchor_index: u64) -> [u8; 32] {
        hash(
            b"tactus/0.02/genesis",
            &[first_input.as_slice(), &anchor_index.to_le_bytes()].concat(),
        )
    }
    /// Canonical 41-byte type args, domain + role + u64 instance/lane index.
    pub fn args(&self, role: Role, index: u64) -> Result<Vec<u8>> {
        self.validate()?;
        let mut out = self.domain.to_vec();
        out.push(role as u8);
        out.extend_from_slice(&index.to_le_bytes());
        Ok(out)
    }
}
impl Wire for Config {
    const MAGIC: [u8; 8] = *b"T02CFG01";
    const MAX_BYTES: usize = 228;
    fn validate(&self) -> Result<()> {
        for h in [
            &self.domain,
            &self.ckb_genesis,
            &self.adapter_code_hash,
            &self.head_lock_code_hash,
            &self.policy,
            &self.allocation,
        ] {
            nonzero(h)?;
        }
        if self.chain == 0
            || self.bridge == [0; 20]
            || (self.bridge[..19] == [0; 19] && self.bridge[19] <= 9)
        {
            return Err(Error::Domain);
        }
        Ok(())
    }
    fn write_fields(&self, out: &mut Vec<u8>) {
        for h in [
            &self.domain,
            &self.ckb_genesis,
            &self.adapter_code_hash,
            &self.head_lock_code_hash,
            &self.policy,
            &self.allocation,
        ] {
            out.extend_from_slice(h);
        }
        out.extend_from_slice(&self.chain.to_le_bytes());
        out.extend_from_slice(&self.bridge);
    }
    fn read_fields(r: &mut Reader<'_>) -> Result<Self> {
        Ok(Self {
            domain: r.array()?,
            ckb_genesis: r.array()?,
            adapter_code_hash: r.array()?,
            head_lock_code_hash: r.array()?,
            policy: r.array()?,
            allocation: r.array()?,
            chain: r.u64()?,
            bridge: r.array()?,
        })
    }
}
