//! Custody arithmetic. Receipts, state proofs and nullifier updates must be
//! authenticated by the adapter before these accounting transitions authorize
//! any payout. Arithmetic success alone is never a claim authorization.
use super::{hash, increment, nonzero, Config, Control, Error, Mode, Policy, Reader, Result, Wire};
use alloc::vec::Vec;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DepositCursor {
    pub count: u64,
    pub cumulative: u128,
    pub accumulator: [u8; 32],
}
impl DepositCursor {
    pub const BYTES: usize = 56;
    pub fn genesis(config: &[u8; 32]) -> Self {
        Self {
            count: 0,
            cumulative: 0,
            accumulator: hash(b"tactus/0.02/deposits/empty", config),
        }
    }
    pub fn validate(&self) -> Result<()> {
        nonzero(&self.accumulator)?;
        if (self.count == 0) != (self.cumulative == 0) || self.cumulative < u128::from(self.count) {
            return Err(Error::Accounting);
        }
        Ok(())
    }
    pub(crate) fn write(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.count.to_le_bytes());
        out.extend_from_slice(&self.cumulative.to_le_bytes());
        out.extend_from_slice(&self.accumulator);
    }
    pub(crate) fn read(r: &mut Reader<'_>) -> Result<Self> {
        let value = Self {
            count: r.u64()?,
            cumulative: r.u128()?,
            accumulator: r.array()?,
        };
        value.validate()?;
        Ok(value)
    }
    pub fn follow(&self, deposit: &Deposit) -> Result<Self> {
        self.validate()?;
        deposit.validate()?;
        if deposit.sequence != increment(self.count)?
            || deposit.previous != self.accumulator
            || deposit.cumulative
                != self
                    .cumulative
                    .checked_add(u128::from(deposit.amount))
                    .ok_or(Error::Arithmetic)?
        {
            return Err(Error::Continuity);
        }
        Ok(Self {
            count: deposit.sequence,
            cumulative: deposit.cumulative,
            accumulator: deposit.commitment()?,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Deposit {
    pub config: [u8; 32],
    /// One based. A completed cursor of zero leaves the first receipt pending.
    pub sequence: u64,
    pub recipient: [u8; 20],
    pub amount: u64,
    pub refund_lock: [u8; 32],
    pub cumulative: u128,
    pub previous: [u8; 32],
}
impl Wire for Deposit {
    const MAGIC: [u8; 8] = *b"T02DEP01";
    const MAX_BYTES: usize = 156;
    fn validate(&self) -> Result<()> {
        for h in [&self.config, &self.refund_lock, &self.previous] {
            nonzero(h)?;
        }
        if self.sequence == 0
            || self.amount == 0
            || self.recipient == [0; 20]
            || self.cumulative < u128::from(self.amount)
            || self.cumulative < u128::from(self.sequence)
        {
            return Err(Error::Accounting);
        }
        Ok(())
    }
    fn write_fields(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.config);
        out.extend_from_slice(&self.sequence.to_le_bytes());
        out.extend_from_slice(&self.recipient);
        out.extend_from_slice(&self.amount.to_le_bytes());
        out.extend_from_slice(&self.refund_lock);
        out.extend_from_slice(&self.cumulative.to_le_bytes());
        out.extend_from_slice(&self.previous);
    }
    fn read_fields(r: &mut Reader<'_>) -> Result<Self> {
        Ok(Self {
            config: r.array()?,
            sequence: r.u64()?,
            recipient: r.array()?,
            amount: r.u64()?,
            refund_lock: r.array()?,
            cumulative: r.u128()?,
            previous: r.array()?,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ClaimKind {
    Release = 0,
    Refund = 1,
    Escape = 2,
}
impl TryFrom<u8> for ClaimKind {
    type Error = Error;
    fn try_from(value: u8) -> Result<Self> {
        match value {
            0 => Ok(Self::Release),
            1 => Ok(Self::Refund),
            2 => Ok(Self::Escape),
            _ => Err(Error::Encoding),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Vault {
    pub config: [u8; 32],
    pub reserve: u64,
    pub deposits: DepositCursor,
    pub released: u128,
    pub refunded: u128,
    pub escaped: u128,
    /// Independent 256-bit nullifier trees, ordered RELEASE / REFUND / ESCAPE.
    pub claims: [[u8; 32]; 3],
}
impl Vault {
    pub fn genesis(config: [u8; 32], reserve: u64) -> Result<Self> {
        let value = Self {
            config,
            reserve,
            deposits: DepositCursor::genesis(&config),
            released: 0,
            refunded: 0,
            escaped: 0,
            claims: [
                super::empty_claim_root(&config, ClaimKind::Release)?,
                super::empty_claim_root(&config, ClaimKind::Refund)?,
                super::empty_claim_root(&config, ClaimKind::Escape)?,
            ],
        };
        value.validate()?;
        Ok(value)
    }
    pub fn capacity(&self) -> Result<u64> {
        let principal = self
            .deposits
            .cumulative
            .checked_sub(self.released)
            .and_then(|v| v.checked_sub(self.refunded))
            .and_then(|v| v.checked_sub(self.escaped))
            .ok_or(Error::Accounting)?;
        u64::try_from(
            principal
                .checked_add(u128::from(self.reserve))
                .ok_or(Error::Arithmetic)?,
        )
        .map_err(|_| Error::Arithmetic)
    }
    /// Validate all three independently nonnegative liability partitions.
    pub fn partitions(&self, control: &Control) -> Result<[u128; 3]> {
        self.validate()?;
        control.validate()?;
        if self.config != control.boundary.config {
            return Err(Error::Domain);
        }
        if control.boundary.deposits.count > self.deposits.count {
            return Err(Error::Accounting);
        }
        if control.boundary.deposits.count == self.deposits.count
            && control.boundary.deposits != self.deposits
        {
            return Err(Error::Accounting);
        }
        if control.mode == Mode::Running && (self.refunded != 0 || self.escaped != 0) {
            return Err(Error::Mode);
        }
        let uncredited = self
            .deposits
            .cumulative
            .checked_sub(control.boundary.deposits.cumulative)
            .and_then(|v| v.checked_sub(self.refunded))
            .ok_or(Error::Accounting)?;
        let circulating = control
            .supply
            .checked_sub(self.escaped)
            .ok_or(Error::Accounting)?;
        let withdrawals = control
            .burned
            .checked_sub(self.released)
            .ok_or(Error::Accounting)?;
        let total = uncredited
            .checked_add(circulating)
            .and_then(|v| v.checked_add(withdrawals))
            .ok_or(Error::Arithmetic)?;
        if total != u128::from(self.capacity()? - self.reserve) {
            return Err(Error::Accounting);
        }
        Ok([uncredited, circulating, withdrawals])
    }
    pub fn deposit(
        &self,
        config: &Config,
        policy: &Policy,
        control: &Control,
        recipient: [u8; 20],
        amount: u64,
        refund_lock: [u8; 32],
    ) -> Result<(Self, Deposit)> {
        config.bind(policy)?;
        control.bind(config, policy)?;
        control.running()?;
        self.partitions(control)?;
        let next = increment(self.deposits.count)?;
        if next
            .checked_sub(control.boundary.deposits.count)
            .ok_or(Error::Continuity)?
            > policy.max_pending_deposits
        {
            return Err(Error::Limit);
        }
        if recipient == config.bridge {
            return Err(Error::Domain);
        }
        let receipt = Deposit {
            config: self.config,
            sequence: next,
            recipient,
            amount,
            refund_lock,
            cumulative: self
                .deposits
                .cumulative
                .checked_add(u128::from(amount))
                .ok_or(Error::Arithmetic)?,
            previous: self.deposits.accumulator,
        };
        let mut result = self.clone();
        result.deposits = self.deposits.follow(&receipt)?;
        result.partitions(control)?;
        Ok((result, receipt))
    }
    /// Accounting only. The adapter separately verifies the claim and the
    /// zero-to-one nullifier update before accepting this candidate state.
    pub fn claim_accounting(
        &self,
        control: &Control,
        kind: ClaimKind,
        amount: u64,
        new_root: [u8; 32],
    ) -> Result<Self> {
        self.partitions(control)?;
        if amount == 0 {
            return Err(Error::Accounting);
        }
        nonzero(&new_root)?;
        if new_root == self.claims[kind as usize] {
            return Err(Error::Identity);
        }
        if kind != ClaimKind::Release && control.mode != Mode::Frozen {
            return Err(Error::Mode);
        }
        if kind != ClaimKind::Refund && !control.initialized {
            return Err(Error::Proof);
        }
        let mut result = self.clone();
        let counter = match kind {
            ClaimKind::Release => &mut result.released,
            ClaimKind::Refund => &mut result.refunded,
            ClaimKind::Escape => &mut result.escaped,
        };
        *counter = counter
            .checked_add(u128::from(amount))
            .ok_or(Error::Arithmetic)?;
        result.claims[kind as usize] = new_root;
        result.partitions(control)?;
        Ok(result)
    }
}
impl Wire for Vault {
    const MAGIC: [u8; 8] = *b"T02VLT01";
    const MAX_BYTES: usize = 248;
    fn validate(&self) -> Result<()> {
        nonzero(&self.config)?;
        self.deposits.validate()?;
        if self.reserve == 0 {
            return Err(Error::Accounting);
        }
        for root in &self.claims {
            nonzero(root)?;
        }
        self.capacity()?;
        Ok(())
    }
    fn write_fields(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.config);
        out.extend_from_slice(&self.reserve.to_le_bytes());
        self.deposits.write(out);
        for n in [self.released, self.refunded, self.escaped] {
            out.extend_from_slice(&n.to_le_bytes());
        }
        for root in &self.claims {
            out.extend_from_slice(root);
        }
    }
    fn read_fields(r: &mut Reader<'_>) -> Result<Self> {
        Ok(Self {
            config: r.array()?,
            reserve: r.u64()?,
            deposits: DepositCursor::read(r)?,
            released: r.u128()?,
            refunded: r.u128()?,
            escaped: r.u128()?,
            claims: [r.array()?, r.array()?, r.array()?],
        })
    }
}
