use super::codec::put_lanes;
use super::{
    check_lanes, nonzero, Config, DepositCursor, Error, Policy, Reader, Result, Wire,
    EPOCH_BATCHES, LANES,
};
use alloc::vec::Vec;

/// Full immutable publication boundary. EVM roots belong to proven Control.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Boundary {
    pub config: [u8; 32],
    pub batches: u64,
    pub inputs: [u8; 32],
    pub blocks: u64,
    pub timestamp: u64,
    pub deposits: DepositCursor,
    pub processed: [u64; LANES],
    pub epoch: u64,
    pub snapshot: [u8; 32],
    pub user_cursor: u8,
    pub deposit_cursor: u8,
    pub epoch_batches: u8,
}
impl Boundary {
    pub fn genesis(config: [u8; 32]) -> Result<Self> {
        let value = Self {
            config,
            batches: 0,
            inputs: [0; 32],
            blocks: 0,
            timestamp: 0,
            deposits: DepositCursor::genesis(&config),
            processed: [0; LANES],
            epoch: 0,
            snapshot: [0; 32],
            user_cursor: 0,
            deposit_cursor: 0,
            epoch_batches: EPOCH_BATCHES,
        };
        value.validate()?;
        Ok(value)
    }
    pub fn bind(&self, config: &Config, policy: &Policy) -> Result<()> {
        config.bind(policy)?;
        self.validate()?;
        if self.config != config.commitment()? {
            return Err(Error::Domain);
        }
        check_lanes(&self.processed, policy.lanes)
    }
    /// Structural progression; immutable checkpoint provenance is checked on L1.
    pub fn advances(&self, next: &Self) -> Result<()> {
        self.validate()?;
        next.validate()?;
        if self.config != next.config {
            return Err(Error::Domain);
        }
        if next.batches <= self.batches
            || next.blocks <= self.blocks
            || next.timestamp < self.timestamp
            || next.epoch < self.epoch
            || next.deposits.count < self.deposits.count
            || next.deposits.cumulative < self.deposits.cumulative
            || self
                .processed
                .iter()
                .zip(next.processed)
                .any(|(a, b)| b < *a)
        {
            return Err(Error::Continuity);
        }
        if next.deposits.count == self.deposits.count && next.deposits != self.deposits {
            return Err(Error::Continuity);
        }
        if next.deposits.count > self.deposits.count
            && next.deposits.cumulative <= self.deposits.cumulative
        {
            return Err(Error::Continuity);
        }
        Ok(())
    }
    pub fn append_allowed(&self, control: &Control, policy: &Policy) -> Result<()> {
        self.validate()?;
        control.validate()?;
        policy.validate()?;
        control.running()?;
        if self.config != control.boundary.config || control.policy != policy.commitment()? {
            return Err(Error::Domain);
        }
        let pending = super::increment(self.batches)?
            .checked_sub(control.boundary.batches)
            .ok_or(Error::Continuity)?;
        if control.boundary.batches > self.batches || pending > policy.max_pending_batches {
            return Err(Error::Limit);
        }
        Ok(())
    }
}
impl Wire for Boundary {
    const MAGIC: [u8; 8] = *b"T02BND01";
    const MAX_BYTES: usize = 227;
    fn validate(&self) -> Result<()> {
        nonzero(&self.config)?;
        self.deposits.validate()?;
        if self.user_cursor > 32
            || self.deposit_cursor > 32
            || self.epoch_batches > EPOCH_BATCHES
            || self.timestamp >= (1u64 << 56)
        {
            return Err(Error::Limit);
        }
        if self.batches == 0 {
            if self.inputs != [0; 32]
                || self.blocks != 0
                || self.timestamp != 0
                || self.deposits != DepositCursor::genesis(&self.config)
                || self.processed != [0; LANES]
                || self.epoch != 0
                || self.snapshot != [0; 32]
                || self.user_cursor != 0
                || self.deposit_cursor != 0
                || self.epoch_batches != EPOCH_BATCHES
            {
                return Err(Error::Continuity);
            }
        } else {
            nonzero(&self.inputs)?;
            nonzero(&self.snapshot)?;
            if self.blocks < self.batches || self.epoch == 0 || self.epoch_batches == 0 {
                return Err(Error::Continuity);
            }
        }
        Ok(())
    }
    fn write_fields(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.config);
        out.extend_from_slice(&self.batches.to_le_bytes());
        out.extend_from_slice(&self.inputs);
        out.extend_from_slice(&self.blocks.to_le_bytes());
        out.extend_from_slice(&self.timestamp.to_le_bytes());
        self.deposits.write(out);
        put_lanes(out, &self.processed);
        out.extend_from_slice(&self.epoch.to_le_bytes());
        out.extend_from_slice(&self.snapshot);
        out.extend_from_slice(&[self.user_cursor, self.deposit_cursor, self.epoch_batches]);
    }
    fn read_fields(r: &mut Reader<'_>) -> Result<Self> {
        Ok(Self {
            config: r.array()?,
            batches: r.u64()?,
            inputs: r.array()?,
            blocks: r.u64()?,
            timestamp: r.u64()?,
            deposits: DepositCursor::read(r)?,
            processed: r.lanes()?,
            epoch: r.u64()?,
            snapshot: r.array()?,
            user_cursor: r.u8()?,
            deposit_cursor: r.u8()?,
            epoch_batches: r.u8()?,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Mode {
    Running = 0,
    Frozen = 1,
}
impl TryFrom<u8> for Mode {
    type Error = Error;
    fn try_from(value: u8) -> Result<Self> {
        match value {
            0 => Ok(Self::Running),
            1 => Ok(Self::Frozen),
            _ => Err(Error::Encoding),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Control {
    pub mode: Mode,
    pub initialized: bool,
    pub policy: [u8; 32],
    pub profile: [u8; 32],
    pub boundary: Boundary,
    pub state_root: [u8; 32],
    pub block_hash: [u8; 32],
    pub supply: u128,
    pub burned: u128,
}
impl Control {
    pub fn genesis(config: &Config, policy: &Policy) -> Result<Self> {
        config.bind(policy)?;
        let value = Self {
            mode: Mode::Running,
            initialized: false,
            policy: config.policy,
            profile: policy.profile,
            boundary: Boundary::genesis(config.commitment()?)?,
            state_root: [0; 32],
            block_hash: [0; 32],
            supply: 0,
            burned: 0,
        };
        value.validate()?;
        Ok(value)
    }
    pub fn bind(&self, config: &Config, policy: &Policy) -> Result<()> {
        self.validate()?;
        self.boundary.bind(config, policy)?;
        if self.policy != config.policy || self.profile != policy.profile {
            return Err(Error::Domain);
        }
        Ok(())
    }
    pub fn running(&self) -> Result<()> {
        if self.mode != Mode::Running {
            Err(Error::Mode)
        } else {
            Ok(())
        }
    }
    /// Returns a candidate after checking public inputs. This deliberately does
    /// not claim to verify a proof; the adapter must do so with the pinned key.
    pub fn settlement_candidate(&self, journal: &Journal, checkpoint: &Boundary) -> Result<Self> {
        self.running()?;
        journal.validate()?;
        if &journal.start != self || &journal.end.boundary != checkpoint {
            return Err(Error::Continuity);
        }
        Ok(journal.end.clone())
    }
    /// CKB consensus checks actual age; this checks the exact since metric and
    /// both thresholds. Source authenticity and live inputs are adapter duties.
    pub fn freeze_candidate(
        &self,
        ticket: &Watch,
        policy: &Policy,
        control_since: u64,
        ticket_since: u64,
    ) -> Result<Self> {
        self.validate()?;
        self.running()?;
        policy.validate()?;
        ticket.validate()?;
        if self.policy != policy.commitment()? || ticket.config != self.boundary.config {
            return Err(Error::Domain);
        }
        if !ticket.work.pending(&self.boundary, policy.lanes)? {
            return Err(Error::Duty);
        }
        relative_blocks(control_since, policy.stall_blocks)?;
        relative_blocks(ticket_since, policy.stall_blocks)?;
        let mut frozen = self.clone();
        frozen.mode = Mode::Frozen;
        Ok(frozen)
    }
}
impl Wire for Control {
    const MAGIC: [u8; 8] = *b"T02CTL01";
    const MAX_BYTES: usize = 397;
    fn validate(&self) -> Result<()> {
        nonzero(&self.policy)?;
        nonzero(&self.profile)?;
        self.boundary.validate()?;
        if self
            .supply
            .checked_add(self.burned)
            .ok_or(Error::Arithmetic)?
            != self.boundary.deposits.cumulative
            || self.supply > u128::from(u64::MAX)
        {
            return Err(Error::Accounting);
        }
        if self.initialized {
            if self.boundary.batches == 0 {
                return Err(Error::Continuity);
            }
            nonzero(&self.state_root)?;
            nonzero(&self.block_hash)?;
        } else if self.boundary.batches != 0
            || self.state_root != [0; 32]
            || self.block_hash != [0; 32]
        {
            return Err(Error::Continuity);
        }
        Ok(())
    }
    fn write_fields(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&[self.mode as u8, u8::from(self.initialized)]);
        out.extend_from_slice(&self.policy);
        out.extend_from_slice(&self.profile);
        out.extend_from_slice(&Boundary::MAGIC);
        self.boundary.write_fields(out);
        out.extend_from_slice(&self.state_root);
        out.extend_from_slice(&self.block_hash);
        out.extend_from_slice(&self.supply.to_le_bytes());
        out.extend_from_slice(&self.burned.to_le_bytes());
    }
    fn read_fields(r: &mut Reader<'_>) -> Result<Self> {
        let mode = Mode::try_from(r.u8()?)?;
        let initialized = match r.u8()? {
            0 => false,
            1 => true,
            _ => return Err(Error::Encoding),
        };
        Ok(Self {
            mode,
            initialized,
            policy: r.array()?,
            profile: r.array()?,
            boundary: Boundary::decode(r.take(Boundary::MAX_BYTES)?)?,
            state_root: r.array()?,
            block_hash: r.array()?,
            supply: r.u128()?,
            burned: r.u128()?,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Journal {
    pub start: Control,
    pub end: Control,
    pub outcomes: [u8; 32],
    pub interval_inputs: [u8; 32],
}
impl Wire for Journal {
    const MAGIC: [u8; 8] = *b"T02JRN01";
    const MAX_BYTES: usize = 866;
    fn validate(&self) -> Result<()> {
        self.start.validate()?;
        self.end.validate()?;
        self.start.running()?;
        self.end.running()?;
        if self.start.policy != self.end.policy || self.start.profile != self.end.profile {
            return Err(Error::Domain);
        }
        self.start.boundary.advances(&self.end.boundary)?;
        if !self.end.initialized || self.end.burned < self.start.burned {
            return Err(Error::Accounting);
        }
        nonzero(&self.outcomes)?;
        nonzero(&self.interval_inputs)
    }
    fn write_fields(&self, out: &mut Vec<u8>) {
        for control in [&self.start, &self.end] {
            out.extend_from_slice(&Control::MAGIC);
            control.write_fields(out);
        }
        out.extend_from_slice(&self.outcomes);
        out.extend_from_slice(&self.interval_inputs);
    }
    fn read_fields(r: &mut Reader<'_>) -> Result<Self> {
        Ok(Self {
            start: Control::decode(r.take(Control::MAX_BYTES)?)?,
            end: Control::decode(r.take(Control::MAX_BYTES)?)?,
            outcomes: r.array()?,
            interval_inputs: r.array()?,
        })
    }
}

/// End-exclusive work indices eliminate the lane/deposit off-by-one ambiguity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Work {
    Batch(u64),
    Deposit(u64),
    Admission { lane: u8, end: u64 },
}
impl Work {
    pub fn admission(lane: u8, sequence: u64) -> Result<Self> {
        let value = Self::Admission {
            lane,
            end: super::increment(sequence)?,
        };
        value.validate()?;
        Ok(value)
    }
    fn fields(self) -> (u8, u8, u64) {
        match self {
            Self::Batch(n) => (0, 0, n),
            Self::Deposit(n) => (1, 0, n),
            Self::Admission { lane, end } => (2, lane, end),
        }
    }
    pub fn validate(self) -> Result<()> {
        let (_, lane, end) = self.fields();
        if end == 0 || usize::from(lane) >= LANES {
            return Err(Error::Limit);
        }
        Ok(())
    }
    pub fn pending(self, boundary: &Boundary, lanes: u8) -> Result<bool> {
        self.validate()?;
        boundary.validate()?;
        check_lanes(&boundary.processed, lanes)?;
        Ok(match self {
            Self::Batch(end) => end > boundary.batches,
            Self::Deposit(end) => end > boundary.deposits.count,
            Self::Admission { lane, end } => {
                if lane >= lanes {
                    return Err(Error::Limit);
                }
                end > boundary.processed[usize::from(lane)]
            }
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Watch {
    pub config: [u8; 32],
    pub work: Work,
    /// Exact CKB outpoint of the typed immutable source, not an arbitrary hash.
    pub source: [u8; 36],
    pub observed_control: [u8; 32],
    pub refund_lock: [u8; 32],
}
impl Watch {
    pub fn close_allowed(&self, control: &Control, policy: &Policy) -> Result<()> {
        self.validate()?;
        control.validate()?;
        if self.config != control.boundary.config || control.policy != policy.commitment()? {
            return Err(Error::Domain);
        }
        if control.mode == Mode::Frozen || !self.work.pending(&control.boundary, policy.lanes)? {
            Ok(())
        } else {
            Err(Error::Duty)
        }
    }
}
impl Wire for Watch {
    const MAGIC: [u8; 8] = *b"T02WCH01";
    const MAX_BYTES: usize = 150;
    fn validate(&self) -> Result<()> {
        for h in [&self.config, &self.observed_control, &self.refund_lock] {
            nonzero(h)?;
        }
        if self.source[..32] == [0; 32] {
            return Err(Error::Identity);
        }
        self.work.validate()
    }
    fn write_fields(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.config);
        let (kind, lane, end) = self.work.fields();
        out.extend_from_slice(&[kind, lane]);
        out.extend_from_slice(&end.to_le_bytes());
        out.extend_from_slice(&self.source);
        out.extend_from_slice(&self.observed_control);
        out.extend_from_slice(&self.refund_lock);
    }
    fn read_fields(r: &mut Reader<'_>) -> Result<Self> {
        let config = r.array()?;
        let kind = r.u8()?;
        let lane = r.u8()?;
        let end = r.u64()?;
        let work = match (kind, lane) {
            (0, 0) => Work::Batch(end),
            (1, 0) => Work::Deposit(end),
            (2, lane) => Work::Admission { lane, end },
            _ => return Err(Error::Encoding),
        };
        Ok(Self {
            config,
            work,
            source: r.array()?,
            observed_control: r.array()?,
            refund_lock: r.array()?,
        })
    }
}

/// CKB since uses the high byte for flags; reserved bits must also be zero.
pub fn relative_blocks(since: u64, minimum: u64) -> Result<()> {
    if minimum == 0
        || minimum >= (1u64 << 56)
        || since >> 56 != 0x80
        || since & ((1u64 << 56) - 1) < minimum
    {
        return Err(Error::Maturity);
    }
    Ok(())
}
pub fn absolute_timestamp(since: u64, seconds: u64) -> Result<()> {
    if seconds >= (1u64 << 56) || since != (0x40u64 << 56) | seconds {
        return Err(Error::Maturity);
    }
    Ok(())
}
