//! Immutable A3 snapshots with independent user and native-deposit duties.
use super::*;
use crate::batch::{
    BlockInput, MAX_BLOCKS, MAX_BLOCK_TRANSACTIONS, MAX_TRANSACTIONS, MAX_TRANSACTION_BYTES,
};
use alloc::vec::Vec;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Message {
    pub sequence: u64,
    pub payload: Vec<u8>,
}
impl Message {
    fn validate(&self) -> Result<()> {
        if self.payload.is_empty() || self.payload.len() > PRIORITY_BYTES {
            return Err(Error::Limit);
        }
        super::increment(self.sequence)?;
        Ok(())
    }
    fn write(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.sequence.to_le_bytes());
        put_blob(out, &self.payload);
    }
    fn read(r: &mut Reader<'_>) -> Result<Self> {
        let value = Self {
            sequence: r.u64()?,
            payload: r.blob(PRIORITY_BYTES)?.to_vec(),
        };
        value.validate()?;
        Ok(value)
    }
}
fn put_blob(out: &mut Vec<u8>, bytes: &[u8]) {
    // All callers validate their objects before serialization.
    out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(bytes);
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Admission {
    pub config: [u8; 32],
    pub lane: u8,
    pub sequence: u64,
    pub epoch: u64,
    pub payload_hash: [u8; 32],
}
impl Wire for Admission {
    const MAGIC: [u8; 8] = *b"T02ADM01";
    const MAX_BYTES: usize = 89;
    fn validate(&self) -> Result<()> {
        nonzero(&self.config)?;
        nonzero(&self.payload_hash)?;
        Work::admission(self.lane, self.sequence)?;
        Ok(())
    }
    fn write_fields(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.config);
        out.push(self.lane);
        out.extend_from_slice(&self.sequence.to_le_bytes());
        out.extend_from_slice(&self.epoch.to_le_bytes());
        out.extend_from_slice(&self.payload_hash);
    }
    fn read_fields(r: &mut Reader<'_>) -> Result<Self> {
        Ok(Self {
            config: r.array()?,
            lane: r.u8()?,
            sequence: r.u64()?,
            epoch: r.u64()?,
            payload_hash: r.array()?,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Lane {
    pub config: [u8; 32],
    pub lane: u8,
    pub epoch: u64,
    pub next: u64,
    pub history: [u8; 32],
    pub messages: Vec<Message>,
}
impl Lane {
    pub fn genesis(config: [u8; 32], lane: u8) -> Result<Self> {
        let value = Self {
            config,
            lane,
            epoch: 0,
            next: 0,
            history: hash(
                b"tactus/0.02/lane/empty",
                &[config.as_slice(), &[lane]].concat(),
            ),
            messages: Vec::new(),
        };
        value.validate()?;
        Ok(value)
    }
    pub fn enqueue(
        &self,
        control: &Control,
        policy: &Policy,
        payload: Vec<u8>,
    ) -> Result<(Self, Admission)> {
        self.validate()?;
        control.validate()?;
        control.running()?;
        if self.config != control.boundary.config || control.policy != policy.commitment()? {
            return Err(Error::Domain);
        }
        if self.lane >= policy.lanes || self.messages.len() >= LANE_MESSAGES {
            return Err(Error::Limit);
        }
        let message = Message {
            sequence: self.next,
            payload,
        };
        message.validate()?;
        let receipt = Admission {
            config: self.config,
            lane: self.lane,
            sequence: self.next,
            epoch: self.epoch,
            payload_hash: hash(b"tactus/0.02/payload", &message.payload),
        };
        let mut next = self.clone();
        next.next = increment(self.next)?;
        next.history = hash(
            b"tactus/0.02/lane/append",
            &[&self.history[..], &receipt.commitment()?[..]].concat(),
        );
        next.messages.push(message);
        next.validate()?;
        Ok((next, receipt))
    }
}
impl Wire for Lane {
    const MAGIC: [u8; 8] = *b"T02LAN01";
    const MAX_BYTES: usize = 90 + LANE_MESSAGES * (12 + PRIORITY_BYTES);
    fn validate(&self) -> Result<()> {
        nonzero(&self.config)?;
        nonzero(&self.history)?;
        if usize::from(self.lane) >= LANES || self.messages.len() > LANE_MESSAGES {
            return Err(Error::Limit);
        }
        let first = self
            .next
            .checked_sub(self.messages.len() as u64)
            .ok_or(Error::Continuity)?;
        for (offset, message) in self.messages.iter().enumerate() {
            message.validate()?;
            if message.sequence != first.checked_add(offset as u64).ok_or(Error::Arithmetic)? {
                return Err(Error::Continuity);
            }
        }
        Ok(())
    }
    fn write_fields(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.config);
        out.push(self.lane);
        out.extend_from_slice(&self.epoch.to_le_bytes());
        out.extend_from_slice(&self.next.to_le_bytes());
        out.extend_from_slice(&self.history);
        out.push(self.messages.len() as u8);
        for message in &self.messages {
            message.write(out);
        }
    }
    fn read_fields(r: &mut Reader<'_>) -> Result<Self> {
        let config = r.array()?;
        let lane = r.u8()?;
        let epoch = r.u64()?;
        let next = r.u64()?;
        let history = r.array()?;
        let count = usize::from(r.u8()?);
        if count > LANE_MESSAGES {
            return Err(Error::Limit);
        }
        let mut messages = Vec::with_capacity(count);
        for _ in 0..count {
            messages.push(Message::read(r)?);
        }
        Ok(Self {
            config,
            lane,
            epoch,
            next,
            history,
            messages,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Priority {
    pub lane: u8,
    pub message: Message,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Snapshot {
    pub config: [u8; 32],
    pub epoch: u64,
    pub lanes: Vec<Lane>,
    pub deposit_start: DepositCursor,
    pub deposit_end: DepositCursor,
}
impl Snapshot {
    pub fn users(&self) -> Result<Vec<Priority>> {
        self.validate()?;
        let mut users = Vec::new();
        for depth in 0..LANE_MESSAGES {
            for lane in &self.lanes {
                if let Some(message) = lane.messages.get(depth) {
                    users.push(Priority {
                        lane: lane.lane,
                        message: message.clone(),
                    });
                }
            }
        }
        Ok(users)
    }
    pub fn processed(&self, cursor: usize) -> Result<[u64; LANES]> {
        let users = self.users()?;
        if cursor > users.len() {
            return Err(Error::Duty);
        }
        let mut q = [0; LANES];
        for lane in &self.lanes {
            q[usize::from(lane.lane)] = lane.next - lane.messages.len() as u64;
        }
        for entry in &users[..cursor] {
            q[usize::from(entry.lane)] = increment(entry.message.sequence)?;
        }
        Ok(q)
    }
    fn deposit_count(&self) -> usize {
        (self.deposit_end.count - self.deposit_start.count) as usize
    }
}
impl Wire for Snapshot {
    const MAGIC: [u8; 8] = *b"T02SNP01";
    const MAX_BYTES: usize = 49 + LANES * (4 + Lane::MAX_BYTES) + 112;
    fn validate(&self) -> Result<()> {
        nonzero(&self.config)?;
        if self.epoch == 0 || self.lanes.is_empty() || self.lanes.len() > LANES {
            return Err(Error::Limit);
        }
        for (index, lane) in self.lanes.iter().enumerate() {
            lane.validate()?;
            if lane.config != self.config
                || usize::from(lane.lane) != index
                || increment(lane.epoch)? != self.epoch
            {
                return Err(Error::Domain);
            }
        }
        self.deposit_start.validate()?;
        self.deposit_end.validate()?;
        let count = self
            .deposit_end
            .count
            .checked_sub(self.deposit_start.count)
            .ok_or(Error::Continuity)?;
        let amount = self
            .deposit_end
            .cumulative
            .checked_sub(self.deposit_start.cumulative)
            .ok_or(Error::Continuity)?;
        if count > 32
            || amount < u128::from(count)
            || (count == 0 && self.deposit_start != self.deposit_end)
        {
            return Err(Error::Limit);
        }
        Ok(())
    }
    fn write_fields(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.config);
        out.extend_from_slice(&self.epoch.to_le_bytes());
        out.push(self.lanes.len() as u8);
        for lane in &self.lanes {
            let mut bytes = Vec::new();
            bytes.extend_from_slice(&Lane::MAGIC);
            lane.write_fields(&mut bytes);
            put_blob(out, &bytes);
        }
        self.deposit_start.write(out);
        self.deposit_end.write(out);
    }
    fn read_fields(r: &mut Reader<'_>) -> Result<Self> {
        let config = r.array()?;
        let epoch = r.u64()?;
        let count = usize::from(r.u8()?);
        if count == 0 || count > LANES {
            return Err(Error::Limit);
        }
        let mut lanes = Vec::with_capacity(count);
        for _ in 0..count {
            lanes.push(Lane::decode(r.blob(Lane::MAX_BYTES)?)?);
        }
        Ok(Self {
            config,
            epoch,
            lanes,
            deposit_start: DepositCursor::read(r)?,
            deposit_end: DepositCursor::read(r)?,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Schedule {
    pub config: [u8; 32],
    pub epoch: u64,
    pub snapshot: [u8; 32],
    pub batches: u8,
    pub user_cursor: u8,
    pub deposit_cursor: u8,
}
impl Schedule {
    pub fn genesis(config: [u8; 32]) -> Result<Self> {
        let value = Self {
            config,
            epoch: 0,
            snapshot: [0; 32],
            batches: EPOCH_BATCHES,
            user_cursor: 0,
            deposit_cursor: 0,
        };
        value.validate()?;
        Ok(value)
    }
    pub fn bind_snapshot(&self, snapshot: &Snapshot) -> Result<()> {
        self.validate()?;
        snapshot.validate()?;
        if self.config != snapshot.config
            || self.epoch != snapshot.epoch
            || self.snapshot != snapshot.commitment()?
        {
            return Err(Error::Domain);
        }
        let slots = usize::from(self.batches) * DUTY;
        if usize::from(self.user_cursor) != slots.min(snapshot.users()?.len())
            || usize::from(self.deposit_cursor) != slots.min(snapshot.deposit_count())
        {
            return Err(Error::Duty);
        }
        Ok(())
    }
    /// The adapter authenticates every consumed lane and Vault, and requires
    /// Vault to be recreated unchanged. This function cannot discover missing cells.
    #[allow(clippy::too_many_arguments)]
    pub fn seal(
        &self,
        config: &Config,
        policy: &Policy,
        control: &Control,
        anchor: &Boundary,
        lanes: &[Lane],
        vault: &Vault,
        previous: Option<&Snapshot>,
    ) -> Result<(Self, Snapshot, Vec<Lane>)> {
        self.validate()?;
        control.bind(config, policy)?;
        control.running()?;
        anchor.bind(config, policy)?;
        vault.partitions(control)?;
        if self.config != anchor.config || self.config != vault.config {
            return Err(Error::Domain);
        }
        if self.batches != EPOCH_BATCHES || lanes.len() != usize::from(policy.lanes) {
            return Err(Error::Duty);
        }
        if self.epoch == 0 {
            if previous.is_some() || *anchor != Boundary::genesis(self.config)? {
                return Err(Error::Continuity);
            }
        } else {
            let old = previous.ok_or(Error::Duty)?;
            self.bind_snapshot(old)?;
            if anchor.epoch != self.epoch
                || anchor.snapshot != self.snapshot
                || anchor.epoch_batches != self.batches
                || anchor.user_cursor != self.user_cursor
                || anchor.deposit_cursor != self.deposit_cursor
                || anchor.deposits != old.deposit_end
                || anchor.processed != old.processed(old.users()?.len())?
            {
                return Err(Error::Continuity);
            }
        }
        let snapshot = Snapshot {
            config: self.config,
            epoch: increment(self.epoch)?,
            lanes: lanes.to_vec(),
            deposit_start: anchor.deposits,
            deposit_end: vault.deposits,
        };
        snapshot.validate()?;
        if snapshot.processed(0)? != anchor.processed
            || snapshot.deposit_count() as u64 > policy.max_pending_deposits
        {
            return Err(Error::Continuity);
        }
        let next = Self {
            config: self.config,
            epoch: snapshot.epoch,
            snapshot: snapshot.commitment()?,
            batches: 0,
            user_cursor: 0,
            deposit_cursor: 0,
        };
        let mut cleared = lanes.to_vec();
        for lane in &mut cleared {
            lane.epoch = snapshot.epoch;
            lane.messages.clear();
        }
        Ok((next, snapshot, cleared))
    }
}
impl Wire for Schedule {
    const MAGIC: [u8; 8] = *b"T02SCH01";
    const MAX_BYTES: usize = 83;
    fn validate(&self) -> Result<()> {
        nonzero(&self.config)?;
        if self.batches > EPOCH_BATCHES || self.user_cursor > 32 || self.deposit_cursor > 32 {
            return Err(Error::Limit);
        }
        if self.epoch == 0 {
            if self.snapshot != [0; 32]
                || self.batches != EPOCH_BATCHES
                || self.user_cursor != 0
                || self.deposit_cursor != 0
            {
                return Err(Error::Continuity);
            }
        } else {
            nonzero(&self.snapshot)?;
        }
        Ok(())
    }
    fn write_fields(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.config);
        out.extend_from_slice(&self.epoch.to_le_bytes());
        out.extend_from_slice(&self.snapshot);
        out.extend_from_slice(&[self.batches, self.user_cursor, self.deposit_cursor]);
    }
    fn read_fields(r: &mut Reader<'_>) -> Result<Self> {
        Ok(Self {
            config: r.array()?,
            epoch: r.u64()?,
            snapshot: r.array()?,
            batches: r.u8()?,
            user_cursor: r.u8()?,
            deposit_cursor: r.u8()?,
        })
    }
}

/// Complete publication envelope. No host-supplied EVM result or outcome roots.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativeBatch {
    pub parent: Boundary,
    pub snapshot: [u8; 32],
    pub priority: Vec<Priority>,
    pub deposits: Vec<Deposit>,
    pub blocks: Vec<BlockInput>,
}
impl NativeBatch {
    /// Derives the exact required successor and checkpoint. All receipt cells
    /// and the consumed parent must also be authenticated by the CKB adapter.
    pub fn append(
        &self,
        config: &Config,
        policy: &Policy,
        control: &Control,
        schedule: &Schedule,
        snapshot: &Snapshot,
        anchor_since: u64,
    ) -> Result<(Boundary, Schedule)> {
        self.validate()?;
        self.parent.bind(config, policy)?;
        control.bind(config, policy)?;
        self.parent.append_allowed(control, policy)?;
        let timestamp = self.blocks.last().ok_or(Error::Limit)?.timestamp;
        absolute_timestamp(anchor_since, timestamp)?;
        self.replay(config, policy, schedule, snapshot)
    }

    /// Deterministic input replay for the guest. Live Control/backpressure and
    /// since maturity are authenticated by CKB publication, not invented here.
    pub fn replay(
        &self,
        config: &Config,
        policy: &Policy,
        schedule: &Schedule,
        snapshot: &Snapshot,
    ) -> Result<(Boundary, Schedule)> {
        self.validate()?;
        self.parent.bind(config, policy)?;
        schedule.bind_snapshot(snapshot)?;
        if snapshot.config != self.parent.config
            || snapshot.lanes.len() != usize::from(policy.lanes)
            || self.snapshot != schedule.snapshot
        {
            return Err(Error::Domain);
        }
        if schedule.batches >= EPOCH_BATCHES {
            return Err(Error::Duty);
        }
        let users = snapshot.users()?;
        let user_start = usize::from(schedule.user_cursor);
        let user_end = (user_start + DUTY).min(users.len());
        if self.priority != users[user_start..user_end] {
            return Err(Error::Duty);
        }
        if self.parent.processed != snapshot.processed(user_start)?
            || self.parent.deposits.count
                != snapshot
                    .deposit_start
                    .count
                    .checked_add(u64::from(schedule.deposit_cursor))
                    .ok_or(Error::Arithmetic)?
        {
            return Err(Error::Continuity);
        }
        if schedule.batches == 0 {
            if self.parent.deposits != snapshot.deposit_start
                || increment(self.parent.epoch)? != schedule.epoch
                || self.parent.epoch_batches != EPOCH_BATCHES
            {
                return Err(Error::Continuity);
            }
        } else if self.parent.epoch != schedule.epoch
            || self.parent.snapshot != schedule.snapshot
            || self.parent.epoch_batches != schedule.batches
            || self.parent.user_cursor != schedule.user_cursor
            || self.parent.deposit_cursor != schedule.deposit_cursor
        {
            return Err(Error::Continuity);
        }
        let remaining = snapshot.deposit_count() - usize::from(schedule.deposit_cursor);
        if self.deposits.len() != remaining.min(DUTY) {
            return Err(Error::Duty);
        }
        let mut cursor = self.parent.deposits;
        for deposit in &self.deposits {
            if deposit.config != self.parent.config || deposit.recipient == config.bridge {
                return Err(Error::Domain);
            }
            cursor = cursor.follow(deposit)?;
        }
        if cursor.count == snapshot.deposit_end.count && cursor != snapshot.deposit_end {
            return Err(Error::Continuity);
        }
        let timestamp = self.blocks.last().ok_or(Error::Limit)?.timestamp;
        let next_schedule = Schedule {
            config: schedule.config,
            epoch: schedule.epoch,
            snapshot: schedule.snapshot,
            batches: schedule.batches + 1,
            user_cursor: user_end as u8,
            deposit_cursor: schedule.deposit_cursor + self.deposits.len() as u8,
        };
        next_schedule.bind_snapshot(snapshot)?;
        let next = Boundary {
            config: self.parent.config,
            batches: increment(self.parent.batches)?,
            inputs: self.commitment()?,
            blocks: self
                .parent
                .blocks
                .checked_add(self.blocks.len() as u64)
                .ok_or(Error::Arithmetic)?,
            timestamp,
            deposits: cursor,
            processed: snapshot.processed(user_end)?,
            epoch: schedule.epoch,
            snapshot: schedule.snapshot,
            user_cursor: next_schedule.user_cursor,
            deposit_cursor: next_schedule.deposit_cursor,
            epoch_batches: next_schedule.batches,
        };
        self.parent.advances(&next)?;
        Ok((next, next_schedule))
    }
}
impl Wire for NativeBatch {
    const MAGIC: [u8; 8] = *b"T02BAT01";
    const MAX_BYTES: usize = BATCH_BYTES;
    fn validate(&self) -> Result<()> {
        self.parent.validate()?;
        nonzero(&self.snapshot)?;
        if self.priority.len() > DUTY
            || self.deposits.len() > DUTY
            || self.blocks.is_empty()
            || self.blocks.len() > MAX_BLOCKS
        {
            return Err(Error::Limit);
        }
        let mut bytes = 8 + Boundary::MAX_BYTES + 32 + 3;
        for entry in &self.priority {
            entry.message.validate()?;
            if usize::from(entry.lane) >= LANES {
                return Err(Error::Limit);
            }
            bytes += 13 + entry.message.payload.len();
        }
        for deposit in &self.deposits {
            deposit.validate()?;
            bytes += Deposit::MAX_BYTES;
        }
        let mut transactions = 0;
        let mut time = self.parent.timestamp;
        for block in &self.blocks {
            if block.timestamp < time || block.timestamp >= (1 << 56) {
                return Err(Error::Continuity);
            }
            time = block.timestamp;
            if block.transactions.len() > MAX_BLOCK_TRANSACTIONS {
                return Err(Error::Limit);
            }
            transactions += block.transactions.len();
            if transactions > MAX_TRANSACTIONS {
                return Err(Error::Limit);
            }
            bytes += 32;
            for tx in &block.transactions {
                if tx.is_empty() || tx.len() > MAX_TRANSACTION_BYTES {
                    return Err(Error::Limit);
                }
                bytes += 4 + tx.len();
                if bytes > BATCH_BYTES {
                    return Err(Error::Limit);
                }
            }
        }
        if bytes > BATCH_BYTES {
            return Err(Error::Limit);
        }
        let first = &self.blocks[0].transactions;
        if first.len() < self.priority.len()
            || self
                .priority
                .iter()
                .zip(first)
                .any(|(a, b)| a.message.payload != *b)
        {
            return Err(Error::Duty);
        }
        Ok(())
    }
    fn write_fields(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&Boundary::MAGIC);
        self.parent.write_fields(out);
        out.extend_from_slice(&self.snapshot);
        out.push(self.priority.len() as u8);
        for entry in &self.priority {
            out.push(entry.lane);
            entry.message.write(out);
        }
        out.push(self.deposits.len() as u8);
        for deposit in &self.deposits {
            out.extend_from_slice(&Deposit::MAGIC);
            deposit.write_fields(out);
        }
        out.push(self.blocks.len() as u8);
        for block in &self.blocks {
            out.extend_from_slice(&block.timestamp.to_le_bytes());
            out.extend_from_slice(&block.fee_recipient);
            out.extend_from_slice(&(block.transactions.len() as u32).to_le_bytes());
            for tx in &block.transactions {
                put_blob(out, tx);
            }
        }
    }
    fn read_fields(r: &mut Reader<'_>) -> Result<Self> {
        let parent = Boundary::decode(r.take(Boundary::MAX_BYTES)?)?;
        let snapshot = r.array()?;
        let priority_count = usize::from(r.u8()?);
        if priority_count > DUTY {
            return Err(Error::Limit);
        }
        let mut priority = Vec::with_capacity(priority_count);
        for _ in 0..priority_count {
            priority.push(Priority {
                lane: r.u8()?,
                message: Message::read(r)?,
            });
        }
        let deposit_count = usize::from(r.u8()?);
        if deposit_count > DUTY {
            return Err(Error::Limit);
        }
        let mut deposits = Vec::with_capacity(deposit_count);
        for _ in 0..deposit_count {
            deposits.push(Deposit::decode(r.take(Deposit::MAX_BYTES)?)?);
        }
        let count = usize::from(r.u8()?);
        if count == 0 || count > MAX_BLOCKS {
            return Err(Error::Limit);
        }
        let mut blocks = Vec::with_capacity(count);
        let mut total = 0;
        for _ in 0..count {
            let timestamp = r.u64()?;
            let fee_recipient = r.array()?;
            let count = usize::try_from(r.u32()?).map_err(|_| Error::Limit)?;
            if count > MAX_BLOCK_TRANSACTIONS {
                return Err(Error::Limit);
            }
            total += count;
            if total > MAX_TRANSACTIONS {
                return Err(Error::Limit);
            }
            let mut transactions = Vec::with_capacity(count);
            for _ in 0..count {
                transactions.push(r.blob(MAX_TRANSACTION_BYTES)?.to_vec());
            }
            blocks.push(BlockInput {
                timestamp,
                fee_recipient,
                transactions,
            });
        }
        Ok(Self {
            parent,
            snapshot,
            priority,
            deposits,
            blocks,
        })
    }
}
