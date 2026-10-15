//! Bounded A3 epoch scheduling. These pure transitions must be enforced by a
//! mandatory on-chain gate before claiming authenticated sealing or liveness.
use crate::{batch, Hash32};
use alloc::vec::Vec;

pub const MAX_LANES: usize = 4;
pub const MAX_LANE_MESSAGES: usize = 8;
pub const MAX_PAYLOAD_BYTES: usize = 1024;
pub const PRIORITY_PER_BATCH: usize = 4;
pub const BATCHES_PER_EPOCH: u8 = 8;
pub const MAX_LANE_BYTES: usize = 122 + MAX_LANE_MESSAGES * (2 + MAX_PAYLOAD_BYTES);
pub const MAX_SNAPSHOT_BYTES: usize = 49 + MAX_LANES * (4 + MAX_LANE_BYTES);
pub const SCHEDULE_BYTES: usize = 182;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Encoding,
    Limit,
    Domain,
    History,
    Epoch,
    Duty,
    Snapshot,
    Overflow,
    Batch(batch::Error),
}
impl From<batch::Error> for Error {
    fn from(e: batch::Error) -> Self {
        Self::Batch(e)
    }
}
pub fn policy_hash() -> Hash32 {
    let mut bytes =
        b"all-lanes-seal;fixed-batch-quota;round-robin-prefix;bounded-active-queues;no-proof-claim"
            .to_vec();
    for n in [
        MAX_LANES,
        MAX_LANE_MESSAGES,
        MAX_PAYLOAD_BYTES,
        PRIORITY_PER_BATCH,
        usize::from(BATCHES_PER_EPOCH),
        MAX_LANE_BYTES,
        MAX_SNAPSHOT_BYTES,
    ] {
        bytes.extend_from_slice(&(n as u64).to_le_bytes());
    }
    batch::hash(b"tactus/o1/sealed-policy/v1", &bytes)
}
fn initial_root(gate: Hash32, lane: u8) -> Hash32 {
    let mut bytes = gate.to_vec();
    bytes.push(lane);
    batch::hash(b"tactus/o1/lane-genesis/v1", &bytes)
}
fn append_root(root: Hash32, sequence: u64, payload: &[u8]) -> Hash32 {
    let mut bytes = root.to_vec();
    bytes.extend_from_slice(&sequence.to_le_bytes());
    bytes.extend_from_slice(&(payload.len() as u16).to_le_bytes());
    bytes.extend_from_slice(payload);
    batch::hash(b"tactus/o1/lane-append/v1", &bytes)
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Lane {
    pub gate: Hash32,
    pub index: u8,
    pub epoch: u64,
    pub next_sequence: u64,
    pub base_root: Hash32,
    pub root: Hash32,
    pub queue: Vec<Vec<u8>>,
}
impl Lane {
    pub fn genesis(gate: Hash32, index: u8) -> Result<Self, Error> {
        let root = initial_root(gate, index);
        let lane = Self {
            gate,
            index,
            epoch: 0,
            next_sequence: 0,
            base_root: root,
            root,
            queue: Vec::new(),
        };
        lane.validate()?;
        Ok(lane)
    }
    pub fn validate(&self) -> Result<(), Error> {
        if self.gate == [0; 32] || usize::from(self.index) >= MAX_LANES {
            return Err(Error::Domain);
        }
        if self.queue.len() > MAX_LANE_MESSAGES {
            return Err(Error::Limit);
        }
        let first = self
            .next_sequence
            .checked_sub(self.queue.len() as u64)
            .ok_or(Error::History)?;
        let mut root = self.base_root;
        if first == 0 && root != initial_root(self.gate, self.index) {
            return Err(Error::History);
        }
        for (i, payload) in self.queue.iter().enumerate() {
            if payload.is_empty() || payload.len() > MAX_PAYLOAD_BYTES {
                return Err(Error::Limit);
            }
            root = append_root(root, first + i as u64, payload);
        }
        if root != self.root {
            return Err(Error::History);
        }
        Ok(())
    }
    /// Exactly one positive append. No empty update can churn an active head.
    pub fn append(&self, payload: Vec<u8>) -> Result<Self, Error> {
        self.validate()?;
        if self.queue.len() == MAX_LANE_MESSAGES
            || payload.is_empty()
            || payload.len() > MAX_PAYLOAD_BYTES
        {
            return Err(Error::Limit);
        }
        let mut next = self.clone();
        next.next_sequence = self.next_sequence.checked_add(1).ok_or(Error::Overflow)?;
        next.root = append_root(self.root, self.next_sequence, &payload);
        next.queue.push(payload);
        Ok(next)
    }
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        self.validate()?;
        let mut bytes = b"TO1LAN01".to_vec();
        bytes.extend_from_slice(&self.gate);
        bytes.push(self.index);
        bytes.extend_from_slice(&self.epoch.to_le_bytes());
        bytes.extend_from_slice(&self.next_sequence.to_le_bytes());
        bytes.extend_from_slice(&self.base_root);
        bytes.extend_from_slice(&self.root);
        bytes.push(self.queue.len() as u8);
        for item in &self.queue {
            bytes.extend_from_slice(&(item.len() as u16).to_le_bytes());
            bytes.extend_from_slice(item);
        }
        Ok(bytes)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > MAX_LANE_BYTES {
            return Err(Error::Limit);
        }
        let mut r = Reader::new(bytes);
        r.magic(b"TO1LAN01")?;
        let gate = r.array()?;
        let index = r.u8()?;
        let epoch = r.u64()?;
        let next_sequence = r.u64()?;
        let base_root = r.array()?;
        let root = r.array()?;
        let n = usize::from(r.u8()?);
        if n > MAX_LANE_MESSAGES {
            return Err(Error::Limit);
        }
        let mut queue = Vec::with_capacity(n);
        for _ in 0..n {
            let len = usize::from(r.u16()?);
            if len == 0 || len > MAX_PAYLOAD_BYTES {
                return Err(Error::Limit);
            }
            queue.push(r.take(len)?.to_vec());
        }
        r.finish()?;
        let lane = Self {
            gate,
            index,
            epoch,
            next_sequence,
            base_root,
            root,
            queue,
        };
        lane.validate()?;
        Ok(lane)
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QueuedMessage {
    pub lane: u8,
    pub sequence: u64,
    pub payload: Vec<u8>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Snapshot {
    pub gate: Hash32,
    pub epoch: u64,
    pub lanes: Vec<Lane>,
}
impl Snapshot {
    pub fn validate(&self) -> Result<(), Error> {
        if self.gate == [0; 32] || self.lanes.is_empty() || self.lanes.len() > MAX_LANES {
            return Err(Error::Domain);
        }
        for (i, lane) in self.lanes.iter().enumerate() {
            lane.validate()?;
            if lane.gate != self.gate || lane.epoch != self.epoch || usize::from(lane.index) != i {
                return Err(Error::Snapshot);
            }
        }
        Ok(())
    }
    /// Deterministic interleave of lane FIFO prefixes, skipping empty lanes.
    pub fn ordered(&self) -> Result<Vec<QueuedMessage>, Error> {
        self.validate()?;
        let mut messages = Vec::new();
        for slot in 0..MAX_LANE_MESSAGES {
            for lane in &self.lanes {
                if let Some(payload) = lane.queue.get(slot) {
                    messages.push(QueuedMessage {
                        lane: lane.index,
                        sequence: lane.next_sequence - lane.queue.len() as u64 + slot as u64,
                        payload: payload.clone(),
                    });
                }
            }
        }
        Ok(messages)
    }
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        self.validate()?;
        let mut bytes = b"TO1SEA01".to_vec();
        bytes.extend_from_slice(&self.gate);
        bytes.extend_from_slice(&self.epoch.to_le_bytes());
        bytes.push(self.lanes.len() as u8);
        for lane in &self.lanes {
            let data = lane.encode()?;
            bytes.extend_from_slice(&(data.len() as u32).to_le_bytes());
            bytes.extend_from_slice(&data);
        }
        Ok(bytes)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > MAX_SNAPSHOT_BYTES {
            return Err(Error::Limit);
        }
        let mut r = Reader::new(bytes);
        r.magic(b"TO1SEA01")?;
        let gate = r.array()?;
        let epoch = r.u64()?;
        let count = usize::from(r.u8()?);
        if count == 0 || count > MAX_LANES {
            return Err(Error::Limit);
        }
        let mut lanes = Vec::with_capacity(count);
        for _ in 0..count {
            let len = r.u32()? as usize;
            if len > MAX_LANE_BYTES {
                return Err(Error::Limit);
            }
            lanes.push(Lane::decode(r.take(len)?)?);
        }
        r.finish()?;
        let snapshot = Self { gate, epoch, lanes };
        snapshot.validate()?;
        Ok(snapshot)
    }
    pub fn commitment(&self) -> Result<Hash32, Error> {
        Ok(batch::hash(
            b"tactus/o1/sealed-snapshot/v1",
            &self.encode()?,
        ))
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Schedule {
    pub gate: Hash32,
    pub rollup_id: Hash32,
    pub anchor_type_hash: Hash32,
    pub lane_count: u8,
    pub epoch: u64,
    pub batches: u8,
    pub cursor: u16,
    pub snapshot_hash: Hash32,
    pub snapshot_messages: u16,
}
impl Schedule {
    pub fn genesis(
        gate: Hash32,
        rollup_id: Hash32,
        anchor_type_hash: Hash32,
        lane_count: u8,
    ) -> Result<Self, Error> {
        let schedule = Self {
            gate,
            rollup_id,
            anchor_type_hash,
            lane_count,
            epoch: 0,
            batches: 0,
            cursor: 0,
            snapshot_hash: [0; 32],
            snapshot_messages: 0,
        };
        schedule.validate()?;
        Ok(schedule)
    }
    pub fn validate(&self) -> Result<(), Error> {
        if self.gate == [0; 32]
            || self.rollup_id == [0; 32]
            || self.anchor_type_hash == [0; 32]
            || self.lane_count == 0
            || usize::from(self.lane_count) > MAX_LANES
        {
            return Err(Error::Domain);
        }
        if self.batches > BATCHES_PER_EPOCH
            || usize::from(self.snapshot_messages)
                > usize::from(self.lane_count) * MAX_LANE_MESSAGES
        {
            return Err(Error::Limit);
        }
        if usize::from(self.cursor)
            != (usize::from(self.batches) * PRIORITY_PER_BATCH)
                .min(usize::from(self.snapshot_messages))
        {
            return Err(Error::Duty);
        }
        if self.epoch == 0 {
            if self.snapshot_hash != [0; 32] || self.snapshot_messages != 0 {
                return Err(Error::Snapshot);
            }
        } else if self.snapshot_hash == [0; 32] {
            return Err(Error::Snapshot);
        }
        Ok(())
    }
    fn authenticate(&self, snapshot: Option<&Snapshot>) -> Result<Vec<QueuedMessage>, Error> {
        self.validate()?;
        match snapshot {
            None if self.epoch == 0 => Ok(Vec::new()),
            Some(s) if self.epoch > 0 => {
                if s.gate != self.gate
                    || s.epoch.checked_add(1) != Some(self.epoch)
                    || s.lanes.len() != usize::from(self.lane_count)
                    || s.commitment()? != self.snapshot_hash
                {
                    return Err(Error::Snapshot);
                }
                let items = s.ordered()?;
                if items.len() != usize::from(self.snapshot_messages) {
                    return Err(Error::Snapshot);
                }
                Ok(items)
            }
            _ => Err(Error::Snapshot),
        }
    }
    pub fn required(&self, snapshot: Option<&Snapshot>) -> Result<Vec<QueuedMessage>, Error> {
        let items = self.authenticate(snapshot)?;
        if self.batches == BATCHES_PER_EPOCH {
            return Err(Error::Epoch);
        }
        let cursor = usize::from(self.cursor);
        Ok(items[cursor..items.len().min(cursor + PRIORITY_PER_BATCH)].to_vec())
    }
    /// Pure duty check. The CKB adapter must require this transition for EVERY
    /// anchor advance and authenticate the named anchor's input/output types.
    pub fn advance(
        &self,
        snapshot: Option<&Snapshot>,
        bytes: &[u8],
        parent: &batch::AnchorState,
    ) -> Result<(Self, batch::BatchSummary), Error> {
        if parent.rollup_id != self.rollup_id {
            return Err(Error::Domain);
        }
        let required = self.required(snapshot)?;
        let mut matched = 0;
        let summary = batch::validate_and_visit(bytes, parent, |number, _, _, slot, payload| {
            if number == parent.last_block_number + 1
                && slot < required.len()
                && payload == required[slot].payload
            {
                matched += 1;
            }
        })?;
        if matched != required.len() {
            return Err(Error::Duty);
        }
        let mut next = self.clone();
        next.batches += 1;
        next.cursor += required.len() as u16;
        next.validate()?;
        Ok((next, summary))
    }
    /// Consuming all configured lane heads is an on-chain adapter obligation;
    /// arbitrary caller-supplied Lane structs are not authenticated evidence.
    pub fn seal(&self, lanes: &[Lane]) -> Result<(Self, Vec<Lane>, Snapshot), Error> {
        self.validate()?;
        if self.batches != BATCHES_PER_EPOCH || self.cursor != self.snapshot_messages {
            return Err(Error::Epoch);
        }
        if lanes.len() != usize::from(self.lane_count) {
            return Err(Error::Snapshot);
        }
        let snapshot = Snapshot {
            gate: self.gate,
            epoch: self.epoch,
            lanes: lanes.to_vec(),
        };
        snapshot.validate()?;
        let epoch = self.epoch.checked_add(1).ok_or(Error::Overflow)?;
        let active = lanes
            .iter()
            .map(|lane| Lane {
                epoch,
                base_root: lane.root,
                queue: Vec::new(),
                ..lane.clone()
            })
            .collect();
        let next = Self {
            epoch,
            batches: 0,
            cursor: 0,
            snapshot_hash: snapshot.commitment()?,
            snapshot_messages: snapshot.ordered()?.len() as u16,
            ..self.clone()
        };
        next.validate()?;
        Ok((next, active, snapshot))
    }
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        self.validate()?;
        let mut b = b"TO1SCH01".to_vec();
        for hash in [&self.gate, &self.rollup_id, &self.anchor_type_hash] {
            b.extend_from_slice(hash);
        }
        b.push(self.lane_count);
        b.extend_from_slice(&self.epoch.to_le_bytes());
        b.push(self.batches);
        b.extend_from_slice(&self.cursor.to_le_bytes());
        b.extend_from_slice(&self.snapshot_hash);
        b.extend_from_slice(&self.snapshot_messages.to_le_bytes());
        b.extend_from_slice(&policy_hash());
        Ok(b)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != SCHEDULE_BYTES {
            return Err(Error::Encoding);
        }
        let mut r = Reader::new(bytes);
        r.magic(b"TO1SCH01")?;
        let gate = r.array()?;
        let rollup_id = r.array()?;
        let anchor_type_hash = r.array()?;
        let lane_count = r.u8()?;
        let epoch = r.u64()?;
        let batches = r.u8()?;
        let cursor = r.u16()?;
        let snapshot_hash = r.array()?;
        let snapshot_messages = r.u16()?;
        if r.array::<32>()? != policy_hash() {
            return Err(Error::Domain);
        }
        r.finish()?;
        let s = Self {
            gate,
            rollup_id,
            anchor_type_hash,
            lane_count,
            epoch,
            batches,
            cursor,
            snapshot_hash,
            snapshot_messages,
        };
        s.validate()?;
        Ok(s)
    }
}
struct Reader<'a>(&'a [u8]);
impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self(bytes)
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        if n > self.0.len() {
            return Err(Error::Encoding);
        }
        let (left, right) = self.0.split_at(n);
        self.0 = right;
        Ok(left)
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        self.take(N)?.try_into().map_err(|_| Error::Encoding)
    }
    fn magic(&mut self, magic: &[u8; 8]) -> Result<(), Error> {
        if self.take(8)? != magic {
            return Err(Error::Encoding);
        }
        Ok(())
    }
    fn u8(&mut self) -> Result<u8, Error> {
        Ok(self.array::<1>()?[0])
    }
    fn u16(&mut self) -> Result<u16, Error> {
        Ok(u16::from_le_bytes(self.array()?))
    }
    fn u32(&mut self) -> Result<u32, Error> {
        Ok(u32::from_le_bytes(self.array()?))
    }
    fn u64(&mut self) -> Result<u64, Error> {
        Ok(u64::from_le_bytes(self.array()?))
    }
    fn finish(self) -> Result<(), Error> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(Error::Encoding)
        }
    }
}
