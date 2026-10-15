//! Mandatory A3 schedule gate and unique active lanes. Empty args provide an
//! immutable snapshot lock. This program authenticates publication, not proofs.
#![cfg_attr(target_arch = "riscv64", no_std)]
#[cfg(target_arch = "riscv64")]
extern crate alloc;
pub const MAX_INPUTS: usize = 8;
pub const MAX_OUTPUTS: usize = 10;
pub const MAX_DEPS: usize = 10;
pub const MAX_WITNESSES: usize = 12;
pub const MAX_WITNESS_BYTES: usize = 4096;
pub const MAX_SCRIPT_CYCLES: u64 = 20_000_000;

#[cfg(target_arch = "riscv64")]
mod onchain {
    use super::*;
    use alloc::{vec, vec::Vec};
    use ckb_std::{
        ckb_constants::Source,
        ckb_types::{packed::Script, prelude::*},
        error::SysError,
        high_level::*,
        syscalls,
    };
    use tactus_o1_protocol::{
        batch::{self, AnchorState},
        sealed::{self as s, Lane, Schedule, Snapshot},
    };
    ckb_std::default_alloc!();
    ckb_std::entry!(main);
    fn main() -> i8 {
        let result = run();
        if syscalls::current_cycles() > MAX_SCRIPT_CYCLES - 4096 {
            return 13;
        }
        result.map_or_else(|e| e, |()| 0)
    }
    fn count(source: Source, max: usize) -> Result<usize, i8> {
        for i in 0..=max {
            match load_cell_capacity(i, source) {
                Ok(_) => {}
                Err(SysError::IndexOutOfBound) => return Ok(i),
                Err(_) => return Err(2),
            }
        }
        Err(12)
    }
    fn data(index: usize, source: Source, max: usize) -> Result<Vec<u8>, i8> {
        let len = match syscalls::load_cell_data(&mut [], 0, index, source) {
            Ok(n) | Err(SysError::LengthNotEnough(n)) => n,
            Err(_) => return Err(3),
        };
        if len > max {
            return Err(12);
        }
        let mut bytes = vec![0; len];
        syscalls::load_cell_data(&mut bytes, 0, index, source).map_err(|_| 3)?;
        Ok(bytes)
    }
    fn unique(hash: [u8; 32], source: Source, max: usize) -> Result<Option<usize>, i8> {
        let n = count(source, max)?;
        let mut result = None;
        for i in 0..n {
            if load_cell_type_hash(i, source).map_err(|_| 4)? == Some(hash) {
                if result.is_some() {
                    return Err(2);
                }
                result = Some(i);
            }
        }
        Ok(result)
    }
    fn hash(script: &Script) -> [u8; 32] {
        batch::hash(b"", script.as_slice())
    }
    fn role(script: &Script, tag: u8, id: &[u8; 32], index: Option<u8>) -> Script {
        let mut args = vec![tag];
        args.extend_from_slice(id);
        if let Some(index) = index {
            args.push(index);
        }
        script.clone().as_builder().args(args.pack()).build()
    }
    fn lock(script: &Script, type_hash: [u8; 32]) -> Script {
        role(script, 0, &type_hash, None)
    }
    fn immutable(script: &Script) -> Script {
        script
            .clone()
            .as_builder()
            .args(Vec::<u8>::new().pack())
            .build()
    }
    fn lane(index: usize, source: Source) -> Result<Lane, i8> {
        Lane::decode(&data(index, source, s::MAX_LANE_BYTES)?).map_err(|_| 3)
    }
    fn schedule(index: usize, source: Source) -> Result<Schedule, i8> {
        Schedule::decode(&data(index, source, s::SCHEDULE_BYTES)?).map_err(|_| 3)
    }
    fn map(error: s::Error) -> i8 {
        match error {
            s::Error::Epoch => 14,
            s::Error::Duty => 15,
            s::Error::Snapshot => 9,
            s::Error::Limit => 12,
            _ => 16,
        }
    }
    fn witness(index: usize, source: Source) -> Result<Vec<u8>, i8> {
        let w = load_witness_args(index, source).map_err(|_| 11)?;
        Ok(w.input_type().to_opt().ok_or(11)?.raw_data().to_vec())
    }
    fn output_lock(index: usize, source: Source, expected: &Script) -> Result<(), i8> {
        if load_cell_lock(index, source).map_err(|_| 5)? != *expected {
            return Err(5);
        }
        Ok(())
    }
    fn snapshot(script: &Script, expected: &Schedule) -> Result<Option<Snapshot>, i8> {
        if expected.epoch == 0 {
            return Ok(None);
        }
        let n = count(Source::CellDep, MAX_DEPS)?;
        for i in 0..n {
            // Skip unrelated code/dependency-group members without allocating them.
            let mut magic = [0; 8];
            let len = match syscalls::load_cell_data(&mut magic, 0, i, Source::CellDep) {
                Ok(n) | Err(SysError::LengthNotEnough(n)) => n,
                Err(_) => return Err(9),
            };
            if !(49..=s::MAX_SNAPSHOT_BYTES).contains(&len) || &magic != b"TO1SEA01" {
                continue;
            }
            let bytes = data(i, Source::CellDep, s::MAX_SNAPSHOT_BYTES)?;
            if batch::hash(b"tactus/o1/sealed-snapshot/v1", &bytes) != expected.snapshot_hash {
                continue;
            }
            output_lock(i, Source::CellDep, &immutable(script))?;
            if load_cell_type_hash(i, Source::CellDep)
                .map_err(|_| 9)?
                .is_some()
            {
                return Err(9);
            }
            return Snapshot::decode(&bytes).map(Some).map_err(|_| 9);
        }
        Err(9)
    }
    fn run() -> Result<(), i8> {
        let script = load_script().map_err(|_| 1)?;
        let args = script.args().raw_data();
        if args.len() != 33 && args.len() != 34 {
            return Err(1);
        }
        let id: [u8; 32] = args[1..33].try_into().map_err(|_| 1)?;
        let inputs = count(Source::Input, MAX_INPUTS)?;
        if args[0] == 0 && args.len() == 33 {
            // The anchor's lock deliberately requires a DIFFERENT type: Schedule.
            if (0..inputs).any(|i| load_cell_type_hash(i, Source::Input) == Ok(Some(id))) {
                return Ok(());
            }
            return Err(7);
        }
        let outputs = count(Source::Output, MAX_OUTPUTS)?;
        count(Source::CellDep, MAX_DEPS)?;
        let mut burden = 0usize;
        for i in 0..=MAX_WITNESSES {
            let n = match syscalls::load_witness(&mut [], 0, i, Source::Input) {
                Ok(n) | Err(SysError::LengthNotEnough(n)) => n,
                Err(SysError::IndexOutOfBound) => break,
                Err(_) => return Err(11),
            };
            if i == MAX_WITNESSES {
                return Err(12);
            }
            burden = burden.checked_add(8 + n).ok_or(12)?;
        }
        if burden > MAX_WITNESS_BYTES {
            return Err(12);
        }
        let group_inputs = count(Source::GroupInput, 1)?;
        if count(Source::GroupOutput, 1)? != 1 {
            return Err(2);
        }
        let type_hash = load_script_hash().map_err(|_| 4)?;
        let expected_lock = lock(&script, type_hash);
        output_lock(0, Source::GroupOutput, &expected_lock)?;
        if group_inputs == 1 {
            output_lock(0, Source::GroupInput, &expected_lock)?;
            if load_cell_capacity(0, Source::GroupInput).map_err(|_| 5)?
                != load_cell_capacity(0, Source::GroupOutput).map_err(|_| 5)?
            {
                return Err(5);
            }
        }
        match (args[0], args.len()) {
            (1, 34) => check_lane(&script, id, args[33], group_inputs),
            (2, 33) => check_schedule(&script, id, group_inputs, outputs),
            _ => Err(1),
        }
    }
    fn check_lane(script: &Script, id: [u8; 32], index: u8, inputs: usize) -> Result<(), i8> {
        let next = lane(0, Source::GroupOutput)?;
        if next.gate != id || next.index != index {
            return Err(4);
        }
        let gate_hash = hash(&role(script, 2, &id, None));
        if inputs == 0 {
            if unique(gate_hash, Source::Input, MAX_INPUTS)?.is_some() {
                return Err(6);
            }
            let gate_index = unique(gate_hash, Source::Output, MAX_OUTPUTS)?.ok_or(7)?;
            let gate = schedule(gate_index, Source::Output)?;
            if gate.gate != id
                || index >= gate.lane_count
                || next != Lane::genesis(id, index).map_err(map)?
            {
                return Err(6);
            }
            let required = (8 + script.as_slice().len() - 20
                + lock(script, hash(script)).as_slice().len()
                - 20
                + s::MAX_LANE_BYTES) as u64
                * 100_000_000;
            if load_cell_capacity(0, Source::GroupOutput).map_err(|_| 5)? < required {
                return Err(5);
            }
            return Ok(());
        }
        let old = lane(0, Source::GroupInput)?;
        if old.gate != id || old.index != index {
            return Err(4);
        }
        if next.epoch == old.epoch {
            let payload = next.queue.last().ok_or(16)?.clone();
            if old.append(payload).map_err(map)? != next {
                return Err(16);
            }
            return Ok(());
        }
        // Only a genuine Schedule seal can authorize clearing an active queue.
        let gi = unique(gate_hash, Source::Input, MAX_INPUTS)?.ok_or(7)?;
        let go = unique(gate_hash, Source::Output, MAX_OUTPUTS)?.ok_or(7)?;
        let prior = schedule(gi, Source::Input)?;
        let successor = schedule(go, Source::Output)?;
        if prior.epoch != old.epoch
            || old.epoch.checked_add(1) != Some(next.epoch)
            || successor.epoch != next.epoch
        {
            return Err(16);
        }
        // The Schedule type independently checks ALL authentic lane inputs and
        // their exact empty successors, not just this lane's claimed epoch.
        Ok(())
    }
    fn check_schedule(
        script: &Script,
        id: [u8; 32],
        inputs: usize,
        outputs: usize,
    ) -> Result<(), i8> {
        let next = schedule(0, Source::GroupOutput)?;
        if next.gate != id {
            return Err(4);
        }
        let gate_hash = hash(script);
        if inputs == 0 {
            if next
                != Schedule::genesis(id, next.rollup_id, next.anchor_type_hash, next.lane_count)
                    .map_err(map)?
            {
                return Err(6);
            }
            let index = unique(gate_hash, Source::Output, outputs)?.ok_or(4)?;
            let input = load_input(0, Source::Input).map_err(|_| 4)?;
            let mut seed = input.as_slice().to_vec();
            seed.extend_from_slice(&(index as u64).to_le_bytes());
            if batch::hash(b"", &seed) != id {
                return Err(4);
            }
            if unique(next.anchor_type_hash, Source::Input, MAX_INPUTS)?.is_some() {
                return Err(6);
            }
            let anchor_index =
                unique(next.anchor_type_hash, Source::Output, MAX_OUTPUTS)?.ok_or(10)?;
            let anchor =
                AnchorState::decode(&data(anchor_index, Source::Output, batch::ANCHOR_LEN)?)
                    .map_err(|_| 10)?;
            anchor.validate_genesis().map_err(|_| 6)?;
            if anchor.rollup_id != next.rollup_id {
                return Err(10);
            }
            output_lock(anchor_index, Source::Output, &lock(script, gate_hash))?;
            for i in 0..next.lane_count {
                let lane_hash = hash(&role(script, 1, &id, Some(i)));
                if unique(lane_hash, Source::Input, MAX_INPUTS)?.is_some() {
                    return Err(6);
                }
                let oi = unique(lane_hash, Source::Output, MAX_OUTPUTS)?.ok_or(8)?;
                if lane(oi, Source::Output)? != Lane::genesis(id, i).map_err(map)? {
                    return Err(6);
                }
            }
            return Ok(());
        }
        let old = schedule(0, Source::GroupInput)?;
        if old.gate != id {
            return Err(4);
        }
        let operation = witness(0, Source::GroupInput)?;
        if operation == [1] {
            let ai = unique(old.anchor_type_hash, Source::Input, MAX_INPUTS)?.ok_or(10)?;
            let ao = unique(old.anchor_type_hash, Source::Output, MAX_OUTPUTS)?.ok_or(10)?;
            output_lock(ai, Source::Input, &lock(script, gate_hash))?;
            output_lock(ao, Source::Output, &lock(script, gate_hash))?;
            let parent = AnchorState::decode(&data(ai, Source::Input, batch::ANCHOR_LEN)?)
                .map_err(|_| 10)?;
            let successor = AnchorState::decode(&data(ao, Source::Output, batch::ANCHOR_LEN)?)
                .map_err(|_| 10)?;
            let pointer = witness(ai, Source::Input)?;
            let data_index =
                u32::from_le_bytes(pointer.as_slice().try_into().map_err(|_| 11)?) as usize;
            let bytes = data(data_index, Source::Output, batch::MAX_BATCH_BYTES)?;
            let snap = snapshot(script, &old)?;
            let (expected, summary) = old.advance(snap.as_ref(), &bytes, &parent).map_err(map)?;
            if next != expected || successor != summary.next {
                return Err(16);
            }
            return Ok(());
        }
        if operation.len() != 5 || operation[0] != 0 {
            return Err(11);
        }
        // Sealing cannot disguise an anchor advance without a prefix duty.
        if unique(old.anchor_type_hash, Source::Input, MAX_INPUTS)?.is_some()
            || unique(old.anchor_type_hash, Source::Output, MAX_OUTPUTS)?.is_some()
        {
            return Err(10);
        }
        let mut lanes = Vec::new();
        let mut output_indices = Vec::new();
        for i in 0..old.lane_count {
            let lane_hash = hash(&role(script, 1, &id, Some(i)));
            let input = unique(lane_hash, Source::Input, MAX_INPUTS)?.ok_or(8)?;
            let output = unique(lane_hash, Source::Output, MAX_OUTPUTS)?.ok_or(8)?;
            lanes.push(lane(input, Source::Input)?);
            output_indices.push(output);
        }
        let (expected, active, sealed) = old.seal(&lanes).map_err(map)?;
        if next != expected {
            return Err(16);
        }
        for (lane_state, index) in active.iter().zip(output_indices) {
            if lane(index, Source::Output)? != *lane_state {
                return Err(16);
            }
        }
        let index = u32::from_le_bytes(operation[1..].try_into().map_err(|_| 11)?) as usize;
        output_lock(index, Source::Output, &immutable(script))?;
        if load_cell_type_hash(index, Source::Output)
            .map_err(|_| 9)?
            .is_some()
            || data(index, Source::Output, s::MAX_SNAPSHOT_BYTES)?
                != sealed.encode().map_err(map)?
        {
            return Err(9);
        }
        Ok(())
    }
}
