//! A2 individual obligations, with protocol-controlled locks. A challenge marker
//! alone cannot force global inclusion. Included records have no spend/proven path.
#![cfg_attr(target_arch = "riscv64", no_std)]
#[cfg(target_arch = "riscv64")]
extern crate alloc;
#[cfg(target_arch = "riscv64")]
mod onchain {
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
        priority::{self as p, Message, Stage},
    };
    ckb_std::default_alloc!();
    ckb_std::entry!(main);
    fn main() -> i8 {
        let result = run();
        if syscalls::current_cycles() > p::MAX_PRIORITY_SCRIPT_CYCLES - 4096 {
            return 14;
        }
        result.map_or_else(|e| e, |()| 0)
    }
    fn data(index: usize, source: Source, limit: usize) -> Result<Vec<u8>, i8> {
        let len = match syscalls::load_cell_data(&mut [], 0, index, source) {
            Ok(n) | Err(SysError::LengthNotEnough(n)) => n,
            Err(_) => return Err(3),
        };
        if len > limit {
            return Err(12);
        }
        let mut bytes = vec![0; len];
        syscalls::load_cell_data(&mut bytes, 0, index, source).map_err(|_| 3)?;
        Ok(bytes)
    }
    fn message(index: usize, source: Source) -> Result<Message, i8> {
        Message::decode(&data(index, source, p::MAX_MESSAGE_BYTES)?).map_err(|_| 3)
    }
    fn count(source: Source, limit: usize) -> Result<usize, i8> {
        for index in 0..=limit {
            match load_cell_capacity(index, source) {
                Ok(_) => {}
                Err(SysError::IndexOutOfBound) => return Ok(index),
                Err(_) => return Err(2),
            }
        }
        Err(12)
    }
    fn same_program(a: &Script, b: &Script) -> bool {
        a.code_hash() == b.code_hash()
            && a.hash_type() == b.hash_type()
            && a.args().raw_data().first() == Some(&0)
    }
    fn run() -> Result<(), i8> {
        let script = load_script().map_err(|_| 1)?;
        let args = script.args().raw_data();
        if args.len() != 33 {
            return Err(1);
        }
        let identity: [u8; 32] = args[1..].try_into().map_err(|_| 1)?;
        if args[0] == 1 {
            let n = count(Source::GroupInput, p::MAX_PRIORITY_INPUTS)?;
            if n == 0 {
                return Err(2);
            }
            for i in 0..n {
                if load_cell_type_hash(i, Source::GroupInput).map_err(|_| 4)? != Some(identity) {
                    return Err(4);
                }
            }
            return Ok(());
        }
        if args[0] != 0 {
            return Err(1);
        }
        let inputs = count(Source::Input, p::MAX_INPUTS)?;
        let outputs = count(Source::Output, p::MAX_OUTPUTS)?;
        if count(Source::GroupInput, 1)? > 1 || count(Source::GroupOutput, 1)? != 1 {
            return Err(2);
        }
        let current_hash = load_script_hash().map_err(|_| 4)?;
        let mut lock_args = vec![1];
        lock_args.extend_from_slice(&current_hash);
        let expected_lock = script.clone().as_builder().args(lock_args.pack()).build();
        if load_cell_lock(0, Source::GroupOutput).map_err(|_| 5)? != expected_lock {
            return Err(5);
        }
        let next = message(0, Source::GroupOutput)?;
        if next.id != identity {
            return Err(4);
        }
        let group_inputs = count(Source::GroupInput, 1)?;
        if group_inputs == 0 {
            if next.stage != Stage::Admitted {
                return Err(6);
            }
            let output_index = (0..outputs)
                .find(|i| load_cell_type_hash(*i, Source::Output) == Ok(Some(current_hash)))
                .ok_or(4)?;
            let input = load_input(0, Source::Input).map_err(|_| 4)?;
            let mut seed = input.as_slice().to_vec();
            seed.extend_from_slice(&(output_index as u64).to_le_bytes());
            if batch::hash(b"", &seed) != identity {
                return Err(4);
            }
            let mut creations = 0;
            for i in 0..outputs {
                if load_cell_type(i, Source::Output)
                    .map_err(|_| 4)?
                    .is_some_and(|s| same_program(&s, &script))
                {
                    creations += 1;
                }
            }
            if creations > p::MAX_PRIORITY_INPUTS {
                return Err(12);
            }
            return Ok(());
        }
        if load_cell_capacity(0, Source::GroupInput).map_err(|_| 5)?
            != load_cell_capacity(0, Source::GroupOutput).map_err(|_| 5)?
            || load_cell_lock(0, Source::GroupInput).map_err(|_| 5)? != expected_lock
        {
            return Err(5);
        }
        let prior = message(0, Source::GroupInput)?;
        if prior.id != identity {
            return Err(4);
        }
        if prior.stage == Stage::Included {
            return Err(6);
        }
        if next.stage == Stage::Challenged {
            if prior.challenge().map_err(|_| 6)? != next {
                return Err(6);
            }
            if load_input_since(0, Source::GroupInput).map_err(|_| 7)? != p::CHALLENGE_SINCE {
                return Err(7);
            }
            return Ok(());
        }
        if next.stage != Stage::Included {
            return Err(6);
        }
        let anchor_inputs: Vec<_> = (0..inputs)
            .filter(|i| load_cell_type_hash(*i, Source::Input) == Ok(Some(prior.anchor_type_hash)))
            .collect();
        let anchor_outputs: Vec<_> = (0..outputs)
            .filter(|i| load_cell_type_hash(*i, Source::Output) == Ok(Some(prior.anchor_type_hash)))
            .collect();
        if anchor_inputs.len() != 1 || anchor_outputs.len() != 1 {
            return Err(8);
        }
        let anchor_index = anchor_inputs[0];
        let old = AnchorState::decode(&data(anchor_index, Source::Input, batch::ANCHOR_LEN)?)
            .map_err(|_| 8)?;
        let new = AnchorState::decode(&data(anchor_outputs[0], Source::Output, batch::ANCHOR_LEN)?)
            .map_err(|_| 8)?;
        // Bound all witnesses before WitnessArgs allocates the anchor witness.
        let mut burden = 0usize;
        for i in 0..=p::MAX_WITNESSES {
            let length = match syscalls::load_witness(&mut [], 0, i, Source::Input) {
                Ok(n) | Err(SysError::LengthNotEnough(n)) => n,
                Err(SysError::IndexOutOfBound) => break,
                Err(_) => return Err(13),
            };
            if i == p::MAX_WITNESSES {
                return Err(12);
            }
            burden = burden.checked_add(8 + length).ok_or(12)?;
        }
        if burden > p::MAX_PRIORITY_BYTES {
            return Err(12);
        }
        let witness = load_witness_args(anchor_index, Source::Input).map_err(|_| 9)?;
        let pointer = witness.input_type().to_opt().ok_or(9)?.raw_data();
        let data_index = u32::from_le_bytes(pointer.as_ref().try_into().map_err(|_| 9)?) as usize;
        let bytes = data(data_index, Source::Output, batch::MAX_BATCH_BYTES)?;
        let summary = batch::validate_batch(&bytes, &old).map_err(|_| 9)?;
        if summary.next != new {
            return Err(9);
        }
        // All priority inputs from this program are one bounded, input-ordered
        // prefix of the first EVM block, regardless of their individual TypeIDs.
        let mut priority = Vec::new();
        let mut priority_types = Vec::new();
        let mut own_slot = None;
        for i in 0..inputs {
            if let Some(kind) = load_cell_type(i, Source::Input).map_err(|_| 4)? {
                if same_program(&kind, &script) {
                    let item = message(i, Source::Input)?;
                    if item.stage == Stage::Included
                        || item.anchor_type_hash != prior.anchor_type_hash
                        || item.rollup_id != prior.rollup_id
                    {
                        return Err(10);
                    }
                    if item.id == identity {
                        own_slot = Some(priority.len());
                    }
                    burden = burden
                        .checked_add(
                            44 + load_cell(i, Source::Input).map_err(|_| 3)?.as_slice().len()
                                + item.encode().map_err(|_| 3)?.len(),
                        )
                        .ok_or(12)?;
                    priority_types.push(
                        load_cell_type_hash(i, Source::Input)
                            .map_err(|_| 4)?
                            .ok_or(4)?,
                    );
                    priority.push(item);
                }
            }
        }
        if priority.is_empty() || priority.len() > p::MAX_PRIORITY_INPUTS {
            return Err(12);
        }
        if burden > p::MAX_PRIORITY_BYTES {
            return Err(12);
        }
        for (position, item) in priority.iter().enumerate() {
            let matching: Vec<_> = (0..outputs)
                .filter(|i| {
                    load_cell_type_hash(*i, Source::Output) == Ok(Some(priority_types[position]))
                })
                .collect();
            if matching.len() != 1
                || message(matching[0], Source::Output)?
                    != item.include(&old, &new, position).map_err(|_| 10)?
            {
                return Err(10);
            }
        }
        let slot = own_slot.ok_or(10)?;
        if prior.include(&old, &new, slot).map_err(|_| 10)? != next {
            return Err(10);
        }
        let mut matched = 0;
        batch::validate_and_visit(&bytes, &old, |number, _, _, index, payload| {
            if number == old.last_block_number + 1
                && index < priority.len()
                && payload == priority[index].payload
            {
                matched += 1;
            }
        })
        .map_err(|_| 9)?;
        if matched != priority.len() {
            return Err(11);
        }
        Ok(())
    }
}
