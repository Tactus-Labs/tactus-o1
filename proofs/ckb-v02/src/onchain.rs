use crate::adapter::{Cell, Transaction, MAX_CELLS};
use alloc::{vec, vec::Vec};
use ckb_std::{
    ckb_constants::Source,
    ckb_types::{packed, prelude::*},
    error::SysError,
    high_level::*,
    syscalls,
};
use tactus_o1_protocol::{
    genesis,
    v02::{hash, Error, Result},
};

// Resource qualification must measure the full transaction, including all type
// groups. This is a development heap ceiling, not a qualification certificate.
ckb_std::default_alloc!(4 * 1024, 3 * 1024 * 1024, 64);
ckb_std::entry!(entrypoint);
fn entrypoint() -> i8 {
    run().map_or_else(|e| e as i8, |()| 0)
}

fn bounded_load(
    limit: usize,
    mut load: impl FnMut(&mut [u8]) -> core::result::Result<usize, SysError>,
) -> Result<Vec<u8>> {
    let size = match load(&mut []) {
        Ok(size) | Err(SysError::LengthNotEnough(size)) => size,
        _ => return Err(Error::Encoding),
    };
    if size > limit {
        return Err(Error::Resource);
    }
    let mut bytes = vec![0; size];
    if load(&mut bytes) != Ok(size) {
        return Err(Error::Encoding);
    }
    Ok(bytes)
}
fn count(source: Source) -> Result<usize> {
    for index in 0..=MAX_CELLS {
        match load_cell_capacity(index, source) {
            Err(SysError::IndexOutOfBound) => return Ok(index),
            Ok(_) if index < MAX_CELLS => {}
            _ => return Err(Error::Resource),
        }
    }
    Err(Error::Resource)
}
fn cell(index: usize, source: Source, outpoint: [u8; 36], script: &packed::Script) -> Result<Cell> {
    let output = load_cell(index, source).map_err(|_| Error::Encoding)?;
    let type_script = output.type_().to_opt();
    let args = script.args().raw_data();
    let is_protocol = type_script.as_ref().is_some_and(|ty| {
        let target = ty.args().raw_data();
        ty.code_hash() == script.code_hash()
            && target.len() >= 32
            && args.len() >= 32
            && target[..32] == args[..32]
    });
    // Code/dependency-group contents are not protocol state and can be large.
    let needs_data = is_protocol || source == Source::Output;
    let data = if needs_data {
        bounded_load(genesis::MAX_BYTES, |bytes| {
            syscalls::load_cell_data(bytes, 0, index, source)
        })?
    } else {
        Vec::new()
    };
    let since = if source == Source::Input {
        load_input_since(index, source).map_err(|_| Error::Encoding)?
    } else {
        0
    };
    Ok(Cell {
        capacity: output.capacity().unpack(),
        occupied: load_cell_occupied_capacity(index, source).map_err(|_| Error::Encoding)?,
        lock: output.lock(),
        type_script,
        data,
        outpoint,
        since,
    })
}
fn run() -> Result<()> {
    let script = load_script().map_err(|_| Error::Identity)?;
    let bytes = bounded_load(1024 * 1024, |buffer| syscalls::load_transaction(buffer, 0))?;
    let tx = packed::Transaction::from_slice(&bytes).map_err(|_| Error::Encoding)?;
    drop(bytes);
    let deps = tx.raw().cell_deps();
    // Explicit outpoints are required for receipts and signed frozen identities.
    // Builders expand standard lock dep groups into direct code/data deps.
    if deps
        .clone()
        .into_iter()
        .any(|dep| dep.dep_type() != 0u8.into())
    {
        return Err(Error::Resource);
    }
    let input_count = count(Source::Input)?;
    let output_count = count(Source::Output)?;
    let dep_count = count(Source::CellDep)?;
    if dep_count != deps.len() || input_count == 0 {
        return Err(Error::Identity);
    }
    let witness = tx.witnesses().get(0).ok_or(Error::Encoding)?.raw_data();
    let witness = packed::WitnessArgs::from_slice(&witness).map_err(|_| Error::Encoding)?;
    let operation = witness
        .output_type()
        .to_opt()
        .ok_or(Error::Encoding)?
        .raw_data()
        .to_vec();
    let mut inputs = Vec::with_capacity(input_count);
    for index in 0..input_count {
        let point = load_input_out_point(index, Source::Input).map_err(|_| Error::Identity)?;
        inputs.push(cell(
            index,
            Source::Input,
            point.as_slice().try_into().map_err(|_| Error::Identity)?,
            &script,
        )?);
    }
    let outputs = (0..output_count)
        .map(|index| cell(index, Source::Output, [0; 36], &script))
        .collect::<Result<Vec<_>>>()?;
    let mut resolved = Vec::with_capacity(dep_count);
    for (index, dep) in deps.into_iter().enumerate() {
        resolved.push(cell(
            index,
            Source::CellDep,
            dep.out_point()
                .as_slice()
                .try_into()
                .map_err(|_| Error::Identity)?,
            &script,
        )?);
    }
    let mut genesis_hash = None;
    if tx.raw().header_deps().len() > MAX_CELLS {
        return Err(Error::Resource);
    }
    for index in 0..tx.raw().header_deps().len() {
        let header = load_header(index, Source::HeaderDep).map_err(|_| Error::Identity)?;
        let number: u64 = header.raw().number().unpack();
        if number == 0 && genesis_hash.replace(hash(b"", header.as_slice())).is_some() {
            return Err(Error::Identity);
        }
    }
    let first_input = load_input(0, Source::Input)
        .map_err(|_| Error::Identity)?
        .as_slice()
        .try_into()
        .map_err(|_| Error::Identity)?;
    drop(tx);
    Transaction {
        script,
        inputs,
        outputs,
        deps: resolved,
        first_input,
        genesis_hash,
        operation,
    }
    .verify()
}
