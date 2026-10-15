//! Build a sparse witness from complete replay, then check the pruned witness.
//! Full history is retained only for the independent HOST oracle; guest stdin
//! contains the sparse boundary/witness and the requested new batches only.
use std::{
    fs,
    io::{Read, Write},
};
use tactus_o1_execution::{checkpoint::Boundary, Executor, Genesis};
use tactus_o1_proof_journal::{execute, Domain};
use tactus_o1_sparse_journal::{self as sparse, SparseJournal};
use tactus_o1_sparse_state::database::SparseDb;

fn main() {
    if let Err(e) = run() {
        eprintln!("{e}");
        std::process::exit(1);
    }
}
fn err(e: impl std::fmt::Debug) -> String {
    format!("{e:?}")
}
fn run() -> Result<(), String> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 5 {
        return Err("usage: prepare-sparse INPUT_JSON START_BATCH COUNT OUTPUT_JSON".into());
    }
    let mut raw = Vec::new();
    fs::File::open(&args[1])
        .map_err(err)?
        .take(64 * 1024 * 1024 + 1)
        .read_to_end(&mut raw)
        .map_err(err)?;
    if raw.len() > 64 * 1024 * 1024 {
        return Err("input too large".into());
    }
    let input: serde_json::Value = serde_json::from_slice(&raw).map_err(err)?;
    if input["schema"] != 1 {
        return Err("unsupported source schema".into());
    }
    let decode = |v: &serde_json::Value| -> Result<Vec<u8>, String> {
        hex::decode(
            v.as_str()
                .ok_or("expected hex string")?
                .strip_prefix("0x")
                .ok_or("expected 0x prefix")?,
        )
        .map_err(err)
    };
    let domain = Domain::decode(&decode(&input["domain_hex"])?).map_err(err)?;
    let allocation = decode(&input["allocation_hex"])?;
    let start: usize = args[2].parse().map_err(err)?;
    let count: usize = args[3].parse().map_err(err)?;
    let end = start.checked_add(count).ok_or("range overflow")?;
    let batches: Vec<_> = input["batches"]
        .as_array()
        .ok_or("missing batches")?
        .iter()
        .map(decode)
        .collect::<Result<_, _>>()?;
    if count == 0 || end > batches.len() {
        return Err("empty or out of bounds interval".into());
    }
    let genesis = Genesis::from_allocation(domain.rollup_id.into(), domain.chain_id, &allocation)
        .map_err(err)?;
    let mut full = Executor::new(&genesis).map_err(err)?;
    let mut headers = vec![full.head().clone()];
    for bytes in &batches[..start] {
        headers.extend(
            full.apply_batch(bytes)
                .map_err(err)?
                .into_iter()
                .map(|b| b.header),
        );
        if headers.len() > 256 {
            headers.drain(..headers.len() - 256);
        }
    }
    let boundary = Boundary {
        anchor: *full.anchor(),
        state_root: full.state_root(),
        header_hash: full.head_hash(),
    };
    let db = SparseDb::from_complete(&full, headers.clone()).map_err(err)?;
    let mut discovery = full.clone().with_backend(db).map_err(err)?;
    for bytes in &batches[start..end] {
        if discovery.apply_batch(bytes).map_err(err)? != full.apply_batch(bytes).map_err(err)? {
            return Err("sparse discovery differs from complete replay".into());
        }
    }
    let witness = discovery.backend().required_witness(headers);
    let witness_bytes = witness.encode().map_err(err)?;
    let mut all = batches[..end].iter();
    let expected = SparseJournal {
        transition: execute(
            domain.clone(),
            &allocation,
            start as u64,
            count as u64,
            || all.next().unwrap().clone(),
        )
        .map_err(err)?,
    };
    if input["prefix_batches"].as_u64() == Some(start as u64) && end == batches.len() {
        let exported = decode(&input["expected_journal_hex"])?;
        if exported != expected.encode() && exported != expected.transition.encode() {
            return Err("source export does not match independently replayed interval".into());
        }
    }
    let mut next = batches[start..end].iter();
    let checked = if start == 0 {
        sparse::execute_genesis(domain, &allocation, &witness_bytes, count as u64, || {
            next.next().unwrap().clone()
        })
    } else {
        sparse::execute_continuation(
            domain,
            expected.transition.allocation_commitment,
            &boundary,
            &witness_bytes,
            count as u64,
            || next.next().unwrap().clone(),
        )
    }
    .map_err(err)?;
    if checked != expected {
        return Err("pruned witness differs from complete replay".into());
    }
    let mut output = input;
    output["schema"] = 1.into();
    output["prefix_batches"] = (start as u64).into();
    output["batches"] = serde_json::json!(batches[..end]
        .iter()
        .map(|b| format!("0x{}", hex::encode(b)))
        .collect::<Vec<_>>());
    output["expected_journal_hex"] = format!("0x{}", hex::encode(expected.encode())).into();
    output["sparse_witness"] = serde_json::to_value(witness).map_err(err)?;
    output["sparse_profile"] = format!("0x{}", hex::encode(sparse::profile_id())).into();
    output["preparation"] = serde_json::json!({"full_replay_matches":true,"pruned_witness_matches":true,
        "witness_encoding":"TO1WIT01","witness_bytes":witness_bytes.len(),"guest_prefix_batches":0,"host_prefix_batches":start,
        "deployment_authorized":false,"native_custody":false});
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&args[4])
        .map_err(err)?;
    file.write_all(&serde_json::to_vec_pretty(&output).map_err(err)?)
        .map_err(err)?;
    file.write_all(b"\n").map_err(err)?;
    println!("Prepared {} new batches with {} witness bytes; {} historical batches used only by host oracle",count,witness_bytes.len(),start);
    Ok(())
}
