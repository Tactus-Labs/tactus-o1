//! Independently replay a canonical CKB proving-input export using the exact
//! execution statement shared with the guest. This does not generate a proof.
use std::{fs::File, io::Read};
use tactus_o1_proof_journal::{execute, Domain};
fn run() -> Result<(), String> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 2 {
        return Err("usage: check-chain-input PROVING_INPUT_JSON".into());
    }
    let mut bytes = Vec::new();
    File::open(&args[1])
        .map_err(err)?
        .take(64 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(err)?;
    if bytes.len() > 64 * 1024 * 1024 {
        return Err("input exceeds local runner limit".into());
    }
    let input: serde_json::Value = serde_json::from_slice(&bytes).map_err(err)?;
    if input["schema"] != 1 {
        return Err("unknown input schema".into());
    }
    let decode = |value: &serde_json::Value| -> Result<Vec<u8>, String> {
        hex::decode(
            value
                .as_str()
                .ok_or("expected hex string")?
                .strip_prefix("0x")
                .ok_or("expected 0x prefix")?,
        )
        .map_err(err)
    };
    let domain = Domain::decode(&decode(&input["domain_hex"])?).map_err(err)?;
    let allocation = decode(&input["allocation_hex"])?;
    let batches = input["batches"]
        .as_array()
        .ok_or("batch list")?
        .iter()
        .map(decode)
        .collect::<Result<Vec<_>, _>>()?;
    let prefix = input["prefix_batches"].as_u64().ok_or("prefix count")?;
    let count = u64::try_from(batches.len()).map_err(err)?;
    let interval = count
        .checked_sub(prefix)
        .filter(|n| *n > 0)
        .ok_or("empty interval or prefix outside input")?;
    let mut iterator = batches.into_iter();
    let journal = execute(domain, &allocation, prefix, interval, || {
        iterator.next().expect("checked batch count")
    })
    .map_err(err)?;
    if decode(&input["expected_journal_hex"])? != journal.encode() {
        return Err("canonical export differs from independently replayed journal".into());
    }
    println!(
        "{}",
        serde_json::json!({"native_journal_match":true,"prefix_batches":prefix,"interval_batches":interval,"next_state_root":hex::encode(journal.next_state_root),"next_header_hash":hex::encode(journal.next_header_hash),"proof_generated":false,"settled":false})
    );
    Ok(())
}
fn err(error: impl std::fmt::Debug) -> String {
    format!("{error:?}")
}
fn main() {
    if let Err(error) = run() {
        eprintln!("check-chain-input: {error}");
        std::process::exit(1);
    }
}
