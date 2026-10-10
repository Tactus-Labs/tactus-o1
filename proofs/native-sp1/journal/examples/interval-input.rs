//! Derive a contiguous proving interval from an existing, replay-checked export.
//! The source's canonical CKB authentication remains an independent prerequisite.
use std::{fs, io::Read};
use tactus_o1_native_proof_journal::{execute, Domain};
fn main() {
    let args: Vec<_> = std::env::args().collect();
    assert_eq!(
        args.len(),
        4,
        "usage: interval-input SOURCE PREFIX END_EXCLUSIVE"
    );
    let mut bytes = Vec::new();
    fs::File::open(&args[1])
        .unwrap()
        .take(64 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .unwrap();
    assert!(bytes.len() <= 64 * 1024 * 1024);
    let mut input: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(input["schema"], "native-proof-input-v2");
    let decode = |v: &serde_json::Value| {
        hex::decode(v.as_str().unwrap().strip_prefix("0x").unwrap()).unwrap()
    };
    let domain = Domain::decode(&decode(&input["domain_hex"])).unwrap();
    let allocation = decode(&input["allocation_hex"]);
    let batches: Vec<_> = input["batches"]
        .as_array()
        .unwrap()
        .iter()
        .map(decode)
        .collect();
    let old = input["prefix_batches"].as_u64().unwrap();
    assert!(old < (batches.len() as u64));
    let mut it = batches.iter();
    let expected = execute(
        domain.clone(),
        &allocation,
        old,
        batches.len() as u64 - old,
        || it.next().unwrap().clone(),
    )
    .unwrap();
    assert_eq!(
        expected.encode().as_slice(),
        decode(&input["expected_journal_hex"])
    );
    let prefix: usize = args[2].parse().unwrap();
    let end: usize = args[3].parse().unwrap();
    assert!(prefix < end && end <= batches.len());
    let mut it = batches.iter();
    let journal = execute(
        domain,
        &allocation,
        prefix as u64,
        (end - prefix) as u64,
        || it.next().unwrap().clone(),
    )
    .unwrap();
    input["batches"].as_array_mut().unwrap().truncate(end);
    input["prefix_batches"] = prefix.into();
    input["expected_journal_hex"] = format!("0x{}", hex::encode(journal.encode())).into();
    input["authenticated_publication"] = false.into();
    println!("{}", serde_json::to_string_pretty(&input).unwrap());
}
