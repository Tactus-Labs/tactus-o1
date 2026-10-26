//! Synthetic execution fixture. Never deploy or report as canonical CKB input.
#[path = "../tests/common/mod.rs"]
mod common;
use tactus_o1_protocol::v02::Wire;
use tactus_v02_proof_journal::{execute, Error};
fn main() {
    let args: Vec<_> = std::env::args().collect();
    assert_eq!(
        args.len(),
        4,
        "usage: fixture-input KEY_JSON PREFIX END_EXCLUSIVE"
    );
    let key: serde_json::Value = serde_json::from_slice(&std::fs::read(&args[1]).unwrap()).unwrap();
    assert_eq!(key["schema"], "tactus-v02-guest-key-v1");
    let key = hex::decode(
        key["guest_verifying_key"]
            .as_str()
            .unwrap()
            .strip_prefix("0x")
            .unwrap(),
    )
    .unwrap()
    .try_into()
    .unwrap();
    let f = common::fixture(key);
    let prefix: u64 = args[2].parse().unwrap();
    let end: usize = args[3].parse().unwrap();
    assert!(end <= f.frames.len() && prefix < (end as u64));
    let frames: Vec<_> = f.frames[..end]
        .iter()
        .map(|f| f.encode().unwrap())
        .collect();
    let mut it = frames.iter();
    let journal = execute(
        f.config.clone(),
        f.policy.clone(),
        &f.allocation,
        prefix,
        end as u64 - prefix,
        || it.next().cloned().ok_or(Error::MissingInput),
    )
    .unwrap();
    let encode = |bytes: Vec<u8>| format!("0x{}", hex::encode(bytes));
    println!("{}",serde_json::to_string_pretty(&serde_json::json!({"schema":"tactus-v02-proof-input-v1",
        "source":"synthetic-execution-fixture", "authenticated_publication":false,
        "config_hex":encode(f.config.encode().unwrap()), "policy_hex":encode(f.policy.encode().unwrap()),
        "allocation_hex":encode(f.allocation),"prefix_batches":prefix,"frames":frames.into_iter().map(encode).collect::<Vec<_>>(),
        "expected_journal_hex":encode(journal.encode().unwrap())})).unwrap());
}
