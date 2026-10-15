//! Deterministic input from the archived, separately audited publication run.
use tactus_o1_native_proof_journal::{execute, Domain};
use tactus_o1_protocol::{batch, native_bridge::Config};
fn main() {
    let prefix: u64 = std::env::args()
        .nth(1)
        .unwrap_or("0".into())
        .parse()
        .unwrap();
    assert!(prefix < 2);
    let deployment: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../specs/evidence/native-publication/0.210.0/deployment.json"
    ))
    .unwrap();
    let execution: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../specs/evidence/native-publication/0.210.0/execution.json"
    ))
    .unwrap();
    let decode = |v: &serde_json::Value| {
        hex::decode(v.as_str().unwrap().strip_prefix("0x").unwrap()).unwrap()
    };
    let domain = Domain {
        config: Config::decode(&decode(&deployment["config"])).unwrap(),
        ordering_type_hash: batch::hash(b"", &decode(&deployment["anchor_script"])),
    };
    let allocation = decode(&deployment["genesis_allocation"]);
    let batches: Vec<_> = execution["cases"][0]["steps"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| decode(&s["wrapper"]))
        .collect();
    let mut iter = batches.iter();
    let expected = execute(domain.clone(), &allocation, prefix, 2 - prefix, || {
        iter.next().unwrap().clone()
    })
    .unwrap();
    println!("{}", serde_json::to_string_pretty(&serde_json::json!({"schema":"native-proof-input-v2", "domain_hex":format!("0x{}", hex::encode(domain.encode())), "allocation_hex":deployment["genesis_allocation"], "batches":batches.iter().map(|b| format!("0x{}",hex::encode(b))).collect::<Vec<_>>(), "prefix_batches":prefix, "expected_journal_hex":format!("0x{}",hex::encode(expected.encode())), "authenticated_publication":false, "source":"specs/evidence/native-publication/0.210.0; authentication must be audited separately"})).unwrap());
}
