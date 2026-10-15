//! Shared bounded laboratory proof loading, Tip construction and cold recovery.
//! Artifact metadata never substitutes for on-chain cryptographic verification.
use crate::{
    lab::{self, Lab},
    molecule, rpc,
    tx::{self, CellOutPoint, OutSpec, TX_FEE},
};
use serde_json::{json, Value};
use std::{fs::File, io::Read, path::Path};
use tactus_o1_ordering_script::ckb_blake2b;
use tactus_o1_protocol::batch::AnchorState;

pub fn tip_data(
    anchor: &AnchorState,
    initialized: bool,
    state: &[u8; 32],
    header: &[u8; 32],
) -> Vec<u8> {
    let mut bytes = b"TO1TIP01".to_vec();
    bytes.push(u8::from(initialized));
    bytes.extend_from_slice(&[0; 7]);
    bytes.extend_from_slice(&anchor.encode());
    bytes.extend_from_slice(state);
    bytes.extend_from_slice(header);
    bytes
}
pub fn tip_output(lab: &Lab, script: &[u8], data: &[u8]) -> OutSpec {
    let lock = molecule::script(&ckb_blake2b(&lab.lock_elf), 2, &ckb_blake2b(script));
    OutSpec {
        capacity: OutSpec::required_capacity(&lock, Some(script), 280),
        lock,
        type_script: Some(script.to_vec()),
        data: data.to_vec(),
    }
}
pub fn advance_tip(
    lab: &Lab,
    point: CellOutPoint,
    capacity: u64,
    script: &[u8],
    data: &[u8],
    witness: &[u8],
) -> Result<Value, String> {
    let w = &lab.wallets[0];
    let mut out = tip_output(lab, script, data);
    out.capacity = capacity;
    tx::build_with_permissionless_prefix(
        &w.key,
        &lab.secp,
        &lab.deps,
        &[(point, capacity), (w.point, w.capacity)],
        &[
            out,
            OutSpec {
                capacity: w.capacity - TX_FEE,
                lock: w.key.lock_script(),
                type_script: None,
                data: vec![],
            },
        ],
        Some(witness),
        1,
    )
    .map(|(_, t)| t)
}
// get_live_cell may report "unknown" for an already spent output. Prove the
// consumption using both canonical transactions instead of assuming "dead".
pub fn consumed_tip(point: CellOutPoint, successor: &str) -> Result<Value, String> {
    let previous =
        json!({"tx_hash":rpc::bytes_to_hex(&point.tx_hash),"index":format!("0x{:x}",point.index)});
    let live = rpc::call("get_live_cell", json!([previous, true]))?;
    let creation = rpc::call("get_transaction", json!([previous["tx_hash"]]))?;
    let consumer = rpc::call("get_transaction", json!([successor]))?;
    if !matches!(live["status"].as_str(), Some("dead" | "unknown"))
        || creation["tx_status"]["status"] != "committed"
        || consumer["tx_status"]["status"] != "committed"
        || creation["transaction"]["outputs"]
            .as_array()
            .ok_or("creation outputs")?
            .get(point.index as usize)
            .is_none()
        || consumer["transaction"]["inputs"]
            .as_array()
            .ok_or("consumer inputs")?
            .iter()
            .filter(|input| input["previous_output"] == previous)
            .count()
            != 1
    {
        return Err("canonical predecessor consumption not established".into());
    }
    Ok(json!({"point":previous,"live_cell":live,"creation":creation,"consumer":consumer}))
}

pub fn reject(
    lab: &mut Lab,
    code: &[u8; 32],
    label: &str,
    transaction: &Value,
    expected: i8,
) -> Result<(), String> {
    let reason = format!("error code {expected}");
    match rpc::send_transaction_json(transaction) {
        Err(error) if lab::rejection_matches(&error, &reason, code) => {
            lab.evidence.push(json!({"label":label,"result":"rejected","expected_reason":reason,"error":error,"transaction":transaction}));
            println!("{label}: rejected ({reason})");
            Ok(())
        }
        other => Err(format!("{label}: expected {reason}, got {other:?}")),
    }
}
pub fn framed(journal: &[u8], proof: &[u8]) -> Vec<u8> {
    let mut out = b"TO1SETW1".to_vec();
    out.extend_from_slice(journal);
    out.extend_from_slice(&(proof.len() as u32).to_le_bytes());
    out.extend_from_slice(proof);
    out
}
pub fn cold_recovery(chain: &[u8], anchor: &[u8], tip: &[u8]) -> Result<Value, String> {
    let output = std::process::Command::new("target/debug/recover-settlement")
        .args([
            rpc::bytes_to_hex(chain),
            rpc::bytes_to_hex(anchor),
            rpc::bytes_to_hex(tip),
        ])
        .output()
        .map_err(|e| e.to_string())?;
    if !output.status.success() {
        return Err(format!(
            "cold settlement recovery: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    serde_json::from_slice(&output.stdout).map_err(|e| e.to_string())
}
pub struct Proof {
    pub bytes: Vec<u8>,
    pub journal: Vec<u8>,
    pub source: Value,
}
fn bounded(path: &Path, limit: u64) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    File::open(path)
        .map_err(|e| e.to_string())?
        .take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() as u64 > limit {
        return Err("proof artifact exceeds runner limit".into());
    }
    Ok(bytes)
}
pub fn read(directory: &Path, expected: &[u8], key: &Value) -> Result<Proof, String> {
    let bytes = bounded(&directory.join("groth16-proof.bin"), 4096)?;
    let journal = bounded(&directory.join("public-values.bin"), 768)?;
    let source: Value = serde_json::from_slice(&bounded(&directory.join("result.json"), 65536)?)
        .map_err(|e| e.to_string())?;
    if journal != expected
        || source["proof_generated"] != true
        || source["proof_kind"] != "SP1 real Groth16"
        || source["guest_verifying_key"] != *key
        || source["public_values_hex"] != rpc::bytes_to_hex(expected)[2..]
        || bytes.is_empty()
    {
        return Err("completed proof does not match canonical deployment export".into());
    }
    Ok(Proof {
        bytes,
        journal,
        source,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn retained_real_proof_cannot_be_reused_for_a_different_a3_deployment() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let proof = root.join("specs/evidence/chain-groth16-proof/proof");
        let original = std::fs::read(proof.join("public-values.bin")).unwrap();
        let metadata: Value =
            serde_json::from_slice(&std::fs::read(proof.join("result.json")).unwrap()).unwrap();
        assert!(read(&proof, &original, &metadata["guest_verifying_key"]).is_ok());
        let a3: Value = serde_json::from_slice(
            &std::fs::read(
                root.join("specs/evidence/sealed-settlement-input/0.210.0/proving-input.json"),
            )
            .unwrap(),
        )
        .unwrap();
        let journal = rpc::decode_hex(a3["expected_journal_hex"].as_str().unwrap()).unwrap();
        assert_ne!(original, journal);
        assert_eq!(
            read(&proof, &journal, &a3["guest_verifying_key"])
                .err()
                .unwrap(),
            "completed proof does not match canonical deployment export"
        );
    }
}
