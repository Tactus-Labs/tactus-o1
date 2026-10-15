//! Real Groth16 verification and immutable public-journal receipts, not settlement.
use serde_json::{json, Value};
use std::{fs, path::Path};
use tactus_o1_devnet_driver::{
    lab::{self, Lab},
    molecule, rpc,
    tx::{self, CellOutPoint, OutSpec, TX_FEE},
};
use tactus_o1_ordering_script::ckb_blake2b;

fn number(value: &str) -> Result<u64, String> {
    u64::from_str_radix(value.strip_prefix("0x").ok_or("expected hex number")?, 16)
        .map_err(|e| e.to_string())
}
fn witness(proof: &[u8]) -> Vec<u8> {
    let mut encoded = b"TO1G1601".to_vec();
    encoded.extend_from_slice(&(proof.len() as u32).to_le_bytes());
    encoded.extend_from_slice(proof);
    encoded
}
fn receipt(lab: &Lab, key: &[u8], journal: &[u8]) -> OutSpec {
    let lock = lab.wallets[0].key.lock_script();
    let script = molecule::script(&ckb_blake2b(&lab.ordering_elf), 2, key);
    OutSpec {
        capacity: OutSpec::required_capacity(&lock, Some(&script), journal.len()),
        lock,
        type_script: Some(script),
        data: journal.to_vec(),
    }
}
fn transaction(
    lab: &Lab,
    mut outputs: Vec<OutSpec>,
    proof: &[u8],
    extra: Option<(CellOutPoint, u64)>,
) -> Result<Value, String> {
    let wallet = &lab.wallets[0];
    let mut inputs = vec![(wallet.point, wallet.capacity)];
    if let Some(cell) = extra {
        inputs.insert(0, cell);
    }
    let incoming: u64 = inputs.iter().map(|(_, cap)| cap).sum();
    let spent: u64 = outputs.iter().map(|o| o.capacity).sum();
    let change = incoming
        .checked_sub(spent + TX_FEE)
        .ok_or("insufficient capacity")?;
    outputs.push(OutSpec {
        capacity: change,
        lock: wallet.key.lock_script(),
        type_script: None,
        data: vec![],
    });
    tx::build_and_sign(
        &wallet.key,
        &lab.secp,
        &lab.deps,
        &inputs,
        &outputs,
        Some(proof),
    )
    .map(|(_, tx)| tx)
}
fn run() -> Result<(), String> {
    let evidence = std::env::var("TACTUS_EVIDENCE_PATH").map_err(|_| "use isolated launcher")?;
    let directory = std::env::var("TACTUS_PROOF_DIR")
        .map_err(|_| "TACTUS_PROOF_DIR must contain a real completed Groth16 proof")?;
    let directory = Path::new(&directory);
    let source: Value = serde_json::from_slice(
        &fs::read(directory.join("result.json")).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    if source["proof_generated"] != true || source["proof_kind"] != "SP1 real Groth16" {
        return Err("require completed real Groth16 proof".into());
    }
    let key = rpc::decode_hex(
        source["guest_verifying_key"]
            .as_str()
            .ok_or("missing key")?,
    )?;
    let proof = fs::read(directory.join("groth16-proof.bin")).map_err(|e| e.to_string())?;
    let public = fs::read(directory.join("public-values.bin")).map_err(|e| e.to_string())?;
    if key.len() != 32 || public.len() != 768 || proof.is_empty() || proof.len() > 4096 {
        return Err("proof material length mismatch".into());
    }
    if source["public_values_hex"] != rpc::bytes_to_hex(&public).trim_start_matches("0x") {
        return Err("source journal differs".into());
    }
    let encoded = witness(&proof);
    let mut lab = Lab::connect_with_script("artifacts/tactus_o1_proof_check_script.elf")?;
    let mut results = json!({"suite":"groth16-proof-receipt-v1","complete":false,"production_ready":false,"settled":false,"G3":"OPEN","source_proof":source,"proof_ckb_hash":rpc::bytes_to_hex(&ckb_blake2b(&proof)),"public_values":rpc::bytes_to_hex(&public),"receipts":[],"scope":"real CKB Groth16 verification and immutable journal publication; no authenticated ordering history, real deployment identity or SettlementTip transition"});
    let outcome = (|| {
        let output = receipt(&lab, &key, &public);
        let baseline = transaction(&lab, vec![receipt(&lab, &key, &public)], &encoded, None)?;
        results["valid_preflight_cycles"] = rpc::call("estimate_cycles", json!([baseline]))?;
        lab.save(&evidence, results.clone())?;
        for (name, offset) in [
            ("profile", 8),
            ("ckb-network", 40),
            ("ordering-script", 72),
            ("settlement-script", 104),
            ("rollup", 136),
            ("chain", 168),
            ("allocation", 176),
            ("predecessor", 248),
            ("end-history", 456),
            ("previous-state", 608),
            ("next-state", 640),
            ("previous-header", 672),
            ("next-header", 704),
            ("interval-data", 736),
        ] {
            let mut changed = public.clone();
            changed[offset] ^= 1;
            let t = transaction(&lab, vec![receipt(&lab, &key, &changed)], &encoded, None)?;
            lab.reject(&format!("proof/{name} tamper"), &t, "error code 7")?;
        }
        for offset in [0, proof.len() - 1] {
            let mut changed = proof.clone();
            changed[offset] ^= 1;
            let t = transaction(
                &lab,
                vec![receipt(&lab, &key, &public)],
                &witness(&changed),
                None,
            )?;
            lab.reject(
                &format!("proof/proof-byte-{offset} tamper"),
                &t,
                "error code 7",
            )?;
        }
        let mut wrong_key = key.clone();
        wrong_key[31] ^= 1;
        for (name, outputs, bytes, code) in [
            (
                "wrong-key",
                vec![receipt(&lab, &wrong_key, &public)],
                encoded.clone(),
                7,
            ),
            (
                "short-key",
                vec![receipt(&lab, &key[..31], &public)],
                encoded.clone(),
                6,
            ),
            (
                "short-journal",
                vec![receipt(&lab, &key, &public[..767])],
                encoded.clone(),
                9,
            ),
            (
                "long-journal",
                vec![receipt(&lab, &key, &[public.clone(), vec![0]].concat())],
                encoded.clone(),
                9,
            ),
            (
                "empty-proof",
                vec![receipt(&lab, &key, &public)],
                witness(&[]),
                5,
            ),
            (
                "trailing-proof",
                vec![receipt(&lab, &key, &public)],
                [encoded.clone(), vec![0]].concat(),
                5,
            ),
            (
                "oversized-witness",
                vec![receipt(&lab, &key, &public)],
                vec![0; 9000],
                3,
            ),
            (
                "duplicate-receipt-output",
                vec![receipt(&lab, &key, &public), receipt(&lab, &key, &public)],
                encoded.clone(),
                8,
            ),
        ] {
            let t = transaction(&lab, outputs, &bytes, None)?;
            lab.reject(&format!("proof/{name}"), &t, &format!("error code {code}"))?;
        }
        // Repeated proofs can publish distinct immutable receipts; this is not
        // settlement replay protection or a reward/custody accounting mechanism.
        for index in 0..2 {
            let t = transaction(&lab, vec![receipt(&lab, &key, &public)], &encoded, None)?;
            let estimated = rpc::call("estimate_cycles", json!([t]))?;
            let cycles = number(estimated["cycles"].as_str().ok_or("missing cycles")?)?;
            let hash = lab.commit(&format!("proof/valid-receipt-{index}"), &t)?;
            let packed = rpc::call("get_transaction", json!([hash, "0x0"]))?;
            let node_bytes =
                rpc::decode_hex(packed["transaction"].as_str().ok_or("packed transaction")?)?.len();
            if node_bytes != tx::wire_bytes(&t)? {
                return Err("wire byte count differs from node".into());
            }
            let change = &t["outputs"][1];
            lab.wallets[0].point = lab::point(&hash, 1)?;
            lab.wallets[0].capacity =
                number(change["capacity"].as_str().ok_or("change capacity")?)?;
            let point = lab::point(&hash, 0)?;
            for (name, outputs) in [
                ("consume", vec![]),
                ("replace", vec![receipt(&lab, &key, &public)]),
            ] {
                let spend = transaction(&lab, outputs, &encoded, Some((point, output.capacity)))?;
                lab.reject(
                    &format!("proof/receipt-{index}-{name}"),
                    &spend,
                    "error code 8",
                )?;
            }
            results["receipts"].as_array_mut().unwrap().push(json!({"hash":hash,"vm_cycles":cycles,"node_wire_bytes":node_bytes,"fee_shannons":TX_FEE,"receipt_capacity_shannons":output.capacity,"settled":false}));
            lab.save(&evidence, results.clone())?;
        }
        results["complete"] = true.into();
        Ok::<_, String>(())
    })();
    results["error"] = json!(outcome.as_ref().err());
    lab.save(&evidence, results)?;
    outcome
}
fn main() {
    if let Err(error) = run() {
        eprintln!("PROOF VERIFIER FAILED: {error}");
        std::process::exit(1);
    }
}
