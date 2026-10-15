//! Real-node qualification of immutable, Anchor-authenticated history checkpoints.
use serde_json::{json, Value};
use tactus_o1_devnet_driver::{
    batch_lab::{self, Anchor},
    lab::{self, Lab},
    molecule, rpc,
    tx::{self, CellOutPoint, OutSpec, TX_FEE},
};
use tactus_o1_ordering_script::ckb_blake2b;
use tactus_o1_protocol::batch;

fn checkpoint(lab: &Lab, code: &[u8; 32], identity: &[u8], data: &[u8]) -> OutSpec {
    let lock = lab.wallets[0].key.lock_script();
    let script = molecule::script(code, 2, identity);
    OutSpec {
        capacity: OutSpec::required_capacity(&lock, Some(&script), data.len()),
        lock,
        type_script: Some(script),
        data: data.to_vec(),
    }
}
fn reject(
    lab: &mut Lab,
    code: &[u8; 32],
    label: &str,
    tx: &Value,
    reason: &str,
) -> Result<(), String> {
    match rpc::send_transaction_json(tx) {
        Err(error) if lab::rejection_matches(&error, reason, code) => {
            lab.evidence.push(json!({"label":label,"result":"rejected","expected_reason":reason,"error":error,"transaction":tx}));
            println!("{label}: rejected ({reason})");
            Ok(())
        }
        other => Err(format!("{label}: expected {reason}, got {other:?}")),
    }
}
fn ordinary(
    lab: &Lab,
    mut outputs: Vec<OutSpec>,
    extra: Option<(CellOutPoint, u64)>,
) -> Result<Value, String> {
    let wallet = &lab.wallets[0];
    let mut inputs = vec![(wallet.point, wallet.capacity)];
    if let Some(cell) = extra {
        inputs.insert(0, cell);
    }
    let available: u64 = inputs.iter().map(|(_, cap)| cap).sum();
    let needed: u64 = outputs.iter().map(|out| out.capacity).sum();
    let change = available.checked_sub(needed + TX_FEE).ok_or("capacity")?;
    outputs.push(OutSpec {
        capacity: change,
        lock: wallet.key.lock_script(),
        type_script: None,
        data: vec![],
    });
    tx::build_and_sign(&wallet.key, &lab.secp, &lab.deps, &inputs, &outputs, None).map(|(_, tx)| tx)
}
fn advancing(
    lab: &Lab,
    anchor: &Anchor,
    bytes: &[u8],
    mut receipts: Vec<OutSpec>,
) -> Result<Value, String> {
    let next = batch::validate_batch(bytes, &anchor.state)
        .map_err(|e| format!("{e:?}"))?
        .next;
    let da_index = receipts.len() as u32 + 1;
    receipts.push(batch_lab::head_output(anchor, next));
    receipts.push(batch_lab::da_output(anchor, bytes));
    batch_lab::shape(lab, anchor, 0, receipts, Some(&da_index.to_le_bytes()))
}
fn run() -> Result<(), String> {
    let evidence = std::env::var("TACTUS_EVIDENCE_PATH").map_err(|_| "use isolated launcher")?;
    let mut lab = Lab::connect_with_script("artifacts/tactus_o1_anchor_script.elf")?;
    let elf = std::fs::read("artifacts/tactus_o1_history_checkpoint_script.elf")
        .map_err(|e| e.to_string())?;
    let code = ckb_blake2b(&elf);
    let deployed = lab.publish_cells("checkpoint/deploy immutable code", &[elf], 0, true)?;
    lab.deps.extend(deployed);
    let mut anchor = batch_lab::create(&mut lab, [9; 32], 777)?;
    let identity = ckb_blake2b(&anchor.script);
    let genesis_point = anchor.point;
    let mut results = json!({"suite":"authenticated-history-checkpoint-v1","complete":false,"settled":false,"production_ready":false,"G3":"OPEN","checkpoint_code_hash":rpc::bytes_to_hex(&code),"anchor_type_hash":rpc::bytes_to_hex(&identity),"checkpoints":[]});
    let outcome = (|| {
        for round in 0..2 {
            let bytes = batch_lab::encode(anchor.state, vec![batch_lab::block(round + 1, vec![])])?;
            let next = batch::validate_batch(&bytes, &anchor.state)
                .map_err(|e| format!("{e:?}"))?
                .next;
            let data = next.encode();
            if round == 0 {
                let good = advancing(
                    &lab,
                    &anchor,
                    &bytes,
                    vec![checkpoint(&lab, &code, &identity, &data)],
                )?;
                results["valid_preflight_cycles"] = rpc::call("estimate_cycles", json!([good]))?;
                lab.save(&evidence, results.clone())?;
                for (field, offset) in [
                    ("magic", 0),
                    ("rollup", 8),
                    ("batch", 40),
                    ("history", 48),
                    ("block", 80),
                    ("time", 88),
                    ("rules", 96),
                    ("da", 128),
                    ("limits", 160),
                    ("chain", 192),
                ] {
                    let mut changed = data;
                    changed[offset] ^= 1;
                    let tx = advancing(
                        &lab,
                        &anchor,
                        &bytes,
                        vec![checkpoint(&lab, &code, &identity, &changed)],
                    )?;
                    reject(
                        &mut lab,
                        &code,
                        &format!("checkpoint/tamper-{field}"),
                        &tx,
                        "error code 7",
                    )?;
                }
                let mut wrong = identity;
                wrong[0] ^= 1;
                for (label, args, journal, expected) in [
                    (
                        "wrong-anchor",
                        wrong.to_vec(),
                        data.to_vec(),
                        "error code 4",
                    ),
                    (
                        "short-key",
                        identity[..31].to_vec(),
                        data.to_vec(),
                        "error code 1",
                    ),
                    (
                        "short-data",
                        identity.to_vec(),
                        data[..199].to_vec(),
                        "error code 5",
                    ),
                    (
                        "long-data",
                        identity.to_vec(),
                        [data.to_vec(), vec![0]].concat(),
                        "error code 5",
                    ),
                ] {
                    let tx = advancing(
                        &lab,
                        &anchor,
                        &bytes,
                        vec![checkpoint(&lab, &code, &args, &journal)],
                    )?;
                    reject(
                        &mut lab,
                        &code,
                        &format!("checkpoint/{label}"),
                        &tx,
                        expected,
                    )?;
                }
                let tx = advancing(
                    &lab,
                    &anchor,
                    &bytes,
                    vec![
                        checkpoint(&lab, &code, &identity, &data),
                        checkpoint(&lab, &code, &identity, &data),
                    ],
                )?;
                reject(&mut lab, &code, "checkpoint/duplicate", &tx, "error code 2")?;
                let tx = ordinary(&lab, vec![checkpoint(&lab, &code, &identity, &data)], None)?;
                reject(
                    &mut lab,
                    &code,
                    "checkpoint/no-anchor-transition",
                    &tx,
                    "error code 4",
                )?;
                lab.deps.push(anchor.point);
                let tx = ordinary(&lab, vec![checkpoint(&lab, &code, &identity, &data)], None)?;
                lab.deps.pop();
                reject(
                    &mut lab,
                    &code,
                    "checkpoint/anchor-dependency-only",
                    &tx,
                    "error code 4",
                )?;
            }
            let receipt = checkpoint(&lab, &code, &identity, &data);
            let receipt_capacity = receipt.capacity;
            let tx = advancing(&lab, &anchor, &bytes, vec![receipt])?;
            let hash = lab.commit(&format!("checkpoint/advance-{round}"), &tx)?;
            let point = lab::point(&hash, 0)?;
            anchor.point = lab::point(&hash, 1)?;
            anchor.state = next;
            lab.wallets[0].point = lab::point(&hash, 3)?;
            lab.wallets[0].capacity = u64::from_str_radix(
                tx["outputs"][3]["capacity"]
                    .as_str()
                    .ok_or("change")?
                    .trim_start_matches("0x"),
                16,
            )
            .map_err(|e| e.to_string())?;
            for (operation, outputs) in [
                ("consume", vec![]),
                ("replace", vec![checkpoint(&lab, &code, &identity, &data)]),
            ] {
                let tx = ordinary(&lab, outputs, Some((point, receipt_capacity)))?;
                reject(
                    &mut lab,
                    &code,
                    &format!("checkpoint/{round}-{operation}"),
                    &tx,
                    "error code 2",
                )?;
            }
            // The next Anchor advance may resolve this old immutable checkpoint,
            // even though the Anchor outpoint that created it is already spent.
            lab.deps.push(point);
            results["checkpoints"].as_array_mut().unwrap().push(json!({"hash":hash,"output_index":0,"data":rpc::bytes_to_hex(&data),"capacity_shannons":receipt_capacity}));
            lab.save(&evidence, results.clone())?;
        }
        // A mutable old Anchor dependency really is stale on this same node.
        lab.deps.push(genesis_point);
        let tx = ordinary(&lab, vec![], None)?;
        lab.deps.pop();
        reject(
            &mut lab,
            &code,
            "checkpoint/stale-anchor-dependency",
            &tx,
            "TransactionFailedToResolve",
        )?;
        for item in results["checkpoints"].as_array().unwrap() {
            let live = rpc::call(
                "get_live_cell",
                json!([{"tx_hash":item["hash"],"index":"0x0"},true]),
            )?;
            if live["status"] != "live" || live["cell"]["data"]["content"] != item["data"] {
                return Err("retained checkpoint differs".into());
            }
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
        eprintln!("HISTORY CHECKPOINT FAILED: {error}");
        std::process::exit(1);
    }
}
