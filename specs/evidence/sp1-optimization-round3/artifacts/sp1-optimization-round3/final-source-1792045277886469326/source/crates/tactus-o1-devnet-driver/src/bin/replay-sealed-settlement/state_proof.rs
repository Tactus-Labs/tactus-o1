//! Real CKB-VM state-read certificates against the already verified A3 Tip.
use serde_json::{json, Value};
use tactus_o1_devnet_driver::{
    lab::{self, Lab},
    molecule, rpc, settlement_lab,
    tx::{self, CellOutPoint, OutSpec, TX_FEE},
};
use tactus_o1_ordering_script::ckb_blake2b;

fn word(value: &Value) -> Result<[u8; 32], String> {
    let text = value
        .as_str()
        .ok_or("hex quantity")?
        .strip_prefix("0x")
        .ok_or("0x quantity")?;
    if text.is_empty() || text.len() > 64 {
        return Err("quantity length".into());
    }
    rpc::decode_hex(&format!("{text:0>64}"))?
        .try_into()
        .map_err(|_| "quantity".into())
}
fn frame(account: &Value, storage: &Value) -> Result<Vec<u8>, String> {
    let mut out = b"TO1MPW01".to_vec();
    for value in [account, storage] {
        let nodes = value.as_array().ok_or("proof nodes")?;
        if nodes.len() > 65 {
            return Err("proof node count".into());
        }
        out.extend_from_slice(&(nodes.len() as u16).to_le_bytes());
        for node in nodes {
            let bytes = rpc::decode_hex(node.as_str().ok_or("node hex")?)?;
            if bytes.is_empty() || bytes.len() > 1024 {
                return Err("node length".into());
            }
            out.extend_from_slice(&(bytes.len() as u16).to_le_bytes());
            out.extend(bytes);
        }
    }
    Ok(out)
}
fn claim(row: &Value, tip: &[u8]) -> Result<(Vec<u8>, Vec<u8>), String> {
    if tip.len() != 280
        || row["tag"] != "latest"
        || row["stateRoot"] != rpc::bytes_to_hex(&tip[216..248])
    {
        return Err("state witness is not for the settled A3 root".into());
    }
    let result = &row["result"];
    let storage = &result["storageProof"][0];
    let mut data = b"TO1EVMR1".to_vec();
    data.extend_from_slice(&tip[216..280]);
    data.extend_from_slice(&tip[56..64]);
    let address = rpc::decode_hex(result["address"].as_str().ok_or("address")?)?;
    if address.len() != 20 {
        return Err("address length".into());
    }
    data.extend(address);
    let code = word(&result["codeHash"])?;
    data.push(u8::from(code != [0; 32]));
    data.extend_from_slice(&[0; 3]);
    data.extend_from_slice(&super::number(&result["nonce"])?.to_le_bytes());
    data.extend_from_slice(&word(&result["balance"])?);
    data.extend_from_slice(&word(&result["storageHash"])?);
    data.extend_from_slice(&code);
    data.extend_from_slice(&word(&storage["key"])?);
    data.extend_from_slice(&word(&storage["value"])?);
    if data.len() != 272 {
        return Err("claim length".into());
    }
    Ok((data, frame(&result["accountProof"], &storage["proof"])?))
}
fn output(lab: &Lab, script: &[u8], data: &[u8]) -> OutSpec {
    let lock = lab.wallets[0].key.lock_script();
    OutSpec {
        capacity: OutSpec::required_capacity(&lock, Some(script), data.len()),
        lock,
        type_script: Some(script.to_vec()),
        data: data.to_vec(),
    }
}
fn build(
    lab: &Lab,
    deps: &[CellOutPoint],
    mut outputs: Vec<OutSpec>,
    proof: &[u8],
    extra: Option<(CellOutPoint, u64)>,
) -> Result<Value, String> {
    let wallet = &lab.wallets[0];
    let mut inputs = vec![(wallet.point, wallet.capacity)];
    if let Some(extra) = extra {
        inputs.push(extra)
    }
    let total = inputs
        .iter()
        .try_fold(0u64, |a, (_, c)| a.checked_add(*c))
        .ok_or("input capacity")?;
    let used = outputs
        .iter()
        .try_fold(TX_FEE, |a, o| a.checked_add(o.capacity))
        .ok_or("output capacity")?;
    outputs.push(OutSpec {
        capacity: total.checked_sub(used).ok_or("change")?,
        lock: wallet.key.lock_script(),
        type_script: None,
        data: vec![],
    });
    tx::build_with_output_type(&wallet.key, &lab.secp, deps, &inputs, &outputs, proof)
        .map(|(_, tx)| tx)
}
fn commit(lab: &mut Lab, label: &str, transaction: &Value) -> Result<String, String> {
    let hash = lab.commit(label, transaction)?;
    let index = transaction["outputs"].as_array().ok_or("outputs")?.len() - 1;
    lab.wallets[0].point = lab::point(&hash, index as u32)?;
    lab.wallets[0].capacity = super::number(&transaction["outputs"][index]["capacity"])?;
    Ok(hash)
}

pub fn qualify(
    lab: &mut Lab,
    settlement_script: &[u8],
    tip: CellOutPoint,
    tip_data: &[u8],
) -> Result<Value, String> {
    let path = std::env::var("TACTUS_STATE_PROOFS_JSON").map_err(|_| "state proof path")?;
    let bytes = std::fs::read(path).map_err(|e| e.to_string())?;
    if bytes.len() > 1024 * 1024 {
        return Err("state proof file limit".into());
    }
    let source: Value = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
    let selected: Vec<_> = source
        .as_array()
        .ok_or("proof array")?
        .iter()
        .filter(|row| row["tag"] == "latest")
        .collect();
    if selected.len() != 3 {
        return Err("expected three actual settled-state queries".into());
    }
    let elf =
        std::fs::read("artifacts/tactus_o1_state_proof_script.elf").map_err(|e| e.to_string())?;
    let code = ckb_blake2b(&elf);
    let code_points = lab.publish_cells("state-proof/deploy verifier", &[elf], 0, true)?;
    lab.deps.extend(code_points);
    let mut deps = lab.deps.clone();
    deps.push(tip);
    let mut args = b"TO1MPT01".to_vec();
    args.extend_from_slice(&ckb_blake2b(settlement_script));
    let script = molecule::script(&code, 2, &args);
    let (data, proof) = claim(selected[0], tip_data)?;
    let mut negatives = Vec::new();
    for (name, offset, expected) in [
        ("wrong state root", 8, 8),
        ("wrong settled header", 40, 8),
        ("wrong settled count", 72, 8),
        ("wrong address", 80, 6),
        ("wrong nonce", 104, 6),
        ("wrong balance", 143, 6),
        ("wrong storage root", 144, 6),
        ("wrong code hash", 176, 6),
        ("invented storage", 271, 7),
        ("reserved claim byte", 101, 3),
    ] {
        let mut changed = data.clone();
        changed[offset] ^= 1;
        let tx = build(
            lab,
            &deps,
            vec![output(lab, &script, &changed)],
            &proof,
            None,
        )?;
        let label = format!("state-proof/{name}");
        settlement_lab::reject(lab, &code, &label, &tx, expected)?;
        negatives.push(label);
    }
    for (name, changed) in [
        ("missing proof", Vec::new()),
        ("trailing proof bytes", [proof.clone(), vec![0]].concat()),
        ("truncated proof", proof[..proof.len() - 1].to_vec()),
    ] {
        let tx = build(
            lab,
            &deps,
            vec![output(lab, &script, &data)],
            &changed,
            None,
        )?;
        let label = format!("state-proof/{name}");
        settlement_lab::reject(lab, &code, &label, &tx, 5)?;
        negatives.push(label);
    }
    let missing = build(
        lab,
        &lab.deps,
        vec![output(lab, &script, &data)],
        &proof,
        None,
    )?;
    settlement_lab::reject(lab, &code, "state-proof/missing settled Tip", &missing, 4)?;
    negatives.push("state-proof/missing settled Tip".into());
    let mut wrong = args.clone();
    wrong[8] ^= 1;
    let wrong_script = molecule::script(&code, 2, &wrong);
    let wrong_tx = build(
        lab,
        &deps,
        vec![output(lab, &wrong_script, &data)],
        &proof,
        None,
    )?;
    settlement_lab::reject(lab, &code, "state-proof/wrong Tip identity", &wrong_tx, 4)?;
    negatives.push("state-proof/wrong Tip identity".into());
    let duplicate = build(
        lab,
        &deps,
        vec![output(lab, &script, &data), output(lab, &script, &data)],
        &proof,
        None,
    )?;
    settlement_lab::reject(
        lab,
        &code,
        "state-proof/multiple claim outputs",
        &duplicate,
        2,
    )?;
    negatives.push("state-proof/multiple claim outputs".into());
    let mut accepted = Vec::new();
    for (index, row) in selected.iter().enumerate() {
        let (data, proof) = claim(row, tip_data)?;
        let out = output(lab, &script, &data);
        let capacity = out.capacity;
        let tx = build(lab, &deps, vec![out], &proof, None)?;
        let hash = commit(lab, &format!("state-proof/authenticated read {index}"), &tx)?;
        let live = rpc::call(
            "get_live_cell",
            json!([{"tx_hash":hash,"index":"0x0"},true]),
        )?;
        if live["status"] != "live" || live["cell"]["data"]["content"] != rpc::bytes_to_hex(&data) {
            return Err("claim not live".into());
        }
        accepted.push(json!({"hash":hash,"data":rpc::bytes_to_hex(&data),"proof":rpc::bytes_to_hex(&proof),"query":row,"capacity":capacity,"live_cell":live}));
    }
    let first = &accepted[0];
    let point = lab::point(first["hash"].as_str().ok_or("claim hash")?, 0)?;
    let capacity = first["capacity"].as_u64().ok_or("capacity")?;
    let mutation = build(
        lab,
        &deps,
        vec![output(lab, &script, &data)],
        &proof,
        Some((point, capacity)),
    )?;
    let label = "state-proof/immutable claim cannot mutate";
    match rpc::send_transaction_json(&mutation) {
        Err(error)
            if lab::rejection_matches_at(&error, "error code 2", &code, "Inputs[1].Type") =>
        {
            lab.evidence.push(json!({"label":label,"result":"rejected","expected_reason":"error code 2","error":error,"transaction":mutation}));
            println!("{label}: rejected (error code 2)");
        }
        other => {
            return Err(format!(
                "{label}: expected input 1 type rejection, got {other:?}"
            ))
        }
    }
    negatives.push("state-proof/immutable claim cannot mutate".into());
    let burn = build(lab, &lab.deps, vec![], &[], Some((point, capacity)))?;
    let burn_hash = commit(
        lab,
        "state-proof/owner recovers certificate capacity",
        &burn,
    )?;
    let consumption = settlement_lab::consumed_tip(point, &burn_hash)?;
    let tip_live = rpc::call("get_live_cell", json!([super::point(tip), true]))?;
    if tip_live["status"] != "live"
        || tip_live["cell"]["data"]["content"] != rpc::bytes_to_hex(tip_data)
    {
        return Err("state reads changed settled Tip".into());
    }
    Ok(
        json!({"code_hash":rpc::bytes_to_hex(&code),"script":rpc::bytes_to_hex(&script),"settlement_tip":super::point(tip),"tip_data":rpc::bytes_to_hex(tip_data),"tip_live_after":tip_live,"accepted":accepted,"negative_controls":negatives,"destroyed_claim":first["hash"],"destruction_hash":burn_hash,"consumption":consumption,"withdrawal_authority":false,"production_ready":false}),
    )
}
