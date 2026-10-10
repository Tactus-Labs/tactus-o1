//! Resume the exact retained dev chain, verify a real native proof, settle once.
use serde_json::{json, Value};
use tactus_o1_devnet_driver::{
    lab::{self, Lab, Wallet},
    molecule, rpc,
    tx::{self, CellOutPoint, DevKey, OutSpec, TX_FEE},
};
use tactus_o1_native_proof_journal as journal;
use tactus_o1_native_settlement_script as verifier;
use tactus_o1_protocol::batch;
fn hx(b: &[u8]) -> String {
    rpc::bytes_to_hex(b)
}
fn raw(v: &Value) -> Result<Vec<u8>, String> {
    rpc::decode_hex(v.as_str().ok_or("expected hex string")?)
}
fn n(v: &Value) -> Result<u64, String> {
    u64::from_str_radix(v.as_str().ok_or("hex number")?.trim_start_matches("0x"), 16)
        .map_err(|e| e.to_string())
}
fn point(v: &Value) -> Result<CellOutPoint, String> {
    lab::point(
        v["tx_hash"].as_str().ok_or("outpoint")?,
        u32::try_from(n(&v["index"])?).map_err(|_| "index")?,
    )
}
fn json_script(v: &Value) -> Result<Vec<u8>, String> {
    let hash = raw(&v["code_hash"])?;
    let hash: [u8; 32] = hash.try_into().map_err(|_| "code hash size")?;
    let kind = match v["hash_type"].as_str() {
        Some("data1") => 2,
        Some("type") => 1,
        _ => return Err("script hash type".into()),
    };
    Ok(molecule::script(&hash, kind, &raw(&v["args"])?))
}
fn live(p: CellOutPoint) -> Result<Value, String> {
    rpc::call(
        "get_live_cell",
        json!([{"tx_hash":hx(&p.tx_hash),"index":format!("0x{:x}",p.index)},true]),
    )
}
/// Exact type and bytes, bounded indexer scan plus a live-cell recheck. This
/// relies on the explicitly selected CKB node's validation, not a light client.
fn find(script: &Value, data: Option<&[u8]>) -> Result<(CellOutPoint, Value), String> {
    let mut cursor = None;
    let mut selected = None;
    let mut seen = 0;
    loop {
        let search = json!({"script":script,"script_type":"type","script_search_mode":"exact"});
        let mut params = json!([search, "asc", "0x40"]);
        if let Some(c) = &cursor {
            params.as_array_mut().unwrap().push(json!(c));
        }
        let page = rpc::call("get_cells", params)?;
        let objects = page["objects"].as_array().ok_or("indexer objects")?;
        if objects.is_empty() {
            break;
        }
        for cell in objects {
            seen += 1;
            if seen > 4096 {
                return Err("cell scan bound".into());
            }
            if cell["output"]["type"] != *script {
                return Err("indexer returned other type".into());
            }
            let bytes = raw(&cell["output_data"])?;
            if data.is_none_or(|expected| expected == bytes) {
                let p = point(&cell["out_point"])?;
                let check = live(p)?;
                if check["status"] != "live"
                    || check["cell"]["output"] != cell["output"]
                    || raw(&check["cell"]["data"]["content"])? != bytes
                {
                    return Err("live cell changed during selection".into());
                }
                if selected.replace((p, check)).is_some() {
                    return Err("ambiguous live typed state".into());
                }
            }
        }
        let next = page["last_cursor"]
            .as_str()
            .ok_or("indexer cursor")?
            .to_owned();
        if cursor.as_ref() == Some(&next) {
            return Err("nonadvancing indexer".into());
        }
        cursor = Some(next);
    }
    selected.ok_or("expected live typed state missing".into())
}
fn build(
    lab: &Lab,
    actor: usize,
    tip: (CellOutPoint, u64),
    mut outputs: Vec<OutSpec>,
    deps: &[CellOutPoint],
    w: &[u8],
) -> Result<Value, String> {
    let wallet = &lab.wallets[actor];
    let total = tip
        .1
        .checked_add(wallet.capacity)
        .ok_or("capacity overflow")?;
    let used = outputs
        .iter()
        .try_fold(TX_FEE, |sum, o| sum.checked_add(o.capacity))
        .ok_or("output overflow")?;
    outputs.push(OutSpec {
        capacity: total.checked_sub(used).ok_or("funding")?,
        lock: wallet.key.lock_script(),
        type_script: None,
        data: vec![],
    });
    let mut all = lab.deps.clone();
    all.extend_from_slice(deps);
    tx::build_with_permissionless_prefix(
        &wallet.key,
        &lab.secp,
        &all,
        &[tip, (wallet.point, wallet.capacity)],
        &outputs,
        Some(w),
        1,
    )
    .map(|(_, v)| v)
}
fn reject(lab: &mut Lab, label: &str, tx: &Value, code: i8) -> Result<(), String> {
    let reason = format!("error code {code}");
    let program = batch::hash(b"", &lab.ordering_elf);
    match rpc::send_transaction_json(tx) {
        Err(error) if lab::rejection_matches_at(&error, &reason, &program, "Inputs[0].Type") => {
            lab.evidence.push(json!({"label":label,"result":"rejected","error":error,"expected_reason":reason,"transaction":tx}));
            println!("{label}: rejected ({reason})");
            Ok(())
        }
        other => Err(format!("{label}: wrong rejection {other:?}")),
    }
}
fn frame(j: &[u8], proof: &[u8]) -> Vec<u8> {
    let mut b = b"TO1NSW02".to_vec();
    b.extend_from_slice(j);
    b.extend_from_slice(&(proof.len() as u32).to_le_bytes());
    b.extend_from_slice(proof);
    b
}
fn run() -> Result<(), String> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 5 {
        return Err(
            "usage: settle-native-proof BOOTSTRAP_JSON INPUT_JSON PROOF_DIR NEW_EVIDENCE_JSON"
                .into(),
        );
    }
    let addr =
        std::env::var("TACTUS_CKB_RPC_ADDR").map_err(|_| "explicit isolated RPC required")?;
    if !addr.starts_with("127.0.0.1:") || addr.ends_with(":8114") {
        return Err("isolated loopback node required".into());
    }
    if std::path::Path::new(&args[4]).exists() {
        return Err("evidence path already exists".into());
    }
    let read = |p: &str| -> Result<Vec<u8>, String> {
        let bytes = std::fs::read(p).map_err(|e| e.to_string())?;
        if bytes.len() > 16 * 1024 * 1024 {
            return Err("file exceeds laboratory bound".into());
        }
        Ok(bytes)
    };
    let source: Value = serde_json::from_slice(&read(&args[1])?).map_err(|e| e.to_string())?;
    let r = &source["results"];
    if r["suite"] != "native-settlement-bootstrap-v2" || r["complete"] != true {
        return Err("qualified bootstrap required".into());
    }
    let input: Value = serde_json::from_slice(&read(&args[2])?).map_err(|e| e.to_string())?;
    if input["schema"] != "native-proof-input-v2"
        || input["guest_verifying_key"] != verifier::GUEST_KEY
    {
        return Err("proof input profile/key".into());
    }
    let public = read(&format!("{}/public-values.bin", args[3]))?;
    let proof = read(&format!("{}/groth16-proof.bin", args[3]))?;
    if public != raw(&input["expected_journal_hex"])?
        || proof.is_empty()
        || proof.len() > verifier::MAX_PROOF_BYTES
    {
        return Err("proof/public input mismatch".into());
    }
    let domain =
        journal::Domain::decode(&raw(&input["domain_hex"])?).map_err(|e| format!("{e:?}"))?;
    let batches: Vec<_> = input["batches"]
        .as_array()
        .ok_or("batches")?
        .iter()
        .map(raw)
        .collect::<Result<_, _>>()?;
    let prefix = input["prefix_batches"].as_u64().ok_or("prefix")?;
    let count = (batches.len() as u64)
        .checked_sub(prefix)
        .filter(|v| *v > 0)
        .ok_or("range")?;
    let mut it = batches.iter();
    let expected = journal::execute(
        domain.clone(),
        &raw(&input["allocation_hex"])?,
        prefix,
        count,
        || it.next().unwrap().clone(),
    )
    .map_err(|e| format!("{e:?}"))?;
    if public != expected.encode() {
        return Err("native replay mismatch".into());
    }
    sp1_verifier::Groth16Verifier::verify(
        &proof,
        &public,
        verifier::GUEST_KEY,
        &sp1_verifier::GROTH16_VK_BYTES,
    )
    .map_err(|e| format!("actual proof verification: {e:?}"))?;
    let consensus = rpc::require_devnet()?;
    let node = rpc::call("local_node_info", json!([]))?;
    if !node["version"]
        .as_str()
        .unwrap_or("")
        .starts_with("0.210.0")
        || rpc::call("get_block_hash", json!(["0x0"]))? != hx(&domain.config.ckb_genesis)
    {
        return Err("wrong node/network".into());
    }
    let settlement = &r["settlement"];
    let config = verifier::Config::decode(&raw(&settlement["config"])?)
        .map_err(|e| format!("config {e}"))?;
    let script = raw(&settlement["script"])?;
    let own = batch::hash(b"", &script);
    if expected.domain.config.encode().as_slice() != raw(&r["config"])?
        || own != domain.config.settlement
        || domain.ordering_type_hash != config.anchor_type_hash
    {
        return Err("wrong actual deployment".into());
    }
    let labels: std::collections::BTreeMap<_, _> = source["evidence"]
        .as_array()
        .ok_or("events")?
        .iter()
        .filter_map(|e| e["label"].as_str().map(|n| (n, e)))
        .collect();
    let ty = &settlement["final_live"]["cell"]["output"]["type"];
    if json_script(ty)? != script {
        return Err("settlement script bytes".into());
    }
    let (tip_point, current) = find(ty, None)?;
    let before = verifier::Tip::decode(&raw(&current["cell"]["data"]["content"])?)
        .map_err(|e| format!("tip {e}"))?;
    let after = verifier::Tip {
        initialized: true,
        anchor: expected.after.ordering.encode(),
        state_root: expected.next_state_root,
        header_hash: expected.next_header_hash,
    };
    let (bs, as_) = verifier::transition(
        &config,
        &own,
        &before,
        &after,
        public.as_slice().try_into().map_err(|_| "journal size")?,
    )
    .map_err(|e| format!("transition {e}"))?;
    let cp_type = &r["checkpoints"][0]["live"]["cell"]["output"]["type"];
    if json_script(cp_type)?
        != molecule::script(
            &verifier::CHECKPOINT_CODE,
            2,
            &[b"TO1NCP02".as_slice(), &config.anchor_type_hash].concat(),
        )
    {
        return Err("checkpoint type".into());
    }
    let mut deps = vec![];
    if before.initialized {
        deps.push(find(cp_type, Some(&bs.encode()))?.0);
    }
    deps.push(find(cp_type, Some(&as_.encode()))?.0);
    let settlement_code =
        raw(&labels["settlement/deploy program"]["transaction"]["outputs_data"][0])?;
    let lock_code = raw(&labels["deploy immutable code and independent actor funds"]
        ["transaction"]["outputs_data"][1])?;
    if molecule::script(&batch::hash(b"", &settlement_code), 2, &config.encode()) != script {
        return Err("deployed verifier bytes".into());
    }
    let code_points = [
        lab::point(
            labels["settlement/deploy program"]["hash"]
                .as_str()
                .ok_or("deployment")?,
            0,
        )?,
        lab::point(
            labels["deploy immutable code and independent actor funds"]["hash"]
                .as_str()
                .ok_or("deployment")?,
            1,
        )?,
    ];
    for (p, bytes) in code_points.iter().zip([&settlement_code, &lock_code]) {
        let c = live(*p)?;
        if c["status"] != "live" || raw(&c["cell"]["data"]["content"])? != *bytes {
            return Err("code dependency changed".into());
        }
    }
    let mut wallets = vec![];
    for key in [DevKey::dev(), DevKey::from_seed([0x22; 32])] {
        let (point, capacity) = tx::collect_live_cells(&key.args)?
            .into_iter()
            .max_by_key(|(_, c)| *c)
            .ok_or("funding unavailable")?;
        wallets.push(Wallet {
            key,
            point,
            capacity,
        });
    }
    let secp = tx::find_secp_dep(&rpc::get_block_detailed(0)?)?;
    let mut lab = Lab {
        secp,
        deps: code_points.to_vec(),
        wallets,
        ordering_elf: settlement_code,
        lock_elf: lock_code,
        evidence: vec![],
        metadata: json!({"node_version":node["version"],"consensus":consensus,"ordering_code_hash":hx(&raw(&ty["code_hash"])?),"lock_code_hash":r["final_anchor"]["cell"]["output"]["lock"]["code_hash"],"bootstrap_genesis_transaction":r["genesis_transaction"],"production_ready":false}),
    };
    let capacity = n(&current["cell"]["output"]["capacity"])?;
    let lock = json_script(&current["cell"]["output"]["lock"])?;
    let output = OutSpec {
        capacity,
        lock,
        type_script: Some(script),
        data: after.encode().to_vec(),
    };
    let mut result = json!({"suite":"native-proof-settlement-v2","complete":false,"error":null,"before":current,"input":input,"guest_key":verifier::GUEST_KEY,"proof_verified_offchain":true,"proof_settled":false,"withdrawal_executed":false,"production_ready":false});
    let outcome = (|| {
        for (mode, label, code) in [
            (0, "native proof/missing endpoint", 8),
            (1, "native proof/forged endpoint cursor", 8),
            (2, "native proof/tampered next root", 9),
            (3, "native proof/tampered proof", 9),
        ] {
            let mut j = public.clone();
            let mut p = proof.clone();
            let mut d = deps.clone();
            let mut o = output.clone();
            match mode {
                0 => {
                    d.pop();
                }
                1 => j[748] ^= 1,
                2 => {
                    j[812] ^= 1;
                    o.data[216] ^= 1;
                }
                _ => {
                    let last = p.len() - 1;
                    p[last] ^= 1;
                }
            }
            let tx = build(&lab, 1, (tip_point, capacity), vec![o], &d, &frame(&j, &p))?;
            reject(&mut lab, label, &tx, code)?;
        }
        if before.initialized {
            let tx = build(
                &lab,
                1,
                (tip_point, capacity),
                vec![output.clone()],
                &deps[1..],
                &frame(&public, &proof),
            )?;
            reject(
                &mut lab,
                "native proof/missing predecessor checkpoint",
                &tx,
                8,
            )?;
            let mut j = public.clone();
            j[492] ^= 1;
            let tx = build(
                &lab,
                1,
                (tip_point, capacity),
                vec![output.clone()],
                &deps,
                &frame(&j, &proof),
            )?;
            reject(&mut lab, "native proof/forged predecessor cursor", &tx, 8)?;
        }
        let tx = build(
            &lab,
            1,
            (tip_point, capacity),
            vec![output.clone()],
            &deps,
            &frame(&public, &proof),
        )?;
        let hash = lab.commit("native proof/settle verified interval", &tx)?;
        lab.wallets[1].point = lab::point(&hash, 1)?;
        lab.wallets[1].capacity = n(&tx["outputs"][1]["capacity"])?;
        let new_point = lab::point(&hash, 0)?;
        let live_tip = live(new_point)?;
        if live_tip["status"] != "live"
            || raw(&live_tip["cell"]["data"]["content"])? != after.encode()
            || live(tip_point)?["status"] != "dead"
        {
            return Err("committed Tip not consumed/recreated".into());
        }
        result["after"] = live_tip;
        result["transaction"] = json!(hash);
        result["proof_settled"] = json!(true);
        let tx = build(
            &lab,
            1,
            (new_point, capacity),
            vec![output],
            &deps,
            &frame(&public, &proof),
        )?;
        reject(&mut lab, "native proof/replay settled interval", &tx, 7)?;
        result["complete"] = json!(true);
        Ok::<(), String>(())
    })();
    if let Err(e) = &outcome {
        result["error"] = json!(e);
    }
    lab.save(&args[4], result)?;
    outcome
}
fn main() {
    if let Err(e) = run() {
        eprintln!("{e}");
        std::process::exit(1);
    }
}
