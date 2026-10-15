//! Matched admission-vs-admission races with independent fee inputs.
use serde_json::{json, Value};
use tactus_o1_devnet_driver::{
    lab::{self, Lab},
    molecule, rpc, sealed_lab as sealed,
    tx::{wire_bytes, CellOutPoint, OutSpec, TX_FEE},
};
use tactus_o1_ordering_script::{ckb_blake2b, genesis_identity};
use tactus_o1_protocol::priority::Message;

fn live(point: CellOutPoint) -> Result<bool, String> {
    Ok(rpc::call(
        "get_live_cell",
        json!([{"tx_hash":rpc::bytes_to_hex(&point.tx_hash),"index":format!("0x{:x}",point.index)},false]),
    )?["status"]
        == "live")
}
fn admitted(
    lab: &Lab,
    net: &sealed::Network,
    code: &[u8; 32],
    actor: usize,
    payload: Vec<u8>,
    fee: u64,
) -> Result<Value, String> {
    let p = lab.wallets[actor].point;
    let seed = molecule::cell_input(0, &molecule::out_point(&p.tx_hash, p.index))
        .try_into()
        .unwrap();
    let id = genesis_identity(&seed, 0);
    let script = sealed::role(code, 0, &id, None);
    let lock = sealed::role(code, 1, &ckb_blake2b(&script), None);
    let data = Message::admitted(
        id,
        net.anchor.state.rollup_id,
        ckb_blake2b(&net.anchor.script),
        payload,
    )
    .map_err(|e| format!("{e:?}"))?
    .encode()
    .map_err(|e| format!("{e:?}"))?;
    let capacity = OutSpec::required_capacity(&lock, Some(&script), data.len()) + TX_FEE;
    sealed::shape_with_fee(
        lab,
        actor,
        &[],
        vec![OutSpec {
            capacity,
            lock,
            type_script: Some(script),
            data,
        }],
        &[],
        &[],
        fee,
    )
}
// Match serialized bytes, not CKB's cycle-weighted virtual size.
const SHANNONS_PER_BYTE: u64 = 100_000;
fn priced(
    density: bool,
    ratio: u64,
    build: impl Fn(u64) -> Result<Value, String>,
) -> Result<Value, String> {
    let provisional = build(TX_FEE * ratio)?;
    if !density {
        return Ok(provisional);
    }
    let bytes = wire_bytes(&provisional)?;
    let fee = (bytes as u64)
        .checked_mul(SHANNONS_PER_BYTE)
        .and_then(|n| n.checked_mul(ratio))
        .ok_or("fee overflow")?;
    let transaction = build(fee)?;
    if wire_bytes(&transaction)? != bytes {
        return Err("fee repricing changed serialized size".into());
    }
    Ok(transaction)
}
fn capacity(v: &Value) -> Result<u64, String> {
    u64::from_str_radix(
        v.as_str()
            .ok_or("capacity string")?
            .trim_start_matches("0x"),
        16,
    )
    .map_err(|e| e.to_string())
}
fn metrics(t: &Value) -> Result<Value, String> {
    let cycles = rpc::call("estimate_cycles", json!([t]))?;
    let mut sources = Vec::new();
    let mut total = 0u64;
    for input in t["inputs"].as_array().ok_or("inputs")? {
        let point = &input["previous_output"];
        let cell = rpc::call("get_live_cell", json!([point, false]))?;
        if cell["status"] != "live" {
            return Err("candidate input is not initially live".into());
        }
        total = total
            .checked_add(capacity(&cell["cell"]["output"]["capacity"])?)
            .ok_or("input overflow")?;
        sources.push(json!({"out_point":point,"cell":cell}));
    }
    for output in t["outputs"].as_array().ok_or("outputs")? {
        total = total
            .checked_sub(capacity(&output["capacity"])?)
            .ok_or("negative fee")?;
    }
    Ok(
        json!({"fee_shannons":total,"wire_bytes":wire_bytes(t)?,"cycles":cycles,"transaction":t,"resolved_inputs":sources}),
    )
}
fn race(
    lab: &mut Lab,
    label: &str,
    txs: [Value; 2],
    victim_state: Option<CellOutPoint>,
    conflict: bool,
    delay: u64,
    ratio: u64,
) -> Result<Value, String> {
    let candidates = [metrics(&txs[0])?, metrics(&txs[1])?];
    let start = rpc::get_tip_block_number()?;
    let first = lab.attempt(&format!("{label}/adversary-first"), &txs[0])??;
    rpc::mine_blocks(delay)?;
    let state_live = victim_state.map(live).transpose()?;
    if !live(lab.wallets[1].point)? {
        return Err("victim funding consumed by adversary".into());
    }
    let second = lab.attempt(&format!("{label}/delayed-victim"), &txs[1])?;
    let mut committed = [false; 2];
    let hashes = [
        Some(first.as_str()),
        second.as_ref().ok().map(String::as_str),
    ];
    for _ in 0..20 {
        for i in 0..2 {
            committed[i] = hashes[i]
                .map(|h| rpc::get_transaction_status(h).map(|s| s.0 == "committed"))
                .transpose()?
                .unwrap_or(false);
        }
        if conflict && committed.iter().all(|v| *v) {
            return Err("conflicting transactions both committed".into());
        }
        if (conflict && committed.iter().any(|v| *v)) || (!conflict && committed.iter().all(|v| *v))
        {
            break;
        }
        rpc::mine_blocks(1)?;
    }
    if (!conflict && committed != [true, true]) || !committed.iter().any(|v| *v) {
        return Err(format!(
            "{label}: missing canonical admission {committed:?}"
        ));
    }
    let mut records = Vec::new();
    for i in 0..2 {
        if committed[i] {
            let hash = hashes[i].unwrap();
            lab.record_committed(&format!("{label}/actor-{i}-canonical"), hash)?;
            let packed = rpc::call("get_transaction", json!([hash, "0x0"]))?;
            let actual_bytes =
                rpc::decode_hex(packed["transaction"].as_str().ok_or("packed transaction")?)?.len();
            if actual_bytes != wire_bytes(&txs[i])? {
                return Err(format!("{label}: node wire size differs from candidate"));
            }

            records.push(
                json!({"actor":i,"hash":hash,"node_wire_bytes":actual_bytes,"view":rpc::call("get_transaction",json!([hash]))?}),
            );
            let outputs = txs[i]["outputs"].as_array().ok_or("outputs")?;
            lab.wallets[i].point = lab::point(hash, (outputs.len() - 1) as u32)?;
            lab.wallets[i].capacity = u64::from_str_radix(
                outputs.last().unwrap()["capacity"]
                    .as_str()
                    .ok_or("capacity")?
                    .trim_start_matches("0x"),
                16,
            )
            .map_err(|e| e.to_string())?;
        } else if !live(lab.wallets[i].point)? {
            return Err("loser funding is not live".into());
        }
    }
    let classification = if committed[1] {
        "victim_committed"
    } else if state_live == Some(false) {
        "stale_input"
    } else if second.is_err() {
        "live_pool_rejection"
    } else {
        "accepted_lost_conflict"
    };
    println!("{label}: {classification}, canonical={committed:?}");
    Ok(
        json!({"label":label,"delay_blocks":delay,"victim_fee_ratio":ratio,"shared_state_input":conflict,"victim_state_live_at_submit":state_live,"victim_funding_live_at_submit":true,"classification":classification,"adversary_committed":committed[0],"victim_committed":committed[1],"victim_submit_error":second.err(),"start_height":start,"end_height":rpc::get_tip_block_number()?,"candidates":candidates,"canonical":records}),
    )
}
fn run() -> Result<(), String> {
    let path = std::env::var("TACTUS_EVIDENCE_PATH").map_err(|_| "use isolated launcher")?;
    let density = match std::env::var("TACTUS_ADMISSION_FEES").as_deref() {
        Err(std::env::VarError::NotPresent) | Ok("absolute") => false,
        Ok("wire-density") => true,
        _ => return Err("TACTUS_ADMISSION_FEES must be absolute or wire-density".into()),
    };
    let mut lab = Lab::connect()?;
    let mut results = json!({"suite":"a123-matched-admission-v1","complete":false,"production_ready":false,"G2":"OPEN","scope":"admission-only; deterministic adversary-first schedule, two repeats; not stochastic fairness, forced execution or settlement"});
    results["fee_policy"] = json!(if density { "wire-density" } else { "absolute" });
    results["base_shannons_per_wire_byte"] = json!(density.then_some(SHANNONS_PER_BYTE));
    let outcome = (|| {
        let anchor =
            std::fs::read("artifacts/tactus_o1_anchor_script.elf").map_err(|e| e.to_string())?;
        let priority =
            std::fs::read("artifacts/tactus_o1_priority_script.elf").map_err(|e| e.to_string())?;
        let gate =
            std::fs::read("artifacts/tactus_o1_sealed_script.elf").map_err(|e| e.to_string())?;
        let priority_code = ckb_blake2b(&priority);
        let gate_code = ckb_blake2b(&gate);
        let deps = lab.publish_cells(
            "admission/deploy comparator programs",
            &[anchor.clone(), priority, gate],
            0,
            true,
        )?;
        lab.deps.extend(deps);
        let mut rows = Vec::new();
        for arm in [
            "A1-shared-head",
            "A2-independent-messages",
            "A3-one-lane",
            "A3-four-lanes-targeted",
            "A3-four-lanes-disjoint",
        ] {
            for delay in [0, 1, 3, 6] {
                for ratio in [1, 2, 10] {
                    for repeat in 0..2 {
                        let label = format!("{arm}/delay-{delay}/fee-{ratio}/repeat-{repeat}");
                        // Identical payload bytes and selected fee policy across arms. A1
                        // stores a commitment; the authenticated A2/A3 arms store bytes.
                        let payloads = [vec![0xa0; 64], vec![0xb1; 64]];
                        let (transactions, state, conflict) = if arm == "A1-shared-head" {
                            let head = lab.create_head(0)?;
                            let mut ts = Vec::new();
                            for (actor, payload) in payloads.iter().enumerate() {
                                let hash = ckb_blake2b(payload);
                                ts.push(priced(
                                    density,
                                    if actor == 0 { 1 } else { ratio },
                                    |fee| {
                                        lab.transition_tx(
                                            &head,
                                            lab::enqueue(&head, &hash),
                                            &hash,
                                            actor,
                                            fee,
                                            &[],
                                        )
                                    },
                                )?);
                            }
                            (ts.try_into().unwrap(), Some(head.point), true)
                        } else {
                            let n = if arm.contains("four-lanes") { 4 } else { 1 };
                            let net =
                                sealed::bootstrap_with_program(&mut lab, gate_code, n, &anchor)?;
                            if arm == "A2-independent-messages" {
                                (
                                    [
                                        priced(density, 1, |fee| {
                                            admitted(
                                                &lab,
                                                &net,
                                                &priority_code,
                                                0,
                                                payloads[0].clone(),
                                                fee,
                                            )
                                        })?,
                                        priced(density, ratio, |fee| {
                                            admitted(
                                                &lab,
                                                &net,
                                                &priority_code,
                                                1,
                                                payloads[1].clone(),
                                                fee,
                                            )
                                        })?,
                                    ],
                                    None,
                                    false,
                                )
                            } else {
                                let other = usize::from(arm.ends_with("disjoint"));
                                let mut ts = Vec::new();
                                for (actor, payload) in payloads.iter().enumerate() {
                                    let (cell, lane) =
                                        &net.lanes[if actor == 0 { 0 } else { other }];
                                    let next = lane
                                        .append(payload.clone())
                                        .map_err(|e| format!("{e:?}"))?;
                                    ts.push(priced(
                                        density,
                                        if actor == 0 { 1 } else { ratio },
                                        |fee| {
                                            sealed::shape_with_fee(
                                                &lab,
                                                actor,
                                                &[(cell.point, cell.capacity)],
                                                vec![cell.output(next.encode().unwrap())],
                                                &[],
                                                &[],
                                                fee,
                                            )
                                        },
                                    )?);
                                }
                                (
                                    ts.try_into().unwrap(),
                                    Some(net.lanes[other].0.point),
                                    other == 0,
                                )
                            }
                        };
                        let mut row = race(
                            &mut lab,
                            &label,
                            transactions,
                            state,
                            conflict,
                            delay,
                            ratio,
                        )?;
                        for (actor, candidate) in row["candidates"]
                            .as_array()
                            .ok_or("candidates")?
                            .iter()
                            .enumerate()
                        {
                            let factor = if actor == 0 { 1 } else { ratio };
                            let expected = if density {
                                candidate["wire_bytes"].as_u64().ok_or("wire size")?
                                    * SHANNONS_PER_BYTE
                                    * factor
                            } else {
                                TX_FEE * factor
                            };
                            if candidate["fee_shannons"] != expected {
                                return Err("resolved fee differs from policy".into());
                            }
                        }
                        row["arm"] = json!(arm);
                        row["repeat"] = json!(repeat);
                        rows.push(row);
                        // Retain partial evidence if a later case fails.
                        results["rows"] = json!(rows);
                    }
                }
            }
        }
        results["complete"] = json!(true);
        Ok::<_, String>(())
    })();
    results["error"] = json!(outcome.as_ref().err());
    lab.save(&path, results)?;
    outcome
}
fn main() {
    if let Err(e) = run() {
        eprintln!("ADMISSION EXPERIMENT FAILED: {e}");
        std::process::exit(1);
    }
}
