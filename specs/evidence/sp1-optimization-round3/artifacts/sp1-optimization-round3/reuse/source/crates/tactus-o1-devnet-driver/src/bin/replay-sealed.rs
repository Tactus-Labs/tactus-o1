//! Real A3 mandatory gate: authenticated complete seals, immutable dependencies,
//! bounded mandatory prefixes, hostile switching and planned rollback.
use serde_json::{json, Value};
use tactus_o1_devnet_driver::sealed_lab::*;
use tactus_o1_devnet_driver::{
    batch_lab,
    lab::{self, Lab},
    rpc,
    tx::OutSpec,
};
use tactus_o1_execution::{Executor, Genesis};
use tactus_o1_ordering_script::ckb_blake2b;
use tactus_o1_protocol::{
    batch,
    sealed::{self as s, Lane, Schedule, Snapshot},
};
// This decoder only consumes a just-executed observer's stdout. A saved JSON
// view is never accepted as a replacement for canonical recovery.
fn recovered_network(v: &Value) -> Result<Network, String> {
    use tactus_o1_devnet_driver::{batch_lab::Anchor, tx::CellOutPoint};
    use tactus_o1_protocol::batch::AnchorState;
    fn bytes(v: &Value) -> Result<Vec<u8>, String> {
        rpc::decode_hex(v.as_str().ok_or("observer bytes")?)
    }
    fn point(v: &Value) -> Result<CellOutPoint, String> {
        lab::point(
            v["tx_hash"].as_str().ok_or("observer point")?,
            u32::from_str_radix(
                v["index"]
                    .as_str()
                    .ok_or("observer index")?
                    .trim_start_matches("0x"),
                16,
            )
            .map_err(|e| e.to_string())?,
        )
    }
    fn cell(v: &Value) -> Result<Cell, String> {
        Ok(Cell {
            point: point(&v["point"])?,
            capacity: u64::from_str_radix(
                v["capacity"]
                    .as_str()
                    .ok_or("observer capacity")?
                    .trim_start_matches("0x"),
                16,
            )
            .map_err(|e| e.to_string())?,
            script: bytes(&v["type_script"])?,
            lock: bytes(&v["lock"])?,
        })
    }
    let ac = cell(&v["anchor"])?;
    Ok(Network {
        code: bytes(&v["code_hash"])?
            .try_into()
            .map_err(|_| "observer code hash length")?,
        anchor: Anchor {
            point: ac.point,
            capacity: ac.capacity,
            script: ac.script,
            lock: ac.lock,
            state: AnchorState::decode(&bytes(&v["anchor"]["data"])?)
                .map_err(|e| format!("{e:?}"))?,
            immutable: bytes(&v["anchor_immutable_lock"])?,
        },
        gate: cell(&v["gate"])?,
        schedule: Schedule::decode(&bytes(&v["gate"]["data"])?).map_err(|e| format!("{e:?}"))?,
        lanes: v["lanes"]
            .as_array()
            .ok_or("observer lanes")?
            .iter()
            .map(|v| {
                Ok((
                    cell(v)?,
                    Lane::decode(&bytes(&v["data"])?).map_err(|e| format!("{e:?}"))?,
                ))
            })
            .collect::<Result<_, String>>()?,
        snapshot: if v["snapshot"].is_null() {
            None
        } else {
            Some((
                point(&v["snapshot"]["point"])?,
                Snapshot::decode(&bytes(&v["snapshot"]["data"])?).map_err(|e| format!("{e:?}"))?,
            ))
        },
    })
}
fn observer(lab: &mut Lab, net: &mut Network, label: &str) -> Result<Value, String> {
    let chain = rpc::call("get_block_hash", json!(["0x0"]))?;
    let binary = std::env::current_exe()
        .map_err(|e| e.to_string())?
        .with_file_name("recover-sealed");
    let result = std::process::Command::new(binary)
        .arg(chain.as_str().ok_or("chain hash")?)
        .arg(rpc::bytes_to_hex(&net.gate.script))
        .arg(rpc::bytes_to_hex(&net.anchor.script))
        .output()
        .map_err(|e| e.to_string())?;
    if !result.status.success() {
        return Err(format!(
            "observer failed: {}",
            String::from_utf8_lossy(&result.stderr)
        ));
    }
    let report: Value = serde_json::from_slice(&result.stdout).map_err(|e| e.to_string())?;
    if report["network"] != tactus_o1_devnet_driver::sealed_recovery::network_view(net) {
        return Err("cold A3 recovery differs from publisher state".into());
    }
    *net = recovered_network(&report["network"])?;
    lab.evidence
        .push(json!({"label":label,"result":"control_passed","observer":report}));
    println!("{label}: independent recovery matched");
    Ok(report)
}
fn observer_wrong_domain(lab: &mut Lab, net: &Network) -> Result<(), String> {
    let chain = rpc::call("get_block_hash", json!(["0x0"]))?
        .as_str()
        .ok_or("chain hash")?
        .to_owned();
    let binary = std::env::current_exe()
        .map_err(|e| e.to_string())?
        .with_file_name("recover-sealed");
    let mut bad_gate = net.gate.script.clone();
    *bad_gate.last_mut().unwrap() ^= 1;
    let mut bad_anchor = net.anchor.script.clone();
    *bad_anchor.last_mut().unwrap() ^= 1;
    for (label, chain, gate, anchor, expected) in [
        (
            "wrong CKB chain",
            rpc::bytes_to_hex(&[0; 32]),
            net.gate.script.clone(),
            net.anchor.script.clone(),
            "CKB genesis hash mismatch",
        ),
        (
            "wrong gate identity",
            chain.clone(),
            bad_gate,
            net.anchor.script.clone(),
            "anchor predates named gate genesis",
        ),
        (
            "wrong anchor identity",
            chain,
            net.gate.script.clone(),
            bad_anchor,
            "gate genesis missing named anchor",
        ),
    ] {
        let result = std::process::Command::new(&binary)
            .arg(chain)
            .arg(rpc::bytes_to_hex(&gate))
            .arg(rpc::bytes_to_hex(&anchor))
            .output()
            .map_err(|e| e.to_string())?;
        let error = String::from_utf8_lossy(&result.stderr).to_string();
        if result.status.success() || !error.contains(expected) {
            return Err(format!("observer {label}: unexpected result {error}"));
        }
        lab.evidence.push(json!({"label":format!("sealed/observer rejects {label}"),"result":"control_passed","expected_error":expected,"error":error}));
    }
    Ok(())
}
fn scenario(lab: &mut Lab, code: [u8; 32], n: u8) -> Result<Value, String> {
    let mut net = bootstrap(lab, code, n)?;
    observer(lab, &mut net, "sealed/cold genesis observer")?;
    if n == 1 {
        observer_wrong_domain(lab, &net)?;
    }
    let genesis = Genesis {
        rollup_id: net.anchor.state.rollup_id.into(),
        chain_id: 31337,
        accounts: Default::default(),
    };
    let mut engine = Executor::new(&genesis).map_err(|e| e.to_string())?;
    // Every scenario separately verifies the mandatory anchor lock boundary.
    let raw = bytes(&net, vec![])?;
    let summary = batch::validate_batch(&raw, &net.anchor.state).unwrap();
    let omitted = shape(
        lab,
        1,
        &[(net.anchor.point, net.anchor.capacity)],
        vec![
            batch_lab::head_output(&net.anchor, summary.next),
            batch_lab::da_output(&net.anchor, &raw),
        ],
        &[(0, 1u32.to_le_bytes().to_vec())],
        &[],
    )?;
    reject(
        lab,
        &code,
        "sealed/anchor cannot omit schedule input",
        &omitted,
        "Inputs[0].Lock",
        7,
    )?;
    let burn = shape(
        lab,
        1,
        &[(net.gate.point, net.gate.capacity)],
        vec![],
        &[],
        &[],
    )?;
    reject(
        lab,
        &code,
        "sealed/schedule cannot be burned",
        &burn,
        "Inputs[0].Type",
        2,
    )?;
    let (outputs, _, _, _) = seal_outputs(&net)?;
    let early = seal_tx(lab, &net, 1, outputs, false)?;
    reject(
        lab,
        &code,
        "sealed/epoch cannot switch early",
        &early,
        "Inputs[0].Type",
        14,
    )?;
    let mut output = net.gate.output(net.schedule.encode().unwrap());
    output.lock = lab.wallets[1].key.lock_script();
    let tx = shape(
        lab,
        1,
        &[(net.gate.point, net.gate.capacity)],
        vec![output],
        &[],
        &[],
    )?;
    reject(
        lab,
        &code,
        "sealed/schedule lock cannot be replaced",
        &tx,
        "Inputs[0].Type",
        5,
    )?;
    let mut output = net.gate.output(net.schedule.encode().unwrap());
    output.capacity -= 1;
    let tx = shape(
        lab,
        1,
        &[(net.gate.point, net.gate.capacity)],
        vec![output],
        &[],
        &[],
    )?;
    reject(
        lab,
        &code,
        "sealed/schedule capacity cannot be drained",
        &tx,
        "Inputs[0].Type",
        5,
    )?;
    let tx = shape(
        lab,
        1,
        &[(net.gate.point, net.gate.capacity)],
        vec![
            net.gate.output(net.schedule.encode().unwrap()),
            net.gate.output(net.schedule.encode().unwrap()),
        ],
        &[],
        &[],
    )?;
    reject(
        lab,
        &code,
        "sealed/schedule cannot be split",
        &tx,
        "Inputs[0].Type",
        12,
    )?;
    // A lane append signed before an unrelated batch remains valid: admission
    // does not read or consume the mutable schedule.
    let (pending, next_lane) = append_tx(lab, &net, 0, 0, vec![2, 0, 0])?;
    advance(
        lab,
        &mut net,
        1,
        &mut engine,
        "sealed/batch advances while lane admission is pending",
    )?;
    let hash = commit(
        lab,
        0,
        "sealed/pre-signed lane admission survives schedule change",
        &pending,
    )?;
    net.lanes[0] = (
        Cell {
            point: lab::point(&hash, 0)?,
            ..net.lanes[0].0.clone()
        },
        next_lane,
    );
    for i in 0..usize::from(n) {
        while net.lanes[i].1.queue.len() < 3 {
            let seq = net.lanes[i].1.next_sequence;
            append(
                lab,
                &mut net,
                i,
                0,
                vec![2, i as u8, seq as u8],
                "sealed/fill initial snapshot lanes",
            )?;
        }
    }
    let (c, _) = &net.lanes[0];
    let counterfeit = shape(
        lab,
        1,
        &[],
        vec![c.output(
            Lane::genesis(net.schedule.gate, 0)
                .unwrap()
                .encode()
                .unwrap(),
        )],
        &[],
        &[],
    )?;
    reject(
        lab,
        &code,
        "sealed/cannot recreate a lane without fresh gate genesis",
        &counterfeit,
        "Outputs[0].Type",
        7,
    )?;
    let (c, old) = &net.lanes[0];
    let tx = shape(
        lab,
        0,
        &[(c.point, c.capacity)],
        vec![c.output(old.encode().unwrap())],
        &[],
        &[],
    )?;
    reject(
        lab,
        &code,
        "sealed/partially filled lane cannot churn with no-op",
        &tx,
        "Inputs[0].Type",
        16,
    )?;
    let (lane_cell, old_lane) = &net.lanes[0];
    let cleared = Lane {
        epoch: old_lane.epoch + 1,
        base_root: old_lane.root,
        queue: vec![],
        ..old_lane.clone()
    };
    let tx = shape(
        lab,
        0,
        &[(lane_cell.point, lane_cell.capacity)],
        vec![lane_cell.output(cleared.encode().unwrap())],
        &[],
        &[],
    )?;
    reject(
        lab,
        &code,
        "sealed/lane queue cannot reset without seal authorization",
        &tx,
        "Inputs[0].Type",
        7,
    )?;
    while net.schedule.batches < s::BATCHES_PER_EPOCH {
        advance(lab, &mut net, 1, &mut engine, "sealed/genesis epoch batch")?;
    }
    let raw = bytes(&net, vec![])?;
    let stale = advance_tx(lab, &net, 1, advance_outputs(&net, &raw)?)?;
    reject(
        lab,
        &code,
        "sealed/ninth batch must wait for seal",
        &stale,
        "Inputs[1].Type",
        14,
    )?;
    let (mut outputs, _, _, _) = seal_outputs(&net)?;
    outputs.remove(usize::from(n));
    let missing = seal_tx(lab, &net, 1, outputs, true)?;
    reject(
        lab,
        &code,
        "sealed/cannot omit configured lane at switch",
        &missing,
        "Inputs[0].Type",
        8,
    )?;
    let (mut outputs, _, _, _) = seal_outputs(&net)?;
    *outputs.last_mut().unwrap().data.last_mut().unwrap() ^= 1;
    let forged = seal_tx(lab, &net, 1, outputs, false)?;
    reject(
        lab,
        &code,
        "sealed/snapshot bytes must equal authentic lane history",
        &forged,
        "Inputs[0].Type",
        9,
    )?;
    let (mut outputs, _, _, _) = seal_outputs(&net)?;
    outputs.last_mut().unwrap().lock = lab.wallets[1].key.lock_script();
    let output = outputs.last_mut().unwrap();
    output.capacity = OutSpec::required_capacity(&output.lock, None, output.data.len());
    let mutable = seal_tx(lab, &net, 1, outputs, false)?;
    reject(
        lab,
        &code,
        "sealed/snapshot retention lock is mandatory",
        &mutable,
        "Inputs[0].Type",
        5,
    )?;
    let (mut outputs, _, _, _) = seal_outputs(&net)?;
    let raw = bytes(&net, vec![])?;
    let summary = batch::validate_batch(&raw, &net.anchor.state).unwrap();
    outputs.push(batch_lab::head_output(&net.anchor, summary.next));
    outputs.push(batch_lab::da_output(&net.anchor, &raw));
    let mut inputs = vec![(net.gate.point, net.gate.capacity)];
    inputs.extend(net.lanes.iter().map(|(c, _)| (c.point, c.capacity)));
    inputs.push((net.anchor.point, net.anchor.capacity));
    let mut operation = vec![0];
    operation.extend_from_slice(&(u32::from(n) + 1).to_le_bytes());
    let tx = shape(
        lab,
        1,
        &inputs,
        outputs,
        &[
            (0, operation),
            (
                usize::from(n) + 1,
                (u32::from(n) + 3).to_le_bytes().to_vec(),
            ),
        ],
        &[],
    )?;
    reject(
        lab,
        &code,
        "sealed/seal cannot disguise an unmetered anchor advance",
        &tx,
        "Inputs[0].Type",
        10,
    )?;
    seal(lab, &mut net, 1, "sealed/authenticated complete first seal")?;
    let first_snapshot = net.snapshot.clone().unwrap();
    let snapshot_view = rpc::call(
        "get_live_cell",
        json!([{"tx_hash":rpc::bytes_to_hex(&first_snapshot.0.tx_hash),"index":format!("0x{:x}",first_snapshot.0.index)},true]),
    )?;
    let snapshot_capacity = u64::from_str_radix(
        snapshot_view["cell"]["output"]["capacity"]
            .as_str()
            .ok_or("snapshot capacity")?
            .trim_start_matches("0x"),
        16,
    )
    .map_err(|e| e.to_string())?;
    let tx = shape(
        lab,
        0,
        &[(first_snapshot.0, snapshot_capacity)],
        vec![],
        &[],
        &[],
    )?;
    reject(
        lab,
        &code,
        "sealed/published snapshot cannot be destroyed",
        &tx,
        "Inputs[0].Lock",
        1,
    )?;
    // A counterfeit snapshot published by anyone cannot replace the gate's hash.
    let mut wrong = first_snapshot.1.clone();
    wrong.epoch += 1;
    for lane in &mut wrong.lanes {
        lane.epoch = wrong.epoch;
    }
    let false_dep = lab.publish_cells(
        "sealed/publish unrelated snapshot bytes",
        &[wrong.encode().unwrap()],
        0,
        true,
    )?[0];
    let valid = required_bytes(&net)?;
    let mut fake = net.clone();
    fake.snapshot = Some((false_dep, wrong));
    let fake_tx = advance_tx(lab, &fake, 1, advance_outputs(&net, &valid)?)?;
    reject(
        lab,
        &code,
        "sealed/unrelated dependency is not the authenticated snapshot",
        &fake_tx,
        "Inputs[1].Type",
        9,
    )?;
    let omitted_bytes = bytes(&net, vec![])?;
    let skip = advance_tx(lab, &net, 1, advance_outputs(&net, &omitted_bytes)?)?;
    reject(
        lab,
        &code,
        "sealed/builder cannot skip mandatory prefix",
        &skip,
        "Inputs[1].Type",
        15,
    )?;
    let mut reversed = net
        .schedule
        .required(net.snapshot.as_ref().map(|(_, s)| s))
        .unwrap()
        .into_iter()
        .map(|m| m.payload)
        .collect::<Vec<_>>();
    reversed.swap(0, 1);
    let bad = bytes(&net, reversed)?;
    let reorder = advance_tx(lab, &net, 1, advance_outputs(&net, &bad)?)?;
    reject(
        lab,
        &code,
        "sealed/builder cannot reorder mandatory prefix",
        &reorder,
        "Inputs[1].Type",
        15,
    )?;
    let mut tx = advance_tx(lab, &net, 1, advance_outputs(&net, &valid)?)?;
    tx["witnesses"][1] = json!(rpc::bytes_to_hex(&vec![0; 4096]));
    reject(
        lab,
        &code,
        "sealed/witness allocation has an executable byte bound",
        &tx,
        "Inputs[1].Type",
        12,
    )?;
    let prepared = advance_tx(lab, &net, 1, advance_outputs(&net, &valid)?)?;
    let victim = vec![2, 0xfe, n, 7];
    let admitted_at = net.anchor.state.next_batch_number;
    for i in 0..usize::from(n) {
        for position in 0..s::MAX_LANE_MESSAGES {
            let payload = if i == usize::from(n) - 1 && position == s::MAX_LANE_MESSAGES - 1 {
                victim.clone()
            } else {
                vec![2, 0xfd, i as u8, position as u8]
            };
            append(
                lab,
                &mut net,
                i,
                0,
                payload,
                "sealed/churn active heads up to finite queue bound",
            )?;
        }
    }
    // Finite queues disallow another valid mutation; build an unchanged-head
    // transaction to ensure a no-op cannot sustain endless seal invalidation.
    let (full_cell, full_lane) = &net.lanes[0];
    let mut oversized = full_cell.output(full_lane.encode().unwrap());
    oversized.data[121] = 9;
    oversized.data.extend_from_slice(&[1, 0, 7]);
    let tx = shape(
        lab,
        0,
        &[(full_cell.point, full_cell.capacity)],
        vec![oversized],
        &[],
        &[],
    )?;
    reject(
        lab,
        &code,
        "sealed/full lane refuses a ninth admission",
        &tx,
        "Inputs[0].Type",
        3,
    )?;
    let (c, lane) = &net.lanes[0];
    let noop = shape(
        lab,
        0,
        &[(c.point, c.capacity)],
        vec![c.output(lane.encode().unwrap())],
        &[],
        &[],
    )?;
    reject(
        lab,
        &code,
        "sealed/full lane cannot churn with no-op",
        &noop,
        "Inputs[0].Type",
        12,
    )?;
    accept_advance(
        lab,
        &mut net,
        1,
        &valid,
        &prepared,
        "sealed/pre-signed batch survives all active-lane churn",
    )?;
    engine.apply_batch(&valid).map_err(|e| e.to_string())?;
    live(first_snapshot.0, true)?;
    while net.schedule.batches < s::BATCHES_PER_EPOCH {
        advance(
            lab,
            &mut net,
            1,
            &mut engine,
            "sealed/process frozen epoch without changing active lanes",
        )?;
    }
    let raw = bytes(&net, vec![])?;
    let extend = advance_tx(lab, &net, 1, advance_outputs(&net, &raw)?)?;
    reject(
        lab,
        &code,
        "sealed/processed snapshot cannot be retained indefinitely",
        &extend,
        "Inputs[1].Type",
        14,
    )?;
    observer(lab, &mut net, "sealed/cold observer before rollback branch")?;
    let stable = net.clone();
    let stable_engine = engine.clone();
    let wallets: Vec<_> = lab.wallets.iter().map(|w| (w.point, w.capacity)).collect();
    let parent = rpc::call("get_tip_header", json!([]))?;
    seal(lab, &mut net, 0, "sealed/planned orphan second seal")?;
    let orphan = net.snapshot.as_ref().unwrap().0;
    advance(
        lab,
        &mut net,
        1,
        &mut engine,
        "sealed/planned orphan first priority batch",
    )?;
    let orphan_report = observer(
        lab,
        &mut net,
        "sealed/cold observer sees orphan seal and batch",
    )?;
    rpc::require_devnet()?;
    rpc::call("truncate", json!([parent["hash"]]))?;
    net = stable;
    engine = stable_engine;
    if tactus_o1_devnet_driver::recovery::assert_canonical(
        orphan_report["pinned_height"]
            .as_u64()
            .ok_or("observer height")?,
        orphan_report["pinned_hash"]
            .as_str()
            .ok_or("observer hash")?,
    )
    .is_ok()
    {
        return Err("orphan observer prefix still considered canonical".into());
    }
    observer(
        lab,
        &mut net,
        "sealed/cold observer restores canonical queues after rollback",
    )?;
    for (wallet, (point, capacity)) in lab.wallets.iter_mut().zip(wallets) {
        wallet.point = point;
        wallet.capacity = capacity;
    }
    for (c, _) in &net.lanes {
        live(c.point, true)?;
    }
    live(orphan, false)?;
    live(net.gate.point, true)?;
    seal(
        lab,
        &mut net,
        1,
        "sealed/other actor reseals restored active heads",
    )?;
    let second_snapshot = net.snapshot.clone().unwrap();
    let mut previous = net.clone();
    previous.snapshot = Some(first_snapshot.clone());
    let raw = required_bytes(&net)?;
    let outdated = advance_tx(lab, &previous, 1, advance_outputs(&net, &raw)?)?;
    reject(
        lab,
        &code,
        "sealed/old snapshot rejected after mandatory switch",
        &outdated,
        "Inputs[1].Type",
        9,
    )?;
    let mut processed_at = None;
    let mut observed = Vec::new();
    for _ in 0..s::BATCHES_PER_EPOCH {
        let duty = net
            .schedule
            .required(net.snapshot.as_ref().map(|(_, s)| s))
            .unwrap();
        if duty.iter().any(|m| m.payload == victim) {
            processed_at = Some(net.anchor.state.next_batch_number + 1);
        }
        observed.extend(duty.iter().map(|m| (m.lane, m.sequence)));
        advance(
            lab,
            &mut net,
            1,
            &mut engine,
            "sealed/mandatory processing of post-seal messages",
        )?;
    }
    let elapsed = processed_at.ok_or("post-seal victim never processed")? - admitted_at;
    let expected = second_snapshot
        .1
        .ordered()
        .unwrap()
        .iter()
        .map(|m| (m.lane, m.sequence))
        .collect::<Vec<_>>();
    if observed != expected || elapsed > 16 {
        return Err("mandatory processing bound/order violated".into());
    }
    live(first_snapshot.0, true)?;
    live(second_snapshot.0, true)?;
    if engine.anchor() != &net.anchor.state {
        return Err("execution/anchor diverged".into());
    }
    let mut maximum_payload_snapshot_bytes = None;
    if n == 4 {
        for index in 0..4 {
            for _ in 0..s::MAX_LANE_MESSAGES {
                append(
                    lab,
                    &mut net,
                    index,
                    0,
                    vec![0xff; s::MAX_PAYLOAD_BYTES],
                    "sealed/admit maximum-size active payload",
                )?;
            }
        }
        seal(
            lab,
            &mut net,
            1,
            "sealed/seal maximum 33385-byte authenticated snapshot",
        )?;
        let length = net.snapshot.as_ref().unwrap().1.encode().unwrap().len();
        if length != s::MAX_SNAPSHOT_BYTES {
            return Err("maximum snapshot shape mismatch".into());
        }
        maximum_payload_snapshot_bytes = Some(length);
        for _ in 0..s::BATCHES_PER_EPOCH {
            advance(
                lab,
                &mut net,
                1,
                &mut engine,
                "sealed/process maximum snapshot with bounded prefixes",
            )?;
        }
    }
    let final_report = observer(
        lab,
        &mut net,
        "sealed/cold observer reconstructs final pending state",
    )?;
    rpc::mine_blocks(1)?;
    tactus_o1_devnet_driver::recovery::assert_canonical(
        final_report["pinned_height"]
            .as_u64()
            .ok_or("observer height")?,
        final_report["pinned_hash"]
            .as_str()
            .ok_or("observer hash")?,
    )?;
    let result = json!({"cold_observer_reconstructions":5,"cold_recovery_drives_reseal":true,"orphan_observer_prefix_rejected":true,"ordinary_tip_growth_accepted":true,"lanes":n,"maximum_payload_snapshot_bytes":maximum_payload_snapshot_bytes,"canonical_batches":net.anchor.state.next_batch_number,"post_seal_victim_batches_to_inclusion":elapsed,"second_snapshot_messages":observed.len(),"consumed_snapshot_messages":net.schedule.cursor,"active_churn_mutations":usize::from(n)*s::MAX_LANE_MESSAGES,"snapshot_retention":true,"planned_seal_and_batch_reorg_recovered":true,"independent_sealer":true,"pre_signed_batch_survived_churn":true,"pre_signed_admission_survived_schedule_change":true,"execution_head":engine.head(),"G2":"OPEN","scope":"Mandatory publication under canonical batch progress; no wall-clock, admission fairness or validity-proof claim"});
    lab.evidence.push(json!({"label":format!("sealed/{n} lanes/verified outcome"),"result":"control_passed","outcome":result}));
    Ok(result)
}
fn run() -> Result<(), String> {
    let path = std::env::var("TACTUS_EVIDENCE_PATH").map_err(|_| "use isolated launcher")?;
    let mut lab = Lab::connect_with_script("artifacts/tactus_o1_anchor_script.elf")?;
    let mut results = json!({"suite":"a3-mandatory-sealed-gate-v1","complete":false,"production_ready":false,"G2":"OPEN","proof_settlement":"NOT_IMPLEMENTED"});
    let outcome = (|| {
        let elf =
            std::fs::read("artifacts/tactus_o1_sealed_script.elf").map_err(|e| e.to_string())?;
        let code = ckb_blake2b(&elf);
        lab.metadata["sealed_code_hash"] = json!(rpc::bytes_to_hex(&code));
        let dep = lab.publish_cells(
            "sealed/deploy immutable gate and lane program",
            &[elf],
            0,
            true,
        )?[0];
        lab.deps.push(dep);
        let mut scenarios = Vec::new();
        for n in [1, 2, 4] {
            scenarios.push(scenario(&mut lab, code, n)?);
        }
        results["scenarios"] = json!(scenarios);
        results["complete"] = json!(true);
        Ok::<_, String>(())
    })();
    results["error"] = json!(outcome.as_ref().err());
    lab.save(&path, results)?;
    outcome
}
fn main() {
    if let Err(error) = run() {
        eprintln!("SEALED EXPERIMENT FAILED: {error}");
        std::process::exit(1);
    }
}
