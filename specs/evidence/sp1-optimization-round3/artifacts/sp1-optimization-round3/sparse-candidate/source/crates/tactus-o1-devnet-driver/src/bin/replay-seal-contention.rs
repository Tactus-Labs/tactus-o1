//! Repeated, freshly signed seal invalidation until valid active-queue churn exhausts.
use serde_json::{json, Value};
use std::{collections::BTreeSet, time::Instant};
use tactus_o1_devnet_driver::{
    lab::{self, Lab},
    rpc, sealed_lab as sealed, tx,
};
use tactus_o1_execution::{Executor, Genesis, Status};
use tactus_o1_ordering_script::ckb_blake2b;
use tactus_o1_protocol::sealed::{BATCHES_PER_EPOCH, MAX_LANE_MESSAGES};

fn payload(epoch: u64, lane: usize, index: usize) -> Vec<u8> {
    let mut bytes = vec![0; 64];
    bytes[1..9].copy_from_slice(&epoch.to_le_bytes());
    bytes[9] = lane as u8;
    bytes[10] = index as u8;
    bytes[11..19].copy_from_slice(b"SEAL0001");
    bytes
}
fn attack_append(
    lab: &mut Lab,
    net: &mut sealed::Network,
    targets: &[usize],
    label: &str,
) -> Result<(), String> {
    let mut outputs = vec![];
    let mut next = vec![];
    let mut inputs = vec![];
    for i in targets {
        let (cell, lane) = &net.lanes[*i];
        let state = lane
            .append(payload(lane.epoch, *i, lane.queue.len()))
            .map_err(|e| format!("{e:?}"))?;
        inputs.push((cell.point, cell.capacity));
        outputs.push(cell.output(state.encode().unwrap()));
        next.push(state);
    }
    let transaction = sealed::shape(lab, 0, &inputs, outputs, &[], &[])?;
    let hash = sealed::commit(lab, 0, label, &transaction)?;
    for (index, (lane, state)) in targets.iter().zip(next).enumerate() {
        net.lanes[*lane].0.point = lab::point(&hash, index as u32)?;
        net.lanes[*lane].1 = state;
    }
    Ok(())
}
fn reject_full_churn(lab: &mut Lab, net: &sealed::Network, label: &str) -> Result<(), String> {
    for (i, (cell, lane)) in net.lanes.iter().enumerate() {
        let mut overflow = cell.output(lane.encode().unwrap());
        overflow.data[121] = 9;
        overflow.data.extend_from_slice(&[1, 0, 7]);
        let mut cleared = lane.clone();
        cleared.epoch += 1;
        cleared.base_root = cleared.root;
        cleared.queue.clear();
        for (name, output, error) in [
            ("ninth admission", overflow, 3),
            ("no-op", cell.output(lane.encode().unwrap()), 12),
            (
                "unauthorized reset",
                cell.output(cleared.encode().unwrap()),
                7,
            ),
        ] {
            let transaction = sealed::shape(
                lab,
                0,
                &[(cell.point, cell.capacity)],
                vec![output],
                &[],
                &[],
            )?;
            sealed::reject(
                lab,
                &net.code,
                &format!("{label}/lane-{i}/{name}"),
                &transaction,
                "Inputs[0].Type",
                error,
            )?;
        }
    }
    Ok(())
}
fn scenario(lab: &mut Lab, code: [u8; 32], lanes: u8, all_at_once: bool) -> Result<Value, String> {
    let mode = if all_at_once {
        "all-lanes"
    } else {
        "one-lane-per-rebuild"
    };
    let stem = format!("seal-contention/{lanes}/{mode}");
    let mut net = sealed::bootstrap(lab, code, lanes)?;
    let genesis = Genesis {
        rollup_id: net.anchor.state.rollup_id.into(),
        chain_id: 31337,
        accounts: Default::default(),
    };
    let mut engine = Executor::new(&genesis).map_err(|e| e.to_string())?;
    for _ in 0..BATCHES_PER_EPOCH {
        sealed::advance(lab, &mut net, 1, &mut engine, &format!("{stem}/warmup"))?;
    }
    let mut epochs = vec![];
    let mut processed = BTreeSet::new();
    for epoch in 0..2 {
        if net.schedule.batches != BATCHES_PER_EPOCH || net.schedule.epoch != epoch {
            return Err("epoch is not ready for seal".into());
        }
        let start = rpc::get_tip_block_number()?;
        let start_batch = net.anchor.state.next_batch_number;
        let mut attempts = vec![];
        let clock = Instant::now();
        let count = MAX_LANE_MESSAGES * if all_at_once { 1 } else { lanes as usize };
        for attempt in 0..count {
            let built = rpc::get_tip_block_number()?;
            let build_clock = Instant::now();
            let (outputs, _, _, snapshot) = sealed::seal_outputs(&net)?;
            let transaction = sealed::seal_tx(lab, &net, 1, outputs, false)?;
            let build_us = build_clock.elapsed().as_micros();
            let cycles = rpc::call("estimate_cycles", json!([transaction]))?;
            let targets = if all_at_once {
                (0..lanes as usize).collect::<Vec<_>>()
            } else {
                vec![attempt % lanes as usize]
            };
            let prior = targets
                .iter()
                .map(|i| net.lanes[*i].0.point)
                .collect::<Vec<_>>();
            attack_append(
                lab,
                &mut net,
                &targets,
                &format!("{stem}/epoch-{epoch}/attempt-{attempt}/attacker admission"),
            )?;
            for point in prior {
                sealed::live(point, false)?;
            }
            sealed::live(net.gate.point, true)?;
            sealed::live(lab.wallets[1].point, true)?;
            lab.reject(
                &format!("{stem}/epoch-{epoch}/attempt-{attempt}/stale signed seal"),
                &transaction,
                "TransactionFailedToResolve",
            )?;
            attempts.push(json!({"attempt":attempt,"built_height":built,"rejected_height":rpc::get_tip_block_number()?,"target_lanes":targets,"snapshot_messages_when_signed":snapshot.lanes.iter().map(|l|l.queue.len()).sum::<usize>(),"candidate_cycles":cycles,"candidate_wire_bytes":tx::wire_bytes(&transaction)?,"candidate_build_us":build_us,"queues_after":net.lanes.iter().map(|(_,l)|l.queue.len()).collect::<Vec<_>>(),"funding_and_gate_remain_live":true}));
        }
        if net
            .lanes
            .iter()
            .any(|(_, l)| l.queue.len() != MAX_LANE_MESSAGES)
        {
            return Err("attack did not exhaust every lane".into());
        }
        reject_full_churn(lab, &net, &format!("{stem}/epoch-{epoch}/exhausted"))?;
        let before_seal = rpc::get_tip_block_number()?;
        sealed::seal(
            lab,
            &mut net,
            1,
            &format!("{stem}/epoch-{epoch}/rebuilt seal after exhausted churn"),
        )?;
        let sealed_height = rpc::get_tip_block_number()?;
        let snapshot = net.snapshot.as_ref().ok_or("snapshot missing")?.1.clone();
        if snapshot.lanes.iter().map(|l| l.queue.len()).sum::<usize>()
            != lanes as usize * MAX_LANE_MESSAGES
        {
            return Err("complete pending set missing from snapshot".into());
        }
        let mut messages = vec![];
        for step in 0..BATCHES_PER_EPOCH {
            let required = net
                .schedule
                .required(net.snapshot.as_ref().map(|(_, s)| s))
                .map_err(|e| format!("{e:?}"))?;
            let bytes = sealed::required_bytes(&net)?;
            let transaction =
                sealed::advance_tx(lab, &net, 1, sealed::advance_outputs(&net, &bytes)?)?;
            sealed::accept_advance(
                lab,
                &mut net,
                1,
                &bytes,
                &transaction,
                &format!("{stem}/epoch-{epoch}/process-{step}"),
            )?;
            let result = engine.apply_batch(&bytes).map_err(|e| e.to_string())?;
            let outcomes = result.iter().flat_map(|b| &b.outcomes).collect::<Vec<_>>();
            if outcomes.len() != required.len()
                || outcomes.iter().any(|o| o.status != Status::Malformed)
                || engine.anchor() != &net.anchor.state
            {
                return Err("execution or anchor mismatch".into());
            }
            for m in required {
                if m.payload.len() != 64 || !processed.insert(m.payload.clone()) {
                    return Err("missing or duplicate execution input".into());
                }
                let lane = m.payload[9] as usize;
                let position = m.payload[10] as usize;
                if m.payload != payload(epoch, lane, position)
                    || lane >= lanes as usize
                    || position >= MAX_LANE_MESSAGES
                {
                    return Err("unauthenticated attack message".into());
                }
                messages.push(json!({"lane":lane,"position":position,"processed_batch":net.anchor.state.next_batch_number,"batch_delay_from_admission":net.anchor.state.next_batch_number-start_batch}));
            }
        }
        if messages.len() != lanes as usize * MAX_LANE_MESSAGES
            || net.lanes.iter().any(|(_, l)| !l.queue.is_empty())
        {
            return Err("epoch did not drain the complete set".into());
        }
        epochs.push(json!({"epoch":epoch,"start_height":start,"sealed_height":sealed_height,"end_height":rpc::get_tip_block_number()?,"elapsed_host_seconds":clock.elapsed().as_secs_f64(),"legal_admissions":lanes as usize*MAX_LANE_MESSAGES,"invalidated_seals":attempts.len(),"maximum_independent_append_budget":lanes as usize*MAX_LANE_MESSAGES,"further_invalid_churn_rejections":lanes as usize*3,"final_seal_commit_delay_blocks":sealed_height-before_seal,"processed_messages":messages,"attempts":attempts,"settled":false}));
        println!("{stem}/epoch-{epoch}: {count} freshly signed seals invalidated; full set sealed and classified");
    }
    Ok(
        json!({"lanes":lanes,"mode":mode,"epochs":epochs,"distinct_processed_messages":processed.len(),"all_messages_processed_once":true,"settled":false}),
    )
}
fn run() -> Result<(), String> {
    let path = std::env::var("TACTUS_EVIDENCE_PATH").map_err(|_| "use isolated launcher")?;
    let mut lab = Lab::connect_with_script("artifacts/tactus_o1_anchor_script.elf")?;
    let mut results = json!({"suite":"seal-contention-v1","complete":false,"production_ready":false,"G2":"OPEN","cases":[],"scope":"freshly signed seal-vs-enqueue races for two consecutive epochs; finite canonical valid-append budget, not a miner inclusion guarantee or user admission fairness"});
    let outcome = (|| {
        let elf =
            std::fs::read("artifacts/tactus_o1_sealed_script.elf").map_err(|e| e.to_string())?;
        let code = ckb_blake2b(&elf);
        let deps = lab.publish_cells("seal-contention/deploy gate", &[elf], 0, true)?;
        lab.deps.extend(deps);
        for lanes in [1, 2, 4] {
            for all in [false, true] {
                let case = scenario(&mut lab, code, lanes, all)?;
                results["cases"].as_array_mut().unwrap().push(case);
                lab.save(&path, results.clone())?;
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
        eprintln!("SEAL CONTENTION FAILED: {e}");
        std::process::exit(1);
    }
}
