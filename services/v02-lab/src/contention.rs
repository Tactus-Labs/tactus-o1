//! Isolated two-actor contention measurements; no fairness or proving guarantee.
use super::*;
use std::{
    sync::{Arc, Barrier},
    thread,
    time::{Duration, Instant},
};
use tactus_o1_devnet_driver::tx::TX_FEE;

fn admission(i: &Instance, lab: &Lab, actor: usize, payload: Vec<u8>, fee: u64) -> Result<Value> {
    let before = i.cell(Role::Lane, 0)?;
    let control = i.cell(Role::Control, 0)?;
    let (next, receipt) = Lane::decode(&before.output.data)
        .map_err(err)?
        .enqueue(
            &Control::decode(&control.output.data).map_err(err)?,
            &i.policy,
            payload,
        )
        .map_err(err)?;
    build::transaction_with_fee(
        lab,
        actor,
        &[(before.clone(), 0)],
        vec![
            build::typed(
                &i.config,
                Role::Lane,
                0,
                next.encode().map_err(err)?,
                Some(before.output.capacity),
            )?,
            build::typed(
                &i.config,
                Role::AdmissionReceipt,
                receipt.sequence,
                receipt.encode().map_err(err)?,
                None,
            )?,
        ],
        &i.deps(&[control.point])?,
        &[],
        Operation::Enqueue,
        &[],
        fee,
    )
}
/// Both transactions pass execution estimation at the same live head, then
/// compete through the actual node pool. Exactly one may consume that head.
fn race(
    i: &mut Instance,
    lab: &mut Lab,
    name: &str,
    txs: [Value; 2],
    delays: [u64; 2],
) -> Result<(usize, Value)> {
    let estimates = txs
        .iter()
        .map(|tx| rpc::call("estimate_cycles", json!([tx])))
        .collect::<Result<Vec<_>>>()?;
    let hashes = txs
        .iter()
        .map(|tx| tactus_v02_lab::recover::raw_hash(tx).map(|h| rpc::bytes_to_hex(&h)))
        .collect::<Result<Vec<_>>>()?;
    let barrier = Arc::new(Barrier::new(2));
    let start = Instant::now();
    let handles: Vec<_> = txs
        .iter()
        .enumerate()
        .map(|(actor, tx)| {
            let barrier = barrier.clone();
            let tx = tx.clone();
            let delay = delays[actor];
            thread::spawn(move || {
                barrier.wait();
                thread::sleep(Duration::from_millis(delay));
                let sent = start.elapsed().as_millis();
                let result = rpc::send_transaction_json(&tx);
                (result, sent, start.elapsed().as_millis())
            })
        })
        .collect();
    let submissions = handles
        .into_iter()
        .map(|h| h.join().map_err(|_| "submission thread panicked".into()))
        .collect::<Result<Vec<_>>>()?;
    for (actor, (result, _, _)) in submissions.iter().enumerate() {
        match result {
            Ok(hash) if hash == &hashes[actor] => {}
            Err(message)
                if ["Resolve(", "RBF", "Conflict", "conflict", "Duplicated"]
                    .iter()
                    .any(|s| message.contains(s)) => {}
            other => return Err(format!("unexpected contention submission: {other:?}")),
        }
    }
    let deadline = Instant::now() + Duration::from_secs(20);
    let winner = loop {
        let states = hashes
            .iter()
            .map(|hash| rpc::get_transaction_status(hash).map(|v| v.0))
            .collect::<Result<Vec<_>>>()?;
        let committed: Vec<_> = states
            .iter()
            .enumerate()
            .filter(|(_, state)| state.as_str() == "committed")
            .map(|(actor, _)| actor)
            .collect();
        if committed.len() > 1 {
            return Err("conflicting spends both committed".into());
        }
        if let Some(actor) = committed.first() {
            break *actor;
        }
        if Instant::now() >= deadline {
            return Err(format!("contention did not commit: {states:?}"));
        }
        rpc::mine_blocks(1)?;
        thread::sleep(Duration::from_millis(50));
    };
    lab.record_committed(name, &hashes[winner])?;
    let cells = build::outputs(&txs[winner], hash32(&json!(hashes[winner]))?)?;
    let change = cells.last().ok_or("race change")?;
    lab.wallets[winner].point = change.point;
    lab.wallets[winner].capacity = change.output.capacity;
    i.adopt(&txs[winner], &cells)?;
    let view = rpc::call("get_transaction", json!([hashes[winner]]))?;
    let row = json!({"name":name,"winner_actor":winner,"winner_tx":hashes[winner],"winner_block_hash":view["tx_status"]["block_hash"],
        "first_commit_elapsed_ms":start.elapsed().as_millis(),"delays_ms":delays,"pre_race_estimates":estimates,
        "submissions":submissions.iter().enumerate().map(|(actor,(result,sent,returned))|json!({"actor":actor,"hash":hashes[actor],"sent_ms":sent,"returned_ms":returned,
            "rpc_accepted":result.is_ok(),"error":result.as_ref().err(),"transaction":txs[actor]})).collect::<Vec<_>>()});
    lab.evidence
        .push(json!({"label":name,"result":"contention measured","measurement":row}));
    Ok((winner, row))
}
fn distribution(mut values: Vec<u128>) -> Value {
    values.sort_unstable();
    if values.is_empty() {
        return Value::Null;
    }
    json!({"samples":values.len(),"samples_ms":values,"min_ms":values[0],"median_ms":(values[(values.len()-1)/2] as f64+values[values.len()/2] as f64)/2.0,"p95_ms":values[(values.len()*95).div_ceil(100)-1],"max_ms":values[values.len()-1]})
}
pub fn run(lab: &mut Lab, dir: &Path) -> Result<Value> {
    let mut i = deploy(lab)?;
    let manifest = dir.join("deployment.json");
    fs::write(
        &manifest,
        serde_json::to_vec_pretty(&i.manifest).map_err(err)?,
    )
    .map_err(err)?;
    let mut rows = vec![];
    let mut admitted_wait = vec![];
    let scenarios = [
        ([TX_FEE, TX_FEE], [0, 0]),
        ([TX_FEE, TX_FEE], [0, 100]),
        ([TX_FEE, 3 * TX_FEE], [0, 100]),
        ([TX_FEE, 3 * TX_FEE], [100, 0]),
    ];
    for (round, (fees, delays)) in scenarios.into_iter().enumerate() {
        let started = Instant::now();
        let payloads = [vec![0xff, 0, round as u8], vec![0xff, 1, round as u8]];
        let txs = [
            admission(&i, lab, 0, payloads[0].clone(), fees[0])?,
            admission(&i, lab, 1, payloads[1].clone(), fees[1])?,
        ];
        let (winner, mut row) = race(
            &mut i,
            lab,
            &format!("same lane round {round}"),
            txs,
            delays,
        )?;
        let winner_wait = started.elapsed().as_millis();
        admitted_wait.push(winner_wait);
        row["winner_admitted_elapsed_ms"] = json!(winner_wait);
        let loser = 1 - winner;
        let retry = admission(&i, lab, loser, payloads[loser].clone(), fees[loser])?;
        let committed = i.commit(
            lab,
            loser,
            "contention loser rebuilt and re-signed admission",
            &retry,
        )?;
        let total = started.elapsed().as_millis();
        admitted_wait.push(total);
        row["fees_shannons"] = json!(fees.map(|f| f.to_string()));
        row["loser_retry_tx"] = json!(rpc::bytes_to_hex(&committed[0].point.tx_hash));
        row["loser_admitted_elapsed_ms"] = json!(total);
        rows.push(row);
    }
    let full = Lane::decode(&i.cell(Role::Lane, 0)?.output.data).map_err(err)?;
    if full.messages.len() != 8 || admission(&i, lab, 0, vec![0xff], TX_FEE).is_ok() {
        return Err("full lane admission bound failed".into());
    }
    let deposit_txs = [
        deposit_tx(&i, lab, 0, 100_000_000)?,
        deposit_tx(&i, lab, 1, 100_000_000)?,
    ];
    let (winner, mut vault_race) = race(
        &mut i,
        lab,
        "two deposits share one Vault",
        deposit_txs,
        [0, 0],
    )?;
    let loser = 1 - winner;
    let retry = deposit_tx(&i, lab, loser, 100_000_000)?;
    i.commit(
        lab,
        loser,
        "contention loser rebuilt and re-signed deposit",
        &retry,
    )?;
    vault_race["deposited_after_retry"] = json!(
        Vault::decode(&i.cell(Role::Vault, 0)?.output.data)
            .map_err(err)?
            .deposits
            .count
    );
    if vault_race["deposited_after_retry"] != 2 {
        return Err("deposit retry sequence mismatch".into());
    }
    let mut seal_races = vec![];
    for round in 0..2 {
        let before = Vault::decode(&i.cell(Role::Vault, 0)?.output.data)
            .map_err(err)?
            .deposits
            .count;
        let (candidate, seal) = seal_tx(&i, lab, 0)?;
        let deposit = deposit_tx(&i, lab, 1, 100_000_000)?;
        let delays = if round == 0 { [0, 100] } else { [100, 0] };
        let (winner, mut row) = race(
            &mut i,
            lab,
            &format!("seal and deposit round {round}"),
            [seal, deposit],
            delays,
        )?;
        let snapshot = if winner == 0 {
            let retry = deposit_tx(&i, lab, 1, 100_000_000)?;
            i.commit(lab, 1, "deposit rebuilt after competing seal", &retry)?;
            candidate
        } else {
            super::seal(&mut i, lab)?
        };
        let expected = before + u64::from(winner == 1);
        if snapshot.deposit_end.count != expected {
            return Err("competing seal used wrong deposit tail".into());
        }
        row["sealed_deposit_tail"] = json!(snapshot.deposit_end.count);
        row["deposit_count_after_retry"] = json!(before + 1);
        let sealed_at = Instant::now();
        for _ in 0..8 {
            let tx = append_tx(&i, lab, &snapshot, 100)?;
            i.commit(lab, 0, "contention sealed epoch publication", &tx)?;
        }
        row["eight_batch_publication_ms"] = json!(sealed_at.elapsed().as_millis());
        seal_races.push(row);
    }
    if seal_races[0]["winner_actor"] != 0 || seal_races[1]["winner_actor"] != 1 {
        return Err(
            "miner behavior did not exercise both seal/deposit orders; inspect evidence".into(),
        );
    }
    let report = recover_cli(
        &manifest,
        &dir.join("contention-report.json"),
        "report",
        None,
    )?;
    if report["published_batches"] != 16
        || report["settled_batches"] != 0
        || report["deposited_count"] != 4
    {
        return Err("contention replay report mismatch".into());
    }
    let result = json!({"schema":"tactus-v02-contention-v1","same_lane_races":rows,"vault_race":vault_race,"seal_deposit_races":seal_races,
        "admission_requests":8,"first_wave_committed":4,"first_wave_not_committed_fraction":0.5,"rebuilds_and_resignatures":4,
        "admission_wait_distribution":distribution(admitted_wait),"full_lane_build_refused":true,
        "canonical_recovery":report,"settlement_measured":false,"proof_generated":false,"g2_admission_fairness":"OPEN",
        "scope":"two local actors, four same-lane races, fees 1/3 CKB, 0/100ms submission delays, default CKB template mining; small sample does not establish adversarial fairness or production latency",
        "miner_policy":"CKB 0.210.0 default txpool and generate_block template, no custom fee selection","production_ready":false});
    fs::write(
        dir.join("contention-summary.json"),
        serde_json::to_vec_pretty(&result).map_err(err)?,
    )
    .map_err(err)?;
    Ok(result)
}
