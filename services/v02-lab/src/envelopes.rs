//! Real-node admission of the maximum encoded Snapshot and NativeBatch.
use super::*;

pub fn run(lab: &mut Lab, dir: &Path) -> Result<Value> {
    let mut i = deploy(lab)?;
    let manifest = dir.join("deployment.json");
    fs::write(
        &manifest,
        serde_json::to_vec_pretty(&i.manifest).map_err(err)?,
    )
    .map_err(err)?;
    for lane in 0..4u64 {
        for _ in 0..8 {
            let old = i.cell(Role::Lane, lane)?;
            let c = i.cell(Role::Control, 0)?;
            let (next, receipt) = Lane::decode(&old.output.data)
                .map_err(err)?
                .enqueue(
                    &Control::decode(&c.output.data).map_err(err)?,
                    &i.policy,
                    vec![0xff; 1024],
                )
                .map_err(err)?;
            let tx = i.tx(
                lab,
                0,
                Operation::Enqueue,
                &[(old.clone(), 0)],
                vec![
                    build::typed(
                        &i.config,
                        Role::Lane,
                        lane,
                        next.encode().map_err(err)?,
                        Some(old.output.capacity),
                    )?,
                    build::typed(
                        &i.config,
                        Role::AdmissionReceipt,
                        receipt.sequence,
                        receipt.encode().map_err(err)?,
                        None,
                    )?,
                ],
                &[c.point],
                &[],
            )?;
            i.commit(lab, 0, "maximum-size priority admission", &tx)?;
        }
    }
    for _ in 0..32 {
        deposit(&mut i, lab, 0, 100_000_000)?;
    }
    let (snapshot, seal) = seal_tx(&i, lab, 0)?;
    if snapshot.encode().map_err(err)?.len() != Snapshot::MAX_BYTES {
        return Err("snapshot is not maximum size".into());
    }
    let seal_estimate = rpc::call("estimate_cycles", json!([seal]))?;
    i.commit(
        lab,
        0,
        "maximum encoded snapshot accepted on canonical CKB",
        &seal,
    )?;
    let anchor = i.cell(Role::Anchor, 0)?;
    let schedule = i.cell(Role::Schedule, 0)?;
    let c = i.cell(Role::Control, 0)?;
    let priority = snapshot.users().map_err(err)?[..4].to_vec();
    let mut deposits = vec![];
    let mut deps = vec![c.point, i.cell(Role::Snapshot, 1)?.point];
    for sequence in 1..=4 {
        let receipt = i.cell(Role::DepositReceipt, sequence)?;
        deposits.push(Deposit::decode(&receipt.output.data).map_err(err)?);
        deps.push(receipt.point);
    }
    let mut blocks = vec![
        tactus_o1_protocol::batch::BlockInput {
            timestamp: 100,
            fee_recipient: [22; 20],
            transactions: vec![]
        };
        16
    ];
    blocks[0].transactions = priority.iter().map(|p| p.message.payload.clone()).collect();
    let mut batch = NativeBatch {
        parent: Boundary::decode(&anchor.output.data).map_err(err)?,
        snapshot: snapshot.commitment().map_err(err)?,
        priority,
        deposits,
        blocks,
    };
    let mut remaining = NativeBatch::MAX_BYTES - batch.encode().map_err(err)?.len();
    while remaining > 4 {
        let mut size = 16384usize.min(remaining - 4);
        if (1..=4).contains(&(remaining - size - 4)) {
            size -= 4;
        }
        batch.blocks[0].transactions.push(vec![0xff; size]);
        remaining -= size + 4;
    }
    if remaining != 0 || batch.encode().map_err(err)?.len() != NativeBatch::MAX_BYTES {
        return Err("batch is not maximum size".into());
    }
    let since = (0x40 << 56) | 100;
    let (next, s) = batch
        .append(
            &i.config,
            &i.policy,
            &Control::decode(&c.output.data).map_err(err)?,
            &Schedule::decode(&schedule.output.data).map_err(err)?,
            &snapshot,
            since,
        )
        .map_err(err)?;
    let append = i.tx(
        lab,
        0,
        Operation::Append,
        &[(anchor.clone(), since), (schedule.clone(), 0)],
        vec![
            build::typed(
                &i.config,
                Role::Anchor,
                0,
                next.encode().map_err(err)?,
                Some(anchor.output.capacity),
            )?,
            build::typed(
                &i.config,
                Role::Schedule,
                0,
                s.encode().map_err(err)?,
                Some(schedule.output.capacity),
            )?,
            build::typed(
                &i.config,
                Role::Batch,
                1,
                batch.encode().map_err(err)?,
                None,
            )?,
            build::typed(
                &i.config,
                Role::Checkpoint,
                1,
                next.encode().map_err(err)?,
                None,
            )?,
        ],
        &deps,
        &[],
    )?;
    let append_estimate = rpc::call("estimate_cycles", json!([append]))?;
    i.commit(
        lab,
        0,
        "maximum encoded batch accepted on canonical CKB",
        &append,
    )?;
    let report = recover_cli(&manifest, &dir.join("envelope-report.json"), "report", None)?;
    if report["published_batches"] != 1
        || report["deposited_count"] != 32
        || report["settled_batches"] != 0
    {
        return Err("maximum envelope replay mismatch".into());
    }
    recover_cli(
        &manifest,
        &dir.join("envelope-proof-input.json"),
        "prove",
        Some("1"),
    )?;
    let result = json!({"schema":"tactus-v02-canonical-envelopes-v1","maximum_snapshot_bytes":Snapshot::MAX_BYTES,
        "maximum_batch_bytes":NativeBatch::MAX_BYTES,"batch_blocks":16,"priority_items":4,"deposits_in_batch":4,
        "total_admissions":32,"total_deposits":32,"seal_estimate":seal_estimate,"append_estimate":append_estimate,
        "seal_transaction":seal,"append_transaction":append,"recovery_pin":report["pinned_hash"],
        "scope":"maximum encoded byte envelopes, including direct code dependencies and standard fee signatures; malformed user payloads do not represent maximum EVM computation",
        "proof_generated":false,"zk_settlement":false,"production_ready":false});
    fs::write(
        dir.join("envelope-summary.json"),
        serde_json::to_vec_pretty(&result).map_err(err)?,
    )
    .map_err(err)?;
    Ok(result)
}
