//! Canonical 32-item admission ceilings and permissionless recovery at both caps.
use super::*;

pub fn run(lab: &mut Lab, dir: &Path) -> Result<Value> {
    let mut i = deploy(lab)?;
    let manifest = dir.join("deployment.json");
    fs::write(
        &manifest,
        serde_json::to_vec_pretty(&i.manifest).map_err(err)?,
    )
    .map_err(err)?;
    for _ in 0..32 {
        deposit(&mut i, lab, 0, 100_000_000)?;
    }
    if deposit_tx(&i, lab, 0, 100_000_000).is_ok() {
        return Err("builder accepted 33rd unsettled deposit".into());
    }
    // Construct the exact otherwise valid successor, bypassing only the host's
    // admission guard, so the real script must enforce the ceiling itself.
    let old = i.cell(Role::Vault, 0)?;
    let mut next = Vault::decode(&old.output.data).map_err(err)?;
    let extra = Deposit {
        config: next.config,
        sequence: 33,
        recipient: owner().0 .0,
        amount: 100_000_000,
        refund_lock: hash(b"", &lab.wallets[0].key.lock_script()),
        cumulative: next.deposits.cumulative + 100_000_000,
        previous: next.deposits.accumulator,
    };
    next.deposits = next.deposits.follow(&extra).map_err(err)?;
    let bad = i.tx(
        lab,
        0,
        Operation::Deposit,
        &[(old, 0)],
        vec![
            build::typed(
                &i.config,
                Role::Vault,
                0,
                next.encode().map_err(err)?,
                Some(next.capacity().map_err(err)?),
            )?,
            build::typed(
                &i.config,
                Role::DepositReceipt,
                33,
                extra.encode().map_err(err)?,
                None,
            )?,
        ],
        &[i.cell(Role::Control, 0)?.point],
        &[],
    )?;
    reject_script(
        lab,
        "33rd unsettled deposit rejected by actual script",
        &bad,
        Error::Limit,
    )?;
    for _ in 0..4 {
        let snapshot = seal(&mut i, lab)?;
        for _ in 0..8 {
            let tx = append_tx(&i, lab, &snapshot, 100)?;
            i.commit(lab, 0, "publication while deposit backlog is full", &tx)?;
        }
    }
    // SEAL itself remains possible at the publication cap, but does not grant
    // another APPEND. Replaying constructs a valid 33rd successor for rejection.
    let snapshot = seal(&mut i, lab)?;
    if append_tx(&i, lab, &snapshot, 100).is_ok() {
        return Err("builder accepted 33rd unsettled batch".into());
    }
    let anchor = i.cell(Role::Anchor, 0)?;
    let schedule = i.cell(Role::Schedule, 0)?;
    let control = i.cell(Role::Control, 0)?;
    let batch = NativeBatch {
        parent: Boundary::decode(&anchor.output.data).map_err(err)?,
        snapshot: snapshot.commitment().map_err(err)?,
        priority: vec![],
        deposits: vec![],
        blocks: vec![tactus_o1_protocol::batch::BlockInput {
            timestamp: 100,
            fee_recipient: [22; 20],
            transactions: vec![],
        }],
    };
    let (next, next_schedule) = batch
        .replay(
            &i.config,
            &i.policy,
            &Schedule::decode(&schedule.output.data).map_err(err)?,
            &snapshot,
        )
        .map_err(err)?;
    let bad = i.tx(
        lab,
        0,
        Operation::Append,
        &[(anchor.clone(), (0x40 << 56) | 100), (schedule.clone(), 0)],
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
                next_schedule.encode().map_err(err)?,
                Some(schedule.output.capacity),
            )?,
            build::typed(
                &i.config,
                Role::Batch,
                33,
                batch.encode().map_err(err)?,
                None,
            )?,
            build::typed(
                &i.config,
                Role::Checkpoint,
                33,
                next.encode().map_err(err)?,
                None,
            )?,
        ],
        &[control.point, i.cell(Role::Snapshot, snapshot.epoch)?.point],
        &[],
    )?;
    reject_script(
        lab,
        "33rd unsettled batch rejected by actual script",
        &bad,
        Error::Limit,
    )?;
    let full = recover_cli(&manifest, &dir.join("full-report.json"), "report", None)?;
    if full["published_batches"] != 32
        || full["settled_batches"] != 0
        || full["deposited_count"] != 32
    {
        return Err("canonical full-backlog reconstruction mismatch".into());
    }
    let input = recover_cli(
        &manifest,
        &dir.join("full-proof-input.json"),
        "prove",
        Some("32"),
    )?;
    let mut journal_bytes =
        tactus_v02_lab::bytes(&input["expected_journal_hex"], Journal::MAX_BYTES)?;
    let journal = Journal::decode(&journal_bytes).map_err(err)?;
    journal_bytes.extend_from_slice(&0u32.to_le_bytes());
    let settle = i.tx(
        lab,
        0,
        Operation::Settle,
        &[(control.clone(), 0)],
        vec![build::typed(
            &i.config,
            Role::Control,
            0,
            journal.end.encode().map_err(err)?,
            Some(control.output.capacity),
        )?],
        &[i.cell(Role::Checkpoint, 32)?.point],
        &journal_bytes,
    )?;
    reject_script(
        lab,
        "SETTLE at both caps reaches proof verification",
        &settle,
        Error::Proof,
    )?;
    let receipt = i.cell(Role::DepositReceipt, 1)?;
    let ticket = watch(&mut i, lab, &receipt)?;
    rpc::mine_blocks(i.policy.stall_blocks + 1)?;
    let since = (0x80 << 56) | i.policy.stall_blocks;
    let frozen = Control::decode(&control.output.data)
        .map_err(err)?
        .freeze_candidate(
            &Watch::decode(&ticket.output.data).map_err(err)?,
            &i.policy,
            since,
            since,
        )
        .map_err(err)?;
    let freeze = i.tx(
        lab,
        1,
        Operation::Freeze,
        &[(control, since), (ticket.clone(), since)],
        vec![
            build::typed(
                &i.config,
                Role::Control,
                0,
                frozen.encode().map_err(err)?,
                Some(i.cell(Role::Control, 0)?.output.capacity),
            )?,
            OutSpec {
                capacity: ticket.output.capacity,
                lock: lab.wallets[0].key.lock_script(),
                type_script: None,
                data: vec![],
            },
        ],
        &[receipt.point],
        &1u32.to_le_bytes(),
    )?;
    i.commit(
        lab,
        1,
        "permissionless freeze at both backlog caps",
        &freeze,
    )?;
    // Rebuild with a fresh fee input so reuse fails on the consumed Control or
    // ticket, not merely a spent fee cell.
    let spent_ticket = i.tx(
        lab,
        1,
        Operation::CloseWatch,
        &[(ticket.clone(), 0)],
        vec![OutSpec {
            capacity: ticket.output.capacity,
            lock: lab.wallets[0].key.lock_script(),
            type_script: None,
            data: vec![],
        }],
        &[i.cell(Role::Control, 0)?.point],
        &0u32.to_le_bytes(),
    )?;
    reject_consensus(
        lab,
        "consumed freeze ticket cannot be reused",
        &spent_ticket,
        &format!("Unknown(OutPoint({}))", hx(&point_bytes(ticket.point))),
    )?;
    let plan = recover_cli(&manifest, &dir.join("refund-1.json"), "refund", Some("1"))?;
    let claim = ClaimWitness::decode(&tactus_v02_lab::bytes(
        &plan["claim_witness_hex"],
        ClaimWitness::MAX_BYTES,
    )?)
    .map_err(err)?;
    let old = i.cell(Role::Vault, 0)?;
    let vault = Vault::decode(&old.output.data).map_err(err)?;
    let record = Deposit::decode(&receipt.output.data).map_err(err)?;
    let c = i.cell(Role::Control, 0)?;
    let paid = claim
        .authorize(&Context {
            config: &i.config,
            policy: &i.policy,
            control: &frozen,
            control_outpoint: point_bytes(c.point),
            vault: &vault,
            receipt: Some((point_bytes(receipt.point), &record)),
        })
        .map_err(err)?;
    let lock = lab.wallets[0].key.lock_script();
    let tx = i.tx(
        lab,
        1,
        Operation::Refund,
        &[(old, 0)],
        vec![
            build::typed(
                &i.config,
                Role::Vault,
                0,
                paid.next.encode().map_err(err)?,
                Some(paid.next.capacity().map_err(err)?),
            )?,
            OutSpec {
                capacity: paid.amount.max(OutSpec::required_capacity(&lock, None, 0)),
                lock,
                type_script: None,
                data: vec![],
            },
        ],
        &[c.point, receipt.point],
        &claim.encode().map_err(err)?,
    )?;
    i.commit(
        lab,
        1,
        "fresh-process refund with both backlogs still full",
        &tx,
    )?;
    let final_report = recover_cli(&manifest, &dir.join("frozen-report.json"), "report", None)?;
    if final_report["mode"] != "FROZEN"
        || final_report["vault"] == full["vault"]
        || final_report["published_batches"] != 32
    {
        return Err("full-backlog refund recovery mismatch".into());
    }
    let result = json!({"schema":"tactus-v02-backpressure-v1", "canonical_deposits":32, "canonical_publications":32,
        "extra_deposit_script_rejected":true, "extra_publication_script_rejected":true, "seal_at_batch_cap":true,
        "settlement_at_caps_reached_proof_verifier":true, "watch_at_caps":true, "permissionless_freeze_at_caps":true,
        "fresh_process_refund_at_caps":true,"spent_ticket_rejected":true,"proof_generated":false,"zk_settlement":false,
        "release_positive":"requires settled state; synthetic VM positive is separate", "production_ready":false,
        "full_report":full,"final_report":final_report});
    fs::write(
        dir.join("backpressure-summary.json"),
        serde_json::to_vec_pretty(&result).map_err(err)?,
    )
    .map_err(err)?;
    Ok(result)
}
