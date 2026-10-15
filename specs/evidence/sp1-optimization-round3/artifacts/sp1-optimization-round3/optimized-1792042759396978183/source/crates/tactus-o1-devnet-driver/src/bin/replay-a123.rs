//! A1/A2/A3 CKB mechanism experiments. The evidence explicitly distinguishes
//! consensus measurements from absent priority/proof enforcement primitives.
use serde_json::{json, Value};
use tactus_o1_devnet_driver::{
    lab::{self, Head, Lab},
    rpc,
    tx::{OutSpec, TX_FEE},
};
use tactus_o1_ordering_script::ckb_blake2b;

fn output(head: &Head) -> OutSpec {
    OutSpec {
        capacity: head.capacity,
        lock: head.lock.clone(),
        type_script: Some(head.type_script.clone()),
        data: head.state.to_bytes().to_vec(),
    }
}

fn safety(lab: &mut Lab) -> Result<Value, String> {
    let mut head = lab.create_head(0)?;
    let message = ckb_blake2b(b"safety-message");
    let next = lab::enqueue(&head, &message);
    lab.advance(
        "safety/second independent key enqueues",
        &mut head,
        next,
        &message,
        1,
        &[],
    )?;
    let batch = ckb_blake2b(b"safety-batch");
    let next = lab::append(&head, &batch);
    let good = Head {
        state: next,
        ..head.clone()
    };
    for (label, outputs, code) in [
        ("burn", vec![], 8),
        ("split", vec![output(&good), output(&good)], 8),
        (
            "lock takeover",
            vec![OutSpec {
                lock: lab.wallets[1].key.lock_script(),
                ..output(&good)
            }],
            10,
        ),
        (
            "capacity drain",
            vec![OutSpec {
                capacity: head.capacity - TX_FEE,
                ..output(&good)
            }],
            10,
        ),
        (
            "remove type",
            vec![OutSpec {
                type_script: None,
                ..output(&good)
            }],
            8,
        ),
    ] {
        let transaction = lab.shaped_tx(&head, 1, outputs, Some(&batch))?;
        lab.reject(
            &format!("safety/{label}"),
            &transaction,
            &format!("error code {code}"),
        )?;
    }
    for (label, mutated, code) in [
        (
            "genesis policy mutation",
            {
                let mut n = next;
                n.da_policy_id = [8; 32];
                n
            },
            3,
        ),
        (
            "cursor beyond tail",
            {
                let mut n = next;
                n.processed_inbox_cursor = 2;
                n
            },
            9,
        ),
        (
            "skipped batch number",
            {
                let mut n = next;
                n.next_batch_number += 1;
                n
            },
            5,
        ),
        (
            "wrong accumulator",
            {
                let mut n = next;
                n.batch_accumulator_root = [8; 32];
                n
            },
            5,
        ),
    ] {
        let transaction = lab.transition_tx(&head, mutated, &batch, 1, TX_FEE, &[])?;
        lab.reject(
            &format!("safety/{label}"),
            &transaction,
            &format!("error code {code}"),
        )?;
    }
    let transaction = lab.shaped_tx(&head, 1, vec![output(&good)], None)?;
    lab.reject("safety/missing commitment", &transaction, "error code 2")?;
    lab.advance(
        "safety/valid append after rejected mutations",
        &mut head,
        next,
        &batch,
        0,
        &[],
    )?;
    // Attempt to re-create this identity from a different genesis seed.
    let wallet = &lab.wallets[1];
    let change = wallet.capacity - head.capacity - TX_FEE;
    let mut recreated = head.clone();
    recreated.state.next_batch_number = 0;
    recreated.state.batch_accumulator_root = [0; 32];
    recreated.state.inbox_root = [0; 32];
    recreated.state.inbox_tail = 0;
    let (_, transaction) = tactus_o1_devnet_driver::tx::build_and_sign(
        &wallet.key,
        &lab.secp,
        &lab.deps,
        &[(wallet.point, wallet.capacity)],
        &[
            output(&recreated),
            OutSpec {
                capacity: change,
                lock: wallet.key.lock_script(),
                type_script: None,
                data: vec![],
            },
        ],
        None,
    )?;
    lab.reject(
        "safety/recreate existing identity",
        &transaction,
        "error code 6",
    )?;
    Ok(
        json!({"negative_cases":11,"independent_actor_enqueue":true,"accepted_invalid_transitions":0}),
    )
}

fn a1(lab: &mut Lab) -> Result<Value, String> {
    let mut rows = Vec::new();
    for delay in [0, 1, 3, 6] {
        for fee_ratio in [1, 2, 10] {
            let mut stats = json!({"delay_blocks":delay,"fee_ratio":fee_ratio,"attempts":0,"wallet_commits":0,"builder_commits":0,"stale":0,"pool_rejections":0});
            for sample in 0..2 {
                let head = lab.create_head(0)?;
                let batch =
                    ckb_blake2b(format!("a1/{delay}/{fee_ratio}/{sample}/batch").as_bytes());
                let message =
                    ckb_blake2b(format!("a1/{delay}/{fee_ratio}/{sample}/message").as_bytes());
                let builder =
                    lab.transition_tx(&head, lab::append(&head, &batch), &batch, 0, TX_FEE, &[])?;
                let wallet = lab.transition_tx(
                    &head,
                    lab::enqueue(&head, &message),
                    &message,
                    1,
                    fee_ratio * TX_FEE,
                    &[],
                )?;
                let builder_hash = lab.attempt("A1/builder broadcasts first", &builder)??;
                rpc::mine_blocks(delay)?;
                // Record liveness of both inputs before wallet broadcast; fee input is independent.
                let live = |p: lab::Head| {
                    rpc::call(
                        "get_live_cell",
                        json!([{"tx_hash":rpc::bytes_to_hex(&p.point.tx_hash),"index":format!("0x{:x}",p.point.index)},false]),
                    )
                };
                let head_live = live(head.clone())?["status"] == "live";
                let funding = lab.wallets[1].point;
                let funding_live = rpc::call(
                    "get_live_cell",
                    json!([{"tx_hash":rpc::bytes_to_hex(&funding.tx_hash),"index":format!("0x{:x}",funding.index)},false]),
                )?["status"]
                    == "live";
                if !funding_live {
                    return Err("A1 wallet funding unexpectedly spent".into());
                }
                let wallet_result = lab.attempt("A1/delayed wallet broadcasts", &wallet)?;
                if !head_live {
                    stats["stale"] = json!(stats["stale"].as_u64().unwrap() + 1);
                } else if wallet_result.is_err() {
                    stats["pool_rejections"] =
                        json!(stats["pool_rejections"].as_u64().unwrap() + 1);
                }
                let mut winner = None;
                for _ in 0..20 {
                    let bc = rpc::get_transaction_status(&builder_hash)?.0 == "committed";
                    let wc = if let Ok(hash) = &wallet_result {
                        rpc::get_transaction_status(hash)?.0 == "committed"
                    } else {
                        false
                    };
                    if bc && wc {
                        return Err("A1 double spend committed".into());
                    }
                    if bc {
                        winner = Some((0, builder_hash.clone(), TX_FEE));
                        break;
                    }
                    if wc {
                        winner = Some((
                            1,
                            wallet_result.as_ref().unwrap().clone(),
                            fee_ratio * TX_FEE,
                        ));
                        break;
                    }
                    rpc::mine_blocks(1)?;
                }
                let (actor, hash, fee) =
                    winner.ok_or("A1 no canonical winner within 20 generated blocks")?;
                lab.record_committed("A1/canonical winner", &hash)?;
                lab.wallets[actor].point = lab::point(&hash, 1)?;
                lab.wallets[actor].capacity -= fee;
                let field = if actor == 0 {
                    "builder_commits"
                } else {
                    "wallet_commits"
                };
                stats[field] = json!(stats[field].as_u64().unwrap() + 1);
                stats["attempts"] = json!(stats["attempts"].as_u64().unwrap() + 1);
            }
            println!("A1 {stats}");
            rows.push(stats);
        }
    }
    Ok(
        json!({"rows":rows,"decision":"KeepA1AsReferenceOnly","scope":"deterministic first-broadcast and signing-delay schedule; 2 samples per cell, not a stochastic estimate"}),
    )
}

fn a2(lab: &mut Lab) -> Result<Value, String> {
    let mut head = lab.create_head(0)?;
    let messages: Vec<Vec<u8>> = (0..8)
        .map(|i| format!("A2 independent message {i}").into_bytes())
        .collect();
    let cells = lab.publish_cells("A2/independent admission baseline", &messages, 1, false)?;
    let start = rpc::get_tip_block_number()?;
    for i in 0..8 {
        let batch = ckb_blake2b(format!("A2/hostile-empty-batch/{i}").as_bytes());
        let next = lab::append(&head, &batch);
        lab.advance(
            "A2/hostile builder omits all messages",
            &mut head,
            next,
            &batch,
            0,
            &[],
        )?;
    }
    let end = rpc::get_tip_block_number()?;
    let mut remaining = 0;
    for p in &cells {
        let status = rpc::call(
            "get_live_cell",
            json!([{"tx_hash":rpc::bytes_to_hex(&p.tx_hash),"index":format!("0x{:x}",p.index)},false]),
        )?;
        remaining += u64::from(status["status"] == "live");
    }
    if remaining != 8 || head.state.processed_inbox_cursor != 0 {
        return Err("A2 omission control was not exercised".into());
    }
    Ok(
        json!({"admitted":8,"still_unconsumed":remaining,"canonical_batches_while_omitting":8,
        "observation_blocks":end-start,"forced_processing":0,"decision":"G2NotPassed",
        "scope":"independent-cell baseline only; typed obligation, challenge and validity-proof enforcement are absent",
        "consumed_but_unproven":"not tested; no settlement verifier implemented",
        "production_candidate_complete":false}),
    )
}

fn a3(lab: &mut Lab) -> Result<Value, String> {
    let mut rows = Vec::new();
    for lanes in [1, 2, 4] {
        for regime in [
            "no-churn",
            "L1-per-lane",
            "L2-fixed-aggregate",
            "L3-targeted",
        ] {
            for sealed in [false, true] {
                let mut heads = Vec::new();
                for _ in 0..lanes {
                    heads.push(lab.create_head(0)?);
                }
                let anchor = lab.create_head(0)?;
                let refs = if sealed {
                    let data: Vec<Vec<u8>> =
                        heads.iter().map(|h| h.state.to_bytes().to_vec()).collect();
                    lab.publish_cells("A3/immutable snapshot control", &data, 0, true)?
                } else {
                    heads.iter().map(|h| h.point).collect()
                };
                let batch = ckb_blake2b(format!("A3/{lanes}/{regime}/{sealed}").as_bytes());
                let transaction = lab.transition_tx(
                    &anchor,
                    lab::append(&anchor, &batch),
                    &batch,
                    1,
                    TX_FEE,
                    &refs,
                )?;
                let updates = match regime {
                    "no-churn" => 0,
                    "L1-per-lane" => lanes,
                    _ => 1,
                };
                let start = rpc::get_tip_block_number()?;
                for (i, head) in heads.iter_mut().take(updates).enumerate() {
                    let msg = ckb_blake2b(format!("A3/churn/{i}").as_bytes());
                    let next = lab::enqueue(head, &msg);
                    lab.advance(
                        "A3/valid lane update during anchor construction",
                        head,
                        next,
                        &msg,
                        0,
                        &[],
                    )?;
                }
                let survive = sealed || updates == 0;
                if survive {
                    let hash = lab.commit("A3/anchor survives", &transaction)?;
                    lab.wallets[1].point = lab::point(&hash, 1)?;
                    lab.wallets[1].capacity -= TX_FEE;
                } else {
                    lab.reject(
                        "A3/stale lane dependency invalidates anchor",
                        &transaction,
                        "TransactionFailedToResolve",
                    )?;
                }
                rows.push(json!({"lanes":lanes,"regime":regime,"sealed":sealed,"updates":updates,
                    "elapsed_blocks":rpc::get_tip_block_number()?-start,"anchor_survived":survive,
                    "decision":if sealed {"ConditionalEnforcementPrimitiveUnimplemented"}else if survive {"ControlPassed"}else{"RejectLiveHeadDependencyStrategy"}}));
            }
        }
    }
    Ok(
        json!({"rows":rows,"scope":"live-cell dependency mechanics; immutable copies have no enforced provenance or snapshot-switch deadline",
        "mandatory_processing_delay":null,"production_candidate_complete":false}),
    )
}

fn reorg_recovery(lab: &mut Lab) -> Result<Value, String> {
    // IntegrationTest truncate is exclusively for this disposable chain.
    if std::env::var("TACTUS_DEVNET_AUTOMINE").as_deref() != Ok("1") {
        return Err("reorg test requires the isolated automined laboratory".into());
    }
    rpc::require_devnet()?;
    let mut head = lab.create_head(0)?;
    let initial = head.clone();
    let parent = rpc::call("get_tip_header", json!([]))?;
    let fund = lab.wallets[0].point;
    let capacity = lab.wallets[0].capacity;
    let message = ckb_blake2b(b"orphaned-message");
    let next = lab::enqueue(&head, &message);
    lab.advance("reorg/branch to orphan", &mut head, next, &message, 0, &[])?;
    let orphan = head.point;
    let orphan_tip = rpc::get_tip_block_number()?;
    rpc::call("truncate", json!([parent["hash"]]))?;
    lab.wallets[0].point = fund;
    lab.wallets[0].capacity = capacity;
    head = initial.clone();
    let (recovered, state) = tactus_o1_devnet_driver::recovery::recover_head(&head.type_script)?;
    if recovered != initial.point || state != initial.state {
        return Err("recovery did not roll back orphaned branch".into());
    }
    let batch = ckb_blake2b(b"alternative-canonical-batch");
    let next = lab::append(&head, &batch);
    lab.advance(
        "reorg/alternative canonical branch",
        &mut head,
        next,
        &batch,
        1,
        &[],
    )?;
    let (recovered, state) = tactus_o1_devnet_driver::recovery::recover_head(&head.type_script)?;
    if recovered != head.point || state != head.state {
        return Err("canonical recovery mismatch".into());
    }
    let result = json!({"rolled_back_blocks":orphan_tip-u64::from_str_radix(parent["number"].as_str().unwrap().trim_start_matches("0x"),16).unwrap(),
        "orphan_transaction":rpc::bytes_to_hex(&orphan.tx_hash),"canonical_transaction":rpc::bytes_to_hex(&head.point.tx_hash),
        "recovered_from_canonical_blocks":true,"operator_snapshot_used":false,
        "scope":"planned local truncate/rebuild; no network partition or competing-PoW reorg; ordering state only, not EVM recovery"});
    lab.evidence.push(
        json!({"label":"reorg/canonical recovery","result":"control_passed","details":result}),
    );
    Ok(result)
}

fn run() -> Result<(), String> {
    let evidence_path = std::env::var("TACTUS_EVIDENCE_PATH")
        .unwrap_or_else(|_| "artifacts/a123-evidence.json".into());
    let mut lab = Lab::connect()?;
    let mut results = json!({"complete":false,"G1":"OPEN","G2":"OPEN","production_ready":false});
    let outcome = (|| {
        results["safety"] = safety(&mut lab)?;
        lab.save(&evidence_path, results.clone())?;
        results["A1"] = a1(&mut lab)?;
        lab.save(&evidence_path, results.clone())?;
        results["A2"] = a2(&mut lab)?;
        lab.save(&evidence_path, results.clone())?;
        results["A3"] = a3(&mut lab)?;
        results["reorg_recovery"] = reorg_recovery(&mut lab)?;
        results["complete"] = json!(true);
        Ok::<_, String>(())
    })();
    results["error"] = json!(outcome.as_ref().err());
    lab.save(&evidence_path, results)?;
    outcome
}
fn main() {
    if let Err(error) = run() {
        eprintln!("A123 FAILED: {error}");
        std::process::exit(1);
    }
}
