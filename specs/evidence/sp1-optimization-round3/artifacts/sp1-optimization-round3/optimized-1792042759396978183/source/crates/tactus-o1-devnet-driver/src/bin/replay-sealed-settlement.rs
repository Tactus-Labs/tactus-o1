//! Authenticated A3 publication composed with an atomic real SettlementTip.
//! Preparation is explicitly unproved; optional qualification consumes only a real proof.
#[path = "replay-sealed-settlement/observer.rs"]
mod observer;
#[path = "replay-sealed-settlement/proof_reorg.rs"]
mod proof_reorg;
#[path = "replay-sealed-settlement/reorg.rs"]
mod reorg;
#[path = "replay-sealed-settlement/state_proof.rs"]
mod state_proof;
use serde_json::{json, Value};
use std::{fs, path::PathBuf};
use tactus_o1_devnet_driver::{
    lab::{self, Lab},
    molecule, recovery, rpc, sealed_lab as sealed, sealed_recovery,
    settlement_lab::{advance_tip, cold_recovery, consumed_tip, framed, read, reject, tip_data},
    tx::{self, CellOutPoint, OutSpec},
};
use tactus_o1_execution::{Executor, Genesis, Status};
use tactus_o1_ordering_script::ckb_blake2b;
use tactus_o1_protocol::{
    batch::{self, AnchorState, BatchInput},
    genesis,
};

fn number(v: &Value) -> Result<u64, String> {
    u64::from_str_radix(v.as_str().ok_or("number")?.trim_start_matches("0x"), 16)
        .map_err(|e| e.to_string())
}
fn point(p: CellOutPoint) -> Value {
    json!({"tx_hash":rpc::bytes_to_hex(&p.tx_hash),"index":format!("0x{:x}",p.index)})
}
fn cold_gate(chain: &[u8], net: &sealed::Network) -> Result<Value, String> {
    let output = std::process::Command::new("target/debug/recover-sealed")
        .args([
            rpc::bytes_to_hex(chain),
            rpc::bytes_to_hex(&net.gate.script),
            rpc::bytes_to_hex(&net.anchor.script),
        ])
        .output()
        .map_err(|e| e.to_string())?;
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).into_owned());
    }
    let report: Value = serde_json::from_slice(&output.stdout).map_err(|e| e.to_string())?;
    if report["network"] != sealed_recovery::network_view(net) {
        return Err("cold gate state differs".into());
    }
    Ok(report)
}
fn cold_obligations(
    chain: &[u8],
    net: &sealed::Network,
    tip: &[u8],
    expected: &str,
) -> Result<Value, String> {
    let output = std::process::Command::new("target/debug/recover-obligations")
        .args([
            rpc::bytes_to_hex(chain),
            rpc::bytes_to_hex(&net.gate.script),
            rpc::bytes_to_hex(&net.anchor.script),
            rpc::bytes_to_hex(tip),
        ])
        .output()
        .map_err(|e| e.to_string())?;
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).into_owned());
    }
    let report: Value = serde_json::from_slice(&output.stdout).map_err(|e| e.to_string())?;
    let rows = report["obligations"]
        .as_array()
        .ok_or("recovered obligations")?;
    let settled = expected == "settled";
    if rows.len() != 4
        || report["admissions"] != 4
        || report["counts"][expected] != 4
        || rows
            .iter()
            .any(|row| row["proof_settled"] != settled || row["status"] != expected)
    {
        return Err("cold obligation lifecycle differs".into());
    }
    let invalid = rows
        .iter()
        .find(|row| row["payload"] == "0x01")
        .ok_or("missing malformed duty")?;
    if matches!(expected, "published" | "settled")
        && (invalid["outcome"]["status"] != "Malformed"
            || invalid["publication"]["input_slot"] != 2)
    {
        return Err("cold recovery lost malformed obligation".into());
    }
    Ok(report)
}
fn run() -> Result<(), String> {
    let evidence = std::env::var("TACTUS_EVIDENCE_PATH").map_err(|_| "use isolated launcher")?;
    let root = PathBuf::from(std::env::var("TACTUS_RUN_DIR").map_err(|_| "run directory")?);
    let mut lab = Lab::connect_with_script("artifacts/tactus_o1_anchor_script.elf")?;
    let mut result = json!({"suite":"sealed-settlement-input-v1","complete":false,"settled":false,
        "production_ready":false,"withdrawal_authority":false,"G2":"OPEN","G3":"OPEN"});
    let outcome = (|| {
        let anchor_elf = lab.ordering_elf.clone();
        let gate_elf =
            fs::read("artifacts/tactus_o1_sealed_script.elf").map_err(|e| e.to_string())?;
        let checkpoint_elf = fs::read("artifacts/tactus_o1_history_checkpoint_script.elf")
            .map_err(|e| e.to_string())?;
        let settlement_elf =
            fs::read("artifacts/tactus_o1_settlement_script.elf").map_err(|e| e.to_string())?;
        let gate_code = ckb_blake2b(&gate_elf);
        let checkpoint_code = ckb_blake2b(&checkpoint_elf);
        let settlement_code = ckb_blake2b(&settlement_elf);
        let dependencies = lab.publish_cells(
            "sealed-settlement/deploy immutable programs",
            &[gate_elf, checkpoint_elf, settlement_elf],
            0,
            true,
        )?;
        lab.deps.extend(dependencies);
        let fixture: Value = serde_json::from_str(include_str!(
            "../../../../specs/test-vectors/execution-v1/geth-1.17.8.json"
        ))
        .map_err(|e| e.to_string())?;
        let case = &fixture["cases"][0];
        let mut genesis: Genesis =
            serde_json::from_value(case["genesis"].clone()).map_err(|e| e.to_string())?;
        let fixture_parent = AnchorState::genesis(
            genesis.rollup_id.0,
            tactus_o1_execution::rules_hash(),
            genesis.chain_id,
        )
        .map_err(|e| format!("{e:?}"))?;
        let fixture_batch = BatchInput::decode(
            &rpc::decode_hex(case["batch"].as_str().ok_or("fixture batch")?)?,
            &fixture_parent,
        )
        .map_err(|e| format!("{e:?}"))?;
        let signed = &fixture_batch.blocks[0].transactions;
        if signed.len() != 3 {
            return Err("expected three signed transfers".into());
        }
        let allocation = genesis.allocation_bytes().map_err(|e| e.to_string())?;
        let allocation_hash = genesis::commitment(&allocation).map_err(|e| format!("{e:?}"))?;
        let chain = rpc::decode_hex(
            rpc::call("get_block_hash", json!(["0x0"]))?
                .as_str()
                .ok_or("chain")?,
        )?;
        let core: Value = serde_json::from_str(include_str!(
            "../../../../specs/evidence/execution-core-proof/result.json"
        ))
        .map_err(|e| e.to_string())?;
        let guest_key = rpc::decode_hex(core["guest_verifying_key"].as_str().ok_or("key")?)?;
        let lock_code = ckb_blake2b(&lab.lock_elf);
        let mut settlement_script = Vec::new();
        let mut initial = Vec::new();
        let mut tip_capacity = 0;
        let mut net = sealed::bootstrap_with_auxiliary(
            &mut lab,
            gate_code,
            2,
            &anchor_elf,
            &allocation,
            |anchor| {
                let mut config = b"TO1CFG01".to_vec();
                for field in [
                    &chain[..],
                    &ckb_blake2b(&anchor.script)[..],
                    &guest_key[..],
                    &checkpoint_code[..],
                    &allocation_hash[..],
                ] {
                    config.extend_from_slice(field);
                }
                settlement_script = molecule::script(&settlement_code, 2, &config);
                initial = tip_data(&anchor.state, false, &[0; 32], &[0; 32]);
                let lock = molecule::script(&lock_code, 2, &ckb_blake2b(&settlement_script));
                tip_capacity =
                    OutSpec::required_capacity(&lock, Some(&settlement_script), initial.len());
                Ok(vec![OutSpec {
                    capacity: tip_capacity,
                    lock,
                    type_script: Some(settlement_script.clone()),
                    data: initial.clone(),
                }])
            },
        )?;
        let initial_point = CellOutPoint {
            tx_hash: net.anchor.point.tx_hash,
            index: 5,
        };
        genesis.rollup_id = net.anchor.state.rollup_id.into();
        let mut engine = Executor::new(&genesis).map_err(|e| e.to_string())?;
        let before = *engine.anchor();
        let previous_state = engine.state_root();
        let previous_header = engine.head().hash_slow();
        let genesis_tip = cold_recovery(&chain, &net.anchor.script, &settlement_script)?;
        if genesis_tip["initialized"] != false || genesis_tip["tip"] != point(initial_point) {
            return Err("atomic Tip genesis not recovered".into());
        }
        for (lane, actor, payload, label) in [
            (
                0,
                0,
                signed[0].clone(),
                "sealed-settlement/admit nonce zero",
            ),
            (1, 1, signed[1].clone(), "sealed-settlement/admit nonce one"),
            (0, 0, vec![1], "sealed-settlement/admit malformed input"),
            (1, 1, signed[2].clone(), "sealed-settlement/admit nonce two"),
        ] {
            sealed::append(&mut lab, &mut net, lane, actor, payload, label)?;
        }
        result["cold_obligations_after_admission"] =
            cold_obligations(&chain, &net, &settlement_script, "admitted")?;
        for batch in 0..8 {
            sealed::advance(
                &mut lab,
                &mut net,
                0,
                &mut engine,
                &format!("sealed-settlement/genesis epoch batch {batch}"),
            )?;
        }
        let reorg_plan = if std::env::var_os("TACTUS_OBLIGATION_REORG").is_some() {
            Some(reorg::prepare(&lab)?)
        } else {
            None
        };
        sealed::seal(
            &mut lab,
            &mut net,
            1,
            "sealed-settlement/seal both authenticated lanes",
        )?;
        result["cold_obligations_after_seal"] =
            cold_obligations(&chain, &net, &settlement_script, "sealed")?;
        let messages = net
            .schedule
            .required(net.snapshot.as_ref().map(|(_, s)| s))
            .map_err(|e| format!("{e:?}"))?;
        let payloads: Vec<_> = messages.iter().map(|m| m.payload.clone()).collect();
        if payloads
            != [
                signed[0].clone(),
                signed[1].clone(),
                vec![1],
                signed[2].clone(),
            ]
        {
            return Err("wrong sealed FIFO ordering".into());
        }
        for (label, altered) in [
            ("sealed-settlement/omit forced inputs", Vec::new()),
            (
                "sealed-settlement/reorder forced inputs",
                vec![
                    payloads[1].clone(),
                    payloads[0].clone(),
                    payloads[2].clone(),
                    payloads[3].clone(),
                ],
            ),
            (
                "sealed-settlement/drop malformed obligation",
                vec![
                    payloads[0].clone(),
                    payloads[1].clone(),
                    payloads[3].clone(),
                ],
            ),
        ] {
            let bytes = sealed::bytes(&net, altered)?;
            let tx = sealed::advance_tx(&lab, &net, 0, sealed::advance_outputs(&net, &bytes)?)?;
            sealed::reject(&mut lab, &gate_code, label, &tx, "Inputs[1].Type", 15)?;
        }
        let bytes = sealed::required_bytes(&net)?;
        let after = batch::validate_batch(&bytes, &net.anchor.state)
            .map_err(|e| format!("{e:?}"))?
            .next;
        let checkpoint_script =
            molecule::script(&checkpoint_code, 2, &ckb_blake2b(&net.anchor.script));
        let lock = lab.wallets[0].key.lock_script();
        let mut outputs = sealed::advance_outputs(&net, &bytes)?;
        outputs.push(OutSpec {
            capacity: OutSpec::required_capacity(&lock, Some(&checkpoint_script), 200),
            lock,
            type_script: Some(checkpoint_script),
            data: after.encode().to_vec(),
        });
        let publication = sealed::advance_tx(&lab, &net, 0, outputs)?;
        sealed::accept_advance(
            &mut lab,
            &mut net,
            0,
            &bytes,
            &publication,
            "sealed-settlement/mandatory publication and typed checkpoint",
        )?;
        let executed = engine.apply_batch(&bytes).map_err(|e| e.to_string())?;
        let block = executed.first().ok_or("executed block")?;
        if block.outcomes.len() != 4
            || block.outcomes.iter().map(|o| o.status).collect::<Vec<_>>()
                != [
                    Status::Success,
                    Status::Success,
                    Status::Malformed,
                    Status::Success,
                ]
            || block.transactions.len() != 3
            || block.receipts.len() != 3
        {
            return Err("forced execution outcomes differ".into());
        }
        let published = net.anchor.point;
        let checkpoint = CellOutPoint {
            tx_hash: published.tx_hash,
            index: 3,
        };
        lab.deps.push(checkpoint);
        let recovered = recovery::recover_published_batches(&net.anchor.script)?;
        if recovered.batches.len() != 9
            || recovered.state != *engine.anchor()
            || recovered.genesis_allocation != allocation
        {
            return Err("canonical A3 input recovery differs".into());
        }
        let mut domain = Vec::new();
        for field in [
            &chain[..],
            &ckb_blake2b(&net.anchor.script)[..],
            &ckb_blake2b(&settlement_script)[..],
            &net.anchor.state.rollup_id[..],
            &net.anchor.state.chain_id.to_le_bytes()[..],
        ] {
            domain.extend_from_slice(field);
        }
        let profile = batch::hash(b"tactus/o1/proof-profile/v1",b"TO1PRF01;replay-canonical-genesis-prefix;nonempty-contiguous-interval;ethereum-state-and-header;no-withdrawal-authorization");
        let mut journal = b"TO1PRF01".to_vec();
        journal.extend_from_slice(&profile);
        journal.extend_from_slice(&domain);
        journal.extend_from_slice(&allocation_hash);
        journal.extend_from_slice(&before.encode());
        journal.extend_from_slice(&engine.anchor().encode());
        for field in [
            previous_state.0,
            engine.state_root().0,
            previous_header.0,
            engine.head().hash_slow().0,
        ] {
            journal.extend_from_slice(&field);
        }
        let mut digest = batch::hash(b"tactus/o1/proof-interval/v1", &9u64.to_le_bytes());
        for batch in &recovered.batches {
            let mut step = digest.to_vec();
            step.extend_from_slice(&(batch.input_bytes.len() as u64).to_le_bytes());
            step.extend_from_slice(&batch.input_bytes);
            digest = batch::hash(b"tactus/o1/proof-interval-step/v1", &step);
        }
        journal.extend_from_slice(&digest);
        let next_tip = tip_data(
            engine.anchor(),
            true,
            &engine.state_root().0,
            &engine.head().hash_slow().0,
        );
        let exported = json!({"schema":1,"source":"canonical nine-batch A3 publication with forced valid and invalid Ethereum inputs","domain_hex":rpc::bytes_to_hex(&domain),"allocation_hex":rpc::bytes_to_hex(&allocation),"prefix_batches":0,"batches":recovered.batches.iter().map(|b|rpc::bytes_to_hex(&b.input_bytes)).collect::<Vec<_>>(),"expected_journal_hex":rpc::bytes_to_hex(&journal),"guest_verifying_key":core["guest_verifying_key"],"anchor_type_script":rpc::bytes_to_hex(&net.anchor.script),"settlement_type_script":rpc::bytes_to_hex(&settlement_script),"gate_type_script":rpc::bytes_to_hex(&net.gate.script),"settlement_tip":point(initial_point),"tip_capacity":tip_capacity,"initial_tip_data":rpc::bytes_to_hex(&initial),"next_tip_data":rpc::bytes_to_hex(&next_tip),"checkpoint":point(checkpoint),"fee_input":point(lab.wallets[0].point),"settled":false,"production_ready":false});
        fs::write(
            root.join("proving-input.json"),
            serde_json::to_vec_pretty(&exported).map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?;
        let cold_publication = cold_recovery(&chain, &net.anchor.script, &settlement_script)?;
        if cold_publication["published_batches"] != 9
            || cold_publication["settled_batches"] != 0
            || cold_publication["initialized"] != false
        {
            return Err("publication falsely advanced settlement".into());
        }
        let malformed = advance_tip(
            &lab,
            initial_point,
            tip_capacity,
            &settlement_script,
            &next_tip,
            &framed(&journal, &[42]),
        )?;
        reject(
            &mut lab,
            &settlement_code,
            "sealed-settlement/malformed proof cannot fulfill obligations",
            &malformed,
            9,
        )?;
        result["cold_obligations_before_proof"] =
            cold_obligations(&chain, &net, &settlement_script, "published")?;
        result["proving_input"] = exported;
        result["genesis"] = json!(genesis);
        result["execution"] = json!(executed);
        result["obligations"]=json!(messages.iter().enumerate().map(|(i,m)|json!({"gate":rpc::bytes_to_hex(&net.schedule.gate),"lane":m.lane,"sequence":m.sequence,"payload":rpc::bytes_to_hex(&m.payload),"batch":8,"block":9,"input_slot":i,"outcome":block.outcomes[i],"proof_settled":false})).collect::<Vec<_>>());
        result["cold_before_proof"] = cold_publication;
        result["cold_gate"] = cold_gate(&chain, &net)?;
        result["settlement_code_hash"] = rpc::bytes_to_hex(&settlement_code).into();
        result["gate_code_hash"] = rpc::bytes_to_hex(&gate_code).into();
        if let Some(directory) = std::env::var_os("TACTUS_SEALED_PROOF_DIR") {
            let proof = read(
                &PathBuf::from(directory),
                &journal,
                &core["guest_verifying_key"],
            )?;
            let proof_reorg_plan = if std::env::var_os("TACTUS_SEALED_PROOF_REORG").is_some() {
                Some(proof_reorg::prepare(&lab)?)
            } else {
                None
            };
            let encoded = framed(&journal, &proof.bytes);
            let valid = advance_tip(
                &lab,
                initial_point,
                tip_capacity,
                &settlement_script,
                &next_tip,
                &encoded,
            )?;
            let cycles = rpc::call("estimate_cycles", json!([valid]))?;
            for (name, offset, expected) in [
                ("interval data", 736, 9),
                ("forced final state", 640, 7),
                ("predecessor", 248, 7),
            ] {
                let mut changed = journal.clone();
                changed[offset] ^= 1;
                let tx = advance_tip(
                    &lab,
                    initial_point,
                    tip_capacity,
                    &settlement_script,
                    &next_tip,
                    &framed(&changed, &proof.bytes),
                )?;
                reject(
                    &mut lab,
                    &settlement_code,
                    &format!("sealed-settlement/tampered {name}"),
                    &tx,
                    expected,
                )?;
            }
            let hash = lab.commit(
                "sealed-settlement/real proof fulfills published obligations",
                &valid,
            )?;
            let consumption = consumed_tip(initial_point, &hash)?;
            lab.wallets[0].point = lab::point(&hash, 1)?;
            lab.wallets[0].capacity = number(&valid["outputs"][1]["capacity"])?;
            let replay = advance_tip(
                &lab,
                lab::point(&hash, 0)?,
                tip_capacity,
                &settlement_script,
                &next_tip,
                &encoded,
            )?;
            reject(
                &mut lab,
                &settlement_code,
                "sealed-settlement/replay cannot fulfill twice",
                &replay,
                7,
            )?;
            let cold = cold_recovery(&chain, &net.anchor.script, &settlement_script)?;
            if cold["settled_batches"] != 9
                || cold["proved_transitions"] != 1
                || cold["data"] != rpc::bytes_to_hex(&next_tip)
                || cold["tip"]["tx_hash"] != hash
            {
                return Err("cold proof fulfillment differs".into());
            }
            let packed = rpc::call("get_transaction", json!([hash, "0x0"]))?;
            let wire = rpc::decode_hex(packed["transaction"].as_str().ok_or("packed tx")?)?.len();
            if wire != tx::wire_bytes(&valid)? {
                return Err("node proof transaction size differs".into());
            }
            result["cold_obligations_after_proof"] =
                cold_obligations(&chain, &net, &settlement_script, "settled")?;
            result["settled"] = true.into();
            result["suite"] = "sealed-settlement-proof-v1".into();
            result["source_proof"] = proof.source;
            result["cold_after_proof"] = cold;
            result["transition"] = json!({"hash":hash,"cycles":cycles,"node_wire_bytes":wire,"consumption":consumption});
            for obligation in result["obligations"].as_array_mut().ok_or("obligations")? {
                obligation["proof_settled"] = true.into();
            }
            if std::env::var_os("TACTUS_STATE_PROOFS_JSON").is_some() {
                result["state_proof"] = state_proof::qualify(
                    &mut lab,
                    &settlement_script,
                    lab::point(&hash, 0)?,
                    &next_tip,
                )?;
                result["suite"] = "settled-state-proof-v1".into();
            }
            if let Some(plan) = proof_reorg_plan {
                result["proof_reorg"] = proof_reorg::qualify(
                    &mut lab,
                    plan,
                    proof_reorg::Context {
                        network: &net,
                        chain: &chain,
                        script: &settlement_script,
                        input: &result["proving_input"],
                        original: &valid,
                        orphan: &hash,
                        witness: &encoded,
                    },
                )?;
                result["suite"] = "sealed-proof-reorg-v1".into();
            }
        }
        if let Some(plan) = reorg_plan {
            result["reorg"] = reorg::qualify(
                &mut lab,
                plan,
                &net,
                &chain,
                &settlement_script,
                &publication,
            )?;
            result["suite"] = "sealed-obligation-reorg-v1".into();
        }
        result["complete"] = true.into();
        Ok::<_, String>(())
    })();
    result["error"] = json!(outcome.as_ref().err());
    lab.save(&evidence, result)?;
    outcome
}
fn main() {
    if let Err(error) = run() {
        eprintln!("SEALED SETTLEMENT FAILED: {error}");
        std::process::exit(1);
    }
}
