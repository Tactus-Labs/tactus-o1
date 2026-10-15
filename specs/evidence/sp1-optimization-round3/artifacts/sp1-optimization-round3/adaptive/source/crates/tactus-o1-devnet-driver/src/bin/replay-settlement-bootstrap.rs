//! Real deployment, canonical input export and optional real-proof settlement qualification.
#[path = "replay-settlement-bootstrap/continuation.rs"]
mod continuation;
#[path = "replay-settlement-bootstrap/reorg.rs"]
mod reorg;
use serde_json::{json, Value};
use tactus_o1_devnet_driver::settlement_lab::{
    advance_tip, cold_recovery, consumed_tip, framed, reject, tip_data, tip_output,
};
use tactus_o1_devnet_driver::{
    batch_lab::{self, Anchor},
    lab::{self, Lab},
    molecule, recovery, rpc,
    tx::{self, OutSpec, TX_FEE},
};
use tactus_o1_execution::{Executor, Genesis};
use tactus_o1_ordering_script::{ckb_blake2b, genesis_identity};
use tactus_o1_protocol::{
    batch::{self, AnchorState, BatchInput},
    genesis,
};

fn number(v: &Value) -> Result<u64, String> {
    u64::from_str_radix(v.as_str().ok_or("number")?.trim_start_matches("0x"), 16)
        .map_err(|e| e.to_string())
}
fn ordinary(lab: &Lab, mut outputs: Vec<OutSpec>) -> Result<Value, String> {
    let w = &lab.wallets[0];
    let spent: u64 = outputs.iter().map(|o| o.capacity).sum();
    outputs.push(OutSpec {
        capacity: w.capacity.checked_sub(spent + TX_FEE).ok_or("capacity")?,
        lock: w.key.lock_script(),
        type_script: None,
        data: vec![],
    });
    tx::build_and_sign(
        &w.key,
        &lab.secp,
        &lab.deps,
        &[(w.point, w.capacity)],
        &outputs,
        None,
    )
    .map(|(_, t)| t)
}
fn bootstrap_tx(
    lab: &Lab,
    anchor: &Anchor,
    allocation: &[u8],
    script: &[u8],
    data: &[u8],
) -> Result<Value, String> {
    ordinary(
        lab,
        vec![
            tip_output(lab, script, data),
            batch_lab::head_output(anchor, anchor.state),
            batch_lab::da_output(anchor, allocation),
        ],
    )
}
fn run() -> Result<(), String> {
    let reorg_mode = std::env::var_os("TACTUS_SETTLEMENT_REORG").is_some();
    if reorg_mode
        && (std::env::var_os("TACTUS_SETTLEMENT_PROOF_DIR").is_none()
            || std::env::var_os("TACTUS_SECOND_SETTLEMENT_PROOF_DIR").is_some()
            || std::env::var_os("TACTUS_PREPARE_SECOND_PROOF").is_some())
    {
        return Err("settlement reorg requires only the first real proof directory".into());
    }
    let second_directory = std::env::var_os("TACTUS_SECOND_SETTLEMENT_PROOF_DIR");
    if second_directory.is_some() && std::env::var_os("TACTUS_SETTLEMENT_PROOF_DIR").is_none() {
        return Err("second proof qualification requires the first real proof directory".into());
    }
    if std::env::var_os("TACTUS_PREPARE_SECOND_PROOF").is_some()
        && std::env::var_os("TACTUS_SETTLEMENT_PROOF_DIR").is_some()
    {
        return Err("input preparation and proof qualification are separate modes".into());
    }

    let evidence = std::env::var("TACTUS_EVIDENCE_PATH").map_err(|_| "use isolated launcher")?;
    let root =
        std::path::PathBuf::from(std::env::var("TACTUS_RUN_DIR").map_err(|_| "run directory")?);
    let mut lab = Lab::connect_with_script("artifacts/tactus_o1_anchor_script.elf")?;
    let mut results = json!({"suite":"settlement-bootstrap-v1","complete":false,"settled":false,"production_ready":false,"G3":"OPEN","scope":"real atomic initialization, structural rejections, malformed-proof rejection and canonical proving input export; no accepted execution proof yet"});
    let outcome = (|| {
        let settlement_elf = std::fs::read("artifacts/tactus_o1_settlement_script.elf")
            .map_err(|e| e.to_string())?;
        let checkpoint_elf = std::fs::read("artifacts/tactus_o1_history_checkpoint_script.elf")
            .map_err(|e| e.to_string())?;
        let code = ckb_blake2b(&settlement_elf);
        let checkpoint_code = ckb_blake2b(&checkpoint_elf);
        let deps = lab.publish_cells(
            "settlement/deploy immutable programs",
            &[settlement_elf, checkpoint_elf],
            0,
            true,
        )?;
        lab.deps.extend(deps);
        let fixture: Value = serde_json::from_str(include_str!(
            "../../../../specs/test-vectors/execution-v1/geth-1.17.8.json"
        ))
        .map_err(|e| e.to_string())?;
        let case = &fixture["cases"][0];
        let mut ethereum_genesis: Genesis =
            serde_json::from_value(case["genesis"].clone()).map_err(|e| e.to_string())?;
        let allocation = ethereum_genesis
            .allocation_bytes()
            .map_err(|e| e.to_string())?;
        let allocation_hash = genesis::commitment(&allocation).map_err(|e| format!("{e:?}"))?;
        let old_parent = AnchorState::genesis(
            ethereum_genesis.rollup_id.0,
            tactus_o1_execution::rules_hash(),
            ethereum_genesis.chain_id,
        )
        .map_err(|e| format!("{e:?}"))?;
        let old_batch = BatchInput::decode(
            &rpc::decode_hex(case["batch"].as_str().ok_or("batch")?)?,
            &old_parent,
        )
        .map_err(|e| format!("{e:?}"))?;
        let wallet = &lab.wallets[0];
        let seed: [u8; 44] = molecule::cell_input(
            0,
            &molecule::out_point(&wallet.point.tx_hash, wallet.point.index),
        )
        .try_into()
        .unwrap();
        let identity = genesis_identity(&seed, 1);
        ethereum_genesis.rollup_id = identity.into();
        let anchor_script = tx::anchor_type_script(&lab.ordering_elf, &identity, &allocation)?;
        let anchor_hash = ckb_blake2b(&anchor_script);
        let state = AnchorState::genesis(
            identity,
            tactus_o1_execution::rules_hash(),
            ethereum_genesis.chain_id,
        )
        .map_err(|e| format!("{e:?}"))?;
        let anchor_lock = molecule::script(&ckb_blake2b(&lab.lock_elf), 2, &anchor_hash);
        let mut anchor = Anchor {
            point: wallet.point,
            capacity: OutSpec::required_capacity(&anchor_lock, Some(&anchor_script), 200)
                + 10 * TX_FEE,
            state,
            lock: anchor_lock,
            script: anchor_script,
            immutable: molecule::script(&ckb_blake2b(&lab.ordering_elf), 2, &[]),
        };
        let chain = rpc::decode_hex(
            rpc::call("get_block_hash", json!(["0x0"]))?
                .as_str()
                .ok_or("chain")?,
        )?;
        let core: Value = serde_json::from_str(include_str!(
            "../../../../specs/evidence/execution-core-proof/result.json"
        ))
        .map_err(|e| e.to_string())?;
        let guest_key = rpc::decode_hex(core["guest_verifying_key"].as_str().ok_or("guest key")?)?;
        let mut config = b"TO1CFG01".to_vec();
        for field in [
            &chain[..],
            &anchor_hash[..],
            &guest_key[..],
            &checkpoint_code[..],
            &allocation_hash[..],
        ] {
            config.extend_from_slice(field);
        }
        let settlement_script = molecule::script(&code, 2, &config);
        let settlement_hash = ckb_blake2b(&settlement_script);
        let initial = tip_data(&anchor.state, false, &[0; 32], &[0; 32]);
        let baseline = bootstrap_tx(&lab, &anchor, &allocation, &settlement_script, &initial)?;
        results["initialization_cycles"] = rpc::call("estimate_cycles", json!([baseline]))?;
        for (name, offset) in [
            ("reserved", 9),
            ("unproved-initial-state", 216),
            ("unproved-initial-header", 248),
            ("initialized-before-proof", 8),
        ] {
            let mut changed = initial.clone();
            changed[offset] ^= 1;
            let tx = bootstrap_tx(&lab, &anchor, &allocation, &settlement_script, &changed)?;
            reject(&mut lab, &code, &format!("settlement/{name}"), &tx, 3)?;
        }
        let tx = bootstrap_tx(
            &lab,
            &anchor,
            &allocation,
            &settlement_script,
            &initial[..279],
        )?;
        reject(&mut lab, &code, "settlement/short-tip", &tx, 3)?;
        let mut wrong = config.clone();
        wrong[136] ^= 1;
        let tx = bootstrap_tx(
            &lab,
            &anchor,
            &allocation,
            &molecule::script(&code, 2, &wrong),
            &initial,
        )?;
        reject(&mut lab, &code, "settlement/wrong-allocation", &tx, 4)?;
        let tx = ordinary(&lab, vec![tip_output(&lab, &settlement_script, &initial)])?;
        reject(&mut lab, &code, "settlement/no-anchor-genesis", &tx, 4)?;
        let tx = ordinary(
            &lab,
            vec![
                tip_output(&lab, &settlement_script, &initial),
                batch_lab::head_output(&anchor, anchor.state),
                batch_lab::da_output(&anchor, &allocation),
                tip_output(&lab, &settlement_script, &initial),
            ],
        )?;
        reject(&mut lab, &code, "settlement/duplicate-tip", &tx, 2)?;
        let boot = lab.commit(
            "settlement/atomic Anchor and uninitialized Tip genesis",
            &baseline,
        )?;
        let tip_point = lab::point(&boot, 0)?;
        let tip_capacity = number(&baseline["outputs"][0]["capacity"])?;
        anchor.point = lab::point(&boot, 1)?;
        lab.wallets[0].point = lab::point(&boot, 3)?;
        lab.wallets[0].capacity = number(&baseline["outputs"][3]["capacity"])?;
        lab.deps.push(anchor.point);
        let tx = ordinary(&lab, vec![tip_output(&lab, &settlement_script, &initial)])?;
        lab.deps.pop();
        reject(
            &mut lab,
            &code,
            "settlement/late-bootstrap-from-anchor-dependency",
            &tx,
            4,
        )?;
        let bytes = BatchInput {
            parent: anchor.state,
            blocks: old_batch.blocks,
        }
        .encode()
        .map_err(|e| format!("{e:?}"))?;
        let mut engine = Executor::new(&ethereum_genesis).map_err(|e| e.to_string())?;
        let previous_state = engine.state_root();
        let previous_header = engine.head().hash_slow();
        let before = *engine.anchor();
        engine.apply_batch(&bytes).map_err(|e| e.to_string())?;
        let after = *engine.anchor();
        let checkpoint_script = molecule::script(&checkpoint_code, 2, &anchor_hash);
        let checkpoint_lock = lab.wallets[0].key.lock_script();
        let checkpoint = OutSpec {
            capacity: OutSpec::required_capacity(&checkpoint_lock, Some(&checkpoint_script), 200),
            lock: checkpoint_lock,
            type_script: Some(checkpoint_script),
            data: after.encode().to_vec(),
        };
        let publication = batch_lab::shape(
            &lab,
            &anchor,
            0,
            vec![
                checkpoint,
                batch_lab::head_output(&anchor, after),
                batch_lab::da_output(&anchor, &bytes),
            ],
            Some(&2u32.to_le_bytes()),
        )?;
        let published = lab.commit(
            "settlement/canonical batch and ending checkpoint",
            &publication,
        )?;
        let checkpoint_point = lab::point(&published, 0)?;
        anchor.point = lab::point(&published, 1)?;
        anchor.state = after;
        lab.wallets[0].point = lab::point(&published, 3)?;
        lab.wallets[0].capacity = number(&publication["outputs"][3]["capacity"])?;
        let recovered = recovery::recover_published_batches(&anchor.script)?;
        if recovered.state != after
            || recovered.genesis_allocation != allocation
            || recovered.batches.len() != 1
            || recovered.batches[0].input_bytes != bytes
        {
            return Err("canonical proving input differs from builder".into());
        }
        let mut domain = chain.clone();
        domain.extend_from_slice(&anchor_hash);
        domain.extend_from_slice(&settlement_hash);
        domain.extend_from_slice(&identity);
        domain.extend_from_slice(&ethereum_genesis.chain_id.to_le_bytes());
        let fixed = rpc::decode_hex(
            include_str!("../../../../specs/test-vectors/proof-v1/transfers-journal.hex").trim(),
        )?;
        let mut journal = b"TO1PRF01".to_vec();
        journal.extend_from_slice(&fixed[8..40]);
        journal.extend_from_slice(&domain);
        journal.extend_from_slice(&allocation_hash);
        journal.extend_from_slice(&before.encode());
        journal.extend_from_slice(&after.encode());
        for field in [
            previous_state.0,
            engine.state_root().0,
            previous_header.0,
            engine.head().hash_slow().0,
        ] {
            journal.extend_from_slice(&field);
        }
        let mut interval =
            batch::hash(b"tactus/o1/proof-interval/v1", &1u64.to_le_bytes()).to_vec();
        interval.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
        interval.extend_from_slice(&bytes);
        journal.extend_from_slice(&batch::hash(b"tactus/o1/proof-interval-step/v1", &interval));
        let next_tip = tip_data(
            &after,
            true,
            &engine.state_root().0,
            &engine.head().hash_slow().0,
        );
        let bad_proof = framed(&journal, &[42]); // Deliberately invalid negative control, never accepted.
        let tx = advance_tip(
            &lab,
            tip_point,
            tip_capacity,
            &settlement_script,
            &next_tip,
            &bad_proof,
        )?;
        reject(
            &mut lab,
            &code,
            "settlement/missing-authenticated-checkpoint",
            &tx,
            8,
        )?;
        lab.deps.push(checkpoint_point);
        let tx = advance_tip(
            &lab,
            tip_point,
            tip_capacity,
            &settlement_script,
            &next_tip,
            &bad_proof,
        )?;
        reject(
            &mut lab,
            &code,
            "settlement/malformed-proof-rejected",
            &tx,
            9,
        )?;
        for (name, offset, expected) in [
            ("network", 40, 6),
            ("ordering", 72, 6),
            ("settlement", 104, 6),
            ("allocation", 176, 6),
            ("predecessor", 248, 7),
            ("ending-history", 456, 7),
            ("state", 640, 7),
            ("header", 704, 7),
        ] {
            let mut changed = journal.clone();
            changed[offset] ^= 1;
            let tx = advance_tip(
                &lab,
                tip_point,
                tip_capacity,
                &settlement_script,
                &next_tip,
                &framed(&changed, &[42]),
            )?;
            reject(
                &mut lab,
                &code,
                &format!("settlement/binding-{name}"),
                &tx,
                expected,
            )?;
        }
        let tx = advance_tip(
            &lab,
            tip_point,
            tip_capacity,
            &settlement_script,
            &next_tip,
            &framed(&journal, &[]),
        )?;
        reject(&mut lab, &code, "settlement/empty-proof", &tx, 5)?;
        let live = rpc::call(
            "get_live_cell",
            json!([{"tx_hash":boot,"index":"0x0"},true]),
        )?;
        if live["status"] != "live"
            || live["cell"]["data"]["content"] != rpc::bytes_to_hex(&initial)
        {
            return Err("negative controls changed uninitialized Tip".into());
        }
        let exported = json!({"schema":1,"source":"canonical CKB genesis allocation and published batch recovery","domain_hex":rpc::bytes_to_hex(&domain),"allocation_hex":rpc::bytes_to_hex(&recovered.genesis_allocation),"prefix_batches":0,"batches":[rpc::bytes_to_hex(&recovered.batches[0].input_bytes)],"expected_journal_hex":rpc::bytes_to_hex(&journal),"guest_verifying_key":core["guest_verifying_key"],"settlement_type_script":rpc::bytes_to_hex(&settlement_script),"anchor_type_script":rpc::bytes_to_hex(&anchor.script),"settlement_tip":{"tx_hash":boot,"index":"0x0","capacity":tip_capacity,"data":rpc::bytes_to_hex(&initial)},"checkpoint":{"tx_hash":published,"index":"0x0"},"fee_input":{"tx_hash":published,"index":"0x3","capacity":lab.wallets[0].capacity},"next_tip_data":rpc::bytes_to_hex(&next_tip),"deployment_dependencies":lab.deps.iter().map(|p|json!({"tx_hash":rpc::bytes_to_hex(&p.tx_hash),"index":format!("0x{:x}",p.index)})).collect::<Vec<_>>(),"observed_canonical_tip":rpc::call("get_tip_header",json!([]))?,"settled":false,"production_ready":false});
        std::fs::write(
            root.join("proving-input.json"),
            serde_json::to_vec_pretty(&exported).map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?;
        let recovered_tip = cold_recovery(&chain, &anchor.script, &settlement_script)?;
        if recovered_tip["initialized"] != false
            || recovered_tip["data"] != rpc::bytes_to_hex(&initial)
        {
            return Err("cold recovery differs from uninitialized Tip".into());
        }
        results["cold_bootstrap_recovery"] = recovered_tip;
        let mut cold_controls = Vec::new();
        for (name, field, offset, reason) in [
            (
                "wrong-chain",
                0,
                0,
                "trusted deployment/chain binding mismatch",
            ),
            (
                "wrong-anchor",
                1,
                53,
                "trusted deployment/chain binding mismatch",
            ),
            (
                "wrong-settlement-key",
                2,
                125,
                "settlement deployment not found",
            ),
        ] {
            let mut arguments = [
                chain.clone(),
                anchor.script.clone(),
                settlement_script.clone(),
            ];
            arguments[field][offset] ^= 1;
            let output = std::process::Command::new("target/debug/recover-settlement")
                .args(arguments.iter().map(|v| rpc::bytes_to_hex(v)))
                .output()
                .map_err(|e| e.to_string())?;
            let error = String::from_utf8_lossy(&output.stderr);
            if output.status.success() || !error.contains(reason) {
                return Err(format!(
                    "cold recovery {name}: expected {reason}, got {error}"
                ));
            }
            cold_controls.push(json!({"control":name,"rejected":true,"error":error}));
        }
        results["cold_recovery_controls"] = json!(cold_controls);

        results["proving_input"] = exported;
        results["settlement_code_hash"] = rpc::bytes_to_hex(&code).into();
        let prepared_second = if let Some(directory) = second_directory {
            let continuation: Value = serde_json::from_str(include_str!(
                "../../../../specs/test-vectors/proof-v1/settlement-continuation.json"
            ))
            .map_err(|e| e.to_string())?;
            let next = tactus_o1_devnet_driver::settlement_inputs::prepare_next_input(
                &mut lab,
                &mut anchor,
                &mut engine,
                &results["proving_input"],
                &continuation,
                checkpoint_code,
                &root,
            )?;
            let expected = rpc::decode_hex(
                next["expected_journal_hex"]
                    .as_str()
                    .ok_or("second journal")?,
            )?;
            let second = continuation::read(
                std::path::Path::new(&directory),
                &expected,
                &core["guest_verifying_key"],
            )?;
            let second_tip = rpc::decode_hex(next["next_tip_data"].as_str().ok_or("second Tip")?)?;
            let skip = advance_tip(
                &lab,
                tip_point,
                tip_capacity,
                &settlement_script,
                &second_tip,
                &framed(&second.journal, &second.bytes),
            )?;
            reject(&mut lab, &code, "settlement/skip-first-interval", &skip, 7)?;
            let cold = cold_recovery(&chain, &anchor.script, &settlement_script)?;
            if cold["settled_batches"] != 0 || cold["published_batches"] != 2 {
                return Err("pre-proof recovery differs from two published intervals".into());
            }
            results["cold_after_second_publication"] = cold;
            results["next_proving_input"] = next.clone();
            results["second_source_proof"] = second.source.clone();
            Some((next, second))
        } else {
            None
        };
        if let Some(directory) = std::env::var_os("TACTUS_SETTLEMENT_PROOF_DIR") {
            let loaded = continuation::read(
                std::path::Path::new(&directory),
                &journal,
                &core["guest_verifying_key"],
            )?;
            let proof = loaded.bytes;
            let source = loaded.source;
            results["settlement_fee_input"] = json!({"tx_hash":rpc::bytes_to_hex(&lab.wallets[0].point.tx_hash),"index":format!("0x{:x}",lab.wallets[0].point.index),"capacity":lab.wallets[0].capacity});
            results["suite"] = "settlement-first-proof-v1".into();
            results["scope"] = "real-domain Groth16 consumption, exact first state transition and live-successor replay rejection; no custody or withdrawals".into();
            results["source_proof"] = source;
            let valid = advance_tip(
                &lab,
                tip_point,
                tip_capacity,
                &settlement_script,
                &next_tip,
                &framed(&journal, &proof),
            )?;
            let cycles = rpc::call("estimate_cycles", json!([valid]))?;
            results["valid_proof_preflight_cycles"] = cycles.clone();
            for (name, offset, expected) in [
                ("profile", 8, 6),
                ("network", 40, 6),
                ("ordering", 72, 6),
                ("settlement", 104, 6),
                ("rollup", 136, 6),
                ("chain", 168, 6),
                ("allocation", 176, 6),
                ("predecessor", 248, 7),
                ("ending-history", 456, 7),
                ("previous-state", 608, 9),
                ("next-state", 640, 7),
                ("previous-header", 672, 9),
                ("next-header", 704, 7),
                ("interval-data", 736, 9),
            ] {
                let mut changed = journal.clone();
                changed[offset] ^= 1;
                let tx = advance_tip(
                    &lab,
                    tip_point,
                    tip_capacity,
                    &settlement_script,
                    &next_tip,
                    &framed(&changed, &proof),
                )?;
                reject(
                    &mut lab,
                    &code,
                    &format!("settlement/proved-{name}-tamper"),
                    &tx,
                    expected,
                )?;
            }
            for offset in [0, proof.len() - 1] {
                let mut changed = proof.clone();
                changed[offset] ^= 1;
                let tx = advance_tip(
                    &lab,
                    tip_point,
                    tip_capacity,
                    &settlement_script,
                    &next_tip,
                    &framed(&journal, &changed),
                )?;
                reject(
                    &mut lab,
                    &code,
                    &format!("settlement/proof-byte-{offset}-tamper"),
                    &tx,
                    9,
                )?;
            }
            // Altering both the claimed output and its matching public value must
            // still fail real cryptography, not merely structural correspondence.
            for (name, journal_offset, tip_offset) in [("state", 640, 216), ("header", 704, 248)] {
                let mut changed = journal.clone();
                changed[journal_offset] ^= 1;
                let mut bad_tip = next_tip.clone();
                bad_tip[tip_offset] ^= 1;
                let tx = advance_tip(
                    &lab,
                    tip_point,
                    tip_capacity,
                    &settlement_script,
                    &bad_tip,
                    &framed(&changed, &proof),
                )?;
                reject(
                    &mut lab,
                    &code,
                    &format!("settlement/coordinated-{name}-tamper"),
                    &tx,
                    9,
                )?;
            }
            let reorg_plan = reorg_mode.then(|| reorg::prepare(&lab)).transpose()?;
            let settled = lab.commit("settlement/first real proof transition", &valid)?;
            let packed = rpc::call("get_transaction", json!([settled, "0x0"]))?;
            let node_bytes =
                rpc::decode_hex(packed["transaction"].as_str().ok_or("packed transaction")?)?.len();
            if node_bytes != tx::wire_bytes(&valid)? {
                return Err("node wire size mismatch".into());
            }
            let next_point = lab::point(&settled, 0)?;
            lab.wallets[0].point = lab::point(&settled, 1)?;
            lab.wallets[0].capacity = number(&valid["outputs"][1]["capacity"])?;
            let successor = rpc::call(
                "get_live_cell",
                json!([{"tx_hash":settled,"index":"0x0"},true]),
            )?;
            if successor["status"] != "live"
                || successor["cell"]["data"]["content"] != rpc::bytes_to_hex(&next_tip)
            {
                return Err("committed successor differs from proved state".into());
            }
            let consumption = consumed_tip(tip_point, &settled)?;
            for (name, data) in [
                ("replay-on-live-successor", &next_tip),
                ("rollback-to-genesis", &initial),
            ] {
                let tx = advance_tip(
                    &lab,
                    next_point,
                    tip_capacity,
                    &settlement_script,
                    data,
                    &framed(&journal, &proof),
                )?;
                reject(&mut lab, &code, &format!("settlement/{name}"), &tx, 7)?;
            }
            results["first_transition"] = json!({"hash":settled,"vm_cycles":number(&cycles["cycles"] )?,"node_wire_bytes":node_bytes,"tip_capacity_shannons":tip_capacity,"fee_shannons":TX_FEE,"data":rpc::bytes_to_hex(&next_tip),"predecessor_status":consumption["live_cell"]["status"],"predecessor_consumption":consumption,"successor_status":successor["status"]});
            let recovered_tip = cold_recovery(&chain, &anchor.script, &settlement_script)?;
            if recovered_tip["initialized"] != true
                || recovered_tip["data"] != rpc::bytes_to_hex(&next_tip)
                || recovered_tip["tip"]["tx_hash"] != settled
                || recovered_tip["settled_batches"] != 1
            {
                return Err("cold recovery differs from committed proof successor".into());
            }
            results["cold_settlement_recovery"] = recovered_tip;
            results["settled"] = true.into();
            results["withdrawal_authority"] = false.into();
            if let Some(plan) = reorg_plan {
                results["reorg"] = reorg::qualify(
                    &mut lab,
                    plan,
                    &results["proving_input"],
                    &valid,
                    &settled,
                    &framed(&journal, &proof),
                )?;
                results["suite"] = "settlement-proof-p2p-reorg-v1".into();
                results["scope"] = "real P2P rollback of a proved Tip, cold canonical recovery and same-proof resubmission with fresh funding; planned partition, no custody".into();
            }
            if let Some((next, second)) = prepared_second {
                let second_transition = continuation::qualify(
                    &mut lab,
                    continuation::Context {
                        code: &code,
                        script: &settlement_script,
                        capacity: tip_capacity,
                        first_transition: &results["first_transition"],
                        first_journal: &journal,
                        first_proof: &proof,
                    },
                    &next,
                    &second,
                )?;
                let cold = cold_recovery(&chain, &anchor.script, &settlement_script)?;
                if cold["settled_batches"] != 2
                    || cold["proved_transitions"] != 2
                    || cold["data"] != second_transition["data"]
                    || cold["tip"]["tx_hash"] != second_transition["hash"]
                {
                    return Err("cold recovery differs from second proof successor".into());
                }
                results["second_transition"] = second_transition;
                results["cold_second_settlement_recovery"] = cold;
                results["suite"] = "settlement-two-proofs-v1".into();
                results["scope"]="two real Groth16 transitions, stale mutable Anchor independence, skipped interval and replay rejection, fresh cold recovery; no custody or withdrawals".into();
            }
        }
        if std::env::var_os("TACTUS_PREPARE_SECOND_PROOF").is_some() {
            if results["settled"] == true {
                return Err(
                    "second-input preparation requires bootstrap mode without proof application"
                        .into(),
                );
            }
            let continuation: Value = serde_json::from_str(include_str!(
                "../../../../specs/test-vectors/proof-v1/settlement-continuation.json"
            ))
            .map_err(|e| e.to_string())?;
            let next = tactus_o1_devnet_driver::settlement_inputs::prepare_next_input(
                &mut lab,
                &mut anchor,
                &mut engine,
                &results["proving_input"],
                &continuation,
                checkpoint_code,
                &root,
            )?;
            let cold = cold_recovery(&chain, &anchor.script, &settlement_script)?;
            if cold["settled_batches"] != 0
                || cold["published_batches"] != 2
                || cold["initialized"] != false
            {
                return Err("second publication falsely advanced recovered settlement".into());
            }
            results["suite"] = "settlement-next-input-v1".into();
            results["scope"]="two real canonical publications and prefix-one proving input; neither interval is settled".into();
            results["next_proving_input"] = next;
            results["cold_after_second_publication"] = cold;
        }
        results["complete"] = true.into();
        Ok::<_, String>(())
    })();
    results["error"] = json!(outcome.as_ref().err());
    lab.save(&evidence, results)?;
    outcome
}
fn main() {
    if let Err(error) = run() {
        eprintln!("SETTLEMENT BOOTSTRAP FAILED: {error}");
        std::process::exit(1);
    }
}
