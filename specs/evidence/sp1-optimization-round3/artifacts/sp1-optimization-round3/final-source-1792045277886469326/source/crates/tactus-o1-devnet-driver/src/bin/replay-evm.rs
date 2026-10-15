//! Real CKB input publication -> independent-process durable EVM replay,
//! including a canonical branch rollback/replacement. No validity-proof claim.
use serde_json::{json, Value};
use std::{fs, path::Path, process::Command};
use tactus_o1_devnet_driver::{
    batch_lab::{self, block, encode, publish},
    lab::Lab,
    recovery, rpc,
};
use tactus_o1_execution::{rules_hash, Executor, Genesis};
use tactus_o1_protocol::batch::{AnchorState, BatchInput, BlockInput};

fn fixture(index: usize) -> Result<(Genesis, Vec<BlockInput>), String> {
    let document: Value = serde_json::from_str(include_str!(
        "../../../../specs/test-vectors/execution-v1/geth-1.17.8.json"
    ))
    .map_err(|e| e.to_string())?;
    let case = &document["cases"][index];
    let genesis: Genesis =
        serde_json::from_value(case["genesis"].clone()).map_err(|e| e.to_string())?;
    let rules: [u8; 32] = rpc::decode_hex(
        document["rules_hash"]
            .as_str()
            .ok_or("fixture rules missing")?,
    )?
    .try_into()
    .map_err(|_| "fixture hash length")?;
    let parent = AnchorState::genesis(genesis.rollup_id.0, rules, genesis.chain_id)
        .map_err(|e| format!("{e:?}"))?;
    let bytes = rpc::decode_hex(case["batch"].as_str().ok_or("fixture batch missing")?)?;
    let batch = BatchInput::decode(&bytes, &parent).map_err(|e| format!("{e:?}"))?;
    Ok((genesis, batch.blocks))
}
fn recover_child(root: &Path, genesis: &Path, script: &[u8]) -> Result<Value, String> {
    let binary = std::env::current_exe()
        .map_err(|e| e.to_string())?
        .with_file_name("recover-execution");
    let mut command = Command::new(binary);
    command.arg(genesis);
    if genesis == Path::new("--chain") {
        command.arg(
            rpc::call("get_block_hash", json!(["0x0"]))?
                .as_str()
                .ok_or("chain")?,
        );
    }
    let result = command
        .arg(rpc::bytes_to_hex(script))
        .arg(root)
        .output()
        .map_err(|e| e.to_string())?;
    if !result.status.success() {
        return Err(format!(
            "independent recovery failed: {}",
            String::from_utf8_lossy(&result.stderr)
        ));
    }
    serde_json::from_slice(&result.stdout).map_err(|e| format!("recovery output: {e}"))
}
fn assert_report(report: &Value, expected: &Executor) -> Result<(), String> {
    if report["state_root"] != json!(expected.state_root())
        || report["hash"] != json!(expected.head().hash_slow())
        || report["header"] != json!(expected.head())
        || report["batch_count"] != json!(expected.anchor().next_batch_number)
    {
        return Err("independent recovered execution differs from publisher execution".into());
    }
    Ok(())
}
fn run() -> Result<(), String> {
    let evidence_path =
        std::env::var("TACTUS_EVIDENCE_PATH").map_err(|_| "use isolated devnet launcher")?;
    let run_dir = std::env::var("TACTUS_RUN_DIR").map_err(|_| "run directory missing")?;
    let root = Path::new(&run_dir).join("observer");
    let genesis_path = Path::new(&run_dir).join("execution-genesis.json");
    let mut lab = Lab::connect_with_script("artifacts/tactus_o1_anchor_script.elf")?;
    let mut results = json!({"suite":"ckb-evm-recovery-v1","complete":false,"production_ready":false,"G5":"OPEN","G6":"OPEN"});
    let outcome = (|| {
        let (mut genesis, fixture_blocks) = fixture(2)?;
        let allocation = genesis.allocation_bytes().map_err(|e| e.to_string())?;
        let mut anchor =
            batch_lab::create_with_allocation(&mut lab, rules_hash(), 31337, &allocation)?;
        genesis.rollup_id = anchor.state.rollup_id.into();
        fs::write(
            &genesis_path,
            serde_json::to_vec_pretty(&genesis).map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?;
        let mut expected = Executor::new(&genesis).map_err(|e| e.to_string())?;
        let at_genesis = recover_child(&root, &genesis_path, &anchor.script)?;
        assert_report(&at_genesis, &expected)?;
        let create = fixture_blocks[0].transactions[0].clone();
        let write = fixture_blocks[0].transactions[1].clone();
        let first = encode(
            anchor.state,
            vec![
                block(10, vec![vec![2, 1, 2], create.clone(), create, write]),
                block(10, vec![]),
            ],
        )?;
        publish(
            &mut lab,
            &mut anchor,
            &first,
            1,
            "evm/deploy-write-with-rejected-slots-and-empty-block",
        )?;
        let executed = expected.apply_batch(&first).map_err(|e| e.to_string())?;
        let first_report = recover_child(&root, &genesis_path, &anchor.script)?;
        assert_report(&first_report, &expected)?;
        lab.evidence.push(json!({"label":"evm/independent process reconstructs deployment storage and outcomes","result":"control_passed","report":first_report,"blocks":executed}));
        let snapshot = recovery::recover_published_batches(&anchor.script)?;
        rpc::mine_blocks(1)?;
        recovery::assert_canonical(snapshot.pinned_height, &snapshot.pinned_hash)?;
        lab.evidence.push(json!({"label":"evm/canonical snapshot survives ordinary tip growth","result":"control_passed","pinned_height":snapshot.pinned_height,"pinned_hash":snapshot.pinned_hash}));
        let stable_anchor = anchor.clone();
        let stable_execution = expected.clone();
        let parent = rpc::call("get_tip_header", json!([]))?;
        let wallet_point = lab.wallets[0].point;
        let wallet_capacity = lab.wallets[0].capacity;
        let orphan = encode(
            anchor.state,
            vec![block(11, fixture_blocks[1].transactions.clone())],
        )?;
        publish(
            &mut lab,
            &mut anchor,
            &orphan,
            0,
            "evm/orphan branch clears contract storage",
        )?;
        expected.apply_batch(&orphan).map_err(|e| e.to_string())?;
        let orphan_report = recover_child(&root, &genesis_path, &anchor.script)?;
        assert_report(&orphan_report, &expected)?;
        let orphan_snapshot = recovery::recover_published_batches(&anchor.script)?;
        rpc::require_devnet()?;
        rpc::call("truncate", json!([parent["hash"]]))?;
        lab.wallets[0].point = wallet_point;
        lab.wallets[0].capacity = wallet_capacity;
        anchor = stable_anchor;
        expected = stable_execution;
        if recovery::assert_canonical(orphan_snapshot.pinned_height, &orphan_snapshot.pinned_hash)
            .is_ok()
        {
            return Err("orphan snapshot remained canonical".into());
        }
        let rolled_back = recover_child(&root, &genesis_path, &anchor.script)?;
        assert_report(&rolled_back, &expected)?;
        if rolled_back["hash"] == orphan_report["hash"] {
            return Err("rollback retained orphan EVM head".into());
        }
        let (_, transfer_blocks) = fixture(0)?;
        let replacement = encode(
            anchor.state,
            vec![block(11, vec![transfer_blocks[0].transactions[2].clone()])],
        )?;
        publish(
            &mut lab,
            &mut anchor,
            &replacement,
            1,
            "evm/replacement transfers value without clearing storage",
        )?;
        expected
            .apply_batch(&replacement)
            .map_err(|e| e.to_string())?;
        let replacement_report = recover_child(&root, &genesis_path, &anchor.script)?;
        assert_report(&replacement_report, &expected)?;
        if replacement_report["state_root"] == orphan_report["state_root"] {
            return Err("branch replacement did not distinguish EVM state".into());
        }
        let fresh_root = Path::new(&run_dir).join("fresh-observer");
        let fresh_report = recover_child(&fresh_root, &genesis_path, &anchor.script)?;
        assert_report(&fresh_report, &expected)?;
        let chain_only = recover_child(
            &Path::new(&run_dir).join("chain-only-observer"),
            Path::new("--chain"),
            &anchor.script,
        )?;
        assert_report(&chain_only, &expected)?;
        let mut wrong_genesis = genesis.clone();
        wrong_genesis
            .accounts
            .values_mut()
            .next()
            .ok_or("fixture allocation")?
            .nonce += 1;
        let wrong_path = Path::new(&run_dir).join("wrong-allocation.json");
        fs::write(&wrong_path, serde_json::to_vec(&wrong_genesis).unwrap())
            .map_err(|e| e.to_string())?;
        let wrong_allocation = recover_child(
            &Path::new(&run_dir).join("wrong-allocation-observer"),
            &wrong_path,
            &anchor.script,
        )
        .expect_err("wrong allocation must reject");
        if !wrong_allocation.contains("genesis allocation does not match immutable CKB publication")
        {
            return Err(wrong_allocation);
        }
        lab.evidence.push(json!({"label":"evm/genesis recovered from chain without local allocation; wrong allocation rejected","result":"control_passed","chain_only":chain_only,"wrong_allocation_error":wrong_allocation}));
        let bad_chain = Command::new(
            std::env::current_exe()
                .map_err(|e| e.to_string())?
                .with_file_name("recover-execution"),
        )
        .arg("--chain")
        .arg(rpc::bytes_to_hex(&[0; 32]))
        .arg(rpc::bytes_to_hex(&anchor.script))
        .arg(Path::new(&run_dir).join("wrong-chain-genesis-observer"))
        .output()
        .map_err(|e| e.to_string())?;
        let bad_chain_error = String::from_utf8_lossy(&bad_chain.stderr).to_string();
        if bad_chain.status.success() || !bad_chain_error.contains("CKB genesis hash mismatch") {
            return Err(format!(
                "wrong chain genesis check failed: {bad_chain_error}"
            ));
        }
        lab.evidence.push(json!({"label":"evm/chain-only recovery rejects wrong trusted CKB genesis","result":"control_passed","error":bad_chain_error}));
        let restarted = recover_child(&root, &genesis_path, &anchor.script)?;
        assert_report(&restarted, &expected)?;
        // Network/anchor identity is pinned independently of execution genesis.
        let binding = root.join("binding.json");
        let binding_bytes = fs::read(&binding).map_err(|e| e.to_string())?;
        let mut wrong: Value = serde_json::from_slice(&binding_bytes).map_err(|e| e.to_string())?;
        wrong["ckb_genesis_hash"] = json!("0x00");
        fs::write(&binding, serde_json::to_vec(&wrong).unwrap()).map_err(|e| e.to_string())?;
        let mismatch = recover_child(&root, &genesis_path, &anchor.script)
            .expect_err("wrong network binding must reject");
        fs::write(binding, binding_bytes).map_err(|e| e.to_string())?;
        if !mismatch.contains("another CKB chain or anchor type") {
            return Err(mismatch);
        }
        lab.evidence.push(json!({"label":"evm/reorg changes canonical execution while independent fresh recovery agrees","result":"control_passed","orphan":orphan_report,"rolled_back":rolled_back,"replacement":replacement_report,"fresh":fresh_report,"restart":restarted,"wrong_network_rejected":true}));
        results["canonical_batches"] = json!(2);
        results["canonical_blocks"] = json!(3);
        results["included_ethereum_transactions"] = json!(3);
        results["rejected_input_slots"] = json!(2);
        results["final_execution"] = replacement_report;
        results["operator_snapshot_used"] = json!(false);
        results["independent_processes"] = json!(11);
        results["genesis_allocation_from_chain"] = json!(true);
        results["scope"]=json!("CKB-published input to durable serial EVM execution, isolated planned reorg and independent fresh recovery; no proof or settlement");
        results["complete"] = json!(true);
        Ok::<_, String>(())
    })();
    results["error"] = json!(outcome.as_ref().err());
    lab.save(&evidence_path, results)?;
    outcome
}
fn main() {
    if let Err(error) = run() {
        eprintln!("EVM RECOVERY FAILED: {error}");
        std::process::exit(1);
    }
}
