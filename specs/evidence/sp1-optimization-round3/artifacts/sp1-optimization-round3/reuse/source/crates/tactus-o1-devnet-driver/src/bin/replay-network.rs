//! Two real CKB peers: partition, competing valid history, P2P fork choice,
//! independent protocol/EVM recovery and resumed mandatory publication.
use serde_json::{json, Value};
use std::{
    path::Path,
    process::Command,
    time::{Duration, Instant},
};
use tactus_o1_devnet_driver::{
    lab::{self, Lab},
    recovery, rpc,
    sealed_lab::*,
    sealed_recovery,
    tx::TX_FEE,
};
use tactus_o1_execution::{Executor, Genesis};
use tactus_o1_ordering_script::ckb_blake2b;
use tactus_o1_protocol::{
    batch::{AnchorState, BatchInput},
    sealed as s,
};
fn number(v: &Value) -> Result<u64, String> {
    u64::from_str_radix(v.as_str().ok_or("number")?.trim_start_matches("0x"), 16)
        .map_err(|e| e.to_string())
}
fn wait(label: &str, mut f: impl FnMut() -> Result<bool, String>) -> Result<(), String> {
    let deadline = Instant::now() + Duration::from_secs(45);
    while !f()? {
        if Instant::now() > deadline {
            return Err(format!("{label}: timeout"));
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    Ok(())
}
fn peer_mine(peer: &str, n: u64) -> Result<(), String> {
    let c = rpc::call_at(peer, "get_consensus", json!([]))?;
    if c["id"] != "ckb_dev" || c["permanent_difficulty_in_dummy"] != true {
        return Err("peer must be permanent Dummy devnet".into());
    }
    for _ in 0..n {
        let hash = rpc::call_at(peer, "generate_block", json!([]))?;
        wait("peer generated block and pool", || {
            Ok(
                rpc::call_at(peer, "get_tip_header", json!([]))?["hash"] == hash
                    && rpc::call_at(peer, "tx_pool_info", json!([]))?["tip_hash"] == hash,
            )
        })?;
    }
    Ok(())
}
fn connect(peer: &str) -> Result<(), String> {
    rpc::call("set_network_active", json!([true]))?;
    rpc::call_at(peer, "set_network_active", json!([true]))?;
    let info = rpc::call("local_node_info", json!([]))?;
    let address = format!(
        "/ip4/127.0.0.1/tcp/{}",
        std::env::var("TACTUS_DEVNET_P2P_PORT").unwrap_or("18715".into())
    );
    rpc::call_at(peer, "add_node", json!([info["node_id"], address]))?;
    wait("P2P connected", || {
        Ok(!rpc::call("get_peers", json!([]))?
            .as_array()
            .ok_or("peers")?
            .is_empty()
            && !rpc::call_at(peer, "get_peers", json!([]))?
                .as_array()
                .ok_or("peer peers")?
                .is_empty())
    })
}
fn converged(peer: &str, expected: &Value) -> Result<(), String> {
    wait("both canonical tips and pools converge", || {
        Ok(rpc::call("get_tip_header", json!([]))?["hash"] == *expected
            && rpc::call_at(peer, "get_tip_header", json!([]))?["hash"] == *expected
            && rpc::call("tx_pool_info", json!([]))?["tip_hash"] == *expected
            && rpc::call_at(peer, "tx_pool_info", json!([]))?["tip_hash"] == *expected)
    })
}
fn partition(peer: &str) -> Result<(), String> {
    let a = rpc::call("local_node_info", json!([]))?;
    let b = rpc::call_at(peer, "local_node_info", json!([]))?;
    rpc::call("set_network_active", json!([false]))?;
    rpc::call_at(peer, "set_network_active", json!([false]))?;
    rpc::call("remove_node", json!([b["node_id"]]))?;
    rpc::call_at(peer, "remove_node", json!([a["node_id"]]))?;
    wait("P2P partition", || {
        Ok(rpc::call("get_peers", json!([]))?
            .as_array()
            .ok_or("peers")?
            .is_empty()
            && rpc::call_at(peer, "get_peers", json!([]))?
                .as_array()
                .ok_or("peer peers")?
                .is_empty())
    })
}
fn fixture() -> Result<(Genesis, [Vec<u8>; 3]), String> {
    let v: Value = serde_json::from_str(include_str!(
        "../../../../specs/test-vectors/execution-v1/geth-1.17.8.json"
    ))
    .map_err(|e| e.to_string())?;
    let case = &v["cases"][2];
    let g: Genesis = serde_json::from_value(case["genesis"].clone()).map_err(|e| e.to_string())?;
    let rules = rpc::decode_hex(v["rules_hash"].as_str().ok_or("rules")?)?
        .try_into()
        .map_err(|_| "rules length")?;
    let parent =
        AnchorState::genesis(g.rollup_id.0, rules, g.chain_id).map_err(|e| format!("{e:?}"))?;
    let b = BatchInput::decode(
        &rpc::decode_hex(case["batch"].as_str().ok_or("batch")?)?,
        &parent,
    )
    .map_err(|e| format!("{e:?}"))?;
    if b.blocks.len() != 2
        || b.blocks[0].transactions.len() != 2
        || b.blocks[1].transactions.len() != 1
    {
        return Err("unexpected deployment/storage fixture shape".into());
    }
    Ok((
        g,
        [
            b.blocks[0].transactions[0].clone(),
            b.blocks[0].transactions[1].clone(),
            b.blocks[1].transactions[0].clone(),
        ],
    ))
}
fn child(binary: &str, args: &[String]) -> Result<Value, String> {
    let binary = std::env::current_exe()
        .map_err(|e| e.to_string())?
        .with_file_name(binary);
    let out = Command::new(binary)
        .args(args)
        .output()
        .map_err(|e| e.to_string())?;
    if !out.status.success() {
        return Err(format!(
            "observer failed: {}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    serde_json::from_slice(&out.stdout).map_err(|e| e.to_string())
}
fn observe(
    lab: &mut Lab,
    net: &Network,
    engine: &Executor,
    root: &Path,
    label: &str,
) -> Result<Value, String> {
    let chain = rpc::call("get_block_hash", json!(["0x0"]))?
        .as_str()
        .ok_or("genesis hash")?
        .to_owned();
    let protocol = child(
        "recover-sealed",
        &[
            chain.clone(),
            rpc::bytes_to_hex(&net.gate.script),
            rpc::bytes_to_hex(&net.anchor.script),
        ],
    )?;
    if protocol["network"] != sealed_recovery::network_view(net) {
        return Err("protocol observer mismatch".into());
    }
    let execution = child(
        "recover-execution",
        &[
            "--chain".into(),
            chain,
            rpc::bytes_to_hex(&net.anchor.script),
            root.join("execution-observer")
                .to_string_lossy()
                .into_owned(),
        ],
    )?;
    if execution["state_root"] != json!(engine.state_root())
        || execution["header"] != json!(engine.head())
        || execution["batch_count"] != json!(engine.anchor().next_batch_number)
    {
        return Err("execution observer mismatch".into());
    }
    let report = json!({"protocol":protocol,"execution":execution});
    lab.evidence
        .push(json!({"label":label,"result":"control_passed","observers":report}));
    println!("{label}: independent protocol and EVM recovery matched");
    Ok(report)
}
fn run() -> Result<(), String> {
    let path = std::env::var("TACTUS_EVIDENCE_PATH").map_err(|_| "use isolated launcher")?;
    let root = std::env::var("TACTUS_RUN_DIR").map_err(|_| "run directory")?;
    let root = Path::new(&root);
    let peer = std::env::var("TACTUS_PEER_RPC_ADDR").map_err(|_| "peer address")?;
    let mut lab = Lab::connect_with_script("artifacts/tactus_o1_anchor_script.elf")?;
    let mut results = json!({"suite":"a3-network-reorg-v1","complete":false,"production_ready":false,"G2":"OPEN","G6":"OPEN","scope":"controlled two-node P2P partition and real fork choice on permanent Dummy devnet; not spontaneous mainnet reorg or validity settlement"});
    let outcome = (|| {
        let chain = rpc::call("get_block_hash", json!(["0x0"]))?;
        if chain != rpc::call_at(&peer, "get_block_hash", json!(["0x0"]))? {
            return Err("peer genesis mismatch".into());
        }
        let elf =
            std::fs::read("artifacts/tactus_o1_sealed_script.elf").map_err(|e| e.to_string())?;
        let code = ckb_blake2b(&elf);
        let dep = lab.publish_cells("network/deploy sealed gate", &[elf], 0, true)?[0];
        lab.deps.push(dep);
        let (mut genesis, [deploy, write, clear]) = fixture()?;
        let allocation = genesis.allocation_bytes().map_err(|e| e.to_string())?;
        let anchor_elf = lab.ordering_elf.clone();
        let mut net = bootstrap_with_allocation(&mut lab, code, 4, &anchor_elf, &allocation)?;
        genesis.rollup_id = net.anchor.state.rollup_id.into();
        std::fs::write(
            root.join("execution-genesis.json"),
            serde_json::to_vec_pretty(&genesis).map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?;
        let mut engine = Executor::new(&genesis).map_err(|e| e.to_string())?;
        for (i, payload) in [deploy, write, vec![0xff], vec![0xfe]]
            .into_iter()
            .enumerate()
        {
            append(
                &mut lab,
                &mut net,
                i,
                0,
                payload,
                "network/common pending message",
            )?;
        }
        for _ in 0..s::BATCHES_PER_EPOCH {
            advance(
                &mut lab,
                &mut net,
                0,
                &mut engine,
                "network/common genesis epoch",
            )?;
        }
        let common = rpc::call("get_tip_header", json!([]))?;
        connect(&peer)?;
        converged(&peer, &common["hash"])?;
        lab.evidence.push(json!({"label":"network/common prefix synchronized over P2P","result":"control_passed","tip":common,"main_peers":rpc::call("get_peers",json!([]))?,"peer_peers":rpc::call_at(&peer,"get_peers",json!([]))?}));
        let common_root = engine.state_root();
        observe(
            &mut lab,
            &net,
            &engine,
            root,
            "network/common prefix observers",
        )?;
        let wallets: Vec<_> = lab.wallets.iter().map(|w| (w.point, w.capacity)).collect();
        let (alternative, _) = append_tx(&lab, &net, 0, 0, clear.clone())?;
        partition(&peer)?;
        lab.evidence.push(json!({"label":"network/nodes have zero peers during partition","result":"control_passed","main_peers":rpc::call("get_peers",json!([]))?,"peer_peers":rpc::call_at(&peer,"get_peers",json!([]))?}));
        seal(&mut lab, &mut net, 1, "network/main branch seal to orphan")?;
        let orphan_snapshot = net.snapshot.as_ref().unwrap().0;
        advance(
            &mut lab,
            &mut net,
            1,
            &mut engine,
            "network/main branch executes deployment and storage write",
        )?;
        let orphan_root = engine.state_root();
        if orphan_root == common_root {
            return Err("orphan branch must change EVM state".into());
        }
        let orphan_tip = rpc::call("get_tip_header", json!([]))?;
        let orphan_report = observe(
            &mut lab,
            &net,
            &engine,
            root,
            "network/orphan branch observers",
        )?;
        let alternative_cycles = rpc::call_at(&peer, "estimate_cycles", json!([alternative]))?;
        let alternative_hash = rpc::call_at(
            &peer,
            "send_transaction",
            json!([alternative, "passthrough"]),
        )?
        .as_str()
        .ok_or("alternative hash")?
        .to_owned();
        let mut accepted = false;
        for _ in 0..20 {
            if rpc::call_at(&peer, "get_transaction", json!([alternative_hash]))?["tx_status"]
                ["status"]
                == "committed"
            {
                accepted = true;
                break;
            }
            peer_mine(&peer, 1)?;
        }
        if !accepted {
            return Err("peer alternative admission did not commit".into());
        }
        let target = number(&orphan_tip["number"])? + 6;
        let current = number(&rpc::call_at(&peer, "get_tip_header", json!([]))?["number"])?;
        peer_mine(&peer, target.saturating_sub(current))?;
        let winning = rpc::call_at(&peer, "get_tip_header", json!([]))?;
        if rpc::call("get_tip_header", json!([]))?["hash"] != orphan_tip["hash"]
            || rpc::call_at(&peer, "get_block_hash", json!([common["number"]]))? != common["hash"]
            || rpc::call_at(&peer, "get_block_hash", json!([orphan_tip["number"]]))?
                == orphan_tip["hash"]
        {
            return Err("partition did not produce independent competing branches".into());
        }
        lab.evidence.push(json!({"label":"network/competing peer admission and longer isolated branch","result":"control_passed","transaction":alternative,"hash":alternative_hash,"cycles":alternative_cycles,"common_tip":common,"orphan_tip":orphan_tip,"winning_tip":winning,"peer_transaction":rpc::call_at(&peer,"get_transaction",json!([alternative_hash]))?}));
        connect(&peer)?;
        converged(&peer, &winning["hash"])?;
        if recovery::assert_canonical(
            orphan_report["protocol"]["pinned_height"]
                .as_u64()
                .ok_or("height")?,
            orphan_report["protocol"]["pinned_hash"]
                .as_str()
                .ok_or("hash")?,
        )
        .is_ok()
        {
            return Err("orphan protocol observation survived P2P reorg".into());
        }
        live(orphan_snapshot, false)?;
        let recovered = sealed_recovery::recover_sealed(
            &net.gate.script,
            &net.anchor.script,
            chain.as_str().ok_or("chain")?,
        )?;
        net = recovered.network;
        if net.schedule.epoch != 0
            || net.schedule.batches != 8
            || net.snapshot.is_some()
            || net.lanes[0].1.queue.last() != Some(&clear)
            || net.lanes.iter().map(|(_, l)| l.queue.len()).sum::<usize>() != 5
        {
            return Err("network reorg did not recover all surviving and new obligations".into());
        }
        engine = Executor::new(&genesis).map_err(|e| e.to_string())?;
        for b in recovery::recover_published_batches(&net.anchor.script)?.batches {
            engine
                .apply_batch(&b.input_bytes)
                .map_err(|e| e.to_string())?;
        }
        if engine.state_root() != common_root || engine.anchor() != &net.anchor.state {
            return Err("orphan EVM state not rolled back".into());
        }
        let restored = observe(
            &mut lab,
            &net,
            &engine,
            root,
            "network/reorg cold observers restore canonical obligations and EVM",
        )?;
        for (w, (p, c)) in lab.wallets.iter_mut().zip(wallets) {
            w.point = p;
            w.capacity = c;
        }
        lab.wallets[0].point = lab::point(&alternative_hash, 1)?;
        lab.wallets[0].capacity -= TX_FEE;
        live(lab.wallets[0].point, true)?;
        live(lab.wallets[1].point, true)?;
        lab.record_committed(
            "network/peer-only message is now canonical on main",
            &alternative_hash,
        )?;
        seal(
            &mut lab,
            &mut net,
            1,
            "network/recovered builder seals five canonical obligations",
        )?;
        for _ in 0..s::BATCHES_PER_EPOCH {
            advance(
                &mut lab,
                &mut net,
                1,
                &mut engine,
                "network/resumed mandatory processing",
            )?;
        }
        if net.schedule.cursor != 5
            || engine.state_root() == orphan_root
            || engine.state_root() == common_root
        {
            return Err("canonical replacement did not execute new storage transition".into());
        }
        let final_tip = rpc::call("get_tip_header", json!([]))?;
        converged(&peer, &final_tip["hash"])?;
        let final_report = observe(
            &mut lab,
            &net,
            &engine,
            root,
            "network/final observers agree after resumed execution",
        )?;
        results["complete"] = json!(true);
        results["network_reorg"] = json!({"common_height":number(&common["number"])?,"orphan_height":number(&orphan_tip["number"])?,"winning_height":number(&winning["number"])?,"orphaned_blocks":number(&orphan_tip["number"])?-number(&common["number"])?,"protocol_observer_processes":4,"execution_observer_processes":4,"recovered_messages":5,"processed_messages":net.schedule.cursor,"canonical_batches":net.anchor.state.next_batch_number,"restored_observers":restored,"final_observers":final_report,"orphan_state_root":orphan_root,"common_state_root":common_root,"final_state_root":engine.state_root(),"truncate_used":false,"submit_block_used":false,"proof_settlement":"NOT_IMPLEMENTED"});
        Ok::<_, String>(())
    })();
    results["error"] = json!(outcome.as_ref().err());
    lab.save(&path, results)?;
    outcome
}
fn main() {
    if let Err(e) = run() {
        eprintln!("NETWORK EXPERIMENT FAILED: {e}");
        std::process::exit(1);
    }
}
