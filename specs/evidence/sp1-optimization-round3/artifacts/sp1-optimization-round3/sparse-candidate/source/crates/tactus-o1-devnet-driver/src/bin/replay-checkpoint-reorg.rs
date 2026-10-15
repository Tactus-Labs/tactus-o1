//! Two-node P2P reorg of authenticated history checkpoints, without truncate.
use serde_json::{json, Value};
use std::time::{Duration, Instant};
use tactus_o1_devnet_driver::{
    batch_lab::{self, Anchor},
    lab::{self, Lab},
    molecule, recovery, rpc,
    tx::{self, CellOutPoint, OutSpec, TX_FEE},
};
use tactus_o1_ordering_script::ckb_blake2b;
use tactus_o1_protocol::batch::{self, AnchorState};
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

fn advance_tx(
    lab: &Lab,
    anchor: &Anchor,
    code: &[u8; 32],
    timestamp: u64,
) -> Result<(Value, AnchorState, Vec<u8>), String> {
    let bytes = batch_lab::encode(anchor.state, vec![batch_lab::block(timestamp, vec![])])?;
    let next = batch::validate_batch(&bytes, &anchor.state)
        .map_err(|e| format!("{e:?}"))?
        .next;
    let script = molecule::script(code, 2, &ckb_blake2b(&anchor.script));
    let lock = lab.wallets[0].key.lock_script();
    let checkpoint = OutSpec {
        capacity: OutSpec::required_capacity(&lock, Some(&script), 200),
        lock,
        type_script: Some(script),
        data: next.encode().to_vec(),
    };
    let tx = batch_lab::shape(
        lab,
        anchor,
        0,
        vec![
            checkpoint,
            batch_lab::head_output(anchor, next),
            batch_lab::da_output(anchor, &bytes),
        ],
        Some(&2u32.to_le_bytes()),
    )?;
    Ok((tx, next, bytes))
}
fn dependency_tx(lab: &Lab, checkpoint: CellOutPoint) -> Result<Value, String> {
    let wallet = &lab.wallets[0];
    let mut deps = lab.deps.clone();
    deps.push(checkpoint);
    let output = OutSpec {
        capacity: wallet.capacity.checked_sub(TX_FEE).ok_or("fee")?,
        lock: wallet.key.lock_script(),
        type_script: None,
        data: vec![],
    };
    tx::build_and_sign(
        &wallet.key,
        &lab.secp,
        &deps,
        &[(wallet.point, wallet.capacity)],
        &[output],
        None,
    )
    .map(|(_, t)| t)
}
fn live(point: CellOutPoint, expected: bool) -> Result<Value, String> {
    let view = rpc::call(
        "get_live_cell",
        json!([{"tx_hash":rpc::bytes_to_hex(&point.tx_hash),"index":format!("0x{:x}",point.index)},true]),
    )?;
    if (view["status"] == "live") != expected {
        return Err(format!("checkpoint liveness differs: {view}"));
    }
    Ok(view)
}
fn run() -> Result<(), String> {
    let path = std::env::var("TACTUS_EVIDENCE_PATH").map_err(|_| "use isolated launcher")?;
    let peer = std::env::var("TACTUS_PEER_RPC_ADDR").map_err(|_| "peer address")?;
    let mut lab = Lab::connect_with_script("artifacts/tactus_o1_anchor_script.elf")?;
    let mut result = json!({"suite":"checkpoint-p2p-reorg-v1","complete":false,"settled":false,"production_ready":false,"G3":"OPEN","truncate_used":false,"submit_block_used":false});
    let outcome = (|| {
        if rpc::call("get_block_hash", json!(["0x0"]))?
            != rpc::call_at(&peer, "get_block_hash", json!(["0x0"]))?
        {
            return Err("peer genesis differs".into());
        }
        let elf = std::fs::read("artifacts/tactus_o1_history_checkpoint_script.elf")
            .map_err(|e| e.to_string())?;
        let code = ckb_blake2b(&elf);
        let dep = lab.publish_cells("checkpoint-reorg/deploy checkpoint code", &[elf], 0, true)?[0];
        lab.deps.push(dep);
        let anchor = batch_lab::create(&mut lab, [9; 32], 777)?;
        result["checkpoint_code_hash"] = rpc::bytes_to_hex(&code).into();
        result["anchor_type_hash"] = rpc::bytes_to_hex(&ckb_blake2b(&anchor.script)).into();
        let common = rpc::call("get_tip_header", json!([]))?;
        connect(&peer)?;
        converged(&peer, &common["hash"])?;
        let (original, original_state, _) = advance_tx(&lab, &anchor, &code, 1)?;
        let (alternative, alternative_state, alternative_bytes) =
            advance_tx(&lab, &anchor, &code, 2)?;
        partition(&peer)?;
        let partition_view = json!({"main_peers":rpc::call("get_peers",json!([]))?,"peer_peers":rpc::call_at(&peer,"get_peers",json!([]))?});
        let orphan = lab.commit(
            "checkpoint-reorg/main branch checkpoint to orphan",
            &original,
        )?;
        let orphan_point = lab::point(&orphan, 0)?;
        let orphan_live_before = live(orphan_point, true)?;
        let orphan_tip = rpc::call("get_tip_header", json!([]))?;
        let alternate_cycles = rpc::call_at(&peer, "estimate_cycles", json!([alternative]))?;
        let alternate_hash = rpc::call_at(
            &peer,
            "send_transaction",
            json!([alternative, "passthrough"]),
        )?
        .as_str()
        .ok_or("peer hash")?
        .to_owned();
        let mut accepted = false;
        for _ in 0..20 {
            if rpc::call_at(&peer, "get_transaction", json!([alternate_hash]))?["tx_status"]
                ["status"]
                == "committed"
            {
                accepted = true;
                break;
            }
            peer_mine(&peer, 1)?;
        }
        if !accepted {
            return Err("peer replacement did not commit".into());
        }
        let target = number(&orphan_tip["number"])? + 6;
        let height = number(&rpc::call_at(&peer, "get_tip_header", json!([]))?["number"])?;
        peer_mine(&peer, target.saturating_sub(height))?;
        let winning = rpc::call_at(&peer, "get_tip_header", json!([]))?;
        if rpc::call("get_tip_header", json!([]))?["hash"] != orphan_tip["hash"]
            || rpc::call_at(&peer, "get_block_hash", json!([common["number"]]))? != common["hash"]
            || rpc::call_at(&peer, "get_block_hash", json!([orphan_tip["number"]]))?
                == orphan_tip["hash"]
        {
            return Err("branches did not diverge during partition".into());
        }
        let peer_transaction = rpc::call_at(&peer, "get_transaction", json!([alternate_hash]))?;
        connect(&peer)?;
        converged(&peer, &winning["hash"])?;
        if recovery::assert_canonical(
            number(&orphan_tip["number"])?,
            orphan_tip["hash"].as_str().ok_or("orphan hash")?,
        )
        .is_ok()
        {
            return Err("orphan pin survived".into());
        }
        let orphan_live_after = live(orphan_point, false)?;
        live(lab::point(&orphan, 1)?, false)?;
        let canonical_point = lab::point(&alternate_hash, 0)?;
        let canonical_live = live(canonical_point, true)?;
        if canonical_live["cell"]["data"]["content"]
            != rpc::bytes_to_hex(&alternative_state.encode())
        {
            return Err("canonical checkpoint differs".into());
        }
        let recovered = recovery::recover_published_batches(&anchor.script)?;
        if recovered.state != alternative_state
            || recovered.batches.len() != 1
            || recovered.batches[0].input_bytes != alternative_bytes
            || recovered.state == original_state
        {
            return Err("canonical history reconstruction did not replace orphan".into());
        }
        lab.record_committed(
            "checkpoint-reorg/peer checkpoint is canonical",
            &alternate_hash,
        )?;
        lab.wallets[0].point = lab::point(&alternate_hash, 3)?;
        lab.wallets[0].capacity = number(&alternative["outputs"][3]["capacity"])?;
        let bad = dependency_tx(&lab, orphan_point)?;
        lab.reject(
            "checkpoint-reorg/orphan checkpoint dependency",
            &bad,
            "TransactionFailedToResolve",
        )?;
        let good = dependency_tx(&lab, canonical_point)?;
        let dependency_commit = lab.commit(
            "checkpoint-reorg/canonical checkpoint dependency accepted",
            &good,
        )?;
        let final_tip = rpc::call("get_tip_header", json!([]))?;
        converged(&peer, &final_tip["hash"])?;
        result["reorg"] = json!({"common_tip":common,"orphan_tip":orphan_tip,"winning_tip":winning,"final_tip":final_tip,"partition":partition_view,"orphaned_blocks":number(&orphan_tip["number"])?-number(&common["number"])?,"orphan_transaction_hash":orphan,"orphan_live_before":orphan_live_before,"orphan_live_after":orphan_live_after,"alternative_transaction":alternative,"alternative_cycles":alternate_cycles,"alternative_hash":alternate_hash,"peer_transaction_before_reconnection":peer_transaction,"canonical_live_after":canonical_live,"recovered_anchor":rpc::bytes_to_hex(&recovered.state.encode()),"canonical_batches":recovered.batches.len(),"dependency_commit":dependency_commit});
        result["complete"] = true.into();
        Ok::<_, String>(())
    })();
    result["error"] = json!(outcome.as_ref().err());
    lab.save(&path, result)?;
    outcome
}
fn main() {
    if let Err(e) = run() {
        eprintln!("CHECKPOINT REORG FAILED: {e}");
        std::process::exit(1);
    }
}
