//! Planned real-P2P rollback of a proved Tip and proof reuse with fresh funding.
use serde_json::{json, Value};
use tactus_o1_devnet_driver::{
    lab::{self, Lab},
    p2p_lab::{connect, converged, partition, peer_mine},
    recovery, rpc,
    tx::{self, TX_FEE},
};
fn number(v: &Value) -> Result<u64, String> {
    u64::from_str_radix(v.as_str().ok_or("number")?.trim_start_matches("0x"), 16)
        .map_err(|e| e.to_string())
}
pub fn prepare(lab: &Lab) -> Result<Value, String> {
    let peer = std::env::var("TACTUS_PEER_RPC_ADDR").map_err(|_| "peer address")?;
    if rpc::call("get_block_hash", json!(["0x0"]))?
        != rpc::call_at(&peer, "get_block_hash", json!(["0x0"]))?
    {
        return Err("peer genesis differs".into());
    }
    let common = rpc::call("get_tip_header", json!([]))?;
    connect(&peer)?;
    converged(&peer, &common["hash"])?;
    // Spend only the first proof transaction's fee input on the alternate branch.
    // This prevents the orphan proof from silently returning through the txpool.
    let alternative = super::ordinary(lab, vec![])?;
    partition(&peer)?;
    Ok(
        json!({"peer":peer,"common_tip":common,"alternative_transaction":alternative,
        "partition":{"main_peers":rpc::call("get_peers",json!([]))?,
        "peer_peers":rpc::call_at(&peer,"get_peers",json!([]))?}}),
    )
}

fn cell(point: &Value) -> Result<Value, String> {
    rpc::call("get_live_cell", json!([point, true]))
}

fn cold_peer(peer: &str, chain: &[u8], anchor: &[u8], tip: &[u8]) -> Result<Value, String> {
    let output = std::process::Command::new("target/debug/recover-settlement")
        .env("TACTUS_CKB_RPC_ADDR", peer)
        .args([
            rpc::bytes_to_hex(chain),
            rpc::bytes_to_hex(anchor),
            rpc::bytes_to_hex(tip),
        ])
        .output()
        .map_err(|e| e.to_string())?;
    if !output.status.success() {
        return Err(format!(
            "peer cold recovery: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    serde_json::from_slice(&output.stdout).map_err(|e| e.to_string())
}

pub fn qualify(
    lab: &mut Lab,
    plan: Value,
    input: &Value,
    original: &Value,
    orphan: &str,
    witness: &[u8],
) -> Result<Value, String> {
    let peer = plan["peer"].as_str().ok_or("peer")?;
    let common = &plan["common_tip"];
    let alternative = &plan["alternative_transaction"];
    let orphan_tip = rpc::call("get_tip_header", json!([]))?;
    let orphan_point = json!({"tx_hash":orphan,"index":"0x0"});
    let before = cell(&orphan_point)?;
    if before["status"] != "live" {
        return Err("proved Tip is not initially live".into());
    }
    let alternate_cycles = rpc::call_at(peer, "estimate_cycles", json!([alternative]))?;
    let alternative_hash = rpc::call_at(
        peer,
        "send_transaction",
        json!([alternative, "passthrough"]),
    )?
    .as_str()
    .ok_or("peer hash")?
    .to_owned();
    let mut accepted = false;
    for _ in 0..20 {
        if rpc::call_at(peer, "get_transaction", json!([alternative_hash]))?["tx_status"]["status"]
            == "committed"
        {
            accepted = true;
            break;
        }
        peer_mine(peer, 1)?;
    }
    if !accepted {
        return Err("alternate funding spend did not commit".into());
    }
    let target = number(&orphan_tip["number"])? + 6;
    let height = number(&rpc::call_at(peer, "get_tip_header", json!([]))?["number"])?;
    peer_mine(peer, target.saturating_sub(height))?;
    let winning = rpc::call_at(peer, "get_tip_header", json!([]))?;
    if rpc::call("get_tip_header", json!([]))?["hash"] != orphan_tip["hash"]
        || rpc::call_at(peer, "get_block_hash", json!([common["number"]]))? != common["hash"]
        || rpc::call_at(peer, "get_block_hash", json!([orphan_tip["number"]]))?
            == orphan_tip["hash"]
    {
        return Err("settlement branches did not diverge".into());
    }
    let peer_transaction = rpc::call_at(peer, "get_transaction", json!([alternative_hash]))?;
    connect(peer)?;
    converged(peer, &winning["hash"])?;
    if recovery::assert_canonical(
        number(&orphan_tip["number"])?,
        orphan_tip["hash"].as_str().ok_or("orphan hash")?,
    )
    .is_ok()
    {
        return Err("orphan settlement pin survived".into());
    }
    let after = cell(&orphan_point)?;
    let original_status = rpc::call("get_transaction", json!([orphan]))?;
    let initial_point = &original["inputs"][0]["previous_output"];
    let restored = cell(initial_point)?;
    if after["status"] == "live"
        || original_status["tx_status"]["status"] == "committed"
        || restored["status"] != "live"
    {
        return Err("settlement UTXO state did not roll back".into());
    }
    let chain = rpc::decode_hex(
        rpc::call("get_block_hash", json!(["0x0"]))?
            .as_str()
            .ok_or("chain")?,
    )?;
    let anchor_script = rpc::decode_hex(
        input["anchor_type_script"]
            .as_str()
            .ok_or("Anchor script")?,
    )?;
    let script = rpc::decode_hex(
        input["settlement_type_script"]
            .as_str()
            .ok_or("Tip script")?,
    )?;
    let cold = super::cold_recovery(&chain, &anchor_script, &script)?;
    if cold["initialized"] != false
        || cold["settled_batches"] != 0
        || cold["proved_transitions"] != 0
        || cold["published_batches"] != 1
        || cold["tip"] != *initial_point
    {
        return Err("cold recovery retained orphan settlement".into());
    }
    let cold_on_peer = cold_peer(peer, &chain, &anchor_script, &script)?;
    if cold_on_peer != cold {
        return Err("independent peer rollback recovery differs".into());
    }
    lab.record_committed(
        "settlement-reorg/peer fee spend is canonical",
        &alternative_hash,
    )?;
    lab.wallets[0].point = lab::point(&alternative_hash, 0)?;
    lab.wallets[0].capacity = number(&alternative["outputs"][0]["capacity"])?;
    lab.reject(
        "settlement-reorg/orphan transaction old funding",
        original,
        "TransactionFailedToResolve",
    )?;
    let snapshot = recovery::recover_published_batches(&anchor_script)?;
    if snapshot.batches.len() != 1
        || rpc::bytes_to_hex(&snapshot.batches[0].input_bytes) != input["batches"][0]
    {
        return Err("canonical proof input changed during fee-only reorg".into());
    }
    let data = rpc::decode_hex(input["next_tip_data"].as_str().ok_or("next Tip")?)?;
    let capacity = number(&original["outputs"][0]["capacity"])?;
    let point = lab::point(initial_point["tx_hash"].as_str().ok_or("initial tx")?, 0)?;
    let replacement = super::advance_tip(lab, point, capacity, &script, &data, witness)?;
    let cycles = rpc::call("estimate_cycles", json!([replacement]))?;
    let replacement_hash = lab.commit(
        "settlement-reorg/recovered proof with fresh funding",
        &replacement,
    )?;
    if replacement_hash == orphan {
        return Err("recovery did not replace spent funding".into());
    }
    let packed = rpc::call("get_transaction", json!([replacement_hash, "0x0"]))?;
    let node_bytes = rpc::decode_hex(packed["transaction"].as_str().ok_or("packed")?)?.len();
    if node_bytes != tx::wire_bytes(&replacement)? {
        return Err("replacement wire mismatch".into());
    }
    let final_tip = rpc::call("get_tip_header", json!([]))?;
    converged(peer, &final_tip["hash"])?;
    let recovered = super::cold_recovery(&chain, &anchor_script, &script)?;
    if recovered["initialized"] != true
        || recovered["settled_batches"] != 1
        || recovered["proved_transitions"] != 1
        || recovered["tip"]["tx_hash"] != replacement_hash
        || recovered["data"] != input["next_tip_data"]
    {
        return Err("recovery did not reconstruct replacement proof transition".into());
    }
    let recovered_on_peer = cold_peer(peer, &chain, &anchor_script, &script)?;
    if recovered_on_peer != recovered {
        return Err("independent peer replacement recovery differs".into());
    }
    Ok(
        json!({"common_tip":common,"partition":plan["partition"],"orphan_tip":orphan_tip,
        "winning_tip":winning,"final_tip":final_tip,"orphan_hash":orphan,
        "orphan_live_before":before,"orphan_live_after":after,"orphan_transaction_after":original_status,
        "restored_initial_tip":restored,"cold_after_rollback":cold,"peer_cold_after_rollback":cold_on_peer,
        "alternative_transaction":alternative,"alternative_hash":alternative_hash,
        "alternative_cycles":alternate_cycles,"peer_transaction_before_reconnection":peer_transaction,
        "replacement_hash":replacement_hash,"replacement_cycles":cycles,"replacement_node_wire_bytes":node_bytes,
        "replacement_fee_shannons":TX_FEE,"cold_after_replacement":recovered,"peer_cold_after_replacement":recovered_on_peer,
        "orphaned_blocks":number(&orphan_tip["number"])?-number(&common["number"])?,
        "truncate_used":false,"submit_block_used":false,"production_ready":false}),
    )
}
