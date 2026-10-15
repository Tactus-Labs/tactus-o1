//! Roll back actual A3 proof fulfillment, then reuse the same proof with fresh fees.
use serde_json::{json, Value};
use tactus_o1_devnet_driver::{
    lab::{self, Lab},
    p2p_lab::{connect, converged, partition, peer_mine},
    recovery, rpc,
    sealed_lab::Network,
    settlement_lab::{advance_tip, consumed_tip},
    tx::{self, OutSpec, TX_FEE},
};

pub fn prepare(lab: &Lab) -> Result<Value, String> {
    let peer = std::env::var("TACTUS_PEER_RPC_ADDR").map_err(|_| "peer")?;
    if rpc::call("get_block_hash", json!(["0x0"]))?
        != rpc::call_at(&peer, "get_block_hash", json!(["0x0"]))?
    {
        return Err("peer chain differs".into());
    }
    let common = rpc::call("get_tip_header", json!([]))?;
    connect(&peer)?;
    converged(&peer, &common["hash"])?;
    let wallet = &lab.wallets[0];
    let (_, alternative) = tx::build_and_sign(
        &wallet.key,
        &lab.secp,
        &lab.deps,
        &[(wallet.point, wallet.capacity)],
        &[OutSpec {
            capacity: wallet.capacity - TX_FEE,
            lock: wallet.key.lock_script(),
            type_script: None,
            data: vec![],
        }],
        None,
    )?;
    partition(&peer)?;
    Ok(
        json!({"peer":peer,"common_tip":common,"alternative":alternative,
        "partition":{"main":rpc::call("get_peers",json!([]))?,"peer":rpc::call_at(&peer,"get_peers",json!([]))?}}),
    )
}
fn cold(peer: Option<&str>, chain: &[u8], net: &Network, tip: &[u8]) -> Result<Value, String> {
    let mut command = std::process::Command::new("target/debug/recover-obligations");
    command.args([
        rpc::bytes_to_hex(chain),
        rpc::bytes_to_hex(&net.gate.script),
        rpc::bytes_to_hex(&net.anchor.script),
        rpc::bytes_to_hex(tip),
    ]);
    if let Some(peer) = peer {
        command.env("TACTUS_CKB_RPC_ADDR", peer);
    }
    let output = command.output().map_err(|e| e.to_string())?;
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).into_owned());
    }
    serde_json::from_slice(&output.stdout).map_err(|e| e.to_string())
}
pub struct Context<'a> {
    pub network: &'a Network,
    pub chain: &'a [u8],
    pub script: &'a [u8],
    pub input: &'a Value,
    pub original: &'a Value,
    pub orphan: &'a str,
    pub witness: &'a [u8],
}
pub fn qualify(lab: &mut Lab, plan: Value, context: Context<'_>) -> Result<Value, String> {
    let Context {
        network,
        chain,
        script,
        input,
        original,
        orphan,
        witness,
    } = context;
    let peer = plan["peer"].as_str().ok_or("peer")?;
    let common = &plan["common_tip"];
    let orphan_tip = rpc::call("get_tip_header", json!([]))?;
    let old_point = json!({"tx_hash":orphan,"index":"0x0"});
    let before = rpc::call("get_live_cell", json!([old_point, true]))?;
    if before["status"] != "live" {
        return Err("proved A3 Tip not initially live".into());
    }
    let alternative = &plan["alternative"];
    let alternative_hash = rpc::call_at(
        peer,
        "send_transaction",
        json!([alternative, "passthrough"]),
    )?
    .as_str()
    .ok_or("alternative hash")?
    .to_owned();
    let mut committed = false;
    for _ in 0..20 {
        if rpc::call_at(peer, "get_transaction", json!([alternative_hash]))?["tx_status"]["status"]
            == "committed"
        {
            committed = true;
            break;
        }
        peer_mine(peer, 1)?;
    }
    if !committed {
        return Err("peer fee spend did not commit".into());
    }
    let target = super::number(&orphan_tip["number"])? + 6;
    let height = super::number(&rpc::call_at(peer, "get_tip_header", json!([]))?["number"])?;
    peer_mine(peer, target.saturating_sub(height))?;
    let winning = rpc::call_at(peer, "get_tip_header", json!([]))?;
    if rpc::call("get_tip_header", json!([]))?["hash"] != orphan_tip["hash"]
        || rpc::call_at(peer, "get_block_hash", json!([common["number"]]))? != common["hash"]
        || rpc::call_at(peer, "get_block_hash", json!([orphan_tip["number"]]))?
            == orphan_tip["hash"]
    {
        return Err("A3 proof branches did not diverge".into());
    }
    connect(peer)?;
    converged(peer, &winning["hash"])?;
    if recovery::assert_canonical(
        super::number(&orphan_tip["number"])?,
        orphan_tip["hash"].as_str().ok_or("orphan hash")?,
    )
    .is_ok()
    {
        return Err("orphan proof pin survived".into());
    }
    let after = rpc::call("get_live_cell", json!([old_point, true]))?;
    let status = rpc::call("get_transaction", json!([orphan]))?;
    let initial = &input["settlement_tip"];
    let restored = rpc::call("get_live_cell", json!([initial, true]))?;
    if after["status"] == "live"
        || status["tx_status"]["status"] == "committed"
        || restored["status"] != "live"
    {
        return Err("A3 proof Tip did not roll back".into());
    }
    let rolled = cold(None, chain, network, script)?;
    let peer_rolled = cold(Some(peer), chain, network, script)?;
    if rolled != peer_rolled
        || rolled["counts"] != json!({"admitted":0,"sealed":0,"published":4,"settled":0})
        || rolled["settlement"]["published_batches"] != 9
        || rolled["settlement"]["settled_batches"] != 0
        || rolled["settlement"]["tip"] != *initial
        || rolled["settlement"]["data"] != input["initial_tip_data"]
    {
        return Err("cold recovery retained orphan proof fulfillment".into());
    }
    lab.record_committed(
        "sealed-proof-reorg/peer fee spend is canonical",
        &alternative_hash,
    )?;
    lab.reject(
        "sealed-proof-reorg/orphan proof funding cannot replay",
        original,
        "TransactionFailedToResolve",
    )?;
    lab.wallets[0].point = lab::point(&alternative_hash, 0)?;
    lab.wallets[0].capacity = super::number(&alternative["outputs"][0]["capacity"])?;
    let recovered = recovery::recover_published_batches(&network.anchor.script)?;
    let batches: Vec<_> = recovered
        .batches
        .iter()
        .map(|b| rpc::bytes_to_hex(&b.input_bytes))
        .collect();
    if json!(batches) != input["batches"] {
        return Err("A3 canonical proof inputs changed".into());
    }
    let initial_point = lab::point(
        initial["tx_hash"].as_str().ok_or("initial hash")?,
        super::number(&initial["index"])? as u32,
    )?;
    let data = rpc::decode_hex(input["next_tip_data"].as_str().ok_or("Tip data")?)?;
    let replacement = advance_tip(
        lab,
        initial_point,
        input["tip_capacity"].as_u64().ok_or("capacity")?,
        script,
        &data,
        witness,
    )?;
    let hash = lab.commit(
        "sealed-proof-reorg/same proof fulfills duties again",
        &replacement,
    )?;
    if hash == orphan {
        return Err("replacement reused spent funding".into());
    }
    let consumption = consumed_tip(initial_point, &hash)?;
    let packed = rpc::call("get_transaction", json!([hash, "0x0"]))?;
    let wire = rpc::decode_hex(packed["transaction"].as_str().ok_or("packed")?)?.len();
    if wire != tx::wire_bytes(&replacement)? {
        return Err("replacement wire differs".into());
    }
    let final_tip = rpc::call("get_tip_header", json!([]))?;
    converged(peer, &final_tip["hash"])?;
    let final_report = cold(None, chain, network, script)?;
    let peer_final = cold(Some(peer), chain, network, script)?;
    if final_report != peer_final
        || final_report["counts"] != json!({"admitted":0,"sealed":0,"published":0,"settled":4})
        || final_report["settlement"]["settled_batches"] != 9
        || final_report["settlement"]["proved_transitions"] != 1
        || final_report["settlement"]["tip"]["tx_hash"] != hash
        || final_report["settlement"]["data"] != input["next_tip_data"]
    {
        return Err("cold recovery failed replacement proof fulfillment".into());
    }
    Ok(
        json!({"plan":plan,"orphan_tip":orphan_tip,"winning_tip":winning,"final_tip":final_tip,"orphan_hash":orphan,"orphan_live_before":before,"orphan_live_after":after,"orphan_transaction_after":status,"restored_initial_tip":restored,"cold_after_rollback":rolled,"peer_cold_after_rollback":peer_rolled,"alternative_hash":alternative_hash,"replacement_hash":hash,"replacement_consumption":consumption,"replacement_node_wire_bytes":wire,"replacement_fee_shannons":TX_FEE,"cold_after_replacement":final_report,"peer_cold_after_replacement":peer_final,"orphaned_blocks":super::number(&orphan_tip["number"])?-super::number(&common["number"])?,"truncate_used":false,"submit_block_used":false,"settled":true,"production_ready":false}),
    )
}
