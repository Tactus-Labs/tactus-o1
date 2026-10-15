//! Roll back the immutable seal and publication via actual peer fork selection.
use serde_json::{json, Value};
use tactus_o1_devnet_driver::{
    lab::{self, Lab},
    p2p_lab::{connect, converged, partition, peer_mine},
    recovery, rpc, sealed_lab as sealed, sealed_recovery,
    tx::{self, OutSpec, TX_FEE},
};

pub fn prepare(lab: &Lab) -> Result<Value, String> {
    let peer = std::env::var("TACTUS_PEER_RPC_ADDR").map_err(|_| "peer")?;
    if rpc::call("get_block_hash", json!(["0x0"]))?
        != rpc::call_at(&peer, "get_block_hash", json!(["0x0"]))?
    {
        return Err("peer chain mismatch".into());
    }
    let common = rpc::call("get_tip_header", json!([]))?;
    connect(&peer)?;
    converged(&peer, &common["hash"])?;
    let wallet = &lab.wallets[1];
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
        json!({"peer":peer,"common_tip":common,"alternative":alternative,"publisher_fee_point":super::point(lab.wallets[0].point),"publisher_capacity":lab.wallets[0].capacity,"partition":{"main":rpc::call("get_peers",json!([]))?,"peer":rpc::call_at(&peer,"get_peers",json!([]))?}}),
    )
}
fn cold(
    peer: Option<&str>,
    chain: &[u8],
    net: &sealed::Network,
    tip: &[u8],
) -> Result<Value, String> {
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
pub fn qualify(
    lab: &mut Lab,
    plan: Value,
    net: &sealed::Network,
    chain: &[u8],
    tip: &[u8],
    publication: &Value,
) -> Result<Value, String> {
    let mut observer = super::observer::Probe::start(chain, &net.anchor.script, tip)?;
    let observed_before = observer
        .as_mut()
        .map(|p| p.observe(9, None, false))
        .transpose()?;
    let peer = plan["peer"].as_str().ok_or("peer")?;
    let common = &plan["common_tip"];
    let orphan = rpc::call("get_tip_header", json!([]))?;
    let alternative = &plan["alternative"];
    let alternative_hash = rpc::call_at(
        peer,
        "send_transaction",
        json!([alternative, "passthrough"]),
    )?
    .as_str()
    .ok_or("hash")?
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
        return Err("peer fee transaction did not commit".into());
    }
    let target = super::number(&orphan["number"])? + 6;
    let peer_height = super::number(&rpc::call_at(peer, "get_tip_header", json!([]))?["number"])?;
    peer_mine(peer, target.saturating_sub(peer_height))?;
    let winning = rpc::call_at(peer, "get_tip_header", json!([]))?;
    if rpc::call("get_tip_header", json!([]))?["hash"] != orphan["hash"]
        || rpc::call_at(peer, "get_block_hash", json!([common["number"]]))? != common["hash"]
        || rpc::call_at(peer, "get_block_hash", json!([orphan["number"]]))? == orphan["hash"]
    {
        return Err("branches did not diverge".into());
    }
    connect(peer)?;
    converged(peer, &winning["hash"])?;
    if recovery::assert_canonical(
        super::number(&orphan["number"])?,
        orphan["hash"].as_str().ok_or("orphan hash")?,
    )
    .is_ok()
    {
        return Err("orphan pin survived".into());
    }
    let observed_rollback = observer
        .as_mut()
        .map(|p| p.observe(8, observed_before.as_ref(), true))
        .transpose()?;
    let rolled = cold(None, chain, net, tip)?;
    let peer_rolled = cold(Some(peer), chain, net, tip)?;
    if rolled != peer_rolled
        || rolled["counts"] != json!({"admitted":4,"sealed":0,"published":0,"settled":0})
        || rolled["settlement"]["published_batches"] != 8
        || rolled["settlement"]["settled_batches"] != 0
    {
        return Err("cold recovery retained orphan duties".into());
    }
    let seal_record = lab
        .evidence
        .iter()
        .find(|e| e["label"] == "sealed-settlement/seal both authenticated lanes")
        .ok_or("seal record")?
        .clone();
    let old_seal = seal_record["transaction"].clone();
    let old_seal_status = rpc::call("get_transaction", json!([seal_record["hash"]]))?;
    let old_publication_status = rpc::call(
        "get_transaction",
        json!([rpc::bytes_to_hex(&net.anchor.point.tx_hash)]),
    )?;
    let old_checkpoint =
        json!({"tx_hash":rpc::bytes_to_hex(&net.anchor.point.tx_hash),"index":"0x3"});
    let checkpoint_status = rpc::call("get_live_cell", json!([old_checkpoint, true]))?;
    if old_seal_status["tx_status"]["status"] == "committed"
        || old_publication_status["tx_status"]["status"] == "committed"
        || checkpoint_status["status"] == "live"
    {
        return Err("orphan outputs remained canonical".into());
    }
    lab.record_committed(
        "obligation-reorg/peer fee spend is canonical",
        &alternative_hash,
    )?;
    lab.reject(
        "obligation-reorg/orphan seal funding cannot replay",
        &old_seal,
        "TransactionFailedToResolve",
    )?;
    let mut recovered = sealed_recovery::recover_sealed(
        &net.gate.script,
        &net.anchor.script,
        &rpc::bytes_to_hex(chain),
    )?
    .network;
    lab.wallets[1].point = lab::point(&alternative_hash, 0)?;
    lab.wallets[1].capacity = super::number(&alternative["outputs"][0]["capacity"])?;
    let fee = &plan["publisher_fee_point"];
    lab.wallets[0].point = lab::point(
        fee["tx_hash"].as_str().ok_or("fee hash")?,
        super::number(&fee["index"])? as u32,
    )?;
    lab.wallets[0].capacity = plan["publisher_capacity"].as_u64().ok_or("capacity")?;
    lab.deps
        .retain(|p| !(p.tx_hash == net.anchor.point.tx_hash && p.index == 3));
    sealed::seal(
        lab,
        &mut recovered,
        1,
        "obligation-reorg/recovered complete seal",
    )?;
    let bytes = sealed::required_bytes(&recovered)?;
    if rpc::bytes_to_hex(&bytes) != publication["outputs_data"][1] {
        return Err("recovered mandatory batch differs".into());
    }
    let mut outputs = sealed::advance_outputs(&recovered, &bytes)?;
    let config = &tip[53..];
    let checkpoint = super::molecule::script(
        &config[104..136].try_into().map_err(|_| "checkpoint code")?,
        2,
        &tactus_o1_ordering_script::ckb_blake2b(&net.anchor.script),
    );
    let lock = lab.wallets[0].key.lock_script();
    outputs.push(OutSpec {
        capacity: OutSpec::required_capacity(&lock, Some(&checkpoint), 200),
        lock,
        type_script: Some(checkpoint),
        data: rpc::decode_hex(
            publication["outputs_data"][3]
                .as_str()
                .ok_or("checkpoint data")?,
        )?,
    });
    let tx = sealed::advance_tx(lab, &recovered, 0, outputs)?;
    sealed::accept_advance(
        lab,
        &mut recovered,
        0,
        &bytes,
        &tx,
        "obligation-reorg/recovered forced publication",
    )?;
    let final_tip = rpc::call("get_tip_header", json!([]))?;
    converged(peer, &final_tip["hash"])?;
    let observed_republication = observer
        .as_mut()
        .map(|p| p.observe(9, observed_before.as_ref(), false))
        .transpose()?;
    let final_report = cold(None, chain, &recovered, tip)?;
    let peer_final = cold(Some(peer), chain, &recovered, tip)?;
    if final_report != peer_final
        || final_report["counts"] != json!({"admitted":0,"sealed":0,"published":4,"settled":0})
        || final_report["settlement"]["published_batches"] != 9
        || final_report["settlement"]["settled_batches"] != 0
    {
        return Err("cold recovery did not restore duties".into());
    }
    Ok(
        json!({"rpc_observer":{"before":observed_before,"after_rollback":observed_rollback,"after_republication":observed_republication},"plan":plan,"orphan_tip":orphan,"winning_tip":winning,"final_tip":final_tip,"orphan_seal_status":old_seal_status,"orphan_publication_status":old_publication_status,"orphan_checkpoint_status":checkpoint_status,"cold_after_rollback":rolled,"peer_cold_after_rollback":peer_rolled,"alternative_hash":alternative_hash,"replacement_publication":rpc::bytes_to_hex(&recovered.anchor.point.tx_hash),"cold_after_republication":final_report,"peer_cold_after_republication":peer_final,"orphaned_blocks":super::number(&orphan["number"])?-super::number(&common["number"])?,"truncate_used":false,"submit_block_used":false,"proof_generated":false,"settled":false,"production_ready":false}),
    )
}
