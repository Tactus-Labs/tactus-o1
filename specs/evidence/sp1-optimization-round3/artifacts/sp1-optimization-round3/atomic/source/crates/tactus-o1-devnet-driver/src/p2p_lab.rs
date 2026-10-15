//! Bounded real-P2P laboratory synchronization; only funded Dummy devnets.
use crate::rpc;
use serde_json::{json, Value};
use std::time::{Duration, Instant};
pub fn wait(label: &str, mut f: impl FnMut() -> Result<bool, String>) -> Result<(), String> {
    let deadline = Instant::now() + Duration::from_secs(45);
    while !f()? {
        if Instant::now() > deadline {
            return Err(format!("{label}: timeout"));
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    Ok(())
}
pub fn peer_mine(peer: &str, n: u64) -> Result<(), String> {
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
pub fn connect(peer: &str) -> Result<(), String> {
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
pub fn converged(peer: &str, expected: &Value) -> Result<(), String> {
    wait("both canonical tips and pools converge", || {
        Ok(rpc::call("get_tip_header", json!([]))?["hash"] == *expected
            && rpc::call_at(peer, "get_tip_header", json!([]))?["hash"] == *expected
            && rpc::call("tx_pool_info", json!([]))?["tip_hash"] == *expected
            && rpc::call_at(peer, "tx_pool_info", json!([]))?["tip_hash"] == *expected)
    })
}
pub fn partition(peer: &str) -> Result<(), String> {
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
