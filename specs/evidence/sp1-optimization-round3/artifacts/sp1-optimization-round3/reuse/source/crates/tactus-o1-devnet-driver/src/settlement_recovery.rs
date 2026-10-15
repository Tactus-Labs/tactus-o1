//! Read-only SettlementTip recovery from a pinned CKB snapshot and full EVM replay.
//! The selected RPC node supplies consensus/script validity; this is not a light
//! client or an independent cryptographic verifier. No custody authority exists.
use crate::{molecule, recovery, rpc};
use serde_json::{json, Value};
use tactus_o1_execution::{Executor, Genesis};
use tactus_o1_ordering_script::ckb_blake2b;
use tactus_o1_protocol::batch::AnchorState;

fn data(value: &Value) -> Result<Vec<u8>, String> {
    rpc::decode_hex(value.as_str().ok_or("missing encoded bytes")?)
}
fn validate_tip(bytes: &[u8], engine: &Executor, initialized: bool) -> Result<(), String> {
    if bytes.len() != 280
        || &bytes[..8] != b"TO1TIP01"
        || bytes[8] != u8::from(initialized)
        || bytes[9..16] != [0; 7]
        || bytes[16..216] != engine.anchor().encode()
    {
        return Err("Tip does not match canonical execution prefix".into());
    }
    if initialized {
        if bytes[216..248] != engine.state_root().0
            || bytes[248..280] != engine.head().hash_slow().0
            || engine.anchor().next_batch_number == 0
        {
            return Err("proved Tip execution roots differ from replay".into());
        }
    } else if bytes[216..] != [0; 64] || engine.anchor().next_batch_number != 0 {
        return Err("uninitialized Tip asserts proved state".into());
    }
    Ok(())
}

pub fn recover_settlement(
    expected_chain: &str,
    anchor_script: &[u8],
    settlement_script: &[u8],
) -> Result<Value, String> {
    recover_snapshot(expected_chain, anchor_script, settlement_script).map(|(report, _)| report)
}

/// Recover settlement and its exact pinned canonical publication snapshot.
/// Consumers must recheck the pin before serving cached state.
pub fn recover_snapshot(
    expected_chain: &str,
    anchor_script: &[u8],
    settlement_script: &[u8],
) -> Result<(Value, recovery::RecoveredAnchor), String> {
    let chain = rpc::call("get_block_hash", json!(["0x0"]))?;
    let expected = molecule::try_script_to_json(settlement_script)?;
    let config = data(&expected["args"])?;
    if chain.as_str() != Some(expected_chain)
        || config.len() != 168
        || &config[..8] != b"TO1CFG01"
        || expected["hash_type"] != "data1"
        || config[8..40] != data(&chain)?
        || config[40..72] != ckb_blake2b(anchor_script)
    {
        return Err("trusted deployment/chain binding mismatch".into());
    }
    let snapshot = recovery::recover_published_batches(anchor_script)?;
    let allocation = tactus_o1_protocol::genesis::commitment(&snapshot.genesis_allocation)
        .map_err(|e| format!("{e:?}"))?;
    if config[136..168] != allocation {
        return Err("settlement allocation differs from canonical Anchor genesis".into());
    }
    let genesis = Genesis::from_allocation(
        snapshot.genesis.rollup_id.into(),
        snapshot.genesis.chain_id,
        &snapshot.genesis_allocation,
    )
    .map_err(|e| e.to_string())?;
    let mut engine = Executor::new(&genesis).map_err(|e| e.to_string())?;
    let anchor_type = molecule::try_script_to_json(anchor_script)?;
    let mut current: Option<(Value, Value, Vec<u8>)> = None;
    let mut previous_hash = None;
    let mut transitions = 0u64;
    for height in 0..=snapshot.pinned_height {
        let block = rpc::get_block_detailed(height)?;
        if previous_hash
            .as_ref()
            .is_some_and(|h| *h != block["header"]["parent_hash"])
        {
            return Err("chain changed during settlement recovery".into());
        }
        previous_hash = Some(block["header"]["hash"].clone());
        for tx in block["transactions"]
            .as_array()
            .ok_or("missing transactions")?
        {
            let outputs = tx["outputs"].as_array().ok_or("missing outputs")?;
            let matching: Vec<_> = outputs
                .iter()
                .enumerate()
                .filter(|(_, o)| o["type"] == expected)
                .collect();
            let consumes = if let Some((point, _, _)) = &current {
                tx["inputs"]
                    .as_array()
                    .ok_or("missing inputs")?
                    .iter()
                    .filter(|i| i["previous_output"] == *point)
                    .count()
            } else {
                0
            };
            if matching.is_empty() {
                if consumes != 0 {
                    return Err("settlement Tip destroyed without successor".into());
                }
                continue;
            }
            if matching.len() != 1 {
                return Err("ambiguous settlement Tip".into());
            }
            let (index, output) = matching[0];
            let bytes = data(&tx["outputs_data"][index])?;
            if bytes.len() != 280 {
                return Err("Tip data length".into());
            }
            let state = AnchorState::decode(&bytes[16..216]).map_err(|e| format!("{e:?}"))?;
            if let Some((_, old_output, _)) = &current {
                if consumes != 1
                    || output != old_output
                    || state.next_batch_number <= engine.anchor().next_batch_number
                {
                    return Err("disconnected or nonadvancing settlement Tip".into());
                }
                let end = usize::try_from(state.next_batch_number).map_err(|e| e.to_string())?;
                let start = usize::try_from(engine.anchor().next_batch_number)
                    .map_err(|e| e.to_string())?;
                if end > snapshot.batches.len() {
                    return Err("Tip extends beyond canonical inputs".into());
                }
                for batch in &snapshot.batches[start..end] {
                    engine
                        .apply_batch(&batch.input_bytes)
                        .map_err(|e| e.to_string())?;
                }
                validate_tip(&bytes, &engine, true)?;
                transitions += 1;
            } else {
                validate_tip(&bytes, &engine, false)?;
                let anchors: Vec<_> = outputs
                    .iter()
                    .enumerate()
                    .filter(|(_, o)| o["type"] == anchor_type)
                    .collect();
                if anchors.len() != 1
                    || data(&tx["outputs_data"][anchors[0].0])? != snapshot.genesis.encode()
                {
                    return Err("Tip genesis is not atomic with canonical Anchor genesis".into());
                }
            }
            let point = json!({"tx_hash":tx["hash"],"index":format!("0x{index:x}")});
            current = Some((point, output.clone(), bytes));
        }
    }
    if previous_hash.as_ref().and_then(Value::as_str) != Some(&snapshot.pinned_hash) {
        return Err("settlement scan differs from pinned canonical chain".into());
    }
    let (point, output, bytes) = current.ok_or("settlement deployment not found")?;
    let live = rpc::call("get_live_cell", json!([point, true]))?;
    if live["status"] != "live"
        || live["cell"]["output"] != output
        || data(&live["cell"]["data"]["content"])? != bytes
    {
        return Err("recovered settlement Tip is no longer live".into());
    }
    recovery::assert_canonical(snapshot.pinned_height, &snapshot.pinned_hash)?;
    let report = json!({"schema":1,"source":"fresh canonical CKB scan and independent full execution replay",
        "ckb_genesis":expected_chain,"anchor_type_script":rpc::bytes_to_hex(anchor_script),
        "settlement_type_script":rpc::bytes_to_hex(settlement_script),
        "pinned_height":snapshot.pinned_height,"pinned_hash":snapshot.pinned_hash,
        "tip":point,"data":rpc::bytes_to_hex(&bytes),"initialized":bytes[8]==1,
        "settled_batches":engine.anchor().next_batch_number,"published_batches":snapshot.batches.len(),
        "proved_transitions":transitions,"settled":bytes[8]==1,"withdrawal_authority":false,
        "independent_cryptographic_verification":false,"production_ready":false});
    Ok((report, snapshot))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn replayed_state_rejects_forged_roots_and_unproved_initialization() {
        let fixture: Value = serde_json::from_str(include_str!(
            "../../../specs/test-vectors/execution-v1/geth-1.17.8.json"
        ))
        .unwrap();
        let case = &fixture["cases"][0];
        let genesis: Genesis = serde_json::from_value(case["genesis"].clone()).unwrap();
        let mut engine = Executor::new(&genesis).unwrap();
        let mut initial = b"TO1TIP01".to_vec();
        initial.extend_from_slice(&[0; 8]);
        initial.extend_from_slice(&engine.anchor().encode());
        initial.extend_from_slice(&[0; 64]);
        assert!(validate_tip(&initial, &engine, false).is_ok());
        let mut forged = initial.clone();
        forged[8] = 1;
        assert!(validate_tip(&forged, &engine, true).is_err());
        engine.apply_batch(&data(&case["batch"]).unwrap()).unwrap();
        let mut proved = b"TO1TIP01".to_vec();
        proved.push(1);
        proved.extend_from_slice(&[0; 7]);
        proved.extend_from_slice(&engine.anchor().encode());
        proved.extend_from_slice(&engine.state_root().0);
        proved.extend_from_slice(&engine.head().hash_slow().0);
        assert!(validate_tip(&proved, &engine, true).is_ok());
        assert!(validate_tip(&initial, &engine, false).is_err());
        for offset in [8, 9, 56, 64, 216, 248] {
            let mut bad = proved.clone();
            bad[offset] ^= 1;
            assert!(
                validate_tip(&bad, &engine, true).is_err(),
                "offset {offset}"
            );
        }
        assert!(validate_tip(&proved[..279], &engine, true).is_err());
    }
}
