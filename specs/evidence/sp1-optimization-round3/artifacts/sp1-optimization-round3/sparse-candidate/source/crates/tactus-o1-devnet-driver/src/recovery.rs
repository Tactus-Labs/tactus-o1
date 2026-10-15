//! Ordering-state recovery using canonical CKB blocks only, with a pinned tip.
//! This recovers input publications; execution_recovery independently replays
//! supported execution domains. Neither path proves settled withdrawals.
use crate::{lab, molecule, rpc, tx::CellOutPoint};
use serde_json::{json, Value};
use tactus_o1_ordering_script::OrderingHead;

pub fn recover_head(type_script: &[u8]) -> Result<(CellOutPoint, OrderingHead), String> {
    let tip = rpc::call("get_tip_header", json!([]))?;
    let number = u64::from_str_radix(
        tip["number"]
            .as_str()
            .ok_or("missing tip number")?
            .trim_start_matches("0x"),
        16,
    )
    .map_err(|e| e.to_string())?;
    let expected_type = molecule::try_script_to_json(type_script)?;
    let mut current: Option<(CellOutPoint, OrderingHead)> = None;
    let mut previous_block = None;
    for height in 0..=number {
        let block = rpc::get_block_detailed(height)?;
        if let Some(parent) = &previous_block {
            if block["header"]["parent_hash"] != *parent {
                return Err("chain changed during recovery".into());
            }
        }
        previous_block = Some(block["header"]["hash"].clone());
        for transaction in block["transactions"]
            .as_array()
            .ok_or("block transactions missing")?
        {
            let outputs = transaction["outputs"]
                .as_array()
                .ok_or("transaction outputs missing")?;
            for (index, output) in outputs.iter().enumerate() {
                if output["type"] != expected_type {
                    continue;
                }
                let state = OrderingHead::from_bytes(&rpc::decode_hex(
                    transaction["outputs_data"][index]
                        .as_str()
                        .ok_or("missing head data")?,
                )?)
                .map_err(|e| format!("head decode: {e:?}"))?;
                if let Some((prior, _)) = &current {
                    let expected = json!({"tx_hash":rpc::bytes_to_hex(&prior.tx_hash),"index":format!("0x{:x}",prior.index)});
                    if !transaction["inputs"]
                        .as_array()
                        .ok_or("inputs missing")?
                        .iter()
                        .any(|i| i["previous_output"] == expected)
                    {
                        return Err("head succession disconnected from recovered identity".into());
                    }
                } else {
                    state
                        .validate_genesis()
                        .map_err(|e| format!("invalid genesis: {e:?}"))?;
                }
                current = Some((
                    lab::point(
                        transaction["hash"]
                            .as_str()
                            .ok_or("transaction hash missing")?,
                        index as u32,
                    )?,
                    state,
                ));
            }
        }
    }
    if previous_block.as_ref() != Some(&tip["hash"])
        || rpc::call("get_tip_header", json!([]))?["hash"] != tip["hash"]
    {
        return Err("canonical tip changed; retry recovery".into());
    }
    let (point, state) = current.ok_or("head identity not found in canonical blocks")?;
    let live = rpc::call(
        "get_live_cell",
        json!([{"tx_hash":rpc::bytes_to_hex(&point.tx_hash),"index":format!("0x{:x}",point.index)},false]),
    )?;
    if live["status"] != "live" {
        return Err("recovered head is not live".into());
    }
    Ok((point, state))
}

/// A complete published input whose commitment and predecessor were verified
/// against canonical anchor states. Opaque bytes are not executed here.
#[derive(Debug)]
pub struct RecoveredBatch {
    pub anchor_transaction: String,
    pub publication_output: usize,
    pub input_bytes: Vec<u8>,
    pub summary: tactus_o1_protocol::batch::BatchSummary,
}

#[derive(Debug)]
pub struct RecoveredAnchor {
    pub pinned_height: u64,
    pub pinned_hash: String,
    pub genesis: tactus_o1_protocol::batch::AnchorState,
    pub genesis_allocation: Vec<u8>,
    pub point: CellOutPoint,
    pub state: tactus_o1_protocol::batch::AnchorState,
    pub batches: Vec<RecoveredBatch>,
}

/// Resolve the unique allocation commitment embedded in a current anchor type.
/// Legacy allocation-unbound anchors are intentionally not accepted here.
pub fn allocation_from_genesis(
    transaction: &serde_json::Value,
    type_script: &[u8],
) -> Result<Vec<u8>, String> {
    let script = molecule::try_script_to_json(type_script)?;
    if type_script.len() != 117 || script["hash_type"] != "data1" {
        return Err("anchor must bind a genesis allocation".into());
    }
    let mut immutable = script;
    immutable["args"] = json!("0x");
    for (i, o) in transaction["outputs"]
        .as_array()
        .ok_or("genesis outputs")?
        .iter()
        .enumerate()
        .take(16)
    {
        if o["type"].is_null() && o["lock"] == immutable {
            let hex = transaction["outputs_data"][i]
                .as_str()
                .ok_or("allocation data")?;
            if hex.len() > 2 + 2 * tactus_o1_protocol::genesis::MAX_BYTES {
                return Err("allocation publication too large".into());
            }
            let bytes = rpc::decode_hex(hex)?;
            if tactus_o1_protocol::genesis::commitment(&bytes)
                .is_ok_and(|h| h == type_script[85..117])
            {
                return Ok(bytes);
            }
        }
    }
    Err("missing immutable committed genesis allocation".into())
}

/// Reconstruct the complete committed input sequence from canonical CKB blocks.
/// No operator database, indexer or unpublished witness cache is consulted.
pub fn recover_published_batches(type_script: &[u8]) -> Result<RecoveredAnchor, String> {
    let pinned = rpc::call("get_tip_header", json!([]))?;
    recover_published_batches_at(type_script, &pinned)
}

/// Replay a specified canonical prefix, allowing several observers to share it.
pub(crate) fn recover_published_batches_at(
    type_script: &[u8],
    pinned: &Value,
) -> Result<RecoveredAnchor, String> {
    use tactus_o1_protocol::batch::{self, AnchorState};
    let height = u64::from_str_radix(
        pinned["number"]
            .as_str()
            .ok_or("tip number missing")?
            .trim_start_matches("0x"),
        16,
    )
    .map_err(|e| e.to_string())?;
    let expected_type = molecule::try_script_to_json(type_script)?;
    if type_script.len() != 117 || expected_type["hash_type"] != "data1" {
        return Err("anchor must bind a genesis allocation".into());
    }

    let mut immutable = expected_type.clone();
    immutable["args"] = json!("0x");
    let mut current: Option<(CellOutPoint, AnchorState)> = None;
    let mut batches = Vec::new();
    let mut genesis = None;
    let mut genesis_allocation = None;
    let mut previous_hash = None;
    for number in 0..=height {
        let block = rpc::get_block_detailed(number)?;
        if previous_hash
            .as_ref()
            .is_some_and(|hash| *hash != block["header"]["parent_hash"])
        {
            return Err("chain changed during batch recovery".into());
        }
        previous_hash = Some(block["header"]["hash"].clone());
        for transaction in block["transactions"]
            .as_array()
            .ok_or("block transactions missing")?
        {
            let outputs = transaction["outputs"].as_array().ok_or("outputs missing")?;
            let heads: Vec<usize> = outputs
                .iter()
                .enumerate()
                .filter(|(_, o)| o["type"] == expected_type)
                .map(|(i, _)| i)
                .collect();
            if heads.is_empty() {
                continue;
            }
            if heads.len() != 1 {
                return Err("ambiguous anchor succession".into());
            }
            let output_index = heads[0];
            let next = AnchorState::decode(&rpc::decode_hex(
                transaction["outputs_data"][output_index]
                    .as_str()
                    .ok_or("state data missing")?,
            )?)
            .map_err(|e| format!("anchor decoding: {e:?}"))?;
            let transaction_hash = transaction["hash"]
                .as_str()
                .ok_or("transaction hash missing")?;
            if let Some((point, state)) = current {
                let expected = json!({"tx_hash":rpc::bytes_to_hex(&point.tx_hash),"index":format!("0x{:x}",point.index)});
                if !transaction["inputs"]
                    .as_array()
                    .ok_or("inputs missing")?
                    .iter()
                    .any(|i| i["previous_output"] == expected)
                {
                    return Err("disconnected anchor predecessor".into());
                }
                let mut recovered = None;
                for (index, output) in outputs.iter().enumerate() {
                    if !output["type"].is_null() || output["lock"] != immutable {
                        continue;
                    }
                    let input_bytes = rpc::decode_hex(
                        transaction["outputs_data"][index]
                            .as_str()
                            .ok_or("publication data missing")?,
                    )?;
                    if let Ok(summary) = batch::validate_batch(&input_bytes, &state) {
                        if summary.next == next {
                            recovered = Some(RecoveredBatch {
                                anchor_transaction: transaction_hash.into(),
                                publication_output: index,
                                input_bytes,
                                summary,
                            });
                            break;
                        }
                    }
                }
                batches
                    .push(recovered.ok_or("anchor has no matching immutable batch publication")?);
            } else {
                next.validate_genesis()
                    .map_err(|e| format!("bad anchor genesis: {e:?}"))?;
                if type_script[53..85] != next.rollup_id {
                    return Err("allocation anchor rollup identity mismatch".into());
                }
                genesis_allocation = Some(allocation_from_genesis(transaction, type_script)?);
                genesis = Some(next);
            }
            current = Some((lab::point(transaction_hash, output_index as u32)?, next));
        }
    }
    if previous_hash.as_ref() != Some(&pinned["hash"]) {
        return Err("chain changed before pinned tip".into());
    }
    let (point, state) = current.ok_or("anchor domain not found")?;
    let pinned_hash = pinned["hash"]
        .as_str()
        .ok_or("pinned hash missing")?
        .to_owned();
    // A growing tip is harmless. A reorg replacing the pinned block is not.
    assert_canonical(height, &pinned_hash)?;
    Ok(RecoveredAnchor {
        pinned_height: height,
        pinned_hash,
        genesis: genesis.ok_or("anchor genesis missing")?,
        genesis_allocation: genesis_allocation.ok_or("allocation missing")?,
        point,
        state,
        batches,
    })
}

/// Confirms a snapshot is still a prefix of the node's current canonical chain.
/// The RPC node is a trust boundary; this is not an independent consensus client.
pub fn assert_canonical(height: u64, expected_hash: &str) -> Result<(), String> {
    let current = rpc::call("get_block_hash", json!([format!("0x{height:x}")]))?;
    if current.as_str() != Some(expected_hash) {
        return Err("pinned CKB block was replaced; retry recovery".into());
    }
    Ok(())
}
