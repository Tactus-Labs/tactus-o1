//! Prepare the next proof interval from a second actual canonical publication.
//! Publishing inputs is not settlement; the preceding Tip may still await proof.
use crate::{
    batch_lab::{self, Anchor},
    lab::{self, Lab},
    molecule, recovery, rpc,
    tx::OutSpec,
};
use serde_json::{json, Value};
use std::path::Path;
use tactus_o1_execution::Executor;
use tactus_o1_ordering_script::ckb_blake2b;
use tactus_o1_protocol::batch;
fn data(value: &Value) -> Result<Vec<u8>, String> {
    rpc::decode_hex(value.as_str().ok_or("missing encoded bytes")?)
}
fn capacity(value: &Value) -> Result<u64, String> {
    u64::from_str_radix(
        value.as_str().ok_or("capacity")?.trim_start_matches("0x"),
        16,
    )
    .map_err(|e| e.to_string())
}
pub fn prepare_next_input(
    lab: &mut Lab,
    anchor: &mut Anchor,
    engine: &mut Executor,
    first: &Value,
    continuation: &Value,
    checkpoint_code: [u8; 32],
    root: &Path,
) -> Result<Value, String> {
    if continuation["schema"] != 1
        || continuation["first_publication"] != first["batches"][0]
        || data(&continuation["before_anchor"])? != anchor.state.encode()
    {
        return Err("continuation is not based on canonical first interval".into());
    }
    let bytes = data(&continuation["second_publication"])?;
    let before = *engine.anchor();
    let previous_state = engine.state_root();
    let previous_header = engine.head().hash_slow();
    engine.apply_batch(&bytes).map_err(|e| e.to_string())?;
    let after = *engine.anchor();
    if data(&continuation["after_anchor"])? != after.encode()
        || continuation["previous_state"] != json!(previous_state)
        || continuation["previous_header"] != json!(previous_header)
        || continuation["next_state"] != json!(engine.state_root())
        || continuation["next_header"] != json!(engine.head().hash_slow())
    {
        return Err("continuation execution differs from independently checked fixture".into());
    }
    let checkpoint_script = molecule::script(&checkpoint_code, 2, &ckb_blake2b(&anchor.script));
    let lock = lab.wallets[0].key.lock_script();
    let checkpoint = OutSpec {
        capacity: OutSpec::required_capacity(&lock, Some(&checkpoint_script), 200),
        lock,
        type_script: Some(checkpoint_script),
        data: after.encode().to_vec(),
    };
    let publication = batch_lab::shape(
        lab,
        anchor,
        0,
        vec![
            checkpoint,
            batch_lab::head_output(anchor, after),
            batch_lab::da_output(anchor, &bytes),
        ],
        Some(&2u32.to_le_bytes()),
    )?;
    let hash = lab.commit(
        "settlement/second canonical batch and ending checkpoint",
        &publication,
    )?;
    anchor.point = lab::point(&hash, 1)?;
    anchor.state = after;
    lab.wallets[0].point = lab::point(&hash, 3)?;
    lab.wallets[0].capacity = capacity(&publication["outputs"][3]["capacity"])?;
    let snapshot = recovery::recover_published_batches(&anchor.script)?;
    if snapshot.state != after
        || snapshot.batches.len() != 2
        || snapshot.batches[0].input_bytes != data(&first["batches"][0])?
        || snapshot.batches[1].input_bytes != bytes
        || snapshot.genesis_allocation != data(&first["allocation_hex"])?
    {
        return Err("second publication differs from canonical recovery".into());
    }
    let mut journal = data(&first["expected_journal_hex"])?;
    if journal.len() != 768 {
        return Err("journal length".into());
    }
    journal[208..408].copy_from_slice(&before.encode());
    journal[408..608].copy_from_slice(&after.encode());
    journal[608..640].copy_from_slice(&previous_state.0);
    journal[640..672].copy_from_slice(&engine.state_root().0);
    journal[672..704].copy_from_slice(&previous_header.0);
    journal[704..736].copy_from_slice(&engine.head().hash_slow().0);
    let mut interval = batch::hash(b"tactus/o1/proof-interval/v1", &1u64.to_le_bytes()).to_vec();
    interval.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
    interval.extend_from_slice(&bytes);
    journal[736..768].copy_from_slice(&batch::hash(b"tactus/o1/proof-interval-step/v1", &interval));
    let mut next_tip = b"TO1TIP01".to_vec();
    next_tip.push(1);
    next_tip.extend_from_slice(&[0; 7]);
    next_tip.extend_from_slice(&after.encode());
    next_tip.extend_from_slice(&engine.state_root().0);
    next_tip.extend_from_slice(&engine.head().hash_slow().0);
    lab.deps.push(lab::point(&hash, 0)?);
    let mut next = first.clone();
    next["source"] =
        "canonical recovery of two published batches; preceding proof not yet settled".into();
    next["prefix_batches"] = 1.into();
    next["batches"] = json!(snapshot
        .batches
        .iter()
        .map(|b| rpc::bytes_to_hex(&b.input_bytes))
        .collect::<Vec<_>>());
    next["expected_journal_hex"] = rpc::bytes_to_hex(&journal).into();
    next["checkpoint"] = json!({"tx_hash":hash,"index":"0x0"});
    next["fee_input"] = json!({"tx_hash":hash,"index":"0x3","capacity":lab.wallets[0].capacity});
    next["required_predecessor_tip_data"] = first["next_tip_data"].clone();
    next["predecessor_ready"] = false.into();
    next["next_tip_data"] = rpc::bytes_to_hex(&next_tip).into();
    next["deployment_dependencies"] = json!(lab
        .deps
        .iter()
        .map(|p| json!({"tx_hash":rpc::bytes_to_hex(&p.tx_hash),"index":format!("0x{:x}",p.index)}))
        .collect::<Vec<_>>());
    next["observed_canonical_tip"] = rpc::call("get_tip_header", json!([]))?;
    std::fs::write(
        root.join("proving-input-next.json"),
        serde_json::to_vec_pretty(&next).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    Ok(next)
}
