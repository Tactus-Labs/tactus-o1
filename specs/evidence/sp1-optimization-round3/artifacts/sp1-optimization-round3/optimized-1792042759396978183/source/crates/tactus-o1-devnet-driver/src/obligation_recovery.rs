//! Join authenticated A3 duties and verified settlement at one canonical prefix.
//! Consensus/script validity still comes from the configured full node. This is
//! not an independent cryptographic verifier or an asset-release authority.
use crate::{recovery, rpc, sealed_recovery, settlement_recovery, tx::CellOutPoint};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use tactus_o1_execution::{Executor, Genesis};
use tactus_o1_protocol::batch::BatchInput;

fn point(p: CellOutPoint) -> Value {
    json!({"tx_hash":rpc::bytes_to_hex(&p.tx_hash),"index":format!("0x{:x}",p.index)})
}

pub fn recover_obligations(
    chain: &str,
    gate: &[u8],
    anchor: &[u8],
    tip: &[u8],
) -> Result<Value, String> {
    let settlement = settlement_recovery::recover_settlement(chain, anchor, tip)?;
    let height = settlement["pinned_height"]
        .as_u64()
        .ok_or("pinned height")?;
    let hash = settlement["pinned_hash"].as_str().ok_or("pinned hash")?;
    let header = json!({"number":format!("0x{height:x}"),"hash":hash});
    let sealed = sealed_recovery::recover_sealed_at(gate, anchor, chain, &header)?;
    let published = recovery::recover_published_batches_at(anchor, &header)?;
    if published.state != sealed.network.anchor.state
        || published.point != sealed.network.anchor.point
    {
        return Err("A3 and publication recovery disagree".into());
    }
    let settled = settlement["settled_batches"]
        .as_u64()
        .ok_or("settled count")?;
    let genesis = Genesis::from_allocation(
        published.genesis.rollup_id.into(),
        published.genesis.chain_id,
        &published.genesis_allocation,
    )
    .map_err(|e| e.to_string())?;
    let mut executor = Executor::new(&genesis).map_err(|e| e.to_string())?;
    let mut executions = BTreeMap::new();
    for (number, batch) in published.batches.iter().enumerate() {
        let decoded = BatchInput::decode(&batch.input_bytes, executor.anchor())
            .map_err(|e| format!("{e:?}"))?;
        let blocks = executor
            .apply_batch(&batch.input_bytes)
            .map_err(|e| e.to_string())?;
        for (block, input) in blocks.into_iter().zip(decoded.blocks) {
            for (slot, (outcome, payload)) in block
                .outcomes
                .into_iter()
                .zip(input.transactions)
                .enumerate()
            {
                executions.insert(
                    (number as u64, block.header.number, slot),
                    (payload, outcome, batch.anchor_transaction.clone()),
                );
            }
        }
    }
    let mut rows = Vec::new();
    let mut counts = BTreeMap::from([
        ("admitted", 0usize),
        ("sealed", 0),
        ("published", 0),
        ("settled", 0),
    ]);
    for duty in &sealed.obligations {
        let mut status = if duty.seal.is_some() {
            "sealed"
        } else {
            "admitted"
        };
        let mut outcome = Value::Null;
        let mut location = Value::Null;
        if let Some(publication) = &duty.publication {
            let (payload, executed, hash) = executions
                .get(&(publication.batch, publication.block, publication.slot))
                .ok_or("duty publication slot not found")?;
            if *payload != duty.payload || *hash != rpc::bytes_to_hex(&publication.point.tx_hash) {
                return Err("duty publication payload or transaction differs".into());
            }
            status = if publication.batch < settled {
                "settled"
            } else {
                "published"
            };
            outcome = json!(executed);
            location = json!({"anchor":point(publication.point),"batch":publication.batch,"block":publication.block,"input_slot":publication.slot});
        }
        *counts.get_mut(status).ok_or("unknown lifecycle")? += 1;
        rows.push(json!({"gate":rpc::bytes_to_hex(&sealed.network.schedule.gate),"lane":duty.lane,"sequence":duty.sequence,"payload":rpc::bytes_to_hex(&duty.payload),"admission":point(duty.admission),"seal":duty.seal.map(point),"publication":location,"status":status,"outcome":outcome,"proof_settled":status=="settled"}));
    }
    if rows.len() as u64 != sealed.admissions {
        return Err("admission accounting mismatch".into());
    }
    // Ordinary tip growth is allowed; replacing the shared prefix is not. No
    // saved observer report or operator-supplied cursor is accepted as input.
    recovery::assert_canonical(height, hash)?;
    Ok(
        json!({"schema":1,"source":"canonical A3 admission, seal and publication reconstruction joined with full settlement replay at the same pinned block","ckb_genesis":chain,"gate_type_script":rpc::bytes_to_hex(gate),"anchor_type_script":rpc::bytes_to_hex(anchor),"settlement_type_script":rpc::bytes_to_hex(tip),"pinned_height":height,"pinned_hash":hash,"admissions":sealed.admissions,"counts":counts,"obligations":rows,"settlement":settlement,"independent_cryptographic_verification":false,"withdrawal_authority":false,"production_ready":false}),
    )
}
