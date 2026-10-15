//! Real second-proof qualification. No positive path accepts placeholder proofs.
use super::{advance_tip, consumed_tip, framed, number, reject};
use serde_json::{json, Value};
use tactus_o1_devnet_driver::{
    lab::{self, Lab},
    rpc,
    tx::{self, TX_FEE},
};

pub(super) use tactus_o1_devnet_driver::settlement_lab::{read, Proof};

pub(super) struct Context<'a> {
    pub code: &'a [u8; 32],
    pub script: &'a [u8],
    pub capacity: u64,
    pub first_transition: &'a Value,
    pub first_journal: &'a [u8],
    pub first_proof: &'a [u8],
}
pub(super) fn qualify(
    lab: &mut Lab,
    context: Context<'_>,
    next: &Value,
    proof: &Proof,
) -> Result<Value, String> {
    let first_hash = context.first_transition["hash"]
        .as_str()
        .ok_or("first transition hash")?;
    let point = lab::point(first_hash, 0)?;
    let tip = rpc::decode_hex(next["next_tip_data"].as_str().ok_or("second Tip")?)?;
    if next["required_predecessor_tip_data"] != context.first_transition["data"] {
        return Err("second proof does not continue first proved Tip".into());
    }
    let valid = advance_tip(
        lab,
        point,
        context.capacity,
        context.script,
        &tip,
        &framed(&proof.journal, &proof.bytes),
    )?;
    let cycles = rpc::call("estimate_cycles", json!([valid]))?;
    for (name, offset, expected) in [
        ("profile", 8, 6),
        ("network", 40, 6),
        ("ordering", 72, 6),
        ("settlement", 104, 6),
        ("rollup", 136, 6),
        ("chain", 168, 6),
        ("allocation", 176, 6),
        ("predecessor", 248, 7),
        ("ending-history", 456, 7),
        ("previous-state", 608, 7),
        ("next-state", 640, 7),
        ("previous-header", 672, 7),
        ("next-header", 704, 7),
        ("interval-data", 736, 9),
    ] {
        let mut changed = proof.journal.clone();
        changed[offset] ^= 1;
        let tx = advance_tip(
            lab,
            point,
            context.capacity,
            context.script,
            &tip,
            &framed(&changed, &proof.bytes),
        )?;
        reject(
            lab,
            context.code,
            &format!("settlement/second-proved-{name}-tamper"),
            &tx,
            expected,
        )?;
    }
    for offset in [0, proof.bytes.len() - 1] {
        let mut changed = proof.bytes.clone();
        changed[offset] ^= 1;
        let tx = advance_tip(
            lab,
            point,
            context.capacity,
            context.script,
            &tip,
            &framed(&proof.journal, &changed),
        )?;
        reject(
            lab,
            context.code,
            &format!("settlement/second-proof-byte-{offset}-tamper"),
            &tx,
            9,
        )?;
    }
    for (name, journal_offset, tip_offset) in [("state", 640, 216), ("header", 704, 248)] {
        let mut changed = proof.journal.clone();
        changed[journal_offset] ^= 1;
        let mut changed_tip = tip.clone();
        changed_tip[tip_offset] ^= 1;
        let tx = advance_tip(
            lab,
            point,
            context.capacity,
            context.script,
            &changed_tip,
            &framed(&changed, &proof.bytes),
        )?;
        reject(
            lab,
            context.code,
            &format!("settlement/second-coordinated-{name}-tamper"),
            &tx,
            9,
        )?;
    }
    let hash = lab.commit("settlement/second real proof transition", &valid)?;
    lab.wallets[0].point = lab::point(&hash, 1)?;
    lab.wallets[0].capacity = number(&valid["outputs"][1]["capacity"])?;
    let packed = rpc::call("get_transaction", json!([hash, "0x0"]))?;
    let wire = rpc::decode_hex(packed["transaction"].as_str().ok_or("packed transaction")?)?.len();
    if wire != tx::wire_bytes(&valid)? {
        return Err("second node wire size differs".into());
    }
    let live = rpc::call(
        "get_live_cell",
        json!([{"tx_hash":hash,"index":"0x0"},true]),
    )?;
    let consumption = consumed_tip(lab::point(first_hash, 0)?, &hash)?;
    if live["status"] != "live" || live["cell"]["data"]["content"] != rpc::bytes_to_hex(&tip) {
        return Err("second transition liveness or data differs".into());
    }
    let current = lab::point(&hash, 0)?;
    let first_tip = rpc::decode_hex(
        context.first_transition["data"]
            .as_str()
            .ok_or("first data")?,
    )?;
    for (name, data, journal, bytes) in [
        (
            "replay-second-on-live-successor",
            tip.as_slice(),
            proof.journal.as_slice(),
            proof.bytes.as_slice(),
        ),
        (
            "replay-first-after-second",
            tip.as_slice(),
            context.first_journal,
            context.first_proof,
        ),
        (
            "rollback-to-first-tip",
            first_tip.as_slice(),
            proof.journal.as_slice(),
            proof.bytes.as_slice(),
        ),
    ] {
        let tx = advance_tip(
            lab,
            current,
            context.capacity,
            context.script,
            data,
            &framed(journal, bytes),
        )?;
        reject(lab, context.code, &format!("settlement/{name}"), &tx, 7)?;
    }
    Ok(
        json!({"hash":hash,"vm_cycles":number(&cycles["cycles"] )?,"node_wire_bytes":wire,
        "tip_capacity_shannons":context.capacity,"fee_shannons":TX_FEE,"data":rpc::bytes_to_hex(&tip),
        "predecessor_status":consumption["live_cell"]["status"],"predecessor_consumption":consumption,"successor_status":live["status"]}),
    )
}
