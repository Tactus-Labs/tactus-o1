//! Observations at one canonical pin. Confirmation depth is not finality, and
//! an execution outcome never creates a custody right by itself.
use crate::{hash32, number, recover::Recovered, Result};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use tactus_o1_protocol::v02::{Mode, Operation, Role};

pub struct InclusionIndex<'a> {
    tip: u64,
    events: BTreeMap<[u8; 32], &'a Value>,
}
impl<'a> InclusionIndex<'a> {
    pub fn new(tip: u64, transitions: &'a [Value]) -> Result<Self> {
        let mut events = BTreeMap::new();
        for event in transitions {
            let height = event["block_number"]
                .as_u64()
                .ok_or("missing inclusion height")?;
            confirmations(tip, height)?;
            if events.insert(hash32(&event["tx_hash"])?, event).is_some() {
                return Err("duplicate canonical transition".into());
            }
        }
        Ok(Self { tip, events })
    }
    pub fn height(&self, tx: &[u8; 32]) -> Result<u64> {
        self.events
            .get(tx)
            .and_then(|v| v["block_number"].as_u64())
            .ok_or_else(|| "missing canonical creation height".into())
    }
    pub fn observation(&self, tx: &[u8; 32]) -> Result<Value> {
        let event = self.events.get(tx).ok_or("missing canonical inclusion")?;
        let height = self.height(tx)?;
        Ok(
            json!({"tx_hash":event["tx_hash"],"block_hash":event["block_hash"],
            "block_number":height,"confirmations":confirmations(self.tip,height)?}),
        )
    }
}
fn confirmations(tip: u64, height: u64) -> Result<u64> {
    tip.checked_sub(height)
        .and_then(|v| v.checked_add(1))
        .ok_or_else(|| "invalid confirmation range".into())
}

/// Events here have already passed canonical reconstruction and adapter checks.
/// Settlement coverage is recorded from the actual SETTLE output, not inferred
/// from a later FREEZE transaction or from the ordered execution candidate.
pub fn summarize(transitions: &[Value], tip: u64, settled: u64, published: usize) -> Result<Value> {
    let index = InclusionIndex::new(tip, transitions)?;
    let mut batches = Vec::new();
    let mut payments = Vec::new();
    let mut covered = 0usize;
    for event in transitions {
        let op = event["operation"].as_u64().ok_or("missing operation")?;
        if op == Operation::Append as u64 {
            let n = event["batch_number"]
                .as_u64()
                .ok_or("missing publication number")?;
            if n != batches.len() as u64 + 1 {
                return Err("lifecycle publication gap".into());
            }
            batches.push(json!({"batch_number":n,"phase":"Ordered",
                "ordered":index.observation(&hash32(&event["tx_hash"])?)?,"settled":null,
                "outcomes_source_tx":event["tx_hash"],"withdrawable_inferred":false}));
        } else if op == Operation::Settle as u64 {
            let end = event["settled_batches"]
                .as_u64()
                .ok_or("missing settlement coverage")?;
            let end = usize::try_from(end).map_err(crate::err)?;
            if end <= covered || end > batches.len() {
                return Err("lifecycle settlement range".into());
            }
            let inclusion = index.observation(&hash32(&event["tx_hash"])?)?;
            for batch in &mut batches[covered..end] {
                batch["phase"] = json!("Settled");
                batch["settled"] = inclusion.clone();
            }
            covered = end;
        } else if [
            Operation::Release as u64,
            Operation::Refund as u64,
            Operation::Escape as u64,
        ]
        .contains(&op)
        {
            if !event["payment"].is_object() {
                return Err("missing canonical payment identity".into());
            }
            payments.push(json!({"phase":"Paid","claim":event["payment"],
                "paid":index.observation(&hash32(&event["tx_hash"])?)?}));
        }
    }
    if batches.len() != published || covered as u64 != settled {
        return Err("lifecycle coverage differs from canonical state".into());
    }
    Ok(json!({
        "phases":{
            "Received":{"observation":"unobserved","meaning":"a local service accepted the request; canonical recovery cannot establish this"},
            "Soft":{"observation":"unobserved","meaning":"a separately identified provider made a provisional promise; no preconfirmation provider is implemented"},
            "Ordered":{"meaning":"the batch was included in canonical CKB ordering"},
            "Settled":{"meaning":"a canonical SETTLE accepted the proof covering the batch; outcomes may include rejected or reverted inputs"},
            "Withdrawable":{"observation":"per-claim export only","meaning":"the requested claim passes current authorization; fees, lock preimage and CKB inclusion are still required"},
            "Paid":{"meaning":"a canonical claim transaction created the required payout; its confirmations are separate from settlement"}
        },
        "batches":batches,"payments":payments,
        "confirmation_policy":{"counting":"tip - inclusion height + 1","required_depth":null,
            "status":"deployment risk policy not qualified","permanent_finality":false},
        "reorg_policy":"rebuild from canonical history; orphaned ordering, settlement and payment observations disappear",
        "execution_outcomes":"compact per-slot results in APPEND transitions; replay is not settlement authority",
        "error_policy":"recovery or API errors abort refresh/export; they are not transaction outcomes"
    }))
}
impl Recovered {
    pub fn lifecycle(&self) -> Result<Value> {
        let mut value = summarize(
            &self.transitions,
            number(&self.tip["number"])?,
            self.control.boundary.batches,
            self.frames.len(),
        )?;
        value["mode"] = json!(if self.control.mode == Mode::Running {
            "RUNNING"
        } else {
            "FROZEN"
        });
        value["control"] = self.control_confirmation()?;
        Ok(value)
    }
    pub fn control_confirmation(&self) -> Result<Value> {
        InclusionIndex::new(number(&self.tip["number"])?, &self.transitions)?
            .observation(&self.cell(Role::Control, 0)?.point.tx_hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tactus_o1_devnet_driver::rpc;
    fn event(op: Operation, n: u8, height: u64) -> Value {
        json!({"operation":op as u8,"tx_hash":rpc::bytes_to_hex(&[n;32]),
            "block_hash":rpc::bytes_to_hex(&[n+10;32]),"block_number":height})
    }
    #[test]
    fn ordering_settlement_and_payment_have_independent_depths_and_reorgs() {
        let mut a = event(Operation::Append, 1, 10);
        a["batch_number"] = json!(1);
        let mut b = event(Operation::Append, 2, 11);
        b["batch_number"] = json!(2);
        let mut s = event(Operation::Settle, 3, 12);
        s["settled_batches"] = json!(1);
        let mut p = event(Operation::Release, 4, 14);
        p["payment"] = json!({"kind":"release","id":"1"});
        let events = vec![a.clone(), b.clone(), s, p];
        let v = summarize(&events, 14, 1, 2).unwrap();
        assert_eq!(v["batches"][0]["phase"], "Settled");
        assert_eq!(v["batches"][0]["ordered"]["confirmations"], 5);
        assert_eq!(v["batches"][0]["settled"]["confirmations"], 3);
        assert_eq!(v["batches"][1]["phase"], "Ordered");
        assert_eq!(v["batches"][1]["withdrawable_inferred"], false);
        assert_eq!(v["payments"][0]["paid"]["confirmations"], 1);
        assert_eq!(v["phases"]["Soft"]["observation"], "unobserved");
        let reorg = summarize(&[a, b], 11, 0, 2).unwrap();
        assert_eq!(reorg["payments"], json!([]));
        assert_eq!(reorg["batches"][0]["phase"], "Ordered");
        assert!(reorg["batches"][0]["settled"].is_null());
        assert!(summarize(&events, 13, 1, 2).is_err());
        assert!(summarize(&events, 14, 2, 2).is_err());
        assert!(summarize(&events, 14, 1, 1).is_err());
        assert!(confirmations(u64::MAX, 0).is_err());
        assert_eq!(confirmations(0, 0).unwrap(), 1);
    }
}
