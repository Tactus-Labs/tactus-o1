//! Cold recovery of authenticated A3 state from a pinned canonical CKB prefix.
//! The configured CKB RPC is a consensus trust boundary; no indexer or operator
//! checkpoint is consulted. This reconstructs publication duties, not proofs.
use crate::{
    batch_lab::Anchor,
    lab, molecule, recovery, rpc,
    sealed_lab::{self, Cell, Network},
    tx::{CellOutPoint, OutSpec},
};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use tactus_o1_ordering_script::{ckb_blake2b, genesis_identity};
use tactus_o1_protocol::{
    batch::{self, AnchorState},
    sealed::{self as s, Lane, Schedule},
};

#[derive(Clone, Debug)]
pub struct Publication {
    pub point: CellOutPoint,
    pub batch: u64,
    pub block: u64,
    pub slot: usize,
}
#[derive(Clone, Debug)]
pub struct Obligation {
    pub lane: u8,
    pub sequence: u64,
    pub payload: Vec<u8>,
    pub admission: CellOutPoint,
    pub seal: Option<CellOutPoint>,
    pub publication: Option<Publication>,
}
pub struct RecoveredSealed {
    pub network: Network,
    pub pinned_height: u64,
    pub pinned_hash: String,
    pub genesis_hash: String,
    pub admissions: u64,
    pub seals: u64,
    pub batches: u64,
    pub obligations: Vec<Obligation>,
}
fn number(v: &Value) -> Result<u64, String> {
    u64::from_str_radix(
        v.as_str()
            .ok_or("missing hex number")?
            .strip_prefix("0x")
            .ok_or("hex prefix")?,
        16,
    )
    .map_err(|e| e.to_string())
}
fn point_json(p: CellOutPoint) -> Value {
    json!({"tx_hash":rpc::bytes_to_hex(&p.tx_hash),"index":format!("0x{:x}",p.index)})
}
fn consumed(t: &Value, p: CellOutPoint) -> Result<bool, String> {
    Ok(t["inputs"]
        .as_array()
        .ok_or("inputs missing")?
        .iter()
        .any(|i| i["previous_output"] == point_json(p)))
}
fn output(t: &Value, script: &[u8]) -> Result<Option<usize>, String> {
    let expected = molecule::try_script_to_json(script)?;
    let found: Vec<_> = t["outputs"]
        .as_array()
        .ok_or("outputs missing")?
        .iter()
        .enumerate()
        .filter(|(_, o)| o["type"] == expected)
        .map(|(i, _)| i)
        .collect();
    if found.len() > 1 {
        return Err("duplicate tracked type output".into());
    }
    Ok(found.first().copied())
}
fn data(t: &Value, i: usize, max: usize) -> Result<Vec<u8>, String> {
    let hex = t["outputs_data"][i].as_str().ok_or("output data missing")?;
    if hex.len() > 2 + max * 2 {
        return Err("tracked data exceeds bound".into());
    }
    rpc::decode_hex(hex)
}
fn cell(t: &Value, i: usize, script: &[u8], lock: &[u8], reserve: usize) -> Result<Cell, String> {
    let o = &t["outputs"][i];
    if o["lock"] != molecule::try_script_to_json(lock)? {
        return Err("tracked cell lock mismatch".into());
    }
    let capacity = number(&o["capacity"])?;
    if capacity < OutSpec::required_capacity(lock, Some(script), reserve) {
        return Err("tracked cell capacity below reservation".into());
    }
    Ok(Cell {
        point: lab::point(t["hash"].as_str().ok_or("transaction hash")?, i as u32)?,
        capacity,
        script: script.to_vec(),
        lock: lock.to_vec(),
    })
}
fn successor(t: &Value, prior: &Cell, reserve: usize) -> Result<Option<(Cell, Vec<u8>)>, String> {
    let index = output(t, &prior.script)?;
    let spent = consumed(t, prior.point)?;
    if spent != index.is_some() {
        return Err("tracked cell disconnected, recreated or destroyed".into());
    }
    index
        .map(|i| {
            let next = cell(t, i, &prior.script, &prior.lock, reserve)?;
            if next.capacity != prior.capacity {
                return Err("tracked capacity changed".into());
            }
            Ok((next, data(t, i, reserve)?))
        })
        .transpose()
}
fn anchor_cell(anchor: &Anchor) -> Cell {
    Cell {
        point: anchor.point,
        capacity: anchor.capacity,
        script: anchor.script.clone(),
        lock: anchor.lock.clone(),
    }
}
fn err(e: impl std::fmt::Debug) -> String {
    format!("sealed replay: {e:?}")
}

struct Scanner {
    code: [u8; 32],
    id: [u8; 32],
    gate_script: Vec<u8>,
    anchor_script: Vec<u8>,
    net: Option<Network>,
    admissions: u64,
    seals: u64,
    batches: u64,
    obligations: BTreeMap<(u8, u64), Obligation>,
}
impl Scanner {
    fn new(gate_script: &[u8], anchor_script: &[u8]) -> Result<Self, String> {
        let gate = molecule::try_script_to_json(gate_script)?;
        let anchor = molecule::try_script_to_json(anchor_script)?;
        if gate["hash_type"] != "data1"
            || anchor["hash_type"] != "data1"
            || gate_script.len() != 86
            || gate_script[53] != 2
            || anchor_script.len() != 117
        {
            return Err("unsupported sealed or anchor type identity".into());
        }
        Ok(Self {
            code: gate_script[16..48].try_into().unwrap(),
            id: gate_script[54..86].try_into().unwrap(),
            gate_script: gate_script.to_vec(),
            anchor_script: anchor_script.to_vec(),
            net: None,
            admissions: 0,
            seals: 0,
            batches: 0,
            obligations: BTreeMap::new(),
        })
    }
    fn genesis(&mut self, t: &Value, i: usize) -> Result<(), String> {
        let schedule = Schedule::decode(&data(t, i, s::SCHEDULE_BYTES)?).map_err(err)?;
        let a = output(t, &self.anchor_script)?.ok_or("gate genesis missing named anchor")?;
        let state = AnchorState::decode(&data(t, a, batch::ANCHOR_LEN)?).map_err(err)?;
        state.validate_genesis().map_err(err)?;
        recovery::allocation_from_genesis(t, &self.anchor_script)?;
        if schedule
            != Schedule::genesis(
                self.id,
                state.rollup_id,
                ckb_blake2b(&self.anchor_script),
                schedule.lane_count,
            )
            .map_err(err)?
        {
            return Err("gate genesis domain mismatch".into());
        }
        let first = &t["inputs"][0];
        let p = lab::point(
            first["previous_output"]["tx_hash"]
                .as_str()
                .ok_or("genesis first input")?,
            u32::try_from(number(&first["previous_output"]["index"])?).map_err(err)?,
        )?;
        let seed = molecule::cell_input(
            number(&first["since"])?,
            &molecule::out_point(&p.tx_hash, p.index),
        )
        .try_into()
        .unwrap();
        if genesis_identity(&seed, i as u64) != self.id
            || genesis_identity(&seed, a as u64) != state.rollup_id
            || self.anchor_script[53..85] != state.rollup_id
        {
            return Err("genesis Type ID mismatch".into());
        }
        let gate_lock = sealed_lab::role(&self.code, 0, &ckb_blake2b(&self.gate_script), None);
        let gate = cell(t, i, &self.gate_script, &gate_lock, s::SCHEDULE_BYTES)?;
        let ac = cell(t, a, &self.anchor_script, &gate_lock, batch::ANCHOR_LEN)?;
        let mut lanes = Vec::new();
        for index in 0..schedule.lane_count {
            let script = sealed_lab::role(&self.code, 1, &self.id, Some(index));
            let oi = output(t, &script)?.ok_or("genesis missing lane")?;
            let lock = sealed_lab::role(&self.code, 0, &ckb_blake2b(&script), None);
            let c = cell(t, oi, &script, &lock, s::MAX_LANE_BYTES)?;
            let lane = Lane::decode(&data(t, oi, s::MAX_LANE_BYTES)?).map_err(err)?;
            if lane != Lane::genesis(self.id, index).map_err(err)? {
                return Err("invalid initial lane".into());
            }
            lanes.push((c, lane));
        }
        let anchor_code = self.anchor_script[16..48].try_into().unwrap();
        self.net = Some(Network {
            code: self.code,
            anchor: Anchor {
                point: ac.point,
                capacity: ac.capacity,
                state,
                lock: ac.lock,
                script: ac.script,
                immutable: molecule::script(&anchor_code, 2, &[]),
            },
            gate,
            schedule,
            lanes,
            snapshot: None,
        });
        Ok(())
    }
    fn apply(&mut self, t: &Value) -> Result<(), String> {
        let Some(net) = self.net.as_ref() else {
            if let Some(i) = output(t, &self.gate_script)? {
                self.genesis(t, i)?;
            } else if output(t, &self.anchor_script)?.is_some() {
                return Err("anchor predates named gate genesis".into());
            }
            return Ok(());
        };
        let gate = successor(t, &net.gate, s::SCHEDULE_BYTES)?;
        let anchor = successor(t, &anchor_cell(&net.anchor), batch::ANCHOR_LEN)?;
        let lanes: Vec<_> = net
            .lanes
            .iter()
            .map(|(c, _)| successor(t, c, s::MAX_LANE_BYTES))
            .collect::<Result<_, _>>()?;
        if gate.is_none() && anchor.is_some() {
            return Err("anchor advanced without gate".into());
        }
        let mut next = net.clone();
        let mut sealed_lanes = None;
        if let Some((c, bytes)) = gate {
            let schedule = Schedule::decode(&bytes).map_err(err)?;
            if let Some((ac, ab)) = anchor {
                let state = AnchorState::decode(&ab).map_err(err)?;
                let mut verified = None;
                for (i, o) in t["outputs"].as_array().ok_or("outputs")?.iter().enumerate() {
                    if !o["type"].is_null()
                        || o["lock"] != molecule::try_script_to_json(&net.anchor.immutable)?
                    {
                        continue;
                    }
                    let bytes = data(t, i, batch::MAX_BATCH_BYTES)?;
                    if let Ok((expected, summary)) = net.schedule.advance(
                        net.snapshot.as_ref().map(|(_, s)| s),
                        &bytes,
                        &net.anchor.state,
                    ) {
                        if expected == schedule && summary.next == state {
                            verified = Some(());
                            break;
                        }
                    }
                }
                verified.ok_or("gate batch missing exact mandatory-prefix publication")?;
                for (slot, message) in net
                    .schedule
                    .required(net.snapshot.as_ref().map(|(_, s)| s))
                    .map_err(err)?
                    .into_iter()
                    .enumerate()
                {
                    let item = self
                        .obligations
                        .get_mut(&(message.lane, message.sequence))
                        .ok_or("published duty was never admitted")?;
                    if item.payload != message.payload
                        || item.seal.is_none()
                        || item.publication.is_some()
                    {
                        return Err("published duty identity or lifecycle differs".into());
                    }
                    item.publication = Some(Publication {
                        point: ac.point,
                        batch: net.anchor.state.next_batch_number,
                        block: net.anchor.state.last_block_number + 1,
                        slot,
                    });
                }
                next.anchor.point = ac.point;
                next.anchor.state = state;
                self.batches = self
                    .batches
                    .checked_add(1)
                    .ok_or("batch counter overflow")?;
            } else {
                let old: Vec<_> = net.lanes.iter().map(|(_, s)| s.clone()).collect();
                let (expected, active, snapshot) = net.schedule.seal(&old).map_err(err)?;
                if schedule != expected {
                    return Err("seal schedule differs from all-lane replay".into());
                }
                let immutable =
                    molecule::try_script_to_json(&molecule::script(&self.code, 2, &[]))?;
                let encoded = snapshot.encode().map_err(err)?;
                let mut found = None;
                for (i, o) in t["outputs"].as_array().ok_or("outputs")?.iter().enumerate() {
                    if o["type"].is_null()
                        && o["lock"] == immutable
                        && data(t, i, s::MAX_SNAPSHOT_BYTES)? == encoded
                    {
                        found = Some(lab::point(t["hash"].as_str().ok_or("hash")?, i as u32)?);
                        break;
                    }
                }
                let point = found.ok_or("seal missing immutable exact snapshot")?;
                for message in snapshot.ordered().map_err(err)? {
                    let item = self
                        .obligations
                        .get_mut(&(message.lane, message.sequence))
                        .ok_or("sealed duty was never admitted")?;
                    if item.payload != message.payload
                        || item.seal.is_some()
                        || item.publication.is_some()
                    {
                        return Err("sealed duty identity or lifecycle differs".into());
                    }
                    item.seal = Some(point);
                }
                next.snapshot = Some((point, snapshot));
                sealed_lanes = Some(active);
                self.seals = self.seals.checked_add(1).ok_or("seal counter overflow")?;
            }
            next.gate = c;
            next.schedule = schedule;
        }
        for (i, update) in lanes.into_iter().enumerate() {
            match update {
                Some((c, bytes)) => {
                    let lane = Lane::decode(&bytes).map_err(err)?;
                    let expected = if let Some(active) = &sealed_lanes {
                        active[i].clone()
                    } else {
                        net.lanes[i]
                            .1
                            .append(
                                lane.queue
                                    .last()
                                    .ok_or("lane update missing message")?
                                    .clone(),
                            )
                            .map_err(err)?
                    };
                    if lane != expected {
                        return Err("lane successor differs from authenticated replay".into());
                    }
                    if sealed_lanes.is_none() {
                        let sequence = lane
                            .next_sequence
                            .checked_sub(1)
                            .ok_or("admission sequence")?;
                        let obligation = Obligation {
                            lane: lane.index,
                            sequence,
                            payload: lane.queue.last().ok_or("admission payload")?.clone(),
                            admission: c.point,
                            seal: None,
                            publication: None,
                        };
                        if self
                            .obligations
                            .insert((lane.index, sequence), obligation)
                            .is_some()
                        {
                            return Err("duplicate admission identity".into());
                        }
                        self.admissions = self
                            .admissions
                            .checked_add(1)
                            .ok_or("admission counter overflow")?;
                    }
                    next.lanes[i] = (c, lane);
                }
                None if sealed_lanes.is_some() => {
                    return Err("seal omitted a configured lane input/output".into())
                }
                None => {}
            }
        }
        self.net = Some(next);
        Ok(())
    }
}

/// Expected type scripts and chain genesis hash must come from trusted deployment
/// configuration. A growing canonical tip is accepted; replacement of any scanned
/// block invalidates the pinned prefix and requires a fresh invocation.
pub fn recover_sealed(
    gate_script: &[u8],
    anchor_script: &[u8],
    genesis_hash: &str,
) -> Result<RecoveredSealed, String> {
    let tip = rpc::call("get_tip_header", json!([]))?;
    recover_sealed_at(gate_script, anchor_script, genesis_hash, &tip)
}

pub(crate) fn recover_sealed_at(
    gate_script: &[u8],
    anchor_script: &[u8],
    genesis_hash: &str,
    tip: &Value,
) -> Result<RecoveredSealed, String> {
    let mut scanner = Scanner::new(gate_script, anchor_script)?;
    if rpc::decode_hex(genesis_hash)?.len() != 32
        || rpc::call("get_block_hash", json!(["0x0"]))?.as_str() != Some(genesis_hash)
    {
        return Err("CKB genesis hash mismatch".into());
    }
    let height = number(&tip["number"])?;
    let mut previous = None;
    for n in 0..=height {
        let block = rpc::get_block_detailed(n)?;
        if number(&block["header"]["number"])? != n
            || previous
                .as_ref()
                .is_some_and(|h| *h != block["header"]["parent_hash"])
        {
            return Err("canonical chain changed during sealed recovery".into());
        }
        if n == 0 && block["header"]["hash"].as_str() != Some(genesis_hash) {
            return Err("scanned genesis mismatch".into());
        }
        previous = Some(block["header"]["hash"].clone());
        for tx in block["transactions"]
            .as_array()
            .ok_or("block transactions")?
        {
            scanner.apply(tx)?;
        }
    }
    if previous.as_ref() != Some(&tip["hash"]) {
        return Err("sealed recovery pinned tip mismatch".into());
    }
    let hash = tip["hash"].as_str().ok_or("pinned hash")?.to_owned();
    recovery::assert_canonical(height, &hash)?;
    Ok(RecoveredSealed {
        network: scanner.net.ok_or("sealed identity not found")?,
        pinned_height: height,
        pinned_hash: hash,
        genesis_hash: genesis_hash.to_owned(),
        admissions: scanner.admissions,
        seals: scanner.seals,
        batches: scanner.batches,
        obligations: scanner.obligations.into_values().collect(),
    })
}

/// Serializable observer output. Hex-encoded canonical state bytes preserve the
/// full queue, domains, reservation and next transaction inputs for an operator.
/// Parsing a saved view is not an alternative to authenticating its chain prefix.
pub fn network_view(net: &Network) -> Value {
    fn view(c: &Cell, data: Vec<u8>) -> Value {
        json!({"point":point_json(c.point),"capacity":format!("0x{:x}",c.capacity),"type_script":rpc::bytes_to_hex(&c.script),"lock":rpc::bytes_to_hex(&c.lock),"data":rpc::bytes_to_hex(&data)})
    }
    json!({"code_hash":rpc::bytes_to_hex(&net.code),"anchor":view(&anchor_cell(&net.anchor),net.anchor.state.encode().to_vec()),"anchor_immutable_lock":rpc::bytes_to_hex(&net.anchor.immutable),"gate":view(&net.gate,net.schedule.encode().expect("validated schedule")),"lanes":net.lanes.iter().map(|(c,s)|view(c,s.encode().expect("validated lane"))).collect::<Vec<_>>(),"snapshot":net.snapshot.as_ref().map(|(p,s)|json!({"point":point_json(*p),"data":rpc::bytes_to_hex(&s.encode().expect("validated snapshot"))}))})
}
impl RecoveredSealed {
    pub fn view(&self) -> Value {
        json!({"schema_version":1,"ckb_genesis_hash":self.genesis_hash,"pinned_height":self.pinned_height,"pinned_hash":self.pinned_hash,"admissions":self.admissions,"seals":self.seals,"batches":self.batches,"network":network_view(&self.network),"settlement":"NOT_PROVEN"})
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> (Scanner, Vec<Value>) {
        let v: Value = serde_json::from_str(include_str!(
            "../tests/fixtures/sealed-canonical-prefix.json"
        ))
        .unwrap();
        let txs = v["transactions"].as_array().unwrap().clone();
        fn script(v: &Value) -> Vec<u8> {
            molecule::script(
                &rpc::decode_hex(v["code_hash"].as_str().unwrap())
                    .unwrap()
                    .try_into()
                    .unwrap(),
                2,
                &rpc::decode_hex(v["args"].as_str().unwrap()).unwrap(),
            )
        }
        (
            Scanner::new(
                &script(&txs[0]["outputs"][1]["type"]),
                &script(&txs[0]["outputs"][0]["type"]),
            )
            .unwrap(),
            txs,
        )
    }
    fn at(index: usize) -> (Scanner, Value) {
        let (mut scanner, txs) = fixture();
        for tx in &txs[..index] {
            scanner.apply(tx).unwrap();
        }
        (scanner, txs[index].clone())
    }
    #[test]
    fn replay_real_canonical_history_and_ignore_counterfeit_snapshot() {
        let (mut scanner, txs) = fixture();
        for tx in &txs {
            scanner.apply(tx).unwrap();
        }
        let net = scanner.net.unwrap();
        assert_eq!(
            (scanner.admissions, scanner.seals, scanner.batches),
            (11, 1, 16)
        );
        assert_eq!(
            (
                net.schedule.epoch,
                net.schedule.batches,
                net.schedule.cursor
            ),
            (1, 8, 3)
        );
        assert_eq!(net.lanes[0].1.queue.len(), 8);
        assert_eq!(net.lanes[0].1.next_sequence, 11);
        assert_eq!(net.snapshot.unwrap().1.ordered().unwrap().len(), 3);
    }
    #[test]
    fn canonical_prefix_rebuilds_obligation_lifecycle_after_rollback() {
        for (end, admitted, sealed, published) in [
            (12, 3, 0, 0),
            (13, 0, 3, 0),
            (22, 8, 3, 0),
            (23, 8, 0, 3),
            (30, 8, 0, 3),
        ] {
            let (mut scanner, txs) = fixture();
            for tx in &txs[..end] {
                scanner.apply(tx).unwrap();
            }
            let rows: Vec<_> = scanner.obligations.values().collect();
            assert_eq!(rows.iter().filter(|o| o.seal.is_none()).count(), admitted);
            assert_eq!(
                rows.iter()
                    .filter(|o| o.seal.is_some() && o.publication.is_none())
                    .count(),
                sealed
            );
            assert_eq!(
                rows.iter().filter(|o| o.publication.is_some()).count(),
                published
            );
            for row in rows.iter().filter(|o| o.publication.is_some()) {
                let publication = row.publication.as_ref().unwrap();
                assert_eq!(
                    (publication.batch, publication.block, publication.slot),
                    (8, 9, row.sequence as usize)
                );
                assert_eq!(
                    rpc::bytes_to_hex(&publication.point.tx_hash),
                    txs[22]["hash"]
                );
                assert_eq!(
                    rpc::bytes_to_hex(&row.seal.unwrap().tx_hash),
                    txs[12]["hash"]
                );
                assert_eq!(
                    rpc::bytes_to_hex(&row.admission.tx_hash),
                    txs[2 + row.sequence as usize]["hash"]
                );
            }
        }
    }
    #[test]
    fn reject_forged_genesis_identity() {
        let (mut scanner, mut tx) = at(0);
        tx["inputs"][0]["previous_output"]["index"] = json!("0xff");
        assert!(scanner.apply(&tx).unwrap_err().contains("Type ID mismatch"));
    }
    #[test]
    fn reject_disconnected_lane_and_capacity_or_lock_takeover() {
        for mutation in 0..3 {
            let (mut scanner, mut tx) = at(2);
            match mutation {
                0 => tx["inputs"][0]["previous_output"]["index"] = json!("0xff"),
                1 => {
                    tx["outputs"][0]["capacity"] = json!(format!(
                        "0x{:x}",
                        number(&tx["outputs"][0]["capacity"]).unwrap() - 1
                    ))
                }
                _ => tx["outputs"][0]["lock"]["args"] = json!("0x"),
            }
            let expected = ["disconnected", "capacity changed", "lock mismatch"][mutation];
            assert!(scanner.apply(&tx).unwrap_err().contains(expected));
        }
    }
    #[test]
    fn reject_noop_or_corrupt_lane() {
        let (mut scanner, mut tx) = at(2);
        tx["outputs_data"][0] = json!(rpc::bytes_to_hex(
            &scanner.net.as_ref().unwrap().lanes[0].1.encode().unwrap()
        ));
        assert!(scanner.apply(&tx).unwrap_err().contains("missing message"));
        let (mut scanner, mut tx) = at(2);
        let mut bytes = data(&tx, 0, s::MAX_LANE_BYTES).unwrap();
        *bytes.last_mut().unwrap() ^= 1;
        tx["outputs_data"][0] = json!(rpc::bytes_to_hex(&bytes));
        assert!(scanner.apply(&tx).is_err());
    }
    #[test]
    fn reject_incomplete_seal_and_replaced_snapshot() {
        let (mut scanner, mut tx) = at(12);
        tx["inputs"].as_array_mut().unwrap().remove(1);
        assert!(scanner.apply(&tx).unwrap_err().contains("disconnected"));
        let (mut scanner, mut tx) = at(12);
        let mut bytes = data(&tx, 2, s::MAX_SNAPSHOT_BYTES).unwrap();
        *bytes.last_mut().unwrap() ^= 1;
        tx["outputs_data"][2] = json!(rpc::bytes_to_hex(&bytes));
        assert!(scanner
            .apply(&tx)
            .unwrap_err()
            .contains("immutable exact snapshot"));
    }
    #[test]
    fn reject_consistent_anchor_that_omits_mandatory_prefix() {
        let (mut scanner, mut tx) = at(22);
        let parent = scanner.net.as_ref().unwrap().anchor.state;
        let bytes = crate::batch_lab::encode(
            parent,
            vec![crate::batch_lab::block(parent.last_timestamp + 1, vec![])],
        )
        .unwrap();
        let summary = batch::validate_batch(&bytes, &parent).unwrap();
        tx["outputs_data"][0] = json!(rpc::bytes_to_hex(&summary.next.encode()));
        tx["outputs_data"][1] = json!(rpc::bytes_to_hex(&bytes));
        assert!(scanner
            .apply(&tx)
            .unwrap_err()
            .contains("mandatory-prefix publication"));
    }
    #[test]
    fn reject_destroyed_gate_on_an_anchor_advance() {
        let (mut scanner, mut tx) = at(22);
        tx["outputs"][2]["type"] = Value::Null;
        assert!(scanner.apply(&tx).unwrap_err().contains("destroyed"));
    }
}
