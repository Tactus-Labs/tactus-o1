//! Real A3 mandatory gate: authenticated complete seals, immutable dependencies,
//! bounded mandatory prefixes, hostile switching and planned rollback.
use crate::{
    batch_lab::{self, Anchor},
    lab::{self, Lab},
    molecule, rpc,
    tx::{self, CellOutPoint, OutSpec, TX_FEE},
};
use serde_json::{json, Value};
use tactus_o1_execution::{rules_hash, Executor};
use tactus_o1_ordering_script::{ckb_blake2b, genesis_identity};
use tactus_o1_protocol::{
    batch::{self, AnchorState},
    sealed::{self as s, Lane, Schedule, Snapshot},
};
#[derive(Clone)]
pub struct Cell {
    pub point: CellOutPoint,
    pub capacity: u64,
    pub script: Vec<u8>,
    pub lock: Vec<u8>,
}
impl Cell {
    pub fn output(&self, data: Vec<u8>) -> OutSpec {
        OutSpec {
            capacity: self.capacity,
            lock: self.lock.clone(),
            type_script: Some(self.script.clone()),
            data,
        }
    }
}
#[derive(Clone)]
pub struct Network {
    pub code: [u8; 32],
    pub anchor: Anchor,
    pub gate: Cell,
    pub schedule: Schedule,
    pub lanes: Vec<(Cell, Lane)>,
    pub snapshot: Option<(CellOutPoint, Snapshot)>,
}
pub fn role(code: &[u8; 32], tag: u8, id: &[u8; 32], index: Option<u8>) -> Vec<u8> {
    let mut args = vec![tag];
    args.extend_from_slice(id);
    if let Some(index) = index {
        args.push(index);
    }
    molecule::script(code, 2, &args)
}
pub fn cell(point: CellOutPoint, code: &[u8; 32], script: Vec<u8>, reserved: usize) -> Cell {
    let lock = role(code, 0, &ckb_blake2b(&script), None);
    let capacity = OutSpec::required_capacity(&lock, Some(&script), reserved) + TX_FEE;
    Cell {
        point,
        capacity,
        script,
        lock,
    }
}
pub fn shape(
    lab: &Lab,
    actor: usize,
    prefix: &[(CellOutPoint, u64)],
    outputs: Vec<OutSpec>,
    input_types: &[(usize, Vec<u8>)],
    extra_deps: &[CellOutPoint],
) -> Result<Value, String> {
    shape_with_fee(lab, actor, prefix, outputs, input_types, extra_deps, TX_FEE)
}
pub fn shape_with_fee(
    lab: &Lab,
    actor: usize,
    prefix: &[(CellOutPoint, u64)],
    mut outputs: Vec<OutSpec>,
    input_types: &[(usize, Vec<u8>)],
    extra_deps: &[CellOutPoint],
    fee: u64,
) -> Result<Value, String> {
    let wallet = &lab.wallets[actor];
    let total = prefix.iter().try_fold(wallet.capacity, |n, (_, c)| {
        n.checked_add(*c).ok_or("capacity overflow")
    })?;
    let spent: u64 = outputs.iter().map(|o| o.capacity).sum();
    let change = total
        .checked_sub(spent.checked_add(fee).ok_or("capacity overflow")?)
        .ok_or("capacity")?;
    outputs.push(OutSpec {
        capacity: change,
        lock: wallet.key.lock_script(),
        type_script: None,
        data: vec![],
    });
    let mut inputs = prefix.to_vec();
    inputs.push((wallet.point, wallet.capacity));
    let mut deps = lab.deps.clone();
    deps.extend_from_slice(extra_deps);
    let (_, mut transaction) = tx::build_with_permissionless_prefix(
        &wallet.key,
        &lab.secp,
        &deps,
        &inputs,
        &outputs,
        None,
        prefix.len(),
    )?;
    for (index, data) in input_types {
        if *index >= prefix.len() {
            return Err("cannot mutate funding witness after signing".into());
        }
        transaction["witnesses"][*index] = json!(rpc::bytes_to_hex(&molecule::witness_args(
            None,
            Some(data),
            None
        )));
    }
    Ok(transaction)
}
pub fn commit(
    lab: &mut Lab,
    actor: usize,
    label: &str,
    transaction: &Value,
) -> Result<String, String> {
    let hash = lab.commit(label, transaction)?;
    let outputs = transaction["outputs"].as_array().ok_or("outputs")?;
    let change = outputs.last().ok_or("change")?;
    lab.wallets[actor].point = lab::point(&hash, (outputs.len() - 1) as u32)?;
    lab.wallets[actor].capacity = u64::from_str_radix(
        change["capacity"]
            .as_str()
            .ok_or("capacity")?
            .trim_start_matches("0x"),
        16,
    )
    .map_err(|e| e.to_string())?;
    Ok(hash)
}
pub fn reject(
    lab: &mut Lab,
    code: &[u8; 32],
    label: &str,
    transaction: &Value,
    location: &str,
    expected: i8,
) -> Result<(), String> {
    let error = match rpc::send_transaction_json(transaction) {
        Err(e) => e,
        Ok(hash) => return Err(format!("{label}: unexpectedly accepted {hash}")),
    };
    let value: Value = error
        .strip_prefix("rpc error: ")
        .and_then(|s| serde_json::from_str(s).ok())
        .ok_or_else(|| error.clone())?;
    if value["code"] != -302
        || !location.split('|').any(|x| error.contains(x))
        || !error.contains(&format!("error code {expected} on page "))
        || !error.contains(&rpc::bytes_to_hex(code)[2..])
    {
        return Err(format!(
            "{label}: expected {location} code {expected}, got {error}"
        ));
    }
    lab.evidence.push(json!({"label":label,"result":"rejected","expected_location":location,"expected_code":expected,"error":error,"transaction":transaction}));
    println!("{label}: rejected ({expected})");
    Ok(())
}
pub fn live(point: CellOutPoint, expected: bool) -> Result<(), String> {
    let view = rpc::call(
        "get_live_cell",
        json!([{"tx_hash":rpc::bytes_to_hex(&point.tx_hash),"index":format!("0x{:x}",point.index)},false]),
    )?;
    if (view["status"] == "live") != expected {
        return Err(format!("liveness mismatch {view}"));
    }
    Ok(())
}
pub fn bootstrap(lab: &mut Lab, code: [u8; 32], n: u8) -> Result<Network, String> {
    let anchor_elf = lab.ordering_elf.clone();
    bootstrap_with_program(lab, code, n, &anchor_elf)
}
pub fn bootstrap_with_program(
    lab: &mut Lab,
    code: [u8; 32],
    n: u8,
    anchor_elf: &[u8],
) -> Result<Network, String> {
    let allocation = tactus_o1_protocol::genesis::Allocation::default()
        .encode()
        .unwrap();
    bootstrap_with_allocation(lab, code, n, anchor_elf, &allocation)
}
pub fn bootstrap_with_allocation(
    lab: &mut Lab,
    code: [u8; 32],
    n: u8,
    anchor_elf: &[u8],
    allocation: &[u8],
) -> Result<Network, String> {
    bootstrap_with_auxiliary(lab, code, n, anchor_elf, allocation, |_| Ok(vec![]))
}

/// Atomically attach additional protocol genesis outputs to the same Anchor.
/// Existing callers produce byte-identical transactions with no auxiliary cells.
pub fn bootstrap_with_auxiliary(
    lab: &mut Lab,
    code: [u8; 32],
    n: u8,
    anchor_elf: &[u8],
    allocation: &[u8],
    extra: impl FnOnce(&Anchor) -> Result<Vec<OutSpec>, String>,
) -> Result<Network, String> {
    let wallet = &lab.wallets[0];
    let seed: [u8; 44] = molecule::cell_input(
        0,
        &molecule::out_point(&wallet.point.tx_hash, wallet.point.index),
    )
    .try_into()
    .unwrap();
    let rollup = genesis_identity(&seed, 0);
    let id = genesis_identity(&seed, 1);
    let anchor_script = tx::anchor_type_script(anchor_elf, &rollup, allocation)?;
    let gate_script = role(&code, 2, &id, None);
    let gate = cell(wallet.point, &code, gate_script, s::SCHEDULE_BYTES);
    let anchor_lock = role(&code, 0, &ckb_blake2b(&gate.script), None);
    let anchor = Anchor {
        point: wallet.point,
        capacity: OutSpec::required_capacity(&anchor_lock, Some(&anchor_script), batch::ANCHOR_LEN)
            + TX_FEE,
        state: AnchorState::genesis(rollup, rules_hash(), 31337).map_err(|e| format!("{e:?}"))?,
        lock: anchor_lock,
        script: anchor_script,
        immutable: molecule::script(&ckb_blake2b(anchor_elf), 2, &[]),
    };
    let schedule = Schedule::genesis(id, rollup, ckb_blake2b(&anchor.script), n)
        .map_err(|e| format!("{e:?}"))?;
    let mut outputs = vec![
        batch_lab::head_output(&anchor, anchor.state),
        gate.output(schedule.encode().unwrap()),
    ];
    let mut lanes = vec![];
    for i in 0..n {
        let c = cell(
            wallet.point,
            &code,
            role(&code, 1, &id, Some(i)),
            s::MAX_LANE_BYTES,
        );
        let lane = Lane::genesis(id, i).unwrap();
        outputs.push(c.output(lane.encode().unwrap()));
        lanes.push((c, lane));
    }
    outputs.push(batch_lab::da_output(&anchor, allocation));
    outputs.extend(extra(&anchor)?);
    let transaction = shape(lab, 0, &[], outputs, &[], &[])?;
    let hash = commit(lab, 0, &format!("sealed/{n} lanes/genesis"), &transaction)?;
    let mut network = Network {
        code,
        anchor,
        gate,
        schedule,
        lanes,
        snapshot: None,
    };
    network.anchor.point = lab::point(&hash, 0)?;
    network.gate.point = lab::point(&hash, 1)?;
    for (i, (c, _)) in network.lanes.iter_mut().enumerate() {
        c.point = lab::point(&hash, (i + 2) as u32)?;
    }
    Ok(network)
}
pub fn append_tx(
    lab: &Lab,
    net: &Network,
    index: usize,
    actor: usize,
    payload: Vec<u8>,
) -> Result<(Value, Lane), String> {
    let (c, old) = &net.lanes[index];
    let next = old.append(payload).map_err(|e| format!("{e:?}"))?;
    Ok((
        shape(
            lab,
            actor,
            &[(c.point, c.capacity)],
            vec![c.output(next.encode().unwrap())],
            &[],
            &[],
        )?,
        next,
    ))
}
pub fn append(
    lab: &mut Lab,
    net: &mut Network,
    index: usize,
    actor: usize,
    payload: Vec<u8>,
    label: &str,
) -> Result<(), String> {
    let (transaction, next) = append_tx(lab, net, index, actor, payload)?;
    let hash = commit(lab, actor, label, &transaction)?;
    net.lanes[index].0.point = lab::point(&hash, 0)?;
    net.lanes[index].1 = next;
    Ok(())
}
pub fn bytes(net: &Network, transactions: Vec<Vec<u8>>) -> Result<Vec<u8>, String> {
    batch_lab::encode(
        net.anchor.state,
        vec![batch_lab::block(
            net.anchor.state.last_timestamp + 1,
            transactions,
        )],
    )
}
pub fn required_bytes(net: &Network) -> Result<Vec<u8>, String> {
    bytes(
        net,
        net.schedule
            .required(net.snapshot.as_ref().map(|(_, s)| s))
            .map_err(|e| format!("{e:?}"))?
            .into_iter()
            .map(|m| m.payload)
            .collect(),
    )
}
pub fn advance_outputs(net: &Network, bytes: &[u8]) -> Result<Vec<OutSpec>, String> {
    let summary = batch::validate_batch(bytes, &net.anchor.state).map_err(|e| format!("{e:?}"))?;
    let mut next = net.schedule.clone();
    // Allows constructing a freshly signed ninth-batch attack with a validly
    // encoded but unchanged schedule; the real gate must reject it.
    if next.batches < s::BATCHES_PER_EPOCH {
        next.batches += 1;
        next.cursor =
            (u16::from(next.batches) * s::PRIORITY_PER_BATCH as u16).min(next.snapshot_messages);
    }
    Ok(vec![
        batch_lab::head_output(&net.anchor, summary.next),
        batch_lab::da_output(&net.anchor, bytes),
        net.gate.output(next.encode().unwrap()),
    ])
}
pub fn advance_tx(
    lab: &Lab,
    net: &Network,
    actor: usize,
    outputs: Vec<OutSpec>,
) -> Result<Value, String> {
    let deps: Vec<_> = net.snapshot.iter().map(|(point, _)| *point).collect();
    shape(
        lab,
        actor,
        &[
            (net.anchor.point, net.anchor.capacity),
            (net.gate.point, net.gate.capacity),
        ],
        outputs,
        &[(0, 1u32.to_le_bytes().to_vec()), (1, vec![1])],
        &deps,
    )
}
pub fn accept_advance(
    lab: &mut Lab,
    net: &mut Network,
    actor: usize,
    bytes: &[u8],
    transaction: &Value,
    label: &str,
) -> Result<(), String> {
    let (next, summary) = net
        .schedule
        .advance(
            net.snapshot.as_ref().map(|(_, s)| s),
            bytes,
            &net.anchor.state,
        )
        .map_err(|e| format!("{e:?}"))?;
    let hash = commit(lab, actor, label, transaction)?;
    net.anchor.point = lab::point(&hash, 0)?;
    net.anchor.state = summary.next;
    net.gate.point = lab::point(&hash, 2)?;
    net.schedule = next;
    Ok(())
}
pub fn advance(
    lab: &mut Lab,
    net: &mut Network,
    actor: usize,
    engine: &mut Executor,
    label: &str,
) -> Result<(), String> {
    let bytes = required_bytes(net)?;
    let transaction = advance_tx(lab, net, actor, advance_outputs(net, &bytes)?)?;
    accept_advance(lab, net, actor, &bytes, &transaction, label)?;
    engine.apply_batch(&bytes).map_err(|e| e.to_string())?;
    Ok(())
}
pub fn seal_outputs(
    net: &Network,
) -> Result<(Vec<OutSpec>, Schedule, Vec<Lane>, Snapshot), String> {
    let lanes: Vec<_> = net.lanes.iter().map(|(_, s)| s.clone()).collect();
    let mut ready = net.schedule.clone();
    ready.batches = s::BATCHES_PER_EPOCH;
    ready.cursor = ready.snapshot_messages;
    let (next, active, sealed) = ready.seal(&lanes).map_err(|e| format!("{e:?}"))?;
    let mut outputs = vec![net.gate.output(next.encode().unwrap())];
    for ((c, _), state) in net.lanes.iter().zip(&active) {
        outputs.push(c.output(state.encode().unwrap()));
    }
    let data = sealed.encode().unwrap();
    let immutable = molecule::script(&net.code, 2, &[]);
    outputs.push(OutSpec {
        capacity: OutSpec::required_capacity(&immutable, None, data.len()),
        lock: immutable,
        type_script: None,
        data,
    });
    Ok((outputs, next, active, sealed))
}
pub fn seal_tx(
    lab: &Lab,
    net: &Network,
    actor: usize,
    outputs: Vec<OutSpec>,
    omit_last: bool,
) -> Result<Value, String> {
    let mut inputs = vec![(net.gate.point, net.gate.capacity)];
    let n = net.lanes.len() - usize::from(omit_last);
    inputs.extend(net.lanes[..n].iter().map(|(c, _)| (c.point, c.capacity)));
    let mut witness = vec![0];
    witness.extend_from_slice(&((outputs.len() - 1) as u32).to_le_bytes());
    shape(lab, actor, &inputs, outputs, &[(0, witness)], &[])
}
pub fn seal(lab: &mut Lab, net: &mut Network, actor: usize, label: &str) -> Result<(), String> {
    let (outputs, next, active, sealed) = seal_outputs(net)?;
    let transaction = seal_tx(lab, net, actor, outputs, false)?;
    let hash = commit(lab, actor, label, &transaction)?;
    net.gate.point = lab::point(&hash, 0)?;
    net.schedule = next;
    for (i, ((c, old), new)) in net.lanes.iter_mut().zip(active).enumerate() {
        c.point = lab::point(&hash, (i + 1) as u32)?;
        *old = new;
    }
    net.snapshot = Some((lab::point(&hash, (net.lanes.len() + 1) as u32)?, sealed));
    Ok(())
}
