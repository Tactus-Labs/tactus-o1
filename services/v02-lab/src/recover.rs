//! Rebuild one pinned canonical snapshot. No persisted cursor is trusted.
//! Reorgs discard the entire attempted snapshot; publication occurs only after
//! the final pin and current live-cell checks. The RPC node supplies consensus.
use crate::limits::{self, Meter};
use crate::nullifiers::Tree;
use crate::{build, bytes, err, hash32, number, point, point_bytes, point_json, script, Result};
use ckb_std::ckb_types::{packed, prelude::*};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use tactus_o1_devnet_driver::{molecule, rpc};
use tactus_o1_execution::{v02::V02Executor, Genesis};
use tactus_o1_protocol::v02::*;
use tactus_v02_proof_journal::{self as journal, Frame};
use tactus_v02_script::{
    adapter,
    claims::{ClaimWitness, Request},
};
#[derive(Clone)]
pub struct Manifest {
    pub config: Config,
    pub policy: Policy,
    pub genesis_tx: [u8; 32],
    pub monitoring: crate::operations::Monitoring,
}
impl Manifest {
    pub fn decode(v: &Value) -> Result<Self> {
        if v["schema"] != "tactus-v02-devnet-manifest-v1" {
            return Err("wrong manifest schema".into());
        }
        let value = Self {
            config: Config::decode(&bytes(&v["config_hex"], Config::MAX_BYTES)?).map_err(err)?,
            policy: Policy::decode(&bytes(&v["policy_hex"], Policy::MAX_BYTES)?).map_err(err)?,
            genesis_tx: hash32(&v["genesis_tx"])?,
            monitoring: crate::operations::Monitoring::decode(&v["monitor"])?,
        };
        value.config.bind(&value.policy).map_err(err)?;
        if value.policy.wrapper_key_hash != adapter::wrapper_key_hash() {
            return Err("wrong compiled wrapper identity".into());
        }
        Ok(value)
    }
}
pub struct Recovered {
    pub manifest: Manifest,
    pub tip: Value,
    pub cells: BTreeMap<[u8; 36], build::Cell>,
    pub frames: Vec<Frame>,
    pub allocation: Vec<u8>,
    pub control: Control,
    pub vault: Vault,
    pub claims: [Tree; 3],
    pub transitions: Vec<Value>,
    pub execution: V02Executor,
}
fn own(config: &Config, c: &build::Cell) -> bool {
    c.output.type_script.as_ref().is_some_and(|ty| {
        packed::Script::from_slice(ty).ok().is_some_and(|ty| {
            ty.code_hash().as_slice() == config.adapter_code_hash
                && ty.args().raw_data().get(..32) == Some(config.domain.as_slice())
        })
    })
}
fn role_cell<'a>(
    cells: &'a BTreeMap<[u8; 36], build::Cell>,
    config: &Config,
    role: Role,
    index: u64,
) -> Result<&'a build::Cell> {
    let ty = adapter::type_script(config, role, index).map_err(err)?;
    let mut it = cells
        .values()
        .filter(|c| c.output.type_script.as_deref() == Some(ty.as_slice()));
    let c = it
        .next()
        .ok_or_else(|| format!("missing live {role:?}/{index}"))?;
    if it.next().is_some() {
        return Err("ambiguous live role".into());
    }
    Ok(c)
}
fn adapter_cell(
    c: &build::Cell,
    since: u64,
    output: bool,
    config: &Config,
) -> Result<adapter::Cell> {
    Ok(adapter::Cell {
        capacity: c.output.capacity,
        occupied: tactus_o1_devnet_driver::tx::OutSpec::required_capacity(
            &c.output.lock,
            c.output.type_script.as_deref(),
            c.output.data.len(),
        ),
        lock: packed::Script::from_slice(&c.output.lock).map_err(err)?,
        type_script: c
            .output
            .type_script
            .as_ref()
            .map(|t| packed::Script::from_slice(t).map_err(err))
            .transpose()?,
        data: if output || own(config, c) {
            c.output.data.clone()
        } else {
            vec![]
        },
        outpoint: point_bytes(c.point),
        since,
    })
}
pub fn raw_hash(tx: &Value) -> Result<[u8; 32]> {
    if number(&tx["version"])? != 0 {
        return Err("unsupported transaction version".into());
    }
    let deps = tx["cell_deps"]
        .as_array()
        .ok_or("deps")?
        .iter()
        .map(|d| {
            Ok(molecule::cell_dep(
                &point_bytes(point(&d["out_point"])?),
                match d["dep_type"].as_str() {
                    Some("code") => 0,
                    Some("dep_group") => 1,
                    _ => return Err("dep type".into()),
                },
            ))
        })
        .collect::<Result<Vec<_>>>()?;
    let headers = tx["header_deps"]
        .as_array()
        .ok_or("headers")?
        .iter()
        .map(hash32)
        .collect::<Result<Vec<_>>>()?;
    let inputs = tx["inputs"]
        .as_array()
        .ok_or("inputs")?
        .iter()
        .map(|i| {
            Ok(molecule::cell_input(
                number(&i["since"])?,
                &point_bytes(point(&i["previous_output"])?),
            ))
        })
        .collect::<Result<Vec<_>>>()?;
    let outputs = tx["outputs"]
        .as_array()
        .ok_or("outputs")?
        .iter()
        .map(|o| {
            Ok(molecule::cell_output(
                number(&o["capacity"])?,
                &script(&o["lock"])?,
                if o["type"].is_null() {
                    None
                } else {
                    Some(script(&o["type"])?)
                }
                .as_deref(),
            ))
        })
        .collect::<Result<Vec<_>>>()?;
    let data = tx["outputs_data"]
        .as_array()
        .ok_or("output data")?
        .iter()
        .map(|d| Ok(molecule::bytes(&bytes(d, 1024 * 1024)?)))
        .collect::<Result<Vec<_>>>()?;
    if outputs.len() != data.len() {
        return Err("output/data count".into());
    }
    Ok(hash(
        b"",
        &molecule::raw_transaction_with_headers(&deps, &headers, &inputs, &outputs, &data),
    ))
}
pub fn recover(manifest: Manifest) -> Result<Recovered> {
    let tip = rpc::call("get_tip_header", json!([]))?;
    let end = number(&tip["number"])?;
    if end > limits::MAX_HEIGHT {
        return Err("development recovery block limit exceeded".into());
    }
    let config = &manifest.config;
    let policy = &manifest.policy;
    let identity = config.commitment().map_err(err)?;
    let mut cells: BTreeMap<[u8; 36], build::Cell> = BTreeMap::new();
    let mut live_payload = Meter::new(limits::MAX_LIVE_PAYLOAD, "live-cell payload");
    let mut frame_payload = Meter::new(limits::MAX_FRAME_PAYLOAD, "frame payload");
    let mut scanned = Meter::new(limits::MAX_SCANNED_TRANSACTIONS, "scanned transactions");
    let mut outcomes = Meter::new(limits::MAX_OUTCOMES, "reported outcome count");
    let mut previous = None;
    let mut initialized = false;
    let mut engine: Option<V02Executor> = None;
    let mut controls = vec![];
    let mut frames = vec![];
    let mut allocation = vec![];
    let mut transitions = vec![];
    let mut trees = [
        Tree::new(identity, ClaimKind::Release),
        Tree::new(identity, ClaimKind::Refund),
        Tree::new(identity, ClaimKind::Escape),
    ];
    for height in 0..=end {
        let block = rpc::get_block_detailed(height)?;
        let block_hash = hash32(&block["header"]["hash"])?;
        if number(&block["header"]["number"])? != height
            || previous.is_some_and(|p| hash32(&block["header"]["parent_hash"]).ok() != Some(p))
            || (height == 0 && block_hash != config.ckb_genesis)
        {
            return Err("chain continuity/genesis mismatch during recovery".into());
        }
        previous = Some(block_hash);
        for tx in block["transactions"]
            .as_array()
            .ok_or("block transactions")?
        {
            scanned.add(1)?;
            let tx_hash = raw_hash(tx)?;
            if tx_hash != hash32(&tx["hash"])? {
                return Err("RPC transaction body/hash mismatch".into());
            }
            let outputs = build::outputs(tx, tx_hash)?;
            let input_points = tx["inputs"]
                .as_array()
                .ok_or("inputs")?
                .iter()
                .map(|i| point(&i["previous_output"]).map(point_bytes))
                .collect::<Result<Vec<_>>>()?;
            let input_cells = input_points
                .iter()
                .filter_map(|p| cells.get(p))
                .collect::<Vec<_>>();
            let related = outputs
                .iter()
                .chain(input_cells.iter().copied())
                .any(|c| own(config, c));
            if related {
                if input_cells.len() != input_points.len() {
                    return Err("protocol input not in canonical live set".into());
                }
                let witness = bytes(&tx["witnesses"][0], adapter::MAX_OPERATION + 1024)?;
                let op_bytes = packed::WitnessArgs::from_slice(&witness)
                    .map_err(err)?
                    .output_type()
                    .to_opt()
                    .ok_or("missing operation")?
                    .raw_data()
                    .to_vec();
                let op =
                    Operation::try_from(*op_bytes.get(8).ok_or("short operation")?).map_err(err)?;
                if op == Operation::Genesis {
                    if initialized || tx_hash != manifest.genesis_tx {
                        return Err("unexpected or duplicate joint genesis".into());
                    }
                } else if !initialized {
                    return Err("transition before trusted genesis".into());
                }
                let mut deps = vec![];
                for d in tx["cell_deps"].as_array().ok_or("deps")? {
                    if d["dep_type"] != "code" {
                        return Err("protocol dep group unsupported".into());
                    }
                    let p = point_bytes(point(&d["out_point"])?);
                    deps.push(adapter_cell(
                        cells.get(&p).ok_or("spent or unknown dependency")?,
                        0,
                        false,
                        config,
                    )?);
                }
                let input_values = tx["inputs"].as_array().ok_or("inputs")?;
                let inputs = input_cells
                    .iter()
                    .enumerate()
                    .map(|(i, c)| {
                        adapter_cell(c, number(&input_values[i]["since"])?, false, config)
                    })
                    .collect::<Result<Vec<_>>>()?;
                let adapter_outputs = outputs
                    .iter()
                    .map(|c| adapter_cell(c, 0, true, config))
                    .collect::<Result<Vec<_>>>()?;
                let current = outputs
                    .iter()
                    .chain(input_cells.iter().copied())
                    .find(|c| own(config, c))
                    .ok_or("protocol script")?;
                let run = adapter::Transaction {
                    script: packed::Script::from_slice(
                        current.output.type_script.as_ref().ok_or("type")?,
                    )
                    .map_err(err)?,
                    inputs,
                    outputs: adapter_outputs,
                    deps,
                    first_input: molecule::cell_input(
                        number(&input_values[0]["since"])?,
                        &input_points[0],
                    )
                    .try_into()
                    .map_err(err)?,
                    genesis_hash: tx["header_deps"]
                        .as_array()
                        .ok_or("headers")?
                        .iter()
                        .any(|h| hash32(h).ok() == Some(config.ckb_genesis))
                        .then_some(config.ckb_genesis),
                    operation: op_bytes.clone(),
                };
                run.verify().map_err(|e| {
                    format!("canonical protocol transaction failed native recheck: {e:?}")
                })?;
                let mut event = json!({"operation":op as u8,"tx_hash":rpc::bytes_to_hex(&tx_hash),"block_number":height,"block_hash":rpc::bytes_to_hex(&block_hash)});
                if op == Operation::Settle {
                    let ty = adapter::type_script(config, Role::Control, 0).map_err(err)?;
                    let next = outputs
                        .iter()
                        .find(|c| c.output.type_script.as_deref() == Some(ty.as_slice()))
                        .ok_or("missing settled Control")?;
                    event["settled_batches"] = json!(
                        Control::decode(&next.output.data)
                            .map_err(err)?
                            .boundary
                            .batches
                    );
                }
                if matches!(
                    op,
                    Operation::Release | Operation::Refund | Operation::Escape
                ) {
                    let claim = ClaimWitness::decode(&op_bytes[9..]).map_err(err)?;
                    let (kind, id, payment) = match claim.request {
                        Request::Release {
                            id,
                            amount,
                            owner,
                            recipient,
                            ..
                        } => (
                            0,
                            id.to_le_bytes().to_vec(),
                            json!({"kind":"release","id":id.to_string(),"owner":rpc::bytes_to_hex(&owner),"principal_shannons":amount.to_string(),"recipient_lock_hash":rpc::bytes_to_hex(&recipient)}),
                        ),
                        Request::Escape {
                            owner,
                            amount,
                            recipient,
                            ..
                        } => (
                            2,
                            owner.to_vec(),
                            json!({"kind":"escape","owner":rpc::bytes_to_hex(&owner),"principal_shannons":amount.to_string(),"recipient_lock_hash":rpc::bytes_to_hex(&recipient)}),
                        ),
                        Request::Refund { receipt_outpoint } => {
                            let d = Deposit::decode(
                                &cells
                                    .get(&receipt_outpoint)
                                    .ok_or("refund receipt")?
                                    .output
                                    .data,
                            )
                            .map_err(err)?;
                            (
                                1,
                                d.sequence.to_le_bytes().to_vec(),
                                json!({"kind":"refund","sequence":d.sequence.to_string(),"principal_shannons":d.amount.to_string(),"recipient_lock_hash":rpc::bytes_to_hex(&d.refund_lock)}),
                            )
                        }
                    };
                    trees[kind].record(&id)?;
                    event["payment"] = payment;
                    event["payment"]["payout_index"] = json!(claim.payout);
                }
                if transitions.len() >= limits::MAX_TRANSITIONS {
                    return Err("development transition count limit exceeded".into());
                }
                transitions.push(event);
                if op == Operation::Genesis {
                    initialized = true;
                }
            }
            for p in &input_points {
                if let Some(cell) = cells.remove(p) {
                    live_payload.remove(limits::cell_payload(&cell)?)?;
                }
            }
            for c in outputs {
                if cells.len() >= limits::MAX_LIVE_CELLS {
                    return Err("development live-cell index limit exceeded".into());
                }
                live_payload.add(limits::cell_payload(&c)?)?;
                if cells.insert(point_bytes(c.point), c).is_some() {
                    return Err("duplicate canonical outpoint".into());
                }
            }
            if related {
                if engine.is_none() {
                    if Config::decode(&role_cell(&cells, config, Role::Config, 0)?.output.data)
                        .map_err(err)?
                        != *config
                        || Policy::decode(&role_cell(&cells, config, Role::Policy, 0)?.output.data)
                            .map_err(err)?
                            != *policy
                    {
                        return Err("manifest differs from actual immutable config/policy".into());
                    }
                    allocation = role_cell(&cells, config, Role::Allocation, 0)?
                        .output
                        .data
                        .clone();
                    let g =
                        Genesis::from_allocation(config.domain.into(), config.chain, &allocation)
                            .map_err(err)?;
                    let e = V02Executor::new(&g, config.clone(), policy.clone()).map_err(err)?;
                    limits::state_usage(&e)?;
                    controls.push(e.control_candidate().map_err(err)?);
                    engine = Some(e);
                }
                let e = engine.as_mut().ok_or("execution")?;
                let anchor =
                    Boundary::decode(&role_cell(&cells, config, Role::Anchor, 0)?.output.data)
                        .map_err(err)?;
                if anchor.batches > e.boundary().batches {
                    if anchor.batches != e.boundary().batches + 1 {
                        return Err("publication gap".into());
                    }
                    let batch = NativeBatch::decode(
                        &role_cell(&cells, config, Role::Batch, anchor.batches)?
                            .output
                            .data,
                    )
                    .map_err(err)?;
                    let snapshot = Snapshot::decode(
                        &role_cell(&cells, config, Role::Snapshot, anchor.epoch)?
                            .output
                            .data,
                    )
                    .map_err(err)?;
                    if frames.len() >= limits::MAX_FRAMES {
                        return Err("development frame count limit exceeded".into());
                    }
                    let frame = Frame { snapshot, batch };
                    frame_payload.add(frame.encode().map_err(err)?.len())?;
                    let executed = e
                        .apply_batch(&frame.batch.encode().map_err(err)?, &frame.snapshot)
                        .map_err(err)?;
                    for block in &executed.blocks {
                        outcomes.add(block.outcomes.len())?;
                    }
                    let event = transitions.last_mut().ok_or("missing publication event")?;
                    event["batch_number"] = json!(anchor.batches);
                    event["execution"] = json!({"authority":"deterministic replay, not custody authority","blocks":executed.blocks.iter().map(|block|json!({"block_number":block.header.number,"block_hash":block.hash,"slots":block.outcomes.iter().enumerate().map(|(slot,o)|json!({"slot":slot,"input_hash":o.input_hash,"status":o.status,"gas_used":o.gas_used,"transaction_index":o.transaction_index,"output_hash":alloy_primitives::keccak256(&o.output),"created_address":o.created_address})).collect::<Vec<_>>()})).collect::<Vec<_>>()});
                    if *e.boundary() != anchor {
                        return Err("replay differs from canonical checkpoint".into());
                    }
                    limits::state_usage(e)?;
                    frames.push(frame);
                    controls.push(e.control_candidate().map_err(err)?);
                }
                let control =
                    Control::decode(&role_cell(&cells, config, Role::Control, 0)?.output.data)
                        .map_err(err)?;
                let mut expected = controls
                    .get(usize::try_from(control.boundary.batches).map_err(err)?)
                    .ok_or("settlement beyond publication")?
                    .clone();
                expected.mode = control.mode;
                if control != expected {
                    return Err("canonical settlement differs from full EVM replay".into());
                }
                let vault = Vault::decode(&role_cell(&cells, config, Role::Vault, 0)?.output.data)
                    .map_err(err)?;
                vault.partitions(&control).map_err(err)?;
                if vault.claims != [trees[0].root(), trees[1].root(), trees[2].root()] {
                    return Err("canonical nullifier history differs from Vault".into());
                }
            }
        }
    }
    if previous != Some(hash32(&tip["hash"])?)
        || rpc::call("get_tip_header", json!([]))?["hash"] != tip["hash"]
    {
        return Err("chain tip changed; discard snapshot and retry".into());
    }
    let control =
        Control::decode(&role_cell(&cells, config, Role::Control, 0)?.output.data).map_err(err)?;
    let vault =
        Vault::decode(&role_cell(&cells, config, Role::Vault, 0)?.output.data).map_err(err)?;
    Ok(Recovered {
        manifest,
        tip,
        cells,
        frames,
        allocation,
        control,
        vault,
        claims: trees,
        transitions,
        execution: engine.ok_or("trusted genesis not found")?,
    })
}
impl Recovered {
    pub fn cell(&self, role: Role, index: u64) -> Result<&build::Cell> {
        role_cell(&self.cells, &self.manifest.config, role, index)
    }
    /// Reconstruct only the authenticated settled prefix, never the ordered head.
    pub fn settled_execution(&self) -> Result<V02Executor> {
        if !self.control.initialized {
            return Err("no settled state available for asset claims".into());
        }
        let count = usize::try_from(self.control.boundary.batches).map_err(err)?;
        let frames = self.frames.get(..count).ok_or("settled publication gap")?;
        let genesis = Genesis::from_allocation(
            self.manifest.config.domain.into(),
            self.manifest.config.chain,
            &self.allocation,
        )
        .map_err(err)?;
        let mut engine = V02Executor::new(
            &genesis,
            self.manifest.config.clone(),
            self.manifest.policy.clone(),
        )
        .map_err(err)?;
        limits::state_usage(&engine)?;
        for frame in frames {
            engine
                .apply_batch(&frame.batch.encode().map_err(err)?, &frame.snapshot)
                .map_err(err)?;
            limits::state_usage(&engine)?;
        }
        let mut candidate = engine.control_candidate().map_err(err)?;
        candidate.mode = self.control.mode;
        if candidate != self.control {
            return Err("settled replay differs from live Control".into());
        }
        Ok(engine)
    }
    pub fn report(&self) -> Result<Value> {
        let state_usage = limits::state_usage(&self.execution)?;
        let role = |r| -> Result<Value> {
            let c = self.cell(r, 0)?;
            Ok(
                json!({"out_point":point_json(c.point),"capacity":c.output.capacity.to_string(),"data":rpc::bytes_to_hex(&c.output.data)}),
            )
        };
        Ok(
            json!({"schema":"tactus-v02-recovery-v1","pinned_height":number(&self.tip["number"] )?,"pinned_hash":self.tip["hash"],
            "config_hex":rpc::bytes_to_hex(&self.manifest.config.encode().map_err(err)?),"control":role(Role::Control)?,"vault":role(Role::Vault)?,"anchor":role(Role::Anchor)?,"schedule":role(Role::Schedule)?,
            "mode":if self.control.mode==Mode::Running{"RUNNING"}else{"FROZEN"},"published_batches":self.frames.len(),"settled_batches":self.control.boundary.batches,
            "deposited_count":self.vault.deposits.count,"credited_count":self.control.boundary.deposits.count,"pending_deposits":self.vault.deposits.count-self.control.boundary.deposits.count,
            "partitions_shannons":self.vault.partitions(&self.control).map_err(err)?.map(|v|v.to_string()),"transitions":self.transitions,
            "execution_candidate":{"state_root":rpc::bytes_to_hex(&self.execution.control_candidate().map_err(err)?.state_root),"burned_shannons":self.execution.control_candidate().map_err(err)?.burned.to_string(),"supply_shannons":self.execution.control_candidate().map_err(err)?.supply.to_string(),"authority":"execution replay, not custody authority"},
            "operations":self.operations()?,"lifecycle":self.lifecycle()?,"recovery_limits":limits::description(),
            "execution_state_usage":{"payload_bytes":state_usage.0,"entries":state_usage.1},
            "canonical_source":"selected CKB node; not an independent consensus client","protocol_transitions_rechecked":true,"evm_replay_match":true,"production_ready":false}),
        )
    }
    pub fn proving_input(&self, end: usize) -> Result<Value> {
        if self.control.mode != Mode::Running {
            return Err("frozen instance cannot accept new settlement".into());
        }
        let prefix = usize::try_from(self.control.boundary.batches).map_err(err)?;
        if end <= prefix || end > self.frames.len() {
            return Err("invalid proving interval".into());
        }
        let frames = self.frames[..end]
            .iter()
            .map(|f| f.encode().map_err(err))
            .collect::<Result<Vec<_>>>()?;
        let mut it = frames.iter();
        let j = journal::execute(
            self.manifest.config.clone(),
            self.manifest.policy.clone(),
            &self.allocation,
            prefix as u64,
            (end - prefix) as u64,
            || it.next().cloned().ok_or(journal::Error::MissingInput),
        )
        .map_err(err)?;
        if j.start != self.control {
            return Err("proof start differs from current Control".into());
        }
        Ok(
            json!({"schema":"tactus-v02-proof-input-v1","source":"pinned-canonical-ckb","authenticated_publication":true,"pinned_height":number(&self.tip["number"] )?,"pinned_hash":self.tip["hash"],
            "control_outpoint":point_json(self.cell(Role::Control,0)?.point),"config_hex":rpc::bytes_to_hex(&self.manifest.config.encode().map_err(err)?),"policy_hex":rpc::bytes_to_hex(&self.manifest.policy.encode().map_err(err)?),"allocation_hex":rpc::bytes_to_hex(&self.allocation),"prefix_batches":prefix,"frames":frames.iter().map(|f|rpc::bytes_to_hex(f)).collect::<Vec<_>>(),"expected_journal_hex":rpc::bytes_to_hex(&j.encode().map_err(err)?),"proof_generated":false}),
        )
    }
}
