use crate::{bytes, err, hash32, number, point_bytes, point_json, script, Result};
use ckb_std::ckb_types::prelude::*;
use secp256k1::{Message, Secp256k1};
use serde_json::{json, Value};
use tactus_o1_devnet_driver::{
    lab::Lab,
    molecule, rpc,
    tx::{CellOutPoint, OutSpec, TX_FEE},
};
use tactus_o1_protocol::v02::*;
use tactus_v02_script::adapter;
#[derive(Clone)]
pub struct Cell {
    pub point: CellOutPoint,
    pub output: OutSpec,
}
pub fn typed(
    config: &Config,
    role: Role,
    index: u64,
    data: Vec<u8>,
    capacity: Option<u64>,
) -> Result<OutSpec> {
    let ty = adapter::type_script(config, role, index).map_err(err)?;
    let lock = adapter::protocol_lock(config, &ty).as_slice().to_vec();
    let ty = ty.as_slice().to_vec();
    let occupied = OutSpec::required_capacity(&lock, Some(&ty), data.len());
    let capacity = capacity.unwrap_or_else(|| {
        occupied
            + if role == Role::Lane {
                (Lane::MAX_BYTES - data.len()) as u64 * 100_000_000
            } else {
                0
            }
    });
    Ok(OutSpec {
        capacity,
        lock,
        type_script: Some(ty),
        data,
    })
}
pub fn operation(op: Operation, payload: &[u8]) -> Vec<u8> {
    let mut b = b"T02OP001".to_vec();
    b.push(op as u8);
    b.extend_from_slice(payload);
    b
}
pub fn direct_secp(lab: &Lab) -> Result<Vec<CellOutPoint>> {
    let tx = rpc::call(
        "get_transaction",
        json!([rpc::bytes_to_hex(&lab.secp.tx_hash)]),
    )?;
    let data = bytes(
        &tx["transaction"]["outputs_data"][lab.secp.index as usize],
        4096,
    )?;
    if data.len() < 4 {
        return Err("short dep group".into());
    }
    let n = u32::from_le_bytes(data[..4].try_into().map_err(err)?) as usize;
    if n == 0 || n > 8 || data.len() != 4 + 36 * n {
        return Err("invalid standard lock dep group".into());
    }
    data[4..]
        .chunks_exact(36)
        .map(|p| {
            Ok(CellOutPoint {
                tx_hash: p[..32].try_into().map_err(err)?,
                index: u32::from_le_bytes(p[32..].try_into().map_err(err)?),
            })
        })
        .collect()
}
/// Exactly one funding group follows permissionless protocol inputs. All deps
/// are explicit code/data outpoints, matching the adapter's source resolution.
#[allow(clippy::too_many_arguments)]
pub fn transaction(
    lab: &Lab,
    actor: usize,
    inputs: &[(Cell, u64)],
    outputs: Vec<OutSpec>,
    deps: &[CellOutPoint],
    headers: &[[u8; 32]],
    op: Operation,
    payload: &[u8],
) -> Result<Value> {
    transaction_with_fee(
        lab, actor, inputs, outputs, deps, headers, op, payload, TX_FEE,
    )
}
/// Explicit external fee for isolated contention/fee-policy measurements.
#[allow(clippy::too_many_arguments)]
pub fn transaction_with_fee(
    lab: &Lab,
    actor: usize,
    inputs: &[(Cell, u64)],
    mut outputs: Vec<OutSpec>,
    deps: &[CellOutPoint],
    headers: &[[u8; 32]],
    op: Operation,
    payload: &[u8],
    fee: u64,
) -> Result<Value> {
    if fee == 0 {
        return Err("explicit fee must be positive".into());
    }
    let wallet = &lab.wallets[actor];
    let fee_index = inputs.len();
    let mut points: Vec<_> = inputs
        .iter()
        .map(|(c, s)| (c.point, c.output.capacity, *s))
        .collect();
    points.push((wallet.point, wallet.capacity, 0));
    let total = points
        .iter()
        .try_fold(0u64, |a, (_, c, _)| a.checked_add(*c))
        .ok_or("input overflow")?;
    let used = outputs
        .iter()
        .try_fold(fee, |a, o| a.checked_add(o.capacity))
        .ok_or("output overflow")?;
    let change = total
        .checked_sub(used)
        .ok_or("insufficient external fee/capacity funding")?;
    if change < OutSpec::required_capacity(&wallet.key.lock_script(), None, 0) {
        return Err("insufficient change cell capacity".into());
    }
    outputs.push(OutSpec {
        capacity: change,
        lock: wallet.key.lock_script(),
        type_script: None,
        data: vec![],
    });
    let mut all = direct_secp(lab)?;
    all.extend(lab.deps.iter().copied());
    all.extend_from_slice(deps);
    let mut unique = std::collections::BTreeSet::new();
    all.retain(|p| unique.insert(point_bytes(*p)));
    let raw_deps: Vec<_> = all
        .iter()
        .map(|p| molecule::cell_dep(&point_bytes(*p), 0))
        .collect();
    let raw_inputs: Vec<_> = points
        .iter()
        .map(|(p, _, s)| molecule::cell_input(*s, &point_bytes(*p)))
        .collect();
    let raw_outputs: Vec<_> = outputs
        .iter()
        .map(|o| molecule::cell_output(o.capacity, &o.lock, o.type_script.as_deref()))
        .collect();
    let data: Vec<_> = outputs.iter().map(|o| molecule::bytes(&o.data)).collect();
    let raw = molecule::raw_transaction_with_headers(
        &raw_deps,
        headers,
        &raw_inputs,
        &raw_outputs,
        &data,
    );
    let tx_hash = hash(b"", &raw);
    let op = operation(op, payload);
    let mut witnesses = vec![vec![]; points.len()];
    witnesses[0] = molecule::witness_args(None, None, Some(&op));
    witnesses[fee_index] = molecule::witness_args(
        Some(&[0; 65]),
        None,
        if fee_index == 0 { Some(&op) } else { None },
    );
    let mut message = tx_hash.to_vec();
    for w in &witnesses[fee_index..] {
        message.extend_from_slice(&(w.len() as u64).to_le_bytes());
        message.extend_from_slice(w);
    }
    let (recovery, signature) = Secp256k1::new()
        .sign_ecdsa_recoverable(
            &Message::from_digest_slice(&hash(b"", &message)).map_err(err)?,
            &wallet.key.secret,
        )
        .serialize_compact();
    let mut sig = signature.to_vec();
    sig.push(recovery.to_i32() as u8);
    witnesses[fee_index] = molecule::witness_args(
        Some(&sig),
        None,
        if fee_index == 0 { Some(&op) } else { None },
    );
    Ok(
        json!({"version":"0x0","cell_deps":all.into_iter().map(|p|json!({"out_point":point_json(p),"dep_type":"code"})).collect::<Vec<_>>(),
        "header_deps":headers.iter().map(|h|rpc::bytes_to_hex(h)).collect::<Vec<_>>(),
        "inputs":points.iter().map(|(p,_,s)|json!({"previous_output":point_json(*p),"since":format!("0x{s:x}")})).collect::<Vec<_>>(),
        "outputs":outputs.iter().map(|o|json!({"capacity":format!("0x{:x}",o.capacity),"lock":molecule::script_to_json(&o.lock),"type":o.type_script.as_ref().map(|t|molecule::script_to_json(t))})).collect::<Vec<_>>(),
        "outputs_data":outputs.iter().map(|o|rpc::bytes_to_hex(&o.data)).collect::<Vec<_>>(),"witnesses":witnesses.iter().map(|w|rpc::bytes_to_hex(w)).collect::<Vec<_>>() }),
    )
}
pub fn outputs(tx: &Value, hash: [u8; 32]) -> Result<Vec<Cell>> {
    tx["outputs"]
        .as_array()
        .ok_or("outputs")?
        .iter()
        .enumerate()
        .map(|(i, o)| {
            Ok(Cell {
                point: CellOutPoint {
                    tx_hash: hash,
                    index: u32::try_from(i).map_err(err)?,
                },
                output: OutSpec {
                    capacity: number(&o["capacity"])?,
                    lock: script(&o["lock"])?,
                    type_script: if o["type"].is_null() {
                        None
                    } else {
                        Some(script(&o["type"])?)
                    },
                    data: bytes(&tx["outputs_data"][i], 1024 * 1024)?,
                },
            })
        })
        .collect()
}
pub fn commit(lab: &mut Lab, actor: usize, label: &str, tx: &Value) -> Result<Vec<Cell>> {
    let h = lab.commit(label, tx)?;
    let cells = outputs(tx, hash32(&json!(h))?)?;
    let change = cells.last().ok_or("change")?;
    lab.wallets[actor].point = change.point;
    lab.wallets[actor].capacity = change.output.capacity;
    Ok(cells)
}
