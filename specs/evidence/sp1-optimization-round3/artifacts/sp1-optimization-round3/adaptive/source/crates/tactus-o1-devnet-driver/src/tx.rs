//! Transaction construction and signing for the devnet replay.
//!
//! All amounts are shannons (1 CKB = 1e8). Transactions are protocol version
//! 0, signed with the dev key's SECP256K1 lock; the first input's witness
//! carries both the recoverable signature (lock group) and the OrderingHead
//! commitment (type group, `WitnessArgs::input_type`).

use secp256k1::{ecdsa::RecoverableSignature, Message, PublicKey, Secp256k1, SecretKey};
use serde_json::{json, Value};

use crate::molecule;
use crate::rpc;
use tactus_o1_ordering_script::{ckb_blake2b, ckb_blakeb160, OrderingHead};

/// SECP256K1/blake160 sighash-all script hash (hash type `type`).
pub const SECP_CODE_HASH: [u8; 32] = [
    0x9b, 0xd7, 0xe0, 0x6f, 0x3e, 0xcf, 0x4b, 0xe0, 0xf2, 0xfc, 0xd2, 0x18, 0x8b, 0x23, 0xf1, 0xb9,
    0xfc, 0xc8, 0x8e, 0x5d, 0x4b, 0x65, 0xa8, 0x63, 0x7b, 0x17, 0x72, 0x3b, 0xbd, 0xa3, 0xcc, 0xe8,
];

pub const SHANNONS_PER_CKB: u64 = 100_000_000;
/// One CKB fee per transaction — devnet tier.
pub const TX_FEE: u64 = SHANNONS_PER_CKB;

#[derive(Clone)]
pub struct DevKey {
    pub secret: SecretKey,
    pub public: PublicKey,
    pub args: [u8; 20],
}

impl DevKey {
    /// The fixed devnet-only key (0x21 × 32). Never use outside dev chains.
    #[must_use]
    pub fn dev() -> Self {
        Self::from_seed([0x21; 32])
    }

    /// Deterministic actor key for isolated devnet experiments.
    pub fn from_seed(seed: [u8; 32]) -> Self {
        let secp = Secp256k1::new();
        let secret = SecretKey::from_slice(&seed).expect("fixed dev key is valid");
        let public = PublicKey::from_secret_key(&secp, &secret);
        let args = ckb_blakeb160(&public.serialize());
        Self {
            secret,
            public,
            args,
        }
    }

    #[must_use]
    pub fn lock_script(&self) -> Vec<u8> {
        molecule::script(&SECP_CODE_HASH, 1, &self.args)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CellOutPoint {
    pub tx_hash: [u8; 32],
    pub index: u32,
}

/// Locates the SECP code cell in the genesis block: the cell whose **type
/// script hash** (ckbhash of the serialized type script, RFC 0022) equals
/// [`SECP_CODE_HASH`]. Verified against this devnet's genesis.
pub fn find_secp_dep(genesis: &Value) -> Result<CellOutPoint, String> {
    let transactions = genesis["transactions"]
        .as_array()
        .ok_or("genesis transactions missing")?;
    // Identify the code cell by its TYPE hash, then find a dep group that
    // actually contains that OutPoint. Size alone also matches unrelated groups.
    let mut secp_code = None;
    for transaction in transactions {
        for (index, output) in transaction["outputs"]
            .as_array()
            .ok_or("genesis outputs missing")?
            .iter()
            .enumerate()
        {
            let script = &output["type"];
            if script.is_null() {
                continue;
            }
            let hash: [u8; 32] =
                rpc::decode_hex(script["code_hash"].as_str().ok_or("code hash missing")?)?
                    .try_into()
                    .map_err(|_| "code hash length")?;
            let hash_type = match script["hash_type"].as_str() {
                Some("data") => 0,
                Some("type") => 1,
                Some("data1") => 2,
                Some("data2") => 4,
                _ => return Err("unknown script hash type".into()),
            };
            let args = rpc::decode_hex(script["args"].as_str().ok_or("script args missing")?)?;
            if ckb_blake2b(&molecule::script(&hash, hash_type, &args)) == SECP_CODE_HASH {
                let hash: [u8; 32] = rpc::decode_hex(
                    transaction["hash"]
                        .as_str()
                        .ok_or("transaction hash missing")?,
                )?
                .try_into()
                .map_err(|_| "transaction hash length")?;
                secp_code = Some(molecule::out_point(&hash, index as u32));
            }
        }
    }
    let secp_code = secp_code.ok_or("SECP code type hash not found")?;
    for transaction in transactions {
        for (index, data) in transaction["outputs_data"]
            .as_array()
            .ok_or("outputs data missing")?
            .iter()
            .enumerate()
        {
            if !transaction["outputs"][index]["type"].is_null() {
                continue;
            }
            let bytes = rpc::decode_hex(data.as_str().ok_or("data string missing")?)?;
            if bytes.len() < 4 {
                continue;
            }
            let count = u32::from_le_bytes(bytes[..4].try_into().unwrap()) as usize;
            if count.checked_mul(36).and_then(|n| n.checked_add(4)) != Some(bytes.len()) {
                continue;
            }
            if bytes[4..].chunks_exact(36).any(|p| p == secp_code) {
                return Ok(CellOutPoint {
                    tx_hash: rpc::decode_hex(
                        transaction["hash"]
                            .as_str()
                            .ok_or("transaction hash missing")?,
                    )?
                    .try_into()
                    .map_err(|_| "transaction hash length")?,
                    index: index as u32,
                });
            }
        }
    }
    Err("SECP dep group not found".into())
}

/// Collects **live** cells paying to the dev lock via the node indexer
/// (requires `ckb run --indexer`). Replaces block scanning: only live cells
/// are returned, so partially-spent replays are safe to re-run.
pub fn collect_live_cells(args: &[u8; 20]) -> Result<Vec<(CellOutPoint, u64)>, String> {
    let lock = serde_json::json!({
        "script": {
            "code_hash": rpc::bytes_to_hex(&SECP_CODE_HASH),
            "hash_type": "type",
            "args": rpc::bytes_to_hex(args),
        },
        "script_type": "lock",
    });
    let mut cells = Vec::new();
    let mut cursor = String::new();
    loop {
        let mut params = serde_json::json!([lock.clone(), "asc", "0x64"]);
        if !cursor.is_empty() {
            params
                .as_array_mut()
                .unwrap()
                .push(serde_json::json!(cursor));
        }
        let v = crate::rpc::call("get_cells", params)?;
        for obj in v["objects"].as_array().cloned().unwrap_or_default() {
            if !obj["output"]["type"].is_null() || obj["output_data"] != "0x" {
                continue;
            }
            let out_point = &obj["out_point"];
            let tx_hash = rpc::hex_to_bytes(out_point["tx_hash"].as_str().unwrap_or_default());
            if tx_hash.len() != 32 {
                continue;
            }
            let mut h = [0u8; 32];
            h.copy_from_slice(&tx_hash);
            let index = u32::from_str_radix(
                out_point["index"]
                    .as_str()
                    .unwrap_or("0x0")
                    .trim_start_matches("0x"),
                16,
            )
            .unwrap_or(0);
            let capacity = u64::from_str_radix(
                obj["output"]["capacity"]
                    .as_str()
                    .unwrap_or("0x0")
                    .trim_start_matches("0x"),
                16,
            )
            .unwrap_or(0);
            cells.push((CellOutPoint { tx_hash: h, index }, capacity));
        }
        let last = v["last_cursor"].as_str().unwrap_or_default().to_string();
        if last.is_empty() || v["objects"].as_array().is_none_or(|o| o.is_empty()) {
            break;
        }
        if last == cursor {
            break;
        }
        cursor = last;
    }
    Ok(cells)
}

/// Collects mature cellbase outputs paying to `args` (devnet maturity is 0).
pub fn collect_coinbase(
    tip: u64,
    args: &[u8; 20],
    max_blocks: u64,
) -> Result<Vec<(CellOutPoint, u64)>, String> {
    let args_hex = rpc::bytes_to_hex(args);
    let mut cells = Vec::new();
    let start = tip.saturating_sub(max_blocks) + 1;
    for block_number in start..=tip {
        let block = rpc::get_block_detailed(block_number)?;
        let Some(cellbase) = block.get("transactions").and_then(|t| t.get(0)).cloned() else {
            continue;
        };
        let tx_hash_hex = cellbase
            .get("hash")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let outputs = cellbase
            .get("outputs")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        for (index, out) in outputs.iter().enumerate() {
            let lock_args = out
                .get("lock")
                .and_then(|l| l.get("args"))
                .and_then(Value::as_str)
                .unwrap_or_default();
            if lock_args.eq_ignore_ascii_case(&args_hex) {
                let capacity = u64::from_str_radix(
                    out.get("capacity")
                        .and_then(Value::as_str)
                        .unwrap_or("0x0")
                        .trim_start_matches("0x"),
                    16,
                )
                .unwrap_or(0);
                let tx_hash = rpc::hex_to_bytes(tx_hash_hex);
                let mut h = [0u8; 32];
                h.copy_from_slice(&tx_hash);
                cells.push((
                    CellOutPoint {
                        tx_hash: h,
                        index: index as u32,
                    },
                    capacity,
                ));
            }
        }
    }
    Ok(cells)
}

/// An output being built.
#[derive(Clone)]
pub struct OutSpec {
    pub capacity: u64,
    pub lock: Vec<u8>,
    pub type_script: Option<Vec<u8>>,
    pub data: Vec<u8>,
}

impl OutSpec {
    /// Minimum capacity covering the occupied storage (bytes × 1 CKB).
    #[must_use]
    pub fn required_capacity(lock: &[u8], type_script: Option<&[u8]>, data_len: usize) -> u64 {
        // Occupied capacity counts field bytes, excluding Molecule headers:
        // capacity(8), each Script(code_hash 32 + hash_type 1 + args), data.
        let occupied =
            8 + lock.len() - 20 + type_script.map_or(0, |script| script.len() - 20) + data_len;
        occupied as u64 * SHANNONS_PER_CKB
    }
}

/// Builds, signs and serializes one transaction. The first input's witness
/// carries `WitnessArgs { lock: signature, input_type }`; remaining inputs
/// get empty witnesses.
pub fn build_and_sign(
    key: &DevKey,
    secp_dep: &CellOutPoint,
    extra_deps: &[CellOutPoint],
    inputs: &[(CellOutPoint, u64)],
    outputs: &[OutSpec],
    input_type: Option<&[u8]>,
) -> Result<(Vec<u8>, Value), String> {
    build_with_permissionless_prefix(key, secp_dep, extra_deps, inputs, outputs, input_type, 0)
}

/// The prefix inputs use type-bound permissionless locks; the remaining inputs
/// form one SECP group belonging to `key`. Fees come from that group's change.
#[allow(clippy::too_many_arguments)]
pub fn build_with_permissionless_prefix(
    key: &DevKey,
    secp_dep: &CellOutPoint,
    extra_deps: &[CellOutPoint],
    inputs: &[(CellOutPoint, u64)],
    outputs: &[OutSpec],
    input_type: Option<&[u8]>,
    unsigned_prefix: usize,
) -> Result<(Vec<u8>, Value), String> {
    build_with_permissionless_prefix_and_since(
        key,
        secp_dep,
        extra_deps,
        inputs,
        outputs,
        input_type,
        unsigned_prefix,
        &vec![0; inputs.len()],
    )
}

/// Like the standard builder, but signs explicit consensus `since` values for
/// every input. The RPC and Molecule representations use exactly the same values.
#[allow(clippy::too_many_arguments)]
pub fn build_with_permissionless_prefix_and_since(
    key: &DevKey,
    secp_dep: &CellOutPoint,
    extra_deps: &[CellOutPoint],
    inputs: &[(CellOutPoint, u64)],
    outputs: &[OutSpec],
    input_type: Option<&[u8]>,
    unsigned_prefix: usize,
    since: &[u64],
) -> Result<(Vec<u8>, Value), String> {
    build_signed(
        key,
        secp_dep,
        extra_deps,
        inputs,
        outputs,
        (input_type, None),
        unsigned_prefix,
        since,
        &[],
    )
}

/// Sign a standard funding group with an output-type creation witness.
pub fn build_with_output_type(
    key: &DevKey,
    secp_dep: &CellOutPoint,
    extra_deps: &[CellOutPoint],
    inputs: &[(CellOutPoint, u64)],
    outputs: &[OutSpec],
    output_type: &[u8],
) -> Result<(Vec<u8>, Value), String> {
    build_signed(
        key,
        secp_dep,
        extra_deps,
        inputs,
        outputs,
        (None, Some(output_type)),
        0,
        &vec![0; inputs.len()],
        &[],
    )
}

/// Sign explicit header dependencies together with the ordinary transaction.
#[allow(clippy::too_many_arguments)]
pub fn build_with_headers(
    key: &DevKey,
    secp_dep: &CellOutPoint,
    extra_deps: &[CellOutPoint],
    inputs: &[(CellOutPoint, u64)],
    outputs: &[OutSpec],
    input_type: Option<&[u8]>,
    unsigned_prefix: usize,
    headers: &[[u8; 32]],
) -> Result<(Vec<u8>, Value), String> {
    build_signed(
        key,
        secp_dep,
        extra_deps,
        inputs,
        outputs,
        (input_type, None),
        unsigned_prefix,
        &vec![0; inputs.len()],
        headers,
    )
}

#[allow(clippy::too_many_arguments)]
fn build_signed(
    key: &DevKey,
    secp_dep: &CellOutPoint,
    extra_deps: &[CellOutPoint],
    inputs: &[(CellOutPoint, u64)],
    outputs: &[OutSpec],
    witness_types: (Option<&[u8]>, Option<&[u8]>),
    unsigned_prefix: usize,
    since: &[u64],
    headers: &[[u8; 32]],
) -> Result<(Vec<u8>, Value), String> {
    let (input_type, output_type) = witness_types;
    if since.len() != inputs.len() {
        return Err("since count must equal input count".into());
    }
    if inputs.is_empty() || unsigned_prefix >= inputs.len() {
        return Err("at least one signed funding input required".into());
    }
    let total_in = inputs
        .iter()
        .try_fold(0u64, |v, (_, c)| v.checked_add(*c))
        .ok_or("input capacity overflow")?;
    let total_out = outputs
        .iter()
        .try_fold(0u64, |v, o| v.checked_add(o.capacity))
        .ok_or("output capacity overflow")?;
    if total_out >= total_in {
        return Err("outputs must leave a positive transaction fee".into());
    }
    let mut deps = vec![molecule::cell_dep(
        &molecule::out_point(&secp_dep.tx_hash, secp_dep.index),
        1,
    )];
    for d in extra_deps {
        deps.push(molecule::cell_dep(
            &molecule::out_point(&d.tx_hash, d.index),
            0,
        ));
    }
    let input_cells: Vec<Vec<u8>> = inputs
        .iter()
        .zip(since)
        .map(|((o, _), value)| {
            molecule::cell_input(*value, &molecule::out_point(&o.tx_hash, o.index))
        })
        .collect();
    let out_cells: Vec<Vec<u8>> = outputs
        .iter()
        .map(|o| molecule::cell_output(o.capacity, &o.lock, o.type_script.as_deref()))
        .collect();
    let out_data: Vec<Vec<u8>> = outputs.iter().map(|o| molecule::bytes(&o.data)).collect();

    let raw =
        molecule::raw_transaction_with_headers(&deps, headers, &input_cells, &out_cells, &out_data);
    let tx_hash = ckb_blake2b(&raw);

    // SECP256K1/blake160 sighash-all message (per the system script source):
    // ckbhash( tx_hash ‖ u64le(len)‖blank_witness0 ‖ Σ u64le(len)‖w_i ),
    // where blank_witness0 keeps input_type/output_type but zeroes the
    // 65-byte lock; remaining same-group witnesses hash as submitted.
    let mut witnesses = vec![Vec::new(); inputs.len()];
    if input_type.is_some() || output_type.is_some() {
        witnesses[0] = molecule::witness_args(None, input_type, output_type);
    }
    witnesses[unsigned_prefix] = molecule::witness_args(
        Some(&[0u8; 65]),
        if unsigned_prefix == 0 {
            input_type
        } else {
            None
        },
        if unsigned_prefix == 0 {
            output_type
        } else {
            None
        },
    );
    let mut message_buf = tx_hash.to_vec();
    for witness in &witnesses[unsigned_prefix..] {
        message_buf.extend_from_slice(&(witness.len() as u64).to_le_bytes());
        message_buf.extend_from_slice(witness);
    }
    let message_hash = ckb_blake2b(&message_buf);

    let secp = Secp256k1::new();
    let message = Message::from_digest_slice(&message_hash).map_err(|e| e.to_string())?;
    let sig: RecoverableSignature = secp.sign_ecdsa_recoverable(&message, &key.secret);
    let (rec_id, data) = sig.serialize_compact();
    let mut signature = Vec::with_capacity(65);
    signature.extend_from_slice(&data);
    signature.push(rec_id.to_i32() as u8);

    witnesses[unsigned_prefix] = molecule::witness_args(
        Some(&signature),
        if unsigned_prefix == 0 {
            input_type
        } else {
            None
        },
        if unsigned_prefix == 0 {
            output_type
        } else {
            None
        },
    );

    let bytes = molecule::transaction(&raw, &witnesses);
    let mut json = transaction_to_json(outputs, inputs, secp_dep, extra_deps, &witnesses, since);
    json["header_deps"] = json!(headers
        .iter()
        .map(|h| rpc::bytes_to_hex(h))
        .collect::<Vec<_>>());
    Ok((bytes, json))
}

/// JSON form for RPC submission (ckb 0.210 requires the object form). The
/// binary form remains authoritative for the tx hash and signature.
fn transaction_to_json(
    outputs: &[OutSpec],
    inputs: &[(CellOutPoint, u64)],
    secp_dep: &CellOutPoint,
    extra_deps: &[CellOutPoint],
    witnesses: &[Vec<u8>],
    since: &[u64],
) -> Value {
    let out_json: Vec<Value> = outputs
        .iter()
        .map(|o| {
            let mut v = json!({
                "capacity": format!("0x{:x}", o.capacity),
                "lock": molecule::script_to_json(&o.lock),
            });
            if let Some(t) = &o.type_script {
                v["type"] = molecule::script_to_json(t);
            }
            v
        })
        .collect();
    let mut cell_deps = vec![serde_json::json!({
        "out_point": {
            "tx_hash": rpc::bytes_to_hex(&secp_dep.tx_hash),
            "index": format!("0x{:x}", secp_dep.index),
        },
        "dep_type": "dep_group",
    })];
    for d in extra_deps {
        cell_deps.push(serde_json::json!({
            "out_point": {
                "tx_hash": rpc::bytes_to_hex(&d.tx_hash),
                "index": format!("0x{:x}", d.index),
            },
            "dep_type": "code",
        }));
    }
    json!({
        "version": "0x0",
        "cell_deps": cell_deps,
        "header_deps": [],
        "inputs": inputs.iter().zip(since).map(|((o, _), value)| json!({
            "previous_output": {
                "tx_hash": rpc::bytes_to_hex(&o.tx_hash),
                "index": format!("0x{:x}", o.index),
            },
            "since": format!("0x{value:x}"),
        })).collect::<Vec<_>>(),
        "outputs": out_json,
        "outputs_data": outputs.iter()
            .map(|o| rpc::bytes_to_hex(&o.data))
            .collect::<Vec<_>>(),
        "witnesses": witnesses.iter()
            .map(|w| rpc::bytes_to_hex(w))
            .collect::<Vec<_>>(),
    })
}

/// Allocation-bound anchor identity. A1's older type helper remains separate.
pub fn anchor_type_script(
    elf: &[u8],
    rollup_id: &[u8; 32],
    allocation: &[u8],
) -> Result<Vec<u8>, String> {
    let hash = tactus_o1_protocol::genesis::commitment(allocation)
        .map_err(|e| format!("genesis allocation: {e:?}"))?;
    let mut args = rollup_id.to_vec();
    args.extend_from_slice(&hash);
    Ok(molecule::script(&ckb_blake2b(elf), 2, &args))
}

/// A1 type script referencing the deployed ELF by data hash.
#[must_use]
pub fn tactus_o1_type_script(elf: &[u8], rollup_id: &[u8; 32]) -> Vec<u8> {
    molecule::script(&ckb_blake2b(elf), 2, rollup_id)
}

/// Builds the successor head cell spec (same lock and type, new state).
#[must_use]
pub fn head_output(
    key: &DevKey,
    type_script: &[u8],
    next: &OrderingHead,
    capacity: u64,
) -> OutSpec {
    OutSpec {
        capacity,
        lock: key.lock_script(),
        type_script: Some(type_script.to_vec()),
        data: next.to_bytes().to_vec(),
    }
}

/// Sends a transaction (JSON form) and waits until it is committed.
pub fn send_and_wait(tx: &Value, timeout_secs: u64) -> Result<(String, Option<u64>), String> {
    rpc::require_devnet()?;
    let tx_hash = rpc::send_transaction_json(tx)?;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(timeout_secs);
    loop {
        let (status, block_number) = rpc::get_transaction_status(&tx_hash)?;
        if status == "rejected" {
            return Err(format!("transaction rejected: {tx_hash}"));
        }
        if status == "committed" {
            return Ok((tx_hash, block_number));
        }
        if std::time::Instant::now() > deadline {
            return Err(format!("timeout in status {status}: {tx_hash}"));
        }
        if std::env::var("TACTUS_DEVNET_AUTOMINE").as_deref() == Ok("1") {
            rpc::mine_blocks(1)?;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}

fn hex_len(v: &Value) -> Result<usize, String> {
    rpc::decode_hex(v.as_str().ok_or("hex string")?).map(|b| b.len())
}
// Molecule table/fixvec/dynvec framing, including witnesses. This is wire
// size, not JSON length and not CKB's cycle-weighted virtual transaction size.
pub fn wire_bytes(t: &Value) -> Result<usize, String> {
    let arr = |key: &str| t[key].as_array().ok_or_else(|| format!("missing {key}"));
    let mut size = 12
        + 28
        + 4
        + 4
        + 37 * arr("cell_deps")?.len()
        + 4
        + 32 * arr("header_deps")?.len()
        + 4
        + 44 * arr("inputs")?.len();
    let outputs = arr("outputs")?;
    size += 4 + 4 * outputs.len();
    for o in outputs {
        size += 16 + 8 + 53 + hex_len(&o["lock"]["args"])?;
        if !o["type"].is_null() {
            size += 53 + hex_len(&o["type"]["args"])?;
        }
    }
    for key in ["outputs_data", "witnesses"] {
        let items = arr(key)?;
        size += 4 + 4 * items.len();
        for item in items {
            size += 4 + hex_len(item)?;
        }
    }
    Ok(size)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn occupied_capacity_uses_fields_not_molecule_overhead() {
        assert_eq!(
            OutSpec::required_capacity(&DevKey::dev().lock_script(), None, 0),
            61 * SHANNONS_PER_CKB
        );
        let typ = molecule::script(&[42; 32], 2, &[5; 32]);
        assert_eq!(
            OutSpec::required_capacity(&DevKey::dev().lock_script(), Some(&typ), 188),
            (61 + 65 + 188) * SHANNONS_PER_CKB
        );
    }
}
