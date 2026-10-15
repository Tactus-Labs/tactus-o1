//! Hand-rolled CKB molecule serialization for the transaction shapes the
//! driver needs. Layout rules (verified byte-for-byte against `ckb-cli
//! molecule encode` as ground truth):
//!
//! - fixed structs: raw little-endian concatenation, no header;
//! - fixed vectors (`FixVec`): `u32` count + raw items;
//! - dynamic vectors and tables (`DynVec`/`Table`): `u32` total size,
//!   `u32` header size (= 8 + 4·(n−1)), then `n − 1` offsets for items
//!   2..n — the first item starts at the header size with an implicit
//!   offset. An empty `DynVec` serializes as a single `u32` equal to 4.
//!   `None` table fields occupy zero bytes (adjacent offsets equal).

fn u32_le(v: u32) -> [u8; 4] {
    v.to_le_bytes()
}

fn u64_le(v: u64) -> [u8; 8] {
    v.to_le_bytes()
}

fn dyn_collection(items: &[Vec<u8>]) -> Vec<u8> {
    if items.is_empty() {
        return u32_le(4).to_vec();
    }
    let header_len = 8 + 4 * (items.len() - 1);
    let payload: usize = items.iter().map(|i| i.len()).sum();
    let total = header_len + payload;
    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(&u32_le(total as u32));
    out.extend_from_slice(&u32_le(header_len as u32));
    // Offsets for items 2..n; the first item implicitly starts at the header.
    let mut offset = header_len as u32;
    for (index, item) in items.iter().enumerate() {
        if index > 0 {
            out.extend_from_slice(&u32_le(offset));
        }
        offset += item.len() as u32;
    }
    for item in items {
        out.extend_from_slice(item);
    }
    out
}

/// Molecule `Table` over optional fields: `None` serializes as empty.
fn table(fields: &[Option<Vec<u8>>]) -> Vec<u8> {
    dyn_collection(
        &fields
            .iter()
            .map(|f| f.clone().unwrap_or_default())
            .collect::<Vec<_>>(),
    )
}

/// `Bytes`: u32 length + payload.
pub fn bytes(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + payload.len());
    out.extend_from_slice(&u32_le(payload.len() as u32));
    out.extend_from_slice(payload);
    out
}

/// `Script` table: code hash (32 raw), hash type (1 raw), args (`Bytes`).
#[must_use]
pub fn script(code_hash: &[u8; 32], hash_type: u8, args: &[u8]) -> Vec<u8> {
    let mut code = Vec::with_capacity(32);
    code.extend_from_slice(code_hash);
    table(&[Some(code), Some(vec![hash_type]), Some(bytes(args))])
}

/// `CellOutput` table: capacity (u64 raw), lock `Script`, optional type `Script`.
#[must_use]
pub fn cell_output(capacity: u64, lock: &[u8], type_script: Option<&[u8]>) -> Vec<u8> {
    table(&[
        Some(u64_le(capacity).to_vec()),
        Some(lock.to_vec()),
        type_script.map(|s| s.to_vec()),
    ])
}

/// `OutPoint` fixed struct: tx hash (32) + index (u32).
#[must_use]
pub fn out_point(tx_hash: &[u8; 32], index: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(36);
    out.extend_from_slice(tx_hash);
    out.extend_from_slice(&u32_le(index));
    out
}

/// `CellInput` fixed struct: since (u64) + out point (36).
#[must_use]
pub fn cell_input(since: u64, previous_output: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(44);
    out.extend_from_slice(&u64_le(since));
    out.extend_from_slice(previous_output);
    out
}

/// `CellDep` fixed struct: out point (36) + dep type (1).
#[must_use]
pub fn cell_dep(out_point: &[u8], dep_type: u8) -> Vec<u8> {
    let mut out = Vec::with_capacity(37);
    out.extend_from_slice(out_point);
    out.push(dep_type);
    out
}

/// `WitnessArgs` table: optional lock / input_type / output_type `Bytes`.
#[must_use]
pub fn witness_args(
    lock: Option<&[u8]>,
    input_type: Option<&[u8]>,
    output_type: Option<&[u8]>,
) -> Vec<u8> {
    table(&[
        lock.map(bytes),
        input_type.map(bytes),
        output_type.map(bytes),
    ])
}

/// Decodes a script serialized by [`script`] back into its RPC JSON form.
#[must_use]
pub fn script_to_json(script: &[u8]) -> serde_json::Value {
    try_script_to_json(script).expect("script was built by the canonical encoder")
}

/// Strict canonical decoding for external script bytes (CLI/RPC configuration).
/// Validate all lengths and offsets before slicing attacker-controlled data.
pub fn try_script_to_json(script: &[u8]) -> Result<serde_json::Value, String> {
    if script.len() < 53 {
        return Err("script shorter than canonical header".into());
    }
    let word = |offset| u32::from_le_bytes(script[offset..offset + 4].try_into().unwrap()) as usize;
    if word(0) != script.len()
        || word(4) != 16
        || word(8) != 48
        || word(12) != 49
        || word(49) != script.len() - 53
    {
        return Err("noncanonical script lengths or offsets".into());
    }
    let hash_type = match script[48] {
        0 => "data",
        1 => "type",
        2 => "data1",
        4 => "data2",
        _ => return Err("unsupported script hash type".into()),
    };
    Ok(
        serde_json::json!({"code_hash":crate::rpc::bytes_to_hex(&script[16..48]),"hash_type":hash_type,"args":crate::rpc::bytes_to_hex(&script[53..])}),
    )
}

fn fix_vec(item_size: usize, raw_items: &[u8]) -> Vec<u8> {
    debug_assert_eq!(raw_items.len() % item_size, 0);
    let mut out = Vec::with_capacity(4 + raw_items.len());
    out.extend_from_slice(&u32_le((raw_items.len() / item_size) as u32));
    out.extend_from_slice(raw_items);
    out
}

/// `RawTransaction` table, protocol version 0.
#[must_use]
pub fn raw_transaction(
    cell_deps: &[Vec<u8>],    // serialized CellDep (37 bytes each)
    inputs: &[Vec<u8>],       // serialized CellInput (44 bytes each)
    outputs: &[Vec<u8>],      // serialized CellOutput tables
    outputs_data: &[Vec<u8>], // serialized Bytes
) -> Vec<u8> {
    raw_transaction_with_headers(cell_deps, &[], inputs, outputs, outputs_data)
}

/// Serialize explicit header dependencies; the transaction signature covers them.
pub fn raw_transaction_with_headers(
    cell_deps: &[Vec<u8>],
    headers: &[[u8; 32]],
    inputs: &[Vec<u8>],
    outputs: &[Vec<u8>],
    outputs_data: &[Vec<u8>],
) -> Vec<u8> {
    let deps_raw: Vec<u8> = cell_deps.concat();
    let inputs_raw: Vec<u8> = inputs.concat();
    table(&[
        Some(u32_le(0).to_vec()),             // version
        Some(fix_vec(37, &deps_raw)),         // cell_deps
        Some(fix_vec(32, &headers.concat())), // header_deps
        Some(fix_vec(44, &inputs_raw)),       // inputs
        Some(dyn_collection(outputs)),        // outputs
        Some(dyn_collection(outputs_data)),   // outputs_data
    ])
}

/// `Transaction` table: raw + witnesses (`DynVec<Bytes>`).
#[must_use]
pub fn transaction(raw: &[u8], witnesses: &[Vec<u8>]) -> Vec<u8> {
    table(&[Some(raw.to_vec()), Some(dyn_collection(witnesses))])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn external_scripts_reject_every_truncation_and_noncanonical_offset() {
        let valid = script(&[7; 32], 2, &[9; 32]);
        assert!(try_script_to_json(&valid).is_ok());
        for end in 0..valid.len() {
            assert!(try_script_to_json(&valid[..end]).is_err());
        }
        for offset in [0, 4, 8, 12, 48, 49] {
            let mut bad = valid.clone();
            bad[offset] = 255;
            assert!(try_script_to_json(&bad).is_err());
        }
        let mut extra = valid;
        extra.push(0);
        assert!(try_script_to_json(&extra).is_err());
    }

    #[test]
    fn script_encoding_matches_ckb_cli_ground_truth() {
        // Produced by: ckb-cli molecule encode --type Script
        //   {"code_hash":"0x0000..00545950455f4944","hash_type":"type","args":"0x"}
        let type_id_ch: [u8; 32] = [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x54, 0x59,
            0x50, 0x45, 0x5f, 0x49, 0x44,
        ];
        let s = script(&type_id_ch, 1, &[]);
        assert_eq!(
            s,
            hex_decode(
                "0x3500000010000000300000003100000000000000000000000000000000000000000000000000000000545950455f49440100000000"
            )
        );
    }

    fn hex_decode(h: &str) -> Vec<u8> {
        let h = h.trim_start_matches("0x");
        (0..h.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&h[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn cell_input_layout_is_44_bytes() {
        let i = cell_input(0, &out_point(&[7u8; 32], 3));
        assert_eq!(i.len(), 44);
    }

    #[test]
    fn witness_args_encoding_matches_ckb_cli_ground_truth() {
        // Produced by: ckb-cli molecule encode --type WitnessArgs
        //   {"lock":null,"input_type":"0x0102..20","output_type":null}
        let input_type: [u8; 32] = core::array::from_fn(|i| (i + 1) as u8);
        let w = witness_args(None, Some(&input_type), None);
        assert_eq!(
            w,
            hex_decode(
                "0x34000000100000001000000034000000200000000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
            )
        );
    }

    #[test]
    fn empty_dynvec_serializes_its_total_size() {
        assert_eq!(dyn_collection(&[]), vec![4, 0, 0, 0]);
    }

    #[test]
    fn single_item_dynvec_has_no_offsets() {
        // Ground truth from RawTransaction outputs_data = ["0x0102"]:
        //   total 14, header 8, item Bytes [len=2][0102] directly.
        let d = dyn_collection(&[bytes(&[0x01, 0x02])]);
        assert_eq!(d, hex_decode("0x0e00000008000000020000000102"));
    }
}
