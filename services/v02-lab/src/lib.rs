//! Separate 0.02 devnet and recovery tools. Recovery trusts the selected CKB
//! node's consensus, then rechecks protocol transitions and replays EVM inputs.
pub mod build;
pub mod claim_export;
pub mod lifecycle;
pub mod limits;
pub mod nullifiers;
pub mod observer;
pub mod operations;
pub mod recover;
pub mod state_proof;
use serde_json::Value;
use tactus_o1_devnet_driver::{molecule, rpc, tx::CellOutPoint};
pub type Result<T> = std::result::Result<T, String>;
pub fn err(value: impl std::fmt::Debug) -> String {
    format!("{value:?}")
}
pub fn number(v: &Value) -> Result<u64> {
    u64::from_str_radix(
        v.as_str()
            .and_then(|s| s.strip_prefix("0x"))
            .ok_or("expected hex number")?,
        16,
    )
    .map_err(err)
}
pub fn bytes(v: &Value, max: usize) -> Result<Vec<u8>> {
    let s = v
        .as_str()
        .filter(|s| s.starts_with("0x") && s.len() <= 2 + 2 * max)
        .ok_or("hex bound/prefix")?;
    rpc::decode_hex(s)
}
pub fn hash32(v: &Value) -> Result<[u8; 32]> {
    bytes(v, 32)?.try_into().map_err(|_| "hash size".into())
}
pub fn point(v: &Value) -> Result<CellOutPoint> {
    Ok(CellOutPoint {
        tx_hash: hash32(&v["tx_hash"])?,
        index: u32::try_from(number(&v["index"])?).map_err(err)?,
    })
}
pub fn point_bytes(p: CellOutPoint) -> [u8; 36] {
    molecule::out_point(&p.tx_hash, p.index)
        .try_into()
        .expect("fixed outpoint")
}
pub fn point_json(p: CellOutPoint) -> Value {
    serde_json::json!({"tx_hash":rpc::bytes_to_hex(&p.tx_hash),"index":format!("0x{:x}",p.index)})
}
pub fn script(v: &Value) -> Result<Vec<u8>> {
    let tag = match v["hash_type"].as_str() {
        Some("data") => 0,
        Some("type") => 1,
        Some("data1") => 2,
        Some("data2") => 4,
        _ => return Err("script hash type".into()),
    };
    Ok(molecule::script(
        &hash32(&v["code_hash"])?,
        tag,
        &bytes(&v["args"], 1024 * 1024)?,
    ))
}
