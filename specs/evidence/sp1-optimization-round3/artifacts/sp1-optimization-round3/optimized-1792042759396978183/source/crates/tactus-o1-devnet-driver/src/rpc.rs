//! Minimal JSON-RPC 2.0 client over plain HTTP for a local CKB devnet node
//! (`http://127.0.0.1:8114`). serde_json is used untyped: the driver reads a
//! handful of well-known fields and hashes everything itself.

use std::io::{Read, Write};
use std::net::TcpStream;

use serde_json::{json, Value};

pub const CKB_RPC_URL: &str = "127.0.0.1:8114";

/// One JSON-RPC call. Returns the `result` field or the error text.
pub fn call(method: &str, params: Value) -> Result<Value, String> {
    let address = std::env::var("TACTUS_CKB_RPC_ADDR").unwrap_or_else(|_| CKB_RPC_URL.into());
    call_at(&address, method, params)
}

/// Explicit endpoint for isolated multi-node experiments; never mutates the
/// process-wide default RPC address while observers or other threads run.
pub fn call_at(address: &str, method: &str, params: Value) -> Result<Value, String> {
    let body = json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params});
    let body = serde_json::to_string(&body).map_err(|e| e.to_string())?;
    let request = format!(
        "POST / HTTP/1.1\r\nHost: {address}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let mut stream = TcpStream::connect_timeout(
        &address.parse().map_err(|e| format!("RPC address: {e}"))?,
        std::time::Duration::from_secs(5),
    )
    .map_err(|e| format!("connect: {e}"))?;
    // Real Groth16 verification can exceed the ordinary query budget. Keep
    // script execution bounded while leaving read-only queries fail-fast.
    let read_seconds = if matches!(method, "estimate_cycles" | "send_transaction") {
        120
    } else {
        15
    };
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(read_seconds)))
        .map_err(|e| e.to_string())?;
    stream
        .set_write_timeout(Some(std::time::Duration::from_secs(15)))
        .map_err(|e| e.to_string())?;
    stream
        .write_all(request.as_bytes())
        .map_err(|e| format!("write: {e}"))?;
    let mut response = String::new();
    stream
        .take(32 * 1024 * 1024)
        .read_to_string(&mut response)
        .map_err(|e| format!("read: {e}"))?;
    let body_start = response.find("\r\n\r\n").ok_or("malformed http response")? + 4;
    if !response.starts_with("HTTP/1.1 200 ") && !response.starts_with("HTTP/1.0 200 ") {
        return Err(format!(
            "http status: {}",
            response.lines().next().unwrap_or("missing")
        ));
    }
    let parsed: Value =
        serde_json::from_str(&response[body_start..]).map_err(|e| format!("json: {e}"))?;
    if let Some(err) = parsed.get("error").filter(|err| !err.is_null()) {
        return Err(format!("rpc error: {err}"));
    }
    parsed
        .get("result")
        .cloned()
        .ok_or_else(|| "no result".to_string())
}

pub fn get_tip_block_number() -> Result<u64, String> {
    let v = call("get_tip_block_number", json!([]))?;
    let h = v.as_str().ok_or("tip not a string")?;
    u64::from_str_radix(h.trim_start_matches("0x"), 16).map_err(|e| e.to_string())
}

/// Detailed block (verbosity 2) — transactions carry outputs and data.
pub fn get_block_detailed(number: u64) -> Result<Value, String> {
    call(
        "get_block_by_number",
        json!([format!("0x{number:x}"), "0x2"]),
    )
}

pub fn send_transaction_json(tx: &Value) -> Result<String, String> {
    call("send_transaction", json!([tx, "passthrough"])).and_then(|v| {
        v.as_str()
            .map(str::to_owned)
            .ok_or_else(|| "transaction hash missing".into())
    })
}

/// `(committed, block_number)` from `get_transaction`.
pub fn get_transaction_status(tx_hash: &str) -> Result<(String, Option<u64>), String> {
    let v = call("get_transaction", json!([tx_hash]))?;
    let status = v
        .get("tx_status")
        .and_then(|s| s.get("status"))
        .and_then(Value::as_str)
        .unwrap_or("unknown")
        .to_string();
    let bn = v
        .get("tx_status")
        .and_then(|s| s.get("block_number"))
        .and_then(Value::as_str)
        .and_then(|h| u64::from_str_radix(h.trim_start_matches("0x"), 16).ok());
    Ok((status, bn))
}

/// Strict hexadecimal decoding; malformed RPC data is never silently truncated.
pub fn decode_hex(h: &str) -> Result<Vec<u8>, String> {
    let h = h.strip_prefix("0x").unwrap_or(h);
    if !h.len().is_multiple_of(2) || !h.is_ascii() {
        return Err("invalid hexadecimal length or character".into());
    }
    h.as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let text = std::str::from_utf8(pair).map_err(|e| e.to_string())?;
            u8::from_str_radix(text, 16).map_err(|e| e.to_string())
        })
        .collect()
}

pub fn hex_to_bytes(h: &str) -> Vec<u8> {
    decode_hex(h).expect("valid hexadecimal RPC value")
}

/// Refuse fixed development keys and block generation on a non-development chain.
pub fn require_devnet() -> Result<Value, String> {
    let consensus = call("get_consensus", json!([]))?;
    if consensus["id"] != "ckb_dev" || consensus["permanent_difficulty_in_dummy"] != true {
        return Err("this driver requires ckb_dev with permanent dummy difficulty".into());
    }
    Ok(consensus)
}

pub fn mine_blocks(count: u64) -> Result<(), String> {
    require_devnet()?;
    for _ in 0..count {
        let before = get_tip_block_number()?;
        let hash = call("generate_block", json!([]))?;
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            let tip = call("get_tip_header", json!([]))?;
            if tip["hash"] == hash {
                break;
            }
            if get_tip_block_number()? > before || std::time::Instant::now() >= deadline {
                return Err("generated block did not become the canonical tip; use an isolated node without another miner".into());
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        // Pool notifications follow chain verification asynchronously. A block
        // must be reflected in the pool before deriving the next block template.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while call("tx_pool_info", json!([]))?["tip_hash"] != hash {
            if std::time::Instant::now() >= deadline {
                return Err("txpool did not catch up with generated block".into());
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
    }
    Ok(())
}

pub fn bytes_to_hex(b: &[u8]) -> String {
    format!(
        "0x{}",
        b.iter().map(|x| format!("{x:02x}")).collect::<String>()
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn malformed_hex_is_rejected_without_panicking_or_losing_bytes() {
        for value in ["0x1", "0xgg", "0xé", "0x00zz", "0x0x00"] {
            assert!(decode_hex(value).is_err(), "{value}");
        }
        assert_eq!(decode_hex("0x00aBff").unwrap(), vec![0, 171, 255]);
        assert_eq!(decode_hex("0x").unwrap(), Vec::<u8>::new());
    }
}
