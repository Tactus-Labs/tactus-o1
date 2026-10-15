//! Recover EVM execution from a pinned canonical CKB input history. A journal is
//! a replay cache, never the authority for CKB canonicality or asset settlement.
use crate::{
    recovery::{self, RecoveredAnchor},
    rpc,
};
use serde_json::{json, Value};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::Path,
};
use tactus_o1_execution::{store::Store, Executor, Genesis};

/// Recover a fresh canonical snapshot, replay all missing inputs, then atomically
/// publish a local checkpoint. Orphan journals remain available for diagnosis.
/// Every invocation rechecks CKB; no current.json output is accepted as evidence.
pub fn recover_execution(
    genesis: &Genesis,
    type_script: &[u8],
    root: &Path,
) -> Result<Value, String> {
    let snapshot = recovery::recover_published_batches(type_script)?;
    persist_recovered(genesis, type_script, root, &snapshot)
}

/// Recover allocation bytes from the immutable creation transaction, then derive
/// EVM genesis. The deployment type and node/chain binding remain trusted inputs.
pub fn recover_execution_from_chain(
    type_script: &[u8],
    root: &Path,
    expected_ckb_genesis: &str,
) -> Result<Value, String> {
    if rpc::decode_hex(expected_ckb_genesis)?.len() != 32
        || rpc::call("get_block_hash", json!(["0x0"]))?.as_str() != Some(expected_ckb_genesis)
    {
        return Err("CKB genesis hash mismatch".into());
    }
    let snapshot = recovery::recover_published_batches(type_script)?;
    let genesis = Genesis::from_allocation(
        snapshot.genesis.rollup_id.into(),
        snapshot.genesis.chain_id,
        &snapshot.genesis_allocation,
    )
    .map_err(|e| e.to_string())?;
    persist_recovered(&genesis, type_script, root, &snapshot)
}
fn persist_recovered(
    genesis: &Genesis,
    type_script: &[u8],
    root: &Path,
    snapshot: &RecoveredAnchor,
) -> Result<Value, String> {
    let network = rpc::call("get_block_hash", json!(["0x0"]))?;
    let binding = json!({"ckb_genesis_hash":network.as_str().ok_or("CKB genesis hash missing")?,"anchor_type_script":rpc::bytes_to_hex(type_script)});
    persist_snapshot(genesis, snapshot, root, &binding, || {
        recovery::assert_canonical(snapshot.pinned_height, &snapshot.pinned_hash)
    })
}

fn persist_snapshot(
    genesis: &Genesis,
    snapshot: &RecoveredAnchor,
    root: &Path,
    binding: &Value,
    mut check: impl FnMut() -> Result<(), String>,
) -> Result<Value, String> {
    if genesis.allocation_bytes().map_err(|e| e.to_string())? != snapshot.genesis_allocation {
        return Err(
            "trusted execution genesis allocation does not match immutable CKB publication".into(),
        );
    }
    let expected = Executor::new(genesis).map_err(|e| e.to_string())?;
    if expected.anchor() != &snapshot.genesis {
        return Err("trusted execution genesis does not match CKB genesis anchor".into());
    }
    check()?;
    let io = |e: std::io::Error| e.to_string();
    match fs::create_dir(root) {
        Ok(()) => {
            let parent = root
                .parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or_else(|| Path::new("."));
            File::open(parent).and_then(|f| f.sync_all()).map_err(io)?;
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(e.to_string()),
    }
    // Also pins allocation/rules/genesis header and serializes all branch updates.
    let _identity = Store::open(root.join("identity"), genesis).map_err(|e| e.to_string())?;
    let binding_path = root.join("binding.json");
    if binding_path.exists() {
        let mut bytes = Vec::new();
        File::open(&binding_path)
            .map_err(io)?
            .take(16_385)
            .read_to_end(&mut bytes)
            .map_err(io)?;
        if bytes.len() > 16_384
            || serde_json::from_slice::<Value>(&bytes).map_err(|e| e.to_string())? != *binding
        {
            return Err("recovery directory belongs to another CKB chain or anchor type".into());
        }
    } else {
        publish_json(root, "binding.json", binding, false)?;
    }
    let branch = format!(
        "branch-{}",
        rpc::bytes_to_hex(&snapshot.state.last_batch_commitment)
    );
    let mut store = Store::open(root.join(&branch), genesis).map_err(|e| e.to_string())?;
    let count = usize::try_from(
        store
            .engine()
            .map_err(|e| e.to_string())?
            .anchor()
            .next_batch_number,
    )
    .map_err(|e| e.to_string())?;
    if count > snapshot.batches.len() {
        return Err("cached branch extends beyond recovered snapshot".into());
    }
    let expected_prefix = if count == 0 {
        snapshot.genesis
    } else {
        snapshot.batches[count - 1].summary.next
    };
    if store.engine().map_err(|e| e.to_string())?.anchor() != &expected_prefix {
        return Err("cached branch does not match canonical prefix".into());
    }
    for input in snapshot.batches.iter().skip(count) {
        store
            .append(&input.input_bytes)
            .map_err(|e| e.to_string())?;
    }
    let engine = store.engine().map_err(|e| e.to_string())?;
    if engine.anchor() != &snapshot.state {
        return Err("executed frontier differs from recovered CKB frontier".into());
    }
    // Chain changes while replaying must not publish the new pointer.
    check()?;
    let report = json!({"schema":1,"ckb":binding,"pinned_height":snapshot.pinned_height,"pinned_hash":snapshot.pinned_hash,
        "anchor":{"transaction":rpc::bytes_to_hex(&snapshot.point.tx_hash),"output_index":snapshot.point.index,"state":rpc::bytes_to_hex(&snapshot.state.encode())},
        "journal":branch,"batch_count":snapshot.batches.len(),"input_bytes":snapshot.batches.iter().map(|b|b.input_bytes.len()).sum::<usize>(),
        "genesis_hash":expected.head().hash_slow(),"execution_rules_hash":rpc::bytes_to_hex(&snapshot.state.execution_rules_hash),
        "header":engine.head(),"hash":engine.head().hash_slow(),"state_root":engine.state_root(),"settled":false,
        "genesis_allocation_commitment":rpc::bytes_to_hex(&tactus_o1_protocol::genesis::commitment(&snapshot.genesis_allocation).map_err(|e|format!("{e:?}"))?),"source":"canonical immutable genesis allocation and batch publications; optional caller allocation cross-check"});
    publish_json(root, "current.json", &report, true)?;
    // A reorg can occur during disk publication. Do not return stale success;
    // saved checkpoints always need a fresh canonicality check before serving.
    check()?;
    Ok(report)
}

fn publish_json(root: &Path, name: &str, value: &Value, replace: bool) -> Result<(), String> {
    let temp = root.join(format!("{name}.pending"));
    match fs::remove_file(&temp) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.to_string()),
    }
    let bytes = serde_json::to_vec_pretty(value).map_err(|e| e.to_string())?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temp)
        .map_err(|e| e.to_string())?;
    file.write_all(&bytes)
        .and_then(|()| file.sync_all())
        .map_err(|e| e.to_string())?;
    if replace {
        fs::rename(&temp, root.join(name)).map_err(|e| e.to_string())?;
    } else {
        fs::hard_link(&temp, root.join(name)).map_err(|e| e.to_string())?;
        fs::remove_file(&temp).map_err(|e| e.to_string())?;
    }
    File::open(root)
        .and_then(|f| f.sync_all())
        .map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{recovery::RecoveredBatch, tx::CellOutPoint};
    use std::{
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };
    use tactus_o1_protocol::batch;
    static NEXT: AtomicU64 = AtomicU64::new(0);
    struct Temp(PathBuf);
    impl Temp {
        fn new() -> Self {
            let p = std::env::temp_dir().join(format!(
                "tactus-canonical-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&p).unwrap();
            Self(p)
        }
    }
    impl Drop for Temp {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }
    fn fixture() -> (Genesis, RecoveredAnchor) {
        let all: Value = serde_json::from_str(include_str!(
            "../../../specs/test-vectors/execution-v1/geth-1.17.8.json"
        ))
        .unwrap();
        let case = &all["cases"][2];
        let genesis: Genesis = serde_json::from_value(case["genesis"].clone()).unwrap();
        let engine = Executor::new(&genesis).unwrap();
        let bytes = rpc::decode_hex(case["batch"].as_str().unwrap()).unwrap();
        let summary = batch::validate_batch(&bytes, engine.anchor()).unwrap();
        let snapshot = RecoveredAnchor {
            pinned_height: 10,
            pinned_hash: "fixture-tip".into(),
            genesis: *engine.anchor(),
            genesis_allocation: genesis.allocation_bytes().unwrap(),
            point: CellOutPoint {
                tx_hash: [1; 32],
                index: 0,
            },
            state: summary.next,
            batches: vec![RecoveredBatch {
                anchor_transaction: "fixture-tx".into(),
                publication_output: 1,
                input_bytes: bytes,
                summary,
            }],
        };
        (genesis, snapshot)
    }
    #[test]
    fn replay_time_reorg_cannot_publish_new_pointer_and_retry_reuses_checked_journal() {
        let temp = Temp::new();
        let root = temp.0.join("cache");
        let (g, snapshot) = fixture();
        let binding = json!({"chain":"test","type":"test"});
        let mut calls = 0;
        let result = persist_snapshot(&g, &snapshot, &root, &binding, || {
            calls += 1;
            if calls == 2 {
                Err("reorg".into())
            } else {
                Ok(())
            }
        });
        assert_eq!(result.unwrap_err(), "reorg");
        assert!(!root.join("current.json").exists());
        let report = persist_snapshot(&g, &snapshot, &root, &binding, || Ok(())).unwrap();
        assert_eq!(report["batch_count"], 1);
        assert_eq!(report["header"]["number"], "0x2");
    }
    #[test]
    fn reorg_during_pointer_publication_never_returns_stale_success() {
        let temp = Temp::new();
        let root = temp.0.join("cache");
        let (g, snapshot) = fixture();
        let mut calls = 0;
        let result = persist_snapshot(&g, &snapshot, &root, &json!({"chain":"test"}), || {
            calls += 1;
            if calls == 3 {
                Err("late reorg".into())
            } else {
                Ok(())
            }
        });
        assert_eq!(result.unwrap_err(), "late reorg");
        assert!(root.join("current.json").exists());
        // The on-disk checkpoint is informational. No API returns it without
        // another fresh canonical scan/check.
    }
    #[test]
    fn chain_type_and_execution_genesis_mismatches_fail_closed() {
        let temp = Temp::new();
        let root = temp.0.join("cache");
        let (mut g, snapshot) = fixture();
        persist_snapshot(
            &g,
            &snapshot,
            &root,
            &json!({"chain":"a","type":"a"}),
            || Ok(()),
        )
        .unwrap();
        for binding in [
            json!({"chain":"b","type":"a"}),
            json!({"chain":"a","type":"b"}),
        ] {
            assert!(persist_snapshot(&g, &snapshot, &root, &binding, || Ok(()))
                .unwrap_err()
                .contains("another CKB chain or anchor type"));
        }
        g.chain_id += 1;
        assert!(
            persist_snapshot(&g, &snapshot, &root, &json!({}), || Ok(()))
                .unwrap_err()
                .contains("does not match CKB genesis anchor")
        );
    }
}
