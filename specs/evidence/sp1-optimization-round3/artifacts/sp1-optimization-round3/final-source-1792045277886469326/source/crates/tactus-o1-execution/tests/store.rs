use alloy_primitives::{hex, B256, U256};
use serde_json::Value;
use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};
use tactus_o1_execution::{
    store::{Error, Store},
    Genesis,
};
use tactus_o1_protocol::batch::{hash, BatchInput, BlockInput};
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "tactus-o1-store-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}
fn fixture() -> (Genesis, Vec<u8>) {
    let v: Value = serde_json::from_str(include_str!(
        "../../../specs/test-vectors/execution-v1/geth-1.17.8.json"
    ))
    .unwrap();
    let c = &v["cases"][2];
    (
        serde_json::from_value(c["genesis"].clone()).unwrap(),
        hex::decode(c["batch"].as_str().unwrap()).unwrap(),
    )
}
fn empty(store: &Store) -> Vec<u8> {
    let engine = store.engine().unwrap();
    BatchInput {
        parent: *engine.anchor(),
        blocks: vec![BlockInput {
            timestamp: engine.head().timestamp,
            fee_recipient: [4; 20],
            transactions: vec![],
        }],
    }
    .encode()
    .unwrap()
}
fn first(path: &std::path::Path) -> PathBuf {
    path.join("00000000000000000000.batch")
}
#[test]
fn exclusive_writer_and_restart_replay_match_independent_fixture() {
    let tmp = Temp::new();
    let path = tmp.0.join("journal");
    let (g, input) = fixture();
    let mut store = Store::open(&path, &g).unwrap();
    assert!(matches!(Store::open(&path, &g), Err(Error::Locked)));
    let blocks = store.append(&input).unwrap();
    let root = store.engine().unwrap().state_root();
    let head = store.engine().unwrap().head().clone();
    assert_eq!(blocks.len(), 2);
    drop(store);
    let mut store = Store::open(&path, &g).unwrap();
    assert_eq!(store.engine().unwrap().state_root(), root);
    assert_eq!(store.engine().unwrap().head(), &head);
    let next = empty(&store);
    store.append(&next).unwrap();
    drop(store);
    let store = Store::open(&path, &g).unwrap();
    assert_eq!(store.engine().unwrap().anchor().next_batch_number, 2);
    assert_eq!(store.engine().unwrap().state_root(), root);
}
#[test]
fn incomplete_staging_file_is_ignored_and_replaced() {
    let tmp = Temp::new();
    let path = tmp.0.join("journal");
    let (g, input) = fixture();
    let mut store = Store::open(&path, &g).unwrap();
    store.append(&input).unwrap();
    drop(store);
    fs::write(path.join("pending"), b"torn record from killed writer").unwrap();
    let mut store = Store::open(&path, &g).unwrap();
    assert_eq!(store.engine().unwrap().anchor().next_batch_number, 1);
    let next = empty(&store);
    store.append(&next).unwrap();
    assert!(!path.join("pending").exists());
}
#[test]
fn published_record_survives_crash_before_staging_unlink() {
    let tmp = Temp::new();
    let path = tmp.0.join("journal");
    let (g, input) = fixture();
    let mut store = Store::open(&path, &g).unwrap();
    store.append(&input).unwrap();
    let expected = store.engine().unwrap().head().clone();
    drop(store);
    // This is the filesystem layout after linking a complete record but before
    // unlinking its staging name. Recovery must not replay it twice.
    fs::hard_link(first(&path), path.join("pending")).unwrap();
    let store = Store::open(&path, &g).unwrap();
    assert_eq!(store.engine().unwrap().head(), &expected);
}
#[test]
fn checksum_truncation_gap_and_wrong_derived_root_fail_closed() {
    for mutation in 0..4 {
        let tmp = Temp::new();
        let path = tmp.0.join("journal");
        let (g, input) = fixture();
        let mut store = Store::open(&path, &g).unwrap();
        store.append(&input).unwrap();
        drop(store);
        let mut bytes = fs::read(first(&path)).unwrap();
        match mutation {
            0 => {
                bytes[30] ^= 1;
                fs::write(first(&path), bytes).unwrap();
            }
            1 => {
                bytes.pop();
                fs::write(first(&path), bytes).unwrap();
            }
            2 => fs::rename(first(&path), path.join("00000000000000000001.batch")).unwrap(),
            3 => {
                let len = bytes.len();
                bytes[len - 64] ^= 1;
                let digest = hash(b"tactus/o1/journal-record/v1", &bytes[..len - 32]);
                bytes[len - 32..].copy_from_slice(&digest);
                fs::write(first(&path), bytes).unwrap();
            }
            _ => unreachable!(),
        }
        assert!(matches!(Store::open(&path, &g), Err(Error::Corrupt(_))));
    }
}
#[test]
fn wrong_genesis_or_missing_genesis_does_not_reinitialize_history() {
    let tmp = Temp::new();
    let path = tmp.0.join("journal");
    let (mut g, input) = fixture();
    let mut store = Store::open(&path, &g).unwrap();
    store.append(&input).unwrap();
    drop(store);
    g.rollup_id = B256::repeat_byte(9);
    assert!(matches!(Store::open(&path, &g), Err(Error::Genesis)));
    fs::remove_file(path.join("genesis.json")).unwrap();
    assert!(matches!(Store::open(&path, &g), Err(Error::Corrupt(_))));
}
#[test]
fn failed_publication_poison_requires_reopen_and_never_overwrites_record() {
    let tmp = Temp::new();
    let path = tmp.0.join("journal");
    let (g, input) = fixture();
    let mut store = Store::open(&path, &g).unwrap();
    fs::write(first(&path), b"already exists").unwrap();
    assert!(matches!(store.append(&input), Err(Error::Io(_))));
    assert!(matches!(store.engine(), Err(Error::Poisoned)));
    assert!(matches!(store.append(&input), Err(Error::Poisoned)));
    assert_eq!(fs::read(first(&path)).unwrap(), b"already exists");
}
#[test]
fn malformed_input_does_not_poison_writer_or_create_a_record() {
    let tmp = Temp::new();
    let path = tmp.0.join("journal");
    let (g, input) = fixture();
    let mut store = Store::open(&path, &g).unwrap();
    assert!(matches!(
        store.append(&input[..input.len() - 1]),
        Err(Error::Execution(_))
    ));
    assert_eq!(store.engine().unwrap().anchor().next_batch_number, 0);
    assert!(!first(&path).exists());
    store.append(&input).unwrap();
}
#[test]
fn unicode_or_unknown_files_fail_without_panicking() {
    let tmp = Temp::new();
    let path = tmp.0.join("journal");
    let (g, _) = fixture();
    drop(Store::open(&path, &g).unwrap());
    fs::write(path.join(format!("{}é.batch", "x".repeat(18))), b"").unwrap();
    assert!(matches!(Store::open(&path, &g), Err(Error::Corrupt(_))));
}

#[test]
fn empty_journal_still_pins_execution_rules_and_genesis_header() {
    let tmp = Temp::new();
    let path = tmp.0.join("journal");
    let (g, _) = fixture();
    drop(Store::open(&path, &g).unwrap());
    let p = path.join("genesis.json");
    let mut saved: Value = serde_json::from_slice(&fs::read(&p).unwrap()).unwrap();
    saved["rules_hash"] = serde_json::json!(B256::ZERO);
    fs::write(p, serde_json::to_vec(&saved).unwrap()).unwrap();
    assert!(matches!(Store::open(&path, &g), Err(Error::Rules)));
}

#[test]
fn cli_restarts_in_another_process_and_returns_identical_head() {
    let tmp = Temp::new();
    let path = tmp.0.join("journal");
    let (g, input) = fixture();
    let genesis_file = tmp.0.join("genesis.json");
    let input_file = tmp.0.join("batch.bin");
    fs::write(&genesis_file, serde_json::to_vec(&g).unwrap()).unwrap();
    fs::write(&input_file, input).unwrap();
    let first = std::process::Command::new(env!("CARGO_BIN_EXE_replay-execution"))
        .arg(&genesis_file)
        .arg(&path)
        .arg(&input_file)
        .output()
        .unwrap();
    assert!(
        first.status.success(),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );
    let second = std::process::Command::new(env!("CARGO_BIN_EXE_replay-execution"))
        .arg(&genesis_file)
        .arg(&path)
        .output()
        .unwrap();
    assert!(
        second.status.success(),
        "{}",
        String::from_utf8_lossy(&second.stderr)
    );
    let first = String::from_utf8(first.stdout).unwrap();
    let second = String::from_utf8(second.stdout).unwrap();
    assert_eq!(first.lines().last(), second.lines().last());
}

#[test]
fn equivalent_zero_storage_encodings_share_one_canonical_genesis() {
    let tmp = Temp::new();
    let (g, input) = fixture();
    let mut with_zero = g.clone();
    with_zero
        .accounts
        .values_mut()
        .next()
        .unwrap()
        .storage
        .insert(U256::ZERO, U256::ZERO);
    assert_eq!(
        with_zero.allocation_bytes().unwrap(),
        g.allocation_bytes().unwrap()
    );
    let mut store = Store::open(&tmp.0, &with_zero).unwrap();
    store.append(&input).unwrap();
    let expected = store.engine().unwrap().head().clone();
    drop(store);
    let reopened = Store::open(&tmp.0, &g).unwrap();
    assert_eq!(reopened.engine().unwrap().head(), &expected);
}
