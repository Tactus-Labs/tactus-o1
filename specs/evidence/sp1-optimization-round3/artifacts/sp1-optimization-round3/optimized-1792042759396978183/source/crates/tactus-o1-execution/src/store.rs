//! Crash-safe append-only batch journal. Rebuilds execution from genesis and
//! record checksums; no serialized operator state is trusted.
use crate::{Error as ExecutionError, ExecutedBlock, Executor, Genesis};
use alloy_primitives::B256;
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};
use tactus_o1_protocol::batch::{hash, MAX_BATCH_BYTES};

const MAGIC: &[u8; 8] = b"TO1LOG01";
const OVERHEAD: usize = 8 + 4 + 32 + 32 + 32;
const MANIFEST_LIMIT: u64 = 16 * 1024 * 1024;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    version: u32,
    genesis: Genesis,
    rules_hash: B256,
    genesis_hash: B256,
}

#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    Locked,
    Corrupt(String),
    Genesis,
    Rules,
    Execution(ExecutionError),
    /// Durability is uncertain after an I/O failure. Drop and reopen the store
    /// before any further access to canonical in-memory state.
    Poisoned,
}
impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}
impl From<ExecutionError> for Error {
    fn from(e: ExecutionError) -> Self {
        Self::Execution(e)
    }
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for Error {}

// A duplicated file description (including the short fork/exec interval) can
// retain an OS lock after the original File is closed. End ownership explicitly,
// including early errors during recovery, instead of relying only on close.
struct WriterLock(File);
impl Drop for WriterLock {
    fn drop(&mut self) {
        let _ = self.0.unlock();
    }
}

pub struct Store {
    directory: PathBuf,
    // An exclusive OS lock is held for the entire lifetime, including replay.
    _lock: WriterLock,
    engine: Executor,
    poisoned: bool,
}
impl Store {
    /// Creates or opens a store. The caller must supply the trusted genesis.
    /// Existing committed inputs are always independently replayed and checked.
    /// An unfinished `pending` file is ignored; committed records are never
    /// truncated, skipped or repaired silently.
    pub fn open(directory: impl AsRef<Path>, genesis: &Genesis) -> Result<Self, Error> {
        let directory = directory.as_ref().to_path_buf();
        match fs::create_dir(&directory) {
            Ok(()) => {
                let parent = directory
                    .parent()
                    .filter(|p| !p.as_os_str().is_empty())
                    .unwrap_or_else(|| Path::new("."));
                File::open(parent)?.sync_all()?;
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e.into()),
        }
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(directory.join("lock"))?;
        match lock.try_lock() {
            Ok(()) => {}
            Err(std::fs::TryLockError::WouldBlock) => return Err(Error::Locked),
            Err(std::fs::TryLockError::Error(error)) => return Err(Error::Io(error)),
        }
        let lock = WriterLock(lock);
        let canonical = Genesis::from_allocation(
            genesis.rollup_id,
            genesis.chain_id,
            &genesis.allocation_bytes()?,
        )?;
        let genesis = &canonical;
        let mut engine = Executor::new(genesis)?;
        let mut records = Vec::new();
        for entry in fs::read_dir(&directory)? {
            let entry = entry?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| Error::Corrupt("non-UTF8 journal filename".into()))?;
            if matches!(name.as_str(), "lock" | "genesis.json" | "pending") {
                continue;
            }
            if name.len() != 26
                || !name.ends_with(".batch")
                || !name.as_bytes()[..20].iter().all(|b| b.is_ascii_digit())
                || !entry.file_type()?.is_file()
            {
                return Err(Error::Corrupt(format!("unexpected journal entry {name}")));
            }
            records.push(name);
        }
        records.sort();
        let manifest_path = directory.join("genesis.json");
        if manifest_path.exists() {
            let bytes = read_bounded(&manifest_path, MANIFEST_LIMIT)?;
            let saved: Manifest = serde_json::from_slice(&bytes)
                .map_err(|e| Error::Corrupt(format!("genesis: {e}")))?;
            if &saved.genesis != genesis {
                return Err(Error::Genesis);
            }
            if saved.version != 1
                || saved.rules_hash.0 != crate::rules_hash()
                || saved.genesis_hash != engine.head().hash_slow()
            {
                return Err(Error::Rules);
            }
        } else {
            if !records.is_empty() {
                return Err(Error::Corrupt("records without genesis".into()));
            }
            let manifest = Manifest {
                version: 1,
                genesis: genesis.clone(),
                rules_hash: B256::from(crate::rules_hash()),
                genesis_hash: engine.head().hash_slow(),
            };
            let bytes = serde_json::to_vec(&manifest).map_err(|e| Error::Corrupt(e.to_string()))?;
            if bytes.len() as u64 > MANIFEST_LIMIT {
                return Err(Error::Genesis);
            }
            publish(&directory, "genesis.json", &bytes)?;
        }
        for (number, name) in records.iter().enumerate() {
            if *name != record_name(number as u64) {
                return Err(Error::Corrupt("journal sequence gap".into()));
            }
            let bytes = read_bounded(&directory.join(name), (MAX_BATCH_BYTES + OVERHEAD) as u64)?;
            if bytes.len() < OVERHEAD || &bytes[..8] != MAGIC {
                return Err(Error::Corrupt(format!("invalid record {name}")));
            }
            let length = u32::from_le_bytes(bytes[8..12].try_into().unwrap()) as usize;
            if length > MAX_BATCH_BYTES || bytes.len() != length + OVERHEAD {
                return Err(Error::Corrupt(format!("record length {name}")));
            }
            let checksum = hash(b"tactus/o1/journal-record/v1", &bytes[..bytes.len() - 32]);
            if bytes[bytes.len() - 32..] != checksum {
                return Err(Error::Corrupt(format!("record checksum {name}")));
            }
            engine.apply_batch(&bytes[12..12 + length])?;
            if bytes[12 + length..44 + length] != engine.head().hash_slow().0
                || bytes[44 + length..76 + length] != engine.state_root().0
            {
                return Err(Error::Corrupt(format!(
                    "replayed state/header mismatch {name}"
                )));
            }
        }
        Ok(Self {
            directory,
            _lock: lock,
            engine,
            poisoned: false,
        })
    }

    pub fn engine(&self) -> Result<&Executor, Error> {
        if self.poisoned {
            Err(Error::Poisoned)
        } else {
            Ok(&self.engine)
        }
    }

    /// Success means the input and its derived roots have been fsynced and the
    /// publication directory has been fsynced. Never overwrites a committed batch.
    pub fn append(&mut self, bytes: &[u8]) -> Result<Vec<ExecutedBlock>, Error> {
        if self.poisoned {
            return Err(Error::Poisoned);
        }
        let mut next = self.engine.clone();
        let blocks = next.apply_batch(bytes)?;
        let mut record = Vec::with_capacity(bytes.len() + OVERHEAD);
        record.extend_from_slice(MAGIC);
        record.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
        record.extend_from_slice(bytes);
        record.extend_from_slice(next.head().hash_slow().as_slice());
        record.extend_from_slice(next.state_root().as_slice());
        record.extend_from_slice(&hash(b"tactus/o1/journal-record/v1", &record));
        let name = record_name(self.engine.anchor().next_batch_number);
        // Once I/O begins, an error can mean the durable record exists even when
        // memory has not advanced. Poison rather than accepting a divergent retry.
        self.poisoned = true;
        publish(&self.directory, &name, &record)?;
        self.engine = next;
        self.poisoned = false;
        Ok(blocks)
    }
}
fn record_name(number: u64) -> String {
    format!("{number:020}.batch")
}
fn read_bounded(path: &Path, limit: u64) -> Result<Vec<u8>, Error> {
    let mut bytes = Vec::new();
    File::open(path)?.take(limit + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        return Err(Error::Corrupt("oversized journal file".into()));
    }
    Ok(bytes)
}
fn publish(directory: &Path, name: &str, bytes: &[u8]) -> Result<(), Error> {
    let pending = directory.join("pending");
    // Only this reserved, uncommitted staging name is replaceable. Lock holder
    // owns it. A hard link publishes without rename-overwriting an old record.
    match fs::remove_file(&pending) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&pending)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    fs::hard_link(&pending, directory.join(name))?;
    File::open(directory)?.sync_all()?;
    fs::remove_file(pending)?;
    File::open(directory)?.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod lock_release_tests {
    use super::*;
    #[test]
    fn closing_writer_releases_lock_even_with_duplicated_descriptor() {
        let path =
            std::env::temp_dir().join(format!("tactus-o1-lock-release-{}", std::process::id()));
        let genesis = Genesis {
            rollup_id: [0x41; 32].into(),
            chain_id: 31337,
            accounts: Default::default(),
        };
        let store = Store::open(&path, &genesis).unwrap();
        // Models the open-file description inherited by a concurrently spawned
        // child before exec closes CLOEXEC descriptors.
        let duplicate = store._lock.0.try_clone().unwrap();
        drop(store);
        let reopened = Store::open(&path, &genesis);
        let success = reopened.is_ok();
        drop(reopened);
        drop(duplicate);
        fs::remove_dir_all(path).unwrap();
        assert!(
            success,
            "a closed writer must not remain locked by a duplicated descriptor"
        );
    }
}
