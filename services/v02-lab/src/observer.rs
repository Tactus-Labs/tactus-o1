//! One-file observer snapshots: failed refreshes never mark cached state current.
use crate::{err, Result};
use serde_json::{json, Value};
use std::{fs, io::Write, path::Path};

pub fn atomic_json(path: &Path, value: &Value) -> Result<()> {
    let temporary = path.with_extension(format!("tmp-{}", std::process::id()));
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)
        .map_err(err)?;
    let write = (|| {
        file.write_all(&serde_json::to_vec_pretty(value).map_err(err)?)
            .map_err(err)?;
        file.write_all(b"\n").map_err(err)?;
        file.sync_all().map_err(err)?;
        fs::rename(&temporary, path).map_err(err)?;
        Ok(())
    })();
    if write.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    write
}
#[derive(Default)]
pub struct Observer {
    last: Option<Value>,
    last_success: Option<u64>,
    failures: u64,
}
impl Observer {
    pub fn snapshot(&mut self, result: Result<Value>, timestamp: u64) -> Value {
        let error = match result {
            Ok(report) => {
                self.last = Some(report);
                self.last_success = Some(timestamp);
                self.failures = 0;
                None
            }
            Err(error) => {
                self.failures = self.failures.saturating_add(1);
                Some(error)
            }
        };
        json!({"schema":"tactus-v02-observer-v1","checked_at_unix_ms":timestamp,
            "refresh_succeeded":error.is_none(),"last_success_unix_ms":self.last_success,
            "consecutive_failures":self.failures,"error":error,"snapshot":self.last,
            "snapshot_is_current_at_check":error.is_none(),
            "consumer_rule":"require a successful refresh, a fresh timestamp and a matching current CKB tip; failures retain historical data only",
            "selected_node_consensus":true,"transactions_submitted":false})
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn failure_preserves_history_without_current_authority_and_reorg_replaces_it() {
        let mut observer = Observer::default();
        let first = observer.snapshot(Err("offline".into()), 1);
        assert!(first["snapshot"].is_null());
        assert_eq!(first["snapshot_is_current_at_check"], false);
        let orphan = json!({"pinned_hash":"old","mode":"FROZEN","claims":[1,2]});
        assert_eq!(
            observer.snapshot(Ok(orphan.clone()), 2)["consecutive_failures"],
            0
        );
        let failure = observer.snapshot(Err("archive missing".into()), 3);
        assert_eq!(failure["snapshot"], orphan);
        assert_eq!(failure["last_success_unix_ms"], 2);
        assert_eq!(failure["snapshot_is_current_at_check"], false);
        let canonical = json!({"pinned_hash":"new","mode":"RUNNING","claims":[]});
        let resumed = observer.snapshot(Ok(canonical.clone()), 4);
        assert_eq!(resumed["snapshot"], canonical);
        assert_eq!(resumed["snapshot_is_current_at_check"], true);
        assert_eq!(resumed["consecutive_failures"], 0);
    }
}
