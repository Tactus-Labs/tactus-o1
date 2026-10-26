//! Read-only continuous canonical recovery. No transaction, proof or private key.
use serde_json::{json, Value};
use std::{
    fs,
    io::Read,
    path::Path,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tactus_o1_devnet_driver::rpc;
use tactus_v02_lab::{
    err,
    observer::{atomic_json, Observer},
    recover::{recover, Manifest},
    Result,
};
fn now() -> Result<u64> {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(err)?
            .as_millis(),
    )
    .map_err(err)
}
fn main() {
    if let Err(e) = run() {
        eprintln!("{e}");
        std::process::exit(1);
    }
}
fn run() -> Result<()> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 4 && args.len() != 5 {
        return Err("usage: observe-v02 MANIFEST OUTPUT INTERVAL_MS [ITERATIONS]".into());
    }
    let interval: u64 = args[3].parse().map_err(err)?;
    if !(1000..=60000).contains(&interval) {
        return Err("interval must be 1000..60000 ms".into());
    }
    let iterations = if args.len() == 5 {
        let count: u64 = args[4].parse().map_err(err)?;
        if count == 0 {
            return Err("iterations must be positive".into());
        }
        Some(count)
    } else {
        None
    };
    let mut bytes = Vec::new();
    fs::File::open(&args[1])
        .map_err(err)?
        .take(1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(err)?;
    if bytes.len() > 1024 * 1024 {
        return Err("manifest limit".into());
    }
    let manifest: Value = serde_json::from_slice(&bytes).map_err(err)?;
    Manifest::decode(&manifest)?;
    let output = Path::new(&args[2]);
    // Invalidate the old file before the first potentially slow recovery.
    atomic_json(
        output,
        &json!({"schema":"tactus-v02-observer-v1","checked_at_unix_ms":now()?,"refresh_succeeded":false,"snapshot_is_current_at_check":false,"snapshot":null,"error":"observer starting; recovery pending"}),
    )?;
    let mut observer = Observer::default();
    let mut completed = 0u64;
    loop {
        let result = Manifest::decode(&manifest).and_then(recover).and_then(|r| {
            let report = r.report()?;
            if rpc::call("get_tip_header", json!([]))?["hash"] != r.tip["hash"] {
                return Err("tip changed before observer export; retry".into());
            }
            Ok(report)
        });
        let snapshot = observer.snapshot(result, now()?);
        atomic_json(output, &snapshot)?;
        println!(
            "refresh_succeeded={} failures={}",
            snapshot["refresh_succeeded"], snapshot["consecutive_failures"]
        );
        completed = completed.saturating_add(1);
        if iterations.is_some_and(|limit| completed >= limit) {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(interval));
    }
}
