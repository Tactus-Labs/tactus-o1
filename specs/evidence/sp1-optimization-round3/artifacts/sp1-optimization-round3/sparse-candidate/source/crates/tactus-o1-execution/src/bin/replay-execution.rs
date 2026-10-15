//! Offline, durable replay. Does not infer CKB canonicality or settlement.
use serde_json::json;
use std::{fs::File, io::Read, path::Path};
use tactus_o1_execution::{store::Store, Genesis};
use tactus_o1_protocol::batch::MAX_BATCH_BYTES;
fn bounded(path: impl AsRef<Path>, limit: usize) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut bytes = Vec::new();
    File::open(path)?
        .take((limit + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err("file exceeds size bound".into());
    }
    Ok(bytes)
}
fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args_os().skip(1);
    let genesis = args
        .next()
        .ok_or("usage: replay-execution GENESIS.json JOURNAL_DIR [BATCH.bin ...]")?;
    let directory = args.next().ok_or("journal directory required")?;
    let genesis: Genesis = serde_json::from_slice(&bounded(genesis, 16 * 1024 * 1024)?)?;
    let mut store = Store::open(directory, &genesis)?;
    for path in args {
        let input = bounded(path, MAX_BATCH_BYTES)?;
        let blocks = store.append(&input)?;
        for block in blocks {
            println!(
                "{}",
                serde_json::to_string(&json!({"event":"durable_block","block":block}))?
            );
        }
    }
    let engine = store.engine()?;
    println!(
        "{}",
        json!({"event":"recovered_head","batch_count":engine.anchor().next_batch_number,"header":engine.head(),"hash":engine.head().hash_slow(),"state_root":engine.state_root(),"settled":false})
    );
    Ok(())
}
fn main() {
    if let Err(error) = run() {
        eprintln!("replay-execution: {error}");
        std::process::exit(1);
    }
}
