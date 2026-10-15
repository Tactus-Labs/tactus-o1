//! Read-only recovery with deployment identity supplied independently of local caches.
use tactus_o1_devnet_driver::{rpc, settlement_recovery};
fn run() -> Result<(), String> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 4 {
        return Err("usage: recover-settlement CKB_GENESIS_HASH ANCHOR_TYPE_SCRIPT_HEX SETTLEMENT_TYPE_SCRIPT_HEX".into());
    }
    if args[2].len() > 2050 || args[3].len() > 2050 {
        return Err("deployment script exceeds runner limit".into());
    }
    let anchor = rpc::decode_hex(&args[2])?;
    let settlement = rpc::decode_hex(&args[3])?;
    println!(
        "{}",
        settlement_recovery::recover_settlement(&args[1], &anchor, &settlement)?
    );
    Ok(())
}
fn main() {
    if let Err(error) = run() {
        eprintln!("recover-settlement: {error}");
        std::process::exit(1);
    }
}
