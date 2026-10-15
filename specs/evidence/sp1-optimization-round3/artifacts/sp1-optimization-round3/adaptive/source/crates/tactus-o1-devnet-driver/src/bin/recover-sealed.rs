//! Read-only cold A3 reconstruction from canonical CKB blocks.
use tactus_o1_devnet_driver::{rpc, sealed_recovery::recover_sealed};
fn run() -> Result<(), String> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.len() != 3 || args.iter().any(|s| s.len() > 2048) {
        return Err(
            "usage: recover-sealed CKB_GENESIS_HASH GATE_TYPE_SCRIPT_HEX ANCHOR_TYPE_SCRIPT_HEX"
                .into(),
        );
    }
    let gate = rpc::decode_hex(&args[1])?;
    let anchor = rpc::decode_hex(&args[2])?;
    let state = recover_sealed(&gate, &anchor, &args[0])?;
    println!("{}", state.view());
    Ok(())
}
fn main() {
    if let Err(e) = run() {
        eprintln!("recover-sealed: {e}");
        std::process::exit(1);
    }
}
