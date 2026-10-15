//! Read-only A3 fulfillment recovery from trusted deployment identities.
use tactus_o1_devnet_driver::{obligation_recovery, rpc};
fn run() -> Result<(), String> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.len() != 4 || args.iter().any(|s| s.len() > 2050) {
        return Err("usage: recover-obligations CKB_GENESIS_HASH GATE_TYPE_SCRIPT_HEX ANCHOR_TYPE_SCRIPT_HEX SETTLEMENT_TYPE_SCRIPT_HEX".into());
    }
    let gate = rpc::decode_hex(&args[1])?;
    let anchor = rpc::decode_hex(&args[2])?;
    let tip = rpc::decode_hex(&args[3])?;
    println!(
        "{}",
        obligation_recovery::recover_obligations(&args[0], &gate, &anchor, &tip)?
    );
    Ok(())
}
fn main() {
    if let Err(error) = run() {
        eprintln!("recover-obligations: {error}");
        std::process::exit(1);
    }
}
