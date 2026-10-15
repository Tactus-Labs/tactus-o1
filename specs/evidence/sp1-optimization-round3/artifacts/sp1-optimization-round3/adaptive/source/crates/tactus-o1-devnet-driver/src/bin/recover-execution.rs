//! Read-only CKB recovery with local durable EVM replay.
use std::{fs::File, io::Read, path::PathBuf};
use tactus_o1_devnet_driver::{
    execution_recovery::{recover_execution, recover_execution_from_chain},
    rpc,
};
use tactus_o1_execution::Genesis;
fn run() -> Result<(), String> {
    let mut args = std::env::args().skip(1);
    let path = args.next().ok_or(
        "usage: recover-execution GENESIS.json TYPE_SCRIPT_HEX RECOVERY_DIRECTORY; or --chain CKB_GENESIS_HASH TYPE_SCRIPT_HEX RECOVERY_DIRECTORY",
    )?;
    let expected_chain = if path == "--chain" {
        Some(
            args.next()
                .ok_or("--chain requires trusted CKB genesis hash")?,
        )
    } else {
        None
    };
    let script = rpc::decode_hex(&args.next().ok_or("type script required")?)?;
    if script.len() > 1024 {
        return Err("unexpectedly large anchor type script".into());
    }
    let root = PathBuf::from(args.next().ok_or("recovery directory required")?);
    if args.next().is_some() {
        return Err("unexpected extra argument".into());
    }
    if path == "--chain" {
        println!(
            "{}",
            recover_execution_from_chain(
                &script,
                &root,
                expected_chain.as_deref().ok_or("chain binding")?
            )?
        );
        return Ok(());
    }
    let mut bytes = Vec::new();
    File::open(path)
        .map_err(|e| e.to_string())?
        .take(16 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() > 16 * 1024 * 1024 {
        return Err("genesis exceeds size limit".into());
    }
    let genesis: Genesis = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
    println!("{}", recover_execution(&genesis, &script, &root)?);
    Ok(())
}
fn main() {
    if let Err(error) = run() {
        eprintln!("recover-execution: {error}");
        std::process::exit(1);
    }
}
