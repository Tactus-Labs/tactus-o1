//! Explicit local key derivation and execution only; this runner cannot prove.
use sp1_sdk::{Elf, HashableKey, Prover, ProverClient, ProvingKey, SP1Stdin};
use std::{
    fs,
    io::{Read, Write},
    path::Path,
};
use tactus_o1_protocol::v02::{Config, Journal, Policy, Wire};
use tactus_v02_proof_journal::{execute, Error, Frame};
fn err(value: impl std::fmt::Debug) -> String {
    format!("{value:?}")
}
fn new_file(path: &Path, bytes: &[u8]) -> Result<(), String> {
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(err)?
        .write_all(bytes)
        .map_err(err)
}
#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
async fn run() -> Result<(), String> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 5 && args.len() != 4 {
        return Err("usage: tactus-v02-sp1-host key GUEST_ELF NEW_KEY_JSON | execute GUEST_ELF INPUT_JSON NEW_OUTPUT_DIR".into());
    }
    let key_mode = args[1] == "key" && args.len() == 4;
    if !key_mode && !(args[1] == "execute" && args.len() == 5) {
        return Err("invalid mode".into());
    }
    let elf = Elf::from(fs::read(&args[2]).map_err(err)?);
    let prover = ProverClient::builder().cpu().build().await;
    let pk = prover.setup(elf.clone()).await.map_err(err)?;
    let key = pk.verifying_key().bytes32();
    if key_mode {
        let result = serde_json::json!({"schema":"tactus-v02-guest-key-v1", "sp1":"6.8.1", "guest_verifying_key":key, "proof_generated":false});
        new_file(
            Path::new(&args[3]),
            &serde_json::to_vec_pretty(&result).map_err(err)?,
        )?;
        println!("0.02 guest key: {key}; no execution or proof");
        return Ok(());
    }
    let mut bytes = Vec::new();
    fs::File::open(&args[3])
        .map_err(err)?
        .take(64 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(err)?;
    if bytes.len() > 64 * 1024 * 1024 {
        return Err("development input exceeds 64 MiB".into());
    }
    let input: serde_json::Value = serde_json::from_slice(&bytes).map_err(err)?;
    if input["schema"] != "tactus-v02-proof-input-v1" {
        return Err("wrong input schema".into());
    }
    let decode = |v: &serde_json::Value| -> Result<Vec<u8>, String> {
        hex::decode(
            v.as_str()
                .and_then(|s| s.strip_prefix("0x"))
                .ok_or("expected 0x hex")?,
        )
        .map_err(err)
    };
    let config = Config::decode(&decode(&input["config_hex"])?).map_err(err)?;
    let policy = Policy::decode(&decode(&input["policy_hex"])?).map_err(err)?;
    if key != format!("0x{}", hex::encode(policy.guest_key)) {
        return Err("Policy does not pin this actual guest key".into());
    }
    let allocation = decode(&input["allocation_hex"])?;
    let frames = input["frames"]
        .as_array()
        .ok_or("missing frames")?
        .iter()
        .map(decode)
        .collect::<Result<Vec<_>, _>>()?;
    for frame in &frames {
        Frame::decode(frame).map_err(err)?;
    }
    let prefix = input["prefix_batches"].as_u64().ok_or("missing prefix")?;
    let interval = (frames.len() as u64)
        .checked_sub(prefix)
        .filter(|n| *n > 0)
        .ok_or("invalid interval")?;
    let mut it = frames.iter();
    let expected = execute(
        config.clone(),
        policy.clone(),
        &allocation,
        prefix,
        interval,
        || it.next().cloned().ok_or(Error::MissingInput),
    )
    .map_err(err)?;
    if decode(&input["expected_journal_hex"])? != expected.encode().map_err(err)? {
        return Err("replay differs from supplied journal".into());
    }
    let mut stdin = SP1Stdin::new();
    stdin.write_vec(config.encode().map_err(err)?);
    stdin.write_vec(policy.encode().map_err(err)?);
    stdin.write_vec(allocation);
    stdin.write(&prefix);
    stdin.write(&interval);
    for frame in frames {
        stdin.write_vec(frame);
    }
    let (public, report) = prover.execute(elf, stdin).await.map_err(err)?;
    if Journal::decode(public.as_slice()).map_err(err)? != expected {
        return Err("guest differs from native replay".into());
    }
    let directory = Path::new(&args[4]);
    fs::create_dir(directory).map_err(err)?;
    new_file(&directory.join("public-values.bin"), public.as_slice())?;
    new_file(
        &directory.join("execution-report.txt"),
        format!("{report:?}\n").as_bytes(),
    )?;
    let result = serde_json::json!({"schema":"tactus-v02-guest-execution-v1", "sp1":"6.8.1", "guest_verifying_key":key,
        "prefix_batches":prefix, "interval_batches":interval, "native_replay_match":true,
        "proof_generated":false,"authenticated_publication":false,"ckb_settlement":false,"custody_release":false});
    new_file(
        &directory.join("result.json"),
        &serde_json::to_vec_pretty(&result).map_err(err)?,
    )?;
    println!("0.02 guest matched full journal; no proof generated");
    Ok(())
}
