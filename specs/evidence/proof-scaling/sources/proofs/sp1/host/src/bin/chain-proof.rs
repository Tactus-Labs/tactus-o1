//! Prove a canonical-chain input export against the unchanged SP1 guest.
//! Export authenticity must be checked against CKB independently; verification
//! here binds the proof to its exact replayed journal and declared guest key.
use sp1_sdk::{
    Elf, HashableKey, ProveRequest, Prover, ProverClient, ProvingKey, SP1ProofWithPublicValues,
    SP1PublicValues, SP1Stdin,
};
use std::{fs, io::Read, path::Path, time::Instant};
use tactus_o1_proof_journal::{execute, Domain, Journal};

#[tokio::main]
async fn main() {
    sp1_sdk::setup_logger();
    if let Err(error) = run().await {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
async fn run() -> Result<(), String> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 5 || !["execute", "prove-groth16", "verify"].contains(&args[1].as_str()) {
        return Err(
            "usage: chain-proof execute|prove-groth16|verify GUEST_ELF CHAIN_INPUT_JSON OUTPUT_DIR"
                .into(),
        );
    }
    let groth16 = args[1] == "prove-groth16";
    if groth16 && !cfg!(feature = "native-gnark") {
        return Err("Build with --features native-gnark for local Groth16 proving".into());
    }
    if groth16
        && std::env::var("SP1_CIRCUIT_MODE").unwrap_or_else(|_| "release".into()) != "release"
    {
        return Err("Groth16 experiment requires release circuit artifacts".into());
    }
    if std::env::var_os("WITHOUT_VK_VERIFICATION").is_some() {
        return Err("verification bypass environment is forbidden".into());
    }
    let mut input_bytes = Vec::new();
    fs::File::open(&args[3])
        .map_err(err)?
        .take(64 * 1024 * 1024 + 1)
        .read_to_end(&mut input_bytes)
        .map_err(err)?;
    if input_bytes.len() > 64 * 1024 * 1024 {
        return Err("chain export exceeds 64 MiB runner limit".into());
    }
    let input: serde_json::Value = serde_json::from_slice(&input_bytes).map_err(err)?;
    if input["schema"] != 1 {
        return Err("unknown chain input schema".into());
    }
    let decode = |value: &serde_json::Value| -> Result<Vec<u8>, String> {
        hex::decode(
            value
                .as_str()
                .ok_or("expected hex string")?
                .strip_prefix("0x")
                .ok_or("expected 0x prefix")?,
        )
        .map_err(err)
    };
    let domain = Domain::decode(&decode(&input["domain_hex"])?).map_err(err)?;
    let allocation = decode(&input["allocation_hex"])?;
    let batches = input["batches"]
        .as_array()
        .ok_or("missing batches")?
        .iter()
        .map(decode)
        .collect::<Result<Vec<_>, _>>()?;
    let prefix = input["prefix_batches"].as_u64().ok_or("prefix count")?;
    let interval = u64::try_from(batches.len())
        .map_err(err)?
        .checked_sub(prefix)
        .filter(|n| *n > 0)
        .ok_or("empty interval or prefix outside input")?;
    let mut iterator = batches.iter();
    let expected = execute(domain.clone(), &allocation, prefix, interval, || {
        iterator.next().expect("checked batch count").clone()
    })
    .map_err(err)?;
    if decode(&input["expected_journal_hex"])? != expected.encode() {
        return Err("chain export differs from independently replayed journal".into());
    }
    let expected_key = input["guest_verifying_key"]
        .as_str()
        .ok_or("missing guest key")?;
    if decode(&input["guest_verifying_key"])?.len() != 32 {
        return Err("guest key length".into());
    }
    let elf = Elf::from(fs::read(&args[2]).map_err(err)?);
    let mut stdin = SP1Stdin::new();
    stdin.write_vec(domain.encode().to_vec());
    stdin.write_vec(allocation);
    stdin.write(&prefix);
    stdin.write(&interval);
    for batch in batches {
        stdin.write_vec(batch);
    }
    let output = Path::new(&args[4]);
    if args[1] != "verify" {
        fs::create_dir(output).map_err(err)?;
    }
    let started = Instant::now();
    let prover = ProverClient::builder().cpu().build().await;
    eprintln!("Local CPU prover initialized after {:?}", started.elapsed());
    let pk = prover.setup(elf.clone()).await.map_err(err)?;
    let key = pk.verifying_key().bytes32();
    if key != expected_key {
        return Err("guest ELF differs from exported deployment key".into());
    }
    if args[1] == "verify" {
        let proof = SP1ProofWithPublicValues::load(output.join("proof.bin")).map_err(err)?;
        prover
            .verify(&proof, pk.verifying_key(), None)
            .map_err(err)?;
        if proof.public_values.as_slice() != expected.encode() {
            return Err("valid proof does not match expected deployment/interval/state".into());
        }
        println!("Fresh process verified real proof and exact expected journal; key {key}");
        return Ok(());
    }
    let (public, report) = prover.execute(elf, stdin.clone()).await.map_err(err)?;
    let decoded = Journal::decode(public.as_slice()).map_err(err)?;
    if decoded != expected {
        return Err("zkVM result differs from native execution".into());
    }
    fs::write(output.join("execution-report.txt"), format!("{report:?}\n")).map_err(err)?;
    fs::write(output.join("public-values.bin"), public.as_slice()).map_err(err)?;
    let execution_seconds = started.elapsed().as_secs_f64();
    eprintln!("Guest matched independently replayed chain export after {execution_seconds:.3}s");
    let mut result = serde_json::json!({"schema":1,"backend":"local-cpu","sp1":"6.8.1","guest_verifying_key":key,"public_values_hex":hex::encode(public.as_slice()),"native_chain_replay_match":true,"prefix_batches":prefix,"interval_batches":interval,"execution_seconds_including_setup":execution_seconds,"proof_generated":false,"ckb_settlement":false,"production_ready":false,"domain":"exact canonical-chain export; chain authentication checked separately"});
    if groth16 {
        let proof = prover.prove(&pk, stdin).groth16().await.map_err(err)?;
        if proof.public_values.as_slice() != expected.encode() {
            return Err("proof public values differ".into());
        }
        prover
            .verify(&proof, pk.verifying_key(), None)
            .map_err(err)?;
        proof.save(output.join("proof.bin")).map_err(err)?;
        let mut rejected = Vec::new();
        for (label, offset) in [
            ("profile", 8),
            ("ckb-network", 40),
            ("ordering-script", 72),
            ("settlement-script", 104),
            ("rollup", 136),
            ("chain", 168),
            ("allocation", 176),
            ("predecessor", 248),
            ("end-history", 456),
            ("previous-state", 608),
            ("next-state", 640),
            ("previous-header", 672),
            ("next-header", 704),
            ("interval-data", 736),
        ] {
            let mut altered = proof.clone();
            let mut bytes = public.as_slice().to_vec();
            bytes[offset] ^= 1;
            altered.public_values = SP1PublicValues::from(&bytes);
            if prover.verify(&altered, pk.verifying_key(), None).is_ok() {
                return Err(format!("accepted tampered {label}"));
            }
            rejected.push(label);
        }
        let mut wrong_key = hex::decode(key.trim_start_matches("0x")).map_err(err)?;
        wrong_key[31] ^= 1;
        if sp1_verifier::Groth16Verifier::verify(
            &proof.bytes(),
            public.as_slice(),
            &format!("0x{}", hex::encode(wrong_key)),
            &sp1_verifier::GROTH16_VK_BYTES,
        )
        .is_ok()
        {
            return Err("accepted wrong guest key".into());
        }
        rejected.push("wrong-guest-key");
        result["proof_generated"] = true.into();
        result["proof_kind"] = if groth16 {
            "SP1 real Groth16"
        } else {
            "SP1 real core STARK"
        }
        .into();
        result["circuit_version"] = sp1_sdk::SP1_CIRCUIT_VERSION.into();
        if groth16 {
            // SDK wire bytes are the input to the small no_std verifier.
            fs::write(output.join("groth16-proof.bin"), proof.bytes()).map_err(err)?;
        }
        result["negative_controls"] = serde_json::json!(rejected);
        result["proof_bytes"] = fs::metadata(output.join("proof.bin"))
            .map_err(err)?
            .len()
            .into();
        result["total_seconds"] = started.elapsed().as_secs_f64().into();
        eprintln!(
            "Real CPU proof verified; {} negative controls passed",
            rejected.len()
        );
    }
    fs::write(
        output.join("result.json"),
        serde_json::to_vec_pretty(&result).map_err(err)?,
    )
    .map_err(err)?;
    Ok(())
}
fn err(error: impl std::fmt::Debug) -> String {
    format!("{error:?}")
}
