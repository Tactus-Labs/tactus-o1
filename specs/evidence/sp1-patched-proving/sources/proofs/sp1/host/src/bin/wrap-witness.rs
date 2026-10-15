//! Finish a retained real recursive witness in a fresh process, releasing all
//! preceding STARK-prover allocations. Uses released circuits and full verification.
#[cfg(not(feature = "native-gnark"))]
fn main() {
    eprintln!("Build wrap-witness with --features native-gnark");
    std::process::exit(1);
}
#[cfg(feature = "native-gnark")]
fn main() {
    if let Err(error) = run() {
        eprintln!("wrap-witness: {error}");
        std::process::exit(1);
    }
}

#[cfg(feature = "native-gnark")]
fn run() -> Result<(), String> {
    use num_bigint::BigUint;
    use sp1_recursion_gnark_ffi::{ffi::prove_groth16_bn254, Groth16Bn254Prover};
    use sp1_sdk::{SP1Proof, SP1ProofWithPublicValues, SP1PublicValues};
    use sp1_verifier::{Groth16Verifier, GROTH16_VK_BYTES, VK_ROOT_BYTES};
    use std::{fs, path::Path, time::Instant};
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 6 {
        return Err("usage: wrap-witness CIRCUIT_DIRECTORY WITNESS_JSON PUBLIC_VALUES_BIN EXPECTED_GUEST_KEY NEW_OUTPUT_DIRECTORY".into());
    }
    if std::env::var("SP1_CIRCUIT_MODE").unwrap_or_else(|_| "release".into()) != "release" {
        return Err("release circuit mode required".into());
    }
    let circuit = Path::new(&args[1]);
    if fs::read(circuit.join("groth16_vk.bin")).map_err(err)? != *GROTH16_VK_BYTES {
        return Err("circuit key differs from pinned SP1 release".into());
    }
    let witness: serde_json::Value =
        serde_json::from_slice(&fs::read(&args[2]).map_err(err)?).map_err(err)?;
    let public = fs::read(&args[3]).map_err(err)?;
    tactus_o1_proof_journal::Journal::decode(&public).map_err(err)?;
    let key =
        hex::decode(args[4].strip_prefix("0x").ok_or("expected 0x guest key")?).map_err(err)?;
    if key.len() != 32 {
        return Err("guest key length".into());
    }
    let values = SP1PublicValues::from(&public);
    for (name, expected) in [
        ("vkey_hash", BigUint::from_bytes_be(&key).to_string()),
        ("committed_values_digest", values.hash_bn254().to_string()),
        ("exit_code", "0".into()),
        (
            "vk_root",
            BigUint::from_bytes_be(&*VK_ROOT_BYTES).to_string(),
        ),
        ("proof_nonce", "0".into()),
    ] {
        if witness[name].as_str() != Some(expected.as_str()) {
            return Err(format!("retained witness {name} differs"));
        }
    }
    let output = Path::new(&args[5]);
    fs::create_dir(output).map_err(err)?;
    let started = Instant::now();
    eprintln!("Retained witness matches the exact public journal, guest key and release VK root");
    let mut wrapped = prove_groth16_bn254(&args[1], &args[2]);
    wrapped.groth16_vkey_hash = Groth16Bn254Prover::get_vkey_hash(circuit);
    let proof = SP1ProofWithPublicValues::new(
        SP1Proof::Groth16(wrapped),
        values,
        sp1_sdk::SP1_CIRCUIT_VERSION.into(),
    );
    let bytes = proof.bytes();
    Groth16Verifier::verify(&bytes, &public, &args[4], &GROTH16_VK_BYTES).map_err(err)?;
    let mut rejected = Vec::new();
    for (name, offset) in [
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
        let mut altered = public.clone();
        altered[offset] ^= 1;
        if Groth16Verifier::verify(&bytes, &altered, &args[4], &GROTH16_VK_BYTES).is_ok() {
            return Err(format!("accepted changed {name}"));
        }
        rejected.push(name);
    }
    let mut wrong = key;
    wrong[31] ^= 1;
    if Groth16Verifier::verify(
        &bytes,
        &public,
        &format!("0x{}", hex::encode(wrong)),
        &GROTH16_VK_BYTES,
    )
    .is_ok()
    {
        return Err("accepted wrong guest key".into());
    }
    rejected.push("wrong-guest-key");
    proof.save(output.join("proof.bin")).map_err(err)?;
    fs::write(output.join("groth16-proof.bin"), &bytes).map_err(err)?;
    fs::write(output.join("public-values.bin"), &public).map_err(err)?;
    let result = serde_json::json!({"schema":1,"proof_generated":true,"proof_kind":"SP1 real Groth16","backend":"local CPU, fresh process final wrapping","resumed_from_wrapped_witness":true,"sp1":"6.8.1","circuit_version":sp1_sdk::SP1_CIRCUIT_VERSION,"guest_verifying_key":args[4],"public_values_hex":hex::encode(public),"negative_controls":rejected,"proof_bytes":fs::metadata(output.join("proof.bin")).map_err(err)?.len(),"groth16_wire_bytes":bytes.len(),"wrapping_and_verification_seconds":started.elapsed().as_secs_f64(),"ckb_settlement":false,"production_ready":false});
    fs::write(
        output.join("result.json"),
        serde_json::to_vec_pretty(&result).map_err(err)?,
    )
    .map_err(err)?;
    println!("Real Groth16 proof verified with 15 negative controls");
    Ok(())
}
#[cfg(feature = "native-gnark")]
fn err(error: impl std::fmt::Debug) -> String {
    format!("{error:?}")
}
