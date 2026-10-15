//! Execution-only prefix-scaling audit. No proof or deployment claims.
use sp1_sdk::{Elf, Prover, ProverClient, SP1Stdin};
use std::{fs, path::Path};
use tactus_o1_proof_journal::{execute, Domain};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() < 4 {
        return Err("usage: proof-scaling-bench CHAIN_INPUT NEW_OUTPUT_DIR ELF [ELF ...]".into());
    }
    let input: serde_json::Value = serde_json::from_slice(&fs::read(&args[1])?)?;
    let decode = |v: &serde_json::Value| -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        Ok(hex::decode(
            v.as_str()
                .ok_or("hex string")?
                .strip_prefix("0x")
                .ok_or("hex prefix")?,
        )?)
    };
    let domain = Domain::decode(&decode(&input["domain_hex"])?).map_err(|e| format!("{e:?}"))?;
    let allocation = decode(&input["allocation_hex"])?;
    let batches = input["batches"]
        .as_array()
        .ok_or("batches")?
        .iter()
        .map(decode)
        .collect::<Result<Vec<_>, _>>()?;
    if batches.len() != 9 || input["prefix_batches"] != 0 {
        return Err("audit expects retained nine-batch, zero-prefix workload".into());
    }
    let out = Path::new(&args[2]);
    fs::create_dir(out)?;
    let prover = ProverClient::builder().cpu().build().await;
    let mut rows = Vec::new();
    for (name, prefix, end) in [
        ("first-1", 0usize, 1usize),
        ("first-3", 0, 3),
        ("all-9", 0, 9),
        ("prefix-8-new-1", 8, 9),
    ] {
        let interval = (end - prefix) as u64;
        let mut iter = batches[..end].iter();
        let expected = execute(domain.clone(), &allocation, prefix as u64, interval, || {
            iter.next().unwrap().clone()
        })
        .map_err(|e| format!("{e:?}"))?;
        if name == "all-9" {
            assert_eq!(
                expected.encode().as_slice(),
                decode(&input["expected_journal_hex"])?
            );
        }
        let mut stdin = SP1Stdin::new();
        stdin.write_vec(domain.encode().to_vec());
        stdin.write_vec(allocation.clone());
        stdin.write(&(prefix as u64));
        stdin.write(&interval);
        for batch in &batches[..end] {
            stdin.write_vec(batch.clone());
        }
        for path in &args[3..] {
            let label = Path::new(path)
                .file_stem()
                .ok_or("ELF label")?
                .to_str()
                .ok_or("UTF8")?;
            let (public, report) = prover
                .execute(Elf::from(fs::read(path)?), stdin.clone())
                .await?;
            assert_eq!(report.exit_code, 0);
            assert_eq!(public.as_slice(), expected.encode());
            fs::write(
                out.join(format!("{label}-{name}.report.txt")),
                format!("{report:?}\n"),
            )?;
            fs::write(
                out.join(format!("{label}-{name}.public.bin")),
                public.as_slice(),
            )?;
            let cycles: std::collections::BTreeMap<_, _> = report.cycle_tracker.iter().collect();
            let invocations: std::collections::BTreeMap<_, _> =
                report.invocation_tracker.iter().collect();
            rows.push(serde_json::json!({"variant":label,"case":name,"prefix_batches":prefix,"interval_batches":interval,"instructions":report.total_instruction_count(),"prover_gas":report.gas(),"cycle_tracker":cycles,"invocations":invocations,"native_journal_match":true,"proof_generated":false}));
            fs::write(out.join("results.json"), serde_json::to_vec_pretty(&rows)?)?;
            println!(
                "{label}/{name}: {} instructions; exact native journal match",
                report.total_instruction_count()
            );
        }
    }
    Ok(())
}
