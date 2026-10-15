//! Compare real guest execution against the same native/Geth fixture oracle.
//! This command generates no proofs and makes no proving-time claims.
use sp1_sdk::{Elf, Prover, ProverClient, SP1Stdin};
use std::{fs, path::Path, time::Instant};
use tactus_o1_execution::{Executor, Genesis};
use tactus_o1_proof_journal::{execute, Domain};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() < 4 {
        return Err("usage: crypto-patch-bench FIXTURE NEW_OUTPUT_DIR ELF [ELF ...]".into());
    }
    let fixture: serde_json::Value = serde_json::from_slice(&fs::read(&args[1])?)?;
    let output = Path::new(&args[2]);
    fs::create_dir(output)?;
    let prover = ProverClient::builder().cpu().build().await;
    let mut inputs = Vec::new();
    for (index, case) in fixture["cases"]
        .as_array()
        .ok_or("missing cases")?
        .iter()
        .enumerate()
    {
        let genesis: Genesis = serde_json::from_value(case["genesis"].clone())?;
        let batch = hex::decode(
            case["batch"]
                .as_str()
                .ok_or("missing batch")?
                .trim_start_matches("0x"),
        )?;
        let domain = Domain {
            ckb_genesis: [1; 32],
            ordering_type_hash: [2; 32],
            settlement_type_hash: [3; 32],
            rollup_id: genesis.rollup_id.0,
            chain_id: genesis.chain_id,
        };
        let allocation = genesis.allocation_bytes()?;
        let expected = execute(domain.clone(), &allocation, 0, 1, || batch.clone())
            .map_err(|e| format!("{e:?}"))?;
        let mut executor = Executor::new(&genesis)?;
        let blocks = executor.apply_batch(&batch)?;
        let geth = case["geth"].as_array().ok_or("missing Geth oracle")?;
        assert_eq!(blocks.len(), geth.len());
        for (block, oracle) in blocks.iter().zip(geth) {
            for (actual, field) in [
                (block.header.state_root, "stateRoot"),
                (block.header.transactions_root, "txRoot"),
                (block.header.receipts_root, "receiptsRoot"),
            ] {
                assert_eq!(
                    format!("{actual}"),
                    oracle[field].as_str().ok_or("missing Geth root")?
                );
            }
        }
        let mut stdin = SP1Stdin::new();
        stdin.write_vec(domain.encode().to_vec());
        stdin.write_vec(allocation);
        stdin.write(&0u64);
        stdin.write(&1u64);
        stdin.write_vec(batch);
        inputs.push((
            index,
            case["name"].as_str().ok_or("case name")?.to_owned(),
            stdin,
            expected.encode(),
            true,
        ));
    }
    // Optional retained chain workload: execute the exact old inputs, but do not
    // claim the new ELF is authorized by its old deployment key or generate a proof.
    if let Ok(path) = std::env::var("TACTUS_PATCH_CHAIN_INPUT") {
        let chain: serde_json::Value = serde_json::from_slice(&fs::read(path)?)?;
        assert_eq!(chain["schema"], 1);
        let decode = |v: &serde_json::Value| -> Result<Vec<u8>, Box<dyn std::error::Error>> {
            Ok(hex::decode(
                v.as_str()
                    .ok_or("hex value")?
                    .strip_prefix("0x")
                    .ok_or("hex prefix")?,
            )?)
        };
        let domain =
            Domain::decode(&decode(&chain["domain_hex"])?).map_err(|e| format!("{e:?}"))?;
        let allocation = decode(&chain["allocation_hex"])?;
        let batches = chain["batches"]
            .as_array()
            .ok_or("batches")?
            .iter()
            .map(decode)
            .collect::<Result<Vec<_>, _>>()?;
        let prefix = chain["prefix_batches"].as_u64().ok_or("prefix")?;
        let interval = (batches.len() as u64)
            .checked_sub(prefix)
            .filter(|n| *n > 0)
            .ok_or("interval")?;
        let mut batches_iter = batches.iter();
        let expected = execute(domain.clone(), &allocation, prefix, interval, || {
            batches_iter.next().unwrap().clone()
        })
        .map_err(|e| format!("{e:?}"))?
        .encode();
        assert_eq!(expected.as_slice(), decode(&chain["expected_journal_hex"])?);
        let mut stdin = SP1Stdin::new();
        stdin.write_vec(domain.encode().to_vec());
        stdin.write_vec(allocation);
        stdin.write(&prefix);
        stdin.write(&interval);
        for batch in batches {
            stdin.write_vec(batch);
        }
        inputs.push((
            inputs.len(),
            "retained-sealed-chain".to_owned(),
            stdin,
            expected,
            false,
        ));
    }
    let mut rows = Vec::new();
    for (index, name, stdin, expected, geth_checked) in inputs {
        for elf_path in &args[3..] {
            let label = Path::new(elf_path)
                .file_stem()
                .ok_or("ELF name")?
                .to_str()
                .ok_or("UTF8 name")?;
            let elf = Elf::from(fs::read(elf_path)?);
            let start = Instant::now();
            let (public, report) = prover.execute(elf, stdin.clone()).await?;
            let elapsed = start.elapsed().as_secs_f64();
            assert_eq!(report.exit_code, 0);
            assert_eq!(public.as_slice(), expected);
            let syscalls: std::collections::BTreeMap<_, _> = report
                .syscall_counts
                .iter()
                .filter(|(_, n)| **n > 0)
                .map(|(code, n)| (format!("{code:?}"), *n))
                .collect();
            fs::write(
                output.join(format!("{label}-{index}.report.txt")),
                format!("{report:?}\n"),
            )?;
            fs::write(
                output.join(format!("{label}-{index}.public.bin")),
                public.as_slice(),
            )?;
            rows.push(serde_json::json!({"variant":label,"case_index":index,"case":name,
                "instructions":report.total_instruction_count(),"prover_gas":report.gas(),
                "crypto_syscalls":syscalls,"execution_seconds":elapsed,"native_match":true,"geth_checked":geth_checked}));
            fs::write(
                output.join("results.json"),
                serde_json::to_vec_pretty(&rows)?,
            )?;
            println!(
                "{label}/{index}: {} instructions, gas {:?}; exact native journal match; Geth checked={geth_checked}",
                report.total_instruction_count(),
                report.gas()
            );
        }
    }
    Ok(())
}
