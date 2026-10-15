//! Full-state/Geth/pruned-witness qualification; optionally execute a real guest.
//! This command generates no proofs and makes no proving-time claims.
use sp1_sdk::{Elf, Prover, ProverClient, SP1Stdin};
use std::{fs, path::Path, time::Instant};
use tactus_o1_execution::{Executor, Genesis};
use tactus_o1_proof_journal::{execute, Domain};
use tactus_o1_sparse_journal::{self as sparse, SparseJournal};
use tactus_o1_sparse_state::database::SparseDb;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().collect();
    if !(3..=4).contains(&args.len()) {
        return Err("usage: qualify-sparse GETH_FIXTURE NEW_OUTPUT_DIRECTORY [GUEST_ELF]".into());
    }
    let fixture: serde_json::Value = serde_json::from_slice(&fs::read(&args[1])?)?;
    let out = Path::new(&args[2]);
    fs::create_dir(out)?;
    let prover = if args.len() == 4 {
        Some(ProverClient::builder().cpu().build().await)
    } else {
        None
    };
    let mut rows = Vec::new();
    for (index, case) in fixture["cases"]
        .as_array()
        .ok_or("cases")?
        .iter()
        .enumerate()
    {
        let genesis: Genesis = serde_json::from_value(case["genesis"].clone())?;
        let batch = hex::decode(
            case["batch"]
                .as_str()
                .ok_or("batch")?
                .strip_prefix("0x")
                .ok_or("hex prefix")?,
        )?;
        let domain = Domain {
            ckb_genesis: [1; 32],
            ordering_type_hash: [2; 32],
            settlement_type_hash: [3; 32],
            rollup_id: genesis.rollup_id.0,
            chain_id: genesis.chain_id,
        };
        let allocation = genesis.allocation_bytes()?;
        let mut full = Executor::new(&genesis)?;
        let headers = vec![full.head().clone()];
        let db = SparseDb::from_complete(&full, headers.clone())?;
        let mut discovery = full.clone().with_backend(db)?;
        let blocks = full.apply_batch(&batch)?;
        assert_eq!(
            discovery.apply_batch(&batch)?,
            blocks,
            "full/sparse blocks in case {index}"
        );
        let geth = case["geth"].as_array().ok_or("Geth oracle")?;
        assert_eq!(blocks.len(), geth.len());
        for (block, oracle) in blocks.iter().zip(geth) {
            for (actual, field) in [
                (block.header.state_root, "stateRoot"),
                (block.header.transactions_root, "txRoot"),
                (block.header.receipts_root, "receiptsRoot"),
            ] {
                assert_eq!(
                    actual.to_string(),
                    oracle[field].as_str().ok_or("Geth root")?,
                    "case {index}: {field}"
                );
            }
            assert_eq!(
                format!("0x{:x}", block.header.gas_used),
                oracle["gasUsed"].as_str().ok_or("Geth gas")?
            );
            assert_eq!(
                block.header.logs_bloom.to_string(),
                oracle["logsBloom"].as_str().ok_or("Geth bloom")?
            );
        }
        let witness = discovery.backend().required_witness(headers);
        let witness_bytes = witness.encode()?;
        let expected = SparseJournal {
            transition: execute(domain.clone(), &allocation, 0, 1, || batch.clone())
                .map_err(|e| format!("{e:?}"))?,
        };
        let checked =
            sparse::execute_genesis(domain.clone(), &allocation, &witness_bytes, 1, || {
                batch.clone()
            })
            .map_err(|e| format!("{e:?}"))?;
        assert_eq!(checked, expected, "pruned witness case {index}");
        fs::write(out.join(format!("{index}.witness.bin")), &witness_bytes)?;
        fs::write(out.join(format!("{index}.expected.bin")), expected.encode())?;
        let mut row = serde_json::json!({"case":case["name"],"index":index,"blocks":blocks.len(),
            "geth_state_transaction_receipt_roots_gas_bloom_match":true,
            "full_sparse_block_outputs_match":true,"pruned_witness_journal_match":true,
            "witness_encoding":"TO1WIT01","witness_bytes":witness_bytes.len(),"witness_nodes":witness.nodes.len(),"witness_codes":witness.codes.len(),
            "allocation_bytes":allocation.len(),"guest_executed":false,"proof_generated":false});
        if let Some(prover) = &prover {
            let mut stdin = SP1Stdin::new();
            stdin.write_vec(domain.encode().to_vec());
            stdin.write(&0u8);
            stdin.write_vec(allocation);
            stdin.write_vec(witness_bytes);
            stdin.write(&1u64);
            stdin.write_vec(batch);
            let started = Instant::now();
            let (public, report) = prover
                .execute(Elf::from(fs::read(&args[3])?), stdin)
                .await?;
            assert_eq!(report.exit_code, 0);
            assert_eq!(public.as_slice(), expected.encode());
            row["guest_executed"] = true.into();
            row["instructions"] = report.total_instruction_count().into();
            row["execution_seconds"] = started.elapsed().as_secs_f64().into();
            row["crypto_syscalls"] = serde_json::json!(report
                .syscall_counts
                .iter()
                .filter(|(_, n)| **n > 0)
                .map(|(code, n)| (format!("{code:?}"), *n))
                .collect::<std::collections::BTreeMap<_, _>>());
            fs::write(
                out.join(format!("{index}.report.txt")),
                format!("{report:?}\n"),
            )?;
        }
        println!(
            "{}: complete, sparse and Geth match; witness {} nodes",
            case["name"],
            witness.nodes.len()
        );
        rows.push(row);
        fs::write(out.join("results.json"), serde_json::to_vec_pretty(&rows)?)?;
    }
    Ok(())
}
