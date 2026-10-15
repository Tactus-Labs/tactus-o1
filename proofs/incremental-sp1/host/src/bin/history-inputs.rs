//! Construct history-length comparisons with identical new transaction bytes.
//! Geth fixtures supply the transaction/state shape, but adjusted environments
//! need independent oracle checks; this generator makes no Geth/proof claims.
use std::{fs, path::Path};
use tactus_o1_execution::{Executor, Genesis};
use tactus_o1_proof_journal::{execute, Domain};
use tactus_o1_protocol::batch::{BatchInput, BlockInput};

fn main() {
    if let Err(e) = run() {
        eprintln!("{e}");
        std::process::exit(1);
    }
}
fn err(e: impl std::fmt::Debug) -> String {
    format!("{e:?}")
}
fn run() -> Result<(), String> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() < 6 {
        return Err("usage: history-inputs GETH_FIXTURE CASE_INDEX BASELINE_GUEST_KEY NEW_OUTPUT_DIR PREFIX_LENGTH...".into());
    }
    let fixture: serde_json::Value =
        serde_json::from_slice(&fs::read(&args[1]).map_err(err)?).map_err(err)?;
    let index: usize = args[2].parse().map_err(err)?;
    let case = fixture["cases"]
        .as_array()
        .ok_or("cases")?
        .get(index)
        .ok_or("case index")?;
    if hex::decode(args[3].strip_prefix("0x").ok_or("key prefix")?)
        .map_err(err)?
        .len()
        != 32
    {
        return Err("key length".into());
    }
    let genesis: Genesis = serde_json::from_value(case["genesis"].clone()).map_err(err)?;
    let original = hex::decode(
        case["batch"]
            .as_str()
            .ok_or("batch")?
            .strip_prefix("0x")
            .ok_or("batch prefix")?,
    )
    .map_err(err)?;
    let engine = Executor::new(&genesis).map_err(err)?;
    let template = BatchInput::decode(&original, engine.anchor()).map_err(err)?;
    let allocation = genesis.allocation_bytes().map_err(err)?;
    let domain = Domain {
        ckb_genesis: [1; 32],
        ordering_type_hash: [2; 32],
        settlement_type_hash: [3; 32],
        rollup_id: genesis.rollup_id.0,
        chain_id: genesis.chain_id,
    };
    let out = Path::new(&args[4]);
    fs::create_dir(out).map_err(err)?;
    let mut rows = Vec::new();
    for value in &args[5..] {
        let prefix: u64 = value.parse().map_err(err)?;
        if prefix > 4096 {
            return Err("experiment prefix limit is 4096".into());
        }
        let mut engine = engine.clone();
        let mut batches = Vec::new();
        for height in 1..=prefix {
            let bytes = BatchInput {
                parent: *engine.anchor(),
                blocks: vec![BlockInput {
                    timestamp: height,
                    fee_recipient: [3; 20],
                    transactions: vec![],
                }],
            }
            .encode()
            .map_err(err)?;
            engine.apply_batch(&bytes).map_err(err)?;
            batches.push(bytes);
        }
        let mut blocks = template.blocks.clone();
        for (offset, block) in blocks.iter_mut().enumerate() {
            block.timestamp = prefix + 1 + offset as u64;
        }
        let interval = BatchInput {
            parent: *engine.anchor(),
            blocks,
        }
        .encode()
        .map_err(err)?;
        engine.apply_batch(&interval).map_err(err)?;
        batches.push(interval);
        let mut iter = batches.iter();
        let expected = execute(domain.clone(), &allocation, prefix, 1, || {
            iter.next().unwrap().clone()
        })
        .map_err(err)?;
        if expected.next_state_root != engine.state_root().0 || expected.after != *engine.anchor() {
            return Err("generated interval mismatch".into());
        }
        let input = serde_json::json!({"schema":1,"domain_hex":format!("0x{}",hex::encode(domain.encode())),
            "allocation_hex":format!("0x{}",hex::encode(&allocation)),"guest_verifying_key":args[3],
            "prefix_batches":prefix,"batches":batches.iter().map(|b|format!("0x{}",hex::encode(b))).collect::<Vec<_>>(),
            "expected_journal_hex":format!("0x{}",hex::encode(expected.encode())),
            "experiment":{"source_case":case["name"],"same_new_transaction_bytes":true,
            "adjusted_environment":true,"geth_checked":false,"frozen_oracle_checked":false,"production_ready":false}});
        let path = out.join(format!("prefix-{prefix}.json"));
        if path.exists() {
            return Err("duplicate prefix/output".into());
        }
        fs::write(&path, serde_json::to_vec_pretty(&input).map_err(err)?).map_err(err)?;
        rows.push(serde_json::json!({"prefix":prefix,"input":path,"interval_batches":1,
            "interval_blocks":template.blocks.len(),"slots":template.blocks.iter().map(|b|b.transactions.len()).sum::<usize>()}));
    }
    fs::write(
        out.join("inputs.json"),
        serde_json::to_vec_pretty(&rows).map_err(err)?,
    )
    .map_err(err)?;
    Ok(())
}
