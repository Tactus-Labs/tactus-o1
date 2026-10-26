//! Synthetic mixed EVM workload export; never deployment or settlement evidence.
#[path = "../../../../crates/tactus-o1-execution/tests/common/v02.rs"]
mod common;
use serde_json::{json, Value};
use std::{
    fs,
    io::{Read, Write},
};
use tactus_o1_devnet_driver::rpc;
use tactus_o1_execution::{v02::V02Executor, Status};
use tactus_o1_protocol::v02::Wire;
use tactus_v02_lab::{err, hash32, Result};
use tactus_v02_proof_journal::{self as journal, Frame};
fn main() {
    if let Err(e) = run() {
        eprintln!("{e}");
        std::process::exit(1);
    }
}
fn run() -> Result<()> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 3 {
        return Err("usage: mixed-input-v02 QUALIFIED_KEY_RECORD NEW_INPUT_JSON".into());
    }
    let mut bytes = Vec::new();
    fs::File::open(&args[1])
        .map_err(err)?
        .take(1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(err)?;
    if bytes.len() > 1024 * 1024 {
        return Err("key record limit".into());
    }
    let record: Value = serde_json::from_slice(&bytes).map_err(err)?;
    let (genesis, mut config, mut policy) = common::fixture();
    policy.guest_key = hash32(&record["guest_key"])?;
    policy.wrapper_key_hash = tactus_v02_script::adapter::wrapper_key_hash();
    config.policy = policy.commitment().map_err(err)?;
    let mut engine = V02Executor::new(&genesis, config.clone(), policy.clone()).map_err(err)?;
    let (batch, snapshot) = common::mixed(&engine);
    let result = engine
        .apply_batch(&batch.encode().map_err(err)?, &snapshot)
        .map_err(err)?;
    let block = &result.blocks[0];
    let statuses: Vec<_> = block.outcomes.iter().map(|o| o.status).collect();
    if statuses
        != [
            Status::Halt,
            Status::Success,
            Status::PriorityGasLimit,
            Status::Success,
            Status::BlockGas,
            Status::Malformed,
            Status::InvalidTransaction,
            Status::WrongChain,
            Status::Success,
            Status::Revert,
            Status::InvalidSignature,
        ]
        || block.receipts.len() != 5
        || engine.account(common::sender()).ok_or("sender")?.nonce != 5
    {
        return Err("mixed workload outcome mismatch".into());
    }
    let frame = Frame { batch, snapshot }.encode().map_err(err)?;
    let allocation = genesis.allocation_bytes().map_err(err)?;
    let mut input = Some(frame.clone());
    let expected = journal::execute(config.clone(), policy.clone(), &allocation, 0, 1, || {
        input.take().ok_or(journal::Error::MissingInput)
    })
    .map_err(err)?;
    if expected.end != engine.control_candidate().map_err(err)? {
        return Err("native journal endpoint mismatch".into());
    }
    let value = json!({"schema":"tactus-v02-proof-input-v1","source":"synthetic-mixed-evm-execution-fixture","authenticated_publication":false,
        "config_hex":rpc::bytes_to_hex(&config.encode().map_err(err)?),"policy_hex":rpc::bytes_to_hex(&policy.encode().map_err(err)?),
        "allocation_hex":rpc::bytes_to_hex(&allocation),"prefix_batches":0,"frames":[rpc::bytes_to_hex(&frame)],"expected_journal_hex":rpc::bytes_to_hex(&expected.encode().map_err(err)?),
        "workload":{"statuses":statuses,"receipt_count":block.receipts.len(),"sender_nonce":5,"priority_halt_gas":block.outcomes[0].gas_used,
            "gas_used":block.header.gas_used,"credited_shannons":expected.end.boundary.deposits.cumulative.to_string(),"supply_shannons":expected.end.supply.to_string(),"burned_shannons":expected.end.burned.to_string()},
        "proof_generated":false});
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&args[2])
        .map_err(err)?;
    file.write_all(&serde_json::to_vec_pretty(&value).map_err(err)?)
        .map_err(err)?;
    println!("exported synthetic mixed workload; no guest execution or proof");
    Ok(())
}
