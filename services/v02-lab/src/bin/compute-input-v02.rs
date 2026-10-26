//! Bounded EVM stress inputs for the existing SP1 guest. No proving or RPC.
// This exporter uses a subset of the shared mixed-workload test helpers.
#[allow(dead_code)]
#[path = "../../../../crates/tactus-o1-execution/tests/common/v02.rs"]
mod common;
use alloy_consensus::{SignableTransaction, TxEip1559, TxEnvelope};
use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::{Address, Bytes, TxKind, U256};
use k256::ecdsa::SigningKey;
use serde_json::{json, Value};
use std::{
    fs,
    io::{Read, Write},
    time::Instant,
};
use tactus_o1_devnet_driver::rpc;
use tactus_o1_execution::{v02::V02Executor, GenesisAccount, Status};
use tactus_o1_protocol::{
    batch::{BlockInput, BLOCK_GAS_LIMIT},
    v02::*,
};
use tactus_v02_lab::{err, hash32, Result};
use tactus_v02_proof_journal::{self as journal, Frame};

fn sign(nonce: u64, target: Address, gas: u64, chain: u64) -> Vec<u8> {
    let tx = TxEip1559 {
        chain_id: chain,
        nonce,
        gas_limit: gas,
        max_fee_per_gas: 100_000_000_000,
        max_priority_fee_per_gas: 1,
        to: TxKind::Call(target),
        ..Default::default()
    };
    let sig = SigningKey::from_bytes((&[0x21; 32]).into())
        .unwrap()
        .sign_prehash_recoverable(tx.signature_hash().as_slice())
        .unwrap()
        .into();
    TxEnvelope::from(tx.into_signed(sig)).encoded_2718()
}
fn main() {
    if let Err(e) = run() {
        eprintln!("{e}");
        std::process::exit(1);
    }
}
fn run() -> Result<()> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 4 || !["loop", "keccak", "signatures", "credits"].contains(&args[1].as_str()) {
        return Err("usage: compute-input-v02 loop|keccak|signatures|credits QUALIFIED_KEY_RECORD NEW_INPUT_JSON".into());
    }
    let mut bytes = vec![];
    fs::File::open(&args[2])
        .map_err(err)?
        .take(1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(err)?;
    if bytes.len() > 1024 * 1024 {
        return Err("key record limit".into());
    }
    let record: Value = serde_json::from_slice(&bytes).map_err(err)?;
    let (mut genesis, mut config, mut policy) = common::fixture();
    policy.guest_key = hash32(&record["guest_key"])?;
    policy.wrapper_key_hash = tactus_v02_script::adapter::wrapper_key_hash();
    config.policy = policy.commitment().map_err(err)?;
    let target = Address::repeat_byte(35);
    let code: &[u8] = if args[1] == "keccak" {
        // JUMPDEST; PUSH1 32; PUSH0; KECCAK256; POP; PUSH0; JUMP.
        &[0x5b, 0x60, 0x20, 0x5f, 0x20, 0x50, 0x5f, 0x56]
    } else {
        // An actual interpreter loop, not the cheap INVALID full-gas charge.
        &[0x5b, 0x5f, 0x56]
    };
    genesis.accounts.insert(
        target,
        GenesisAccount {
            nonce: 1,
            code: Bytes::copy_from_slice(code),
            ..Default::default()
        },
    );
    genesis
        .accounts
        .get_mut(&common::sender())
        .ok_or("sender")?
        .balance = U256::from(u64::MAX);
    let allocation = genesis.allocation_bytes().map_err(err)?;
    config.allocation = tactus_o1_protocol::genesis::commitment(&allocation).map_err(err)?;
    let mut engine = V02Executor::new(&genesis, config.clone(), policy.clone()).map_err(err)?;
    let heavy = args[1] == "loop" || args[1] == "keccak";
    let priority = if heavy {
        (0..4)
            .map(|nonce| sign(nonce, target, policy.priority_gas, config.chain))
            .collect()
    } else {
        vec![]
    };
    let each = (u64::MAX - 1000) / 4;
    let (mut batch, mut snapshot) = common::build(&engine, priority, vec![], &[each; 4]);
    let mut cursor = batch.parent.deposits;
    for (n, record) in batch.deposits.iter_mut().enumerate() {
        record.recipient = [41 + n as u8; 20];
        record.previous = cursor.accumulator;
        cursor = cursor.follow(record).map_err(err)?;
    }
    snapshot.deposit_end = cursor;
    batch.snapshot = snapshot.commitment().map_err(err)?;
    if heavy {
        for n in 0..15 {
            batch.blocks.push(BlockInput {
                timestamp: 100,
                fee_recipient: [29; 20],
                transactions: vec![sign(4 + n, target, BLOCK_GAS_LIMIT, config.chain)],
            });
        }
    } else if args[1] == "signatures" {
        // Every slot has a valid recoverable signature but a wrong nonce. No
        // gas is spent, so all 1,024 slots reach signature/transaction checks.
        let transaction = sign(99, Address::repeat_byte(36), 21000, config.chain);
        batch.blocks = vec![
            BlockInput {
                timestamp: 100,
                fee_recipient: [29; 20],
                transactions: vec![transaction; 64]
            };
            16
        ];
    }
    let started = Instant::now();
    let executed = engine
        .apply_batch(&batch.encode().map_err(err)?, &snapshot)
        .map_err(err)?;
    let execution_ms = started.elapsed().as_millis();
    let statuses: Vec<_> = executed
        .blocks
        .iter()
        .flat_map(|b| b.outcomes.iter().map(|o| o.status))
        .collect();
    let gas: Vec<_> = executed.blocks.iter().map(|b| b.header.gas_used).collect();
    let receipts: usize = executed.blocks.iter().map(|b| b.receipts.len()).sum();
    let nonce = engine.account(common::sender()).ok_or("sender")?.nonce;
    if heavy
        && (gas != vec![BLOCK_GAS_LIMIT; 16]
            || statuses != vec![Status::Halt; 19]
            || receipts != 19
            || nonce != 19)
    {
        return Err(format!("full-gas loop failed: gas={gas:?} statuses={statuses:?} receipts={receipts} nonce={nonce}"));
    }
    if args[1] == "signatures"
        && (statuses != vec![Status::InvalidTransaction; 1024] || receipts != 0 || nonce != 0)
    {
        return Err("signature stress did not verify/reject all slots".into());
    }
    if executed.deposits.len() != 4
        || executed
            .deposits
            .iter()
            .any(|d| d.gas_used > policy.credit_gas)
        || engine.control_candidate().map_err(err)?.supply != u128::from(each) * 4
    {
        return Err("maximum safe distinct-recipient credits failed".into());
    }
    let encoded_batch_size = batch.encode().map_err(err)?.len();
    let frame = Frame { batch, snapshot }.encode().map_err(err)?;
    let mut next_frame = Some(frame.clone());
    let expected = journal::execute(config.clone(), policy.clone(), &allocation, 0, 1, || {
        next_frame.take().ok_or(journal::Error::MissingInput)
    })
    .map_err(err)?;
    if expected.end != engine.control_candidate().map_err(err)? {
        return Err("journal endpoint mismatch".into());
    }
    let value = json!({"schema":"tactus-v02-proof-input-v1","source":"synthetic-evm-computation-envelope","authenticated_publication":false,
        "config_hex":rpc::bytes_to_hex(&config.encode().map_err(err)?),"policy_hex":rpc::bytes_to_hex(&policy.encode().map_err(err)?),
        "allocation_hex":rpc::bytes_to_hex(&allocation),"prefix_batches":0,"frames":[rpc::bytes_to_hex(&frame)],"expected_journal_hex":rpc::bytes_to_hex(&expected.encode().map_err(err)?),
        "workload":{"case":args[1],"encoded_batch_bytes":encoded_batch_size,"blocks":gas.len(),"slots":statuses.len(),"receipts":receipts,"sender_nonce":nonce,
            "gas_per_block":gas,"credit_gas":executed.deposits.iter().map(|d|d.gas_used).collect::<Vec<_>>(),"credited_shannons":expected.end.supply.to_string(),
            "native_single_replay_ms":execution_ms,"scope":"selected stress paths at explicit policy maxima, not an exhaustive upper bound for every EVM opcode/state; native timing excludes journal replay and proving"},"proof_generated":false});
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&args[3])
        .map_err(err)?
        .write_all(&serde_json::to_vec_pretty(&value).map_err(err)?)
        .map_err(err)?;
    println!(
        "exported {} computation fixture; {receipts} receipts; no guest execution or proof",
        args[1]
    );
    Ok(())
}
