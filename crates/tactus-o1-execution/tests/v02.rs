#![cfg(feature = "v02")]
#[path = "common/v02.rs"]
mod common;
use alloy_primitives::Address;
use common::{build, fixture, sender};
use tactus_o1_execution::{
    v02::{self, V02Executor},
    Status,
};
use tactus_o1_protocol::v02::*;

#[test]
fn v02_rules_and_domain_are_distinct_and_allocation_is_bound() {
    let descriptor = [
        include_bytes!("../rules-v02.txt").as_slice(),
        include_bytes!("../rules-v1.txt").as_slice(),
        include_bytes!("../../../Cargo.lock").as_slice(),
        include_bytes!("../../../contracts/bridge/NativeCKB.json").as_slice(),
    ]
    .concat();
    assert_eq!(
        v02::rules_hash(),
        hash(b"tactus/0.02/execution-rules", &descriptor)
    );
    assert_ne!(v02::rules_hash(), tactus_o1_execution::rules_hash());
    assert_ne!(
        v02::rules_hash(),
        tactus_o1_execution::native_bridge::rules_hash()
    );
    let (genesis, mut config, policy) = fixture();
    assert!(V02Executor::new(&genesis, config.clone(), policy.clone()).is_ok());
    config.allocation[0] ^= 1;
    assert!(V02Executor::new(&genesis, config.clone(), policy.clone()).is_err());
    let (genesis, config, mut policy) = fixture();
    policy.credit_gas = 1;
    assert!(policy.commitment().is_err());
    assert!(V02Executor::new(&genesis, config, policy).is_err());
}

#[test]
fn full_priority_slot_cannot_starve_following_withdrawal_and_caps_have_fixed_outcomes() {
    let (genesis, config, policy) = fixture();
    let mut engine = V02Executor::new(&genesis, config.clone(), policy).unwrap();
    let (batch, snapshot) = common::mixed(&engine);
    let executed = engine
        .apply_batch(&batch.encode().unwrap(), &snapshot)
        .unwrap();
    let block = &executed.blocks[0];
    assert_eq!(
        block.outcomes.iter().map(|o| o.status).collect::<Vec<_>>(),
        vec![
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
            Status::InvalidSignature
        ]
    );
    assert_eq!(block.outcomes[0].gas_used, 250000);
    assert_eq!(block.receipts.len(), 5);
    assert_eq!(
        block.header.gas_used,
        block.outcomes.iter().map(|o| o.gas_used).sum::<u64>()
    );
    assert_eq!(executed.deposits.len(), 1);
    assert!(executed.deposits[0].gas_used <= 200000);
    let candidate = engine.control_candidate().unwrap();
    assert_eq!(
        (
            candidate.boundary.deposits.cumulative,
            candidate.supply,
            candidate.burned
        ),
        (100, 93, 7)
    );
    assert_eq!(candidate.boundary.processed, [1; 4]);
    assert_eq!(engine.account(sender()).unwrap().nonce, 5);
}

#[test]
fn equal_time_continuation_preserves_boundary_and_bad_input_cannot_apply_credits() {
    let (genesis, config, policy) = fixture();
    let mut engine = V02Executor::new(&genesis, config, policy).unwrap();
    let (input, snapshot) = build(&engine, vec![], vec![], &[7, 8]);
    let before = engine.head().clone();
    let mut wrong = input.clone();
    wrong.deposits[0].refund_lock[0] ^= 1;
    assert!(engine
        .apply_batch(&wrong.encode().unwrap(), &snapshot)
        .is_err());
    assert_eq!(engine.head(), &before);
    assert_eq!(engine.boundary(), &input.parent);
    engine
        .apply_batch(&input.encode().unwrap(), &snapshot)
        .unwrap();
    let next = NativeBatch {
        parent: engine.boundary().clone(),
        snapshot: input.snapshot,
        priority: vec![],
        deposits: vec![],
        blocks: input.blocks.clone(),
    };
    engine
        .apply_batch(&next.encode().unwrap(), &snapshot)
        .unwrap();
    assert_eq!(engine.head().timestamp, 100);
    assert_eq!(engine.head().number, 2);
    assert_eq!(engine.control_candidate().unwrap().supply, 15);
    let before = engine.head().clone();
    assert!(engine
        .apply_batch(&next.encode().unwrap(), &snapshot)
        .is_err());
    assert_eq!(engine.head(), &before);
}

#[test]
fn four_maximum_total_safe_credits_fit_fixed_system_gas_without_using_user_budget() {
    let (genesis, config, policy) = fixture();
    let mut engine = V02Executor::new(&genesis, config, policy).unwrap();
    let each = (u64::MAX - 1000) / 4;
    let (batch, snapshot) = build(&engine, vec![], vec![], &[each; 4]);
    let executed = engine
        .apply_batch(&batch.encode().unwrap(), &snapshot)
        .unwrap();
    assert_eq!(executed.deposits.len(), 4);
    assert!(executed
        .deposits
        .iter()
        .all(|d| d.gas_used <= 200000 && d.gas_used > 0));
    assert_eq!(
        engine.control_candidate().unwrap().supply,
        u128::from(each) * 4
    );
    assert_eq!(executed.blocks[0].header.gas_used, 0);
    assert!(executed.blocks[0].receipts.is_empty());
}

#[test]
fn late_credit_failure_aborts_earlier_credit_and_never_becomes_user_rejection() {
    let (genesis, config, policy) = fixture();
    let mut engine = V02Executor::new(&genesis, config, policy).unwrap();
    let (mut batch, mut snapshot) = build(&engine, vec![], vec![], &[7, 8]);
    // Host-forged transcript exceeds any admissible funded Vault. It reaches
    // the credit hook here to test failure atomicity, not L1 admission.
    let mut cursor = batch.parent.deposits;
    for (record, amount) in batch.deposits.iter_mut().zip([u64::MAX, 1]) {
        record.amount = amount;
        record.previous = cursor.accumulator;
        record.cumulative = cursor.cumulative + u128::from(amount);
        cursor = cursor.follow(record).unwrap();
    }
    snapshot.deposit_end = cursor;
    batch.snapshot = snapshot.commitment().unwrap();
    let before = engine.head().clone();
    let bridge = engine.account(Address::from(engine.config().bridge));
    assert_eq!(
        engine.apply_batch(&batch.encode().unwrap(), &snapshot),
        Err(v02::V02Error::Credit)
    );
    assert_eq!(engine.head(), &before);
    assert_eq!(engine.boundary(), &batch.parent);
    assert_eq!(
        engine.account(Address::from(engine.config().bridge)),
        bridge
    );
}

#[test]
fn distinct_recipient_credits_fit_budget_and_remain_outside_user_receipts() {
    let (genesis, config, policy) = fixture();
    let mut engine = V02Executor::new(&genesis, config, policy).unwrap();
    let (mut batch, mut snapshot) = build(&engine, vec![], vec![], &[1; 4]);
    let mut cursor = batch.parent.deposits;
    for (index, record) in batch.deposits.iter_mut().enumerate() {
        record.recipient = [index as u8 + 41; 20];
        record.previous = cursor.accumulator;
        cursor = cursor.follow(record).unwrap();
    }
    snapshot.deposit_end = cursor;
    batch.snapshot = snapshot.commitment().unwrap();
    let executed = engine
        .apply_batch(&batch.encode().unwrap(), &snapshot)
        .unwrap();
    assert!(executed.deposits.iter().all(|d| d.gas_used <= 200000));
    assert_eq!(engine.control_candidate().unwrap().supply, 4);
    assert!(executed.blocks[0].receipts.is_empty());
}
