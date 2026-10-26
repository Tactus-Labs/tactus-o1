use super::*;
use crate::batch::BlockInput;
use alloc::vec;
use alloc::vec::Vec;

fn fixture() -> (Config, Policy, Control, Vault) {
    let policy = Policy {
        lanes: 4,
        max_pending_batches: 32,
        max_pending_deposits: 32,
        stall_blocks: 120,
        priority_gas: 250_000,
        credit_gas: 200_000,
        rules: [1; 32],
        profile: [2; 32],
        guest_key: [3; 32],
        wrapper_key_hash: [4; 32],
        bridge_code_hash: [5; 32],
    };
    let config = Config {
        domain: Config::domain_id(&[6; 44], 0),
        ckb_genesis: [7; 32],
        adapter_code_hash: [8; 32],
        head_lock_code_hash: [9; 32],
        policy: policy.commitment().unwrap(),
        allocation: [10; 32],
        chain: 71402,
        bridge: [11; 20],
    };
    let control = Control::genesis(&config, &policy).unwrap();
    let vault = Vault {
        config: config.commitment().unwrap(),
        reserve: 1000,
        deposits: control.boundary.deposits,
        released: 0,
        refunded: 0,
        escaped: 0,
        claims: [[12; 32], [13; 32], [14; 32]],
    };
    (config, policy, control, vault)
}

fn proven(start: &Control) -> Control {
    let mut next = start.clone();
    next.initialized = true;
    next.boundary.batches += 1;
    next.boundary.blocks += 1;
    next.boundary.inputs = [15; 32];
    next.boundary.epoch = 1;
    next.boundary.epoch_batches = 1;
    next.boundary.snapshot = [16; 32];
    next.state_root = [17; 32];
    next.block_hash = [18; 32];
    next
}
fn journal(start: &Control, end: &Control) -> Journal {
    Journal {
        start: start.clone(),
        end: end.clone(),
        outcomes: [19; 32],
        interval_inputs: [20; 32],
    }
}
fn watch(control: &Control, work: Work) -> Watch {
    Watch {
        config: control.boundary.config,
        work,
        source: [21; 36],
        observed_control: control.commitment().unwrap(),
        refund_lock: [22; 32],
    }
}

fn exact<T: Wire + PartialEq + core::fmt::Debug>(value: T) {
    let bytes = value.encode().unwrap();
    assert_eq!(bytes.len(), T::MAX_BYTES);
    assert_eq!(T::decode(&bytes).unwrap(), value);
    for length in 0..bytes.len() {
        assert!(T::decode(&bytes[..length]).is_err());
    }
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(T::decode(&trailing).is_err());
    let mut wrong_tag = bytes;
    wrong_tag[0] ^= 1;
    assert!(T::decode(&wrong_tag).is_err());
}

#[test]
fn versioned_objects_reject_truncation_and_alternate_interpretations() {
    let (config, policy, control, vault) = fixture();
    let (_, receipt) = vault
        .deposit(&config, &policy, &control, [23; 20], 7, [24; 32])
        .unwrap();
    exact(config);
    exact(policy);
    exact(control.boundary.clone());
    exact(vault);
    exact(receipt);
    exact(watch(&control, Work::Deposit(1)));
    exact(journal(&control, &proven(&control)));
    exact(control);
}

#[test]
fn bounded_reader_rejects_lengths_before_reading_or_allocating() {
    let bytes = u32::MAX.to_le_bytes();
    assert_eq!(
        Reader::new(&bytes, 4).unwrap().blob(1024),
        Err(Error::Limit)
    );
    assert!(Reader::new(&[0; 5], 4).is_err());
    assert_eq!(
        Reader::new(&[], 0).unwrap().take(usize::MAX),
        Err(Error::Encoding)
    );
    assert!(Operation::try_from(255).is_err());
    assert!(Role::try_from(255).is_err());
    let (_, _, control, _) = fixture();
    let mut bytes = control.encode().unwrap();
    bytes[9] = 2;
    assert_eq!(Control::decode(&bytes), Err(Error::Encoding));
}

#[test]
fn policy_and_genesis_domains_cannot_be_substituted() {
    let (config, mut policy, control, _) = fixture();
    assert_ne!(
        Config::domain_id(&[6; 44], 0),
        Config::domain_id(&[6; 44], 1)
    );
    assert_ne!(
        config.args(Role::Control, 0).unwrap(),
        config.args(Role::Vault, 0).unwrap()
    );
    policy.guest_key[0] ^= 1;
    assert_eq!(control.bind(&config, &policy), Err(Error::Domain));
    let mut bad = control.clone();
    bad.boundary.deposits.accumulator[0] ^= 1;
    assert!(bad.validate().is_err());
    let mut config2 = config;
    config2.chain += 1;
    assert_ne!(config2.commitment().unwrap(), control.boundary.config);
}

#[test]
fn equal_time_settlement_progress_is_valid_but_heartbeat_is_not() {
    let (_, _, start, _) = fixture();
    let first = proven(&start);
    let second = proven(&first);
    let j = journal(&first, &second);
    assert_eq!(
        first.settlement_candidate(&j, &second.boundary).unwrap(),
        second
    );
    assert!(journal(&first, &first).validate().is_err());
    let mut later = first.clone();
    later.boundary.timestamp = 100;
    assert_eq!(journal(&later, &second).validate(), Err(Error::Continuity));
    let mut wrong = j.clone();
    wrong.end.profile[0] ^= 1;
    assert_eq!(wrong.validate(), Err(Error::Domain));
    let mut wrong_endpoint = second.boundary.clone();
    wrong_endpoint.inputs[0] ^= 1;
    assert!(first.settlement_candidate(&j, &wrong_endpoint).is_err());
}

#[test]
fn time_binding_rejects_wrong_metric_reserved_bits_and_milliseconds() {
    let seconds = 1_800_000_000;
    assert!(absolute_timestamp((0x40 << 56) | seconds, seconds).is_ok());
    for since in [
        seconds,
        (0xc0 << 56) | seconds,
        (0x41 << 56) | seconds,
        (0x40 << 56) | (seconds * 1000),
        (0x40 << 56) | (seconds - 1),
    ] {
        assert_eq!(absolute_timestamp(since, seconds), Err(Error::Maturity));
    }
    assert_eq!(absolute_timestamp(0, 1 << 56), Err(Error::Maturity));
}

#[test]
fn independent_freeze_timers_require_exact_relative_block_metric() {
    let (_, policy, control, _) = fixture();
    let ticket = watch(&control, Work::Deposit(1));
    let mature = (0x80 << 56) | 120;
    assert_eq!(
        control
            .freeze_candidate(&ticket, &policy, mature, mature)
            .unwrap()
            .mode,
        Mode::Frozen
    );
    for bad in [
        0,
        120,
        (0x80 << 56) | 119,
        (0xa0 << 56) | 120,
        (0xc0 << 56) | 120,
        (0x81 << 56) | 120,
    ] {
        assert_eq!(
            control.freeze_candidate(&ticket, &policy, bad, mature),
            Err(Error::Maturity)
        );
        assert_eq!(
            control.freeze_candidate(&ticket, &policy, mature, bad),
            Err(Error::Maturity)
        );
    }
}

#[test]
fn settled_work_cannot_freeze_and_frozen_state_cannot_settle() {
    let (_, policy, control, _) = fixture();
    let ticket = watch(&control, Work::Batch(1));
    let settled = proven(&control);
    let mature = (0x80 << 56) | 120;
    assert_eq!(
        settled.freeze_candidate(&ticket, &policy, mature, mature),
        Err(Error::Duty)
    );
    assert!(ticket.close_allowed(&settled, &policy).is_ok());
    let frozen = control
        .freeze_candidate(&ticket, &policy, mature, mature)
        .unwrap();
    assert_eq!(
        frozen.settlement_candidate(&journal(&control, &settled), &settled.boundary),
        Err(Error::Mode)
    );
    assert!(ticket.close_allowed(&frozen, &policy).is_ok());
    assert_eq!(ticket.close_allowed(&control, &policy), Err(Error::Duty));
}

#[test]
fn lane_zero_and_deposit_one_both_remain_pending_at_genesis() {
    let (_, _, control, _) = fixture();
    assert!(Work::admission(0, 0)
        .unwrap()
        .pending(&control.boundary, 4)
        .unwrap());
    assert!(Work::Deposit(1).pending(&control.boundary, 4).unwrap());
    let mut next = proven(&control).boundary;
    next.processed[0] = 1;
    next.deposits = DepositCursor {
        count: 1,
        cumulative: 1,
        accumulator: [25; 32],
    };
    assert!(!Work::admission(0, 0).unwrap().pending(&next, 4).unwrap());
    assert!(!Work::Deposit(1).pending(&next, 4).unwrap());
    assert!(Work::admission(0, 1).unwrap().pending(&next, 4).unwrap());
    assert!(Work::Deposit(2).pending(&next, 4).unwrap());
    assert!(Work::admission(4, 0).is_err());
    assert!(Work::admission(0, u64::MAX).is_err());
    assert!(Work::Deposit(0).validate().is_err());
}

#[test]
fn deposit_backpressure_is_exact_and_does_not_disable_freeze() {
    let (config, policy, control, mut vault) = fixture();
    let mut receipts = Vec::new();
    for _ in 0..32 {
        let (next, receipt) = vault
            .deposit(&config, &policy, &control, [23; 20], 7, [24; 32])
            .unwrap();
        assert_eq!(receipt.sequence, vault.deposits.count + 1);
        vault = next;
        receipts.push(receipt);
    }
    assert_eq!(
        vault.deposit(&config, &policy, &control, [23; 20], 7, [24; 32]),
        Err(Error::Limit)
    );
    let mature = (0x80 << 56) | policy.stall_blocks;
    let frozen = control
        .freeze_candidate(&watch(&control, Work::Deposit(1)), &policy, mature, mature)
        .unwrap();
    assert_eq!(vault.partitions(&frozen).unwrap(), [224, 0, 0]);
    let paid = vault
        .claim_accounting(&frozen, ClaimKind::Refund, 7, [26; 32])
        .unwrap();
    assert_eq!(paid.capacity().unwrap(), vault.capacity().unwrap() - 7);
    assert!(vault
        .deposit(&config, &policy, &frozen, [23; 20], 7, [24; 32])
        .is_err());
    let mut bad = receipts[0].clone();
    bad.refund_lock[0] ^= 1;
    assert_ne!(bad.commitment().unwrap(), receipts[0].commitment().unwrap());
    assert!(control.boundary.deposits.follow(&receipts[1]).is_err());
}

#[test]
fn batch_backpressure_does_not_require_a_live_anchor_to_settle() {
    let (_, policy, control, _) = fixture();
    let mut anchor = proven(&control).boundary;
    anchor.batches = 31;
    anchor.blocks = 31;
    assert!(anchor.append_allowed(&control, &policy).is_ok());
    anchor.batches = 32;
    anchor.blocks = 32;
    assert_eq!(anchor.append_allowed(&control, &policy), Err(Error::Limit));
    let first = proven(&control);
    let settled = control
        .settlement_candidate(&journal(&control, &first), &first.boundary)
        .unwrap();
    assert!(anchor.append_allowed(&settled, &policy).is_ok());
    let mut future_control = settled;
    future_control.boundary.batches = 33;
    future_control.boundary.blocks = 33;
    assert!(anchor.append_allowed(&future_control, &policy).is_err());
}

#[test]
fn custody_partitions_preserve_burns_and_exclude_preproof_escape() {
    let (config, policy, control, vault) = fixture();
    let (vault, _) = vault
        .deposit(&config, &policy, &control, [23; 20], 100, [24; 32])
        .unwrap();
    assert_eq!(
        vault.claim_accounting(&control, ClaimKind::Refund, 1, [26; 32]),
        Err(Error::Mode)
    );
    let mut frozen = control.clone();
    frozen.mode = Mode::Frozen;
    assert_eq!(
        vault.claim_accounting(&frozen, ClaimKind::Escape, 1, [26; 32]),
        Err(Error::Proof)
    );
    let mut settled = proven(&control);
    settled.boundary.deposits = vault.deposits;
    settled.supply = 70;
    settled.burned = 30;
    assert_eq!(vault.partitions(&settled).unwrap(), [0, 70, 30]);
    let paid = vault
        .claim_accounting(&settled, ClaimKind::Release, 10, [26; 32])
        .unwrap();
    settled.mode = Mode::Frozen;
    let escaped = paid
        .claim_accounting(&settled, ClaimKind::Escape, 70, [27; 32])
        .unwrap();
    assert_eq!(escaped.partitions(&settled).unwrap(), [0, 0, 20]);
    assert!(escaped
        .claim_accounting(&settled, ClaimKind::Escape, 1, [28; 32])
        .is_err());
    assert!(escaped
        .claim_accounting(&settled, ClaimKind::Refund, 1, [28; 32])
        .is_err());
    let final_vault = escaped
        .claim_accounting(&settled, ClaimKind::Release, 20, [28; 32])
        .unwrap();
    assert_eq!(final_vault.capacity().unwrap(), final_vault.reserve);
}

#[test]
fn capacity_limit_reserves_room_for_all_uncredited_supply() {
    let (config, policy, control, vault) = fixture();
    let amount = u64::MAX - vault.reserve;
    let (full, _) = vault
        .deposit(&config, &policy, &control, [23; 20], amount, [24; 32])
        .unwrap();
    assert_eq!(full.capacity().unwrap(), u64::MAX);
    assert_eq!(
        full.deposit(&config, &policy, &control, [23; 20], 1, [24; 32]),
        Err(Error::Arithmetic)
    );
    assert!(vault
        .deposit(&config, &policy, &control, config.bridge, 1, [24; 32])
        .is_err());
    assert!(vault
        .deposit(&config, &policy, &control, [23; 20], 0, [24; 32])
        .is_err());
    assert!(vault
        .deposit(&config, &policy, &control, [23; 20], 1, [0; 32])
        .is_err());
}

fn sealed_fixture(
    occupancy: [usize; 4],
    deposits: usize,
) -> (
    Config,
    Policy,
    Control,
    Vault,
    Schedule,
    Snapshot,
    Vec<Lane>,
    Vec<Deposit>,
) {
    let (config, policy, control, mut vault) = fixture();
    let mut receipts = Vec::new();
    for _ in 0..deposits {
        let (next, receipt) = vault
            .deposit(&config, &policy, &control, [23; 20], 7, [24; 32])
            .unwrap();
        vault = next;
        receipts.push(receipt);
    }
    let mut lanes = Vec::new();
    for (lane, count) in occupancy.into_iter().enumerate() {
        let mut value = Lane::genesis(control.boundary.config, lane as u8).unwrap();
        for sequence in 0..count {
            let (next, receipt) = value
                .enqueue(&control, &policy, vec![lane as u8 + 1, sequence as u8])
                .unwrap();
            assert_eq!(receipt.sequence, sequence as u64);
            exact(receipt);
            value = next;
        }
        lanes.push(value);
    }
    let (schedule, snapshot, cleared) = Schedule::genesis(control.boundary.config)
        .unwrap()
        .seal(
            &config,
            &policy,
            &control,
            &control.boundary,
            &lanes,
            &vault,
            None,
        )
        .unwrap();
    (
        config, policy, control, vault, schedule, snapshot, cleared, receipts,
    )
}
fn next_batch(
    parent: &Boundary,
    schedule: &Schedule,
    snapshot: &Snapshot,
    receipts: &[Deposit],
) -> NativeBatch {
    let users = snapshot.users().unwrap();
    let start = usize::from(schedule.user_cursor);
    let priority = users[start..(start + DUTY).min(users.len())].to_vec();
    let start = usize::from(schedule.deposit_cursor);
    NativeBatch {
        parent: parent.clone(),
        snapshot: schedule.snapshot,
        deposits: receipts[start..(start + DUTY).min(receipts.len())].to_vec(),
        blocks: vec![BlockInput {
            timestamp: 100,
            fee_recipient: [29; 20],
            transactions: priority
                .iter()
                .map(|entry| entry.message.payload.clone())
                .collect(),
        }],
        priority,
    }
}

#[test]
fn seal_authenticates_all_lanes_and_drains_two_independent_full_queues() {
    let (config, policy, control, vault, mut schedule, snapshot, cleared, receipts) =
        sealed_fixture([8; 4], 32);
    assert_eq!(snapshot.users().unwrap().len(), 32);
    assert!(cleared
        .iter()
        .all(|lane| lane.messages.is_empty() && lane.next == 8 && lane.epoch == 1));
    let base = Schedule::genesis(control.boundary.config).unwrap();
    assert!(base
        .seal(
            &config,
            &policy,
            &control,
            &control.boundary,
            &snapshot.lanes[..3],
            &vault,
            None
        )
        .is_err());
    let mut wrong = snapshot.lanes.clone();
    wrong.swap(0, 1);
    assert!(base
        .seal(
            &config,
            &policy,
            &control,
            &control.boundary,
            &wrong,
            &vault,
            None
        )
        .is_err());
    let mut anchor = control.boundary.clone();
    for round in 0..8 {
        let input = next_batch(&anchor, &schedule, &snapshot, &receipts);
        assert_eq!(
            NativeBatch::decode(&input.encode().unwrap()).unwrap(),
            input
        );
        let (next, updated) = input
            .append(
                &config,
                &policy,
                &control,
                &schedule,
                &snapshot,
                (0x40 << 56) | 100,
            )
            .unwrap();
        assert_eq!(next.deposits.count, (round + 1) * 4);
        assert_eq!(next.processed, [round + 1; 4]);
        assert_eq!(next.epoch_batches, round as u8 + 1);
        anchor = next;
        schedule = updated;
        if round < 7 {
            assert!(schedule
                .seal(
                    &config,
                    &policy,
                    &control,
                    &anchor,
                    &cleared,
                    &vault,
                    Some(&snapshot)
                )
                .is_err());
        }
    }
    let (next, second, _) = schedule
        .seal(
            &config,
            &policy,
            &control,
            &anchor,
            &cleared,
            &vault,
            Some(&snapshot),
        )
        .unwrap();
    assert_eq!(next.epoch, 2);
    assert!(second.users().unwrap().is_empty());
    assert_eq!(second.deposit_start, second.deposit_end);
    assert!(next_batch(&anchor, &schedule, &snapshot, &receipts)
        .append(
            &config,
            &policy,
            &control,
            &schedule,
            &snapshot,
            (0x40 << 56) | 100
        )
        .is_err());
    assert!(second.commitment().unwrap() != snapshot.commitment().unwrap());
}

#[test]
fn publication_cannot_skip_either_duty_or_move_users_to_another_block() {
    let (config, policy, control, _, schedule, snapshot, _, receipts) = sealed_fixture([2; 4], 5);
    let input = next_batch(&control.boundary, &schedule, &snapshot, &receipts);
    let check = |input: &NativeBatch| {
        input.append(
            &config,
            &policy,
            &control,
            &schedule,
            &snapshot,
            (0x40 << 56) | 100,
        )
    };
    assert!(check(&input).is_ok());
    let mut bad = input.clone();
    bad.deposits.pop();
    assert_eq!(check(&bad), Err(Error::Duty));
    let mut bad = input.clone();
    bad.priority.pop();
    bad.blocks[0].transactions.pop();
    assert_eq!(check(&bad), Err(Error::Duty));
    let mut bad = input.clone();
    bad.deposits.swap(0, 1);
    assert!(check(&bad).is_err());
    let mut bad = input.clone();
    bad.priority[0].message.sequence += 1;
    assert_eq!(check(&bad), Err(Error::Duty));
    let mut bad = input.clone();
    bad.blocks.insert(
        0,
        BlockInput {
            timestamp: 100,
            fee_recipient: [29; 20],
            transactions: vec![],
        },
    );
    assert_eq!(check(&bad), Err(Error::Duty));
    let mut bad = input.clone();
    bad.snapshot[0] ^= 1;
    assert_eq!(check(&bad), Err(Error::Domain));
    let mut bad = input;
    bad.deposits[0].config[0] ^= 1;
    assert_eq!(check(&bad), Err(Error::Domain));
}

#[test]
fn postseal_deposit_and_admission_do_not_modify_frozen_snapshot() {
    let (config, policy, control, vault, schedule, snapshot, mut lanes, receipts) =
        sealed_fixture([1, 0, 0, 0], 1);
    let bytes = snapshot.encode().unwrap();
    let (later_vault, receipt) = vault
        .deposit(&config, &policy, &control, [23; 20], 7, [24; 32])
        .unwrap();
    lanes[0] = lanes[0].enqueue(&control, &policy, vec![42]).unwrap().0;
    assert_eq!(snapshot.encode().unwrap(), bytes);
    assert_eq!(receipt.sequence, 2);
    let mut batch = next_batch(&control.boundary, &schedule, &snapshot, &receipts);
    batch.deposits.push(receipt);
    assert_eq!(
        batch.append(
            &config,
            &policy,
            &control,
            &schedule,
            &snapshot,
            (0x40 << 56) | 100
        ),
        Err(Error::Duty)
    );
    assert_eq!(later_vault.deposits.count, 2);
    assert_eq!(lanes[0].messages[0].sequence, 1);
}

#[test]
fn asymmetric_lane_occupancies_preserve_fifo_and_drain_within_eight_batches() {
    for encoded in 0..81 {
        let mut n = encoded;
        let mut counts = [0; 4];
        for count in &mut counts {
            *count = [0, 1, 8][n % 3];
            n /= 3;
        }
        let (config, policy, control, _, mut schedule, snapshot, _, receipts) =
            sealed_fixture(counts, encoded % 33);
        let mut anchor = control.boundary.clone();
        let mut seen = [0u64; 4];
        for _ in 0..8 {
            let batch = next_batch(&anchor, &schedule, &snapshot, &receipts);
            for entry in &batch.priority {
                assert_eq!(entry.message.sequence, seen[usize::from(entry.lane)]);
                seen[usize::from(entry.lane)] += 1;
            }
            (anchor, schedule) = batch
                .append(
                    &config,
                    &policy,
                    &control,
                    &schedule,
                    &snapshot,
                    (0x40 << 56) | 100,
                )
                .unwrap();
        }
        assert_eq!(anchor.processed, counts.map(|n| n as u64));
        assert_eq!(anchor.deposits.count, receipts.len() as u64);
        assert_eq!(seen, anchor.processed);
    }
}

#[test]
fn native_batch_whole_envelope_bound_includes_new_metadata() {
    let (_, _, control, _, schedule, snapshot, _, receipts) = sealed_fixture([0; 4], 0);
    let mut batch = next_batch(&control.boundary, &schedule, &snapshot, &receipts);
    let mut remaining = BATCH_BYTES - batch.encode().unwrap().len();
    while remaining > 0 {
        let size = (remaining - 4).min(crate::batch::MAX_TRANSACTION_BYTES);
        batch.blocks[0].transactions.push(vec![1; size]);
        remaining -= size + 4;
    }
    let encoded = batch.encode().unwrap();
    assert_eq!(encoded.len(), BATCH_BYTES);
    assert_eq!(NativeBatch::decode(&encoded).unwrap(), batch);
    batch.blocks[0].transactions.last_mut().unwrap().push(1);
    assert_eq!(batch.encode(), Err(Error::Limit));
}
