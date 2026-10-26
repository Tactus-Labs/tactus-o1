mod common;
use tactus_o1_protocol::v02::{Error as WireError, Journal, Wire};
use tactus_v02_proof_journal::{execute, Error, Frame};
fn run(f: &common::Fixture, prefix: u64, end: usize) -> Result<Journal, Error> {
    let mut frames = f.frames[..end].iter();
    execute(
        f.config.clone(),
        f.policy.clone(),
        &f.allocation,
        prefix,
        end as u64 - prefix,
        || {
            frames
                .next()
                .map(|f| f.encode().unwrap())
                .ok_or(Error::MissingInput)
        },
    )
}
#[test]
fn full_and_continuation_replay_agree_with_equal_time_and_both_mandatory_prefixes() {
    let f = common::fixture([13; 32]);
    let complete = run(&f, 0, 8).unwrap();
    let first = run(&f, 0, 4).unwrap();
    let second = run(&f, 4, 8).unwrap();
    assert_eq!(first.end, second.start);
    assert_eq!(second.end, complete.end);
    assert_eq!(complete.end, f.end);
    assert_eq!(complete.end.boundary.processed, [8; 4]);
    assert_eq!(complete.end.boundary.deposits.count, 32);
    assert_eq!(complete.end.supply, 3200);
    assert_eq!(complete.end.burned, 0);
    assert_eq!(first.end.boundary.timestamp, second.end.boundary.timestamp);
    assert_ne!(complete.outcomes, second.outcomes);
    assert_ne!(complete.interval_inputs, second.interval_inputs);
    assert_eq!(
        Journal::decode(&complete.encode().unwrap()).unwrap(),
        complete
    );
}
#[test]
fn missing_out_of_order_or_changed_inputs_are_fatal_not_transaction_rejections() {
    let f = common::fixture([13; 32]);
    assert_eq!(
        execute(
            f.config.clone(),
            f.policy.clone(),
            &f.allocation,
            0,
            1,
            || Err(Error::MissingInput)
        ),
        Err(Error::MissingInput)
    );
    let mut bad = f.frames[0].clone();
    bad.batch.deposits.remove(0);
    assert!(execute(
        f.config.clone(),
        f.policy.clone(),
        &f.allocation,
        0,
        1,
        || Ok(bad.encode().unwrap())
    )
    .is_err());
    let mut bad = f.frames[0].clone();
    bad.batch.priority.remove(0);
    assert!(execute(
        f.config.clone(),
        f.policy.clone(),
        &f.allocation,
        0,
        1,
        || Ok(bad.encode().unwrap())
    )
    .is_err());
    assert!(execute(
        f.config.clone(),
        f.policy.clone(),
        &f.allocation,
        0,
        1,
        || Ok(f.frames[1].encode().unwrap())
    )
    .is_err());
    let mut bad = f.frames[0].clone();
    bad.snapshot.lanes[0].messages[0].payload[0] ^= 1;
    assert!(bad.encode().is_err());
}
#[test]
fn wrong_allocation_profile_and_ranges_fail_without_producing_a_journal() {
    let f = common::fixture([13; 32]);
    let mut calls = 0;
    for (prefix, interval) in [(0, 0), (0, 33), (u64::MAX, 1)] {
        assert_eq!(
            execute(
                f.config.clone(),
                f.policy.clone(),
                &f.allocation,
                prefix,
                interval,
                || {
                    calls += 1;
                    Err(Error::MissingInput)
                }
            ),
            Err(Error::Range)
        );
    }
    assert_eq!(calls, 0);
    let mut allocation = f.allocation.clone();
    allocation[0] ^= 1;
    assert_eq!(
        execute(
            f.config.clone(),
            f.policy.clone(),
            &allocation,
            0,
            1,
            || Err(Error::MissingInput)
        ),
        Err(Error::Allocation)
    );
    let mut policy = f.policy.clone();
    policy.rules[0] ^= 1;
    let mut config = f.config.clone();
    config.policy = policy.commitment().unwrap();
    assert!(matches!(
        execute(config, policy, &f.allocation, 0, 1, || Err(
            Error::MissingInput
        )),
        Err(Error::Execution(_))
    ));
}
#[test]
fn private_frame_lengths_and_exact_consumption_are_bounded() {
    let f = common::fixture([13; 32]);
    let bytes = f.frames[0].encode().unwrap();
    assert_eq!(Frame::decode(&bytes).unwrap(), f.frames[0]);
    let mut bad = bytes.clone();
    bad[8..12].copy_from_slice(&u32::MAX.to_le_bytes());
    assert_eq!(Frame::decode(&bad), Err(WireError::Limit));
    let mut bad = bytes.clone();
    bad.push(0);
    assert_eq!(Frame::decode(&bad), Err(WireError::Encoding));
    for cut in [0, 7, 8, 11, bytes.len() - 1] {
        assert!(Frame::decode(&bytes[..cut]).is_err());
    }
}

#[test]
fn independent_python_frame_matches_nested_objects() {
    use tactus_o1_protocol::v02::{NativeBatch, Snapshot};
    let vector = |name: &str| -> Vec<u8> {
        let hex = include_str!("../../../../specs/test-vectors/v02.txt")
            .lines()
            .find_map(|line| line.strip_prefix(&format!("{name}=")))
            .unwrap();
        hex.as_bytes()
            .chunks_exact(2)
            .map(|b| u8::from_str_radix(core::str::from_utf8(b).unwrap(), 16).unwrap())
            .collect()
    };
    let expected = Frame {
        snapshot: Snapshot::decode(&vector("snapshot")).unwrap(),
        batch: NativeBatch::decode(&vector("batch")).unwrap(),
    };
    let bytes = vector("frame");
    assert_eq!(Frame::decode(&bytes).unwrap(), expected);
    assert_eq!(expected.encode().unwrap(), bytes);
    for end in 0..bytes.len() {
        assert!(Frame::decode(&bytes[..end]).is_err());
    }
}
