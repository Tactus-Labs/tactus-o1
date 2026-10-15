use tactus_o1_protocol::{
    batch::{AnchorState, BatchInput, BlockInput},
    sealed::*,
};
fn schedule(n: u8) -> Schedule {
    Schedule::genesis([1; 32], [2; 32], [3; 32], n).unwrap()
}
fn parent() -> AnchorState {
    AnchorState::genesis([2; 32], [4; 32], 31337).unwrap()
}
fn batch(parent: AnchorState, transactions: Vec<Vec<u8>>) -> Vec<u8> {
    BatchInput {
        parent,
        blocks: vec![BlockInput {
            timestamp: parent.last_timestamp + 1,
            fee_recipient: [0; 20],
            transactions,
        }],
    }
    .encode()
    .unwrap()
}
fn populated(counts: &[usize]) -> Vec<Lane> {
    counts
        .iter()
        .enumerate()
        .map(|(i, n)| {
            let mut lane = Lane::genesis([1; 32], i as u8).unwrap();
            for seq in 0..*n {
                lane = lane.append(vec![i as u8, seq as u8]).unwrap();
            }
            lane
        })
        .collect()
}
fn ready(n: u8) -> Schedule {
    Schedule {
        batches: BATCHES_PER_EPOCH,
        ..schedule(n)
    }
}
#[test]
fn admission_is_positive_bounded_and_preserves_contiguous_history() {
    let mut lane = Lane::genesis([1; 32], 0).unwrap();
    for seq in 0..MAX_LANE_MESSAGES {
        let previous = lane.clone();
        lane = lane.append(vec![seq as u8]).unwrap();
        assert_eq!(&lane.queue[..seq], previous.queue);
        assert_ne!(lane.root, previous.root);
        assert_eq!(lane.next_sequence, seq as u64 + 1);
    }
    assert_eq!(lane.append(vec![9]), Err(Error::Limit));
    assert_eq!(
        Lane::genesis([1; 32], 0).unwrap().append(vec![]),
        Err(Error::Limit)
    );
    let mut corrupt = lane.clone();
    corrupt.queue[0][0] ^= 1;
    assert_eq!(corrupt.validate(), Err(Error::History));
    let mut corrupt = lane;
    corrupt.next_sequence = 0;
    assert_eq!(corrupt.validate(), Err(Error::History));
}
#[test]
fn genesis_has_a_finite_batch_quota_and_sealing_requires_all_lanes() {
    let mut state = schedule(4);
    let mut parent = parent();
    let lanes = populated(&[1, 0, 2, 0]);
    assert_eq!(state.seal(&lanes), Err(Error::Epoch));
    for _ in 0..BATCHES_PER_EPOCH {
        let result = state
            .advance(None, &batch(parent, vec![]), &parent)
            .unwrap();
        state = result.0;
        parent = result.1.next;
    }
    assert_eq!(
        state.advance(None, &batch(parent, vec![]), &parent),
        Err(Error::Epoch)
    );
    assert_eq!(state.seal(&lanes[..3]), Err(Error::Snapshot));
    let mut duplicate = lanes.clone();
    duplicate[1] = lanes[0].clone();
    assert_eq!(state.seal(&duplicate), Err(Error::Snapshot));
    let (next, active, sealed) = state.seal(&lanes).unwrap();
    assert_eq!(next.epoch, 1);
    assert_eq!(next.batches, 0);
    assert_eq!(next.snapshot_messages, 3);
    for (old, new) in lanes.iter().zip(active) {
        assert_eq!(old.root, new.root);
        assert_eq!(old.next_sequence, new.next_sequence);
        assert!(new.queue.is_empty());
        assert_eq!(new.base_root, old.root);
        assert_eq!(new.epoch, 1);
    }
    assert_eq!(sealed.lanes, lanes);
}
#[test]
fn fifo_round_robin_skips_empty_lanes_and_rejects_favorable_subsets() {
    let lanes = populated(&[3, 0, 2, 1]);
    let (s, _, snapshot) = ready(4).seal(&lanes).unwrap();
    let ids: Vec<_> = snapshot
        .ordered()
        .unwrap()
        .iter()
        .map(|m| (m.lane, m.sequence))
        .collect();
    assert_eq!(ids, vec![(0, 0), (2, 0), (3, 0), (0, 1), (2, 1), (0, 2)]);
    let required: Vec<_> = s
        .required(Some(&snapshot))
        .unwrap()
        .into_iter()
        .map(|m| m.payload)
        .collect();
    assert_eq!(required.len(), 4);
    let p = parent();
    assert_eq!(
        s.advance(Some(&snapshot), &batch(p, required[1..].to_vec()), &p),
        Err(Error::Duty)
    );
    let mut reversed = required.clone();
    reversed.swap(0, 1);
    assert_eq!(
        s.advance(Some(&snapshot), &batch(p, reversed), &p),
        Err(Error::Duty)
    );
    let next = s.advance(Some(&snapshot), &batch(p, required), &p).unwrap();
    assert_eq!(next.0.cursor, 4);
    assert_eq!(next.0.required(Some(&snapshot)).unwrap().len(), 2);
    assert_eq!(s.cursor, 0); // Both rejected and accepted checks are pure.
}
#[test]
fn duty_cannot_be_moved_to_a_later_evm_block() {
    let (s, _, snapshot) = ready(1).seal(&populated(&[1])).unwrap();
    let p = parent();
    let bytes = BatchInput {
        parent: p,
        blocks: vec![
            BlockInput {
                timestamp: 1,
                fee_recipient: [0; 20],
                transactions: vec![],
            },
            BlockInput {
                timestamp: 2,
                fee_recipient: [0; 20],
                transactions: vec![vec![0, 0]],
            },
        ],
    }
    .encode()
    .unwrap();
    assert_eq!(s.advance(Some(&snapshot), &bytes, &p), Err(Error::Duty));
    let mut other = p;
    other.rollup_id = [5; 32];
    assert_eq!(
        s.advance(Some(&snapshot), &batch(other, vec![vec![0, 0]]), &other),
        Err(Error::Domain)
    );
}
#[test]
fn full_snapshot_is_exhausted_within_quota_and_old_snapshot_cannot_be_reused() {
    let (mut s, mut active, snapshot) = ready(4).seal(&populated(&[8, 8, 8, 8])).unwrap();
    let sealed_hash = snapshot.commitment().unwrap();
    let mut p = parent();
    // Post-seal admissions do not mutate the frozen snapshot or its duty.
    active[2] = active[2].append(vec![99]).unwrap();
    for i in 0..BATCHES_PER_EPOCH {
        let required = s.required(Some(&snapshot)).unwrap();
        assert_eq!(required.len(), 4);
        let bytes = batch(p, required.into_iter().map(|m| m.payload).collect());
        let next = s.advance(Some(&snapshot), &bytes, &p).unwrap();
        s = next.0;
        p = next.1.next;
        assert_eq!(s.cursor, 4 * (u16::from(i) + 1));
        assert_eq!(snapshot.commitment().unwrap(), sealed_hash);
    }
    assert_eq!(s.cursor, 32);
    assert_eq!(s.required(Some(&snapshot)), Err(Error::Epoch));
    let (s, _, new_snapshot) = s.seal(&active).unwrap();
    assert_eq!(s.required(Some(&snapshot)), Err(Error::Snapshot));
    let required = s.required(Some(&new_snapshot)).unwrap();
    assert_eq!(required.len(), 1);
    assert_eq!(required[0].lane, 2);
    assert_eq!(required[0].sequence, 8);
    assert_eq!(required[0].payload, vec![99]);
    assert_eq!(s.required(None), Err(Error::Snapshot));
}
#[test]
fn every_small_occupancy_pattern_drains_without_skipping_or_duplication() {
    // All 81 occupancies with 0/1/2 messages in each of four configured lanes.
    for pattern in 0..81usize {
        let counts: Vec<_> = (0..4).map(|i| (pattern / 3usize.pow(i)) % 3).collect();
        let (mut s, _, snapshot) = ready(4).seal(&populated(&counts)).unwrap();
        let expected = snapshot.ordered().unwrap();
        let mut observed = vec![];
        let mut p = parent();
        for _ in 0..BATCHES_PER_EPOCH {
            let duty = s.required(Some(&snapshot)).unwrap();
            observed.extend(duty.clone());
            let next = s
                .advance(
                    Some(&snapshot),
                    &batch(p, duty.into_iter().map(|m| m.payload).collect()),
                    &p,
                )
                .unwrap();
            s = next.0;
            p = next.1.next;
        }
        assert_eq!(observed, expected);
        assert_eq!(s.cursor, s.snapshot_messages);
    }
}
#[test]
fn canonical_codecs_reject_truncation_suffix_mutation_and_excess_allocation() {
    let lanes = populated(&[1, 2]);
    let (s, _, snapshot) = ready(2).seal(&lanes).unwrap();
    let lane_bytes = lanes[1].encode().unwrap();
    let snap_bytes = snapshot.encode().unwrap();
    let schedule_bytes = s.encode().unwrap();
    assert_eq!(schedule_bytes.len(), SCHEDULE_BYTES);
    assert_eq!(Lane::decode(&lane_bytes), Ok(lanes[1].clone()));
    assert_eq!(Snapshot::decode(&snap_bytes), Ok(snapshot));
    assert_eq!(Schedule::decode(&schedule_bytes), Ok(s));
    for n in 0..lane_bytes.len() {
        assert!(Lane::decode(&lane_bytes[..n]).is_err());
    }
    for n in 0..snap_bytes.len() {
        assert!(Snapshot::decode(&snap_bytes[..n]).is_err());
    }
    for n in 0..schedule_bytes.len() {
        assert!(Schedule::decode(&schedule_bytes[..n]).is_err());
    }
    let mut extra = lane_bytes.clone();
    extra.push(0);
    assert!(Lane::decode(&extra).is_err());
    let mut extra = snap_bytes.clone();
    extra.push(0);
    assert!(Snapshot::decode(&extra).is_err());
    let mut extra = schedule_bytes.clone();
    extra.push(0);
    assert!(Schedule::decode(&extra).is_err());
    let mut bad = schedule_bytes;
    bad[181] ^= 1;
    assert_eq!(Schedule::decode(&bad), Err(Error::Domain));
    let mut bad = lane_bytes;
    bad[121] = 255;
    assert_eq!(Lane::decode(&bad), Err(Error::Limit));
    let mut bad = snap_bytes;
    bad[49..53].copy_from_slice(&u32::MAX.to_le_bytes());
    assert_eq!(Snapshot::decode(&bad), Err(Error::Limit));
    let mut lanes = vec![];
    for i in 0..MAX_LANES {
        let mut lane = Lane::genesis([1; 32], i as u8).unwrap();
        for _ in 0..MAX_LANE_MESSAGES {
            lane = lane.append(vec![7; MAX_PAYLOAD_BYTES]).unwrap();
        }
        assert_eq!(lane.encode().unwrap().len(), MAX_LANE_BYTES);
        lanes.push(lane);
    }
    let (_, _, snapshot) = ready(4).seal(&lanes).unwrap();
    let bytes = snapshot.encode().unwrap();
    assert_eq!(bytes.len(), MAX_SNAPSHOT_BYTES);
    assert_eq!(Snapshot::decode(&bytes), Ok(snapshot));
}
#[test]
fn counter_overflow_and_cursor_forgery_fail_closed() {
    let mut lane = Lane::genesis([1; 32], 0).unwrap();
    lane.next_sequence = u64::MAX;
    assert_eq!(lane.append(vec![1]), Err(Error::Overflow));
    let (mut s, mut lanes, _) = ready(1).seal(&populated(&[1])).unwrap();
    s.cursor = 1;
    assert_eq!(s.validate(), Err(Error::Duty));
    s.cursor = 1;
    s.batches = BATCHES_PER_EPOCH;
    s.epoch = u64::MAX;
    lanes[0].epoch = u64::MAX;
    assert_eq!(s.seal(&lanes), Err(Error::Overflow));
    let (mut s, _, _) = ready(1).seal(&populated(&[1])).unwrap();
    s.snapshot_hash = [0; 32];
    assert_eq!(s.validate(), Err(Error::Snapshot));
}
