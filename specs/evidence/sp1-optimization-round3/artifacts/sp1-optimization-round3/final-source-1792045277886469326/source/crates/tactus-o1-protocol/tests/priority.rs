use tactus_o1_protocol::{
    batch::{AnchorState, BatchInput, BlockInput},
    priority::*,
};
fn message() -> Message {
    Message::admitted([1; 32], [2; 32], [3; 32], vec![2, 1, 2]).unwrap()
}
#[test]
fn canonical_codec_rejects_all_truncations_unknown_stages_and_suffixes() {
    let m = message();
    let bytes = m.encode().unwrap();
    assert_eq!(bytes.len(), FIXED_BYTES + 3);
    assert_eq!(Message::decode(&bytes), Ok(m));
    for end in 0..bytes.len() {
        assert!(Message::decode(&bytes[..end]).is_err());
    }
    let mut bad = bytes.clone();
    bad.push(0);
    assert!(Message::decode(&bad).is_err());
    let mut bad = bytes.clone();
    bad[8] = 3;
    assert_eq!(Message::decode(&bad), Err(Error::Stage));
    let mut bad = bytes;
    bad[105] ^= 1;
    assert_eq!(Message::decode(&bad), Err(Error::Domain));
}
#[test]
fn challenge_preserves_identity_and_cannot_rechallenge_or_invent_inclusion() {
    let m = message();
    let challenged = m.challenge().unwrap();
    assert_eq!(challenged.stage, Stage::Challenged);
    assert_eq!(challenged.id, m.id);
    assert_eq!(challenged.payload, m.payload);
    assert!(challenged.challenge().is_err());
    let mut bad = m;
    bad.batch_commitment = [5; 32];
    assert!(bad.encode().is_err());
    assert_eq!(CHALLENGE_SINCE, (1u64 << 63) | 12);
}
#[test]
fn bounded_inclusion_record_keeps_message_and_cannot_be_included_again() {
    let m = message();
    let parent = AnchorState::genesis([2; 32], [4; 32], 31337).unwrap();
    let bytes = BatchInput {
        parent,
        blocks: vec![BlockInput {
            timestamp: 10,
            fee_recipient: [3; 20],
            transactions: vec![m.payload.clone()],
        }],
    }
    .encode()
    .unwrap();
    let next = tactus_o1_protocol::batch::validate_batch(&bytes, &parent)
        .unwrap()
        .next;
    let included = m.include(&parent, &next, 0).unwrap();
    assert_eq!(included.stage, Stage::Included);
    assert_eq!(included.batch_number, 0);
    assert_eq!(included.block_number, 1);
    assert_eq!(
        Message::decode(&included.encode().unwrap()),
        Ok(included.clone())
    );
    assert!(included.include(&parent, &next, 0).is_err());
    assert!(included.challenge().is_err());
    assert!(m.include(&parent, &next, MAX_PRIORITY_INPUTS).is_err());
}
#[test]
fn payload_and_policy_resource_bounds_are_binding() {
    assert!(Message::admitted([1; 32], [2; 32], [3; 32], vec![]).is_err());
    let m = Message::admitted([1; 32], [2; 32], [3; 32], vec![2; MAX_PAYLOAD_BYTES]).unwrap();
    assert_eq!(m.encode().unwrap().len(), MAX_MESSAGE_BYTES);
    assert!(Message::admitted([1; 32], [2; 32], [3; 32], vec![2; MAX_PAYLOAD_BYTES + 1]).is_err());
    assert_eq!(MAX_PRIORITY_CYCLES, 96_000_000);
    assert_eq!(MAX_PRIORITY_GAS, 1_000_000);
}
