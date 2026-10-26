#![cfg(feature = "v02")]
use tactus_o1_protocol::v02::*;

fn vector(name: &str) -> Vec<u8> {
    let (_, hex) = include_str!("../../../specs/test-vectors/v02.txt")
        .lines()
        .filter_map(|line| line.split_once('='))
        .find(|(key, _)| *key == name)
        .unwrap();
    hex.as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(core::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}
fn object<T: Wire>(name: &str) -> T {
    let bytes = vector(name);
    let result = T::decode(&bytes).unwrap();
    assert_eq!(result.encode().unwrap(), bytes);
    // Apply exact-decoding checks to every independently encoded object, not
    // just a subset of the transition fixtures. Every truncated prefix fails.
    for end in 0..bytes.len() {
        assert!(
            T::decode(&bytes[..end]).is_err(),
            "{name}: truncation at {end}"
        );
    }
    let mut suffix = bytes.clone();
    suffix.push(0);
    assert!(T::decode(&suffix).is_err(), "{name}: trailing byte");
    let mut duplicate = bytes.clone();
    duplicate.extend_from_slice(&bytes);
    assert!(T::decode(&duplicate).is_err(), "{name}: duplicate object");
    let mut unknown_magic = bytes.clone();
    unknown_magic[0] ^= 1;
    assert!(T::decode(&unknown_magic).is_err(), "{name}: unknown magic");
    let mut oversized = bytes.clone();
    oversized.resize(T::MAX_BYTES + 1, 0);
    assert!(
        T::decode(&oversized).is_err(),
        "{name}: outer envelope limit"
    );
    result
}

#[test]
fn independent_encoder_matches_joint_genesis_and_all_transitions() {
    let policy: Policy = object("policy");
    let config: Config = object("config");
    assert_eq!(config.domain, Config::domain_id(&[6; 44], 0));
    config.bind(&policy).unwrap();
    let boundary: Boundary = object("boundary");
    let control: Control = object("control");
    assert_eq!(control, Control::genesis(&config, &policy).unwrap());
    assert_eq!(
        boundary,
        Boundary::genesis(config.commitment().unwrap()).unwrap()
    );
    let vault: Vault = object("vault");
    assert_eq!(
        vault,
        Vault::genesis(config.commitment().unwrap(), 1000).unwrap()
    );
    let (funded, receipt) = vault
        .deposit(&config, &policy, &control, [23; 20], 7, [24; 32])
        .unwrap();
    assert_eq!(funded, object::<Vault>("vault_deposit"));
    assert_eq!(receipt, object::<Deposit>("deposit"));
    let mut lanes: Vec<_> = (0..4)
        .map(|i| Lane::genesis(boundary.config, i).unwrap())
        .collect();
    let (lane, admission) = lanes[0].enqueue(&control, &policy, vec![1, 0]).unwrap();
    assert_eq!(lane, object::<Lane>("lane"));
    assert_eq!(admission, object::<Admission>("admission"));
    lanes[0] = lane;
    let (schedule, snapshot, _) = Schedule::genesis(boundary.config)
        .unwrap()
        .seal(&config, &policy, &control, &boundary, &lanes, &funded, None)
        .unwrap();
    assert_eq!(schedule, object::<Schedule>("schedule"));
    assert_eq!(snapshot, object::<Snapshot>("snapshot"));
    let batch: NativeBatch = object("batch");
    let (successor, schedule_next) = batch
        .append(
            &config,
            &policy,
            &control,
            &schedule,
            &snapshot,
            (0x40 << 56) | 100,
        )
        .unwrap();
    assert_eq!(successor, object::<Boundary>("successor"));
    assert_eq!(schedule_next, object::<Schedule>("schedule_next"));
    let journal: Journal = object("journal");
    let settled: Control = object("settled");
    assert_eq!(
        control.settlement_candidate(&journal, &successor).unwrap(),
        settled
    );
    let ticket: Watch = object("watch");
    assert_eq!(ticket.close_allowed(&control, &policy), Err(Error::Duty));
    assert!(ticket.close_allowed(&settled, &policy).is_ok());
    let proof: NullifierProof = object("nullifier");
    let key = claim_key(&boundary.config, ClaimKind::Refund, &1u64.to_le_bytes()).unwrap();
    assert_eq!(key.as_slice(), vector("refund_key"));
    let new_root = proof
        .insert(&boundary.config, ClaimKind::Refund, &key, &vault.claims[1])
        .unwrap();
    assert_eq!(new_root.as_slice(), vector("refund_root"));
}
