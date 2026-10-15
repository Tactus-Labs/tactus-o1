use tactus_o1_execution::Genesis;
use tactus_o1_native_proof_journal::{
    execute, Domain, Error, Journal, DOMAIN_LEN, JOURNAL_LEN, VAULT_CODE,
};
use tactus_o1_protocol::{
    batch,
    native_bridge::{Anchor, Config},
};
fn decode(v: &serde_json::Value) -> Vec<u8> {
    hex::decode(v.as_str().unwrap().strip_prefix("0x").unwrap()).unwrap()
}
fn fixture() -> (Domain, Vec<u8>, Vec<Vec<u8>>, serde_json::Value) {
    let d: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../specs/evidence/native-publication/0.210.0/deployment.json"
    ))
    .unwrap();
    let e: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../specs/evidence/native-publication/0.210.0/execution.json"
    ))
    .unwrap();
    let domain = Domain {
        config: Config::decode(&decode(&d["config"])).unwrap(),
        ordering_type_hash: batch::hash(b"", &decode(&d["anchor_script"])),
    };
    let batches = e["cases"][0]["steps"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| decode(&s["wrapper"]))
        .collect();
    (domain, decode(&d["genesis_allocation"]), batches, e)
}
fn replay(d: Domain, a: &[u8], b: &[Vec<u8>], p: u64) -> Result<Journal, Error> {
    let mut iter = b.iter();
    execute(d, a, p, b.len() as u64 - p, || iter.next().unwrap().clone())
}
#[test]
fn real_publications_match_independent_geth_roots_and_chain_anchors() {
    let (d, a, b, e) = fixture();
    let geth: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../specs/evidence/native-publication/0.210.0/geth.json"
    ))
    .unwrap();
    let first = replay(d.clone(), &a, &b[..1], 0).unwrap();
    let second = replay(d.clone(), &a, &b, 1).unwrap();
    let whole = replay(d, &a, &b, 0).unwrap();
    for (i, j) in [first.clone(), second.clone()].iter().enumerate() {
        let step = &e["cases"][0]["steps"][i];
        assert_eq!(j.before, Anchor::decode(&decode(&step["before"])).unwrap());
        assert_eq!(j.after, Anchor::decode(&decode(&step["after"])).unwrap());
        assert_eq!(
            j.next_state_root.as_slice(),
            decode(&geth["blocks"][i]["state_root"])
        );
        assert_eq!(
            j.next_header_hash.as_slice(),
            decode(&step["blocks"][0]["hash"])
        );
        assert_eq!(Journal::decode(&j.encode()), Ok(j.clone()));
    }
    assert_eq!(first.after, second.before);
    assert_eq!(first.next_state_root, second.previous_state_root);
    assert_eq!(first.next_header_hash, second.previous_header_hash);
    assert_eq!(whole.after, second.after);
    assert_eq!(whole.next_state_root, second.next_state_root);
    assert_eq!(whole.after.deposits.cumulative, 25_000_000_000);
    assert_eq!(whole.after.deposits.count, 2);
    assert_eq!(
        hex::encode(VAULT_CODE),
        "3b0c9f82f019407ad1784fcf0d62fe695eba3cf235c2e8ce474af5aebbe39237"
    );
}
#[test]
fn rejects_missing_reordered_repeated_and_tampered_deposit_batches() {
    let (d, a, b, _) = fixture();
    for bad in [
        vec![b[1].clone()],
        vec![b[1].clone(), b[0].clone()],
        vec![b[0].clone(), b[0].clone()],
    ] {
        assert_eq!(replay(d.clone(), &a, &bad, 0), Err(Error::Execution));
    }
    // Parent cursor, record amount, recipient, cumulative value and user envelope.
    for offset in [
        8,
        8 + 56 + 2 + 36,
        8 + 56 + 2 + 16,
        8 + 56 + 2 + 108,
        b[0].len() - 1,
    ] {
        let mut bad = b.clone();
        bad[0][offset] ^= 1;
        assert_eq!(replay(d.clone(), &a, &bad, 0), Err(Error::Execution));
    }
    for len in [0, 7, 64, b[0].len() - 1] {
        assert_eq!(
            replay(d.clone(), &a, &[b[0][..len].to_vec()], 0),
            Err(Error::Execution)
        );
    }
}
#[test]
fn binds_every_custody_domain_field_and_allocation() {
    let (d, a, b, e) = fixture();
    let baseline = replay(d.clone(), &a, &b, 0).unwrap();
    // All config edits must fail replay of an unchanged, full canonical transcript.
    for offset in [8, 40, 72, 104, 112, 132] {
        let mut wire = d.encode();
        wire[offset] ^= 1;
        let altered = Domain::decode(&wire).unwrap();
        assert!(replay(altered, &a, &b, 0).is_err(), "offset {offset}");
    }
    // Ordering type is an authenticated external binding, not an EVM input.
    let mut altered = d.clone();
    altered.ordering_type_hash[0] ^= 1;
    assert_ne!(
        replay(altered, &a, &b, 0).unwrap().encode(),
        baseline.encode()
    );
    let mut g: Genesis = serde_json::from_value(e["cases"][0]["genesis"].clone()).unwrap();
    let account = g
        .accounts
        .iter_mut()
        .find(|(address, _)| address.as_slice() != d.config.contract)
        .unwrap()
        .1;
    account.balance = account.balance.checked_add("1".parse().unwrap()).unwrap();
    let changed = replay(d.clone(), &g.allocation_bytes().unwrap(), &b, 0).unwrap();
    assert_ne!(
        changed.allocation_commitment,
        baseline.allocation_commitment
    );
    assert_ne!(changed.next_state_root, baseline.next_state_root);
    let bridge = g.accounts.get_mut(&d.config.contract).unwrap();
    bridge
        .storage
        .insert("1".parse().unwrap(), "1".parse().unwrap());
    assert_eq!(
        replay(d, &g.allocation_bytes().unwrap(), &b, 0),
        Err(Error::Execution)
    );
}
#[test]
fn strict_decoding_and_cursor_continuity() {
    let (d, a, b, _) = fixture();
    let j = replay(d.clone(), &a, &b, 0).unwrap();
    let bytes = j.encode();
    for len in 0..JOURNAL_LEN {
        assert!(Journal::decode(&bytes[..len]).is_err());
    }
    let mut extra = bytes.to_vec();
    extra.push(0);
    assert!(Journal::decode(&extra).is_err());
    for len in 0..DOMAIN_LEN {
        assert!(Domain::decode(&d.encode()[..len]).is_err());
    }
    for offset in [0, 8, 40, 268, 268 + 96, 524 + 96, 268 + 200, 268 + 224] {
        let mut bad = bytes;
        bad[offset] ^= 1;
        assert!(Journal::decode(&bad).is_err(), "offset {offset}");
    }
    let mut bad = j.clone();
    bad.after = bad.before;
    assert_eq!(Journal::decode(&bad.encode()), Err(Error::Range));
    let mut bad = j.clone();
    bad.after.deposits.count = 0;
    assert!(Journal::decode(&bad.encode()).is_err());
    let mut bad = j;
    bad.after.deposits.cumulative = 0;
    assert!(Journal::decode(&bad.encode()).is_err());
}
#[test]
fn rejects_empty_and_overflowed_interval_before_requesting_input() {
    let (d, a, _, _) = fixture();
    for (p, n) in [(0, 0), (u64::MAX, 1), (u64::MAX, 2)] {
        assert_eq!(
            execute(d.clone(), &a, p, n, || panic!("must not read input")),
            Err(Error::Range)
        );
    }
}
