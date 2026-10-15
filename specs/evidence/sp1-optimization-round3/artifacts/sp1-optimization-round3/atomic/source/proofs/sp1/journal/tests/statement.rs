use tactus_o1_execution::{Executor, Genesis};
use tactus_o1_proof_journal::{execute, Domain, Error, Journal, JOURNAL_LEN};
use tactus_o1_protocol::batch::BatchInput;

fn fixtures() -> serde_json::Value {
    serde_json::from_str(include_str!(
        "../../../../specs/test-vectors/execution-v1/geth-1.17.8.json"
    ))
    .unwrap()
}
fn domain(g: &Genesis) -> Domain {
    Domain {
        ckb_genesis: [1; 32],
        ordering_type_hash: [2; 32],
        settlement_type_hash: [3; 32],
        rollup_id: g.rollup_id.0,
        chain_id: g.chain_id,
    }
}

#[test]
fn real_signed_fixtures_commit_exact_host_and_geth_results() {
    for (index, case) in fixtures()["cases"].as_array().unwrap().iter().enumerate() {
        let g: Genesis = serde_json::from_value(case["genesis"].clone()).unwrap();
        let batch = hex::decode(case["batch"].as_str().unwrap().trim_start_matches("0x")).unwrap();
        let mut host = Executor::new(&g).unwrap();
        let before_root = host.state_root().0;
        host.apply_batch(&batch).unwrap();
        let journal = execute(domain(&g), &g.allocation_bytes().unwrap(), 0, 1, || {
            batch.clone()
        })
        .unwrap();
        assert_eq!(journal.previous_state_root, before_root);
        assert_eq!(journal.next_state_root, host.state_root().0);
        assert_eq!(journal.next_header_hash, host.head().hash_slow().0);
        assert_eq!(journal.after, *host.anchor());
        assert_eq!(
            format!("0x{}", hex::encode(journal.next_state_root)),
            case["geth"].as_array().unwrap().last().unwrap()["stateRoot"]
        );
        let bytes = journal.encode();
        if index == 0 {
            assert_eq!(
                format!("0x{}", hex::encode(bytes)),
                include_str!("../../../../specs/test-vectors/proof-v1/transfers-journal.hex")
                    .trim()
            );
        }
        assert_eq!(bytes.len(), JOURNAL_LEN);
        assert_eq!(Journal::decode(&bytes).unwrap(), journal);
        for length in 0..JOURNAL_LEN {
            assert!(Journal::decode(&bytes[..length]).is_err());
        }
        let mut extra = bytes.to_vec();
        extra.push(0);
        assert!(Journal::decode(&extra).is_err());
    }
}

#[test]
fn prefix_is_executed_and_order_and_allocation_cannot_be_substituted() {
    let fixture = fixtures();
    let case = &fixture["cases"][2];
    let g: Genesis = serde_json::from_value(case["genesis"].clone()).unwrap();
    let mut host = Executor::new(&g).unwrap();
    let original = hex::decode(case["batch"].as_str().unwrap().trim_start_matches("0x")).unwrap();
    let blocks = BatchInput::decode(&original, host.anchor()).unwrap().blocks;
    assert!(blocks.len() > 1);
    let first = BatchInput {
        parent: *host.anchor(),
        blocks: vec![blocks[0].clone()],
    }
    .encode()
    .unwrap();
    host.apply_batch(&first).unwrap();
    let before = *host.anchor();
    let root = host.state_root().0;
    let second = BatchInput {
        parent: before,
        blocks: blocks[1..].to_vec(),
    }
    .encode()
    .unwrap();
    let allocation = g.allocation_bytes().unwrap();
    let mut ordered = [first.clone(), second.clone()].into_iter();
    let journal = execute(domain(&g), &allocation, 1, 1, || ordered.next().unwrap()).unwrap();
    assert_eq!(journal.before, before);
    assert_eq!(journal.previous_state_root, root);
    assert_eq!(journal.after.next_batch_number, 2);
    for sequence in [
        [second.clone(), first.clone()],
        [first.clone(), first.clone()],
    ] {
        let mut batches = sequence.into_iter();
        assert_eq!(
            execute(domain(&g), &allocation, 1, 1, || batches.next().unwrap()),
            Err(Error::Execution)
        );
    }
    let mut wrong = g.clone();
    let account = wrong.accounts.values_mut().next().unwrap();
    account.balance = account.balance.checked_sub("1".parse().unwrap()).unwrap();
    let mut batches = [first.clone(), second.clone()].into_iter();
    let changed = execute(domain(&g), &wrong.allocation_bytes().unwrap(), 1, 1, || {
        batches.next().unwrap()
    })
    .unwrap();
    assert_ne!(changed.allocation_commitment, journal.allocation_commitment);
    assert_ne!(changed.previous_state_root, journal.previous_state_root);
    for field in 0..3 {
        let mut d = domain(&g);
        match field {
            0 => d.ckb_genesis[0] ^= 1,
            1 => d.ordering_type_hash[0] ^= 1,
            _ => d.settlement_type_hash[0] ^= 1,
        }
        let mut batches = [first.clone(), second.clone()].into_iter();
        let changed = execute(d, &allocation, 1, 1, || batches.next().unwrap()).unwrap();
        assert_ne!(changed.encode(), journal.encode());
    }
}

#[test]
fn rejects_empty_overflow_wrong_domain_and_noncanonical_journal() {
    let fixture = fixtures();
    let case = &fixture["cases"][0];
    let g: Genesis = serde_json::from_value(case["genesis"].clone()).unwrap();
    let allocation = g.allocation_bytes().unwrap();
    assert_eq!(
        execute(domain(&g), &allocation, 0, 0, || panic!()),
        Err(Error::Range)
    );
    assert_eq!(
        execute(domain(&g), &allocation, u64::MAX, 1, || panic!()),
        Err(Error::Range)
    );
    let mut d = domain(&g);
    d.ckb_genesis = [0; 32];
    assert_eq!(
        execute(d, &allocation, 0, 1, || panic!()),
        Err(Error::Domain)
    );
    let batch = hex::decode(case["batch"].as_str().unwrap().trim_start_matches("0x")).unwrap();
    let valid = execute(domain(&g), &allocation, 0, 1, || batch.clone())
        .unwrap()
        .encode();
    for offset in [0, 8, 136, 168, 208, 408, 448] {
        let mut changed = valid;
        changed[offset] ^= 1;
        assert!(Journal::decode(&changed).is_err(), "offset {offset}");
    }
}
