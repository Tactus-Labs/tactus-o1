use tactus_o1_execution::{
    checkpoint::{Boundary, Checkpoint},
    Executor, Genesis,
};
use tactus_o1_proof_journal::{
    checkpoint::{self, CheckpointJournal},
    execute, Domain, Journal,
};

#[test]
fn bootstrap_and_continuation_match_replay_with_distinct_profile() {
    let input: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../specs/evidence/sealed-chain-proof/proving-input.json"
    ))
    .unwrap();
    let decode = |v: &serde_json::Value| {
        hex::decode(v.as_str().unwrap().strip_prefix("0x").unwrap()).unwrap()
    };
    let domain = Domain::decode(&decode(&input["domain_hex"])).unwrap();
    let allocation = decode(&input["allocation_hex"]);
    let batches: Vec<_> = input["batches"]
        .as_array()
        .unwrap()
        .iter()
        .map(decode)
        .collect();
    assert!(batches.len() > 3);
    let genesis =
        Genesis::from_allocation(domain.rollup_id.into(), domain.chain_id, &allocation).unwrap();
    let mut engine = Executor::new(&genesis).unwrap();
    let mut headers = vec![engine.head().clone()];
    let genesis_boundary = Boundary {
        anchor: *engine.anchor(),
        state_root: engine.state_root(),
        header_hash: engine.head_hash(),
    };
    let genesis_snapshot = Checkpoint {
        accounts: engine.accounts().collect(),
        recent_headers: headers.clone(),
    };
    let mut first_iter = batches.iter();
    let first = checkpoint::execute_genesis(domain.clone(), &allocation, 3, || {
        first_iter.next().unwrap().clone()
    })
    .unwrap();
    for batch in &batches[..3] {
        headers.extend(
            engine
                .apply_batch(batch)
                .unwrap()
                .into_iter()
                .map(|b| b.header),
        );
    }
    let (boundary, snapshot) = Checkpoint::capture(&engine, headers).unwrap();
    let remaining = (batches.len() - 3) as u64;
    let mut new_batches = batches[3..].iter();
    let second = checkpoint::execute_continuation(
        domain.clone(),
        first.transition.allocation_commitment,
        &boundary,
        &snapshot.encode().unwrap(),
        remaining,
        || new_batches.next().unwrap().clone(),
    )
    .unwrap();
    let mut all_batches = batches.iter();
    let replay = execute(domain.clone(), &allocation, 3, remaining, || {
        all_batches.next().unwrap().clone()
    })
    .unwrap();
    assert_eq!(second.transition, replay);
    assert_eq!(CheckpointJournal::decode(&second.encode()).unwrap(), second);
    assert!(Journal::decode(&second.encode()).is_err());
    assert!(CheckpointJournal::decode(&replay.encode()).is_err());
    second.follows(&first).unwrap();
    for variant in 0..5 {
        let mut wrong = second.clone();
        match variant {
            0 => wrong.transition.previous_state_root[0] ^= 1,
            1 => wrong.transition.previous_header_hash[0] ^= 1,
            2 => wrong.transition.before.last_batch_commitment[0] ^= 1,
            3 => wrong.transition.allocation_commitment[0] ^= 1,
            4 => wrong.transition.domain.ckb_genesis[0] ^= 1,
            _ => unreachable!(),
        }
        assert!(wrong.follows(&first).is_err());
    }
    // A continuation cannot smuggle an arbitrary genesis snapshot past bootstrap.
    assert!(checkpoint::execute_continuation(
        domain,
        first.transition.allocation_commitment,
        &genesis_boundary,
        &genesis_snapshot.encode().unwrap(),
        1,
        || batches[0].clone()
    )
    .is_err());
}
