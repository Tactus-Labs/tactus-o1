use tactus_o1_execution::{checkpoint::Boundary, Executor, Genesis};
use tactus_o1_settlement_script::{self as settlement, Config, Tip};
use tactus_o1_sparse_journal::{self as sparse, Domain, Journal, SparseJournal};
use tactus_o1_sparse_state::database::SparseDb;

#[test]
fn consecutive_sparse_intervals_match_full_replay_and_bind_settlement() {
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
    let genesis =
        Genesis::from_allocation(domain.rollup_id.into(), domain.chain_id, &allocation).unwrap();
    let mut full = Executor::new(&genesis).unwrap();
    let mut headers = vec![full.head().clone()];
    let initial = Boundary {
        anchor: *full.anchor(),
        state_root: full.state_root(),
        header_hash: full.head_hash(),
    };
    let mut previous: Option<SparseJournal> = None;
    let mut tip = Tip::initial(full.anchor().encode()).unwrap();
    let commitment = tactus_o1_protocol::genesis::commitment(&allocation).unwrap();
    let config = Config {
        ckb_genesis: domain.ckb_genesis,
        anchor_type_hash: domain.ordering_type_hash,
        guest_key: [4; 32],
        checkpoint_code_hash: [5; 32],
        allocation_commitment: commitment,
    };
    assert_eq!(settlement::PROFILE, sparse::profile_id());
    assert_eq!(settlement::JOURNAL_MAGIC, sparse::MAGIC);
    for (start, end) in [(0, 3), (3, batches.len())] {
        let boundary = Boundary {
            anchor: *full.anchor(),
            state_root: full.state_root(),
            header_hash: full.head_hash(),
        };
        assert_eq!(
            sparse::decode_boundary(&sparse::encode_boundary(&boundary)).unwrap(),
            boundary
        );
        let db = SparseDb::from_complete(&full, headers.clone()).unwrap();
        let mut discovery = full.clone().with_backend(db).unwrap();
        let old_headers = headers.clone();
        for bytes in &batches[start..end] {
            let blocks = full.apply_batch(bytes).unwrap();
            assert_eq!(discovery.apply_batch(bytes).unwrap(), blocks);
            headers.extend(blocks.into_iter().map(|b| b.header));
            if headers.len() > 256 {
                headers.drain(..headers.len() - 256);
            }
        }
        let witness = discovery.backend().required_witness(old_headers);
        let bytes = serde_json::to_vec(&witness).unwrap();
        let count = (end - start) as u64;
        let mut iter = batches[start..end].iter();
        let journal = if start == 0 {
            sparse::execute_genesis(domain.clone(), &allocation, &bytes, count, || {
                iter.next().unwrap().clone()
            })
        } else {
            sparse::execute_continuation(
                domain.clone(),
                commitment,
                &boundary,
                &bytes,
                count,
                || iter.next().unwrap().clone(),
            )
        }
        .unwrap();
        let mut all = batches[..end].iter();
        let replay = tactus_o1_proof_journal::execute(
            domain.clone(),
            &allocation,
            start as u64,
            count,
            || all.next().unwrap().clone(),
        )
        .unwrap();
        assert_eq!(journal.transition, replay);
        assert!(Journal::decode(&journal.encode()).is_err());
        assert!(SparseJournal::decode(&replay.encode()).is_err());
        assert_eq!(SparseJournal::decode(&journal.encode()).unwrap(), journal);
        if let Some(prior) = &previous {
            journal.follows(prior).unwrap();
        }
        let next = Tip {
            initialized: true,
            anchor: journal.transition.after.encode(),
            state_root: journal.transition.next_state_root,
            header_hash: journal.transition.next_header_hash,
        };
        // This is structural binding only. Real Groth16 acceptance is a separate
        // required experiment; a fabricated guest_key here confers no authority.
        settlement::transition(
            &config,
            &domain.settlement_type_hash,
            &tip,
            &next,
            &journal.encode(),
        )
        .unwrap();
        if start > 0 {
            for offset in [176, 208, 248, 608, 672] {
                let mut altered = journal.encode();
                altered[offset] ^= 1;
                assert!(settlement::transition(
                    &config,
                    &domain.settlement_type_hash,
                    &tip,
                    &next,
                    &altered
                )
                .is_err());
            }
            let mut stale = tip.clone();
            stale.state_root[0] ^= 1;
            assert!(settlement::transition(
                &config,
                &domain.settlement_type_hash,
                &stale,
                &next,
                &journal.encode()
            )
            .is_err());
            let mut wrong = domain.clone();
            wrong.rollup_id[0] ^= 1;
            assert!(sparse::execute_continuation(
                wrong,
                commitment,
                &boundary,
                &bytes,
                count,
                || panic!("must reject before batch")
            )
            .is_err());
        } else {
            assert!(sparse::execute_continuation(
                domain.clone(),
                commitment,
                &initial,
                &bytes,
                count,
                || panic!("must reject genesis continuation")
            )
            .is_err());
        }
        tip = next;
        previous = Some(journal);
    }
}
