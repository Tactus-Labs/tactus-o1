use tactus_o1_protocol::batch::*;

fn decode(hex: &str) -> Vec<u8> {
    let h = hex.trim();
    assert!(h.len().is_multiple_of(2));
    h.as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(core::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}
fn parent() -> AnchorState {
    AnchorState::genesis([7; 32], [9; 32], 31337).unwrap()
}
fn example() -> BatchInput {
    BatchInput {
        parent: parent(),
        blocks: vec![
            BlockInput {
                timestamp: 10,
                fee_recipient: [3; 20],
                transactions: vec![vec![2, 1, 2]],
            },
            BlockInput {
                timestamp: 10,
                fee_recipient: [4; 20],
                transactions: vec![],
            },
        ],
    }
}
#[test]
fn independent_python_wire_vectors_match_rust_and_next_state() {
    let genesis = decode(include_str!(
        "../../../specs/test-vectors/batch-v1/genesis.hex"
    ));
    let input = decode(include_str!(
        "../../../specs/test-vectors/batch-v1/input.hex"
    ));
    let next = decode(include_str!(
        "../../../specs/test-vectors/batch-v1/next-state.hex"
    ));
    assert_eq!(parent().encode().as_slice(), genesis);
    assert_eq!(AnchorState::decode(&genesis).unwrap(), parent());
    assert_eq!(example().encode().unwrap(), input);
    let summary = validate_batch(&input, &parent()).unwrap();
    let (decoded, decoded_summary) = BatchInput::decode_with_summary(&input, &parent()).unwrap();
    assert_eq!(decoded, example());
    assert_eq!(decoded_summary, summary);
    let (view, view_summary) = BatchView::decode_with_summary(&input, &parent()).unwrap();
    assert_eq!(view_summary, summary);
    assert_eq!(view.blocks.len(), 2);
    assert_eq!(
        view.blocks[0].transactions,
        [example().blocks[0].transactions[0].as_slice()]
    );
    assert_eq!(view.blocks[1].fee_recipient, [4; 20]);
    assert!(view.blocks[1].transactions.is_empty());
    assert_eq!(summary.next.encode().as_slice(), next);
    assert_eq!(
        (
            summary.blocks,
            summary.transactions,
            summary.bytes,
            summary.gas_ceiling
        ),
        (2, 1, 261, 2_000_000)
    );
}
#[test]
fn every_truncation_and_trailing_bytes_fail() {
    let input = example().encode().unwrap();
    for end in 0..input.len() {
        assert!(validate_batch(&input[..end], &parent()).is_err(), "{end}");
        assert!(
            BatchView::decode_with_summary(&input[..end], &parent()).is_err(),
            "{end}"
        );
        assert!(
            BatchInput::decode_with_summary(&input[..end], &parent()).is_err(),
            "{end}"
        );
    }
    let mut extra = input.clone();
    extra.push(0);
    assert_eq!(validate_batch(&extra, &parent()), Err(Error::Encoding));
    assert_eq!(
        BatchView::decode_with_summary(&extra, &parent()),
        Err(Error::Encoding)
    );
    assert_eq!(
        BatchInput::decode_with_summary(&extra, &parent()),
        Err(Error::Encoding)
    );
    let mut state = parent().encode().to_vec();
    state.push(0);
    assert_eq!(AnchorState::decode(&state), Err(Error::Encoding));
}
#[test]
fn domain_and_chain_replay_and_gaps_fail() {
    let input = example().encode().unwrap();
    for offset in [8, 40, 88, 120, 152] {
        let mut changed = input.clone();
        changed[offset] ^= 1;
        assert_eq!(
            validate_batch(&changed, &parent()),
            Err(Error::Domain),
            "offset {offset}"
        );
    }
    for offset in [48, 56, 184] {
        let mut changed = input.clone();
        changed[offset] ^= 1;
        assert_eq!(
            validate_batch(&changed, &parent()),
            Err(Error::Succession),
            "offset {offset}"
        );
    }
    let next = validate_batch(&input, &parent()).unwrap().next;
    assert_eq!(validate_batch(&input, &next), Err(Error::Succession));
}
#[test]
fn commits_block_boundaries_order_and_fee_recipient() {
    let mut batch = example();
    let initial = validate_batch(&batch.encode().unwrap(), &parent()).unwrap();
    batch.blocks[1].transactions = batch.blocks[0].transactions.clone();
    batch.blocks[0].transactions.clear();
    let moved = validate_batch(&batch.encode().unwrap(), &parent()).unwrap();
    assert_ne!(
        initial.next.last_batch_commitment,
        moved.next.last_batch_commitment
    );
    batch.blocks[1].fee_recipient = [5; 20];
    let fee_changed = validate_batch(&batch.encode().unwrap(), &parent()).unwrap();
    assert_ne!(
        moved.next.last_batch_commitment,
        fee_changed.next.last_batch_commitment
    );
}
#[test]
fn same_second_blocks_are_allowed_but_regressions_are_not() {
    let mut batch = example();
    batch.blocks[1].timestamp = 9;
    assert_eq!(batch.encode(), Err(Error::Timestamp));
    batch = example();
    batch.parent.last_timestamp = 11;
    assert_eq!(batch.encode(), Err(Error::Timestamp));
}
#[test]
fn counts_and_byte_limits_reject_before_unbounded_allocation() {
    let mut batch = example();
    batch.blocks.clear();
    assert_eq!(batch.encode(), Err(Error::Limit));
    batch = example();
    batch.blocks[0].transactions[0].clear();
    assert_eq!(batch.encode(), Err(Error::Limit));
    batch = example();
    batch.blocks[0].transactions[0] = vec![2; MAX_TRANSACTION_BYTES + 1];
    assert_eq!(batch.encode(), Err(Error::Limit));
    let mut input = example().encode().unwrap();
    input[192..194].copy_from_slice(&u16::MAX.to_le_bytes());
    assert_eq!(validate_batch(&input, &parent()), Err(Error::Limit));
    let mut input = example().encode().unwrap();
    input[224..228].copy_from_slice(&u32::MAX.to_le_bytes());
    assert_eq!(validate_batch(&input, &parent()), Err(Error::Limit));
    let block = BlockInput {
        timestamp: 10,
        fee_recipient: [3; 20],
        transactions: vec![],
    };
    batch = BatchInput {
        parent: parent(),
        blocks: vec![block.clone(); MAX_BLOCKS],
    };
    assert!(batch.encode().is_ok());
    batch.blocks.push(block);
    assert_eq!(batch.encode(), Err(Error::Limit));
    let block = BlockInput {
        timestamp: 10,
        fee_recipient: [3; 20],
        transactions: vec![vec![2]; MAX_BLOCK_TRANSACTIONS],
    };
    batch = BatchInput {
        parent: parent(),
        blocks: vec![block; 4],
    };
    assert!(batch.encode().is_ok());
    batch.blocks.push(BlockInput {
        timestamp: 10,
        fee_recipient: [3; 20],
        transactions: vec![vec![2]],
    });
    assert_eq!(batch.encode(), Err(Error::Limit));
}
#[test]
fn exact_maximum_bytes_are_accepted_one_more_is_rejected() {
    let mut transactions = vec![vec![2; MAX_TRANSACTION_BYTES]; 15];
    transactions.push(vec![
        2;
        MAX_BATCH_BYTES
            - 194
            - 30
            - 16 * 4
            - 15 * MAX_TRANSACTION_BYTES
    ]);
    let mut batch = BatchInput {
        parent: parent(),
        blocks: vec![BlockInput {
            timestamp: 10,
            fee_recipient: [3; 20],
            transactions,
        }],
    };
    let input = batch.encode().unwrap();
    assert_eq!(input.len(), MAX_BATCH_BYTES);
    assert_eq!(validate_batch(&input, &parent()).unwrap().transactions, 16);
    batch.blocks[0].transactions[15].push(2);
    assert_eq!(batch.encode(), Err(Error::Limit));
}
#[test]
fn counters_never_wrap_and_genesis_cannot_start_mid_history() {
    let mut batch = example();
    batch.parent.next_batch_number = u64::MAX;
    assert_eq!(batch.encode(), Err(Error::Overflow));
    batch = example();
    batch.parent.last_block_number = u64::MAX - 1;
    assert_eq!(batch.encode(), Err(Error::Overflow));
    let mut state = parent();
    state.last_timestamp = 1;
    assert_eq!(state.validate_genesis(), Err(Error::Genesis));
    assert_eq!(
        AnchorState::genesis([7; 32], [0; 32], 31337),
        Err(Error::Domain)
    );
    assert_eq!(
        AnchorState::genesis([7; 32], [9; 32], 0),
        Err(Error::Domain)
    );
}

#[test]
fn malformed_suffix_cannot_apply_partial_transaction_effects() {
    let mut input = example().encode().unwrap();
    let mut calls = 0;
    input.push(0);
    assert_eq!(
        validate_and_visit(&input, &parent(), |_, _, _, _, _| calls += 1),
        Err(Error::Encoding)
    );
    assert_eq!(calls, 0);
    input.pop();
    validate_and_visit(&input, &parent(), |number, time, recipient, index, tx| {
        calls += 1;
        assert_eq!((number, time, recipient, index), (1, 10, [3; 20], 0));
        assert_eq!(tx, &[2, 1, 2]);
    })
    .unwrap();
    assert_eq!(calls, 1);
}
