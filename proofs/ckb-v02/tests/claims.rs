//! Real trie and ECDSA checks over synthetic states, not CKB settlement evidence.
mod common;
use alloy_primitives::U256;
use common::*;
use tactus_o1_protocol::v02::*;
use tactus_o1_state_proof_script::encode_proofs;
use tactus_v02_script::claims::*;

#[test]
fn real_burn_proof_releases_once_before_or_after_freeze() {
    let mut f = fixture(1);
    f.control.mode = Mode::Running;
    let paid = f.release.authorize(&f.context()).unwrap();
    assert_eq!(paid.amount, 30);
    assert_eq!(paid.lock, [94; 32]);
    assert_eq!(paid.next.capacity().unwrap(), 1070);
    f.control.mode = Mode::Frozen;
    assert_eq!(f.release.authorize(&f.context()).unwrap(), paid);
    f.vault = paid.next;
    assert_eq!(f.release.authorize(&f.context()), Err(Error::Proof));
    assert_eq!(
        f.escape
            .authorize(&f.context())
            .unwrap()
            .next
            .capacity()
            .unwrap(),
        1000
    );
}

#[test]
fn burn_amount_owner_id_recipient_root_code_and_storage_must_all_match() {
    let f = fixture(1);
    assert!(f.release.authorize(&f.context()).is_ok());
    for field in 0..8 {
        let mut bad = f.release.clone();
        if let Request::Release {
            id,
            amount,
            recipient,
            owner,
            bridge,
        } = &mut bad.request
        {
            match field {
                0 => *id += 1,
                1 => *amount -= 1,
                2 => recipient[0] ^= 1,
                3 => owner[0] ^= 1,
                4 => bridge.claim.root.0[0] ^= 1,
                5 => bridge.claim.code_hash.0[0] ^= 1,
                6 => bridge.claim.slot.0[0] ^= 1,
                _ => bridge.proof[12] ^= 1,
            }
        }
        assert!(bad.authorize(&f.context()).is_err(), "field {field}");
    }
}

#[test]
fn eoa_exit_accepts_proven_absence_and_existing_empty_code_but_rejects_contracts() {
    for mode in [0, 1] {
        let mut f = fixture(mode);
        let payout = f.escape.authorize(&f.context()).unwrap();
        assert_eq!(payout.amount, 70);
        assert_eq!(payout.next.escaped, 70);
        f.vault = payout.next;
        assert_eq!(f.escape.authorize(&f.context()), Err(Error::Proof));
        assert_eq!(
            f.release
                .authorize(&f.context())
                .unwrap()
                .next
                .capacity()
                .unwrap(),
            1000
        );
    }
    let f = fixture(2);
    assert_eq!(f.escape.authorize(&f.context()), Err(Error::Authorization));
}

#[test]
fn fabricated_account_absence_and_redirected_or_malleable_signatures_fail() {
    let f = fixture(0);
    for field in 0..7 {
        let mut bad = f.escape.clone();
        if let Request::Escape {
            recipient,
            signature,
            bridge,
            account,
            ..
        } = &mut bad.request
        {
            match field {
                0 => account.proof = encode_proofs(&[], &[]).unwrap(),
                1 => account.claim.address[0] ^= 1,
                2 => account.claim.root.0[0] ^= 1,
                3 => recipient[0] ^= 1,
                4 => signature[0] ^= 1,
                5 => bridge.claim.value -= U256::from(1),
                _ => {
                    // Valid ECDSA counterpart with high s is still rejected.
                    let order = U256::from_str_radix(
                        "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
                        16,
                    )
                    .unwrap();
                    let high = order - U256::from_be_slice(&signature[32..64]);
                    signature[32..64].copy_from_slice(&high.to_be_bytes::<32>());
                    signature[64] ^= 1;
                }
            }
        }
        assert!(bad.authorize(&f.context()).is_err(), "field {field}");
    }
    let mut bad = f.escape.clone();
    bad.control_outpoint[0] ^= 1;
    let mut context = f.context();
    context.control_outpoint = bad.control_outpoint;
    assert_eq!(bad.authorize(&context), Err(Error::Authorization));
}

#[test]
fn signatures_bind_domain_frozen_state_amount_and_recipient() {
    let f = fixture(1);
    let original =
        escape_digest(&f.config, &f.control, &[91; 36], &owner(), 70, &[95; 32]).unwrap();
    for field in 0..5 {
        let mut config = f.config.clone();
        let mut control = f.control.clone();
        let mut recipient = [95; 32];
        let mut source = [91; 36];
        let mut amount = 70;
        match field {
            0 => {
                config.chain += 1;
                control.boundary.config = config.commitment().unwrap();
            }
            1 => control.state_root[0] ^= 1,
            2 => source[0] ^= 1,
            3 => amount -= 1,
            _ => recipient[0] ^= 1,
        }
        assert_ne!(
            original,
            escape_digest(&config, &control, &source, &owner(), amount, &recipient).unwrap()
        );
    }
    let mut running = f.control.clone();
    running.mode = Mode::Running;
    assert_eq!(
        escape_digest(&f.config, &running, &[91; 36], &owner(), 70, &[95; 32]),
        Err(Error::Mode)
    );
}

#[test]
fn refund_requires_frozen_uncredited_exact_receipt_and_survives_no_first_proof() {
    let mut f = fixture(1);
    assert_eq!(f.refund.authorize(&f.context()), Err(Error::Authorization));
    f.control = Control::genesis(&f.config, &f.policy).unwrap();
    assert_eq!(f.refund.authorize(&f.context()), Err(Error::Mode));
    f.control.mode = Mode::Frozen;
    let payout = f.refund.authorize(&f.context()).unwrap();
    assert_eq!(payout.lock, f.receipt.refund_lock);
    assert_eq!(payout.amount, 100);
    assert_eq!(payout.next.capacity().unwrap(), 1000);
    assert!(f.escape.authorize(&f.context()).is_err());
    let mut context = f.context();
    context.receipt = None;
    assert_eq!(f.refund.authorize(&context), Err(Error::Identity));
    let mut context = f.context();
    context.receipt = Some(([90; 36], &f.receipt));
    assert!(f.refund.authorize(&context).is_err());
    f.vault = payout.next;
    assert_eq!(f.refund.authorize(&f.context()), Err(Error::Proof));
}

#[test]
fn payout_topup_is_allowed_but_principal_reserve_and_recipient_cannot_pay_fees() {
    let f = fixture(1);
    let payout = f.escape.authorize(&f.context()).unwrap();
    assert!(payout
        .check_output(1, payout.lock, 120, 120, false, &[])
        .is_ok());
    assert!(payout
        .check_output(1, payout.lock, 69, 60, false, &[])
        .is_err());
    assert!(payout
        .check_output(1, payout.lock, 70, 120, false, &[])
        .is_err());
    assert!(payout
        .check_output(1, [99; 32], 120, 120, false, &[])
        .is_err());
    assert!(payout
        .check_output(1, payout.lock, 120, 120, true, &[])
        .is_err());
    assert!(payout.check_vault_capacity(&f.vault, 1100, 1030).is_ok());
    assert!(payout.check_vault_capacity(&f.vault, 1100, 1029).is_err());
    assert!(payout.check_vault_capacity(&f.vault, 1101, 1030).is_err());
}

#[test]
fn canonical_claim_witness_rejects_truncation_suffix_unknown_kind_and_bad_lengths() {
    let f = fixture(1);
    for witness in [&f.release, &f.escape, &f.refund] {
        let bytes = witness.encode().unwrap();
        assert_eq!(ClaimWitness::decode(&bytes).unwrap(), *witness);
        for cut in 0..bytes.len() {
            assert!(ClaimWitness::decode(&bytes[..cut]).is_err());
        }
        let mut bad = bytes.clone();
        bad.push(0);
        assert!(ClaimWitness::decode(&bad).is_err());
        let mut bad = bytes;
        bad[8] = 3;
        assert!(ClaimWitness::decode(&bad).is_err());
    }
    let mut bad = f.refund.encode().unwrap();
    bad[85..89].copy_from_slice(&u32::MAX.to_le_bytes());
    assert_eq!(ClaimWitness::decode(&bad), Err(Error::Limit));
}

#[test]
fn independent_python_claim_vectors_match_fields_and_maximum_codec_envelope() {
    use alloy_primitives::B256;
    use tactus_o1_state_proof_script::Claim;
    let proof = StateProof {
        claim: Claim {
            root: B256::repeat_byte(17),
            header: B256::repeat_byte(18),
            settled_batches: 1,
            address: [12; 20],
            exists: true,
            nonce: 1,
            balance: U256::from(2),
            storage_root: B256::repeat_byte(25),
            code_hash: B256::repeat_byte(26),
            slot: B256::repeat_byte(27),
            value: U256::from(3),
        },
        proof: encode_proofs(&[], &[]).unwrap(),
    };
    let mut signature = [1; 65];
    signature[64] = 0;
    let requests = [
        (
            "claim_release",
            Request::Release {
                id: 1,
                amount: 7,
                recipient: [24; 32],
                owner: [23; 20],
                bridge: proof.clone(),
            },
        ),
        (
            "claim_refund",
            Request::Refund {
                receipt_outpoint: [22; 36],
            },
        ),
        (
            "claim_escape",
            Request::Escape {
                owner: [23; 20],
                amount: 7,
                recipient: [24; 32],
                signature,
                bridge: proof.clone(),
                account: Box::new(proof),
            },
        ),
    ];
    for (name, request) in requests {
        let expected = ClaimWitness {
            payout: 1,
            control_outpoint: [21; 36],
            request,
            nullifier: NullifierProof::empty(),
        };
        let text = include_str!("../../../specs/test-vectors/v02.txt")
            .lines()
            .find_map(|line| line.strip_prefix(&format!("{name}=")))
            .unwrap();
        let bytes: Vec<_> = text
            .as_bytes()
            .chunks_exact(2)
            .map(|b| u8::from_str_radix(core::str::from_utf8(b).unwrap(), 16).unwrap())
            .collect();
        assert_eq!(ClaimWitness::decode(&bytes).unwrap(), expected);
        assert_eq!(expected.encode().unwrap(), bytes);
    }
    // The parser's maximum is larger than valid deep MPT witnesses. Exercise
    // it as framing only; padded proof payloads are not cryptographic evidence.
    let mut maximum = fixture(1).escape;
    let Request::Escape {
        bridge, account, ..
    } = &mut maximum.request
    else {
        unreachable!()
    };
    bridge
        .proof
        .resize(tactus_o1_state_proof_script::MAX_PROOF_BYTES, 0);
    account
        .proof
        .resize(tactus_o1_state_proof_script::MAX_PROOF_BYTES, 0);
    maximum.nullifier = NullifierProof {
        bitmap: [255; 32],
        siblings: vec![[1; 32]; 256],
    };
    let bytes = maximum.encode().unwrap();
    assert_eq!(bytes.len(), ClaimWitness::MAX_BYTES);
    assert_eq!(ClaimWitness::decode(&bytes).unwrap(), maximum);
    let mut bad = bytes.clone();
    bad.push(0);
    assert_eq!(ClaimWitness::decode(&bad), Err(Error::Limit));
    let mut bad = bytes;
    bad[446..450].copy_from_slice(&u32::MAX.to_le_bytes());
    assert_eq!(ClaimWitness::decode(&bad), Err(Error::Limit));
}
