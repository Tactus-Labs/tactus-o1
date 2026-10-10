use tactus_o1_native_settlement_script::*;
fn fixture(prefix: bool) -> (Config, [u8; 32], Tip, Tip, [u8; JOURNAL_BYTES]) {
    let j = if prefix {
        *include_bytes!(
            "../../../specs/evidence/native-guest/execution/execute-1/public-values.bin"
        )
    } else {
        *include_bytes!(
            "../../../specs/evidence/native-guest/execution/execute-0/public-values.bin"
        )
    };
    let cfg = Config {
        ckb_genesis: j[80..112].try_into().unwrap(),
        anchor_type_hash: j[204..236].try_into().unwrap(),
        allocation_commitment: j[236..268].try_into().unwrap(),
        vault_identity: j[48..80].try_into().unwrap(),
    };
    let before = if prefix {
        Tip {
            initialized: true,
            anchor: j[268..468].try_into().unwrap(),
            state_root: j[780..812].try_into().unwrap(),
            header_hash: j[844..876].try_into().unwrap(),
        }
    } else {
        Tip::initial(j[268..468].try_into().unwrap()).unwrap()
    };
    let after = Tip {
        initialized: true,
        anchor: j[524..724].try_into().unwrap(),
        state_root: j[812..844].try_into().unwrap(),
        header_hash: j[876..908].try_into().unwrap(),
    };
    (cfg, j[172..204].try_into().unwrap(), before, after, j)
}
#[test]
fn exact_native_journals_bind_full_boundaries_and_pinned_profile() {
    for prefix in [false, true] {
        let (c, own, b, a, j) = fixture(prefix);
        let (bs, as_) = transition(&c, &own, &b, &a, &j).unwrap();
        assert_eq!(bs.encode()[8..172], j[40..204]);
        assert_eq!(bs.encode()[172..], j[268..524]);
        assert_eq!(as_.encode()[172..], j[524..780]);
        for offset in [
            0, 8, 48, 80, 112, 144, 172, 204, 236, 268, 308, 524, 564, 812, 876,
        ] {
            let mut bad = j;
            bad[offset] ^= 1;
            assert!(
                transition(&c, &own, &b, &a, &bad).is_err(),
                "{prefix} {offset}"
            );
        }
        if prefix {
            for offset in [780, 844] {
                let mut bad = j;
                bad[offset] ^= 1;
                assert!(transition(&c, &own, &b, &a, &bad).is_err());
            }
        }
        let mut other = own;
        other[0] ^= 1;
        assert!(transition(&c, &other, &b, &a, &j).is_err());
        for offset in [8, 40, 72, 104] {
            let mut wire = c.encode();
            wire[offset] ^= 1;
            let wrong = Config::decode(&wire).unwrap();
            assert!(transition(&wrong, &own, &b, &a, &j).is_err());
        }
    }
    let result: serde_json::Value = serde_json::from_str(include_str!(
        "../../../specs/evidence/native-guest/execution/execute-0/result.json"
    ))
    .unwrap();
    assert_eq!(result["guest_verifying_key"], GUEST_KEY);
}
#[test]
fn cursor_authentication_requires_exact_checkpoint_not_only_base_tip() {
    let (c, own, b, a, j) = fixture(true);
    let (original, _) = transition(&c, &own, &b, &a, &j).unwrap();
    // These deliberately pass structural checks: mandatory on-chain full-state
    // checkpoint comparison is what rejects a forged prefix accumulator.
    let mut bad = j;
    bad[492] ^= 1;
    let (forged, _) = transition(&c, &own, &b, &a, &bad).unwrap();
    assert_eq!(original.anchor.ordering, forged.anchor.ordering);
    assert_ne!(original.encode(), forged.encode());
    let mut bad = j;
    bad[724..732].copy_from_slice(&j[468..476]);
    assert!(transition(&c, &own, &b, &a, &bad).is_err());
    let (c, own, b, a, mut j) = fixture(false);
    j[468] ^= 1;
    assert!(transition(&c, &own, &b, &a, &j).is_err());
}
#[test]
fn framing_and_tip_are_strict_without_mock_verification() {
    let (c, _, b, a, j) = fixture(false);
    for len in 0..CONFIG_BYTES {
        assert!(Config::decode(&c.encode()[..len]).is_err());
    }
    for t in [a, b] {
        for len in 0..TIP_BYTES {
            assert!(Tip::decode(&t.encode()[..len]).is_err());
        }
    }
    let mut wire = b"TO1NSW02".to_vec();
    wire.extend_from_slice(&j);
    wire.extend_from_slice(&1u32.to_le_bytes());
    wire.push(42);
    assert_eq!(witness(&wire), Ok((&j, &[42][..])));
    for len in 0..wire.len() {
        assert!(witness(&wire[..len]).is_err());
    }
    wire.push(0);
    assert!(witness(&wire).is_err());
    wire[948..952].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(witness(&wire).is_err());
    let old = include_bytes!("../../../specs/evidence/sealed-chain-proof/proof/groth16-proof.bin");
    assert!(sp1_verifier::Groth16Verifier::verify(
        old,
        &j,
        GUEST_KEY,
        &sp1_verifier::GROTH16_VK_BYTES
    )
    .is_err());
}
