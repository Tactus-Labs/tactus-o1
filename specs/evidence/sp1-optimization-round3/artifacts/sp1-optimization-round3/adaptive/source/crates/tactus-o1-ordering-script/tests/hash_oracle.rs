//! Cross-checks ckb_blake2b against the ckb-cli `util blake2b` oracle.
//! Ground truth (ckb-cli v0.210.0):
//!   blake2b(0x0102030405) = 0x92127fcdf8cfe548d605843a48c294179711fa81c84ad1ea7f109f8d462e4f22
#[test]
fn ckb_blake2b_matches_ckb_cli_oracle() {
    let h = tactus_o1_ordering_script::ckb_blake2b(&[1, 2, 3, 4, 5]);
    let hex: String = h.iter().map(|x| format!("{x:02x}")).collect();
    assert_eq!(
        hex,
        "92127fcdf8cfe548d605843a48c294179711fa81c84ad1ea7f109f8d462e4f22"
    );
}
