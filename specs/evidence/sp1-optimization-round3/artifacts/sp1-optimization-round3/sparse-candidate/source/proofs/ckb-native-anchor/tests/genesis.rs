use tactus_o1_native_anchor_script::{runtime, validate_allocation, State, RULES, STATE_BYTES};
use tactus_o1_protocol::genesis::{self, Account, Allocation};

fn decode(s: &str) -> Vec<u8> {
    s.trim_start_matches("0x")
        .as_bytes()
        .chunks_exact(2)
        .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
        .collect()
}
fn actual() -> (State, Vec<u8>) {
    let v: serde_json::Value = serde_json::from_str(include_str!(
        "../../../specs/evidence/native-publication/0.210.0/deployment.json"
    ))
    .unwrap();
    (
        State::decode(&decode(v["genesis_state"].as_str().unwrap())).unwrap(),
        decode(v["genesis_allocation"].as_str().unwrap()),
    )
}
#[test]
fn actual_genesis_binds_current_profile_and_exact_zero_storage_runtime() {
    let (s, bytes) = actual();
    assert_eq!(s, State::genesis(s.config.clone()).unwrap());
    assert_eq!(s.anchor.ordering.execution_rules_hash, RULES);
    validate_allocation(&s.config, &bytes, genesis::commitment(&bytes).unwrap()).unwrap();
    let a = Allocation::decode(&bytes).unwrap();
    assert_eq!(
        a.accounts
            .iter()
            .find(|a| a.address == s.config.contract)
            .unwrap()
            .code,
        runtime(&s.config)
    );
    let candidate: serde_json::Value = serde_json::from_str(include_str!(
        "../../../specs/evidence/native-bridge-execution/candidate.json"
    ))
    .unwrap();
    assert_eq!(
        RULES.as_slice(),
        decode(candidate["rules_hash"].as_str().unwrap())
    );
}
#[test]
fn allocation_cannot_forge_system_authority_or_initial_token_ownership() {
    let (s, bytes) = actual();
    let original = Allocation::decode(&bytes).unwrap();
    for mode in 0..7 {
        let mut a = original.clone();
        let i = a
            .accounts
            .iter()
            .position(|a| a.address == s.config.contract)
            .unwrap();
        match mode {
            0 => a.accounts[i].storage.push(([0; 32], [1; 32])),
            1 => a.accounts[i].nonce = 0,
            2 => a.accounts[i].balance[31] = 1,
            3 => a.accounts[i].code[0] ^= 1,
            4 => {
                a.accounts.remove(i);
            }
            5 => a.accounts.insert(
                0,
                Account {
                    address: [0; 20],
                    balance: [0; 32],
                    nonce: 1,
                    code: vec![],
                    storage: vec![],
                },
            ),
            _ => a.accounts.insert(
                0,
                Account {
                    address: [0; 20],
                    balance: [0; 32],
                    nonce: 0,
                    code: vec![0],
                    storage: vec![],
                },
            ),
        }
        let encoded = a.encode().unwrap();
        let hash = genesis::commitment(&encoded).unwrap();
        assert_eq!(
            validate_allocation(&s.config, &encoded, hash),
            Err(6),
            "mode {mode}"
        );
    }
    assert_eq!(validate_allocation(&s.config, &bytes, [0; 32]), Err(6));
    let mut precompile = s.config.clone();
    precompile.contract = [0; 20];
    precompile.contract[19] = 1;
    assert_eq!(
        validate_allocation(&precompile, &bytes, genesis::commitment(&bytes).unwrap()),
        Err(6)
    );
}
#[test]
fn metadata_wire_and_runtime_domain_reject_cross_deployment_changes() {
    let (s, _) = actual();
    let raw = s.encode();
    assert_eq!(raw.len(), STATE_BYTES);
    for end in 0..raw.len() {
        assert!(State::decode(&raw[..end]).is_err());
    }
    let mut long = raw.to_vec();
    long.push(0);
    assert!(State::decode(&long).is_err());
    for i in [0, 8 + 72, 172 + 8, 172 + 96, 172 + 192] {
        let mut b = raw;
        b[i] ^= 1;
        assert!(State::decode(&b).is_err());
    }
    let code = runtime(&s.config);
    for mode in 0..5 {
        let mut c = s.config.clone();
        match mode {
            0 => c.identity[0] ^= 1,
            1 => c.ckb_genesis[0] ^= 1,
            2 => c.rollup[0] ^= 1,
            3 => c.chain += 1,
            _ => c.contract[0] ^= 1,
        }
        assert_ne!(runtime(&c), code);
    }
    // Settlement identity is fixed by anchor metadata, not the EVM allocation;
    // putting it in DOMAIN would reintroduce a deployment hash cycle.
    let mut c = s.config.clone();
    c.settlement[0] ^= 1;
    assert_eq!(runtime(&c), code);
    assert_ne!(c.deposit_id(1), s.config.deposit_id(1));
    assert_ne!(State::genesis(c).unwrap().encode(), raw);
}
