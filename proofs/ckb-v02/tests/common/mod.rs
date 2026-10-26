#![allow(dead_code)]
//! Real trie and ECDSA checks over synthetic states, not CKB settlement evidence.
use alloy_primitives::{keccak256, Bytes, B256, U256};
use alloy_trie::{proof::ProofRetainer, HashBuilder, Nibbles, TrieAccount, EMPTY_ROOT_HASH};
use k256::ecdsa::SigningKey;
use tactus_o1_protocol::v02::*;
use tactus_o1_state_proof_script::{encode_proofs, Claim};
use tactus_v02_script::claims::*;

pub fn signing_key() -> SigningKey {
    SigningKey::from_bytes((&[21; 32]).into()).unwrap()
}
pub fn owner() -> [u8; 20] {
    keccak256(
        &signing_key()
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()[1..],
    )[12..]
        .try_into()
        .unwrap()
}
fn trie(mut entries: Vec<(B256, Vec<u8>)>, targets: &[B256]) -> (B256, Vec<Vec<Bytes>>) {
    entries.sort_by_key(|e| e.0);
    let paths: Vec<_> = targets.iter().map(|key| Nibbles::unpack(*key)).collect();
    let mut builder = HashBuilder::default().with_proof_retainer(ProofRetainer::new(paths.clone()));
    for (key, value) in entries {
        builder.add_leaf(Nibbles::unpack(key), &value);
    }
    let root = builder.root();
    let nodes = builder.take_proof_nodes();
    (
        root,
        paths
            .iter()
            .map(|path| {
                nodes
                    .matching_nodes_sorted(path)
                    .into_iter()
                    .map(|(_, node)| node)
                    .collect()
            })
            .collect(),
    )
}
pub struct Fixture {
    pub config: Config,
    pub policy: Policy,
    pub control: Control,
    pub vault: Vault,
    pub receipt: Deposit,
    pub release: ClaimWitness,
    pub escape: ClaimWitness,
    pub refund: ClaimWitness,
}
impl Fixture {
    pub fn context(&self) -> Context<'_> {
        Context {
            config: &self.config,
            policy: &self.policy,
            control: &self.control,
            control_outpoint: [91; 36],
            vault: &self.vault,
            receipt: Some(([92; 36], &self.receipt)),
        }
    }
}

// mode: 0 absent native account, 1 empty-code EOA, 2 contract account.
pub fn fixture(mode: u8) -> Fixture {
    let policy = Policy {
        lanes: 4,
        max_pending_batches: 32,
        max_pending_deposits: 32,
        stall_blocks: 120,
        priority_gas: 250000,
        credit_gas: 200000,
        rules: [1; 32],
        profile: [2; 32],
        guest_key: [3; 32],
        wrapper_key_hash: [4; 32],
        bridge_code_hash: keccak256([0x60, 0]).0,
    };
    let config = Config {
        domain: [5; 32],
        ckb_genesis: [6; 32],
        adapter_code_hash: [7; 32],
        head_lock_code_hash: [8; 32],
        policy: policy.commitment().unwrap(),
        allocation: [9; 32],
        chain: 71402,
        bridge: [10; 20],
    };
    with_config(mode, config, policy, 1000, [94; 32], [95; 32])
}

/// Injected settled state for script authorization tests, not a valid proof.
pub fn with_config(
    mode: u8,
    config: Config,
    policy: Policy,
    reserve: u64,
    release_recipient: [u8; 32],
    escape_recipient: [u8; 32],
) -> Fixture {
    let initial = Control::genesis(&config, &policy).unwrap();
    let (vault, receipt) = Vault::genesis(config.commitment().unwrap(), reserve)
        .unwrap()
        .deposit(&config, &policy, &initial, owner(), 100, [93; 32])
        .unwrap();
    let mut control = initial;
    control.mode = Mode::Frozen;
    control.initialized = true;
    control.boundary.batches = 1;
    control.boundary.blocks = 1;
    control.boundary.timestamp = 100;
    control.boundary.inputs = [11; 32];
    control.boundary.deposits = vault.deposits;
    control.boundary.epoch = 1;
    control.boundary.snapshot = [12; 32];
    control.boundary.epoch_batches = 1;
    control.block_hash = [13; 32];
    control.supply = 70;
    control.burned = 30;
    let mut owner_word = [0; 32];
    owner_word[12..].copy_from_slice(&owner());
    let balance_slot = mapping_slot(owner_word, 3);
    let withdrawal_slot = mapping_slot(U256::from(1).to_be_bytes::<32>(), 7);
    let withdrawal =
        U256::from_be_bytes(withdrawal_commitment(&config, 1, 30, &release_recipient, &owner()).0);
    let (storage_root, storage_proofs) = trie(
        vec![
            (keccak256(balance_slot), alloy_rlp::encode(U256::from(70))),
            (keccak256(withdrawal_slot), alloy_rlp::encode(withdrawal)),
        ],
        &[keccak256(balance_slot), keccak256(withdrawal_slot)],
    );
    let bridge_account = TrieAccount::new(
        1,
        U256::ZERO,
        storage_root,
        B256::from(policy.bridge_code_hash),
    );
    let owner_code = if mode == 2 {
        keccak256([0x60, 1])
    } else {
        keccak256([])
    };
    let mut accounts = vec![(keccak256(config.bridge), alloy_rlp::encode(bridge_account))];
    if mode != 0 {
        accounts.push((
            keccak256(owner()),
            alloy_rlp::encode(TrieAccount::new(
                1,
                U256::from(10),
                EMPTY_ROOT_HASH,
                owner_code,
            )),
        ));
    }
    let (root, account_proofs) = trie(accounts, &[keccak256(config.bridge), keccak256(owner())]);
    control.state_root = root.0;
    control.validate().unwrap();
    vault.partitions(&control).unwrap();
    let bridge_claim = |slot, value| Claim {
        root,
        header: B256::from(control.block_hash),
        settled_batches: 1,
        address: config.bridge,
        exists: true,
        nonce: 1,
        balance: U256::ZERO,
        storage_root,
        code_hash: B256::from(policy.bridge_code_hash),
        slot,
        value,
    };
    let balance = StateProof {
        claim: bridge_claim(balance_slot, U256::from(70)),
        proof: encode_proofs(&account_proofs[0], &storage_proofs[0]).unwrap(),
    };
    let burn = StateProof {
        claim: bridge_claim(withdrawal_slot, withdrawal),
        proof: encode_proofs(&account_proofs[0], &storage_proofs[1]).unwrap(),
    };
    let account = StateProof {
        claim: Claim {
            root,
            header: B256::from(control.block_hash),
            settled_batches: 1,
            address: owner(),
            exists: mode != 0,
            nonce: if mode == 0 { 0 } else { 1 },
            balance: if mode == 0 {
                U256::ZERO
            } else {
                U256::from(10)
            },
            storage_root: if mode == 0 {
                B256::ZERO
            } else {
                EMPTY_ROOT_HASH
            },
            code_hash: if mode == 0 { B256::ZERO } else { owner_code },
            slot: B256::ZERO,
            value: U256::ZERO,
        },
        proof: encode_proofs(&account_proofs[1], &[]).unwrap(),
    };
    let digest = escape_digest(
        &config,
        &control,
        &[91; 36],
        &owner(),
        70,
        &escape_recipient,
    )
    .unwrap();
    let (sig, recovery) = signing_key().sign_prehash_recoverable(&digest).unwrap();
    let mut signature = [0; 65];
    signature[..64].copy_from_slice(&sig.to_bytes());
    signature[64] = recovery.to_byte();
    let release = ClaimWitness {
        payout: 1,
        control_outpoint: [91; 36],
        nullifier: NullifierProof::empty(),
        request: Request::Release {
            id: 1,
            amount: 30,
            recipient: release_recipient,
            owner: owner(),
            bridge: burn,
        },
    };
    let escape = ClaimWitness {
        payout: 1,
        control_outpoint: [91; 36],
        nullifier: NullifierProof::empty(),
        request: Request::Escape {
            owner: owner(),
            amount: 70,
            recipient: escape_recipient,
            signature,
            bridge: balance,
            account: Box::new(account),
        },
    };
    let refund = ClaimWitness {
        payout: 1,
        control_outpoint: [91; 36],
        nullifier: NullifierProof::empty(),
        request: Request::Refund {
            receipt_outpoint: [92; 36],
        },
    };
    Fixture {
        config,
        policy,
        control,
        vault,
        receipt,
        release,
        escape,
        refund,
    }
}

/// Conservative trie envelope with engineered hashed-key neighbours. These
/// keys need not have address/slot preimages: this measures accepted proof
/// structure under a synthetic root, not a reachable canonical EVM history.
fn deep_trie(entries: Vec<(B256, Vec<u8>)>, targets: &[B256]) -> (B256, Vec<Vec<Bytes>>) {
    let mut expanded = std::collections::BTreeMap::new();
    for target in targets {
        for depth in 0..64 {
            let shift = if depth % 2 == 0 { 4 } else { 0 };
            let actual = (target[depth / 2] >> shift) & 15;
            for sibling in 0..16u8 {
                if sibling == actual {
                    continue;
                }
                let mut key = *target;
                key[depth / 2] = (key[depth / 2] & !(15 << shift)) | (sibling << shift);
                // Large leaf values ensure sibling references are hashes.
                expanded.insert(key, vec![0x5a; 80]);
            }
        }
    }
    expanded.extend(entries);
    let (root, mut proofs) = trie(expanded.into_iter().collect(), targets);
    for nodes in &mut proofs {
        assert_eq!(nodes.len(), 65, "64 branch levels plus leaf");
        assert!(nodes.iter().all(|node| node.len() <= 532));
        // A short terminal leaf is already embedded in its parent branch.
        // Supplying it again would be a noncanonical extra proof node.
        if nodes.last().unwrap().len() < 32 {
            nodes.pop();
        }
    }
    (root, proofs)
}

pub fn deepen_fixture(f: &mut Fixture) {
    let Request::Release { bridge: burn, .. } = &mut f.release.request else {
        unreachable!()
    };
    let Request::Escape {
        bridge: balance,
        account,
        ..
    } = &mut f.escape.request
    else {
        unreachable!()
    };
    let slots = [keccak256(balance.claim.slot), keccak256(burn.claim.slot)];
    let (storage_root, storage_proofs) = deep_trie(
        vec![
            (slots[0], alloy_rlp::encode(balance.claim.value)),
            (slots[1], alloy_rlp::encode(burn.claim.value)),
        ],
        &slots,
    );
    let keys = [keccak256(f.config.bridge), keccak256(owner())];
    let (root, account_proofs) = deep_trie(
        vec![
            (
                keys[0],
                alloy_rlp::encode(TrieAccount::new(
                    1,
                    U256::ZERO,
                    storage_root,
                    B256::from(f.policy.bridge_code_hash),
                )),
            ),
            (
                keys[1],
                alloy_rlp::encode(TrieAccount::new(
                    account.claim.nonce,
                    account.claim.balance,
                    account.claim.storage_root,
                    account.claim.code_hash,
                )),
            ),
        ],
        &keys,
    );
    f.control.state_root = root.0;
    for (proof, nodes) in [(balance, &storage_proofs[0]), (burn, &storage_proofs[1])] {
        proof.claim.root = root;
        proof.claim.storage_root = storage_root;
        proof.proof = encode_proofs(&account_proofs[0], nodes).unwrap();
        tactus_o1_state_proof_script::verify(&proof.claim, &proof.proof).unwrap();
    }
    account.claim.root = root;
    account.proof = encode_proofs(&account_proofs[1], &[]).unwrap();
    tactus_o1_state_proof_script::verify(&account.claim, &account.proof).unwrap();
}

/// All 256 non-default siblings, independently reconstructing the unspent root.
/// Opaque sibling roots bound verification work; no historical claims are implied.
pub fn full_nullifier(
    config: &[u8; 32],
    kind: ClaimKind,
    identity: &[u8],
) -> (NullifierProof, [u8; 32]) {
    let key = claim_key(config, kind, identity).unwrap();
    let proof = NullifierProof {
        bitmap: [255; 32],
        siblings: (0..256u16)
            .map(|i| hash(b"resource-fixture-sibling", &i.to_le_bytes()))
            .collect(),
    };
    let mut root = hash(
        b"tactus/0.02/claim/leaf",
        &[config.as_slice(), &[kind as u8, 0]].concat(),
    );
    for (level, sibling) in proof.siblings.iter().enumerate() {
        let bit = 255 - level;
        let (left, right) = if key[bit / 8] & (1 << (7 - bit % 8)) == 0 {
            (&root, sibling)
        } else {
            (sibling, &root)
        };
        root = hash(
            b"tactus/0.02/claim/branch",
            &[&(level as u16).to_le_bytes()[..], left, right].concat(),
        );
    }
    assert_eq!(proof.encode().unwrap().len(), NullifierProof::MAX_BYTES);
    assert_ne!(proof.insert(config, kind, &key, &root).unwrap(), root);
    (proof, root)
}
