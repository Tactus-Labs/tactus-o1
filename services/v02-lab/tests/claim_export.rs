//! Synthetic settled fixtures test export correctness, not proof validity.
#[path = "../../../proofs/ckb-v02/tests/common/mod.rs"]
mod common;
#[path = "../../../proofs/v02-sp1/journal/tests/common/mod.rs"]
mod replay;
use alloy_primitives::{Address, Bytes, B256, U256};
use serde_json::json;
use std::collections::BTreeMap;
use tactus_o1_devnet_driver::{rpc, tx::CellOutPoint};
use tactus_o1_execution::{v02::V02Executor, Genesis, GenesisAccount};
use tactus_o1_protocol::v02::*;
use tactus_v02_lab::{
    build,
    claim_export::*,
    nullifiers::Tree,
    point_bytes,
    recover::{Manifest, Recovered},
    state_proof,
};
use tactus_v02_script::claims::*;

fn accounts(f: &common::Fixture, mode: u8) -> BTreeMap<Address, GenesisAccount> {
    let mut owner = [0; 32];
    owner[12..].copy_from_slice(&common::owner());
    let storage = BTreeMap::from([
        (
            U256::from_be_bytes(mapping_slot(owner, 3).0),
            U256::from(70),
        ),
        (
            U256::from_be_bytes(mapping_slot(U256::from(1).to_be_bytes::<32>(), 7).0),
            U256::from_be_bytes(
                withdrawal_commitment(&f.config, 1, 30, &[94; 32], &common::owner()).0,
            ),
        ),
    ]);
    let mut accounts = BTreeMap::from([(
        Address::from(f.config.bridge),
        GenesisAccount {
            nonce: 1,
            code: Bytes::from_static(&[0x60, 0]),
            storage,
            ..Default::default()
        },
    )]);
    if mode != 0 {
        accounts.insert(
            common::owner().into(),
            GenesisAccount {
                nonce: 1,
                balance: U256::from(10),
                code: if mode == 2 {
                    Bytes::from_static(&[0x60, 1])
                } else {
                    Bytes::new()
                },
                ..Default::default()
            },
        );
    }
    accounts
}
#[test]
fn reconstructed_burn_proofs_authorize_and_reject_redirected_receipts() {
    let f = common::fixture(1);
    let accounts = accounts(&f, 1);
    let mut input = json!({"id":"1","amount_shannons":"30","owner":rpc::bytes_to_hex(&common::owner()),"recipient_lock_hash":rpc::bytes_to_hex(&[94;32])});
    let mut witness = f.release.clone();
    witness.request = release_request(&accounts, &f.context(), &input).unwrap();
    assert_eq!(witness.authorize(&f.context()).unwrap().amount, 30);
    for field in ["id", "amount_shannons", "owner", "recipient_lock_hash"] {
        let original = input[field].clone();
        input[field] = match field {
            "id" => json!("2"),
            "amount_shannons" => json!("31"),
            "owner" => json!(rpc::bytes_to_hex(&[99; 20])),
            _ => json!(rpc::bytes_to_hex(&[99; 32])),
        };
        witness.request = release_request(&accounts, &f.context(), &input).unwrap();
        assert!(witness.authorize(&f.context()).is_err(), "{field}");
        input[field] = original;
    }
    let mut wrong = accounts;
    wrong
        .get_mut(&Address::from(f.config.bridge))
        .unwrap()
        .nonce += 1;
    assert!(release_request(&wrong, &f.context(), &input).is_err());
}
#[test]
fn escape_reconstructs_inclusion_and_absence_then_checks_real_signature() {
    for mode in [0, 1, 2] {
        let f = common::fixture(mode);
        let accounts = accounts(&f, mode);
        let input = json!({"owner":rpc::bytes_to_hex(&common::owner()),"recipient_lock_hash":rpc::bytes_to_hex(&[95;32])});
        let request = escape_request(&accounts, &f.context(), &input);
        if mode == 2 {
            assert!(request.is_err());
            continue;
        }
        let mut witness = f.escape.clone();
        witness.request = request.unwrap();
        assert!(witness.authorize(&f.context()).is_err());
        let digest = escape_digest(
            &f.config,
            &f.control,
            &[91; 36],
            &common::owner(),
            70,
            &[95; 32],
        )
        .unwrap();
        let (signature, recovery) = common::signing_key()
            .sign_prehash_recoverable(&digest)
            .unwrap();
        let mut bytes = signature.to_bytes().to_vec();
        bytes.push(recovery.to_byte());
        let mut signed = input.clone();
        signed["signature_hex"] = json!(rpc::bytes_to_hex(&bytes));
        witness.request = escape_request(&accounts, &f.context(), &signed).unwrap();
        assert_eq!(witness.authorize(&f.context()).unwrap().amount, 70);
        signed["recipient_lock_hash"] = json!(rpc::bytes_to_hex(&[96; 32]));
        witness.request = escape_request(&accounts, &f.context(), &signed).unwrap();
        assert!(witness.authorize(&f.context()).is_err());
    }
}
fn recovered() -> Recovered {
    let f = replay::fixture([13; 32]);
    let genesis =
        Genesis::from_allocation(f.config.domain.into(), f.config.chain, &f.allocation).unwrap();
    let mut execution = V02Executor::new(&genesis, f.config.clone(), f.policy.clone()).unwrap();
    execution
        .apply_batch(&f.frames[0].batch.encode().unwrap(), &f.frames[0].snapshot)
        .unwrap();
    let mut control = execution.control_candidate().unwrap();
    control.mode = Mode::Frozen;
    execution
        .apply_batch(&f.frames[1].batch.encode().unwrap(), &f.frames[1].snapshot)
        .unwrap();
    let mut vault = Vault::genesis(f.config.commitment().unwrap(), 1000).unwrap();
    vault.deposits = f.frames[0].snapshot.deposit_end;
    let mut cells = BTreeMap::new();
    for (index, role, data) in [
        (0, Role::Control, control.encode().unwrap()),
        (1, Role::Vault, vault.encode().unwrap()),
    ] {
        let point = CellOutPoint {
            tx_hash: [91; 32],
            index,
        };
        let cell = build::Cell {
            point,
            output: build::typed(&f.config, role, 0, data, Some(100000000000)).unwrap(),
        };
        cells.insert(point_bytes(point), cell);
    }
    let identity = f.config.commitment().unwrap();
    Recovered {
        manifest: Manifest {
            config: f.config,
            policy: f.policy,
            genesis_tx: [92; 32],
            monitoring: Default::default(),
        },
        tip: json!({"hash":rpc::bytes_to_hex(&[93;32]),"number":"0x1"}),
        cells,
        allocation: f.allocation,
        frames: f.frames,
        control,
        vault,
        claims: [
            Tree::new(identity, ClaimKind::Release),
            Tree::new(identity, ClaimKind::Refund),
            Tree::new(identity, ClaimKind::Escape),
        ],
        transitions: vec![
            json!({"tx_hash":rpc::bytes_to_hex(&[91;32]),"block_number":1,"block_hash":rpc::bytes_to_hex(&[93;32])}),
        ],
        execution,
    }
}
#[test]
fn export_replays_only_settled_prefix_and_unsigned_escape_is_not_a_witness() {
    let mut r = recovered();
    assert_eq!(r.execution.boundary().batches, 2);
    let settled = r.settled_execution().unwrap();
    assert_eq!(settled.boundary().batches, 1);
    assert_eq!(settled.control_candidate().unwrap().supply, 400);
    assert_eq!(r.execution.control_candidate().unwrap().supply, 800);
    let input = json!({"owner":rpc::bytes_to_hex(&[20;20]),"recipient_lock_hash":rpc::bytes_to_hex(&[95;32])});
    let plan = r.asset_claim("escape", &input).unwrap();
    assert_eq!(plan["amount_shannons"], "400");
    assert_eq!(plan["claim_witness_available"], false);
    assert!(plan.get("claim_witness_hex").is_none());
    assert_eq!(
        plan["digest_hex"],
        rpc::bytes_to_hex(
            &escape_digest(
                &r.manifest.config,
                &r.control,
                &point_bytes(r.cell(Role::Control, 0).unwrap().point),
                &[20; 20],
                400,
                &[95; 32]
            )
            .unwrap()
        )
    );
    let mut signed = input.clone();
    signed["signature_hex"] = json!(rpc::bytes_to_hex(&[0; 65]));
    assert!(r.asset_claim("escape", &signed).is_err());
    // A valid MPT at the ordered head must not be exported under the older root.
    assert!(state_proof::prove(
        &r.execution.accounts().collect(),
        &r.control,
        r.manifest.config.bridge.into(),
        B256::ZERO
    )
    .is_err());
    r.control.state_root[0] ^= 1;
    assert!(r.settled_execution().is_err());
}
#[test]
fn claim_export_rejects_unsettled_running_missing_and_spent_states() {
    let mut r = recovered();
    let input = json!({"owner":rpc::bytes_to_hex(&[20;20]),"recipient_lock_hash":rpc::bytes_to_hex(&[95;32])});
    r.control.mode = Mode::Running;
    assert!(r.asset_claim("escape", &input).is_err());
    r.control.mode = Mode::Frozen;
    r.claims[2].record(&[20; 20]).unwrap();
    r.vault.claims[2] = r.claims[2].root();
    assert!(r.asset_claim("escape", &input).is_err());
    r.frames.clear();
    assert!(r.settled_execution().is_err());
    r.control = Control::genesis(&r.manifest.config, &r.manifest.policy).unwrap();
    assert!(r.settled_execution().is_err());
}

#[test]
fn later_publication_preserves_interval_and_overlapping_settlement_rebuilds_start() {
    let mut r = recovered();
    let frames = r.frames.clone();
    let genesis = Genesis::from_allocation(
        r.manifest.config.domain.into(),
        r.manifest.config.chain,
        &r.allocation,
    )
    .unwrap();
    r.execution = V02Executor::new(
        &genesis,
        r.manifest.config.clone(),
        r.manifest.policy.clone(),
    )
    .unwrap();
    r.frames = frames[..1].to_vec();
    r.execution
        .apply_batch(&frames[0].batch.encode().unwrap(), &frames[0].snapshot)
        .unwrap();
    let update_control = |r: &mut Recovered, control: Control, tx_hash: [u8; 32]| {
        let previous = point_bytes(r.cell(Role::Control, 0).unwrap().point);
        let mut cell = r.cells.remove(&previous).unwrap();
        cell.point.tx_hash = tx_hash;
        cell.output.data = control.encode().unwrap();
        r.control = control;
        r.cells.insert(point_bytes(cell.point), cell);
    };
    let initial = Control::genesis(&r.manifest.config, &r.manifest.policy).unwrap();
    update_control(&mut r, initial, [91; 32]);
    let first = r.proving_input(1).unwrap();
    let decode = |value: &serde_json::Value| {
        Journal::decode(
            &tactus_v02_lab::bytes(&value["expected_journal_hex"], Journal::MAX_BYTES).unwrap(),
        )
        .unwrap()
    };
    let first_journal = decode(&first);
    r.frames.push(frames[1].clone());
    r.execution
        .apply_batch(&frames[1].batch.encode().unwrap(), &frames[1].snapshot)
        .unwrap();
    r.tip = json!({"hash":rpc::bytes_to_hex(&[94;32]),"number":"0x2"});
    let after_publication = r.proving_input(1).unwrap();
    assert_eq!(
        after_publication["expected_journal_hex"],
        first["expected_journal_hex"]
    );
    assert_eq!(after_publication["frames"], first["frames"]);
    assert_eq!(
        after_publication["control_outpoint"],
        first["control_outpoint"]
    );
    // Inject the correctly executed endpoint as a *synthetic* competing
    // settlement; this does not claim a proof or canonical CKB transition.
    update_control(&mut r, first_journal.end.clone(), [95; 32]);
    assert!(r.proving_input(1).is_err());
    let rebuilt = r.proving_input(2).unwrap();
    assert_eq!(rebuilt["prefix_batches"], 1);
    assert_eq!(rebuilt["frames"].as_array().unwrap().len(), 2);
    assert_ne!(rebuilt["control_outpoint"], first["control_outpoint"]);
    assert_eq!(decode(&rebuilt).start, first_journal.end);
    assert_eq!(
        decode(&rebuilt).end,
        r.execution.control_candidate().unwrap()
    );
    let mut bad = r.control.clone();
    bad.state_root[0] ^= 1;
    update_control(&mut r, bad, [96; 32]);
    assert!(r
        .proving_input(2)
        .unwrap_err()
        .contains("proof start differs"));
}
