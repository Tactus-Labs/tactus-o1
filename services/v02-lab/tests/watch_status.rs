//! Reporting over explicit synthetic states, paired with actual-chain checks in replay-v02.
#[path = "../../../proofs/ckb-v02/tests/common/mod.rs"]
mod common;
use serde_json::json;
use std::collections::BTreeMap;
use tactus_o1_devnet_driver::{rpc, tx::CellOutPoint};
use tactus_o1_execution::{v02::V02Executor, Genesis};
use tactus_o1_protocol::v02::*;
use tactus_v02_lab::{
    build::{self, Cell},
    nullifiers::Tree,
    point_bytes,
    recover::{Manifest, Recovered},
};
#[path = "../../../proofs/v02-sp1/journal/tests/common/mod.rs"]
mod replay;
#[test]
fn watcher_reports_both_ages_pending_work_and_terminal_mode() {
    let f = replay::fixture([13; 32]);
    let genesis =
        Genesis::from_allocation(f.config.domain.into(), f.config.chain, &f.allocation).unwrap();
    let execution = V02Executor::new(&genesis, f.config.clone(), f.policy.clone()).unwrap();
    let control = execution.control_candidate().unwrap();
    let vault = Vault::genesis(f.config.commitment().unwrap(), 1000).unwrap();
    let ticket = Watch {
        config: f.config.commitment().unwrap(),
        work: Work::Deposit(1),
        source: [5; 36],
        observed_control: control.commitment().unwrap(),
        refund_lock: [6; 32],
    };
    let mut cells = BTreeMap::new();
    let mut transitions = vec![];
    for (hash, role, data, height) in [
        (91, Role::Control, control.encode().unwrap(), 1),
        (92, Role::Watch, ticket.encode().unwrap(), 200),
    ] {
        let point = CellOutPoint {
            tx_hash: [hash; 32],
            index: 0,
        };
        cells.insert(
            point_bytes(point),
            Cell {
                point,
                output: build::typed(&f.config, role, 0, data, None).unwrap(),
            },
        );
        transitions
            .push(json!({"tx_hash":rpc::bytes_to_hex(&point.tx_hash),"block_number":height}));
    }
    let id = f.config.commitment().unwrap();
    let mut recovered = Recovered {
        manifest: Manifest {
            config: f.config,
            policy: f.policy,
            genesis_tx: [93; 32],
            monitoring: Default::default(),
        },
        tip: json!({"number":"0xc8"}),
        cells,
        frames: vec![],
        allocation: f.allocation,
        control,
        vault,
        claims: [
            Tree::new(id, ClaimKind::Release),
            Tree::new(id, ClaimKind::Refund),
            Tree::new(id, ClaimKind::Escape),
        ],
        transitions,
        execution,
    };
    let young = recovered.operations().unwrap();
    assert_eq!(young["watches"][0]["eligible_for_next_block"], false);
    assert_eq!(young["watches"][0]["earliest_candidate_height"], 320);
    assert_eq!(
        young["watches"][0]["remaining_blocks_before_candidate"],
        119
    );
    recovered.tip["number"] = json!("0x13f"); // tip 319, candidate 320
    assert_eq!(
        recovered.operations().unwrap()["watches"][0]["eligible_for_next_block"],
        true
    );
    recovered.control.mode = Mode::Frozen;
    let frozen = recovered.operations().unwrap();
    assert_eq!(frozen["watches"][0]["eligible_for_next_block"], false);
    assert_eq!(frozen["watches"][0]["close_allowed"], true);
    recovered.control.mode = Mode::Running;
    recovered.transitions[0]["block_number"] = json!(300);
    assert_eq!(
        recovered.operations().unwrap()["watches"][0]["eligible_for_next_block"],
        false
    );
    assert_eq!(
        recovered.operations().unwrap()["watches"][0]["earliest_candidate_height"],
        420
    );
    recovered.transitions.clear();
    assert!(recovered.operations().is_err());
}
