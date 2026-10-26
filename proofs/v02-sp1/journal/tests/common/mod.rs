#![allow(dead_code)]
use alloy_primitives::{keccak256, Address, U256};
use std::collections::BTreeMap;
use tactus_o1_execution::{
    v02::{self, V02Executor},
    Genesis, GenesisAccount,
};
use tactus_o1_protocol::{batch::BlockInput, v02::*};
use tactus_v02_proof_journal::Frame;

pub struct Fixture {
    pub config: Config,
    pub policy: Policy,
    pub allocation: Vec<u8>,
    pub frames: Vec<Frame>,
    pub end: Control,
}
pub fn fixture(key: [u8; 32]) -> Fixture {
    let mut config = Config {
        domain: Config::domain_id(&[6; 44], 0),
        ckb_genesis: [7; 32],
        adapter_code_hash: [8; 32],
        head_lock_code_hash: [9; 32],
        policy: [10; 32],
        allocation: [11; 32],
        chain: 71402,
        bridge: [12; 20],
    };
    let code = v02::runtime(&config);
    let genesis = Genesis {
        rollup_id: config.domain.into(),
        chain_id: config.chain,
        accounts: BTreeMap::from([
            (
                Address::from(config.bridge),
                GenesisAccount {
                    nonce: 1,
                    code: code.clone(),
                    ..Default::default()
                },
            ),
            (
                Address::repeat_byte(20),
                GenesisAccount {
                    balance: U256::from(10u64.pow(18)),
                    ..Default::default()
                },
            ),
        ]),
    };
    let policy = Policy {
        lanes: 4,
        max_pending_batches: 32,
        max_pending_deposits: 32,
        stall_blocks: 120,
        priority_gas: 250000,
        credit_gas: 200000,
        rules: v02::rules_hash(),
        profile: v02::profile_hash(),
        guest_key: key,
        wrapper_key_hash: [14; 32],
        bridge_code_hash: keccak256(code).0,
    };
    let allocation = genesis.allocation_bytes().unwrap();
    config.policy = policy.commitment().unwrap();
    config.allocation = tactus_o1_protocol::genesis::commitment(&allocation).unwrap();
    let mut engine = V02Executor::new(&genesis, config.clone(), policy.clone()).unwrap();
    let control = engine.control_candidate().unwrap();
    let mut vault = Vault::genesis(control.boundary.config, 1000).unwrap();
    let mut deposits = vec![];
    for _ in 0..32 {
        let (v, d) = vault
            .deposit(&config, &policy, &control, [20; 20], 100, [21; 32])
            .unwrap();
        vault = v;
        deposits.push(d);
    }
    let mut lanes: Vec<_> = (0..4)
        .map(|lane| Lane::genesis(control.boundary.config, lane).unwrap())
        .collect();
    for lane in &mut lanes {
        for _ in 0..8 {
            *lane = lane.enqueue(&control, &policy, vec![0xff]).unwrap().0;
        }
    }
    let (schedule, snapshot, _) = Schedule::genesis(control.boundary.config)
        .unwrap()
        .seal(
            &config,
            &policy,
            &control,
            &control.boundary,
            &lanes,
            &vault,
            None,
        )
        .unwrap();
    let users = snapshot.users().unwrap();
    let mut frames = vec![];
    for index in 0..8 {
        let priority = users[index * 4..(index + 1) * 4].to_vec();
        let transactions = priority.iter().map(|p| p.message.payload.clone()).collect();
        let frame = Frame {
            snapshot: snapshot.clone(),
            batch: NativeBatch {
                parent: engine.boundary().clone(),
                snapshot: schedule.snapshot,
                priority,
                deposits: deposits[index * 4..(index + 1) * 4].to_vec(),
                blocks: vec![BlockInput {
                    timestamp: 100,
                    fee_recipient: [22; 20],
                    transactions,
                }],
            },
        };
        engine
            .apply_batch(&frame.batch.encode().unwrap(), &frame.snapshot)
            .unwrap();
        frames.push(frame);
    }
    Fixture {
        config,
        policy,
        allocation,
        frames,
        end: engine.control_candidate().unwrap(),
    }
}
