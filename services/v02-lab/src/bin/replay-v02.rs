//! Isolated 0.02 canonical-chain acceptance. Never generates a ZK proof.
#[path = "../backpressure.rs"]
mod backpressure;
#[path = "../contention.rs"]
mod contention;
#[path = "../envelopes.rs"]
mod envelopes;
use alloy_consensus::{SignableTransaction, TxEip1559, TxEnvelope};
use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::{keccak256, Address, TxKind, U256};
use k256::ecdsa::SigningKey;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, fs, path::Path, process::Command};
use tactus_o1_devnet_driver::{
    lab::{self, Lab},
    molecule, rpc,
    tx::{CellOutPoint, OutSpec},
};
use tactus_o1_execution::{v02, Genesis, GenesisAccount};
use tactus_o1_protocol::v02::*;
use tactus_v02_lab::{
    build::{self, Cell},
    err, hash32, number, point_bytes, point_json, Result,
};
use tactus_v02_script::{
    adapter,
    claims::{ClaimWitness, Context},
};
fn hx(b: &[u8]) -> String {
    rpc::bytes_to_hex(b)
}
fn owner() -> Address {
    Address::from_public_key(
        SigningKey::from_bytes((&[0x21; 32]).into())
            .expect("fixed dev key")
            .verifying_key(),
    )
}
fn withdrawal(config: &Config, recipient: [u8; 32]) -> Vec<u8> {
    let mut data = keccak256(b"withdraw(uint64,bytes32)")[..4].to_vec();
    data.extend_from_slice(&U256::from(100_000_000u64).to_be_bytes::<32>());
    data.extend_from_slice(&recipient);
    let tx = TxEip1559 {
        chain_id: config.chain,
        nonce: 0,
        gas_limit: 250_000,
        max_fee_per_gas: 2_000_000_000,
        max_priority_fee_per_gas: 1_000_000_000,
        to: TxKind::Call(Address::from(config.bridge)),
        input: data.into(),
        ..Default::default()
    };
    let sig = SigningKey::from_bytes((&[0x21; 32]).into())
        .expect("fixed dev key")
        .sign_prehash_recoverable(tx.signature_hash().as_slice())
        .expect("fixed transaction")
        .into();
    TxEnvelope::from(tx.into_signed(sig)).encoded_2718()
}
#[derive(Clone)]
struct Instance {
    config: Config,
    policy: Policy,
    cells: Vec<Cell>,
    manifest: Value,
}
impl Instance {
    fn cell(&self, role: Role, index: u64) -> Result<Cell> {
        use ckb_std::ckb_types::prelude::*;
        let ty = adapter::type_script(&self.config, role, index).map_err(err)?;
        let mut matching = self
            .cells
            .iter()
            .filter(|c| c.output.type_script.as_deref() == Some(ty.as_slice()));
        let c = matching
            .next()
            .ok_or_else(|| format!("missing {role:?}/{index}"))?
            .clone();
        if matching.next().is_some() {
            return Err("ambiguous singleton".into());
        }
        Ok(c)
    }
    fn deps(&self, extra: &[CellOutPoint]) -> Result<Vec<CellOutPoint>> {
        let mut d = vec![
            self.cell(Role::Config, 0)?.point,
            self.cell(Role::Policy, 0)?.point,
        ];
        d.extend_from_slice(extra);
        Ok(d)
    }
    #[allow(clippy::too_many_arguments)]
    fn tx(
        &self,
        lab: &Lab,
        actor: usize,
        op: Operation,
        inputs: &[(Cell, u64)],
        outputs: Vec<OutSpec>,
        deps: &[CellOutPoint],
        payload: &[u8],
    ) -> Result<Value> {
        build::transaction(
            lab,
            actor,
            inputs,
            outputs,
            &self.deps(deps)?,
            &[],
            op,
            payload,
        )
    }
    fn commit(
        &mut self,
        lab: &mut Lab,
        actor: usize,
        label: &str,
        tx: &Value,
    ) -> Result<Vec<Cell>> {
        let cells = build::commit(lab, actor, label, tx)?;
        self.adopt(tx, &cells)?;
        Ok(cells)
    }
    fn adopt(&mut self, tx: &Value, cells: &[Cell]) -> Result<()> {
        let spent = tx["inputs"]
            .as_array()
            .ok_or("inputs")?
            .iter()
            .map(|i| tactus_v02_lab::point(&i["previous_output"]).map(point_bytes))
            .collect::<Result<Vec<_>>>()?;
        self.cells
            .retain(|c| !spent.contains(&point_bytes(c.point)));
        self.cells.extend(cells[..cells.len() - 1].iter().cloned());
        Ok(())
    }
}
fn deploy(lab: &mut Lab) -> Result<Instance> {
    let recorded: Value = serde_json::from_slice(
        &fs::read("specs/test-vectors/v02-local-validation.json").map_err(err)?,
    )
    .map_err(err)?;
    let guest = recorded["programs"]
        .as_array()
        .ok_or("guest record")?
        .iter()
        .find(|p| {
            p["path"]
                .as_str()
                .is_some_and(|p| p.ends_with("/tactus-v02-sp1-guest"))
        })
        .ok_or("guest program")?;
    let guest_file = guest["path"].as_str().ok_or("guest path")?;
    let digest = format!("{:x}", Sha256::digest(fs::read(guest_file).map_err(err)?));
    if guest["sha256"] != digest {
        return Err("guest differs from key-qualified build; rerun key qualification".into());
    }
    let key = hash32(&recorded["guest_key"])?;
    let first = molecule::cell_input(0, &point_bytes(lab.wallets[0].point));
    let chain = hash32(&rpc::call("get_block_hash", json!(["0x0"]))?)?;
    let mut config = Config {
        domain: Config::domain_id(&first.try_into().map_err(err)?, 0),
        ckb_genesis: chain,
        adapter_code_hash: hash(b"", &lab.ordering_elf),
        head_lock_code_hash: hash(b"", &lab.lock_elf),
        policy: [1; 32],
        allocation: [2; 32],
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
                owner(),
                GenesisAccount {
                    balance: U256::from(10u64.pow(18)),
                    ..Default::default()
                },
            ),
        ]),
    };
    let allocation = genesis.allocation_bytes().map_err(err)?;
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
        wrapper_key_hash: adapter::wrapper_key_hash(),
        bridge_code_hash: keccak256(code).0,
    };
    config.policy = policy.commitment().map_err(err)?;
    config.allocation = tactus_o1_protocol::genesis::commitment(&allocation).map_err(err)?;
    v02::V02Executor::new(&genesis, config.clone(), policy.clone()).map_err(err)?;
    let identity = config.commitment().map_err(err)?;
    let temp = build::typed(
        &config,
        Role::Vault,
        0,
        Vault::genesis(identity, 1)
            .map_err(err)?
            .encode()
            .map_err(err)?,
        None,
    )?;
    let mut outputs = vec![
        build::typed(
            &config,
            Role::Anchor,
            0,
            Boundary::genesis(identity)
                .map_err(err)?
                .encode()
                .map_err(err)?,
            None,
        )?,
        build::typed(
            &config,
            Role::Schedule,
            0,
            Schedule::genesis(identity)
                .map_err(err)?
                .encode()
                .map_err(err)?,
            None,
        )?,
        build::typed(
            &config,
            Role::Vault,
            0,
            Vault::genesis(identity, temp.capacity)
                .map_err(err)?
                .encode()
                .map_err(err)?,
            None,
        )?,
        build::typed(
            &config,
            Role::Control,
            0,
            Control::genesis(&config, &policy)
                .map_err(err)?
                .encode()
                .map_err(err)?,
            None,
        )?,
        build::typed(
            &config,
            Role::Config,
            0,
            config.encode().map_err(err)?,
            None,
        )?,
        build::typed(
            &config,
            Role::Policy,
            0,
            policy.encode().map_err(err)?,
            None,
        )?,
        build::typed(&config, Role::Allocation, 0, allocation, None)?,
    ];
    for lane in 0..4 {
        outputs.push(build::typed(
            &config,
            Role::Lane,
            lane,
            Lane::genesis(identity, lane as u8)
                .map_err(err)?
                .encode()
                .map_err(err)?,
            None,
        )?);
    }
    let tx = build::transaction(lab, 0, &[], outputs, &[], &[chain], Operation::Genesis, &[])?;
    let cells = build::commit(lab, 0, "v02 joint genesis", &tx)?;
    let manifest = json!({"schema":"tactus-v02-devnet-manifest-v1","config_hex":hx(&config.encode().map_err(err)?),"policy_hex":hx(&policy.encode().map_err(err)?),
        "genesis_tx":hx(&cells[0].point.tx_hash),"genesis_cells":cells[..cells.len()-1].iter().map(|c|point_json(c.point)).collect::<Vec<_>>(),
        "code_dependencies":lab.deps.iter().map(|p|point_json(*p)).collect::<Vec<_>>(),"adapter_sha256":format!("{:x}",Sha256::digest(&lab.ordering_elf)),
        "head_lock_sha256":format!("{:x}",Sha256::digest(&lab.lock_elf)),"guest_elf_sha256":digest,"guest_key":recorded["guest_key"],
        "qualification":"isolated development instance; resource and acceptance audit incomplete","contract_escape_supported":false,"production_ready":false});
    Ok(Instance {
        config,
        policy,
        cells: cells[..cells.len() - 1].to_vec(),
        manifest,
    })
}
fn reject_script(lab: &mut Lab, label: &str, tx: &Value, code: Error) -> Result<()> {
    let expected = format!("error code {}", code as u8);
    let program = hash(b"", &lab.ordering_elf);
    match rpc::send_transaction_json(tx) {
        Err(e)
            if ["Inputs", "Outputs"].iter().any(|side| {
                (0..16).any(|i| {
                    lab::rejection_matches_at(&e, &expected, &program, &format!("{side}[{i}].Type"))
                })
            }) =>
        {
            lab.evidence.push(json!({"label":label,"result":"rejected","expected_reason":expected,"error":e,"transaction":tx}));
            println!("{label}: expected script rejection");
            Ok(())
        }
        other => Err(format!("{label}: expected {expected}, got {other:?}")),
    }
}
fn reject_consensus(lab: &mut Lab, label: &str, tx: &Value, reason: &str) -> Result<()> {
    match rpc::send_transaction_json(tx) {
        Err(e) if e.contains(reason) => {
            lab.evidence.push(json!({"label":label,"result":"rejected","expected_reason":reason,"error":e,"transaction":tx}));
            println!("{label}: expected {reason}");
            Ok(())
        }
        other => Err(format!("{label}: expected {reason}, got {other:?}")),
    }
}
fn deposit(i: &mut Instance, lab: &mut Lab, actor: usize, amount: u64) -> Result<Cell> {
    let tx = deposit_tx(i, lab, actor, amount)?;
    Ok(i.commit(lab, actor, "v02 deposit", &tx)?[1].clone())
}
fn deposit_tx(i: &Instance, lab: &Lab, actor: usize, amount: u64) -> Result<Value> {
    let before = i.cell(Role::Vault, 0)?;
    let vault = Vault::decode(&before.output.data).map_err(err)?;
    let control = i.cell(Role::Control, 0)?;
    let (next, record) = vault
        .deposit(
            &i.config,
            &i.policy,
            &Control::decode(&control.output.data).map_err(err)?,
            owner().0 .0,
            amount,
            hash(b"", &lab.wallets[actor].key.lock_script()),
        )
        .map_err(err)?;
    let tx = i.tx(
        lab,
        actor,
        Operation::Deposit,
        &[(before, 0)],
        vec![
            build::typed(
                &i.config,
                Role::Vault,
                0,
                next.encode().map_err(err)?,
                Some(next.capacity().map_err(err)?),
            )?,
            build::typed(
                &i.config,
                Role::DepositReceipt,
                record.sequence,
                record.encode().map_err(err)?,
                None,
            )?,
        ],
        &[control.point],
        &[],
    )?;
    Ok(tx)
}
fn enqueue(i: &mut Instance, lab: &mut Lab) -> Result<()> {
    let before = i.cell(Role::Lane, 0)?;
    let control = i.cell(Role::Control, 0)?;
    let (next, record) = Lane::decode(&before.output.data)
        .map_err(err)?
        .enqueue(
            &Control::decode(&control.output.data).map_err(err)?,
            &i.policy,
            withdrawal(&i.config, hash(b"", &lab.wallets[0].key.lock_script())),
        )
        .map_err(err)?;
    let tx = i.tx(
        lab,
        0,
        Operation::Enqueue,
        &[(before.clone(), 0)],
        vec![
            build::typed(
                &i.config,
                Role::Lane,
                0,
                next.encode().map_err(err)?,
                Some(before.output.capacity),
            )?,
            build::typed(
                &i.config,
                Role::AdmissionReceipt,
                record.sequence,
                record.encode().map_err(err)?,
                None,
            )?,
        ],
        &[control.point],
        &[],
    )?;
    i.commit(lab, 0, "v02 enqueue", &tx)?;
    Ok(())
}
fn seal(i: &mut Instance, lab: &mut Lab) -> Result<Snapshot> {
    let (snapshot, tx) = seal_tx(i, lab, 0)?;
    i.commit(lab, 0, "v02 complete seal", &tx)?;
    Ok(snapshot)
}
fn seal_tx(i: &Instance, lab: &Lab, actor: usize) -> Result<(Snapshot, Value)> {
    let control = i.cell(Role::Control, 0)?;
    let anchor = i.cell(Role::Anchor, 0)?;
    let schedule = i.cell(Role::Schedule, 0)?;
    let vault = i.cell(Role::Vault, 0)?;
    let lane_cells = (0..4)
        .map(|n| i.cell(Role::Lane, n))
        .collect::<Result<Vec<_>>>()?;
    let lanes = lane_cells
        .iter()
        .map(|c| Lane::decode(&c.output.data).map_err(err))
        .collect::<Result<Vec<_>>>()?;
    let state = Schedule::decode(&schedule.output.data).map_err(err)?;
    let previous_cell = if state.epoch == 0 {
        None
    } else {
        Some(i.cell(Role::Snapshot, state.epoch)?)
    };
    let previous = previous_cell
        .as_ref()
        .map(|cell| Snapshot::decode(&cell.output.data).map_err(err))
        .transpose()?;
    let (next, snapshot, cleared) = state
        .seal(
            &i.config,
            &i.policy,
            &Control::decode(&control.output.data).map_err(err)?,
            &Boundary::decode(&anchor.output.data).map_err(err)?,
            &lanes,
            &Vault::decode(&vault.output.data).map_err(err)?,
            previous.as_ref(),
        )
        .map_err(err)?;
    let mut inputs = vec![(schedule.clone(), 0), (vault.clone(), 0)];
    inputs.extend(lane_cells.iter().cloned().map(|c| (c, 0)));
    let mut outputs = vec![
        build::typed(
            &i.config,
            Role::Schedule,
            0,
            next.encode().map_err(err)?,
            Some(schedule.output.capacity),
        )?,
        vault.output.clone(),
    ];
    for (lane, c) in cleared.iter().zip(&lane_cells) {
        outputs.push(build::typed(
            &i.config,
            Role::Lane,
            u64::from(lane.lane),
            lane.encode().map_err(err)?,
            Some(c.output.capacity),
        )?);
    }
    outputs.push(build::typed(
        &i.config,
        Role::Snapshot,
        snapshot.epoch,
        snapshot.encode().map_err(err)?,
        None,
    )?);
    let mut dependencies = vec![control.point, anchor.point];
    if let Some(previous) = previous_cell {
        dependencies.push(previous.point);
    }
    let tx = i.tx(
        lab,
        actor,
        Operation::Seal,
        &inputs,
        outputs,
        &dependencies,
        &[],
    )?;
    Ok((snapshot, tx))
}
fn append_tx(i: &Instance, lab: &Lab, snapshot: &Snapshot, timestamp: u64) -> Result<Value> {
    let anchor = i.cell(Role::Anchor, 0)?;
    let schedule = i.cell(Role::Schedule, 0)?;
    let control = i.cell(Role::Control, 0)?;
    let parent = Boundary::decode(&anchor.output.data).map_err(err)?;
    let s = Schedule::decode(&schedule.output.data).map_err(err)?;
    let users = snapshot.users().map_err(err)?;
    let priority = users[usize::from(s.user_cursor)..]
        .iter()
        .take(4)
        .cloned()
        .collect::<Vec<_>>();
    let mut deps = vec![control.point, i.cell(Role::Snapshot, snapshot.epoch)?.point];
    let mut deposits = vec![];
    for sequence in
        parent.deposits.count + 1..=snapshot.deposit_end.count.min(parent.deposits.count + 4)
    {
        let r = i.cell(Role::DepositReceipt, sequence)?;
        deps.push(r.point);
        deposits.push(Deposit::decode(&r.output.data).map_err(err)?);
    }
    let transactions = priority.iter().map(|p| p.message.payload.clone()).collect();
    let batch = NativeBatch {
        parent,
        snapshot: snapshot.commitment().map_err(err)?,
        priority,
        deposits,
        blocks: vec![tactus_o1_protocol::batch::BlockInput {
            timestamp,
            fee_recipient: [22; 20],
            transactions,
        }],
    };
    let since = (0x40 << 56) | timestamp;
    let (next, s) = batch
        .append(
            &i.config,
            &i.policy,
            &Control::decode(&control.output.data).map_err(err)?,
            &s,
            snapshot,
            since,
        )
        .map_err(err)?;
    i.tx(
        lab,
        0,
        Operation::Append,
        &[(anchor.clone(), since), (schedule.clone(), 0)],
        vec![
            build::typed(
                &i.config,
                Role::Anchor,
                0,
                next.encode().map_err(err)?,
                Some(anchor.output.capacity),
            )?,
            build::typed(
                &i.config,
                Role::Schedule,
                0,
                s.encode().map_err(err)?,
                Some(schedule.output.capacity),
            )?,
            build::typed(
                &i.config,
                Role::Batch,
                next.batches,
                batch.encode().map_err(err)?,
                None,
            )?,
            build::typed(
                &i.config,
                Role::Checkpoint,
                next.batches,
                next.encode().map_err(err)?,
                None,
            )?,
        ],
        &deps,
        &[],
    )
}
fn watch(i: &mut Instance, lab: &mut Lab, receipt: &Cell) -> Result<Cell> {
    let c = i.cell(Role::Control, 0)?;
    let control = Control::decode(&c.output.data).map_err(err)?;
    let d = Deposit::decode(&receipt.output.data).map_err(err)?;
    let ticket = Watch {
        config: control.boundary.config,
        work: Work::Deposit(d.sequence),
        source: point_bytes(receipt.point),
        observed_control: control.commitment().map_err(err)?,
        refund_lock: hash(b"", &lab.wallets[0].key.lock_script()),
    };
    let tx = i.tx(
        lab,
        0,
        Operation::Watch,
        &[],
        vec![build::typed(
            &i.config,
            Role::Watch,
            0,
            ticket.encode().map_err(err)?,
            None,
        )?],
        &[c.point, receipt.point],
        &[],
    )?;
    Ok(i.commit(lab, 0, "v02 permissionless watch", &tx)?[0].clone())
}
fn recover_cli(
    manifest: &Path,
    output: &Path,
    mode: &str,
    argument: Option<&str>,
) -> Result<Value> {
    let binary = std::env::current_exe()
        .map_err(err)?
        .with_file_name("recover-v02");
    let mut cmd = Command::new(binary);
    cmd.arg(manifest).arg(output).arg(mode);
    if let Some(arg) = argument {
        cmd.arg(arg);
    }
    let status = cmd.status().map_err(err)?;
    if !status.success() {
        return Err(format!("fresh recovery failed: {status}"));
    }
    serde_json::from_slice(&fs::read(output).map_err(err)?).map_err(err)
}
fn run(lab: &mut Lab, dir: &Path) -> Result<Value> {
    let mut i = deploy(lab)?;
    let peer = std::env::var("TACTUS_PEER_RPC_ADDR").map_err(err)?;
    let common = rpc::call("get_tip_header", json!([]))?;
    tactus_o1_devnet_driver::p2p_lab::connect(&peer)?;
    tactus_o1_devnet_driver::p2p_lab::converged(&peer, &common["hash"])?;
    tactus_o1_devnet_driver::p2p_lab::partition(&peer)?;
    let mut alternate = i.clone();
    let common_wallets: Vec<_> = lab.wallets.iter().map(|w| (w.point, w.capacity)).collect();
    // Local monitoring declarations do not alter Config, Policy or custody.
    i.manifest["monitor"] = json!({"fee_lock_hash":rpc::bytes_to_hex(&hash(b"",&lab.wallets[1].key.lock_script())),
        "fee_target_shannons":tactus_o1_devnet_driver::tx::TX_FEE.to_string(),
        "declared_prover_budget_shannons":"0","quoted_proof_cost_shannons":"100000000"});
    let manifest = dir.join("deployment.json");
    fs::write(
        &manifest,
        serde_json::to_vec_pretty(&i.manifest).map_err(err)?,
    )
    .map_err(err)?;
    let first = deposit(&mut i, lab, 0, 10 * 100_000_000)?;
    enqueue(&mut i, lab)?;
    let snapshot = seal(&mut i, lab)?;
    let second = deposit(&mut i, lab, 1, 5 * 100_000_000)?;
    let future = number(&rpc::call("get_tip_header", json!([]))?["timestamp"])? / 1000 + 86400;
    let tx = append_tx(&i, lab, &snapshot, future)?;
    reject_consensus(lab, "future L2 timestamp", &tx, "Immature")?;
    let tx = append_tx(&i, lab, &snapshot, 100)?;
    i.commit(lab, 0, "v02 first append", &tx)?;
    let tx = append_tx(&i, lab, &snapshot, 100)?;
    i.commit(lab, 0, "v02 equal-time append", &tx)?;
    let published = recover_cli(&manifest, &dir.join("running-report.json"), "report", None)?;
    let proof_input = recover_cli(
        &manifest,
        &dir.join("frozen-branch-proof-input.json"),
        "prove",
        Some("2"),
    )?;
    if published["execution_candidate"]["burned_shannons"] != "100000000"
        || published["published_batches"] != 2
        || published["settled_batches"] != 0
        || proof_input["authenticated_publication"] != true
    {
        return Err("canonical reconstruction mismatch".into());
    }
    // Make Control old, then demonstrate a fresh ticket still cannot freeze it.
    rpc::mine_blocks(i.policy.stall_blocks + 1)?;
    let ticket = watch(&mut i, lab, &second)?;
    let other = watch(&mut i, lab, &first)?;
    let young_status = recover_cli(
        &manifest,
        &dir.join("young-watch-report.json"),
        "report",
        None,
    )?;
    if young_status["operations"]["watches"]
        .as_array()
        .ok_or("watches")?
        .iter()
        .any(|w| w["eligible_for_next_block"] != false)
    {
        return Err("observer treated a young ticket as mature".into());
    }
    let control_cell = i.cell(Role::Control, 0)?;
    let control = Control::decode(&control_cell.output.data).map_err(err)?;
    let since = (0x80 << 56) | i.policy.stall_blocks;
    let frozen = control
        .freeze_candidate(
            &Watch::decode(&ticket.output.data).map_err(err)?,
            &i.policy,
            since,
            since,
        )
        .map_err(err)?;
    let payout = OutSpec {
        capacity: ticket.output.capacity,
        lock: lab.wallets[0].key.lock_script(),
        type_script: None,
        data: vec![],
    };
    let freeze = i.tx(
        lab,
        1,
        Operation::Freeze,
        &[(control_cell.clone(), since), (ticket.clone(), since)],
        vec![
            build::typed(
                &i.config,
                Role::Control,
                0,
                frozen.encode().map_err(err)?,
                Some(control_cell.output.capacity),
            )?,
            payout.clone(),
        ],
        &[second.point],
        &1u32.to_le_bytes(),
    )?;
    reject_consensus(
        lab,
        "new ticket cannot freeze old Control",
        &freeze,
        "Immature",
    )?;
    rpc::mine_blocks(i.policy.stall_blocks + 1)?;
    let mature_status = recover_cli(
        &manifest,
        &dir.join("mature-watch-report.json"),
        "report",
        None,
    )?;
    if mature_status["operations"]["watches"]
        .as_array()
        .ok_or("watches")?
        .iter()
        .any(|w| w["eligible_for_next_block"] != true)
    {
        return Err("observer missed mature pending tickets".into());
    }
    let mut bad_inputs = vec![(control_cell.clone(), since), (ticket.clone(), since - 1)];
    let bad = i.tx(
        lab,
        1,
        Operation::Freeze,
        &bad_inputs,
        vec![
            build::typed(
                &i.config,
                Role::Control,
                0,
                frozen.encode().map_err(err)?,
                Some(control_cell.output.capacity),
            )?,
            payout,
        ],
        &[second.point],
        &1u32.to_le_bytes(),
    )?;
    reject_script(lab, "wrong freeze threshold", &bad, Error::Maturity)?;
    bad_inputs.clear();
    // Save a fully signed RUNNING transaction whose fee input remains untouched.
    let stale = append_tx(&i, lab, &snapshot, 100)?;
    let stale_valid = rpc::call("estimate_cycles", json!([stale]))?;
    lab.evidence.push(json!({"label":"pre-freeze RUNNING transaction is executable", "result":"simulated", "cycles":stale_valid, "transaction":stale}));
    i.commit(
        lab,
        1,
        "v02 mature permissionless freeze by another actor",
        &freeze,
    )?;
    let live = rpc::call(
        "get_live_cell",
        json!([point_json(control_cell.point), false]),
    )?;
    if live["status"] == "live" {
        return Err("consumed Control still reported live".into());
    }
    let spent_reason = format!(
        "Unknown(OutPoint({}))",
        hx(&point_bytes(control_cell.point))
    );
    reject_consensus(lab, "spent RUNNING dependency", &stale, &spent_reason)?;
    let closed = i.tx(
        lab,
        1,
        Operation::CloseWatch,
        &[(other.clone(), 0)],
        vec![OutSpec {
            capacity: other.output.capacity,
            lock: lab.wallets[0].key.lock_script(),
            type_script: None,
            data: vec![],
        }],
        &[i.cell(Role::Control, 0)?.point],
        &0u32.to_le_bytes(),
    )?;
    i.commit(lab, 1, "v02 close other ticket after freeze", &closed)?;
    for (sequence, receipt) in [(1, &first), (2, &second)] {
        let plan = recover_cli(
            &manifest,
            &dir.join(format!("refund-{sequence}.json")),
            "refund",
            Some(&sequence.to_string()),
        )?;
        if plan["phase"] != "Withdrawable"
            || plan["control_confirmation"]["confirmations"]
                .as_u64()
                .unwrap_or(0)
                == 0
        {
            return Err("refund lifecycle or inclusion missing".into());
        }
        let witness = ClaimWitness::decode(&tactus_v02_lab::bytes(
            &plan["claim_witness_hex"],
            ClaimWitness::MAX_BYTES,
        )?)
        .map_err(err)?;
        let old = i.cell(Role::Vault, 0)?;
        let vault = Vault::decode(&old.output.data).map_err(err)?;
        let record = Deposit::decode(&receipt.output.data).map_err(err)?;
        let c = i.cell(Role::Control, 0)?;
        let paid = witness
            .authorize(&Context {
                config: &i.config,
                policy: &i.policy,
                control: &frozen,
                control_outpoint: point_bytes(c.point),
                vault: &vault,
                receipt: Some((point_bytes(receipt.point), &record)),
            })
            .map_err(err)?;
        let recipient = if sequence == 1 { 0 } else { 1 };
        let lock = lab.wallets[recipient].key.lock_script();
        let capacity = paid.amount.max(OutSpec::required_capacity(&lock, None, 0));
        let tx = i.tx(
            lab,
            1,
            Operation::Refund,
            &[(old, 0)],
            vec![
                build::typed(
                    &i.config,
                    Role::Vault,
                    0,
                    paid.next.encode().map_err(err)?,
                    Some(paid.next.capacity().map_err(err)?),
                )?,
                OutSpec {
                    capacity,
                    lock,
                    type_script: None,
                    data: vec![],
                },
            ],
            &[c.point, receipt.point],
            &witness.encode().map_err(err)?,
        )?;
        i.commit(lab, 1, "v02 refund reconstructed by fresh process", &tx)?;
    }
    let recovered = recover_cli(&manifest, &dir.join("frozen-report.json"), "report", None)?;
    if recovered["lifecycle"]["payments"].as_array().map(Vec::len) != Some(2)
        || recovered["lifecycle"]["batches"][0]["phase"] != "Ordered"
        || recovered["lifecycle"]["mode"] != "FROZEN"
    {
        return Err(
            "canonical lifecycle did not distinguish ordered batches and paid refunds".into(),
        );
    }
    if recovered["mode"] != "FROZEN" || recovered["partitions_shannons"] != json!(["0", "0", "0"]) {
        return Err("final frozen custody conservation".into());
    }
    // Publish a conflicting deposit on the isolated peer, then let real P2P
    // consensus choose its heavier branch. No truncate or submit_block RPC.
    let orphan_tip = rpc::call("get_tip_header", json!([]))?;
    for (wallet, (point, capacity)) in lab.wallets.iter_mut().zip(common_wallets) {
        wallet.point = point;
        wallet.capacity = capacity;
    }
    let old_vault = alternate.cell(Role::Vault, 0)?;
    let old_control = alternate.cell(Role::Control, 0)?;
    let (new_vault, new_receipt) = Vault::decode(&old_vault.output.data)
        .map_err(err)?
        .deposit(
            &alternate.config,
            &alternate.policy,
            &Control::decode(&old_control.output.data).map_err(err)?,
            owner().0 .0,
            3 * 100_000_000,
            hash(b"", &lab.wallets[0].key.lock_script()),
        )
        .map_err(err)?;
    let alternative_tx = alternate.tx(
        lab,
        0,
        Operation::Deposit,
        &[(old_vault.clone(), 0)],
        vec![
            build::typed(
                &alternate.config,
                Role::Vault,
                0,
                new_vault.encode().map_err(err)?,
                Some(new_vault.capacity().map_err(err)?),
            )?,
            build::typed(
                &alternate.config,
                Role::DepositReceipt,
                1,
                new_receipt.encode().map_err(err)?,
                None,
            )?,
        ],
        &[old_control.point],
        &[],
    )?;
    let alternative_hash = rpc::call_at(
        &peer,
        "send_transaction",
        json!([alternative_tx, "passthrough"]),
    )?;
    for _ in 0..8 {
        tactus_o1_devnet_driver::p2p_lab::peer_mine(&peer, 1)?;
        if rpc::call_at(&peer, "get_transaction", json!([alternative_hash]))?["tx_status"]["status"]
            == "committed"
        {
            break;
        }
    }
    if rpc::call_at(&peer, "get_transaction", json!([alternative_hash]))?["tx_status"]["status"]
        != "committed"
    {
        return Err("alternative deposit did not commit".into());
    }
    let peer_height = number(&rpc::call_at(&peer, "get_tip_header", json!([]))?["number"])?;
    let extra = number(&orphan_tip["number"])?
        .checked_sub(peer_height)
        .ok_or("fork height")?
        + 4;
    tactus_o1_devnet_driver::p2p_lab::peer_mine(&peer, extra)?;
    let winning = rpc::call_at(&peer, "get_tip_header", json!([]))?;
    tactus_o1_devnet_driver::p2p_lab::connect(&peer)?;
    tactus_o1_devnet_driver::p2p_lab::converged(&peer, &winning["hash"])?;
    lab.evidence.push(json!({"label":"P2P rollback of deposit/seal/publication/freeze/refunds","result":"reorganized","common_tip":common,"orphan_tip":orphan_tip,"winning_tip":winning,"alternative_transaction":alternative_tx,"alternative_hash":alternative_hash,"truncate_used":false,"submit_block_used":false}));
    fs::copy(
        dir.join("frozen-report.json"),
        dir.join("recovered-state.json"),
    )
    .map_err(err)?;
    let rolled = recover_cli(&manifest, &dir.join("recovered-state.json"), "report", None)?;
    if rolled["lifecycle"]["payments"] != json!([])
        || rolled["lifecycle"]["batches"] != json!([])
        || rolled["mode"] != "RUNNING"
        || rolled["published_batches"] != 0
        || rolled["deposited_count"] != 1
        || rolled["partitions_shannons"] != json!(["300000000", "0", "0"])
        || rolled["control"]["out_point"] != point_json(old_control.point)
    {
        return Err("canonical rollback retained orphan rights/state".into());
    }
    let orphan_claim = Command::new(
        std::env::current_exe()
            .map_err(err)?
            .with_file_name("recover-v02"),
    )
    .arg(&manifest)
    .arg(dir.join("orphan-refund.json"))
    .arg("refund")
    .arg("2")
    .output()
    .map_err(err)?;
    if orphan_claim.status.success()
        || !String::from_utf8_lossy(&orphan_claim.stderr).contains("missing live DepositReceipt/2")
    {
        return Err("orphan receipt was not rejected by fresh recovery".into());
    }
    // Continue from canonical peer outputs and leave a RUNNING instance/input
    // for the separate 0.03 proof/settlement milestone.
    let alternative_cells = build::outputs(&alternative_tx, hash32(&alternative_hash)?)?;
    alternate.cells.retain(|c| c.point != old_vault.point);
    alternate.cells.extend(
        alternative_cells[..alternative_cells.len() - 1]
            .iter()
            .cloned(),
    );
    let change = alternative_cells.last().ok_or("alternate funding")?;
    lab.wallets[0].point = change.point;
    lab.wallets[0].capacity = change.output.capacity;
    enqueue(&mut alternate, lab)?;
    let replacement_snapshot = seal(&mut alternate, lab)?;
    for label in [
        "v02 replacement first append",
        "v02 replacement equal-time append",
    ] {
        let tx = append_tx(&alternate, lab, &replacement_snapshot, 100)?;
        alternate.commit(lab, 0, label, &tx)?;
    }
    let funded = recover_cli(&manifest, &dir.join("funded-report.json"), "report", None)?;
    if funded["operations"]["funding"]["external_fees"]["status"] != "target_met" {
        return Err("missing external fee budget".into());
    }
    // Exhaust only the separate operator wallet, retaining its occupied capacity.
    // This ordinary untyped transfer cannot consume any protocol cell.
    let reserve = OutSpec::required_capacity(&lab.wallets[1].key.lock_script(), None, 0);
    let amount = lab.wallets[1]
        .capacity
        .checked_sub(reserve)
        .and_then(|n| n.checked_sub(tactus_o1_devnet_driver::tx::TX_FEE))
        .ok_or("fee exhaustion amount")?;
    let drain = build::transaction(
        lab,
        1,
        &[],
        vec![OutSpec {
            capacity: amount,
            lock: lab.wallets[0].key.lock_script(),
            type_script: None,
            data: vec![],
        }],
        &[],
        &[],
        Operation::Enqueue,
        &[],
    )?;
    build::commit(
        lab,
        1,
        "v02 external fee wallet exhausted without custody input",
        &drain,
    )?;
    let failed_fee_build =
        build::transaction(lab, 1, &[], vec![], &[], &[], Operation::Enqueue, &[]);
    if !matches!(failed_fee_build,Err(ref e) if e.contains("insufficient change cell capacity")) {
        return Err("empty fee wallet unexpectedly funds a transaction".into());
    }
    let final_report = recover_cli(&manifest, &dir.join("recovered-state.json"), "report", None)?;
    if final_report["vault"] != funded["vault"]
        || final_report["control"] != funded["control"]
        || final_report["operations"]["funding"]["external_fees"]["status"]
            != "insufficient_for_target"
        || final_report["operations"]["funding"]["prover"]["status"]
            != "declared_budget_insufficient"
    {
        return Err("funding failure reporting or custody isolation mismatch".into());
    }
    recover_cli(
        &manifest,
        &dir.join("canonical-proof-input.json"),
        "prove",
        Some("2"),
    )?;
    if final_report["mode"] != "RUNNING" || final_report["published_batches"] != 2 {
        return Err("replacement progress failed".into());
    }
    Ok(
        json!({"schema":"tactus-v02-canonical-acceptance-v1","joint_genesis":true,"future_time_rejected":true,"equal_time_accepted":true,"young_watch_rejected":true,
        "permissionless_freeze":true,"spent_control_dependency_rejected":true,"fresh_process_refunds":2,"watch_age_reporting":true,"external_fee_exhaustion_without_custody_debit":true,"all_principal_refunded":true,"recoveries":[published,recovered,rolled,final_report],"real_p2p_reorg":true,"orphan_claim_rejected":true,"replacement_progress":true,
        "canonical_input_exported_before_freeze":true,"exported_instance_now_frozen":false,"proof_generated":false,"zk_settlement":false,"production_ready":false}),
    )
}
fn main() {
    if let Err(e) = main_result() {
        eprintln!("{e}");
        std::process::exit(1);
    }
}
fn main_result() -> Result<()> {
    rpc::require_devnet()?;
    let dir = std::env::var("TACTUS_RUN_DIR").map_err(err)?;
    let mut lab = Lab::connect_with_script("artifacts/tactus_v02_script.elf")?;
    let result = match std::env::var("TACTUS_V02_CASE").as_deref() {
        Ok("backpressure") => backpressure::run(&mut lab, Path::new(&dir)),
        Ok("envelopes") => envelopes::run(&mut lab, Path::new(&dir)),
        Ok("contention") => contention::run(&mut lab, Path::new(&dir)),
        Err(std::env::VarError::NotPresent) | Ok("canonical") => run(&mut lab, Path::new(&dir)),
        _ => Err("TACTUS_V02_CASE must be canonical, contention, backpressure or envelopes".into()),
    };
    let report = match &result {
        Ok(r) => r.clone(),
        Err(e) => json!({"complete":false,"error":e,"production_ready":false}),
    };
    lab.save(&format!("{dir}/evidence.json"), report)?;
    result.map(|_| ())
}
