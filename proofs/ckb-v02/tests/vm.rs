#![cfg(feature = "vm-tests")]
//! Actual CKB-VM script execution. The harness does NOT check chain-time
//! maturity, txpool liveness or reorgs; those require the devnet acceptance run.
use ckb_testtool::{
    builtin::ALWAYS_SUCCESS,
    ckb_types::{
        bytes::Bytes,
        core::{Capacity, HeaderBuilder, ScriptHashType, TransactionBuilder, TransactionView},
        packed::*,
        prelude::*,
    },
    context::Context,
};
use tactus_o1_protocol::{
    genesis::{Account, Allocation},
    v02::*,
};
use tactus_v02_script::adapter::wrapper_key_hash;
use tactus_v02_script::claims::{ClaimWitness, Context as ClaimContext, Request};

const CYCLES: u64 = 500_000_000;
const SHANNON: u64 = 100_000_000;
struct Lab {
    context: Context,
    config: Config,
    policy: Policy,
    code: Vec<CellDep>,
    lock: Script,
    genesis: TransactionView,
    points: Vec<OutPoint>,
    outputs: Vec<(CellOutput, Bytes)>,
}
fn typed(
    config: &Config,
    role: Role,
    index: u64,
    bytes: Vec<u8>,
    capacity: Option<u64>,
) -> (CellOutput, Bytes) {
    let ty = Script::new_builder()
        .code_hash(config.adapter_code_hash.pack())
        .hash_type(ScriptHashType::Data1)
        .args(config.args(role, index).unwrap().pack())
        .build();
    let lock = Script::new_builder()
        .code_hash(config.head_lock_code_hash.pack())
        .hash_type(ScriptHashType::Data1)
        .args(ty.calc_script_hash().as_slice().pack())
        .build();
    let cell = CellOutput::new_builder()
        .lock(lock)
        .type_(Some(ty).pack())
        .build();
    let occupied = cell
        .occupied_capacity(Capacity::bytes(bytes.len()).unwrap())
        .unwrap()
        .as_u64();
    let amount = capacity.unwrap_or_else(|| {
        occupied
            + if role == Role::Lane {
                (Lane::MAX_BYTES - bytes.len()) as u64 * SHANNON
            } else {
                0
            }
    });
    (cell.as_builder().capacity(amount).build(), bytes.into())
}
fn operation(op: Operation, payload: &[u8]) -> Bytes {
    let mut data = b"T02OP001".to_vec();
    data.push(op as u8);
    data.extend_from_slice(payload);
    WitnessArgs::new_builder()
        .output_type(Some(Bytes::from(data)).pack())
        .build()
        .as_bytes()
}
fn duplicate_output(tx: &TransactionView, index: usize) -> TransactionView {
    let mut outputs = tx.outputs().into_iter().collect::<Vec<_>>();
    let mut data = tx.outputs_data().into_iter().collect::<Vec<_>>();
    outputs.push(outputs[index].clone());
    data.push(data[index].clone());
    tx.as_advanced_builder()
        .set_outputs(outputs)
        .set_outputs_data(data)
        .build()
}
fn replace_dep(tx: &TransactionView, before: &OutPoint, after: &OutPoint) -> TransactionView {
    let mut count = 0;
    let deps = tx
        .cell_deps()
        .into_iter()
        .map(|d| {
            if d.out_point() == *before {
                count += 1;
                dep(after.clone())
            } else {
                d
            }
        })
        .collect();
    assert_eq!(count, 1);
    tx.as_advanced_builder().set_cell_deps(deps).build()
}
fn dep(point: OutPoint) -> CellDep {
    CellDep::new_builder().out_point(point).build()
}
impl Lab {
    fn new() -> Self {
        let mut context = Context::default();
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../artifacts");
        let binary: Bytes = std::fs::read(root.join("tactus_v02_script.elf"))
            .expect("build-v02-script.sh first")
            .into();
        let head: Bytes = std::fs::read(root.join("tactus_o1_head_lock.elf"))
            .expect("head-lock ELF")
            .into();
        let adapter_hash: [u8; 32] = CellOutput::calc_data_hash(&binary)
            .as_slice()
            .try_into()
            .unwrap();
        let head_hash: [u8; 32] = CellOutput::calc_data_hash(&head)
            .as_slice()
            .try_into()
            .unwrap();
        let code = vec![
            dep(context.deploy_cell(binary)),
            dep(context.deploy_cell(head)),
            dep(context.deploy_cell(ALWAYS_SUCCESS.clone())),
        ];
        let lock = context
            .build_script_with_hash_type(&code[2].out_point(), ScriptHashType::Data1, Bytes::new())
            .unwrap();
        let funding = context.create_cell(
            CellOutput::new_builder()
                .capacity(1_000_000 * SHANNON)
                .lock(lock.clone())
                .build(),
            Bytes::new(),
        );
        let input = CellInput::new_builder().previous_output(funding).build();
        let header = HeaderBuilder::default().number(0).build();
        context.insert_header(header.clone());
        let allocation = Allocation {
            accounts: vec![Account {
                address: [10; 20],
                nonce: 1,
                balance: [0; 32],
                code: vec![0x60, 0],
                storage: vec![],
            }],
        }
        .encode()
        .unwrap();
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
            wrapper_key_hash: wrapper_key_hash(),
            bridge_code_hash: alloy_primitives::keccak256([0x60, 0]).0,
        };
        let config = Config {
            domain: Config::domain_id(&input.as_slice().try_into().unwrap(), 0),
            ckb_genesis: header.hash().as_slice().try_into().unwrap(),
            adapter_code_hash: adapter_hash,
            head_lock_code_hash: head_hash,
            policy: policy.commitment().unwrap(),
            allocation: tactus_o1_protocol::genesis::commitment(&allocation).unwrap(),
            chain: 71402,
            bridge: [10; 20],
        };
        let identity = config.commitment().unwrap();
        let placeholder = Vault::genesis(identity, 1).unwrap().encode().unwrap();
        let (temporary, _) = typed(&config, Role::Vault, 0, placeholder, None);
        let reserve: u64 = temporary.capacity().unpack();
        let mut outputs = vec![
            typed(
                &config,
                Role::Anchor,
                0,
                Boundary::genesis(identity).unwrap().encode().unwrap(),
                None,
            ),
            typed(
                &config,
                Role::Schedule,
                0,
                Schedule::genesis(identity).unwrap().encode().unwrap(),
                None,
            ),
            typed(
                &config,
                Role::Vault,
                0,
                Vault::genesis(identity, reserve).unwrap().encode().unwrap(),
                None,
            ),
            typed(
                &config,
                Role::Control,
                0,
                Control::genesis(&config, &policy)
                    .unwrap()
                    .encode()
                    .unwrap(),
                None,
            ),
            typed(&config, Role::Config, 0, config.encode().unwrap(), None),
            typed(&config, Role::Policy, 0, policy.encode().unwrap(), None),
            typed(&config, Role::Allocation, 0, allocation, None),
        ];
        for lane in 0..4 {
            outputs.push(typed(
                &config,
                Role::Lane,
                lane,
                Lane::genesis(identity, lane as u8)
                    .unwrap()
                    .encode()
                    .unwrap(),
                None,
            ));
        }
        let genesis = TransactionBuilder::default()
            .input(input)
            .cell_deps(code.clone())
            .header_dep(header.hash())
            .outputs(outputs.iter().map(|v| v.0.clone()).collect::<Vec<_>>())
            .outputs_data(outputs.iter().map(|v| v.1.pack()).collect::<Vec<_>>())
            .witness(operation(Operation::Genesis, &[]).pack())
            .build();
        Self {
            context,
            config,
            policy,
            code,
            lock,
            genesis,
            points: vec![],
            outputs,
        }
    }
    fn verify(&self, name: &str, tx: &TransactionView) -> u64 {
        let cycles = self
            .context
            .verify_tx(tx, CYCLES)
            .unwrap_or_else(|error| panic!("{name}: {error:?}"));
        println!(
            "v02-vm {name}: {cycles} cycles, {} bytes",
            tx.data().as_slice().len()
        );
        cycles
    }
    fn reject(&self, name: &str, tx: &TransactionView, code: u8) {
        self.reject_with_budget(name, tx, code, CYCLES);
    }
    fn reject_with_budget(&self, name: &str, tx: &TransactionView, code: u8, budget: u64) {
        let error = format!("{:?}", self.context.verify_tx(tx, budget).expect_err(name));
        assert!(
            error.contains("ValidationFailure")
                && error.contains(".Type")
                && error.contains(&format!("error code {code}")),
            "{name}: {error}"
        );
        println!("v02-vm reject {name}: type error {code}, completed within {budget} cycle budget");
    }
    // Replace only a genuine RUNNING dependency after the paired positive
    // transaction has passed. This isolates the terminal-mode entry gate.
    fn reject_frozen_dependency(&mut self, name: &str, tx: &TransactionView) {
        let mut control = Control::genesis(&self.config, &self.policy).unwrap();
        control.mode = Mode::Frozen;
        let (cell, data) = typed(
            &self.config,
            Role::Control,
            0,
            control.encode().unwrap(),
            None,
        );
        let point = self.context.create_cell(cell, data);
        let mut replaced = 0;
        let deps = tx
            .cell_deps()
            .into_iter()
            .map(|d| {
                if d.out_point() == self.points[3] {
                    replaced += 1;
                    dep(point.clone())
                } else {
                    d
                }
            })
            .collect();
        assert_eq!(replaced, 1);
        let bad = tx.as_advanced_builder().set_cell_deps(deps).build();
        self.reject(name, &bad, Error::Mode as u8);
    }
    fn install(&mut self, tx: &TransactionView) -> Vec<OutPoint> {
        tx.outputs_with_data_iter()
            .enumerate()
            .map(|(i, (output, data))| {
                let point = OutPoint::new_builder()
                    .tx_hash(tx.hash())
                    .index(i as u32)
                    .build();
                self.context
                    .create_cell_with_out_point(point.clone(), output, data);
                point
            })
            .collect()
    }
    fn start(&mut self) {
        self.verify("genesis", &self.genesis);
        let tx = self.genesis.clone();
        self.points = self.install(&tx);
    }
    fn deposit(&mut self) -> (Vault, Deposit, Vec<OutPoint>) {
        let initial = Vault::decode(&self.outputs[2].1).unwrap();
        let control = Control::genesis(&self.config, &self.policy).unwrap();
        let refund_lock = self.lock.calc_script_hash().as_slice().try_into().unwrap();
        let (vault, record) = initial
            .deposit(
                &self.config,
                &self.policy,
                &control,
                [20; 20],
                10 * SHANNON,
                refund_lock,
            )
            .unwrap();
        let outputs = vec![
            typed(
                &self.config,
                Role::Vault,
                0,
                vault.encode().unwrap(),
                Some(vault.capacity().unwrap()),
            ),
            typed(
                &self.config,
                Role::DepositReceipt,
                1,
                record.encode().unwrap(),
                None,
            ),
        ];
        let tx = self.tx(
            Operation::Deposit,
            vec![(self.points[2].clone(), 0)],
            outputs,
            vec![self.points[3].clone()],
            &[],
        );
        self.verify("deposit", &tx);
        self.reject_frozen_dependency("frozen deposit", &tx);
        let points = self.install(&tx);
        (vault, record, points)
    }
    fn tx(
        &mut self,
        op: Operation,
        inputs: Vec<(OutPoint, u64)>,
        outputs: Vec<(CellOutput, Bytes)>,
        dependencies: Vec<OutPoint>,
        payload: &[u8],
    ) -> TransactionView {
        let fee = self.context.create_cell(
            CellOutput::new_builder()
                .lock(self.lock.clone())
                .capacity(1_000_000 * SHANNON)
                .build(),
            Bytes::new(),
        );
        let mut input_cells: Vec<_> = inputs
            .into_iter()
            .map(|(point, since)| {
                CellInput::new_builder()
                    .previous_output(point)
                    .since(since)
                    .build()
            })
            .collect();
        input_cells.push(CellInput::new_builder().previous_output(fee).build());
        let mut deps = self.code.clone();
        deps.extend([dep(self.points[4].clone()), dep(self.points[5].clone())]);
        deps.extend(dependencies.into_iter().map(dep));
        TransactionBuilder::default()
            .inputs(input_cells)
            .cell_deps(deps)
            .outputs(outputs.iter().map(|v| v.0.clone()).collect::<Vec<_>>())
            .outputs_data(outputs.iter().map(|v| v.1.pack()).collect::<Vec<_>>())
            .witness(operation(op, payload).pack())
            .build()
    }
}

#[test]
fn actual_vm_joint_genesis_enforces_complete_roles_domain_and_protocol_locks() {
    let mut lab = Lab::new();
    lab.verify("genesis", &lab.genesis);
    // Even a dependency containing the exact new bytes under the old adapter
    // identity cannot replace a role that must be jointly created at genesis.
    let old_hash = hash(
        b"",
        &std::fs::read("../../artifacts/tactus_o1_native_anchor_script.elf").unwrap(),
    );
    let anchor = lab.genesis.outputs().get(0).unwrap();
    let old_type = anchor
        .type_()
        .to_opt()
        .unwrap()
        .as_builder()
        .code_hash(old_hash.pack())
        .build();
    let old_anchor = lab.context.create_cell(
        anchor.as_builder().type_(Some(old_type).pack()).build(),
        lab.genesis.outputs_data().get(0).unwrap().raw_data(),
    );
    let with_old_dep = lab
        .genesis
        .as_advanced_builder()
        .cell_dep(dep(old_anchor))
        .build();
    lab.verify(
        "unrelated old-code dep grants no genesis authority",
        &with_old_dep,
    );
    let without_new_anchor = with_old_dep
        .as_advanced_builder()
        .set_outputs(lab.genesis.outputs().into_iter().skip(1).collect())
        .set_outputs_data(lab.genesis.outputs_data().into_iter().skip(1).collect())
        .build();
    lab.reject(
        "old-code Anchor dependency cannot replace joint genesis output",
        &without_new_anchor,
        Error::Identity as u8,
    );
    for index in [2, 3] {
        lab.reject(
            "duplicate genesis vault/control",
            &duplicate_output(&lab.genesis, index),
            Error::Identity as u8,
        );
    }
    let other = lab.context.create_cell(
        CellOutput::new_builder()
            .lock(lab.lock.clone())
            .capacity(1_000_000 * SHANNON)
            .build(),
        Bytes::new(),
    );
    let bad_seed = lab
        .genesis
        .as_advanced_builder()
        .set_inputs(vec![CellInput::new_builder()
            .previous_output(other)
            .build()])
        .build();
    lab.reject(
        "old domain with a different genesis input",
        &bad_seed,
        Error::Domain as u8,
    );
    let outputs = lab
        .genesis
        .outputs()
        .into_iter()
        .take(10)
        .collect::<Vec<_>>();
    let data = lab
        .genesis
        .outputs_data()
        .into_iter()
        .take(10)
        .collect::<Vec<_>>();
    let bad = lab
        .genesis
        .as_advanced_builder()
        .set_outputs(outputs)
        .set_outputs_data(data)
        .build();
    lab.reject("missing lane", &bad, Error::Identity as u8);
    let mut outputs = lab.genesis.outputs().into_iter().collect::<Vec<_>>();
    outputs[0] = outputs[0]
        .clone()
        .as_builder()
        .lock(lab.lock.clone())
        .build();
    let bad = lab
        .genesis
        .as_advanced_builder()
        .set_outputs(outputs)
        .build();
    lab.reject("wrong anchor lock", &bad, Error::Authorization as u8);
}

#[test]
fn actual_vm_admission_record_is_required_and_frozen_control_cannot_authorize_it() {
    let mut lab = Lab::new();
    lab.start();
    let control = Control::genesis(&lab.config, &lab.policy).unwrap();
    let lane = Lane::genesis(control.boundary.config, 0).unwrap();
    let (next, receipt) = lane.enqueue(&control, &lab.policy, vec![1, 2]).unwrap();
    let outputs = vec![
        typed(
            &lab.config,
            Role::Lane,
            0,
            next.encode().unwrap(),
            Some(lab.outputs[7].0.capacity().unpack()),
        ),
        typed(
            &lab.config,
            Role::AdmissionReceipt,
            receipt.sequence,
            receipt.encode().unwrap(),
            None,
        ),
    ];
    let tx = lab.tx(
        Operation::Enqueue,
        vec![(lab.points[7].clone(), 0)],
        outputs.clone(),
        vec![lab.points[3].clone()],
        &[],
    );
    lab.verify("enqueue", &tx);
    lab.reject(
        "duplicate admission record",
        &duplicate_output(&tx, 1),
        Error::Identity as u8,
    );
    let mut foreign = lab.config.clone();
    foreign.domain[0] ^= 1;
    let (c, d) = typed(&foreign, Role::Control, 0, control.encode().unwrap(), None);
    let foreign_control = lab.context.create_cell(c, d);
    lab.reject(
        "foreign Control cannot authorize admission",
        &replace_dep(&tx, &lab.points[3], &foreign_control),
        Error::Identity as u8,
    );
    for change_adapter in [true, false] {
        let mut changed_config = lab.config.clone();
        if change_adapter {
            changed_config.adapter_code_hash[0] ^= 1;
        } else {
            changed_config.head_lock_code_hash[0] ^= 1;
        }
        let (c, d) = typed(
            &lab.config,
            Role::Config,
            0,
            changed_config.encode().unwrap(),
            None,
        );
        let changed = lab.context.create_cell(c, d);
        lab.reject(
            "immutable code identities cannot change in Config",
            &replace_dep(&tx, &lab.points[4], &changed),
            if change_adapter {
                Error::Identity
            } else {
                Error::Authorization
            } as u8,
        );
    }
    for field in 0..3 {
        let mut policy = lab.policy.clone();
        match field {
            0 => policy.guest_key[0] ^= 1,
            1 => policy.rules[0] ^= 1,
            _ => policy.wrapper_key_hash[0] ^= 1,
        };
        let (c, d) = typed(&lab.config, Role::Policy, 0, policy.encode().unwrap(), None);
        let changed = lab.context.create_cell(c, d);
        lab.reject(
            "changed immutable policy/key dependency",
            &replace_dep(&tx, &lab.points[5], &changed),
            Error::Domain as u8,
        );
    }
    let bad = lab.tx(
        Operation::Enqueue,
        vec![(lab.points[7].clone(), 0)],
        outputs[..1].to_vec(),
        vec![lab.points[3].clone()],
        &[],
    );
    lab.reject("missing admission receipt", &bad, Error::Identity as u8);
    // Injected frozen fixture tests the actual mode gate, not freeze provenance.
    let mut frozen = control;
    frozen.mode = Mode::Frozen;
    let c = typed(
        &lab.config,
        Role::Control,
        0,
        frozen.encode().unwrap(),
        None,
    );
    let frozen_point = lab.context.create_cell(c.0, c.1);
    let bad = lab.tx(
        Operation::Enqueue,
        vec![(lab.points[7].clone(), 0)],
        outputs,
        vec![frozen_point],
        &[],
    );
    lab.reject("frozen enqueue", &bad, Error::Mode as u8);
}

#[test]
fn actual_vm_seal_binds_deposit_tail_and_append_requires_checkpoint_and_true_receipt() {
    let mut lab = Lab::new();
    lab.start();
    let (vault, record, deposited) = lab.deposit();
    let control = Control::genesis(&lab.config, &lab.policy).unwrap();
    let schedule = Schedule::genesis(control.boundary.config).unwrap();
    let lanes: Vec<_> = (0..4)
        .map(|i| Lane::genesis(control.boundary.config, i).unwrap())
        .collect();
    let (schedule, snapshot, cleared) = schedule
        .seal(
            &lab.config,
            &lab.policy,
            &control,
            &control.boundary,
            &lanes,
            &vault,
            None,
        )
        .unwrap();
    let mut inputs = vec![(lab.points[1].clone(), 0), (deposited[0].clone(), 0)];
    inputs.extend(lab.points[7..11].iter().map(|p| (p.clone(), 0)));
    let mut outputs = vec![
        typed(
            &lab.config,
            Role::Schedule,
            0,
            schedule.encode().unwrap(),
            Some(lab.outputs[1].0.capacity().unpack()),
        ),
        typed(
            &lab.config,
            Role::Vault,
            0,
            vault.encode().unwrap(),
            Some(vault.capacity().unwrap()),
        ),
    ];
    for lane in &cleared {
        outputs.push(typed(
            &lab.config,
            Role::Lane,
            u64::from(lane.lane),
            lane.encode().unwrap(),
            Some(
                lab.outputs[usize::from(lane.lane) + 7]
                    .0
                    .capacity()
                    .unpack(),
            ),
        ));
    }
    outputs.push(typed(
        &lab.config,
        Role::Snapshot,
        1,
        snapshot.encode().unwrap(),
        None,
    ));
    let seal = lab.tx(
        Operation::Seal,
        inputs,
        outputs,
        vec![lab.points[3].clone(), lab.points[0].clone()],
        &[],
    );
    lab.verify("seal", &seal);
    // The current Vault is a mandatory co-input. A snapshot cannot simply
    // pretend that an already accepted deposit was not present at sealing.
    let mut omitted = snapshot.clone();
    omitted.deposit_end = omitted.deposit_start;
    let mut omitted_schedule = schedule.clone();
    omitted_schedule.snapshot = omitted.commitment().unwrap();
    let mut omitted_data = seal.outputs_data().into_iter().collect::<Vec<_>>();
    omitted_data[0] = Bytes::from(omitted_schedule.encode().unwrap()).pack();
    omitted_data[6] = Bytes::from(omitted.encode().unwrap()).pack();
    let bad_tail = seal
        .as_advanced_builder()
        .set_outputs_data(omitted_data)
        .build();
    lab.reject(
        "SEAL cannot omit the already accepted deposit tail",
        &bad_tail,
        Error::Continuity as u8,
    );
    let mut missing_lane_inputs = seal.inputs().into_iter().collect::<Vec<_>>();
    missing_lane_inputs.remove(2);
    let missing_lane = seal
        .as_advanced_builder()
        .set_inputs(missing_lane_inputs)
        .build();
    lab.reject(
        "seal cannot omit a lane",
        &missing_lane,
        Error::Identity as u8,
    );
    lab.reject_frozen_dependency("frozen seal", &seal);
    let sealed = lab.install(&seal);
    let batch = NativeBatch {
        parent: control.boundary.clone(),
        snapshot: snapshot.commitment().unwrap(),
        priority: vec![],
        deposits: vec![record.clone()],
        blocks: vec![tactus_o1_protocol::batch::BlockInput {
            timestamp: 100,
            fee_recipient: [21; 20],
            transactions: vec![],
        }],
    };
    let (next, after) = batch
        .append(
            &lab.config,
            &lab.policy,
            &control,
            &schedule,
            &snapshot,
            (0x40 << 56) | 100,
        )
        .unwrap();
    let inputs = vec![
        (lab.points[0].clone(), (0x40 << 56) | 100),
        (sealed[0].clone(), 0),
    ];
    let outputs = vec![
        typed(
            &lab.config,
            Role::Anchor,
            0,
            next.encode().unwrap(),
            Some(lab.outputs[0].0.capacity().unpack()),
        ),
        typed(
            &lab.config,
            Role::Schedule,
            0,
            after.encode().unwrap(),
            Some(lab.outputs[1].0.capacity().unpack()),
        ),
        typed(&lab.config, Role::Batch, 1, batch.encode().unwrap(), None),
        typed(
            &lab.config,
            Role::Checkpoint,
            1,
            next.encode().unwrap(),
            None,
        ),
    ];
    let dependencies = vec![
        lab.points[3].clone(),
        sealed[6].clone(),
        deposited[1].clone(),
    ];
    let append = lab.tx(
        Operation::Append,
        inputs.clone(),
        outputs.clone(),
        dependencies.clone(),
        &[],
    );
    lab.verify("append", &append);
    lab.reject(
        "duplicate checkpoint",
        &duplicate_output(&append, 3),
        Error::Identity as u8,
    );
    lab.reject_frozen_dependency("frozen append", &append);
    let appended = lab.install(&append);
    let second = NativeBatch {
        parent: next.clone(),
        snapshot: batch.snapshot,
        priority: vec![],
        deposits: vec![],
        blocks: batch.blocks.clone(),
    };
    let (second_boundary, second_schedule) = second
        .append(
            &lab.config,
            &lab.policy,
            &control,
            &after,
            &snapshot,
            (0x40 << 56) | 100,
        )
        .unwrap();
    let second_inputs = vec![
        (appended[0].clone(), (0x40 << 56) | 100),
        (appended[1].clone(), 0),
    ];
    let mut second_outputs = vec![
        typed(
            &lab.config,
            Role::Anchor,
            0,
            second_boundary.encode().unwrap(),
            Some(lab.outputs[0].0.capacity().unpack()),
        ),
        typed(
            &lab.config,
            Role::Schedule,
            0,
            second_schedule.encode().unwrap(),
            Some(lab.outputs[1].0.capacity().unpack()),
        ),
        typed(&lab.config, Role::Batch, 2, second.encode().unwrap(), None),
        typed(
            &lab.config,
            Role::Checkpoint,
            2,
            second_boundary.encode().unwrap(),
            None,
        ),
    ];
    let second_deps = vec![lab.points[3].clone(), sealed[6].clone()];
    let equal_time = lab.tx(
        Operation::Append,
        second_inputs.clone(),
        second_outputs.clone(),
        second_deps.clone(),
        &[],
    );
    lab.verify("equal-time second APPEND", &equal_time);
    let mut backwards = second.encode().unwrap();
    let timestamp_offset = backwards.len() - 32; // Empty block: u64 time, address20, u32 count.
    assert_eq!(
        &backwards[timestamp_offset..timestamp_offset + 8],
        &100u64.to_le_bytes()
    );
    backwards[timestamp_offset..timestamp_offset + 8].copy_from_slice(&99u64.to_le_bytes());
    second_outputs[2].1 = Bytes::from(backwards);
    let bad_time = lab.tx(
        Operation::Append,
        second_inputs,
        second_outputs,
        second_deps,
        &[],
    );
    lab.reject(
        "backwards timestamp in APPEND",
        &bad_time,
        Error::Continuity as u8,
    );
    let missing = lab.tx(
        Operation::Append,
        inputs.clone(),
        outputs[..3].to_vec(),
        dependencies.clone(),
        &[],
    );
    lab.reject("missing checkpoint", &missing, Error::Identity as u8);
    let fake = lab.context.create_cell(
        CellOutput::new_builder()
            .lock(lab.lock.clone())
            .capacity(1000 * SHANNON)
            .build(),
        record.encode().unwrap().into(),
    );
    let forged = lab.tx(
        Operation::Append,
        inputs.clone(),
        outputs.clone(),
        vec![lab.points[3].clone(), sealed[6].clone(), fake],
        &[],
    );
    lab.reject("untyped receipt substitute", &forged, Error::Identity as u8);
    let mut wrong_since = inputs;
    wrong_since[0].1 = 100;
    let bad = lab.tx(Operation::Append, wrong_since, outputs, dependencies, &[]);
    lab.reject("wrong append time metric", &bad, Error::Maturity as u8);
}

#[test]
fn actual_vm_permissionless_freeze_and_refund_preserve_both_payouts_and_reject_replay() {
    let mut lab = Lab::new();
    lab.start();
    let (vault, record, deposited) = lab.deposit();
    let control = Control::genesis(&lab.config, &lab.policy).unwrap();
    let ticket = Watch {
        config: control.boundary.config,
        work: Work::Deposit(1),
        source: deposited[1].as_slice().try_into().unwrap(),
        observed_control: control.commitment().unwrap(),
        refund_lock: lab.lock.calc_script_hash().as_slice().try_into().unwrap(),
    };
    let watch_output = typed(&lab.config, Role::Watch, 0, ticket.encode().unwrap(), None);
    let watch = lab.tx(
        Operation::Watch,
        vec![],
        vec![watch_output.clone()],
        vec![lab.points[3].clone(), deposited[1].clone()],
        &[],
    );
    lab.verify("watch", &watch);
    for foreign in [false, true] {
        let source = if foreign {
            let mut other = lab.config.clone();
            other.domain[0] ^= 1;
            let (c, d) = typed(
                &other,
                Role::DepositReceipt,
                record.sequence,
                record.encode().unwrap(),
                None,
            );
            lab.context.create_cell(c, d)
        } else {
            lab.context.create_cell(
                CellOutput::new_builder()
                    .lock(lab.lock.clone())
                    .capacity(1000 * SHANNON)
                    .build(),
                record.encode().unwrap().into(),
            )
        };
        let mut forged = ticket.clone();
        forged.source = source.as_slice().try_into().unwrap();
        let bad = lab.tx(
            Operation::Watch,
            vec![],
            vec![typed(
                &lab.config,
                Role::Watch,
                0,
                forged.encode().unwrap(),
                None,
            )],
            vec![lab.points[3].clone(), source],
            &[],
        );
        lab.reject(
            "untyped or foreign source cannot create Watch",
            &bad,
            Error::Identity as u8,
        );
    }
    lab.reject_frozen_dependency("frozen watch creation", &watch);
    let watched = lab.install(&watch);
    let since = (0x80 << 56) | 120;
    let frozen = control
        .freeze_candidate(&ticket, &lab.policy, since, since)
        .unwrap();
    let ticket_capacity: u64 = watch_output.0.capacity().unpack();
    let refund = (
        CellOutput::new_builder()
            .lock(lab.lock.clone())
            .capacity(ticket_capacity)
            .build(),
        Bytes::new(),
    );
    let outputs = vec![
        typed(
            &lab.config,
            Role::Control,
            0,
            frozen.encode().unwrap(),
            Some(lab.outputs[3].0.capacity().unpack()),
        ),
        refund,
    ];
    let inputs = vec![(lab.points[3].clone(), since), (watched[0].clone(), since)];
    let freeze = lab.tx(
        Operation::Freeze,
        inputs.clone(),
        outputs.clone(),
        vec![deposited[1].clone()],
        &1u32.to_le_bytes(),
    );
    lab.verify("freeze", &freeze);
    for side in 0..2 {
        let mut bad_inputs = inputs.clone();
        bad_inputs[side].1 -= 1;
        let bad = lab.tx(
            Operation::Freeze,
            bad_inputs,
            outputs.clone(),
            vec![deposited[1].clone()],
            &1u32.to_le_bytes(),
        );
        lab.reject("one immature threshold", &bad, Error::Maturity as u8);
    }
    let mut underpaid = outputs;
    underpaid[1].0 = underpaid[1]
        .0
        .clone()
        .as_builder()
        .capacity(ticket_capacity - 1)
        .build();
    let bad = lab.tx(
        Operation::Freeze,
        inputs,
        underpaid,
        vec![deposited[1].clone()],
        &1u32.to_le_bytes(),
    );
    lab.reject("ticket refund charged a fee", &bad, Error::Accounting as u8);
    let frozen_points = lab.install(&freeze);
    let witness = ClaimWitness {
        payout: 1,
        control_outpoint: frozen_points[0].as_slice().try_into().unwrap(),
        request: Request::Refund {
            receipt_outpoint: deposited[1].as_slice().try_into().unwrap(),
        },
        nullifier: NullifierProof::empty(),
    };
    let next = witness
        .authorize(&ClaimContext {
            config: &lab.config,
            policy: &lab.policy,
            control: &frozen,
            control_outpoint: witness.control_outpoint,
            vault: &vault,
            receipt: Some((deposited[1].as_slice().try_into().unwrap(), &record)),
        })
        .unwrap()
        .next;
    let outputs = vec![
        typed(
            &lab.config,
            Role::Vault,
            0,
            next.encode().unwrap(),
            Some(next.capacity().unwrap()),
        ),
        (
            CellOutput::new_builder()
                .lock(lab.lock.clone())
                .capacity(100 * SHANNON)
                .build(),
            Bytes::new(),
        ),
    ];
    let paid = lab.tx(
        Operation::Refund,
        vec![(deposited[0].clone(), 0)],
        outputs.clone(),
        vec![frozen_points[0].clone(), deposited[1].clone()],
        &witness.encode().unwrap(),
    );
    lab.verify("refund with capacity topup", &paid);
    let paid_points = lab.install(&paid);
    let replay = lab.tx(
        Operation::Refund,
        vec![(paid_points[0].clone(), 0)],
        outputs,
        vec![frozen_points[0].clone(), deposited[1].clone()],
        &witness.encode().unwrap(),
    );
    lab.reject("duplicate refund", &replay, Error::Proof as u8);
}

mod common;

// This test injects already-settled Control/Vault cells. It exercises real MPT,
// secp256k1 and CKB-VM payout checks; it is NOT a successful SP1 settlement.
#[test]
fn actual_vm_release_then_eoa_escape_preserve_reserve_and_reject_replay_and_redirection() {
    for account_mode in [0, 1, 2] {
        let mut lab = Lab::new();
        lab.start();
        let recipient = lab.lock.calc_script_hash().as_slice().try_into().unwrap();
        let initial = Vault::decode(&lab.outputs[2].1).unwrap();
        let mut f = common::with_config(
            account_mode,
            lab.config.clone(),
            lab.policy.clone(),
            initial.reserve,
            recipient,
            recipient,
        );
        let (c, d) = typed(
            &lab.config,
            Role::Control,
            0,
            f.control.encode().unwrap(),
            Some(lab.outputs[3].0.capacity().unpack()),
        );
        let control_point = lab.context.create_cell(c, d);
        let (c, d) = typed(
            &lab.config,
            Role::Vault,
            0,
            f.vault.encode().unwrap(),
            Some(f.vault.capacity().unwrap()),
        );
        let vault_point = lab.context.create_cell(c, d);
        f.release.control_outpoint = control_point.as_slice().try_into().unwrap();
        f.escape.control_outpoint = f.release.control_outpoint;
        if let Request::Escape {
            owner,
            amount,
            recipient,
            signature,
            ..
        } = &mut f.escape.request
        {
            let digest = tactus_v02_script::claims::escape_digest(
                &lab.config,
                &f.control,
                &f.escape.control_outpoint,
                owner,
                *amount,
                recipient,
            )
            .unwrap();
            let (sig, recovery) = common::signing_key()
                .sign_prehash_recoverable(&digest)
                .unwrap();
            signature[..64].copy_from_slice(&sig.to_bytes());
            signature[64] = recovery.to_byte();
        }
        let context = ClaimContext {
            config: &lab.config,
            policy: &lab.policy,
            control: &f.control,
            control_outpoint: f.release.control_outpoint,
            vault: &f.vault,
            receipt: None,
        };
        let released = f.release.authorize(&context).unwrap().next;
        let payout = (
            CellOutput::new_builder()
                .lock(lab.lock.clone())
                .capacity(100 * SHANNON)
                .build(),
            Bytes::new(),
        );
        let outputs = vec![
            typed(
                &lab.config,
                Role::Vault,
                0,
                released.encode().unwrap(),
                Some(released.capacity().unwrap()),
            ),
            payout.clone(),
        ];
        let release = lab.tx(
            Operation::Release,
            vec![(vault_point.clone(), 0)],
            outputs.clone(),
            vec![control_point.clone()],
            &f.release.encode().unwrap(),
        );
        lab.verify("release against injected settled root", &release);
        let mut foreign = lab.config.clone();
        foreign.domain[0] ^= 1;
        let (c, d) = typed(
            &foreign,
            Role::Vault,
            0,
            f.vault.encode().unwrap(),
            Some(f.vault.capacity().unwrap()),
        );
        let other_vault = lab.context.create_cell(c, d);
        let (c, d) = typed(&foreign, Role::Config, 0, foreign.encode().unwrap(), None);
        let other_config = lab.context.create_cell(c, d);
        let (c, d) = typed(
            &foreign,
            Role::Policy,
            0,
            lab.policy.encode().unwrap(),
            None,
        );
        let other_policy = lab.context.create_cell(c, d);
        let cross_instance = lab.tx(
            Operation::Release,
            vec![(other_vault, 0)],
            outputs.clone(),
            vec![control_point.clone(), other_config, other_policy],
            &f.release.encode().unwrap(),
        );
        lab.reject(
            "new domain cannot consume the old instance Vault",
            &cross_instance,
            Error::Domain as u8,
        );
        for other in [&f.refund, &f.escape] {
            let wrong_kind = lab.tx(
                Operation::Release,
                vec![(vault_point.clone(), 0)],
                outputs.clone(),
                vec![control_point.clone()],
                &other.encode().unwrap(),
            );
            lab.reject(
                "other claim kind cannot bypass release nullifier",
                &wrong_kind,
                Error::Encoding as u8,
            );
        }
        let mut bad_outputs = outputs.clone();
        bad_outputs[1].0 = bad_outputs[1]
            .0
            .clone()
            .as_builder()
            .lock(
                lab.lock
                    .clone()
                    .as_builder()
                    .args(Bytes::from_static(&[1]).pack())
                    .build(),
            )
            .build();
        let bad = lab.tx(
            Operation::Release,
            vec![(vault_point.clone(), 0)],
            bad_outputs,
            vec![control_point.clone()],
            &f.release.encode().unwrap(),
        );
        lab.reject("relayer redirects release", &bad, Error::Accounting as u8);
        let mut bad_outputs = outputs.clone();
        bad_outputs[0].0 = bad_outputs[0]
            .0
            .clone()
            .as_builder()
            .capacity(released.capacity().unwrap() - 1)
            .build();
        let bad = lab.tx(
            Operation::Release,
            vec![(vault_point, 0)],
            bad_outputs,
            vec![control_point.clone()],
            &f.release.encode().unwrap(),
        );
        lab.reject("release charges vault fee", &bad, Error::Accounting as u8);
        let paid = lab.install(&release);
        let replay = lab.tx(
            Operation::Release,
            vec![(paid[0].clone(), 0)],
            outputs,
            vec![control_point.clone()],
            &f.release.encode().unwrap(),
        );
        lab.reject("duplicate release", &replay, Error::Proof as u8);
        let context = ClaimContext {
            config: &lab.config,
            policy: &lab.policy,
            control: &f.control,
            control_outpoint: f.escape.control_outpoint,
            vault: &released,
            receipt: None,
        };
        if account_mode == 2 {
            let bad = lab.tx(
                Operation::Escape,
                vec![(paid[0].clone(), 0)],
                vec![
                    typed(
                        &lab.config,
                        Role::Vault,
                        0,
                        released.encode().unwrap(),
                        Some(released.capacity().unwrap()),
                    ),
                    payout.clone(),
                ],
                vec![control_point.clone()],
                &f.escape.encode().unwrap(),
            );
            lab.reject(
                "contract account cannot use EOA escape",
                &bad,
                Error::Authorization as u8,
            );
            continue;
        }
        let escaped = f.escape.authorize(&context).unwrap().next;
        assert_eq!(escaped.capacity().unwrap(), initial.reserve);
        let outputs = vec![
            typed(
                &lab.config,
                Role::Vault,
                0,
                escaped.encode().unwrap(),
                Some(escaped.capacity().unwrap()),
            ),
            payout,
        ];
        let escape = lab.tx(
            Operation::Escape,
            vec![(paid[0].clone(), 0)],
            outputs.clone(),
            vec![control_point.clone()],
            &f.escape.encode().unwrap(),
        );
        lab.verify(
            if account_mode == 0 {
                "escape with proven account absence"
            } else {
                "escape existing EOA"
            },
            &escape,
        );
        for attack in 0..5 {
            let mut bad = f.escape.clone();
            if let Request::Escape {
                recipient,
                signature,
                account,
                ..
            } = &mut bad.request
            {
                match attack {
                    0 => recipient[0] ^= 1,
                    1 => signature[0] ^= 1,
                    2 => {
                        account.proof =
                            tactus_o1_state_proof_script::encode_proofs(&[], &[]).unwrap()
                    }
                    3 => account.claim.root.0[0] ^= 1,
                    _ => {
                        let mut foreign = lab.config.clone();
                        foreign.domain[0] ^= 1;
                        let mut foreign_control = f.control.clone();
                        foreign_control.boundary.config = foreign.commitment().unwrap();
                        let digest = tactus_v02_script::claims::escape_digest(
                            &foreign,
                            &foreign_control,
                            &bad.control_outpoint,
                            &common::owner(),
                            70,
                            recipient,
                        )
                        .unwrap();
                        let (sig, recovery) = common::signing_key()
                            .sign_prehash_recoverable(&digest)
                            .unwrap();
                        signature[..64].copy_from_slice(&sig.to_bytes());
                        signature[64] = recovery.to_byte();
                    }
                }
            }
            let bad_tx = lab.tx(
                Operation::Escape,
                vec![(paid[0].clone(), 0)],
                outputs.clone(),
                vec![control_point.clone()],
                &bad.encode().unwrap(),
            );
            lab.reject(
                "invalid escape authorization",
                &bad_tx,
                if attack < 2 || attack == 4 {
                    Error::Authorization
                } else {
                    Error::Proof
                } as u8,
            );
        }
        let escaped_points = lab.install(&escape);
        let replay = lab.tx(
            Operation::Escape,
            vec![(escaped_points[0].clone(), 0)],
            outputs,
            vec![control_point],
            &f.escape.encode().unwrap(),
        );
        lab.reject("duplicate escape", &replay, Error::Proof as u8);
    }
}

#[test]
fn actual_vm_settlement_checks_real_verifier_and_cannot_replace_or_unfreeze_control() {
    let mut lab = Lab::new();
    lab.start();
    let initial = Control::genesis(&lab.config, &lab.policy).unwrap();
    // Synthetic endpoint is used only to get to the cryptographic rejection.
    let mut f = common::with_config(
        1,
        lab.config.clone(),
        lab.policy.clone(),
        Vault::decode(&lab.outputs[2].1).unwrap().reserve,
        [94; 32],
        [95; 32],
    );
    f.control.mode = Mode::Running;
    let journal = Journal {
        start: initial.clone(),
        end: f.control.clone(),
        outcomes: [71; 32],
        interval_inputs: [72; 32],
    };
    let (c, d) = typed(
        &lab.config,
        Role::Checkpoint,
        1,
        f.control.boundary.encode().unwrap(),
        None,
    );
    let endpoint = lab.context.create_cell(c, d);
    let outputs = vec![typed(
        &lab.config,
        Role::Control,
        0,
        f.control.encode().unwrap(),
        Some(lab.outputs[3].0.capacity().unpack()),
    )];
    let mut bytes = journal.encode().unwrap();
    bytes.extend_from_slice(&0u32.to_le_bytes());
    let empty = lab.tx(
        Operation::Settle,
        vec![(lab.points[3].clone(), 0)],
        outputs.clone(),
        vec![endpoint.clone()],
        &bytes,
    );
    lab.reject("empty proof cannot settle", &empty, Error::Proof as u8);
    // Rebuilding the same Control cannot reset its age. Keep a raw malformed
    // journal because the host encoder correctly refuses non-progress first.
    let mut heartbeat = journal.encode().unwrap();
    let encoded_initial = initial.encode().unwrap();
    heartbeat[8 + encoded_initial.len()..8 + 2 * encoded_initial.len()]
        .copy_from_slice(&encoded_initial);
    heartbeat.extend_from_slice(&0u32.to_le_bytes());
    let no_progress = lab.tx(
        Operation::Settle,
        vec![(lab.points[3].clone(), 0)],
        vec![typed(
            &lab.config,
            Role::Control,
            0,
            encoded_initial,
            Some(lab.outputs[3].0.capacity().unpack()),
        )],
        vec![endpoint.clone()],
        &heartbeat,
    );
    lab.reject(
        "heartbeat with unchanged settled boundary",
        &no_progress,
        Error::Continuity as u8,
    );
    // Another settlement changes the live starting Control. A proof interval
    // pinned to the old start must be rebuilt, even with the same endpoint dep.
    let (c, d) = outputs[0].clone();
    let advanced = lab.context.create_cell(c, d);
    let stale = lab.tx(
        Operation::Settle,
        vec![(advanced, 0)],
        outputs.clone(),
        vec![endpoint.clone()],
        &bytes,
    );
    lab.reject(
        "overlapping settlement with stale starting Control",
        &stale,
        Error::Continuity as u8,
    );
    let mut bytes = journal.encode().unwrap();
    bytes.extend_from_slice(&356u32.to_le_bytes());
    bytes.extend_from_slice(&[0; 356]);
    let invalid = lab.tx(
        Operation::Settle,
        vec![(lab.points[3].clone(), 0)],
        outputs.clone(),
        vec![endpoint.clone()],
        &bytes,
    );
    lab.reject(
        "invalid wrapper proof cannot settle",
        &invalid,
        Error::Proof as u8,
    );
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../specs/evidence");
    let legacy = [
        (root.join("chain-groth16-proof/proof"), "0x00eb2677694b390a31db8883db49c1a828d73618173ce6f3e5790b7678958b14"),
        (root.join("sp1-optimization-round3/artifacts/sp1-optimization-round3/sparse-proofs-1792043336864656751/proof-first/resumed-proof"), "0x0017cf9eee019ac2f5933907aa0cf7cc50746d7a50d82504e31dede2fc1681a4"),
    ];
    for (directory, key) in legacy {
        let proof = std::fs::read(directory.join("groth16-proof.bin")).unwrap();
        let old_public = std::fs::read(directory.join("public-values.bin")).unwrap();
        sp1_verifier::Groth16Verifier::verify(
            &proof,
            &old_public,
            key,
            &sp1_verifier::GROTH16_VK_BYTES,
        )
        .expect("historical proof must remain valid under its own statement");
        let mut old_payload = old_public.clone();
        old_payload.extend_from_slice(&(proof.len() as u32).to_le_bytes());
        old_payload.extend_from_slice(&proof);
        let old_statement = lab.tx(
            Operation::Settle,
            vec![(lab.points[3].clone(), 0)],
            outputs.clone(),
            vec![endpoint.clone()],
            &old_payload,
        );
        lab.reject(
            "legacy public values are not a 0.02 journal",
            &old_statement,
            Error::Encoding as u8,
        );
        let mut payload = journal.encode().unwrap();
        payload.extend_from_slice(&(proof.len() as u32).to_le_bytes());
        payload.extend_from_slice(&proof);
        let mismatched = lab.tx(
            Operation::Settle,
            vec![(lab.points[3].clone(), 0)],
            outputs.clone(),
            vec![endpoint.clone()],
            &payload,
        );
        // Full Groth16 pairing is substantially more expensive than malformed
        // prefixes. Keep its separate observed budget explicit; do not silently
        // relax the 500M ceiling used for all other operation checks.
        lab.reject_with_budget(
            "genuine legacy or sparse proof cannot settle 0.02",
            &mismatched,
            Error::Proof as u8,
            10_000_000_000,
        );
        if let Ok(directory) = std::env::var("TACTUS_V02_DUMP_SETTLE") {
            let path = std::path::Path::new(&directory);
            std::fs::create_dir_all(path).unwrap();
            // Keep the exact resolved transaction for debugger resource measurement.
            let resolved = lab.context.dump_tx(&mismatched).unwrap();
            std::fs::write(
                path.join(format!("legacy-{}.json", &key[2..10])),
                serde_json::to_vec_pretty(&resolved).unwrap(),
            )
            .unwrap();
        }
    }
    let mut frozen = initial.clone();
    frozen.mode = Mode::Frozen;
    let (c, d) = typed(
        &lab.config,
        Role::Control,
        0,
        frozen.encode().unwrap(),
        Some(lab.outputs[3].0.capacity().unpack()),
    );
    let frozen_point = lab.context.create_cell(c, d);
    let unfreeze = lab.tx(
        Operation::Settle,
        vec![(frozen_point, 0)],
        outputs.clone(),
        vec![endpoint.clone()],
        &bytes,
    );
    lab.reject("frozen control cannot settle", &unfreeze, Error::Mode as u8);
    // Mutate the encoded start directly: malformed/domain-bound journal must fail.
    let mut bytes = journal.encode().unwrap();
    bytes[58] ^= 1;
    bytes.extend_from_slice(&0u32.to_le_bytes());
    let wrong_start = lab.tx(
        Operation::Settle,
        vec![(lab.points[3].clone(), 0)],
        outputs.clone(),
        vec![endpoint.clone()],
        &bytes,
    );
    lab.reject("wrong starting profile", &wrong_start, Error::Domain as u8);
    let mut bytes = journal.encode().unwrap();
    bytes.extend_from_slice(&4097u32.to_le_bytes());
    let oversized = lab.tx(
        Operation::Settle,
        vec![(lab.points[3].clone(), 0)],
        outputs,
        vec![endpoint],
        &bytes,
    );
    lab.reject(
        "oversized proof length rejected before allocation",
        &oversized,
        Error::Limit as u8,
    );
}

#[test]
fn actual_vm_fulfilled_watch_can_close_but_cannot_freeze_other_pending_work() {
    let mut lab = Lab::new();
    lab.start();
    let (_, _, deposited) = lab.deposit();
    let control = Control::genesis(&lab.config, &lab.policy).unwrap();
    let ticket = Watch {
        config: control.boundary.config,
        work: Work::Deposit(1),
        source: deposited[1].as_slice().try_into().unwrap(),
        observed_control: control.commitment().unwrap(),
        refund_lock: lab.lock.calc_script_hash().as_slice().try_into().unwrap(),
    };
    let output = typed(&lab.config, Role::Watch, 0, ticket.encode().unwrap(), None);
    let watch = lab.tx(
        Operation::Watch,
        vec![],
        vec![output.clone()],
        vec![lab.points[3].clone(), deposited[1].clone()],
        &[],
    );
    lab.verify("watch for closure", &watch);
    let points = lab.install(&watch);
    let capacity: u64 = output.0.capacity().unpack();
    let payout = (
        CellOutput::new_builder()
            .lock(lab.lock.clone())
            .capacity(capacity)
            .build(),
        Bytes::new(),
    );
    let pending = lab.tx(
        Operation::CloseWatch,
        vec![(points[0].clone(), 0)],
        vec![payout.clone()],
        vec![lab.points[3].clone()],
        &0u32.to_le_bytes(),
    );
    lab.reject("pending ticket cannot close", &pending, Error::Duty as u8);
    // Actual proof completion is deferred to 0.03; this fixture isolates the
    // completed-work gate and payout authorization in the CKB script.
    let f = common::with_config(
        1,
        lab.config.clone(),
        lab.policy.clone(),
        1000,
        [94; 32],
        [95; 32],
    );
    let mut completed = f.control;
    completed.mode = Mode::Running;
    let (c, d) = typed(
        &lab.config,
        Role::Control,
        0,
        completed.encode().unwrap(),
        Some(lab.outputs[3].0.capacity().unpack()),
    );
    let completed_point = lab.context.create_cell(c, d);
    let close = lab.tx(
        Operation::CloseWatch,
        vec![(points[0].clone(), 0)],
        vec![payout.clone()],
        vec![completed_point.clone()],
        &0u32.to_le_bytes(),
    );
    lab.verify(
        "close fulfilled watch against injected settled root",
        &close,
    );
    let mut frozen = completed.clone();
    frozen.mode = Mode::Frozen;
    let freeze = lab.tx(
        Operation::Freeze,
        vec![
            (completed_point, (0x80 << 56) | 120),
            (points[0].clone(), (0x80 << 56) | 120),
        ],
        vec![
            typed(
                &lab.config,
                Role::Control,
                0,
                frozen.encode().unwrap(),
                Some(lab.outputs[3].0.capacity().unpack()),
            ),
            payout,
        ],
        vec![deposited[1].clone()],
        &1u32.to_le_bytes(),
    );
    lab.reject("fulfilled ticket cannot freeze", &freeze, Error::Duty as u8);
}

#[test]
fn actual_vm_full_queues_and_maximum_byte_batch_fit_the_development_script_budget() {
    let mut lab = Lab::new();
    lab.start();
    let control = Control::genesis(&lab.config, &lab.policy).unwrap();
    let mut lanes: Vec<_> = (0..4)
        .map(|i| Lane::genesis(control.boundary.config, i).unwrap())
        .collect();
    let mut lane_points = lab.points[7..11].to_vec();
    for i in 0..4 {
        for _ in 0..8 {
            let (next, receipt) = lanes[i]
                .enqueue(&control, &lab.policy, vec![0xff; 1024])
                .unwrap();
            let tx = lab.tx(
                Operation::Enqueue,
                vec![(lane_points[i].clone(), 0)],
                vec![
                    typed(
                        &lab.config,
                        Role::Lane,
                        i as u64,
                        next.encode().unwrap(),
                        Some(lab.outputs[i + 7].0.capacity().unpack()),
                    ),
                    typed(
                        &lab.config,
                        Role::AdmissionReceipt,
                        receipt.sequence,
                        receipt.encode().unwrap(),
                        None,
                    ),
                ],
                vec![lab.points[3].clone()],
                &[],
            );
            lab.verify("bounded queue admission", &tx);
            lane_points[i] = lab.install(&tx)[0].clone();
            lanes[i] = next;
        }
    }
    let mut vault = Vault::decode(&lab.outputs[2].1).unwrap();
    let mut vault_point = lab.points[2].clone();
    let mut receipts = vec![];
    let mut receipt_points = vec![];
    let refund_lock = lab.lock.calc_script_hash().as_slice().try_into().unwrap();
    for _ in 0..32 {
        let (next, receipt) = vault
            .deposit(
                &lab.config,
                &lab.policy,
                &control,
                [20; 20],
                100,
                refund_lock,
            )
            .unwrap();
        let tx = lab.tx(
            Operation::Deposit,
            vec![(vault_point, 0)],
            vec![
                typed(
                    &lab.config,
                    Role::Vault,
                    0,
                    next.encode().unwrap(),
                    Some(next.capacity().unwrap()),
                ),
                typed(
                    &lab.config,
                    Role::DepositReceipt,
                    receipt.sequence,
                    receipt.encode().unwrap(),
                    None,
                ),
            ],
            vec![lab.points[3].clone()],
            &[],
        );
        lab.verify("bounded deposit admission", &tx);
        let points = lab.install(&tx);
        vault_point = points[0].clone();
        receipt_points.push(points[1].clone());
        receipts.push(receipt);
        vault = next;
    }
    assert!(vault
        .deposit(
            &lab.config,
            &lab.policy,
            &control,
            [20; 20],
            100,
            refund_lock
        )
        .is_err());
    let (schedule, snapshot, cleared) = Schedule::genesis(control.boundary.config)
        .unwrap()
        .seal(
            &lab.config,
            &lab.policy,
            &control,
            &control.boundary,
            &lanes,
            &vault,
            None,
        )
        .unwrap();
    assert_eq!(snapshot.encode().unwrap().len(), Snapshot::MAX_BYTES);
    let mut inputs = vec![(lab.points[1].clone(), 0), (vault_point, 0)];
    inputs.extend(lane_points.into_iter().map(|p| (p, 0)));
    let mut outputs = vec![
        typed(
            &lab.config,
            Role::Schedule,
            0,
            schedule.encode().unwrap(),
            Some(lab.outputs[1].0.capacity().unpack()),
        ),
        typed(
            &lab.config,
            Role::Vault,
            0,
            vault.encode().unwrap(),
            Some(vault.capacity().unwrap()),
        ),
    ];
    for (i, lane) in cleared.iter().enumerate() {
        outputs.push(typed(
            &lab.config,
            Role::Lane,
            i as u64,
            lane.encode().unwrap(),
            Some(lab.outputs[i + 7].0.capacity().unpack()),
        ));
    }
    outputs.push(typed(
        &lab.config,
        Role::Snapshot,
        1,
        snapshot.encode().unwrap(),
        None,
    ));
    let seal = lab.tx(
        Operation::Seal,
        inputs,
        outputs,
        vec![lab.points[3].clone(), lab.points[0].clone()],
        &[],
    );
    lab.verify("maximum snapshot seal", &seal);
    let sealed = lab.install(&seal);
    let priority = snapshot.users().unwrap()[..4].to_vec();
    let mut blocks = vec![
        tactus_o1_protocol::batch::BlockInput {
            timestamp: 100,
            fee_recipient: [21; 20],
            transactions: vec![]
        };
        16
    ];
    blocks[0].transactions = priority.iter().map(|p| p.message.payload.clone()).collect();
    let mut batch = NativeBatch {
        parent: control.boundary.clone(),
        snapshot: snapshot.commitment().unwrap(),
        priority,
        deposits: receipts[..4].to_vec(),
        blocks,
    };
    let mut remaining = NativeBatch::MAX_BYTES - batch.encode().unwrap().len();
    while remaining > 4 {
        let mut length = 16384usize.min(remaining - 4);
        if (1..=4).contains(&(remaining - length - 4)) {
            length -= 4;
        }
        batch.blocks[0].transactions.push(vec![0xff; length]);
        remaining -= length + 4;
    }
    assert_eq!(remaining, 0);
    assert_eq!(batch.encode().unwrap().len(), NativeBatch::MAX_BYTES);
    let (next, schedule) = batch
        .append(
            &lab.config,
            &lab.policy,
            &control,
            &schedule,
            &snapshot,
            (0x40 << 56) | 100,
        )
        .unwrap();
    let mut dependencies = vec![lab.points[3].clone(), sealed[6].clone()];
    dependencies.extend_from_slice(&receipt_points[..4]);
    let tx = lab.tx(
        Operation::Append,
        vec![
            (lab.points[0].clone(), (0x40 << 56) | 100),
            (sealed[0].clone(), 0),
        ],
        vec![
            typed(
                &lab.config,
                Role::Anchor,
                0,
                next.encode().unwrap(),
                Some(lab.outputs[0].0.capacity().unpack()),
            ),
            typed(
                &lab.config,
                Role::Schedule,
                0,
                schedule.encode().unwrap(),
                Some(lab.outputs[1].0.capacity().unpack()),
            ),
            typed(&lab.config, Role::Batch, 1, batch.encode().unwrap(), None),
            typed(
                &lab.config,
                Role::Checkpoint,
                1,
                next.encode().unwrap(),
                None,
            ),
        ],
        dependencies,
        &[],
    );
    lab.verify(
        "maximum 262144-byte batch with both duties and 16 blocks",
        &tx,
    );
}

#[test]
fn actual_vm_deep_claim_envelopes_with_all_nullifier_siblings() {
    for kind in [ClaimKind::Release, ClaimKind::Refund, ClaimKind::Escape] {
        let mut lab = Lab::new();
        lab.start();
        let recipient = lab.lock.calc_script_hash().as_slice().try_into().unwrap();
        let reserve = Vault::decode(&lab.outputs[2].1).unwrap().reserve;
        let mut f = common::with_config(
            1,
            lab.config.clone(),
            lab.policy.clone(),
            reserve,
            recipient,
            recipient,
        );
        common::deepen_fixture(&mut f);
        if kind == ClaimKind::Release {
            // Normal release must remain possible with all 32 newer deposits
            // uncredited. It does not depend on or consume the ordered Anchor.
            f.control.mode = Mode::Running;
            for _ in 0..32 {
                f.vault = f
                    .vault
                    .deposit(
                        &lab.config,
                        &lab.policy,
                        &f.control,
                        common::owner(),
                        100,
                        recipient,
                    )
                    .unwrap()
                    .0;
            }
            assert_eq!(
                f.vault.deposits.count - f.control.boundary.deposits.count,
                32
            );
        }
        if kind == ClaimKind::Refund {
            // Before the first settlement all deposited principal is refundable.
            f.control = Control::genesis(&lab.config, &lab.policy).unwrap();
            f.control.mode = Mode::Frozen;
            f.receipt.refund_lock = recipient;
        }
        let identity = if kind == ClaimKind::Escape {
            common::owner().to_vec()
        } else {
            1u64.to_le_bytes().to_vec()
        };
        let (nullifier, root) = common::full_nullifier(&f.vault.config, kind, &identity);
        f.vault.claims[kind as usize] = root;
        let (c, d) = typed(
            &lab.config,
            Role::Control,
            0,
            f.control.encode().unwrap(),
            Some(lab.outputs[3].0.capacity().unpack()),
        );
        let control_point = lab.context.create_cell(c, d);
        let (c, d) = typed(
            &lab.config,
            Role::Vault,
            0,
            f.vault.encode().unwrap(),
            Some(f.vault.capacity().unwrap()),
        );
        let vault_point = lab.context.create_cell(c, d);
        let (c, d) = typed(
            &lab.config,
            Role::DepositReceipt,
            1,
            f.receipt.encode().unwrap(),
            None,
        );
        let receipt_point = lab.context.create_cell(c, d);
        let (op, name, mut claim) = match kind {
            ClaimKind::Release => (
                Operation::Release,
                "release at deposit cap with 130 trie nodes and 256 nullifier siblings",
                f.release.clone(),
            ),
            ClaimKind::Refund => (
                Operation::Refund,
                "refund with 256 nullifier siblings",
                f.refund.clone(),
            ),
            ClaimKind::Escape => (
                Operation::Escape,
                "escape with 194 trie nodes and 256 nullifier siblings",
                f.escape.clone(),
            ),
        };
        claim.control_outpoint = control_point.as_slice().try_into().unwrap();
        claim.nullifier = nullifier;
        match &mut claim.request {
            Request::Refund { receipt_outpoint } => {
                *receipt_outpoint = receipt_point.as_slice().try_into().unwrap()
            }
            Request::Escape {
                owner,
                amount,
                recipient,
                signature,
                ..
            } => {
                let digest = tactus_v02_script::claims::escape_digest(
                    &lab.config,
                    &f.control,
                    &claim.control_outpoint,
                    owner,
                    *amount,
                    recipient,
                )
                .unwrap();
                let (sig, recovery) = common::signing_key()
                    .sign_prehash_recoverable(&digest)
                    .unwrap();
                signature[..64].copy_from_slice(&sig.to_bytes());
                signature[64] = recovery.to_byte();
            }
            _ => {}
        }
        let context = ClaimContext {
            config: &lab.config,
            policy: &lab.policy,
            control: &f.control,
            control_outpoint: claim.control_outpoint,
            vault: &f.vault,
            receipt: Some((receipt_point.as_slice().try_into().unwrap(), &f.receipt)),
        };
        let next = claim.authorize(&context).unwrap().next;
        let outputs = vec![
            typed(
                &lab.config,
                Role::Vault,
                0,
                next.encode().unwrap(),
                Some(next.capacity().unwrap()),
            ),
            (
                CellOutput::new_builder()
                    .lock(lab.lock.clone())
                    .capacity(100 * SHANNON)
                    .build(),
                Bytes::new(),
            ),
        ];
        let mut dependencies = vec![control_point];
        if kind == ClaimKind::Refund {
            dependencies.push(receipt_point);
        }
        let tx = lab.tx(
            op,
            vec![(vault_point.clone(), 0)],
            outputs.clone(),
            dependencies.clone(),
            &claim.encode().unwrap(),
        );
        lab.verify(name, &tx);
        for other in [&f.release, &f.refund, &f.escape] {
            if other.request.kind() == kind {
                continue;
            }
            let wrong_kind = lab.tx(
                op,
                vec![(vault_point.clone(), 0)],
                outputs.clone(),
                dependencies.clone(),
                &other.encode().unwrap(),
            );
            lab.reject(
                "claim operation rejects every other witness kind",
                &wrong_kind,
                Error::Encoding as u8,
            );
        }
        if let Ok(directory) = std::env::var("TACTUS_V02_DUMP_SETTLE") {
            let path = std::path::Path::new(&directory);
            std::fs::create_dir_all(path).unwrap();
            std::fs::write(
                path.join(format!("deep-claim-{}.json", kind as u8)),
                serde_json::to_vec_pretty(&lab.context.dump_tx(&tx).unwrap()).unwrap(),
            )
            .unwrap();
        }
        claim.nullifier.siblings[255][0] ^= 1;
        let bad = lab.tx(
            op,
            vec![(vault_point, 0)],
            outputs,
            dependencies,
            &claim.encode().unwrap(),
        );
        lab.reject(
            "deep claim with modified nullifier sibling",
            &bad,
            Error::Proof as u8,
        );
    }
}

#[test]
fn actual_vm_watch_requires_genuine_admission_and_deposit_sources() {
    let mut lab = Lab::new();
    lab.start();
    let (_, deposit, deposited) = lab.deposit();
    let control = Control::genesis(&lab.config, &lab.policy).unwrap();
    let (lane, admission) = Lane::genesis(control.boundary.config, 0)
        .unwrap()
        .enqueue(&control, &lab.policy, vec![0xff])
        .unwrap();
    let enqueue = lab.tx(
        Operation::Enqueue,
        vec![(lab.points[7].clone(), 0)],
        vec![
            typed(
                &lab.config,
                Role::Lane,
                0,
                lane.encode().unwrap(),
                Some(lab.outputs[7].0.capacity().unpack()),
            ),
            typed(
                &lab.config,
                Role::AdmissionReceipt,
                0,
                admission.encode().unwrap(),
                None,
            ),
        ],
        vec![lab.points[3].clone()],
        &[],
    );
    lab.verify("real admission source for Watch", &enqueue);
    let admitted = lab.install(&enqueue);
    let old_code = std::fs::read(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../artifacts/tactus_o1_native_anchor_script.elf"),
    )
    .unwrap();
    let old_code_hash: [u8; 32] = CellOutput::calc_data_hash(&Bytes::from(old_code))
        .as_slice()
        .try_into()
        .unwrap();
    for (role, index, data, point, work, op) in [
        (
            Role::AdmissionReceipt,
            0,
            admission.encode().unwrap(),
            admitted[1].clone(),
            Work::admission(0, 0).unwrap(),
            Operation::Enqueue,
        ),
        (
            Role::DepositReceipt,
            1,
            deposit.encode().unwrap(),
            deposited[1].clone(),
            Work::Deposit(1),
            Operation::Deposit,
        ),
    ] {
        let make_watch = |source: &OutPoint| Watch {
            config: control.boundary.config,
            work,
            source: source.as_slice().try_into().unwrap(),
            observed_control: control.commitment().unwrap(),
            refund_lock: lab.lock.calc_script_hash().as_slice().try_into().unwrap(),
        };
        let genuine = make_watch(&point);
        let positive = lab.tx(
            Operation::Watch,
            vec![],
            vec![typed(
                &lab.config,
                Role::Watch,
                0,
                genuine.encode().unwrap(),
                None,
            )],
            vec![lab.points[3].clone(), point],
            &[],
        );
        lab.verify("Watch against genuine immutable source", &positive);
        let self_authored = lab.tx(
            op,
            vec![],
            vec![typed(&lab.config, role, index, data.clone(), None)],
            vec![lab.points[3].clone()],
            &[],
        );
        lab.reject(
            "self-authored typed receipt without state transition",
            &self_authored,
            Error::Identity as u8,
        );
        for attack in 0..3 {
            let mut other = lab.config.clone();
            if attack == 1 {
                other.domain[0] ^= 1;
            }
            if attack == 2 {
                other.adapter_code_hash = old_code_hash;
            }
            let (mut c, d) = typed(&other, role, index, data.clone(), None);
            if attack == 0 {
                c = c
                    .as_builder()
                    .type_(ScriptOpt::default())
                    .lock(lab.lock.clone())
                    .build();
            }
            let source = lab.context.create_cell(c, d);
            let mut ticket = genuine.clone();
            ticket.source = source.as_slice().try_into().unwrap();
            let forged = lab.tx(
                Operation::Watch,
                vec![],
                vec![typed(
                    &lab.config,
                    Role::Watch,
                    0,
                    ticket.encode().unwrap(),
                    None,
                )],
                vec![lab.points[3].clone(), source],
                &[],
            );
            lab.reject(
                "untyped, foreign-domain or old-code receipt cannot authorize Watch",
                &forged,
                Error::Identity as u8,
            );
        }
    }
}
