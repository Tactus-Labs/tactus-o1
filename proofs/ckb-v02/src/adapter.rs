//! Whole-transaction rules over syscall-resolved CKB cells. Unit fixtures are
//! not chain evidence; on CKB the runtime must populate every field from syscalls.
use crate::claims::{ClaimWitness, Context, Request};
use alloc::{format, string::String, vec::Vec};
use ckb_std::ckb_types::{packed::Script, prelude::*};
use tactus_o1_protocol::v02::Reader;
use tactus_o1_protocol::{genesis, v02::*};

pub const MAX_CELLS: usize = 64;
pub const MAX_PROOF: usize = 4096;
pub const MAX_OPERATION: usize = ClaimWitness::MAX_BYTES + 9;
pub const MAX_RESOLVED_DATA: usize = 2 * 1024 * 1024;

#[derive(Clone, Debug)]
pub struct Cell {
    pub capacity: u64,
    pub occupied: u64,
    pub lock: Script,
    pub type_script: Option<Script>,
    pub data: Vec<u8>,
    pub outpoint: [u8; 36],
    pub since: u64,
}
pub struct Transaction {
    pub script: Script,
    pub inputs: Vec<Cell>,
    pub outputs: Vec<Cell>,
    pub deps: Vec<Cell>,
    pub first_input: [u8; 44],
    /// Only populated after authenticating a number-zero CKB header dependency.
    pub genesis_hash: Option<[u8; 32]>,
    /// WitnessArgs.output_type at absolute input index zero, shared by all roles.
    pub operation: Vec<u8>,
}
pub fn script_hash(script: &Script) -> [u8; 32] {
    hash(b"", script.as_slice())
}
pub fn wrapper_key_hash() -> [u8; 32] {
    hash(b"tactus/0.02/groth16-vk", &sp1_verifier::GROTH16_VK_BYTES)
}
pub fn type_script(config: &Config, role: Role, index: u64) -> Result<Script> {
    Ok(Script::new_builder()
        .code_hash(config.adapter_code_hash.pack())
        .hash_type(2u8.into())
        .args(config.args(role, index)?.pack())
        .build())
}
pub fn protocol_lock(config: &Config, type_script: &Script) -> Script {
    Script::new_builder()
        .code_hash(config.head_lock_code_hash.pack())
        .hash_type(2u8.into())
        .args(script_hash(type_script).to_vec().pack())
        .build()
}
fn own_role(script: &Script, config: &Config) -> Result<RoleRef> {
    if script.code_hash().as_slice() != config.adapter_code_hash || script.hash_type() != 2u8.into()
    {
        return Err(Error::Identity);
    }
    RoleRef::from_args(config, &script.args().raw_data())
}
fn cell<'a>(cells: &'a [Cell], config: &Config, role: Role, index: u64) -> Result<&'a Cell> {
    let expected = type_script(config, role, index)?;
    let mut found = None;
    for c in cells {
        if c.type_script.as_ref() == Some(&expected) && found.replace(c).is_some() {
            return Err(Error::Identity);
        }
    }
    found.ok_or(Error::Identity)
}
fn one_role<'a>(cells: &'a [Cell], config: &Config, role: Role) -> Result<(&'a Cell, u64)> {
    let mut found = None;
    for c in cells {
        if let Some(script) = &c.type_script {
            if let Ok(id) = own_role(script, config) {
                if id.role == role && found.replace((c, id.index)).is_some() {
                    return Err(Error::Identity);
                }
            }
        }
    }
    found.ok_or(Error::Identity)
}
fn read<T: Wire>(cells: &[Cell], config: &Config, role: Role, index: u64) -> Result<T> {
    T::decode(&cell(cells, config, role, index)?.data)
}
fn expect<T: Wire>(
    cells: &[Cell],
    config: &Config,
    role: Role,
    index: u64,
    value: &T,
) -> Result<()> {
    if cell(cells, config, role, index)?.data != value.encode()? {
        return Err(Error::Continuity);
    }
    Ok(())
}
fn source<'a>(deps: &'a [Cell], point: &[u8; 36]) -> Result<&'a Cell> {
    let mut found = None;
    for c in deps {
        if c.outpoint == *point && found.replace(c).is_some() {
            return Err(Error::Identity);
        }
    }
    found.ok_or(Error::Identity)
}
fn source_role(c: &Cell, config: &Config, role: Role, index: u64) -> Result<()> {
    if c.type_script.as_ref() != Some(&type_script(config, role, index)?) {
        return Err(Error::Identity);
    }
    Ok(())
}

impl Transaction {
    fn configuration(&self, operation: Operation) -> Result<Config> {
        let args = self.script.args().raw_data();
        if args.len() != 41 || self.script.hash_type() != 2u8.into() {
            return Err(Error::Identity);
        }
        let mut config_args = args[..32].to_vec();
        config_args.push(Role::Config as u8);
        config_args.extend_from_slice(&0u64.to_le_bytes());
        let expected = self
            .script
            .clone()
            .as_builder()
            .args(config_args.pack())
            .build();
        let cells = if operation == Operation::Genesis {
            &self.outputs
        } else {
            &self.deps
        };
        let mut found = None;
        for c in cells {
            if c.type_script.as_ref() == Some(&expected) && found.replace(c).is_some() {
                return Err(Error::Identity);
            }
        }
        let config = Config::decode(&found.ok_or(Error::Identity)?.data)?;
        own_role(&self.script, &config)?;
        Ok(config)
    }
    fn bounds(&self) -> Result<()> {
        if self.inputs.is_empty() || self.operation.len() > MAX_OPERATION {
            return Err(Error::Resource);
        }
        let mut bytes = 0usize;
        for cells in [&self.inputs, &self.outputs, &self.deps] {
            if cells.len() > MAX_CELLS {
                return Err(Error::Resource);
            }
            for c in cells {
                bytes = bytes.checked_add(c.data.len()).ok_or(Error::Resource)?;
                if bytes > MAX_RESOLVED_DATA || c.capacity < c.occupied {
                    return Err(Error::Resource);
                }
            }
        }
        Ok(())
    }
    fn roles(&self, config: &Config, policy: &Policy, operation: Operation) -> Result<()> {
        let mut sides = [Vec::new(), Vec::new()];
        for (side, cells) in [&self.inputs, &self.outputs].into_iter().enumerate() {
            for c in cells {
                if let Some(script) = &c.type_script {
                    let id = own_role(script, config)?;
                    if c.lock != protocol_lock(config, script) {
                        return Err(Error::Authorization);
                    }
                    sides[side].push(id);
                }
            }
        }
        check_role_shape(operation, &sides[0], &sides[1], policy.lanes)?;
        // The running script must actually be one of this transaction's types.
        if !self
            .inputs
            .iter()
            .chain(&self.outputs)
            .any(|c| c.type_script.as_ref() == Some(&self.script))
        {
            return Err(Error::Identity);
        }
        for before in &self.inputs {
            let Some(script) = &before.type_script else {
                continue;
            };
            let role = own_role(script, config)?;
            if matches!(
                role.role,
                Role::Anchor | Role::Schedule | Role::Lane | Role::Control
            ) {
                let after = cell(&self.outputs, config, role.role, role.index)?;
                if before.capacity != after.capacity {
                    return Err(Error::Accounting);
                }
            }
        }
        Ok(())
    }
    fn live_control(&self, config: &Config, policy: &Policy) -> Result<Control> {
        let control: Control = read(&self.deps, config, Role::Control, 0)?;
        control.bind(config, policy)?;
        Ok(control)
    }
    fn payout(&self, index: u32, lock: [u8; 32], amount: u64) -> Result<()> {
        let output = self.outputs.get(index as usize).ok_or(Error::Accounting)?;
        if output.type_script.is_some()
            || !output.data.is_empty()
            || script_hash(&output.lock) != lock
            || output.capacity < amount
            || output.capacity < output.occupied
        {
            return Err(Error::Accounting);
        }
        Ok(())
    }
    fn work(&self, config: &Config, ticket: &Watch) -> Result<()> {
        let c = source(&self.deps, &ticket.source)?;
        match ticket.work {
            Work::Batch(end) => {
                source_role(c, config, Role::Checkpoint, end)?;
                let boundary = Boundary::decode(&c.data)?;
                if boundary.config != ticket.config || boundary.batches != end {
                    return Err(Error::Identity);
                }
            }
            Work::Deposit(end) => {
                source_role(c, config, Role::DepositReceipt, end)?;
                let receipt = Deposit::decode(&c.data)?;
                if receipt.config != ticket.config || receipt.sequence != end {
                    return Err(Error::Identity);
                }
            }
            Work::Admission { lane, end } => {
                let sequence = end.checked_sub(1).ok_or(Error::Identity)?;
                source_role(c, config, Role::AdmissionReceipt, sequence)?;
                let receipt = Admission::decode(&c.data)?;
                if receipt.config != ticket.config
                    || receipt.sequence != sequence
                    || receipt.lane != lane
                {
                    return Err(Error::Identity);
                }
            }
        }
        Ok(())
    }
    pub fn verify(&self) -> Result<()> {
        self.bounds()?;
        let mut r = Reader::new(&self.operation, MAX_OPERATION)?;
        if r.array::<8>()? != *b"T02OP001" {
            return Err(Error::Encoding);
        }
        let operation = Operation::try_from(r.u8()?)?;
        let config = self.configuration(operation)?;
        let policy: Policy = read(
            if operation == Operation::Genesis {
                &self.outputs
            } else {
                &self.deps
            },
            &config,
            Role::Policy,
            0,
        )?;
        config.bind(&policy)?;
        if policy.wrapper_key_hash != wrapper_key_hash() {
            return Err(Error::Domain);
        }
        self.roles(&config, &policy, operation)?;
        match operation {
            Operation::Genesis => self.genesis(&config, &policy)?,
            Operation::Enqueue => self.enqueue(&config, &policy)?,
            Operation::Deposit => self.deposit(&config, &policy)?,
            Operation::Seal => self.seal(&config, &policy)?,
            Operation::Append => self.append(&config, &policy)?,
            Operation::Settle => self.settle(&config, &policy, &mut r)?,
            Operation::Watch => {
                let control = self.live_control(&config, &policy)?;
                control.running()?;
                let ticket: Watch = read(&self.outputs, &config, Role::Watch, 0)?;
                if ticket.config != config.commitment()?
                    || ticket.observed_control != control.commitment()?
                    || !ticket.work.pending(&control.boundary, policy.lanes)?
                {
                    return Err(Error::Duty);
                }
                self.work(&config, &ticket)?;
            }
            Operation::CloseWatch | Operation::Freeze => {
                self.close_watch(&config, &policy, operation, r.u32()?)?
            }
            Operation::Release | Operation::Refund | Operation::Escape => {
                let bytes = r.take(self.operation.len() - 9)?;
                let witness = ClaimWitness::decode(bytes)?;
                let kind = match operation {
                    Operation::Release => ClaimKind::Release,
                    Operation::Refund => ClaimKind::Refund,
                    _ => ClaimKind::Escape,
                };
                if witness.request.kind() != kind {
                    return Err(Error::Encoding);
                }
                self.claim(&config, &policy, &witness)?;
            }
        }
        r.finish()
    }
    fn genesis(&self, config: &Config, policy: &Policy) -> Result<()> {
        let anchor = cell(&self.outputs, config, Role::Anchor, 0)?;
        let index = self
            .outputs
            .iter()
            .position(|c| core::ptr::eq(c, anchor))
            .ok_or(Error::Identity)?;
        if Config::domain_id(&self.first_input, index as u64) != config.domain
            || self.genesis_hash != Some(config.ckb_genesis)
        {
            return Err(Error::Domain);
        }
        let identity = config.commitment()?;
        expect(
            &self.outputs,
            config,
            Role::Anchor,
            0,
            &Boundary::genesis(identity)?,
        )?;
        expect(
            &self.outputs,
            config,
            Role::Schedule,
            0,
            &Schedule::genesis(identity)?,
        )?;
        expect(
            &self.outputs,
            config,
            Role::Control,
            0,
            &Control::genesis(config, policy)?,
        )?;
        let vault_cell = cell(&self.outputs, config, Role::Vault, 0)?;
        expect(
            &self.outputs,
            config,
            Role::Vault,
            0,
            &Vault::genesis(identity, vault_cell.occupied)?,
        )?;
        if vault_cell.capacity != vault_cell.occupied {
            return Err(Error::Accounting);
        }
        for lane in 0..policy.lanes {
            let c = cell(&self.outputs, config, Role::Lane, u64::from(lane))?;
            expect(
                &self.outputs,
                config,
                Role::Lane,
                u64::from(lane),
                &Lane::genesis(identity, lane)?,
            )?;
            // Pre-fund the full bounded queue so ENQUEUE never has to steal capacity.
            let additional = (Lane::MAX_BYTES - c.data.len()) as u64 * 100_000_000;
            if c.capacity
                < c.occupied
                    .checked_add(additional)
                    .ok_or(Error::Arithmetic)?
            {
                return Err(Error::Accounting);
            }
        }
        let bytes = &cell(&self.outputs, config, Role::Allocation, 0)?.data;
        if genesis::commitment(bytes).map_err(|_| Error::Encoding)? != config.allocation {
            return Err(Error::Domain);
        }
        let allocation = genesis::Allocation::decode(bytes).map_err(|_| Error::Encoding)?;
        if allocation.accounts.iter().any(|a| a.address == [0; 20]) {
            return Err(Error::Authorization);
        }
        let bridge = allocation
            .accounts
            .iter()
            .find(|a| a.address == config.bridge)
            .ok_or(Error::Identity)?;
        if bridge.nonce != 1
            || bridge.balance != [0; 32]
            || !bridge.storage.is_empty()
            || alloy_primitives::keccak256(&bridge.code).0 != policy.bridge_code_hash
        {
            return Err(Error::Authorization);
        }
        Ok(())
    }
    fn enqueue(&self, config: &Config, policy: &Policy) -> Result<()> {
        let control = self.live_control(config, policy)?;
        let (c, index) = one_role(&self.inputs, config, Role::Lane)?;
        let lane = Lane::decode(&c.data)?;
        if u64::from(lane.lane) != index {
            return Err(Error::Identity);
        }
        let after: Lane = read(&self.outputs, config, Role::Lane, index)?;
        let payload = after.messages.last().ok_or(Error::Duty)?.payload.clone();
        let (expected, receipt) = lane.enqueue(&control, policy, payload)?;
        if expected != after {
            return Err(Error::Continuity);
        }
        expect(
            &self.outputs,
            config,
            Role::AdmissionReceipt,
            receipt.sequence,
            &receipt,
        )
    }
    fn deposit(&self, config: &Config, policy: &Policy) -> Result<()> {
        let control = self.live_control(config, policy)?;
        let before: Vault = read(&self.inputs, config, Role::Vault, 0)?;
        let (record_cell, index) = one_role(&self.outputs, config, Role::DepositReceipt)?;
        let receipt = Deposit::decode(&record_cell.data)?;
        if receipt.sequence != index {
            return Err(Error::Identity);
        }
        let (after, expected) = before.deposit(
            config,
            policy,
            &control,
            receipt.recipient,
            receipt.amount,
            receipt.refund_lock,
        )?;
        if receipt != expected {
            return Err(Error::Continuity);
        }
        expect(&self.outputs, config, Role::Vault, 0, &after)?;
        self.vault_capacities(config, &before, &after)
    }
    fn vault_capacities(&self, config: &Config, before: &Vault, after: &Vault) -> Result<()> {
        if cell(&self.inputs, config, Role::Vault, 0)?.capacity != before.capacity()?
            || cell(&self.outputs, config, Role::Vault, 0)?.capacity != after.capacity()?
            || before.reserve != after.reserve
        {
            return Err(Error::Accounting);
        }
        Ok(())
    }
    fn seal(&self, config: &Config, policy: &Policy) -> Result<()> {
        let control = self.live_control(config, policy)?;
        let anchor: Boundary = read(&self.deps, config, Role::Anchor, 0)?;
        let before: Schedule = read(&self.inputs, config, Role::Schedule, 0)?;
        let vault: Vault = read(&self.inputs, config, Role::Vault, 0)?;
        let lanes: Result<Vec<Lane>> = (0..policy.lanes)
            .map(|lane| read(&self.inputs, config, Role::Lane, u64::from(lane)))
            .collect();
        let previous = if before.epoch == 0 {
            None
        } else {
            Some(read::<Snapshot>(
                &self.deps,
                config,
                Role::Snapshot,
                before.epoch,
            )?)
        };
        let (schedule, snapshot, lanes) = before.seal(
            config,
            policy,
            &control,
            &anchor,
            &lanes?,
            &vault,
            previous.as_ref(),
        )?;
        expect(&self.outputs, config, Role::Schedule, 0, &schedule)?;
        expect(
            &self.outputs,
            config,
            Role::Snapshot,
            snapshot.epoch,
            &snapshot,
        )?;
        for lane in &lanes {
            expect(
                &self.outputs,
                config,
                Role::Lane,
                u64::from(lane.lane),
                lane,
            )?;
        }
        expect(&self.outputs, config, Role::Vault, 0, &vault)?;
        self.vault_capacities(config, &vault, &vault)
    }
    fn append(&self, config: &Config, policy: &Policy) -> Result<()> {
        let control = self.live_control(config, policy)?;
        let parent: Boundary = read(&self.inputs, config, Role::Anchor, 0)?;
        let schedule: Schedule = read(&self.inputs, config, Role::Schedule, 0)?;
        let snapshot: Snapshot = read(&self.deps, config, Role::Snapshot, schedule.epoch)?;
        let (batch_cell, index) = one_role(&self.outputs, config, Role::Batch)?;
        let batch = NativeBatch::decode(&batch_cell.data)?;
        if batch.parent != parent
            || index != parent.batches.checked_add(1).ok_or(Error::Arithmetic)?
        {
            return Err(Error::Continuity);
        }
        for deposit in &batch.deposits {
            let receipt: Deposit =
                read(&self.deps, config, Role::DepositReceipt, deposit.sequence)?;
            if receipt != *deposit {
                return Err(Error::Identity);
            }
        }
        let (next, schedule) = batch.append(
            config,
            policy,
            &control,
            &schedule,
            &snapshot,
            cell(&self.inputs, config, Role::Anchor, 0)?.since,
        )?;
        expect(&self.outputs, config, Role::Anchor, 0, &next)?;
        expect(&self.outputs, config, Role::Schedule, 0, &schedule)?;
        expect(&self.outputs, config, Role::Checkpoint, next.batches, &next)
    }
    fn settle(&self, config: &Config, policy: &Policy, r: &mut Reader<'_>) -> Result<()> {
        let bytes = r.take(Journal::MAX_BYTES)?;
        let journal = Journal::decode(bytes)?;
        let proof = r.blob(MAX_PROOF)?;
        let before: Control = read(&self.inputs, config, Role::Control, 0)?;
        before.bind(config, policy)?;
        if before.initialized {
            expect(
                &self.deps,
                config,
                Role::Checkpoint,
                before.boundary.batches,
                &before.boundary,
            )?;
        }
        let endpoint: Boundary = read(
            &self.deps,
            config,
            Role::Checkpoint,
            journal.end.boundary.batches,
        )?;
        let after = before.settlement_candidate(&journal, &endpoint)?;
        after.bind(config, policy)?;
        expect(&self.outputs, config, Role::Control, 0, &after)?;
        let key: String = policy
            .guest_key
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        sp1_verifier::Groth16Verifier::verify(
            proof,
            bytes,
            &format!("0x{key}"),
            &sp1_verifier::GROTH16_VK_BYTES,
        )
        .map_err(|_| Error::Proof)
    }
    fn close_watch(
        &self,
        config: &Config,
        policy: &Policy,
        operation: Operation,
        payout: u32,
    ) -> Result<()> {
        let c = cell(&self.inputs, config, Role::Watch, 0)?;
        let ticket = Watch::decode(&c.data)?;
        if operation == Operation::Freeze {
            let control_cell = cell(&self.inputs, config, Role::Control, 0)?;
            let control = Control::decode(&control_cell.data)?;
            control.bind(config, policy)?;
            self.work(config, &ticket)?;
            let frozen = control.freeze_candidate(&ticket, policy, control_cell.since, c.since)?;
            expect(&self.outputs, config, Role::Control, 0, &frozen)?;
        } else {
            ticket.close_allowed(&self.live_control(config, policy)?, policy)?;
        }
        self.payout(payout, ticket.refund_lock, c.capacity)
    }
    fn claim(&self, config: &Config, policy: &Policy, witness: &ClaimWitness) -> Result<()> {
        let control_cell = cell(&self.deps, config, Role::Control, 0)?;
        let control = self.live_control(config, policy)?;
        let vault: Vault = read(&self.inputs, config, Role::Vault, 0)?;
        let receipt = if let Request::Refund { receipt_outpoint } = &witness.request {
            let c = source(&self.deps, receipt_outpoint)?;
            let receipt = Deposit::decode(&c.data)?;
            source_role(c, config, Role::DepositReceipt, receipt.sequence)?;
            Some((c.outpoint, receipt))
        } else {
            None
        };
        let payout = witness.authorize(&Context {
            config,
            policy,
            control: &control,
            control_outpoint: control_cell.outpoint,
            vault: &vault,
            receipt: receipt.as_ref().map(|(p, r)| (*p, r)),
        })?;
        expect(&self.outputs, config, Role::Vault, 0, &payout.next)?;
        self.vault_capacities(config, &vault, &payout.next)?;
        self.payout(payout.output, payout.lock, payout.amount)
    }
}
