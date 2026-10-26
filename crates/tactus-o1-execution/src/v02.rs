//! Full-state 0.02 execution. The L1 adapter authenticates publication; the new
//! proof guest must commit its result. Calling this executor proves neither.
use super::*;
use revm::{DatabaseCommit, SystemCallEvm};
use tactus_o1_protocol::v02::{
    self as wire, Boundary, Config, Control, Deposit, Mode, NativeBatch, Policy, Schedule,
    Snapshot, Wire,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum V02Error {
    Wire(wire::Error),
    Execution(Error),
    Genesis,
    Credit,
    Invariant,
}
impl From<wire::Error> for V02Error {
    fn from(e: wire::Error) -> Self {
        Self::Wire(e)
    }
}
impl From<Error> for V02Error {
    fn from(e: Error) -> Self {
        Self::Execution(e)
    }
}
impl std::fmt::Display for V02Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for V02Error {}

pub fn rules_hash() -> [u8; 32] {
    V02_EXECUTION_RULES_HASH
}
pub fn profile_hash() -> [u8; 32] {
    wire::hash(b"tactus/0.02/profile", &rules_hash())
}
pub fn domain(config: &Config) -> B256 {
    keccak256(
        [
            b"TO2BRDG1".as_slice(),
            &config.domain,
            &config.ckb_genesis,
            &U256::from(config.chain).to_be_bytes::<32>(),
            &config.bridge,
        ]
        .concat(),
    )
}
pub fn runtime(config: &Config) -> Bytes {
    let mut code = NATIVE_RUNTIME.to_vec();
    for &start in NATIVE_DOMAIN_OFFSETS {
        code[start..start + 32].copy_from_slice(domain(config).as_slice());
    }
    code.into()
}
fn calldata(record: &Deposit) -> Result<Bytes, V02Error> {
    let mut bytes = keccak256(b"creditDeposit(bytes32,address,uint64)")[..4].to_vec();
    bytes.extend_from_slice(&record.commitment()?);
    bytes.extend_from_slice(&[0; 12]);
    bytes.extend_from_slice(&record.recipient);
    bytes.extend_from_slice(&U256::from(record.amount).to_be_bytes::<32>());
    Ok(bytes.into())
}
fn env(inner: &Executor, block: &batch::BlockInput) -> Result<BlockEnv, Error> {
    Ok(BlockEnv {
        number: U256::from(inner.head.number.checked_add(1).ok_or(Error::Arithmetic)?),
        beneficiary: Address::from(block.fee_recipient),
        timestamp: U256::from(block.timestamp),
        gas_limit: BLOCK_GAS_LIMIT,
        basefee: next_base_fee(
            inner.head.base_fee_per_gas.ok_or(Error::Rules)?,
            inner.head.gas_used,
        )?,
        difficulty: U256::ZERO,
        prevrandao: Some(B256::ZERO),
        blob_excess_gas_and_price: None,
        slot_num: 0,
    })
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DepositOutcome {
    pub record: Deposit,
    pub gas_used: u64,
    pub logs: Vec<alloy_primitives::Log>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecutedBatch {
    pub deposits: Vec<DepositOutcome>,
    pub blocks: Vec<ExecutedBlock>,
}

#[derive(Clone, Debug)]
pub struct V02Executor {
    inner: Executor,
    config: Config,
    policy: Policy,
    boundary: Boundary,
}
impl V02Executor {
    pub fn new(genesis: &Genesis, config: Config, policy: Policy) -> Result<Self, V02Error> {
        config.bind(&policy)?;
        if policy.rules != rules_hash()
            || policy.profile != profile_hash()
            || policy.credit_gas != 200_000
            || genesis.rollup_id.0 != config.domain
            || genesis.chain_id != config.chain
            || genesis.accounts.contains_key(&Address::ZERO)
            || tactus_o1_protocol::genesis::commitment(&genesis.allocation_bytes()?)
                .map_err(|_| V02Error::Genesis)?
                != config.allocation
        {
            return Err(V02Error::Genesis);
        }
        let bridge = genesis
            .accounts
            .get(&Address::from(config.bridge))
            .ok_or(V02Error::Genesis)?;
        let code = runtime(&config);
        if bridge.code != code
            || bridge.nonce != 1
            || !bridge.balance.is_zero()
            || !bridge.storage.is_empty()
            || keccak256(&code).0 != policy.bridge_code_hash
        {
            return Err(V02Error::Genesis);
        }
        let boundary = Boundary::genesis(config.commitment()?)?;
        let mut inner = Executor::new(genesis)?;
        inner.anchor.execution_rules_hash = rules_hash();
        inner.head.extra_data = wire::hash(
            b"tactus/0.02/evm-genesis",
            &[boundary.config.as_slice(), &policy.profile].concat(),
        )
        .to_vec()
        .into();
        inner
            .db
            .cache
            .block_hashes
            .insert(U256::ZERO, inner.head.hash_slow());
        let value = Self {
            inner,
            config,
            policy,
            boundary,
        };
        value.invariant()?;
        Ok(value)
    }
    pub fn boundary(&self) -> &Boundary {
        &self.boundary
    }
    pub fn config(&self) -> &Config {
        &self.config
    }
    pub fn policy(&self) -> &Policy {
        &self.policy
    }
    pub fn head(&self) -> &Header {
        &self.inner.head
    }
    pub fn account(&self, address: Address) -> Option<GenesisAccount> {
        self.inner.account(address)
    }
    fn invariant(&self) -> Result<(), V02Error> {
        Self::check(&self.inner, &self.config, &self.policy, &self.boundary)
    }
    fn check(
        inner: &Executor,
        config: &Config,
        policy: &Policy,
        boundary: &Boundary,
    ) -> Result<(), V02Error> {
        let bridge = inner
            .account(Address::from(config.bridge))
            .ok_or(V02Error::Invariant)?;
        let slot = |i: u64| {
            bridge
                .storage
                .get(&U256::from(i))
                .copied()
                .unwrap_or_default()
        };
        if bridge.code != runtime(config)
            || bridge.nonce != 1
            || keccak256(&bridge.code).0 != policy.bridge_code_hash
            || slot(1) != U256::from(boundary.deposits.cumulative)
            || slot(0).checked_add(slot(2)) != Some(slot(1))
            || slot(0) > U256::from(u64::MAX)
            || inner
                .account(Address::ZERO)
                .is_some_and(|a| a.nonce != 0 || !a.code.is_empty() || !a.storage.is_empty())
        {
            return Err(V02Error::Invariant);
        }
        Ok(())
    }
    /// Proof output candidate derived from actual bridge storage, never host totals.
    pub fn control_candidate(&self) -> Result<Control, V02Error> {
        self.invariant()?;
        if self.boundary.batches == 0 {
            return Ok(Control::genesis(&self.config, &self.policy)?);
        }
        let bridge = self
            .inner
            .account(Address::from(self.config.bridge))
            .ok_or(V02Error::Invariant)?;
        let read = |index: u64| -> Result<u128, V02Error> {
            bridge
                .storage
                .get(&U256::from(index))
                .copied()
                .unwrap_or_default()
                .try_into()
                .map_err(|_| V02Error::Invariant)
        };
        let value = Control {
            mode: Mode::Running,
            initialized: true,
            policy: self.config.policy,
            profile: self.policy.profile,
            boundary: self.boundary.clone(),
            state_root: self.inner.state_root().0,
            block_hash: self.inner.head_hash().0,
            supply: read(0)?,
            burned: read(2)?,
        };
        value.bind(&self.config, &self.policy)?;
        Ok(value)
    }
    pub fn apply_batch(
        &mut self,
        bytes: &[u8],
        snapshot: &Snapshot,
    ) -> Result<ExecutedBatch, V02Error> {
        self.invariant()?;
        let input = NativeBatch::decode(bytes)?;
        if input.parent != self.boundary {
            return Err(wire::Error::Continuity.into());
        }
        let schedule = if self.boundary.snapshot == input.snapshot {
            Schedule {
                config: self.boundary.config,
                epoch: self.boundary.epoch,
                snapshot: self.boundary.snapshot,
                batches: self.boundary.epoch_batches,
                user_cursor: self.boundary.user_cursor,
                deposit_cursor: self.boundary.deposit_cursor,
            }
        } else {
            Schedule {
                config: self.boundary.config,
                epoch: snapshot.epoch,
                snapshot: input.snapshot,
                batches: 0,
                user_cursor: 0,
                deposit_cursor: 0,
            }
        };
        let (next, _) = input.replay(&self.config, &self.policy, &schedule, snapshot)?;
        let config = &self.config;
        let policy = &self.policy;
        let mut candidate = ExecutionTransaction::new(&mut self.inner);
        let environment = env(&candidate, &input.blocks[0])?;
        let mut deposits = Vec::with_capacity(input.deposits.len());
        for record in input.deposits {
            let result = Context::mainnet()
                .modify_cfg_chained(|cfg| {
                    cfg.set_spec_and_mainnet_gas_params(SpecId::SHANGHAI);
                    cfg.chain_id = config.chain;
                })
                .with_db(&mut candidate.db)
                .with_block(environment.clone())
                .build_mainnet()
                .system_call_with_caller(
                    Address::ZERO,
                    Address::from(config.bridge),
                    calldata(&record)?,
                )
                .map_err(|e| Error::Engine(e.to_string()))?;
            if !result.result.is_success() || result.result.tx_gas_used() > policy.credit_gas {
                return Err(V02Error::Credit);
            }
            deposits.push(DepositOutcome {
                record,
                gas_used: result.result.tx_gas_used(),
                logs: result.result.logs().to_vec(),
            });
            candidate.db.commit(result.state);
        }
        let working = &mut *candidate;
        let mut blocks = Vec::with_capacity(input.blocks.len());
        let mut deposited_state = !deposits.is_empty();
        for (block_index, block) in input.blocks.into_iter().enumerate() {
            let environment = env(working, &block)?;
            let number = working
                .head
                .number
                .checked_add(1)
                .ok_or(Error::Arithmetic)?;
            let mut gas_used = 0;
            let mut outcomes = Vec::with_capacity(block.transactions.len());
            let mut transactions = Vec::new();
            let mut receipts = Vec::new();
            let mut bloom = Bloom::ZERO;
            for (slot, raw) in block.transactions.into_iter().enumerate() {
                let priority = block_index == 0 && slot < input.priority.len();
                let limit = if priority {
                    policy.priority_gas
                } else {
                    BLOCK_GAS_LIMIT - gas_used
                };
                let mut outcome = SlotOutcome {
                    input_hash: keccak256(&raw),
                    status: Status::Malformed,
                    gas_used: 0,
                    output: Bytes::new(),
                    created_address: None,
                    transaction_index: None,
                };
                let (envelope, tx) = match decode_transaction(&raw, config.chain, limit) {
                    Ok(value) => value,
                    Err(status) => {
                        outcome.status = if priority && status == Status::BlockGas {
                            Status::PriorityGasLimit
                        } else {
                            status
                        };
                        outcomes.push(outcome);
                        continue;
                    }
                };
                if tx.caller == Address::ZERO {
                    outcome.status = Status::InvalidSignature;
                    outcomes.push(outcome);
                    continue;
                }
                let result = Context::mainnet()
                    .modify_cfg_chained(|cfg| {
                        cfg.set_spec_and_mainnet_gas_params(SpecId::SHANGHAI);
                        cfg.chain_id = config.chain;
                    })
                    .with_db(&mut working.db)
                    .with_block(environment.clone())
                    .build_mainnet()
                    .transact(tx);
                let result = match result {
                    Ok(result) => result,
                    Err(EVMError::Transaction(_)) => {
                        outcome.status = Status::InvalidTransaction;
                        outcomes.push(outcome);
                        continue;
                    }
                    Err(error) => return Err(Error::Engine(error.to_string()).into()),
                };
                outcome.status = match &result.result {
                    ExecutionResult::Success { .. } => Status::Success,
                    ExecutionResult::Revert { .. } => Status::Revert,
                    ExecutionResult::Halt { .. } => Status::Halt,
                };
                outcome.gas_used = result.result.tx_gas_used();
                outcome.output = result.result.output().cloned().unwrap_or_default();
                outcome.created_address = result.result.created_address();
                outcome.transaction_index = Some(transactions.len() as u32);
                gas_used = gas_used
                    .checked_add(outcome.gas_used)
                    .filter(|gas| *gas <= BLOCK_GAS_LIMIT)
                    .ok_or(Error::Arithmetic)?;
                let receipt = ReceiptEnvelope::from_typed(
                    envelope.tx_type(),
                    Receipt {
                        status: result.result.is_success().into(),
                        cumulative_gas_used: gas_used,
                        logs: if result.result.is_success() {
                            result.result.logs().to_vec()
                        } else {
                            Vec::new()
                        },
                    },
                );
                bloom |= *receipt.logs_bloom();
                working.db.commit(result.state);
                receipts.push(receipt);
                transactions.push(Bytes::from(raw));
                outcomes.push(outcome);
            }
            let outcome_root = outcomes_commitment(&working.anchor, next.inputs, number, &outcomes);
            let header = Header {
                parent_hash: working.head_hash(),
                beneficiary: environment.beneficiary,
                state_root: if !deposited_state && transactions.is_empty() {
                    working.head.state_root
                } else {
                    state_root(&working.db)
                },
                transactions_root: ordered_trie_root_encoded(&transactions),
                receipts_root: ordered_trie_root_encoded(
                    &receipts
                        .iter()
                        .map(Encodable2718::encoded_2718)
                        .collect::<Vec<_>>(),
                ),
                logs_bloom: bloom,
                number,
                gas_limit: BLOCK_GAS_LIMIT,
                gas_used,
                timestamp: block.timestamp,
                base_fee_per_gas: Some(environment.basefee),
                withdrawals_root: Some(EMPTY_ROOT_HASH),
                extra_data: wire::hash(
                    b"tactus/0.02/evm-block",
                    &[outcome_root.as_slice(), &next.commitment()?].concat(),
                )
                .to_vec()
                .into(),
                ..Default::default()
            };
            let hash = header.hash_slow();
            working
                .db
                .cache
                .block_hashes
                .insert(U256::from(number), hash);
            working
                .db
                .cache
                .block_hashes
                .retain(|n, _| *n >= U256::from(number.saturating_sub(255)));
            working.head = header.clone();
            deposited_state = false;
            blocks.push(ExecutedBlock {
                header,
                hash,
                outcomes,
                transactions,
                receipts,
            });
        }
        working.anchor.next_batch_number = next.batches;
        working.anchor.last_batch_commitment = next.inputs;
        working.anchor.last_block_number = next.blocks;
        working.anchor.last_timestamp = next.timestamp;
        Self::check(&candidate, config, policy, &next)?;
        candidate.accept();
        self.boundary = next;
        Ok(ExecutedBatch { deposits, blocks })
    }
}

// Keep host-only witness access separate from the pinned guest implementation.
#[cfg(not(target_os = "zkvm"))]
impl V02Executor {
    /// Read-only state export for independently verified recovery witnesses.
    pub fn accounts(&self) -> impl Iterator<Item = (Address, GenesisAccount)> + '_ {
        self.inner.accounts()
    }
}
