//! Candidate v2 execution. CKB publication/settlement must authenticate the
//! deposit transcript; executing caller-provided records is not custody authority.
use super::*;
use revm::SystemCallEvm;
use tactus_o1_protocol::native_bridge::{self as wire, Anchor, Batch, Config, Cursor, Record};

/// Bound checked on successful pinned-contract calls, outside user block gas.
pub const MAX_CREDIT_GAS: u64 = 200_000;
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BridgeError {
    Wire(wire::Error),
    Execution(Error),
    Genesis,
    Credit,
    Invariant,
}
impl From<wire::Error> for BridgeError {
    fn from(e: wire::Error) -> Self {
        Self::Wire(e)
    }
}
impl From<Error> for BridgeError {
    fn from(e: Error) -> Self {
        Self::Execution(e)
    }
}
impl std::fmt::Display for BridgeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for BridgeError {}

pub fn rules_hash() -> [u8; 32] {
    batch::hash(
        b"tactus/o1/native-execution-rules/v2",
        &[
            include_bytes!("../rules-native-v2.txt").as_slice(),
            include_bytes!("../rules-v1.txt").as_slice(),
            include_bytes!("../../../Cargo.lock").as_slice(),
            include_bytes!("../../../contracts/bridge/NativeCKB.json").as_slice(),
        ]
        .concat(),
    )
}
/// Exact immutable DOMAIN used by the funded CKB vault program.
pub fn domain(c: &Config) -> B256 {
    let seed = keccak256(
        [
            b"TO1CKBD1".as_slice(),
            &c.ckb_genesis,
            &c.rollup,
            &c.identity,
        ]
        .concat(),
    );
    keccak256(
        [
            b"TO1BRDG1".as_slice(),
            seed.as_slice(),
            &U256::from(c.chain).to_be_bytes::<32>(),
            &c.contract,
        ]
        .concat(),
    )
}
pub fn runtime(c: &Config) -> Bytes {
    let artifact: serde_json::Value =
        serde_json::from_slice(include_bytes!("../../../contracts/bridge/NativeCKB.json"))
            .expect("pinned artifact");
    let deployed = &artifact["contract"]["evm"]["deployedBytecode"];
    let mut code = alloy_primitives::hex::decode(deployed["object"].as_str().unwrap()).unwrap();
    let refs = deployed["immutableReferences"].as_object().unwrap();
    assert_eq!(refs.len(), 1);
    for patch in refs.values().next().unwrap().as_array().unwrap() {
        assert_eq!(patch["length"], 32);
        let start = patch["start"].as_u64().unwrap() as usize;
        assert_eq!(&code[start..start + 32], &[0; 32]);
        code[start..start + 32].copy_from_slice(domain(c).as_slice());
    }
    code.into()
}
pub fn credit_calldata(c: &Config, r: &Record) -> Bytes {
    let mut input = keccak256(b"creditDeposit(bytes32,address,uint64)")[..4].to_vec();
    input.extend_from_slice(&c.deposit_id(r.sequence));
    input.extend_from_slice(&[0; 12]);
    input.extend_from_slice(&r.recipient);
    input.extend_from_slice(&U256::from(r.amount).to_be_bytes::<32>());
    input.into()
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DepositOutcome {
    pub record: Record,
    pub deposit_id: [u8; 32],
    pub gas_used: u64,
    pub logs: Vec<alloy_primitives::Log>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecutedBatch {
    pub deposits: Vec<DepositOutcome>,
    pub blocks: Vec<ExecutedBlock>,
}
#[derive(Clone, Debug)]
pub struct NativeExecutor {
    inner: Executor,
    config: Config,
    vault_code_hash: [u8; 32],
    cursor: Cursor,
}
impl NativeExecutor {
    pub fn new(
        genesis: &Genesis,
        config: Config,
        vault_code_hash: [u8; 32],
    ) -> Result<Self, BridgeError> {
        Config::decode(&config.encode())?;
        let address = Address::from(config.contract);
        // Zero has exclusive system-call authority. Shanghai precompiles cannot
        // host this contract. The bridge starts with absolutely no token storage.
        if vault_code_hash == [0; 32]
            || genesis.rollup_id.0 != config.rollup
            || genesis.chain_id != config.chain
            || genesis.accounts.contains_key(&Address::ZERO)
            || U256::from_be_slice(address.as_slice()) <= U256::from(9)
        {
            return Err(BridgeError::Genesis);
        }
        let bridge = genesis.accounts.get(&address).ok_or(BridgeError::Genesis)?;
        if bridge.code != runtime(&config)
            || bridge.nonce != 1
            || !bridge.balance.is_zero()
            || !bridge.storage.is_empty()
        {
            return Err(BridgeError::Genesis);
        }
        let mut inner = Executor::new(genesis)?;
        inner.anchor.execution_rules_hash = rules_hash();
        inner.head.extra_data = batch::hash(
            b"tactus/o1/native-genesis/v2",
            &[
                inner.anchor.encode().as_slice(),
                config.vault_script(vault_code_hash).as_slice(),
            ]
            .concat(),
        )
        .to_vec()
        .into();
        inner
            .db
            .cache
            .block_hashes
            .insert(U256::ZERO, inner.head.hash_slow());
        let cursor = Cursor::genesis(&config);
        Ok(Self {
            inner,
            config,
            vault_code_hash,
            cursor,
        })
    }
    pub fn anchor(&self) -> Anchor {
        Anchor {
            ordering: *self.inner.anchor(),
            deposits: self.cursor,
        }
    }
    pub fn head(&self) -> &Header {
        self.inner.head()
    }
    pub fn state_root(&self) -> B256 {
        self.inner.state_root()
    }
    pub fn account(&self, address: Address) -> Option<GenesisAccount> {
        self.inner.account(address)
    }
    pub fn vault_type_hash(&self) -> [u8; 32] {
        batch::hash(b"", &self.config.vault_script(self.vault_code_hash))
    }
    pub fn config(&self) -> &Config {
        &self.config
    }
    fn invariant(&self) -> Result<(), BridgeError> {
        let a = self
            .account(Address::from(self.config.contract))
            .ok_or(BridgeError::Invariant)?;
        let slot = |i: u64| a.storage.get(&U256::from(i)).copied().unwrap_or_default();
        if a.code != runtime(&self.config)
            || a.nonce != 1
            || slot(1) != U256::from(self.cursor.cumulative)
            || slot(0).checked_add(slot(2)) != Some(slot(1))
            || slot(0) > U256::from(u64::MAX)
            || self
                .account(Address::ZERO)
                .is_some_and(|a| a.nonce != 0 || !a.code.is_empty() || !a.storage.is_empty())
        {
            return Err(BridgeError::Invariant);
        }
        Ok(())
    }
    /// Deposits execute before the first user block; the entire wrapper is atomic.
    /// This does not fetch CKB data: its caller must authenticate the transcript.
    pub fn apply_batch(&mut self, bytes: &[u8]) -> Result<ExecutedBatch, BridgeError> {
        self.invariant()?;
        if self.inner.anchor.execution_rules_hash != rules_hash() {
            return Err(BridgeError::Invariant);
        }
        let (input, next) = Batch::decode(bytes, &self.config, &self.anchor())?;
        let mut candidate = self.clone();
        let mut deposits = Vec::with_capacity(input.deposits.len());
        let first = &input.users.blocks[0];
        let env = BlockEnv {
            number: U256::from(
                candidate
                    .inner
                    .head
                    .number
                    .checked_add(1)
                    .ok_or(Error::Arithmetic)?,
            ),
            beneficiary: Address::from(first.fee_recipient),
            timestamp: U256::from(first.timestamp),
            gas_limit: BLOCK_GAS_LIMIT,
            basefee: next_base_fee(
                candidate.inner.head.base_fee_per_gas.ok_or(Error::Rules)?,
                candidate.inner.head.gas_used,
            )?,
            difficulty: U256::ZERO,
            prevrandao: Some(B256::ZERO),
            blob_excess_gas_and_price: None,
            slot_num: 0,
        };
        for record in input.deposits {
            let result = Context::mainnet()
                .modify_cfg_chained(|cfg| {
                    cfg.set_spec_and_mainnet_gas_params(SpecId::SHANGHAI);
                    cfg.chain_id = candidate.config.chain;
                })
                .with_db(&mut candidate.inner.db)
                .with_block(env.clone())
                .build_mainnet()
                .system_call_with_caller(
                    Address::ZERO,
                    Address::from(candidate.config.contract),
                    credit_calldata(&candidate.config, &record),
                )
                .map_err(|e| BridgeError::Execution(Error::Engine(e.to_string())))?;
            if !result.result.is_success() || result.result.tx_gas_used() > MAX_CREDIT_GAS {
                return Err(BridgeError::Credit);
            }
            deposits.push(DepositOutcome {
                deposit_id: candidate.config.deposit_id(record.sequence),
                record,
                gas_used: result.result.tx_gas_used(),
                logs: result.result.logs().to_vec(),
            });
            candidate.inner.db.commit(result.state);
        }
        candidate.cursor = next.deposits;
        // v2 deliberately has its own block driver; changing it must not silently
        // change the already-proved v1 executable. Transaction decoding, fee
        // arithmetic and trie construction use the pinned common primitives.
        let working = &mut candidate.inner;
        let mut blocks = Vec::with_capacity(input.users.blocks.len());
        for block in input.users.blocks {
            let number = working
                .head
                .number
                .checked_add(1)
                .ok_or(Error::Arithmetic)?;
            let basefee = next_base_fee(
                working.head.base_fee_per_gas.ok_or(Error::Rules)?,
                working.head.gas_used,
            )?;
            let env = BlockEnv {
                number: U256::from(number),
                beneficiary: Address::from(block.fee_recipient),
                timestamp: U256::from(block.timestamp),
                gas_limit: BLOCK_GAS_LIMIT,
                basefee,
                difficulty: U256::ZERO,
                prevrandao: Some(B256::ZERO),
                blob_excess_gas_and_price: None,
                slot_num: 0,
            };
            let mut gas_used = 0;
            let mut outcomes = Vec::with_capacity(block.transactions.len());
            let mut transactions = Vec::new();
            let mut receipts = Vec::new();
            let mut bloom = Bloom::ZERO;
            for raw in block.transactions {
                let mut outcome = SlotOutcome {
                    input_hash: keccak256(&raw),
                    status: Status::Malformed,
                    gas_used: 0,
                    output: Bytes::new(),
                    created_address: None,
                    transaction_index: None,
                };
                let (envelope, tx) = match decode_transaction(
                    &raw,
                    working.anchor.chain_id,
                    BLOCK_GAS_LIMIT - gas_used,
                ) {
                    Ok(value) => value,
                    Err(status) => {
                        outcome.status = status;
                        outcomes.push(outcome);
                        continue;
                    }
                };
                if tx.caller == Address::ZERO {
                    outcome.status = Status::InvalidSignature;
                    outcomes.push(outcome);
                    continue;
                }
                // Fresh journal per slot: a rejected transaction cannot poison
                // the next slot, and no state is committed on validation failure.
                let result = Context::mainnet()
                    .modify_cfg_chained(|cfg| {
                        cfg.set_spec_and_mainnet_gas_params(SpecId::SHANGHAI);
                        cfg.chain_id = working.anchor.chain_id;
                    })
                    .with_db(&mut working.db)
                    .with_block(env.clone())
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
                // REVERT/HALT logs must not appear in Ethereum receipts.
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
            let outcome_root = outcomes_commitment(
                &working.anchor,
                next.ordering.last_batch_commitment,
                number,
                &outcomes,
            );
            let header = Header {
                parent_hash: working.head.hash_slow(),
                beneficiary: env.beneficiary,
                state_root: state_root(&working.db),
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
                base_fee_per_gas: Some(basefee),
                withdrawals_root: Some(EMPTY_ROOT_HASH),
                extra_data: batch::hash(
                    b"tactus/o1/native-block/v2",
                    &[
                        outcome_root.as_slice(),
                        next.deposits.encode().as_slice(),
                        candidate
                            .config
                            .vault_script(candidate.vault_code_hash)
                            .as_slice(),
                    ]
                    .concat(),
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
            blocks.push(ExecutedBlock {
                header,
                hash,
                outcomes,
                transactions,
                receipts,
            });
        }
        working.anchor = next.ordering;
        candidate.invariant()?;
        *self = candidate;
        Ok(ExecutedBatch { deposits, blocks })
    }
}
