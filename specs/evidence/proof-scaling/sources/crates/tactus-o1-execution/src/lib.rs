//! Pinned serial execution. See specs/EXECUTION_V1.md for the rollup rules.
pub mod store;
use alloy_consensus::{
    transaction::SignerRecoverable, Header, Receipt, ReceiptEnvelope, Transaction, TxEnvelope,
};
use alloy_eips::eip2718::{Decodable2718, Encodable2718, Typed2718};
use alloy_primitives::{keccak256, Address, Bloom, Bytes, B256, U256};
use alloy_trie::{
    root::{ordered_trie_root_encoded, state_root_unhashed, storage_root_unhashed},
    TrieAccount, EMPTY_ROOT_HASH,
};
use revm::{
    context::{BlockEnv, TxEnv},
    context_interface::result::{EVMError, ExecutionResult},
    database::{AccountState, InMemoryDB},
    primitives::hardfork::SpecId,
    state::{AccountInfo, Bytecode},
    Context, DatabaseCommit, ExecuteEvm, MainBuilder, MainContext,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use tactus_o1_protocol::batch::{self, AnchorState, BatchInput, BLOCK_GAS_LIMIT};

/// Genesis is an explicit input. It must eventually be authenticated by settlement.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Genesis {
    pub rollup_id: B256,
    pub chain_id: u64,
    pub accounts: BTreeMap<Address, GenesisAccount>,
}

impl Genesis {
    pub fn allocation_bytes(&self) -> Result<Vec<u8>, Error> {
        use tactus_o1_protocol::genesis::{Account, Allocation};
        Allocation {
            accounts: self
                .accounts
                .iter()
                .map(|(address, a)| Account {
                    address: address.0 .0,
                    balance: a.balance.to_be_bytes(),
                    nonce: a.nonce,
                    code: a.code.to_vec(),
                    storage: a
                        .storage
                        .iter()
                        .filter(|(_, v)| !v.is_zero())
                        .map(|(k, v)| (k.to_be_bytes(), v.to_be_bytes()))
                        .collect(),
                })
                .collect(),
        }
        .encode()
        .map_err(|_| Error::Genesis)
    }
    pub fn from_allocation(rollup_id: B256, chain_id: u64, bytes: &[u8]) -> Result<Self, Error> {
        let allocation =
            tactus_o1_protocol::genesis::Allocation::decode(bytes).map_err(|_| Error::Genesis)?;
        let accounts = allocation
            .accounts
            .into_iter()
            .map(|a| {
                (
                    Address::from(a.address),
                    GenesisAccount {
                        balance: U256::from_be_bytes(a.balance),
                        nonce: a.nonce,
                        code: a.code.into(),
                        storage: a
                            .storage
                            .into_iter()
                            .map(|(k, v)| (U256::from_be_bytes(k), U256::from_be_bytes(v)))
                            .collect(),
                    },
                )
            })
            .collect();
        Ok(Self {
            rollup_id,
            chain_id,
            accounts,
        })
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GenesisAccount {
    pub balance: U256,
    pub nonce: u64,
    pub code: Bytes,
    pub storage: BTreeMap<U256, U256>,
}

/// Numeric discriminants are consensus bytes, not dependency error strings.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum Status {
    Malformed = 1,
    UnsupportedType = 2,
    InvalidSignature = 3,
    WrongChain = 4,
    BlockGas = 5,
    InvalidTransaction = 6,
    Success = 7,
    Revert = 8,
    Halt = 9,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlotOutcome {
    pub input_hash: B256,
    pub status: Status,
    pub gas_used: u64,
    pub output: Bytes,
    pub created_address: Option<Address>,
    /// Dense Ethereum index, absent for rejected input slots.
    pub transaction_index: Option<u32>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutedBlock {
    pub header: Header,
    pub hash: B256,
    pub outcomes: Vec<SlotOutcome>,
    pub transactions: Vec<Bytes>,
    pub receipts: Vec<ReceiptEnvelope>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    Batch(batch::Error),
    Rules,
    Genesis,
    Arithmetic,
    Engine(String),
}
impl From<batch::Error> for Error {
    fn from(value: batch::Error) -> Self {
        Self::Batch(value)
    }
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for Error {}

/// Changes to these bytes require a new execution domain and regression vectors.
pub fn rules_hash() -> [u8; 32] {
    let mut descriptor = include_bytes!("../rules-v1.txt").to_vec();
    descriptor.extend_from_slice(include_bytes!("../../../Cargo.lock"));
    batch::hash(b"tactus/o1/execution-rules/v1", &descriptor)
}

#[derive(Clone, Debug)]
pub struct Executor {
    db: InMemoryDB,
    anchor: AnchorState,
    head: Header,
}

impl Executor {
    pub fn new(genesis: &Genesis) -> Result<Self, Error> {
        genesis.allocation_bytes()?;
        let anchor = AnchorState::genesis(genesis.rollup_id.0, rules_hash(), genesis.chain_id)?;
        let mut db = InMemoryDB::default();
        // With no issuance, this supply bound keeps all reachable base fees in
        // u64. It is explicit in the experimental rules, not silent saturation.
        let mut supply = U256::ZERO;
        for (address, account) in &genesis.accounts {
            supply = supply.checked_add(account.balance).ok_or(Error::Genesis)?;
            if supply > U256::from(u64::MAX)
                || (account.balance.is_zero() && account.nonce == 0 && account.code.is_empty())
            {
                return Err(Error::Genesis);
            }
            let code = Bytecode::new_legacy(account.code.clone());
            db.insert_account_info(
                *address,
                AccountInfo::new(account.balance, account.nonce, code.hash_slow(), code),
            );
            for (key, value) in &account.storage {
                if !value.is_zero() {
                    db.insert_account_storage(*address, *key, *value)
                        .expect("infallible memory database");
                }
            }
        }
        let mut domain = Vec::new();
        domain.extend_from_slice(&anchor.rollup_id);
        domain.extend_from_slice(&anchor.chain_id.to_le_bytes());
        domain.extend_from_slice(&anchor.execution_rules_hash);
        let head = Header {
            state_root: state_root(&db),
            gas_limit: BLOCK_GAS_LIMIT,
            base_fee_per_gas: Some(1_000_000_000),
            withdrawals_root: Some(EMPTY_ROOT_HASH),
            extra_data: batch::hash(b"tactus/o1/genesis/v1", &domain)
                .to_vec()
                .into(),
            ..Default::default()
        };
        db.cache.block_hashes.insert(U256::ZERO, head.hash_slow());
        Ok(Self { db, anchor, head })
    }

    pub fn anchor(&self) -> &AnchorState {
        &self.anchor
    }
    pub fn head(&self) -> &Header {
        &self.head
    }
    pub fn state_root(&self) -> B256 {
        state_root(&self.db)
    }
    pub fn account(&self, address: Address) -> Option<GenesisAccount> {
        let account = self.db.cache.accounts.get(&address)?;
        if account.account_state == AccountState::NotExisting || account.info.is_empty() {
            return None;
        }
        Some(GenesisAccount {
            balance: account.info.balance,
            nonce: account.info.nonce,
            code: self
                .db
                .cache
                .contracts
                .get(&account.info.code_hash)?
                .original_bytes(),
            storage: account
                .storage
                .iter()
                .filter(|(_, v)| !v.is_zero())
                .map(|(k, v)| (*k, *v))
                .collect(),
        })
    }

    /// Whole-batch atomicity: invalid bytes and fatal engine errors never leave
    /// partial state. Invalid *transaction slots* instead have total outcomes.
    pub fn apply_batch(&mut self, bytes: &[u8]) -> Result<Vec<ExecutedBlock>, Error> {
        if self.anchor.execution_rules_hash != rules_hash() {
            return Err(Error::Rules);
        }
        let summary = batch::validate_batch(bytes, &self.anchor)?;
        let input = BatchInput::decode(bytes, &self.anchor)?;
        let mut working = self.clone();
        let mut blocks = Vec::with_capacity(input.blocks.len());
        for block in input.blocks {
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
                    Err(error) => return Err(Error::Engine(error.to_string())),
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
                summary.next.last_batch_commitment,
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
                extra_data: outcome_root.to_vec().into(),
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
        working.anchor = summary.next;
        *self = working;
        Ok(blocks)
    }
}

fn decode_transaction(
    raw: &[u8],
    chain_id: u64,
    remaining_gas: u64,
) -> Result<(TxEnvelope, TxEnv), Status> {
    // Unknown and post-Shanghai typed envelopes are consistently unsupported,
    // even when their payload is also malformed.
    if raw.first().is_some_and(|tag| *tag < 0x80 && *tag > 2) {
        return Err(Status::UnsupportedType);
    }
    let envelope = TxEnvelope::decode_2718_exact(raw).map_err(|_| Status::Malformed)?;
    if envelope.encoded_2718() != raw {
        return Err(Status::Malformed);
    }
    if envelope.ty() > 2 {
        return Err(Status::UnsupportedType);
    }
    let caller = envelope
        .recover_signer()
        .map_err(|_| Status::InvalidSignature)?;
    if envelope.chain_id() != Some(chain_id) {
        return Err(Status::WrongChain);
    }
    if envelope.gas_limit() > remaining_gas {
        return Err(Status::BlockGas);
    }
    let tx = TxEnv {
        tx_type: envelope.ty(),
        caller,
        gas_limit: envelope.gas_limit(),
        gas_price: envelope.max_fee_per_gas(),
        kind: envelope.kind(),
        value: envelope.value(),
        data: envelope.input().clone(),
        nonce: envelope.nonce(),
        chain_id: envelope.chain_id(),
        access_list: envelope.access_list().cloned().unwrap_or_default(),
        gas_priority_fee: envelope.max_priority_fee_per_gas(),
        ..Default::default()
    };
    Ok((envelope, tx))
}

fn state_root(db: &InMemoryDB) -> B256 {
    state_root_unhashed(db.cache.accounts.iter().filter_map(|(address, account)| {
        if account.account_state == AccountState::NotExisting || account.info.is_empty() {
            return None;
        }
        let storage = storage_root_unhashed(
            account
                .storage
                .iter()
                .filter(|(_, value)| !value.is_zero())
                .map(|(key, value)| (B256::from(key.to_be_bytes::<32>()), *value)),
        );
        Some((
            *address,
            TrieAccount::new(
                account.info.nonce,
                account.info.balance,
                storage,
                account.info.code_hash,
            ),
        ))
    }))
}

/// EIP-1559 with checked intermediates. Supply conservation and the genesis
/// bound make an overflowing result unreachable by valid execution.
pub fn next_base_fee(parent_fee: u64, parent_gas: u64) -> Result<u64, Error> {
    let target = BLOCK_GAS_LIMIT / 2;
    if parent_gas > BLOCK_GAS_LIMIT {
        return Err(Error::Arithmetic);
    }
    let change =
        u128::from(parent_fee) * u128::from(parent_gas.abs_diff(target)) / u128::from(target) / 8;
    if parent_gas > target {
        let fee = u128::from(parent_fee) + change.max(1);
        u64::try_from(fee).map_err(|_| Error::Arithmetic)
    } else {
        Ok(parent_fee - change as u64)
    }
}

fn outcomes_commitment(
    anchor: &AnchorState,
    batch_hash: [u8; 32],
    number: u64,
    outcomes: &[SlotOutcome],
) -> [u8; 32] {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&anchor.rollup_id);
    bytes.extend_from_slice(&anchor.execution_rules_hash);
    bytes.extend_from_slice(&anchor.chain_id.to_le_bytes());
    bytes.extend_from_slice(&batch_hash);
    bytes.extend_from_slice(&number.to_le_bytes());
    bytes.extend_from_slice(&(outcomes.len() as u32).to_le_bytes());
    for outcome in outcomes {
        bytes.extend_from_slice(outcome.input_hash.as_slice());
        bytes.push(outcome.status as u8);
        bytes.extend_from_slice(&outcome.gas_used.to_le_bytes());
        bytes.extend_from_slice(&outcome.transaction_index.unwrap_or(u32::MAX).to_le_bytes());
        bytes.extend_from_slice(keccak256(&outcome.output).as_slice());
        bytes.push(u8::from(outcome.created_address.is_some()));
        bytes.extend_from_slice(outcome.created_address.unwrap_or_default().as_slice());
    }
    batch::hash(b"tactus/o1/slot-outcomes/v1", &bytes)
}

// Host-side witness construction must not add code to the pinned zkVM guest.
#[cfg(not(target_os = "zkvm"))]
impl Executor {
    /// Read the complete live state for independent trie construction and witnesses.
    /// This exposes no mutable execution state and uses the same account visibility
    /// rules as individual account queries.
    pub fn accounts(&self) -> impl Iterator<Item = (Address, GenesisAccount)> + '_ {
        self.db
            .cache
            .accounts
            .keys()
            .filter_map(|address| self.account(*address).map(|account| (*address, account)))
    }
}

/// Separate candidate execution domain for authenticated native deposits.
#[cfg(feature = "native-bridge")]
pub mod native_bridge;
