//! Read-only claim preparation. No keys, signatures or settled roots are invented.
use crate::{bytes, err, hash32, point_bytes, point_json, recover::Recovered, state_proof, Result};
use alloy_primitives::{keccak256, Address, B256, U256};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use tactus_o1_devnet_driver::rpc;
use tactus_o1_execution::GenesisAccount;
use tactus_o1_protocol::v02::*;
use tactus_v02_script::claims::{escape_digest, mapping_slot, ClaimWitness, Context, Request};

/// Caller supplies withdrawal receipt fields; the settled commitment authenticates
/// every field, so unknown IDs, altered owners and redirected payouts fail.
pub fn release_request(
    accounts: &BTreeMap<Address, GenesisAccount>,
    context: &Context<'_>,
    input: &Value,
) -> Result<Request> {
    let id = decimal(&input["id"])?;
    let amount = decimal(&input["amount_shannons"])?;
    let owner = address(&input["owner"])?;
    let recipient = hash32(&input["recipient_lock_hash"])?;
    Ok(Request::Release {
        id,
        amount,
        owner,
        recipient,
        bridge: state_proof::prove(
            accounts,
            context.control,
            context.config.bridge.into(),
            mapping_slot(U256::from(id).to_be_bytes::<32>(), 7),
        )?,
    })
}
/// An unsigned request carries a zero signature only internally. It is never
/// exported as a transaction witness; signed exports must pass full authorization.
pub fn escape_request(
    accounts: &BTreeMap<Address, GenesisAccount>,
    context: &Context<'_>,
    input: &Value,
) -> Result<Request> {
    if context.control.mode != Mode::Frozen {
        return Err("escape requires frozen Control".into());
    }
    let owner = address(&input["owner"])?;
    let recipient = hash32(&input["recipient_lock_hash"])?;
    if owner == [0; 20] || recipient == [0; 32] {
        return Err("zero claim identity".into());
    }
    let mut word = [0; 32];
    word[12..].copy_from_slice(&owner);
    let bridge = state_proof::prove(
        accounts,
        context.control,
        context.config.bridge.into(),
        mapping_slot(word, 3),
    )?;
    if !bridge.claim.exists
        || bridge.claim.nonce != 1
        || bridge.claim.code_hash.0 != context.policy.bridge_code_hash
    {
        return Err("unexpected bridge account".into());
    }
    let amount = u64::try_from(bridge.claim.value).map_err(err)?;
    if amount == 0 {
        return Err("no settled wCKB balance".into());
    }
    let account = state_proof::prove(accounts, context.control, owner.into(), B256::ZERO)?;
    if account.claim.exists && account.claim.code_hash != keccak256([]) {
        return Err("contract account escape unsupported".into());
    }
    let signature = match input.get("signature_hex") {
        None => [0; 65],
        Some(v) => bytes(v, 65)?
            .try_into()
            .map_err(|_| "signature must contain 65 bytes")?,
    };
    Ok(Request::Escape {
        owner,
        amount,
        recipient,
        signature,
        bridge,
        account: Box::new(account),
    })
}
fn decimal(value: &Value) -> Result<u64> {
    let text = value
        .as_str()
        .ok_or("amounts and IDs must be decimal strings")?;
    if text.is_empty() || !text.bytes().all(|v| v.is_ascii_digit()) {
        return Err("invalid decimal integer".into());
    }
    text.parse().map_err(err)
}
fn address(value: &Value) -> Result<[u8; 20]> {
    bytes(value, 20)?
        .try_into()
        .map_err(|_| "owner must contain 20 bytes".into())
}
impl Recovered {
    pub fn asset_claim(&self, mode: &str, input: &Value) -> Result<Value> {
        let engine = self.settled_execution()?;
        let accounts = engine.accounts().collect();
        let control = self.cell(Role::Control, 0)?;
        let vault = self.cell(Role::Vault, 0)?;
        let context = Context {
            config: &self.manifest.config,
            policy: &self.manifest.policy,
            control: &self.control,
            control_outpoint: point_bytes(control.point),
            vault: &self.vault,
            receipt: None,
        };
        let request = match mode {
            "release" => release_request(&accounts, &context, input)?,
            "escape" => escape_request(&accounts, &context, input)?,
            _ => return Err("unknown claim mode".into()),
        };
        let (index, identity) = match &request {
            Request::Release { id, .. } => (0, id.to_le_bytes().to_vec()),
            Request::Escape { owner, .. } => (2, owner.to_vec()),
            _ => unreachable!(),
        };
        let witness = ClaimWitness {
            payout: 1,
            control_outpoint: context.control_outpoint,
            nullifier: self.claims[index].proof(&identity, self.vault.claims[index])?,
            request,
        };
        if let Request::Escape {
            owner,
            amount,
            recipient,
            ..
        } = &witness.request
        {
            if input.get("signature_hex").is_none() {
                // Check custody availability before asking for a signature.
                let key = claim_key(&self.vault.config, ClaimKind::Escape, owner).map_err(err)?;
                let root = witness
                    .nullifier
                    .insert(
                        &self.vault.config,
                        ClaimKind::Escape,
                        &key,
                        &self.vault.claims[2],
                    )
                    .map_err(err)?;
                self.vault
                    .claim_accounting(&self.control, ClaimKind::Escape, *amount, root)
                    .map_err(err)?;
                let digest = escape_digest(
                    context.config,
                    context.control,
                    &context.control_outpoint,
                    owner,
                    *amount,
                    recipient,
                )
                .map_err(err)?;
                return Ok(
                    json!({"schema":"tactus-v02-escape-signing-request-v1", "pinned_hash":self.tip["hash"],
                    "control_outpoint":point_json(control.point),"vault_outpoint":point_json(vault.point),
                    "config_hex":rpc::bytes_to_hex(&context.config.encode().map_err(err)?),"control_hex":rpc::bytes_to_hex(&context.control.encode().map_err(err)?),
                    "owner":rpc::bytes_to_hex(owner),"amount_shannons":amount.to_string(),"recipient_lock_hash":rpc::bytes_to_hex(recipient),
                    "digest_hex":rpc::bytes_to_hex(&digest),"signature_format":"65 bytes: r || low-s || recovery id 0/1; EIP-712 digest, no personal_sign prefix",
                    "claim_witness_available":false,"phase":null,"readiness":"owner signature required","control_confirmation":self.control_confirmation()?,"transaction_submitted":false}),
                );
            }
        }
        let payout = witness.authorize(&context).map_err(err)?;
        Ok(
            json!({"schema":"tactus-v02-asset-claim-plan-v1","kind":mode,"pinned_hash":self.tip["hash"],
            "control_outpoint":point_json(control.point),"vault_outpoint":point_json(vault.point),
            "operation":if mode=="release" {Operation::Release as u8} else {Operation::Escape as u8},
            "claim_witness_hex":rpc::bytes_to_hex(&witness.encode().map_err(err)?),
            "next_vault_hex":rpc::bytes_to_hex(&payout.next.encode().map_err(err)?),"next_vault_capacity":payout.next.capacity().map_err(err)?.to_string(),
            "recipient_lock_hash":rpc::bytes_to_hex(&payout.lock),"principal_shannons":payout.amount.to_string(),"payout_index":1,
            "phase":"Withdrawable","control_confirmation":self.control_confirmation()?,"permanent_finality":false,
            "requires_recipient_lock_preimage":true,"external_capacity_topup_may_be_required":true,"transaction_submitted":false}),
        )
    }
}
