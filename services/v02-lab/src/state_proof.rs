//! Locally constructed witnesses, checked against the live settled Control root.
use crate::{err, Result};
use alloy_primitives::{keccak256, Address, Bytes, B256, U256};
use alloy_trie::{
    proof::ProofRetainer, root::storage_root_unhashed, HashBuilder, Nibbles, TrieAccount,
    EMPTY_ROOT_HASH,
};
use std::collections::BTreeMap;
use tactus_o1_execution::GenesisAccount;
use tactus_o1_protocol::v02::{Control, Wire};
use tactus_o1_state_proof_script::{encode_proofs, verify, Claim};
use tactus_v02_script::claims::StateProof;

fn account_value(account: &GenesisAccount) -> TrieAccount {
    TrieAccount::new(
        account.nonce,
        account.balance,
        storage_root_unhashed(
            account
                .storage
                .iter()
                .map(|(k, v)| (B256::from(k.to_be_bytes::<32>()), *v)),
        ),
        keccak256(&account.code),
    )
}
fn trie(mut entries: Vec<(B256, Vec<u8>)>, target: B256) -> (B256, Vec<Bytes>) {
    entries.sort_unstable_by_key(|e| e.0);
    let path = Nibbles::unpack(target);
    let mut builder = HashBuilder::default().with_proof_retainer(ProofRetainer::new(vec![path]));
    for (key, value) in entries {
        builder.add_leaf(Nibbles::unpack(key), &value);
    }
    let root = builder.root();
    let nodes = if root == EMPTY_ROOT_HASH {
        vec![]
    } else {
        builder
            .take_proof_nodes()
            .matching_nodes_sorted(&path)
            .into_iter()
            .map(|(_, node)| node)
            .collect()
    };
    (root, nodes)
}
/// `accounts` must come from replay at the settled prefix. Root matching and the
/// same bounded verifier used on CKB reject mismatched state or oversized paths.
pub fn prove(
    accounts: &BTreeMap<Address, GenesisAccount>,
    control: &Control,
    address: Address,
    slot: B256,
) -> Result<StateProof> {
    control.validate().map_err(err)?;
    if !control.initialized {
        return Err("unsettled state".into());
    }
    let (root, account_nodes) = trie(
        accounts
            .iter()
            .map(|(a, v)| (keccak256(a), alloy_rlp::encode(account_value(v))))
            .collect(),
        keccak256(address),
    );
    if root.0 != control.state_root {
        return Err("claim state is not the settled root".into());
    }
    let value = accounts.get(&address);
    let account = value.map(account_value);
    let key = U256::from_be_bytes(slot.0);
    let (storage_root, storage_nodes) = match value {
        Some(v) => trie(
            v.storage
                .iter()
                .filter(|(_, v)| !v.is_zero())
                .map(|(k, v)| (keccak256(k.to_be_bytes::<32>()), alloy_rlp::encode(*v)))
                .collect(),
            keccak256(slot),
        ),
        None => (B256::ZERO, vec![]),
    };
    if storage_root
        != account
            .as_ref()
            .map(|a| a.storage_root)
            .unwrap_or(B256::ZERO)
    {
        return Err("storage root mismatch".into());
    }
    let claim = Claim {
        root,
        header: control.block_hash.into(),
        settled_batches: control.boundary.batches,
        address: address.into_array(),
        exists: value.is_some(),
        nonce: account.as_ref().map(|a| a.nonce).unwrap_or_default(),
        balance: account.as_ref().map(|a| a.balance).unwrap_or_default(),
        storage_root,
        code_hash: account.as_ref().map(|a| a.code_hash).unwrap_or(B256::ZERO),
        slot,
        value: value
            .and_then(|v| v.storage.get(&key))
            .copied()
            .unwrap_or_default(),
    };
    let proof = encode_proofs(&account_nodes, &storage_nodes).map_err(err)?;
    verify(&claim, &proof).map_err(err)?;
    Ok(StateProof { claim, proof })
}
