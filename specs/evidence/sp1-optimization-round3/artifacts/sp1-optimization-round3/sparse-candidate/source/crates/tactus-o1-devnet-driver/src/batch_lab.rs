//! Devnet-only helpers for publishing bounded multi-block inputs.
use crate::{
    lab::{self, Lab},
    molecule,
    tx::{self, CellOutPoint, OutSpec, TX_FEE},
};
use serde_json::Value;
use tactus_o1_ordering_script::{ckb_blake2b, genesis_identity};
use tactus_o1_protocol::batch::{self, AnchorState, BatchInput, BlockInput};
#[derive(Clone)]
pub struct Anchor {
    pub point: CellOutPoint,
    pub capacity: u64,
    pub state: AnchorState,
    pub lock: Vec<u8>,
    pub script: Vec<u8>,
    pub immutable: Vec<u8>,
}
pub fn head_output(anchor: &Anchor, state: AnchorState) -> OutSpec {
    OutSpec {
        capacity: anchor.capacity,
        lock: anchor.lock.clone(),
        type_script: Some(anchor.script.clone()),
        data: state.encode().to_vec(),
    }
}
pub fn da_output(anchor: &Anchor, bytes: &[u8]) -> OutSpec {
    OutSpec {
        capacity: OutSpec::required_capacity(&anchor.immutable, None, bytes.len()),
        lock: anchor.immutable.clone(),
        type_script: None,
        data: bytes.to_vec(),
    }
}
pub fn shape(
    lab: &Lab,
    anchor: &Anchor,
    actor: usize,
    mut outputs: Vec<OutSpec>,
    witness: Option<&[u8]>,
) -> Result<Value, String> {
    let wallet = &lab.wallets[actor];
    let spent: u64 = outputs.iter().map(|o| o.capacity).sum();
    let change = wallet
        .capacity
        .checked_add(anchor.capacity)
        .and_then(|c| c.checked_sub(spent + TX_FEE))
        .ok_or("insufficient capacity")?;
    outputs.push(OutSpec {
        capacity: change,
        lock: wallet.key.lock_script(),
        type_script: None,
        data: vec![],
    });
    tx::build_with_permissionless_prefix(
        &wallet.key,
        &lab.secp,
        &lab.deps,
        &[
            (anchor.point, anchor.capacity),
            (wallet.point, wallet.capacity),
        ],
        &outputs,
        witness,
        1,
    )
    .map(|(_, v)| v)
}
pub fn create(lab: &mut Lab, rules_hash: [u8; 32], chain_id: u64) -> Result<Anchor, String> {
    let bytes = tactus_o1_protocol::genesis::Allocation::default()
        .encode()
        .unwrap();
    create_with_allocation(lab, rules_hash, chain_id, &bytes)
}
pub fn create_with_allocation(
    lab: &mut Lab,
    rules_hash: [u8; 32],
    chain_id: u64,
    allocation: &[u8],
) -> Result<Anchor, String> {
    let wallet = &lab.wallets[0];
    let seed: [u8; 44] = molecule::cell_input(
        0,
        &molecule::out_point(&wallet.point.tx_hash, wallet.point.index),
    )
    .try_into()
    .unwrap();
    let id = genesis_identity(&seed, 0);
    let script = tx::anchor_type_script(&lab.ordering_elf, &id, allocation)?;
    let lock = molecule::script(&ckb_blake2b(&lab.lock_elf), 2, &ckb_blake2b(&script));
    let immutable = molecule::script(&ckb_blake2b(&lab.ordering_elf), 2, &[]);
    let state = AnchorState::genesis(id, rules_hash, chain_id).map_err(|e| format!("{e:?}"))?;
    let capacity =
        OutSpec::required_capacity(&lock, Some(&script), batch::ANCHOR_LEN) + 10 * TX_FEE;
    let allocation_capacity = OutSpec::required_capacity(&immutable, None, allocation.len());
    let change = wallet
        .capacity
        .checked_sub(capacity + allocation_capacity + TX_FEE)
        .ok_or("insufficient genesis capacity")?;
    let anchor = Anchor {
        point: wallet.point,
        capacity,
        state,
        lock,
        script,
        immutable,
    };
    let outputs = vec![
        head_output(&anchor, state),
        da_output(&anchor, allocation),
        OutSpec {
            capacity: change,
            lock: wallet.key.lock_script(),
            type_script: None,
            data: vec![],
        },
    ];
    let (_, transaction) = tx::build_and_sign(
        &wallet.key,
        &lab.secp,
        &lab.deps,
        &[(wallet.point, wallet.capacity)],
        &outputs,
        None,
    )?;
    let hash = lab.commit("batch/genesis", &transaction)?;
    lab.wallets[0].point = lab::point(&hash, 2)?;
    lab.wallets[0].capacity = change;
    Ok(Anchor {
        point: lab::point(&hash, 0)?,
        ..anchor
    })
}
pub fn block(timestamp: u64, transactions: Vec<Vec<u8>>) -> BlockInput {
    BlockInput {
        timestamp,
        fee_recipient: [3; 20],
        transactions,
    }
}
pub fn encode(parent: AnchorState, blocks: Vec<BlockInput>) -> Result<Vec<u8>, String> {
    BatchInput { parent, blocks }
        .encode()
        .map_err(|e| format!("{e:?}"))
}
pub fn publish(
    lab: &mut Lab,
    anchor: &mut Anchor,
    bytes: &[u8],
    actor: usize,
    label: &str,
) -> Result<CellOutPoint, String> {
    let summary = batch::validate_batch(bytes, &anchor.state).map_err(|e| format!("{e:?}"))?;
    let outputs = vec![head_output(anchor, summary.next), da_output(anchor, bytes)];
    let transaction = shape(lab, anchor, actor, outputs, Some(&1u32.to_le_bytes()))?;
    let hash = lab.commit(label, &transaction)?;
    lab.wallets[actor].point = lab::point(&hash, 2)?;
    lab.wallets[actor].capacity -=
        TX_FEE + OutSpec::required_capacity(&anchor.immutable, None, bytes.len());
    anchor.point = lab::point(&hash, 0)?;
    anchor.state = summary.next;
    lab::point(&hash, 1)
}
