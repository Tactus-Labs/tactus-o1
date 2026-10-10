//! Actual native bridge publications. No new proof or custody payout is claimed.
use alloy_consensus::{SignableTransaction, TxEip1559, TxEnvelope};
use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::{keccak256, Address, Bytes, TxKind, U256};
use k256::ecdsa::SigningKey;
use serde_json::{json, Value};
use tactus_o1_devnet_driver::{
    lab::{self, Lab},
    molecule, rpc,
    tx::{self, CellOutPoint, OutSpec, TX_FEE},
};
use tactus_o1_execution::{
    native_bridge::{self, NativeExecutor},
    Genesis, GenesisAccount,
};
use tactus_o1_native_anchor_script::{State, RULES, VAULT_CODE};
use tactus_o1_native_vault_script as vault;
use tactus_o1_protocol::{
    batch::{self, BatchInput, BlockInput},
    genesis,
    native_bridge::{Batch, Config, Record},
};
#[path = "support/settlement.rs"]
mod settlement;
use tactus_o1_native_settlement_script as native_settlement;
fn n(v: &Value) -> u64 {
    u64::from_str_radix(v.as_str().unwrap().trim_start_matches("0x"), 16).unwrap()
}
fn hx(b: &[u8]) -> String {
    rpc::bytes_to_hex(b)
}
fn typed(lock: Vec<u8>, script: Vec<u8>, data: Vec<u8>, capacity: Option<u64>) -> OutSpec {
    OutSpec {
        capacity: capacity
            .unwrap_or_else(|| OutSpec::required_capacity(&lock, Some(&script), data.len())),
        lock,
        type_script: Some(script),
        data,
    }
}
fn untyped(lock: Vec<u8>, data: Vec<u8>) -> OutSpec {
    OutSpec {
        capacity: OutSpec::required_capacity(&lock, None, data.len()),
        lock,
        type_script: None,
        data,
    }
}
fn build(
    lab: &Lab,
    actor: usize,
    prefix: &[(CellOutPoint, u64)],
    mut outputs: Vec<OutSpec>,
    deps: &[CellOutPoint],
    headers: &[[u8; 32]],
    pointer: Option<&[u8]>,
) -> Result<Value, String> {
    let w = &lab.wallets[actor];
    let mut inputs = prefix.to_vec();
    inputs.push((w.point, w.capacity));
    let total = inputs
        .iter()
        .try_fold(0u64, |a, (_, c)| a.checked_add(*c))
        .ok_or("input overflow")?;
    let used = outputs
        .iter()
        .try_fold(TX_FEE, |a, o| a.checked_add(o.capacity))
        .ok_or("output overflow")?;
    outputs.push(OutSpec {
        capacity: total.checked_sub(used).ok_or("funding")?,
        lock: w.key.lock_script(),
        type_script: None,
        data: vec![],
    });
    let mut all = lab.deps.clone();
    all.extend_from_slice(deps);
    tx::build_with_headers(
        &w.key,
        &lab.secp,
        &all,
        &inputs,
        &outputs,
        pointer,
        prefix.len(),
        headers,
    )
    .map(|(_, v)| v)
}
fn commit(lab: &mut Lab, actor: usize, label: &str, tx: &Value) -> Result<String, String> {
    let hash = lab.commit(label, tx)?;
    let i = tx["outputs"].as_array().unwrap().len() - 1;
    lab.wallets[actor].point = lab::point(&hash, i as u32)?;
    lab.wallets[actor].capacity = n(&tx["outputs"][i]["capacity"]);
    Ok(hash)
}
fn reject(lab: &mut Lab, label: &str, tx: &Value, code: i8) -> Result<(), String> {
    let reason = format!("error code {code}");
    let program = batch::hash(b"", &lab.ordering_elf);
    let sources: &[&str] = if code == 1 {
        &["Inputs[0].Lock"]
    } else {
        &["Inputs[0].Type", "Outputs[0].Type"]
    };
    match rpc::send_transaction_json(tx) {
        Err(e)
            if sources
                .iter()
                .any(|s| lab::rejection_matches_at(&e, &reason, &program, s)) =>
        {
            lab.evidence.push(json!({"label":label,"result":"rejected","expected_reason":reason,"error":e,"transaction":tx}));
            println!("{label}: rejected ({reason})");
            Ok(())
        }
        other => Err(format!(
            "{label}: expected native anchor error {code}, got {other:?}"
        )),
    }
}
struct Checkpoint {
    code: [u8; 32],
    script: Vec<u8>,
    lock: Vec<u8>,
}
impl Checkpoint {
    fn output(&self, data: Vec<u8>) -> OutSpec {
        typed(self.lock.clone(), self.script.clone(), data, None)
    }
    fn reject(
        &self,
        lab: &mut Lab,
        label: &str,
        tx: &Value,
        code: i8,
        source: &str,
    ) -> Result<(), String> {
        let reason = format!("error code {code}");
        match rpc::send_transaction_json(tx) {
            Err(e) if lab::rejection_matches_at(&e, &reason, &self.code, source) => {
                lab.evidence.push(json!({"label":format!("checkpoint/{label}"),"result":"rejected","expected_reason":reason,"error":e,"transaction":tx}));
                println!("checkpoint/{label}: rejected ({reason})");
                Ok(())
            }
            other => Err(format!(
                "checkpoint/{label}: expected own {source} error {code}, got {other:?}"
            )),
        }
    }
}
fn user(i: u8) -> Address {
    Address::from_public_key(
        SigningKey::from_bytes((&[0x21 + i; 32]).into())
            .unwrap()
            .verifying_key(),
    )
}
fn allocation(c: &Config) -> Genesis {
    let mut accounts = std::collections::BTreeMap::new();
    for i in 0..2 {
        accounts.insert(
            user(i),
            GenesisAccount {
                balance: U256::from(1_000_000_000_000_000_000u64),
                ..Default::default()
            },
        );
    }
    accounts.insert(
        c.contract.into(),
        GenesisAccount {
            nonce: 1,
            code: native_bridge::runtime(c),
            ..Default::default()
        },
    );
    Genesis {
        rollup_id: c.rollup.into(),
        chain_id: c.chain,
        accounts,
    }
}
fn burn(e: &NativeExecutor, i: u8, amount: u64, recipient: [u8; 32]) -> Vec<u8> {
    let mut data = keccak256(b"withdraw(uint64,bytes32)")[..4].to_vec();
    data.extend_from_slice(&U256::from(amount).to_be_bytes::<32>());
    data.extend_from_slice(&recipient);
    let tx = TxEip1559 {
        chain_id: e.config().chain,
        nonce: e.account(user(i)).unwrap().nonce,
        gas_limit: 950_000,
        max_fee_per_gas: 2_000_000_000,
        max_priority_fee_per_gas: 1_000_000_000,
        to: TxKind::Call(e.config().contract.into()),
        value: U256::ZERO,
        input: Bytes::from(data),
        ..Default::default()
    };
    let key = SigningKey::from_bytes((&[0x21 + i; 32]).into()).unwrap();
    let sig = key
        .sign_prehash_recoverable(tx.signature_hash().as_slice())
        .unwrap()
        .into();
    TxEnvelope::from(tx.into_signed(sig)).encoded_2718()
}
struct GenesisOutputs {
    outputs: Vec<OutSpec>,
    script: Vec<u8>,
    lock: Vec<u8>,
}
fn genesis_outputs(lab: &Lab, state: &State, g: &Genesis) -> Result<GenesisOutputs, String> {
    let alloc = g.allocation_bytes().map_err(|e| e.to_string())?;
    let commitment = genesis::commitment(&alloc).map_err(|e| format!("{e:?}"))?;
    let code = batch::hash(b"", &lab.ordering_elf);
    let script = molecule::script(
        &code,
        2,
        &[state.config.rollup.as_slice(), &commitment].concat(),
    );
    let anchor_lock = molecule::script(
        &batch::hash(b"", &lab.lock_elf),
        2,
        &batch::hash(b"", &script),
    );
    let vs = state.vault_script();
    let vl = molecule::script(
        &batch::hash(b"", &lab.lock_elf),
        2,
        &state.vault_type_hash(),
    );
    let reserve = OutSpec::required_capacity(&vl, Some(&vs), vault::STATE_BYTES);
    let cfg = vault::Config::decode(&state.config.encode()).unwrap();
    let v = vault::State::genesis(&cfg, reserve);
    Ok(GenesisOutputs {
        outputs: vec![
            typed(
                anchor_lock.clone(),
                script.clone(),
                state.encode().to_vec(),
                None,
            ),
            typed(vl, vs, v.encode().to_vec(), Some(reserve)),
            untyped(molecule::script(&code, 2, &[]), alloc),
        ],
        script,
        lock: anchor_lock,
    })
}
fn deposit(
    lab: &mut Lab,
    actor: usize,
    c: &Config,
    current: &vault::State,
    point: CellOutPoint,
    amount: u64,
    label: &str,
) -> Result<(vault::State, Record, CellOutPoint, CellOutPoint), String> {
    let cfg = vault::Config::decode(&c.encode()).unwrap();
    let (next, r) = current
        .deposit(&cfg, user(actor as u8).0 .0, amount)
        .map_err(|e| format!("deposit {e}"))?;
    let script = c.vault_script(VAULT_CODE);
    let hash = batch::hash(b"", &script);
    let lock = molecule::script(&batch::hash(b"", &lab.lock_elf), 2, &hash);
    let receipt = molecule::script(&VAULT_CODE, 2, &[b"TO1REC01".as_slice(), &hash].concat());
    let outputs = vec![
        typed(
            lock,
            script,
            next.encode().to_vec(),
            Some(next.capacity().unwrap()),
        ),
        typed(
            molecule::script(&VAULT_CODE, 2, &[]),
            receipt,
            r.encode().to_vec(),
            None,
        ),
    ];
    let tx = build(
        lab,
        actor,
        &[(point, current.capacity().unwrap())],
        outputs,
        &[],
        &[],
        None,
    )?;
    let hash = commit(lab, actor, label, &tx)?;
    Ok((
        next,
        Record::decode(&r.encode()).unwrap(),
        lab::point(&hash, 0)?,
        lab::point(&hash, 1)?,
    ))
}
fn publication_outputs(
    state: &State,
    script: &[u8],
    lock: &[u8],
    capacity: u64,
    bytes: Vec<u8>,
) -> Result<Vec<OutSpec>, String> {
    let (_, next) =
        Batch::decode(&bytes, &state.config, &state.anchor).map_err(|e| format!("batch {e:?}"))?;
    let output = State {
        config: state.config.clone(),
        anchor: next,
    };
    let code: &[u8] = &script[16..48];
    let immutable = molecule::script(code.try_into().unwrap(), 2, &[]);
    Ok(vec![
        typed(
            lock.to_vec(),
            script.to_vec(),
            output.encode().to_vec(),
            Some(capacity),
        ),
        untyped(immutable, bytes),
    ])
}
fn run() -> Result<(), String> {
    let path = std::env::var("TACTUS_EVIDENCE_PATH").map_err(|_| "isolated launcher required")?;
    let mut lab = Lab::connect_with_script("artifacts/tactus_o1_native_anchor_script.elf")?;
    let mut result = json!({"suite":"native-publication-v2","complete":false,"error":null,"production_ready":false,"proof_settled":false,"withdrawal_executed":false,"publications":[]});
    let settlement_mode =
        std::env::var("TACTUS_DEVNET_SUITE").as_deref() == Ok("replay-native-settlement");
    let checkpoint_mode = settlement_mode
        || std::env::var("TACTUS_DEVNET_SUITE").as_deref() == Ok("replay-native-checkpoint");
    if checkpoint_mode {
        result["suite"] = json!("native-checkpoint-v2");
        result["checkpoints"] = json!([]);
    }
    if settlement_mode {
        result["suite"] = json!("native-settlement-bootstrap-v2");
    }
    let outcome = (|| {
        let elf = std::fs::read("artifacts/tactus_o1_native_vault_script.elf")
            .map_err(|e| e.to_string())?;
        if batch::hash(b"", &elf) != VAULT_CODE || RULES != native_bridge::rules_hash() {
            return Err("pinned program/rules mismatch".into());
        }
        let immutable = molecule::script(&batch::hash(b"", &lab.lock_elf), 2, &[]);
        let tx = build(&lab, 0, &[], vec![untyped(immutable, elf)], &[], &[], None)?;
        let h = commit(&mut lab, 0, "native/deploy pinned vault", &tx)?;
        lab.deps.push(lab::point(&h, 0)?);
        let checkpoint_code = if checkpoint_mode {
            let elf = std::fs::read("artifacts/tactus_o1_native_checkpoint_script.elf")
                .map_err(|e| e.to_string())?;
            let code = batch::hash(b"", &elf);
            let o = untyped(
                molecule::script(&batch::hash(b"", &lab.lock_elf), 2, &[]),
                elf,
            );
            let tx = build(&lab, 0, &[], vec![o], &[], &[], None)?;
            let h = commit(&mut lab, 0, "checkpoint/deploy program", &tx)?;
            lab.deps.push(lab::point(&h, 0)?);
            Some(code)
        } else {
            None
        };
        let settlement_code = if settlement_mode {
            if checkpoint_code != Some(native_settlement::CHECKPOINT_CODE) {
                return Err("checkpoint program mismatch".into());
            }
            let elf = std::fs::read("artifacts/tactus_o1_native_settlement_script.elf")
                .map_err(|e| e.to_string())?;
            let code = batch::hash(b"", &elf);
            let tx = build(
                &lab,
                0,
                &[],
                vec![untyped(
                    molecule::script(&batch::hash(b"", &lab.lock_elf), 2, &[]),
                    elf,
                )],
                &[],
                &[],
                None,
            )?;
            let h = commit(&mut lab, 0, "settlement/deploy program", &tx)?;
            lab.deps.push(lab::point(&h, 0)?);
            Some(code)
        } else {
            None
        };
        let fund = lab.wallets[0].point;
        let input = molecule::cell_input(0, &molecule::out_point(&fund.tx_hash, fund.index));
        let ckb: [u8; 32] = rpc::decode_hex(
            rpc::call("get_block_hash", json!(["0x0"]))?
                .as_str()
                .ok_or("genesis")?,
        )?
        .try_into()
        .map_err(|_| "genesis hash")?;
        let mut c = Config {
            identity: batch::hash(b"", &[input.as_slice(), &1u64.to_le_bytes()].concat()),
            ckb_genesis: ckb,
            rollup: batch::hash(b"", &[input.as_slice(), &0u64.to_le_bytes()].concat()),
            chain: 31337,
            contract: [4; 20],
            settlement: [5; 32],
        };
        let settlement = settlement_code
            .map(|code| settlement::Settlement::new(&lab, &mut c, code))
            .transpose()?;
        let mut state = State::genesis(c.clone()).map_err(|e| format!("state {e}"))?;
        let g = allocation(&c);
        let GenesisOutputs {
            outputs: mut outs,
            script,
            lock,
        } = genesis_outputs(&lab, &state, &g)?;
        let initial_tip = native_settlement::Tip::initial(state.anchor.ordering.encode())
            .map_err(|e| format!("tip {e}"))?;
        if let Some(s) = &settlement {
            outs.push(s.output(&initial_tip));
        }
        let checkpoint = checkpoint_code.map(|code| {
            let checkpoint_script = molecule::script(
                &code,
                2,
                &[b"TO1NCP02".as_slice(), &batch::hash(b"", &script)].concat(),
            );
            Checkpoint {
                code,
                lock: molecule::script(
                    &batch::hash(b"", &lab.lock_elf),
                    2,
                    &batch::hash(b"", &checkpoint_script),
                ),
                script: checkpoint_script,
            }
        });
        let capacity = outs[0].capacity;
        for (mode, label, code) in [
            (0, "missing genesis header", 7),
            (1, "nonempty genesis cursor", 5),
            (2, "missing joint vault", 8),
            (3, "wrong chain genesis", 7),
            (4, "wrong anchor lock", 9),
            (5, "inflated anchor reserve", 9),
            (6, "old execution rules", 4),
            (7, "seeded bridge storage", 6),
            (8, "zero caller allocation", 6),
            (9, "wrong bridge runtime", 6),
            (10, "wrong singleton identity", 5),
        ] {
            let mut o = outs.clone();
            let mut headers = vec![ckb];
            match mode {
                0 => headers.clear(),
                1 => o[0].data[172 + 200] ^= 1,
                2 => o[1].type_script = None,
                3 => {
                    let mut bad = c.clone();
                    bad.ckb_genesis[0] ^= 1;
                    let badstate = State::genesis(bad.clone()).unwrap();
                    o = genesis_outputs(&lab, &badstate, &allocation(&bad))?.outputs;
                }
                4 => o[0].lock = lab.wallets[0].key.lock_script(),
                5 => o[0].capacity += 1,
                6 => o[0].data[172 + 96..172 + 128]
                    .copy_from_slice(&tactus_o1_execution::rules_hash()),
                7..=9 => {
                    let mut bad = g.clone();
                    match mode {
                        7 => {
                            bad.accounts
                                .get_mut(&Address::from(c.contract))
                                .unwrap()
                                .storage
                                .insert(U256::ZERO, U256::from(1));
                        }
                        8 => {
                            bad.accounts.insert(
                                Address::ZERO,
                                GenesisAccount {
                                    balance: U256::from(1),
                                    ..Default::default()
                                },
                            );
                        }
                        _ => {
                            bad.accounts
                                .get_mut(&Address::from(c.contract))
                                .unwrap()
                                .code = vec![0].into()
                        }
                    };
                    o = genesis_outputs(&lab, &state, &bad)?.outputs;
                }
                _ => {
                    let mut bad = c.clone();
                    bad.rollup[0] ^= 1;
                    let badstate = State::genesis(bad.clone()).unwrap();
                    o = genesis_outputs(&lab, &badstate, &allocation(&bad))?.outputs;
                }
            }
            let tx = build(&lab, 0, &[], o, &[], &headers, None)?;
            reject(&mut lab, &format!("native/{label}"), &tx, code)?;
        }
        if let Some(s) = &settlement {
            s.genesis_controls(&mut lab, &outs, ckb)?;
        }
        let tx = build(&lab, 0, &[], outs.clone(), &[], &[ckb], None)?;
        let h = commit(&mut lab, 0, "native/joint genesis", &tx)?;
        let tip_point = lab::point(&h, 3)?;
        let mut anchor_point = lab::point(&h, 0)?;
        let mut vault_point = lab::point(&h, 1)?;
        let mut custody = vault::State::decode(&outs[1].data).unwrap();
        result["config"] = json!(hx(&c.encode()));
        result["anchor_script"] = json!(hx(&script));
        result["genesis_allocation"] = json!(hx(&g.allocation_bytes().unwrap()));
        result["genesis_state"] = json!(hx(&state.encode()));
        result["genesis_transaction"] = json!(h);
        let allocation_point = lab::point(&h, 2)?;
        let allocation_capacity = outs[2].capacity;
        let mut engine =
            NativeExecutor::new(&g, c.clone(), VAULT_CODE).map_err(|e| e.to_string())?;
        let mut oracle_steps = vec![];
        let mut publication_cells = vec![];
        let genesis_header = engine.head().clone();
        for round in 0..2 {
            let (v, record, vp, rp) = deposit(
                &mut lab,
                round,
                &c,
                &custody,
                vault_point,
                (100 + 50 * round as u64) * 100_000_000,
                &format!("native/deposit actor {round}"),
            )?;
            custody = v;
            vault_point = vp;

            let recipient = batch::hash(b"", &lab.wallets[round].key.lock_script());
            let user_tx = burn(
                &engine,
                round as u8,
                (40 + 10 * round as u64) * 100_000_000,
                recipient,
            );
            let input = Batch {
                deposits: vec![record.clone()],
                users: BatchInput {
                    parent: state.anchor.ordering,
                    blocks: vec![BlockInput {
                        timestamp: round as u64 + 1,
                        fee_recipient: [0x22; 20],
                        transactions: vec![user_tx],
                    }],
                },
            };
            let bytes = input
                .encode(&c, &state.anchor)
                .map_err(|e| format!("encode {e:?}"))?;
            let mut outputs = publication_outputs(&state, &script, &lock, capacity, bytes.clone())?;
            if round == 0 {
                let fake = build(
                    &lab,
                    0,
                    &[],
                    vec![untyped(
                        molecule::script(&VAULT_CODE, 2, &[]),
                        record.encode().to_vec(),
                    )],
                    &[],
                    &[],
                    None,
                )?;
                let fake_hash = commit(&mut lab, 0, "native/untyped copied receipt data", &fake)?;
                let fake_point = lab::point(&fake_hash, 0)?;
                let foreign_fund = lab.wallets[0].point;
                let input = molecule::cell_input(
                    0,
                    &molecule::out_point(&foreign_fund.tx_hash, foreign_fund.index),
                );
                let mut foreign = c.clone();
                foreign.identity =
                    batch::hash(b"", &[input.as_slice(), &0u64.to_le_bytes()].concat());
                let fs = foreign.vault_script(VAULT_CODE);
                let fl =
                    molecule::script(&batch::hash(b"", &lab.lock_elf), 2, &batch::hash(b"", &fs));
                let reserve = OutSpec::required_capacity(&fl, Some(&fs), vault::STATE_BYTES);
                let fv = vault::State::genesis(
                    &vault::Config::decode(&foreign.encode()).unwrap(),
                    reserve,
                );
                let tx = build(
                    &lab,
                    0,
                    &[],
                    vec![typed(fl, fs, fv.encode().to_vec(), Some(reserve))],
                    &[],
                    &[],
                    None,
                )?;
                let fh = commit(&mut lab, 0, "native/foreign vault genesis", &tx)?;
                let (_, _, _, foreign_receipt) = deposit(
                    &mut lab,
                    0,
                    &foreign,
                    &fv,
                    lab::point(&fh, 0)?,
                    100_000_000,
                    "native/foreign funded receipt",
                )?;
                for (mode, label, code) in [
                    (0, "missing authenticated receipt", 14),
                    (1, "untyped copied receipt", 14),
                    (2, "cross vault receipt", 14),
                    (3, "forged amount with valid transcript", 14),
                    (4, "forged recipient with valid transcript", 14),
                    (5, "wrong successor cursor", 12),
                    (6, "mutable publication", 10),
                    (7, "metadata rewrite", 4),
                    (8, "truncated batch", 11),
                    (9, "wrong publication pointer", 10),
                    (10, "anchor capacity rewrite", 9),
                    (11, "anchor lock takeover", 9),
                    (12, "duplicate deposit", 11),
                ] {
                    let mut o = outputs.clone();
                    let mut deps = vec![rp];
                    let mut pointer = 1u32.to_le_bytes();
                    match mode {
                        0 => deps.clear(),
                        1 => deps = vec![fake_point],
                        2 => deps = vec![foreign_receipt],
                        3 | 4 => {
                            let mut bad = input_for_record(&state, &bytes)?;
                            if mode == 3 {
                                bad.deposits[0].amount += 1;
                            } else {
                                bad.deposits[0].recipient = user(1).0 .0;
                            }
                            let r = &mut bad.deposits[0];
                            r.cumulative = state.anchor.deposits.cumulative + u128::from(r.amount);
                            r.after = batch::hash(
                                b"tactus/o1/deposits/append/v1",
                                &[
                                    c.encode().as_slice(),
                                    &r.encode()[..76],
                                    &r.cumulative.to_le_bytes(),
                                ]
                                .concat(),
                            );
                            o = publication_outputs(
                                &state,
                                &script,
                                &lock,
                                capacity,
                                bad.encode(&c, &state.anchor).unwrap(),
                            )?;
                        }
                        5 => o[0].data[172 + 200] ^= 1,
                        6 => {
                            o[1].lock = lab.wallets[1].key.lock_script();
                            o[1].capacity =
                                OutSpec::required_capacity(&o[1].lock, None, o[1].data.len());
                        }
                        7 => o[0].data[8 + 132] ^= 1,
                        8 => {
                            o[1].data.pop();
                        }
                        9 => pointer = 99u32.to_le_bytes(),
                        10 => o[0].capacity += 1,
                        11 => o[0].lock = lab.wallets[1].key.lock_script(),
                        _ => {
                            let raw = record.encode();
                            o[1].data.splice(66 + 124..66 + 124, raw);
                            o[1].data[64..66].copy_from_slice(&2u16.to_le_bytes());
                            o[1].capacity =
                                OutSpec::required_capacity(&o[1].lock, None, o[1].data.len());
                        }
                    }
                    let tx = build(
                        &lab,
                        1,
                        &[(anchor_point, capacity)],
                        o,
                        &deps,
                        &[],
                        Some(&pointer),
                    )?;
                    reject(&mut lab, &format!("native/{label}"), &tx, code)?;
                }
            }
            if let Some(cp) = &checkpoint {
                let correct = cp.output(outputs[0].data.clone());
                if round == 0 {
                    let tx = build(
                        &lab,
                        0,
                        &[],
                        vec![correct.clone()],
                        &[anchor_point],
                        &[],
                        None,
                    )?;
                    cp.reject(&mut lab, "dependency alone", &tx, 4, "Outputs[0].Type")?;
                    for (mode, label, code) in [
                        (0, "previous state", 7),
                        (1, "forged cursor", 7),
                        (2, "changed custody config", 7),
                        (3, "wrong publication hash", 7),
                        (4, "truncated state", 5),
                        (5, "duplicate checkpoint", 2),
                        (6, "wrong anchor binding", 4),
                        (7, "wrong argument domain", 1),
                        (8, "zero anchor identity", 1),
                        (9, "old anchor wire", 5),
                    ] {
                        let mut candidate = correct.clone();
                        match mode {
                            0 => candidate.data = state.encode().to_vec(),
                            1 => candidate.data[372] ^= 1,
                            2 => candidate.data[140] ^= 1,
                            3 => candidate.data[220] ^= 1,
                            4 => {
                                candidate.data.pop();
                            }
                            6 => {
                                candidate.type_script = Some(molecule::script(
                                    &cp.code,
                                    2,
                                    &[b"TO1NCP02".as_slice(), &[9; 32]].concat(),
                                ))
                            }
                            7 => {
                                candidate.type_script = Some(molecule::script(
                                    &cp.code,
                                    2,
                                    &[b"TO1NCP01".as_slice(), &batch::hash(b"", &script)].concat(),
                                ))
                            }
                            8 => {
                                candidate.type_script = Some(molecule::script(
                                    &cp.code,
                                    2,
                                    &[b"TO1NCP02".as_slice(), &[0; 32]].concat(),
                                ))
                            }
                            9 => candidate.data = candidate.data[172..372].to_vec(),
                            _ => {}
                        }
                        let mut o = outputs.clone();
                        o.push(candidate);
                        if mode == 5 {
                            o.push(correct.clone());
                        }
                        let tx = build(
                            &lab,
                            1,
                            &[(anchor_point, capacity)],
                            o,
                            &[rp],
                            &[],
                            Some(&1u32.to_le_bytes()),
                        )?;
                        cp.reject(&mut lab, label, &tx, code, "Outputs[2].Type")?;
                    }
                }
                outputs.push(correct);
            }
            let publication_capacity = outputs[1].capacity;
            let tx = build(
                &lab,
                1 - round,
                &[(anchor_point, capacity)],
                outputs,
                &[rp],
                &[],
                Some(&1u32.to_le_bytes()),
            )?;
            let h = commit(
                &mut lab,
                1 - round,
                &format!("native/publish authenticated batch {round}"),
                &tx,
            )?;
            if let Some(cp) = &checkpoint {
                let cell = (lab::point(&h, 2)?, n(&tx["outputs"][2]["capacity"]));
                let data = rpc::decode_hex(tx["outputs_data"][2].as_str().unwrap())?;
                let out = cp.output(data.clone());
                let live = rpc::call("get_live_cell", json!([{"tx_hash":h,"index":"0x2"},true]))?;
                if live["status"] != "live" || live["cell"]["data"]["content"] != hx(&data) {
                    return Err("checkpoint not live".into());
                }
                result["checkpoints"]
                    .as_array_mut()
                    .unwrap()
                    .push(json!({"transaction":h,"index":2,"script":hx(&cp.script),"live":live}));
                for (label, o) in [
                    ("destroy checkpoint", vec![]),
                    ("consume and recreate", vec![out.clone()]),
                ] {
                    let bad = build(&lab, 0, &[cell], o, &[], &[], None)?;
                    cp.reject(
                        &mut lab,
                        &format!("{label} {round}"),
                        &bad,
                        2,
                        "Inputs[0].Type",
                    )?;
                }
                if round == 1 {
                    let p = &result["checkpoints"][0];
                    let old = lab::point(p["transaction"].as_str().unwrap(), 2)?;
                    let bad = build(&lab, 0, &[], vec![out], &[old], &[], None)?;
                    cp.reject(
                        &mut lab,
                        "historical checkpoint dependency",
                        &bad,
                        4,
                        "Outputs[0].Type",
                    )?;
                    let old_live = rpc::call(
                        "get_live_cell",
                        json!([{"tx_hash":hx(&old.tx_hash),"index":"0x2"},true]),
                    )?;
                    if old_live != p["live"] {
                        return Err("historical checkpoint changed".into());
                    }
                    result["historical_checkpoint_rechecked"] = json!(true);
                }
            }
            anchor_point = lab::point(&h, 0)?;
            publication_cells.push((lab::point(&h, 1)?, publication_capacity));
            let parent_header = engine.head().clone();
            let before = state.anchor;
            let executed = engine.apply_batch(&bytes).map_err(|e| e.to_string())?;
            let (_, next) = Batch::decode(&bytes, &c, &state.anchor).unwrap();
            state.anchor = next;
            if engine.anchor() != state.anchor
                || executed.blocks[0].outcomes[0].status != tactus_o1_execution::Status::Success
            {
                return Err("execution/publication divergence".into());
            }
            result["publications"].as_array_mut().unwrap().push(json!({"transaction":h,"batch":hx(&bytes),"state":hx(&state.encode()),"receipt":{"tx_hash":hx(&rp.tx_hash),"index":format!("0x{:x}",rp.index)},"record":hx(&record.encode()),"deposit_id":hx(&c.deposit_id(record.sequence)),"blocks":executed.blocks,"credit_gas":executed.deposits[0].gas_used}));
            oracle_steps.push(json!({"wrapper":hx(&bytes),"before":hx(&before.encode()),"after":hx(&state.anchor.encode()),"parent":parent_header,
                "deposits":executed.deposits.iter().map(|d|json!({"record":hx(&d.record.encode()),"deposit_id":hx(&d.deposit_id),"calldata":native_bridge::credit_calldata(&c,&d.record),"gas_used":d.gas_used,"logs":d.logs})).collect::<Vec<_>>(),
                "blocks":executed.blocks.iter().map(|b|json!({"header":b.header,"hash":b.hash,"outcomes":b.outcomes,"transactions":b.transactions,"receipts":b.receipts.iter().map(|r|hx(&r.encoded_2718())).collect::<Vec<_>>() })).collect::<Vec<_>>() }));
            if round == 0 {
                let empty = Batch {
                    deposits: vec![],
                    users: BatchInput {
                        parent: state.anchor.ordering,
                        blocks: vec![BlockInput {
                            timestamp: 2,
                            fee_recipient: [0x22; 20],
                            transactions: vec![],
                        }],
                    },
                }
                .encode(&c, &state.anchor)
                .unwrap();
                let mut output = publication_outputs(&state, &script, &lock, capacity, empty)?;
                output[1].data.splice(66..66, record.encode());
                output[1].data[64..66].copy_from_slice(&1u16.to_le_bytes());
                output[1].capacity =
                    OutSpec::required_capacity(&output[1].lock, None, output[1].data.len());
                let tx = build(
                    &lab,
                    0,
                    &[(anchor_point, capacity)],
                    output,
                    &[rp],
                    &[],
                    Some(&1u32.to_le_bytes()),
                )?;
                reject(&mut lab, "native/replay already published deposit", &tx, 11)?;
            }
            // Every published receipt remains live: it cannot be refunded later.
            let live = rpc::call(
                "get_live_cell",
                json!([{"tx_hash":hx(&rp.tx_hash),"index":format!("0x{:x}",rp.index)},true]),
            )?;
            if live["status"] != "live" {
                return Err("receipt not live".into());
            }
        }
        let live = rpc::call(
            "get_live_cell",
            json!([{"tx_hash":hx(&anchor_point.tx_hash),"index":format!("0x{:x}",anchor_point.index)},true]),
        )?;
        if live["status"] != "live" || live["cell"]["data"]["content"] != hx(&state.encode()) {
            return Err("final anchor mismatch".into());
        }
        for (label, cell) in [
            (
                "native/spend immutable allocation",
                (allocation_point, allocation_capacity),
            ),
            ("native/spend immutable publication", publication_cells[0]),
        ] {
            let tx = build(&lab, 0, &[cell], vec![], &[], &[], None)?;
            reject(&mut lab, label, &tx, 1)?;
        }
        result["final_anchor"] = live;
        result["final_custody_state"] = json!(hx(&custody.encode()));
        result["final_bridge_account"] = json!(engine.account(c.contract.into()).unwrap());
        result["final_root"] = json!(engine.state_root());
        result["final_header"] = json!(engine.head());
        let exe = std::env::current_exe().map_err(|e| e.to_string())?;
        let recovery = std::process::Command::new(
            exe.parent()
                .ok_or("exe directory")?
                .join("recover-native-vault"),
        )
        .args([hx(&c.ckb_genesis), hx(&c.vault_script(VAULT_CODE))])
        .env_remove("TACTUS_VAULT_CAPTURE")
        .env_remove("TACTUS_VAULT_MAX_BLOCKS")
        .env_remove("TACTUS_VAULT_MAX_DEPOSITS")
        .output()
        .map_err(|e| e.to_string())?;
        if !recovery.status.success() {
            return Err(format!(
                "cold vault recovery: {}",
                String::from_utf8_lossy(&recovery.stderr)
            ));
        }
        let recovered: Value =
            serde_json::from_slice(&recovery.stdout).map_err(|e| e.to_string())?;
        if recovered["state"] != hx(&custody.encode()) || recovered["deposit_count"] != 2 {
            return Err("cold custody differs".into());
        }
        result["cold_vault_recovery"] = recovered;
        if let Some(s) = &settlement {
            s.qualify(
                &mut lab,
                &mut result,
                &g,
                &c,
                tip_point,
                &initial_tip,
                anchor_point,
                &oracle_steps,
                &path,
            )?;
        }
        let oracle = json!({"config":hx(&c.encode()),"authenticated_publication":false,"proof_settled":false,"custody_release":false,"production_ready":false,
            "scope":"EVM oracle input from accepted CKB publications; oracle does not verify CKB consensus",
            "cases":[{"name":"actual-native-publication-v2","genesis":g,"genesis_header":genesis_header,"steps":oracle_steps}]});
        std::fs::write(
            std::path::Path::new(&path).with_file_name("execution.json"),
            serde_json::to_string_pretty(&oracle).unwrap() + "\n",
        )
        .map_err(|e| e.to_string())?;
        result["authenticated_publication"] = json!(true);
        result["complete"] = json!(true);
        Ok::<(), String>(())
    })();
    if let Err(e) = &outcome {
        result["error"] = json!(e);
    }
    lab.save(&path, result)?;
    outcome
}
fn input_for_record(state: &State, bytes: &[u8]) -> Result<Batch, String> {
    Batch::decode(bytes, &state.config, &state.anchor)
        .map(|(b, _)| b)
        .map_err(|e| format!("{e:?}"))
}
fn main() {
    if let Err(e) = run() {
        eprintln!("NATIVE PUBLICATION FAILED: {e}");
        std::process::exit(1)
    }
}
