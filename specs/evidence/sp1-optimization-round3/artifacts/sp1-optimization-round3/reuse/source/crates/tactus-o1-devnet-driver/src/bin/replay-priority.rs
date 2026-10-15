//! Authentic individual A2 obligations. The challenge-only comparator is
//! expected to FAIL forced inclusion; recording that counterexample is success
//! for this experiment, never a production liveness claim.
use serde_json::{json, Value};
use tactus_o1_devnet_driver::{
    batch_lab::{self, block, encode, publish, Anchor},
    lab::{self, Lab},
    molecule, rpc,
    tx::{self, CellOutPoint, OutSpec, TX_FEE},
};
use tactus_o1_execution::{rules_hash, Executor, Genesis, Status};
use tactus_o1_ordering_script::{ckb_blake2b, genesis_identity};
use tactus_o1_protocol::{
    batch::{self, AnchorState, BatchInput},
    priority::{self as p, Message},
};

#[derive(Clone)]
struct Cell {
    point: CellOutPoint,
    capacity: u64,
    script: Vec<u8>,
    lock: Vec<u8>,
    message: Message,
}
impl Cell {
    fn output(&self, message: &Message) -> Result<OutSpec, String> {
        Ok(OutSpec {
            capacity: self.capacity,
            lock: self.lock.clone(),
            type_script: Some(self.script.clone()),
            data: message.encode().map_err(|e| format!("{e:?}"))?,
        })
    }
}

// Build and re-sign every negative control. Incorrect SECP signatures cannot
// stand in for the protocol error that the control is meant to exercise.
fn shape(
    lab: &Lab,
    actor: usize,
    prefix: &[(CellOutPoint, u64)],
    mut outputs: Vec<OutSpec>,
    witness: Option<&[u8]>,
    prefix_since: &[u64],
) -> Result<Value, String> {
    let wallet = &lab.wallets[actor];
    let spent: u64 = outputs.iter().map(|o| o.capacity).sum();
    let available = prefix.iter().try_fold(wallet.capacity, |n, (_, cap)| {
        n.checked_add(*cap).ok_or("capacity overflow")
    })?;
    let change = available.checked_sub(spent + TX_FEE).ok_or("capacity")?;
    outputs.push(OutSpec {
        capacity: change,
        lock: wallet.key.lock_script(),
        type_script: None,
        data: vec![],
    });
    let mut inputs = prefix.to_vec();
    inputs.push((wallet.point, wallet.capacity));
    let mut since = prefix_since.to_vec();
    since.push(0);
    tx::build_with_permissionless_prefix_and_since(
        &wallet.key,
        &lab.secp,
        &lab.deps,
        &inputs,
        &outputs,
        witness,
        prefix.len(),
        &since,
    )
    .map(|(_, v)| v)
}
fn commit(lab: &mut Lab, actor: usize, label: &str, transaction: &Value) -> Result<String, String> {
    let hash = lab.commit(label, transaction)?;
    let outputs = transaction["outputs"].as_array().ok_or("outputs")?;
    let change = outputs.last().ok_or("change")?;
    lab.wallets[actor].point = lab::point(&hash, (outputs.len() - 1) as u32)?;
    lab.wallets[actor].capacity = u64::from_str_radix(
        change["capacity"]
            .as_str()
            .ok_or("capacity")?
            .trim_start_matches("0x"),
        16,
    )
    .map_err(|e| e.to_string())?;
    Ok(hash)
}
fn reject(
    lab: &mut Lab,
    code: &[u8; 32],
    label: &str,
    transaction: &Value,
    location: &str,
    error_code: i8,
) -> Result<(), String> {
    let error = match rpc::send_transaction_json(transaction) {
        Err(error) => error,
        Ok(hash) => {
            return Err(format!(
                "{label}: negative transaction unexpectedly accepted: {hash}"
            ))
        }
    };
    let parsed: Value = error
        .strip_prefix("rpc error: ")
        .and_then(|s| serde_json::from_str(s).ok())
        .ok_or_else(|| format!("transport failure: {error}"))?;
    if parsed["code"] != -302
        || !location.split('|').any(|allowed| error.contains(allowed))
        || !error.contains(&format!("error code {error_code} on page "))
        || !error.contains(&rpc::bytes_to_hex(code)[2..])
    {
        return Err(format!(
            "{label}: expected {location} code {error_code}, got {error}"
        ));
    }
    lab.evidence.push(json!({"label":label,"result":"rejected","expected_script_location":location,"expected_error_code":error_code,"error":error,"transaction":transaction}));
    println!("{label}: rejected ({error_code})");
    Ok(())
}
fn assert_live(cell: CellOutPoint, expected: bool) -> Result<(), String> {
    let value = rpc::call(
        "get_live_cell",
        json!([{"tx_hash":rpc::bytes_to_hex(&cell.tx_hash),"index":format!("0x{:x}",cell.index)},false]),
    )?;
    if (value["status"] == "live") != expected {
        return Err(format!("cell liveness mismatch: {value}"));
    }
    Ok(())
}
fn admission(
    lab: &Lab,
    anchor: &Anchor,
    code: &[u8; 32],
    actor: usize,
    payloads: Vec<Vec<u8>>,
) -> Result<(Vec<Cell>, Value), String> {
    let wallet = &lab.wallets[actor];
    let seed: [u8; 44] = molecule::cell_input(
        0,
        &molecule::out_point(&wallet.point.tx_hash, wallet.point.index),
    )
    .try_into()
    .unwrap();
    let mut cells = Vec::new();
    let mut outputs = Vec::new();
    for (index, payload) in payloads.into_iter().enumerate() {
        let id = genesis_identity(&seed, index as u64);
        let mut args = vec![0];
        args.extend_from_slice(&id);
        let script = molecule::script(code, 2, &args);
        let mut args = vec![1];
        args.extend_from_slice(&ckb_blake2b(&script));
        let lock = molecule::script(code, 2, &args);
        let message = Message::admitted(
            id,
            anchor.state.rollup_id,
            ckb_blake2b(&anchor.script),
            payload,
        )
        .map_err(|e| format!("{e:?}"))?;
        let capacity =
            OutSpec::required_capacity(&lock, Some(&script), message.encode().unwrap().len())
                + TX_FEE;
        let cell = Cell {
            point: wallet.point,
            capacity,
            script,
            lock,
            message,
        };
        outputs.push(cell.output(&cell.message)?);
        cells.push(cell);
    }
    Ok((cells, shape(lab, actor, &[], outputs, None, &[])?))
}
fn admit(
    lab: &mut Lab,
    anchor: &Anchor,
    code: &[u8; 32],
    actor: usize,
    payloads: Vec<Vec<u8>>,
    label: &str,
) -> Result<Vec<Cell>, String> {
    let (mut cells, transaction) = admission(lab, anchor, code, actor, payloads)?;
    let hash = commit(lab, actor, label, &transaction)?;
    for (i, c) in cells.iter_mut().enumerate() {
        c.point = lab::point(&hash, i as u32)?;
    }
    Ok(cells)
}
fn challenge_tx(lab: &Lab, cell: &Cell, actor: usize, since: u64) -> Result<Value, String> {
    shape(
        lab,
        actor,
        &[(cell.point, cell.capacity)],
        vec![cell.output(&cell.message.challenge().map_err(|e| format!("{e:?}"))?)?],
        None,
        &[since],
    )
}
fn inclusion_outputs(
    anchor: &Anchor,
    cells: &[Cell],
    bytes: &[u8],
) -> Result<Vec<OutSpec>, String> {
    let summary = batch::validate_batch(bytes, &anchor.state).map_err(|e| format!("{e:?}"))?;
    let mut outputs = vec![
        batch_lab::head_output(anchor, summary.next),
        batch_lab::da_output(anchor, bytes),
    ];
    for (i, cell) in cells.iter().enumerate() {
        // min is only relevant to the deliberately over-limit 5-input control.
        let next = cell
            .message
            .include(
                &anchor.state,
                &summary.next,
                i.min(p::MAX_PRIORITY_INPUTS - 1),
            )
            .map_err(|e| format!("{e:?}"))?;
        outputs.push(cell.output(&next)?);
    }
    Ok(outputs)
}
fn inclusion_tx(
    lab: &Lab,
    anchor: &Anchor,
    cells: &[Cell],
    actor: usize,
    outputs: Vec<OutSpec>,
) -> Result<Value, String> {
    let mut inputs = vec![(anchor.point, anchor.capacity)];
    inputs.extend(cells.iter().map(|c| (c.point, c.capacity)));
    shape(
        lab,
        actor,
        &inputs,
        outputs,
        Some(&1u32.to_le_bytes()),
        &vec![0; inputs.len()],
    )
}
fn include(
    lab: &mut Lab,
    anchor: &mut Anchor,
    cells: &[Cell],
    actor: usize,
    label: &str,
) -> Result<(Vec<Cell>, Vec<u8>), String> {
    let bytes = encode(
        anchor.state,
        vec![block(
            anchor.state.last_timestamp + 1,
            cells.iter().map(|c| c.message.payload.clone()).collect(),
        )],
    )?;
    let outputs = inclusion_outputs(anchor, cells, &bytes)?;
    let transaction = inclusion_tx(lab, anchor, cells, actor, outputs)?;
    let hash = commit(lab, actor, label, &transaction)?;
    let input_burden: usize = cells
        .iter()
        .map(|cell| {
            44 + molecule::cell_output(cell.capacity, &cell.lock, Some(&cell.script)).len()
                + cell.message.encode().unwrap().len()
        })
        .sum();
    let witness_burden: usize = transaction["witnesses"]
        .as_array()
        .ok_or("witnesses")?
        .iter()
        .map(|w| rpc::decode_hex(w.as_str().unwrap()).map(|bytes| 8 + bytes.len()))
        .collect::<Result<Vec<_>, _>>()?
        .iter()
        .sum();
    if input_burden + witness_burden > p::MAX_PRIORITY_BYTES {
        return Err("accepted inclusion exceeded priority burden".into());
    }
    lab.evidence.push(json!({"label":format!("{label}/burden"),"result":"control_passed","transaction_hash":hash,"priority_inputs":cells.len(),"input_burden_bytes":input_burden,"witness_burden_bytes":witness_burden,"total_burden_bytes":input_burden+witness_burden}));
    let summary = batch::validate_batch(&bytes, &anchor.state).map_err(|e| format!("{e:?}"))?;
    let pending = cells
        .iter()
        .enumerate()
        .map(|(i, c)| {
            Ok(Cell {
                point: lab::point(&hash, (i + 2) as u32)?,
                message: c
                    .message
                    .include(&anchor.state, &summary.next, i)
                    .map_err(|e| format!("{e:?}"))?,
                ..c.clone()
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    anchor.point = lab::point(&hash, 0)?;
    anchor.state = summary.next;
    Ok((pending, bytes))
}
fn fixture() -> Result<(Genesis, Vec<u8>), String> {
    let value: Value = serde_json::from_str(include_str!(
        "../../../../specs/test-vectors/execution-v1/geth-1.17.8.json"
    ))
    .map_err(|e| e.to_string())?;
    let case = &value["cases"][0];
    let genesis: Genesis =
        serde_json::from_value(case["genesis"].clone()).map_err(|e| e.to_string())?;
    let rules = rpc::decode_hex(value["rules_hash"].as_str().ok_or("rules")?)?
        .try_into()
        .map_err(|_| "rules length")?;
    let parent = AnchorState::genesis(genesis.rollup_id.0, rules, genesis.chain_id)
        .map_err(|e| format!("{e:?}"))?;
    let batch = BatchInput::decode(
        &rpc::decode_hex(case["batch"].as_str().ok_or("batch")?)?,
        &parent,
    )
    .map_err(|e| format!("{e:?}"))?;
    Ok((genesis, batch.blocks[0].transactions[0].clone()))
}
fn run() -> Result<(), String> {
    let path = std::env::var("TACTUS_EVIDENCE_PATH").map_err(|_| "use isolated devnet launcher")?;
    let mut lab = Lab::connect_with_script("artifacts/tactus_o1_anchor_script.elf")?;
    let mut results = json!({"suite":"a2-authenticated-challenge-comparator-v1","complete":false,"production_ready":false,"forced_inclusion":"FAILED","G2":"OPEN","proof_settlement":"NOT_IMPLEMENTED"});
    let outcome = (|| {
        let elf =
            std::fs::read("artifacts/tactus_o1_priority_script.elf").map_err(|e| e.to_string())?;
        let code = ckb_blake2b(&elf);
        lab.metadata["priority_code_hash"] = json!(rpc::bytes_to_hex(&code));
        let dep = lab.publish_cells("priority/deploy immutable program", &[elf], 0, true)?[0];
        lab.deps.push(dep);
        let (mut genesis, payload) = fixture()?;
        let allocation = genesis.allocation_bytes().map_err(|e| e.to_string())?;
        let mut anchor =
            batch_lab::create_with_allocation(&mut lab, rules_hash(), 31337, &allocation)?;
        genesis.rollup_id = anchor.state.rollup_id.into();
        let mut engine = Executor::new(&genesis).map_err(|e| e.to_string())?;
        // Forged creation must fail before any authentic obligation exists.
        let (fresh, _) = admission(&lab, &anchor, &code, 0, vec![vec![2, 1, 2]])?;
        let bytes = encode(anchor.state, vec![block(1, vec![])])?;
        let next = batch::validate_batch(&bytes, &anchor.state).unwrap().next;
        let fake = fresh[0].message.include(&anchor.state, &next, 0).unwrap();
        let transaction = shape(&lab, 0, &[], vec![fresh[0].output(&fake)?], None, &[])?;
        reject(
            &mut lab,
            &code,
            "priority/cannot mint an included record",
            &transaction,
            "Outputs[0].Type",
            6,
        )?;
        let mut fake = fresh[0].clone();
        fake.message.id[0] ^= 1;
        let mut args = vec![0];
        args.extend_from_slice(&fake.message.id);
        fake.script = molecule::script(&code, 2, &args);
        let mut args = vec![1];
        args.extend_from_slice(&ckb_blake2b(&fake.script));
        fake.lock = molecule::script(&code, 2, &args);
        let transaction = shape(&lab, 0, &[], vec![fake.output(&fake.message)?], None, &[])?;
        reject(
            &mut lab,
            &code,
            "priority/cannot mint an arbitrary message identity",
            &transaction,
            "Outputs[0].Type",
            4,
        )?;
        let mut output = fresh[0].output(&fresh[0].message)?;
        output.data[8] = 3;
        let transaction = shape(&lab, 0, &[], vec![output], None, &[])?;
        reject(
            &mut lab,
            &code,
            "priority/no forged Proven stage",
            &transaction,
            "Outputs[0].Type",
            3,
        )?;
        let mut output = fresh[0].output(&fresh[0].message)?;
        output.data.truncate(p::FIXED_BYTES);
        output.data[187..191].copy_from_slice(&((p::MAX_PAYLOAD_BYTES + 1) as u32).to_le_bytes());
        output.data.extend(vec![0; p::MAX_PAYLOAD_BYTES + 1]);
        output.capacity = OutSpec::required_capacity(
            &output.lock,
            output.type_script.as_deref(),
            output.data.len(),
        );
        let transaction = shape(&lab, 0, &[], vec![output], None, &[])?;
        reject(
            &mut lab,
            &code,
            "priority/payload allocation is bounded",
            &transaction,
            "Outputs[0].Type",
            12,
        )?;
        let (_, transaction) = admission(&lab, &anchor, &code, 0, vec![vec![2, 1, 2]; 5])?;
        reject(
            &mut lab,
            &code,
            "priority/admission fanout is bounded",
            &transaction,
            "Outputs[0].Type|Outputs[1].Type|Outputs[2].Type|Outputs[3].Type|Outputs[4].Type",
            12,
        )?;
        let mut victim = admit(
            &mut lab,
            &anchor,
            &code,
            0,
            vec![payload],
            "priority/independent admission without anchor dependency",
        )?
        .remove(0);
        let premature = challenge_tx(&lab, &victim, 1, p::CHALLENGE_SINCE)?;
        let error = rpc::send_transaction_json(&premature)
            .expect_err("immature since unexpectedly admitted");
        let parsed: Value = error
            .strip_prefix("rpc error: ")
            .and_then(|s| serde_json::from_str(s).ok())
            .ok_or_else(|| error.clone())?;
        if parsed["code"] != -302 || !error.contains("Immature") {
            return Err(format!("expected consensus Immature: {error}"));
        }
        lab.evidence.push(json!({"label":"priority/consensus rejects early relative-block challenge","result":"rejected","error":error,"transaction":premature}));
        let zero = challenge_tx(&lab, &victim, 1, 0)?;
        reject(
            &mut lab,
            &code,
            "priority/challenge cannot omit consensus since",
            &zero,
            "Inputs[0].Type",
            7,
        )?;
        let burn = shape(
            &lab,
            1,
            &[(victim.point, victim.capacity)],
            vec![],
            None,
            &[0],
        )?;
        reject(
            &mut lab,
            &code,
            "priority/message cannot be burned",
            &burn,
            "Inputs[0].Type",
            2,
        )?;
        let mut output = victim.output(&victim.message.challenge().unwrap())?;
        output.lock = lab.wallets[1].key.lock_script();
        let replaced = shape(
            &lab,
            1,
            &[(victim.point, victim.capacity)],
            vec![output],
            None,
            &[0],
        )?;
        reject(
            &mut lab,
            &code,
            "priority/protocol lock cannot be substituted",
            &replaced,
            "Inputs[0].Type",
            5,
        )?;
        let mut output = victim.output(&victim.message.challenge().unwrap())?;
        output.capacity -= 1;
        let shrink = shape(
            &lab,
            1,
            &[(victim.point, victim.capacity)],
            vec![output],
            None,
            &[0],
        )?;
        reject(
            &mut lab,
            &code,
            "priority/locked capacity cannot be removed",
            &shrink,
            "Inputs[0].Type",
            5,
        )?;
        let mut changed = victim.message.challenge().unwrap();
        changed.payload[0] ^= 1;
        let changed = shape(
            &lab,
            1,
            &[(victim.point, victim.capacity)],
            vec![victim.output(&changed)?],
            None,
            &[0],
        )?;
        reject(
            &mut lab,
            &code,
            "priority/challenge cannot alter admitted payload",
            &changed,
            "Inputs[0].Type",
            6,
        )?;
        let challenged = victim.message.challenge().unwrap();
        let duplicate = shape(
            &lab,
            1,
            &[(victim.point, victim.capacity)],
            vec![victim.output(&challenged)?, victim.output(&challenged)?],
            None,
            &[0],
        )?;
        reject(
            &mut lab,
            &code,
            "priority/message cannot be split",
            &duplicate,
            "Inputs[0].Type",
            12,
        )?;
        let bytes = encode(
            anchor.state,
            vec![block(1, vec![victim.message.payload.clone()])],
        )?;
        let next = batch::validate_batch(&bytes, &anchor.state).unwrap().next;
        let invented = victim.message.include(&anchor.state, &next, 0).unwrap();
        let invented = shape(
            &lab,
            1,
            &[(victim.point, victim.capacity)],
            vec![victim.output(&invented)?],
            None,
            &[0],
        )?;
        reject(
            &mut lab,
            &code,
            "priority/inclusion requires the real anchor transition",
            &invented,
            "Inputs[0].Type",
            8,
        )?;
        rpc::mine_blocks(p::CHALLENGE_DELAY_BLOCKS)?;
        let challenge = challenge_tx(&lab, &victim, 1, p::CHALLENGE_SINCE)?;
        let hash = commit(
            &mut lab,
            1,
            "priority/independent actor matures challenge",
            &challenge,
        )?;
        victim.point = lab::point(&hash, 0)?;
        victim.message = victim.message.challenge().unwrap();
        let first_batch = anchor.state.next_batch_number;
        for index in 0..3 {
            let bytes = encode(
                anchor.state,
                vec![block(anchor.state.last_timestamp + 1, vec![])],
            )?;
            publish(
                &mut lab,
                &mut anchor,
                &bytes,
                0,
                &format!("priority/challenged victim omitted from batch {index}"),
            )?;
            engine.apply_batch(&bytes).map_err(|e| e.to_string())?;
            assert_live(victim.point, true)?;
        }
        results["post_challenge_empty_batches"] =
            json!(anchor.state.next_batch_number - first_batch);
        // Ordinary EVM inclusion and protocol processing are distinct predicates.
        let bytes = encode(
            anchor.state,
            vec![block(
                anchor.state.last_timestamp + 1,
                vec![victim.message.payload.clone()],
            )],
        )?;
        publish(
            &mut lab,
            &mut anchor,
            &bytes,
            0,
            "priority/ordinary payload inclusion leaves obligation unconsumed",
        )?;
        let ordinary = engine.apply_batch(&bytes).map_err(|e| e.to_string())?;
        if ordinary[0].transactions.len() != 1 || ordinary[0].outcomes[0].status != Status::Success
        {
            return Err("fixture payload did not execute".into());
        }
        assert_live(victim.point, true)?;
        let executed_once_state = engine.state_root();
        lab.evidence.push(json!({"label":"priority/ordinary execution without obligation consumption","result":"control_passed","blocks":ordinary}));
        let favorable = admit(
            &mut lab,
            &anchor,
            &code,
            0,
            (0..4).map(|i| vec![2, 1, i]).collect(),
            "priority/admit favorable subset independently",
        )?;
        let reversed = encode(
            anchor.state,
            vec![block(
                anchor.state.last_timestamp + 1,
                vec![
                    favorable[1].message.payload.clone(),
                    favorable[0].message.payload.clone(),
                ],
            )],
        )?;
        let tx = inclusion_tx(
            &lab,
            &anchor,
            &favorable[..2],
            1,
            inclusion_outputs(&anchor, &favorable[..2], &reversed)?,
        )?;
        reject(
            &mut lab,
            &code,
            "priority/distinct messages cannot swap input order",
            &tx,
            "Inputs[1].Type|Inputs[2].Type",
            11,
        )?;
        let mut five = vec![victim.clone()];
        five.extend(favorable.clone());
        let bytes = encode(
            anchor.state,
            vec![block(
                anchor.state.last_timestamp + 1,
                five.iter().map(|c| c.message.payload.clone()).collect(),
            )],
        )?;
        let tx = inclusion_tx(
            &lab,
            &anchor,
            &five,
            1,
            inclusion_outputs(&anchor, &five, &bytes)?,
        )?;
        reject(
            &mut lab,
            &code,
            "priority/input count is bounded",
            &tx,
            "Inputs[1].Type|Inputs[2].Type|Inputs[3].Type|Inputs[4].Type|Inputs[5].Type",
            12,
        )?;
        let bytes = encode(
            anchor.state,
            vec![block(anchor.state.last_timestamp + 1, vec![vec![9]])],
        )?;
        let tx = inclusion_tx(
            &lab,
            &anchor,
            &favorable[..1],
            1,
            inclusion_outputs(&anchor, &favorable[..1], &bytes)?,
        )?;
        reject(
            &mut lab,
            &code,
            "priority/batch prefix must equal admitted bytes",
            &tx,
            "Inputs[1].Type",
            11,
        )?;
        let bytes = encode(
            anchor.state,
            vec![block(
                anchor.state.last_timestamp + 1,
                vec![favorable[0].message.payload.clone()],
            )],
        )?;
        let mut outputs = inclusion_outputs(&anchor, &favorable[..1], &bytes)?;
        // Output record encodes slot at byte 185; payload remains identical.
        outputs[2].data[185] = 1;
        let tx = inclusion_tx(&lab, &anchor, &favorable[..1], 1, outputs)?;
        reject(
            &mut lab,
            &code,
            "priority/record cannot lie about slot",
            &tx,
            "Inputs[1].Type",
            10,
        )?;
        let mut tx = inclusion_tx(
            &lab,
            &anchor,
            &favorable[..1],
            1,
            inclusion_outputs(&anchor, &favorable[..1], &bytes)?,
        )?;
        // This witness belongs to the permissionless message lock, not SECP.
        tx["witnesses"][1] = json!(rpc::bytes_to_hex(&vec![0; p::MAX_PRIORITY_BYTES]));
        reject(
            &mut lab,
            &code,
            "priority/input witnesses count toward byte limit",
            &tx,
            "Inputs[1].Type",
            12,
        )?;
        let (pending, bytes) = include(
            &mut lab,
            &mut anchor,
            &favorable,
            1,
            "priority/process favorable four while challenged victim starves",
        )?;
        engine.apply_batch(&bytes).map_err(|e| e.to_string())?;
        assert_live(victim.point, true)?;
        results["favorable_subset_starvation"] = json!(true);
        for cell in &pending {
            assert_live(cell.point, true)?;
        }
        let tx = shape(
            &lab,
            0,
            &[(pending[0].point, pending[0].capacity)],
            vec![pending[0].output(&pending[0].message)?],
            None,
            &[0],
        )?;
        reject(
            &mut lab,
            &code,
            "priority/included record cannot be spent or reprocessed",
            &tx,
            "Inputs[0].Type",
            6,
        )?;
        let tx = shape(
            &lab,
            0,
            &[(pending[0].point, pending[0].capacity)],
            vec![],
            None,
            &[0],
        )?;
        reject(
            &mut lab,
            &code,
            "priority/unproven record cannot disappear",
            &tx,
            "Inputs[0].Type",
            2,
        )?;
        let mut all_pending = pending.clone();
        // Finite, known laboratory workload. This is not an authenticated global
        // queue inventory and makes no global completeness assertion.
        let mut backlog = Vec::new();
        let mut saturation = Vec::new();
        for round in 0..3 {
            backlog.extend(admit(
                &mut lab,
                &anchor,
                &code,
                0,
                vec![vec![2, 1, 2]; 4],
                &format!("priority/saturation admit {round}"),
            )?);
            let next = backlog.remove(0);
            let (new_pending, bytes) = include(
                &mut lab,
                &mut anchor,
                &[next],
                1,
                &format!("priority/saturation service {round}"),
            )?;
            all_pending.extend(new_pending);
            engine.apply_batch(&bytes).map_err(|e| e.to_string())?;
            saturation.push(backlog.len());
        }
        let mut drain = Vec::new();
        while !backlog.is_empty() {
            let cells: Vec<_> = backlog
                .drain(..backlog.len().min(p::MAX_PRIORITY_INPUTS))
                .collect();
            let (new_pending, bytes) = include(
                &mut lab,
                &mut anchor,
                &cells,
                1,
                "priority/honest actor drains known laboratory backlog",
            )?;
            all_pending.extend(new_pending);
            engine.apply_batch(&bytes).map_err(|e| e.to_string())?;
            drain.push(backlog.len());
        }
        assert_live(victim.point, true)?;
        results["known_workload_backlog"] =
            json!({"saturation":saturation,"drain":drain,"additional_starved_challenged_victim":1});
        // Max-sized payloads exercise the accepted boundary, not only rejects.
        let large = admit(
            &mut lab,
            &anchor,
            &code,
            0,
            vec![vec![0xff; p::MAX_PAYLOAD_BYTES]; 4],
            "priority/admit maximum payloads",
        )?;
        let (new_pending, bytes) = include(
            &mut lab,
            &mut anchor,
            &large,
            1,
            "priority/process maximum four payloads within burden bound",
        )?;
        engine.apply_batch(&bytes).map_err(|e| e.to_string())?;
        all_pending.extend(new_pending);
        // A planned canonical reorg restores the original obligation; a second
        // actor can process it in the replacement branch with no orphan record.
        let stable_anchor = anchor.clone();
        let stable_engine = engine.clone();
        let stable_wallet = (lab.wallets[0].point, lab.wallets[0].capacity);
        let parent = rpc::call("get_tip_header", json!([]))?;
        let (orphan, bytes) = include(
            &mut lab,
            &mut anchor,
            &[victim.clone()],
            0,
            "priority/include victim in planned orphan branch",
        )?;
        let blocks = engine.apply_batch(&bytes).map_err(|e| e.to_string())?;
        if !blocks[0].transactions.is_empty()
            || blocks[0].outcomes[0].status != Status::InvalidTransaction
            || engine.state_root() != executed_once_state
        {
            return Err("duplicate nonce executed again".into());
        }
        lab.evidence.push(json!({"label":"priority/orphan inclusion rejects already executed nonce","result":"control_passed","blocks":blocks}));
        assert_live(victim.point, false)?;
        assert_live(orphan[0].point, true)?;
        rpc::require_devnet()?;
        rpc::call("truncate", json!([parent["hash"]]))?;
        anchor = stable_anchor;
        engine = stable_engine;
        lab.wallets[0].point = stable_wallet.0;
        lab.wallets[0].capacity = stable_wallet.1;
        assert_live(victim.point, true)?;
        assert_live(orphan[0].point, false)?;
        let (replacement, bytes) = include(
            &mut lab,
            &mut anchor,
            &[victim],
            1,
            "priority/reinclude restored obligation in replacement branch",
        )?;
        let blocks = engine.apply_batch(&bytes).map_err(|e| e.to_string())?;
        if !blocks[0].transactions.is_empty()
            || blocks[0].outcomes[0].status != Status::InvalidTransaction
            || engine.state_root() != executed_once_state
        {
            return Err("repeated Ethereum transaction executed again".into());
        }
        lab.evidence.push(json!({"label":"priority/replacement inclusion rejects already executed nonce","result":"control_passed","blocks":blocks}));
        assert_live(replacement[0].point, true)?;
        results["planned_reorg_restores_obligation"] = json!(true);
        results["ordinary_then_priority_payload_does_not_double_execute"] = json!(true);
        results["bounds"] = json!({"inputs":p::MAX_PRIORITY_INPUTS,"payload_bytes":p::MAX_PAYLOAD_BYTES,"priority_burden_bytes":p::MAX_PRIORITY_BYTES,"per_script_cycles":p::MAX_PRIORITY_SCRIPT_CYCLES,"priority_script_cycles":p::MAX_PRIORITY_CYCLES,"first_evm_block_gas":p::MAX_PRIORITY_GAS,"challenge_delay_blocks":p::CHALLENGE_DELAY_BLOCKS});
        results["canonical_batches"] = json!(anchor.state.next_batch_number);
        all_pending.extend(replacement);
        for record in &all_pending {
            assert_live(record.point, true)?;
        }
        results["pending_record_count"] = json!(all_pending.len());
        results["scope"]=json!("Authentic independent obligations with immutable unproven records and bounded input-ordered inclusion; relative since authenticates individual delay. A challenge marker does not constrain ordinary anchor advancement, give FIFO, or authenticate the complete pending set. No proof/settlement gate or production liveness claim.");
        results["complete"] = json!(true);
        Ok::<_, String>(())
    })();
    results["error"] = json!(outcome.as_ref().err());
    lab.save(&path, results)?;
    outcome
}
fn main() {
    if let Err(error) = run() {
        eprintln!("PRIORITY EXPERIMENT FAILED: {error}");
        std::process::exit(1);
    }
}
