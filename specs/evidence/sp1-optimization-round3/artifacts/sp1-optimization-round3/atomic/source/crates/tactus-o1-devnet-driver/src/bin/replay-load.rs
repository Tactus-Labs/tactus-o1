//! Sustained offered-load comparison across authenticated active and sealed sets.
//! This measures publication and total EVM classification, never validity settlement.
use serde_json::{json, Value};
use std::{collections::VecDeque, time::Instant};
use tactus_o1_devnet_driver::{
    lab::{self, Lab},
    rpc, sealed_lab as sealed,
    tx::{self, TX_FEE},
};
use tactus_o1_execution::{Executor, Genesis, Status};
use tactus_o1_ordering_script::ckb_blake2b;
use tactus_o1_protocol::sealed::{BATCHES_PER_EPOCH, MAX_LANE_MESSAGES};

const ROUNDS: usize = 32;
const QUANTUM_BLOCKS: u64 = 4;
const MAX_DRAIN_ROUNDS: usize = 512;
#[derive(Clone)]
struct Message {
    lane: usize,
    offered_height: u64,
    admitted_height: Option<u64>,
    admitted_batch: Option<u64>,
    processed_height: Option<u64>,
    processed_batch: Option<u64>,
}
struct Workload {
    messages: Vec<Message>,
    pending: Vec<VecDeque<usize>>,
    peaks: Vec<usize>,
    full_lane_ticks: u64,
    classified: usize,
}
impl Workload {
    fn new(lanes: usize) -> Self {
        Self {
            messages: vec![],
            pending: vec![VecDeque::new(); lanes],
            peaks: vec![0; lanes],
            full_lane_ticks: 0,
            classified: 0,
        }
    }
    fn offer(&mut self, lane: usize, height: u64) {
        let id = self.messages.len();
        self.messages.push(Message {
            lane,
            offered_height: height,
            admitted_height: None,
            admitted_batch: None,
            processed_height: None,
            processed_batch: None,
        });
        self.pending[lane].push_back(id);
        self.peaks[lane] = self.peaks[lane].max(self.pending[lane].len());
    }
    fn counts(&self) -> Value {
        let admitted = self
            .messages
            .iter()
            .filter(|m| m.admitted_height.is_some())
            .count();
        let processed = self
            .messages
            .iter()
            .filter(|m| m.processed_height.is_some())
            .count();
        json!({"offered":self.messages.len(),"admitted":admitted,"processed":processed,"outside_chain_backlog":self.messages.len()-admitted,"admitted_not_processed":admitted-processed,"pending_per_lane":self.pending.iter().map(VecDeque::len).collect::<Vec<_>>(),"offchain_peak_per_lane":self.peaks,"full_lane_ticks":self.full_lane_ticks,"evm_classified_malformed":self.classified})
    }
}
fn hex_u64(value: &str) -> Result<u64, String> {
    u64::from_str_radix(value.strip_prefix("0x").ok_or("hex prefix")?, 16)
        .map_err(|e| e.to_string())
}
fn payload(id: usize) -> Vec<u8> {
    // An intentionally malformed, fixed 64-byte envelope. Distinct IDs permit a
    // complete offered/admitted/processed audit, not an Ethereum TPS claim.
    let mut b = vec![0; 64];
    b[1..9].copy_from_slice(&(id as u64).to_le_bytes());
    b[9..17].copy_from_slice(b"LOAD0001");
    b
}
fn id_from_payload(bytes: &[u8]) -> Result<usize, String> {
    if bytes.len() != 64 {
        return Err("load payload length".into());
    }
    let id = u64::from_le_bytes(bytes[1..9].try_into().unwrap()) as usize;
    if payload(id) != bytes {
        return Err("load payload mismatch".into());
    }
    Ok(id)
}
fn admissions(
    lab: &mut Lab,
    net: &mut sealed::Network,
    load: &mut Workload,
    label: &str,
) -> Result<usize, String> {
    let mut selected = vec![];
    for (i, (_, lane)) in net.lanes.iter().enumerate() {
        if load.pending[i].is_empty() {
            continue;
        }
        if lane.queue.len() == MAX_LANE_MESSAGES {
            load.full_lane_ticks += 1;
            continue;
        }
        selected.push((i, *load.pending[i].front().unwrap()));
    }
    if selected.is_empty() {
        return Ok(0);
    }
    // One independently authenticated append per selected lane in one CKB
    // transaction: a fixed quantum has equal mining overhead for all lane counts.
    let mut next = vec![];
    for (lane, id) in &selected {
        next.push(
            net.lanes[*lane]
                .1
                .append(payload(*id))
                .map_err(|e| format!("{e:?}"))?,
        );
    }
    let inputs = selected
        .iter()
        .map(|(i, _)| (net.lanes[*i].0.point, net.lanes[*i].0.capacity))
        .collect::<Vec<_>>();
    let outputs = selected
        .iter()
        .zip(&next)
        .map(|((i, _), n)| net.lanes[*i].0.output(n.encode().unwrap()))
        .collect();
    let transaction = sealed::shape(lab, 0, &inputs, outputs, &[], &[])?;
    let hash = sealed::commit(lab, 0, label, &transaction)?;
    let height = rpc::get_tip_block_number()?;
    for (output, ((lane, id), new)) in selected.iter().zip(next).enumerate() {
        net.lanes[*lane].0.point = lab::point(&hash, output as u32)?;
        net.lanes[*lane].1 = new;
        if load.pending[*lane].pop_front() != Some(*id) {
            return Err("offchain FIFO mismatch".into());
        }
        let m = &mut load.messages[*id];
        if m.admitted_height.is_some() {
            return Err("duplicate admission".into());
        }
        m.admitted_height = Some(height);
        m.admitted_batch = Some(net.anchor.state.next_batch_number);
    }
    Ok(selected.len())
}
fn candidate(lab: &Lab, net: &sealed::Network, mutable: bool) -> Result<(Vec<u8>, Value), String> {
    let bytes = sealed::required_bytes(net)?;
    let outputs = sealed::advance_outputs(net, &bytes)?;
    let mut deps = net.snapshot.iter().map(|(p, _)| *p).collect::<Vec<_>>();
    if mutable {
        deps.extend(net.lanes.iter().map(|(c, _)| c.point));
    }
    let tx = sealed::shape(
        lab,
        1,
        &[
            (net.anchor.point, net.anchor.capacity),
            (net.gate.point, net.gate.capacity),
        ],
        outputs,
        &[(0, 1u32.to_le_bytes().to_vec()), (1, vec![1])],
        &deps,
    )?;
    Ok((bytes, tx))
}
fn advance(
    lab: &mut Lab,
    net: &mut sealed::Network,
    engine: &mut Executor,
    load: &mut Workload,
    bytes: &[u8],
    transaction: &Value,
    label: &str,
) -> Result<(), String> {
    let required = net
        .schedule
        .required(net.snapshot.as_ref().map(|(_, s)| s))
        .map_err(|e| format!("{e:?}"))?;
    let mut ids = vec![];
    for m in required {
        let id = id_from_payload(&m.payload)?;
        let message = load.messages.get(id).ok_or("unoffered message processed")?;
        if message.admitted_height.is_none() || message.processed_height.is_some() {
            return Err("unadmitted or duplicate processing".into());
        }
        ids.push(id);
    }
    sealed::accept_advance(lab, net, 1, bytes, transaction, label)?;
    let execution = engine.apply_batch(bytes).map_err(|e| e.to_string())?;
    let outcomes = execution
        .iter()
        .flat_map(|b| &b.outcomes)
        .collect::<Vec<_>>();
    if outcomes.len() != ids.len()
        || outcomes.iter().any(|o| o.status != Status::Malformed)
        || engine.anchor() != &net.anchor.state
    {
        return Err("execution outcome or canonical anchor mismatch".into());
    }
    let height = rpc::get_tip_block_number()?;
    for id in ids {
        let m = &mut load.messages[id];
        m.processed_height = Some(height);
        m.processed_batch = Some(net.anchor.state.next_batch_number);
    }
    load.classified += outcomes.len();
    Ok(())
}
fn seal_if_ready(lab: &mut Lab, net: &mut sealed::Network, label: &str) -> Result<bool, String> {
    if net.schedule.batches == BATCHES_PER_EPOCH {
        sealed::seal(lab, net, 1, label)?;
        Ok(true)
    } else {
        Ok(false)
    }
}
fn pad_quantum(start: u64) -> Result<(), String> {
    let elapsed = rpc::get_tip_block_number()?
        .checked_sub(start)
        .ok_or("height reversal")?;
    if elapsed > QUANTUM_BLOCKS {
        return Err(format!("admission exceeded fixed quantum: {elapsed}"));
    }
    rpc::mine_blocks(QUANTUM_BLOCKS - elapsed)
}
fn stats(values: &[u64]) -> Value {
    if values.is_empty() {
        return Value::Null;
    }
    let mut sorted = values.to_vec();
    sorted.sort_unstable();
    json!({"count":sorted.len(),"min":sorted[0],"p50":sorted[(sorted.len()-1)/2],"p95":sorted[(sorted.len()*95).div_ceil(100)-1],"max":sorted[sorted.len()-1],"mean":sorted.iter().sum::<u64>() as f64/sorted.len() as f64})
}
fn economic_events(lab: &Lab, start: usize) -> Result<Value, String> {
    let mut count = 0u64;
    let mut wire = 0usize;
    let mut cycles = 0u64;
    for event in &lab.evidence[start..] {
        if event["result"] != "committed" {
            continue;
        }
        count += 1;
        let hash = event["hash"].as_str().ok_or("hash")?;
        let packed = rpc::call("get_transaction", json!([hash, "0x0"]))?;
        let actual =
            rpc::decode_hex(packed["transaction"].as_str().ok_or("packed transaction")?)?.len();
        if tx::wire_bytes(&event["transaction"])? != actual {
            return Err("wire byte calculation differs from node".into());
        }
        wire += actual;
        cycles += hex_u64(
            event["cycles"]["cycles"]
                .as_str()
                .ok_or("cycle estimate missing")?,
        )
        .map_err(|e| e.to_string())?;
    }
    Ok(
        json!({"committed_transactions":count,"fees_shannons":count*TX_FEE,"node_confirmed_wire_bytes":wire,"estimated_committed_vm_cycles":cycles}),
    )
}
fn run_case(
    lab: &mut Lab,
    code: [u8; 32],
    lanes: u8,
    regime: &str,
    window: usize,
    mutable: bool,
) -> Result<Value, String> {
    let arm = if mutable {
        "live-dependency-diagnostic"
    } else {
        "mandatory-sealed"
    };
    let label = format!("load/{lanes}/{regime}/window-{window}/{arm}");
    let mut net = sealed::bootstrap(lab, code, lanes)?;
    let genesis = Genesis {
        rollup_id: net.anchor.state.rollup_id.into(),
        chain_id: 31337,
        accounts: Default::default(),
    };
    let mut engine = Executor::new(&genesis).map_err(|e| e.to_string())?;
    for _ in 0..BATCHES_PER_EPOCH {
        sealed::advance(lab, &mut net, 1, &mut engine, &format!("{label}/warmup"))?;
    }
    sealed::seal(lab, &mut net, 1, &format!("{label}/initial empty seal"))?;
    let mut load = Workload::new(lanes as usize);
    let start = rpc::get_tip_block_number()?;
    let start_batch = net.anchor.state.next_batch_number;
    let start_evidence = lab.evidence.len();
    let start_capacity = lab.wallets.iter().map(|w| w.capacity).sum::<u64>();
    let clock = Instant::now();
    let mut rounds = vec![];
    let mut invalid = 0;
    let mut seals = 0;
    let mut discarded_cycles = 0u64;
    let mut discarded_bytes = 0usize;
    let mut discarded_build_us = 0u128;
    for round in 0..ROUNDS {
        seals += usize::from(seal_if_ready(
            lab,
            &mut net,
            &format!("{label}/{round}/seal"),
        )?);
        let built_height = rpc::get_tip_block_number()?;
        let build = Instant::now();
        let (bytes, transaction) = candidate(lab, &net, mutable)?;
        let build_us = build.elapsed().as_micros();
        // Fresh candidate must first pass real VM execution; this separates
        // stale dependency rejection from pre-existing script/resource failures.
        let estimate = rpc::call("estimate_cycles", json!([transaction]))?;
        let vm_cycles = hex_u64(estimate["cycles"].as_str().ok_or("estimate")?)?;
        let mut updates = vec![0usize; lanes as usize];
        let mut tick_rows = vec![];
        for tick in 0..window {
            let tick_start = rpc::get_tip_block_number()?;
            let offered_before = load.messages.len();
            if regime == "L1-per-lane" {
                for i in 0..lanes as usize {
                    load.offer(i, tick_start);
                }
            } else if regime == "L2-fixed-aggregate" {
                load.offer((round * window + tick) % lanes as usize, tick_start);
            } else if tick == window - 1 {
                for _ in 0..window {
                    load.offer(0, tick_start);
                }
            }
            let before = net
                .lanes
                .iter()
                .map(|(_, l)| l.next_sequence)
                .collect::<Vec<_>>();
            if regime != "L3-targeted" || tick == window - 1 {
                admissions(
                    lab,
                    &mut net,
                    &mut load,
                    &format!("{label}/{round}/tick-{tick}/admit"),
                )?;
            }
            let delta = net
                .lanes
                .iter()
                .enumerate()
                .map(|(i, (_, l))| (l.next_sequence - before[i]) as usize)
                .collect::<Vec<_>>();
            for (a, b) in updates.iter_mut().zip(&delta) {
                *a += b;
            }
            pad_quantum(tick_start)?;
            tick_rows.push(json!({"start_height":tick_start,"end_height":rpc::get_tip_block_number()?,"offered":load.messages.len()-offered_before,"admissions_per_lane":delta}));
        }
        let submit_height = rpc::get_tip_block_number()?;
        let survived = !mutable || updates.iter().sum::<usize>() == 0;
        if survived {
            advance(
                lab,
                &mut net,
                &mut engine,
                &mut load,
                &bytes,
                &transaction,
                &format!("{label}/{round}/canonical batch"),
            )?;
        } else {
            // Funding and state inputs remain live; only stale lane dependencies
            // may account for this RPC -301 rejection. Do not count -302 errors.
            sealed::live(lab.wallets[1].point, true)?;
            sealed::live(net.anchor.point, true)?;
            sealed::live(net.gate.point, true)?;
            lab.reject(
                &format!("{label}/{round}/invalidated candidate"),
                &transaction,
                "TransactionFailedToResolve",
            )?;
            invalid += 1;
            discarded_cycles += vm_cycles;
            discarded_bytes += tx::wire_bytes(&transaction)?;
            discarded_build_us += build_us;
        }
        rounds.push(json!({"round":round,"built_height":built_height,"submit_height":submit_height,"end_height":rpc::get_tip_block_number()?,"candidate_survived":survived,"candidate_wire_bytes":tx::wire_bytes(&transaction)?,"candidate_estimated_vm_cycles":vm_cycles,"candidate_build_us":build_us,"ticks":tick_rows,"lane_updates":updates,"queue_sizes":net.lanes.iter().map(|(_,l)|l.queue.len()).collect::<Vec<_>>(),"epoch":net.schedule.epoch,"batches_in_epoch":net.schedule.batches,"counts":load.counts()}));
    }
    let elapsed_seconds = clock.elapsed().as_secs_f64();
    let end = rpc::get_tip_block_number()?;
    let batches = net.anchor.state.next_batch_number - start_batch;
    let active_counts = load.counts();
    let active_economics = economic_events(lab, start_evidence)?;
    let spent = start_capacity - lab.wallets.iter().map(|w| w.capacity).sum::<u64>();
    let permanent_capacity = spent - active_economics["fees_shannons"].as_u64().ok_or("fees")?;
    // Stop arrivals explicitly. Drain is outside the throughput window; every
    // offered message, including those rejected by queue backpressure, must finish.
    let drain_start = rpc::get_tip_block_number()?;
    let mut drain_rounds = 0;
    while load.messages.iter().any(|m| m.processed_height.is_none()) {
        if drain_rounds >= MAX_DRAIN_ROUNDS {
            return Err("bounded drain did not complete".into());
        }
        seal_if_ready(lab, &mut net, &format!("{label}/drain-{drain_rounds}/seal"))?;
        admissions(
            lab,
            &mut net,
            &mut load,
            &format!("{label}/drain-{drain_rounds}/admit"),
        )?;
        let (bytes, transaction) = candidate(lab, &net, mutable)?;
        advance(
            lab,
            &mut net,
            &mut engine,
            &mut load,
            &bytes,
            &transaction,
            &format!("{label}/drain-{drain_rounds}/batch"),
        )?;
        drain_rounds += 1;
    }
    let offered_expected = ROUNDS
        * window
        * if regime == "L1-per-lane" {
            lanes as usize
        } else {
            1
        };
    if load.messages.len() != offered_expected
        || load.classified != offered_expected
        || load.pending.iter().any(|p| !p.is_empty())
    {
        return Err("offered/admitted/processed conservation failed".into());
    }
    if !mutable && (invalid != 0 || batches != ROUNDS as u64) {
        return Err("sealed gate lost canonical progress".into());
    }
    let admissions_per_lane = (0..lanes as usize)
        .map(|i| {
            load.messages
                .iter()
                .filter(|m| m.lane == i && m.admitted_height.is_some_and(|h| h <= end))
                .count()
        })
        .collect::<Vec<_>>();
    let latencies = load
        .messages
        .iter()
        .map(|m| m.admitted_height.unwrap() - m.offered_height)
        .collect::<Vec<_>>();
    let processing = load
        .messages
        .iter()
        .map(|m| m.processed_height.unwrap() - m.admitted_height.unwrap())
        .collect::<Vec<_>>();
    let publication_batches = load
        .messages
        .iter()
        .map(|m| m.processed_batch.unwrap() - m.admitted_batch.unwrap())
        .collect::<Vec<_>>();
    let theoretical = 16u64; // 8 remaining batches + 8 to drain a maximum 32-message snapshot.
    if publication_batches.iter().any(|d| *d > theoretical) {
        return Err("mandatory processing exceeded canonical batch bound".into());
    }
    let messages=load.messages.iter().enumerate().map(|(id,m)|json!({"id":id,"lane":m.lane,"offered_height":m.offered_height,"admitted_height":m.admitted_height,"admitted_batch":m.admitted_batch,"processed_height":m.processed_height,"processed_batch":m.processed_batch})).collect::<Vec<_>>();
    let result = json!({"lanes":lanes,"regime":regime,"window_quanta":window,"arm":arm,"rounds":ROUNDS,"quantum_blocks":QUANTUM_BLOCKS,"start_height":start,"end_height":end,"elapsed_blocks":end-start,"elapsed_host_seconds":elapsed_seconds,"canonical_batches":batches,"seals_in_window":seals,"candidate_count":ROUNDS,"invalidated_candidates":invalid,"candidate_survival_rate":(ROUNDS-invalid) as f64/ROUNDS as f64,"active_counts":active_counts,"admissions_per_lane":admissions_per_lane,"admission_per_ckb_block":active_counts["admitted"].as_u64().unwrap() as f64/(end-start) as f64,"canonical_batches_per_ckb_block":batches as f64/(end-start) as f64,"admission_per_host_second":active_counts["admitted"].as_u64().unwrap() as f64/elapsed_seconds,"canonical_batches_per_host_second":batches as f64/elapsed_seconds,"economics":active_economics,"retained_da_and_snapshot_capacity_shannons":permanent_capacity,"abandoned_candidates":{"estimated_vm_cycles":discarded_cycles,"wire_bytes":discarded_bytes,"build_us":discarded_build_us,"paid_chain_fees":0},"drain":{"arrivals_stopped":true,"rounds":drain_rounds,"elapsed_blocks":rpc::get_tip_block_number()?-drain_start,"final_counts":load.counts()},"latency_including_drain":{"offered_to_admitted_ckb_blocks":stats(&latencies),"admitted_to_processed_ckb_blocks":stats(&processing),"admitted_to_processed_canonical_batches":stats(&publication_batches)},"messages":messages,"timeline":rounds,"final_execution_hash":engine.head().hash_slow(),"final_state_root":engine.state_root(),"settled":false});
    println!("{label}: {batches}/{ROUNDS} canonical batches, {invalid} stale candidates, {} offered, drain {drain_rounds}",load.messages.len());
    Ok(result)
}
fn run() -> Result<(), String> {
    let path = std::env::var("TACTUS_EVIDENCE_PATH").map_err(|_| "use isolated launcher")?;
    let mut lab = Lab::connect_with_script("artifacts/tactus_o1_anchor_script.elf")?;
    let mut results = json!({"suite":"sustained-lane-load-v1","complete":false,"production_ready":false,"G2":"OPEN","G4":"OPEN","scope":"32 consecutive construction windows per case, deterministic offered-load quanta; actual canonical publication and malformed-input EVM classification, no useful Ethereum TPS, stochastic fairness, proof or settlement claim","policy":{"arrival_clock":"four generated CKB blocks per quantum; batch/seal overhead outside arrival clock and included in measured rates","miner":"configured default CKB template selection via generate_block; no hostile external miner","fee_shannons":TX_FEE,"actors":"actor 0 admits all offered messages; actor 1 independently funds canonical batches and seals","backpressure":"FIFO offchain retries, no dropped offered messages; separate no-arrival drain","live_control":"same authenticated mandatory gate plus live-lane cell_deps; diagnostic forbidden production strategy","payload":"unique deterministic 64-byte malformed envelopes; all count as total rejection processing, zero included Ethereum transactions"},"cases":[]});
    let outcome = (|| {
        let gate =
            std::fs::read("artifacts/tactus_o1_sealed_script.elf").map_err(|e| e.to_string())?;
        let code = ckb_blake2b(&gate);
        let deps = lab.publish_cells("load/deploy sealed gate", &[gate], 0, true)?;
        lab.deps.extend(deps);
        results["initial_tx_pool_info"] = rpc::call("tx_pool_info", json!([]))?;
        for lanes in [1, 2, 4] {
            for regime in ["L1-per-lane", "L2-fixed-aggregate", "L3-targeted"] {
                for window in [1, 3] {
                    for mutable in [true, false] {
                        let case = run_case(&mut lab, code, lanes, regime, window, mutable)?;
                        results["cases"].as_array_mut().unwrap().push(case);
                        lab.save(&path, results.clone())?;
                    }
                }
            }
        }
        results["complete"] = json!(true);
        Ok::<_, String>(())
    })();
    results["error"] = json!(outcome.as_ref().err());
    lab.save(&path, results)?;
    outcome
}
fn main() {
    if let Err(e) = run() {
        eprintln!("LOAD EXPERIMENT FAILED: {e}");
        std::process::exit(1);
    }
}
