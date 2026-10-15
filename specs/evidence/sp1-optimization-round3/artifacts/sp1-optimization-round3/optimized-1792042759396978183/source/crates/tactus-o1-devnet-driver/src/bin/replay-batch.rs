//! Real VM tests for multi-block input commitments and atomic immutable DA.
use serde_json::{json, Value};
use tactus_o1_devnet_driver::{
    batch_lab::{self, *},
    lab::Lab,
    rpc,
    tx::{self, CellOutPoint, OutSpec, TX_FEE},
};
use tactus_o1_ordering_script::ckb_blake2b;
use tactus_o1_protocol::batch::{self, AnchorState};

fn negative_controls(lab: &mut Lab, anchor: &Anchor) -> Result<usize, String> {
    let good = encode(
        anchor.state,
        vec![block(10, vec![vec![2, 1, 2]]), block(10, vec![])],
    )?;
    let next = batch::validate_batch(&good, &anchor.state).unwrap().next;
    let pointer = 1u32.to_le_bytes();
    type RejectionCase<'a> = (&'a str, Vec<OutSpec>, Option<&'a [u8]>, i8);
    let cases: [RejectionCase<'_>; 8] = [
        (
            "hash-only witness",
            vec![head_output(anchor, next), da_output(anchor, &good)],
            Some(&[1; 32]),
            7,
        ),
        (
            "missing DA",
            vec![head_output(anchor, next)],
            Some(&pointer),
            8,
        ),
        (
            "missing witness",
            vec![head_output(anchor, next), da_output(anchor, &good)],
            None,
            7,
        ),
        (
            "state output as DA",
            vec![head_output(anchor, next), da_output(anchor, &good)],
            Some(&[0; 4]),
            8,
        ),
        (
            "spendable DA",
            vec![
                head_output(anchor, next),
                OutSpec {
                    lock: lab.wallets[1].key.lock_script(),
                    capacity: OutSpec::required_capacity(
                        &lab.wallets[1].key.lock_script(),
                        None,
                        good.len(),
                    ),
                    ..da_output(anchor, &good)
                },
            ],
            Some(&pointer),
            8,
        ),
        (
            "split anchor",
            vec![
                head_output(anchor, next),
                da_output(anchor, &good),
                head_output(anchor, next),
            ],
            Some(&pointer),
            2,
        ),
        (
            "burn anchor",
            vec![da_output(anchor, &good)],
            Some(&pointer),
            2,
        ),
        (
            "invented next block frontier",
            vec![
                head_output(
                    anchor,
                    AnchorState {
                        last_block_number: 99,
                        ..next
                    },
                ),
                da_output(anchor, &good),
            ],
            Some(&pointer),
            15,
        ),
    ];
    for (label, outputs, witness, code) in cases {
        let transaction = shape(lab, anchor, 1, outputs, witness)?;
        lab.reject(
            &format!("batch/{label}"),
            &transaction,
            &format!("error code {code}"),
        )?;
    }
    let mut cases = Vec::new();
    for (label, offset, code) in [
        ("wrong rollup", 8, 10),
        ("wrong chain ID", 40, 10),
        ("skipped batch", 48, 11),
        ("wrong predecessor", 56, 11),
        ("wrong rules", 88, 10),
        ("wrong DA policy", 120, 10),
        ("wrong limits", 152, 10),
        ("skipped block", 184, 11),
        ("unknown version", 7, 9),
    ] {
        let mut bytes = good.clone();
        bytes[offset] ^= 1;
        cases.push((label, bytes, code));
    }
    cases.push(("truncated", good[..good.len() - 1].to_vec(), 9));
    let mut bytes = good.clone();
    bytes.push(0);
    cases.push(("trailing bytes", bytes, 9));
    let mut bytes = good.clone();
    bytes[192..194].copy_from_slice(&u16::MAX.to_le_bytes());
    cases.push(("too many blocks", bytes, 13));
    let mut bytes = good.clone();
    bytes[224..228].copy_from_slice(&u32::MAX.to_le_bytes());
    cases.push(("oversized transaction", bytes, 13));
    let mut bytes = good.clone();
    bytes[231..239].copy_from_slice(&9u64.to_le_bytes());
    cases.push(("timestamp regression", bytes, 12));
    let count = 8 + cases.len();
    for (label, bytes, code) in cases {
        let transaction = shape(
            lab,
            anchor,
            1,
            vec![head_output(anchor, next), da_output(anchor, &bytes)],
            Some(&pointer),
        )?;
        lab.reject(
            &format!("batch/{label}"),
            &transaction,
            &format!("error code {code}"),
        )?;
    }
    Ok(count)
}
fn immutable_control(
    lab: &mut Lab,
    anchor: &Anchor,
    point: CellOutPoint,
    bytes: &[u8],
) -> Result<(), String> {
    let wallet = &lab.wallets[1];
    let capacity = OutSpec::required_capacity(&anchor.immutable, None, bytes.len());
    let output = OutSpec {
        capacity: wallet.capacity + capacity - TX_FEE,
        lock: wallet.key.lock_script(),
        type_script: None,
        data: vec![],
    };
    let (_, transaction) = tx::build_with_permissionless_prefix(
        &wallet.key,
        &lab.secp,
        &lab.deps,
        &[(point, capacity), (wallet.point, wallet.capacity)],
        &[output],
        None,
        1,
    )?;
    let error = rpc::send_transaction_json(&transaction)
        .expect_err("immutable publication must reject a spend");
    if !error.contains("error code 1 on page ")
        || !error.contains("Inputs[0].Lock")
        || !error.contains(&rpc::bytes_to_hex(&ckb_blake2b(&lab.ordering_elf))[2..])
    {
        return Err(format!("unexpected immutability rejection: {error}"));
    }
    lab.evidence.push(json!({"label":"batch/published DA cannot be spent","result":"rejected","error":error,"transaction":transaction}));
    Ok(())
}
fn recovery_control(
    lab: &mut Lab,
    anchor: &mut Anchor,
    expected: &[Vec<u8>],
) -> Result<Value, String> {
    use tactus_o1_devnet_driver::recovery::recover_published_batches;
    let baseline = recover_published_batches(&anchor.script)?;
    if baseline.point != anchor.point
        || baseline.state != anchor.state
        || baseline
            .batches
            .iter()
            .map(|b| &b.input_bytes)
            .collect::<Vec<_>>()
            != expected.iter().collect::<Vec<_>>()
    {
        return Err("published-input recovery mismatch".into());
    }
    if std::env::var("TACTUS_DEVNET_AUTOMINE").as_deref() != Ok("1") {
        return Err("reorg control requires isolated automining".into());
    }
    let parent = rpc::call("get_tip_header", json!([]))?;
    let before = anchor.clone();
    let fund = lab.wallets[0].point;
    let capacity = lab.wallets[0].capacity;
    let orphan = encode(anchor.state, vec![block(12, vec![vec![2, 9, 9]])])?;
    publish(lab, anchor, &orphan, 0, "batch/reorg branch to orphan")?;
    let orphan_transaction = rpc::bytes_to_hex(&anchor.point.tx_hash);
    rpc::require_devnet()?;
    rpc::call("truncate", json!([parent["hash"]]))?;
    lab.wallets[0].point = fund;
    lab.wallets[0].capacity = capacity;
    *anchor = before;
    let rollback = recover_published_batches(&anchor.script)?;
    if rollback.point != anchor.point || rollback.batches.len() != expected.len() {
        return Err("orphaned input survived canonical rollback".into());
    }
    let replacement = encode(anchor.state, vec![block(12, vec![vec![2, 8, 8]])])?;
    publish(
        lab,
        anchor,
        &replacement,
        1,
        "batch/reorg replacement input",
    )?;
    let recovered = recover_published_batches(&anchor.script)?;
    if recovered.point != anchor.point
        || recovered.state != anchor.state
        || recovered.batches.len() != expected.len() + 1
        || recovered.batches.last().unwrap().input_bytes != replacement
    {
        return Err("replacement input recovery failed".into());
    }
    let result = json!({"canonical_batches":recovered.batches.len(),"canonical_blocks":recovered.state.last_block_number,
        "orphan_transaction":orphan_transaction,"reconstructed_bytes":recovered.batches.iter().map(|b|b.input_bytes.len()).sum::<usize>(),
        "operator_snapshot_used":false,"scope":"canonical input bytes and boundaries, not executed EVM state"});
    lab.evidence.push(json!({"label":"batch/independent input recovery after reorg","result":"control_passed","details":result}));
    Ok(result)
}

fn genesis_controls(lab: &mut Lab) -> Result<Value, String> {
    use tactus_o1_devnet_driver::{molecule, sealed_lab};
    use tactus_o1_ordering_script::genesis_identity;
    use tactus_o1_protocol::genesis::{self, Account, Allocation};
    let allocation = Allocation::default().encode().unwrap();
    for (mutation, label, expected) in [
        (0, "missing allocation", 16),
        (1, "wrong allocation commitment", 16),
        (2, "spendable allocation", 16),
        (3, "noncanonical allocation suffix", 16),
        (4, "duplicate allocation addresses", 16),
        (5, "legacy unbound identity", 1),
        (6, "oversized allocation", 13),
    ] {
        let wallet = &lab.wallets[0];
        let seed = molecule::cell_input(
            0,
            &molecule::out_point(&wallet.point.tx_hash, wallet.point.index),
        )
        .try_into()
        .unwrap();
        let id = genesis_identity(&seed, 0);
        let mut bytes = allocation.clone();
        if mutation == 3 {
            bytes.push(0);
        }
        if mutation == 4 {
            let a = Account {
                address: [1; 20],
                balance: [0; 32],
                nonce: 1,
                code: vec![],
                storage: vec![],
            };
            let one = Allocation { accounts: vec![a] }.encode().unwrap();
            bytes = one.clone();
            bytes[8..12].copy_from_slice(&2u32.to_le_bytes());
            bytes.extend_from_slice(&one[12..]);
        }
        if mutation == 6 {
            bytes.resize(genesis::MAX_BYTES + 1, 0);
        }
        let mut commitment = batch::hash(b"tactus/o1/genesis-allocation/v1", &bytes);
        if mutation == 1 {
            commitment[0] ^= 1;
        }
        let mut args = id.to_vec();
        if mutation != 5 {
            args.extend_from_slice(&commitment);
        }
        let script = molecule::script(&ckb_blake2b(&lab.ordering_elf), 2, &args);
        let lock = molecule::script(&ckb_blake2b(&lab.lock_elf), 2, &ckb_blake2b(&script));
        let anchor = Anchor {
            point: wallet.point,
            capacity: OutSpec::required_capacity(&lock, Some(&script), batch::ANCHOR_LEN) + TX_FEE,
            state: AnchorState::genesis(id, ckb_blake2b(b"genesis-controls"), 31337).unwrap(),
            script,
            lock,
            immutable: molecule::script(&ckb_blake2b(&lab.ordering_elf), 2, &[]),
        };
        let mut outputs = vec![head_output(&anchor, anchor.state)];
        if mutation != 0 {
            let mut o = da_output(&anchor, &bytes);
            if mutation == 2 {
                o.lock = wallet.key.lock_script();
                o.capacity = OutSpec::required_capacity(&o.lock, None, bytes.len());
            }
            outputs.push(o);
        }
        let tx = sealed_lab::shape(lab, 0, &[], outputs, &[], &[])?;
        lab.reject(
            &format!("genesis/{label}"),
            &tx,
            &format!("error code {expected}"),
        )?;
    }
    let mut accounts = vec![];
    for i in 0..11 {
        accounts.push(Account {
            address: [i; 20],
            balance: [0; 32],
            nonce: 1,
            code: vec![
                0;
                if i == 10 {
                    15624
                } else {
                    genesis::MAX_CODE_BYTES
                }
            ],
            storage: vec![],
        });
    }
    let maximum = Allocation { accounts }.encode().unwrap();
    if maximum.len() != genesis::MAX_BYTES {
        return Err("maximum allocation shape".into());
    }
    let anchor = batch_lab::create_with_allocation(
        lab,
        ckb_blake2b(b"maximum-allocation-control"),
        31337,
        &maximum,
    )?;
    immutable_control(
        lab,
        &anchor,
        tactus_o1_devnet_driver::lab::point(&rpc::bytes_to_hex(&anchor.point.tx_hash), 1)?,
        &maximum,
    )?;
    let recovered = tactus_o1_devnet_driver::recovery::recover_published_batches(&anchor.script)?;
    if recovered.genesis_allocation != maximum {
        return Err("maximum allocation recovery mismatch".into());
    }
    Ok(
        json!({"invalid_genesis_rejections":7,"immutable_genesis_rejection":true,"maximum_allocation_bytes":maximum.len(),"maximum_allocation_recovered":true}),
    )
}

fn run() -> Result<(), String> {
    let path = std::env::var("TACTUS_EVIDENCE_PATH")
        .unwrap_or_else(|_| "artifacts/batch-evidence.json".into());
    let mut lab = Lab::connect_with_script("artifacts/tactus_o1_anchor_script.elf")?;
    let mut results =
        json!({"suite":"batch-input-v1","complete":false,"production_ready":false,"W12":"OPEN"});
    let outcome = (|| {
        results["genesis_publication"] = genesis_controls(&mut lab)?;
        let mut anchor = batch_lab::create(
            &mut lab,
            ckb_blake2b(b"unimplemented-evm-execution-devnet-only"),
            31337,
        )?;
        results["rejected_invalid_transitions"] = json!(negative_controls(&mut lab, &anchor)?);
        let first = encode(
            anchor.state,
            vec![block(10, vec![vec![2, 1, 2]]), block(10, vec![])],
        )?;
        let first_point = publish(
            &mut lab,
            &mut anchor,
            &first,
            1,
            "batch/independent actor publishes two blocks and data atomically",
        )?;
        immutable_control(&mut lab, &anchor, first_point, &first)?;
        let mut txs = vec![vec![2; batch::MAX_TRANSACTION_BYTES]; 15];
        txs.push(vec![
            2;
            batch::MAX_BATCH_BYTES
                - 194
                - 30
                - 16 * 4
                - 15 * batch::MAX_TRANSACTION_BYTES
        ]);
        let maximum = encode(anchor.state, vec![block(11, txs)])?;
        assert_eq!(maximum.len(), batch::MAX_BATCH_BYTES);
        let next = batch::validate_batch(&maximum, &anchor.state).unwrap().next;
        let mut oversized = maximum.clone();
        oversized.push(0);
        let transaction = shape(
            &lab,
            &anchor,
            0,
            vec![head_output(&anchor, next), da_output(&anchor, &oversized)],
            Some(&1u32.to_le_bytes()),
        )?;
        lab.reject(
            "batch/above publication byte ceiling",
            &transaction,
            "error code 13",
        )?;
        publish(
            &mut lab,
            &mut anchor,
            &maximum,
            0,
            "batch/exact 256 KiB publication ceiling",
        )?;
        results["input_recovery"] =
            recovery_control(&mut lab, &mut anchor, &[first, maximum.clone()])?;
        results["published_batches"] = json!(3);
        results["published_blocks"] = json!(anchor.state.last_block_number);
        results["maximum_payload_bytes"] = json!(maximum.len());
        results["scope"]=json!("bounded opaque transaction inputs, atomic immutable CKB DA and contiguous block inputs; no EVM execution, proof or priority enforcement");
        results["complete"] = json!(true);
        Ok::<_, String>(())
    })();
    results["error"] = json!(outcome.as_ref().err());
    lab.save(&path, results)?;
    outcome
}
fn main() {
    if let Err(error) = run() {
        eprintln!("BATCH FAILED: {error}");
        std::process::exit(1);
    }
}
