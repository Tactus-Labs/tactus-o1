//! Fresh-process recovery and read-only input/claim export. No transaction is sent.
use serde_json::{json, Value};
use std::{fs, io::Read, path::Path};
use tactus_o1_devnet_driver::rpc;
use tactus_o1_protocol::v02::*;
use tactus_v02_lab::{
    err,
    observer::atomic_json,
    point_bytes, point_json,
    recover::{recover, Manifest},
    Result,
};
use tactus_v02_script::claims::{ClaimWitness, Context, Request};
fn main() {
    if let Err(e) = run() {
        eprintln!("{e}");
        std::process::exit(1);
    }
}
fn run() -> Result<()> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() < 4 || args.len() > 5 {
        return Err(
            "usage: recover-v02 MANIFEST OUTPUT report | prove END | refund SEQUENCE | release REQUEST_JSON | escape REQUEST_JSON".into(),
        );
    }
    let mut b = vec![];
    fs::File::open(&args[1])
        .map_err(err)?
        .take(1024 * 1024 + 1)
        .read_to_end(&mut b)
        .map_err(err)?;
    if b.len() > 1024 * 1024 {
        return Err("manifest limit".into());
    }
    let manifest: Value = serde_json::from_slice(&b).map_err(err)?;
    let recovered = recover(Manifest::decode(&manifest)?)?;
    let report = match args[3].as_str() {
        "report" if args.len() == 4 => recovered.report()?,
        "prove" if args.len() == 5 => recovered.proving_input(args[4].parse().map_err(err)?)?,
        "refund" if args.len() == 5 => {
            let sequence: u64 = args[4].parse().map_err(err)?;
            let record = recovered.cell(Role::DepositReceipt, sequence)?;
            let deposit = Deposit::decode(&record.output.data).map_err(err)?;
            let control = recovered.cell(Role::Control, 0)?;
            let vault = recovered.cell(Role::Vault, 0)?;
            let witness = ClaimWitness {
                payout: 1,
                control_outpoint: point_bytes(control.point),
                request: Request::Refund {
                    receipt_outpoint: point_bytes(record.point),
                },
                nullifier: recovered.claims[1]
                    .proof(&sequence.to_le_bytes(), recovered.vault.claims[1])?,
            };
            let payout = witness
                .authorize(&Context {
                    config: &recovered.manifest.config,
                    policy: &recovered.manifest.policy,
                    control: &recovered.control,
                    control_outpoint: witness.control_outpoint,
                    vault: &recovered.vault,
                    receipt: Some((point_bytes(record.point), &deposit)),
                })
                .map_err(err)?;
            json!({"schema":"tactus-v02-refund-plan-v1","pinned_hash":recovered.tip["hash"],"vault_outpoint":point_json(vault.point),"control_outpoint":point_json(control.point),"receipt_outpoint":point_json(record.point),
                "operation":Operation::Refund as u8,"claim_witness_hex":rpc::bytes_to_hex(&witness.encode().map_err(err)?),"next_vault_hex":rpc::bytes_to_hex(&payout.next.encode().map_err(err)?),
                "next_vault_capacity":payout.next.capacity().map_err(err)?.to_string(),"recipient_lock_hash":rpc::bytes_to_hex(&payout.lock),"principal_shannons":payout.amount.to_string(),"payout_index":1,
                "phase":"Withdrawable","control_confirmation":recovered.control_confirmation()?,"permanent_finality":false,
                "requires_recipient_lock_preimage":true,"external_capacity_topup_may_be_required":true,"transaction_submitted":false})
        }
        mode @ ("release" | "escape") if args.len() == 5 => {
            let mut bytes = Vec::new();
            fs::File::open(&args[4])
                .map_err(err)?
                .take(16 * 1024 + 1)
                .read_to_end(&mut bytes)
                .map_err(err)?;
            if bytes.len() > 16 * 1024 {
                return Err("claim request limit".into());
            }
            recovered.asset_claim(mode, &serde_json::from_slice::<Value>(&bytes).map_err(err)?)?
        }
        _ => return Err("invalid recovery mode".into()),
    };
    // A successful output always replaces the complete snapshot, never merges
    // new-chain claims with old-chain data. Check the pin again after replay.
    if rpc::call("get_tip_header", json!([]))?["hash"] != recovered.tip["hash"] {
        return Err("tip changed before export; retry".into());
    }
    let output = Path::new(&args[2]);
    atomic_json(output, &report)?;
    println!("Recovered pinned canonical snapshot; {}", args[3]);
    Ok(())
}
