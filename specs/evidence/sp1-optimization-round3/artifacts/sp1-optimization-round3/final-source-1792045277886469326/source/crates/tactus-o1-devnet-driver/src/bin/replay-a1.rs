//! Real CKB-VM safety and stale-head regression, with two independent actors.
use serde_json::json;
use tactus_o1_devnet_driver::{
    lab::{self, Lab},
    tx::TX_FEE,
};
use tactus_o1_ordering_script::ckb_blake2b;
fn run() -> Result<(), String> {
    let mut lab = Lab::connect()?;
    let outcome = (|| {
        let mut head = lab.create_head(0)?;
        let message = ckb_blake2b(b"a1-message");
        let next = lab::enqueue(&head, &message);
        lab.advance(
            "E1 independent actor enqueue",
            &mut head,
            next,
            &message,
            1,
            &[],
        )?;
        let batch = ckb_blake2b(b"a1-batch");
        let next = lab::append(&head, &batch);
        lab.advance("E2 builder append", &mut head, next, &batch, 0, &[])?;
        let next = lab::enqueue(&head, &message);
        let stale = lab.transition_tx(&head, next, &message, 1, 10 * TX_FEE, &[])?;
        let next = lab::append(&head, &batch);
        lab.advance(
            "E3 consume head before wallet broadcasts",
            &mut head,
            next,
            &batch,
            0,
            &[],
        )?;
        lab.reject(
            "E3 stale head at 10x fee",
            &stale,
            "TransactionFailedToResolve",
        )?;
        let mut next = lab::append(&head, &batch);
        next.da_policy_id = [12; 32];
        let bad = lab.transition_tx(&head, next, &batch, 1, TX_FEE, &[])?;
        lab.reject("E4 immutable policy mutation", &bad, "error code 3")?;
        Ok::<_, String>(())
    })();
    lab.save(
        "artifacts/a1-evidence.json",
        json!({"passed":outcome.is_ok(),"error":outcome.as_ref().err(),"G2":"OPEN"}),
    )?;
    outcome
}
fn main() {
    if let Err(error) = run() {
        eprintln!("A1 FAILED: {error}");
        std::process::exit(1);
    }
}
