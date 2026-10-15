#![no_main]
sp1_zkvm::entrypoint!(main);
fn main() {
    let domain = tactus_o1_proof_journal::Domain::decode(&sp1_zkvm::io::read_vec()).unwrap();
    let allocation = sp1_zkvm::io::read_vec();
    let prefix_batches: u64 = sp1_zkvm::io::read();
    let interval_batches: u64 = sp1_zkvm::io::read();
    let journal = tactus_o1_proof_journal::execute(
        domain,
        &allocation,
        prefix_batches,
        interval_batches,
        sp1_zkvm::io::read_vec,
    )
    .unwrap();
    sp1_zkvm::io::commit_slice(&journal.encode());
}
