#![no_main]
sp1_zkvm::entrypoint!(main);
fn main() {
    use tactus_o1_sparse_journal::{self as journal, Domain};
    let domain = Domain::decode(&sp1_zkvm::io::read_vec()).unwrap();
    let mode: u8 = sp1_zkvm::io::read();
    let journal = match mode {
        0 => {
            let allocation = sp1_zkvm::io::read_vec();
            let witness = sp1_zkvm::io::read_vec();
            let count: u64 = sp1_zkvm::io::read();
            journal::execute_genesis(domain, &allocation, &witness, count, sp1_zkvm::io::read_vec)
        }
        1 => {
            let commitment: [u8; 32] = sp1_zkvm::io::read();
            let boundary = journal::decode_boundary(&sp1_zkvm::io::read_vec()).unwrap();
            let witness = sp1_zkvm::io::read_vec();
            let count: u64 = sp1_zkvm::io::read();
            journal::execute_continuation(
                domain,
                commitment,
                &boundary,
                &witness,
                count,
                sp1_zkvm::io::read_vec,
            )
        }
        _ => panic!("unknown sparse proof mode"),
    }
    .unwrap();
    sp1_zkvm::io::commit_slice(&journal.encode());
}
