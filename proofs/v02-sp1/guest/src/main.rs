#![no_main]
use tactus_o1_protocol::v02::{Config, Policy, Wire};
sp1_zkvm::entrypoint!(main);
fn main() {
    let config = Config::decode(&sp1_zkvm::io::read_vec()).expect("config");
    let policy = Policy::decode(&sp1_zkvm::io::read_vec()).expect("policy");
    let allocation = sp1_zkvm::io::read_vec();
    let prefix: u64 = sp1_zkvm::io::read();
    let interval: u64 = sp1_zkvm::io::read();
    let journal =
        tactus_v02_proof_journal::execute(config, policy, &allocation, prefix, interval, || {
            Ok(sp1_zkvm::io::read_vec())
        })
        .expect("complete 0.02 execution");
    sp1_zkvm::io::commit_slice(&journal.encode().expect("journal"));
}
