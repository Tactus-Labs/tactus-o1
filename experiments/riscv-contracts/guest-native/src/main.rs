//! Unbuilt/unexecuted static-link kernel prototype, not a contract sandbox.
#![no_main]
use tactus_riscv_research_model::{journal, kernel};
sp1_zkvm::entrypoint!(main);
fn main() {
    let seed: [u8; 32] = sp1_zkvm::io::read();
    let steps: u32 = sp1_zkvm::io::read();
    let (success, result) = kernel(seed, steps);
    sp1_zkvm::io::commit_slice(&journal(seed, steps, success, result));
}
