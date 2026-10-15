//! Distinct valid ELF used only for the wrong verification-key rejection control.
#![no_main]
sp1_zkvm::entrypoint!(main);
fn main() {
    sp1_zkvm::io::commit_slice(b"tactus/o1/wrong-guest-control");
}
