#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p artifacts
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-2}"
cargo rustc --crate-type staticlib --locked --release --manifest-path proofs/ckb-state-proof/Cargo.toml --target riscv64imac-unknown-none-elf
state_proof_lld="$(rustc --print sysroot)/lib/rustlib/$(rustc -vV | sed -n 's/^host: //p')/bin/rust-lld"
state_proof_temporary="$(mktemp "$PWD/artifacts/state-proof-XXXXXXXX.elf")"
trap 'rm -f "$state_proof_temporary"' EXIT
"$state_proof_lld" -flavor gnu -o "$state_proof_temporary" \
  proofs/ckb-state-proof/target/riscv64imac-unknown-none-elf/release/libtactus_o1_state_proof_script.a \
  --entry _start -nostdlib --gc-sections --strip-all \
  -T scripts/ordering-script.ld -z max-page-size=0x1000 -z separate-code
mv "$state_proof_temporary" artifacts/tactus_o1_state_proof_script.elf
sha256sum artifacts/tactus_o1_state_proof_script.elf
