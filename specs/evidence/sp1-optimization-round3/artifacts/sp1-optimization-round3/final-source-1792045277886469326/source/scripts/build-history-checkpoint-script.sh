#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p artifacts
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-2}"
cargo build --locked --release --manifest-path proofs/ckb-history-checkpoint/Cargo.toml --target riscv64imac-unknown-none-elf
checkpoint_lld="$(rustc --print sysroot)/lib/rustlib/$(rustc -vV | sed -n 's/^host: //p')/bin/rust-lld"
temporary="$(mktemp "$PWD/artifacts/history-checkpoint-XXXXXXXX.elf")"
trap 'rm -f "$temporary"' EXIT
"$checkpoint_lld" -flavor gnu -o "$temporary" \
  proofs/ckb-history-checkpoint/target/riscv64imac-unknown-none-elf/release/libtactus_o1_history_checkpoint_script.a \
  --entry _start -nostdlib --gc-sections --strip-all \
  -T scripts/ordering-script.ld -z max-page-size=0x1000 -z separate-code
mv "$temporary" artifacts/tactus_o1_history_checkpoint_script.elf
sha256sum artifacts/tactus_o1_history_checkpoint_script.elf
