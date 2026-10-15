#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p artifacts
export RUSTFLAGS="${RUSTFLAGS:+$RUSTFLAGS }--cfg tactus_ckb_single_thread --check-cfg=cfg(tactus_ckb_single_thread)"
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-2}"
cargo build --locked --release --manifest-path proofs/ckb-settlement/Cargo.toml --target riscv64imac-unknown-none-elf
settlement_lld="$(rustc --print sysroot)/lib/rustlib/$(rustc -vV | sed -n 's/^host: //p')/bin/rust-lld"
temporary="$(mktemp "$PWD/artifacts/settlement-XXXXXXXX.elf")"
trap 'rm -f "$temporary"' EXIT
"$settlement_lld" -flavor gnu -o "$temporary" \
  proofs/ckb-settlement/target/riscv64imac-unknown-none-elf/release/libtactus_o1_settlement_script.a \
  --entry _start -nostdlib --gc-sections --strip-all \
  -T scripts/ordering-script.ld -z max-page-size=0x1000 -z separate-code
mv "$temporary" artifacts/tactus_o1_settlement_script.elf
sha256sum artifacts/tactus_o1_settlement_script.elf
