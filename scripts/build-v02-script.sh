#!/usr/bin/env bash
# Local build only. Does not run a prover, RISC-V comparison, CI or deployment.
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p artifacts
exec 9>artifacts/.v02-script-build.lock
flock 9
export RUSTFLAGS="${RUSTFLAGS:+$RUSTFLAGS }--cfg tactus_ckb_single_thread --check-cfg=cfg(tactus_ckb_single_thread)"
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-2}"
cargo rustc --locked --release --manifest-path proofs/ckb-v02/Cargo.toml \
  --target riscv64imac-unknown-none-elf --crate-type staticlib
v02_lld="$(rustc --print sysroot)/lib/rustlib/$(rustc -vV | sed -n 's/^host: //p')/bin/rust-lld"
v02_temporary="$(mktemp "$PWD/artifacts/v02-script-XXXXXXXX.elf")"
trap 'rm -f "$v02_temporary"' EXIT
"$v02_lld" -flavor gnu -o "$v02_temporary" \
  proofs/ckb-v02/target/riscv64imac-unknown-none-elf/release/libtactus_v02_script.a \
  --entry _start -nostdlib --gc-sections --strip-all \
  -T scripts/ordering-script.ld -z max-page-size=0x1000 -z separate-code
mv "$v02_temporary" artifacts/tactus_v02_script.elf
sha256sum artifacts/tactus_v02_script.elf
