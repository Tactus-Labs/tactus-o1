#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
bash scripts/build-native-vault-script.sh
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-2}"
cargo rustc --locked --release --manifest-path proofs/ckb-native-anchor/Cargo.toml --target riscv64imac-unknown-none-elf --crate-type staticlib
anchor_lld="$(rustc --print sysroot)/lib/rustlib/$(rustc -vV | sed -n 's/^host: //p')/bin/rust-lld"
anchor_temporary="$(mktemp "$PWD/artifacts/native-anchor-XXXXXXXX.elf")"
trap 'rm -f "$anchor_temporary"' EXIT
"$anchor_lld" -flavor gnu -o "$anchor_temporary" proofs/ckb-native-anchor/target/riscv64imac-unknown-none-elf/release/libtactus_o1_native_anchor_script.a \
  --entry _start -nostdlib --gc-sections --strip-all -T scripts/ordering-script.ld -z max-page-size=0x1000 -z separate-code
mv "$anchor_temporary" artifacts/tactus_o1_native_anchor_script.elf
sha256sum artifacts/tactus_o1_native_anchor_script.elf
