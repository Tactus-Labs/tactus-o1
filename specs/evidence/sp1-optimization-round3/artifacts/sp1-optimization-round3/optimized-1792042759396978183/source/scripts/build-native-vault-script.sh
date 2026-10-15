#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p artifacts
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-2}"
cargo build --locked --release --manifest-path proofs/ckb-native-vault/Cargo.toml --target riscv64imac-unknown-none-elf
vault_lld="$(rustc --print sysroot)/lib/rustlib/$(rustc -vV | sed -n 's/^host: //p')/bin/rust-lld"
vault_temporary="$(mktemp "$PWD/artifacts/native-vault-XXXXXXXX.elf")"
trap 'rm -f "$vault_temporary"' EXIT
"$vault_lld" -flavor gnu -o "$vault_temporary" \
  proofs/ckb-native-vault/target/riscv64imac-unknown-none-elf/release/libtactus_o1_native_vault_script.a \
  --entry _start -nostdlib --gc-sections --strip-all \
  -T scripts/ordering-script.ld -z max-page-size=0x1000 -z separate-code
mv "$vault_temporary" artifacts/tactus_o1_native_vault_script.elf
sha256sum artifacts/tactus_o1_native_vault_script.elf
