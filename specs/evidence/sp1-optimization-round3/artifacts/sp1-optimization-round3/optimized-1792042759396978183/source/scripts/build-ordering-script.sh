#!/usr/bin/env bash
# Builds the OrderingHead type script ELF for CKB-VM.
#
# The Rust→CKB-VM chain: host-tested validation core (cargo test) →
# riscv64imac staticlib → rust-lld static ELF with _start entry.
# Note: cdylib is dropped by recent rustc on none-elf targets, so the
# final ELF is linked directly from the staticlib archive.
set -euo pipefail
cd "$(dirname "$0")/.."

# Serialize the shared final artifacts across independently running devnet suites.
# Cargo's target lock does not protect the later standalone linker invocations.
mkdir -p artifacts
exec 9>artifacts/.script-build.lock
flock 9
script_build_dir="$(mktemp -d "$PWD/artifacts/script-build-XXXXXXXX")"
trap 'rm -rf "$script_build_dir"' EXIT
rustup target add riscv64imac-unknown-none-elf
cargo build --locked --release --target riscv64imac-unknown-none-elf \
  -p tactus-o1-ordering-script -p tactus-o1-head-lock -p tactus-o1-anchor-script -p tactus-o1-priority-script -p tactus-o1-sealed-script

LLD="$(rustc --print sysroot)/lib/rustlib/$(rustc -vV | sed -n 's/^host: //p')/bin/rust-lld"
mkdir -p artifacts
for name in tactus_o1_ordering_script tactus_o1_head_lock tactus_o1_anchor_script tactus_o1_priority_script tactus_o1_sealed_script; do
  "$LLD" -flavor gnu \
    -o "$script_build_dir/$name.elf" \
    "target/riscv64imac-unknown-none-elf/release/lib$name.a" \
    --entry _start -nostdlib --gc-sections --strip-all \
    -T scripts/ordering-script.ld -z max-page-size=0x1000 -z separate-code
  mv "$script_build_dir/$name.elf" "artifacts/$name.elf"
  sha256sum "artifacts/$name.elf"
done
