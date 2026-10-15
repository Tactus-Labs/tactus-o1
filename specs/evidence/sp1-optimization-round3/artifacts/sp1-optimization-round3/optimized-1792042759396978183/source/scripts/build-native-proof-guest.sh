#!/usr/bin/env bash
set -euo pipefail
task_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
proof_tool="${TACTUS_CARGO_PROVE:-$task_root/artifacts/prover-tools/cargo-prove}"
if [[ ! -x "$proof_tool" ]]; then
  echo 'Set TACTUS_CARGO_PROVE to the official SP1 6.8.1 cargo-prove executable.' >&2
  exit 1
fi
if [[ "$("$proof_tool" prove --version)" != *c84ada1* ]]; then
  echo 'This experiment requires the pinned SP1 6.8.1 CLI (c84ada1).' >&2
  exit 1
fi
export CC_riscv64im_succinct_zkvm_elf="${TACTUS_PROOF_CC:-clang}"
# Clang defaults to compressed/atomic RISC-V extensions, unsupported by this VM.
# The header supplies declarations only; the linked guest supplies memory routines.
export CFLAGS_riscv64im_succinct_zkvm_elf="--target=riscv64-unknown-elf -march=rv64im -mabi=lp64 -I$task_root/proofs/sp1/guest -include $task_root/proofs/sp1/guest/string.h"
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-4}"
cd "$task_root/proofs/native-sp1"
"$proof_tool" prove build --locked -p tactus-o1-native-sp1-guest
elf="$task_root/proofs/native-sp1/target/elf-compilation/riscv64im-succinct-zkvm-elf/release/tactus-o1-native-sp1-guest"
if readelf -h "$elf" | rg -q RVC; then
  echo 'Guest contains unsupported compressed instructions.' >&2
  exit 1
fi
sha256sum "$elf"
