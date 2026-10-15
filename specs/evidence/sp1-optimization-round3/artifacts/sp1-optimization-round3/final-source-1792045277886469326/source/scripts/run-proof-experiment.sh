#!/usr/bin/env bash
set -euo pipefail
task_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$task_root"
case_index="${1:-0}"
[[ "$case_index" =~ ^[0-8]$ ]] || { echo 'Expected Geth fixture case index 0..8' >&2; exit 1; }
proof_mode="${2:-prove}"
case "$proof_mode" in prove|prove-groth16) ;; *) echo 'Expected prove or prove-groth16' >&2; exit 1 ;; esac
host_features=()
if [[ "$proof_mode" == prove-groth16 ]]; then
  : "${SP1_GROTH16_CIRCUIT_PATH:?Set the directory containing released v6.1.0 Groth16 circuit artifacts}"
  [[ -f "$SP1_GROTH16_CIRCUIT_PATH/v6.1.0/groth16_vk.bin" && -f "$SP1_GROTH16_CIRCUIT_PATH/v6.1.0/groth16_pk.bin" ]] || { echo 'Released circuit files are missing' >&2; exit 1; }
  export SP1_CIRCUIT_MODE=release
  host_features=(--features native-gnark)
fi
mkdir -p artifacts
exec 9>artifacts/.proof-run.lock
flock -n 9 || { echo 'Another local proof experiment is running.' >&2; exit 1; }
run_dir="$(mktemp -d "$task_root/artifacts/execution-proof-$case_index-XXXXXXXX")"
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-4}"
scripts/build-proof-guest.sh > "$run_dir/guest-build.txt" 2>&1
export CARGO_TARGET_DIR="$task_root/artifacts/prover-host/target"
cargo +1.97.1 build --release --locked --manifest-path proofs/sp1/Cargo.toml -p tactus-o1-sp1-host "${host_features[@]}" > "$run_dir/host-build.txt" 2>&1
# Bound concurrency on the reference CPU host without disabling verification.
export RAYON_NUM_THREADS=4 TOKIO_WORKER_THREADS=4
export SP1_WORKER_NUM_CORE_WORKERS=1 SP1_WORKER_CORE_BUFFER_SIZE=1
export SP1_WORKER_NUM_SETUP_WORKERS=1 SP1_WORKER_SETUP_BUFFER_SIZE=1
export SP1_WORKER_NUM_PREPARE_REDUCE_WORKERS=1 SP1_WORKER_PREPARE_REDUCE_BUFFER_SIZE=1
export SP1_WORKER_NUM_RECURSION_EXECUTOR_WORKERS=1 SP1_WORKER_RECURSION_EXECUTOR_BUFFER_SIZE=1
export SP1_WORKER_NUM_RECURSION_PROVER_WORKERS=1 SP1_WORKER_RECURSION_PROVER_BUFFER_SIZE=1
export GOMAXPROCS=4 RUST_LOG=info
export ELEMENT_THRESHOLD=50331648 HEIGHT_THRESHOLD=524288 SHARD_SIZE=1048576
unset WITHOUT_VK_VERIFICATION SP1_DUMP
host="$CARGO_TARGET_DIR/release/tactus-o1-sp1-host"
guest_dir="$task_root/proofs/sp1/target/elf-compilation/riscv64im-succinct-zkvm-elf/release"
fixture="$task_root/specs/test-vectors/execution-v1/geth-1.17.8.json"
sha256sum "$host" "$guest_dir/tactus-o1-sp1-guest" "$guest_dir/tactus-o1-wrong-guest" Cargo.lock proofs/sp1/Cargo.lock "$fixture" > "$run_dir/input-hashes.txt"
if [[ "$proof_mode" == prove-groth16 ]]; then
  sha256sum "$SP1_GROTH16_CIRCUIT_PATH/v6.1.0/"* > "$run_dir/circuit-hashes.txt"
fi
printf 'Proof experiment: %s\n' "$run_dir"
/usr/bin/time -v "$host" "$proof_mode" "$guest_dir/tactus-o1-sp1-guest" "$fixture" "$case_index" "$run_dir/proof" "$guest_dir/tactus-o1-wrong-guest" > "$run_dir/prove.txt" 2>&1
"$host" verify "$guest_dir/tactus-o1-sp1-guest" "$fixture" "$case_index" "$run_dir/proof" > "$run_dir/fresh-verification.txt" 2>&1
printf 'Verified real local proof: %s\n' "$run_dir/proof/result.json"
