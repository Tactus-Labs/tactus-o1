#!/usr/bin/env bash
# Execute the new guest against both full and split archived native publications.
set -euo pipefail
task_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$task_root"
mkdir -p artifacts
exec 9>artifacts/.proof-run.lock
flock -n 9 || { echo 'Another local proof experiment is running.' >&2; exit 1; }
run_dir="$(mktemp -d "$task_root/artifacts/native-guest-XXXXXXXX")"
echo "$run_dir"
bash scripts/build-native-proof-guest.sh > "$run_dir/guest-build.txt" 2>&1
CARGO_TARGET_DIR="$task_root/artifacts/prover-host/target" CARGO_BUILD_JOBS=4 cargo +1.97.1 build --release --locked --manifest-path proofs/native-sp1/Cargo.toml -p tactus-o1-native-sp1-host > "$run_dir/host-build.txt" 2>&1
host="$task_root/artifacts/prover-host/target/release/tactus-o1-native-sp1-host"
guest="$task_root/proofs/native-sp1/target/elf-compilation/riscv64im-succinct-zkvm-elf/release/tactus-o1-native-sp1-guest"
export RAYON_NUM_THREADS=4 TOKIO_WORKER_THREADS=4
for prefix in 0 1; do
  cargo run --locked --quiet --manifest-path proofs/native-sp1/Cargo.toml -p tactus-o1-native-proof-journal --example publication-input -- "$prefix" > "$run_dir/input-$prefix.json"
  "$host" "$guest" "$run_dir/input-$prefix.json" "$run_dir/execute-$prefix" > "$run_dir/execute-$prefix.txt" 2>&1
done
python3 - "$run_dir" "$guest" "$host" <<'PY'
import hashlib,json,pathlib,sys
run,guest,host=map(pathlib.Path,sys.argv[1:])
paths=[pathlib.Path('Cargo.lock'),pathlib.Path('contracts/bridge/NativeCKB.json'),pathlib.Path('scripts/build-native-proof-guest.sh'),pathlib.Path('scripts/run-native-guest-experiment.sh')]
paths+=sorted(p for base in ['crates/tactus-o1-execution','crates/tactus-o1-protocol','proofs/native-sp1'] for p in pathlib.Path(base).rglob('*') if p.is_file() and 'target' not in p.parts)
paths+=sorted(p for p in pathlib.Path('specs/evidence/native-publication').rglob('*') if p.is_file())
manifest={'schema':'native-guest-execution-v2','guest_sha256':hashlib.sha256(guest.read_bytes()).hexdigest(),'host_sha256':hashlib.sha256(host.read_bytes()).hexdigest(),'inputs':{str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in paths},'proof_generated':False,'ckb_settlement':False,'custody_release':False,'production_ready':False}
(run/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
PY
python3 -B scripts/check-native-guest.py "$run_dir" > "$run_dir/check.json"
cat "$run_dir/check.json"
