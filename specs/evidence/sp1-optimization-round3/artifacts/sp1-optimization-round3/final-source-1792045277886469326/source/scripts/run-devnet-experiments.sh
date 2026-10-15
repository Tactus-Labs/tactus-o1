#!/usr/bin/env bash
# Run against an isolated, funded, loopback-only chain. Never touches an existing node.
set -euo pipefail
cd "$(dirname "$0")/.."
CKB_BIN="${CKB_BIN:-ckb}"
CKB_BIN="$(command -v "$CKB_BIN")"
required_version="${TACTUS_CKB_VERSION:-0.210.0}"
if [[ "$required_version" != 0.210.0 ]]; then
  echo 'Supported laboratory version: 0.210.0.' >&2
  exit 1
fi
if [[ "$($CKB_BIN --version)" != "ckb $required_version "* ]]; then
  echo "Experiments require CKB $required_version; set CKB_BIN to that binary." >&2
  exit 1
fi
suite="${TACTUS_DEVNET_SUITE:-replay-a123}"
case "$suite" in replay-a123|replay-batch|replay-evm|replay-priority|replay-sealed|replay-admission|replay-network|replay-load|replay-seal-contention|replay-proof-verifier|replay-history-checkpoint|replay-checkpoint-reorg|replay-settlement-bootstrap|replay-sealed-settlement|replay-native-vault|replay-native-publication|replay-native-checkpoint|replay-native-settlement) ;; *) echo 'Unknown devnet suite' >&2; exit 1 ;; esac
if [[ -v TACTUS_SPARSE_SETTLEMENT ]]; then
  if [[ "$TACTUS_SPARSE_SETTLEMENT" != 1 || "$suite" != replay-settlement-bootstrap || ! "${TACTUS_SPARSE_GUEST_KEY:-}" =~ ^0x[[:xdigit:]]{64}$ ]]; then
    echo 'Sparse settlement requires explicit mode 1, bootstrap suite and the compiled sparse guest key.' >&2
    exit 1
  fi
elif [[ -v TACTUS_SPARSE_GUEST_KEY || -v TACTUS_SETTLEMENT_CONTINUATION_JSON ]]; then
  echo 'Sparse guest/continuation inputs require explicit sparse settlement mode.' >&2
  exit 1
fi
if [[ -v TACTUS_SETTLEMENT_CONTINUATION_JSON && ! -f "$TACTUS_SETTLEMENT_CONTINUATION_JSON" ]]; then
  echo 'Missing sparse continuation input.' >&2
  exit 1
fi
if [[ -v TACTUS_SETTLEMENT_REORG ]]; then
  if [[ "$TACTUS_SETTLEMENT_REORG" != 1 || "$suite" != replay-settlement-bootstrap || -z "${TACTUS_SETTLEMENT_PROOF_DIR:-}" || -v TACTUS_SECOND_SETTLEMENT_PROOF_DIR || -v TACTUS_PREPARE_SECOND_PROOF ]]; then
    echo 'Settlement reorg requires TACTUS_SETTLEMENT_REORG=1 and only a first real proof directory in the settlement suite.' >&2
    exit 1
  fi
fi
if [[ -v TACTUS_OBLIGATION_REORG ]]; then
  if [[ "$TACTUS_OBLIGATION_REORG" != 1 || "$suite" != replay-sealed-settlement || -v TACTUS_SEALED_PROOF_DIR ]]; then
    echo 'Obligation reorg requires TACTUS_OBLIGATION_REORG=1 in the A3 suite without a proof directory.' >&2
    exit 1
  fi
fi
if [[ -v TACTUS_OBLIGATION_CRASH && ( "$TACTUS_OBLIGATION_CRASH" != 1 || "${TACTUS_OBLIGATION_REORG:-}" != 1 ) ]]; then
  echo 'Obligation crash qualification requires TACTUS_OBLIGATION_CRASH=1 and TACTUS_OBLIGATION_REORG=1.' >&2
  exit 1
fi
if [[ -v TACTUS_SEALED_PROOF_REORG ]]; then
  if [[ "$TACTUS_SEALED_PROOF_REORG" != 1 || "$suite" != replay-sealed-settlement || -z "${TACTUS_SEALED_PROOF_DIR:-}" || -v TACTUS_OBLIGATION_REORG || -v TACTUS_OBLIGATION_CRASH ]]; then
    echo 'A3 proof reorg requires TACTUS_SEALED_PROOF_REORG=1 and a real A3 proof, without pending-duty reorg/crash modes.' >&2
    exit 1
  fi
fi
if [[ -v TACTUS_OBSERVER_RPC_BIN && ( "${TACTUS_OBLIGATION_REORG:-}" != 1 || ! -x "$TACTUS_OBSERVER_RPC_BIN" ) ]]; then
  echo 'Observer qualification requires the pending-duty P2P reorg and an executable TACTUS_OBSERVER_RPC_BIN.' >&2
  exit 1
fi
if [[ -v TACTUS_STATE_PROOFS_JSON && ( "$suite" != replay-sealed-settlement || -z "${TACTUS_SEALED_PROOF_DIR:-}" || -v TACTUS_SEALED_PROOF_REORG || -v TACTUS_OBLIGATION_REORG || ! -f "$TACTUS_STATE_PROOFS_JSON" ) ]]; then
  echo 'State witness qualification requires the A3 real proof suite, a witness file, and no reorg mode.' >&2
  exit 1
fi
if [[ -v TACTUS_STATE_PROOFS_JSON ]]; then bash scripts/build-state-proof-script.sh; fi
driver_binary="target/debug/$suite"
if [[ "$suite" == replay-native-vault || "$suite" == replay-native-publication || "$suite" == replay-native-checkpoint || "$suite" == replay-native-settlement ]]; then
  bash scripts/build-native-anchor-script.sh
  cargo build --locked --manifest-path services/native-vault-lab/Cargo.toml
  driver_binary="services/native-vault-lab/target/debug/$suite"
  if [[ "$suite" == replay-native-checkpoint || "$suite" == replay-native-settlement ]]; then
    bash scripts/build-native-checkpoint-script.sh
    if [[ "$suite" == replay-native-settlement ]]; then bash scripts/build-native-settlement-script.sh; fi
    driver_binary="services/native-vault-lab/target/debug/replay-native-publication"
  fi
else
  cargo build --locked --bin "$suite"
fi
export TACTUS_DRIVER_BINARY="$driver_binary"
if [[ "$suite" == replay-evm || "$suite" == replay-network ]]; then
  cargo build --locked --bin recover-execution
fi
if [[ "$suite" == replay-sealed || "$suite" == replay-network || "$suite" == replay-sealed-settlement ]]; then
  cargo build --locked --bin recover-sealed
fi
if [[ "$suite" == replay-sealed-settlement ]]; then
  cargo build --locked --bin recover-obligations
fi
bash scripts/build-ordering-script.sh
if [[ "$suite" == replay-proof-verifier ]]; then
  bash scripts/build-proof-check-script.sh
fi
if [[ "$suite" == replay-history-checkpoint || "$suite" == replay-checkpoint-reorg || "$suite" == replay-settlement-bootstrap || "$suite" == replay-sealed-settlement ]]; then
  bash scripts/build-history-checkpoint-script.sh
fi
if [[ "$suite" == replay-settlement-bootstrap || "$suite" == replay-sealed-settlement ]]; then
  if [[ "${TACTUS_SPARSE_SETTLEMENT:-}" == 1 ]]; then
    bash scripts/build-sparse-settlement-script.sh
  else
    bash scripts/build-settlement-script.sh
  fi
  cargo build --locked --bin recover-settlement
fi
mkdir -p artifacts
run_dir="$(mktemp -d "$PWD/artifacts/${suite#replay-}-XXXXXXXX")"
export TACTUS_CKB_RPC_ADDR="127.0.0.1:${TACTUS_DEVNET_RPC_PORT:-18714}"
export TACTUS_PEER_RPC_ADDR="127.0.0.1:${TACTUS_PEER_RPC_PORT:-18716}"
export TACTUS_DEVNET_AUTOMINE=1
export TACTUS_EVIDENCE_PATH="$run_dir/evidence.json"
export TACTUS_RUN_DIR="$run_dir"
export TACTUS_CKB_BIN="$CKB_BIN"
export TACTUS_DEVNET_SUITE="$suite"
python3 - <<'PY'
import os,socket
ports=[int(os.environ['TACTUS_CKB_RPC_ADDR'].split(':')[1]),int(os.getenv('TACTUS_DEVNET_P2P_PORT','18715'))]
if os.environ['TACTUS_DEVNET_SUITE'] in ('replay-network','replay-checkpoint-reorg') or os.getenv('TACTUS_SETTLEMENT_REORG') or os.getenv('TACTUS_OBLIGATION_REORG') or os.getenv('TACTUS_SEALED_PROOF_REORG'):ports.extend([int(os.environ['TACTUS_PEER_RPC_ADDR'].split(':')[1]),int(os.getenv('TACTUS_PEER_P2P_PORT','18717'))])
assert len(set(ports))==len(ports), 'Node ports must be distinct'
for port in ports:
 s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
 try:s.bind(('127.0.0.1',port));s.listen(1)
 except OSError:raise SystemExit(f'Port {port} is occupied; refusing to touch an existing node')
 finally:s.close()

PY
"$CKB_BIN" init -C "$run_dir/node" --chain dev --rpc-port "${TACTUS_DEVNET_RPC_PORT:-18714}" \
  --p2p-port "${TACTUS_DEVNET_P2P_PORT:-18715}" \
  --ba-arg 0xc155c0113355a061173d1ff21075ec37754ec1ca --genesis-message tactus-o1-experiment-a-v1 > "$run_dir/init.log"
python3 - <<'PY'
import os,pathlib,hashlib,json,subprocess,shutil
root=pathlib.Path(os.environ['TACTUS_RUN_DIR']);p=root/'node/ckb.toml'
s=p.read_text().replace('"Experiment", "Debug"','"Experiment", "Debug", "IntegrationTest"').replace('/ip4/0.0.0.0/','/ip4/127.0.0.1/')
assert '"IntegrationTest"' in s
p.write_text(s)
p=root/'node/specs/dev.toml';s=p.read_text();i=s.index('[params]')
s=s[:i]+'''[[genesis.issued_cells]]
capacity = 20000000000000000
lock.code_hash = "0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8"
lock.args = "0xc155c0113355a061173d1ff21075ec37754ec1ca"
lock.hash_type = "type"

'''+s[i:]
# Optional local resource envelope; never raises the laboratory's default limit.
if 'TACTUS_DEVNET_MAX_BLOCK_CYCLES' in os.environ:
 import re
 budget=int(os.environ['TACTUS_DEVNET_MAX_BLOCK_CYCLES'])
 assert 0 < budget <= 10_000_000_000, 'Invalid devnet cycle budget'
 s,count=re.subn(r'(?m)^max_block_cycles\s*=.*$', 'max_block_cycles = '+str(budget), s)
 assert count==1, 'Missing/ambiguous devnet cycle budget'
p.write_text(s)
if os.environ['TACTUS_DEVNET_SUITE'] in ('replay-network','replay-checkpoint-reorg') or os.getenv('TACTUS_SETTLEMENT_REORG') or os.getenv('TACTUS_OBLIGATION_REORG') or os.getenv('TACTUS_SEALED_PROOF_REORG'):
 shutil.copytree(root/'node',root/'peer')
 peer=root/'peer/ckb.toml'
 peer.write_text(peer.read_text().replace(os.environ['TACTUS_CKB_RPC_ADDR'],os.environ['TACTUS_PEER_RPC_ADDR']).replace('/tcp/'+os.getenv('TACTUS_DEVNET_P2P_PORT','18715')+'"','/tcp/'+os.getenv('TACTUS_PEER_P2P_PORT','18717')+'"'))
manifest={'node_version':subprocess.check_output([os.environ['TACTUS_CKB_BIN'],'--version'],text=True).strip(),
 'rustc':subprocess.check_output(['rustc','-Vv'],text=True),'git_head':subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip(),
 'git_diff_sha256':hashlib.sha256(subprocess.check_output(['git','diff','HEAD'])).hexdigest(),
 'files':{}}
for name in ['Cargo.lock','scripts/build-ordering-script.sh','scripts/ordering-script.ld','artifacts/tactus_o1_ordering_script.elf','artifacts/tactus_o1_head_lock.elf','artifacts/tactus_o1_anchor_script.elf','artifacts/tactus_o1_priority_script.elf','artifacts/tactus_o1_sealed_script.elf',str(root/'node/ckb.toml'),str(p),os.environ['TACTUS_CKB_BIN']]:
 manifest['files'][name]=hashlib.sha256(pathlib.Path(name).read_bytes()).hexdigest()
binaries=[os.environ['TACTUS_DRIVER_BINARY']]
if os.environ['TACTUS_DEVNET_SUITE'] in ('replay-native-vault','replay-native-publication','replay-native-checkpoint','replay-native-settlement'):binaries.extend(['artifacts/tactus_o1_native_vault_script.elf','artifacts/tactus_o1_native_anchor_script.elf','services/native-vault-lab/target/debug/recover-native-vault'])
if os.environ['TACTUS_DEVNET_SUITE'] in ('replay-native-checkpoint','replay-native-settlement'):binaries.append('artifacts/tactus_o1_native_checkpoint_script.elf')
if os.environ['TACTUS_DEVNET_SUITE']=='replay-native-settlement':binaries.append('artifacts/tactus_o1_native_settlement_script.elf')
if os.getenv('TACTUS_OBSERVER_RPC_BIN'):binaries.append(os.environ['TACTUS_OBSERVER_RPC_BIN'])
if os.getenv('TACTUS_STATE_PROOFS_JSON'):binaries.extend(['artifacts/tactus_o1_state_proof_script.elf',os.environ['TACTUS_STATE_PROOFS_JSON']])
if os.environ['TACTUS_DEVNET_SUITE'] in ('replay-evm','replay-network'):binaries.append('target/debug/recover-execution')
if os.environ['TACTUS_DEVNET_SUITE'] in ('replay-sealed','replay-network','replay-sealed-settlement'):binaries.append('target/debug/recover-sealed')
if os.environ['TACTUS_DEVNET_SUITE'] in ('replay-network','replay-checkpoint-reorg') or os.getenv('TACTUS_SETTLEMENT_REORG') or os.getenv('TACTUS_OBLIGATION_REORG') or os.getenv('TACTUS_SEALED_PROOF_REORG'):binaries.extend([str(root/'peer/ckb.toml'),str(root/'peer/specs/dev.toml')])
if os.environ['TACTUS_DEVNET_SUITE']=='replay-proof-verifier':
 binaries.append('artifacts/tactus_o1_proof_check_script.elf')
 proof_dir=pathlib.Path(os.environ['TACTUS_PROOF_DIR'])
 binaries.extend(str(proof_dir/name) for name in ['result.json','public-values.bin','groth16-proof.bin','proof.bin'])
if os.environ['TACTUS_DEVNET_SUITE'] in ('replay-history-checkpoint','replay-checkpoint-reorg','replay-settlement-bootstrap','replay-sealed-settlement'):
 binaries.append('artifacts/tactus_o1_history_checkpoint_script.elf')
if os.environ['TACTUS_DEVNET_SUITE'] in ('replay-settlement-bootstrap','replay-sealed-settlement'):
 binaries.append('target/debug/recover-settlement')
 if os.getenv('TACTUS_SPARSE_SETTLEMENT')=='1':
  binaries.append('artifacts/tactus_o1_sparse_settlement_script.elf')
  manifest['sparse_settlement']={'guest_key':os.environ['TACTUS_SPARSE_GUEST_KEY'],'profile':'TO1SPF01','local_experiment_only':True}
  if os.getenv('TACTUS_SETTLEMENT_CONTINUATION_JSON'):binaries.append(os.environ['TACTUS_SETTLEMENT_CONTINUATION_JSON'])
 else:binaries.extend(['artifacts/tactus_o1_settlement_script.elf','specs/evidence/execution-core-proof/result.json'])
 for key in ['TACTUS_SETTLEMENT_PROOF_DIR','TACTUS_SECOND_SETTLEMENT_PROOF_DIR','TACTUS_SEALED_PROOF_DIR']:
  if key in os.environ:
   proof_dir=pathlib.Path(os.environ[key])
   binaries.extend(str(proof_dir/name) for name in ['result.json','public-values.bin','groth16-proof.bin','proof.bin'])
if os.environ['TACTUS_DEVNET_SUITE']=='replay-sealed-settlement':binaries.append('target/debug/recover-obligations')
for name in binaries:manifest['files'][name]=hashlib.sha256(pathlib.Path(name).read_bytes()).hexdigest()

paths=subprocess.check_output(['git','ls-files','--cached','--others','--exclude-standard','-z'],text=True).split('\0')
manifest['source_files']={name:hashlib.sha256(pathlib.Path(name).read_bytes()).hexdigest()
 for name in sorted(set(paths)) if name and pathlib.Path(name).is_file()
 and (name.startswith(('crates/','proofs/','services/','contracts/','scripts/','.github/','.cargo/','specs/test-vectors/')) or name in ('Cargo.toml','Cargo.lock','rust-toolchain.toml'))}
(root/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
PY
"$CKB_BIN" run -C "$run_dir/node" --indexer > "$run_dir/node.log" 2>&1 &
node_pid=$!
peer_pid=""
cleanup() {
  kill "$node_pid" 2>/dev/null || true
  if [[ -n "$peer_pid" ]]; then kill "$peer_pid" 2>/dev/null || true; wait "$peer_pid" 2>/dev/null || true; fi
  wait "$node_pid" 2>/dev/null || true
}
trap cleanup EXIT
if [[ "$suite" == replay-network || "$suite" == replay-checkpoint-reorg || -n "${TACTUS_SETTLEMENT_REORG:-}" || -n "${TACTUS_OBLIGATION_REORG:-}" || -n "${TACTUS_SEALED_PROOF_REORG:-}" ]]; then
  "$CKB_BIN" run -C "$run_dir/peer" --indexer > "$run_dir/peer.log" 2>&1 &
  peer_pid=$!
fi
python3 - <<'PY'
import os,urllib.request,json,time
addresses=[os.environ['TACTUS_CKB_RPC_ADDR']]
if os.environ['TACTUS_DEVNET_SUITE'] in ('replay-network','replay-checkpoint-reorg') or os.getenv('TACTUS_SETTLEMENT_REORG') or os.getenv('TACTUS_OBLIGATION_REORG') or os.getenv('TACTUS_SEALED_PROOF_REORG'):addresses.append(os.environ['TACTUS_PEER_RPC_ADDR'])
for address in addresses:
 url='http://'+address
 for _ in range(150):
  try:
   req=urllib.request.Request(url,json.dumps({'jsonrpc':'2.0','id':1,'method':'get_tip_block_number','params':[]}).encode(),{'Content-Type':'application/json'})
   if json.load(urllib.request.urlopen(req,timeout=1))['result']=='0x0':break
  except (OSError,KeyError):pass
  time.sleep(.1)
 else:raise SystemExit('Isolated CKB node did not start at genesis: '+address)

PY
printf 'Evidence directory: %s\n' "$run_dir"
"$driver_binary" 2>&1 | tee "$run_dir/replay.log"
if [[ "${TACTUS_OBLIGATION_CRASH:-}" == 1 ]]; then
  crash_old_pid="$node_pid"
  kill -KILL "$node_pid"
  set +e
  wait "$node_pid"
  crash_status=$?
  set -e
  [[ "$crash_status" == 137 ]] || { echo 'Primary child did not exit from SIGKILL.' >&2; exit 1; }
  node_pid=""
  python3 -B scripts/qualify-obligation-restart.py peer-after-crash "$run_dir" "$crash_old_pid" 0 "$crash_status"
  "$CKB_BIN" run -C "$run_dir/node" --indexer > "$run_dir/restarted-node.log" 2>&1 &
  node_pid=$!
  python3 -B scripts/qualify-obligation-restart.py after-restart "$run_dir" "$crash_old_pid" "$node_pid" "$crash_status"
fi
if [[ "$suite" == replay-admission ]]; then
  python3 -B scripts/check-admission-fees.py "$run_dir/evidence.json" > "$run_dir/fee-check.json"
fi
if [[ "$suite" == replay-native-vault ]]; then
  python3 -B scripts/check-native-vault.py "$run_dir/evidence.json" > "$run_dir/vault-check.json"
  python3 -B scripts/check-native-vault-recovery.py "$run_dir" > "$run_dir/recovery-check.json"
fi
python3 scripts/summarize-experiments.py "$run_dir/evidence.json" "$run_dir/summary.json"
printf 'Complete: %s\n' "$run_dir/summary.json"
