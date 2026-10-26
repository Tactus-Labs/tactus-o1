#!/usr/bin/env bash
# Isolated loopback CKB acceptance only. No CI, prover, or RISC-V contract experiment.
set -euo pipefail
cd "$(dirname "$0")/.."
v02_node="$(command -v "${TACTUS_V02_CKB_BIN:-ckb}")"
[[ "$("$v02_node" --version)" == 'ckb 0.210.0 '* ]] || { echo 'CKB 0.210.0 is required.' >&2; exit 1; }
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-4}"
scripts/build-v02-script.sh
cargo build --locked --offline --manifest-path services/v02-lab/Cargo.toml
export TACTUS_CKB_RPC_ADDR="127.0.0.1:${TACTUS_V02_RPC_PORT:-18724}"
export TACTUS_DEVNET_AUTOMINE=1
v02_p2p="${TACTUS_V02_P2P_PORT:-18725}"
export TACTUS_RUN_DIR="$(mktemp -d "$PWD/artifacts/v02-canonical-XXXXXXXX")"
export TACTUS_EVIDENCE_PATH="$TACTUS_RUN_DIR/evidence.json"
export TACTUS_V02_P2P_PORT="$v02_p2p"
export TACTUS_DEVNET_P2P_PORT="$v02_p2p"
export TACTUS_PEER_RPC_ADDR="127.0.0.1:${TACTUS_V02_PEER_RPC_PORT:-18726}"
export TACTUS_V02_PEER_P2P_PORT="${TACTUS_V02_PEER_P2P_PORT:-18727}"
python3 - <<'PY'
import socket,os
ports=[int(os.environ['TACTUS_CKB_RPC_ADDR'].split(':')[1]),int(os.environ['TACTUS_V02_P2P_PORT']),int(os.environ['TACTUS_PEER_RPC_ADDR'].split(':')[1]),int(os.environ['TACTUS_V02_PEER_P2P_PORT'])]
assert len(set(ports))==4
for port in ports:
 with socket.socket() as s:
  s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
  try:s.bind(('127.0.0.1',port));s.listen(1)
  except OSError:raise SystemExit(f'Port {port} is occupied; refusing to touch an existing node')
PY
"$v02_node" init -C "$TACTUS_RUN_DIR/node" --chain dev --rpc-port "${TACTUS_CKB_RPC_ADDR##*:}" --p2p-port "$v02_p2p" \
  --ba-arg 0xc155c0113355a061173d1ff21075ec37754ec1ca --genesis-message tactus-v02-canonical-acceptance > "$TACTUS_RUN_DIR/init.log"
python3 - <<'PY'
import os,pathlib,shutil
root=pathlib.Path(os.environ['TACTUS_RUN_DIR'])/'node'
p=root/'ckb.toml';s=p.read_text().replace('"Experiment", "Debug"','"Experiment", "Debug", "IntegrationTest"').replace('/ip4/0.0.0.0/','/ip4/127.0.0.1/')
assert '"IntegrationTest"' in s
p.write_text(s)
p=root/'specs/dev.toml';s=p.read_text();i=s.index('[params]')
s=s[:i]+'''[[genesis.issued_cells]]
capacity = 20000000000000000
lock.code_hash = "0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8"
lock.args = "0xc155c0113355a061173d1ff21075ec37754ec1ca"
lock.hash_type = "type"

'''+s[i:]
p.write_text(s)
peer=root.parent/'peer';shutil.copytree(root,peer)
p=peer/'ckb.toml';p.write_text(p.read_text().replace(os.environ['TACTUS_CKB_RPC_ADDR'],os.environ['TACTUS_PEER_RPC_ADDR']).replace('/tcp/'+os.environ['TACTUS_V02_P2P_PORT']+'"','/tcp/'+os.environ['TACTUS_V02_PEER_P2P_PORT']+'"'))
PY
"$v02_node" run -C "$TACTUS_RUN_DIR/node" --indexer > "$TACTUS_RUN_DIR/node.log" 2>&1 &
v02_pid=$!
"$v02_node" run -C "$TACTUS_RUN_DIR/peer" --indexer > "$TACTUS_RUN_DIR/peer.log" 2>&1 &
v02_peer_pid=$!
cleanup(){ kill "$v02_pid" "$v02_peer_pid" 2>/dev/null || true; wait "$v02_pid" 2>/dev/null || true; wait "$v02_peer_pid" 2>/dev/null || true; }
trap cleanup EXIT
python3 - <<'PY'
import os,json,urllib.request,time
for address in [os.environ['TACTUS_CKB_RPC_ADDR'],os.environ['TACTUS_PEER_RPC_ADDR']]:
 for _ in range(100):
  try:
   r=urllib.request.Request('http://'+address,data=json.dumps({'jsonrpc':'2.0','id':1,'method':'get_tip_header','params':[]}).encode(),headers={'Content-Type':'application/json'})
   with urllib.request.urlopen(r,timeout=1) as response:
    if json.load(response).get('result'):break
  except (OSError,ValueError):pass
  time.sleep(.1)
 else:raise SystemExit('New isolated node did not become ready')
PY
printf '%s\n' "$TACTUS_RUN_DIR"
if ! services/v02-lab/target/debug/replay-v02 > "$TACTUS_RUN_DIR/driver.log" 2>&1; then
  cat "$TACTUS_RUN_DIR/driver.log"
  exit 1
fi
cat "$TACTUS_RUN_DIR/driver.log"
