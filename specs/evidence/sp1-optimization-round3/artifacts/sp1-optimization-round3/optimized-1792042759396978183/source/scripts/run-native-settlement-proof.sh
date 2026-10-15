#!/usr/bin/env bash
# Resume only a retained isolated 0.210.0 laboratory node, then settle one proof.
set -euo pipefail
cd "$(dirname "$0")/.."
[[ $# == 3 ]] || { echo 'Usage: run-native-settlement-proof.sh BOOTSTRAP_RUN INPUT_JSON VERIFIED_PROOF_DIR' >&2; exit 1; }
bootstrap="$(realpath "$1")"
input_file="$(realpath "$2")"
proof_dir="$(realpath "$3")"
[[ -s "$proof_dir/public-values.bin" && -s "$proof_dir/groth16-proof.bin" && -d "$bootstrap/node/data/db" ]] || { echo 'Retained node database and completed proof required.' >&2; exit 1; }
CKB_BIN="$(command -v "${CKB_BIN:-ckb}")"
[[ "$("$CKB_BIN" --version)" == 'ckb 0.210.0 '* ]] || { echo 'CKB 0.210.0 required.' >&2; exit 1; }
exec 9>"$bootstrap/.resume.lock"
flock -n 9 || { echo 'This retained experiment is already in use.' >&2; exit 1; }
export TACTUS_CKB_RPC_ADDR="$(python3 - "$bootstrap" <<'PY'
import hashlib,json,pathlib,re,socket,sys,tomllib
root=pathlib.Path(sys.argv[1]);manifest=json.loads((root/'manifest.json').read_text());e=json.loads((root/'evidence.json').read_text())
assert e['results']['suite']=='native-settlement-bootstrap-v2' and e['results']['complete'] is True
assert manifest['node_version'].startswith('ckb 0.210.0 ')
for name in ['node/ckb.toml','node/specs/dev.toml']:
 p=root/name;assert manifest['files'][str(p)]==hashlib.sha256(p.read_bytes()).hexdigest(), 'retained configuration changed'
cfg=tomllib.loads((root/'node/ckb.toml').read_text());addr=cfg['rpc']['listen_address']
m=re.fullmatch(r'127\.0\.0\.1:(\d+)',addr);assert m and int(m[1])!=8114,'isolated RPC required'
ports=[int(m[1])]
for item in cfg['network']['listen_addresses']:
 m=re.fullmatch(r'/ip4/127\.0\.0\.1/tcp/(\d+)',item);assert m,'loopback P2P required';ports.append(int(m[1]))
assert len(ports)==len(set(ports))
for port in ports:
 with socket.socket() as sock:sock.bind(('127.0.0.1',port));sock.listen(1)
print(addr)
PY
)"
[[ "$TACTUS_CKB_RPC_ADDR" == 127.0.0.1:* ]] || exit 1
export TACTUS_DEVNET_AUTOMINE=1
run_dir="$(mktemp -d "$PWD/artifacts/native-proof-settlement-XXXXXXXX")"
echo "$run_dir"
CARGO_BUILD_JOBS=1 cargo build --locked --manifest-path services/native-vault-lab/Cargo.toml --bin settle-native-proof > "$run_dir/build.txt" 2>&1
sha256sum services/native-vault-lab/target/debug/settle-native-proof services/native-vault-lab/src/bin/settle-native-proof.rs "$bootstrap/evidence.json" "$input_file" "$proof_dir/groth16-proof.bin" "$proof_dir/public-values.bin" "$bootstrap/node/ckb.toml" "$bootstrap/node/specs/dev.toml" "$CKB_BIN" > "$run_dir/input-hashes.txt"
"$CKB_BIN" run -C "$bootstrap/node" --indexer > "$run_dir/node.log" 2>&1 &
node_pid=$!
cleanup() { kill "$node_pid" 2>/dev/null || true; wait "$node_pid" 2>/dev/null || true; }
trap cleanup EXIT
python3 - "$run_dir" <<'PY'
import json,os,pathlib,time,urllib.request,sys
addr=os.environ['TACTUS_CKB_RPC_ADDR']
def rpc(method):
 req=urllib.request.Request('http://'+addr,data=json.dumps({'id':1,'jsonrpc':'2.0','method':method,'params':[]}).encode(),headers={'Content-Type':'application/json'})
 with urllib.request.urlopen(req,timeout=1) as response:return json.load(response)['result']
for _ in range(120):
 try:
  tip=rpc('get_tip_header');indexed=rpc('get_indexer_tip')
  if indexed and indexed['block_hash']==tip['hash']:
   pathlib.Path(sys.argv[1],'starting-tip.json').write_text(json.dumps(tip,indent=2)+'\n');break
 except (OSError,ValueError,KeyError):pass
 time.sleep(0.25)
else:raise SystemExit('Owned node/indexer did not become ready')
PY
services/native-vault-lab/target/debug/settle-native-proof "$bootstrap/evidence.json" "$input_file" "$proof_dir" "$run_dir/evidence.json" 2>&1 | tee "$run_dir/replay.log"
python3 - "$run_dir" <<'PY'
import json,pathlib,sys
p=pathlib.Path(sys.argv[1]);e=json.loads((p/'evidence.json').read_text());r=e['results']
assert r['complete'] is True and r['proof_verified_offchain'] is True and r['proof_settled'] is True and r['withdrawal_executed'] is False
assert sum(x['result']=='committed' for x in e['evidence'])==1
(p/'summary.json').write_text(json.dumps(r,indent=2)+'\n')
print('Actual native proof settled; custody release remains pending')
PY
