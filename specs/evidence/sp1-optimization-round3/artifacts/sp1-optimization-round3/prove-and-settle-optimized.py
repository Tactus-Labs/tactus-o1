"""Two exact-key real sparse proofs, fresh verification, then isolated CKB tests."""
from pathlib import Path
import fcntl,hashlib,json,os,re,subprocess,time
ROOT=Path.cwd();BASE=ROOT/'artifacts/sp1-optimization-round3'
preparation=json.loads((BASE/'optimized-pipeline.json').read_text())
assert preparation['status']=='complete' and preparation['source_unchanged']
SOURCE=Path(preparation['output']);KEY=preparation['guest_key']
for name,expected in json.loads((SOURCE/'source-sha256.json').read_text()).items():
 assert hashlib.sha256((ROOT/name).read_bytes()).hexdigest()==expected,name
OUT=BASE/('sparse-proofs-'+str(time.time_ns()));OUT.mkdir()
status={'status':'running','source_output':str(SOURCE),'output':str(OUT),'guest_key':KEY,'checks':[],'proofs':{},'started_unix':time.time(),'ci_run':False,'production_ready':False}
def save():
 (BASE/'optimized-proof-pipeline.json').write_text(json.dumps(status,indent=2)+'\n')
 (OUT/'progress.json').write_text(json.dumps(status,indent=2)+'\n')
save();(OUT/'runner-at-launch.py').write_bytes(Path(__file__).read_bytes())
env=os.environ.copy();env.update(CARGO_BUILD_JOBS='2',CARGO_NET_OFFLINE='true',RUSTUP_TOOLCHAIN='1.97.1',RAYON_NUM_THREADS='8',TOKIO_WORKER_THREADS='8')
for name in ['TACTUS_SETTLEMENT_PROOF_DIR','TACTUS_SECOND_SETTLEMENT_PROOF_DIR','TACTUS_PREPARE_SECOND_PROOF','TACTUS_SETTLEMENT_REORG','TACTUS_SETTLEMENT_CONTINUATION_JSON','TACTUS_SPARSE_SETTLEMENT','TACTUS_SPARSE_GUEST_KEY','CARGO_TARGET_DIR']:
 env.pop(name,None)
def run(name,command,extra=None):
 entry={'name':name,'command':[str(x) for x in command],'status':'running','started_unix':time.time(),'log':str(OUT/(name+'.txt'))};status['checks'].append(entry);save()
 e=env.copy();e.update(extra or {})
 with Path(entry['log']).open('w') as log:completed=subprocess.run(entry['command'],cwd=ROOT,env=e,stdout=log,stderr=subprocess.STDOUT)
 entry.update(status='passed' if completed.returncode==0 else 'failed',exit_code=completed.returncode,elapsed_seconds=time.time()-entry['started_unix']);save()
 if completed.returncode:raise RuntimeError(name+' failed; inspect '+entry['log'])
 return Path(entry['log'])
def check_source():
 for name,expected in json.loads((SOURCE/'source-sha256.json').read_text()).items():
  assert hashlib.sha256((ROOT/name).read_bytes()).hexdigest()==expected,name
try:
 for label in ['first','second']:
  target=OUT/('proof-'+label)
  run('prove-'+label,['python3','-B','scripts/run-sparse-proof-benchmark.py','--elf',SOURCE/'guest.elf','--host',SOURCE/'host/sparse-chain-proof','--input',SOURCE/(label+'-sparse-input.json'),'--output',target,'--threads',8,'--go-threads',4,'--shard-size',1048576])
  complete=json.loads((target/'completion.json').read_text());assert complete['proof_generated'] and complete['fresh_verification'] and len(set(complete['negative_controls']))==15
  selected=Path((target/'selected-proof-dir.txt').read_text().strip());expected=json.loads((SOURCE/(label+'-sparse-input.json')).read_text());assert (selected/'public-values.bin').read_bytes()==bytes.fromhex(expected['expected_journal_hex'][2:])
  status['proofs'][label]={'directory':str(selected),'completion':complete};save()
 check_source()
 lock=(ROOT/'artifacts/.proof-run.lock').open('a');fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
 try:
  first=Path(status['proofs']['first']['directory']);second=Path(status['proofs']['second']['directory'])
  local={'CKB_BIN':'/home/arthur/devnet/ckb-bin/ckb','TACTUS_DEVNET_SUITE':'replay-settlement-bootstrap','TACTUS_SPARSE_SETTLEMENT':'1','TACTUS_SPARSE_GUEST_KEY':KEY,'TACTUS_SETTLEMENT_CONTINUATION_JSON':str(SOURCE/'continuation/continuation.json'),'TACTUS_SETTLEMENT_PROOF_DIR':str(first)}
  for name,extra,proofs in [('two-settlements',dict(local,TACTUS_SECOND_SETTLEMENT_PROOF_DIR=str(second)),[first,second]),('settlement-reorg',dict(local,TACTUS_SETTLEMENT_REORG='1'),[first])]:
   log=run(name,['bash','scripts/run-devnet-experiments.sh'],extra)
   paths=re.findall(r'^Evidence directory: (.+)$',log.read_text(),re.M);assert len(paths)==1
   directory=Path(paths[0]).resolve();assert directory.is_relative_to(ROOT/'artifacts')
   check=run(name+'-check',['python3','-B','scripts/check-sparse-settlements.py',directory/'evidence.json',SOURCE/'settlement.elf',KEY,*proofs])
   status[name]={'directory':str(directory),'check':json.loads(check.read_text())};save()
  # Compare latest continuation execution against the already executed frozen
  # replay guest. These adjusted histories are explicitly laboratory inputs.
  history=OUT/'history';history.mkdir();rows=[]
  for prefix in [1,256,1024]:
   source=BASE/f'history-scaling-inputs/prefix-{prefix}.json';prepared=history/f'prefix-{prefix}-prepared.json';sparse_input=history/f'prefix-{prefix}-sparse.json'
   run(f'history-{prefix}-prepare',[SOURCE/'host/prepare-sparse',source,prefix,1,prepared])
   value=json.loads(prepared.read_text());value['guest_verifying_key']=KEY;value['experiment'].update(execution_only=True,canonical_deployment_export=False,guest_key_replaced_for_lab_execution=True);sparse_input.write_text(json.dumps(value,indent=2)+'\n')
   target=history/str(prefix);run(f'history-{prefix}-guest',[SOURCE/'host/sparse-chain-proof','execute',SOURCE/'guest.elf',sparse_input,target])
   replay=(BASE/f'history-qualification/{prefix}-replay/public-values.bin').read_bytes();sparse=(target/'public-values.bin').read_bytes();assert replay[40:]==sparse[40:]
   report=(target/'execution-report.txt').read_text();part=re.search(r'opcode_counts: \{([^}]*)\}',report).group(1);instructions=sum(map(int,re.findall(r': (\d+)',part)))
   old=next(r for r in json.loads((BASE/'history-qualification/progress.json').read_text())['rows'] if r['prefix_batches']==prefix)
   rows.append({'prefix_batches':prefix,'replay_instructions':old['replay_instructions'],'initial_sparse_instructions':old['sparse_instructions'],'optimized_sparse_instructions':instructions,'frozen_replay_guest_transition_match':True,'guest_prefix_batches':0,'witness_bytes':value['preparation']['witness_bytes'],'proof_generated':False,'adjusted_environment_geth_checked':False})
   (history/'results.json').write_text(json.dumps(rows,indent=2)+'\n')
  check_source();status.update(status='complete',two_real_proofs_verified=True,local_two_settlements_accepted=True,local_reorg_qualified=True,history_qualification=str(history/'results.json'),finished_unix=time.time());save()
 finally:
  fcntl.flock(lock,fcntl.LOCK_UN);lock.close()
except BaseException as error:
 status.update(status='failed',error=repr(error),finished_unix=time.time());save();raise
