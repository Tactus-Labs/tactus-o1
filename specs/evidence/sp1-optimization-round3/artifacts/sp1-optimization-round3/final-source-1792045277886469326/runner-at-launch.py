"""Serialize final formal guest qualification after the observed sparse pipeline."""
from pathlib import Path
import fcntl,hashlib,json,os,re,shutil,subprocess,time
ROOT=Path.cwd();BASE=ROOT/'artifacts/sp1-optimization-round3'
PIPE=BASE/'optimized-proof-pipeline.json'
observed=json.loads(PIPE.read_text());expected_output=observed['output']
STATUS=BASE/'final-source-progress.json'
assert not STATUS.exists(), 'Use existing results; do not restart this coordinator'
status={'status':'waiting_for_sparse_pipeline','pipeline_output':expected_output,'checks':[],'ci_run':False,'production_ready':False}
def save():
 STATUS.write_text(json.dumps(status,indent=2)+'\n')
 if 'output' in status:(Path(status['output'])/'progress.json').write_text(json.dumps(status,indent=2)+'\n')
def digest(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def verify_sparse_source():
 source=Path(observed['source_output'])
 for name,expected in json.loads((source/'source-sha256.json').read_text()).items():assert digest(ROOT/name)==expected,name
save()
while True:
 current=json.loads(PIPE.read_text());assert current['output']==expected_output,'Sparse pipeline replaced'
 if current['status']=='complete':break
 if current['status']!='running':
  status.update(status='upstream_failed',upstream_error=current.get('error'));save();raise SystemExit(2)
 time.sleep(10)
verify_sparse_source()
lock=(ROOT/'artifacts/.proof-run.lock').open('a');fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
OUT=BASE/('final-source-'+str(time.time_ns()));OUT.mkdir();status.update(status='running',output=str(OUT));save()
(OUT/'runner-at-launch.py').write_bytes(Path(__file__).read_bytes())
env=os.environ.copy();env.update(CARGO_BUILD_JOBS='2',CARGO_NET_OFFLINE='true',RUSTUP_TOOLCHAIN='1.97.1',RAYON_NUM_THREADS='8',TOKIO_WORKER_THREADS='8')
for k in ['CARGO_TARGET_DIR','WITHOUT_VK_VERIFICATION','SP1_DUMP']:env.pop(k,None)
def sources():
 paths=[ROOT/n for n in ['Cargo.toml','Cargo.lock','rust-toolchain.toml','contracts/bridge/NativeCKB.json']]
 for name in ['crates','proofs/sp1','proofs/native-sp1','proofs/incremental-sp1','proofs/vendor','proofs/ckb-settlement','proofs/ckb-native-settlement','scripts']:
  for parent,dirs,files in os.walk(ROOT/name):
   dirs[:]=[d for d in dirs if d not in ['target','.git','__pycache__']]
   for file in files:
    p=Path(parent)/file
    if p.suffix in ['.rs','.toml','.lock','.txt','.json','.py','.sh','.h','.c','.ld']:paths.append(p)
 return {str(p.relative_to(ROOT)):digest(p) for p in sorted(set(paths)) if p.is_file()}
initial=sources();(OUT/'source-sha256.json').write_text(json.dumps(initial,indent=2)+'\n')
def run(name,command,extra=None):
 entry={'name':name,'command':[str(c) for c in command],'status':'running','log':str(OUT/(name+'.txt')),'started_unix':time.time()};status['checks'].append(entry);save()
 e=env.copy();e.update(extra or {})
 with Path(entry['log']).open('w') as stream:r=subprocess.run(entry['command'],cwd=ROOT,env=e,stdout=stream,stderr=subprocess.STDOUT)
 entry.update(status='passed' if r.returncode==0 else 'failed',exit_code=r.returncode,elapsed_seconds=time.time()-entry['started_unix']);save()
 if r.returncode:raise RuntimeError(name+' failed; preserve all completed evidence')
try:
 # Retain the independent pre-refactor native oracle before any host rebuild.
 host=OUT/'oracle';host.mkdir()
 for name in ['crypto-patch-bench','tactus-o1-native-sp1-host']:
  shutil.copy2(ROOT/'artifacts/prover-host/target/release'/name,host/name)
 (OUT/'oracle-sha256.json').write_text(json.dumps({p.name:digest(p) for p in host.iterdir()},indent=2)+'\n')
 run('full-guest-build',['bash','scripts/build-proof-guest.sh'])
 run('native-guest-build',['bash','scripts/build-native-proof-guest.sh'])
 guests={}
 for label,workspace,filename in [('full','sp1','tactus-o1-sp1-guest'),('native','native-sp1','tactus-o1-native-sp1-guest')]:
  target=OUT/(label+'.elf');shutil.copy2(ROOT/f'proofs/{workspace}/target/elf-compilation/riscv64im-succinct-zkvm-elf/release'/filename,target)
  run(label+'-vkey',[ROOT/'artifacts/prover-tools/cargo-prove','prove','vkey','--elf',target])
  keys=set(re.findall(r'0x[0-9a-fA-F]{64}',(OUT/(label+'-vkey.txt')).read_text()));assert len(keys)==1
  guests[label]={'sha256':digest(target),'guest_key':keys.pop()}
 status['guests']=guests;save()
 run('full-qualification',[host/'crypto-patch-bench',BASE/'qualification-fixtures.json',OUT/'full-qualification',OUT/'full.elf'],{'TACTUS_PATCH_CHAIN_INPUT':str(ROOT/'specs/evidence/sealed-chain-proof/proving-input.json')})
 rows=json.loads((OUT/'full-qualification/results.json').read_text());assert len(rows)==26 and sum(r['geth_checked'] for r in rows)==25 and all(r['native_match'] for r in rows)
 for prefix,label in [(0,'full'),(1,'prefix')]:
  run('native-'+label,[host/'tactus-o1-native-sp1-host',OUT/'native.elf',ROOT/f'artifacts/native-guest-qXKMQ1qa/input-{prefix}.json',OUT/('native-'+label)])
  assert (OUT/('native-'+label)/'public-values.bin').read_bytes()==(BASE/'adaptive'/('native-'+label)/'public-values.bin').read_bytes()
 assert initial==sources(),'Source changed during final qualification'
 for name in initial:
  dst=OUT/'source'/name;dst.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(ROOT/name,dst)
 status['source_unchanged']=True
 same=guests['full']['sha256']==digest(BASE/'adaptive.elf');status['full_identical_to_proved_adaptive']=same;save()
 # The frozen adaptive proofs only cover this final binary if hashes match.
 fcntl.flock(lock,fcntl.LOCK_UN);lock.close();lock=None
 if not same:
  run('full-real-proof',['python3','-B','scripts/run-patched-proof-benchmark.py','--elf',OUT/'full.elf','--host',BASE/'proof-tools/chain-proof','--input',ROOT/'artifacts/sp1-optimization-round2/transfers-32-proof-input.json','--output',OUT/'full-proof','--threads',8,'--go-threads',4,'--shard-size',1048576])
  complete=json.loads((OUT/'full-proof/completion.json').read_text());assert complete['proof_generated'] and complete['fresh_verification'] and len(set(complete['negative_controls']))==15
  status['full_real_proof']=complete
 assert initial==sources(),'Source changed during final proof'
 status.update(status='complete',finished_unix=time.time(),native_qualification='execution-only; no new custody proof or deployment');save()
except BaseException as error:
 status.update(status='failed',error=repr(error));save();raise
finally:
 if lock is not None:fcntl.flock(lock,fcntl.LOCK_UN);lock.close()
