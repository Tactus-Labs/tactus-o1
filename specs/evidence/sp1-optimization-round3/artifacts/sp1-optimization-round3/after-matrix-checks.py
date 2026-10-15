"""One-shot local checks with an exclusive proof-resource lock; no CI/network.
--between-runs requires the observed coordinator to be stopped and run two fully
verified. Otherwise wait for the observed live matrix to finish. Stops on failure.
"""
from pathlib import Path
import fcntl,hashlib,json,os,subprocess,sys,time
ROOT=Path.cwd(); BASE=ROOT/'artifacts/sp1-optimization-round3'; PID=278412

def process(pid):
 try:
  f=Path(f'/proc/{pid}/stat').read_text().rsplit(')',1)[1].split()
  return f[0],f[19]
 except FileNotFoundError:return None,None

mode='between_runs' if '--between-runs' in sys.argv else 'after_matrix'
state,identity=process(PID)
status={'status':'waiting_for_matrix','mode':mode,'matrix_pid':PID,'matrix_starttime':identity,'checks':[], 'ci_run':False}
def save():
 (BASE/'qualification-progress.json').write_text(json.dumps(status,indent=2)+'\n')
if mode=='between_runs':
 if state!='T':raise SystemExit('Coordinator must be stopped before inter-run checks')
 completion=json.loads((BASE/'proof-threads8/completion.json').read_text())
 if not completion['proof_generated'] or not completion['fresh_verification'] or len(completion['negative_controls'])!=15:
  raise SystemExit('Second proof qualification incomplete')
 if json.loads((BASE/'proof-threads8/status.json').read_text())['stage']!='complete':
  raise SystemExit('Second runner is not complete')
else:
 if identity is None:raise SystemExit('Expected live matrix coordinator')
 save()
 while process(PID)[1]==identity:time.sleep(10)
 if json.loads((BASE/'matrix-progress.json').read_text())['status']!='complete':
  status['status']='matrix_not_complete';save();raise SystemExit(2)
lock=(ROOT/'artifacts/.proof-run.lock').open('a')
try:fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
except BlockingIOError:raise SystemExit('Proof resource is still in use; do not compile')
attempt=BASE/'qualifications'/str(time.time_ns());attempt.mkdir(parents=True)
status.update(status='running',started_unix=time.time(),attempt=str(attempt));save()
(attempt/'runner-at-launch.py').write_bytes(Path(__file__).read_bytes())

def sources():
 paths={ROOT/p for p in ['Cargo.toml','Cargo.lock','rust-toolchain.toml','contracts/bridge/NativeCKB.json']}
 for prefix in ['crates/tactus-o1-execution','crates/tactus-o1-protocol','crates/tactus-o1-devnet-driver',
                'proofs/incremental-sp1','proofs/sp1/journal','proofs/ckb-settlement',
                'proofs/ckb-native-settlement','proofs/ckb-native-anchor','proofs/vendor','scripts']:
  for parent,dirs,files in os.walk(ROOT/prefix):
   dirs[:]=[d for d in dirs if d not in ['target','.git','__pycache__']]
   for name in files:
    p=Path(parent)/name
    if p.suffix in ['.rs','.toml','.lock','.txt','.json','.py','.sh','.h','.c']:paths.add(p)
 return {str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(paths) if p.is_file()}
initial=sources();(attempt/'source-sha256.json').write_text(json.dumps(initial,indent=2)+'\n')
env=os.environ.copy();env['CARGO_BUILD_JOBS']='2'
checks=[
 ('execution-native',['cargo','+1.97.1','test','--locked','--offline','-p','tactus-o1-execution','--features','native-bridge'],None),
 ('checkpoint-journal',['cargo','+1.97.1','test','--locked','--offline','--manifest-path','proofs/sp1/Cargo.toml','-p','tactus-o1-proof-journal'],None),
 ('sparse-state-journal',['cargo','+1.97.1','test','--locked','--offline','--manifest-path','proofs/incremental-sp1/Cargo.toml','-p','tactus-o1-sparse-state','-p','tactus-o1-sparse-journal'],'proofs/sp1/target'),
 ('replay-settlement',['cargo','+1.97.1','test','--locked','--offline','--manifest-path','proofs/ckb-settlement/Cargo.toml'],None),
 ('sparse-settlement',['cargo','+1.97.1','test','--locked','--offline','--manifest-path','proofs/ckb-settlement/Cargo.toml','--features','sparse-proof'],None),
 ('native-settlement',['cargo','+1.97.1','test','--locked','--offline','--manifest-path','proofs/ckb-native-settlement/Cargo.toml'],None),
 ('devnet-driver',['cargo','+1.97.1','test','--locked','--offline','-p','tactus-o1-devnet-driver'],None),
 ('devnet-bins',['cargo','+1.97.1','build','--locked','--offline','--bin','replay-settlement-bootstrap','--bin','recover-settlement'],None),
 ('sparse-host-check',['cargo','+1.97.1','check','--locked','--offline','--manifest-path','proofs/incremental-sp1/Cargo.toml','-p','tactus-o1-sparse-sp1-host','--bins'],'artifacts/prover-host/target'),
]
for name,command,target in checks:
 entry={'name':name,'command':command,'status':'running','started_unix':time.time(),'log':str(attempt/(name+'.txt'))}
 status['checks'].append(entry);save()
 run_env=env.copy()
 if target:run_env['CARGO_TARGET_DIR']=str(ROOT/target)
 else:run_env.pop('CARGO_TARGET_DIR',None)
 with Path(entry['log']).open('w') as log:
  result=subprocess.run(command,cwd=ROOT,env=run_env,stdout=log,stderr=subprocess.STDOUT)
 entry.update(status='passed' if result.returncode==0 else 'failed',exit_code=result.returncode,elapsed_seconds=time.time()-entry['started_unix'])
 if result.returncode:
  status['status']='failed';save();(attempt/'result.json').write_text(json.dumps(status,indent=2)+'\n');raise SystemExit(result.returncode)
 save()
status['source_unchanged']=initial==sources()
status['status']='complete' if status['source_unchanged'] else 'source_changed_during_checks'
status['finished_unix']=time.time();save();(attempt/'result.json').write_text(json.dumps(status,indent=2)+'\n')
print(json.dumps(status,indent=2),flush=True)
