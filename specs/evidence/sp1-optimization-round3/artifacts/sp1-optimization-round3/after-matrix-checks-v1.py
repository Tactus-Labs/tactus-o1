"""One-shot dependent local checks, only after the observed proof matrix exits.
No CI, network, deployment or source edits. Stops at the first failed check.
"""
from pathlib import Path
import fcntl,hashlib,json,os,subprocess,sys,time
ROOT=Path.cwd(); BASE=ROOT/'artifacts/sp1-optimization-round3'
PID=278412

def process_identity(pid):
 try:
  # Everything after the final ')' starts with field 3; starttime is field 22.
  fields=Path(f'/proc/{pid}/stat').read_text().rsplit(')',1)[1].split()
  return fields[19] if fields[0]!='Z' else None
 except FileNotFoundError:
  return None

identity=process_identity(PID)
if identity is None: raise SystemExit('Expected live matrix coordinator before queuing checks')
status={'status':'waiting_for_matrix','matrix_pid':PID,'matrix_starttime':identity,'checks':[], 'ci_run':False}

def save():
 (BASE/'qualification-progress.json').write_text(json.dumps(status,indent=2)+'\n')

def sources():
 paths={ROOT/'Cargo.toml',ROOT/'Cargo.lock'}
 for prefix in ['crates/tactus-o1-execution','crates/tactus-o1-protocol',
                'proofs/incremental-sp1','proofs/sp1/journal','proofs/ckb-settlement',
                'proofs/ckb-native-settlement','proofs/ckb-native-anchor','proofs/vendor/lazy_static-1.5.1']:
  for parent,dirs,files in os.walk(ROOT/prefix):
   dirs[:]=[d for d in dirs if d not in ['target','.git']]
   for name in files:
    p=Path(parent)/name
    if p.suffix in ['.rs','.toml','.lock','.txt','.json']:
     paths.add(p)
 return {str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(paths)}

save()
while process_identity(PID)==identity:
 time.sleep(10)
matrix=json.loads((BASE/'matrix-progress.json').read_text())
if matrix['status']!='complete':
 status.update(status='matrix_not_complete',matrix_status=matrix['status']);save();raise SystemExit(2)
lock=(ROOT/'artifacts/.proof-run.lock').open('a')
try: fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
except BlockingIOError:
 status['status']='proof_resource_in_use';save();raise SystemExit(3)
# Hold this resource lock for the checks; prevent a new proof timing run from
# accidentally overlapping these builds/tests. Cargo's own lock is separate.
initial=sources();(BASE/'qualification-source-sha256.json').write_text(json.dumps(initial,indent=2)+'\n')
status.update(status='running',started_unix=time.time());save()
env=os.environ.copy();env['CARGO_BUILD_JOBS']='2'
checks=[
 ('execution-native',['cargo','+1.97.1','test','--locked','--offline','-p','tactus-o1-execution','--features','native-bridge'],None),
 ('checkpoint-journal',['cargo','+1.97.1','test','--locked','--offline','--manifest-path','proofs/sp1/Cargo.toml','-p','tactus-o1-proof-journal'],None),
 ('sparse-state-journal',['cargo','+1.97.1','test','--locked','--offline','--manifest-path','proofs/incremental-sp1/Cargo.toml','-p','tactus-o1-sparse-state','-p','tactus-o1-sparse-journal'],'proofs/sp1/target'),
 ('replay-settlement',['cargo','+1.97.1','test','--locked','--offline','--manifest-path','proofs/ckb-settlement/Cargo.toml'],None),
 ('sparse-settlement',['cargo','+1.97.1','test','--locked','--offline','--manifest-path','proofs/ckb-settlement/Cargo.toml','--features','sparse-proof'],None),
 ('native-settlement',['cargo','+1.97.1','test','--locked','--offline','--manifest-path','proofs/ckb-native-settlement/Cargo.toml'],None),
 ('sparse-host-check',['cargo','+1.97.1','check','--locked','--offline','--manifest-path','proofs/incremental-sp1/Cargo.toml','-p','tactus-o1-sparse-sp1-host','--bins'],'artifacts/prover-host/target'),
]
for name,command,target in checks:
 entry={'name':name,'command':command,'status':'running','started_unix':time.time()};status['checks'].append(entry);save()
 run_env=env.copy()
 if target: run_env['CARGO_TARGET_DIR']=str(ROOT/target)
 else: run_env.pop('CARGO_TARGET_DIR',None)
 with (BASE/('qualification-'+name+'.txt')).open('w') as log:
  result=subprocess.run(command,cwd=ROOT,env=run_env,stdout=log,stderr=subprocess.STDOUT)
 entry.update(status='passed' if result.returncode==0 else 'failed',exit_code=result.returncode,elapsed_seconds=time.time()-entry['started_unix'])
 if result.returncode:
  status['status']='failed';save();raise SystemExit(result.returncode)
 save()
final=sources();status['source_unchanged']=initial==final
status['status']='complete' if initial==final else 'source_changed_during_checks'
status['finished_unix']=time.time();save()
print(json.dumps(status,indent=2),flush=True)
