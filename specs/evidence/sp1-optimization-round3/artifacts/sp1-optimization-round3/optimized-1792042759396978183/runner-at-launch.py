"""Qualify the latest sparse candidate and prepare canonical local CKB inputs.
Waits for the observed frozen resource matrix; never runs CI or proves concurrently.
Real sparse proofs are a subsequent stage after these results have been reviewed.
"""
from pathlib import Path
import fcntl,hashlib,json,os,re,shutil,subprocess,time,traceback
ROOT=Path.cwd();BASE=ROOT/'artifacts/sp1-optimization-round3';PID=278412;IDENTITY='16011753'
def proc():
 try:
  parts=Path(f'/proc/{PID}/stat').read_text().rsplit(')',1)[1].split();return parts[0],parts[19]
 except FileNotFoundError:return None,None
status={'status':'waiting_for_matrix','matrix_pid':PID,'matrix_starttime':IDENTITY,'ci_run':False,'checks':[]}
def save():
 (BASE/'optimized-pipeline.json').write_text(json.dumps(status,indent=2)+'\n')
save()
state,identity=proc()
if identity not in (None,IDENTITY):raise SystemExit('Matrix PID was reused')
while identity==IDENTITY and state!='Z':
 time.sleep(10);state,identity=proc()
matrix=json.loads((BASE/'matrix-progress.json').read_text())
if matrix['status']!='complete':
 status['status']='matrix_not_complete';save();raise SystemExit(2)
for entry in matrix['runs']:
 assert entry['completion']['proof_generated'] and entry['completion']['fresh_verification'] and len(entry['completion']['negative_controls'])==15
lock=(ROOT/'artifacts/.proof-run.lock').open('a');fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
OUT=BASE/('optimized-'+str(time.time_ns()));OUT.mkdir();status.update(status='running',output=str(OUT),started_unix=time.time());save()
(OUT/'runner-at-launch.py').write_bytes(Path(__file__).read_bytes())
env=os.environ.copy();env.update(CARGO_BUILD_JOBS='2',CARGO_NET_OFFLINE='true',RUSTUP_TOOLCHAIN='1.97.1',RAYON_NUM_THREADS='8',TOKIO_WORKER_THREADS='8')
for name in ['TACTUS_SETTLEMENT_PROOF_DIR','TACTUS_SECOND_SETTLEMENT_PROOF_DIR','TACTUS_PREPARE_SECOND_PROOF','TACTUS_SETTLEMENT_REORG','TACTUS_SETTLEMENT_CONTINUATION_JSON','TACTUS_SPARSE_SETTLEMENT','TACTUS_SPARSE_GUEST_KEY','CARGO_TARGET_DIR']:
 env.pop(name,None)
def sources():
 paths=[ROOT/n for n in ['Cargo.toml','Cargo.lock','rust-toolchain.toml','contracts/bridge/NativeCKB.json']]
 for name in ['crates','proofs/incremental-sp1','proofs/sp1','proofs/vendor','proofs/ckb-settlement','proofs/ckb-native-settlement','proofs/ckb-native-anchor','scripts']:
  for parent,dirs,files in os.walk(ROOT/name):
   dirs[:]=[d for d in dirs if d not in ['target','.git','__pycache__']]
   for file in files:
    p=Path(parent)/file
    if p.suffix in ['.rs','.toml','.lock','.txt','.json','.py','.sh','.h','.c','.ld']:paths.append(p)
 return {str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(set(paths)) if p.is_file()}
initial=sources();(OUT/'source-sha256.json').write_text(json.dumps(initial,indent=2)+'\n')
assert initial['Cargo.lock']=='d1e83ee7925c86276223c5b01a46cc25c9a1c81d811b713381dd9d3a4e835f92'
def run(name,command,extra=None):
 entry={'name':name,'command':[str(c) for c in command],'status':'running','started_unix':time.time(),'log':str(OUT/(name+'.txt'))};status['checks'].append(entry);save()
 e=env.copy();e.update(extra or {})
 with Path(entry['log']).open('w') as stream:result=subprocess.run(entry['command'],cwd=ROOT,env=e,stdout=stream,stderr=subprocess.STDOUT)
 entry.update(status='passed' if result.returncode==0 else 'failed',exit_code=result.returncode,elapsed_seconds=time.time()-entry['started_unix']);save()
 if result.returncode:raise RuntimeError(name+' failed; see '+entry['log'])
 return Path(entry['log'])
def devnet(name,extra):
 log=run(name,['bash','scripts/run-devnet-experiments.sh'],extra)
 matches=re.findall(r'^Evidence directory: (.+)$',log.read_text(),re.M)
 if len(matches)!=1:raise RuntimeError('Ambiguous local devnet directory')
 p=Path(matches[0]).resolve();assert p.is_relative_to(ROOT/'artifacts')
 run(name+'-check',['python3','-B','scripts/check-sparse-settlements.py',p/'evidence.json',ROOT/'artifacts/tactus_o1_sparse_settlement_script.elf',key])
 status[name+'_directory']=str(p);save();return p
try:
 run('sparse-tests',['cargo','+1.97.1','test','--locked','--offline','--manifest-path','proofs/incremental-sp1/Cargo.toml','-p','tactus-o1-sparse-state','-p','tactus-o1-sparse-journal'],{'CARGO_TARGET_DIR':str(ROOT/'proofs/sp1/target')})
 run('host-build',['cargo','+1.97.1','build','--locked','--offline','--release','--manifest-path','proofs/incremental-sp1/Cargo.toml','-p','tactus-o1-sparse-sp1-host','--features','native-gnark','--bins'],{'CARGO_TARGET_DIR':str(ROOT/'artifacts/prover-host/target')})
 host=OUT/'host';host.mkdir()
 for name in ['prepare-sparse','history-inputs','qualify-sparse','sparse-chain-proof','sparse-wrap-witness']:
  shutil.copy2(ROOT/'artifacts/prover-host/target/release'/name,host/('wrap-witness' if name=='sparse-wrap-witness' else name))
 run('guest-build',['bash','scripts/build-sparse-proof-guest.sh'])
 guest=OUT/'guest.elf';shutil.copy2(ROOT/'proofs/incremental-sp1/target/elf-compilation/riscv64im-succinct-zkvm-elf/release/tactus-o1-sparse-sp1-guest',guest)
 run('geth-guest-qualification',[host/'qualify-sparse',BASE/'qualification-fixtures.json',OUT/'qualification',guest])
 rows=json.loads((OUT/'qualification/results.json').read_text());assert len(rows)==25 and sum(r['blocks'] for r in rows)==93 and all(r['guest_executed'] for r in rows)
 previous={r['case']:r for r in json.loads((BASE/'sparse-guest-qualification/results.json').read_text())};adaptive={r['case']:r for r in json.loads((BASE/'adaptive-qualification/results.json').read_text())}
 comparison=[{'case':r['case'],'adaptive_instructions':adaptive[r['case']]['instructions'],'initial_sparse_instructions':previous[r['case']]['instructions'],'optimized_sparse_instructions':r['instructions'],'proof_generated':False} for r in rows]
 (OUT/'instruction-comparison.json').write_text(json.dumps(comparison,indent=2)+'\n')
 vkey=run('vkey',[ROOT/'artifacts/prover-tools/cargo-prove','prove','vkey','--elf',guest]);keys=set(re.findall(r'0x[0-9a-fA-F]{64}',vkey.read_text()));assert len(keys)==1;key=keys.pop();status['guest_key']=key;save()
 assert initial==sources(),'Source changed during build/qualification'
 source=OUT/'source'
 for name in initial:
  dst=source/name;dst.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(ROOT/name,dst)
 artifacts=[guest,*[p for p in host.iterdir() if p.is_file()],BASE/'qualification-fixtures.json']
 (OUT/'artifact-sha256.json').write_text(json.dumps({str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in artifacts},indent=2)+'\n')
 local={'CKB_BIN':'/home/arthur/devnet/ckb-bin/ckb','TACTUS_DEVNET_SUITE':'replay-settlement-bootstrap','TACTUS_SPARSE_SETTLEMENT':'1','TACTUS_SPARSE_GUEST_KEY':key}
 first=devnet('bootstrap',local)
 run('continuation',['cargo','+1.97.1','run','--locked','--offline','-p','tactus-o1-execution','--example','settlement-continuation','--',first/'proving-input.json',OUT/'continuation'])
 run('continuation-geth',['python3','-B','scripts/check-execution-geth.py',ROOT/'artifacts/evm-tools/evm',OUT/'continuation'])
 second=devnet('two-inputs',dict(local,TACTUS_SETTLEMENT_CONTINUATION_JSON=str(OUT/'continuation/continuation.json'),TACTUS_PREPARE_SECOND_PROOF='1'))
 a=json.loads((first/'proving-input.json').read_text());b=json.loads((second/'proving-input.json').read_text());assert a['domain_hex']==b['domain_hex'] and a['expected_journal_hex']==b['expected_journal_hex'] and a['guest_verifying_key']==b['guest_verifying_key']==key
 run('prepare-first',[host/'prepare-sparse',second/'proving-input.json',0,1,OUT/'first-sparse-input.json'])
 run('prepare-second',[host/'prepare-sparse',second/'proving-input-next.json',1,1,OUT/'second-sparse-input.json'])
 run('first-guest-execute',[host/'sparse-chain-proof','execute',guest,OUT/'first-sparse-input.json',OUT/'first-execution'])
 run('second-guest-execute',[host/'sparse-chain-proof','execute',guest,OUT/'second-sparse-input.json',OUT/'second-execution'])
 assert initial==sources(),'Source changed during local preparation'
 status.update(status='complete',proofs_generated=False,actual_sparse_proof_acceptance=False,source_unchanged=True,finished_unix=time.time());save()
except BaseException as error:
 status.update(status='failed',error=repr(error),finished_unix=time.time());save();raise
finally:
 fcntl.flock(lock,fcntl.LOCK_UN);lock.close()
