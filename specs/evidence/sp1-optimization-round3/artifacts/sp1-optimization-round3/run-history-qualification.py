from pathlib import Path
import fcntl,hashlib,json,os,re,signal,subprocess,time
ROOT=Path.cwd();BASE=ROOT/'artifacts/sp1-optimization-round3';OUT=BASE/'history-qualification';OUT.mkdir()
PID=278412
stat=Path(f'/proc/{PID}/stat').read_text().rsplit(')',1)[1].split()
assert stat[0]=='T' and stat[19]=='16011753'
lock=(ROOT/'artifacts/.proof-run.lock').open('a');fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
keys=set(re.findall(r'0x[0-9a-fA-F]{64}',(BASE/'sparse-candidate/vkey.txt').read_text()));assert len(keys)==1;KEY=keys.pop()
env=os.environ.copy();env.update(RAYON_NUM_THREADS='8',TOKIO_WORKER_THREADS='8')
status={'status':'running','proof_generated':False,'ckb_settlement':False,'adjusted_environment_geth_checked':False,'rows':[],'started_unix':time.time(),'resume_coordinator_when_finished':PID}
def save():(OUT/'progress.json').write_text(json.dumps(status,indent=2)+'\n')
def run(cmd,log):
 with log.open('w') as f:subprocess.run([str(x) for x in cmd],cwd=ROOT,env=env,stdout=f,stderr=subprocess.STDOUT,check=True)
def instructions(path):
 text=path.read_text();part=re.search(r'opcode_counts: \{([^}]*)\}',text).group(1)
 return sum(map(int,re.findall(r': (\d+)',part)))
files=[BASE/'proof-tools/chain-proof',BASE/'adaptive.elf',BASE/'sparse-proof-tools/sparse-chain-proof',BASE/'sparse-proof-tools/prepare-sparse',BASE/'sparse-candidate/guest.elf',Path(__file__)]
(OUT/'sha256.json').write_text(json.dumps({str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in files},indent=2)+'\n');save()
try:
 for prefix in [1,256,1024]:
  source=BASE/f'history-scaling-inputs/prefix-{prefix}.json';prepared=OUT/f'prefix-{prefix}-prepared.json';sparse_input=OUT/f'prefix-{prefix}-sparse.json'
  run([BASE/'sparse-proof-tools/prepare-sparse',source,prefix,1,prepared],OUT/f'{prefix}-prepare.txt')
  value=json.loads(prepared.read_text());value['guest_verifying_key']=KEY;value['experiment'].update(execution_only=True,canonical_deployment_export=False,guest_key_replaced_for_lab_execution=True);sparse_input.write_text(json.dumps(value,indent=2)+'\n')
  row={'prefix_batches':prefix,'status':'running'};status['rows'].append(row);save()
  for label,host,elf,inp in [('replay',BASE/'proof-tools/chain-proof',BASE/'adaptive.elf',source),('sparse',BASE/'sparse-proof-tools/sparse-chain-proof',BASE/'sparse-candidate/guest.elf',sparse_input)]:
   target=OUT/f'{prefix}-{label}';run([host,'execute',elf,inp,target],OUT/f'{prefix}-{label}.txt')
   result=json.loads((target/'result.json').read_text());assert result['native_chain_replay_match'] and not result['proof_generated']
   row[label+'_instructions']=instructions(target/'execution-report.txt');save()
  replay=(OUT/f'{prefix}-replay/public-values.bin').read_bytes();sparse=(OUT/f'{prefix}-sparse/public-values.bin').read_bytes()
  assert replay[40:]==sparse[40:]
  row.update(status='complete',frozen_replay_guest_transition_match=True,sparse_guest_prefix_batches=0,sparse_instruction_change_percent=100*(row['sparse_instructions']/row['replay_instructions']-1));save()
 status['status']='complete'
except BaseException as error:
 status['status']='failed';status['error']=repr(error);raise
finally:
 status['finished_unix']=time.time();save();fcntl.flock(lock,fcntl.LOCK_UN);lock.close()
 current=Path(f'/proc/{PID}/stat').read_text().rsplit(')',1)[1].split()
 if current[19]=='16011753' and current[0]=='T':
  os.kill(PID,signal.SIGCONT)
  status['matrix_resumed_unix']=time.time();save()
  window=json.loads((BASE/'matrix-compilation-window.json').read_text());window.update(status='coordinator_resumed',resumed_unix=time.time(),qualification=str(OUT/'progress.json'));(BASE/'matrix-compilation-window.json').write_text(json.dumps(window,indent=2)+'\n')
