"""Pause only the outer coordinator during run-two fresh verification.
The proof runner/verifier keep running to completion. No proof is interrupted.
Resume the same coordinator with SIGCONT after the isolated compilation window.
"""
from pathlib import Path
import json,os,signal,time
base=Path('artifacts/sp1-optimization-round3');pid=278412
identity=Path(f'/proc/{pid}/stat').read_text().rsplit(')',1)[1].split()[19]
while True:
 state=Path(f'/proc/{pid}/stat').read_text().rsplit(')',1)[1].split()
 if state[19]!=identity: raise SystemExit('coordinator identity changed')
 matrix=json.loads((base/'matrix-progress.json').read_text())
 if any(r['name']=='threads8-shard19' for r in matrix['runs']):
  raise SystemExit('third run already started; leave matrix running')
 status=json.loads((base/'proof-threads8/status.json').read_text())
 if status['stage']=='fresh-verification':
  os.kill(pid,signal.SIGSTOP)
  record={'coordinator_pid':pid,'starttime':identity,'status':'coordinator_stopped',
          'unix':time.time(),'reason':'isolated compilation window between proof runs',
          'child_runner_continues':True,'proof_interrupted':False,
          'resume_command':'kill -CONT 278412',
          'must_wait_for_second_child_completion_before_compiling':True}
  (base/'matrix-compilation-window.json').write_text(json.dumps(record,indent=2)+'\n')
  print(json.dumps(record),flush=True);break
 if matrix['status']!='running':raise SystemExit('matrix is no longer running')
 time.sleep(2)
