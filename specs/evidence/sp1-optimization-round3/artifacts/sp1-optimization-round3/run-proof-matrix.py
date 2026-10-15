from pathlib import Path
import json,os,subprocess,time
root=Path.cwd();base=root/'artifacts/sp1-optimization-round3'
runs=[('threads4',4,2,1048576),('threads8',8,4,1048576),('threads8-shard19',8,4,524288)]
progress={'status':'running','runs':[],'same_elf':str(base/'adaptive.elf'),'same_input':str(root/'artifacts/sp1-optimization-round2/transfers-32-proof-input.json')}
def save():
 (base/'matrix-progress.json').write_text(json.dumps(progress,indent=2)+'\n')
for name,threads,go,shard in runs:
 out=base/('proof-'+name)
 cmd=['python3','-B',str(root/'scripts/run-patched-proof-benchmark.py'),'--elf',progress['same_elf'],'--input',progress['same_input'],'--host',str(base/'proof-tools/chain-proof'),'--output',str(out),'--threads',str(threads),'--go-threads',str(go),'--shard-size',str(shard)]
 entry={'name':name,'status':'running','command':cmd,'started_unix':time.time()};progress['runs'].append(entry);save()
 with (base/(name+'-runner.txt')).open('w') as log:
  process=subprocess.Popen(cmd,stdout=log,stderr=subprocess.STDOUT)
  entry['pid']=process.pid;save()
  with (base/(name+'-machine.jsonl')).open('w') as samples:
   while process.poll() is None:
    samples.write(json.dumps({'unix':time.time(),'meminfo':Path('/proc/meminfo').read_text(),'memory_pressure':Path('/proc/pressure/memory').read_text(),'loadavg':Path('/proc/loadavg').read_text()})+'\n');samples.flush()
    time.sleep(10)
  entry['exit_code']=process.returncode
 if process.returncode:
  entry['status']='failed';progress['status']='failed';save();raise SystemExit(process.returncode)
 completion=json.loads((out/'completion.json').read_text())
 assert completion['proof_generated'] and completion['fresh_verification'] and len(completion['negative_controls'])==15
 phase=json.loads((out/'recursive-phase.json').read_text())
 selected=Path((out/'selected-proof-dir.txt').read_text().strip())
 result=json.loads((selected/'result.json').read_text())
 entry.update(status='complete',completion=completion,comparable_seconds=phase['elapsed_seconds']+result['wrapping_and_verification_seconds'],recursive_max_rss_kib=phase['max_rss_kib'])
 save();print(name,entry['comparable_seconds'],flush=True)
progress['status']='complete';save()
