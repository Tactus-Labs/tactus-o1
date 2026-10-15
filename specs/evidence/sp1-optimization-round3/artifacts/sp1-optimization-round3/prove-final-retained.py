"""Measure the final guest on the original retained ~59-minute workload."""
from pathlib import Path
import hashlib,json,os,subprocess,time
ROOT=Path.cwd();B=ROOT/'artifacts/sp1-optimization-round3';STATUS=B/'final-retained-progress.json'
assert not STATUS.exists(),'Preserve existing run; do not restart'
original=json.loads((B/'final-source-progress.json').read_text());expected=original['output']
status={'status':'waiting_for_final_source','final_source_output':expected,'ci_run':False,'production_ready':False}
def save():STATUS.write_text(json.dumps(status,indent=2)+'\n')
save()
while True:
 f=json.loads((B/'final-source-progress.json').read_text());assert f['output']==expected
 if f['status']=='complete':break
 if f['status']!='running':status.update(status='upstream_failed',error=f.get('error'));save();raise SystemExit(2)
 time.sleep(10)
F=Path(expected);OUT=F/'retained-proof'
def unchanged():
 for name,expected in json.loads((F/'source-sha256.json').read_text()).items():assert hashlib.sha256((ROOT/name).read_bytes()).hexdigest()==expected,name
try:
 unchanged();source=ROOT/'specs/evidence/sealed-chain-proof/proving-input.json';value=json.loads(source.read_text());assert value['prefix_batches']==0 and len(value['batches'])==9
 cmd=['python3','-B','scripts/run-patched-proof-benchmark.py','--elf',str(F/'full.elf'),'--host',str(B/'proof-tools/chain-proof'),'--input',str(source),'--output',str(OUT),'--threads','8','--go-threads','4','--shard-size','1048576']
 status.update(status='running',output=str(OUT),command=cmd,started_unix=time.time(),same_retained_workload=True,guest_key_replacement_only=True);save()
 (F/'retained-runner-at-launch.py').write_bytes(Path(__file__).read_bytes())
 with (F/'retained-proof-runner.txt').open('w') as log:r=subprocess.run(cmd,cwd=ROOT,stdout=log,stderr=subprocess.STDOUT)
 assert r.returncode==0,'Retained proof failed; preserve artifacts'
 c=json.loads((OUT/'completion.json').read_text());assert c['proof_generated'] and c['fresh_verification'] and len(set(c['negative_controls']))==15
 selected=Path((OUT/'selected-proof-dir.txt').read_text().strip());result=json.loads((selected/'result.json').read_text());phase=json.loads((OUT/'recursive-phase.json').read_text());comparable=phase['elapsed_seconds']+result['wrapping_and_verification_seconds']
 assert (selected/'public-values.bin').read_bytes()==bytes.fromhex(value['expected_journal_hex'].removeprefix('0x'))
 unchanged();status.update(status='complete',completion=c,comparable_seconds=comparable,recursive_max_rss_kib=phase['max_rss_kib'],baseline_59min_comparable_seconds=3536.863,round2_comparable_seconds=1189.920512,reduction_vs_59min_percent=100*(1-comparable/3536.863),finished_unix=time.time(),source_unchanged=True);save()
except BaseException as e:status.update(status='failed',error=repr(e));save();raise
