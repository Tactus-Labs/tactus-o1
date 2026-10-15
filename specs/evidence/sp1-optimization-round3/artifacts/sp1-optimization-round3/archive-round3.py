"""Reconcile completed local evidence and retain a checksum-verified archive.
No proofs, CI, network calls, or deployment. Run only after final qualification.
"""
from pathlib import Path
import fcntl,gzip,hashlib,json,os,re,shutil
ROOT=Path.cwd();BASE=ROOT/'artifacts/sp1-optimization-round3'
OUT=ROOT/'specs/evidence/sp1-optimization-round3'
def read(p):return json.loads(p.read_text())
def sha(p):
 h=hashlib.sha256()
 with p.open('rb') as stream:
  for b in iter(lambda:stream.read(1024*1024),b''):h.update(b)
 return h.hexdigest()
lock=(ROOT/'artifacts/.proof-run.lock').open('a');fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
matrix=read(BASE/'matrix-progress.json');sparse=read(BASE/'optimized-proof-pipeline.json');final=read(BASE/'final-source-progress.json')
retained=read(BASE/'final-retained-progress.json')
assert matrix['status']==sparse['status']==final['status']==retained['status']=='complete'
assert sparse['two_real_proofs_verified'] and sparse['local_two_settlements_accepted'] and sparse['local_reorg_qualified']
source=Path(sparse['source_output']);sparse_out=Path(sparse['output']);formal=Path(final['output'])
for label in ['two-settlements','settlement-reorg']:
 check=sparse[label]['check'];assert check['pinned_guest_key']==sparse['guest_key'] and check['settlement_elf_sha256']==sha(source/'settlement.elf')
 assert check['evidence_sha256']==sha(Path(sparse[label]['directory'])/'evidence.json')
for label in ['full','native']:assert final['guests'][label]['sha256']==sha(formal/(label+'.elf'))
for frozen in [source,formal]:
 for name,expected in read(frozen/'source-sha256.json').items():assert sha(ROOT/name)==expected,name
assert final['source_unchanged'] and all(r['status']=='passed' for r in final['checks'])
assert all(r['status']=='passed' for r in sparse['checks'])
workload=read(BASE/'retained-workload-reconciliation.json');assert workload['exact_workload_match_except_guest_key'] and workload['expected_journal_identical']
for item in workload['inputs']:assert sha(Path(item['path']))==item['sha256']
coverage=read(BASE/'test-coverage-reconciliation.json');assert coverage['earlier_suite_status']=='complete' and coverage['sparse_pipeline_complete'] and coverage['formal_build_and_execution_checks_passed']
for item in coverage['changed_previously_hashed_files']:assert sha(ROOT/item['path'])==item['current_sha256']
proofs=[]
def reconcile(run,expected_key=None,expected_elf=None,canonical_input=None):
 c=read(run/'completion.json');m=read(run/'manifest.json');selected=Path((run/'selected-proof-dir.txt').read_text().strip())
 assert selected.parent==run
 r=read(selected/'result.json');input=read(run/'proving-input.json')
 assert c['proof_generated'] and c['fresh_verification'] and len(set(c['negative_controls']))==15
 assert r['negative_controls']==c['negative_controls'] and r['proof_kind']=='SP1 real Groth16'
 public=(selected/'public-values.bin').read_bytes()
 assert public==bytes.fromhex(input['expected_journal_hex'].removeprefix('0x'))==bytes.fromhex(r['public_values_hex'].removeprefix('0x'))
 assert input['guest_verifying_key']==r['guest_verifying_key']
 if expected_key:assert r['guest_verifying_key']==expected_key
 if expected_elf:assert sha(run/'guest.elf')==sha(expected_elf)
 if canonical_input:assert input==read(canonical_input),'Canonical proof input was changed'
 assert len((selected/'proof.bin').read_bytes())==r['proof_bytes']
 assert len((selected/'groth16-proof.bin').read_bytes())==r['groth16_wire_bytes']
 assert 'Fresh process verified real proof and exact expected journal' in (run/'fresh-verification.txt').read_text()
 phase=read(run/'recursive-phase.json');assert sha(run/'retained-wrapped-witness.json')==phase['handoff']['witness_sha256']
 timing={'run':str(run.relative_to(ROOT)),'guest_key':r['guest_verifying_key'],'guest_sha256':sha(run/'guest.elf'),'comparable_seconds':phase['elapsed_seconds']+r['wrapping_and_verification_seconds'],'total_seconds_including_fresh_verification':c['total_seconds_including_fresh_verification'],'recursive_max_rss_kib':phase['max_rss_kib'],'fresh_sdk_verified':True,'negative_controls':c['negative_controls'],'canonical_input_unchanged':bool(canonical_input)}
 proofs.append(timing)
for label in ['threads4','threads8','threads8-shard19']:reconcile(BASE/('proof-'+label),expected_elf=BASE/'adaptive.elf')
for label in ['first','second']:reconcile(sparse_out/('proof-'+label),sparse['guest_key'],source/'guest.elf',source/(label+'-sparse-input.json'))
if not final['full_identical_to_proved_adaptive']:reconcile(formal/'full-proof',final['guests']['full']['guest_key'],formal/'full.elf')
reconcile(Path(retained['output']),final['guests']['full']['guest_key'],formal/'full.elf')
assert retained['same_retained_workload'] and retained['source_unchanged']
history=read(Path(sparse['history_qualification']));assert [r['prefix_batches'] for r in history]==[1,256,1024] and all(r['frozen_replay_guest_transition_match'] and r['guest_prefix_batches']==0 for r in history)
assert len(read(source/'qualification/results.json'))==25 and len(read(formal/'full-qualification/results.json'))==26
# Every archive byte is reconciled to its original; binaries excluded below
# remain pinned by the frozen artifact manifests and preserved in artifacts/.
OUT.mkdir(parents=True,exist_ok=False)
index=[];seen=set()
def retain(p):
 p=p.resolve()
 if p in seen:return
 seen.add(p);relative=p.relative_to(ROOT);dst=OUT/relative
 compressed=p.suffix=='.elf' or p.name=='retained-wrapped-witness.json'
 if compressed:dst=Path(str(dst)+'.gz')
 dst.parent.mkdir(parents=True,exist_ok=True)
 if compressed:
  with p.open('rb') as src,dst.open('wb') as raw,gzip.GzipFile(fileobj=raw,mode='wb',mtime=0) as target:shutil.copyfileobj(src,target)
  h=hashlib.sha256()
  with gzip.open(dst,'rb') as stream:
   for b in iter(lambda:stream.read(1024*1024),b''):h.update(b)
  assert h.hexdigest()==sha(p)
 else:shutil.copy2(p,dst);assert sha(p)==sha(dst)
 index.append({'source':str(relative),'archive':str(dst.relative_to(OUT)),'source_sha256':sha(p),'stored_sha256':sha(dst),'gzip':compressed})
def tree(directory):
 for parent,dirs,files in os.walk(directory):
  dirs[:]=[d for d in dirs if d not in ['target','tmp','.git','__pycache__','host','oracle','node','peer','node2']]
  for name in files:
   p=Path(parent)/name
   if p.suffix in ['.json','.txt','.log','.md','.rs','.toml','.lock','.py','.sh','.h','.c','.ld','.bin','.elf']:retain(p)
for p in BASE.iterdir():
 if p.is_file() and p.name!='progress.json' and p.suffix in ['.json','.py','.txt','.md','.elf']:retain(p)
for name in ['proof-tools','sparse-proof-tools','adaptive','reuse','atomic','adaptive-qualification','sparse-candidate','sparse-guest-qualification','state-workloads','state-ablation','qualifications','pinned-verification','history-qualification','history-scaling-inputs','proof-threads4','proof-threads8','proof-threads8-shard19']:
 tree(BASE/name)
for directory in [source,sparse_out,formal]:tree(directory)
preparation=read(BASE/'optimized-pipeline.json')
for directory in [preparation['bootstrap_directory'],preparation['two-inputs_directory'],sparse['two-settlements']['directory'],sparse['settlement-reorg']['directory']]:
 for p in Path(directory).iterdir():
  if p.is_file():retain(p)
for p in [ROOT/'specs/SP1_OPTIMIZATION_ROUND3_REPORT.md',ROOT/'specs/PRODUCTION_READINESS.md',ROOT/'specs/evidence/sealed-chain-proof/proving-input.json',ROOT/'artifacts/sp1-optimization-round2/transfers-32-proof-input.json',ROOT/'artifacts/native-guest-qXKMQ1qa/input-0.json',ROOT/'artifacts/native-guest-qXKMQ1qa/input-1.json']:retain(p)
for directory in ['specs/evidence/sp1-patched-proving','specs/evidence/sp1-optimization-round2/retained-proof']:
 for name in ['proving-input.json','manifest.json','completion.json','recursive-phase.json','proof/result.json']:
  retain(ROOT/directory/name)
(OUT/'archive-index.json').write_text(json.dumps(index,indent=2)+'\n')
audit={'status':'evidence_reconciled','ci_run':False,'production_ready':False,'proofs':proofs,'sparse_two_settlements':sparse['two-settlements'],'sparse_reorg':sparse['settlement-reorg'],'history':history,'full_final_guest':final['guests']['full'],'native_final_guest':final['guests']['native'],'native_qualification':'execution only','sources_match_current_worktree':True,'binary_oracle_and_prover_hosts':'Preserved in original artifacts directories; hashes retained, binaries omitted from this archive.'}
audit['requirements']=[
 {'id':'redundant-work','status':'passed','evidence':'Final full/native guest equivalence and full instruction comparison; complete final full proof.'},
 {'id':'input-memory','status':'passed','evidence':'Borrowed parsing and bounded binary witnesses; full and sparse guest equivalence and real proofs.'},
 {'id':'atomic-state','status':'passed','evidence':'Broader local execution tests plus updated sparse overlay/deletion/rollback tests; Geth and actual settlements.'},
 {'id':'verification','status':'passed','evidence':'Pinned verification positives and seven rejection cases; independent fresh SDK verification for all seven new proofs.'},
 {'id':'prover-tuning','status':'passed','evidence':'Three real same-input/same-ELF resource experiments with memory and phase timing records.'},
 {'id':'incremental-proof','status':'passed','evidence':'Two exact-key actual sparse proofs, consecutive CKB acceptance, P2P reorg/reapplication and bounded-history guest execution.'},
 {'id':'qualification','status':'passed','evidence':'Final formal source/key pinning, Geth/native equivalence, real proofs, test coverage reconciliation and this archived evidence. Archive integrity is checked after writing SHA256SUMS.'}
]
(OUT/'completion-audit.json').write_text(json.dumps(audit,indent=2)+'\n')
files=sorted(p for p in OUT.rglob('*') if p.is_file());(OUT/'SHA256SUMS').write_text(''.join(sha(p)+'  '+str(p.relative_to(OUT))+'\n' for p in files))
for line in (OUT/'SHA256SUMS').read_text().splitlines():
 expected,name=line.split('  ',1);assert sha(OUT/name)==expected,name
print(json.dumps({'files_verified':len(files),'archive':str(OUT),'real_proofs_reconciled':len(proofs),'requirements':[r['id'] for r in audit['requirements']]},indent=2))
