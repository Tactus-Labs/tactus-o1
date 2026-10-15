"""Audit and archive the completed filled-workload proof; never starts proving."""
from pathlib import Path
import gzip
import hashlib
import json
import shutil

root = Path.cwd()
base = root / 'artifacts/sp1-optimization-round2'
run = root / 'artifacts/sp1-optimized-transfers32-proof'
archive = root / 'specs/evidence/sp1-optimization-round2/transfers32-proof'

def read(path):
    return json.loads(path.read_bytes())

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

completion = read(run / 'completion.json')
assert completion['proof_generated'] and completion['fresh_verification']
assert completion['public_values_unchanged']
assert len(set(completion['negative_controls'])) == 15
assert not completion['ckb_settlement'] and not completion['deployment_authorized']
selected = Path((run / 'selected-proof-dir.txt').read_text().strip())
assert selected.parent == run
result = read(selected / 'result.json')
manifest = read(run / 'manifest.json')
formal = read(base / 'formal-manifest.json')
source = read(base / 'transfers-32-proof-input.json')
candidate = read(run / 'proving-input.json')
assert source.keys() == candidate.keys()
assert {k for k in source if source[k] != candidate[k]} == {'guest_verifying_key'}
assert candidate['guest_verifying_key'] == result['guest_verifying_key'] == formal['formal_guest_key']
assert sha(run / 'guest.elf') == formal['guest_sha256']
assert result['proof_kind'] == 'SP1 real Groth16' and result['proof_generated']
assert result['negative_controls'] == completion['negative_controls']
public = (selected / 'public-values.bin').read_bytes()
assert public == bytes.fromhex(source['expected_journal_hex'].removeprefix('0x'))
assert public == bytes.fromhex(result['public_values_hex'].removeprefix('0x'))
rows = read(base / 'formal-qualification/results.json')
row = next(r for r in rows if r['case'] == 'transfers-32')
assert row['native_match'] and row['geth_checked']
assert public == (base / 'formal-qualification' / f"formal-{row['case_index']}.public.bin").read_bytes()
assert len((selected / 'proof.bin').read_bytes()) == result['proof_bytes']
assert len((selected / 'groth16-proof.bin').read_bytes()) == result['groth16_wire_bytes']
assert 'Fresh process verified real proof and exact expected journal' in (run / 'fresh-verification.txt').read_text()
for name, frozen in [('run-patched-proof-benchmark.py','runner-at-launch.py'), ('finish-chain-proof-staged.py','staged-runner-at-launch.py')]:
    assert sha(run / frozen) == manifest['sha256'][str(root / 'scripts' / name)]
phase = read(run / 'recursive-phase.json')
assert sha(run / 'retained-wrapped-witness.json') == phase['handoff']['witness_sha256']
comparison = {
    'workload': '32 signed transfers in one synthetic block; not canonical CKB publication',
    'same_workload_as_historical_59_minute_run': False,
    'instructions': row['instructions'], 'prover_gas': row['prover_gas'],
    'recursive_seconds': phase['elapsed_seconds'],
    'final_wrapping_and_verification_seconds': result['wrapping_and_verification_seconds'],
    'comparable_seconds': phase['elapsed_seconds'] + result['wrapping_and_verification_seconds'],
    'pipeline_seconds': completion['pipeline_seconds'],
    'fresh_verification_seconds': completion['fresh_verification_seconds'],
    'including_fresh_verification_seconds': completion['total_seconds_including_fresh_verification'],
    'recursive_peak_rss_kib': phase['max_rss_kib'],
    'public_matches_formal_qualification': True,
    'proof_files_and_launch_manifest_verified': True,
}
(run / 'timing-summary.json').write_text(json.dumps(comparison, indent=2) + '\n')
archive.mkdir(exist_ok=False)
for name in ['completion.json','manifest.json','status.json','recursive-phase.json','proving-input.json','pipeline.txt','resume-wrap.txt','fresh-verification.txt','vkey.txt','machine-during-proving.json','machine-during-wrap.json','runner-at-launch.py','staged-runner-at-launch.py','timing-summary.json']:
    shutil.copy2(run / name, archive / name)
for name in ['prove.txt','retained-wrapped-witness.json']:
    with (archive / (name + '.gz')).open('wb') as raw:
        with gzip.GzipFile(fileobj=raw, mode='wb', mtime=0) as compressed:
            compressed.write((run / name).read_bytes())
shutil.copytree(selected, archive / 'proof')
shutil.copy2(run / 'proof/execution-report.txt', archive / 'execution-report.txt')
assert gzip.decompress((archive / 'retained-wrapped-witness.json.gz').read_bytes()) == (run / 'retained-wrapped-witness.json').read_bytes()
print(json.dumps(comparison, indent=2))
