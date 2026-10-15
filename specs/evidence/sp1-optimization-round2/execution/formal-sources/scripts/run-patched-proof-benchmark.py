#!/usr/bin/env python3
"""Time a complete local patched-guest Groth16 pipeline on the retained workload.

Uses the same staged memory handoff as the historical run. The candidate input
changes only guest_verifying_key; it is NOT an authorized new CKB deployment.
No CI, remote proving, chain transaction, or production configuration change.
"""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parent.parent


def digest(path):
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--elf', type=Path, required=True)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--circuit-parent', type=Path,
                        default=ROOT / 'artifacts/prover-tools/circuits/groth16')
    args = parser.parse_args()
    elf, circuit = args.elf.resolve(), args.circuit_parent.resolve()
    lock = (ROOT / 'artifacts/.proof-run.lock').open('a')
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    out = args.output.resolve() if args.output else Path(tempfile.mkdtemp(prefix='patched-chain-proof-', dir=ROOT / 'artifacts'))
    if args.output:
        out.mkdir(parents=True, exist_ok=False)
    (out / 'tmp').mkdir()
    shutil.copy2(elf, out / 'guest.elf')
    elf = out / 'guest.elf'
    host = ROOT / 'artifacts/prover-host/target/release/chain-proof'
    wrapper = host.with_name('wrap-witness')
    env = os.environ.copy()
    env.update(RAYON_NUM_THREADS='4', TOKIO_WORKER_THREADS='4', GOMAXPROCS='2',
               GOMEMLIMIT='16GiB', GOGC='25', RUST_LOG='info', SP1_CIRCUIT_MODE='release',
               SP1_GROTH16_CIRCUIT_PATH=str(circuit), ELEMENT_THRESHOLD='50331648',
               HEIGHT_THRESHOLD='524288', SHARD_SIZE='1048576', TMPDIR=str(out / 'tmp'),
               TACTUS_PROOF_MODE='staged')
    for name in ['CORE', 'SETUP', 'PREPARE_REDUCE', 'RECURSION_EXECUTOR', 'RECURSION_PROVER']:
        env[f'SP1_WORKER_NUM_{name}_WORKERS'] = '1'
        env[f'SP1_WORKER_{name}_BUFFER_SIZE'] = '1'
    for name in ['WITHOUT_VK_VERIFICATION', 'SP1_DUMP']:
        env.pop(name, None)
    def run(command, log):
        with (out / log).open('w') as stream:
            subprocess.run(command, cwd=ROOT, env=env, stdout=stream,
                           stderr=subprocess.STDOUT, check=True)

    print(f'Proof benchmark directory: {out}', flush=True)
    run([str(ROOT / 'artifacts/prover-tools/cargo-prove'), 'prove', 'vkey', '--elf', str(elf)], 'vkey.txt')
    keys = re.findall(r'0x[0-9a-fA-F]{64}', (out / 'vkey.txt').read_text())
    if len(set(keys)) != 1:
        raise RuntimeError('Could not resolve one unambiguous guest key')
    source_path = ROOT / 'specs/evidence/sealed-chain-proof/proving-input.json'
    source = json.loads(source_path.read_bytes())
    original_key = source['guest_verifying_key']
    assert keys[0] != original_key, 'Expected a changed guest key'
    candidate = dict(source, guest_verifying_key=keys[0])
    assert {k for k in source if source[k] != candidate[k]} == {'guest_verifying_key'}
    (out / 'proving-input.json').write_text(json.dumps(candidate, indent=2) + '\n')
    environment_keys = ['RAYON_NUM_THREADS', 'TOKIO_WORKER_THREADS', 'GOMAXPROCS', 'GOMEMLIMIT',
                        'GOGC', 'SP1_CIRCUIT_MODE', 'SP1_GROTH16_CIRCUIT_PATH',
                        'ELEMENT_THRESHOLD', 'HEIGHT_THRESHOLD', 'SHARD_SIZE', 'TMPDIR', 'TACTUS_PROOF_MODE']
    environment_keys += sorted(k for k in env if k.startswith('SP1_WORKER_'))
    files = [elf, host, wrapper, source_path, out / 'proving-input.json', Path(__file__).resolve(),
             ROOT / 'scripts/finish-chain-proof-staged.py', ROOT / 'proofs/sp1/Cargo.lock']
    files += [circuit / 'v6.1.0' / name for name in ['groth16_vk.bin', 'groth16_pk.bin', 'groth16_circuit.bin']]
    manifest = {'environment': {k: env[k] for k in environment_keys},
                'sha256': {str(p): digest(p) for p in files}, 'original_guest_key': original_key,
                'candidate_guest_key': keys[0], 'changed_input_fields': ['guest_verifying_key'],
                'ckb_settlement': False, 'deployment_authorized': False, 'ci_run': False}
    (out / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    started = time.monotonic()
    (out / 'status.json').write_text(json.dumps({'stage': 'proving', 'started_unix': time.time()}) + '\n')
    run(['/usr/bin/time', '-v', 'python3', '-B', 'scripts/finish-chain-proof-staged.py',
         str(host), str(elf), str(out), str(circuit)], 'pipeline.txt')
    pipeline_seconds = time.monotonic() - started
    selected = Path((out / 'selected-proof-dir.txt').read_text().strip())
    (out / 'status.json').write_text(json.dumps({'stage': 'fresh-verification', 'pipeline_seconds': pipeline_seconds}) + '\n')
    verify_started = time.monotonic()
    run(['/usr/bin/time', '-v', str(host), 'verify', str(elf), str(out / 'proving-input.json'), str(selected)], 'fresh-verification.txt')
    verification_seconds = time.monotonic() - verify_started
    result = json.loads((selected / 'result.json').read_bytes())
    assert result['proof_generated'] and result['proof_kind'] == 'SP1 real Groth16'
    assert result['guest_verifying_key'] == keys[0] and len(result['negative_controls']) == 15
    assert (selected / 'public-values.bin').read_bytes() == bytes.fromhex(source['expected_journal_hex'][2:])
    assert 'Fresh process verified real proof and exact expected journal' in (out / 'fresh-verification.txt').read_text()
    completion = {'proof_generated': True, 'proof_directory': str(selected),
                  'pipeline_seconds': pipeline_seconds, 'fresh_verification_seconds': verification_seconds,
                  'total_seconds_including_fresh_verification': time.monotonic() - started,
                  'preparation_and_build_excluded': True, 'fresh_verification': True,
                  'negative_controls': result['negative_controls'],
                  'public_values_unchanged': True, 'staged': bool(result.get('resumed_from_wrapped_witness')),
                  'ckb_settlement': False, 'deployment_authorized': False, 'production_ready': False}
    (out / 'completion.json').write_text(json.dumps(completion, indent=2) + '\n')
    (out / 'status.json').write_text(json.dumps({'stage': 'complete'}) + '\n')
    print(json.dumps(completion, indent=2), flush=True)


if __name__ == '__main__':
    main()
