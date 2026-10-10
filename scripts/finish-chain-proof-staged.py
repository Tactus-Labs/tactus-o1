#!/usr/bin/env python3
"""Release the recursive prover at a complete witness boundary, then wrap afresh.

This is a deliberate phase handoff, never a timeout-based retry or a proof bypass.
The native wrapper checks the journal digest, guest key, release VK root and proof;
the caller must additionally run chain-proof verify against the canonical export.
"""
import hashlib
import json
import os
import pathlib
import resource
import subprocess
import sys
import time


def retained_witness(directory, expected_key):
    for path in sorted(directory.glob('.tmp*')):
        if not path.is_file() or not 0 < path.stat().st_size <= 16 * 1024 * 1024:
            continue
        with path.open('rb') as stream:
            content = stream.read(16 * 1024 * 1024 + 1)
        if len(content) > 16 * 1024 * 1024:
            continue
        try:
            value = json.loads(content)
            if (not isinstance(value, dict) or int(value.get('vkey_hash', '-1')) != int(expected_key, 16)
                    or value.get('exit_code') != '0' or value.get('proof_nonce') != '0'
                    or not all(isinstance(value.get(k), str) for k in ('committed_values_digest', 'vk_root'))
                    or not all(isinstance(value.get(k), list) and value[k] for k in ('vars', 'felts', 'exts'))):
                continue
        except (ValueError, TypeError):
            continue  # The writer may not have finished yet.
        return path, content
    return None


def run(host, guest, root, circuit, wrapper=None):
    source = json.loads((root / 'proving-input.json').read_bytes())
    expected = bytes.fromhex(source['expected_journal_hex'][2:])
    key = source['guest_verifying_key']
    started = time.monotonic()
    usage_before = resource.getrusage(resource.RUSAGE_CHILDREN)
    with (root / 'prove.txt').open('w') as log:
        process = subprocess.Popen([str(host), 'prove-groth16', str(guest),
                                    str(root / 'proving-input.json'), str(root / 'proof')],
                                   stdout=log, stderr=subprocess.STDOUT)
        handoff = None
        try:
            while process.poll() is None:
                witness = retained_witness(root / 'tmp', key)
                if witness is not None:
                    if (root / 'proof/public-values.bin').read_bytes() != expected:
                        raise ValueError('recursive run journal differs from chain export')
                    path, content = witness
                    destination = root / 'retained-wrapped-witness.json'
                    with destination.open('xb') as output:
                        output.write(content)
                        output.flush()
                        os.fsync(output.fileno())
                    directory_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
                    try:
                        os.fsync(directory_fd)
                    finally:
                        os.close(directory_fd)
                    # Only terminate our own live child, after its complete output
                    # has been retained. Do not infer death from an observation gap.
                    process.terminate()
                    try:
                        status = process.wait(timeout=30)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        status = process.wait()
                    handoff = {'reason': 'deliberate fresh-process final wrapping after complete recursive witness',
                               'original_process_returncode': status, 'witness_source': str(path),
                               'witness_sha256': hashlib.sha256(content).hexdigest(), 'witness_bytes': len(content),
                               'continuous_full_proof_success': False}
                    break
                time.sleep(1)
            if handoff is None and process.wait() != 0:
                raise RuntimeError(f'recursive prover failed with exit {process.returncode}; no completed witness')
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=30)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
    usage_after = resource.getrusage(resource.RUSAGE_CHILDREN)
    phase = {'elapsed_seconds': time.monotonic() - started,
             'user_seconds': usage_after.ru_utime - usage_before.ru_utime,
             'system_seconds': usage_after.ru_stime - usage_before.ru_stime,
             'max_rss_kib': usage_after.ru_maxrss, 'handoff': handoff}
    (root / 'recursive-phase.json').write_text(json.dumps(phase, indent=2) + '\n')
    if handoff is None:
        selected = root / 'proof'
    else:
        selected = root / 'resumed-proof'
        with (root / 'resume-wrap.txt').open('w') as log:
            subprocess.run(['/usr/bin/time', '-v', str(wrapper or host.with_name('wrap-witness')),
                            str(circuit / 'v6.1.0'), str(root / 'retained-wrapped-witness.json'),
                            str(root / 'proof/public-values.bin'), key, str(selected)],
                           stdout=log, stderr=subprocess.STDOUT, check=True)
    (root / 'selected-proof-dir.txt').write_text(str(selected) + '\n')
    print('Real proof phase completed; fresh canonical verification still required:', selected, flush=True)


if __name__ == '__main__':
    if len(sys.argv) not in (5, 6):
        raise SystemExit('usage: finish-chain-proof-staged.py HOST GUEST RUN_DIR CIRCUIT_PARENT [WRAPPER]')
    run(*(pathlib.Path(arg).resolve() for arg in sys.argv[1:]))
