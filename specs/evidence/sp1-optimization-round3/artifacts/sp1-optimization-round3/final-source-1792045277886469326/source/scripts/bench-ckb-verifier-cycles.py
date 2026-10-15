#!/usr/bin/env python3
"""Replay retained real-proof transactions with baseline/optimized CKB programs.

Runs only the selected type-script group, not all transaction scripts or consensus.
--bin replacement preserves old deployment identities for a controlled code-only
comparison. It does not demonstrate migration of an existing settlement deployment.
"""
import argparse
import gzip
import hashlib
import json
import pathlib
import re
import subprocess
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--debugger', type=pathlib.Path, default=ROOT / 'artifacts/debugger/ckb-debugger')
    parser.add_argument('--output', type=pathlib.Path)
    args = parser.parse_args()
    (ROOT / 'artifacts').mkdir(exist_ok=True)
    output = (args.output or pathlib.Path(tempfile.mkdtemp(prefix='verifier-cycles-', dir=ROOT / 'artifacts'))).resolve()
    output.mkdir(parents=True, exist_ok=True)
    evidence = ROOT / 'specs/evidence/verifier-cycles'
    results = {'scope': 'selected CKB type script; retained real proof; binary replacement',
               'debugger_sha256': digest(args.debugger), 'cases': [], 'ci_run': False}
    for label, executable in [('receipt', 'proof_check'), ('settlement', 'settlement')]:
        tx = output / (label + '.json')
        tx.write_bytes(gzip.decompress((evidence / (label + '.json.gz')).read_bytes()))
        baseline = output / ('baseline-' + label + '.elf')
        baseline.write_bytes(gzip.decompress((evidence / ('baseline-' + label + '.elf.gz')).read_bytes()))
        optimized = ROOT / 'artifacts' / f'tactus_o1_{executable}_script.elf'
        row = {'case': label, 'tx_sha256': digest(tx)}
        for mode, binary, budget in [('baseline', baseline, 10_000_000_000),
                                     ('optimized', optimized, 3_500_000_000)]:
            cmd = [str(args.debugger), '--mode', 'fast', '--tx-file', str(tx), '--script',
                   'output.0.type', '--bin', str(binary), '--max-cycles', str(budget)]
            proc = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, timeout=120, check=True)
            text = proc.stdout + proc.stderr
            (output / f'{label}-{mode}.txt').write_text(text)
            match = re.search(r'All cycles: (\d+)', text)
            if not re.search(r'(?m)^Run result: 0$', text) or not match:
                raise RuntimeError(f'{label}/{mode}: {text}')
            row[mode] = {'cycles': int(match[1]), 'elf_sha256': digest(binary), 'limit': budget}
        if row['optimized']['cycles'] >= row['baseline']['cycles']:
            raise RuntimeError('No measured cycle improvement')
        row['reduction_percent'] = 100 * (1 - row['optimized']['cycles'] / row['baseline']['cycles'])
        results['cases'].append(row)
    (output / 'result.json').write_text(json.dumps(results, indent=2) + '\n')
    print(json.dumps(results, indent=2))


if __name__ == '__main__':
    main()
