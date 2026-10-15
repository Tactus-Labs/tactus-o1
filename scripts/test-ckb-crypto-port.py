#!/usr/bin/env python3
"""Run arithmetic differential tests locally in isolated copies of the vendors.

Does not run CI, generate ZK proofs or modify the vendored manifests/lockfiles.
The full SP1 SDK test suite is not included: it requires different proof artifacts.
"""
import argparse
import os
import pathlib
import re
import shutil
import subprocess
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=pathlib.Path)
    args = parser.parse_args()
    (ROOT / 'artifacts').mkdir(exist_ok=True)
    output = args.output or pathlib.Path(tempfile.mkdtemp(prefix='crypto-port-tests-', dir=ROOT / 'artifacts'))
    output = output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ, CARGO_BUILD_JOBS='2')
    # Reuse compilation products while keeping test source copies isolated.
    env['CARGO_TARGET_DIR'] = str(ROOT / 'artifacts/crypto-port-test-target')
    names = ['substrate-bn-succinct-rs-0.6.0', 'sp1-verifier-6.8.1']
    evidence = ROOT / 'specs/evidence/verifier-cycles'
    for name, lock, log in zip(names, ['field-test.Cargo.lock', 'verifier-test.Cargo.lock'],
                               ['field-tests.log', 'verifier-tests.log']):
        target = output / name
        shutil.copytree(ROOT / 'proofs/vendor' / name, target)
        manifest = target / 'Cargo.toml'
        text = manifest.read_text() + '\n[workspace]\n'
        if name.startswith('sp1-'):
            # These upstream dev dependencies are used only by the disabled
            # `full` feature tests, not the local projective-equivalence test.
            text = re.sub(r'\[dev-dependencies\.[^\]]+\]\n.*?(?=\n\[|\Z)', '', text, flags=re.S)
            text += '\n[patch.crates-io]\nsubstrate-bn-succinct-rs = { path = "../substrate-bn-succinct-rs-0.6.0" }\n'
        manifest.write_text(text)
        shutil.copyfile(evidence / lock, target / 'Cargo.lock')
        command = ['cargo', 'test', '--offline', '--locked', '--release', '--no-default-features',
                   '--manifest-path', str(manifest), '--lib']
        with (output / log).open('w') as stream:
            subprocess.run(command, cwd=ROOT, env=env, stdout=stream, stderr=subprocess.STDOUT, check=True)
        print((output / log).read_text().split('running ')[-1], flush=True)
    print(f'Test evidence: {output}')


if __name__ == '__main__':
    main()
