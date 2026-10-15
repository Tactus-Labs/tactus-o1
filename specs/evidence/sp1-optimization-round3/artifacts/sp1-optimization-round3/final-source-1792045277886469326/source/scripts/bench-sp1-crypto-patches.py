#!/usr/bin/env python3
"""Build isolated SP1 crypto-patch variants and compare their real execution.

No CI or proof generation. Existing guest manifests, locks and deployment keys
are left intact. Requires the pinned SP1 CLI and Rust toolchains used by this repo.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parent.parent
HASHES = 'https://github.com/sp1-patches/RustCrypto-hashes'
PATCHES = {
    'sha3': (HASHES, '540d99e46fbe7aab00caf83c4144cb4eaaf62a17', 'sha3'),
    'k256': ('https://github.com/sp1-patches/elliptic-curves', '476243d31d3ffd9d882d0e5da1f6adaa2a204b62', 'k256'),
    'sha2_010': (HASHES, 'e48b656ebc806117554bb33c2f8687e4637e37ff', 'sha2'),
    'sha2_011': (HASHES, '8993e08b9f7c47cd4a056decbf85d2d7ab3fe77c', 'sha2'),
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, help='New experiment directory')
    args = parser.parse_args()
    (ROOT / 'artifacts').mkdir(exist_ok=True)
    if args.output:
        out = args.output.resolve()
        out.mkdir(parents=True, exist_ok=False)
    else:
        out = Path(tempfile.mkdtemp(prefix='sp1-patches-', dir=ROOT / 'artifacts'))
    env = os.environ.copy()
    env['CARGO_BUILD_JOBS'] = env.get('CARGO_BUILD_JOBS', '4')

    def run(command, log, cwd=ROOT):
        print(f'{log}: {command}', flush=True)
        with (out / log).open('w') as stream:
            subprocess.run(command, cwd=cwd, env=env, stdout=stream,
                           stderr=subprocess.STDOUT, check=True)

    run(['bash', 'scripts/build-proof-guest.sh'], 'baseline-build.txt')
    elf_rel = Path('target/elf-compilation/riscv64im-succinct-zkvm-elf/release/tactus-o1-sp1-guest')
    shutil.copy2(ROOT / 'proofs/sp1' / elf_rel, out / 'baseline.elf')
    shutil.copy2(ROOT / 'proofs/sp1/Cargo.lock', out / 'baseline.Cargo.lock')
    source = out / 'source'
    source.mkdir()
    for name in ['Cargo.toml', 'Cargo.lock', 'rust-toolchain.toml']:
        shutil.copy2(ROOT / name, source / name)
    for name in ['crates', 'proofs/sp1']:
        shutil.copytree(ROOT / name, source / name,
                        ignore=shutil.ignore_patterns('target', '__pycache__'))
    source_hashes = {str(p.relative_to(source)): hashlib.sha256(p.read_bytes()).hexdigest()
                     for p in sorted(source.rglob('*')) if p.is_file()}
    (out / 'source-hashes.json').write_text(json.dumps(source_hashes, indent=2) + '\n')
    workspace = source / 'proofs/sp1'
    original = (workspace / 'Cargo.toml').read_text()
    if '[patch.crates-io]' in original:
        raise RuntimeError('Baseline already has patches; review this experiment before rerunning')
    tool = Path(env.get('TACTUS_CARGO_PROVE', ROOT / 'artifacts/prover-tools/cargo-prove')).resolve()
    env['CC_riscv64im_succinct_zkvm_elf'] = env.get('TACTUS_PROOF_CC', 'clang')
    env['CFLAGS_riscv64im_succinct_zkvm_elf'] = (
        f'--target=riscv64-unknown-elf -march=rv64im -mabi=lp64 '
        f'-I{ROOT}/proofs/sp1/guest -include {ROOT}/proofs/sp1/guest/string.h')
    for variant, names, packages in [
        ('sha3-only', ['sha3'], ['sha3']),
        ('combined', list(PATCHES), ['k256', 'sha2@0.10.9', 'sha2@0.11.0']),
    ]:
        lines = ['\n[patch.crates-io]\n']
        for name in names:
            url, rev, package = PATCHES[name]
            lines.append(f'{name} = {{ package = "{package}", git = "{url}", rev = "{rev}" }}\n')
        (workspace / 'Cargo.toml').write_text(original + ''.join(lines))
        # Use the retained experiment lockfiles to pin transitive git dependencies
        # as well. They are separate from the production guest's Cargo.lock.
        pinned = ROOT / f'specs/evidence/sp1-crypto-patches/{variant}.Cargo.lock'
        if pinned.is_file():
            shutil.copy2(pinned, workspace / 'Cargo.lock')
        else:
            command = ['cargo', '+1.97.1', 'update']
            for package in packages:
                command += ['-p', package]
            run(command, f'{variant}-resolve.txt', workspace)
        run([str(tool), 'prove', 'build', '--locked', '-p', 'tactus-o1-sp1-guest'],
            f'{variant}-build.txt', workspace)
        shutil.copy2(workspace / elf_rel, out / f'{variant}.elf')
        shutil.copy2(workspace / 'Cargo.lock', out / f'{variant}.Cargo.lock')
        shutil.copy2(workspace / 'Cargo.toml', out / f'{variant}.Cargo.toml')
    env['CARGO_TARGET_DIR'] = str(ROOT / 'artifacts/prover-host/target')
    run(['cargo', '+1.97.1', 'build', '--release', '--locked', '--manifest-path',
         'proofs/sp1/Cargo.toml', '-p', 'tactus-o1-sp1-host', '--bin', 'crypto-patch-bench'], 'bench-build.txt')
    env.update(RAYON_NUM_THREADS='4', TOKIO_WORKER_THREADS='4',
               TACTUS_PATCH_CHAIN_INPUT=str(ROOT / 'specs/evidence/sealed-chain-proof/proving-input.json'))
    run([str(Path(env['CARGO_TARGET_DIR']) / 'release/crypto-patch-bench'),
         str(ROOT / 'specs/test-vectors/execution-v1/geth-1.17.8.json'), str(out / 'comparison'),
         *[str(out / f'{name}.elf') for name in ['baseline', 'sha3-only', 'combined']]], 'comparison.txt')
    print(f'Completed execution comparison: {out / "comparison/results.json"}')


if __name__ == '__main__':
    main()
