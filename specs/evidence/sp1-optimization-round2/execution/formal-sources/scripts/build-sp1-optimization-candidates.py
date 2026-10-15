#!/usr/bin/env python3
"""Build pinned crypto/batch/proving ablations in an isolated source tree."""
import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess

ROOT = Path(__file__).resolve().parent.parent


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    source = out / 'source'
    source.mkdir()
    for name in ['Cargo.toml', 'Cargo.lock', 'rust-toolchain.toml']:
        shutil.copy2(ROOT / name, source / name)
    for name in ['crates', 'proofs/sp1']:
        shutil.copytree(ROOT / name, source / name, ignore=shutil.ignore_patterns('target', '__pycache__'))
    workspace = source / 'proofs/sp1'
    for name in ['Cargo.toml', 'Cargo.lock']:
        shutil.copy2(ROOT / 'specs/evidence/sp1-crypto-patches' / ('combined.' + name), workspace / name)
    execution = source / 'crates/tactus-o1-execution/src/lib.rs'
    manifest = execution.parent.parent / 'Cargo.toml'
    full_code, full_manifest = execution.read_text(), manifest.read_text()
    env = os.environ.copy()
    env.update(CARGO_BUILD_JOBS='4', CARGO_NET_OFFLINE='true', CC_riscv64im_succinct_zkvm_elf='clang')
    env['CFLAGS_riscv64im_succinct_zkvm_elf'] = f'--target=riscv64-unknown-elf -march=rv64im -mabi=lp64 -I{ROOT}/proofs/sp1/guest -include {ROOT}/proofs/sp1/guest/string.h'
    for variant in ['constant-only', 'batch-optimized', 'full']:
        code = full_code
        if variant == 'constant-only':
            code = code.replace('let (input, summary) = BatchInput::decode_with_summary(bytes, &self.anchor)?;',
                                'let summary = batch::validate_batch(bytes, &self.anchor)?;\n        let input = BatchInput::decode(bytes, &self.anchor)?;')
        execution.write_text(code)
        manifest.write_text(full_manifest if variant == 'full' else full_manifest.replace('features = ["std", "portable"]', 'features = ["std", "portable", "secp256k1"]'))
        shutil.copy2(execution, out / f'{variant}-execution.rs')
        shutil.copy2(manifest, out / f'{variant}-execution.Cargo.toml')
        print('building', variant, flush=True)
        with (out / f'{variant}-build.txt').open('w') as stream:
            subprocess.run([str(ROOT / 'artifacts/prover-tools/cargo-prove'), 'prove', 'build', '--locked', '-p', 'tactus-o1-sp1-guest'], cwd=workspace, env=env, stdout=stream, stderr=subprocess.STDOUT, check=True)
        shutil.copy2(workspace / 'target/elf-compilation/riscv64im-succinct-zkvm-elf/release/tactus-o1-sp1-guest', out / f'{variant}.elf')
    (out / 'baseline.elf').write_bytes(gzip.decompress((ROOT / 'specs/evidence/sp1-crypto-patches/combined.elf.gz').read_bytes()))
    files = {str(p.relative_to(source)): hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(source.rglob('*')) if p.is_file() and 'target' not in p.relative_to(source).parts}
    result = {'source_sha256': files, 'elf_sha256': {v: hashlib.sha256((out / f'{v}.elf').read_bytes()).hexdigest() for v in ['baseline', 'constant-only', 'batch-optimized', 'full']}, 'proof_generated': False}
    (out / 'manifest.json').write_text(json.dumps(result, indent=2) + '\n')
    print('Completed', out, flush=True)


if __name__ == '__main__':
    main()
