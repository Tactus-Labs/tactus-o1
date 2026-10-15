#!/usr/bin/env python3
"""Isolated execution profiling and rules-hash memoization candidate.

No CI, proof generation, production guest edits, or CKB writes. Uses the pinned
crypto-patch experiment manifests. Cycle-tracker regions overlap; do not sum them.
"""
import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess

ROOT = Path(__file__).resolve().parent.parent


def wrap_function(text, signature, label, indent=''):
    start = text.index(signature) + len(signature)
    end = text.index('\n' + indent + '}', start)
    body = text[start:end]
    return (text[:start] + '\n' + indent + '    println!("cycle-tracker-report-start: ' + label + '");\n'
            + indent + '    let measured_result = (|| {' + body + '\n' + indent + '    })();\n'
            + indent + '    println!("cycle-tracker-report-end: ' + label + '");\n'
            + indent + '    measured_result' + text[end:])


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
    original_hashes = {str(p.relative_to(source)): hashlib.sha256(p.read_bytes()).hexdigest()
                       for p in sorted(source.rglob('*')) if p.is_file()}
    (out / 'source-hashes.json').write_text(json.dumps(original_hashes, indent=2) + '\n')
    workspace = source / 'proofs/sp1'
    for name in ['Cargo.toml', 'Cargo.lock']:
        shutil.copy2(ROOT / 'specs/evidence/sp1-crypto-patches' / ('combined.' + name), workspace / name)
    env = os.environ.copy()
    env.update(CARGO_BUILD_JOBS='4', CARGO_NET_OFFLINE='true', RAYON_NUM_THREADS='4', TOKIO_WORKER_THREADS='4')
    env['CC_riscv64im_succinct_zkvm_elf'] = 'clang'
    env['CFLAGS_riscv64im_succinct_zkvm_elf'] = f'--target=riscv64-unknown-elf -march=rv64im -mabi=lp64 -I{ROOT}/proofs/sp1/guest -include {ROOT}/proofs/sp1/guest/string.h'

    def run(command, log, cwd=ROOT):
        print(f'{log}: {command}', flush=True)
        with (out / log).open('w') as stream:
            subprocess.run(command, cwd=cwd, env=env, stdout=stream, stderr=subprocess.STDOUT, check=True)

    execution = source / 'crates/tactus-o1-execution/src/lib.rs'
    journal = workspace / 'journal/src/lib.rs'
    original_execution = execution.read_text()
    original_journal = journal.read_text()
    tool = ROOT / 'artifacts/prover-tools/cargo-prove'
    elf_rel = Path('target/elf-compilation/riscv64im-succinct-zkvm-elf/release/tactus-o1-sp1-guest')
    for variant in ['profiled', 'memoized']:
        code = original_execution
        if variant == 'profiled':
            for signature, label, indent in [
                ('pub fn rules_hash() -> [u8; 32] {', 'rules-hash', ''),
                ('fn state_root(db: &InMemoryDB) -> B256 {', 'state-root', ''),
                ('    pub fn apply_batch(&mut self, bytes: &[u8]) -> Result<Vec<ExecutedBlock>, Error> {', 'apply-batch', '    '),
                (') -> Result<(TxEnvelope, TxEnv), Status> {', 'decode-transaction', ''),
            ]:
                code = wrap_function(code, signature, label, indent)
            j = original_journal.replace('    for _ in 0..prefix_batches {', '    println!("cycle-tracker-report-start: prefix");\n    for _ in 0..prefix_batches {')
            j = j.replace('    let before = *engine.anchor();', '    println!("cycle-tracker-report-end: prefix");\n    let before = *engine.anchor();')
            j = j.replace('    for _ in 0..interval_batches {', '    println!("cycle-tracker-report-start: interval");\n    for _ in 0..interval_batches {')
            j = j.replace('    let journal = Journal {', '    println!("cycle-tracker-report-end: interval");\n    let journal = Journal {')
            journal.write_text(j)
        else:
            signature = 'pub fn rules_hash() -> [u8; 32] {'
            start = code.index(signature) + len(signature)
            end = code.index('\n}', start)
            body = code[start:end]
            code = (code[:start] + '\n    static HASH: std::sync::OnceLock<[u8; 32]> = std::sync::OnceLock::new();\n'
                    + '    *HASH.get_or_init(|| {' + body + '\n    })' + code[end:])
            journal.write_text(original_journal)
        execution.write_text(code)
        shutil.copy2(execution, out / f'{variant}-execution.rs')
        shutil.copy2(journal, out / f'{variant}-journal.rs')
        run([str(tool), 'prove', 'build', '--locked', '-p', 'tactus-o1-sp1-guest'], f'{variant}-build.txt', workspace)
        shutil.copy2(workspace / elf_rel, out / f'{variant}.elf')

    baseline = ROOT / 'specs/evidence/sp1-crypto-patches/combined.elf.gz'
    (out / 'baseline.elf').write_bytes(gzip.decompress(baseline.read_bytes()))
    env['CARGO_TARGET_DIR'] = str(ROOT / 'artifacts/prover-host/target')
    run(['cargo', '+1.97.1', 'build', '--release', '--locked', '--offline', '--manifest-path',
         'proofs/sp1/Cargo.toml', '-p', 'tactus-o1-sp1-host', '--features', 'sp1-sdk/profiling',
         '--bin', 'proof-scaling-bench', '--bin', 'crypto-patch-bench'], 'host-build.txt')
    run([str(Path(env['CARGO_TARGET_DIR']) / 'release/proof-scaling-bench'),
         str(ROOT / 'specs/evidence/sealed-chain-proof/proving-input.json'), str(out / 'comparison'),
         *[str(out / f'{v}.elf') for v in ['baseline', 'profiled', 'memoized']]], 'comparison.txt')
    rows = json.loads((out / 'comparison/results.json').read_text())
    profiled = next(r for r in rows if r['variant'] == 'profiled' and r['case'] == 'all-9')
    assert profiled['invocations']['rules-hash'] == 11, 'profiling host must collect cycle trackers'
    assert profiled['cycle_tracker']['rules-hash'] > 0
    env['TACTUS_PATCH_CHAIN_INPUT'] = str(ROOT / 'specs/evidence/sealed-chain-proof/proving-input.json')
    run([str(Path(env['CARGO_TARGET_DIR']) / 'release/crypto-patch-bench'),
         str(ROOT / 'specs/test-vectors/execution-v1/geth-1.17.8.json'), str(out / 'regression'),
         str(out / 'memoized.elf')], 'regression.txt')
    manifest = {'proof_generated': False, 'production_modified': False,
                'elf_sha256': {v: hashlib.sha256((out / f'{v}.elf').read_bytes()).hexdigest() for v in ['baseline', 'profiled', 'memoized']},
                'input_sha256': hashlib.sha256((ROOT / 'specs/evidence/sealed-chain-proof/proving-input.json').read_bytes()).hexdigest()}
    (out / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    print(f'Completed: {out / "comparison/results.json"}', flush=True)


if __name__ == '__main__':
    main()
