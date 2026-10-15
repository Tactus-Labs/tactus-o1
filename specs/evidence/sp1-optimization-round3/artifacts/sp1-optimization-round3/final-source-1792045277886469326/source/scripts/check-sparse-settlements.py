#!/usr/bin/env python3
"""Reconcile sparse local CKB evidence against exact script/key/proof artifacts.

Retains all existing deployment, negative-control, canonical-consumption and
recovery checks. This is evidence consistency checking, not cryptographic proof
verification; the real CKB execution and independent SDK checks remain required.
"""
import hashlib
import importlib.util
import json
from pathlib import Path
import sys


def sibling(name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


bootstrap = sibling('check-settlement-bootstrap')
require, raw, digest = bootstrap.require, bootstrap.raw, bootstrap.digest
SPARSE_PROFILE = digest(b'tactus/o1/sparse-proof-profile/v1' + b'TO1SPF01;genesis-allocation-or-authenticated-nonzero-boundary;ethereum-mpt-sparse-account-storage-code;missing-witness-fatal;linked-256-header-window;nonempty-contiguous-interval;no-withdrawal-authorization')


def check_document(document, settlement_elf, expected_guest_key, proof_dirs=()):
    require(len(raw(expected_guest_key)) == 32 and raw(expected_guest_key) != bytes(32), 'invalid pinned guest key')
    result = document['results']
    require(result['proof_profile'] == 'TO1SPF01', 'not sparse laboratory evidence')
    code = digest(settlement_elf)
    require(raw(result['settlement_code_hash']) == code, 'wrong compiled settlement program')
    export = result['proving_input']
    require(export['guest_verifying_key'] == expected_guest_key, 'export differs from independently pinned guest key')
    records = {r['label']: r for r in document['evidence']}
    deployed = records['settlement/deploy immutable programs']
    require(deployed['result'] == 'committed' and any(raw(data) == settlement_elf
            for data in deployed['transaction']['outputs_data']), 'compiled script not in actual deployment record')
    params = dict(journal_magic=b'TO1SPF01', journal_profile=SPARSE_PROFILE)
    suite = result['suite']
    if suite == 'settlement-bootstrap-v1':
        require(not proof_dirs, 'unexpected proof directories')
        checked = bootstrap.check_document(document, **params)
    elif suite == 'settlement-next-input-v1':
        require(not proof_dirs, 'unexpected proof directories')
        checked = sibling('check-next-proof-input').check_document(document, **params)
    elif suite == 'settlement-first-proof-v1':
        require(len(proof_dirs) == 1, 'first proof directory required')
        checked = sibling('check-first-settlement').check_document(document, proof_dirs[0], **params)
    elif suite == 'settlement-two-proofs-v1':
        require(len(proof_dirs) == 2, 'two actual proof directories required')
        checked = sibling('check-two-settlements').check_document(document, *proof_dirs, **params)
    elif suite == 'settlement-proof-p2p-reorg-v1':
        require(len(proof_dirs) == 1, 'first proof directory required for reorg')
        checked = sibling('check-settlement-reorg').check_document(document, proof_dirs[0], **params)
    else:
        raise ValueError('unsupported sparse evidence suite')
    return dict(checked, profile='TO1SPF01', pinned_guest_key=expected_guest_key,
                settlement_elf_sha256=hashlib.sha256(settlement_elf).hexdigest(),
                cryptographic_verification_performed_by_checker=False)


if __name__ == '__main__':
    if not 4 <= len(sys.argv) <= 6:
        raise SystemExit('usage: check-sparse-settlements EVIDENCE_JSON SETTLEMENT_ELF EXPECTED_GUEST_KEY [FIRST_PROOF_DIR [SECOND_PROOF_DIR]]')
    data = Path(sys.argv[1]).read_bytes()
    result = check_document(json.loads(data), Path(sys.argv[2]).read_bytes(), sys.argv[3],
                            tuple(Path(p) for p in sys.argv[4:]))
    result['evidence_sha256'] = hashlib.sha256(data).hexdigest()
    print(json.dumps(result, indent=2))
