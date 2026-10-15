#!/usr/bin/env python3
"""Reconcile raw receipt transactions against retained proof bytes.

This checks evidence consistency, not cryptography or canonical settlement.
The real node must have executed the pinned verifier separately.
"""
import hashlib
import json
import pathlib
import re
import sys


def require(condition, message):
    if not condition:
        raise ValueError(message)


def raw(value):
    require(isinstance(value, str) and value.startswith('0x'), 'expected hex')
    return bytes.fromhex(value[2:])


def fields(encoded, count):
    require(len(encoded) >= 4 * (count + 1), 'short Molecule table')
    words = [int.from_bytes(encoded[i:i + 4], 'little')
             for i in range(0, 4 * (count + 1), 4)]
    require(words[0] == len(encoded), 'Molecule total size')
    offsets = words[1:] + [len(encoded)]
    require(offsets[0] == 4 * (count + 1), 'Molecule first offset')
    require(offsets == sorted(offsets), 'Molecule offset order')
    return [encoded[a:b] for a, b in zip(offsets, offsets[1:])]


def witness(tx):
    option = fields(raw(tx['witnesses'][0]), 3)[1]
    require(len(option) >= 4, 'missing input_type')
    require(int.from_bytes(option[:4], 'little') == len(option) - 4,
            'Molecule bytes size')
    return option[4:]


def wire_bytes(tx):
    def dynamic(sizes):
        return 4 + 4 * len(sizes) + sum(sizes)
    def script_size(script):
        return 53 + len(raw(script['args']))
    outputs = [16 + 8 + script_size(out['lock'])
               + (script_size(out['type']) if out.get('type') is not None else 0)
               for out in tx['outputs']]
    raw_size = (28 + 4 + 4 + 37 * len(tx['cell_deps'])
                + 4 + 32 * len(tx['header_deps']) + 4 + 44 * len(tx['inputs'])
                + dynamic(outputs) + dynamic([4 + len(raw(v)) for v in tx['outputs_data']]))
    return 12 + raw_size + dynamic([4 + len(raw(v)) for v in tx['witnesses']])


def check(evidence_path, proof_dir):
    evidence_bytes = evidence_path.read_bytes()
    evidence = json.loads(evidence_bytes)
    results = evidence['results']
    source = json.loads((proof_dir / 'result.json').read_bytes())
    proof = (proof_dir / 'groth16-proof.bin').read_bytes()
    journal = (proof_dir / 'public-values.bin').read_bytes()
    require(source['proof_generated'] and source['proof_kind'] == 'SP1 real Groth16',
            'requires completed real Groth16 experiment')
    require(len(journal) == 768 and source['public_values_hex'] == journal.hex(),
            'source public values differ')
    require(results['suite'] == 'groth16-proof-receipt-v1'
            and results['complete'] and results['error'] is None,
            'incomplete receipt experiment')
    require(results['source_proof'] == source, 'proof source differs')
    require(results['settled'] is False and results['production_ready'] is False
            and results['G3'] == 'OPEN', 'unsupported settlement claim')
    require(raw(results['public_values']) == journal, 'result public values differ')
    encoded = b'TO1G1601' + len(proof).to_bytes(4, 'little') + proof
    records = evidence['evidence']
    require(len(records) == 31, 'expected three commits and 28 rejections')
    labels = {item['label']: item for item in records}
    require(len(labels) == len(records), 'duplicate evidence labels')
    code_hash = evidence['metadata']['ordering_code_hash']
    key = raw(source['guest_verifying_key'])
    accepted = []
    for index in range(2):
        item = labels[f'proof/valid-receipt-{index}']
        tx = item['transaction']
        require(item['result'] == 'committed', 'receipt was not committed')
        require(len(tx['outputs']) == 2 and len(tx['outputs_data']) == 2,
                'receipt output shape')
        require(raw(tx['outputs_data'][0]) == journal, 'receipt journal differs')
        require(tx['outputs'][0]['type'] == {
            'code_hash': code_hash, 'hash_type': 'data1',
            'args': '0x' + key.hex()}, 'receipt verifier identity differs')
        require(tx['outputs'][1].get('type') is None, 'change unexpectedly typed')
        require(witness(tx) == encoded, 'receipt proof differs')
        measured = results['receipts'][index]
        require(measured['hash'] == item['hash'] and measured['settled'] is False,
                'receipt metadata differs')
        require(measured['vm_cycles'] == int(item['cycles']['cycles'], 16),
                'cycle reports differ')
        require(measured['node_wire_bytes'] == wire_bytes(tx), 'packed wire bytes differ')
        require(measured['receipt_capacity_shannons'] ==
                int(tx['outputs'][0]['capacity'], 16), 'receipt capacity differs')
        accepted.append(item['hash'])
        for operation in ('consume', 'replace'):
            spend = labels[f'proof/receipt-{index}-{operation}']['transaction']
            require(spend['inputs'][0]['previous_output'] == {
                'tx_hash': item['hash'], 'index': '0x0'}, 'wrong receipt spent')
    require(accepted[0] != accepted[1], 'duplicate receipt transaction')
    offsets = dict(zip(
        ['profile', 'ckb-network', 'ordering-script', 'settlement-script', 'rollup',
         'chain', 'allocation', 'predecessor', 'end-history', 'previous-state',
         'next-state', 'previous-header', 'next-header', 'interval-data'],
        [8, 40, 72, 104, 136, 168, 176, 248, 456, 608, 640, 672, 704, 736]))
    expected_codes = {}
    for name, offset in offsets.items():
        label = f'proof/{name} tamper'
        tx = labels[label]['transaction']
        mutated = bytearray(journal)
        mutated[offset] ^= 1
        require(raw(tx['outputs_data'][0]) == mutated, 'wrong journal mutation')
        require(witness(tx) == encoded, 'journal control also changed proof')
        expected_codes[label] = 7
    for offset in (0, len(proof) - 1):
        label = f'proof/proof-byte-{offset} tamper'
        mutated = bytearray(encoded)
        mutated[12 + offset] ^= 1
        require(witness(labels[label]['transaction']) == mutated, 'wrong proof mutation')
        expected_codes[label] = 7
    for name, code in [('wrong-key', 7), ('short-key', 6), ('short-journal', 9),
                       ('long-journal', 9), ('empty-proof', 5), ('trailing-proof', 5),
                       ('oversized-witness', 3), ('duplicate-receipt-output', 8)]:
        expected_codes[f'proof/{name}'] = code
    for index in range(2):
        for operation in ('consume', 'replace'):
            expected_codes[f'proof/receipt-{index}-{operation}'] = 8
    require({item['label'] for item in records if item['result'] == 'rejected'}
            == set(expected_codes), 'rejection set differs')
    for label, code in expected_codes.items():
        item = labels[label]
        require(item['expected_reason'] == f'error code {code}', 'wrong expected code')
        require(item['error'].startswith('rpc error: '), 'not a node RPC rejection')
        error = json.loads(item['error'][len('rpc error: '):])
        require(error['code'] == -302, 'not script rejection')
        message = json.dumps(error)
        require(re.search(r'(Inputs|Outputs)\[0\]\.Type', message)
                and f'error code {code} on page ' in message
                and code_hash[2:] in message, 'wrong script or return code')
    return {'evidence_sha256': hashlib.sha256(evidence_bytes).hexdigest(),
            'proof_sha256': hashlib.sha256(proof).hexdigest(),
            'receipts': accepted, 'rejections': len(expected_codes),
            'cryptographic_verification_performed_by_this_checker': False,
            'settled': False, 'production_ready': False}


if __name__ == '__main__':
    if len(sys.argv) != 3:
        raise SystemExit('usage: check-proof-receipts.py EVIDENCE_JSON PROOF_DIR')
    print(json.dumps(check(pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])), indent=2))
