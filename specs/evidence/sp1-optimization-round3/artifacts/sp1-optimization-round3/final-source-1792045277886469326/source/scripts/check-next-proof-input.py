#!/usr/bin/env python3
"""Reconcile two actual publications and a pending prefix-one proof input."""
import copy
import hashlib
import importlib.util
import json
import pathlib
import sys

spec = importlib.util.spec_from_file_location('bootstrap', pathlib.Path(__file__).with_name('check-settlement-bootstrap.py'))
bootstrap = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bootstrap)
require, raw, digest = bootstrap.require, bootstrap.raw, bootstrap.digest


def check_document(evidence, **profile):
    results = evidence['results']
    require(results['suite'] == 'settlement-next-input-v1' and results['complete']
            and results['error'] is None and results['settled'] is False
            and results['production_ready'] is False and results['G3'] == 'OPEN',
            'incomplete or unsupported next-input claim')
    require(len(evidence['evidence']) == 25, 'expected five commits and 20 rejections')
    projected = copy.deepcopy(evidence)
    projected['evidence'] = projected['evidence'][:24]
    projected['results']['suite'] = 'settlement-bootstrap-v1'
    bootstrap.check_document(projected, **profile)
    first, second = results['proving_input'], results['next_proving_input']
    record = evidence['evidence'][-1]
    require(record['label'] == 'settlement/second canonical batch and ending checkpoint'
            and record['result'] == 'committed', 'second publication not committed')
    tx = record['transaction']
    require(tx['inputs'][0]['previous_output'] == {'tx_hash': first['checkpoint']['tx_hash'], 'index': '0x1'},
            'second publication disconnected from first Anchor')
    require(second['schema'] == 1 and second['prefix_batches'] == 1
            and second['predecessor_ready'] is False and second['settled'] is False
            and second['batches'] == [first['batches'][0], tx['outputs_data'][2]],
            'second input prefix or data differs')
    for key in ['domain_hex', 'allocation_hex', 'guest_verifying_key', 'settlement_type_script', 'anchor_type_script', 'settlement_tip']:
        require(second[key] == first[key], 'second input changed ' + key)
    require(second['checkpoint'] == {'tx_hash': record['hash'], 'index': '0x0'}
            and second['fee_input']['tx_hash'] == record['hash']
            and second['fee_input']['index'] == '0x3'
            and second['fee_input']['capacity'] == int(tx['outputs'][3]['capacity'], 16),
            'second dependency or funding export differs')
    a, b = raw(first['expected_journal_hex']), raw(second['expected_journal_hex'])
    require(len(b) == 768 and b[:208] == a[:208] and b[208:408] == a[408:608]
            and b[608:640] == a[640:672] and b[672:704] == a[704:736],
            'journal prefix continuity differs')
    require(b[408:608] == raw(tx['outputs_data'][0]) == raw(tx['outputs_data'][1]),
            'journal differs from authenticated ending checkpoint')
    # Compare exact checkpoint type with the already validated first publication.
    earlier = next(r for r in evidence['evidence'] if r['label'] == 'settlement/canonical batch and ending checkpoint')
    require(tx['outputs'][0]['type'] == earlier['transaction']['outputs'][0]['type']
            and tx['outputs'][1]['type'] == earlier['transaction']['outputs'][1]['type'],
            'second checkpoint or Anchor type differs')
    interval = digest(b'tactus/o1/proof-interval/v1' + (1).to_bytes(8, 'little'))
    batch = raw(second['batches'][1])
    interval = digest(b'tactus/o1/proof-interval-step/v1' + interval + len(batch).to_bytes(8, 'little') + batch)
    require(b[736:] == interval, 'second interval digest differs')
    require(b[640:672] != a[640:672] and b[704:736] != a[704:736],
            'continuation did not change state and header')
    require(second['required_predecessor_tip_data'] == first['next_tip_data']
            and raw(second['next_tip_data']) == b'TO1TIP01' + b'\1' + bytes(7)
            + b[408:608] + b[640:672] + b[704:736], 'required or successor Tip differs')
    cold = results['cold_after_second_publication']
    require(cold['tip']['tx_hash'] == first['settlement_tip']['tx_hash']
            and cold['data'] == first['settlement_tip']['data'] and cold['published_batches'] == 2
            and cold['settled_batches'] == 0 and cold['proved_transitions'] == 0
            and cold['initialized'] is False and cold['settled'] is False,
            'cold recovery treated publication as settlement')
    return {'journal_sha256': hashlib.sha256(b).hexdigest(), 'published_batches': 2,
            'prefix_batches': 1, 'settled_batches': 0, 'negative_controls': 20,
            'proof_generated': False, 'settled': False, 'production_ready': False}


def check(path):
    source = path.read_bytes()
    return {'evidence_sha256': hashlib.sha256(source).hexdigest(),
            **check_document(json.loads(source))}


if __name__ == '__main__':
    if len(sys.argv) != 2:
        raise SystemExit('usage: check-next-proof-input.py EVIDENCE_JSON')
    print(json.dumps(check(pathlib.Path(sys.argv[1])), indent=2))
