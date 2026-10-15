#!/usr/bin/env python3
"""Reconcile real-proof first settlement evidence; does not perform cryptography."""
import copy
import hashlib
import importlib.util
import json
import pathlib
import sys


def sibling(name):
    spec = importlib.util.spec_from_file_location(name, pathlib.Path(__file__).with_name(name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


bootstrap = sibling('check-settlement-bootstrap')
receipts = sibling('check-proof-receipts')
require, raw = bootstrap.require, bootstrap.raw


def check_consumption(measured, predecessor, successor):
    observation = measured['predecessor_consumption']
    point = {'tx_hash': predecessor['hash'], 'index': '0x0'}
    require(observation['point'] == point
            and observation['live_cell']['status'] == measured['predecessor_status']
            and measured['predecessor_status'] in ('dead', 'unknown'), 'predecessor still live or wrong identity')
    for name, record in [('creation', predecessor), ('consumer', successor)]:
        view = observation[name]
        require(view['tx_status']['status'] == 'committed'
                and view['transaction']['hash'] == record['hash']
                and view['tx_status']['block_hash'] == record['block_hash']
                and view['transaction']['outputs'][0] == record['transaction']['outputs'][0]
                and view['transaction']['outputs_data'] == record['transaction']['outputs_data'], 'canonical consumption identity differs')
    inputs = observation['consumer']['transaction']['inputs']
    require(inputs == successor['transaction']['inputs']
            and sum(i['previous_output'] == point for i in inputs) == 1, 'successor does not consume predecessor')


def check_document(evidence, proof_dir, **profile):
    results = evidence['results']
    require(results['suite'] == 'settlement-first-proof-v1' and results['complete']
            and results['error'] is None and results['settled'] is True,
            'first settlement did not complete')
    require(results['production_ready'] is False and results['G3'] == 'OPEN'
            and results['withdrawal_authority'] is False, 'unsupported production/withdrawal claim')
    records = evidence['evidence']
    labels = {item['label']: item for item in records}
    require(len(records) == len(labels) == 45, 'expected five commits and 40 rejections')
    # Reconcile the initial 24-record bootstrap independently. This projection
    # describes only the pre-proof phase, not the overall settlement result.
    projected = copy.deepcopy(evidence)
    projected['evidence'] = projected['evidence'][:24]
    projected['results']['suite'] = 'settlement-bootstrap-v1'
    projected['results']['settled'] = False
    bootstrap.check_document(projected, **profile)
    export = results['proving_input']
    journal = (proof_dir / 'public-values.bin').read_bytes()
    proof = (proof_dir / 'groth16-proof.bin').read_bytes()
    metadata = json.loads((proof_dir / 'result.json').read_bytes())
    require(metadata == results['source_proof'] and metadata['proof_generated'] is True
            and metadata['proof_kind'] == 'SP1 real Groth16', 'incomplete or different proof')
    require(journal == raw(export['expected_journal_hex'])
            and metadata['public_values_hex'] == journal.hex()
            and metadata['guest_verifying_key'] == export['guest_verifying_key'], 'proof identity differs')
    encoded = b'TO1SETW1' + journal + len(proof).to_bytes(4, 'little') + proof
    item = labels['settlement/first real proof transition']
    tx = item['transaction']
    require(item['result'] == 'committed', 'proof transition not committed')
    require(len(tx['inputs']) == len(tx['outputs']) == len(tx['outputs_data']) == 2,
            'first transition shape')
    require(tx['inputs'][0]['previous_output'] == {
        'tx_hash': export['settlement_tip']['tx_hash'], 'index': '0x0'}, 'wrong predecessor Tip')
    require(tx['inputs'][1]['previous_output'] == {
        'tx_hash': export['fee_input']['tx_hash'], 'index': '0x3'}, 'wrong fee input')
    require(bootstrap.packed(tx['outputs'][0]['type']) == raw(export['settlement_type_script']),
            'successor changes settlement identity')
    boot_tx = labels['settlement/atomic Anchor and uninitialized Tip genesis']['transaction']
    require(tx['outputs'][0] == boot_tx['outputs'][0], 'successor changes capacity/lock/type')
    require(tx['outputs_data'][0] == export['next_tip_data']
            and receipts.witness(tx) == encoded, 'proof or successor data differs')
    require(export['checkpoint'] in [d['out_point'] for d in tx['cell_deps']], 'missing ending checkpoint')
    measured = results['first_transition']
    require(measured['hash'] == item['hash'] and measured['data'] == export['next_tip_data']
            and measured['vm_cycles'] == int(item['cycles']['cycles'], 16)
            and measured['node_wire_bytes'] == receipts.wire_bytes(tx)
            and measured['tip_capacity_shannons'] == int(tx['outputs'][0]['capacity'], 16)
            and measured['successor_status'] == 'live',
            'measurement or live-cell result differs')
    check_consumption(measured, labels['settlement/atomic Anchor and uninitialized Tip genesis'], item)
    require(measured['fee_shannons'] == export['fee_input']['capacity']
            - int(tx['outputs'][1]['capacity'], 16), 'fee differs')
    expected = {}
    for name, offset, code in [
        ('profile', 8, 6), ('network', 40, 6), ('ordering', 72, 6), ('settlement', 104, 6),
        ('rollup', 136, 6), ('chain', 168, 6), ('allocation', 176, 6), ('predecessor', 248, 7),
        ('ending-history', 456, 7), ('previous-state', 608, 9), ('next-state', 640, 7),
        ('previous-header', 672, 9), ('next-header', 704, 7), ('interval-data', 736, 9),
    ]:
        label = 'settlement/proved-' + name + '-tamper'
        altered = bytearray(encoded)
        altered[8 + offset] ^= 1
        require(receipts.witness(labels[label]['transaction']) == altered, 'wrong public mutation')
        expected[label] = code
    for offset in [0, len(proof) - 1]:
        label = f'settlement/proof-byte-{offset}-tamper'
        altered = bytearray(encoded)
        altered[780 + offset] ^= 1
        require(receipts.witness(labels[label]['transaction']) == altered, 'wrong proof mutation')
        expected[label] = 9
    for name, journal_offset, tip_offset in [('state', 640, 216), ('header', 704, 248)]:
        label = 'settlement/coordinated-' + name + '-tamper'
        altered, data = bytearray(encoded), bytearray(raw(export['next_tip_data']))
        altered[8 + journal_offset] ^= 1
        data[tip_offset] ^= 1
        mutated = labels[label]['transaction']
        require(receipts.witness(mutated) == altered and raw(mutated['outputs_data'][0]) == data,
                'wrong coordinated mutation')
        expected[label] = 9
    for name, data in [('replay-on-live-successor', export['next_tip_data']),
                       ('rollback-to-genesis', export['settlement_tip']['data'])]:
        label = 'settlement/' + name
        attempted = labels[label]['transaction']
        require(attempted['inputs'][0]['previous_output'] == {'tx_hash': item['hash'], 'index': '0x0'}
                and attempted['outputs_data'][0] == data and receipts.witness(attempted) == encoded,
                'replay did not target live successor with original proof')
        expected[label] = 7
    require({r['label'] for r in records[24:]} == set(expected) | {item['label']},
            'unexpected settlement control set')
    code_hash = results['settlement_code_hash'][2:]
    for label, code in expected.items():
        rejected = labels[label]
        require(rejected['result'] == 'rejected' and rejected['expected_reason'] == f'error code {code}'
                and rejected['error'].startswith('rpc error: '), 'wrong expected rejection')
        error = json.loads(rejected['error'][len('rpc error: '):])
        text = json.dumps(error)
        require(error['code'] == -302 and code_hash in text
                and ('Inputs[0].Type' in text or 'Outputs[0].Type' in text)
                and f'error code {code} on page ' in text, 'not exact settlement script rejection')
    cold = results['cold_settlement_recovery']
    require(cold['tip'] == {'tx_hash': item['hash'], 'index': '0x0'}
            and cold['data'] == export['next_tip_data'] and cold['initialized'] is True
            and cold['settled_batches'] == cold['proved_transitions'] == 1
            and cold['settled'] is True and cold['withdrawal_authority'] is False
            and cold['settlement_type_script'] == export['settlement_type_script'],
            'cold settlement recovery differs')
    return {'proof_sha256': hashlib.sha256(proof).hexdigest(),
            'settlement_transaction': item['hash'], 'negative_controls': 40,
            'cryptographic_verification_performed_by_this_checker': False,
            'settled': True, 'withdrawal_authority': False, 'production_ready': False}


def check(path, proof_dir):
    source = path.read_bytes()
    return {'evidence_sha256': hashlib.sha256(source).hexdigest(),
            **check_document(json.loads(source), proof_dir)}


if __name__ == '__main__':
    if len(sys.argv) != 3:
        raise SystemExit('usage: check-first-settlement.py EVIDENCE_JSON PROOF_DIR')
    print(json.dumps(check(pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])), indent=2))
