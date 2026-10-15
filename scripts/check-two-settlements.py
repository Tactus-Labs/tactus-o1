#!/usr/bin/env python3
"""Reconcile two genuine proof-consuming transitions; no cryptographic verification."""
import copy
import gzip
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


first_check = sibling('check-first-settlement')
next_check = sibling('check-next-proof-input')
require, raw = first_check.require, first_check.raw
receipt = first_check.receipts


def check(path, first_dir, second_dir):
    source = path.read_bytes()
    if path.suffix == '.gz':
        source = gzip.decompress(source)
    return {'evidence_sha256': hashlib.sha256(source).hexdigest(),
            **check_document(json.loads(source), first_dir, second_dir)}


def check_document(document, first_dir, second_dir, **profile):
    results = document['results']
    require(results['suite'] == 'settlement-two-proofs-v1' and results['complete']
            and results['error'] is None and results['settled'] is True,
            'two proof transitions did not complete')
    require(results['production_ready'] is False and results['withdrawal_authority'] is False
            and results['G3'] == 'OPEN', 'unsupported production or withdrawal claim')
    records = document['evidence']
    labels = {r['label']: r for r in records}
    require(len(records) == len(labels) == 69
            and sum(r['result'] == 'committed' for r in records) == 7,
            'expected seven commits and 62 rejections')
    next_input = results['next_proving_input']
    # Reconcile the actual initial publication phase, then the actual first-proof
    # phase. Projections describe these earlier snapshots, not the final Tip.
    published = copy.deepcopy(document)
    published['evidence'] = published['evidence'][:25]
    published['results']['suite'] = 'settlement-next-input-v1'
    published['results']['settled'] = False
    next_check.check_document(published, **profile)
    require(results['settlement_fee_input'] == next_input['fee_input'], 'wrong first-proof funding source')
    initial = copy.deepcopy(document)
    initial['evidence'] = initial['evidence'][:24] + initial['evidence'][26:47]
    initial['results']['suite'] = 'settlement-first-proof-v1'
    initial['results']['proving_input']['fee_input'] = results['settlement_fee_input']
    first_check.check_document(initial, first_dir, **profile)
    require(results['cold_settlement_recovery']['published_batches'] == 2,
            'first proof did not settle while Anchor was already advanced')
    first_journal = (first_dir / 'public-values.bin').read_bytes()
    first_proof = (first_dir / 'groth16-proof.bin').read_bytes()
    journal = (second_dir / 'public-values.bin').read_bytes()
    proof = (second_dir / 'groth16-proof.bin').read_bytes()
    metadata = json.loads((second_dir / 'result.json').read_bytes())
    require(metadata == results['second_source_proof'] and metadata['proof_generated'] is True
            and metadata['proof_kind'] == 'SP1 real Groth16'
            and metadata['guest_verifying_key'] == next_input['guest_verifying_key']
            and metadata['public_values_hex'] == journal.hex()
            and journal == raw(next_input['expected_journal_hex']), 'second proof identity differs')
    encoded = b'TO1SETW1' + journal + len(proof).to_bytes(4, 'little') + proof
    encoded_first = b'TO1SETW1' + first_journal + len(first_proof).to_bytes(4, 'little') + first_proof
    skip = labels['settlement/skip-first-interval']['transaction']
    first_export = results['proving_input']
    require(records[25]['label'] == 'settlement/skip-first-interval'
            and skip['inputs'][0]['previous_output'] == {
                'tx_hash': first_export['settlement_tip']['tx_hash'], 'index': '0x0'}
            and skip['outputs_data'][0] == next_input['next_tip_data']
            and receipt.witness(skip) == encoded, 'skip did not use second proof on uninitialized Tip')
    item = labels['settlement/second real proof transition']
    tx = item['transaction']
    prior = labels['settlement/first real proof transition']
    require(item['result'] == 'committed' and len(tx['inputs']) == len(tx['outputs']) == 2,
            'second proof transaction shape/status')
    require(tx['inputs'][0]['previous_output'] == {'tx_hash': prior['hash'], 'index': '0x0'}
            and tx['inputs'][1]['previous_output'] == {'tx_hash': prior['hash'], 'index': '0x1'},
            'second proof does not consume first Tip and fee change')
    require(tx['outputs'][0] == prior['transaction']['outputs'][0]
            and tx['outputs_data'][0] == next_input['next_tip_data']
            and receipt.witness(tx) == encoded, 'second output or proof differs')
    require(next_input['checkpoint'] in [d['out_point'] for d in tx['cell_deps']],
            'missing second authenticated checkpoint')
    measured = results['second_transition']
    require(measured['hash'] == item['hash'] and measured['data'] == tx['outputs_data'][0]
            and measured['vm_cycles'] == int(item['cycles']['cycles'], 16)
            and measured['node_wire_bytes'] == receipt.wire_bytes(tx)
            and measured['tip_capacity_shannons'] == int(tx['outputs'][0]['capacity'], 16)
            and measured['fee_shannons'] == int(prior['transaction']['outputs'][1]['capacity'], 16)
            - int(tx['outputs'][1]['capacity'], 16)
            and measured['successor_status'] == 'live',
            'second measurement differs')
    first_check.check_consumption(measured, prior, item)
    expected = {'settlement/skip-first-interval': 7}
    for name, offset, code in [
        ('profile',8,6),('network',40,6),('ordering',72,6),('settlement',104,6),
        ('rollup',136,6),('chain',168,6),('allocation',176,6),('predecessor',248,7),
        ('ending-history',456,7),('previous-state',608,7),('next-state',640,7),
        ('previous-header',672,7),('next-header',704,7),('interval-data',736,9),
    ]:
        label = 'settlement/second-proved-' + name + '-tamper'
        changed = bytearray(encoded)
        changed[8 + offset] ^= 1
        require(receipt.witness(labels[label]['transaction']) == changed, 'wrong second journal mutation')
        expected[label] = code
    for offset in [0, len(proof) - 1]:
        label = f'settlement/second-proof-byte-{offset}-tamper'
        changed = bytearray(encoded)
        changed[780 + offset] ^= 1
        require(receipt.witness(labels[label]['transaction']) == changed, 'wrong second proof mutation')
        expected[label] = 9
    for name, journal_offset, tip_offset in [('state',640,216),('header',704,248)]:
        label = 'settlement/second-coordinated-' + name + '-tamper'
        changed, data = bytearray(encoded), bytearray(raw(tx['outputs_data'][0]))
        changed[8 + journal_offset] ^= 1
        data[tip_offset] ^= 1
        mutated = labels[label]['transaction']
        require(receipt.witness(mutated) == changed and raw(mutated['outputs_data'][0]) == data,
                'wrong second coordinated mutation')
        expected[label] = 9
    for name, data, witness in [
        ('replay-second-on-live-successor', tx['outputs_data'][0], encoded),
        ('replay-first-after-second', tx['outputs_data'][0], encoded_first),
        ('rollback-to-first-tip', prior['transaction']['outputs_data'][0], encoded),
    ]:
        label = 'settlement/' + name
        attempt = labels[label]['transaction']
        require(attempt['inputs'][0]['previous_output'] == {'tx_hash': item['hash'], 'index': '0x0'}
                and attempt['outputs_data'][0] == data and receipt.witness(attempt) == witness,
                'replay does not use exact retained proof and live successor')
        expected[label] = 7
    require({r['label'] for r in [records[25], *records[47:]]} == set(expected) | {item['label']},
            'second phase control set differs')
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
    cold = results['cold_second_settlement_recovery']
    require(cold['tip'] == {'tx_hash': item['hash'], 'index': '0x0'}
            and cold['data'] == tx['outputs_data'][0] and cold['initialized'] is True
            and cold['settled_batches'] == cold['published_batches'] == cold['proved_transitions'] == 2
            and cold['settled'] is True and cold['withdrawal_authority'] is False,
            'second cold recovery differs')
    return {'settlement_transactions': [prior['hash'], item['hash']], 'negative_controls': 62,
            'settled_batches': 2, 'cryptographic_verification_performed_by_this_checker': False,
            'settled': True, 'withdrawal_authority': False, 'production_ready': False}


if __name__ == '__main__':
    if len(sys.argv) != 4:
        raise SystemExit('usage: check-two-settlements.py EVIDENCE_JSON FIRST_PROOF_DIR SECOND_PROOF_DIR')
    print(json.dumps(check(*(pathlib.Path(v) for v in sys.argv[1:])), indent=2))
