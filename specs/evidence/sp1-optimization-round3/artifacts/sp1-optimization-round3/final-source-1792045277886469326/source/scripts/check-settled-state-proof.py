#!/usr/bin/env python3
"""Reconcile CKB state-read receipts against the real settled A3 proof.

This checks retained evidence; Rust/Geth verify MPT cryptography separately.
"""
import copy
import gzip
import hashlib
import importlib.util
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location('sealed_proof', pathlib.Path(__file__).with_name('check-sealed-proof.py'))
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)
require, raw = base.require, base.raw


def h(value):
    return '0x' + value.hex()


def ckb_hash(value):
    return hashlib.blake2b(value, digest_size=32, person=b'ckb-default-hash').digest()


def word(value):
    return int(value, 16).to_bytes(32, 'big')


def encode(row, tip):
    r = row['result']; s = r['storageProof'][0]
    data = (b'TO1EVMR1' + tip[216:280] + tip[56:64] + raw(r['address'])
            + bytes([int(int(r['codeHash'], 16) != 0)]) + bytes(3)
            + int(r['nonce'], 16).to_bytes(8, 'little') + word(r['balance'])
            + raw(r['storageHash']) + raw(r['codeHash']) + word(s['key']) + word(s['value']))
    proof = b'TO1MPW01'
    for nodes in (r['accountProof'], s['proof']):
        require(len(nodes) <= 65, 'node count')
        proof += len(nodes).to_bytes(2, 'little')
        for node in nodes:
            value = raw(node)
            require(0 < len(value) <= 1024, 'node size')
            proof += len(value).to_bytes(2, 'little') + value
    require(len(data) == 272 and len(proof) <= 131072, 'wire bounds')
    return data, proof


def witness(tx):
    fields = base.receipts.fields(raw(tx['witnesses'][0]), 3)
    require(fields[1] == b'', 'unexpected input_type')
    option = fields[2]
    require(len(option) >= 4 and int.from_bytes(option[:4], 'little') == len(option)-4,
            'output_type Molecule bytes')
    return option[4:]


def check(evidence, source):
    result = evidence['results']; state = result['state_proof']; events = evidence['evidence']
    require(result['suite'] == 'settled-state-proof-v1' and result['complete'] is True
            and result['production_ready'] is False, 'incomplete or unsupported qualification')
    require(len(events) == 48 and sum(e['result'] == 'committed' for e in events) == 23,
            'expected 23 commits and 25 rejections')
    projected = copy.deepcopy(evidence)
    projected['evidence'] = projected['evidence'][:26]
    projected['results']['suite'] = 'sealed-settlement-proof-v1'
    base.check_document(projected, ROOT/'specs/evidence/sealed-chain-proof/proof')
    labels = {e['label']: e for e in events}
    require(len(labels) == len(events), 'duplicate event')
    settled = labels['sealed-settlement/real proof fulfills published obligations']
    tip = raw(settled['transaction']['outputs_data'][0]); point = {'tx_hash': settled['hash'], 'index': '0x0'}
    require(state['settlement_tip'] == point and raw(state['tip_data']) == tip
            and state['withdrawal_authority'] is False and state['production_ready'] is False,
            'wrong trust boundary')
    require(state['tip_live_after']['status'] == 'live'
            and state['tip_live_after']['cell']['data']['content'] == h(tip), 'Tip changed')
    code = raw(labels['state-proof/deploy verifier']['transaction']['outputs_data'][0])
    require(h(ckb_hash(code)) == state['code_hash'], 'deployed verifier differs')
    serialized = raw(state['script']); parts = base.receipts.fields(serialized, 3)
    args = b'TO1MPT01' + ckb_hash(raw(result['proving_input']['settlement_type_script']))
    require(parts == [raw(state['code_hash']), b'\x02', len(args).to_bytes(4, 'little') + args],
            'wrong verifier or trusted Tip identity')
    expected_type = {'code_hash': state['code_hash'], 'hash_type': 'data1', 'args': h(args)}
    rows = [r for r in source if r['tag'] == 'latest']
    require(len(rows) == len(state['accepted']) == 3, 'read count')
    measured = []
    by_hash = {e['hash']: e for e in events if e['result'] == 'committed'}
    for index, (record, row) in enumerate(zip(state['accepted'], rows)):
        event = labels[f'state-proof/authenticated read {index}']; tx = event['transaction']
        data, proof = encode(row, tip)
        require(row['stateRoot'] == h(tip[216:248]) and record['query'] == row,
                'query not bound to settled root')
        require(event['result'] == 'committed' and record['hash'] == event['hash']
                and raw(record['data']) == data and raw(record['proof']) == proof, 'read receipt mismatch')
        require(len(tx['inputs']) == 1 and len(tx['outputs']) == 2
                and tx['outputs'][0]['type'] == expected_type and raw(tx['outputs_data'][0]) == data
                and witness(tx) == proof and point in [d['out_point'] for d in tx['cell_deps']], 'read transaction differs')
        live = record['live_cell']
        require(live['status'] == 'live' and live['cell']['output'] == tx['outputs'][0]
                and live['cell']['data']['content'] == h(data), 'read was not live')
        capacity = int(tx['outputs'][0]['capacity'], 16)
        require(record['capacity'] == capacity, 'capacity differs')
        cycles = int(event['cycles']['cycles'], 16)
        require(0 < cycles <= 10_000_000_000, 'invalid cycle measurement')
        measured.append({'address': row['result']['address'], 'vm_cycles': cycles,
                         'wire_bytes': base.receipts.wire_bytes(tx), 'proof_bytes': len(proof),
                         'certificate_capacity_shannons': capacity})
    # Every post-settlement commit is funded by previously retained committed outputs.
    for event in events[26:]:
        if event['result'] != 'committed':
            continue
        tx = event['transaction']; incoming = 0
        for inp in tx['inputs']:
            p = inp['previous_output']; parent = by_hash[p['tx_hash']]['transaction']
            incoming += int(parent['outputs'][int(p['index'], 16)]['capacity'], 16)
        require(incoming - sum(int(o['capacity'], 16) for o in tx['outputs']) == 100_000_000,
                'post-settlement capacity/fee imbalance')
    controls = {}
    data, proof = encode(rows[0], tip)
    for name, offset, error in [('wrong state root',8,8), ('wrong settled header',40,8),
            ('wrong settled count',72,8), ('wrong address',80,6), ('wrong nonce',104,6),
            ('wrong balance',143,6), ('wrong storage root',144,6), ('wrong code hash',176,6),
            ('invented storage',271,7), ('reserved claim byte',101,3)]:
        label = 'state-proof/' + name; controls[label] = error
        changed = bytearray(data); changed[offset] ^= 1
        tx = labels[label]['transaction']
        require(raw(tx['outputs_data'][0]) == changed and witness(tx) == proof, 'wrong field mutation')
    for name, changed in [('missing proof',b''), ('trailing proof bytes',proof+b'\0'), ('truncated proof',proof[:-1])]:
        label = 'state-proof/' + name; controls[label] = 5
        require(witness(labels[label]['transaction']) == changed, 'wrong proof mutation')
    controls.update({'state-proof/missing settled Tip':4, 'state-proof/wrong Tip identity':4,
                     'state-proof/multiple claim outputs':2, 'state-proof/immutable claim cannot mutate':2})
    require(set(state['negative_controls']) == set(controls) and len(state['negative_controls']) == 17,
            'wrong negative set')
    for label, code in controls.items():
        event = labels[label]; error = json.loads(event['error'].removeprefix('rpc error: '))
        origin = 'Inputs[1].Type' if label.endswith('cannot mutate') else 'Outputs[0].Type'
        require(event['result'] == 'rejected' and event['expected_reason'] == f'error code {code}'
                and error['code'] == -302 and f'error code {code} on page ' in event['error']
                and state['code_hash'][2:] in event['error'] and origin in event['error'], 'wrong rejection boundary')
    missing = labels['state-proof/missing settled Tip']['transaction']
    require(point not in [d['out_point'] for d in missing['cell_deps']], 'Tip not removed')
    wrong = labels['state-proof/wrong Tip identity']['transaction']['outputs'][0]['type']
    changed_args = bytearray(args); changed_args[8] ^= 1
    require(wrong == dict(expected_type, args=h(changed_args)), 'Tip identity not changed')
    duplicate = labels['state-proof/multiple claim outputs']['transaction']
    require(duplicate['outputs'][0] == duplicate['outputs'][1]
            and duplicate['outputs_data'][:2] == [h(data)]*2, 'not duplicate certificates')
    first = state['accepted'][0]; first_point = {'tx_hash':first['hash'], 'index':'0x0'}
    mutation = labels['state-proof/immutable claim cannot mutate']['transaction']
    require(mutation['inputs'][1]['previous_output'] == first_point
            and mutation['outputs'][0]['type'] == expected_type, 'not a certificate replacement')
    burn = labels['state-proof/owner recovers certificate capacity']; tx = burn['transaction']
    require(state['destroyed_claim'] == first['hash'] and state['destruction_hash'] == burn['hash']
            and tx['inputs'][1]['previous_output'] == first_point and len(tx['outputs']) == 1
            and tx['outputs'][0].get('type') is None and tx['outputs_data'] == ['0x'], 'wrong destruction')
    consumption = state['consumption']
    require(consumption['point'] == first_point and consumption['live_cell']['status'] in ('dead','unknown'),
            'certificate not consumed')
    for name, event in [('creation', labels['state-proof/authenticated read 0']), ('consumer', burn)]:
        observed = consumption[name]; expected = copy.deepcopy(event['transaction'])
        for output in expected['outputs']: output.setdefault('type', None)
        require(observed['tx_status']['status'] == 'committed'
                and observed['transaction']['hash'] == event['hash']
                and observed['tx_status']['block_hash'] == event['block_hash']
                and all(observed['transaction'][f] == expected[f] for f in ['inputs','outputs','outputs_data','witnesses']),
                'canonical consumption differs')
    return {'commits':23, 'negative_controls':25, 'authenticated_reads':measured,
            'state_read_negative_controls':17, 'settled_batches':9,
            'withdrawal_authority':False, 'independent_cryptographic_verification':False, 'production_ready':False}


if __name__ == '__main__':
    path = pathlib.Path(sys.argv[1])
    evidence = json.loads(gzip.decompress(path.read_bytes()) if path.suffix == '.gz' else path.read_bytes())
    source = json.loads((ROOT/'specs/evidence/observer-state-proofs/state-proofs.json').read_bytes())
    print(json.dumps(check(evidence, source), indent=2))
