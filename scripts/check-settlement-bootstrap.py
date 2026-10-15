#!/usr/bin/env python3
"""Reconcile atomic deployment and proof-input exports; no cryptographic verification."""
import hashlib
import json
import pathlib
import sys


def require(ok, message):
    if not ok:
        raise ValueError(message)


def raw(value):
    require(value.startswith('0x'), 'hex prefix')
    return bytes.fromhex(value[2:])


def digest(data):
    return hashlib.blake2b(data, digest_size=32, person=b'ckb-default-hash').digest()


def packed(script):
    args = raw(script['args'])
    return (b''.join(n.to_bytes(4, 'little') for n in [53 + len(args), 16, 48, 49])
            + raw(script['code_hash'])
            + bytes([{'data': 0, 'type': 1, 'data1': 2, 'data2': 4}[script['hash_type']]])
            + len(args).to_bytes(4, 'little') + args)


REPLAY_PROFILE = digest(b'tactus/o1/proof-profile/v1' + b'TO1PRF01;replay-canonical-genesis-prefix;nonempty-contiguous-interval;ethereum-state-and-header;no-withdrawal-authorization')


def check_document(evidence, *, journal_magic=b'TO1PRF01', journal_profile=REPLAY_PROFILE):
    result = evidence['results']
    require(result['suite'] == 'settlement-bootstrap-v1' and result['complete']
            and result['error'] is None, 'incomplete bootstrap')
    require(result['settled'] is False and result['production_ready'] is False
            and result['G3'] == 'OPEN', 'unsupported settlement claim')
    records = evidence['evidence']
    labels = {item['label']: item for item in records}
    require(len(records) == len(labels) == 24, 'wrong or duplicate record count')
    require(sum(item['result'] == 'committed' for item in records) == 4, 'wrong commit count')
    boot = labels['settlement/atomic Anchor and uninitialized Tip genesis']
    publication = labels['settlement/canonical batch and ending checkpoint']
    tx = boot['transaction']
    next_tx = publication['transaction']
    export = result['proving_input']
    require(export['schema'] == 1 and export['prefix_batches'] == 0
            and len(export['batches']) == 1 and export['settled'] is False, 'export scope differs')
    settlement = packed(tx['outputs'][0]['type'])
    anchor = packed(tx['outputs'][1]['type'])
    require(settlement == raw(export['settlement_type_script'])
            and anchor == raw(export['anchor_type_script']), 'exported script differs')
    config = raw(tx['outputs'][0]['type']['args'])
    require(len(config) == 168 and config[:8] == b'TO1CFG01', 'config encoding')
    require(config[8:40] == raw(evidence['metadata']['consensus']['genesis_hash'])
            and config[40:72] == digest(anchor)
            and config[72:104] == raw(export['guest_verifying_key']), 'config identity differs')
    allocation = raw(tx['outputs_data'][2])
    allocation_hash = digest(b'tactus/o1/genesis-allocation/v1' + allocation)
    require(allocation == raw(export['allocation_hex'])
            and allocation_hash == config[136:168] == raw(tx['outputs'][1]['type']['args'])[32:],
            'allocation binding differs')
    initial = raw(tx['outputs_data'][0])
    require(len(initial) == 280 and initial[:16] == b'TO1TIP01' + bytes(8)
            and initial[216:] == bytes(64) and initial[16:216] == raw(tx['outputs_data'][1]),
            'bootstrap asserts execution state or mismatches Anchor')
    require(export['settlement_tip']['tx_hash'] == boot['hash']
            and export['settlement_tip']['index'] == '0x0'
            and raw(export['settlement_tip']['data']) == initial, 'wrong Tip outpoint')
    require(next_tx['inputs'][0]['previous_output'] == {'tx_hash': boot['hash'], 'index': '0x1'},
            'publication spends wrong Anchor')
    require(next_tx['outputs'][0]['type'] == {
        'code_hash': '0x' + config[104:136].hex(), 'hash_type': 'data1',
        'args': '0x' + digest(anchor).hex()}, 'wrong checkpoint identity')
    require(next_tx['outputs_data'][0] == next_tx['outputs_data'][1], 'checkpoint differs')
    require(next_tx['outputs_data'][2] == export['batches'][0], 'export batch differs')
    require(export['checkpoint'] == {'tx_hash': publication['hash'], 'index': '0x0'},
            'wrong checkpoint outpoint')
    journal = raw(export['expected_journal_hex'])
    domain = raw(export['domain_hex'])
    require(len(domain) == 136 and len(journal) == 768 and journal[:8] == journal_magic
            and journal[8:40] == journal_profile, 'journal encoding/profile')
    require(domain[:32] == config[8:40] and domain[32:64] == digest(anchor)
            and domain[64:96] == digest(settlement) and domain[96:128] == initial[24:56]
            and domain[128:] == initial[208:216], 'deployment domain differs')
    require(journal[40:176] == domain and journal[176:208] == allocation_hash
            and journal[208:408] == initial[16:216]
            and journal[408:608] == raw(next_tx['outputs_data'][1]), 'journal Anchor/domain binding')
    batch = raw(export['batches'][0])
    interval = digest(b'tactus/o1/proof-interval/v1' + (1).to_bytes(8, 'little'))
    interval = digest(b'tactus/o1/proof-interval-step/v1' + interval + len(batch).to_bytes(8, 'little') + batch)
    require(journal[736:] == interval, 'interval digest differs')
    next_tip = raw(export['next_tip_data'])
    require(next_tip == b'TO1TIP01' + b'\1' + bytes(7) + journal[408:608]
            + journal[640:672] + journal[704:736], 'proposed next Tip differs')
    expected = {name: 3 for name in ['reserved', 'unproved-initial-state', 'unproved-initial-header',
                                    'initialized-before-proof', 'short-tip']}
    expected.update({'wrong-allocation': 4, 'no-anchor-genesis': 4, 'duplicate-tip': 2,
                     'late-bootstrap-from-anchor-dependency': 4, 'missing-authenticated-checkpoint': 8,
                     'malformed-proof-rejected': 9, 'empty-proof': 5})
    expected.update({'binding-' + name: 6 for name in ['network', 'ordering', 'settlement', 'allocation']})
    expected.update({'binding-' + name: 7 for name in ['predecessor', 'ending-history', 'state', 'header']})
    require({item['label'] for item in records if item['result'] == 'rejected'}
            == {'settlement/' + name for name in expected}, 'rejection set differs')
    code_hash = result['settlement_code_hash']
    require(code_hash == tx['outputs'][0]['type']['code_hash'], 'wrong settlement code hash')
    for name, code in expected.items():
        item = labels['settlement/' + name]
        require(item['expected_reason'] == f'error code {code}'
                and item['error'].startswith('rpc error: '), 'wrong expected rejection')
        error = json.loads(item['error'][len('rpc error: '):])
        text = json.dumps(error)
        require(error['code'] == -302 and f'error code {code} on page ' in text
                and code_hash[2:] in text and ('Inputs[0].Type' in text or 'Outputs[0].Type' in text),
                'not the precise settlement script rejection')
    if 'cold_bootstrap_recovery' in result:
        cold = result['cold_bootstrap_recovery']
        require(cold['tip'] == {'tx_hash': boot['hash'], 'index': '0x0'}
                and raw(cold['data']) == initial and cold['initialized'] is False
                and cold['settled_batches'] == 0 and cold['published_batches'] == 1
                and cold['proved_transitions'] == 0 and cold['settled'] is False
                and cold['ckb_genesis'] == evidence['metadata']['consensus']['genesis_hash']
                and raw(cold['anchor_type_script']) == anchor
                and raw(cold['settlement_type_script']) == settlement,
                'cold bootstrap recovery differs')
        if 'cold_recovery_controls' in result:
            controls = result['cold_recovery_controls']
            require(len(controls) == 3 and {c['control'] for c in controls} == {
                'wrong-chain', 'wrong-anchor', 'wrong-settlement-key'}
                and all(c['rejected'] is True for c in controls), 'cold rejection set differs')
    return {'journal_sha256': hashlib.sha256(journal).hexdigest(), 'negative_controls': 20,
            'initialization_cycles': int(result['initialization_cycles']['cycles'], 16),
            'accepted_execution_proof': False, 'settled': False, 'production_ready': False}


def check(path):
    source = path.read_bytes()
    return {'evidence_sha256': hashlib.sha256(source).hexdigest(),
            **check_document(json.loads(source))}


if __name__ == '__main__':
    if len(sys.argv) != 2:
        raise SystemExit('usage: check-settlement-bootstrap.py EVIDENCE_JSON')
    print(json.dumps(check(pathlib.Path(sys.argv[1])), indent=2))
