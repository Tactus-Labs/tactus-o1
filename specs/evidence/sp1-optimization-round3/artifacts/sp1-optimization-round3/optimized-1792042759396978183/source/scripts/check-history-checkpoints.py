#!/usr/bin/env python3
"""Reconcile retained checkpoint transitions; this does not execute CKB scripts."""
import hashlib
import json
import pathlib
import sys


def require(ok, message):
    if not ok:
        raise ValueError(message)


def raw(value):
    require(value.startswith('0x'), 'expected hex')
    return bytes.fromhex(value[2:])


def script_hash(script):
    args = raw(script['args'])
    encoded = (53 + len(args)).to_bytes(4, 'little')
    encoded += b''.join(n.to_bytes(4, 'little') for n in [16, 48, 49])
    encoded += raw(script['code_hash'])
    encoded += bytes([{'data': 0, 'type': 1, 'data1': 2, 'data2': 4}[script['hash_type']]])
    encoded += len(args).to_bytes(4, 'little') + args
    return '0x' + hashlib.blake2b(encoded, digest_size=32, person=b'ckb-default-hash').hexdigest()


def check(path):
    data = path.read_bytes()
    evidence = json.loads(data)
    result = evidence['results']
    require(result['suite'] == 'authenticated-history-checkpoint-v1'
            and result['complete'] and result['error'] is None, 'incomplete experiment')
    require(result['settled'] is False and result['production_ready'] is False
            and result['G3'] == 'OPEN', 'unsupported settlement claim')
    records = evidence['evidence']
    labels = {item['label']: item for item in records}
    require(len(labels) == len(records) == 27, 'wrong or duplicate evidence count')
    require(sum(item['result'] == 'committed' for item in records) == 5, 'wrong commit count')
    identity = result['anchor_type_hash']
    code = result['checkpoint_code_hash']
    genesis = labels['batch/genesis']
    anchor_script = genesis['transaction']['outputs'][0]['type']
    require(script_hash(anchor_script) == identity, 'Anchor type hash differs')
    previous = {'tx_hash': genesis['hash'], 'index': '0x0'}
    previous_data = raw(genesis['transaction']['outputs_data'][0])
    cycles = []
    for index, checkpoint in enumerate(result['checkpoints']):
        item = labels[f'checkpoint/advance-{index}']
        tx = item['transaction']
        require(item['result'] == 'committed', 'uncommitted checkpoint')
        require(tx['inputs'][0]['previous_output'] == previous, 'wrong Anchor input')
        require(tx['outputs'][1]['type'] == anchor_script, 'Anchor identity changed')
        require(tx['outputs'][0]['type'] == {
            'code_hash': code, 'hash_type': 'data1', 'args': identity}, 'checkpoint identity differs')
        require(tx['outputs_data'][0] == tx['outputs_data'][1] == checkpoint['data'],
                'checkpoint does not equal advanced Anchor')
        advanced = raw(checkpoint['data'])
        require(len(advanced) == 200 and advanced[:8] == b'TO1ANC01', 'Anchor encoding')
        require(int.from_bytes(advanced[40:48], 'little') == index + 1, 'wrong cursor')
        require(advanced[8:40] == previous_data[8:40] and advanced[96:] == previous_data[96:],
                'Anchor domain changed')
        require(checkpoint['hash'] == item['hash'] and checkpoint['output_index'] == 0,
                'checkpoint outpoint differs')
        if index:
            old = result['checkpoints'][index - 1]
            require(any(dep['out_point'] == {'tx_hash': old['hash'], 'index': '0x0'}
                        for dep in tx['cell_deps']), 'missing historical checkpoint dependency')
        for operation in ('consume', 'replace'):
            spend = labels[f'checkpoint/{index}-{operation}']['transaction']
            require(spend['inputs'][0]['previous_output'] == {
                'tx_hash': item['hash'], 'index': '0x0'}, 'wrong checkpoint spent')
        previous = {'tx_hash': item['hash'], 'index': '0x1'}
        previous_data = advanced
        cycles.append(int(item['cycles']['cycles'], 16))
    require(len(cycles) == 2, 'expected two retained checkpoints')
    expected = {}
    first = raw(result['checkpoints'][0]['data'])
    for field, offset in [('magic', 0), ('rollup', 8), ('batch', 40), ('history', 48),
                          ('block', 80), ('time', 88), ('rules', 96), ('da', 128),
                          ('limits', 160), ('chain', 192)]:
        label = f'checkpoint/tamper-{field}'
        mutated = bytearray(first)
        mutated[offset] ^= 1
        tx = labels[label]['transaction']
        require(raw(tx['outputs_data'][0]) == mutated and raw(tx['outputs_data'][1]) == first,
                'wrong checkpoint mutation')
        expected[label] = 7
    for name, code_number in [('wrong-anchor', 4), ('short-key', 1), ('short-data', 5),
                              ('long-data', 5), ('duplicate', 2), ('no-anchor-transition', 4),
                              ('anchor-dependency-only', 4)]:
        expected[f'checkpoint/{name}'] = code_number
    for index in range(2):
        for operation in ('consume', 'replace'):
            expected[f'checkpoint/{index}-{operation}'] = 2
    expected['checkpoint/stale-anchor-dependency'] = None
    require({item['label'] for item in records if item['result'] == 'rejected'} == set(expected),
            'rejection set differs')
    for label, code_number in expected.items():
        item = labels[label]
        require(item['error'].startswith('rpc error: '), 'not a node rejection')
        error = json.loads(item['error'][len('rpc error: '):])
        text = json.dumps(error)
        if code_number is None:
            require(error['code'] == -301 and 'TransactionFailedToResolve' in text,
                    'not stale dependency rejection')
        else:
            require(item['expected_reason'] == f'error code {code_number}'
                    and error['code'] == -302 and code[2:] in text
                    and f'error code {code_number} on page ' in text
                    and ('Inputs[0].Type' in text or 'Outputs[0].Type' in text),
                    'wrong script rejection')
    return {'evidence_sha256': hashlib.sha256(data).hexdigest(),
            'checkpoint_cycles': cycles, 'committed_records': 5, 'negative_controls': 22,
            'settled': False, 'production_ready': False,
            'script_execution_performed_by_this_checker': False}


if __name__ == '__main__':
    if len(sys.argv) != 2:
        raise SystemExit('usage: check-history-checkpoints.py EVIDENCE_JSON')
    print(json.dumps(check(pathlib.Path(sys.argv[1])), indent=2))
