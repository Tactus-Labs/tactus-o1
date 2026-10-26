#!/usr/bin/env python3
"""Independent Molecule sizing for retained canonical 0.02 envelope evidence.

Read-only: no RPC, proof generation, CI or RISC-V contract experiment. Rebuilds
raw transaction bytes and requires their CKB hashes to match committed evidence.
"""
import hashlib
import json
from pathlib import Path
import sys


def u32(n):
    return n.to_bytes(4, 'little')


def raw(value):
    if not isinstance(value, str) or not value.startswith('0x'):
        raise ValueError('expected hex bytes')
    return bytes.fromhex(value[2:])


def integer(value, width):
    return int(value, 16).to_bytes(width, 'little')


def blob(value):
    return u32(len(value)) + value


def table(fields):
    offset = 4 * (len(fields) + 1)
    offsets = []
    for value in fields:
        offsets.append(u32(offset))
        offset += len(value)
    return u32(offset) + b''.join(offsets + fields)


def vector(fields):
    return table(fields) if fields else u32(4)


def fixed(fields):
    return u32(len(fields)) + b''.join(fields)


def script(value):
    return table([raw(value['code_hash']), bytes([{'data': 0, 'type': 1, 'data1': 2, 'data2': 4}[value['hash_type']]]), blob(raw(value['args']))])


def point(value):
    return raw(value['tx_hash']) + integer(value['index'], 4)


def serialize(tx):
    body = table([
        integer(tx['version'], 4),
        fixed([point(d['out_point']) + bytes([{'code': 0, 'dep_group': 1}[d['dep_type']]]) for d in tx['cell_deps']]),
        fixed([raw(h) for h in tx['header_deps']]),
        fixed([integer(i['since'], 8) + point(i['previous_output']) for i in tx['inputs']]),
        vector([table([integer(o['capacity'], 8), script(o['lock']), script(o['type']) if o.get('type') else b'']) for o in tx['outputs']]),
        vector([blob(raw(d)) for d in tx['outputs_data']]),
    ])
    return body, table([body, vector([blob(raw(w)) for w in tx['witnesses']])])


def measure(directory):
    directory = Path(directory)
    evidence = json.loads((directory / 'evidence.json').read_text())
    rows = []
    for event in evidence['evidence']:
        if event['label'] not in ('maximum encoded snapshot accepted on canonical CKB', 'maximum encoded batch accepted on canonical CKB'):
            continue
        body, complete = serialize(event['transaction'])
        digest = '0x' + hashlib.blake2b(body, digest_size=32, person=b'ckb-default-hash').hexdigest()
        if digest != event['hash'] or event['result'] != 'committed':
            raise ValueError('raw serialization does not match committed transaction')
        cycles = event['cycles']
        if isinstance(cycles, dict):
            cycles = cycles['cycles']
        rows.append({'label': event['label'], 'transaction_hash': digest,
                     'transaction_bytes': len(complete), 'raw_bytes': len(body),
                     'witness_envelope_bytes': len(complete) - len(body),
                     'node_cycles': int(cycles, 16) if isinstance(cycles, str) else cycles,
                     'block_number': event['block_number'], 'block_hash': event['block_hash']})
    if len(rows) != 2:
        raise ValueError('expected two committed maximum-envelope operations')
    return {'schema': 'tactus-v02-independent-envelope-measurement-v1',
            'source': str(directory), 'raw_hashes_match_committed_transactions': True,
            'measurements': rows, 'scope': 'full signed canonical transactions; byte maximum, not computational maximum'}


if __name__ == '__main__':
    if len(sys.argv) != 2:
        raise SystemExit('usage: measure-v02-envelope.py CANONICAL_ENVELOPE_RUN')
    print(json.dumps(measure(sys.argv[1]), indent=2))
