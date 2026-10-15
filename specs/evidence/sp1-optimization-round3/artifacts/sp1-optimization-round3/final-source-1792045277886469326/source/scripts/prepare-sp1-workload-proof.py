#!/usr/bin/env python3
"""Export a Geth/guest-qualified synthetic workload for real proving.

The output is explicitly not a CKB deployment or canonical-chain export. Its
unassigned guest key must be replaced/bound by the benchmark runner.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct


def integer(value):
    return int(value, 0) if isinstance(value, str) else value


def allocation(genesis):
    accounts = sorted(genesis['accounts'].items())
    data = bytearray(b'TO1GEN01' + struct.pack('<I', len(accounts)))
    for address, account in accounts:
        data += bytes.fromhex(address.removeprefix('0x'))
        data += integer(account['balance']).to_bytes(32, 'big')
        data += struct.pack('<Q', integer(account['nonce']))
        code = bytes.fromhex(account['code'].removeprefix('0x'))
        data += struct.pack('<I', len(code)) + code
        storage = sorted((integer(k), integer(v)) for k, v in account['storage'].items() if integer(v))
        data += struct.pack('<I', len(storage))
        for key, value in storage:
            data += key.to_bytes(32, 'big') + value.to_bytes(32, 'big')
    return bytes(data)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--fixture', type=Path, required=True)
    parser.add_argument('--qualification', type=Path, required=True)
    parser.add_argument('--case', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    fixture = json.loads(args.fixture.read_text())
    selected = [c for c in fixture['cases'] if c['name'] == args.case]
    assert len(selected) == 1
    case = selected[0]
    rows = json.loads((args.qualification / 'results.json').read_text())
    rows = [r for r in rows if r['case'] == args.case]
    assert len(rows) == 1 and rows[0]['native_match'] and rows[0]['geth_checked']
    row = rows[0]
    public = (args.qualification / f"{row['variant']}-{row['case_index']}.public.bin").read_bytes()
    assert len(public) == 768 and public[:8] == b'TO1PRF01'
    alloc = allocation(case['genesis'])
    assert hashlib.blake2b(b'tactus/o1/genesis-allocation/v1' + alloc, digest_size=32, person=b'ckb-default-hash').digest() == public[176:208]
    assert public[136:168] == bytes.fromhex(case['genesis']['rollup_id'].removeprefix('0x'))
    assert int.from_bytes(public[168:176], 'little') == case['genesis']['chain_id']
    assert public[640:672] == bytes.fromhex(case['geth'][-1]['stateRoot'].removeprefix('0x'))
    value = {'schema': 1, 'source': f'Synthetic Geth-verified workload {args.case}; no CKB deployment',
             'synthetic': True, 'ckb_settlement': False, 'production_ready': False,
             'domain_hex': '0x' + public[40:176].hex(), 'allocation_hex': '0x' + alloc.hex(),
             'prefix_batches': 0, 'batches': [case['batch']], 'expected_journal_hex': '0x' + public.hex(),
             'guest_verifying_key': '0x' + '00' * 32,
             'fixture_sha256': hashlib.sha256(args.fixture.read_bytes()).hexdigest(),
             'case': args.case, 'geth_version': fixture['geth_version']}
    with args.output.open('x') as stream:
        json.dump(value, stream, indent=2)
        stream.write('\n')
    print(f'Prepared synthetic proof input: {args.output}')


if __name__ == '__main__':
    main()
