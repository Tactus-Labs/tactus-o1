#!/usr/bin/env python3
"""Reconcile cold-process reports against captured actual-node blocks/receipts.

This independently checks evidence relationships, not CKB consensus or Groth16.
"""
import copy
import gzip
import importlib.util
import json
import pathlib
import sys

spec = importlib.util.spec_from_file_location('vault', pathlib.Path(__file__).with_name('check-native-vault.py'))
v = importlib.util.module_from_spec(spec)
spec.loader.exec_module(v)
require = v.require


def check(e, blocks, reports):
    base = v.check(e)
    require(len(blocks) == 21, 'expected canonical capture through height 20')
    cfg = v.raw(e['results']['config'])
    require(blocks[0]['header']['hash'] == v.hx(cfg[40:72]), 'captured network')
    txs = {}
    for height, block in enumerate(blocks):
        require(int(block['header']['number'], 16) == height, 'block height')
        if height:
            require(block['header']['parent_hash'] == blocks[height-1]['header']['hash'], 'disconnected history')
        for index, tx in enumerate(block['transactions']):
            require(tx['hash'] not in txs, 'duplicate transaction')
            txs[tx['hash']] = (height, index, tx)
    events = {row['label']: row for row in e['evidence'] if row['result'] == 'committed'}
    for event in events.values():
        require(event['hash'] in txs, 'missing actual committed transaction')
        tx = dict(txs[event['hash']][2])
        del tx['hash']
        submitted = copy.deepcopy(event['transaction'])
        for output in submitted['outputs']:
            output.setdefault('type', None)
        require(tx == submitted, 'captured transaction differs from evidence')
    expected_labels = ['cold_genesis', 'cold_after_deposit_0', 'cold_after_deposit_1', 'cold_final']
    require(set(reports) == set(expected_labels), 'four cold reports required')
    for label, count, height in zip(expected_labels, [0, 1, 2, 2], [8, 12, 16, 20]):
        r = reports[label]
        require(r == e['results'][label], 'report differs from child process evidence')
        require(r['schema'] == 1 and r['kind'] == 'canonical-native-vault-v1', 'report schema')
        require(r['production_ready'] is False and r['authenticated_l2_credit'] is False, 'scope')
        require(r['canonical_pin_rechecked'] is True and r['current_live_rechecked'] is True, 'missing final rechecks')
        require(r['consensus_source'] == 'selected CKB node; no independent consensus or Groth16 verification', 'trust boundary')
        require(r['ckb_genesis'] == v.hx(cfg[40:72]) and r['vault_script'] == e['results']['vault_script'], 'trusted domain')
        require(r['pinned_height'] == height and r['pinned_hash'] == blocks[height]['header']['hash'], 'pin')
        genesis = events['vault/genesis']['hash']
        require(r['genesis'] == {'point': {'tx_hash': genesis, 'index': '0x0'}, 'height': 8, 'block_hash': blocks[8]['header']['hash']}, 'genesis')
        last = events['vault/genesis' if count == 0 else f'vault/deposit actor {count-1}']
        require(r['point'] == {'tx_hash': last['hash'], 'index': '0x0'}, 'current outpoint')
        require(r['output'] == last['transaction']['outputs'][0] and r['state'] == last['transaction']['outputs_data'][0], 'live custody state')
        state = v.state(r['state'])
        require(r['deposit_count'] == count and len(r['deposits']) == count and r['release_transitions'] == 0, 'deposit/release count')
        for field in ['deposited', 'released', 'reserve', 'capacity']:
            require(r[field+'_shannons'] == str(state[field]), 'lossless accounting')
        for i, row in enumerate(r['deposits']):
            event = events[f'vault/deposit actor {i}']
            h, index, tx = txs[event['hash']]
            record = v.raw(tx['outputs_data'][1])
            expected = {'sequence': i+1, 'deposit_id': v.hx(v.digest(b'tactus/o1/deposit/id/v1', cfg+(i+1).to_bytes(8, 'little'))),
                        'recipient': v.hx(record[16:36]), 'amount_shannons': str(v.num(record[36:44])),
                        'cumulative_shannons': str(v.num(record[108:124])), 'record': v.hx(record),
                        'point': {'tx_hash': event['hash'], 'index': '0x1'}, 'output': tx['outputs'][1],
                        'height': h, 'block_hash': blocks[h]['header']['hash'], 'transaction_index': index}
            require(row == expected, 'canonical deposit row differs')
    return dict(base, cold_processes=4, recovered_counts=[0, 1, 2, 2], captured_blocks=21,
                consensus_verified_independently=False)


if __name__ == '__main__':
    path = pathlib.Path(sys.argv[1])
    evidence = path / 'evidence.json'
    e = json.loads(evidence.read_bytes() if evidence.exists() else gzip.decompress((path / 'evidence.json.gz').read_bytes()))
    reports = {k: value for k, value in e['results'].items() if k.startswith('cold_')}
    if (path / 'recovery.json').exists():
        reports = json.loads((path / 'recovery.json').read_text())
    print(json.dumps(check(e, json.loads((path / 'canonical-blocks.json').read_text()), reports), indent=2))
