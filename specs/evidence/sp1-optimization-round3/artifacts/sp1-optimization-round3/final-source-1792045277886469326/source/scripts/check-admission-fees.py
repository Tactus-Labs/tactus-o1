#!/usr/bin/env python3
"""Reconcile admission fee policies, input capacities and canonical outcomes."""
import collections
import hashlib
import importlib.util
import itertools
import json
import pathlib
import sys

spec = importlib.util.spec_from_file_location('receipts', pathlib.Path(__file__).with_name('check-proof-receipts.py'))
receipts = importlib.util.module_from_spec(spec)
spec.loader.exec_module(receipts)
require = receipts.require
ARMS = ('A1-shared-head', 'A2-independent-messages', 'A3-one-lane',
        'A3-four-lanes-targeted', 'A3-four-lanes-disjoint')


def check_document(evidence):
    require(evidence['metadata']['node_version'].startswith('0.210.0'), 'requires current CKB version')
    results = evidence['results']
    require(results['suite'] == 'a123-matched-admission-v1' and results['complete']
            and results['error'] is None, 'incomplete admission suite')
    require(results['production_ready'] is False and results['G2'] == 'OPEN', 'unsupported gate claim')
    policy = results['fee_policy']
    require(policy in ('absolute', 'wire-density'), 'fee policy')
    require(results['base_shannons_per_wire_byte'] == (100_000 if policy == 'wire-density' else None), 'base rate')
    expected = set(itertools.product(ARMS, (0, 1, 3, 6), (1, 2, 10), (0, 1)))
    seen = set()
    summary = {arm: collections.Counter() for arm in ARMS}
    canonical_records = [r for r in evidence['evidence'] if r['label'].endswith('-canonical')]
    records = {r['label']: r for r in canonical_records}
    require(len(records) == len(canonical_records), 'duplicate canonical labels')
    for row in results['rows']:
        key = (row['arm'], row['delay_blocks'], row['victim_fee_ratio'], row['repeat'])
        require(key in expected and key not in seen, 'unexpected or duplicate race')
        seen.add(key)
        require(row['label'] == f'{key[0]}/delay-{key[1]}/fee-{key[2]}/repeat-{key[3]}', 'race label')
        candidates = row['candidates']
        require(len(candidates) == 2 and row['victim_funding_live_at_submit'] is True, 'funding or candidate count')
        funding = []
        for actor, candidate in enumerate(candidates):
            tx = candidate['transaction']
            sources = candidate['resolved_inputs']
            require(len(sources) == len(tx['inputs']), 'missing input resolution')
            total = 0
            for source, inp in zip(sources, tx['inputs']):
                require(source['out_point'] == inp['previous_output'] and source['cell']['status'] == 'live', 'input identity/liveness')
                total += int(source['cell']['cell']['output']['capacity'], 16)
            fee = total - sum(int(o['capacity'], 16) for o in tx['outputs'])
            size = receipts.wire_bytes(tx)
            ratio = row['victim_fee_ratio'] if actor else 1
            target = size * 100_000 * ratio if policy == 'wire-density' else 100_000_000 * ratio
            require(fee == candidate['fee_shannons'] == target and size == candidate['wire_bytes'], 'fee/size mismatch')
            require(int(candidate['cycles']['cycles'], 16) > 0, 'missing VM preflight')
            funding.append(tx['inputs'][-1]['previous_output'])
        require(funding[0] != funding[1], 'shared fee input')
        points = [{json.dumps(i['previous_output'], sort_keys=True) for i in c['transaction']['inputs']}
                  for c in candidates]
        conflict = bool(points[0] & points[1])
        require(conflict == row['shared_state_input'], 'conflict classification')
        committed = [row['adversary_committed'], row['victim_committed']]
        require(any(committed) and (not all(committed) if conflict else all(committed)), 'canonical safety/liveness')
        canonical = row['canonical']
        require(sorted(c['actor'] for c in canonical) == [i for i in range(2) if committed[i]], 'canonical actor set')
        for item in canonical:
            actor = item['actor']
            record = records[row['label'] + f'/actor-{actor}-canonical']
            require(record['result'] == 'committed' and record['hash'] == item['hash'], 'missing canonical record')
            view = item['view']
            require(view['tx_status']['block_hash'] == record['block_hash']
                    and view['tx_status']['block_number'] == record['block_number'], 'canonical block identity')
            require(view['tx_status']['status'] == 'committed' and view['transaction']['hash'] == item['hash'], 'node status')
            tx = candidates[actor]['transaction']
            normalized = json.loads(json.dumps(tx))
            for out in normalized['outputs']:
                out.setdefault('type', None)
            for field, value in normalized.items():
                require(view['transaction'][field] == value, 'node transaction differs')
            require(item['node_wire_bytes'] == receipts.wire_bytes(tx), 'node packed size')
        classification = ('victim_committed' if committed[1] else
                          'stale_input' if row['victim_state_live_at_submit'] is False else
                          'live_pool_rejection' if row['victim_submit_error'] is not None else
                          'accepted_lost_conflict')
        require(row['classification'] == classification, 'outcome classification')
        summary[row['arm']][classification] += 1
        summary[row['arm']]['both_committed'] += int(all(committed))
    require(seen == expected, 'missing races')
    require(len(records) == sum(sum(r[k] for k in ('adversary_committed', 'victim_committed')) for r in results['rows']), 'extra canonical record')
    return {'fee_policy': policy, 'races': len(seen), 'outcomes': summary,
            'production_ready': False, 'scope': 'serialized-byte fee matching; not cycle-weighted miner fairness or forced execution'}


def check(path):
    raw = path.read_bytes()
    report = check_document(json.loads(raw))
    report['evidence_sha256'] = hashlib.sha256(raw).hexdigest()
    return report


if __name__ == '__main__':
    print(json.dumps(check(pathlib.Path(sys.argv[1])), indent=2))
