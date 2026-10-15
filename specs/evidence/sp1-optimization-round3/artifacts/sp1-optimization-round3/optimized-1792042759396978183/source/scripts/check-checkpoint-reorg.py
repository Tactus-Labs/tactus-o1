#!/usr/bin/env python3
"""Reconcile P2P checkpoint replacement evidence; does not re-execute consensus."""
import hashlib
import json
import pathlib
import sys


def require(ok, message):
    if not ok:
        raise ValueError(message)


def check(path):
    raw = path.read_bytes()
    evidence = json.loads(raw)
    result = evidence['results']
    require(result['suite'] == 'checkpoint-p2p-reorg-v1' and result['complete']
            and result['error'] is None, 'incomplete reorg experiment')
    require(result['settled'] is False and result['production_ready'] is False
            and result['truncate_used'] is False and result['submit_block_used'] is False,
            'unsupported experiment mode or settlement claim')
    reorg = result['reorg']
    records = evidence['evidence']
    labels = {r['label']: r for r in records}
    require(len(records) == len(labels) == 7, 'wrong evidence count')
    require(sum(r['result'] == 'committed' for r in records) == 6, 'wrong commit count')
    require(reorg['partition'] == {'main_peers': [], 'peer_peers': []}, 'nodes were not partitioned')
    height = lambda h: int(h['number'], 16)
    require(height(reorg['common_tip']) < height(reorg['orphan_tip'])
            < height(reorg['winning_tip']) < height(reorg['final_tip']), 'wrong branch heights')
    require(reorg['orphaned_blocks'] == height(reorg['orphan_tip']) - height(reorg['common_tip'])
            and reorg['orphaned_blocks'] > 0, 'no replaced blocks')
    old = labels['checkpoint-reorg/main branch checkpoint to orphan']
    new = labels['checkpoint-reorg/peer checkpoint is canonical']
    require(old['hash'] == reorg['orphan_transaction_hash']
            and new['hash'] == reorg['alternative_hash'] and old['hash'] != new['hash'],
            'wrong replacement transaction identities')
    require(old['transaction']['inputs'] == new['transaction']['inputs'],
            'transactions do not compete for the same Anchor and fee input')
    for item in (old, new):
        tx = item['transaction']
        require(tx['outputs'][0]['type'] == {
            'code_hash': result['checkpoint_code_hash'], 'hash_type': 'data1',
            'args': result['anchor_type_hash']}, 'wrong checkpoint type')
        require(tx['outputs_data'][0] == tx['outputs_data'][1], 'checkpoint/Anchor mismatch')
    require(old['transaction']['outputs_data'][0] != new['transaction']['outputs_data'][0],
            'replacement did not change authenticated history')
    require(reorg['orphan_live_before']['status'] == 'live'
            and reorg['orphan_live_after']['status'] != 'live', 'orphan checkpoint survived')
    require(reorg['orphan_live_before']['cell']['data']['content']
            == old['transaction']['outputs_data'][0], 'wrong original live cell')
    require(reorg['canonical_live_after']['status'] == 'live'
            and reorg['canonical_live_after']['cell']['data']['content']
            == new['transaction']['outputs_data'][0] == reorg['recovered_anchor'],
            'canonical checkpoint and reconstruction differ')
    require(reorg['canonical_batches'] == 1, 'wrong recovered batch count')
    peer = reorg['peer_transaction_before_reconnection']
    require(peer['tx_status']['status'] == 'committed'
            and peer['transaction']['hash'] == new['hash'], 'replacement not committed on peer')
    rejected = labels['checkpoint-reorg/orphan checkpoint dependency']
    require(rejected['result'] == 'rejected'
            and rejected['expected_reason'] == 'TransactionFailedToResolve', 'wrong rejection')
    require(rejected['error'].startswith('rpc error: '), 'not node rejection')
    error = json.loads(rejected['error'][len('rpc error: '):])
    require(error['code'] == -301 and 'TransactionFailedToResolve' in json.dumps(error),
            'not dependency resolution failure')
    accepted = labels['checkpoint-reorg/canonical checkpoint dependency accepted']
    require(accepted['result'] == 'committed' and accepted['hash'] == reorg['dependency_commit'],
            'canonical dependency was not accepted')
    for item, target in [(rejected, old), (accepted, new)]:
        require(item['transaction']['cell_deps'][-1]['out_point'] == {
            'tx_hash': target['hash'], 'index': '0x0'}, 'wrong checkpoint dependency')
    require(rejected['transaction']['inputs'] == accepted['transaction']['inputs']
            and rejected['transaction']['outputs'] == accepted['transaction']['outputs']
            and rejected['transaction']['outputs_data'] == accepted['transaction']['outputs_data']
            and rejected['transaction']['cell_deps'][:-1] == accepted['transaction']['cell_deps'][:-1],
            'dependency controls changed other transaction fields')
    return {'evidence_sha256': hashlib.sha256(raw).hexdigest(),
            'orphaned_blocks': reorg['orphaned_blocks'], 'canonical_batches': 1,
            'orphan_dependency_rejected': True, 'canonical_dependency_committed': True,
            'settled': False, 'production_ready': False,
            'consensus_reexecuted_by_this_checker': False}


if __name__ == '__main__':
    if len(sys.argv) != 2:
        raise SystemExit('usage: check-checkpoint-reorg.py EVIDENCE_JSON')
    print(json.dumps(check(pathlib.Path(sys.argv[1])), indent=2))
