#!/usr/bin/env python3
"""Reconcile historical proof acceptance, P2P rollback and canonical reapplication."""
import copy
import hashlib
import importlib.util
import json
import pathlib
import sys

spec = importlib.util.spec_from_file_location('first', pathlib.Path(__file__).with_name('check-first-settlement.py'))
first = importlib.util.module_from_spec(spec)
spec.loader.exec_module(first)
require, raw = first.require, first.raw


def check_document(evidence, proof_dir, **profile):
    result = evidence['results']
    require(result['suite'] == 'settlement-proof-p2p-reorg-v1' and result['complete']
            and result['error'] is None, 'incomplete settlement reorg')
    records = evidence['evidence']
    labels = {r['label']: r for r in records}
    require(len(records) == len(labels) == 48, 'expected seven historical commits and 41 rejections')
    # Validate the historical pre-reorg stage, not its present canonical status.
    projected = copy.deepcopy(evidence)
    projected['evidence'] = projected['evidence'][:45]
    projected['results']['suite'] = 'settlement-first-proof-v1'
    first.check_document(projected, proof_dir, **profile)
    reorg = result['reorg']
    require(reorg['truncate_used'] is False and reorg['submit_block_used'] is False
            and reorg['production_ready'] is False, 'unsupported reorg mode')
    require(reorg['partition'] == {'main_peers': [], 'peer_peers': []}, 'not partitioned')
    height = lambda tip: int(tip['number'], 16)
    require(height(reorg['common_tip']) < height(reorg['orphan_tip'])
            < height(reorg['winning_tip']) < height(reorg['final_tip']), 'branch heights')
    require(reorg['orphaned_blocks'] == height(reorg['orphan_tip']) - height(reorg['common_tip']), 'reorg depth')
    old = labels['settlement/first real proof transition']
    peer = labels['settlement-reorg/peer fee spend is canonical']
    new = labels['settlement-reorg/recovered proof with fresh funding']
    rejection = labels['settlement-reorg/orphan transaction old funding']
    require(old['hash'] == reorg['orphan_hash'] and peer['hash'] == reorg['alternative_hash']
            and new['hash'] == reorg['replacement_hash'] and old['hash'] != new['hash'], 'transaction identities')
    old_tx, new_tx, fee_tx = old['transaction'], new['transaction'], peer['transaction']
    require(peer['result'] == new['result'] == 'committed', 'missing replacement commits')
    require(fee_tx['inputs'] == [old_tx['inputs'][1]] and len(fee_tx['outputs']) == 1
            and fee_tx['outputs_data'] == ['0x'] and fee_tx['outputs'][0].get('type') is None, 'alternate spends more than funding')
    require(new_tx['inputs'][0] == old_tx['inputs'][0]
            and new_tx['inputs'][1]['previous_output'] == {'tx_hash': peer['hash'], 'index': '0x0'}, 'replacement input continuity')
    require(new_tx['outputs'][0] == old_tx['outputs'][0]
            and new_tx['outputs_data'] == old_tx['outputs_data']
            and new_tx['cell_deps'] == old_tx['cell_deps']
            and first.receipts.witness(new_tx) == first.receipts.witness(old_tx), 'proof/state/checkpoint changed')
    require(int(fee_tx['outputs'][0]['capacity'], 16) - int(new_tx['outputs'][1]['capacity'], 16)
            == reorg['replacement_fee_shannons'] == 100_000_000, 'replacement fee')
    require(first.receipts.wire_bytes(new_tx) == reorg['replacement_node_wire_bytes']
            and new['cycles'] == reorg['replacement_cycles'], 'replacement measurements')
    require(reorg['orphan_live_before']['status'] == 'live'
            and reorg['orphan_live_before']['cell']['data']['content'] == old_tx['outputs_data'][0]
            and reorg['orphan_live_after']['status'] != 'live'
            and reorg['orphan_transaction_after']['tx_status']['status'] != 'committed', 'orphan still canonical')
    boot = labels['settlement/atomic Anchor and uninitialized Tip genesis']['transaction']
    restored = reorg['restored_initial_tip']
    require(restored['status'] == 'live' and restored['cell']['output'] == boot['outputs'][0]
            and restored['cell']['data']['content'] == boot['outputs_data'][0], 'initial Tip not restored')
    require(rejection['result'] == 'rejected' and rejection['transaction'] == old_tx
            and rejection['expected_reason'] == 'TransactionFailedToResolve', 'old funding rejection')
    error = json.loads(rejection['error'].removeprefix('rpc error: '))
    require(error['code'] == -301 and 'TransactionFailedToResolve' in json.dumps(error), 'wrong RPC failure')
    before = reorg['peer_transaction_before_reconnection']
    require(before['tx_status']['status'] == 'committed' and before['transaction']['hash'] == peer['hash']
            and before['tx_status']['block_hash'] == peer['block_hash'], 'peer branch evidence')
    for name, initialized, count, point, data in [
        ('cold_after_rollback', False, 0, old_tx['inputs'][0]['previous_output'], boot['outputs_data'][0]),
        ('cold_after_replacement', True, 1, {'tx_hash': new['hash'], 'index': '0x0'}, new_tx['outputs_data'][0]),
    ]:
        cold = reorg[name]
        require(reorg['peer_' + name] == cold, 'independent peer recovery differs')
        require(cold['initialized'] is initialized and cold['settled_batches'] == count
                and cold['proved_transitions'] == count and cold['published_batches'] == 1
                and cold['tip'] == point and cold['data'] == data
                and cold['production_ready'] is False and cold['withdrawal_authority'] is False, 'cold recovery differs')
    return {'orphaned_blocks': reorg['orphaned_blocks'], 'settled_batches_after_rollback': 0,
            'settled_batches_after_reapplication': 1, 'same_proof_reused': True,
            'old_funding_rejected': True, 'production_ready': False, 'cryptography_reexecuted_by_checker': False}


def check(path, proof_dir):
    content = path.read_bytes()
    report = check_document(json.loads(content), proof_dir)
    report['evidence_sha256'] = hashlib.sha256(content).hexdigest()
    return report


if __name__ == '__main__':
    print(json.dumps(check(pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])), indent=2))
