#!/usr/bin/env python3
"""Reconcile actual P2P rollback of A3 sealing and mandatory publication."""
import copy
import gzip
import hashlib
import importlib.util
import json
import pathlib
import sys

spec=importlib.util.spec_from_file_location('recovery',pathlib.Path(__file__).with_name('check-obligation-recovery.py'))
c=importlib.util.module_from_spec(spec)
spec.loader.exec_module(c)
require,raw=c.require,c.c.raw


def check_document(evidence):
    r=evidence['results'];events=evidence['evidence'];labels={e['label']:e for e in events}
    require(r['suite']=='sealed-obligation-reorg-v1' and r['complete'] is True and r['error'] is None
            and r['settled'] is False, 'reorg did not complete')
    require(len(events)==len(labels)==25 and sum(e['result']=='committed' for e in events)==20,
            'expected 20 historical commits and five rejections')
    projected=copy.deepcopy(evidence);projected['results']['suite']='sealed-settlement-input-v1';projected['evidence']=projected['evidence'][:21]
    c.check_document(projected)
    reorg=r['reorg'];plan=reorg['plan']
    require(reorg['truncate_used'] is False and reorg['submit_block_used'] is False
            and reorg['proof_generated'] is False and reorg['settled'] is False and reorg['production_ready'] is False, 'reorg scope overclaim')
    require(plan['partition']=={'main':[],'peer':[]},'peers not partitioned')
    common,orphan,winning,final=[int(x['number'],16) for x in [plan['common_tip'],reorg['orphan_tip'],reorg['winning_tip'],reorg['final_tip']]]
    require(orphan>common and reorg['orphaned_blocks']==orphan-common and winning>=orphan+6
            and final>winning and reorg['orphan_tip']['hash']!=reorg['winning_tip']['hash'], 'branch heights')
    old_seal=labels['sealed-settlement/seal both authenticated lanes']
    old_pub=labels['sealed-settlement/mandatory publication and typed checkpoint']
    fee=labels['obligation-reorg/peer fee spend is canonical']
    new_seal=labels['obligation-reorg/recovered complete seal']
    new_pub=labels['obligation-reorg/recovered forced publication']
    require(all(e['result']=='committed' for e in [fee,new_seal,new_pub]) and fee['hash']==reorg['alternative_hash']
            and new_pub['hash']==reorg['replacement_publication'] and new_seal['hash']!=old_seal['hash']
            and new_pub['hash']!=old_pub['hash'], 'replacement transaction identities')
    alt=plan['alternative']
    normalized=copy.deepcopy(alt)
    for output in normalized['outputs']:output.setdefault('type',None)
    require(all(fee['transaction'][key]==value for key,value in normalized.items()) and len(alt['inputs'])==len(alt['outputs'])==1
            and alt['inputs'][0]==old_seal['transaction']['inputs'][-1]
            and alt['outputs'][0].get('type') is None and alt['outputs_data']==['0x'], 'alternative is not seal-fee-only spend')
    source=alt['inputs'][0]['previous_output']
    parent=next(e for e in events if e.get('hash')==source['tx_hash'])
    require(int(parent['transaction']['outputs'][int(source['index'],16)]['capacity'],16)-int(alt['outputs'][0]['capacity'],16)==100_000_000, 'alternative fee')
    for key in ['orphan_seal_status','orphan_publication_status']:
        require(reorg[key]['tx_status']['status']!='committed', 'orphan still canonical')
    require(reorg['orphan_checkpoint_status']['status']!='live','orphan checkpoint is live')
    replay=labels['obligation-reorg/orphan seal funding cannot replay']
    require(replay['transaction']==old_seal['transaction'] and replay['result']=='rejected'
            and replay['expected_reason']=='TransactionFailedToResolve' and replay['error'].startswith('rpc error: '), 'wrong replay attempt')
    error=json.loads(replay['error'][11:])
    require(error['code']==-301 and 'TransactionFailedToResolve' in error['message']
            and source['tx_hash'][2:] in json.dumps(error), 'not consumed funding rejection')
    rolled=reorg['cold_after_rollback']
    require(rolled==reorg['peer_cold_after_rollback'] and rolled['pinned_height']==winning
            and rolled['pinned_hash']==reorg['winning_tip']['hash'], 'rollback observers differ or wrong prefix')
    c.check_report(rolled,r,events,'admitted',8)
    require(new_seal['transaction']['inputs'][:-1]==old_seal['transaction']['inputs'][:-1]
            and new_seal['transaction']['inputs'][-1]['previous_output']=={'tx_hash':fee['hash'],'index':'0x0'}, 'replacement seal does not use restored lanes and fresh funding')
    require(new_seal['transaction']['outputs_data']==old_seal['transaction']['outputs_data']
            and new_pub['transaction']['outputs_data']==old_pub['transaction']['outputs_data'], 'same admitted duties were not republished')
    require(new_pub['transaction']['inputs'][0]==old_pub['transaction']['inputs'][0]
            and new_pub['transaction']['inputs'][1]['previous_output']=={'tx_hash':new_seal['hash'],'index':'0x0'}, 'replacement publication does not use recovered gate/anchor')
    final_report=reorg['cold_after_republication']
    require(final_report==reorg['peer_cold_after_republication'] and final_report['pinned_height']==final
            and final_report['pinned_hash']==reorg['final_tip']['hash'], 'republication observers differ')
    # Reconcile final duties against the actual replacement seal/publication.
    replaced=copy.deepcopy(r)
    indices=[i for i,d in enumerate(new_seal['transaction']['outputs_data']) if raw(d).startswith(b'TO1SEA01')]
    require(len(indices)==1,'replacement snapshot ambiguous')
    replaced['cold_gate']['network']['snapshot']['point']={'tx_hash':new_seal['hash'],'index':hex(indices[0])}
    replaced_events=copy.deepcopy(events)
    for e in replaced_events:
        if e['label']==old_pub['label']:
            e.update(copy.deepcopy(new_pub));e['label']=old_pub['label']
    c.check_report(final_report,replaced,replaced_events,'published',9)
    require({(o['lane'],o['sequence'],o['payload'],json.dumps(o['admission'],sort_keys=True)) for o in rolled['obligations']}
            =={(o['lane'],o['sequence'],o['payload'],json.dumps(o['admission'],sort_keys=True)) for o in final_report['obligations']}, 'lost or duplicated admitted identity across rollback')
    return {'historical_commits_including_orphans':20,'negative_controls':5,'orphaned_blocks':orphan-common,'restored_admitted_duties':4,'republished_duties':4,'settled_duties':0,'both_nodes_cold_recovery_match':True,'same_payloads_and_execution':True,'truncate_used':False,'submit_block_used':False,'production_ready':False}


if __name__=='__main__':
    if len(sys.argv)!=2:raise SystemExit('usage: check-obligation-reorg.py EVIDENCE_JSON[.gz]')
    source=pathlib.Path(sys.argv[1]).read_bytes()
    if sys.argv[1].endswith('.gz'):source=gzip.decompress(source)
    print(json.dumps({'evidence_sha256':hashlib.sha256(source).hexdigest(),**check_document(json.loads(source))},indent=2))
