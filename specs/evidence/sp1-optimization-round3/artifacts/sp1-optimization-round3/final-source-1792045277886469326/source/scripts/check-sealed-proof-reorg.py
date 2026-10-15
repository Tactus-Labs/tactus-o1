#!/usr/bin/env python3
"""Reconcile actual rollback and reuse of an A3 proof; not a crypto verifier."""
import copy
import gzip
import hashlib
import importlib.util
import json
import pathlib
import sys
spec=importlib.util.spec_from_file_location('proof',pathlib.Path(__file__).with_name('check-sealed-proof.py'))
c=importlib.util.module_from_spec(spec);spec.loader.exec_module(c)
require,raw=c.require,c.raw


def check_document(evidence,proof_dir):
    r=evidence['results'];events=evidence['evidence'];labels={x['label']:x for x in events}
    require(r['suite']=='sealed-proof-reorg-v1' and r['complete'] is True and r['error'] is None
            and r['settled'] is True,'A3 proof reorg did not complete')
    require(len(events)==len(labels)==29 and sum(x['result']=='committed' for x in events)==20,
            'expected 20 historical commits and nine rejections')
    projected=copy.deepcopy(evidence);projected['results']['suite']='sealed-settlement-proof-v1';projected['evidence']=projected['evidence'][:26]
    c.check_document(projected,proof_dir)
    reorg=r['proof_reorg'];plan=reorg['plan'];export=r['proving_input']
    require(reorg['truncate_used'] is False and reorg['submit_block_used'] is False
            and reorg['settled'] is True and reorg['production_ready'] is False,'unsupported reorg method or scope')
    require(plan['partition']=={'main':[],'peer':[]},'no actual partition')
    common,orphan,winning,final=[int(x['number'],16) for x in [plan['common_tip'],reorg['orphan_tip'],reorg['winning_tip'],reorg['final_tip']]]
    require(orphan>common and reorg['orphaned_blocks']==orphan-common and winning>=orphan+6 and final>winning,'wrong branch heights')
    original=labels['sealed-settlement/real proof fulfills published obligations']
    require(reorg['orphan_hash']==original['hash'] and reorg['orphan_live_before']['status']=='live'
            and reorg['orphan_live_after']['status']!='live' and reorg['orphan_transaction_after']['tx_status']['status']!='committed'
            and reorg['restored_initial_tip']['status']=='live','Tip did not roll back')
    require(reorg['restored_initial_tip']['cell']['data']['content']==export['initial_tip_data'],'wrong restored Tip')
    alternative=labels['sealed-proof-reorg/peer fee spend is canonical']
    alt=copy.deepcopy(plan['alternative'])
    for output in alt['outputs']:output.setdefault('type',None)
    require(alternative['result']=='committed' and alternative['hash']==reorg['alternative_hash']
            and all(alternative['transaction'][k]==v for k,v in alt.items())
            and len(alt['inputs'])==len(alt['outputs'])==1 and alt['outputs'][0]['type'] is None
            and alt['inputs'][0]==original['transaction']['inputs'][1], 'alternative does not conflict only with fee input')
    replay=labels['sealed-proof-reorg/orphan proof funding cannot replay']
    require(replay['result']=='rejected' and replay['transaction']==original['transaction']
            and replay['expected_reason']=='TransactionFailedToResolve' and replay['error'].startswith('rpc error: '),'wrong orphan replay')
    error=json.loads(replay['error'][11:])
    require(error['code']==-301 and 'TransactionFailedToResolve' in error['message']
            and alt['inputs'][0]['previous_output']['tx_hash'][2:] in json.dumps(error),'wrong funding rejection')
    rolled=reorg['cold_after_rollback']
    require(rolled==reorg['peer_cold_after_rollback'] and rolled['pinned_height']==winning
            and rolled['pinned_hash']==reorg['winning_tip']['hash'],'rollback peers disagree')
    c.pending.check_report(rolled,r,events,'published',9)
    replacement=labels['sealed-proof-reorg/same proof fulfills duties again'];tx=replacement['transaction']
    require(replacement['result']=='committed' and replacement['hash']==reorg['replacement_hash']
            and replacement['hash']!=original['hash'] and tx['inputs'][0]==original['transaction']['inputs'][0]
            and tx['inputs'][1]['previous_output']=={'tx_hash':alternative['hash'],'index':'0x0'},'replacement uses wrong Tip/funding')
    require(tx['outputs'][0]==original['transaction']['outputs'][0] and tx['outputs_data']==original['transaction']['outputs_data']
            and tx['cell_deps']==original['transaction']['cell_deps']
            and c.receipts.witness(tx)==c.receipts.witness(original['transaction']),'replacement changes proof, journal, checkpoint or Tip')
    fee=int(alt['outputs'][0]['capacity'],16)-int(tx['outputs'][1]['capacity'],16)
    require(fee==reorg['replacement_fee_shannons']==100_000_000
            and c.receipts.wire_bytes(tx)==reorg['replacement_node_wire_bytes'],'replacement cost differs')
    consumed=reorg['replacement_consumption']
    require(consumed['point']==export['settlement_tip'] and consumed['live_cell']['status'] in ('dead','unknown')
            and consumed['creation']['tx_status']['status']=='committed'
            and consumed['creation']['transaction']['hash']==export['settlement_tip']['tx_hash']
            and consumed['consumer']['tx_status']['status']=='committed'
            and consumed['consumer']['transaction']['hash']==replacement['hash']
            and consumed['consumer']['tx_status']['block_hash']==replacement['block_hash']
            and consumed['consumer']['transaction']['inputs']==tx['inputs'], 'canonical replacement consumption differs')
    boot=labels['sealed/2 lanes/genesis']
    creator=consumed['creation']
    require(creator['tx_status']['block_hash']==boot['block_hash']
            and creator['transaction']['outputs'][5]==boot['transaction']['outputs'][5]
            and creator['transaction']['outputs_data']==boot['transaction']['outputs_data'], 'replacement predecessor creation differs')
    normalized=copy.deepcopy(tx)
    for output in normalized['outputs']:output.setdefault('type',None)
    require(all(consumed['consumer']['transaction'][field]==normalized[field] for field in ['inputs','outputs','outputs_data','witnesses']), 'replacement consumer bytes differ')
    final_report=reorg['cold_after_replacement']
    require(final_report==reorg['peer_cold_after_replacement'] and final_report['pinned_height']==final
            and final_report['pinned_hash']==reorg['final_tip']['hash'],'replacement peers disagree')
    c.pending.check_report(final_report,r,events,'settled',9,True)
    require(final_report['settlement']['tip']=={'tx_hash':replacement['hash'],'index':'0x0'},'wrong canonical replacement Tip')
    before={ (o['lane'],o['sequence']):(o['payload'],o['admission'],o['seal'],o['publication'],o['outcome']) for o in rolled['obligations'] }
    after={ (o['lane'],o['sequence']):(o['payload'],o['admission'],o['seal'],o['publication'],o['outcome']) for o in final_report['obligations'] }
    require(before==after,'proof rollback changed admission or execution identity')
    return {'historical_commits_including_orphan':20,'negative_controls':9,'orphaned_blocks':orphan-common,'duties_after_rollback':{'published':4,'settled':0},'duties_after_replacement':{'published':0,'settled':4},'canonical_proved_transitions':1,'same_exact_proof':True,'both_nodes_cold_recovery_match':True,'replacement_cycles':int(replacement['cycles']['cycles'],16),'production_ready':False}


if __name__=='__main__':
    if len(sys.argv)!=3:raise SystemExit('usage: check-sealed-proof-reorg.py EVIDENCE_JSON[.gz] PROOF_DIRECTORY')
    source=pathlib.Path(sys.argv[1]).read_bytes()
    if sys.argv[1].endswith('.gz'):source=gzip.decompress(source)
    print(json.dumps({'evidence_sha256':hashlib.sha256(source).hexdigest(),**check_document(json.loads(source),pathlib.Path(sys.argv[2]))},indent=2))
