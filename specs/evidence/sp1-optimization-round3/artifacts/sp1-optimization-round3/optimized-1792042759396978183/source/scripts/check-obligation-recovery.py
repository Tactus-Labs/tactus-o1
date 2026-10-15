#!/usr/bin/env python3
"""Reconcile fresh A3 duty lifecycle reports against retained canonical receipts."""
import gzip
import hashlib
import importlib.util
import json
import pathlib
import sys

spec=importlib.util.spec_from_file_location('sealed',pathlib.Path(__file__).with_name('check-sealed-settlement.py'))
c=importlib.util.module_from_spec(spec)
spec.loader.exec_module(c)
require=c.require


def check_report(report, result, events, stage, published, settled=False):
    export=result['proving_input']
    require(report['schema']==1 and report['gate_type_script']==export['gate_type_script']
            and report['anchor_type_script']==export['anchor_type_script']
            and report['settlement_type_script']==export['settlement_type_script'], 'recovery deployment differs')
    tip=report['settlement']
    require(report['ckb_genesis']==tip['ckb_genesis'] and report['pinned_height']==tip['pinned_height']
            and report['pinned_hash']==tip['pinned_hash'], 'recovery combines different canonical prefixes')
    require(tip['anchor_type_script']==export['anchor_type_script'] and tip['settlement_type_script']==export['settlement_type_script']
            and tip['published_batches']==published and tip['settled_batches']==(9 if settled else 0)
            and tip['proved_transitions']==int(settled) and tip['initialized'] is settled and tip['settled'] is settled,
            'recovered settlement boundary differs')
    for observation in (report,tip):
        require(observation['production_ready'] is False and observation['withdrawal_authority'] is False
                and observation['independent_cryptographic_verification'] is False, 'observer authority overclaim')
    require(tip['data']==export['next_tip_data' if settled else 'initial_tip_data'], 'recovered Tip data differs')
    if not settled:
        require(tip['tip']==export['settlement_tip'], 'pending duties use wrong Tip')
    require(report['admissions']==4 and report['counts']=={s:4 if s==stage else 0 for s in ['admitted','sealed','published','settled']}, 'lifecycle counts')
    canonical={(row['lane'],row['sequence']):row for row in result['obligations']}
    rows=report['obligations']
    require(len(rows)==4 and len({(row['lane'],row['sequence']) for row in rows})==4, 'duplicate/missing recovered duty')
    labels={e['label']:e for e in events}
    admission_labels={(0,0):'nonce zero',(1,0):'nonce one',(0,1):'malformed input',(1,1):'nonce two'}
    seal=result['cold_gate']['network']['snapshot']['point']
    publication=labels['sealed-settlement/mandatory publication and typed checkpoint']
    for row in rows:
        key=(row['lane'],row['sequence']);original=canonical[key]
        require(row['gate']==original['gate'] and row['payload']==original['payload']
                and row['proof_settled'] is settled and row['status']==stage, 'duty identity or fulfillment differs')
        admission=labels['sealed-settlement/admit '+admission_labels[key]]
        require(row['admission']=={'tx_hash':admission['hash'],'index':'0x0'}, 'admission outpoint differs')
        require(row['seal']==(None if stage=='admitted' else seal), 'seal lifecycle differs')
        if stage in ('published','settled'):
            require(row['publication']=={'anchor':{'tx_hash':publication['hash'],'index':'0x0'},'batch':8,'block':9,'input_slot':original['input_slot']}
                    and row['outcome']==original['outcome'], 'published execution slot differs')
        else:
            require(row['publication'] is None and row['outcome'] is None, 'unpublished duty asserts execution')


def check_document(evidence):
    base=c.check_document(evidence)
    result=evidence['results']
    for key,stage,count in [('after_admission','admitted',0),('after_seal','sealed',8),('before_proof','published',9)]:
        check_report(result['cold_obligations_'+key],result,evidence['evidence'],stage,count)
    return {**base,'cold_lifecycle_phases':3,'same_prefix_settlement_binding':True,'settled_duties':0}


if __name__=='__main__':
    if len(sys.argv)!=2:raise SystemExit('usage: check-obligation-recovery.py EVIDENCE_JSON[.gz]')
    source=pathlib.Path(sys.argv[1]).read_bytes()
    if sys.argv[1].endswith('.gz'):source=gzip.decompress(source)
    print(json.dumps({'evidence_sha256':hashlib.sha256(source).hexdigest(),**check_document(json.loads(source))},indent=2))
