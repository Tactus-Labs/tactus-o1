#!/usr/bin/env python3
"""Reconcile real A3 proof settlement; RPC receipts supply script validity.

This never generates a proof or independently re-executes cryptography.
"""
import copy
import gzip
import hashlib
import importlib.util
import json
import pathlib
import sys


def sibling(name):
    spec=importlib.util.spec_from_file_location(name,pathlib.Path(__file__).with_name(name+'.py'))
    module=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


pending=sibling('check-obligation-recovery')
receipts=sibling('check-proof-receipts')
require,raw=pending.c.require,pending.c.raw


def check_document(evidence,proof_dir):
    result=evidence['results']
    require(result['suite']=='sealed-settlement-proof-v1' and result['complete'] is True
            and result['settled'] is True and result['error'] is None, 'real A3 settlement did not complete')
    events=evidence['evidence'];labels={e['label']:e for e in events}
    require(len(events)==len(labels)==26 and sum(e['result']=='committed' for e in events)==18, 'expected 18 commits and eight rejections')
    projected=copy.deepcopy(evidence)
    projected['evidence']=projected['evidence'][:21]
    projected['results']['suite']='sealed-settlement-input-v1'
    projected['results']['settled']=False
    for row in projected['results']['obligations']:row['proof_settled']=False
    pending.check_document(projected)
    export=result['proving_input']
    proof=(proof_dir/'groth16-proof.bin').read_bytes()
    journal=(proof_dir/'public-values.bin').read_bytes()
    metadata=json.loads((proof_dir/'result.json').read_bytes())
    require(result['source_proof']==metadata and metadata['proof_generated'] is True
            and metadata['proof_kind']=='SP1 real Groth16' and metadata['native_chain_replay_match'] is True
            and metadata['prefix_batches']==0 and metadata['interval_batches']==9
            and metadata['guest_verifying_key']==export['guest_verifying_key'], 'proof provenance differs')
    require(0<len(proof)<=4096 and len(journal)==768 and journal==raw(export['expected_journal_hex'])
            and metadata['public_values_hex']==journal.hex(), 'wrong proof journal or size')
    encoded=b'TO1SETW1'+journal+len(proof).to_bytes(4,'little')+proof
    boot=labels['sealed/2 lanes/genesis']
    publication=labels['sealed-settlement/mandatory publication and typed checkpoint']
    accepted=labels['sealed-settlement/real proof fulfills published obligations']
    tx=accepted['transaction'];transition=result['transition']
    require(accepted['result']=='committed' and transition['hash']==accepted['hash'], 'not committed')
    require(len(tx['inputs'])==len(tx['outputs'])==len(tx['outputs_data'])==2
            and tx['inputs'][0]['previous_output']==export['settlement_tip']
            and tx['inputs'][1]['previous_output']==export['fee_input'], 'wrong settlement inputs')
    require(tx['outputs'][0]==boot['transaction']['outputs'][5]
            and tx['outputs_data'][0]==export['next_tip_data']
            and receipts.witness(tx)==encoded and export['checkpoint'] in [d['out_point'] for d in tx['cell_deps']], 'wrong Tip/proof/checkpoint')
    fee_point=export['fee_input']
    require(fee_point['tx_hash']==publication['hash'], 'unexpected fee provenance')
    fee=int(publication['transaction']['outputs'][int(fee_point['index'],16)]['capacity'],16)-int(tx['outputs'][1]['capacity'],16)
    require(fee==100_000_000 and int(tx['outputs'][0]['capacity'],16)==export['tip_capacity'], 'fee or reserved capacity differs')
    cycles=int(accepted['cycles']['cycles'],16)
    require(transition['cycles']==accepted['cycles'] and 0<cycles<=10_000_000_000
            and transition['node_wire_bytes']==receipts.wire_bytes(tx), 'cycles or wire measurement differs')
    consumed=transition['consumption']
    require(consumed['point']==export['settlement_tip'] and consumed['live_cell']['status'] in ('dead','unknown'), 'predecessor still live or wrong point')
    for name,event in [('creation',boot),('consumer',accepted)]:
        observed=consumed[name]
        expected_transaction=copy.deepcopy(event['transaction'])
        for output in expected_transaction['outputs']:output.setdefault('type',None)
        require(observed['tx_status']['status']=='committed' and observed['transaction']['hash']==event['hash']
                and observed['tx_status']['block_hash']==event['block_hash']
                and all(observed['transaction'][field]==expected_transaction[field] for field in ['inputs','outputs','outputs_data','witnesses']), 'canonical consumption record differs')
    require(sum(i['previous_output']==export['settlement_tip'] for i in consumed['consumer']['transaction']['inputs'])==1, 'Tip not consumed exactly once')
    controls={}
    for name,offset,code in [('interval data',736,9),('forced final state',640,7),('predecessor',248,7)]:
        label='sealed-settlement/tampered '+name
        modified=bytearray(encoded);modified[8+offset]^=1
        attempted=labels[label]['transaction']
        require(receipts.witness(attempted)==modified and attempted['inputs']==tx['inputs']
                and attempted['outputs']==tx['outputs'] and attempted['outputs_data']==tx['outputs_data'], 'wrong tamper attempt')
        controls[label]=code
    replay='sealed-settlement/replay cannot fulfill twice'
    replay_tx=labels[replay]['transaction']
    require(replay_tx['inputs'][0]['previous_output']=={'tx_hash':accepted['hash'],'index':'0x0'}
            and replay_tx['outputs_data'][0]==export['next_tip_data'] and receipts.witness(replay_tx)==encoded, 'replay targets wrong Tip or proof')
    controls[replay]=7
    require({e['label'] for e in events[21:]}==set(controls)|{accepted['label']}, 'wrong post-preparation control set')
    for label,code in controls.items():
        event=labels[label]
        require(event['result']=='rejected' and event['expected_reason']==f'error code {code}'
                and event['error'].startswith('rpc error: '), 'not expected rejection')
        error=json.loads(event['error'][11:]);text=json.dumps(error)
        require(error['code']==-302 and result['settlement_code_hash'][2:] in text
                and 'Inputs[0].Type' in text and f'error code {code} on page ' in text, 'not exact settlement script rejection')
    cold=result['cold_after_proof']
    require(cold['tip']=={'tx_hash':accepted['hash'],'index':'0x0'} and cold['data']==export['next_tip_data']
            and cold['published_batches']==cold['settled_batches']==9 and cold['proved_transitions']==1
            and cold['settled'] is True and cold['initialized'] is True, 'cold settled boundary differs')
    require(all(row['proof_settled'] is True for row in result['obligations']), 'not all duties fulfilled')
    report=result['cold_obligations_after_proof']
    pending.check_report(report,result,events,'settled',9,True)
    require(report['settlement']['tip']==cold['tip'] and report['settlement']['data']==cold['data'], 'cold duty fulfillment uses different Tip')
    return {'commits':18,'negative_controls':8,'published_batches':9,'settled_batches':9,'settled_duties':4,'malformed_settled_duties':1,'vm_cycles':cycles,'node_wire_bytes':transition['node_wire_bytes'],'fee_shannons':fee,'proof_sha256':hashlib.sha256(proof).hexdigest(),'journal_sha256':hashlib.sha256(journal).hexdigest(),'accepted_execution_proof':True,'independent_cryptographic_verification':False,'production_ready':False}


if __name__=='__main__':
    if len(sys.argv)!=3:raise SystemExit('usage: check-sealed-proof.py EVIDENCE_JSON[.gz] PROOF_DIRECTORY')
    source=pathlib.Path(sys.argv[1]).read_bytes()
    if sys.argv[1].endswith('.gz'):source=gzip.decompress(source)
    print(json.dumps({'evidence_sha256':hashlib.sha256(source).hexdigest(),**check_document(json.loads(source),pathlib.Path(sys.argv[2]))},indent=2))
