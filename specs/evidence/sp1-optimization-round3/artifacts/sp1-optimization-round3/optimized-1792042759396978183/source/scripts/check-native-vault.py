#!/usr/bin/env python3
"""Audit actual native-vault deposits; this is not execution/proof verification."""
import copy
import gzip
import hashlib
import importlib.util
import json
import pathlib
import sys
ROOT=pathlib.Path(__file__).resolve().parent.parent
spec=importlib.util.spec_from_file_location('receipts',pathlib.Path(__file__).with_name('check-proof-receipts.py'))
r=importlib.util.module_from_spec(spec);spec.loader.exec_module(r)
require,raw=r.require,r.raw

def digest(domain,data):return hashlib.blake2b(domain+data,digest_size=32,person=b'ckb-default-hash').digest()
def hx(data):return '0x'+data.hex()
def num(data):return int.from_bytes(data,'little')
def empty_claims():
    root=digest(b'tactus/o1/claims/leaf/v1',b'\0')
    for _ in range(64):root=digest(b'tactus/o1/claims/branch/v1',root+root)
    return root

def state(data):
    b=raw(data);require(len(b)==120 and b[:8]==b'TO1VST01','state encoding')
    out={'reserve':num(b[8:16]),'deposited':num(b[16:32]),'released':num(b[32:48]),'count':num(b[48:56]),'deposits':b[56:88],'claimed':b[88:120]}
    require(0<=out['released']<=out['deposited'],'negative custody')
    out['capacity']=out['reserve']+out['deposited']-out['released'];require(out['capacity']<2**64,'capacity overflow');return out

def check(e):
    result=e['results'];events=e['evidence'];labels={x['label']:x for x in events}
    require(result['suite']=='native-vault-deposits-v1' and result['complete'] is True and result['error'] is None,'incomplete experiment')
    require(all(result[k] is False for k in ['production_ready','authenticated_l2_credit','withdrawal_executed']),'unsupported custody scope')
    require(e['metadata']['node_version'].startswith('0.210.0'),'wrong CKB version')
    require(len(events)==len(labels)==24 and sum(x['result']=='committed' for x in events)==5,'expected five commits/nineteen rejections')
    cfg=raw(result['config']);require(len(cfg)==164 and cfg[:8]==b'TO1VAU01','config')
    require(hx(cfg[40:72])==e['metadata']['consensus']['genesis_hash'],'wrong network')
    require(cfg[72:104]==bytes([3])*32 and cfg[112:132]==bytes([4])*20 and cfg[132:164]==bytes([5])*32,'qualification must retain its separate unproved fixture domain')
    code=e['metadata']['ordering_code_hash'];lock_code=e['metadata']['lock_code_hash']
    deployment=events[0]
    require(hx(digest(b'',raw(deployment['transaction']['outputs_data'][0])))==code,'program bytes')
    require(hx(digest(b'',raw(deployment['transaction']['outputs_data'][1])))==lock_code,'permissionless lock bytes')
    script=raw(result['vault_script']);identity=hx(digest(b'',script))
    require(r.fields(script,3)==[raw(code),b'\x02',len(cfg).to_bytes(4,'little')+cfg],'vault script')
    typ={'code_hash':code,'hash_type':'data1','args':hx(cfg)}
    lock={'code_hash':lock_code,'hash_type':'data1','args':identity}
    record_args=b'TO1REC01'+raw(identity)
    record_type={'code_hash':code,'hash_type':'data1','args':hx(record_args)}
    require(r.fields(raw(result['receipt_script']),3)==[raw(code),b'\x02',len(record_args).to_bytes(4,'little')+record_args],'receipt script metadata')
    immutable={'code_hash':code,'hash_type':'data1','args':'0x'}
    genesis=labels['vault/genesis'];tx=genesis['transaction'];s=state(tx['outputs_data'][0])
    previous=tx['inputs'][0]['previous_output']
    seed=int(tx['inputs'][0]['since'],16).to_bytes(8,'little')+raw(previous['tx_hash'])+int(previous['index'],16).to_bytes(4,'little')+bytes(8)
    require(cfg[8:40]==digest(b'',seed),'singleton genesis identity')
    require(s=={'reserve':39000000000,'deposited':0,'released':0,'count':0,'deposits':digest(b'tactus/o1/deposits/empty/v1',cfg),'claimed':empty_claims(),'capacity':39000000000},'wrong genesis accounting')
    require(result['reserve']==s['reserve'] and result['genesis']['hash']==genesis['hash'] and result['genesis']['state']==tx['outputs_data'][0],'genesis report')
    require(tx['outputs'][0]=={'capacity':hex(s['capacity']),'lock':lock,'type':typ},'wrong initial output')
    last=genesis;measure=[]
    require(len(result['deposits'])==2,'deposit count')
    for i,row in enumerate(result['deposits']):
        event=labels[f'vault/deposit actor {i}'];tx=event['transaction'];record=raw(row['record'])
        require(len(record)==124 and record[:8]==b'TO1DPR01' and num(record[8:16])==i+1,'record frame/sequence')
        amount=(100+50*i)*100000000
        require(record[16:36]==bytes([0x11+i])*20 and num(record[36:44])==amount and record[44:76]==s['deposits']
                and num(record[108:124])==s['deposited']+amount,'record fields')
        accumulator=digest(b'tactus/o1/deposits/append/v1',cfg+record[:76]+record[108:124])
        require(record[76:108]==accumulator,'append digest')
        require(row['actor']==i and row['hash']==event['hash'] and row['deposit_id']==hx(digest(b'tactus/o1/deposit/id/v1',cfg+(i+1).to_bytes(8,'little'))),'deposit identity')
        expected=copy.deepcopy(s);expected.update(deposited=s['deposited']+amount,count=i+1,deposits=accumulator,capacity=s['capacity']+amount)
        require(state(tx['outputs_data'][0])==expected and tx['outputs_data'][1]==hx(record),'state delta')
        require(tx['inputs'][0]['previous_output']=={'tx_hash':last['hash'],'index':'0x0'} and len(tx['inputs'])==2,'predecessor not consumed')
        require(tx['outputs'][0]=={'capacity':hex(expected['capacity']),'lock':lock,'type':typ},'custody identity changed')
        require(tx['outputs'][1]=={'capacity':hex(23800000000),'lock':immutable,'type':record_type},'immutable receipt differs')
        live=row['receipt_live'];require(live['status']=='live' and live['cell']['output']==tx['outputs'][1] and live['cell']['data']['content']==hx(record),'receipt not live')
        cycles=int(event['cycles']['cycles'],16);require(0<cycles<=10000000000,'cycle bound')
        measure.append({'actor':i,'amount_shannons':amount,'vm_cycles':cycles,'wire_bytes':r.wire_bytes(tx),'receipt_capacity_shannons':23800000000})
        s=expected;last=event
    require(state(result['final_state'])==s and result['final_live']['status']=='live'
            and result['final_live']['cell']['data']['content']==result['final_state']
            and result['final_live']['cell']['output']==last['transaction']['outputs'][0],'final custody differs')
    by_hash={x['hash']:x for x in events if x['result']=='committed'}
    for event in events[1:]:
        if event['result']!='committed':continue
        tx=event['transaction'];incoming=sum(int(by_hash[p['previous_output']['tx_hash']]['transaction']['outputs'][int(p['previous_output']['index'],16)]['capacity'],16) for p in tx['inputs'])
        require(incoming-sum(int(o['capacity'],16) for o in tx['outputs'])==100000000,'funding conservation/fee')
    expected={'false reserve':4,'forged genesis identity':2,'receipt without funding transition':2,'wrong recipient':5,'wrong amount':5,'wrong sequence':5,'wrong previous accumulator':5,'wrong next accumulator':5,'wrong cumulative deposit':5,'missing receipt':2,'duplicate receipts':2,'underfunded deposit':4,'lock takeover':4,'reserve rewrite':5,'mutable receipt lock':5,'only one typed input per transition':2,'cannot recreate singleton':2,'no release without proof':6,'cannot destroy funded vault':3}
    require({x['label'] for x in events if x['result']=='rejected'}=={'vault/'+name for name in expected},'negative set')
    for name,number in expected.items():
        event=labels['vault/'+name];error=json.loads(event['error'].removeprefix('rpc error: '));text=event['error']
        require(event['expected_reason']==f'error code {number}' and error['code']==-302 and f'error code {number} on page ' in text and code[2:] in text,'wrong script rejection')
        require(any(f'source: {origin}' in text for origin in ['Inputs[0].Type','Inputs[1].Type','Outputs[0].Type','Outputs[1].Type']),'wrong boundary')
    positive=labels['vault/deposit actor 0']['transaction'];base=raw(positive['outputs_data'][1])
    for name,offset in [('wrong recipient',16),('wrong amount',36),('wrong sequence',8),('wrong previous accumulator',44),('wrong next accumulator',76),('wrong cumulative deposit',108)]:
        changed=bytearray(base);changed[offset]^=1
        require(raw(labels['vault/'+name]['transaction']['outputs_data'][1])==changed,'missing mutation')
    missing=labels['vault/missing receipt']['transaction'];require(len(missing['outputs'])==2 and missing['outputs'][0]['type']==typ and missing['outputs'][1].get('type') is None,'receipt was not removed')
    duplicate=labels['vault/duplicate receipts']['transaction'];require(duplicate['outputs'][1]==duplicate['outputs'][2] and duplicate['outputs_data'][1:3]==[hx(base)]*2,'not duplicated')
    require(int(labels['vault/underfunded deposit']['transaction']['outputs'][0]['capacity'],16)==int(positive['outputs'][0]['capacity'],16)-1,'not underfunded')
    combined=labels['vault/only one typed input per transition']['transaction'];second=labels['vault/second independent vault']
    other_cfg=raw(result['second_vault']['config']);other_tx=second['transaction']
    previous=other_tx['inputs'][0]['previous_output']
    seed=int(other_tx['inputs'][0]['since'],16).to_bytes(8,'little')+raw(previous['tx_hash'])+int(previous['index'],16).to_bytes(4,'little')+bytes(8)
    require(other_cfg[:8]==cfg[:8] and other_cfg[40:]==cfg[40:] and other_cfg[8:40]==digest(b'',seed) and other_cfg!=cfg,'second singleton domain')
    require(other_tx['outputs'][0]['type']==dict(typ,args=hx(other_cfg)) and result['second_vault']['hash']==second['hash'] and result['second_vault']['state']==other_tx['outputs_data'][0],'second vault metadata')
    require(combined['inputs'][0]['previous_output']=={'tx_hash':last['hash'],'index':'0x0'} and combined['inputs'][1]['previous_output']=={'tx_hash':second['hash'],'index':'0x0'}
            and second['transaction']['outputs'][0]['type']['code_hash']==code,'not two independent vaults')
    return {'commits':5,'negative_controls':19,'deposited_shannons':s['deposited'],'reserved_shannons':s['reserve'],'vault_capacity_shannons':s['capacity'],'deposits':measure,'authenticated_l2_credit':False,'withdrawal_executed':False,'production_ready':False}

if __name__=='__main__':
    path=pathlib.Path(sys.argv[1]);data=path.read_bytes()
    print(json.dumps(check(json.loads(gzip.decompress(data) if path.suffix=='.gz' else data)),indent=2))
