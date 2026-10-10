#!/usr/bin/env python3
"""Reconcile actual publication evidence; this is not consensus/proof verification."""
import gzip
import importlib.util
import json
import pathlib
import sys
spec=importlib.util.spec_from_file_location('vault',pathlib.Path(__file__).with_name('check-native-vault.py'))
v=importlib.util.module_from_spec(spec);spec.loader.exec_module(v)
raw,hx,num,digest,require=v.raw,v.hx,v.num,v.digest,v.require
def le(n,size):return n.to_bytes(size,'little')
def point(event,i):return {'tx_hash':event['hash'],'index':hex(i)}
def anchor(data):
    b=raw(data);require(len(b)==428 and b[:8]==b'TO1NAP02','native anchor wire')
    return b[8:172],b[172:]
def advance(cfg,before,wire):
    b=raw(wire);require(b[:8]==b'TO1BRG02' and b[8:64]==before[200:] and len(b)<=262144,'batch parent/frame')
    count=num(b[64:66]);require(count<=32,'record bound');records=[]
    seq,cum,acc=num(before[200:208]),num(before[208:224]),before[224:256]
    for i in range(count):
        r=b[66+i*124:66+(i+1)*124];seq+=1;cum+=num(r[36:44])
        require(len(r)==124 and r[:8]==b'TO1DPR01' and num(r[8:16])==seq and num(r[36:44])>0 and r[16:36] not in [bytes(20),cfg[112:132]],'record identity')
        require(r[44:76]==acc and num(r[108:124])==cum,'record continuation')
        acc=digest(b'tactus/o1/deposits/append/v1',cfg+r[:76]+le(cum,16));require(r[76:108]==acc,'record append')
        records.append(r)
    end=66+124*count;inner=b[end+4:];require(num(b[end:end+4])==len(inner),'user envelope length')
    require(inner[:192]==b'TO1BAT01'+before[8:40]+before[192:200]+before[40:80]+before[96:192]+le(num(before[80:88])+1,8),'user parent domain')
    require(num(inner[192:194])==1,'fixture block count');stamp=num(inner[194:202])
    after=before[:40]+le(num(before[40:48])+1,8)+digest(b'tactus/o1/native-batch/v2',b)+le(num(before[80:88])+1,8)+le(stamp,8)+before[96:200]+le(seq,8)+le(cum,16)+acc
    return after,records,inner

def check(e,execution,geth,*,allow_settlement=False):
    r=e['results'];events=e['evidence'];labels={x['label']:x for x in events}
    settlement_mode=r['suite']=='native-settlement-bootstrap-v2'
    require(not settlement_mode or allow_settlement,'use the complete native settlement auditor')
    checkpoint_mode=r['suite'] in ['native-checkpoint-v2','native-settlement-bootstrap-v2']
    require(r['suite'] in ['native-publication-v2','native-checkpoint-v2','native-settlement-bootstrap-v2'] and r['complete'] is True and r['error'] is None,'incomplete suite')
    require(r['authenticated_publication'] is True and all(r[k] is False for k in ['proof_settled','withdrawal_executed','production_ready']),'unsupported scope')
    require(e['metadata']['node_version'].startswith('0.210.0'),'CKB version')
    require(len(events)==len(labels)==(81 if settlement_mode else 54 if checkpoint_mode else 37) and sum(x['result']=='committed' for x in events)==(13 if settlement_mode else 11 if checkpoint_mode else 10),'exact commit/rejection inventory')
    cfg=raw(r['config']);code=e['metadata']['ordering_code_hash'];lockcode=e['metadata']['lock_code_hash']
    require(code==hx(digest(b'',raw(events[0]['transaction']['outputs_data'][0]))),'deployed anchor program')
    vaultcode=hx(digest(b'',raw(labels['native/deploy pinned vault']['transaction']['outputs_data'][0])))
    require(vaultcode=='0x3b0c9f82f019407ad1784fcf0d62fe695eba3cf235c2e8ce474af5aebbe39237','pinned custody program')
    allocation=raw(r['genesis_allocation']);alloc_hash=digest(b'tactus/o1/genesis-allocation/v1',allocation)
    script=raw(r['anchor_script']);require(v.r.fields(script,3)==[raw(code),b'\x02',le(64,4)+cfg[72:104]+alloc_hash],'anchor type/alloc identity')
    anchor_type={'code_hash':code,'hash_type':'data1','args':hx(cfg[72:104]+alloc_hash)}
    lock={'code_hash':lockcode,'hash_type':'data1','args':hx(digest(b'',script))};immutable={'code_hash':code,'hash_type':'data1','args':'0x'}
    vault_script=b''.join(le(i,4) for i in [217,16,48,49])+raw(vaultcode)+b'\x02'+le(164,4)+cfg
    vault_hash=digest(b'',vault_script);vault_type={'code_hash':vaultcode,'hash_type':'data1','args':hx(cfg)}
    receipt_type={'code_hash':vaultcode,'hash_type':'data1','args':hx(b'TO1REC01'+vault_hash)}
    receipt_lock={'code_hash':vaultcode,'hash_type':'data1','args':'0x'}
    genesis=labels['native/joint genesis'];tx=genesis['transaction'];parent=tx['inputs'][0]
    seed=int(parent['since'],16).to_bytes(8,'little')+raw(parent['previous_output']['tx_hash'])+le(int(parent['previous_output']['index'],16),4)
    require(cfg[72:104]==digest(b'',seed+bytes(8)) and cfg[8:40]==digest(b'',seed+le(1,8)),'joint singleton identities')
    require(tx['header_deps']==[hx(cfg[40:72])] and tx['outputs'][0]['type']==anchor_type and tx['outputs'][0]['lock']==lock,'genesis network/type/lock')
    require(tx['outputs'][1]['type']==vault_type and tx['outputs_data'][2]==r['genesis_allocation'] and tx['outputs'][2]['lock']==immutable and tx['outputs'][2].get('type') is None,'joint vault/immutable allocation')
    require(tx['outputs_data'][0]==r['genesis_state'] and genesis['hash']==r['genesis_transaction'],'genesis report')
    stored,before=anchor(r['genesis_state']);require(stored==cfg and before[40:96]==bytes(56) and before[200:224]==bytes(24) and before[224:]==digest(b'tactus/o1/deposits/empty/v1',cfg),'initial cursor')
    descriptor=b''.join((v.ROOT/p).read_bytes() for p in ['crates/tactus-o1-execution/rules-native-v2.txt','crates/tactus-o1-execution/rules-v1.txt','Cargo.lock','contracts/bridge/NativeCKB.json'])
    require(before[96:128]==digest(b'tactus/o1/native-execution-rules/v2',descriptor),'execution rules binding')
    require(cfg[132:164]==(digest(b'',raw(r['settlement']['script'])) if settlement_mode else bytes([5])*32),'full settlement identity')
    capacity=int(tx['outputs'][0]['capacity'],16);require(capacity==59800000000,'fixed anchor reserve')
    custody=v.state(tx['outputs_data'][1]);require(custody['deposited']==custody['released']==custody['count']==0 and custody['reserve']==39000000000,'empty funded vault')
    require(custody['deposits']==digest(b'tactus/o1/deposits/empty/v1',cfg) and custody['claimed']==v.empty_claims(),'vault genesis accumulators')
    require(len(r['publications'])==2 and len(execution['cases'])==1,'publication count')
    oracle=execution['cases'][0];require(raw(execution['config'])==cfg and len(oracle['steps'])==2,'oracle domain')
    last=genesis;last_vault=point(genesis,1);rows=[];measure=[]
    for i,p in enumerate(r['publications']):
        event=labels[f'native/publish authenticated batch {i}'];tx=event['transaction'];deposit=labels[f'native/deposit actor {i}'];dt=deposit['transaction']
        require(event['result']=='committed' and event['hash']==p['transaction'],'committed publication')
        require(tx['inputs'][0]['previous_output']==point(last,0) and dt['inputs'][0]['previous_output']==last_vault,'singleton continuation')
        require(tx['outputs'][0]=={'capacity':hex(capacity),'lock':lock,'type':anchor_type},'anchor custody unchanged')
        require(v.r.witness(tx)==le(1,4) and tx['outputs'][1]['lock']==immutable and tx['outputs'][1].get('type') is None and tx['outputs_data'][1]==p['batch'],'immutable published bytes')
        require(p['receipt']==point(deposit,1) and {'out_point':p['receipt'],'dep_type':'code'} in tx['cell_deps'],'actual receipt dependency')
        require(dt['outputs'][1]['type']==receipt_type and dt['outputs'][1]['lock']==receipt_lock and dt['outputs_data'][1]==p['record'],'authenticated typed receipt')
        after,records,inner=advance(cfg,before,p['batch']);require(records==[raw(p['record'])],'included record exactness')
        record=records[0];require(num(record[36:44])==(100+50*i)*100000000 and num(record[8:16])==i+1,'funded amount/sequence')
        require(p['deposit_id']==hx(digest(b'tactus/o1/deposit/id/v1',cfg+le(i+1,8))),'deposit id')
        new=v.state(dt['outputs_data'][0]);require(new==dict(custody,deposited=custody['deposited']+num(record[36:44]),count=i+1,deposits=record[76:108],capacity=custody['capacity']+num(record[36:44])),'funded vault accounting')
        require(int(dt['outputs'][0]['capacity'],16)==new['capacity'] and dt['outputs'][0]['type']==vault_type,'funded capacity/type')
        require(tx['outputs_data'][0]==p['state'] and anchor(p['state'])==(cfg,after),'published state/cursor')
        step=oracle['steps'][i];require(raw(step['wrapper'])==raw(p['batch']) and raw(step['before'])==before and raw(step['after'])==after,'oracle canonical input')
        require(len(step['blocks'])==len(p['blocks'])==1 and len(step['deposits'])==1,'oracle block/credit count')
        sb=step['blocks'][0];b=p['blocks'][0];require(all(sb[k]==b[k] for k in ['header','hash','outcomes','transactions']),'oracle execution differs')
        require(step['deposits'][0]['record']==p['record'] and step['deposits'][0]['deposit_id']==p['deposit_id'] and step['deposits'][0]['gas_used']==p['credit_gas'],'oracle system input')
        require(num(inner[222:224])==1 and num(inner[224:228])==len(raw(b['transactions'][0])) and inner[228:]==raw(b['transactions'][0]),'signed user input')
        require(b['outcomes'][0]['status']=='Success' and b['outcomes'][0]['transaction_index']==0 and num(raw(b['outcomes'][0]['output'])[::-1])==i+1,'successful permanent burn')
        h=b['header'];rows.append({'case':'actual-native-publication-v2','number':i+1,'state_root':h['stateRoot'],'gas_used':int(h['gasUsed'],16),'transaction_root':h['transactionsRoot'],'receipt_root':h['receiptsRoot']})
        measure.append({'cycles':int(event['cycles']['cycles'],16),'wire_bytes':v.r.wire_bytes(tx),'deposit_amount_shannons':num(record[36:44])})
        before=after;last=event;last_vault=point(deposit,0);custody=new
    require(geth['geth']=='1.17.8' and geth['fork']=='Shanghai' and geth['blocks']==rows and (geth['deposits'],geth['signed_transactions'],geth['reverts'])==(2,2,0),'independent Geth execution')
    for report in [execution,geth]:require(all(report[k] is False for k in ['authenticated_publication','proof_settled','custody_release','production_ready']),'oracle does not assert CKB authentication')
    require(r['final_anchor']['status']=='live' and r['final_anchor']['cell']['data']['content']==r['publications'][-1]['state'] and r['final_anchor']['cell']['output']==last['transaction']['outputs'][0],'final live anchor')
    require(v.state(r['final_custody_state'])==custody and custody['capacity']==64000000000,'final custody')
    cold=r['cold_vault_recovery'];require(cold['canonical_pin_rechecked'] is True and cold['current_live_rechecked'] is True and cold['deposit_count']==2 and cold['state']==r['final_custody_state'] and cold['vault_script']==hx(vault_script),'independent cold custody recovery')
    require([d['record'] for d in cold['deposits']]==[p['record'] for p in r['publications']],'cold record equality')
    storage=r['final_bridge_account']['storage'];slot=lambda n:int(storage.get(hex(n),'0x0'),16)
    require((slot(0),slot(1),slot(2),slot(6))==(16000000000,25000000000,9000000000,2),'local token conservation')
    require(r['final_root']==rows[-1]['state_root'] and r['final_header']==r['publications'][-1]['blocks'][0]['header'],'final replay report')
    codes={'missing genesis header':7,'nonempty genesis cursor':5,'missing joint vault':8,'wrong chain genesis':7,'wrong anchor lock':9,'inflated anchor reserve':9,'old execution rules':4,'seeded bridge storage':6,'zero caller allocation':6,'wrong bridge runtime':6,'wrong singleton identity':5,'missing authenticated receipt':14,'untyped copied receipt':14,'cross vault receipt':14,'forged amount with valid transcript':14,'forged recipient with valid transcript':14,'wrong successor cursor':12,'mutable publication':10,'metadata rewrite':4,'truncated batch':11,'wrong publication pointer':10,'anchor capacity rewrite':9,'anchor lock takeover':9,'duplicate deposit':11,'replay already published deposit':11,'spend immutable allocation':1,'spend immutable publication':1}
    require({x['label'] for x in events if x['result']=='rejected' and not (checkpoint_mode and x['label'].startswith('checkpoint/')) and not (settlement_mode and x['label'].startswith('settlement/'))}=={'native/'+name for name in codes},'negative controls')
    for label,code_num in codes.items():
        event=labels['native/'+label];error=json.loads(event['error'].removeprefix('rpc error: '))
        require(error['code']==-302 and event['expected_reason']==f'error code {code_num}' and f'error code {code_num} on page ' in event['error'] and code[2:] in event['error'],'wrong program/reason')
        origins=['Inputs[0].Lock'] if code_num==1 else ['Inputs[0].Type','Outputs[0].Type']
        require(any(f'source: {origin}' in event['error'] for origin in origins),'wrong script group')
    # The forged records are internally valid; only receipt authentication rejects them.
    for label,offset in [('forged amount with valid transcript',36),('forged recipient with valid transcript',16)]:
        tx=labels['native/'+label]['transaction'];_,start=anchor(r['genesis_state']);after,records,_=advance(cfg,start,tx['outputs_data'][1])
        require(anchor(tx['outputs_data'][0])==(cfg,after) and records[0][offset:offset+1]!=raw(r['publications'][0]['record'])[offset:offset+1],'not a valid forged transcript')
    committed={x['hash']:x for x in events if x['result']=='committed'}
    for event in list(committed.values())[1:]:
        tx=event['transaction'];incoming=sum(int(committed[p['previous_output']['tx_hash']]['transaction']['outputs'][int(p['previous_output']['index'],16)]['capacity'],16) for p in tx['inputs'])
        require(incoming-sum(int(o['capacity'],16) for o in tx['outputs'])==100000000,'fee funding conservation')
    checkpoint_report=check_checkpoints(e) if checkpoint_mode else None
    return {'checkpoint':checkpoint_report,'commits':13 if settlement_mode else 11 if checkpoint_mode else 10,'script_rejections':68 if settlement_mode else 43 if checkpoint_mode else 27,'authenticated_publications':2,'deposited_shannons':25000000000,'local_circulating_shannons':16000000000,'local_burned_shannons':9000000000,'vault_capacity_shannons':64000000000,'anchor_capacity_shannons':capacity,'publications':measure,'proof_settled':False,'withdrawal_executed':False,'production_ready':False}

def check_checkpoints(e):
    r=e['results'];labels={x['label']:x for x in e['evidence']}
    deploy=labels['checkpoint/deploy program'];require(deploy['result']=='committed','checkpoint deployment')
    code=digest(b'',raw(deploy['transaction']['outputs_data'][0]))
    script=b''.join(le(i,4) for i in [93,16,48,49])+code+b'\x02'+le(40,4)+b'TO1NCP02'+digest(b'',raw(r['anchor_script']))
    lock={'code_hash':e['metadata']['lock_code_hash'],'hash_type':'data1','args':hx(digest(b'',script))}
    ty={'code_hash':hx(code),'hash_type':'data1','args':hx(script[53:])}
    require(len(r['checkpoints'])==2 and r['historical_checkpoint_rechecked'] is True,'checkpoint history count/recheck')
    for i,cp in enumerate(r['checkpoints']):
        event=labels[f'native/publish authenticated batch {i}'];tx=event['transaction']
        require(cp['transaction']==event['hash'] and cp['index']==2 and cp['script']==hx(script),'checkpoint output identity')
        require({'out_point':point(deploy,0),'dep_type':'code'} in tx['cell_deps'],'checkpoint deployed program')
        require(tx['outputs'][2]=={'capacity':hex(57400000000),'lock':lock,'type':ty},'checkpoint reserve/type/lock')
        require(tx['outputs_data'][2]==tx['outputs_data'][0]==r['publications'][i]['state'],'full transition checkpoint data')
        live=cp['live'];require(live['status']=='live' and live['cell']['data']['content']==tx['outputs_data'][2] and live['cell']['output']==tx['outputs'][2],'checkpoint live report')
        require(live['cell']['data']['hash']==hx(digest(b'',raw(tx['outputs_data'][2]))),'checkpoint data hash')
    codes={'dependency alone':(4,'Outputs[0].Type'),'previous state':(7,'Outputs[2].Type'),'forged cursor':(7,'Outputs[2].Type'),'changed custody config':(7,'Outputs[2].Type'),'wrong publication hash':(7,'Outputs[2].Type'),'truncated state':(5,'Outputs[2].Type'),'duplicate checkpoint':(2,'Outputs[2].Type'),'wrong anchor binding':(4,'Outputs[2].Type'),'wrong argument domain':(1,'Outputs[2].Type'),'zero anchor identity':(1,'Outputs[2].Type'),'old anchor wire':(5,'Outputs[2].Type'),'historical checkpoint dependency':(4,'Outputs[0].Type')}
    for i in range(2):
        codes[f'destroy checkpoint {i}']=(2,'Inputs[0].Type');codes[f'consume and recreate {i}']=(2,'Inputs[0].Type')
    require({x['label'] for x in e['evidence'] if x['result']=='rejected' and x['label'].startswith('checkpoint/')}=={'checkpoint/'+name for name in codes},'checkpoint negative inventory')
    for name,(number,source) in codes.items():
        event=labels['checkpoint/'+name];error=json.loads(event['error'].removeprefix('rpc error: '))
        require(error['code']==-302 and event['expected_reason']==f'error code {number}' and f'error code {number} on page ' in event['error'] and code.hex() in event['error'] and f'source: {source}' in event['error'],'checkpoint exact rejection provenance')
    require(len(labels['checkpoint/dependency alone']['transaction']['inputs'])==1,'dependency-only control inputs')
    require(labels['checkpoint/previous state']['transaction']['outputs_data'][2]==r['genesis_state'],'previous-state control')
    duplicate=labels['checkpoint/duplicate checkpoint']['transaction'];require(duplicate['outputs'][2]==duplicate['outputs'][3] and duplicate['outputs_data'][2]==duplicate['outputs_data'][3],'duplicate checkpoint control')
    return {'authenticated_checkpoints':2,'script_rejections':16,'code_hash':hx(code),'capacity_shannons_each':57400000000,'historical_checkpoint_rechecked':True}

if __name__=='__main__':
    p=pathlib.Path(sys.argv[1]);f=p/'evidence.json'
    e=json.loads(f.read_bytes() if f.exists() else gzip.decompress((p/'evidence.json.gz').read_bytes()))
    print(json.dumps(check(e,json.loads((p/'execution.json').read_text()),json.loads((p/'geth.json').read_text())),indent=2))
