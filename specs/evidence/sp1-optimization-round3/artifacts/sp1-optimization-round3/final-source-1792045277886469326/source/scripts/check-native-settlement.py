#!/usr/bin/env python3
"""Audit actual native settlement bootstrap and proof preparation, not a proof."""
import gzip
import hashlib
import importlib.util
import json
import pathlib
import sys
ROOT=pathlib.Path(__file__).resolve().parent.parent
spec=importlib.util.spec_from_file_location('publication',ROOT/'scripts/check-native-publication.py')
pub=importlib.util.module_from_spec(spec);spec.loader.exec_module(pub)
raw,hx,digest,require=pub.raw,pub.hx,pub.digest,pub.require
KEY='0x00d159402000943b66d0df65c2c154592efbc8490b1ee44dfce8a181cd5e77e5'
PROFILE=b'TO1NPR02;full-vault-config;fixed-vault-code;replay-canonical-genesis-prefix;authenticated-publication-required;nonempty-contiguous-interval;native-deposit-cursors;ethereum-state-and-header;ckb-settlement-required'

def check(e,x,g,inputs,guests,*,require_guest=True):
    require(len(inputs)==2 and (guests is None or len(guests)==2),'complete interval inventory')
    require(not require_guest or guests is not None,'actual guest execution required')
    require(e['results']['suite']=='native-settlement-bootstrap-v2','settlement suite')
    base=pub.check(e,x,g,allow_settlement=True)
    r=e['results'];s=r['settlement'];events={v['label']:v for v in e['evidence']}
    deployment=events['settlement/deploy program'];code=digest(b'',raw(deployment['transaction']['outputs_data'][0]))
    require(deployment['result']=='committed','actual settlement deployment')
    cfg=raw(r['config']);args=b'TO1NSC02'+cfg[40:72]+digest(b'',raw(r['anchor_script']))+digest(b'tactus/o1/genesis-allocation/v1',raw(r['genesis_allocation']))+cfg[8:40]
    script=b''.join(n.to_bytes(4,'little') for n in [189,16,48,49])+code+b'\x02'+(136).to_bytes(4,'little')+args
    require(s['config']==hx(args) and s['script']==hx(script) and s['guest_key']==KEY and cfg[132:164]==digest(b'',script),'real custody/settlement binding without hash cycle')
    genesis=events['native/joint genesis'];tx=genesis['transaction'];tip=raw(s['initial_tip'])
    require(tip==b'TO1TIP01'+bytes(8)+raw(r['genesis_state'])[172:372]+bytes(64),'empty initial Tip')
    output={'capacity':hex(52200000000),'lock':{'code_hash':e['metadata']['lock_code_hash'],'hash_type':'data1','args':hx(digest(b'',script))},'type':{'code_hash':hx(code),'hash_type':'data1','args':hx(args)}}
    require(tx['outputs'][3]==output and raw(tx['outputs_data'][3])==tip and s['tip_point']==pub.point(genesis,3),'joint exact Tip output')
    require({'out_point':pub.point(deployment,0),'dep_type':'code'} in tx['cell_deps'],'deployed verifier executed at genesis')
    live=s['final_live'];require(live['status']=='live' and live['cell']['output']==output and live['cell']['data']['content']==hx(tip),'all unproved transitions left original Tip live')
    domain=cfg+digest(b'',raw(r['anchor_script']));steps=x['cases'][0]['steps'];journal_hashes=[]
    for prefix,inp in enumerate(inputs):
        guest=guests[prefix] if guests is not None else None
        require(inp['schema']=='native-proof-input-v2' and inp['prefix_batches']==prefix and inp['guest_verifying_key']==KEY and inp['authenticated_publication'] is False,'proof input identity/scope')
        require(raw(inp['domain_hex'])==domain and inp['allocation_hex']==r['genesis_allocation'] and inp['batches']==[t['wrapper'] for t in steps],'canonical proof input')
        previous_root=raw(x['cases'][0]['genesis_header']['stateRoot']) if prefix==0 else raw(g['blocks'][0]['state_root'])
        previous_header=raw(steps[0]['blocks'][0]['header']['parentHash']) if prefix==0 else raw(steps[0]['blocks'][0]['hash'])
        interval=digest(b'tactus/o1/native-proof-interval/v2',(2-prefix).to_bytes(8,'little'))
        for step in steps[prefix:]:
            wire=raw(step['wrapper']);interval=digest(b'tactus/o1/native-proof-interval-step/v2',interval+len(wire).to_bytes(8,'little')+wire)
        expected=b'TO1NPR02'+digest(b'tactus/o1/native-proof-profile/v2',PROFILE)+domain+args[72:104]+raw(steps[prefix]['before'])+raw(steps[-1]['after'])+previous_root+raw(g['blocks'][-1]['state_root'])+previous_header+raw(steps[-1]['blocks'][0]['hash'])+interval
        require(len(expected)==940 and raw(inp['expected_journal_hex'])==expected,'independently reconstructed native public journal')
        if guest is not None:
            require(bytes.fromhex(guest['public_values_hex'])==expected,'actual guest public values')
            require(guest['schema']=='native-guest-execution-v2' and guest['sp1']=='6.8.1' and guest['backend']=='local-cpu' and guest['guest_verifying_key']==KEY and guest['native_replay_match'] is True and guest['prefix_batches']==prefix and guest['interval_batches']==2-prefix,'actual guest execution scope')
            require(all(guest[k] is False for k in ['proof_generated','authenticated_publication','ckb_settlement','custody_release','production_ready']),'no proof fabricated from guest execution')
        if prefix==0:
            require(s['candidate_journal']==hx(expected),'candidate journal')
            require(raw(s['candidate_tip'])==b'TO1TIP01'+b'\x01'+bytes(7)+expected[524:724]+expected[812:844]+expected[876:908],'candidate Tip roots/header')
        journal_hashes.append(hashlib.sha256(expected).hexdigest())
    codes={'missing joint anchor':(4,'Outputs[3].Type'),'wrong vault identity':(6,'Outputs[3].Type'),'wrong allocation':(6,'Outputs[3].Type'),'wrong network':(6,'Outputs[3].Type'),'caller selected guest':(1,'Outputs[3].Type'),'initialized genesis':(3,'Outputs[3].Type'),'inflated reserve':(10,'Outputs[3].Type'),'owner lock':(10,'Outputs[3].Type'),'seeded root':(3,'Outputs[3].Type'),'duplicate tip':(2,'Outputs[3].Type'),'dependency cannot bootstrap':(4,'Outputs[0].Type')}
    for label,number in [('missing checkpoint',8),('untyped checkpoint',8),('stale checkpoint',8),('forged endpoint cursor',8),('wrong own identity',6),('wrong profile',6),('wrong output root',7),('inflated tip',10),('tip lock takeover',10),('duplicate successor',2),('malformed witness',5),('v1 proof cannot settle native',9),('destroy tip',3),('nonempty genesis cursor',7)]:codes[label]=(number,'Inputs[0].Type')
    require({v['label'] for v in e['evidence'] if v['result']=='rejected' and v['label'].startswith('settlement/')}=={'settlement/'+k for k in codes},'settlement rejection inventory')
    for label,(number,source) in codes.items():
        event=events['settlement/'+label];error=json.loads(event['error'].removeprefix('rpc error: '))
        require(error['code']==-302 and event['expected_reason']==f'error code {number}' and f'error code {number} on page ' in event['error'] and code.hex() in event['error'] and f'source: {source}' in event['error'],'exact settlement rejection origin')
    copied=events['settlement/untyped checkpoint copy'];require(copied['transaction']['outputs'][0].get('type') is None and copied['transaction']['outputs_data'][0]==r['publications'][-1]['state'],'untyped copy is exact')
    rejected=events['settlement/v1 proof cannot settle native'];w=pub.v.r.witness(rejected['transaction']);public=raw(s['candidate_journal']);old=(ROOT/'specs/evidence/sealed-chain-proof/proof/groth16-proof.bin').read_bytes()
    require(w==b'TO1NSW02'+public+len(old).to_bytes(4,'little')+old,'retained real v1 proof rejected under new guest')
    require({'out_point':pub.point(events['native/publish authenticated batch 1'],2),'dep_type':'code'} in rejected['transaction']['cell_deps'],'wrong-proof control has actual endpoint checkpoint')
    base['settlement']={'type_hash':hx(digest(b'',script)),'code_hash':hx(code),'tip_capacity_shannons':52200000000,'script_rejections':25,'guest_key':KEY,'guest_execution_checked':guests is not None,'journal_sha256':journal_hashes,'proof_generated':False,'tip_initialized':False}
    return base

def read_run(path,guest=True):
    p=path/'evidence.json';e=json.loads(p.read_bytes() if p.exists() else gzip.decompress((path/'evidence.json.gz').read_bytes()))
    return e,json.loads((path/'execution.json').read_text()),json.loads((path/'geth.json').read_text()),[json.loads((path/f'proving-input-{i}.json').read_text()) for i in [0,1]],([json.loads((path/f'guest-{i}/result.json').read_text()) for i in [0,1]] if guest else None)
if __name__=='__main__':
    require(len(sys.argv) in [2,3] and (len(sys.argv)==2 or sys.argv[2]=='--without-guest-execution'),'usage: check-native-settlement.py RUN [--without-guest-execution]')
    path=pathlib.Path(sys.argv[1]);guest=len(sys.argv)==2;args=read_run(path,guest)
    for i,g in enumerate(args[-1] or []):require((path/f'guest-{i}/public-values.bin').read_bytes()==bytes.fromhex(g['public_values_hex']),'guest public-value file')
    print(json.dumps(check(*args,require_guest=guest),indent=2))
