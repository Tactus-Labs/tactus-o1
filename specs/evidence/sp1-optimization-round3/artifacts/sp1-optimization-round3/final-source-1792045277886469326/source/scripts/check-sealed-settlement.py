#!/usr/bin/env python3
"""Reconcile A3 admission, sealed ordering and pending proof input from raw evidence.

This checks retained bytes and RPC receipts, not consensus or Groth16 cryptography.
"""
import hashlib
import gzip
import importlib.util
import json
import pathlib
import sys

spec = importlib.util.spec_from_file_location('bootstrap', pathlib.Path(__file__).with_name('check-settlement-bootstrap.py'))
b = importlib.util.module_from_spec(spec)
spec.loader.exec_module(b)
require, raw, digest, packed = b.require, b.raw, b.digest, b.packed


def u(data, offset, size=8):
    require(offset + size <= len(data), 'truncated integer')
    return int.from_bytes(data[offset:offset + size], 'little')


def lane(data):
    require(len(data) >= 122 and data[:8] == b'TO1LAN01', 'lane encoding')
    count, offset, payloads = data[121], 122, []
    require(count <= 8 and u(data, 49) >= count, 'lane limits')
    root = data[57:89]
    first = u(data, 49) - count
    if first == 0:
        require(root == digest(b'tactus/o1/lane-genesis/v1' + data[8:41]), 'lane genesis root')
    for i in range(count):
        size = u(data, offset, 2)
        offset += 2
        require(0 < size <= 1024 and offset + size <= len(data), 'payload bounds')
        payload = data[offset:offset + size]
        offset += size
        root = digest(b'tactus/o1/lane-append/v1' + root + (first+i).to_bytes(8, 'little') + size.to_bytes(2, 'little') + payload)
        payloads.append(payload)
    require(offset == len(data) and root == data[89:121], 'lane commitment differs')
    return data[40], first, payloads


def batch_payloads(data):
    require(data[:8] == b'TO1BAT01' and u(data, 192, 2) == 1, 'expected one block')
    offset, payloads = 224, []
    for _ in range(u(data, 222, 2)):
        size = u(data, offset, 4)
        offset += 4
        require(offset + size <= len(data), 'truncated transaction')
        payloads.append(data[offset:offset+size])
        offset += size
    require(offset == len(data), 'trailing batch data')
    return payloads


def check_document(evidence):
    r = evidence['results']
    require(r['suite'] == 'sealed-settlement-input-v1' and r['complete'] is True
            and r['error'] is None and r['settled'] is False, 'not a completed pending-proof preparation')
    require(r['production_ready'] is False and r['withdrawal_authority'] is False
            and r['G2'] == r['G3'] == 'OPEN', 'unsupported readiness claim')
    events = evidence['evidence']
    labels = {e['label']: e for e in events}
    require(len(events) == len(labels) == 21 and sum(e['result'] == 'committed' for e in events) == 17, 'record counts')
    boot = labels['sealed/2 lanes/genesis']
    pub = labels['sealed-settlement/mandatory publication and typed checkpoint']
    seal = labels['sealed-settlement/seal both authenticated lanes']
    tx, pt, export = boot['transaction'], pub['transaction'], r['proving_input']
    anchor, tip, gate = [packed(tx['outputs'][i]['type']) for i in (0, 5, 1)]
    require(anchor == raw(export['anchor_type_script']) and tip == raw(export['settlement_type_script'])
            and gate == raw(export['gate_type_script']), 'exported identities')
    initial, config = raw(tx['outputs_data'][5]), raw(tx['outputs'][5]['type']['args'])
    require(len(initial) == 280 and initial[:16] == b'TO1TIP01' + bytes(8)
            and initial[216:] == bytes(64) and initial[16:216] == raw(tx['outputs_data'][0]), 'unproved genesis state')
    require(export['initial_tip_data'] == tx['outputs_data'][5] and export['settlement_tip'] == {'tx_hash':boot['hash'], 'index':'0x5'}
            and export['tip_capacity'] == int(tx['outputs'][5]['capacity'],16), 'Tip outpoint/capacity')
    require(len(config) == 168 and config[:8] == b'TO1CFG01'
            and config[8:40] == raw(evidence['metadata']['consensus']['genesis_hash'])
            and config[40:72] == digest(anchor) and config[72:104] == raw(export['guest_verifying_key']), 'Tip configuration')
    allocation = raw(tx['outputs_data'][4])
    allocation_hash = digest(b'tactus/o1/genesis-allocation/v1' + allocation)
    require(allocation == raw(export['allocation_hex']) and allocation_hash == config[136:]
            == raw(tx['outputs'][0]['type']['args'])[32:], 'genesis allocation')
    require(pt['outputs'][3]['type'] == {'code_hash':'0x'+config[104:136].hex(), 'hash_type':'data1','args':'0x'+digest(anchor).hex()}
            and pt['outputs_data'][3] == pt['outputs_data'][0]
            and export['checkpoint'] == {'tx_hash':pub['hash'],'index':'0x3'}, 'checkpoint identity')
    publications = [labels[f'sealed-settlement/genesis epoch batch {i}'] for i in range(8)] + [pub]
    require(export['schema'] == 1 and export['prefix_batches'] == 0 and export['settled'] is False
            and export['batches'] == [e['transaction']['outputs_data'][1] for e in publications], 'canonical interval')
    prior = {'tx_hash':boot['hash'], 'index':'0x0'}
    for e in publications:
        require(e['result'] == 'committed' and e['transaction']['inputs'][0]['previous_output'] == prior, 'disconnected publication')
        prior = {'tx_hash':e['hash'], 'index':'0x0'}
    batches = list(map(raw, export['batches']))
    require(all(batch_payloads(x) == [] for x in batches[:8]), 'unexpected early duty')
    # Reconstruct lane history from actual admissions, then bind the immutable seal.
    lanes = {i:raw(tx['outputs_data'][i+2]) for i in range(2)}
    points = {i:{'tx_hash':boot['hash'],'index':hex(i+2)} for i in range(2)}
    for name, index in [('nonce zero',0),('nonce one',1),('malformed input',0),('nonce two',1)]:
        e = labels['sealed-settlement/admit '+name]
        t = e['transaction']
        data = raw(t['outputs_data'][0])
        idx, first, queue = lane(data)
        old_idx, old_first, old_queue = lane(lanes[index])
        require(idx == old_idx == index and first == old_first == 0 and queue[:-1] == old_queue
                and data[8:49] == lanes[index][8:49] and t['inputs'][0]['previous_output'] == points[index], 'admission history')
        lanes[index], points[index] = data, {'tx_hash':e['hash'],'index':'0x0'}
    snapshot_view = r['cold_gate']['network']['snapshot']
    snapshot = raw(snapshot_view['data'])
    require(snapshot[:8] == b'TO1SEA01' and snapshot[8:40] == lanes[0][8:40]
            and u(snapshot,40) == 0 and snapshot[48] == 2, 'snapshot header')
    offset = 49
    for i in range(2):
        length = u(snapshot,offset,4)
        offset += 4
        require(snapshot[offset:offset+length] == lanes[i], 'snapshot does not match admitted lane')
        offset += length
        require(points[i] in [x['previous_output'] for x in seal['transaction']['inputs']], 'seal misses lane')
    require(offset == len(snapshot) and snapshot_view['point']['tx_hash'] == seal['hash']
            and raw(seal['transaction']['outputs_data'][int(snapshot_view['point']['index'],16)]) == snapshot, 'immutable snapshot location')
    ordered = [(i,j,p) for j in range(2) for i in range(2) for p in [lane(lanes[i])[2][j]]]
    require(batch_payloads(batches[8]) == [p for _,_,p in ordered], 'mandatory round robin prefix')
    outcomes = r['execution'][0]['outcomes']
    require(len(outcomes) == len(r['obligations']) == 4
            and [o['status'] for o in outcomes] == ['Success','Success','Malformed','Success']
            and [o['transaction_index'] for o in outcomes] == [0,1,None,2]
            and len(r['execution'][0]['transactions']) == len(r['execution'][0]['receipts']) == 3, 'execution slot mapping')
    for slot,(index,sequence,payload) in enumerate(ordered):
        o = r['obligations'][slot]
        require((o['lane'],o['sequence'],raw(o['payload'])) == (index,sequence,payload)
                and raw(o['gate']) == snapshot[8:40] and o['input_slot'] == slot and o['batch'] == 8 and o['block'] == 9
                and o['outcome'] == outcomes[slot] and o['proof_settled'] is False, 'obligation mapping')
    require(ordered[2][2] == b'\1' and outcomes[2]['gas_used'] == 0, 'malformed obligation')
    journal, domain = raw(export['expected_journal_hex']), raw(export['domain_hex'])
    require(len(journal) == 768 and journal[:8] == b'TO1PRF01'
            and domain == config[8:40] + digest(anchor) + digest(tip) + initial[24:56] + initial[208:216]
            and journal[40:176] == domain and journal[176:208] == allocation_hash
            and journal[208:408] == initial[16:216] and journal[408:608] == raw(pt['outputs_data'][0]), 'journal domain and endpoints')
    interval = digest(b'tactus/o1/proof-interval/v1' + (9).to_bytes(8,'little'))
    for data in batches:
        interval = digest(b'tactus/o1/proof-interval-step/v1' + interval + len(data).to_bytes(8,'little') + data)
    require(journal[736:] == interval and raw(export['next_tip_data']) == b'TO1TIP01\1' + bytes(7) + journal[408:608] + journal[640:672] + journal[704:736], 'journal interval/Tip')
    require(raw(r['execution'][0]['header']['stateRoot']) == journal[640:672]
            and raw(r['execution'][0]['hash']) == journal[704:736], 'execution roots differ')
    cold, gate_cold = r['cold_before_proof'], r['cold_gate']
    require(cold['tip'] == export['settlement_tip'] and cold['data'] == export['initial_tip_data']
            and cold['published_batches'] == 9 and cold['settled_batches'] == cold['proved_transitions'] == 0
            and cold['initialized'] is False and cold['settled'] is False, 'publication falsely settled')
    require((gate_cold['admissions'],gate_cold['seals'],gate_cold['batches']) == (4,1,9)
            and gate_cold['network']['anchor']['point'] == prior
            and gate_cold['settlement'] == 'NOT_PROVEN', 'cold A3 reconstruction')
    expected = [('omit forced inputs',15,r['gate_code_hash'],'Inputs[1].Type'),('reorder forced inputs',15,r['gate_code_hash'],'Inputs[1].Type'),('drop malformed obligation',15,r['gate_code_hash'],'Inputs[1].Type'),('malformed proof cannot fulfill obligations',9,r['settlement_code_hash'],'Inputs[0].Type')]
    require({e['label'] for e in events if e['result']=='rejected'} == {'sealed-settlement/'+x[0] for x in expected}, 'rejection set')
    for name,code,code_hash,location in expected:
        e = labels['sealed-settlement/'+name]
        require(e['error'].startswith('rpc error: '), 'not RPC rejection')
        err = json.loads(e['error'][11:])
        text = json.dumps(err)
        require(err['code'] == -302 and f'error code {code} on page ' in text and code_hash[2:] in text and location in text, 'wrong rejection cause')
    return {'commits':17,'negative_controls':4,'admissions':4,'lanes':2,'published_batches':9,'settled_batches':0,'malformed_slot':2,'journal_sha256':hashlib.sha256(journal).hexdigest(),'accepted_execution_proof':False,'production_ready':False}


if __name__ == '__main__':
    if len(sys.argv) != 2:
        raise SystemExit('usage: check-sealed-settlement.py EVIDENCE_JSON')
    source = pathlib.Path(sys.argv[1]).read_bytes()
    if sys.argv[1].endswith('.gz'):
        source = gzip.decompress(source)
    print(json.dumps({'evidence_sha256':hashlib.sha256(source).hexdigest(),**check_document(json.loads(source))},indent=2))
