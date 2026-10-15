#!/usr/bin/env python3
"""Exercise real HTTP against a copy of a stopped CKB 0.210.0 A3 lab DB.

Usage: qualify-observer-rpc.py CKB_BIN STOPPED_SEALED_LAB_DIR [OBSERVER_BIN]
Only subprocesses created here are stopped. Fixed isolated ports: 18744/18745,
18545. Refuse occupied ports before launching. No calls to the user's node.
"""
import json
import pathlib
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import tomllib
import urllib.request


def main():
    ckb = pathlib.Path(sys.argv[1]).resolve()
    source = pathlib.Path(sys.argv[2]).resolve()
    binary = pathlib.Path(sys.argv[3] if len(sys.argv) > 3 else 'artifacts/observer-rpc-target/debug/tactus-o1-observer-rpc').resolve()
    version = subprocess.check_output([str(ckb), '--version'], text=True).strip()
    assert version.split()[1] == '0.210.0', version
    for port in (18744, 18745, 18545):
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', port))
    root = pathlib.Path(tempfile.mkdtemp(prefix='observer-rpc-', dir='artifacts')).resolve()
    print(root, flush=True)
    shutil.copytree(source / 'node', root / 'node')
    # Clear discovered peers in the COPY so this observer lab cannot join other labs.
    shutil.rmtree(root / 'node/data/network', ignore_errors=True)
    config = root / 'node/ckb.toml'
    text = config.read_text()
    parsed = tomllib.loads(text)
    text = text.replace(parsed['rpc']['listen_address'], '127.0.0.1:18744').replace(parsed['network']['listen_addresses'][0], '/ip4/127.0.0.1/tcp/18745')
    assert 'listen_address = "127.0.0.1:18744"' in text
    config.write_text(text)
    evidence = json.loads((source / 'evidence.json').read_bytes())['results']
    inputs = json.loads((source / 'proving-input.json').read_bytes())
    settings = {'listen': '127.0.0.1:18545', 'ckb_rpc': '127.0.0.1:18744',
                'ckb_genesis': evidence['cold_before_proof']['ckb_genesis'],
                'anchor_type_script': inputs['anchor_type_script'],
                'settlement_type_script': inputs['settlement_type_script'], 'max_batches': 64}
    (root / 'config.json').write_text(json.dumps(settings, indent=2) + '\n')
    (root / 'proving-input.json').write_text(json.dumps(inputs, indent=2) + '\n')
    records = []
    node = observer = None
    logs = []

    def start_node(name):
        log = open(root / name, 'wb'); logs.append(log)
        return subprocess.Popen([str(ckb), '-C', str(root / 'node'), 'run', '--skip-spec-check'], stdout=log, stderr=subprocess.STDOUT)

    def stop(process):
        if process and process.poll() is None:
            process.terminate()
            try: process.wait(timeout=20)
            except subprocess.TimeoutExpired:
                process.kill(); process.wait(timeout=10)

    def wire(value, record=True):
        raw = json.dumps(value).encode()
        req = urllib.request.Request('http://127.0.0.1:18545', raw, {'Content-Type': 'application/json'})
        with urllib.request.urlopen(req, timeout=40) as response:
            body = response.read(); status = response.status
        reply = json.loads(body) if body else None
        if record: records.append({'request': value, 'http_status': status, 'response': reply})
        return reply

    def call(method, params=(), id=1):
        reply = wire({'jsonrpc': '2.0', 'id': id, 'method': method, 'params': list(params)})
        assert reply['id'] == id, reply
        assert 'error' not in reply, reply
        return reply['result']

    def wait_ready():
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            assert node.poll() is None and observer.poll() is None, 'child exited'
            try:
                reply = wire({'jsonrpc':'2.0','id':'ready','method':'eth_blockNumber'}, False)
                if reply.get('result') == '0x9': return
            except OSError: pass
            time.sleep(.2)
        raise TimeoutError('observer did not become ready')

    try:
        node = start_node('node.log')
        log = open(root / 'observer.log', 'wb'); logs.append(log)
        observer = subprocess.Popen([str(binary), str(root / 'config.json')], stdout=log, stderr=subprocess.STDOUT)
        wait_ready()
        status = call('tactus_getStatus')
        expected_proved = '0x9' if evidence['settled'] else '0x0'
        assert status['publishedBatches'] == '0x9' and status['provedBatches'] == expected_proved
        assert status['latestIsProofSettled'] == evidence['settled'] and status['safeFinalizedPolicy'] is None
        assert status['withdrawalAuthority'] is False and status['productionReady'] is False
        assert call('eth_chainId') == '0x7a69' and call('net_version') == '31337'
        block = call('eth_getBlockByNumber', ['latest', False])
        journal = bytes.fromhex(inputs['expected_journal_hex'][2:])
        assert block['number'] == '0x9'
        assert block['hash'] == '0x' + journal[704:736].hex()
        assert block['stateRoot'] == '0x' + journal[640:672].hex()
        assert call('eth_getBlockByHash', [block['hash'], False]) == block
        hashes = block['transactions']; assert len(hashes) == 3
        full = call('eth_getBlockByNumber', ['0x9', True])
        assert len(full['transactions']) == 3
        sender = None
        for i, (hash, gas) in enumerate(zip(hashes, [21000, 21000, 25300])):
            tx = call('eth_getTransactionByHash', [hash])
            receipt = call('eth_getTransactionReceipt', [hash])
            assert full['transactions'][i] == tx
            assert tx['transactionIndex'] == receipt['transactionIndex'] == hex(i)
            assert tx['blockHash'] == receipt['blockHash'] == block['hash']
            assert tx['hash'] == receipt['transactionHash'] == hash
            assert receipt['status'] == '0x1' and receipt['gasUsed'] == hex(gas)
            assert receipt['logs'] == []
            sender = tx['from']
        assert call('eth_getTransactionCount', [sender, 'latest']) == '0x3'
        assert call('eth_getTransactionCount', [sender, 'earliest']) == '0x0'
        assert int(call('eth_getBalance', [sender, 'latest']), 16) < int(call('eth_getBalance', [sender, 'earliest']), 16)
        assert call('eth_getCode', [sender, 'latest']) == '0x'
        assert call('eth_getStorageAt', [sender, '0x0', 'latest']) == '0x' + '00' * 32
        assert call('eth_getBlockByNumber', ['0xa', False]) is None
        assert call('eth_getTransactionReceipt', ['0x' + '00' * 32]) is None
        for tag in ['safe', 'finalized', 'pending', '0x09', '0x+9']:
            reply = wire({'jsonrpc':'2.0','id':tag,'method':'eth_getBlockByNumber','params':[tag,False]})
            assert reply['id'] == tag and 'error' in reply
        batch = [{'jsonrpc':'2.0','id':'a','method':'eth_blockNumber'}, {'jsonrpc':'2.0','method':'eth_blockNumber'}, {'jsonrpc':'2.0','id':17,'method':'eth_sendRawTransaction','params':['0x01']}]
        replies = wire(batch)
        assert len(replies) == 2 and replies[0]['id'] == 'a' and replies[0]['result'] == '0x9'
        assert replies[1]['id'] == 17 and replies[1]['error']['code'] == -32601
        assert wire({'jsonrpc':'2.0','method':'eth_blockNumber'}) is None
        stop(node)
        reply = wire({'jsonrpc':'2.0','id':'node-offline','method':'eth_blockNumber'})
        assert reply['id'] == 'node-offline' and reply['error']['code'] == -32001
        assert wire({'jsonrpc':'2.0','method':'eth_blockNumber'}) is None
        node = start_node('restarted-node.log')
        wait_ready()
        assert call('eth_getBlockByNumber', ['latest',False]) == block
        assert call('tactus_getStatus') == status
        base_count = len(records)
        for filter in [{}, {'fromBlock':'earliest','toBlock':'latest'}, {'blockHash':block['hash']}, {'address':[sender],'topics':[None]}]:
            assert call('eth_getLogs',[filter]) == []
        for filter, code in [({'blockHash':'0x'+'00'*32},-32000), ({'blockHash':block['hash'],'fromBlock':'0x0'},-32602), ({'toBlock':'0xa'},-32602), ({'topics':[None]*5},-32602), ({'blockHash':'0x01'},-32602)]:
            reply = wire({'jsonrpc':'2.0','id':'logs-error','method':'eth_getLogs','params':[filter]})
            assert reply['id']=='logs-error' and reply['error']['code']==code
        log_filter_records = records[base_count:]
        records = records[:base_count]
        base_count = len(records)
        state_proofs = []
        for tag, offset in [('earliest',608),('latest',640)]:
            for address in [sender,'0x'+'11'*20,'0x'+'00'*20]:
                result = call('eth_getProof',[address,['0x0','0x1','0x'+'00'*32],tag])
                assert result['address']==address and len(result['storageProof'])==3
                state_proofs.append({'tag':tag,'stateRoot':'0x'+journal[offset:offset+32].hex(),'result':result})
        for params, code in [([sender,['0x0']*65,'latest'],-32005),([sender,[],'0x1'],-32000),(['0x01',[],'latest'],-32602)]:
            reply = wire({'jsonrpc':'2.0','id':'proof-error','method':'eth_getProof','params':params})
            assert reply['id']=='proof-error' and reply['error']['code']==code
        proof_records = records[base_count:]
        records = records[:base_count]
        (root/'state-proofs.json').write_text(json.dumps(state_proofs,indent=2)+'\n')
        report = {'schema':1, 'ckb_version':version,'source_lab':source.name,'records':records,
                  'log_filter_records':log_filter_records,'proof_records':proof_records,'state_proofs':state_proofs,'complete':True,'node_unavailability_recovery':True,'rpc_p2p_reorg_measured':False,'production_ready':False}
        (root / 'http-evidence.json').write_text(json.dumps(report,indent=2)+'\n')
        print(f'PASS: {len(records)} baseline + {len(log_filter_records)} log + {len(proof_records)} proof HTTP exchanges, dense receipts, canonical roots, node loss/recovery', flush=True)
    finally:
        stop(observer); stop(node)
        for log in logs: log.close()


if __name__ == '__main__': main()
