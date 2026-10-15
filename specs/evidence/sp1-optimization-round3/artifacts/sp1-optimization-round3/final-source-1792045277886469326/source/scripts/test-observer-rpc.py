#!/usr/bin/env python3
"""Independently reconcile retained HTTP observations; not a live CKB test."""
import copy
import json
import pathlib
import tomllib

ROOT = pathlib.Path(__file__).resolve().parent.parent
ARCHIVE = ROOT / 'specs/evidence/observer-rpc'


def check(report, source, proved_batches=0):
    assert report['complete'] is True and report['node_unavailability_recovery'] is True
    assert report['production_ready'] is False and report['rpc_p2p_reorg_measured'] is False
    assert report['ckb_version'].split()[1] == '0.210.0'
    records = report['records']; assert len(records) == 31
    calls = {}
    for row in records:
        request, response = row['request'], row['response']
        if isinstance(request, dict):
            if 'id' not in request:
                assert response is None and row['http_status'] == 204
                continue
            assert row['http_status'] == 200 and response['id'] == request['id'] and response['jsonrpc'] == '2.0'
            calls.setdefault((request['method'], json.dumps(request.get('params', []))), []).append(response)
        else:
            assert len(response) == 2
            assert response[0] == {'jsonrpc':'2.0','id':'a','result':'0x9'}
            assert response[1]['id'] == 17 and response[1]['error']['code'] == -32601
    def results(method, params=()):
        return [r['result'] for r in calls[(method,json.dumps(list(params)))]]
    statuses = results('tactus_getStatus')
    assert len(statuses) == 2 and statuses[0] == statuses[1]
    status = statuses[0]
    assert status['publishedBatches'] == '0x9' and status['provedBatches'] == hex(proved_batches)
    assert status['latestIsProofSettled'] == (proved_batches == 9) and status['safeFinalizedPolicy'] is None
    assert status['productionReady'] is False and status['withdrawalAuthority'] is False
    journal = bytes.fromhex(source['expected_journal_hex'][2:])
    blocks = results('eth_getBlockByNumber',['latest',False])
    assert len(blocks) == 2 and blocks[0] == blocks[1]
    block = blocks[0]
    assert block['hash'] == '0x'+journal[704:736].hex()
    assert block['stateRoot'] == '0x'+journal[640:672].hex()
    assert results('eth_getBlockByHash',[block['hash'],False]) == [block]
    full = results('eth_getBlockByNumber',['0x9',True])[0]
    assert len(block['transactions']) == len(full['transactions']) == 3
    cumulative = 0
    for i, (hash, gas) in enumerate(zip(block['transactions'], [21000,21000,25300])):
        tx = results('eth_getTransactionByHash',[hash])[0]
        receipt = results('eth_getTransactionReceipt',[hash])[0]
        assert tx == full['transactions'][i]
        assert tx['hash'] == receipt['transactionHash'] == hash
        assert tx['blockHash'] == receipt['blockHash'] == block['hash']
        assert tx['transactionIndex'] == receipt['transactionIndex'] == hex(i)
        assert receipt['gasUsed'] == hex(gas) and receipt['status'] == '0x1'
        cumulative += gas
        assert receipt['cumulativeGasUsed'] == hex(cumulative)
    assert block['gasUsed'] == hex(cumulative)
    for tag in ['safe','finalized','pending','0x09','0x+9']:
        r = calls[('eth_getBlockByNumber',json.dumps([tag,False]))][0]
        assert r['error']['code'] == (-32000 if tag in ['safe','finalized','pending'] else -32602)
    assert calls[('eth_blockNumber','[]')][0]['error']['code'] == -32001


def main():
    report = json.loads((ARCHIVE/'http-evidence.json').read_bytes())
    source = json.loads((ARCHIVE/'proving-input.json').read_bytes())
    check(report, source)
    mutations = [
        lambda r: r['records'][3]['response']['result'].__setitem__('stateRoot','0x'+'00'*32),
        lambda r: r['records'][8]['response']['result'].__setitem__('transactionIndex','0x7'),
        lambda r: r['records'][0]['response']['result'].__setitem__('provedBatches','0x9'),
        lambda r: r['records'][27]['response'].__setitem__('id','wrong'),
        lambda r: r['records'].pop(),
    ]
    for change in mutations:
        bad = copy.deepcopy(report); change(bad)
        try: check(bad, source)
        except (AssertionError,KeyError,TypeError): pass
        else: raise AssertionError('corrupted HTTP evidence accepted')
    # HTTP dependencies must not silently replace the execution dependency versions.
    old = tomllib.loads((ROOT/'Cargo.lock').read_text())['package']
    new = tomllib.loads((ROOT/'services/observer-rpc/Cargo.lock').read_text())['package']
    frozen = {(p['name'],p['version'],p.get('source'),p.get('checksum')) for p in old}
    old_names = {p['name'] for p in old}
    for p in new:
        if p['name'] in old_names:
            assert (p['name'],p['version'],p.get('source'),p.get('checksum')) in frozen, p['name']
    print('Retained observer HTTP evidence and 5 corruption controls passed; shared dependency pins unchanged.')


if __name__ == '__main__': main()
