#!/usr/bin/env python3
"""Audit actual HTTP log requests; nonempty EVM log checks live in Rust tests."""
import copy
import importlib.util
import json
import pathlib

ROOT=pathlib.Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('base',ROOT/'scripts/test-observer-rpc.py')
c=importlib.util.module_from_spec(spec);spec.loader.exec_module(c)


def check(report, source, proved_batches=0):
    c.check(report,source,proved_batches)
    logs=report['log_filter_records']
    assert len(logs)==9
    for i,row in enumerate(logs):
        request,reply=row['request'],row['response']
        assert row['http_status']==200 and request['method']=='eth_getLogs'
        assert reply['id']==request['id'] and reply['jsonrpc']=='2.0'
        assert len(request['params'])==1
        if i<4:assert reply['result']==[] and 'error' not in reply
        else:assert reply['error']['code']==(-32000 if i==4 else -32602) and 'result' not in reply
    block=report['records'][3]['response']['result']
    assert logs[0]['request']['params']==[{}]
    assert logs[1]['request']['params']==[{'fromBlock':'earliest','toBlock':'latest'}]
    assert logs[2]['request']['params']==[{'blockHash':block['hash']}]
    assert logs[3]['request']['params'][0]['topics']==[None]
    assert logs[4]['request']['params']==[{'blockHash':'0x'+'00'*32}]
    assert logs[5]['request']['params']==[{'blockHash':block['hash'],'fromBlock':'0x0'}]
    assert logs[6]['request']['params']==[{'toBlock':'0xa'}]
    assert logs[7]['request']['params']==[{'topics':[None]*5}]
    assert logs[8]['request']['params']==[{'blockHash':'0x01'}]


def main():
    root=ROOT/'specs/evidence/observer-logs'
    report=json.loads((root/'http-evidence.json').read_bytes())
    source=json.loads((root/'proving-input.json').read_bytes())
    check(report,source)
    mutations=[
        lambda r:r['log_filter_records'][0]['response'].__setitem__('result',[{'data':'forged'}]),
        lambda r:r['log_filter_records'][4]['response']['error'].__setitem__('code',-32602),
        lambda r:r['log_filter_records'][2]['request'].__setitem__('method','eth_blockNumber'),
        lambda r:r['log_filter_records'][5]['response'].__setitem__('id','wrong'),
        lambda r:r['log_filter_records'].pop(),
    ]
    for mutate in mutations:
        bad=copy.deepcopy(report);mutate(bad)
        try:check(bad,source)
        except (AssertionError,KeyError,TypeError):pass
        else:raise AssertionError('forged log evidence accepted')
    print('40 real HTTP observations and five corrupted-log controls passed.')


if __name__=='__main__':main()
