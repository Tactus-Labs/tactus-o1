#!/usr/bin/env python3
"""Bind actual HTTP state witnesses to the separately verified A3 proof journal."""
import copy
import gzip
import importlib.util
import json
import pathlib
ROOT=pathlib.Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('logs',ROOT/'scripts/test-observer-logs.py')
c=importlib.util.module_from_spec(spec);spec.loader.exec_module(c)
ARCHIVE=ROOT/'specs/evidence/observer-state-proofs'


def check(report,source):
    c.check(report,source,9)
    journal=(ROOT/'specs/evidence/sealed-chain-proof/proof/public-values.bin').read_bytes()
    assert bytes.fromhex(source['expected_journal_hex'][2:])==journal
    canonical=json.loads(gzip.decompress((ROOT/'specs/evidence/sealed-proof-settlement/0.210.0/evidence.json.gz').read_bytes()))['results']
    for row in report['records']:
        if isinstance(row['request'],dict) and row['request']['method']=='tactus_getStatus':
            assert row['response']['result']['settlementTip']==canonical['cold_after_proof']['tip']
    proofs,records=report['state_proofs'],report['proof_records']
    assert len(proofs)==6 and len(records)==9
    for index,(proof,record) in enumerate(zip(proofs,records)):
        tag,offset=('earliest',608) if index<3 else ('latest',640)
        assert proof['tag']==tag and proof['stateRoot']=='0x'+journal[offset:offset+32].hex()
        request,reply=record['request'],record['response']
        assert record['http_status']==200 and request['method']=='eth_getProof'
        assert reply['id']==request['id'] and reply['result']==proof['result']
        assert request['params']==[proof['result']['address'],['0x0','0x1','0x'+'00'*32],tag]
        assert len(proof['result']['storageProof'])==3
    for record,code in zip(records[6:],[-32005,-32000,-32602]):
        assert record['request']['method']=='eth_getProof' and record['response']['error']['code']==code
        assert record['response']['id']==record['request']['id']=='proof-error'


def main():
    report=json.loads((ARCHIVE/'http-evidence.json').read_bytes())
    source=json.loads((ARCHIVE/'proving-input.json').read_bytes())
    check(report,source)
    assert report['state_proofs']==json.loads((ARCHIVE/'state-proofs.json').read_bytes())
    changes=[
        lambda r:r['state_proofs'][3].update(stateRoot=r['state_proofs'][0]['stateRoot']),
        lambda r:r['proof_records'][0]['response'].update(id='wrong'),
        lambda r:r['records'][0]['response']['result'].update(provedBatches='0x0'),
        lambda r:r['proof_records'][8]['response']['error'].update(code=-32001),
        lambda r:r['proof_records'].pop(),
    ]
    for change in changes:
        bad=copy.deepcopy(report);change(bad)
        try:check(bad,source)
        except (AssertionError,KeyError,TypeError):pass
        else:raise AssertionError('forged settled proof response accepted')
    print('49 actual HTTP responses bound to accepted A3 proof roots; five corruption controls passed.')


if __name__=='__main__':main()
