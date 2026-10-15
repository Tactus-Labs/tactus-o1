#!/usr/bin/env python3
"""Audit retained contract execution evidence; no L1 authentication is claimed."""
import gzip
import hashlib
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent

def require(value, message):
    if not value:
        raise ValueError(message)

def load(path):
    data = path.read_bytes()
    return json.loads(gzip.decompress(data) if path.suffix == '.gz' else data)

def check(candidate, geth, system):
    for data in [candidate, system]:
        require(all(data[k] is False for k in ['authenticated_l1_deposits','custody_release','production_ready']),
                'unsupported custody claim')
    require(geth['geth_version'] == 'evm version 1.17.8-stable' and geth['case_count'] == 2
            and geth['block_count'] == 27 and geth['rules_hash'] == candidate['rules_hash'], 'wrong execution profile')
    require(len(candidate['cases']) == len(geth['cases']) == 2, 'case count')
    reverts = 0
    for case, independent in zip(candidate['cases'], geth['cases']):
        require(case['name'] == independent['name'] and case['genesis'] == independent['genesis']
                and case['batch'] == independent['batch'], 'input identity differs')
        require(len(case['batch']['sequence']) == len(case['blocks']) == len(independent['geth']), 'block count')
        for block, result in zip(case['blocks'], independent['geth']):
            header = block['expected']['header']; outcome = block['expected']['outcomes'][0]
            for actual, wanted in [('stateRoot','stateRoot'),('txRoot','transactionsRoot'),('receiptsRoot','receiptsRoot'),('logsBloom','logsBloom')]:
                require(result[actual] == header[wanted], 'independent '+actual+' differs')
            require(int(result['gasUsed'], 0) == int(header['gasUsed'], 0), 'block gas')
            require(len(result['receipts']) == 1 and result.get('rejected',[]) == [], 'not one executed signed call')
            receipt = result['receipts'][0]
            require(int(receipt['gasUsed'], 0) == outcome['gas_used']
                    and int(receipt['status'], 0) == int(outcome['status'] == 'Success'), 'receipt differs')
            require(outcome['status'] in ('Success','Revert'), 'unexpected EVM halt or invalid transaction')
            reverts += outcome['status'] == 'Revert'
    require(reverts == 14, 'expected fourteen reverted signed calls')
    storage = candidate['cases'][0]['final_bridge_account']['storage']
    require(int(storage.get('0x0','0x0'),16) == 0 and storage['0x1'] == storage['0x2'] == '0x3e8'
            and storage['0x6'] == '0x4', 'final seeded conservation differs')
    require(system['geth_version'] == '1.17.8' and system['evm_fork'] == 'Shanghai'
            and len(system['calls']) == 20 and sum(not r['success'] for r in system['calls']) == 9,
            'system call evidence differs')
    require((system['credited'],system['burnt'],system['supply'],system['withdrawals']) == (1000,1000,0,2),
            'system accounting differs')
    credited = [r for r in system['calls'] if r['signature'].startswith('creditDeposit') and r['success']]
    require(len(credited) == 1 and credited[0]['caller'] == '0x'+'00'*20, 'wrong credit caller')
    return {'signed_cases':2,'signed_blocks':27,'signed_reverts':14,'system_calls':20,'system_reverts':9,
            'authenticated_l1_deposits':False,'custody_release':False,'production_ready':False}

if __name__ == '__main__':
    folder = ROOT/'specs/evidence/native-ckb-contract'
    candidate = load(folder/'candidates.json.gz'); geth = load(folder/'verified.json.gz')
    system = load(folder/'system-calls-geth.json')
    for filename, digest in load(folder/'source-manifest.json')['files'].items():
        require(hashlib.sha256((ROOT/filename).read_bytes()).hexdigest() == digest, 'source changed: '+filename)
    print(json.dumps(check(candidate,geth,system),indent=2))
