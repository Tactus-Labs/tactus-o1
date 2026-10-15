#!/usr/bin/env python3
"""Reconcile live observer snapshots with the actual A3 P2P branch replacement."""
import gzip
import importlib.util
import json
import pathlib
import sys

spec=importlib.util.spec_from_file_location('reorg',pathlib.Path(__file__).with_name('check-obligation-reorg.py'))
c=importlib.util.module_from_spec(spec);spec.loader.exec_module(c)
require=c.require


def check_document(document):
    result=c.check_document(document)
    r=document['results']; reorg=r['reorg']; probes=reorg['rpc_observer']
    before,rolled,after=[probes[k] for k in ('before','after_rollback','after_republication')]
    require(before['process_id']==rolled['process_id']==after['process_id'] and before['process_id']>0,'observer restarted')
    for probe,count,pin in [(before,9,reorg['orphan_tip']),(rolled,8,reorg['winning_tip']),(after,9,reorg['final_tip'])]:
        status=probe['status']
        require(probe['expected_batches']==count and probe['block']['number']==hex(count),'wrong observer head')
        require(status['ckbHash']==pin['hash'] and status['ckbHeight']==pin['number'],'wrong canonical pin')
        require(status['publishedBatches']==hex(count) and status['provedBatches']=='0x0','incorrect settlement boundary')
        require(status['latestIsProofSettled'] is False and status['safeFinalizedPolicy'] is None
                and status['withdrawalAuthority'] is False and status['productionReady'] is False,'overclaim')
    block=before['block']; execution=r['execution'][0]
    require(block['hash']==execution['hash'] and all(block[k]==v for k,v in execution['header'].items()),'wrong executed header')
    require(len(block['transactions'])==3 and len(before['transactions'])==len(before['receipts'])==3,'invalid input became Ethereum transaction')
    for index,(tx,receipt) in enumerate(zip(before['transactions'],before['receipts'])):
        require(tx['hash']==receipt['transactionHash']==block['transactions'][index],'transaction identity')
        require(tx['blockHash']==receipt['blockHash']==block['hash'],'transaction block')
        require(tx['transactionIndex']==receipt['transactionIndex']==hex(index),'dense transaction index')
        require(int(receipt['gasUsed'],16)==[21000,21000,25300][index],'receipt gas')
    require(rolled['block']['hash']==block['parentHash'] and rolled['block']['transactions']==[],'rollback not at previous Ethereum block')
    require(rolled['transactions']==rolled['receipts']==[None,None,None] and rolled['prior_block_lookup'] is None,'orphan reads survived')
    require(after['block']==block and after['transactions']==before['transactions'] and after['receipts']==before['receipts']
            and after['prior_block_lookup']==block,'same mandatory publication not restored')
    return {**result,'same_observer_process':True,'rpc_prefix_sequence':[9,8,9],
            'orphan_transactions_and_receipts_removed':3,'same_execution_restored':True,
            'rollback_unavailable_polls':rolled['unavailable_poll_count']}


if __name__=='__main__':
    path=pathlib.Path(sys.argv[1]); data=path.read_bytes()
    if path.suffix=='.gz':data=gzip.decompress(data)
    print(json.dumps(check_document(json.loads(data)),indent=2))
