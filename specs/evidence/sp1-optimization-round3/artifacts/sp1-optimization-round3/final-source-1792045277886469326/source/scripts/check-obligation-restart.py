#!/usr/bin/env python3
"""Reconcile an actual launcher-owned SIGKILL with the retained observer reports."""
import gzip
import importlib.util
import json
import pathlib
import re
import sys
spec=importlib.util.spec_from_file_location('reorg',pathlib.Path(__file__).with_name('check-obligation-reorg.py'))
c=importlib.util.module_from_spec(spec);spec.loader.exec_module(c)
require=c.require


def check_document(evidence,crash,launch,restarted):
    result=c.check_document(evidence)
    expected=evidence['results']['reorg']['cold_after_republication']
    require(crash['schema']==1 and crash['old_pid']>0 and crash['new_pid']>0
            and crash['old_pid']!=crash['new_pid'] and crash['wait_exit_status']==137, 'not a distinct SIGKILL restart')
    require(crash['same_database'] is True and crash['mid_transaction_fault'] is False
            and crash['power_loss_simulated'] is False and crash['production_ready'] is False, 'fault scope differs')
    require(re.search(r'\b'+str(crash['old_pid'])+r'\s+Killed\b',launch) is not None, 'launcher lacks actual killed-child observation')
    require('ckb version: 0.210.0 ' in restarted
            and f"current tip: {expected['pinned_height']}-Byte32({expected['pinned_hash']})" in restarted, 'restarted database loaded a different prefix')
    require(crash['peer_while_primary_down']==crash['main_after_restart']==crash['peer_after_restart']==expected,
            'restart or uninterrupted peer changed canonical duties')
    require(crash['settled_duties']==0 and expected['counts']=={'admitted':0,'sealed':0,'published':4,'settled':0}, 'fault invented proof settlement')
    return {**result,'primary_sigkill_exit_status':137,'same_database_restart':True,'uninterrupted_peer_agrees':True,'recovered_height':expected['pinned_height'],'mid_transaction_fault':False,'power_loss_simulated':False}


def read(path):
    source=path.read_bytes()
    return gzip.decompress(source) if path.suffix=='.gz' else source


if __name__=='__main__':
    if len(sys.argv)!=2:raise SystemExit('usage: check-obligation-restart.py EVIDENCE_DIRECTORY')
    root=pathlib.Path(sys.argv[1])
    print(json.dumps(check_document(json.loads(read(root/'evidence.json.gz')),json.loads(read(root/'crash-recovery.json')),read(root/'launch.txt.gz').decode(),read(root/'restarted-node.log.gz').decode()),indent=2))
