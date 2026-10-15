#!/usr/bin/env python3
"""Observe a launcher-owned CKB SIGKILL/restart experiment; never controls PIDs."""
import json
import os
import pathlib
import subprocess
import sys
import time
import urllib.request


def rpc(address,method,params):
    request=urllib.request.Request('http://'+address,json.dumps({'jsonrpc':'2.0','id':1,'method':method,'params':params}).encode(),{'Content-Type':'application/json'})
    with urllib.request.urlopen(request,timeout=2) as response:reply=json.load(response)
    if 'error' in reply:raise ValueError(reply['error'])
    return reply['result']


def main():
    phase,root,old_pid,new_pid,exit_status=sys.argv[1:]
    root=pathlib.Path(root)
    evidence=json.loads((root/'evidence.json').read_bytes())
    result=evidence['results']
    assert result['suite']=='sealed-obligation-reorg-v1' and result['complete'] and result['error'] is None
    expected=result['reorg']['cold_after_republication']
    export=result['proving_input']
    command=['target/debug/recover-obligations',expected['ckb_genesis'],export['gate_type_script'],export['anchor_type_script'],export['settlement_type_script']]
    assert int(exit_status)==137 and int(old_pid)>0
    def recover(address):
        return json.loads(subprocess.check_output(command,env={**os.environ,'TACTUS_CKB_RPC_ADDR':address},timeout=120))
    peer=os.environ['TACTUS_PEER_RPC_ADDR']
    if phase=='peer-after-crash':
        report=recover(peer)
        assert report==expected
        (root/'peer-during-crash.json').write_text(json.dumps(report,indent=2)+'\n')
        return
    assert phase=='after-restart' and int(new_pid)>0 and new_pid!=old_pid
    address=os.environ['TACTUS_CKB_RPC_ADDR']
    deadline=time.monotonic()+45
    while True:
        try:
            tip=rpc(address,'get_tip_header',[])
            if tip['hash']==expected['pinned_hash']:break
        except (OSError,ValueError,KeyError):pass
        if time.monotonic()>deadline:raise TimeoutError('restarted node did not recover the expected prefix')
        time.sleep(.1)
    main_report=recover(address)
    peer_report=recover(peer)
    during=json.loads((root/'peer-during-crash.json').read_bytes())
    assert main_report==peer_report==during==expected
    report={'schema':1,'fault':'SIGKILL of the launcher-owned primary node after completed A3 republication','old_pid':int(old_pid),'new_pid':int(new_pid),'wait_exit_status':int(exit_status),'same_database':True,'peer_while_primary_down':during,'main_after_restart':main_report,'peer_after_restart':peer_report,'settled_duties':0,'mid_transaction_fault':False,'power_loss_simulated':False,'production_ready':False}
    (root/'crash-recovery.json').write_text(json.dumps(report,indent=2)+'\n')
    print('Abrupt primary-node restart recovered the same canonical duties as the uninterrupted peer.')


if __name__=='__main__':main()
