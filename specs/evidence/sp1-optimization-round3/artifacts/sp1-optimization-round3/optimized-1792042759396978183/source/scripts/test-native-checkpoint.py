#!/usr/bin/env python3
"""Audit native checkpoints and reject independently corrupted archive copies."""
import gzip
import importlib.util
import json
import pathlib
import unittest
spec=importlib.util.spec_from_file_location('audit',pathlib.Path(__file__).with_name('check-native-publication.py'))
audit=importlib.util.module_from_spec(spec);spec.loader.exec_module(audit)
ROOT=pathlib.Path(__file__).resolve().parent.parent/'specs/evidence/native-checkpoint/0.210.0'
class NativeCheckpoint(unittest.TestCase):
    def fixture(self):
        return (json.loads(gzip.decompress((ROOT/'evidence.json.gz').read_bytes())),json.loads((ROOT/'execution.json').read_text()),json.loads((ROOT/'geth.json').read_text()))
    def test_real_checkpoint_transitions(self):
        e,x,g=self.fixture();r=audit.check(e,x,g)
        self.assertEqual((r['commits'],r['script_rejections']),(11,43))
        self.assertEqual(r['checkpoint']['authenticated_checkpoints'],2)
    def test_forged_evidence(self):
        for mode in ['old-state','cursor','wrong-type','wrong-lock','missing-code','reported-outpoint','dead-checkpoint','data-hash','capacity','historical-unchecked','wrong-rejection-program','wrong-rejection-source','missing-negative','settled']:
            with self.subTest(mode=mode):
                e,x,g=self.fixture();r=e['results'];rows={a['label']:a for a in e['evidence']}
                tx=rows['native/publish authenticated batch 0']['transaction'];cp=r['checkpoints'][0]
                if mode=='old-state':tx['outputs_data'][2]=r['genesis_state']
                elif mode=='cursor':
                    b=bytearray(audit.raw(tx['outputs_data'][2]));b[372]^=1;tx['outputs_data'][2]=audit.hx(b)
                elif mode=='wrong-type':tx['outputs'][2]['type']['args']='0x'+'00'*40
                elif mode=='wrong-lock':tx['outputs'][2]['lock']['args']='0x'+'00'*32
                elif mode=='missing-code':tx['cell_deps']=[]
                elif mode=='reported-outpoint':cp['index']=0
                elif mode=='dead-checkpoint':cp['live']['status']='dead'
                elif mode=='data-hash':cp['live']['cell']['data']['hash']='0x'+'00'*32
                elif mode=='capacity':tx['outputs'][2]['capacity']='0x1'
                elif mode=='historical-unchecked':r['historical_checkpoint_rechecked']=False
                elif mode=='wrong-rejection-program':
                    event=rows['checkpoint/dependency alone'];code=tx['outputs'][2]['type']['code_hash'][2:];event['error']=event['error'].replace(code,'00'*32)
                elif mode=='wrong-rejection-source':
                    event=rows['checkpoint/dependency alone'];event['error']=event['error'].replace('Outputs[0].Type','Inputs[0].Lock')
                elif mode=='missing-negative':e['evidence'].remove(rows['checkpoint/old anchor wire'])
                else:r['proof_settled']=True
                with self.assertRaises((AssertionError,ValueError,KeyError)):
                    audit.check(e,x,g)
if __name__=='__main__':unittest.main()
