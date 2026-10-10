#!/usr/bin/env python3
"""Reject fabricated native settlement bootstrap and proof input evidence."""
import importlib.util
import pathlib
import unittest
spec=importlib.util.spec_from_file_location('audit',pathlib.Path(__file__).with_name('check-native-settlement.py'))
audit=importlib.util.module_from_spec(spec);spec.loader.exec_module(audit)
ROOT=pathlib.Path(__file__).resolve().parent.parent/'specs/evidence/native-settlement/0.210.0'
class NativeSettlement(unittest.TestCase):
    def test_actual_joint_deployment(self):
        args=audit.read_run(ROOT);report=audit.check(*args)
        self.assertEqual((report['commits'],report['script_rejections']),(13,68))
        self.assertTrue(report['settlement']['guest_execution_checked'])
        args=list(args);args[-1]=None
        with self.assertRaises(ValueError):audit.check(*args)
        self.assertFalse(audit.check(*args,require_guest=False)['settlement']['guest_execution_checked'])
    def test_forged_reports(self):
        for mode in ['config','tip-output','tip-live','tip-initialized','guest-key','guest-root','proof-claimed','wrong-prefix','missing-prefix','wrong-input-domain','candidate-root','rejection-source','rejection-program','missing-negative','fake-v1-proof','wrong-proof-endpoint']:
            with self.subTest(mode=mode):
                e,x,g,inp,guests=audit.read_run(ROOT);r=e['results'];s=r['settlement'];events={v['label']:v for v in e['evidence']}
                tx=events['native/joint genesis']['transaction']
                if mode=='config':s['config']='0x'+'00'*136
                elif mode=='tip-output':tx['outputs'][3]['type']['args']='0x'
                elif mode=='tip-live':s['final_live']['status']='dead'
                elif mode=='tip-initialized':s['initial_tip']='0x'+'00'*280
                elif mode=='guest-key':guests[0]['guest_verifying_key']='0x'+'00'*32
                elif mode=='guest-root':guests[0]['public_values_hex']='00'*940
                elif mode=='proof-claimed':guests[0]['proof_generated']=True
                elif mode=='wrong-prefix':inp[1]['prefix_batches']=0
                elif mode=='missing-prefix':inp.pop();guests.pop()
                elif mode=='wrong-input-domain':inp[0]['domain_hex']='0x'+'00'*196
                elif mode=='candidate-root':s['candidate_tip']='0x'+'00'*280
                elif mode=='rejection-source':
                    v=events['settlement/v1 proof cannot settle native'];v['error']=v['error'].replace('Inputs[0].Type','Inputs[0].Lock')
                elif mode=='rejection-program':
                    v=events['settlement/v1 proof cannot settle native'];code=audit.digest(b'',audit.raw(events['settlement/deploy program']['transaction']['outputs_data'][0])).hex();v['error']=v['error'].replace(code,'00'*32)
                elif mode=='missing-negative':e['evidence'].remove(events['settlement/missing checkpoint'])
                elif mode=='fake-v1-proof':
                    t=events['settlement/v1 proof cannot settle native']['transaction'];b=bytearray(audit.raw(t['witnesses'][0]));b[-1]^=1;t['witnesses'][0]=audit.hx(b)
                else:events['settlement/v1 proof cannot settle native']['transaction']['cell_deps']=[]
                with self.assertRaises((AssertionError,ValueError,KeyError)):audit.check(e,x,g,inp,guests)
if __name__=='__main__':unittest.main()
