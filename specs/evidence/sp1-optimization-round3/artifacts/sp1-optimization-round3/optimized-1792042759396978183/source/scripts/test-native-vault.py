#!/usr/bin/env python3
import copy,gzip,importlib.util,json,pathlib,unittest
spec=importlib.util.spec_from_file_location('vault',pathlib.Path(__file__).with_name('check-native-vault.py'))
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class EvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.e=json.loads(gzip.decompress((m.ROOT/'specs/evidence/native-vault/0.210.0/evidence.json.gz').read_bytes()))
    def test_actual_deposits(self):
        self.assertEqual(m.check(self.e)['deposited_shannons'],25000000000)
    def test_forged_evidence(self):
        for mode in range(10):
            with self.subTest(mode=mode):
                e=copy.deepcopy(self.e);r=e['results'];labels={v['label']:v for v in e['evidence']}
                if mode==0:r['authenticated_l2_credit']=True
                elif mode==1:r['withdrawal_executed']=True
                elif mode==2:r['deposits'][0]['deposit_id']='0x'+'00'*32
                elif mode==3:r['deposits'][0]['receipt_live']['status']='dead'
                elif mode==4:r['final_live']['cell']['output']['capacity']='0x0'
                elif mode==5:labels['vault/deposit actor 1']['transaction']['inputs'][0]['previous_output']['index']='0x1'
                elif mode==6:labels['vault/wrong recipient']['transaction']['outputs_data'][1]=r['deposits'][0]['record']
                elif mode==7:labels['vault/underfunded deposit']['error']=labels['vault/underfunded deposit']['error'].replace('.Type','.Lock')
                elif mode==8:labels['vault/only one typed input per transition']['transaction']['inputs'][1]['previous_output']['index']='0x1'
                else:labels['vault/deposit actor 0']['transaction']['outputs'][2]['capacity']='0x1'
                with self.assertRaises(ValueError):m.check(e)
if __name__=='__main__':unittest.main()
