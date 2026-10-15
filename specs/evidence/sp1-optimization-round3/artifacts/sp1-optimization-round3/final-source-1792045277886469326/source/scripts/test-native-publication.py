#!/usr/bin/env python3
import copy,gzip,importlib.util,json,pathlib,unittest
spec=importlib.util.spec_from_file_location('publication',pathlib.Path(__file__).with_name('check-native-publication.py'))
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class EvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        p=m.v.ROOT/'specs/evidence/native-publication/0.210.0'
        cls.e=json.loads(gzip.decompress((p/'evidence.json.gz').read_bytes()))
        cls.x=json.loads((p/'execution.json').read_text());cls.g=json.loads((p/'geth.json').read_text())
    def test_actual_publication_and_independent_replay(self):
        self.assertEqual(m.check(self.e,self.x,self.g)['script_rejections'],27)
    def test_forged_evidence(self):
        for mode in range(12):
            with self.subTest(mode=mode):
                e,x,g=copy.deepcopy((self.e,self.x,self.g));r=e['results'];labels={v['label']:v for v in e['evidence']}
                if mode==0:r['proof_settled']=True
                elif mode==1:r['publications'][0]['receipt']['index']='0x0'
                elif mode==2:labels['native/publish authenticated batch 0']['transaction']['cell_deps'].pop()
                elif mode==3:labels['native/joint genesis']['transaction']['header_deps']=[]
                elif mode==4:r['cold_vault_recovery']['canonical_pin_rechecked']=False
                elif mode==5:r['final_bridge_account']['storage']['0x2']='0x0'
                elif mode==6:g['blocks'][0]['state_root']='0x'+'00'*32
                elif mode==7:x['cases'][0]['steps'][0]['wrapper']='0x00'
                elif mode==8:labels['native/deposit actor 0']['transaction']['outputs'][2]['capacity']='0x1'
                elif mode==9:labels['native/missing authenticated receipt']['error']=labels['native/missing authenticated receipt']['error'].replace('Inputs[0].Type','Inputs[0].Lock')
                elif mode==10:
                    positive=labels['native/publish authenticated batch 0']['transaction'];labels['native/forged amount with valid transcript']['transaction']=copy.deepcopy(positive)
                else:e['metadata']['ordering_code_hash']='0x'+'00'*32
                with self.assertRaises(ValueError):m.check(e,x,g)
if __name__=='__main__':unittest.main()
