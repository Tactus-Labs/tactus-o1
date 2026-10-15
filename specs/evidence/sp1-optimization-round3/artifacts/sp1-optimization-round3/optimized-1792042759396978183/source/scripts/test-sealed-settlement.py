#!/usr/bin/env python3
"""Corrupt retained A3 proof-input evidence at independent trust boundaries."""
import copy
import gzip
import importlib.util
import json
import pathlib
import unittest

spec = importlib.util.spec_from_file_location('checker', pathlib.Path(__file__).with_name('check-sealed-settlement.py'))
c = importlib.util.module_from_spec(spec)
spec.loader.exec_module(c)
SOURCE = pathlib.Path(__file__).resolve().parents[1] / 'specs/evidence/sealed-settlement-input/0.210.0/evidence.json.gz'


class EvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.evidence = json.loads(gzip.decompress(SOURCE.read_bytes()))

    def test_real_evidence(self):
        self.assertEqual(c.check_document(self.evidence)['admissions'], 4)

    def test_forged_claims(self):
        def alter_snapshot(e):
            view=e['results']['cold_gate']['network']['snapshot']
            view['data']=view['data'][:-2]+('ff' if view['data'][-2:]!='ff' else '00')
        def reorder_batch(e):
            x=e['results']['proving_input']['batches']
            x[0],x[-1]=x[-1],x[0]
        def fake_rejection(e):
            x=next(x for x in e['evidence'] if x['result']=='rejected')
            x['error']='rpc error: '+json.dumps({'code':-32602,'message':'invalid parameters'})
        controls=[
            ('publication-as-settlement',lambda e:e['results']['cold_before_proof'].update(settled_batches=9)),
            ('forged-fulfillment',lambda e:e['results']['obligations'][0].update(proof_settled=True)),
            ('omitted-invalid-slot',lambda e:e['results']['obligations'].pop(2)),
            ('lane-identity',lambda e:e['results']['obligations'][0].update(lane=1)),
            ('snapshot',alter_snapshot),('batch-order',reorder_batch),('wrong-rejection',fake_rejection),
            ('wrong-tip',lambda e:e['results']['proving_input']['settlement_tip'].update(index='0x0')),
            ('production',lambda e:e['results'].update(production_ready=True)),
        ]
        for name,mutation in controls:
            with self.subTest(name=name):
                evidence=copy.deepcopy(self.evidence)
                mutation(evidence)
                with self.assertRaises(ValueError):
                    c.check_document(evidence)


if __name__=='__main__':
    unittest.main()
