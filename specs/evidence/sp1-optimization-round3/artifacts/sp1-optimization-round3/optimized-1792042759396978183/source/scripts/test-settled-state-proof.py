#!/usr/bin/env python3
"""Reject inconsistent retained state-read evidence; not a crypto verifier."""
import copy
import gzip
import importlib.util
import json
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location('state_proof', pathlib.Path(__file__).with_name('check-settled-state-proof.py'))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class EvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.evidence = json.loads(gzip.decompress((ROOT/'specs/evidence/settled-state-proof/0.210.0/evidence.json.gz').read_bytes()))
        cls.source = json.loads((ROOT/'specs/evidence/observer-state-proofs/state-proofs.json').read_bytes())

    def test_actual_receipts(self):
        result = module.check(self.evidence, self.source)
        self.assertEqual(result['commits'], 23)
        self.assertEqual(result['state_read_negative_controls'], 17)

    def test_forged_evidence(self):
        for scenario in range(14):
            with self.subTest(scenario=scenario):
                e = copy.deepcopy(self.evidence); r = e['results']['state_proof']
                labels = {x['label']:x for x in e['evidence']}
                if scenario == 0: r['withdrawal_authority'] = True
                elif scenario == 1: r['tip_data'] = '0x' + '00'*280
                elif scenario == 2: r['tip_live_after']['status'] = 'dead'
                elif scenario == 3: r['accepted'][0]['proof'] += '00'
                elif scenario == 4: r['accepted'][0]['query']['result']['balance'] = '0x1'
                elif scenario == 5: r['accepted'][0]['live_cell']['status'] = 'unknown'
                elif scenario == 6: labels['state-proof/authenticated read 0']['transaction']['cell_deps'].pop()
                elif scenario == 7: labels['state-proof/authenticated read 0']['cycles']['cycles'] = '0x0'
                elif scenario == 8: labels['state-proof/wrong nonce']['error'] = labels['state-proof/wrong nonce']['error'].replace('Outputs[0].Type', 'Outputs[0].Lock')
                elif scenario == 9: labels['state-proof/immutable claim cannot mutate']['error'] = labels['state-proof/immutable claim cannot mutate']['error'].replace('Inputs[1].Type', 'Inputs[0].Type')
                elif scenario == 10: r['consumption']['consumer']['tx_status']['status'] = 'pending'
                elif scenario == 11: labels['state-proof/owner recovers certificate capacity']['transaction']['outputs'][0]['capacity'] = '0x1'
                elif scenario == 12: r['negative_controls'].pop()
                else: labels['state-proof/wrong balance']['transaction']['outputs_data'][0] = r['accepted'][0]['data']
                with self.assertRaises((ValueError, KeyError, IndexError)):
                    module.check(e, self.source)


if __name__ == '__main__':
    unittest.main()
