#!/usr/bin/env python3
import copy
import importlib.util
import json
import pathlib
import unittest
spec = importlib.util.spec_from_file_location('bridge', pathlib.Path(__file__).with_name('check-native-bridge-execution.py'))
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
class EvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        p = m.ROOT/'specs/evidence/native-bridge-execution'
        cls.c = json.loads((p/'candidate.json').read_text()); cls.g = json.loads((p/'geth.json').read_text())
    def test_independent_transitions(self):
        self.assertEqual(m.check(self.c, self.g)['system_credits'], 5)
    def test_forged_evidence(self):
        for mode in range(9):
            with self.subTest(mode=mode):
                c, g = copy.deepcopy((self.c, self.g)); s = c['cases'][0]['steps'][0]
                if mode == 0: c['proof_settled'] = True
                elif mode == 1: c['rules_hash'] = '00'*32
                elif mode == 2: s['deposits'][0]['deposit_id'] = '00'*32
                elif mode == 3: s['deposits'][0]['record'] = '00'*124
                elif mode == 4: s['after'] = s['before']
                elif mode == 5: s['wrapper'] += '00'
                elif mode == 6: g['blocks'][0]['state_root'] = '0x'+'00'*32
                elif mode == 7: c['cases'][1]['final_bridge']['storage']['0x2'] = '0x0'
                else: s['deposits'][0]['gas_used'] = 200001
                with self.assertRaises(ValueError): m.check(c, g)
if __name__ == '__main__': unittest.main()
