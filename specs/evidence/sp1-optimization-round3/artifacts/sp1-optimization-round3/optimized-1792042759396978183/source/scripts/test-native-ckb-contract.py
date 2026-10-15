#!/usr/bin/env python3
import copy
import importlib.util
import pathlib
import unittest

spec = importlib.util.spec_from_file_location('bridge',pathlib.Path(__file__).with_name('check-native-ckb-contract.py'))
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)

class EvidenceTests(unittest.TestCase):
    def setUp(self):
        folder = m.ROOT/'specs/evidence/native-ckb-contract'
        self.c = m.load(folder/'candidates.json.gz'); self.g = m.load(folder/'verified.json.gz')
        self.s = m.load(folder/'system-calls-geth.json')
    def test_real_evidence(self):
        self.assertEqual(m.check(self.c,self.g,self.s)['signed_blocks'],27)
    def test_corruptions(self):
        for case in range(7):
            with self.subTest(case=case):
                c,g,s = copy.deepcopy((self.c,self.g,self.s))
                if case == 0: c['authenticated_l1_deposits'] = True
                elif case == 1: g['cases'][0]['geth'][0]['stateRoot'] = '0x'+'00'*32
                elif case == 2: g['cases'][0]['geth'][0]['receipts'][0]['status'] = '0x1'
                elif case == 3: c['cases'][0]['final_bridge_account']['storage']['0x2'] = '0x0'
                elif case == 4: s['evm_fork'] = 'Cancun'
                elif case == 5: s['supply'] = 1000
                else:
                    next(x for x in s['calls'] if x['signature'].startswith('creditDeposit') and x['success'])['caller'] = s['contract']
                with self.assertRaises(ValueError): m.check(c,g,s)
if __name__ == '__main__': unittest.main()
