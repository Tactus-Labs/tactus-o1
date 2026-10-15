#!/usr/bin/env python3
"""Audit actual first settlement and reject unsupported consumption assertions."""
import copy
import gzip
import json
import pathlib
import runpy
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
CHECK = runpy.run_path(str(ROOT / 'scripts/check-first-settlement.py'))['check_document']
PROOF = ROOT / 'specs/evidence/chain-groth16-proof/proof'


class FirstSettlement(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.evidence = json.loads(gzip.decompress((ROOT / 'specs/evidence/first-settlement/0.210.0/evidence.json.gz').read_bytes()))

    def test_real_node_proof_transition_and_all_rejections(self):
        CHECK(self.evidence, PROOF)
        self.assertEqual(self.evidence['results']['first_transition']['predecessor_status'], 'unknown')

    def test_unknown_is_not_accepted_without_canonical_consumption(self):
        for kind in ('creation', 'consumer', 'input', 'live', 'hash'):
            evidence = copy.deepcopy(self.evidence)
            measured = evidence['results']['first_transition']
            observation = measured['predecessor_consumption']
            if kind in ('creation', 'consumer'):
                observation[kind]['tx_status']['status'] = 'unknown'
            elif kind == 'input':
                observation['consumer']['transaction']['inputs'][0]['previous_output']['index'] = '0x1'
            elif kind == 'live':
                observation['live_cell']['status'] = measured['predecessor_status'] = 'live'
            else:
                observation['consumer']['transaction']['hash'] = '0x' + '00' * 32
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                CHECK(evidence, PROOF)


if __name__ == '__main__':
    unittest.main()
