#!/usr/bin/env python3
"""Reject falsified fee-density or admission claims against retained node evidence."""
import copy
import gzip
import json
import pathlib
import runpy
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
CHECK = runpy.run_path(str(ROOT / 'scripts/check-admission-fees.py'))['check_document']


class AdmissionEvidence(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.evidence = {policy: json.loads(gzip.decompress(
            (ROOT / f'specs/evidence/admission-fees/{policy}/evidence.json.gz').read_bytes()))
            for policy in ('absolute', 'wire-density')}

    def test_both_policies_reconcile(self):
        for policy, evidence in self.evidence.items():
            with self.subTest(policy=policy):
                self.assertEqual(CHECK(evidence)['races'], 120)

    def test_false_fee_and_canonical_claims_rejected(self):
        for kind in ('capacity', 'size', 'fee', 'policy', 'canonical', 'classification', 'missing', 'duplicate'):
            evidence = copy.deepcopy(self.evidence['wire-density'])
            row = evidence['results']['rows'][0]
            candidate = row['candidates'][0]
            if kind == 'capacity':
                candidate['resolved_inputs'][0]['cell']['cell']['output']['capacity'] = '0x0'
            elif kind == 'size':
                candidate['wire_bytes'] += 1
            elif kind == 'fee':
                candidate['fee_shannons'] += 1
            elif kind == 'policy':
                evidence['results']['fee_policy'] = 'absolute'
            elif kind == 'canonical':
                row['canonical'][0]['view']['tx_status']['status'] = 'pending'
            elif kind == 'classification':
                row['classification'] = 'victim_committed'
            elif kind == 'missing':
                evidence['results']['rows'].pop()
            else:
                evidence['results']['rows'][-1] = copy.deepcopy(row)
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                CHECK(evidence)


if __name__ == '__main__':
    unittest.main()
