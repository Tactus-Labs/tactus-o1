#!/usr/bin/env python3
"""Reject forged joins between A3 duties and settlement observer reports."""
import copy
import gzip
import importlib.util
import json
import pathlib
import unittest

spec=importlib.util.spec_from_file_location('checker',pathlib.Path(__file__).with_name('check-obligation-recovery.py'))
c=importlib.util.module_from_spec(spec)
spec.loader.exec_module(c)
SOURCE=pathlib.Path(__file__).resolve().parents[1]/'specs/evidence/obligation-recovery/0.210.0/evidence.json.gz'


class RecoveryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.evidence=json.loads(gzip.decompress(SOURCE.read_bytes()))

    def test_measured_cold_lifecycle(self):
        self.assertEqual(c.check_document(self.evidence)['cold_lifecycle_phases'],3)

    def test_forged_joins(self):
        controls=[
            ('cross-prefix',lambda r:r['settlement'].update(pinned_hash='0x'+'01'*32)),
            ('false-proof',lambda r:r['obligations'][0].update(proof_settled=True)),
            ('missing-duty',lambda r:r['obligations'].pop()),
            ('different-slot',lambda r:r['obligations'][0]['publication'].update(input_slot=99)),
            ('different-admission',lambda r:r['obligations'][0]['admission'].update(index='0xff')),
            ('different-seal',lambda r:r['obligations'][0]['seal'].update(index='0xff')),
            ('different-outcome',lambda r:r['obligations'][0]['outcome'].update(status='Malformed')),
            ('different-boundary',lambda r:r['settlement'].update(settled_batches=9)),
            ('custody-claim',lambda r:r.update(withdrawal_authority=True)),
        ]
        for name,mutate in controls:
            with self.subTest(name=name):
                evidence=copy.deepcopy(self.evidence)
                mutate(evidence['results']['cold_obligations_before_proof'])
                with self.assertRaises(ValueError):c.check_document(evidence)


if __name__=='__main__':unittest.main()
