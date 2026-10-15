#!/usr/bin/env python3
"""Corrupt continuity and canonical consumption in two measured settlements."""
import copy
import gzip
import importlib.util
import json
import pathlib
import unittest
spec=importlib.util.spec_from_file_location('checker',pathlib.Path(__file__).with_name('check-two-settlements.py'))
c=importlib.util.module_from_spec(spec);spec.loader.exec_module(c)
ROOT=pathlib.Path(__file__).resolve().parents[1]
FIRST=ROOT/'specs/evidence/chain-groth16-proof/proof'
SECOND=ROOT/'specs/evidence/second-chain-proof/proof'


class ContinuityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.evidence=json.loads(gzip.decompress((ROOT/'specs/evidence/two-settlements/0.210.0/evidence.json.gz').read_bytes()))

    def test_two_actual_settlements(self):
        self.assertEqual(c.check_document(self.evidence,FIRST,SECOND)['settled_batches'],2)

    def test_falsified_continuity(self):
        controls=[
            ('wrong-boundary',lambda r:r['cold_second_settlement_recovery'].update(settled_batches=1)),
            ('live-predecessor',lambda r:r['second_transition'].update(predecessor_status='live')),
            ('wrong-consumer',lambda r:r['second_transition']['predecessor_consumption']['consumer']['transaction']['inputs'][0]['previous_output'].update(index='0xff')),
            ('noncanonical-consumer',lambda r:r['second_transition']['predecessor_consumption']['consumer']['tx_status'].update(status='pending')),
            ('wrong-proof-source',lambda r:r['second_source_proof'].update(guest_verifying_key='0x'+'01'*32)),
            ('wrong-fee',lambda r:r['second_transition'].update(fee_shannons=0)),
        ]
        for name,mutate in controls:
            with self.subTest(name=name):
                evidence=copy.deepcopy(self.evidence);mutate(evidence['results'])
                with self.assertRaises(ValueError):c.check_document(evidence,FIRST,SECOND)


if __name__=='__main__':unittest.main()
