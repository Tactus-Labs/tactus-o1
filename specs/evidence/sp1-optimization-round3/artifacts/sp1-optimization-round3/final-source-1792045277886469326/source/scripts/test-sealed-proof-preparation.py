#!/usr/bin/env python3
"""A pending actual A3 run must never qualify as real proof settlement."""
import copy
import gzip
import importlib.util
import json
import pathlib
import unittest

spec=importlib.util.spec_from_file_location('checker',pathlib.Path(__file__).with_name('check-sealed-proof.py'))
c=importlib.util.module_from_spec(spec)
spec.loader.exec_module(c)
ROOT=pathlib.Path(__file__).resolve().parents[1]


class PreparationGuards(unittest.TestCase):
    def test_actual_pending_evidence_is_not_a_settlement(self):
        evidence=json.loads(gzip.decompress((ROOT/'specs/evidence/obligation-recovery/0.210.0/evidence.json.gz').read_bytes()))
        proof=ROOT/'specs/evidence/chain-groth16-proof/proof'
        reorg_spec=importlib.util.spec_from_file_location('reorg',pathlib.Path(__file__).with_name('check-sealed-proof-reorg.py'))
        reorg=importlib.util.module_from_spec(reorg_spec);reorg_spec.loader.exec_module(reorg)
        with self.assertRaisesRegex(ValueError,'A3 proof reorg did not complete'):
            reorg.check_document(evidence,proof)
        with self.assertRaisesRegex(ValueError,'real A3 settlement did not complete'):
            c.check_document(evidence,proof)
        falsified=copy.deepcopy(evidence)
        falsified['results'].update(suite='sealed-settlement-proof-v1',settled=True)
        for row in falsified['results']['obligations']:row['proof_settled']=True
        with self.assertRaisesRegex(ValueError,'expected 18 commits and eight rejections'):
            c.check_document(falsified,proof)


if __name__=='__main__':unittest.main()
