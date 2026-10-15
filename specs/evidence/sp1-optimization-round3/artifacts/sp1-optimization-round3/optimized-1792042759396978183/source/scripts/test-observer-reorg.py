#!/usr/bin/env python3
"""Regression controls for retained live RPC observations during a CKB P2P reorg."""
import copy
import gzip
import importlib.util
import json
import pathlib
import unittest
spec=importlib.util.spec_from_file_location('checker',pathlib.Path(__file__).with_name('check-observer-reorg.py'))
c=importlib.util.module_from_spec(spec);spec.loader.exec_module(c)
SOURCE=pathlib.Path(__file__).resolve().parents[1]/'specs/evidence/observer-reorg/evidence.json.gz'


class ObserverReorgTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.evidence=json.loads(gzip.decompress(SOURCE.read_bytes()))

    def test_actual_http_and_p2p(self):
        self.assertEqual(c.check_document(self.evidence)['rpc_prefix_sequence'],[9,8,9])

    def test_forged_observations(self):
        mutations=[
            lambda p:p['after_rollback']['transactions'].__setitem__(0,p['before']['transactions'][0]),
            lambda p:p['after_rollback']['receipts'].__setitem__(0,p['before']['receipts'][0]),
            lambda p:p['after_rollback'].__setitem__('prior_block_lookup',p['before']['block']),
            lambda p:p['after_republication'].__setitem__('process_id',0),
            lambda p:p['after_rollback']['status'].__setitem__('provedBatches','0x8'),
            lambda p:p['after_rollback']['status'].__setitem__('ckbHash',p['before']['status']['ckbHash']),
            lambda p:p['after_republication']['receipts'][0].__setitem__('gasUsed','0x0'),
        ]
        for mutate in mutations:
            bad=copy.deepcopy(self.evidence);mutate(bad['results']['reorg']['rpc_observer'])
            with self.assertRaises(ValueError):c.check_document(bad)


if __name__=='__main__':unittest.main()
