#!/usr/bin/env python3
"""Reconcile actual A3 proof fulfillment and reorg; reject forged lifecycle views."""
import copy
import gzip
import importlib.util
import json
import pathlib
import unittest
ROOT=pathlib.Path(__file__).resolve().parents[1]
PROOF=ROOT/'specs/evidence/sealed-chain-proof/proof'

def module(name):
    spec=importlib.util.spec_from_file_location(name,ROOT/'scripts'/f'{name}.py')
    result=importlib.util.module_from_spec(spec);spec.loader.exec_module(result);return result
c=module('check-sealed-proof');r=module('check-sealed-proof-reorg')

class FulfillmentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.first=json.loads(gzip.decompress((ROOT/'specs/evidence/sealed-proof-settlement/0.210.0/evidence.json.gz').read_bytes()))
        cls.reorg=json.loads(gzip.decompress((ROOT/'specs/evidence/sealed-proof-reorg/0.210.0/evidence.json.gz').read_bytes()))

    def test_actual_settlement_and_actual_reorg(self):
        self.assertEqual(c.check_document(self.first,PROOF)['settled_duties'],4)
        self.assertTrue(r.check_document(self.reorg,PROOF)['same_exact_proof'])

    def test_forged_first_fulfillment(self):
        changes=[
            lambda x:x['cold_after_proof'].update(settled_batches=8),
            lambda x:x['cold_after_proof'].update(proved_transitions=2),
            lambda x:x['obligations'][2].update(proof_settled=False),
            lambda x:x['cold_obligations_after_proof']['obligations'][2].update(status='published'),
            lambda x:x['source_proof'].update(interval_batches=8),
            lambda x:x['transition'].update(node_wire_bytes=1),
            lambda x:x['transition']['consumption']['live_cell'].update(status='live'),
        ]
        for change in changes:
            bad=copy.deepcopy(self.first);change(bad['results'])
            with self.assertRaises(ValueError):c.check_document(bad,PROOF)

    def test_forged_rollback_or_reapplication(self):
        changes=[
            lambda x:x.update(orphaned_blocks=0),
            lambda x:x['orphan_live_after'].update(status='live'),
            lambda x:x['restored_initial_tip']['cell']['data'].update(content='0x'),
            lambda x:x['cold_after_rollback']['counts'].update(settled=4),
            lambda x:x['cold_after_replacement']['settlement'].update(proved_transitions=2),
            lambda x:x.update(replacement_hash=x['orphan_hash']),
            lambda x:x.update(replacement_fee_shannons=0),
            lambda x:x['peer_cold_after_replacement'].update(pinned_hash='0x'+'00'*32),
        ]
        for change in changes:
            bad=copy.deepcopy(self.reorg);change(bad['results']['proof_reorg'])
            with self.assertRaises(ValueError):r.check_document(bad,PROOF)

if __name__=='__main__':unittest.main()
