#!/usr/bin/env python3
"""Reject false settlement rollback/reapplication claims using actual node evidence."""
import copy
import gzip
import json
import pathlib
import runpy
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
CHECK = runpy.run_path(str(ROOT / 'scripts/check-settlement-reorg.py'))['check_document']
PROOF = ROOT / 'specs/evidence/chain-groth16-proof/proof'


class SettlementReorg(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.evidence = json.loads(gzip.decompress((ROOT / 'specs/evidence/first-settlement/reorg-0.210.0/evidence.json.gz').read_bytes()))

    def test_two_independent_nodes_recover_actual_rollback_and_reapplication(self):
        self.assertEqual(CHECK(self.evidence, PROOF)['orphaned_blocks'], 4)

    def test_false_rollback_and_different_proof_rejected(self):
        for kind in ('rollback', 'peer', 'live-orphan', 'proof', 'funding-rejection'):
            evidence = copy.deepcopy(self.evidence)
            reorg = evidence['results']['reorg']
            if kind == 'rollback':
                reorg['cold_after_rollback']['settled_batches'] = 1
            elif kind == 'peer':
                reorg['peer_cold_after_replacement']['tip']['tx_hash'] = reorg['orphan_hash']
            elif kind == 'live-orphan':
                reorg['orphan_live_after']['status'] = 'live'
            elif kind == 'proof':
                item = next(r for r in evidence['evidence'] if r['label'] == 'settlement-reorg/recovered proof with fresh funding')
                witness = bytearray.fromhex(item['transaction']['witnesses'][0][2:])
                witness[-1] ^= 1
                item['transaction']['witnesses'][0] = '0x' + witness.hex()
            else:
                item = next(r for r in evidence['evidence'] if r['label'] == 'settlement-reorg/orphan transaction old funding')
                item['error'] = 'rpc error: {"code":-1,"message":"TransactionFailedToResolve"}'
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                CHECK(evidence, PROOF)


if __name__ == '__main__':
    unittest.main()
