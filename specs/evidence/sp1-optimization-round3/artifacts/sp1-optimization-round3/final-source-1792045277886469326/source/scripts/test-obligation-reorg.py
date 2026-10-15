#!/usr/bin/env python3
"""Reject corrupted actual A3 rollback and republication evidence."""
import copy
import gzip
import importlib.util
import json
import pathlib
import unittest
spec=importlib.util.spec_from_file_location('checker',pathlib.Path(__file__).with_name('check-obligation-reorg.py'))
c=importlib.util.module_from_spec(spec);spec.loader.exec_module(c)
SOURCE=pathlib.Path(__file__).resolve().parents[1]/'specs/evidence/obligation-reorg/0.210.0/evidence.json.gz'


class ReorgTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.evidence=json.loads(gzip.decompress(SOURCE.read_bytes()))

    def test_actual_p2p_recovery(self):
        self.assertEqual(c.check_document(self.evidence)['orphaned_blocks'],8)

    def test_forged_recovery(self):
        controls=[
            ('retained-orphan',lambda r:r['orphan_publication_status']['tx_status'].update(status='committed')),
            ('live-checkpoint',lambda r:r['orphan_checkpoint_status'].update(status='live')),
            ('wrong-peer-prefix',lambda r:r['peer_cold_after_rollback'].update(pinned_hash='0x'+'01'*32)),
            ('retained-publication',lambda r:r['cold_after_rollback']['obligations'][0].update(status='published')),
            ('lost-duty',lambda r:r['cold_after_republication']['obligations'].pop()),
            ('fake-replacement',lambda r:r.update(replacement_publication='0x'+'02'*32)),
            ('local-truncation',lambda r:r.update(truncate_used=True)),
            ('false-settlement',lambda r:r.update(settled=True)),
        ]
        for name,mutate in controls:
            with self.subTest(name=name):
                evidence=copy.deepcopy(self.evidence);mutate(evidence['results']['reorg'])
                with self.assertRaises(ValueError):c.check_document(evidence)


if __name__=='__main__':unittest.main()
