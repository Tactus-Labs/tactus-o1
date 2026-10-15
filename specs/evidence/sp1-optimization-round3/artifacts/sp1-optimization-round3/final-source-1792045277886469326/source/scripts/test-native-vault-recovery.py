#!/usr/bin/env python3
import copy
import gzip
import importlib.util
import json
import pathlib
import unittest

spec = importlib.util.spec_from_file_location('recovery', pathlib.Path(__file__).with_name('check-native-vault-recovery.py'))
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class RecoveryEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        p = m.v.ROOT / 'specs/evidence/native-vault-recovery/0.210.0'
        cls.e = json.loads(gzip.decompress((p / 'evidence.json.gz').read_bytes()))
        cls.blocks = json.loads((p / 'canonical-blocks.json').read_text())
        cls.reports = json.loads((p / 'recovery.json').read_text())

    def test_actual_cold_processes(self):
        self.assertEqual(m.check(self.e, self.blocks, self.reports)['recovered_counts'], [0, 1, 2, 2])

    def test_forged_reports_and_blocks(self):
        for mode in range(12):
            with self.subTest(mode=mode):
                e, blocks, reports = copy.deepcopy((self.e, self.blocks, self.reports))
                r = reports['cold_final']
                if mode == 0: blocks[12]['header']['parent_hash'] = '0x00'
                elif mode == 1: blocks[12]['transactions'][1]['outputs_data'][1] = '0x00'
                elif mode == 2: r['pinned_hash'] = '0x00'
                elif mode == 3: r['point']['index'] = '0x1'
                elif mode == 4: r['deposits'][0]['deposit_id'] = '0x00'
                elif mode == 5: r['deposits'][0]['recipient'] = '0x00'
                elif mode == 6: r['deposits'][0]['amount_shannons'] = '1'
                elif mode == 7: r['canonical_pin_rechecked'] = False
                elif mode == 8: r['current_live_rechecked'] = False
                elif mode == 9: r['authenticated_l2_credit'] = True
                elif mode == 10: r['deposits'].pop()
                else: r['capacity_shannons'] = 64000000000
                # Mutate both reports so equality alone cannot catch forged claims.
                e['results']['cold_final'] = copy.deepcopy(r)
                with self.assertRaises(ValueError):
                    m.check(e, blocks, reports)


if __name__ == '__main__':
    unittest.main()
