#!/usr/bin/env python3
"""Reject falsified seal-contention claims using retained actual transaction bytes."""
import copy
import gzip
import json
import pathlib
import runpy
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
ANALYZER = runpy.run_path(str(ROOT / 'scripts/analyze-seal-contention.py'))


class SealEvidence(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.evidence = {}
        for version in ['0.210.0']:
            path = ROOT / f'specs/evidence/seal-contention/ckb-{version}-evidence.json.gz'
            cls.evidence[version] = json.loads(gzip.decompress(path.read_bytes()))

    def test_current_version_reconciles_every_epoch(self):
        for version, evidence in self.evidence.items():
            with self.subTest(version=version):
                self.assertEqual(len(ANALYZER['audit'](evidence)), 12)

    def test_missing_epoch_and_fabricated_progress_are_rejected(self):
        for kind in ['epoch', 'count', 'targets', 'latency', 'duplicate']:
            evidence = copy.deepcopy(self.evidence['0.210.0'])
            case = evidence['results']['cases'][0]
            if kind == 'epoch':
                case['epochs'].pop()
            elif kind == 'count':
                case['epochs'][0]['invalidated_seals'] = 0
            elif kind == 'targets':
                case['epochs'][0]['attempts'][0]['target_lanes'] = []
            elif kind == 'latency':
                case['epochs'][0]['final_seal_commit_delay_blocks'] = 0
            else:
                evidence['results']['cases'][-1] = copy.deepcopy(case)
            with self.subTest(kind=kind), self.assertRaises(AssertionError):
                ANALYZER['audit'](evidence)

    def test_snapshot_omission_and_false_input_overlap_are_rejected(self):
        for kind in ['snapshot', 'input']:
            evidence = copy.deepcopy(self.evidence['0.210.0'])
            for event in evidence['evidence']:
                if kind == 'snapshot' and event['label'].endswith('/rebuilt seal after exhausted churn'):
                    transaction = event['transaction']
                    index = len(transaction['outputs_data']) - 2
                    value = transaction['outputs_data'][index]
                    transaction['outputs_data'][index] = value[:-2] + '01'
                    break
                if kind == 'input' and event['label'].endswith('/stale signed seal'):
                    event['transaction']['inputs'].pop(1)
                    break
            else:
                self.fail('missing retained attack fixture')
            with self.subTest(kind=kind), self.assertRaises(AssertionError):
                ANALYZER['audit'](evidence)

    def test_wrong_actual_processing_order_is_rejected(self):
        evidence = copy.deepcopy(self.evidence['0.210.0'])
        for event in evidence['evidence']:
            if event['label'].endswith('/process-0'):
                encoded = bytearray.fromhex(event['transaction']['outputs_data'][1][2:])
                # One block has a 194-byte header and 30-byte block prefix;
                # the first two 64-byte payloads each have a four-byte length.
                first = bytes(encoded[228:292])
                second = bytes(encoded[296:360])
                encoded[228:292] = second
                encoded[296:360] = first
                event['transaction']['outputs_data'][1] = '0x' + encoded.hex()
                break
        else:
            self.fail('missing retained processing fixture')
        with self.assertRaises(AssertionError):
            ANALYZER['audit'](evidence)


if __name__ == '__main__':
    unittest.main()
