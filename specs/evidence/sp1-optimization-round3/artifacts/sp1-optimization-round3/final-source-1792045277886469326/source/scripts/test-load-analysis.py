#!/usr/bin/env python3
"""Check the independent load auditor against retained real-node evidence and corruptions."""
import copy
import gzip
import json
import pathlib
import runpy
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
ANALYZER = runpy.run_path(str(ROOT / 'scripts/analyze-load.py'))


class RetainedLoadEvidence(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.evidence = {}
        for version in ['0.210.0']:
            path = ROOT / f'specs/evidence/sustained-load/ckb-{version}-evidence.json.gz'
            cls.evidence[version] = json.loads(gzip.decompress(path.read_bytes()))
        cls.reference = cls.evidence['0.210.0']
        cls.fees = ANALYZER['fees_by_event'](cls.reference['evidence'])

    def test_current_matrix_reconciles(self):
        for version, evidence in self.evidence.items():
            with self.subTest(version=version):
                self.assertEqual(len(ANALYZER['audit'](evidence)), 36)

    def test_corrupted_summaries_fail_against_signed_bytes(self):
        corruptions = [
            ('fake throughput', lambda c: c.update(canonical_batches=32)),
            ('missing message', lambda c: c['messages'].pop()),
            ('wrong admission', lambda c: c['messages'][0].update(admitted_height=0)),
            ('wrong processing', lambda c: c['messages'][0].update(processed_batch=0)),
            ('false fee total', lambda c: c['economics'].update(fees_shannons=0)),
            ('hidden churn', lambda c: c['timeline'][0]['ticks'][0].update(admissions_per_lane=[0])),
            ('false retained capacity', lambda c: c.update(retained_da_and_snapshot_capacity_shannons=0)),
        ]
        for label, corrupt in corruptions:
            with self.subTest(corruption=label):
                case = copy.deepcopy(self.reference['results']['cases'][0])
                corrupt(case)
                with self.assertRaises((AssertionError, KeyError)):
                    ANALYZER['audit_case'](case, self.reference['evidence'], self.fees)

    def test_omitted_or_duplicated_scenario_cannot_pass_matrix(self):
        for duplicate in [False, True]:
            evidence = copy.copy(self.reference)
            evidence['results'] = copy.copy(evidence['results'])
            evidence['results']['cases'] = list(evidence['results']['cases'])
            evidence['results']['cases'].pop()
            if duplicate:
                evidence['results']['cases'].append(evidence['results']['cases'][0])
            with self.subTest(duplicate=duplicate), self.assertRaises(AssertionError):
                ANALYZER['audit'](evidence)

    def test_raw_publication_payload_mutation_is_detected(self):
        evidence = copy.deepcopy(self.reference['evidence'])
        case = self.reference['results']['cases'][0]
        prefix = 'load/1/L1-per-lane/window-1/live-dependency-diagnostic/'
        for event in evidence:
            if event['label'].startswith(prefix) and event['label'].endswith('/admit'):
                text = event['transaction']['outputs_data'][0]
                event['transaction']['outputs_data'][0] = text[:-2] + '01'
                break
        else:
            self.fail('missing actual admission fixture')
        with self.assertRaises(AssertionError):
            ANALYZER['audit_case'](case, evidence, self.fees)


if __name__ == '__main__':
    unittest.main()
