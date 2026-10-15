#!/usr/bin/env python3
"""Witness selection controls use a retained real recursive witness, not a mock proof."""
import gzip
import json
import pathlib
import runpy
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SELECT = runpy.run_path(str(ROOT / 'scripts/finish-chain-proof-staged.py'))['retained_witness']
ARCHIVE = ROOT / 'specs/evidence/chain-groth16-proof'


class WitnessSelection(unittest.TestCase):
    def test_exact_completed_witness_selected_and_incomplete_candidates_excluded(self):
        original = gzip.decompress((ARCHIVE / 'retained-wrapped-witness.json.gz').read_bytes())
        key = json.loads((ARCHIVE / 'proving-input.json').read_bytes())['guest_verifying_key']
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            path = root / '.tmpWitness'
            path.write_bytes(original)
            self.assertEqual(SELECT(root, key), (path, original))
            for kind in ('truncated', 'wrong-key', 'exit-code', 'missing-witness', 'missing-vk-root', 'oversize'):
                value = json.loads(original)
                if kind == 'wrong-key':
                    value['vkey_hash'] = '1'
                elif kind == 'exit-code':
                    value['exit_code'] = '1'
                elif kind == 'missing-witness':
                    value['vars'] = []
                elif kind == 'missing-vk-root':
                    del value['vk_root']
                path.write_text(json.dumps(value))
                if kind == 'truncated':
                    path.write_bytes(path.read_bytes()[:-1])
                elif kind == 'oversize':
                    with path.open('wb') as stream:
                        stream.truncate(16 * 1024 * 1024 + 1)
                with self.subTest(kind=kind):
                    self.assertIsNone(SELECT(root, key))


if __name__ == '__main__':
    unittest.main()
