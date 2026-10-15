#!/usr/bin/env python3
"""Ensure the execution evidence auditor rejects fabricated native statements."""
import importlib.util
import json
import pathlib
import shutil
import tempfile
import unittest

HERE = pathlib.Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('audit', HERE/'check-native-guest.py')
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)
ARCHIVE = HERE.parent/'specs/evidence/native-guest/execution'

class NativeGuestEvidence(unittest.TestCase):
    def test_actual_execution(self):
        self.assertTrue(audit.check(ARCHIVE)['passed'])

    def test_fabricated_reports(self):
        for mode in ['amount','range','domain','allocation','journal','coordinated-root','coordinated-cursor','key','proof','settlement','release','production','manifest-source']:
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as tmp:
                run = pathlib.Path(tmp)/'run'
                shutil.copytree(ARCHIVE,run)
                ip = run/'input-0.json'
                rp = run/'execute-0/result.json'
                inp = json.loads(ip.read_text())
                result = json.loads(rp.read_text())
                if mode == 'amount':
                    b=bytearray.fromhex(inp['batches'][0][2:]);b[102]^=1;inp['batches'][0]='0x'+b.hex()
                elif mode == 'range': inp['prefix_batches']=1
                elif mode == 'domain': inp['domain_hex']='0x'+'00'*196
                elif mode == 'allocation':
                    b=bytearray.fromhex(inp['allocation_hex'][2:]);b[-1]^=1;inp['allocation_hex']='0x'+b.hex()
                elif mode == 'journal': result['public_values_hex']='00'*940
                elif mode.startswith('coordinated-'):
                    bp=run/'execute-0/public-values.bin'
                    b=bytearray(bp.read_bytes());b[812 if mode.endswith('root') else 724]^=1;bp.write_bytes(b)
                    inp['expected_journal_hex']='0x'+b.hex();result['public_values_hex']=b.hex()
                elif mode == 'key': result['guest_verifying_key']='0x'+'01'*32
                elif mode in ['proof','settlement','release','production']:
                    field={'proof':'proof_generated','settlement':'ckb_settlement','release':'custody_release','production':'production_ready'}[mode]
                    result[field]=True
                else:
                    mp=run/'manifest.json';m=json.loads(mp.read_text());m['inputs']['proofs/native-sp1/journal/src/lib.rs']='00'*32;mp.write_text(json.dumps(m))
                ip.write_text(json.dumps(inp));rp.write_text(json.dumps(result))
                with self.assertRaises((AssertionError,ValueError,KeyError)):
                    audit.check(run)

if __name__ == '__main__':
    unittest.main()
