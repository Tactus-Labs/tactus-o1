#!/usr/bin/env python3
"""Reject false process-fault and post-restart recovery claims."""
import copy
import importlib.util
import json
import pathlib
import unittest
spec=importlib.util.spec_from_file_location('checker',pathlib.Path(__file__).with_name('check-obligation-restart.py'))
c=importlib.util.module_from_spec(spec);spec.loader.exec_module(c)
ROOT=pathlib.Path(__file__).resolve().parents[1]/'specs/evidence/obligation-restart/0.210.0'


class RestartTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.evidence=json.loads(c.read(ROOT/'evidence.json.gz'))
        cls.crash=json.loads(c.read(ROOT/'crash-recovery.json'))
        cls.launch=c.read(ROOT/'launch.txt.gz').decode()
        cls.restart=c.read(ROOT/'restarted-node.log.gz').decode()

    def test_actual_restart(self):
        self.assertEqual(c.check_document(self.evidence,self.crash,self.launch,self.restart)['recovered_height'],81)

    def test_forged_restart(self):
        controls=[
            ('graceful-exit',lambda r:r.update(wait_exit_status=0)),
            ('same-process',lambda r:r.update(new_pid=r['old_pid'])),
            ('changed-peer',lambda r:r['peer_while_primary_down']['counts'].update(published=3)),
            ('lost-duty',lambda r:r['main_after_restart']['obligations'].pop()),
            ('power-loss-overclaim',lambda r:r.update(power_loss_simulated=True)),
            ('different-database',lambda r:r.update(same_database=False)),
        ]
        for name,mutate in controls:
            with self.subTest(name=name):
                changed=copy.deepcopy(self.crash);mutate(changed)
                with self.assertRaises(ValueError):c.check_document(self.evidence,changed,self.launch,self.restart)
        with self.assertRaises(ValueError):c.check_document(self.evidence,self.crash,'',self.restart)
        with self.assertRaises(ValueError):c.check_document(self.evidence,self.crash,self.launch,'')


if __name__=='__main__':unittest.main()
