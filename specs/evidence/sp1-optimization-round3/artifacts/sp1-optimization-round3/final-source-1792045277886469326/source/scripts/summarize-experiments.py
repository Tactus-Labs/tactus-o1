#!/usr/bin/env python3
"""Derive a compact, reviewable summary from raw evidence; never infer gate passes."""
import hashlib
import json
import pathlib
import sys

source = pathlib.Path(sys.argv[1])
raw = source.read_bytes()
evidence = json.loads(raw)
if not evidence['results']['complete'] or evidence['results']['error'] is not None:
    raise SystemExit('Cannot summarize a failed or incomplete mechanism suite as completed')
committed = [e for e in evidence['evidence'] if e['result'] == 'committed']
rejected = [e for e in evidence['evidence'] if e['result'] == 'rejected']
cycles = [int(e['cycles']['cycles'], 16) for e in committed if e.get('cycles')]
summary = {
    'schema_version': 1,
    'evidence_sha256': hashlib.sha256(raw).hexdigest(),
    'metadata': evidence['metadata'],
    'results': evidence['results'],
    'transactions': {'committed_evidence_records': len(committed), 'rejected_records': len(rejected)},
    'estimated_cycles': {'samples': len(cycles), 'minimum': min(cycles) if cycles else None,
                         'maximum': max(cycles) if cycles else None},
    'interpretation': 'Boundary suite completed; full Experiment A and production gates remain OPEN.',
}
pathlib.Path(sys.argv[2]).write_text(json.dumps(summary, indent=2) + '\n')
print(json.dumps(summary['transactions']))
