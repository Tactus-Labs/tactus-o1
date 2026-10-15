#!/usr/bin/env python3
"""Audit retained native SP1 execution against separately audited publication data.
This is artifact consistency checking, not cryptographic proof verification.
"""
import hashlib
import importlib.util
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location('publication', ROOT/'scripts/check-native-publication.py')
pub = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pub)
raw, digest, require = pub.raw, pub.digest, pub.require
PROFILE = b'TO1NPR02;full-vault-config;fixed-vault-code;replay-canonical-genesis-prefix;authenticated-publication-required;nonempty-contiguous-interval;native-deposit-cursors;ethereum-state-and-header;ckb-settlement-required'


def check(run):
    fixture = ROOT/'specs/evidence/native-publication/0.210.0'
    deployment = json.loads((fixture/'deployment.json').read_text())
    execution = json.loads((fixture/'execution.json').read_text())
    geth = json.loads((fixture/'geth.json').read_text())
    import gzip
    evidence = json.loads(gzip.decompress((fixture/'evidence.json.gz').read_bytes()))
    pub.check(evidence, execution, geth)
    cfg = raw(deployment['config'])
    allocation = raw(deployment['genesis_allocation'])
    steps = execution['cases'][0]['steps']
    domain = cfg+digest(b'', raw(deployment['anchor_script']))
    key = None
    totals = []
    for prefix in [0, 1]:
        inp = json.loads((run/f'input-{prefix}.json').read_text())
        result = json.loads((run/f'execute-{prefix}/result.json').read_text())
        public = (run/f'execute-{prefix}/public-values.bin').read_bytes()
        require(inp['schema'] == 'native-proof-input-v2' and inp['prefix_batches'] == prefix, 'input profile/range')
        require(raw(inp['domain_hex']) == domain and raw(inp['allocation_hex']) == allocation, 'input domain/allocation')
        require(inp['batches'] == [s['wrapper'] for s in steps], 'exact published transcript')
        require(inp['authenticated_publication'] is False, 'input does not authenticate CKB')
        before = raw(steps[prefix]['before'])
        after = raw(steps[-1]['after'])
        previous_root = raw(execution['cases'][0]['genesis_header']['stateRoot']) if prefix == 0 else raw(geth['blocks'][0]['state_root'])
        previous_header = raw(steps[0]['blocks'][0]['header']['parentHash']) if prefix == 0 else raw(steps[0]['blocks'][0]['hash'])
        interval = digest(b'tactus/o1/native-proof-interval/v2', (2-prefix).to_bytes(8,'little'))
        for step in steps[prefix:]:
            wire = raw(step['wrapper'])
            interval = digest(b'tactus/o1/native-proof-interval-step/v2', interval+len(wire).to_bytes(8,'little')+wire)
        expected = b'TO1NPR02'+digest(b'tactus/o1/native-proof-profile/v2', PROFILE)+domain+digest(b'tactus/o1/genesis-allocation/v1', allocation)+before+after+previous_root+raw(geth['blocks'][-1]['state_root'])+previous_header+raw(steps[-1]['blocks'][0]['hash'])+interval
        require(len(expected) == len(public) == 940 and public == expected == raw(inp['expected_journal_hex']), 'independent full journal')
        require(result['schema'] == 'native-guest-execution-v2' and result['backend'] == 'local-cpu' and result['sp1'] == '6.8.1', 'guest runner profile')
        require(result['native_replay_match'] is True and result['prefix_batches'] == prefix and result['interval_batches'] == 2-prefix, 'guest result')
        require(bytes.fromhex(result['public_values_hex']) == expected, 'guest output bytes')
        require(all(result[k] is False for k in ['proof_generated','authenticated_publication','ckb_settlement','custody_release','production_ready']), 'scope inflation')
        current = raw(result['guest_verifying_key'])
        require(len(current) == 32 and current != bytes(32) and (key is None or key == current), 'same guest identity')
        key = current
        require(result['execution_seconds_including_setup'] > 0 and (run/f'execute-{prefix}/execution-report.txt').stat().st_size > 0, 'execution telemetry')
        totals.append({'prefix':prefix,'interval':2-prefix,'journal_sha256':hashlib.sha256(public).hexdigest()})
    manifest = json.loads((run/'manifest.json').read_text())
    require(manifest['schema'] == 'native-guest-execution-v2' and all(manifest[k] is False for k in ['proof_generated','ckb_settlement','custody_release','production_ready']), 'manifest scope')
    for name in ['Cargo.lock','proofs/native-sp1/Cargo.lock','proofs/native-sp1/guest/src/main.rs','proofs/native-sp1/journal/src/lib.rs','contracts/bridge/NativeCKB.json']:
        require(manifest['inputs'][name] == hashlib.sha256((ROOT/name).read_bytes()).hexdigest(), f'source binding {name}')
    return {'schema':'native-guest-execution-v2','passed':True,'guest_verifying_key':'0x'+key.hex(),'guest_sha256':manifest['guest_sha256'],'journals':totals,'authenticated_publication_audited_separately':True,'proof_generated':False,'ckb_settlement':False,'custody_release':False,'production_ready':False}


if __name__ == '__main__':
    print(json.dumps(check(pathlib.Path(sys.argv[1])),indent=2))
