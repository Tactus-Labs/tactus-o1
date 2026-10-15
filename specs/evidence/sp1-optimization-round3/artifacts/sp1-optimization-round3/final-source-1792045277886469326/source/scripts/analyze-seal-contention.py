#!/usr/bin/env python3
"""Reconcile seal contention evidence against signed lane/snapshot/batch bytes.
This checks retained evidence consistency; it is not a CKB consensus verifier.
"""
import hashlib
import itertools
import json
import pathlib
import struct
import sys


def decode(value):
    assert value.startswith('0x')
    return bytes.fromhex(value[2:])


def point(value):
    return value['tx_hash'], int(value['index'], 16)


def payload(epoch, lane, position):
    return b'\x00' + struct.pack('<Q', epoch) + bytes([lane, position]) + b'SEAL0001' + bytes(45)


def lane(data):
    assert data[:8] == b'TO1LAN01'
    count = data[121]
    assert count <= 8
    offset = 122
    queue = []
    for _ in range(count):
        size = struct.unpack_from('<H', data, offset)[0]
        offset += 2
        queue.append(data[offset:offset + size])
        offset += size
    assert offset == len(data)
    return dict(index=data[40], epoch=struct.unpack_from('<Q', data, 41)[0],
                sequence=struct.unpack_from('<Q', data, 49)[0], queue=queue,
                base_root=data[57:89], root=data[89:121])


def snapshot(data):
    assert data[:8] == b'TO1SEA01'
    count = data[48]
    offset = 49
    result = []
    for _ in range(count):
        size = struct.unpack_from('<I', data, offset)[0]
        offset += 4
        result.append(data[offset:offset + size])
        offset += size
    assert offset == len(data)
    return result


def batch_payloads(data):
    assert data[:8] == b'TO1BAT01'
    assert struct.unpack_from('<H', data, 192)[0] == 1
    offset = 222
    count = struct.unpack_from('<H', data, offset)[0]
    offset += 2
    result = []
    for _ in range(count):
        size = struct.unpack_from('<I', data, offset)[0]
        offset += 4
        result.append(data[offset:offset + size])
        offset += size
    assert offset == len(data)
    return result


def audit(evidence):
    results = evidence['results']
    assert results['complete'] and results['error'] is None
    cases = results['cases']
    assert len(cases) == 6
    assert {(c['lanes'], c['mode']) for c in cases} == set(itertools.product([1, 2, 4], ['one-lane-per-rebuild', 'all-lanes']))
    selected = [e for e in evidence['evidence'] if e['label'].startswith('seal-contention/') and not e['label'].endswith('/warmup')]
    records = {e['label']: e for e in selected}
    assert len(records) == len(selected)
    cells = {}
    for event in evidence['evidence']:
        if event['result'] == 'committed':
            for i, data in enumerate(event['transaction']['outputs_data']):
                cells[event['hash'], i] = decode(data)
    rows = []
    for case in cases:
        k, mode = case['lanes'], case['mode']
        assert len(case['epochs']) == 2
        distinct = set()
        for epoch, report in enumerate(case['epochs']):
            assert report['epoch'] == epoch
            stem = f'seal-contention/{k}/{mode}/epoch-{epoch}'
            count = 8 * k if mode == 'one-lane-per-rebuild' else 8
            assert len(report['attempts']) == count
            assert report['invalidated_seals'] == count
            assert report['legal_admissions'] == report['maximum_independent_append_budget'] == 8 * k
            current = None
            for attempt, row in enumerate(report['attempts']):
                assert row['attempt'] == attempt
                targets = [attempt % k] if mode == 'one-lane-per-rebuild' else list(range(k))
                assert row['target_lanes'] == targets
                rejected = records[f'{stem}/attempt-{attempt}/stale signed seal']
                assert rejected['result'] == 'rejected'
                assert json.loads(rejected['error'].removeprefix('rpc error: '))['code'] == -301
                signed = rejected['transaction']
                old_points = [point(i['previous_output']) for i in signed['inputs'][1:-1]]
                assert len(old_points) == k
                if current is not None:
                    assert old_points == current
                old_data = [cells[p] for p in old_points]
                old_lanes = [lane(d) for d in old_data]
                assert all(l['index'] == i and l['epoch'] == epoch for i, l in enumerate(old_lanes))
                assert snapshot(decode(signed['outputs_data'][k + 1])) == old_data
                assert sum(len(l['queue']) for l in old_lanes) == row['snapshot_messages_when_signed']
                admitted = records[f'{stem}/attempt-{attempt}/attacker admission']
                assert admitted['result'] == 'committed'
                tx = admitted['transaction']
                assert [point(i['previous_output']) for i in tx['inputs'][:-1]] == [old_points[i] for i in targets]
                # Only the target lane inputs overlap. The sealer's funding and
                # Schedule inputs are not consumed by the attack transaction.
                attack_inputs = {point(i['previous_output']) for i in tx['inputs']}
                assert point(signed['inputs'][0]['previous_output']) not in attack_inputs
                assert point(signed['inputs'][-1]['previous_output']) not in attack_inputs
                current = old_points[:]
                states = old_lanes[:]
                for output_index, i in enumerate(targets):
                    new = lane(decode(tx['outputs_data'][output_index]))
                    old = old_lanes[i]
                    assert new['queue'] == old['queue'] + [payload(epoch, i, len(old['queue']))]
                    assert new['sequence'] == old['sequence'] + 1
                    assert new['epoch'] == old['epoch'] and new['base_root'] == old['base_root']
                    states[i] = new
                    current[i] = admitted['hash'], output_index
                assert row['queues_after'] == [len(l['queue']) for l in states]
                assert row['rejected_height'] == int(admitted['block_number'], 16)
                assert row['funding_and_gate_remain_live']
            for i in range(k):
                for name, code in [('ninth admission', 3), ('no-op', 12), ('unauthorized reset', 7)]:
                    rejected = records[f'{stem}/exhausted/lane-{i}/{name}']
                    assert rejected['result'] == 'rejected' and rejected['expected_code'] == code
                    assert json.loads(rejected['error'].removeprefix('rpc error: '))['code'] == -302
            assert report['further_invalid_churn_rejections'] == 3 * k
            sealed = records[f'{stem}/rebuilt seal after exhausted churn']
            assert sealed['result'] == 'committed'
            tx = sealed['transaction']
            assert [point(i['previous_output']) for i in tx['inputs'][1:-1]] == current
            snap = snapshot(decode(tx['outputs_data'][k + 1]))
            assert snap == [cells[p] for p in current]
            for i, encoded in enumerate(snap):
                old = lane(encoded)
                assert old['queue'] == [payload(epoch, i, j) for j in range(8)]
                new = lane(decode(tx['outputs_data'][i + 1]))
                assert new['epoch'] == old['epoch'] + 1 and new['sequence'] == old['sequence']
                assert new['queue'] == [] and new['base_root'] == new['root'] == old['root']
            assert report['sealed_height'] == int(sealed['block_number'], 16)
            last_append = records[f'{stem}/attempt-{count - 1}/attacker admission']
            assert report['final_seal_commit_delay_blocks'] == int(sealed['block_number'], 16) - int(last_append['block_number'], 16)
            ordered = [payload(epoch, i, j) for j in range(8) for i in range(k)]
            executed = []
            for step in range(8):
                event = records[f'{stem}/process-{step}']
                assert event['result'] == 'committed'
                actual = batch_payloads(decode(event['transaction']['outputs_data'][1]))
                assert actual == ordered[4 * step:4 * step + 4]
                batch = struct.unpack_from('<Q', decode(event['transaction']['outputs_data'][0]), 40)[0]
                assert batch == 8 + epoch * 8 + step + 1
                for message in actual:
                    assert message not in distinct
                    distinct.add(message)
                    executed.append(dict(lane=message[9], position=message[10], processed_batch=batch,
                                         batch_delay_from_admission=step + 1))
            assert executed == report['processed_messages']
            rows.append(dict(lanes=k, mode=mode, epoch=epoch, invalidated_seals=count,
                             legal_admissions=8 * k, extra_invalid_churn_rejections=3 * k,
                             final_seal_delay_blocks=report['final_seal_commit_delay_blocks'],
                             processed_messages=len(executed), maximum_processing_batches=max(m['batch_delay_from_admission'] for m in executed)))
        assert len(distinct) == case['distinct_processed_messages'] == 16 * k
        assert case['all_messages_processed_once']
    return rows


if __name__ == '__main__':
    source = pathlib.Path(sys.argv[1])
    raw = source.read_bytes()
    rows = audit(json.loads(raw))
    target = pathlib.Path(sys.argv[2])
    target.write_text(json.dumps(dict(schema=1, evidence_sha256=hashlib.sha256(raw).hexdigest(),
                                     analyzer_sha256=hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest(),
                                     production_ready=False, independently_reconciled_epochs=len(rows), rows=rows), indent=2) + '\n')
    print(f'Independently reconciled {len(rows)} adversarial epochs')
