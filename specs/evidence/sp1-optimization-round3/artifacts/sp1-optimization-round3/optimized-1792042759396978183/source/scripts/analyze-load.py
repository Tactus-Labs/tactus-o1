#!/usr/bin/env python3
"""Independently reconcile sustained-load claims with retained signed CKB bytes.

This is an evidence consistency check, not a CKB consensus or execution verifier.
It decodes lane/batch payloads without the Rust driver and derives admission,
publication, fee, backlog and latency counts from the transaction event stream.
"""
import hashlib
import itertools
import json
import pathlib
import struct
import sys


def number(value):
    return int(value, 16)


def data(value):
    assert value.startswith('0x')
    return bytes.fromhex(value[2:])


def message_id(payload):
    assert len(payload) == 64
    identity = struct.unpack_from('<Q', payload, 1)[0]
    expected = bytes([0]) + struct.pack('<Q', identity) + b'LOAD0001' + bytes(47)
    assert payload == expected
    return identity


def lane_append(encoded):
    assert encoded[:8] == b'TO1LAN01'
    lane = encoded[40]
    count = encoded[121]
    assert 1 <= count <= 8
    position = 122
    messages = []
    for _ in range(count):
        size = struct.unpack_from('<H', encoded, position)[0]
        position += 2
        messages.append(message_id(encoded[position:position + size]))
        position += size
    assert position == len(encoded)
    return lane, messages[-1]


def batch_messages(encoded):
    assert encoded[:8] == b'TO1BAT01'
    count = struct.unpack_from('<H', encoded, 192)[0]
    assert count == 1
    position = 194 + 28
    slots = struct.unpack_from('<H', encoded, position)[0]
    position += 2
    messages = []
    for _ in range(slots):
        size = struct.unpack_from('<I', encoded, position)[0]
        position += 4
        messages.append(message_id(encoded[position:position + size]))
        position += size
    assert position == len(encoded)
    return messages


def fees_by_event(events):
    outputs = {}
    fees = {}
    for event in events:
        if event['result'] != 'committed':
            continue
        transaction = event['transaction']
        consumed = [outputs.get((i['previous_output']['tx_hash'], number(i['previous_output']['index'])))
                    for i in transaction['inputs']]
        produced = sum(number(o['capacity']) for o in transaction['outputs'])
        if all(c is not None for c in consumed):
            fees[event['hash']] = sum(consumed) - produced
        for index, output in enumerate(transaction['outputs']):
            outputs[event['hash'], index] = number(output['capacity'])
    return fees


def latency(values):
    ordered = sorted(values)
    return dict(count=len(values), p50=ordered[(len(values) * 50 + 99) // 100 - 1],
                p95=ordered[(len(values) * 95 + 99) // 100 - 1],
                p99=ordered[(len(values) * 99 + 99) // 100 - 1], maximum=ordered[-1])


def audit_case(case, events, fees):
    lanes = case['lanes']
    regime = case['regime']
    window = case['window_quanta']
    stem = f"load/{lanes}/{regime}/window-{window}/{case['arm']}/"
    records = [event for event in events if event['label'].startswith(stem)]
    offered = []
    assert case['rounds'] == 32 and len(case['timeline']) == 32
    for r, row in enumerate(case['timeline']):
        assert row['round'] == r and len(row['ticks']) == window
        assert row['ticks'][0]['start_height'] == row['built_height']
        for tick, slot in enumerate(row['ticks']):
            assert slot['end_height'] - slot['start_height'] == 4
            if tick:
                assert row['ticks'][tick - 1]['end_height'] == slot['start_height']
            targets = (list(range(lanes)) if regime == 'L1-per-lane' else
                       [(r * window + tick) % lanes] if regime == 'L2-fixed-aggregate' else
                       [0] * window if tick == window - 1 else [])
            assert len(targets) == slot['offered']
            offered.extend((lane, slot['start_height']) for lane in targets)
        assert row['submit_height'] == row['ticks'][-1]['end_height']
    assert len(offered) == len(case['messages'])
    messages = {m['id']: m for m in case['messages']}
    assert len(messages) == len(offered) and set(messages) == set(range(len(offered)))
    for identity, (lane, height) in enumerate(offered):
        assert messages[identity]['lane'] == lane and messages[identity]['offered_height'] == height
    admitted = {}
    processed = {}
    current_batch = 0
    publication_order = []
    tick_admissions = {}
    retained_capacity = 0
    active_batches = 0
    failed = 0
    total_fees = 0
    active_transactions = 0
    for event in records:
        local = event['label'][len(stem):]
        if event['result'] == 'rejected':
            assert local.endswith('/invalidated candidate')
            error = json.loads(event['error'].removeprefix('rpc error: '))
            assert error['code'] == -301
            failed += 1
            continue
        assert event['result'] == 'committed'
        height = number(event['block_number'])
        transaction = event['transaction']
        encoded = [data(d) for d in transaction['outputs_data']]
        if local.endswith('/admit'):
            for output in encoded[:-1]:
                lane, identity = lane_append(output)
                assert identity not in admitted
                m = messages[identity]
                assert (m['lane'], m['admitted_height'], m['admitted_batch']) == (lane, height, current_batch)
                assert m['offered_height'] <= height
                admitted[identity] = (lane, height)
                if local.split('/')[0].isdigit():
                    parts = local.split('/')
                    key = (int(parts[0]), int(parts[1].removeprefix('tick-')))
                    tick_admissions.setdefault(key, [0] * lanes)[lane] += 1
        elif len(encoded) > 1 and encoded[1][:8] == b'TO1BAT01':
            assert encoded[0][:8] == b'TO1ANC01'
            next_batch = struct.unpack_from('<Q', encoded[0], 40)[0]
            assert next_batch == current_batch + 1
            current_batch = next_batch
            for identity in batch_messages(encoded[1]):
                assert identity in admitted and identity not in processed
                m = messages[identity]
                assert (m['processed_height'], m['processed_batch']) == (height, current_batch)
                assert 1 <= current_batch - m['admitted_batch'] <= 16
                processed[identity] = height
                publication_order.append(identity)
            if '/canonical batch' in local:
                active_batches += 1
        if local.split('/')[0].isdigit():
            assert fees[event['hash']] == 100_000_000
            total_fees += fees[event['hash']]
            active_transactions += 1
            retained_capacity += sum(number(output['capacity']) for output in transaction['outputs']
                                     if output.get('type') is None and output['lock']['args'] == '0x')
    assert set(admitted) == set(processed) == set(messages)
    for r, row in enumerate(case['timeline']):
        totals = [0] * lanes
        for tick, slot in enumerate(row['ticks']):
            actual = tick_admissions.get((r, tick), [0] * lanes)
            assert slot['admissions_per_lane'] == actual
            totals = [a + b for a, b in zip(totals, actual)]
        assert row['lane_updates'] == totals
        assert row['candidate_survived'] == (case['arm'] == 'mandatory-sealed' or sum(totals) == 0)
    # Per-lane input FIFO is checked against actual publication heights/batches.
    for lane in range(lanes):
        ids = [i for i, m in messages.items() if m['lane'] == lane]
        assert [messages[i]['admitted_height'] for i in ids] == sorted(messages[i]['admitted_height'] for i in ids)
        assert [messages[i]['processed_batch'] for i in ids] == sorted(messages[i]['processed_batch'] for i in ids)
        assert [i for i in publication_order if messages[i]['lane'] == lane] == ids
    end = case['end_height']
    n_admitted = sum(height <= end for _, height in admitted.values())
    n_processed = sum(height <= end for height in processed.values())
    assert case['active_counts']['admitted'] == n_admitted
    assert case['active_counts']['processed'] == n_processed
    assert case['active_counts']['offered'] == len(messages)
    assert case['active_counts']['outside_chain_backlog'] == len(messages) - n_admitted
    assert case['active_counts']['admitted_not_processed'] == n_admitted - n_processed
    assert case['drain']['final_counts']['processed'] == len(messages)
    assert case['drain']['final_counts']['outside_chain_backlog'] == 0
    assert case['canonical_batches'] == active_batches
    assert case['invalidated_candidates'] == failed == 32 - active_batches
    assert case['candidate_survival_rate'] == active_batches / 32
    assert case['economics']['fees_shannons'] == total_fees
    assert case['retained_da_and_snapshot_capacity_shannons'] == retained_capacity
    assert case['economics']['committed_transactions'] == active_transactions
    elapsed = case['end_height'] - case['start_height']
    assert case['admission_per_ckb_block'] == n_admitted / elapsed
    assert case['canonical_batches_per_ckb_block'] == active_batches / elapsed
    per_lane = [sum(lane == i and height <= end for lane, height in admitted.values()) for i in range(lanes)]
    assert case['admissions_per_lane'] == per_lane
    if case['arm'] == 'mandatory-sealed':
        assert active_batches == 32 and failed == 0
    return dict(lanes=lanes, regime=regime, window_quanta=window, arm=case['arm'],
                offered=len(messages), admitted=n_admitted, processed=n_processed,
                offchain_backlog=len(messages) - n_admitted, canonical_batches=active_batches,
                active_admission_success_rate=n_admitted / len(messages),
                latency_including_stopped_arrival_drain=dict(
                    admission_blocks=latency([m['admitted_height'] - m['offered_height'] for m in messages.values()]),
                    processing_batches=latency([m['processed_batch'] - m['admitted_batch'] for m in messages.values()])),
                invalidated_candidates=failed, elapsed_blocks=elapsed,
                admission_per_ckb_block=n_admitted / elapsed,
                canonical_batches_per_ckb_block=active_batches / elapsed,
                lane_churn_per_ckb_block=[n / elapsed for n in per_lane],
                fees_shannons=total_fees, retained_capacity_shannons=case['retained_da_and_snapshot_capacity_shannons'],
                drain_rounds=case['drain']['rounds'],
                maximum_processing_batches=max(m['processed_batch'] - m['admitted_batch'] for m in messages.values()))


def audit(evidence):
    results = evidence['results']
    assert results['complete'] and results['error'] is None
    cases = results['cases']
    expected = set(itertools.product([1, 2, 4], ['L1-per-lane', 'L2-fixed-aggregate', 'L3-targeted'],
                                    [1, 3], ['live-dependency-diagnostic', 'mandatory-sealed']))
    actual = [(c['lanes'], c['regime'], c['window_quanta'], c['arm']) for c in cases]
    assert len(actual) == 36 and set(actual) == expected
    fees = fees_by_event(evidence['evidence'])
    return [audit_case(case, evidence['evidence'], fees) for case in cases]


if __name__ == '__main__':
    source = pathlib.Path(sys.argv[1])
    raw = source.read_bytes()
    rows = audit(json.loads(raw))
    result = dict(schema=1, evidence_sha256=hashlib.sha256(raw).hexdigest(),
                  analyzer_sha256=hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest(),
                  production_ready=False, independently_reconciled_cases=len(rows), rows=rows)
    pathlib.Path(sys.argv[2]).write_text(json.dumps(result, indent=2) + '\n')
    print(f'Independently reconciled {len(rows)} sustained-load cases')
