#!/usr/bin/env python3
"""Independent transcript/fixture audit, not CKB or proof authorization."""
import hashlib
import json
import pathlib
import sys
ROOT = pathlib.Path(__file__).resolve().parent.parent
def raw(s): return bytes.fromhex(s.removeprefix('0x'))
def digest(domain, data): return hashlib.blake2b(domain+data, digest_size=32, person=b'ckb-default-hash').digest()
def num(b): return int.from_bytes(b, 'little')
def le(n, size): return n.to_bytes(size, 'little')
def require(ok, message):
    if not ok: raise ValueError(message)

def check(c, g):
    for report in [c, g]:
        require(all(report[k] is False for k in ['authenticated_publication', 'proof_settled', 'custody_release', 'production_ready']), 'candidate scope')
    require(c['schema'] == 1 and c['profile'] == 'native-custody-execution-v2-candidate', 'profile')
    descriptor = b''.join((ROOT/p).read_bytes() for p in ['crates/tactus-o1-execution/rules-native-v2.txt', 'crates/tactus-o1-execution/rules-v1.txt', 'Cargo.lock', 'contracts/bridge/NativeCKB.json'])
    rules = digest(b'tactus/o1/native-execution-rules/v2', descriptor)
    require(raw(c['rules_hash']) == rules, 'rules hash')
    cfg = raw(c['config']); code = raw(c['vault_code_hash'])
    require(len(cfg) == 164 and cfg[:8] == b'TO1VAU01' and len(code) == 32, 'config')
    script = b''.join(le(n, 4) for n in [217, 16, 48, 49])+code+b'\x02'+le(164, 4)+cfg
    require(raw(c['vault_type_hash']) == digest(b'', script), 'vault type')
    original = json.loads((ROOT/'specs/evidence/native-vault-recovery/0.210.0/recovery.json').read_text())['cold_final']
    require(script == raw(original['vault_script']), 'actual vault domain')
    require(g['geth'] == '1.17.8' and g['fork'] == 'Shanghai' and len(c['cases']) == 2, 'independent engine')
    rows = []; deposits = transactions = reverts = 0
    for case_index, case in enumerate(c['cases']):
        require(case['name'] == ['actual-funded-record-bytes', 'synthetic-records-signed-transfer-burn-refill'][case_index], 'case identity')
        previous = None; count = cumulative = 0; accumulator = digest(b'tactus/o1/deposits/empty/v1', cfg)
        for step in case['steps']:
            before, after, wrapper = raw(step['before']), raw(step['after']), raw(step['wrapper'])
            require(len(before) == len(after) == 256 and wrapper[:8] == b'TO1BRG02' and len(wrapper) <= 262144, 'wire')
            require(before[:8] == b'TO1ANC01' and before[8:40] == cfg[72:104] and before[96:128] == rules and before[192:200] == cfg[104:112], 'ordering domain')
            if previous is not None: require(before == previous, 'noncontiguous anchors')
            else:
                require(before[40:96] == bytes(56), 'nonempty genesis anchor')
                require(raw(case['genesis_header']['extraData']) == digest(b'tactus/o1/native-genesis/v2', before[:200]+script), 'genesis domain hash')
            require(before[200:] == le(count, 8)+le(cumulative, 16)+accumulator and wrapper[8:64] == before[200:], 'parent deposit cursor')
            n = num(wrapper[64:66]); require(n == len(step['deposits']) and n <= 32, 'bounded record count')
            for i, row in enumerate(step['deposits']):
                r = wrapper[66+i*124:66+(i+1)*124]
                require(r == raw(row['record']) and r[:8] == b'TO1DPR01', 'record wire')
                count += 1; amount = num(r[36:44]); cumulative += amount
                require(0 < amount < 2**64 and count < 2**64 and cumulative < 2**128 and r[16:36] not in [bytes(20), cfg[112:132]], 'record range/recipient')
                require(num(r[8:16]) == count and num(r[108:124]) == cumulative and r[44:76] == accumulator, 'record succession')
                accumulator = digest(b'tactus/o1/deposits/append/v1', cfg+r[:76]+le(cumulative, 16))
                require(r[76:108] == accumulator and raw(row['deposit_id']) == digest(b'tactus/o1/deposit/id/v1', cfg+le(count, 8)), 'record commitment/id')
                require(0 < row['gas_used'] <= 200000 and len(row['logs']) == 2, 'credit gas/logs')
                if case_index == 0: require(r == raw(original['deposits'][count-1]['record']), 'actual funded receipt differs')
                deposits += 1
            offset = 66+124*n; inner = wrapper[offset+4:]
            require(num(wrapper[offset:offset+4]) == len(inner), 'inner frame')
            require(len(step['blocks']) == 1, 'fixture block count')
            block = step['blocks'][0]; h = block['header']; number = int(h['number'], 16); timestamp = int(h['timestamp'], 16)
            expected_inner = b'TO1BAT01'+before[8:40]+before[192:200]+before[40:80]+before[96:192]+le(num(before[80:88])+1, 8)+le(1, 2)
            expected_inner += le(timestamp, 8)+raw(h['miner'])+le(len(block['transactions']), 2)
            for tx in block['transactions']: expected_inner += le(len(raw(tx)), 4)+raw(tx)
            require(inner == expected_inner and number == num(before[80:88])+1, 'user input commitment')
            expected_after = before[:40]+le(num(before[40:48])+1, 8)+digest(b'tactus/o1/native-batch/v2', wrapper)+le(number, 8)+le(timestamp, 8)+before[96:200]
            expected_after += le(count, 8)+le(cumulative, 16)+accumulator
            require(after == expected_after, 'next anchor/cursor')
            require(len(block['receipts']) == len(block['transactions']) == len(block['outcomes']), 'user outcomes')
            for outcome in block['outcomes']:
                require(outcome['status'] in ['Success', 'Revert'], 'unexpected user outcome')
                transactions += 1; reverts += outcome['status'] == 'Revert'
            rows.append({'case': case['name'], 'number': number, 'state_root': h['stateRoot'], 'gas_used': int(h['gasUsed'], 16), 'transaction_root': h['transactionsRoot'], 'receipt_root': h['receiptsRoot']})
            previous = after
        storage = case['final_bridge']['storage']
        slot = lambda i: int(storage.get(hex(i), '0x0'), 16)
        require(slot(1) == cumulative and slot(0)+slot(2) == cumulative, 'final token conservation')
        require((slot(0), slot(2), slot(6)) == [(25000000000, 0, 0), (0, 1750, 3)][case_index], 'final fixture outcome')
    require(rows == g['blocks'] and len(rows) == 7, 'independent Geth transitions')
    require((deposits, transactions, reverts) == (g['deposits'], g['signed_transactions'], g['reverts']) == (5, 5, 1), 'coverage')
    return {'blocks': 7, 'system_credits': 5, 'signed_transactions': 5, 'reverts': 1, 'actual_record_bytes': 2,
            'synthetic_records': 3, 'authenticated_publication': False, 'proof_settled': False, 'custody_release': False, 'production_ready': False}

if __name__ == '__main__':
    path = pathlib.Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT/'specs/evidence/native-bridge-execution'
    print(json.dumps(check(json.loads((path/'candidate.json').read_text()), json.loads((path/'geth.json').read_text())), indent=2))
