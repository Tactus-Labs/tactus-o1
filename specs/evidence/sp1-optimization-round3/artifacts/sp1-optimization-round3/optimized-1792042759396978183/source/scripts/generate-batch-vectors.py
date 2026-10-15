#!/usr/bin/env python3
"""Independent struct/hashlib oracle for the documented BatchInput v1 layout."""
import hashlib
import json
from pathlib import Path
import struct

root=Path(__file__).resolve().parents[1]/'specs/test-vectors/batch-v1'
root.mkdir(parents=True,exist_ok=True)
def h(tag,data):
    return hashlib.blake2b(tag+data,digest_size=32,person=b'ckb-default-hash').digest()
limits=h(b'tactus/o1/admission-limits/v1',struct.pack('<6Q',262144,16,1024,256,16384,1000000))
da=h(b'tactus/o1/da-policy/v1',b'inline-immutable-cell')
rollup=bytes([7])*32
rules=bytes([9])*32
state=b'TO1ANC01'+rollup+struct.pack('<Q',0)+bytes(32)+struct.pack('<2Q',0,0)+rules+da+limits+struct.pack('<Q',31337)
batch=b'TO1BAT01'+rollup+struct.pack('<2Q',31337,0)+bytes(32)+rules+da+limits+struct.pack('<QH',1,2)
batch+=struct.pack('<Q',10)+bytes([3])*20+struct.pack('<H',1)+struct.pack('<I',3)+b'\x02\x01\x02'
batch+=struct.pack('<Q',10)+bytes([4])*20+struct.pack('<H',0)
commitment=h(b'tactus/o1/batch-input/v1',batch)
next_state=b'TO1ANC01'+rollup+struct.pack('<Q',1)+commitment+struct.pack('<2Q',2,10)+rules+da+limits+struct.pack('<Q',31337)
for name,data in [('genesis',state),('input',batch),('next-state',next_state)]:
    (root/f'{name}.hex').write_text(data.hex()+'\n')
(root/'expected.json').write_text(json.dumps({'scope':'opaque codec fixture, not a valid Ethereum transaction',
    'da_policy_id':da.hex(),'limits_hash':limits.hex(),'batch_commitment':commitment.hex(),
    'batch_bytes':len(batch),'blocks':2,'transactions':1,'gas_ceiling':2000000},indent=2)+'\n')
