#!/usr/bin/env python3
"""Compile immutable bridge bytecode using a hash-pinned stable solc."""
import hashlib
import json
import pathlib
import subprocess
import sys
import urllib.request

root = pathlib.Path(__file__).resolve().parent.parent
compiler = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else root/'artifacts/solc-tools/solc-0.8.30').resolve()
pin = json.loads((root/'contracts/bridge/compiler.json').read_text())
if not compiler.exists():
    compiler.parent.mkdir(parents=True, exist_ok=True)
    with urllib.request.urlopen(pin['url'], timeout=60) as response:
        binary = response.read(32 * 1024 * 1024 + 1)
    if hashlib.sha256(binary).hexdigest() != pin['sha256']:
        raise ValueError('downloaded compiler hash mismatch')
    compiler.write_bytes(binary)
    compiler.chmod(0o755)
if hashlib.sha256(compiler.read_bytes()).hexdigest() != pin['sha256']:
    raise ValueError('unrecognized compiler binary')
source = (root/'contracts/bridge/NativeCKB.sol').read_text()
request = {'language':'Solidity', 'sources':{'NativeCKB.sol':{'content':source}}, 'settings':{
    'evmVersion':'shanghai', 'optimizer':{'enabled':True,'runs':200},
    'metadata':{'bytecodeHash':'none','appendCBOR':False},
    'outputSelection':{'*':{'*':['abi','storageLayout','evm.bytecode.object','evm.deployedBytecode.object','evm.deployedBytecode.immutableReferences','evm.methodIdentifiers']}}}}
process = subprocess.run([str(compiler),'--standard-json'], input=json.dumps(request), capture_output=True, text=True, check=True)
result = json.loads(process.stdout)
if any(e['severity']=='error' for e in result.get('errors',[])):
    raise ValueError(result['errors'])
contract = result['contracts']['NativeCKB.sol']['NativeCKB']
artifact = {'compiler':pin, 'source_sha256':hashlib.sha256(source.encode()).hexdigest(),
            'settings':request['settings'], 'contract':contract}
path = root/'contracts/bridge/NativeCKB.json'
path.write_text(json.dumps(artifact, indent=2, sort_keys=True)+'\n')
print('compiled', len(contract['evm']['bytecode']['object'])//2, 'creation bytes;',
      len(contract['evm']['deployedBytecode']['object'])//2, 'runtime bytes')
