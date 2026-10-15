#!/usr/bin/env python3
"""Verify unchanged vendor files against the retained Cargo-checksummed upstream."""
import hashlib
import json
import pathlib
import tarfile

root = pathlib.Path(__file__).resolve().parent.parent / 'proofs/vendor/lazy_static-1.5.1'
metadata = json.loads((root / 'UPSTREAM.json').read_text())
archive = root / 'upstream.crate'
assert hashlib.sha256(archive.read_bytes()).hexdigest() == metadata['crate_sha256']
hashes = json.loads((root / 'UPSTREAM_SHA256.json').read_text())
modified = set(metadata['modified_upstream_files'])
checked = 0
with tarfile.open(archive, 'r:gz') as source:
    entries = {member.name.removeprefix('lazy_static-1.5.1/'): member
               for member in source.getmembers() if member.isfile()}
    for name, digest in hashes.items():
        member = entries[name]
        original = source.extractfile(member).read()
        assert hashlib.sha256(original).hexdigest() == digest, name
        if name not in modified:
            assert (root / name).read_bytes() == original, name
            checked += 1
lib = (root / 'src/lib.rs').read_text()
assert 'tactus_ckb_single_thread' in lib and 'compile_error!' in lib
assert 'ckb_single_thread' in (root / 'Cargo.toml').read_text()
print(json.dumps({'crate_sha256': metadata['crate_sha256'],
                  'unchanged_upstream_files': checked,
                  'declared_modified_upstream_files': sorted(modified),
                  'cryptographic_implementation_patched': False}, indent=2))
