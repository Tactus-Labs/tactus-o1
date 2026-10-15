#!/usr/bin/env python3
"""Check the two CKB crypto ports against their pinned upstream crate archives."""
import hashlib
import json
import pathlib
import tarfile


def check(root):
    metadata = json.loads((root / 'UPSTREAM.json').read_text())
    archive = root / 'upstream.crate'
    assert hashlib.sha256(archive.read_bytes()).hexdigest() == metadata['crate_sha256']
    hashes = json.loads((root / 'UPSTREAM_SHA256.json').read_text())
    changed = set(metadata['modified_upstream_files'])
    assert changed <= hashes.keys()
    unchanged = 0
    with tarfile.open(archive, 'r:gz') as source:
        prefix = root.name + '/'
        for name, digest in hashes.items():
            original = source.extractfile(prefix + name).read()
            assert hashlib.sha256(original).hexdigest() == digest, name
            if name not in changed:
                assert (root / name).read_bytes() == original, name
                unchanged += 1
    for name in metadata.get('added_runtime_files', []):
        assert (root / name).is_file(), name
    return {'crate': metadata['crate'], 'version': metadata['version'],
            'archive_sha256': metadata['crate_sha256'],
            'unchanged_upstream_files': unchanged, 'modified_files': sorted(changed)}


if __name__ == '__main__':
    vendor = pathlib.Path(__file__).resolve().parent.parent / 'proofs/vendor'
    print(json.dumps([check(vendor / name) for name in
                      ['sp1-verifier-6.8.1', 'substrate-bn-succinct-rs-0.6.0']], indent=2))
