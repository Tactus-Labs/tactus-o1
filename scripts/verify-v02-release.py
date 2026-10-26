#!/usr/bin/env python3
"""Verify the release evidence archive in memory without extracting or executing it."""
import argparse
import hashlib
import json
import pathlib
import tarfile


def verify(path, expected_commit=None):
    with tarfile.open(path, "r:gz") as tar:
        members = tar.getmembers()
        names = [m.name for m in members]
        if len(names) != len(set(names)) or len(names) > 2000:
            raise ValueError("duplicate members or too many files")
        if sum(m.size for m in members) > 256 * 1024 * 1024:
            raise ValueError("archive exceeds development evidence size limit")
        for member in members:
            name = pathlib.PurePosixPath(member.name)
            if not member.isfile() or name.is_absolute() or ".." in name.parts:
                raise ValueError("unsafe archive member")
        manifest_file = tar.extractfile("V02_EVIDENCE_MANIFEST.json")
        if manifest_file is None:
            raise ValueError("manifest missing")
        manifest = json.load(manifest_file)
        if manifest.get("schema") != "tactus-v02-release-bundle-v1" or manifest.get("tag") != "v0.02":
            raise ValueError("wrong bundle schema or tag")
        if expected_commit is not None and manifest["source_commit"] != expected_commit:
            raise ValueError("release commit mismatch")
        if set(names) != set(manifest["files"]) | {"V02_EVIDENCE_MANIFEST.json"}:
            raise ValueError("manifest membership mismatch")
        for name, record in manifest["files"].items():
            stream = tar.extractfile(name)
            if stream is None:
                raise ValueError(f"missing file: {name}")
            data = stream.read()
            if len(data) != record["bytes"] or hashlib.sha256(data).hexdigest() != record["sha256"]:
                raise ValueError(f"integrity mismatch: {name}")
        return {"verified_files":len(manifest["files"]),"source_commit":manifest["source_commit"],"proof_validity_checked":False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=pathlib.Path)
    parser.add_argument("--commit", help="expected Git commit of release tag")
    args = parser.parse_args()
    print(json.dumps(verify(args.archive, args.commit), indent=2))


if __name__ == "__main__":
    main()
