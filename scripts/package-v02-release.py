#!/usr/bin/env python3
"""Package pinned local 0.02 evidence for a release; never prove or deploy."""
import argparse
import gzip
import hashlib
import io
import json
import pathlib
import re
import subprocess
import tarfile

ROOT = pathlib.Path(__file__).resolve().parents[1]


def digest(data):
    return hashlib.sha256(data).hexdigest()


def collect():
    files = set()
    def path(value):
        if not isinstance(value, str):
            return
        relative = value.removeprefix(str(ROOT) + "/")
        if len(relative) >= 512 or not relative.startswith(("artifacts/", "proofs/")):
            return
        candidate = ROOT / relative
        if candidate.is_file() and candidate.resolve().is_relative_to(ROOT):
            files.add(relative)
    def walk(value):
        if isinstance(value, dict):
            for key, item in value.items():
                if key.startswith("artifacts/") and isinstance(item, str) and re.fullmatch(r"[0-9a-f]{64}", item):
                    if not (ROOT / key).is_file() or digest((ROOT / key).read_bytes()) != item:
                        raise ValueError(f"historical artifact mismatch: {key}")
                path(key)
                walk(item)
            if isinstance(value.get("sha256"), str):
                for key in ("path", "log"):
                    name = value.get(key)
                    if isinstance(name, str) and name.startswith(("artifacts/", "proofs/")):
                        if digest((ROOT / name).read_bytes()) != value["sha256"]:
                            raise ValueError(f"pinned artifact mismatch: {name}")
        elif isinstance(value, list):
            for item in value:
                walk(item)
        else:
            path(value)
    for record in sorted((ROOT / "specs/test-vectors").glob("v02-*-validation.json")):
        files.add(str(record.relative_to(ROOT)))
        walk(json.loads(record.read_text()))
    for name in ["artifacts/tactus_v02_script.elf", "artifacts/tactus_o1_head_lock.elf", "artifacts/tactus_o1_native_anchor_script.elf"]:
        if not (ROOT / name).is_file():
            raise ValueError(f"required executable missing: {name}")
        files.add(name)
    for log in (ROOT / "artifacts").glob("v02-release-*.log"):
        files.add(str(log.relative_to(ROOT)))
    return sorted(files)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=pathlib.Path, help="new output directory")
    args = parser.parse_args()
    status = subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT, text=True)
    if status:
        raise ValueError("commit reviewed release sources before packaging")
    commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    timestamp = int(subprocess.check_output(["git", "show", "-s", "--format=%ct", "HEAD"], cwd=ROOT, text=True))
    files = collect()
    payload = {name: (ROOT / name).read_bytes() for name in files}
    manifest = {
        "schema": "tactus-v02-release-bundle-v1", "tag": "v0.02", "source_commit": commit,
        "scope": "isolated-development evidence; historical tests and executions, not new proof settlement",
        "files": {name: {"sha256": digest(data), "bytes": len(data)} for name, data in payload.items()},
        "ci_run": False, "riscv_contract_experiment_executed": False,
        "node_databases_included": False,
    }
    payload["V02_EVIDENCE_MANIFEST.json"] = (json.dumps(manifest, indent=2) + "\n").encode()
    args.output.mkdir(parents=True, exist_ok=False)
    archive = args.output / "tactus-v0.02-evidence.tar.gz"
    with archive.open("xb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as zipped:
            with tarfile.open(fileobj=zipped, mode="w") as tar:
                for name, data in sorted(payload.items()):
                    item = tarfile.TarInfo(name)
                    item.size = len(data)
                    item.mtime = timestamp
                    item.mode = 0o644
                    tar.addfile(item, io.BytesIO(data))
    (args.output / "V02_EVIDENCE_MANIFEST.json").write_bytes(payload["V02_EVIDENCE_MANIFEST.json"])
    checksums = []
    for name in [archive.name, "V02_EVIDENCE_MANIFEST.json"]:
        checksums.append(f"{digest((args.output / name).read_bytes())}  {name}\n")
    (args.output / "SHA256SUMS").write_text("".join(checksums))
    print(json.dumps({"source_commit":commit,"files":len(files),"archive_bytes":archive.stat().st_size,"output":str(args.output)}))


if __name__ == "__main__":
    main()
