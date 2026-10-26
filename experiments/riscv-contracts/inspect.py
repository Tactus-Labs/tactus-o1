#!/usr/bin/env python3
"""Read-only experiment metadata/results. Never launches builds, workloads or provers."""
import argparse
import json
import math
import pathlib
import re

BASE = pathlib.Path(__file__).resolve().parent


def read(path):
    raw = pathlib.Path(path).read_bytes()
    if len(raw) > 2 * 1024 * 1024:
        raise ValueError("metadata exceeds 2 MiB")
    return json.loads(raw)


def compare(left, right):
    if [left.get("arm"), right.get("arm")] != ["evm", "native"]:
        raise ValueError("provide EVM then native records")
    for record in [left, right]:
        if record.get("schema") != "tactus-riscv-research-result-v1":
            raise ValueError("unknown result schema")
        if record.get("status") not in ["executed", "proved"]:
            raise ValueError("unexecuted template is not a result")
        for name in ["request_sha256", "semantic_result_sha256", "guest_elf_sha256", "source_snapshot_sha256"]:
            if not re.fullmatch(r"[0-9a-f]{64}", record.get(name) or ""):
                raise ValueError(f"missing digest: {name}")
        for name in ["stage", "guest_key", "hardware_id", "software_id", "scope_id", "patch_policy_id", "proof_mode", "threads", "repetition"]:
            if record.get(name) is None:
                raise ValueError(f"unrecorded comparison control: {name}")
        counts = record.get("counts", {})
        for name in ["batches", "blocks", "calls", "prefix_batches"]:
            if type(counts.get(name)) is not int or counts[name] < 0:
                raise ValueError(f"invalid workload count: {name}")
    for name in ["status", "stage", "request_sha256", "semantic_result_sha256", "hardware_id", "software_id", "scope_id", "patch_policy_id", "proof_mode", "threads", "repetition", "counts"]:
        if left[name] != right[name]:
            raise ValueError(f"unmatched comparison: {name}")
    proved = left["status"] == "proved"
    if proved:
        for record in [left, right]:
            if record.get("proof_generated") is not True or record.get("proof_verified") is not True:
                raise ValueError("proof not independently verified")
            for name in ["proof_artifact_sha256", "verification_log_sha256"]:
                if not re.fullmatch(r"[0-9a-f]{64}", record.get(name) or ""):
                    raise ValueError(f"missing proof evidence digest: {name}")
    names = ["execute_ms"]
    if proved:
        names += ["end_to_end_ms", "independent_verify_ms"]
    ratios = {}
    for name in names:
        values = [r.get("measurements", {}).get(name) for r in [left, right]]
        if any(type(v) not in [int, float] or not math.isfinite(v) or v <= 0 for v in values):
            raise ValueError(f"missing positive measured time: {name}")
        ratios[name] = values[0] / values[1]
    return {"scope":"single matched sample; no statistical or product conclusion", "evm_over_native_time_ratio":ratios,
            "proof_comparison":proved,"claimed_tactus_throughput":None}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("plan", help="print prepared metadata; no execution")
    paired = sub.add_parser("compare", help="compare two already-produced records")
    paired.add_argument("evm")
    paired.add_argument("native")
    args = parser.parse_args()
    value = read(BASE / "plan.json") if args.command == "plan" else compare(read(args.evm), read(args.native))
    print(json.dumps(value, indent=2))


if __name__ == "__main__":
    main()
