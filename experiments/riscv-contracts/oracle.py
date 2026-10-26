#!/usr/bin/env python3
"""Prepared independent big-integer oracle; not invoked during preparation."""
import hashlib
import json
import pathlib


def expected(seed_hex, steps):
    if len(seed_hex) != 64 or type(steps) is not int or not 0 <= steps < 2**32:
        raise ValueError("input width")
    seed = bytes.fromhex(seed_hex)
    value = int.from_bytes(seed, "big")
    success = steps <= 4096
    if success:
        for _ in range(steps):
            value = (3 * value + 1) % (2**256)
    output = value.to_bytes(32, "big")
    journal = b"TARVR001" + seed + steps.to_bytes(4, "little") + bytes([success]) + output
    return success, output.hex(), hashlib.sha256(journal).hexdigest()


def main():
    vectors = json.loads((pathlib.Path(__file__).parent / "vectors.json").read_text())
    for vector in vectors["vectors"]:
        success, output, digest = expected(vector["seed_hex"], vector["steps"])
        if (success, output) != (vector["success"], vector["output_hex"]):
            raise ValueError(f"independent oracle mismatch: {vector['id']}")
        print(json.dumps({"id":vector["id"],"journal_sha256":digest}))


if __name__ == "__main__":
    main()
