#!/usr/bin/env python3
"""Independent standard-library wire/hash vectors; no prover or network calls."""
import argparse
import hashlib
from pathlib import Path


def n(value, size=8):
    return value.to_bytes(size, "little")


def repeat(value, size=32):
    return bytes([value]) * size


def digest(domain, body):
    return hashlib.blake2b(domain + body, digest_size=32, person=b"ckb-default-hash").digest()


def commitment(body):
    return digest(b"tactus/0.02/object", body)


def blob(body):
    return n(len(body), 4) + body


def vectors():
    policy = (b"T02POL01" + n(4, 1) + b"".join(n(v) for v in [32, 32, 120, 250000, 200000])
              + b"".join(repeat(v) for v in range(1, 6)))
    domain = digest(b"tactus/0.02/genesis", repeat(6, 44) + n(0))
    config = (b"T02CFG01" + domain + repeat(7) + repeat(8) + repeat(9)
              + commitment(policy) + repeat(10) + n(71402) + repeat(11, 20))
    c = commitment(config)
    cursor = n(0) + n(0, 16) + digest(b"tactus/0.02/deposits/empty", c)
    boundary = (b"T02BND01" + c + n(0) + bytes(32) + n(0) + n(0) + cursor
                + bytes(32) + n(0) + bytes(32) + bytes([0, 0, 8]))
    control = b"T02CTL01" + bytes([0, 0]) + commitment(policy) + repeat(2) + boundary + bytes(96)
    deposit = b"T02DEP01" + c + n(1) + repeat(23, 20) + n(7) + repeat(24) + n(7, 16) + cursor[24:]
    deposit_end = n(1) + n(7, 16) + commitment(deposit)
    payload = bytes([1, 0])
    admission = b"T02ADM01" + c + n(0, 1) + n(0) + n(0) + digest(b"tactus/0.02/payload", payload)
    lanes = []
    for lane in range(4):
        history = digest(b"tactus/0.02/lane/empty", c + n(lane, 1))
        if lane == 0:
            history = digest(b"tactus/0.02/lane/append", history + commitment(admission))
        lanes.append(b"T02LAN01" + c + n(lane, 1) + n(0) + n(lane == 0) + history
                     + n(lane == 0, 1) + (n(0) + blob(payload) if lane == 0 else b""))
    snapshot = b"T02SNP01" + c + n(1) + n(4, 1) + b"".join(blob(lane) for lane in lanes) + cursor + deposit_end
    schedule = b"T02SCH01" + c + n(1) + commitment(snapshot) + bytes(3)
    batch = (b"T02BAT01" + boundary + commitment(snapshot) + n(1, 1) + n(0, 1) + n(0) + blob(payload)
             + n(1, 1) + deposit + n(1, 1) + n(100) + repeat(29, 20) + n(1, 4) + blob(payload))
    successor = (b"T02BND01" + c + n(1) + commitment(batch) + n(1) + n(100) + deposit_end
                 + n(1) + n(0) * 3 + n(1) + commitment(snapshot) + bytes([1, 1, 1]))
    schedule_next = b"T02SCH01" + c + n(1) + commitment(snapshot) + bytes([1, 1, 1])
    settled = (b"T02CTL01" + bytes([0, 1]) + commitment(policy) + repeat(2) + successor
               + repeat(17) + repeat(18) + n(7, 16) + n(0, 16))
    journal = b"T02JRN01" + control + settled + repeat(19) + repeat(20)
    watch = b"T02WCH01" + c + bytes([1, 0]) + n(1) + repeat(21, 36) + commitment(control) + repeat(22)

    def leaf(kind, key=None):
        return digest(b"tactus/0.02/claim/leaf", c + bytes([kind, key is not None]) + (key or b""))

    def branch(level, left, right):
        return digest(b"tactus/0.02/claim/branch", n(level, 2) + left + right)

    roots = []
    for kind in range(3):
        root = leaf(kind)
        for level in range(256):
            root = branch(level, root, root)
        roots.append(root)
    vault = b"T02VLT01" + c + n(1000) + cursor + bytes(48) + b"".join(roots)
    vault_deposit = b"T02VLT01" + c + n(1000) + deposit_end + bytes(48) + b"".join(roots)
    key = digest(b"tactus/0.02/claim/key", c + bytes([1]) + n(1))
    root = leaf(1, key)
    default = leaf(1)
    for level in range(256):
        bit = 255 - level
        root = branch(level, default, root) if key[bit // 8] & (1 << (7 - bit % 8)) else branch(level, root, default)
        default = branch(level, default, default)
    # Claim framing is independent of cryptographic authorization. These small
    # witnesses use structural MPT placeholders, not valid asset proofs.
    nullifier = b"T02NUL01" + bytes(36)
    state_claim = (b"TO1EVMR1" + repeat(17) + repeat(18) + n(1) + repeat(12, 20)
                   + bytes([1, 0, 0, 0]) + n(1) + (2).to_bytes(32, "big")
                   + repeat(25) + repeat(26) + repeat(27) + (3).to_bytes(32, "big"))
    state_proof = state_claim + blob(b"TO1MPW01" + bytes(4))
    prefix = lambda kind: b"T02CLM01" + n(kind, 1) + n(1, 4) + repeat(21, 36)
    claim_release = prefix(0) + n(1) + n(7) + repeat(24) + repeat(23, 20) + state_proof + blob(nullifier)
    claim_refund = prefix(1) + repeat(22, 36) + blob(nullifier)
    claim_escape = (prefix(2) + repeat(23, 20) + n(7) + repeat(24) + repeat(1, 64) + bytes(1)
                    + state_proof + state_proof + blob(nullifier))
    return dict(policy=policy, config=config, boundary=boundary, control=control, vault=vault,
                deposit=deposit, vault_deposit=vault_deposit, admission=admission, lane=lanes[0],
                snapshot=snapshot, schedule=schedule, batch=batch, successor=successor,
                schedule_next=schedule_next, settled=settled, journal=journal, watch=watch,
                nullifier=nullifier, refund_key=key, refund_root=root,
                claim_release=claim_release, claim_refund=claim_refund, claim_escape=claim_escape,
                frame=b"T02FRM01" + blob(snapshot) + blob(batch))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="check committed vectors without writing")
    args = parser.parse_args()
    target = Path(__file__).resolve().parents[1] / "specs/test-vectors/v02.txt"
    content = "".join(f"{name}={body.hex()}\n" for name, body in vectors().items())
    if args.check:
        if not target.exists() or target.read_text() != content:
            raise SystemExit("v02 vectors differ; inspect before regenerating")
    else:
        target.write_text(content)
    print(f"{'Verified' if args.check else 'Wrote'} {len(vectors())} independent v02 vectors")


if __name__ == "__main__":
    main()
