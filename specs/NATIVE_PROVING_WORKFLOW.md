# Native proof generation and retained-chain settlement workflow

Status: proving/resume tooling; positive real native proof settlement remains
unqualified until actual receipts are retained. This document is not a claim
that a proof has completed. Production gates remain open.

`proofs/native-prover` is a separate host-tool workspace. Its addition does not
change the fixed native guest's workspace lockfile, binary or key. It reuses SP1
6.8.1 with the released 6.1.0 Groth16 circuit and pins the same toolchain/settings
as the already qualified v1 local proof experiment. The host first independently
replays the entire allocation/prefix/interval, compares the declared journal,
checks the ELF's key, executes the actual guest and compares all 940 output bytes.
Only then does it invoke the real local CPU prover. No mock backend is used.

The default staged mode durably retains a completed recursive witness before
terminating its own recursive child and starting the final wrapper in a fresh
process. That wrapper verifies guest key, public-value digest, zero exit/nonce,
release VK root and actual Groth16 proof. Twenty public-field mutations and a
wrong guest key must all fail. The launcher then runs SDK verification again in
a fresh process against the exact canonical input export. The shared handoff
script now accepts an explicit wrapper executable; its v1 default is unchanged.
Monolithic mode remains selectable, without claiming it has completed here.

## Two consecutive intervals

Use the actual joint-deployment input from `NATIVE_SETTLEMENT_REPORT.md`.
Derive a first-batch input by replaying the source export, validating its original
journal, then selecting the contiguous range `[0,1)`. The existing prefix-one
export covers `[1,2)` after reconstructing the full first batch. This lets the
second actual settlement exercise preceding-checkpoint and previous-root binding.
The helper never asserts CKB authentication; the retained source must be audited
separately.

```sh
cargo run --locked --manifest-path proofs/native-sp1/Cargo.toml \
  -p tactus-o1-native-proof-journal --example interval-input -- \
  /absolute/BOOTSTRAP/proving-input-0.json 0 1 > /absolute/FIRST_INPUT.json
SP1_GROTH16_CIRCUIT_PATH=/absolute/released-circuit-parent \
  bash scripts/run-native-chain-proof.sh /absolute/FIRST_INPUT.json
# The same launcher can later prove BOOTSTRAP/proving-input-1.json.
```

Requirements: Rust 1.97.1 for host tools, pinned native guest built by
`build-native-proof-guest.sh`, Go/native gnark build dependencies and actual
released circuit files under `v6.1.0/`. The launcher takes the shared local proof
lock, records binary/source/input/VK hashes and runtime settings, and never
restarts a prover just because a log stops changing.

## Resume the owned chain

`run-native-settlement-proof.sh BOOTSTRAP_RUN INPUT_JSON VERIFIED_PROOF_DIR`
reopens the original retained isolated node database. It checks CKB 0.210.0,
original node/spec hashes, loopback ports excluding 8114, free listen ports,
an exclusive resume lock and indexer readiness. Cleanup stops only its own child.
It does not deploy another chain or replace the original anchor/vault/Tip.

The `settle-native-proof` driver verifies the real Groth16 proof and native replay
before contacting the node. It then checks actual genesis/domain, exact live Tip,
pinned deployed code cells and complete live checkpoint boundaries. Another
funded actor signs the fee input. Intended qualification includes actual
settlement plus missing/forged checkpoint, changed proof/root and replay controls;
subsequent intervals also exercise missing/forged predecessor checkpoints.
A successful result must observe the old Tip dead and the exact new Tip live.
The script reports no custody payout; that still needs separate MPT exit tests.

The driver compiled and passed clippy. A retained real v1 proof paired with the
native first-batch journal was rejected by the actual cryptographic verifier
before RPC and without writing a settlement receipt. This verifies the early
rejection path only; successful on-chain behavior requires the new proof.
