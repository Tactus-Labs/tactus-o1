# CKB prime-field multiplication

This is the crates.io `substrate-bn-succinct-rs` 0.6.0 source, pinned by
`upstream.crate`, `UPSTREAM.json` and `UPSTREAM_SHA256.json`.

The upstream CPU multiplication computes a 512-bit product then reduces it by
512 iterations of binary long division. On CKB that dominates pairing cost.
The port dispatches **only canonical operands for the exact BN254 base or
scalar modulus** to `ark-ff` 0.5.0's portable Montgomery arithmetic. It converts
into Montgomery representation with `from_bigint`, multiplies, then converts
back with `into_bigint`. No Montgomery value escapes the helper, so all existing
field representations, serialization, curve operations and pairings retain
their contracts. No CPU assembly feature or CKB protocol extension is used.

Unrecognized moduli and noncanonical operands retain the original reducer.
This matters for upstream constructors that reduce arbitrary integers. The
original reducer is also preserved as a differential oracle. Tests compare
the fast and fallback paths against both that reducer and `num_bigint` for
edge values and 8,192 seeded products across the two fields. Including the
edge/fallback matrix gives 8,321 compared products.

Changes: one dependency/lint addition in `Cargo.toml`, a dispatch in
`src/arith.rs`, and `src/arith/ckb_mul.rs`. The other upstream files are unchanged.
The original arithmetic/group/pairing tests run alongside the new tests (39
tests total). SP1 prover/guest workspaces do not select this patch.

See `specs/VERIFIER_CYCLE_OPTIMIZATION_REPORT.md`. This port changes a critical
arithmetic implementation and requires independent review before production;
the local differential and real-proof checks are evidence, not a formal proof.
