# CKB public-input accumulation

This is the crates.io `sp1-verifier` 6.8.1 source. `upstream.crate`,
`UPSTREAM.json` and `UPSTREAM_SHA256.json` retain its checksum and provenance.
Only `src/groth16/verify.rs` differs from upstream.

`prepare_inputs` now borrows the key and accumulates `k[0] + sum(k[i+1] * input[i])`
using the existing Jacobian `bn::G1` operations. Upstream's `AffineG1` scalar
multiplication converts back to affine after every double and addition, each
requiring a field inversion. The new path normalizes at the pairing boundary.
The input-count check and zero-scalar handling remain in place.

The test compares both paths using the released verification key, scalar edges
and 32 deterministic dense input vectors. The proof decoder, public-input
hashing including SHA-256/Blake3 fallback, exit-code/root checks, released keys,
point checks and pairing equation are unchanged.

Only the three CKB verifier workspaces select this port. SP1 guests and proving
hosts retain their original dependencies and keys. Changed CKB ELF bytes create
new script identities; old proofs cannot simply be relabeled for a new deployment.

See `specs/VERIFIER_CYCLE_OPTIMIZATION_REPORT.md` and run the local provenance
and differential checks documented there. No CI or new proof generation is
needed for those checks. This is an independently maintained source patch, not
an upstream-audited release.
