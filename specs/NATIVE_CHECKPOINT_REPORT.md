# Immutable native custody history checkpoints

Status: actual CKB 0.210.0 transition qualification; no proof settlement or
withdrawal. G1–G9 remain OPEN.

The v1 checkpoint stores only a 200-byte ordering anchor and cannot authenticate
the native custody config or deposit cursor. The new isolated
`proofs/ckb-native-checkpoint` program stores the complete **428-byte `TO1NAP02`**
state: 164-byte vault config followed by the 256-byte native ordering anchor and
cursor. Type args are `TO1NCP02 || trusted_anchor_type_hash` (40 bytes), with Data1
hash type. A settlement verifier must pin both this program and the complete
trusted anchor identity; caller-selected arguments alone confer no authority.

Creation requires exactly one checkpoint output in its type group, no checkpoint
inputs, and exactly one input and output carrying the named anchor type hash.
Thus the actual anchor program executes in the same transaction and authenticates
the funded receipts and whole publication wrapper. A live anchor or historical
checkpoint supplied only as a dependency is insufficient. The checkpoint bytes
must equal the complete output anchor state. Defense-in-depth checks enforce
unchanged config/domain, exactly one batch increment, increasing block/time and
a coherent deposit cursor, with at most 32 new records. Input/output scans are
bounded at 64 cells and data loads at 428 bytes.

Every later attempt to consume this checkpoint fails, including identical
recreation. Experiment outputs use the permissionless head lock bound to their
checkpoint type hash, so the negative controls reach the checkpoint type program
without relying on a missing signature. No owner can rewrite or reclaim the
record. This intentionally costs permanent capacity; production archival economics
and any future authenticated pruning scheme remain unresolved.

## Actual node evidence

Archive: `specs/evidence/native-checkpoint/0.210.0`, raw run
`artifacts/native-checkpoint-ApK8qvfW`. The isolated node used ports 18744/18745
and was stopped by its launcher. No existing node was contacted.

- Program SHA-256: `f936a2cac813694359acf22cc9899cb8bbe0a674e322764dfd33836c58eb307a`.
- Program Data1 hash: `3e9faaf6e62593e756a28f5c5bc2f1f30e4932d3f99e076583ee9979c3416218`.
- **11 committed transactions and 43 exact script rejections**. These include all
  27 original publication controls and 16 checkpoint-specific controls.
- Each of two authenticated publications creates a 574 CKB checkpoint. The
  598 CKB anchor reserve stays fixed; the vault ends at 640 CKB, including 250 CKB
  deposited principal. Every transaction's 1 CKB fee comes from external funding.
- First publication: 2,041,391 cycles, 2,612 wire bytes,
  `0xcdecc54f1e55ecbc284b02c339d6bc3a92f67a62d1b952ae4a9cf24061f3bed3`.
- Second publication: 2,083,583 cycles, 2,612 wire bytes,
  `0x3d3703e77df27dab506def2e35866caafa0b23e0a0031f8e4664c78ea4fd8063`.
- The first checkpoint remains live with identical data after the second
  publication. Both signed burns still match independent Geth execution; cold
  custody recovery finds the exact two original funded records and vault state.

Checkpoint controls reject dependency-only creation, old state, forged cursor,
changed custody config, wrong publication commitment, truncation, duplicate
outputs, wrong anchor identity, wrong argument domain, zero identity and old
200-byte wire data. Both checkpoints reject destruction and consume/recreate.
The final control rejects creation from a historical checkpoint dependency.
Every rejection is checked against the exact deployed checkpoint program, error
code and input/output type-group source, not merely any transaction failure.

Two Rust test groups exercise actual state pairs, every immutable-domain byte,
cursor regression, unchanged cursors, bounded record counts and batch overflow.
The independent archive auditor joins checkpoint outputs to real anchor updates,
program deployment, exact full type/lock identity, occupied capacity, live cells,
funded receipts, fee flows, Geth roots and rejection provenance. Fourteen forged
archive variants are rejected. Manifests and audits are consistency evidence,
not substitutes for CKB consensus or proof verification.

## Reproduction and remaining integration

```sh
cargo test --locked --manifest-path proofs/ckb-native-checkpoint/Cargo.toml
bash scripts/build-native-checkpoint-script.sh
CKB_BIN=/path/to/ckb-0.210.0 TACTUS_DEVNET_SUITE=replay-native-checkpoint \
  bash scripts/run-devnet-experiments.sh
# For the emitted RUN directory:
(cd services/bridge-checker && \
  TACTUS_NATIVE_PUBLICATION_VECTOR=/absolute/RUN/execution.json \
  TACTUS_NATIVE_PUBLICATION_GETH_EXPORT=/absolute/RUN/geth.json \
  go test -count=1 -mod=readonly -run TestPublishedNativeExecutionAgainstGeth .)
python3 -B scripts/check-native-publication.py /absolute/RUN
python3 -B scripts/test-native-checkpoint.py
```

The [native settlement verifier](NATIVE_SETTLEMENT_REPORT.md) now authenticates
these checkpoints, matches the 940-byte native journal and enforces previous
root/header continuity. Its successful new-proof settlement path remains
unqualified. Its new joint deployment binds an actual settlement type; this
earlier checkpoint run retains the intentionally uninstantiated settlement
hash of the publication experiment. Real custody payouts, native A3
obligations, full recovery/RPC, reorg qualification and production cost/liveness
remain required. Checkpoint immutability on this branch is not a finality or
reorg-recovery claim.
