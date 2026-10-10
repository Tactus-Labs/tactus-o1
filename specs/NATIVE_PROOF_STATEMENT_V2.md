# Native custody execution statement v2

Status: execution qualification, not proof settlement. G1–G9 remain OPEN.
The isolated `proofs/native-sp1` workspace enables the native bridge executor
without changing the existing v1 proof workspace, root lockfile or guest.
All shared dependency versions are inherited unchanged from the v1 proof lock.

## Statement and trust boundary

The `TO1NPR02` public journal is exactly 940 bytes. Integers inside config,
anchors and cursors retain their existing canonical little-endian encodings.

| Offset | Bytes | Field |
| --- | ---: | --- |
| 0 | 8 | `TO1NPR02` |
| 8 | 32 | native proof profile hash |
| 40 | 164 | complete `TO1VAU01` custody configuration |
| 204 | 32 | authenticated ordering type hash |
| 236 | 32 | canonical genesis allocation commitment |
| 268 | 256 | previous ordering anchor and deposit cursor |
| 524 | 256 | next ordering anchor and deposit cursor |
| 780 | 32 | previous Ethereum state root |
| 812 | 32 | next Ethereum state root |
| 844 | 32 | previous Ethereum header hash |
| 876 | 32 | next Ethereum header hash |
| 908 | 32 | native interval digest |

The program pins the native vault Data1 code hash
`3b0c9f82f019407ad1784fcf0d62fe695eba3cf235c2e8ce474af5aebbe39237`.
Full config therefore also determines the custody type hash. There is no
caller-selected custody code. The profile, envelope, interval hash and guest
identity are distinct from v1. Both anchors must use the native execution rules.
The decoder rejects empty/reversed intervals, invalid genesis cursors, decreasing
monetary/count cursors and inconsistent unchanged cursors.

The guest replays the canonical allocation and the complete prefix before
executing a nonempty interval. It accepts no initial EVM snapshot or deposit
cursor from the prover. Every deposit must match its transcript accumulator;
credit calls and signed user transactions use the native executor and its token
conservation checks. The full wrapper bytes determine the interval digest.

This proves execution only when a real cryptographic proof is generated and
verified. Neither native replay nor zkVM execution verifies CKB consensus or
receipt liveness. A future settlement program must authenticate both boundary
anchors, the allocation, ordering type, full config and its own settlement
identity, then enforce previous-root/header continuity and verify the pinned
guest's proof. Matching arbitrary caller-selected config is insufficient.
The current archived config still names an uninstantiated settlement hash.

## Qualification

The test inputs use the exact two published batches and allocation from
[NATIVE_PUBLICATION_REPORT.md](NATIVE_PUBLICATION_REPORT.md). They include two
real funded deposits totaling 250 CKB and signed burns totaling 90 CKB. Native
statement tests compare both segment roots with the independent Geth archive,
both boundaries with actual publication anchors, and the header hashes with the
independently checked execution vectors. Whole-range replay and prefix-one replay
must end at identical state/header/cursor values.

Five test groups cover these positive comparisons, missing/reordered/repeated
batches, changed deposit amount/recipient/accumulator, every custody-domain field,
allocation changes, seeded token storage, malformed/truncated journal/domain,
empty ranges and count overflow. The ordering type is external authority: changing
it changes the public statement, even though it does not change EVM execution.

Actual retained runs are in `specs/evidence/native-guest/execution`:

- Guest ELF SHA-256: `dba570acf089f81e396a8daef4b96a5ab1da33cb906a62ed8e3e9854076249a5`.
- Guest verification key: `0x00d159402000943b66d0df65c2c154592efbc8490b1ee44dfce8a181cd5e77e5`.
- Full two-batch execution: 44.885 seconds including setup.
- Prefix-one / interval-one execution: 45.599 seconds including setup.
- Both public journals match independently reconstructed bytes; 13 forged
  evidence variants are rejected, including coordinated root/cursor edits.

The local CPU runner compares real SP1 6.8.1 guest output byte-for-byte with native
execution and the declared expected journal. Its result explicitly reports
`proof_generated=false`, `ckb_settlement=false`, `custody_release=false`.
The separate Python auditor reconstructs the public bytes from the actual
publication archive and independent Geth roots. It also reruns the publication
auditor; this remains evidence consistency checking, not proof verification.

```sh
cargo test --locked --manifest-path proofs/native-sp1/Cargo.toml \
  -p tactus-o1-native-proof-journal
cargo clippy --locked --manifest-path proofs/native-sp1/Cargo.toml \
  -p tactus-o1-native-proof-journal --all-targets -- -D warnings
bash scripts/run-native-guest-experiment.sh
```

Guest compilation requires the pinned official SP1 CLI and succinct toolchain,
as the existing proof experiment does. Host SDK compilation uses Rust 1.97.1;
statement tests use Rust 1.92. The experiment exclusively reads the retained
CKB 0.210.0 evidence and does not connect to an existing node.

## Remaining work

Native checkpoints now have [actual transition qualification](NATIVE_CHECKPOINT_REPORT.md).
[Native settlement bootstrap](NATIVE_SETTLEMENT_REPORT.md) now binds a real
settlement type in a fresh joint deployment. Generate and independently verify
a new cryptographic proof, positively qualify native settlement, and execute
real CKB withdrawals against proven nonzero burn commitments. Native A3
obligations, recovery, observer RPC and reorg qualification also remain required. The v1 proof cannot authorize native custody, and the new
execution evidence does not close those production gates.
