# Comprehensive optimization — round three, in progress

Date: 2026-10-15. Goal: 好的全面优化. This report is provisional: the resource
matrix is complete, and incremental/sparse proving and settlement integration are
not complete. No CI or deployment. Baseline is the completed round-two result,
not the older unpatched guest.

## Implemented and execution-qualified candidates

The frozen `artifacts/sp1-optimization-round3/adaptive/source` candidate reuses
completed block state roots and cached header hashes, collects validated borrowed
transaction slices in one parser pass, and avoids recomputing state roots when
no accepted transaction or native deposit changed state. Empty blocks still
advance headers, time and base fees. Reverted/halted accepted transactions still
count as state changes because their gas/nonce effects persist.

Native execution rules and immutable bridge bytecode are generated at build time
from the exact pinned files. Reference tests confirm the old hash expression and
runtime bytecode for multiple domains. Root Cargo.lock and execution rules hashes
are unchanged; guest keys are not assumed unchanged.

A rollback guard protects account/code writes, headers and anchors. Large states
retain first-written accounts/code rather than cloning the whole database. Small
states use a bounded snapshot (at most eight accounts, eight code entries and 32
storage slots). Unconditional journaling increased small-state transfer instructions
by about 1.3%, so it was not adopted unconditionally. Reads use the complete
database's immutable interface and do not insert absent account/slot cache entries.
Rollback and panic-unwind tests pass. The journal currently still copies a touched
account's storage; fine-grained/sparse state work remains.

The candidate matches an unchanged native oracle on 25 independently Geth-checked
cases / 93 blocks, plus the retained chain input. This includes eight new cases
separating total state size, writes and empty blocks. Two native custody guest
inputs (full interval and prefix continuation) match their old journals exactly.

| Workload | Round-two instructions | Frozen adaptive instructions | Reduction |
|---|---:|---:|---:|
| Retained chain input | 1,435,772 | 1,167,477 | 18.69% |
| 32 transfers, small state | 4,074,217 | 3,978,052 | 2.36% |
| 512 added accounts, 32 transfers | 25,094,450 | 16,347,042 | 34.86% |
| 512 added accounts, 16 empty blocks | 86,615,888 | 8,727,408 | 89.92% |
| 1,024 storage slots, eight writes | 30,839,661 | 19,478,638 | 36.84% |
| Native full retained input | 21,101,594 | 1,659,332 | 92.14% |
| Native prefix retained input | 21,102,096 | 1,611,839 | 92.36% |

These are combined execution gains, not proving-time gains or savings attributable
solely to rollback. Isolating the initial journal from the reuse candidate gives
small and workload-dependent changes: for example, 512-account transfers improve
by 0.30%, while 128-account transfers regress by 0.65%. The large gains in the
table primarily come from eliminating redundant hashing/root construction.

## Verification and full-proof resource experiments

`chain-proof verify-pinned TRUSTED_GUEST_KEY INPUT_JSON PROOF_DIR` independently
replays the input and verifies the actual Groth16 wire proof against that journal
and an independently supplied deployment key. It avoids CPU prover initialization.
The original SDK/ELF `verify` mode remains unchanged as a separate qualification
oracle. The key must come from authenticated configuration, not merely the export.

Both actual round-two proofs pass three fresh-process runs each at approximately
0.20–0.21 seconds total. Wrong pinned keys, wrong keys in both supplied locations,
changed journals, mismatched valid intervals, altered/truncated/oversized wire
proofs all reject. This is verification of existing proofs, not a new proof.

Three new complete 32-transfer proofs run serially with the same frozen adaptive
ELF/input: four CPU threads/two Go threads; eight/four; eight/four with the shard
size reduced from 1,048,576 to 524,288. Worker counts and buffer sizes remain one.
The runner pins its binary/ELF/scripts and retains machine memory snapshots,
phase timings, fifteen negative controls and fresh SDK verification. Results are
recorded in `artifacts/sp1-optimization-round3/matrix-progress.json`.

The four-thread run completed with a real Groth16 proof, all fifteen negative
controls and independent fresh-process SDK verification. Comparable recursive
plus final wrapping/verification time is **1,600.402 seconds (26m40.4s)**, versus
round two's 1,607.494 seconds on the same 32-transfer workload: a difference of
only **0.44%**, insufficient evidence of a material latency improvement from a
single run. Pipeline wall time is 1,601.044 seconds; including the additional
fresh-process verification it is 1,640.305 seconds (27m20.3s). Recursive maximum
RSS is 20,488,400 KiB. Build/preparation are excluded, consistently with the prior
comparison. The eight-thread / 1,048,576-shard run also completed with all fifteen negative
controls and fresh SDK verification. Comparable time is **1,156.604 seconds
(19m16.6s)**; including fresh verification it is **1,185.620 seconds (19m45.6s)**.
That is a **27.73%** comparable reduction from the four-thread run, with one sample
per configuration. Recursive maximum RSS is 20,640,392 KiB. The smaller-shard configuration also completed with all fifteen negatives and
fresh verification: **1,146.884 seconds** comparable and **1,177.464 seconds
(19m37.5s)** including fresh verification, with recursive maximum RSS
21,250,924 KiB. Its comparable improvement over the other eight-thread run is
only **0.84%** and it uses more peak memory; this is insufficient evidence of a
stable advantage. Follow-up sparse proofs will use eight CPU/four Go threads
and the original 1,048,576 shard size. These results validate the frozen adaptive
candidate, not the newer sparse/generic-backend source.

## Initial sparse candidate: implementation and qualification

The initial frozen sparse candidate uses a generic state backend shared by complete replay and
sparse execution. Complete checkpoints authenticate state, code and an exact
linked BLOCKHASH window of up to 256 headers against a supplied boundary. Sparse
execution authenticates account/storage reads and updates against Ethereum MPT
roots and code against its hash. Missing nodes/code are fatal; verified absence
is distinct from missing evidence. Deletion also requires the sibling evidence
needed to collapse a branch. Failed batches restore roots, headers and boundaries.

The host discovers a pruned witness by complete independent replay. The sparse
guest receives only new batches, their witness and the starting boundary. Genesis
is derived from the committed allocation; continuation rejects a zero-height
boundary. A distinct `TO1SPF01` journal profile, guest and optional settlement
build keep this execution experiment separate from replay and native custody.
The sparse settlement permits equal timestamps, matching execution rules; batch
and block numbers must advance and time cannot move backwards. The replay
settlement's existing timestamp behavior is unchanged.

**Completed qualification:**

* Nine local check groups passed, totaling 92 Rust tests: execution/native,
  checkpoint journal, sparse state/journal, replay settlement, sparse settlement,
  native settlement, devnet driver, devnet binary builds and sparse host checking.
  The source manifest was unchanged throughout. Trie tests compare every update
  against Alloy's independent full trie builder; other tests cover omitted state,
  altered code/headers, rollback/retry, two-interval continuity, BLOCKHASH edges
  and native-profile exclusion.
* Native and actual SP1 sparse guest execution both match **25 independently
  Geth-checked cases / 93 blocks**. State, transaction and receipt roots, gas,
  bloom, complete block outputs and pruned-witness journals match.
* The native-gnark release host binaries, guest ELF and source snapshot are frozen
  under `artifacts/sp1-optimization-round3/sparse-proof-tools` and
  `sparse-candidate`. Guest SHA-256 is
  `d867dfdba7c8300ce0da2bd75050cd02f035294e4a6d7a18c030281294cff590`;
  guest key is
  `0x00adca22e4ba834599c9ff5039f27d1c4e0223e40d9dee46f1af272c0f7c54cb`.
* Root Cargo.lock remains unchanged. The separate incremental lockfile resolves
  offline. Its lazy_static patch supplies the CKB settlement test dependency;
  the guest uses the ordinary feature, not CKB single-thread mode.
* Four existing first/two-settlement Python evidence-checker regressions pass.
  These are evidence-consistency checks, not cryptographic or VM verification.

### Measured limits of the sparse candidate

All 25 guest cases above use the genesis branch. They do not demonstrate savings
from skipping historical replay. Sparse execution is **not uniformly faster**:

| Genesis workload | Adaptive instructions | Sparse instructions | Change |
|---|---:|---:|---:|
| 32 transfers, small state | 3,978,052 | 7,497,638 | +88.48% |
| 512 added accounts, 32 transfers | 16,347,042 | 21,021,550 | +28.60% |
| 1,024 storage slots, eight writes | 19,478,638 | 15,443,830 | -20.71% |

The sparse backend currently updates trie paths after each transaction; the
complete backend computes the root at block boundaries. Bootstrap still derives
the complete genesis state. These are plausible sources of overhead, not an
isolated attribution of the measured differences. The new profile has not been
promoted to the default. The same-transaction history experiment is now complete. Each case adds the
same 32 signed transaction bytes after the indicated empty historical prefix:

| Historical batches | Frozen replay instructions | Sparse continuation instructions | Change |
|---|---:|---:|---:|
| 1 | 4,034,783 | 7,567,180 | +87.55% |
| 256 | 19,836,071 | 19,310,116 | -2.65% |
| 1,024 | 75,831,975 | 19,351,431 | -74.48% |

Both actual guests produce identical transition fields in all three cases; their
profile identifiers intentionally differ. Sparse guest input contains no old
batches. The independent host still replays history to check the journal. Between
256 and 1,024 historical batches, sparse instruction count changes by only 0.21%,
consistent with the bounded header window. Short histories still regress.
These adjusted history environments have not been independently Geth-checked;
frozen replay guest agreement is separate from the 25 original Geth cases.
Guest keys are substituted only in these explicitly labeled execution-only lab
inputs, not in canonical inputs for actual settlement. No sparse proving-time
claim is made. The exclusive history run finished successfully and resumed the
matrix coordinator; the third smaller-shard real proof is running.

### Remaining settlement and proof qualification

A new guest key changes the settlement type identity. Canonical local CKB inputs
must therefore be generated using the exact sparse key and compiled sparse
settlement artifact, with a new continuation fixture for that domain. The explicit
sparse devnet mode and exact-key proof runner implement this workflow. The runner
rejects a source key that differs from the ELF; it never replaces the canonical
key. The separate final wrapper strictly decodes the sparse journal and retains
all key, digest, release-VK-root and negative-control checks.

The local driver and settlement code compile and pass tests, but **two real
consecutive sparse proofs and actual local CKB acceptance are still pending**.
The sparse evidence checker pins the compiled script and guest key while reusing
existing deployment, continuity, canonical-consumption and rejection checks. It
supplements actual CKB execution and independent SDK verification.

Safety conditions for adoption remain:

* Bootstrap derives its state from the deployment's committed genesis allocation.
* The continuation's starting anchor, state root and header hash exactly match
  the consumed, accepted settlement tip. Self-consistency of a prover-chosen
  boundary or an unchecked predecessor journal confers no authority.
* Verification binds deployment domain, allocation, proof profile, guest identity
  and the canonically published contiguous batch interval.
* The sparse execution profile grants no native withdrawal authority. Native
  custody requires separately authenticated vault identity/configuration/code,
  deposit transcript and cursors, publication boundaries and custody invariants.
* Acceptance requires real consecutive proofs and local CKB acceptance/rejection,
  recovery and applicable reorg checks, in addition to execution equivalence.

Local checks ran in a controlled window after the second proof completed all
verification. Only the matrix coordinator was stopped; no proof was interrupted.
The history qualification script releases the exclusive resource lock and resumes
that same coordinator when finished, including on a test failure. No CI ran.

The goal remains open for the third resource experiment, history/performance
qualification, real sparse proofs and CKB settlement, final formal full/native/
sparse-source qualification, evidence archive and requirement-by-requirement audit.

## Follow-up candidate, awaiting compilation

The working source now defers sparse account/storage trie writes to each block
boundary. Later transactions read pending metadata and explicit storage zeroes;
creation resets storage overlays, and failed batches discard pending writes.
A flush publishes its new root/cache only after all authenticated updates succeed.
New tests cover repeated storage reads/writes across transactions, distinct block
roots, destruction/recreation, and missing deletion-sibling failure/rollback.

A second change replaces guest-side witness JSON parsing with `TO1WIT01` binary
framing and canonical RLP headers. Counts, individual lengths, aggregate sizes,
header limits and trailing data are checked. JSON remains a host artifact format.
New tests cover every truncation, oversized counts/lengths, trailing bytes and
noncanonical header RLP. No authentication check is intentionally removed.

**The latest sparse/state and journal test suite now passes all 12 tests.**
An initial attempt stopped on a test-only TransactionId type mismatch; that was
corrected and the full affected suite rerun. Release host linking is underway;
new guest execution and performance are still unmeasured. The preceding sparse results and key refer to the frozen
initial candidate. The completed resource matrix used its original adaptive ELF.
A deferred-trie/JSON snapshot is preserved for comparison, without a separate
performance claim. A local worker waits for that observed matrix to complete,
then acquires the exclusive resource lock before tests, builds, actual guest/Geth
qualification and exact-key local CKB input preparation. It stops on any failure.
Real sparse proofs and settlement acceptance remain subsequent required work.

The reorg evidence checker now forwards explicit profile binding through the
existing first-settlement checks, and the sparse checker can reconcile the P2P
reorg suite. Both retained reorg regression tests pass; this is not new sparse
reorg execution evidence.

## Optimized sparse qualification update

The follow-up candidate now passes all 12 affected state/journal tests and all
25 Geth cases / 93 blocks in its actual guest. The source remained unchanged
through build and qualification. Its frozen source, native-gnark host binaries,
ELF and manifests are in
`artifacts/sp1-optimization-round3/optimized-1792042759396978183`.
The new guest key is
`0x0017cf9eee019ac2f5933907aa0cf7cc50746d7a50d82504e31dede2fc1681a4`.

| Genesis workload | Adaptive instructions | Initial sparse | Optimized sparse |
|---|---:|---:|---:|
| 32 transfers, small state | 3,978,052 | 7,497,638 | 4,413,468 |
| 512 added accounts, 32 transfers | 16,347,042 | 21,021,550 | 12,769,100 |
| 1,024 storage slots, eight writes | 19,478,638 | 15,443,830 | 14,247,946 |

These are combined gains from deferred trie writes and binary/RLP witnesses, not
isolated attribution to either change. Relative to adaptive complete state, the
small-state genesis case is still 10.95% slower in instructions; the larger
account and storage cases improve by 21.89% and 26.85%. The profile remains an
explicit experimental option. Proving-time improvements are not inferred from
these execution counts.

Exact-key isolated CKB bootstrap and two-publication input preparation both pass
actual local execution and independent evidence checks. A newly generated
continuation fixture passes Geth, and both canonical intervals execute in the
actual optimized guest with exact exported journals. Their domains, allocation,
predecessor anchor/state/header and guest key are checked for continuity.
The compiled L1 script is frozen alongside the guest. These steps prepare real
proof inputs; they do not establish that either interval has been settled.

The real proof pipeline is now running serially with eight CPU/four Go threads
and a 1,048,576 shard size. It requires fifteen negatives and fresh independent
SDK verification for each of two proofs, then actual two-settlement acceptance,
P2P reorg/recovery and profile-pinned evidence reconciliation. It stops on any
failure and preserves completed stages. The latest source's long-history guest
comparison follows those tests. Final formal full/native guest qualification
and a complete evidence archive/audit remain pending. No CI or production
migration has occurred.
