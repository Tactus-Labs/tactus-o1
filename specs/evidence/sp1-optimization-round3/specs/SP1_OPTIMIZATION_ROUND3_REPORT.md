# SP1 execution and proving optimization — round three

Date: 2026-10-15. **Local qualification and same-input proving measurements complete; this remains an experimental profile, not production readiness.** No CI ran. Existing deployments and native custody authority were not migrated.

## What the measurements establish

The retained approximately 59-minute benchmark already used the crypto-patched
guest and had `prefix_batches = 0`; historical
replay did not explain that original latency. Round two's same-input complete
proof already measured 1,189.921 seconds (19m49.9s) by the comparable phase sum.
This round removes redundant state work, measures prover resources, and implements
an authenticated incremental execution profile. Different workload timings are
reported separately; cycle reductions are not treated as proving-time reductions.

Small local proof workloads do not establish sustainable production TPS or that
settlement can keep pace with L1 ordering. No automatic proof-batch scheduler or
production capacity guarantee is provided by these experiments.

## Implementation

* Reuse completed block state roots and header hashes. Empty blocks still update
  headers, timestamps and base fees; reverted/halted accepted transactions still
  retain gas/nonce effects.
* Parse and validate borrowed transaction slices in one pass. Precompute immutable
  native rules and bridge bytecode from pinned build inputs. The root Cargo.lock
  and execution rules hash remain unchanged.
* Protect batches with rollback guards. Small states use bounded snapshots
  (eight accounts, eight code entries, 32 storage slots); larger states retain
  first-written account/code values. The full backend still copies touched
  accounts' storage. Sparse state is a separate option.
* `verify-pinned` retains independent replay, exact journal binding and a trusted
  guest key while avoiding CPU prover initialization. Existing real proofs verify
  in fresh processes in about 0.20–0.21 seconds; seven negative-control categories
  reject. Original SDK/ELF verification remains an independent qualification path.
* A generic backend supports both full and authenticated sparse state. The sparse
  guest reads only new batches, authenticated MPT paths, hash-checked code and a
  linked header window. Its host deliberately retains independent full replay as
  the qualification oracle; persistent incremental host verification is not added.
* Sparse writes are combined at each block root. Later transactions see pending
  values, including explicit zeroes; account recreation clears the prior storage
  incarnation. Failed batches restore roots/headers. Binary `TO1WIT01` witnesses
  replace guest-side JSON and use bounded framing plus canonical RLP headers.

Unconditional full-backend journaling slightly regressed small-state workloads,
so bounded snapshots remain. Gains below combine several changes and are not
attributed solely to rollback or a particular crypto operation.

## Final formal guest execution

The final full guest matches 25 independently Geth-checked cases / 93 blocks and
the retained chain journal. Both native guest intervals match their retained
940-byte journals. The source manifests were checked before and after compilation
and execution. Native results are execution qualification, not a new custody
proof, settlement or payout.

| Workload | Round-two instructions | Final instructions | Reduction |
|---|---:|---:|---:|
| retained-sealed-chain | 1,435,772 | 1,163,410 | 18.97% |
| transfers-32 | 4,074,217 | 3,984,816 | 2.19% |
| state-512-transfers-32 | 25,094,450 | 16,342,022 | 34.88% |
| state-512-empty-16 | 86,615,888 | 8,719,535 | 89.93% |
| storage-1024-writes-8 | 30,839,661 | 19,507,340 | 36.75% |
| native-full | 21,101,594 | 1,662,380 | 92.12% |
| native-prefix | 21,102,096 | 1,614,887 | 92.35% |

Relative to the earlier frozen adaptive candidate, final full-guest changes range
from approximately -0.35% to +0.55% in these fixtures. The 32-transfer case changes
by +0.17%; no uniform improvement is claimed for the generic-backend refactor.

## Complete proof resource matrix

All three runs use identical frozen adaptive ELF and 32-transfer input, one
worker/buffer per stage, and real Groth16 proofs. Each passed 15 negative controls
and fresh-process SDK verification. Timings exclude preparation/builds; the
comparable sum includes recursive proving and final wrapping/verification. The
last column is recursive maximum RSS. These are single samples per configuration.

| Configuration | Comparable seconds | Including fresh verify, seconds | Peak RSS, KiB |
|---|---:|---:|---:|
| threads4 | 1600.402 | 1640.305 | 20,488,400 |
| threads8 | 1156.604 | 1185.620 | 20,640,392 |
| threads8-shard19 | 1146.884 | 1177.464 | 21,250,924 |

Eight CPU/four Go threads reduce comparable time by 27.73% versus four/two.
Halving shard size from 1,048,576 to 524,288 changes time by only 0.84% and raises
peak memory, insufficient evidence of a stable advantage. Follow-up proofs use
eight/four threads and the original shard size. Four-thread adaptive time differs
from round two's 1,607.494 seconds by only 0.44%.

The final full guest also produced a fresh 32-transfer Groth16 proof: **1223.017 seconds** comparable and **1251.720 seconds** including independent fresh SDK verification. All 15 negative controls passed; recursive peak RSS was 20,356,240 KiB. This lab input replaces only the guest key and does not authorize an existing deployment.

The final 32-transfer run is 5.74% slower than the earlier frozen adaptive
eight-thread sample, despite only 0.17% more instructions; it is 23.92% faster
than the round-two four-thread measurement. These single samples do not isolate
the cause of the timing difference or establish a uniform code-only speedup.

The final full guest was also measured on the **same original zero-prefix, nine-batch workload**: **830.397 seconds** comparable, **858.996 seconds** including fresh SDK verification; recursive peak RSS 20,217,076 KiB. This is **76.52%** below the previous 3,536.863-second (~59-minute) comparable run. The newer configuration uses eight CPU/four Go threads rather than four/two, so this measures combined code and resource changes, not an isolated code speedup. All 15 negative controls and fresh SDK verification passed. Only the lab guest key changed; the original batches and expected journal were retained.

All measured proofs use the retained staged memory handoff: the recursive witness
completes first, then a fresh process wraps and verifies it. The full timings
include both stages. This is not a claim of one uninterrupted prover process.

## Incremental profile: actual proofs and CKB acceptance

`TO1SPF01` is an explicit experimental profile with a distinct guest and optional
settlement build. Exact-key canonical inputs were exported from fresh isolated
CKB deployments; their key was never replaced. A new continuation fixture for
that domain passed independent Geth checks. Both intervals produced exact journals.

| Canonical interval | Comparable seconds | Including fresh verify, seconds | Peak RSS, KiB |
|---|---:|---:|---:|
| first | 876.604 | 907.130 | 20,930,436 |
| second | 817.316 | 846.241 | 19,403,772 |

Both proofs passed all 15 negative controls and independent fresh SDK verification.
CKB 0.210.0 accepted them consecutively; the two-settlement suite rejected all
**62 controls**, including altered proof/journal fields, replay and rollback.
Independent evidence reconciliation pins the compiled settlement ELF and guest
key; it supplements actual node/SDK verification and does not itself reexecute
cryptography.

A separate real P2P reorg orphaned four blocks. Cold recovery returned settled
batches to zero. The old funding transaction was rejected; the same valid proof
with fresh funding committed again, restoring one settled batch. That experiment
recorded 41 rejections, including the old-funding rejection. It does not establish
native withdrawal authority.

## Where sparse execution helps—and where it does not

The optimized sparse guest passes 25 Geth cases / 93 blocks. These genesis cases
include both deferred trie writes and binary witnesses; their separate effects
have not been isolated.

| Genesis workload | Adaptive full | Initial sparse | Optimized sparse |
|---|---:|---:|---:|
| transfers-32 | 3,978,052 | 7,497,638 | 4,413,468 |
| state-512-transfers-32 | 16,347,042 | 21,021,550 | 12,769,100 |
| storage-1024-writes-8 | 19,478,638 | 15,443,830 | 14,247,946 |

Small-state bootstrap remains 10.95% more instructions than adaptive full state;
the larger account and storage cases improve by 21.89% and 26.85%. The sparse
profile therefore remains an explicit option, not a default replacement.

The history experiment appends the same 32 signed transactions after empty
historical batches. Actual frozen replay and optimized sparse guests agree on all
transition fields; their profile identifiers differ intentionally.

| Historical batches | Full replay instructions | Sparse continuation | Reduction |
|---|---:|---:|---:|
| 1 | 4,034,783 | 4,407,616 | -9.24% |
| 256 | 19,836,071 | 10,913,185 | 44.98% |
| 1024 | 75,831,975 | 10,975,222 | 85.53% |

Sparse guest inputs contain zero old batches. Between 256 and 1,024 historical
batches, witness sizes remain about 146–147 kB and instruction counts change by
about 0.57%, consistent with the bounded 256-header window. Short histories still
regress. These adjusted history environments are execution-only lab cases checked
against the frozen replay guest, not independently Geth-checked environments and
not measured full proofs. They must not be presented as 85.5% proving-time savings.

## Safety properties and remaining limits

Bootstrap derives state from the committed genesis allocation. Continuations must
bind the starting anchor/state root/header hash to the consumed accepted settlement
tip. A self-consistent prover-chosen boundary or unchecked predecessor journal has
no authority. Domain, allocation, profile, guest identity and canonical contiguous
publication remain bound by the proof and settlement script. Missing nodes/code
are fatal; authenticated absence is distinct from missing evidence. Deletion
requires sibling paths. Batch/block numbers advance; sparse timestamps may remain
equal, matching execution, but cannot decrease.

The sparse state/journal suite passes 12 tests covering trie/reference agreement,
missing/altered witnesses, rollback/retry, continuity, storage overlays, explicit
zeroes, recreation, deletion siblings, framing/truncation and canonical RLP.
Earlier unchanged components passed 92 local Rust tests across execution/native,
checkpoint journal, settlement profiles and devnet driver; the 12-test sparse
suite supersedes its earlier eight-test component. Evidence-checker regressions
also pass. This is not a claim that a fresh 96-test aggregate ran in one command.

Experimental resource caps remain: 16 MiB initial trie witness, 64 MiB node store,
262,144 nodes, 8 MiB aggregate code, 16,384 code entries, protocol-sized individual
code, 40 MiB encoded witness, and 256 headers. Universal workload support is not
claimed. The sparse profile grants no native custody/withdrawal authority; separate
vault identity, deposit, publication and payout invariants remain necessary.
Production gates remain open. No deployment, CI, remote proving or new custody
release is authorized by this evidence.

## Identities and evidence

* Final full guest: `0x0080f615f0c5ae00a998ffae474f42d59c3c936f63309fa8b8390c0d0ff934c2`;
  SHA-256 `d9f53f93e115557591b57a44699594973040001fef885921088b14f6f0e5fbeb`.
* Final native guest: `0x00ad5da8b3dcc308cc8e36d42f28c0c093e3874949eb59531143119eb345e2cd`;
  SHA-256 `8def06725fb45f4554dfc1dd9dd7b75ad9900d9476e05eef6d73f811fca5dd6f`.
* Optimized sparse guest: `0x0017cf9eee019ac2f5933907aa0cf7cc50746d7a50d82504e31dede2fc1681a4`.
* Sparse settlement ELF SHA-256: `c8d0afe795225a0edebc969256f5e43920ac2b047f2159f636530fd6f22a0b36`.
* Frozen optimized source and guest: `artifacts/sp1-optimization-round3/optimized-1792042759396978183`.
* Sparse proof/settlement/history evidence: `artifacts/sp1-optimization-round3/sparse-proofs-1792043336864656751`.
* Final formal source and qualification: `artifacts/sp1-optimization-round3/final-source-1792045277886469326`.
* Archive: `specs/evidence/sp1-optimization-round3`, with `archive-index.json`,
  `completion-audit.json` and verified `SHA256SUMS`. Original host binaries and
  circuit files stay in artifacts; their immutable hashes are retained.

The archive is generated only after all final qualification gates pass. The
completion audit distinguishes proof generation, SDK verification, actual local
CKB acceptance, execution-only history tests and native execution-only checks.
