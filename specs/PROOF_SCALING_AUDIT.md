# Proving scalability audit and incremental-proof design

Date: 2026-10-15. Scope: the existing SP1 execution profile, its retained
nine-batch workload, and CKB settlement continuity. No CI or CKB transactions.

Subsequent implementation: [optimization round two](SP1_OPTIMIZATION_ROUND2_REPORT.md)
now precomputes the rules hash at build time, reuses batch validation, and enables
the patched guest ECRECOVER backend. The source findings and memoization results
below describe the earlier audit baseline. Full-prefix replay and full-state
work remain relevant architectural findings.

## Findings supported by the current code

1. `proofs/sp1/journal/src/lib.rs::execute` reconstructs genesis, executes every
   `prefix_batches` entry, then executes the requested interval. Prefix execution
   happens **inside the proved guest**, not only in the host. The native-custody
   guest has the same full-prefix design. Later proofs can repeat already-settled
   history; changing the interval counters alone does not make proving incremental.
2. The retained ~59-minute run has `prefix_batches = 0`, nine interval batches,
   nine blocks, and only four transaction input slots, all in the last block.
   Its first eight blocks are empty. It contains **no redundant old-prefix
   execution**. Removing old-prefix replay therefore cannot directly explain a
   reduction in this particular first proof. This is not a production TPS sample.
3. `Executor::apply_batch` clones the in-memory database for atomicity and
   rebuilds the Ethereum state root for each block. `state_root` walks all cached
   live accounts and their nonzero storage. Full-prefix replay and whole-state
   work are separate scaling problems.
4. `rules_hash()` hashes the same embedded rules and 84,988-byte root Cargo.lock
   at genesis, each batch, and final journal validation. It uses personalized
   Blake2b through `batch::hash`; the previously integrated SHA/Keccak/k256 patches
   do not eliminate this invariant computation.
5. The CKB verifier already checks an interval proof and links its before/after
   anchors, state roots and header hashes to the consumed/recreated SettlementTip.
   It does not execute Ethereum history or reverify all previous proofs.
6. The host `chain-proof verify` does independently replay history to bind an
   expected journal, then verifies the proof. This is a diagnostic/oracle policy,
   not a requirement of Groth16 verification. Its prover initialization is also
   expensive. Neither this native replay nor a fresh verifier run should be
   confused with another full ZK proof generation.

## Isolated execution experiment

`scripts/audit-sp1-proof-scaling.py` copies the current source, applies the same
pinned crypto-patch manifests used in the ~59-minute experiment, and builds:

- `profiled`: cycle-tracker regions around rules hashing, state roots, transaction
  decoding, batch execution, prefix execution and interval execution.
- `memoized`: the original guest with only `rules_hash` cached in a process-local
  `OnceLock`. The first call computes the original expression from embedded bytes;
  no prover-supplied digest is trusted and no check is removed.

The comparison baseline is the previously retained crypto-patched ELF. Four
input selections compare the first one/three/nine batches and prefix-eight plus
one new batch. Every public journal is compared with native execution from the
unmodified repository. A separate regression run checks the candidate on all nine
archived Geth fixtures and the retained chain input. Tracker regions are inclusive
and overlap; their counts must not be added together or treated as wall time.

Results and exact candidate identity are retained in `evidence/proof-scaling/`.
These are **execution measurements**, not a new complete proof, a new on-chain
settlement or a production guest change. The previous ~59-minute result does not
describe the memoized candidate. Its actual proving time requires a fresh run.

Measured uninstrumented results (baseline already includes the crypto patches):

| Input selection | Baseline instructions | Memoized instructions | Reduction |
|---|---:|---:|---:|
| First empty batch | 6,196,245 | 2,262,658 | 63.48% |
| First three empty batches | 10,347,816 | 2,480,468 | 76.03% |
| All nine batches, prefix zero | 23,257,553 | 3,588,795 | **84.57%** |
| Eight prefix batches, one new batch | 23,159,433 | 3,490,675 | 84.93% |

For the full nine-batch input, SP1's estimated prover gas drops from 23,211,934
to 3,933,768 (**83.05%**). This is neither EVM gas nor a wall-time measurement.
All twelve variant/input comparisons match their original native journal. The
memoized ELF also passes all nine Geth fixture comparisons and the retained chain
journal check (ten additional guest executions). This tests preservation of
the existing statement; it does not implement checkpoint-based proving.

The prefix-eight case deliberately executes the same history with only the last
batch designated as new. Its near-full cost demonstrates that interval labeling
alone saves almost no guest execution. Caching the hash substantially reduces
this implementation overhead, but prefix replay still grows with history.

Function profiling was repeated with the SDK's `profiling` host feature enabled
(the first host build did not collect tracker counters). All twelve repeated
executions have identical instruction counts/gas/journals to the first run.
For the instrumented full-nine-batch guest:

| Inclusive region | Invocations | Tracked cycles |
|---|---:|---:|
| Fixed execution rules hash | 11 | 21,998,253 |
| Whole-state root | 12 | 211,463 |
| Transaction decode/recovery | 4 | 148,464 |

This makes invariant hashing the dominant measured guest hotspot in this tiny
state workload. Whole-state rebuilding is still a real future scaling problem,
but not its current dominant measured hotspot. These tracker counts include
instrumentation effects; use the uninstrumented table above for candidate gains.
The memoized candidate's remaining first hash can potentially be moved to build
time, provided the digest is automatically regenerated from the exact embedded
inputs and checked against the reference implementation. That additional change
has not been implemented or measured here.

## Recommended incremental statement

Prove a bounded transition from an authenticated boundary:

`(domain, old_anchor, old_state_root, old_header_hash, new_batches, state_witness)`
`-> (new_anchor, new_state_root, new_header_hash, interval_commitment)`.

The witness is untrusted. The guest must authenticate everything it reads against
the public old state/header, execute only the new interval, and derive the new
roots. Settlement must bind the public old boundary to the live consumed Tip and
the new anchor to authenticated canonical publication. Keeping this binding
avoids putting an old proof verifier inside every execution guest: the CKB Tip
transition supplies the induction step. Proofs may be computed ahead of previous
settlement, but are accepted only against their matching canonical predecessor.

Bootstrap needs a separate enforced branch: when no prior Tip is initialized,
derive the starting state/header from the committed genesis allocation. The
existing verifier deliberately does not compare its zero placeholder roots with
the guest's genesis roots; simply accepting an arbitrary snapshot there would be
unsound. A new profile/version and guest key must identify the changed statement.

### Stage one: authenticated complete checkpoint

Supply complete account/storage/code state, the parent header, and required
recent block-header history. Reconstruct and check the state root **inside the
guest**, authenticate the parent header hash, require its state root to match,
and prove the parent chain used by BLOCKHASH. Preserve all execution inputs, including base fee, parent gas usage,
height, timestamp, anchor and domain. Authenticate code by its account code hash.
Then run just the new interval. Recomputing a complete snapshot root removes
history replay, but still costs O(total state); this is a transitional approach.

### Stage two: authenticated sparse state witness

Replace `InMemoryDB`/whole-state rebuilding in the proved path with a witness-backed
database and incremental Ethereum trie updates. Account/storage inclusion and
non-inclusion must be checked against the old root. Missing witness data must
fail, not silently return a zero balance/slot. Authenticate code bytes, update
all modified trie paths (including deletion and empty-account semantics), and
derive each new block root. Use an undo journal/overlay for atomicity rather than
copying the full database per batch. Receipt/transaction roots and all block
semantics remain checked.

The native custody profile additionally needs its full configuration, vault
identity, authenticated deposit transcript and both deposit cursors bound across
the boundary. An execution-only checkpoint does not establish bridge authority.

### Stage three: pipeline and aggregation, after bounded intervals work

Produce proofs for bounded intervals, retain canonical boundary witnesses, and
pipeline execution/witness generation/proving/settlement. State execution is
sequential; proof generation can overlap once each boundary witness is available.
Reorgs invalidate work whose publication/boundary is no longer canonical.

Evaluate aggregation only with measurements. SP1 already shards and recursively
aggregates a large program internally. Splitting into many small independent
proofs adds per-proof and aggregation overhead; it is not automatically faster.
If aggregation is used, verify authorized child keys, matching domains/profiles,
contiguous batch/anchor/state/header boundaries, and the aggregate statement.
The current interval digest starts from the interval length and folds the raw
batch bytes; concatenating child digests does not recreate that digest. An
aggregation profile must define a sound composable commitment or authenticate
the required inputs/commitment paths explicitly, rather than reuse the current
digest format by assumption.
Do not independently Groth16-wrap every small batch unless measurements justify
the additional fixed cost and L1 verification frequency.

Source: [SP1 proof aggregation documentation](https://docs.succinct.xyz/docs/sp1/writing-programs/proof-aggregation).

## Implementation and measurement order

1. Remove measured invariant work (memoize, or automatically compute the same
   digest at build time with reference-equivalence checks). Keep crypto patches.
   Retest full proving on the candidate before making wall-time claims.
2. Implement the authenticated checkpoint statement as a distinct profile, with
   an explicit genesis branch and settlement-bound continuation.
3. Test the same new interval after increasingly long histories; guest work must
   not grow with discarded history. Test separately as total state grows, since
   a complete checkpoint will still have whole-state costs.
4. Qualify sparse witnesses and incremental root updates against native execution
   and Geth: storage reads/writes, absent keys/accounts, code hashes, creation,
   destruction, revert/halt, BLOCKHASH, base fee and invalid transaction outcomes.
5. Check tampered snapshots, omitted trie paths, forged recent headers, wrong
   domain/key/profile, wrong/skipped/stale boundaries, reordered batches and
   reorgs. Require two real consecutive proofs accepted by matching CKB scripts.
6. Benchmark batch-size choices and sustained proving throughput, backlog growth,
   end-to-end settlement latency, memory and cost on representative filled blocks.

A production host verifier can separately authenticate the deployment key,
canonical before/after checkpoints and public journal, then verify the proof
without replaying all Ethereum history. Keep independent replay as an oracle and
recovery tool. Do not merely delete the current expected-journal comparison and
substitute an unauthenticated prover-supplied JSON file. Reuse verification setup
where appropriate; the prior fresh-verification run took about 42 seconds in
total, so optimizing it cannot account for most of a ~59-minute proving run.

The bounded-incremental design addresses the long-term history-growth problem.
It does not by itself remove SP1 recursion/wrapping costs, improve L1 DA bandwidth,
or demonstrate sustained settlement throughput.
