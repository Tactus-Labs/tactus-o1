# Production readiness

- [Execution, incremental proving and resource optimization round three](SP1_OPTIMIZATION_ROUND3_REPORT.md)
  qualifies the final full/native guests and an explicit sparse execution profile.
  On the exact original nine-batch input, final full proving measures 830.397 s
  by the comparable phase sum (76.52% below the earlier patched ~59-minute run),
  or 858.996 s including independent fresh verification. This combines code
  changes with eight CPU/four Go threads versus four/two. Two real sparse proofs
  settle consecutively on isolated CKB; 62 rejection controls and a separate
  P2P reorg/reapplication experiment pass. Long-history instruction savings are
  measured separately from proving time. The sparse profile remains optional;
  no production deployment or native custody authority changes. G1–G9 remain OPEN.

- [Crypto, batching and proving optimization round two](SP1_OPTIMIZATION_ROUND2_REPORT.md)
  integrates pinned guest crypto patches, build-time rules hashing and reuse of
  batch validation. The formal guest matches 17 Geth cases / 40 blocks and the
  retained chain journal. ECRECOVER-specific and filled-batch ablations are
  measured. The retained input's complete proof passes fresh verification in
  1,189.921 s by the comparable phase sum (66.36% less than the previous patched
  run). A separate 32-transfer full proof also passes fresh verification: phase
  sum 1,607.494 s, or 1,646.693 s including the unified pipeline and independent
  verification. Both proofs reject all 15 negative controls. Existing deployments
  and all production gates remain unchanged.

- [SP1 crypto patches full proving measurement](SP1_PATCHED_PROVING_REPORT.md)
  now produces and independently verifies a real proof of the retained sealed-chain
  workload with a candidate patched guest. Comparable phase time falls from
  4,674.679 s to 3,536.863 s (24.34%). This is a benchmark with a new guest key,
  not a newly authorized settlement deployment; production gates remain open.


Status: **NOT READY**, 15 October 2026. G1–G9 remain OPEN. Passing the mechanism
suite is necessary implementation evidence; it does not authorize a production
rollup deployment or custody of user assets.

## Implemented and measured

- [CKB verifier cycle optimization](VERIFIER_CYCLE_OPTIMIZATION_REPORT.md) reduces
  the retained A3 settlement type-script replay from 3,983,164,412 to 333,144,448
  cycles. Fresh complete proof-receipt transactions also commit under an explicit
  3.5-billion-cycle devnet limit, with 28 rejected controls. This does not measure
  L2 proving acceleration or qualify a new settlement/custody deployment; G1–G9
  remain OPEN.

- [Native settlement bootstrap](NATIVE_SETTLEMENT_REPORT.md) now deploys a
  verifier with fixed native guest/publisher/checkpoint identities and jointly
  binds the real vault/anchor/Tip without a hash cycle. 13 actual commits, 68
  rejected controls and two SP1 executions pass; no native proof has yet settled
  and no custody payout is authorized by this evidence.
- [Immutable native custody checkpoints](NATIVE_CHECKPOINT_REPORT.md) now retain
  the complete config and deposit cursor only during a real authenticated anchor
  update: two checkpoints, 11 actual commits and 43 rejected controls on CKB
  0.210.0. Successful native proof settlement and actual custody release remain
  missing.
- [Native custody proof statement v2](NATIVE_PROOF_STATEMENT_V2.md) now binds
  complete custody config, both deposit cursors and state/header roots in a
  separate guest. Two real SP1 CPU executions match the complete 940-byte
  journals, real publication anchors and independent Geth roots. Cryptographic
  proof, native settlement and actual custody release remain unqualified; G7 remains OPEN.
- [Authenticated native publication](NATIVE_PUBLICATION_REPORT.md) binds funded
  receipts at the CKB script boundary: ten commits and 27 exact rejections on
  0.210.0. Two published credit/burn blocks match Geth. A3 integration, new proof
  settlement, v2 observer/reorg recovery and actual payouts remain required.

- [Candidate native custody execution v2](NATIVE_BRIDGE_EXECUTION_V2.md) processes
  contiguous records and signed token burns atomically. Seven blocks match Geth,
  with six execution tests. Standalone CKB publication is now authenticated;
  successful new-proof settlement, observer support and actual payouts remain
  required.

- [Canonical native vault recovery](NATIVE_VAULT_RECOVERY_REPORT.md) reconstructs
  funded deposit records in four fresh processes, without an operator database
  or indexer. Pin/live-cell rechecks fail closed on changes; actual P2P vault
  reorgs, authenticated L2 credit and real release remain unqualified.

- [Funded native CKB vault deposits](NATIVE_VAULT_REPORT.md) now atomically append
  immutable records for two independent actors. Five commits and nineteen exact
  negative controls pass on 0.210.0. Release validation is implemented but awaits
  an authenticated bridge execution profile and a real proof-covered payout.

- [Native CKB ledger and burn commitments](NATIVE_CKB_BRIDGE.md) now have pinned
  Solidity bytecode, 27 signed execution/Geth comparisons and independent system-
  call contract tests. Candidate execution v2 is now implemented; authenticated
  A3 publication integration, proof settlement and actual release remain
  missing; G7 is OPEN.

- [CKB authenticated settled-state reads](SETTLED_STATE_PROOF_REPORT.md) now verify
  three actual A3 account/slot witnesses against the live, proof-settled Tip.
  Seventeen script-specific negative controls reject; immutable read certificates
  can be destroyed to recover capacity. This does not implement custody or exits.

- [User-accessible state witnesses](OBSERVER_STATE_PROOFS_REPORT.md) now provide
  account and storage proofs, independently checked by pinned Geth against
  reconstructed roots. Live HTTP witnesses match the accepted A3 proof's state
  roots and settled Tip. This supplies authenticated read evidence, not a vault
  release rule or an implemented bridge.

- [Real A3 proof fulfillment and rollback](SEALED_PROOF_SETTLEMENT_REPORT.md) now
  settles all four duties, including a proved malformed-input rejection, across
  nine canonical batches. Real P2P rollback restores them as pending; the same
  proof with fresh funding settles them again on both observers. Costs remain
  roughly 78 minutes proving and 3.985 billion CKB verification cycles for that
  historical binary; the optimized verifier replay is measured separately above.

- [Read-only Ethereum RPC observer](OBSERVER_RPC_REPORT.md) now serves canonical
  blocks, transactions, receipts and current/genesis state over local HTTP.
  Thirty-one actual requests qualify A3 dense indices, roots and node outage
  recovery. [A live P2P reorg](OBSERVER_REORG_REPORT.md) removes and restores
  orphan block/transaction/receipt queries in the same service. Full tooling,
  incremental indexing and settled RPC rollback remain open.

- [Abrupt CKB primary restart](OBLIGATION_RESTART_REPORT.md) after A3 republication
  now preserves all four duties and execution outcomes across SIGKILL and same-DB
  restart, matching an uninterrupted peer. This covers a completed-publication
  boundary, not power loss, write interruption or settled A3 duties.

- [Canonical A3 obligation recovery](OBLIGATION_RECOVERY_REPORT.md) now reconstructs
  each admission, seal and publication, joins them with settlement at the same
  pinned block, and retains deterministic invalid-input outcomes. Actual cold
  recovery distinguishes all three pending phases. [Actual two-node rollback](OBLIGATION_REORG_REPORT.md)
  restores four duties after removing their seal/publication and republishes them
  with identical outcomes. Proof-covered fulfillment and rollback now pass the
  separate actual-proof experiment linked above.

- [A3 with atomic SettlementTip preparation](SEALED_SETTLEMENT_REPORT.md) now binds
  four authenticated duties across two lanes to a nine-batch canonical proof input.
  Current CKB rejects omitted/reordered duties and malformed proof; independent
  cold recovery still reports zero settled batches. Native journal replay and Geth
  roots agree; the dedicated real proof and Tip transition now pass the
  [subsequent proof experiment](SEALED_PROOF_SETTLEMENT_REPORT.md).

- Deterministic A1/A2/A3 simulations and conditional decisions.
- CKB-VM OrderingHead creation and succession, singleton identity, checked
  counters, fixed capacity, immutable deployment code and a permissionless lock.
- Two independent fee-paying actors, real txpool competition, stale input and
  dependency rejection, and script-specific negative tests.
- An isolated, funded devnet launcher, raw transaction evidence, code/config/source
  hashes, bounded RPC waits and a CI mechanism job.
- Canonical OrderingHead reconstruction from CKB blocks after a planned local
  reorg. No operator snapshot or indexer is used by that reconstruction.

See [devnet results](EXPERIMENT_A_DEVNET_REPORT.md) and the
[fixture wire format and limitations](DEVNET_WIRE_FORMAT.md).

- Canonical bounded multi-block input encoding, tested against independent Python
  vectors, plus a distinct CKB-VM anchor enforcing atomic immutable data publication.
- Full batch-input recovery from canonical CKB blocks, including a maximum-size
  publication and replacement of an orphaned branch. This is input recovery,
  not recovery of executed EVM state. See [batch results](BATCH_INPUT_REPORT.md).

- Pinned Shanghai serial EVM execution with signed Ethereum envelopes, total input
  rejection outcomes, real account/storage/transaction/receipt tries and block
  hashes. Empty blocks, fee accounting and in-memory atomic replay are tested.
  See [execution rules and limits](EXECUTION_V1.md). This is not proof-backed
  settlement.
- Independent Geth 1.17.8 comparison: 9 scenarios, 14 blocks, matching Ethereum
  roots, gas, logs bloom and rejection indices. Frozen independent results are
  enforced by Rust tests; see [comparison evidence](EXECUTION_DIFFERENTIAL_REPORT.md).

- Durable append-only batch journal with exclusive writer locking, fsync publication,
  corruption checks and EVM replay on restart. Separate-process CLI restart and
  interrupted-write layouts are tested; see [journal contract](EXECUTION_JOURNAL.md).

- Real CKB input publications now reconstruct executed EVM state in independent
  processes across a planned rollback/replacement on both CKB versions. Ordinary
  tip growth is accepted; wrong chain/type/genesis and replay-time reorgs are
  rejected. See [recovery evidence and limits](CKB_EVM_RECOVERY_REPORT.md).

- Authentic individual A2 message/lock state machine with consensus-mature
  challenges, bounded input-ordered publication and immutable pending records.
  The [real-node comparator](A2_OBLIGATION_REPORT.md) demonstrates that standalone
  challenge markers still fail forced inclusion; G2 remains OPEN.

- The [bounded A3 sealed schedule](A3_SEALED_V1.md) now has a mandatory CKB gate,
  authentic all-lane seals, retained snapshots and FIFO prefix enforcement.
  [Real-node evidence](A3_SEALED_REPORT.md) measures hostile switching, active-lane
  churn, full queues, maximum snapshots and planned seal/batch rollback. This
  establishes publication duties under batch progress, not wall-clock liveness,
  admission fairness or proof settlement.

- [Matched authenticated admission races](ADMISSION_CONTENTION_REPORT.md) compare
  five arms on both CKB versions, with independent fee cells and identical delays
  and absolute fees. A3 targeted same-lane conflicts retain A1's failure modes;
  independent A2 and disjoint A3 admissions succeed in this bounded schedule.

- [Matched serialized-byte fees](ADMISSION_FEE_DENSITY_REPORT.md) now add 120
  current-version races per fee policy with independently resolved capacities and
  node-confirmed transaction sizes. The targeted-input failure classifications
  remain unchanged; miner fairness and forced execution are still unqualified.

- [Independent A3 cold recovery](SEALED_RECOVERY_REPORT.md) reconstructs the
  Schedule, lane queues and current snapshot from canonical blocks in fresh
  processes. Recovered state drives replacement sealing after a planned rollback;
  wrong domains and orphan pins fail. This does not recover validity settlement.

- A [two-node P2P partition/reorg experiment](NETWORK_REORG_REPORT.md) now replaces
  eight original canonical blocks, recovers a peer-only A3 admission, rolls back
  executed contract state and resumes mandatory processing on both CKB versions.
  It uses real peer synchronization, not `truncate`; broader network qualification
  and validity settlement remain outstanding.

- [Canonical genesis publication](GENESIS_ALLOCATION_REPORT.md) now binds the
  allocation in the anchor type and retains its exact bytes in an immutable output.
  Independent recovery derives genesis from CKB and rejects different caller
  allocations. The updated domain passes the Geth comparison and both CKB suites;
  CKB-enforced proof-bound state-root derivation and production supply policy remain open.

- [Sustained lane load](SUSTAINED_LOAD_REPORT.md) now measures repeated queue
  saturation, dual admission/batch progress and stopped-arrival drain under
  deterministic L1/L2/L3 schedules. This exposes backpressure and dependency
  failure without claiming useful Ethereum TPS or seal-submission fairness.
  The [Experiment A acceptance audit](EXPERIMENT_A_ACCEPTANCE_MATRIX.md) preserves
  remaining miner-policy, admission-fairness and proof-fulfillment requirements.

- [Execution proof guest](EXECUTION_PROOF_V1.md) now executes a real three-transfer
  batch inside SP1 and matches the native/Geth roots. Its canonical public journal
  binds deployment context, allocation, interval history and both state roots.
  This guest-execution evidence does not establish proof-accepted CKB settlement,
  production proving cost, trusted setup/key provenance or withdrawal authority.

- [First real execution proof](EXECUTION_CORE_PROOF_REPORT.md) now proves that
  batch with a local SP1 core STARK, passes 15 public-value/key rejection controls
  and verifies in a fresh process. The proof and measured workstation cost are
  retained. A subsequent [real Groth16 proof](EXECUTION_GROTH16_PROOF_REPORT.md) now
  verifies in CKB on both versions. The later [canonical first settlement](FIRST_SETTLEMENT_REPORT.md)
  now passes, as do [two consecutive intervals](TWO_SETTLEMENTS_REPORT.md);
  production proving economics remain open.

- [Transition-authenticated history checkpoints](HISTORY_CHECKPOINT_V1.md) now
  retain exact Anchor successor states in immutable typed cells. Both CKB versions
  reject 22 negative controls and allow later ordering to reference old checkpoints
  while rejecting a spent mutable Anchor dependency. This supplies a bounded
  history mechanism. A [real P2P checkpoint reorg](CHECKPOINT_REORG_REPORT.md) now
  rejects an orphaned checkpoint dependency and accepts its canonical replacement
  on both versions. The [first proof-consuming Tip and planned P2P rollback](FIRST_SETTLEMENT_REPORT.md)
  now pass; unplanned-fault qualification remains open. The [Groth16 receipt experiment](EXECUTION_GROTH16_PROOF_REPORT.md) now
  commits two real verified receipts and rejects 28 controls on each version.
  Final wrapping recovered from an OOM in a fresh process. That original verifier
  cost approximately 3.977 billion CKB cycles; the later
  [verifier optimization](VERIFIER_CYCLE_OPTIMIZATION_REPORT.md) reduces complete
  receipt transactions to approximately 334 million cycles on CKB 0.210.0.
  Throughput qualification remains open.

- [SettlementTip atomic genesis](SETTLEMENT_TIP_V1.md) and 20 rejection controls
  pass on both CKB versions. Canonical chain data exports replay to the exact guest
  journal under real deployment identities. The script implements proof and
  checkpoint binding. A later [real proof-consuming transition](FIRST_SETTLEMENT_REPORT.md)
  now passes with 40 script rejection controls; neither result alone closes G3.

- [A real canonical-domain Groth16 proof](CHAIN_GROTH16_PROOF_REPORT.md) now
  matches the actual deployment's full journal and passes fresh SDK verification
  plus 15 cryptographic negative controls. It completed through a deliberate
  fresh-process final-wrap handoff. [First canonical settlement](FIRST_SETTLEMENT_REPORT.md)
  now passes on CKB 0.210.0, including two-node recovery after a four-block P2P
  rollback and reuse of the same proof with fresh funding. [Two sequential real
  proof intervals](TWO_SETTLEMENTS_REPORT.md) now pass, including skipped-first-proof
  rejection and automated staged proving; production proving cost remains open.

- [A state-changing second interval](SETTLEMENT_CONTINUATION_REPORT.md) now has
  canonical CKB 0.210.0 publication, exact prefix-one journal replay and independent
  Geth comparison across both blocks. Cold recovery distinguishes two published
  batches from zero settled batches. [Actual sequential proof consumption](TWO_SETTLEMENTS_REPORT.md)
  now advances to two proved batches with 62 rejection controls; this does not close G3.

- [Repeated fresh seal contention](SEAL_CONTENTION_REPORT.md) now attains the
  finite `8 × lane_count` valid-append budget, rejects further full-queue churn,
  seals the complete set and processes every payload across two consecutive
  epochs on both versions. This is conditional canonical progress, not a miner
  inclusion promise or protection against a user losing every admission race.

## Work that still blocks the user's production objective

| Priority | Boundary | Required completion evidence |
|---|---|---|
| P0 | Full Experiment A / G2 | Add mandatory forced processing beyond the measured challenge-only failure; qualify independent-wallet load and hostile inclusion policy beyond the measured finite seal-churn budget, sustained queue/dependency workload and targeted-lane failure, hostile miner policies and unplanned reorgs. Proof-bound A3 duty recovery and planned proof rollback/reapplication now pass. Individual A2 authenticity, bounded overload/drain and planned-reorg carry-forward now have measurements. |
| P0 | Batch admission / W-12 | The implemented input encoding/inline-DA bounds have optional authenticated A2 input prefixes and an A3 mandatory sealed-set gate, but still need the production enforcement selection, L1 timestamp bounds, on-chain/proved binding to the new Ethereum envelope and deterministic rejection semantics, plus proved execution resource limits. |
| P0 | Execution / G5 | Extend the measured allocation-bound verified transition with state checkpoints, broader differential conformance and ordinary Ethereum tool deployment; replace experimental genesis/supply limits. |
| P0 | Validity settlement / G3 | The first real-domain proof-consuming transition, 40 script rejections and planned P2P rollback/reapplication now pass. Two sequential nonempty intervals and skipped-proof rejection now pass. Proof-bound A3 fulfillment and same-proof P2P recovery now pass. Qualify key/setup provenance and the remaining production envelope. |
| P0 | Recovery / G6 | Cold settlement recovery on two nodes now survives a planned P2P rollback and proof reapplication. Qualify another prover completing canonical inputs, unplanned faults/reorgs and archival retrieval. |
| P0 | Bridge and exits / G7 | Deposit/withdrawal conservation, replay resistance and operator-independent exit evidence; no release on experimental cursors. |
| P1 | Operations / G9 | Qualify the local journal under hardware/long-run faults; add network-driven reorg handling, monitored archival retrieval, independent operators and long-duration fault injection. |
| P1 | Governance / G8 | Enforced upgrade boundaries and exit-preserving rules. |
| P1 | Performance / G4 | Published deployment thresholds and sustained workload measurements including DA and proving cost. |

## Next implementation order

First close Experiment A's enforcement gap and define the production batch
admission envelope. Keep A1 as a correctness reference and reject live mutable
A3 dependencies for canonical anchors. Treat A2 obligations and authenticated
sealed snapshots as candidate constructions with bounded mechanism evidence,
requiring admission fairness, proof-bound fulfillment and hostile-network
qualification before selection as a production mechanism.

Then implement one complete path: Ethereum transaction → deterministic execution
→ CKB-published data and anchor → validity proof → verified settlement → withdrawal.
Only extend throughput, fast confirmations or external DA after this path is
recoverable without its original operator. No stand-in proof, simulated inclusion
or hash-only publication may be used to pass these gates.

## Local validation

```bash
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace
cargo run --locked --bin tactus-o1-experiment-a
CKB_BIN=/absolute/path/to/ckb scripts/run-devnet-experiments.sh
```

The supported development and CI target is CKB 0.210.0 only. Previous 0.121.0
measurements are historical evidence. The launcher uses isolated RPC/P2P ports
18714/18715. `TACTUS_DEVNET_RPC_PORT` and `TACTUS_DEVNET_P2P_PORT` select other ports.
The selected binary must be CKB 0.210.0. Each run creates a fresh directory under
`artifacts/a123-*`; configuration, manifest, logs, evidence and summary are kept
there, and its own node is stopped on exit. Existing nodes are never stopped or
reconfigured. The fixed keys are for these funded dummy chains only.

CI also runs the reference devnet suite and uploads evidence on failure. Its
presence in the workflow is not a claim that remote CI has run on unpushed changes.

The input-publication suite can be run independently with
`TACTUS_DEVNET_SUITE=replay-batch CKB_BIN=/absolute/path/to/ckb scripts/run-devnet-experiments.sh`.
Its code and wire format are separate from the A1 bare-commitment reference so the
latter cannot serve as an accidental fallback for the input-publication anchor.

The authenticated A2 comparator runs with
`TACTUS_DEVNET_SUITE=replay-priority CKB_BIN=/absolute/path/to/ckb scripts/run-devnet-experiments.sh`.
A completed comparator records `forced_inclusion: FAILED`: this is the expected
adversarial finding, never a G2 pass. Its rules and scope are specified in
[A2_OBLIGATION_V1.md](A2_OBLIGATION_V1.md).
