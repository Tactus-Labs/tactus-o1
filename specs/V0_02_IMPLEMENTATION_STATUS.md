# Tactus 0.02 implementation status

Updated 26 October 2026. **All eight work packages have completed isolated-development acceptance for the v0.02 development release.** The scope remains all eight work packages and 36 acceptance cases in the [implementation plan](V0_02_IMPLEMENTATION_PLAN.md). Local tests now include shared rules, EVM replay, and actual CKB-VM script executions. Injected settled-state fixtures are labeled explicitly; they do not establish SP1 proof validity or safe asset custody.

## Implemented locally

- A separate `v02` protocol feature with versioned Policy, Config, Boundary, Control, Journal, Deposit, Vault, Admission, Lane, Snapshot, Schedule, Watch, batch and nullifier encodings. Historical wire formats remain separate.
- Independent Python and Rust vectors for 24 encoded objects and hashes. Bounds are checked before decoding variable-length collections, and the native batch limit includes all metadata.
- Shared A3 transitions covering all configured lanes and the sealed deposit tail, two independent mandatory prefixes, eight-batch epochs, admission receipts and publication checkpoints in the required transaction role sets.
- Structural settlement progress, equal timestamps, pending-work indices, batch/deposit backpressure, terminal mode changes, and exact since flag checks. Actual live-cell and maturity checks remain an adapter responsibility.
- Custody partition arithmetic and three independent 256-bit nullifier trees, now connected to MPT burn proofs, typed receipt refunds, EIP-712 low-S ownership signatures, exact payout locks, and Vault capacity checks.
- A separate full-state EVM execution profile with committed allocation and bridge runtime, credits before user transactions, reserved priority gas, deterministic over-limit outcomes, actual bridge supply/burn reads, and atomic rollback.
- A separately buildable CKB adapter covering all twelve operations, actual joint genesis, immutable records, full transaction role sets, live Control dependencies, mandatory records, direct source outpoints, capacity preservation, exact since flags and the actual SP1 Groth16 verifier.
- Actual CKB-VM test sequences for genesis, admission, deposit, seal, append, watch, freeze and refund. Separate injected-state tests exercise normal release, existing/absent EOA escape, fulfilled-ticket closure, invalid proof rejection and terminal freeze. A real ZK settlement is not injected and reported as successful.
- A separate SP1 6.8.1 EVM guest/journal/host workspace with pinned cryptographic patches, bounded snapshot/batch frames, full-prefix replay, execution-derived start/end Controls and commitments to interval inputs and outcomes. Key derivation and guest execution are separate from proving.

The new EVM tests include a priority transaction exhausting 250,000 gas followed by a successful withdrawal; malformed, wrong-chain, nonce and gas-limit rejection; equal-time continuation; maximum safely funded aggregate credits; distinct recipient credits; and a late credit failure rolling back an earlier successful credit.

## Work package audit

| Package | Current implementation | Continuing limit / next milestone |
| --- | --- | --- |
| WP1 | Versioned wire, immutable identities, independent vectors, joint genesis and qualified development envelopes | Public parameter selection remains open |
| WP2 | Total EVM execution, equal time, gas reservations, credits and actual selected stress guest runs | Universal worst-case/long-history proving cost not established |
| WP3 | Control, backpressure, exact live dependencies and strict settlement progress | Real proof races in 0.03 |
| WP4 | Complete sealed snapshots, dual FIFO obligations, authenticated receipts, actual lane/Vault races | G2 adversarial admission fairness remains OPEN |
| WP5 | Canonical Watch/Freeze/Close, dual ages, fixed refunds and terminal mode gates | Actual proof-versus-freeze competition in 0.03 |
| WP6 | Three claim paths, real MPT/ECDSA/nullifiers in VM, canonical refunds and independent exports | Canonical positive release/escape from real settlement in 0.03; contract exits unsupported |
| WP7 | Pinned new guest/key/journal, actual verifier, legacy negatives and canonical proof-input export | Real proof/settlement/release in 0.03 |
| WP8 | Canonical reconstruction/reorg/outage recovery, claims, per-slot outcomes, lifecycle/confirmations, funding and retention limits | Confirmation risk policy, archive scale and process RSS remain unqualified |

No V02 acceptance case is marked fully closed merely because a shared-library test passes. `settlement_candidate`, `freeze_candidate` and `claim_accounting` remain pure functions; the new adapter supplies source, proof, signature and payout checks. Canonical-chain authority, maturity and races must still be tested at that layer.

## Local validation

```sh
python3 scripts/generate-v02-vectors.py --check
cargo test -p tactus-o1-protocol -p tactus-o1-execution --all-features --quiet
cargo clippy -p tactus-o1-protocol --all-features --all-targets -- -D warnings
cargo clippy -p tactus-o1-execution --features v02 --lib -- -D warnings -A clippy::needless_borrow
scripts/build-v02-script.sh
cargo test --manifest-path proofs/ckb-v02/Cargo.toml --all-features --locked --offline -- --nocapture
cargo clippy --manifest-path proofs/ckb-v02/Cargo.toml --all-features --all-targets --locked --offline --no-deps -- -D warnings
cargo +1.97.1 test --manifest-path proofs/v02-sp1/Cargo.toml -p tactus-v02-proof-journal --locked --offline
cargo +1.97.1 clippy --manifest-path proofs/v02-sp1/Cargo.toml -p tactus-v02-proof-journal --all-targets --locked --offline --no-deps -- -D warnings
scripts/build-v02-proof-guest.sh
```

The protocol and execution suites contain 99 passing tests, including 28 new tests for 0.02. The new adapter adds nine host cryptographic/encoding tests and ten actual CKB-VM test functions; the new proof statement adds five tests. The new recovery workspace adds thirteen tests covering sparse-tree reconstruction, claim exports, settled-prefix selection, observer failure/recovery, funding and Watch status, including payload/count ceiling checks, bringing these suites to 136 passing tests. The current canonical-chain run records 25 deployment/operation/rejection/reorg/funding events; a separate contention run records 39 events; the full-backlog run records 78 and the maximum-byte-envelope run records 68; these are reported separately from Rust test counts. These include legacy regression suites and independent Geth execution vectors. Protocol Clippy passes with warnings denied. The new adapter, journal, host and recovery-workspace targets also pass Clippy with warnings denied. The SP1 host dependency build reports a pre-existing future-incompatibility notice for proc-macro-error2 2.0.1. The adapter dependency build emits existing vendored lifetime-syntax warnings; those vendor files were not changed. No CI, new proving run, or RISC-V comparison experiment was executed.

Execution-library Clippy passes with the existing `needless_borrow` lint allowed. Without that allowance it reports the pre-existing `credit_calldata(&config, &record)` call in the historical native profile at `src/native_bridge.rs:238`; that profile was left unchanged. This is not a clean strict-Clippy result for the execution crate.

## Current CKB-VM evidence and limits

The adapter tests execute the actual RISC-V ELF with the CKB script verifier. They verify the precise script error for missing records, wrong locks, forged receipt substitutes, wrong since metrics, insufficient freeze thresholds, refund capacity loss, invalid proofs, frozen settlement, unauthorized closure, modified payout locks/signatures, fabricated account absence, and duplicate claims. Existing and absent EOA states are both exercised. Settled roots for release/escape are explicitly synthetic; the freeze/refund sequence starts from verified genesis and real test transactions without requiring a first proof.

The maximum envelope test constructs 32 actual admissions (eight 1,024-byte messages per lane) and 32 actual deposits before sealing, then publishes a 262,144-byte batch with both four-item obligations and 16 blocks. Measured complete transaction sizes/cycles for the current adapter are:

| Fixture | Transaction bytes | CKB-VM cycles |
| --- | ---: | ---: |
| Maximum snapshot SEAL | 36,557 | 27,367,317 |
| Maximum encoded batch APPEND | 264,185 | 61,234,422 |
| Release, synthetic settled root | 1,686–1,770 | 7,692,418–7,729,453 |
| Escape, proven absent native account | 2,107 | 13,885,985 |
| Escape, existing EOA | 2,275 | 14,129,751 |

These figures are not proof-generation timing or a complete V02-26 qualification. Deep MPT/nullifier combinations and full Groth16 rejection now have separate measurements below. Valid SETTLE, guest computational limits and actual node envelope admission still need qualification. CKB testtool verifies scripts/output-data counts; this harness does not by itself establish capacity conservation under all consensus checks, actual since maturity, dependency liveness, txpool fairness, or reorg behavior. The adapter currently accepts only direct CellDeps, so builders must expand dep groups. Arbitrary contract-held asset escape remains unsupported.

## Next implementation sequence

1. Qualify the remaining transaction/claim/guest and recovery resource limits.
2. Complete remaining source/key/role, backpressure and competing-progress cases from the [36-case audit](V0_02_ACCEPTANCE_AUDIT.md).
3. Audit all 36 acceptance cases against actual evidence, clearly retaining the real-proof settlement/release boundary for 0.03.
4. Prepare the plain-English release notes with Mermaid diagrams from completed results. Then prepare the independent RISC-V experiment framework and detailed comparison method, leaving the experiment unexecuted.

The RISC-V work is not a dependency of 0.02. It will compare execution choices after the protocol boundary is stable, without making a second execution environment part of this release.

## Current program identities

The locally built CKB adapter ELF SHA-256 is `6eb225224ff2ed7d713a5bd72ef0dcd5237292ed64332cd8030b8a87a9d6cd25`. The locally built 0.02 EVM guest ELF SHA-256 is `77bf8f4082a8e059ee07f734c906d0f2ad08dd2f1b68775f148de89c1b3c79fc`, with actual SP1 key `0x000fcab5ecc9b6b3c2616ca0f8e76d9396876f26ea4fc0701997df7045acc0c6`. These identify development builds, not a qualified deployment manifest.

Two actual guest executions use labeled synthetic fixtures: prefix 0 / interval 1 and prefix 1 / interval 1. Each interval contains four deposit credits and four malformed priority inputs. All 866 public journal bytes match native replay, and the first end Control exactly equals the second start Control. Both batches have the same timestamp. The second execution still replays the first batch as its full prefix; this is not incremental proving. Its report includes actual Keccak and SHA syscalls, confirming those patched paths are active. This is an execution/correctness check, not proving time or canonical settlement. Build logs, the key, input and execution report are retained locally under `artifacts/v02-*`; the input source is the checked-in `fixture-input` example.

A compact source/build/evidence fingerprint is retained in [the local validation record](test-vectors/v02-local-validation.json). The raw logs and input fixtures remain local artifacts; this record is not a release or production qualification.

## Canonical CKB deployment and recovery evidence

The new `services/v02-lab` workspace and `scripts/run-v02-devnet.sh` run on two fresh loopback-only CKB 0.210.0 nodes. The earlier successful run is `artifacts/v02-canonical-FYpANyan`; its [compact evidence record](test-vectors/v02-canonical-validation.json) pins the deployment, files, source fingerprint, transactions, errors, branch identities and guest execution.

The run jointly created all protocol cells, published a signed priority withdrawal and two equal-time batches, and showed that a post-seal deposit stayed outside the earlier sealed prefix. CKB consensus rejected a future timestamp and a young Watch even after the Control was already old. A separate fee-paying actor successfully froze the matured instance and returned ticket capacity. A previously executable transaction then failed on the exact spent Control outpoint. Fresh processes reconstructed and submitted both real refunds, including a nonempty nullifier path for the second claim and external occupied-capacity top-ups. All principal on that branch was refunded with the reserve intact.

A real P2P heavier-branch reorg then replaced that history with a conflicting deposit. The fresh reconstruction returned to RUNNING at the common Control, removed the old publication/freeze/refund history and rejected the orphan deposit receipt. This is a CKB branch rollback, not an in-protocol unfreeze. Publication subsequently resumed on the winning branch. SETTLE and normal RELEASE reorgs have not been established with real proofs and are not claimed here.

The final stopped devnet retains a RUNNING instance and `canonical-proof-input.json`, containing two batches and a real signed 1-CKB burn. SP1 execution of this exact export matches every journal byte from native canonical replay. The guest report itself does not authenticate CKB; the separate canonical export and matching input hash provide that association under the selected-node trust assumption. No full proof was generated, and the live Control remains unsettled. The successful historical frozen-branch export is kept separately and must not be submitted as the current settlement input.

The CLI exports reports, current proving intervals, refundable deposit witnesses and settled-prefix release/EOA witnesses (with a separate unsigned escape signing step). It rescans canonical data, atomically replaces whole successful snapshots and fails on a tip change; the separate continuous observer records failed refreshes and preserves cached state only as historical data. Optional funding reports are implemented; production archive qualification remains incomplete. A claim still requires the owner/submitter's recipient-lock preimage and external funding as applicable. Resource limits and selected-node trust are documented in the [tool README](../services/v02-lab/README.md).


## Claim export and observer continuation

The release exporter now reconstructs the settled withdrawal commitment; the EOA exporter reconstructs bridge balance and owner inclusion/absence proofs and verifies a supplied EIP-712 signature. Unsigned escape requests expose the digest and exact context but cannot be submitted as claim witnesses. Four integration tests use explicit synthetic settled fixtures, reject redirected amounts/recipients and invalid signatures, reject contract owners and repeated claims, and prove that later publication cannot raise an earlier settled balance. The current canonical instance remains uninitialized for settlement, and both real CLI asset exports correctly reject it.

The continuous observer rescans canonical data, checks the tip again before export, atomically replaces one status document and marks cached data non-current on failure. A local integration check stopped and restarted the actual selected CKB node under a live observer: it reported failure without losing historical context, then recovered at the same canonical pin. No transactions or proofs were produced. The compact [recovery-tool evidence record](test-vectors/v02-recovery-validation.json) identifies the tested sources and logs.

A host-only read access method supports trie reconstruction. The rebuilt guest SHA-256 remains `77bf8f4082a8e059ee07f734c906d0f2ad08dd2f1b68775f148de89c1b3c79fc`, byte-for-byte equal to the previously executed guest; its Policy key and canonical input remain unchanged. At that checkpoint, the six recovery-workspace tests, execution regression suite, strict new-workspace Clippy and guest rebuild passed locally. These checks do not close the remaining resource, race, contention or real-proof gates.


## Funding, Watch maturity and contention continuation

The latest main run is `artifacts/v02-canonical-PbHWETqt`; the independent contention run is `artifacts/v02-canonical-V4ztU6kT`. Their compact [operations evidence record](test-vectors/v02-operations-validation.json) supersedes older run locations for these checks while preserving the older evidence as historical records.

The main run verifies that Watch reporting uses both actual canonical creation heights. Both young tickets were ineligible; both became eligible after the configured delay. It then performs an ordinary transfer that leaves the dedicated fee wallet at occupied capacity. Another fee-paying build fails, the report shows insufficient external funds and declared insufficient prover budget, and the exact live Vault and Control remain unchanged. Budget declarations are visibly local observations, not payment or provider commitments. A repeated actual observer outage/recovery check passes with this reporting enabled.

The contention run uses two independent fee wallets and actual CKB pool submissions. Four pairs compete for one lane under equal/different fees and 0/100-ms delays. Only one original transaction per pair is included; all four losers rebuild and re-sign successfully. A separate same-Vault deposit race preserves consecutive receipts. Both deposit/seal orders produce the correct sealed tail, followed by two full eight-batch epochs and canonical EVM recovery. This exposed and fixed the development builder's missing previous-Snapshot dependency when sealing epoch two. One default CKB miner policy and eight admission samples are not adversarial fairness evidence; G2 remains OPEN. Settlement latency is not measured.

The expanded actual-VM checks reject frozen DEPOSIT, SEAL, APPEND and WATCH transactions after their paired RUNNING transactions pass; ENQUEUE and SETTLE terminal gates were already covered. The mixed native EVM workload now includes explicit REVERT and invalid-signature slots alongside HALT, nonce/chain errors and a successful withdrawal, with receipt and nonce behavior checked. The full mixed workload has since matched all 866 journal bytes in the actual pinned SP1 guest; the remaining [acceptance audit](V0_02_ACCEPTANCE_AUDIT.md) is still open.


## Boundary and resource continuation

The [boundary validation record](test-vectors/v02-boundary-validation.json) fingerprints the additional evidence. The mixed workload includes HALT, success, priority/ordinary gas rejection, malformed input, wrong nonce/chain, REVERT and invalid signature. The pinned SP1 guest reproduces all 866 journal bytes, five receipts and native outcomes. Its execution report shows real secp256k1, Keccak and SHA precompile activity; this is not a proof or a proof-time benchmark. The actual new-guest host rejects a consistently encoded input that pins the historical guest key.

Two genuine historical Groth16 proofs still pass verification under their own original statements. Their old public-value formats fail the new journal decoder, and the same proof bytes with a new journal fail the actual CKB verifier. The full cryptographic mismatch path takes about 659 million type-script cycles, plus separately measured lock groups. This exceeds the usual 500-million development test budget; only these checks use the explicit 10-billion devnet block ceiling. The current verifier attempts SHA-256 public values and a Blake3 fallback, so invalid well-formed proofs can incur two pairing checks. These are rejection measurements, not a positive 0.02 SETTLE cost.

Conservative deep-claim fixtures fill 64 trie branch levels and all 256 non-default nullifier siblings. They use engineered hashed-key neighbours and opaque nullifier sibling roots: accepted cryptographic structures under synthetic settled roots, not demonstrated reachable EVM/claim histories. Release covers 130 explicit trie nodes; escape covers 194 because a short terminal storage leaf is embedded in its parent. Refund carries the full nullifier path. Exact transaction/cycle measurements are in the boundary record. Modified nullifier siblings fail. Release also succeeds with 32 later deposits still uncredited; contract-owned EOA escape is explicitly rejected.

The independent canonical run `artifacts/v02-canonical-pZiwqPGu` fills both 32-item caps, rejects both 33rd operations in the actual adapter, exports the complete proving input, and reaches the proof check for SETTLE. WATCH, mature permissionless FREEZE and a fresh-process refund all succeed at the caps. A newly funded repeated-ticket transaction fails on the exact spent ticket. Its 32-batch input also executes in the pinned SP1 guest and matches all 866 journal bytes. This is a historical pre-freeze input: the later canonical freeze spent its starting Control, so it cannot now settle that instance. No proof or settlement is synthesized for this run.

Recovery now fails closed at explicit height, transaction, cell, frame, transition, claim and visible live-state limits. It reports their scope and measured usage. Cell/frame byte ceilings bound retained canonical payload; the live-state meter does not count deleted-account/code caches or transient execution allocations. These are development retention guards, not a process-memory or production archive qualification. The real observer/node outage check passes with these guards enabled. The final resource and 36-case dispositions are recorded in the acceptance audit; product gates remain open.


## Canonical maximum-byte envelopes

The independent run `artifacts/v02-canonical-sqt8sk8P` fills all four lanes with eight 1,024-byte messages each, admits 32 deposits, commits the maximum encoded Snapshot, and commits a 262,144-byte NativeBatch with 16 blocks and both four-item mandatory prefixes. All inputs, output capacity, standard fee signatures, direct code dependencies and actual inclusion are checked by the isolated CKB node. [The envelope record](test-vectors/v02-envelope-validation.json) pins all 68 events and measurements.

| Canonically committed operation | Complete signed transaction bytes | Node cycles |
| --- | ---: | ---: |
| Maximum Snapshot SEAL | 36,836 | 29,119,128 |
| Maximum NativeBatch APPEND | 264,432 | 62,941,949 |

The independent Python Molecule estimator reconstructs both raw transaction hashes exactly and includes the full witness envelope in these sizes. Differences from the earlier VM figures reflect actual fee signatures and transaction construction. Fresh-process canonical EVM replay and actual SP1 guest execution match all 866 journal bytes. The user payloads here are malformed by design to fill the byte envelope; this does not qualify maximum EVM computation, long-prefix proving or real SETTLE cost.


## Computation and final boundary checks

The [computation validation record](test-vectors/v02-computation-validation.json) adds four actual guest executions. A real interpreter loop and a repeated Keccak loop each exhaust the gas budget in all 16 blocks. Four priority calls use their complete reserved gas before later blocks run ordinary calls. Both workloads produce 19 HALT receipts and advance the sender nonce to 19. Another workload checks all 1,024 transaction slots with valid signatures and wrong nonces. Every workload also credits four distinct recipients at the maximum safely funded aggregate used by the fixture. Each system credit remains below its fixed gas cap. All 866 journal bytes match native execution in every case.

| Synthetic workload | EVM user gas | SP1 reported execution gas |
| --- | ---: | ---: |
| Interpreter loop, 16 blocks | 16,000,000 | 2,499,792,854 |
| Repeated Keccak, 16 blocks | 16,000,000 | 14,791,875,112 |
| 1,024 valid signatures with wrong nonces | 0 | 2,132,276,750 |
| Four maximum aggregate credits alone | 0 | 40,600,673 |

These are different meters, not conversion factors or proof-generation times. Wrong-nonce inputs still incur cryptographic work. The cases establish selected stress paths at policy limits, not an exhaustive maximum over all opcode/state combinations or long histories. Full-prefix replay and eventual production proving economics remain separate roadmap work.

Additional actual-VM checks reject forged receipt creation, untyped/foreign-domain/old-code Watch sources, Config code substitutions, foreign Vault inputs, foreign-domain escape signatures and all cross-kind claim substitutions. Equal-time continuation passes, while a backwards timestamp and an omitted sealed deposit tail fail. Recovery tests preserve a pinned interval when later publication arrives and rebuild its start after a synthetic overlapping settlement, retaining the full prefix. This last test is not canonical proof-settlement evidence.

Independent Python/Rust vectors now include all three claim kinds and the private Frame. Generic exact-decoding checks cover every independently encoded protocol object. The claim parser accepts its maximum framing envelope and rejects larger lengths before allocating them; padded framing fixtures are explicitly separate from valid cryptographic paths. The latest covered suites total 136 passing Rust tests. The [plain-English release notes](RELEASE_NOTES_0_02.md) is prepared with Mermaid diagrams and retains the real-proof and product limits. The final requirement-by-requirement dispositions are recorded in the acceptance audit. Preparation of the separate RISC-V framework follows this local acceptance and must not execute that experiment.

## Lifecycle reporting and closing acceptance

[Final acceptance](V0_02_ACCEPTANCE_AUDIT.md) distinguishes complete 0.02 development work from 0.03 real-proof evidence and public-product gates. Recovery now reports per-batch Ordered/Settled observations, separate payment confirmations, authorized Withdrawable claim plans, and unobserved Received/Soft phases. Unsigned escape requests need authorization before they can become claim plans. Compact per-slot replay outcomes are separate from API failures and settlement authority.

The fresh canonical run `artifacts/v02-canonical-abyeUlVB` verifies two distinct Paid refunds, actual P2P rollback of those observations, and resumed ordering. Actual node outage/recovery also passes in `artifacts/v02-recovery-tools-lx9hunqh`. Adapter and recovery Clippy pass after the closing changes. No consensus runtime change was made; the pinned adapter ELF and EVM guest/key remain unchanged. The [resource review](V0_02_RESOURCE_REVIEW.md) collects measured envelopes and their limits.

## Independent research preparation

After the local 0.02 acceptance, the [RISC-V experiment design](RISCV_EXPERIMENT_PLAN.md) and [separate framework](../experiments/riscv-contracts/README.md) were prepared. Rust/native-guest and Solidity kernel sources, fixed-width semantic vectors, an independent oracle, result templates and a read-only comparator are present. The matched minimal EVM guest is specified as an activation prerequisite; this is framework preparation, not a complete second execution engine. No experimental code was compiled or executed, no key derived and no proof generated. Only Python syntax, JSON/TOML structure, Rust formatting and local links were checked.

## Release validation

The 26 October local rerun passed all 136 tests: protocol/execution 99, adapter host/actual-VM 19, journal 5 and recovery 13. All 24 independent vectors match. The rebuilt adapter retains the qualified hash. Historical artifact checks are separate from test execution and from proof validity. The [release validation record](test-vectors/v02-release-validation.json) pins current sources and fresh logs; the downloadable evidence bundle binds its files to the release commit. See the [release guide](V0_02_RELEASE_GUIDE.md). No CI, new proof or independent RISC-V contract experiment was run for publication.
