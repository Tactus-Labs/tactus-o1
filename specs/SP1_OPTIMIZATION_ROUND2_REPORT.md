# Crypto, batching and proving optimization — round two

Date: 2026-10-15. Status: implementation, execution qualification and both new
complete Groth16 proofs pass, including independent fresh-process verification.
No CI or CKB deployment.

## Implementation

The execution crate now computes its invariant execution-rules hash at build
time using the exact previous personalized Blake2b expression. Cargo reruns the
generator when the rules file or root Cargo.lock changes. The generated constant
is part of the guest ELF and therefore its verification-key identity; it is not
a caller-provided digest. A runtime-reference test and the retained journals
confirm the rules hash did not change. Root Cargo.lock is unchanged.

`BatchInput::decode_with_summary` returns the summary of its complete validation
together with the decoded input. `Executor::apply_batch` reuses it instead of
validating/hashing the same envelope separately before calling the decoder. The
validator still completes before allocation/return, preserves empty blocks, and
rejects malformed suffixes. Whole-batch atomicity and invalid-slot semantics are
unchanged. This removes one validation/hash pass, not every parsing pass.

Native execution keeps revm's C secp256k1 backend. For target_os=zkvm, revm uses
its existing k256 recovery backend, enabling the pinned SP1 curve precompiles.
The upstream backend already normalizes high-S signatures and adjusts recovery
parity; this code does not replace signature validation with a trusted hint.
The guest dependency tree confirms no secp256k1 0.31.1 backend in the guest and
the patched k256 revision is present. Runtime precompile counts and ECRECOVER
output comparisons confirm actual acceleration.

The previously tested Keccak, k256 and SHA-256 patches are now integrated into
both SP1 workspaces with pinned lockfiles. The guest keys change; historical CKB
deployments are not automatically upgraded or authorized to accept the new ELF.
The native-custody guest builds and both its full-range and prefix-one retained
inputs execute to the same public journals; no native custody proof or payout is
claimed.

## Controlled ablations and realistic batches

Eight new cases were generated with signed Ethereum transactions, then compared
with pinned Geth 1.17.8 over **26 blocks**: 1/8/32/128/512 transfers, 1/8 ECRECOVER
calls, and recovery edge cases. Transfers are packed at up to 32 per block (16
blocks for the 512-transfer case), within the existing admission/gas limits.
No block/gas limits or sequencing policy were increased.

The ECRECOVER cases check the recovered address directly against the signing
key, high-S/parity equivalence, invalid v/padding, zero r/s, s equal to the curve
order, empty input and ignored trailing input. These are precompile inputs inside
valid signed transactions, not invalid transaction signatures. Geth checks state,
transaction and receipt roots, gas, logs and acceptance/status. Guest journal
comparison also covers the execution outcome commitment, including return data.

All 32 variant/case executions match the native journal and archived Geth roots.
`baseline` is the retained already-crypto-patched ELF from the ~59-minute run;
`constant-only` precomputes the rules hash but keeps the old duplicate validation
and C crypto backend; `batch-optimized` additionally reuses validation; `full`
also enables the k256 ECRECOVER backend in the guest.

| Workload | Baseline instructions | Constant only | + batch validation reuse | + guest k256 |
|---|---:|---:|---:|---:|
| 1 transfer | 6,381,211 | 481,223 | 458,305 | 458,305 |
| 8 transfers | 7,225,278 | 1,325,463 | 1,283,842 | 1,283,842 |
| 32 transfers | 10,071,519 | 4,171,522 | 4,074,217 | 4,074,217 |
| 128 transfers / 4 blocks | 21,645,481 | 15,745,271 | 15,416,592 | 15,416,592 |
| 512 transfers / 16 blocks | 68,168,620 | 62,267,597 | 60,999,304 | 60,999,304 |
| 1 ECRECOVER call | 7,419,884 | 1,519,896 | 1,494,139 | 488,841 |
| 8 ECRECOVER calls | 12,255,965 | 6,355,970 | 6,291,573 | 1,619,806 |
| ECRECOVER edge cases | 9,593,781 | 3,693,791 | 3,626,698 | 1,574,839 |

Observations:

- The build-time constant eliminates a fixed cost, so its percentage gain is
  much larger for sparse batches than for filled ones. It is not a universal
  90%+ gain: the 512-transfer case improves by **10.52%** overall.
- Reusing validation contributes another **2.04%** on 512 transfers relative to
  the constant-only variant, with identical execution/journal outputs.
- Switching only the guest ECRECOVER backend reduces the eight-call workload by
  **74.25%**, relative to the batch-optimized C-backend variant. Ordinary transfer
  counts stay identical; the experiment isolates where the crypto change helps.
- Full-variant instructions per transfer fall from 458,305 at one transfer to
  127,319 at 32 and 119,139 at 512. Batching amortizes fixed costs, with diminishing
  gains in this workload. This is neither sustained TPS nor an optimal production
  proof interval: memory, latency, DA cost and proving still need consideration.

## Formal workspace qualification

Both formal guests build. The exact formal base ELF is separately checked on all
17 Geth cases (the old nine plus the new eight, **40 blocks**) and the retained
chain input: eighteen guest executions, exact full public-journal matches.
The isolated and formal ELF hashes differ, so the full proof uses the separately
qualified formal ELF; ablation percentages above describe the isolated variants.

On the retained zero-prefix, nine-batch input, the formal ELF executes
**1,435,772 instructions**, versus **23,257,553** after the previous crypto patches
(**93.83% fewer instructions**). Estimated SP1 prover gas is **1,673,923**.
The input still contains eight empty blocks and four transaction slots in the
last block. It must not be represented as nine full production batches.

The old nine Geth fixtures also pass on the isolated full candidate. Native
execution/protocol tests, native-bridge execution tests and both proof-journal
suites pass. This round changes no settlement scripts, root lockfile, wire
statement or execution rules hash. It does change the guest key and the guest
workspace dependency sources.

## Complete proving experiment

Run: `artifacts/sp1-optimized-full-proof`, launched with
`scripts/run-patched-proof-benchmark.py` using `artifacts/sp1-optimization-round2/formal.elf`.
Formal ELF SHA-256:
`5d3b788da108ff0a4466ea5101ee255e36019d65413d644f6fdadb6c3a675396`.

The retained input is changed only to bind the candidate guest key. CPU/thread,
shard, memory and staged wrapping settings match the previous run. The runner
must generate a new recursive witness, complete Groth16 wrapping, reject all
fifteen negative controls and independently verify the actual proof/journal in a
fresh process. Compilation and key preflight are outside the timed pipeline.

The real proof completes, all fifteen negative controls reject, and the fresh
process verifies the proof and exact unchanged public journal. The staged
handoff deliberately terminates the original child only after retaining the
complete new recursive witness; it is not an interrupted/incomplete proof claim.

| Comparable scope | Historical unpatched | Previous crypto patches | Round two |
|---|---:|---:|---:|
| Recursive phase | 4,560.600 s | 3,415.892 s | 1,081.928 s |
| Final wrapping + verification | 114.078 s | 120.971 s | 107.993 s |
| Sum of phases | **4,674.679 s** | **3,536.863 s** | **1,189.921 s** |
| Human-readable total | 77m54.7s | 58m56.9s | **19m49.9s** |

Round two reduces the comparable total by **66.36%** versus the previous patched
run (2.97x speedup, 39m06.9s saved), or **74.55%** versus the historical unpatched
run. This is materially smaller than the guest instruction reduction.

The unified pipeline timer is **1,190.608 s**; additional fresh verification takes
**38.311 s**. Total including fresh verification is **1,228.919 s (20m28.9s)**.
The recursive-phase peak RSS is **19,714,528 KiB**. Shrink completes at
17:42:00.984 UTC and wrap at 17:50:48.308 UTC; large wrap/preparation overhead
remains despite cheaper guest execution. System memory pressure was reported;
the machine snapshot records host swap usage, not an attribution of that swap
to the prover. These are single runs against historical baselines, not repeated
interleaved trials or production latency guarantees.

A second real proof completes on the separately Geth/guest-qualified **32-transfer**
synthetic workload and the same formal ELF/settings. It is explicitly not a
canonical CKB deployment; it measures a filled workload rather than treating
the original eight empty blocks as production traffic. This workload executes
4,074,217 instructions with estimated prover gas 4,822,591.

| 32-transfer measurement | Result |
|---|---:|
| Recursive phase | 1,499.036 s |
| Final wrapping + verification | 108.458 s |
| Sum of phases | **1,607.494 s (26m47.5s)** |
| Unified pipeline timer | 1,608.226 s |
| Additional fresh-process verification | 38.467 s |
| Total including fresh verification | **1,646.693 s (27m26.7s)** |
| Recursive-phase peak RSS | 21,102,752 KiB (20.1 GiB) |

The actual proof passes fresh verification and all fifteen negative controls.
Its public journal exactly matches both the input export and the previously
qualified formal guest result. Launch-script hashes, guest identity, new retained
witness hash and actual proof-file sizes are checked before archiving. System
memory-pressure warnings and host snapshots are retained with the evidence.
The historical ~59-minute run has a different workload, so this second result
does not provide another before/after speedup percentage or sustained TPS.

## Remaining architectural scope

The original ~59-minute measurement cannot be attributed to replaying previously
settled history: its prefix is zero. This round's same-input reduction comes
without changing the proof statement to an incremental one. It primarily removes
repeated invariant hashing in that sparse workload. Whole-state reconstruction
also exists, but the earlier profile measured only 211,463 inclusive state-root
cycles versus 21,998,253 rules-hash cycles; this tiny-state fixture does not
establish whole-state work as the dominant current cost.

The guest still replays the genesis prefix. This round removes measured crypto
and batch overhead; it does not implement authenticated checkpoints or sparse
state witnesses. Those remain the next architectural steps described in
[the scalability audit](PROOF_SCALING_AUDIT.md). Reusing the rules digest does not
make arbitrary history replay bounded, and full-state cloning/root rebuilding
remains a scaling concern even when the current fixture is tiny.

Verification has a different scope. CKB checks the interval proof and its link to
the current settlement tip; it does not rerun Ethereum history or verify every
old proof. The diagnostic host verifier replays the input to independently
derive its expected journal. The fresh verification timer includes that replay
and setup, and is separately reported above. Removing the oracle check would
not explain the observed 39-minute proving reduction. A production verifier can
instead authenticate its expected public boundaries against canonical chain
state, but must not trust a journal supplied only by the prover.

The next architecture experiment should therefore introduce an authenticated
checkpoint profile, then compare the same new interval after progressively
longer histories. A complete checkpoint first removes prefix replay; sparse
authenticated state witnesses and trie updates then address total-state growth.
Neither change is implemented by this round. Splitting the present guest into
many small proofs would retain prefix costs and add recursion/wrapping overhead.

No sustained settlement throughput, real-time proving, new CKB settlement,
deployment migration, native custody proof, or exit readiness follows from these
execution benchmarks. All production gates retain their independent requirements.

## Reproduction

```sh
python3 scripts/build-sp1-optimization-candidates.py --output artifacts/new-optimization-round
cargo +1.97.1 run --locked --offline -p tactus-o1-execution --example optimization-vectors -- artifacts/new-optimization-workloads
python3 scripts/check-execution-geth.py artifacts/evm-tools/evm artifacts/new-optimization-workloads
```

Run `crypto-patch-bench` against `verified.json` and the four candidate ELFs,
then qualify the formally built guest on both fixture sets and the retained
chain input. The benchmark requires pinned/cached toolchains and dependencies;
the existing execution-only host binary is used as the unchanged native oracle.
The full proof command and immutable hashes are retained with the evidence.

The checked archive is [evidence/sp1-optimization-round2](evidence/sp1-optimization-round2/),
including both actual proofs, journals, fresh verification logs, negative-control
results, timings, source snapshots, Geth comparisons and compressed guest ELFs.
`SHA256SUMS` covers the archive files; `completion-audit.json` records the completed
requirements and the remaining production exclusions.
