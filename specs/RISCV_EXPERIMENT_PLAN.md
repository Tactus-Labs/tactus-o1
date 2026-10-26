# Tactus native RISC-V experiment plan

Prepared 18 October 2026 after the local 0.02 implementation acceptance. **Not executed.** The [framework](../experiments/riscv-contracts/README.md) contains source scaffolds, vectors, an independent oracle, measurement fields and read-only comparison tooling. It does not implement a second rollup or a general native contract runtime. There are no speedup results.

## Decision and sequencing

Complete the main protocol milestones while keeping this research isolated. The 0.02 protocol baseline now exists; 0.03 still needs actual proof-driven asset settlement, and 0.04 needs authenticated incremental execution. A bounded kernel experiment may run separately once explicitly authorized. Production integration waits for evidence from the main line and the integration gates below. It must not make the asset-loop work depend on a new VM.

The research asks two questions separately: how much interpreter-related work can be removed for equivalent application logic, and how much of the **complete proving pipeline** this actually saves once common costs return. A faster arithmetic loop cannot answer the second question.

Vitalik's April 2025 proposal distinguishes directly executable new contract code from compatibility execution for existing EVM contracts. Accounts, storage and calls still need defined semantics. That motivates a native execution arm; it does not establish a speedup for Tactus. [Original proposal](https://ethereum-magicians.org/t/long-term-l1-execution-layer-proposal-replace-the-evm-with-risc-v/23617).

Jiandong's published comparison runs ECDSA inside CKB-VM inside SP1 versus directly in SP1, reporting 135.07M versus 2.62M SP1 instructions with the Rust k256 variant. This is evidence about that nested-interpreter workload, not a 51× prediction for revm or complete proof time. Our comparison does not add CKB-VM to SP1. [Benchmark source](https://github.com/XuJiandong/ckb-vm-on-sp1#benchmark).

## Controlled stages

| Stage | What changes | What stays comparable | What a result could support |
| --- | --- | --- | --- |
| A: kernel | EVM bytecode through revm versus statically compiled native application logic | Same 256-bit semantics, requests/results, SP1 version/target, host hardware and measurement scope | Selected execution overhead only |
| B: application | Contract execution path | Same ordered input, caller/authentication, nonce handling, state reads/writes, failure atomicity and commitments | Cost attributable to application execution with shared work included |
| C: full proof | The two already-qualified implementations | Same input counts, hardware, crypto policy, proof mode, security settings and independent verification | End-to-end proving difference for the tested workload |
| D: integration | A proposed second execution environment | Existing ordering, custody conservation, recovery and claim invariants | Whether the added runtime is justified; requires a fresh profile/deployment |

Stage A is deliberately small. The prepared kernel repeats `x = 3*x + 1 mod 2^256` for a bounded runtime-provided count, including seeds above 2^255. The Solidity and Rust versions use equivalent word widths; a u64-only variant would be a separate experiment. The oracle must agree on every output and the exact 77-byte research journal, including the bounded rejection case. Vary runtime inputs and inspect generated code if optimizing compilers remove or transform the loop. Do not attribute the full difference to interpreter dispatch alone: language lowering and ABI costs also differ.

The minimal matched EVM guest remains an activation task, specified in the framework README. The prepared native guest must not be compared directly with the existing full-state Tactus guest. Neither guest source has been compiled during preparation.

## Stage B execution boundary

Use a separate research statement and no custody integration. Both arms receive identical canonical requests and authenticated starting-state witnesses. Both verify authorization and nonces, apply the same application state transition, and compute the same abstract application-state commitment and outcome sequence. Do not replace authenticated state with an unchecked host map in one arm.

Initially compare normalized application state, not identical whole-chain roots: EVM bytecode and native program identities differ, so global account/code roots may differ even with equivalent application behavior. Record each implementation's root separately and bind program identities. A matching application digest alone is not an Ethereum-equivalence proof. Any design claiming equal EVM roots must additionally define the common code/state representation and verify that stronger requirement.

| Concern | Required common behavior / future negative control |
| --- | --- |
| Authorization | Same message digest, signer, chain/domain, nonce and replay rejection; identical patched crypto or explicitly separate ablation |
| State access | Authenticated old values, deterministic writes and final commitment; altered/omitted witness fails |
| Resources | Bounded calls, memory and steps; exhaustion has specified atomic rollback; do not use incomparable gas numbers as equal work |
| Failure | Separate bad authorization, application revert, exhaustion and invalid witness; witness/API errors never become successful empty work |
| Arithmetic | Matching overflow/underflow, shifts, division and zero cases; no silent word-width reduction |
| Cross-contract calls | Specify caller/origin/value, return data, depth, reentrancy, static calls and revert propagation before enabling them |
| Isolation | Untrusted native code cannot write kernel/state-verification memory, bypass metering or forge successful host calls |
| Program identity | Bind code, ABI, rules, guest/key and state format; no silent use of the old settlement verifier |

Recommended application workload progression is counter/storage updates, bounded transfers, authorization-heavy calls, hashing-heavy calls, then a small DEX operation with checked rounding and failure cases. Do not start with arbitrary EVM bytecode translation or a general replacement for Solidity tooling. CKB-style modular authorization is a separate choice: first determine the needed signer/multisig/recovery behavior, then test an equivalent dedicated proving path without changing the acceptance rules.

## Measurements and reproducibility

Before execution, fill the null hardware, thread, GPU, wall-time and memory budgets in `plan.json`. Freeze the source snapshot, lockfiles, compiler versions/options, guest ELFs/keys, patch policy and input digest. Use the same host and alternate arm order; record one warmup and at least five measured repetitions, cold/warm conditions and background load. Keep CPU/GPU and prover comparisons separate. These are planned sample sizes, not completed measurements.

Control batch, block, call, input-byte and prefix-history counts. Stage A proposes 0/16/256/4096 steps and 1/16/64 calls. Stage B proposes 1/8/32 batches and independent prefix lengths 0/32/256. Only compare matching cells of the matrix. Explicitly separate deployment/setup cost from steady-state calls; a new native ELF/key for every program is not free.

Record input preparation, guest execution, core proof, compression, wrapping, independent verification, total elapsed time, peak memory, proof bytes and precompile/instruction counts. Distinguish SP1 instructions, SP1 execution gas, EVM gas and CKB cycles. Total time includes required data/witness work and failed attempts; report one-time setup separately. Keep raw stage logs and artifacts. An execute-only record cannot support a proof-time comparison. The read-only inspector refuses unrun templates and mismatched scope, workloads, hardware or result digests; it reports single-sample ratios only, not statistical conclusions.

Published conclusions need median and spread across repetitions and transparent timeout/failure counts. Do not extrapolate kernel gains to TPS, CKB ordering latency, cell-contention fairness or withdrawal finality. Those depend on other stages and assumptions. Amdahl's law is a useful sensitivity check, but the measured fraction of total cost must come from the same workload, not somebody else's ECDSA benchmark.

## Activation and decision gates

1. The existing 0.02 acceptance and baseline identities remain intact; this workspace has no product or CI dependency.
2. Explicit authorization precedes any experiment execution. Review and lock the matched EVM guest, native guest, oracle, budgets and manifest first.
3. Every correctness case passes before timed runs. Reject the comparison on a semantic discrepancy, missing authentication or differing workload.
4. Finish complete proofs and independent verification before claiming faster proving. Assess total cost, memory and tail behavior, not only instruction count.
5. Choose a practical integration threshold before results are available, based on intended applications and maintenance costs. No threshold has been retrofitted to a measured result because no run exists.
6. Integration requires qualified isolation, metering, deployment, tooling, call semantics and migration/exit behavior. Keep the EVM route working for existing contracts. Separate the new profile and verifier identity.

Jolt Pro or another prover can be investigated later against an already-fixed statement; no unverified CPU/GPU superiority is assumed. Native RISC-V remains research unless the measured benefit survives common state/authorization work and outweighs the added compatibility and security burden.
