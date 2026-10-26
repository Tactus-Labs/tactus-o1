# Native RISC-V contract research — prepared, not executed

This directory is an independent experiment framework prepared after 0.02 development acceptance. **No experiment, compiler build, key derivation, guest execution or proof has been run here.** The product remains on its EVM roadmap. There are no benchmark results.

The question is whether executing selected new contract logic directly in the prover's RISC-V guest reduces enough work to justify a new execution environment. Today's Tactus EVM guest already compiles to RISC-V; it still interprets EVM bytecode through revm. Recompiling that same interpreter is not this experiment.

[Detailed experiment design](../../specs/RISCV_EXPERIMENT_PLAN.md) defines the comparison, decision gates and integration questions. This folder contains:

| File | Prepared role |
| --- | --- |
| `plan.json` | Scope, pinned baseline references, independent stages and unfilled hardware/budget controls |
| `contracts/Kernel.sol` | Solidity version of a bounded 256-bit arithmetic kernel |
| `model/src/lib.rs` | Rust version with the same arithmetic and independent research journal |
| `guest-native/src/main.rs` | Static-link SP1 guest source; not a general contract sandbox |
| `vectors.json` | Small semantic expectations, including full-word overflow and upper-half bits |
| `oracle.py` | Independent Python big-integer reference, prepared but not run |
| `inspect.py` | Read-only plan inspection and comparison of already-produced matched records; no execution command |
| `results/record-template.json` | Empty measurements; null is not zero |

The native kernel source is a first measurement scaffold, not an implemented RISC-V rollup. Before any experiment, implement the matched **minimal revm kernel guest** under the interface below. The existing full Tactus EVM guest must not be compared against this stripped-down kernel and called a fair end-to-end result. The detailed phase-B design adds the common authorization, state and witness work back to both arms.

## Adapter contract for the first comparison

Both guests receive a 32-byte big-endian seed and a `u32` iteration count. The Solidity call is `run(uint256,uint32)` with a compiler-derived selector. Compile using the repository's hash-pinned Solidity 0.8.30 binary, Shanghai target, optimizer enabled with 200 runs, and no appended CBOR/bytecode hash. Record both source and runtime-bytecode hashes. Do not infer that Solidity has a qualified RISC-V compiler backend.

The EVM guest must execute the compiled runtime through the same pinned revm dependency as Tactus, decode exactly `(bool,uint256)`, and construct the journal from the returned values. It must reject ABI failure or host-supplied replacement output. Configure a sufficient fixed call gas limit and measure it; a HALT/REVERT is a mismatch, except when explicitly added as a separate failure case. The kernel's step-limit rejection is a normal `(false,seed)` result in both implementations, not an EVM revert. Fix caller, address and execution environment even though this pure kernel does not read them.

The native guest runs the Rust kernel and constructs the same journal. It is statically linked trusted program code, with no arbitrary ELF loading, contract memory isolation, storage syscall or cross-contract call support. New native code changes its ELF/key. That cost must be included before considering dynamic deployment.

The 77-byte journal is `TARVR001 || seed[32] || steps_u32_le || success_u8 || result[32]`. Compare all bytes with the independent oracle before comparing resource measurements. It is deliberately incompatible with the 0.02 journal; the existing settlement verifier must never accept it.

## Later activation

The first future session should fill hardware/resource limits, review semantics, implement the matched EVM guest, generate and review a new Cargo.lock, pin both resulting ELFs and keys, and only then run semantic checks and execute-only measurements. No lockfile or fabricated executable hash has been supplied now. The separate workspace has no dependency from the product or CI.

These are **future commands**, not executed during preparation:

```sh
# Read-only metadata, no experiment execution:
python3 experiments/riscv-contracts/inspect.py plan
# Later, after explicit authorization to execute experiments:
python3 experiments/riscv-contracts/oracle.py
# Comparison consumes existing records; it never starts a prover:
python3 experiments/riscv-contracts/inspect.py compare EVM_RESULT.json NATIVE_RESULT.json
```

Do not run a standalone native guest and report its time as a Tactus improvement. Do not insert this code into a live Config, reuse a settlement key, introduce a CKB interpreter, change the state tree, or switch prover while measuring the execution-environment effect. Jolt can be a separate later arm with its own version and hardware records.
