# CKB single-thread initialization adapter

This is lazy_static 1.5.1, the version already selected by the two isolated
CKB verifier workspaces. `UPSTREAM_SHA256.json` records every copied upstream
file's original SHA-256. Original MIT/Apache licenses and source are retained.
Changes are limited to Cargo feature/cfg declarations, backend selection in
`src/lib.rs`, and the added `src/ckb_lazy.rs` backend. No cryptographic arithmetic,
SP1 verification rules, wrapper key or recursion VK root is changed.

The upstream `spin_no_std` backend emits RISC-V `lr.w`/`sc.w` atomic operations.
The real CKB 0.121 VM rejected such an instruction when initializing the SP1
verification-key static. CKB script VMs have a single execution thread, isolated
memory and no interrupt callbacks into Rust. Therefore this backend uses an
explicit initialization state and UnsafeCell storage instead of an atomic lock.
Recursive/poisoned initialization panics before any uninitialized read. Values
are published only after initialization and are immutable thereafter.

The new `ckb_single_thread` feature is enabled only by the two CKB-target
dependencies. It additionally requires RISC-V bare-metal plus the explicit
`tactus_ckb_single_thread` cfg set by their build scripts. It must never be used
on a multithreaded or interrupt-driven target. Native builds retain the original
thread-safe backend. The SP1 guest, CPU prover and root execution Cargo.lock do
not use this patch.

The backend's initialization/reentrancy tests can be compiled directly on a
native host and run serially:

```bash
rustc --edition=2021 --test proofs/vendor/lazy_static-1.5.1/src/ckb_lazy.rs -o artifacts/ckb-lazy-tests
artifacts/ckb-lazy-tests --test-threads=1
```

Those tests check the local state machine, not cryptographic correctness or VM
compatibility. Real CKB acceptance/rejection experiments remain required.
