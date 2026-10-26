# 0.02 EVM proof statement

This is the separate Tactus 0.02 SP1 program. It still executes EVM transactions through the existing Rust executor. It is **not** the proposed experiment with contracts executing directly on RISC-V. It is also not an incremental state-witness guest: the current statement replays the full committed prefix.

The shared journal derives both complete Controls, including the published deposit/priority cursors, EVM root/header and actual bridge supply/burn. Each private frame supplies the complete sealed snapshot and batch. CKB must independently authenticate the publication checkpoints and verify a real proof before updating Control. Native replay and guest execution are not settlement evidence.

## Local build and checks

From the repository root:

```sh
cargo +1.97.1 test --locked --offline --manifest-path proofs/v02-sp1/Cargo.toml -p tactus-v02-proof-journal
scripts/build-v02-proof-guest.sh
CARGO_TARGET_DIR=artifacts/prover-host/target CARGO_BUILD_JOBS=4 cargo +1.97.1 build --release --locked --offline --manifest-path proofs/v02-sp1/Cargo.toml -p tactus-v02-sp1-host
```

The build script requires the pinned official SP1 6.8.1 CLI already used by the historical experiment. The new guest is at `proofs/v02-sp1/target/elf-compilation/riscv64im-succinct-zkvm-elf/release/tactus-v02-sp1-guest`. The host is at `artifacts/prover-host/target/release/tactus-v02-sp1-host`.

Derive a key with `tactus-v02-sp1-host key GUEST_ELF NEW_KEY_JSON`. Construct an input that pins that actual key and run `tactus-v02-sp1-host execute GUEST_ELF INPUT_JSON NEW_OUTPUT_DIR`. Both destinations must be new; existing reports are not overwritten. The host rejects a mismatched Policy key and compares all 866 journal bytes with native replay. It has no proving mode and makes no submission to CKB. CPU setup can use several GiB of RAM; use the existing local thread limit when running it.

For labeled synthetic execution checks only, `cargo +1.97.1 run --locked --offline --manifest-path proofs/v02-sp1/Cargo.toml -p tactus-v02-proof-journal --example fixture-input -- KEY_JSON PREFIX END_EXCLUSIVE` emits an input JSON. This example uses synthetic Config and wrapper identities and must not be deployed or described as canonical chain evidence. It contains four full lanes and 32 deposits, processed over eight same-timestamp batches. The selected interval determines which prefix is replayed. Canonical exports will instead come from the new observer/deployment workflow.

## Evidence boundaries

- `key`: actual guest verification-key derivation; no execution or proof.
- `execute`: actual guest execution and complete native/guest journal comparison; no proof.
- `proof_generated`, `authenticated_publication`, `ckb_settlement` and `custody_release` remain false in execution reports.
- The 64 MiB JSON-file bound is a development importer constraint, not a claim that arbitrary historical prefixes fit it.
- Real complete proof generation, canonical settlement and release are the separate 0.03 acceptance milestone. The 0.02 negative controls must still reject wrong keys, profiles, boundaries and invalid proofs.

See [wire format](../../specs/V0_02_WIRE.md) and [implementation status](../../specs/V0_02_IMPLEMENTATION_STATUS.md) for the exact statement and remaining work. No CI or independent RISC-V comparison is started by these commands.
