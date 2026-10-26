# Tactus 0.02 local development guide

Version `v0.02` is a development prerelease. It contains a new protocol profile, EVM execution/proof statement, CKB adapter and recovery tools. It is not an upgrade for existing instances. Do not reuse a historical Config, deployment identity or proving key for new code. Public custody and the complete new proof-to-asset-release demonstration remain outside this release.

The [release notes](RELEASE_NOTES_0_02.md) explain the behavior; the [acceptance audit](V0_02_ACCEPTANCE_AUDIT.md) maps the original 36 cases to evidence and explicit remaining gates. The product label is 0.02; older Cargo packages retain their existing versions and historical behavior.

## Obtain and check the release

With Git, Python 3.11 or newer, and GitHub CLI installed:

```sh
git clone --branch v0.02 https://github.com/Tactus-Labs/tactus-o1.git
cd tactus-o1
mkdir -p artifacts/release-download
gh release download v0.02 --repo Tactus-Labs/tactus-o1 \
  --dir artifacts/release-download
(cd artifacts/release-download && sha256sum --check SHA256SUMS)
python3 scripts/verify-v02-release.py \
  artifacts/release-download/tactus-v0.02-evidence.tar.gz \
  --commit "$(git rev-parse HEAD)"
```

The verifier checks archive membership, file lengths, SHA-256 digests and the release commit without executing or extracting anything. These checks establish download integrity, not cryptographic proof validity. The manifest and checksums come from this GitHub release, not an independent attestation.

The archive retains relative repository paths. In this fresh checkout, restore the evidence and qualified executables before running the tests:

```sh
tar -xzf artifacts/release-download/tactus-v0.02-evidence.tar.gz
```

The archive includes historical raw transactions, execution reports, public-value comparisons, current test logs and the qualified CKB adapter, head lock, legacy negative-control adapter and EVM SP1 guest. It excludes node databases, prover setup caches and host executables. Historical records preserve their original source fingerprints and narrower claims; the current release source is the tag commit. A record reporting zero new proofs must not be interpreted as successful proof settlement.

## Run the local tests

Install the repository's pinned Rust 1.92.0 and Rust 1.97.1 toolchains. Install the `riscv64imac-unknown-none-elf` target for Rust 1.92.0 when rebuilding CKB programs. Initial dependency retrieval needs network access; after fetching, the validation commands can use `--offline` as in the retained logs.

```sh
python3 scripts/generate-v02-vectors.py --check
cargo test --locked -p tactus-o1-protocol -p tactus-o1-execution --all-features
cargo test --locked --manifest-path proofs/ckb-v02/Cargo.toml --all-features
cargo +1.97.1 test --locked --manifest-path proofs/v02-sp1/Cargo.toml \
  -p tactus-v02-proof-journal
cargo test --locked --manifest-path services/v02-lab/Cargo.toml
```

These suites contain 136 tests. The adapter suite runs the actual CKB ELF, so it needs the executable files restored above. Its positive release/escape tests use labelled synthetic settled roots; the genuine historical proof checks are rejection controls for the new statement.

To rebuild the adapter locally, use `scripts/build-v02-script.sh`; then compare its hash with `specs/test-vectors/v02-local-validation.json`. To rebuild the EVM guest or derive its key, follow [the pinned SP1 workspace instructions](../proofs/v02-sp1/README.md). Downloading the included guest does not require starting SP1 or generating a proof. The separate native-contract research directory is prepared source only and is not executed by these tests.

## Start an isolated CKB development run

Install CKB **0.210.0** and provide the absolute binary path:

```sh
TACTUS_V02_CKB_BIN=/absolute/path/to/ckb scripts/run-v02-devnet.sh
```

This creates two fresh loopback-only development nodes, refuses occupied ports and stops its own processes after completion. It exercises actual ordering, stalls, refunds, competing branches and recovery. Its funded test wallets and Dummy consensus are only for this isolated scenario. It does not start a prover, CI or the native RISC-V contract experiment.

The run prints a new `artifacts/v02-canonical-*` directory. The deployment and canonical proof-input files belong only to that run. Keep them together. For continuous observation, independent claim preparation and additional backlog/contention scenarios, see [the development tools](../services/v02-lab/README.md). A downloaded historical proof input is evidence, not a transaction ready for a new instance.

## What comes next

0.03 must generate new proofs, accept consecutive settlements and release assets on the same canonical deployment. 0.04 addresses repeated history replay. Admission fairness, public confirmation/stall parameters, general contract-asset emergency exits and operating economics remain open. The development release does not close those gates.
