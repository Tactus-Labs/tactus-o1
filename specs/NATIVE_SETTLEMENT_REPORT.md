# Native custody settlement bootstrap and proof preparation

Status: actual joint deployment and rejection qualification on CKB 0.210.0;
**no successful native proof settlement or custody payout yet**. G1–G9 remain OPEN.

The native vault now binds a real deployed settlement type instead of the
placeholder hash used in earlier isolated experiments. A distinct verifier pins
native guest key
`0x00d159402000943b66d0df65c2c154592efbc8490b1ee44dfce8a181cd5e77e5`,
native publisher Data1 hash
`429ba46208c39ed0b2b0012d03148b33870885856043e368c3bb42f9b27a9a9b`,
and native checkpoint Data1 hash
`3e9faaf6e62593e756a28f5c5bc2f1f30e4932d3f99e076583ee9979c3416218`.
It calls the real SP1 6.8.1 Groth16 verifier with its bundled release verification
key; there is no mock or configuration bypass for proof acceptance.

## Deployment and transition binding

Type args are exactly 136 bytes: `TO1NSC02`, CKB genesis hash, full anchor type
hash, allocation commitment, vault identity (four 32-byte fields). Guest and
checkpoint identities are fixed in the verifier program. The full vault type
hash is deliberately omitted from these args, avoiding a recursive hash between
vault config and settlement identity.

Given the known first funding input, derive ordering identity at output 0 and
vault identity at output 1. The NativeCKB runtime DOMAIN omits settlement identity,
so allocation bytes and the full anchor type are known first. Construct settlement
args/type, set the vault config's settlement hash to that actual type hash, then
jointly create anchor, vault, immutable allocation and uninitialized Tip. The
native publisher enforces empty custody and the actual CKB genesis header; the
settlement script additionally verifies its own identity in that full config,
the fixed publisher type, exact allocation, unique joint anchor creation, empty
Tip and exact 522 CKB occupied capacity under its permissionless type-bound lock.
An existing anchor supplied merely as a dependency cannot bootstrap another Tip.

The 280-byte `TO1TIP01` layout remains readable by the existing native vault MPT
withdrawal verifier: initialized flag, base anchor, Ethereum root and header.
Updates consume exactly one Tip and recreate exactly one, preserving capacity
and the exact type-bound lock. A bounded `TO1NSW02` witness contains the full
940-byte `TO1NPR02` journal, proof length and actual Groth16 bytes. It binds
network, ordering type, allocation, vault identity, its own settlement type,
complete config, both native anchors/cursors and next state/header. Subsequent
updates also require previous root/header equality and strict batch/block/time
progress.

The ending **full 428-byte checkpoint** is mandatory. When the previous Tip is
initialized, the preceding full checkpoint is mandatory too; its cursor cannot
be replaced just because the base 200-byte anchor matches. At genesis, the full
before-state must instead equal a freshly constructed empty native state. Both
checkpoint type and complete bytes are checked against live dependencies, then
the actual proof is verified under the fixed native guest. A caller-selected
contract/config or arithmetic-only transcript cannot substitute for these
checkpoint checks. The host test explicitly shows that structural checks alone
can accept a changed prefix accumulator, while the returned full-state bytes no
longer match the mandatory checkpoint: no structural helper is proof authority.

## Actual run

Retained run: `artifacts/native-settlement-auOtql6c`; archive:
`specs/evidence/native-settlement/0.210.0`. The launcher stopped its isolated node
at completion; its local database remains available for the subsequent real
proof settlement experiment.

- Verifier ELF SHA-256: `4a42209ce0fcbb42133728ead8d537d53ce535e890a9ae6b4211c601898186f2`.
- Verifier Data1 hash: `d15995a26033333a67ba1a6aa12312382ce302b3ce4ae9d57de22b69e82a65bb`.
- Actual settlement type hash: `50084bc56b145efe1048fc8d2fa3e8dd7ac4e9844975826210450ebe42626854`.
- Joint genesis transaction: `0xf36e40be187ecec3cf9f0984aa1e0835859f23c97da7fda02a157aa8016526c0`; Tip output 3.
- **13 commits, 68 precisely attributed rejections**: 27 publication controls,
  16 checkpoint controls and 25 settlement controls.
- Two funded deposits total 250 CKB. Local EVM burns total 90 CKB and match Geth.
  Both publications create full immutable checkpoints. The Tip remains
  uninitialized and unchanged after all attempted unproved transitions.
- Actual SP1 CPU executions of this deployment's full interval and prefix-one
  interval take 52.382 and 51.977 seconds including setup. Both exactly match
  independently reconstructed 940-byte journals. This is execution, not proving.

Settlement genesis controls reject absent joint anchor, wrong vault identity,
allocation/network, caller-selected guest args, initialized/seeded Tip, inflated
reserve, owner lock and duplicate Tip. Update controls reject dependency-only
bootstrap, missing/untyped/stale checkpoints, a forged endpoint cursor, wrong
own identity/profile/root, changed capacity/lock, duplicate successor, malformed
witness, destruction and a nonempty genesis cursor. The retained **real v1
Groth16 proof** reaches the new verifier with the correct native journal and
actual endpoint checkpoint, and is rejected by that exact program with code 9.
No successful v2 cryptographic verification is claimed by this test.

Three host test groups cover both retained native journals, domain/config/root
binding, full-cursor checkpoint necessity, canonical Tip/args/witness bounds and
real v1-proof rejection. The independent auditor joins actual deployment,
joint Tip, funded publications, checkpoints, Geth outputs and both guest
journals. Sixteen corrupted evidence variants are rejected. Runtime and later
audit manifests are separate; their hashes are provenance, not proof validity.

## Reproduction and remaining work

```sh
bash scripts/build-native-settlement-script.sh
cargo test --locked --manifest-path proofs/ckb-native-settlement/Cargo.toml
CKB_BIN=/path/to/ckb-0.210.0 TACTUS_DEVNET_SUITE=replay-native-settlement \
  bash scripts/run-devnet-experiments.sh
# Run the independent Geth checker for the emitted execution.json, then run
# the native SP1 host on proving-input-0.json and proving-input-1.json into
# guest-0/ and guest-1/, respectively (see NATIVE_PROOF_STATEMENT_V2.md).
python3 -B scripts/check-native-settlement.py /absolute/RUN
python3 -B scripts/test-native-settlement.py
```

CI repeats the actual CKB/Geth qualification and structurally audits fresh proof
inputs using explicit `--without-guest-execution`; that report says
`guest_execution_checked=false`. The separate archive test always requires the
two retained actual SP1 execution reports. CI does not silently fabricate fresh
zkVM output or claim to run the absent prover toolchain.

Next, generate and independently verify a new real proof for the retained actual
deployment, restart the owned node, execute the first settlement and a subsequent
interval with both full checkpoints, and derive nonzero burn MPT witnesses for
real CKB payouts. Negative/replay/redirected exits, reorg recovery, native A3
obligations, full observer/recovery, archival economics, operational durability
and the other production gates remain open. This implementation must not be
presented as production custody before those positive paths are qualified.
