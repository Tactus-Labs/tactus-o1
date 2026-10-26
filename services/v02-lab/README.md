# 0.02 canonical development tools

This separate workspace connects the new CKB adapter, actual EVM replay and fresh-process recovery. It is an isolated development harness, not a production wallet or consensus client.

## Local acceptance

With the pinned CKB 0.210.0 binary installed, run from the repository root:

```sh
TACTUS_V02_CKB_BIN=/absolute/path/to/ckb scripts/run-v02-devnet.sh
```

The script creates new node directories, binds only loopback ports, refuses occupied ports, and cleans up only its own processes. It starts two funded Dummy-consensus nodes. It never starts CI, a prover, or the independent RISC-V contract experiment. The guest/key-qualified development build from `specs/test-vectors/v02-local-validation.json` must exist; the deployment checks the guest ELF hash before pinning that key into the immutable Policy.

The run deploys immutable code and all eleven genesis cells together. It exercises a signed priority withdrawal, deposits on both sides of a seal, equal-time batches, an actually immature future timestamp, an old Control with a young Watch, a mature permissionless freeze, spent Control dependencies, ticket refunds and two real principal refunds reconstructed by separate processes. External fee inputs pay occupied-capacity top-ups; Vault reserve and principal accounting are checked on-chain.

The nodes then create competing real P2P branches. The winning branch contains a conflicting deposit. Recovery must discard the orphan deposit/receipt, seal, publication, freeze and refund history together, reject the orphan receipt, and resume publication on the winning branch. It does not use `truncate` or `submit_block`. The final canonical instance remains RUNNING with a complete two-batch proof input, including a signed withdrawal, for the later real-proof milestone. This run itself does not settle a ZK proof or exercise a normal burn release on-chain.

Evidence, deployment manifest, node configurations, full transactions, historical snapshots and the final proof input are retained in the newly printed `artifacts/v02-canonical-*` directory. The historical frozen-branch input is explicitly separate from the final `canonical-proof-input.json`.

## Fresh-process recovery

Build with `cargo build --locked --offline --manifest-path services/v02-lab/Cargo.toml`. The read-only CLI is:

```text
recover-v02 MANIFEST OUTPUT report
recover-v02 MANIFEST OUTPUT prove END_EXCLUSIVE
recover-v02 MANIFEST OUTPUT refund DEPOSIT_SEQUENCE
```

Set `TACTUS_CKB_RPC_ADDR` to the intended node. This recovery command does not require development keys or submit transactions. It trusts the selected CKB node's consensus, checks transaction raw hashes and chain continuity, reconstructs the live-cell set, independently rechecks the new adapter rules, rebuilds nullifier history, and replays all canonical EVM publications. It matches every observed Control to the corresponding execution prefix. Proof export starts at the current live Control and refuses a frozen instance.

Each invocation starts from chain data. The complete output is atomically replaced only after successful reconstruction and a final tip check; a failed invocation does not produce an updated snapshot. Callers must handle its exit status and recheck the pin before serving cached state. A concurrent tip change causes a retryable failure. Ordinary CKB input/dependency checks still protect a transaction prepared from a subsequently stale snapshot.

Refund export produces a verified claim witness, exact Vault successor, principal amount and recipient-lock hash. The submitter must supply the matching recipient-lock bytes and external fees/capacity top-up. An already-claimed sequence, running Control or orphaned receipt is rejected. Release/EOA export and continuous observer commands are described below. Funding observations and their limits are described below.

Development limits are height 100,000, 1,000,000 scanned transactions, 100,000 live cells, 100,000 protocol transitions, 10,000 frames and 65,536 claims per claim kind. Retained canonical cell payload is capped at 128 MiB, encoded frames at 24 MiB, and visible live EVM state payload at 128 MiB / 1,000,000 account-and-storage entries. The RPC response reader is separately bounded. Each exceeded limit fails the refresh/export; rights are never pruned or silently skipped. These measurements exclude deleted-account/code caches, allocation overhead and transient replay/JSON memory, so they are not process-RSS limits. These limits are not a production archive qualification. The program does not independently validate CKB PoW consensus. The fresh-process and P2P tests do not replace the separate real-proof settlement/release and resource-qualification gates.

## Settled asset claims

The additional read-only commands accept a small JSON request file:

```text
recover-v02 MANIFEST OUTPUT release REQUEST_JSON
recover-v02 MANIFEST OUTPUT escape REQUEST_JSON
```

A release request supplies `id` and `amount_shannons` as decimal strings, `owner` as a 20-byte hex address, and `recipient_lock_hash` as a 32-byte hex hash. These must match the original withdrawal. The tool reconstructs the bridge storage proof and checks the exact settled withdrawal commitment; it cannot choose a different recipient or amount.

An escape request supplies `owner` and `recipient_lock_hash`. The tool derives the **entire balance at the settled prefix**, checks an actual empty-code or absent-account proof, and requires a frozen Control. Without `signature_hex`, it emits a signing request containing the EIP-712 digest, Config, Control, outpoints, amount and recipient. This unsigned response contains no claim witness. The owner signs that digest without a personal-sign prefix and adds `signature_hex` (65 bytes: r, low-s, recovery ID 0/1) to the request. A second invocation reconstructs current chain state and exports a witness only after full signature, MPT, nullifier and custody authorization. A changed Control requires a new signature. The tool does not handle private keys.

Both paths replay from allocation **only through the live Control's settled boundary**. Later ordered publications cannot increase a claim. An uninitialized Control, wrong settled root, unsupported contract owner or spent claim fails. Output still requires the recipient lock preimage and external fee/capacity funding to construct and submit a transaction. No submission occurs here.

The positive release/escape export tests use explicitly synthetic settled Controls, real trie witnesses and real signatures. They are not proof-settlement evidence. A stopped canonical devnet with two published but zero settled batches is used separately to verify that both export paths refuse those unproven assets.

## Continuous observer

```text
observe-v02 MANIFEST OUTPUT INTERVAL_MS [ITERATIONS]
```

This read-only process replaces one JSON snapshot after each full canonical rescan. The interval is 1,000–60,000 ms between completed scans; optional positive `ITERATIONS` gives a bounded run. It clears old status on startup, retains the last successful report as **historical data** after a failed refresh, and records the error, failure count and last-success time. Recovery replaces the entire state; it never merges old-branch claims into a new branch. Consumers must require a successful refresh, a fresh timestamp and a matching current CKB tip. Stopping the process does not keep its last file current.

Reports expose unsettled batches, pending deposits, capacity-limit flags, custody partitions and terminal mode. Without local monitoring inputs, external fee budget and prover remuneration are explicitly unobserved. Optional inputs and Watch eligibility reports are described below; no liveness claim follows from an apparently healthy observer. Long-archive efficiency and resource qualification remain incomplete.

To verify the CLI against a stopped development instance produced by `run-v02-devnet.sh`:

```sh
python3 scripts/check-v02-recovery-tools.py artifacts/v02-canonical-RUN --ckb /absolute/path/to/ckb
```

This check refuses occupied ports, temporarily starts that isolated node, rejects unsettled asset exports while preserving the previous output file, then tests one observer through a real node outage and recovery. It stops only the processes it started. It does not mine, submit transactions, generate a proof, run CI or execute the RISC-V contract experiment.

## Funding and freeze eligibility

A deployment manifest may include a local `monitor` object. This changes observation only, never the immutable Config, Policy, proof statement or asset rights:

```json
{
  "monitor": {
    "fee_lock_hash": "0x<32-byte dedicated fee-wallet lock hash>",
    "fee_target_shannons": "100000000",
    "declared_prover_budget_shannons": "0",
    "quoted_proof_cost_shannons": "100000000"
  }
}
```

Fee lock and positive target must be supplied together. The optional prover budget and positive quote must also be paired. All amounts are decimal strings. Unknown fields and malformed inputs fail. The fee report scans canonical untyped, empty-data cells under that lock, excludes typed assets and data-bearing cells, preserves occupied capacity, and compares the largest single-cell spare capacity with the supplied target. It also reports the aggregate spare capacity, but fragmented funds are not treated as sufficient for this builder's one-fee-input transaction. This is a capacity observation, not proof of signing authority, spendability under arbitrary locks or miner inclusion. Set the target high enough for the intended operation's fees and newly occupied capacity.

Prover budget is explicitly an operator declaration. Meeting a quote does not establish payment or an available prover; an insufficient declaration is reported without claiming continued liveness. Vault principal and reserve are never included as available fee funds. The canonical development run now drains a separate fee wallet with an ordinary transaction, confirms that another transaction cannot be funded from its remaining occupied capacity, and verifies that Vault and Control are unchanged.

Live Watch reports include the exact source, whether its work remains pending, Control and ticket creation heights, earliest candidate height, next-block eligibility and fixed refund-lock hash. Both creation heights contribute to maturity. A new ticket does not inherit an old Control's age, completed work cannot freeze an instance, and frozen instances permit ticket closure rather than another freeze. These observations do not bypass final CKB input, since or consensus checks.

## Contention measurements

```sh
TACTUS_V02_CASE=contention TACTUS_V02_CKB_BIN=/absolute/path/to/ckb scripts/run-v02-devnet.sh
```

This separate fresh-instance scenario competes through the actual CKB pool with two independently signed actors. It records same-lane races at 1/3-CKB fees and 0/100-ms submission delays, loser rebuilds and re-signatures, full-lane refusal, competing deposits on one Vault, and both deposit/seal orderings. It separates admission timing from eight-batch publication timing and does not measure settlement. The default CKB block template is the only miner policy tested. The sample does not establish adversarial fairness or production throughput; G2 remains OPEN.


## Full-backlog recovery

```sh
TACTUS_V02_CASE=backpressure TACTUS_V02_CKB_BIN=/absolute/path/to/ckb scripts/run-v02-devnet.sh
```

This independent fresh instance accepts 32 deposits and publishes 32 batches without settlement. The builder refuses both 33rd operations. The harness then constructs otherwise-valid candidates that bypass only the builder guard, and checks the actual CKB script rejects them with the limit error. Complete epochs and another SEAL remain possible at the appropriate boundaries. A canonical proof input is exported; an empty-proof SETTLE reaches the proof verifier at both caps, without claiming proof success. Another actor freezes a mature Watch, a new process reconstructs the first refund, and a fresh-fee attempt to reuse the consumed ticket fails on that exact outpoint. Ordinary RELEASE at full deposit backlog is covered separately by the VM's synthetic settled-state fixture; a canonical positive requires real settlement.


## Maximum encoded envelopes

```sh
TACTUS_V02_CASE=envelopes TACTUS_V02_CKB_BIN=/absolute/path/to/ckb scripts/run-v02-devnet.sh
python3 scripts/measure-v02-envelope.py artifacts/v02-canonical-RUN
```

This fresh-instance scenario fills every lane slot with its largest payload, admits 32 deposits, then submits the largest Snapshot and a maximum-byte NativeBatch with 16 blocks and both mandatory prefixes. The node estimates and commits each operation using real fee signatures and capacity funding. Fresh recovery exports the exact one-batch input. The read-only independent Python estimator reconstructs raw transaction hashes against committed evidence and reports complete signed transaction bytes. The scenario itself does not execute a guest or generate a proof. Maximum byte size is distinct from maximum EVM computation; these user payloads are malformed fillers.


## Existing EVM guest stress inputs

```text
compute-input-v02 loop|keccak|signatures|credits QUALIFIED_KEY_RECORD NEW_INPUT_JSON
```

This synthetic exporter checks native outcomes and writes an input for the existing EVM SP1 guest. The loop and Keccak cases genuinely exhaust gas in 16 blocks; the signature case checks 1,024 validly signed wrong-nonce slots. Every case includes four distinct-recipient credits near the fixture's safe aggregate capacity ceiling. It creates a new file only, makes no RPC calls and generates no proof. It is not the separate native RISC-V contract comparison. Actual guest execution is a separate explicit `tactus-v02-sp1-host execute` command. These selected maxima are not a universal worst-case opcode-cost bound.

## Lifecycle observations

`recover-v02 ... report` and the continuous observer include `lifecycle`: per-batch Ordered/Settled observations, canonical Paid claim identities and payout indices, and independent CKB confirmation depths (`tip - inclusion height + 1`). Received/Soft remain unobserved because canonical recovery cannot authenticate a local submission or a provider promise. No preconfirmation provider or safe confirmation target is implied. Mode remains separate.

Successful signed claim/refund exports have phase Withdrawable, current Control confirmations, and the existing fee/lock-preimage requirements. An unsigned escape signing request has no phase and requires the owner signature. Failed exports do not replace prior output. APPEND transitions contain compact per-slot input hashes, statuses, gas, receipt indices and output hashes from deterministic replay, not settlement authority. The 65,536-outcome reporting ceiling fails the entire refresh if exceeded; it never prunes canonical rights. Reorg recovery replaces the entire report, including payments.
