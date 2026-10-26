# Tactus 0.02 wire format

This is the implemented development encoding for the separate `v02` feature. It is not a deployed profile. The [implementation status](V0_02_IMPLEMENTATION_STATUS.md) records the remaining proof integration, recovery and resource qualification.

## Common encoding

Each object starts with its eight ASCII magic bytes. Integers are unsigned little-endian except existing EVM ABI words. Boolean values are exactly 0 or 1. Decoders consume the entire object and reject unknown tags, truncation and suffixes. A blob is a `u32` byte length followed by that many bytes; its bound is checked before allocation. A nested fixed object includes its own magic.

`H(tag, bytes)` is Blake2b-256 with personalization `ckb-default-hash`, hashing `tag || bytes`. Object commitment is `H("tactus/0.02/object", complete_encoded_object)`. The tag is fixed by each call site; it is not caller-selected input to a consensus operation.

All hashes are 32 bytes. A deposit cursor is `count:u64, cumulative:u128, accumulator:hash`, totaling 56 bytes. Its initial accumulator is `H("tactus/0.02/deposits/empty", config_commitment)`. Each positive deposit follows its predecessor count, cumulative amount and hash. Its object commitment becomes the next accumulator.

## Object layouts

Fields below follow the magic in serialization order. Fixed-size values are exact lengths; variable-size values show maximum bytes including magic.

| Object | Magic | Bytes | Fields |
| --- | --- | --- | --- |
| Policy | `T02POL01` | 209 | lanes:u8; pending batches, pending deposits, stall blocks, priority gas, credit gas: five u64; rules, profile, guest key, wrapper key hash, bridge code hash |
| Config | `T02CFG01` | 228 | domain, CKB genesis, adapter code hash, head lock code hash, Policy commitment, allocation commitment; chain:u64; bridge:20 bytes |
| Boundary | `T02BND01` | 227 | Config commitment; batches:u64; input accumulator; blocks:u64; timestamp:u64; deposit cursor; processed counts:four u64; epoch:u64; snapshot commitment; user cursor, deposit cursor, epoch batches:three u8 |
| Control | `T02CTL01` | 397 | mode:u8; initialized:bool; Policy commitment; profile; complete Boundary; EVM root; block hash; supply:u128; cumulative burn:u128 |
| Journal | `T02JRN01` | 866 | complete start Control; complete end Control; outcomes commitment; interval input commitment |
| Deposit | `T02DEP01` | 156 | Config commitment; sequence:u64; recipient:20 bytes; amount:u64; refund lock hash; cumulative:u128; previous deposit accumulator |
| Vault | `T02VLT01` | 248 | Config commitment; reserve:u64; deposit cursor; released, refunded, escaped:three u128; three nullifier roots |
| Admission | `T02ADM01` | 89 | Config commitment; lane:u8; sequence:u64; epoch:u64; payload hash |
| Lane | `T02LAN01` | ≤8,378 | Config commitment; lane:u8; epoch:u64; next sequence:u64; history; message count:u8; messages, each sequence:u64 and payload blob |
| Snapshot | `T02SNP01` | ≤33,689 | Config commitment; epoch:u64; lane count:u8; complete Lane blobs in lane order; start and end deposit cursors |
| Schedule | `T02SCH01` | 83 | Config commitment; epoch:u64; snapshot commitment; completed batches, user cursor, deposit cursor:three u8 |
| NativeBatch | `T02BAT01` | ≤262,144 | complete parent Boundary; snapshot commitment; priority count:u8; priority entries, each lane:u8, sequence:u64, payload blob; deposit count:u8; complete Deposits; block count:u8; blocks |
| Watch | `T02WCH01` | 150 | Config commitment; work kind:u8; lane:u8; exclusive work end:u64; source outpoint:36 bytes; observed Control commitment; refund lock hash |
| NullifierProof | `T02NUL01` | ≤8,236 | bitmap:32 bytes; sibling count:u32; non-default sibling hashes in increasing level order |

A block is `timestamp:u64, fee_recipient:20 bytes, transaction_count:u32`, then transaction blobs. The entire native wrapper shares one 262,144-byte bound. Bounds also limit a batch to 16 blocks, 1,024 transactions, 256 transactions per block and 16,384 bytes per ordinary transaction. The priority prefix is at most four payloads of at most 1,024 bytes each. There are at most four deposit records per batch.

Unused processed-count entries are zero. There are one to four configured lanes and at most eight messages per lane per snapshot. Every snapshot contains every configured lane. The initial Schedule has epoch zero and eight completed batches, allowing the first SEAL. A new epoch starts with zero completed batches; another SEAL requires all eight and both obligations completed.

## Indices and operation roles

Lane sequences begin at zero; deposit sequences begin at one. A Watch uses an exclusive work end: `lane_sequence + 1`, deposit sequence, or completed batch count. Thus work remains pending when its exclusive end exceeds the corresponding completed count. The increment is checked for overflow.

Modes are RUNNING=0 and FROZEN=1. Work kinds are batch=0, deposit=1 and admission=2; the lane byte must be zero for the first two kinds.

Operation tags are GENESIS=0, ENQUEUE=1, DEPOSIT=2, SEAL=3, APPEND=4, SETTLE=5, RELEASE=6, WATCH=7, CLOSE_WATCH=8, FREEZE=9, REFUND=10 and ESCAPE=11. Each transaction has one operation.

The shared adapter uses 41-byte type args: `domain:32, role:u8, index:u64`. Roles are Anchor=0, Schedule=1, Lane=2, Vault=3, Control=4, Checkpoint=5, DepositReceipt=6, AdmissionReceipt=7, Snapshot=8, Watch=9, Policy=10, Allocation=11, Batch=12 and Config=13. Mutable singletons, Config, Policy, Allocation and Watch use index zero; a lane uses its configured index. Immutable record indices are additionally bound to the originating transition by the adapter. Full record identity includes its outpoint and data, not only the type args.

`check_role_shape` enforces the exact input/output role combination from the [protocol operation table](V0_02_PROTOCOL_DESIGN.md#4-ckb-交易状态转换), including mandatory checkpoint and admission receipt outputs. It does not classify CKB cells or verify their script hashes itself.

## Genesis dependencies

1. Derive domain as `H("tactus/0.02/genesis", first_input:44 || anchor_output_index:u64)`. The adapter must check those values against the actual genesis transaction.
2. Build the programs, verifier and guest independently of instance-specific Config bytes. Determine immutable code/key identities.
3. Derive the bridge DOMAIN from the instance domain, CKB genesis, chain and bridge address; patch the pinned runtime. Build and commit the allocation. This step does not depend on the Config commitment or Policy commitment.
4. Commit Policy using the code/key/rules/runtime identities. Build Config and its commitment. Build all initial states from that Config commitment.
5. Jointly create Config, Policy, Allocation, Anchor, Schedule, all lanes, Vault and Control. Each adapter entry must require the same creation boundary. The CKB-VM tests exercise this joint creation, while deployment on a canonical devnet is still required.

The dependency graph has no runtime/config/key hash fixed point. Changing program code, proof inputs or execution rules requires recalculating downstream identities before deployment.

## Nullifiers and time

Claim kinds are release=0, refund=1 and escape=2. Their keys use `H("tactus/0.02/claim/key", Config_commitment || kind:u8 || identity)`. Identity is a nonzero withdrawal/deposit sequence as u64 little-endian, or the 20-byte owner address for escape. All 256 key bits participate.

An empty leaf hashes `Config_commitment || kind:u8 || 0:u8` under `tactus/0.02/claim/leaf`. A spent leaf hashes `Config_commitment || kind:u8 || 1:u8 || key` under the same tag. A branch hashes `level:u16 || left || right` under `tactus/0.02/claim/branch`; level zero is immediately above leaves. A proof folds from leaf to root using key bits from least significant to most significant in a big-endian key. Bitmap bit i, with low bit first within each byte, marks an explicit sibling at level i. An explicit default sibling is noncanonical and rejected. Insertion verifies the prior empty-leaf root before deriving the spent root.

The APPEND since value is exactly `(0x40 << 56) | last_L2_timestamp_seconds`. Each FREEZE input since must have top byte exactly `0x80` and a lower 56-bit block count at least Policy.stall_blocks. This checks encoding and thresholds; consensus enforces actual maturity. The bit interpretation follows the [CKB since RFC](https://github.com/nervosnetwork/rfcs/blob/master/rfcs/0017-tx-valid-since/0017-tx-valid-since.md).

## Reproducible vectors

`scripts/generate-v02-vectors.py --check` independently encodes the fixture with Python standard-library integer and hash functions. `crates/tactus-o1-protocol/tests/v02_vectors.rs` independently derives the Rust transitions and compares exact bytes and hashes against `specs/test-vectors/v02.txt`. Test identities are synthetic and must not be used as a deployment manifest.

## Actual CKB operation witness and adapter

The separate `proofs/ckb-v02` program now implements the transaction adapter. Every protocol type uses Data1, the Config adapter code hash, and the 41-byte args above. Its lock uses Data1, the Config head-lock code hash, and the exact type-script hash as its args. Every participating type checks the complete operation role combination. Untyped external fee/payout cells are allowed; unrelated typed inputs/outputs are rejected.

All groups read `WitnessArgs.output_type` at absolute input index zero. Its bytes are `T02OP001 || operation:u8 || payload`. GENESIS, ENQUEUE, DEPOSIT, SEAL, APPEND and WATCH have no payload. SETTLE has the complete 866-byte Journal and a proof blob of at most 4,096 bytes. FREEZE and CLOSE_WATCH have `payout_output_index:u32`. RELEASE, REFUND and ESCAPE carry the complete ClaimWitness below, whose kind must agree with the operation.

The syscall adapter reads actual input outpoints, since values, script identities, occupied capacities and data. It currently accepts only direct CellDeps, not dep groups; transaction builders must expand standard lock dep groups. Each input/output/dep set is limited to 64 cells, the complete transaction to 1 MiB, and resolved protocol data to 2 MiB. These are development parser limits, not claims about CKB consensus limits or completed resource qualification. Mutable Anchor, Schedule, lanes and Control preserve their input capacity exactly. Lanes are pre-funded for the maximum queue at genesis. Vault capacity equals its encoded reserve plus unclaimed principal, and every payout preserves that equation.

The immutable Policy pins the instance's guest verification key; the adapter also requires its wrapper key hash to equal `H("tactus/0.02/groth16-vk", SP1_6_8_1_GROTH16_VK_BYTES)` compiled into the adapter. A deployment manifest must independently match the actual guest ELF/key, execution rules/profile, bridge runtime and all script hashes. An arbitrary genesis Policy is not a certificate that the chosen guest is the intended program.

## Claim witnesses and EOA signatures

ClaimWitness is at most 271,110 bytes. The common prefix is `T02CLM01 || kind:u8 || payout_output_index:u32 || control_outpoint:36`. Kinds use the release/refund/escape numbering above. The control outpoint must equal the actual live same-domain Control dependency.

| Kind | Fields following the common prefix |
| --- | --- |
| RELEASE | withdrawal ID:u64; amount:u64; recipient lock hash; owner:20; bridge StateProof |
| REFUND | exact DepositReceipt outpoint:36 |
| ESCAPE | owner:20; amount:u64; recipient lock hash; signature:65; bridge StateProof; owner StateProof |

Every variant ends with a NullifierProof blob. A StateProof contains the historical 272-byte exact MPT Claim encoding plus a proof blob of at most 131,072 bytes. Reuse is limited to the MPT encoding/math: the new adapter binds its root, header and settled count to the actual new Control. An uninitialized Control cannot authorize an MPT claim. A refund instead authenticates the exact typed receipt dependency and its fixed refund lock.

Release proves the bridge's mapping slot 7 commitment `keccak256(TO1EXIT1 || bridge_DOMAIN || id:u64be || amount:u64be || recipient_lock32 || owner20)`. Escape proves the owner's complete bridge balance at mapping slot 3, the bridge's pinned runtime/nonce, and either an empty-code owner account or actual owner-account absence at the same frozen state. Contract accounts are rejected. The owner must sign; an absence proof alone does not authorize a payout.

The signature uses [EIP-712](https://eips.ethereum.org/EIPS/eip-712), with domain type `EIP712Domain(string name,string version,uint256 chainId,bytes32 salt)`, name `Tactus escape`, version `0.02`, Config.chain and Config commitment as salt. The message type is exactly `Escape(bytes32 controlOutpoint,bytes32 controlCommitment,bytes32 stateRoot,address owner,uint256 amount,bytes32 recipientLock)`. `controlOutpoint` is keccak256 of the exact 36-byte CKB outpoint. The other fields are the complete frozen Control commitment, its root, owner, full balance and payout lock hash. ABI words and the `0x1901` envelope follow EIP-712. Signature bytes are `r32 || s32 || recovery_id:u8`; recovery ID is exactly 0 or 1, and high-S signatures are rejected. Domain/state binding and the separate persistent nullifier together prevent replay.

The payout is an untyped, empty-data output to the exact authorized lock. Its capacity must cover both the authorized amount and its own occupied capacity. External fee inputs may top it up; the Vault debit remains exactly the authorized amount. Watch closure/freeze similarly returns at least the ticket's entire capacity to its immutable refund lock.

## New proof input and journal derivation

`proofs/v02-sp1` is a separate program and workspace with the existing pinned SP1 6.8.1 cryptographic patches. Its private input sequence is Config bytes, Policy bytes, allocation bytes, prefix count:u64, interval count:u64, then one complete Frame per prefix/interval batch. A Frame is `T02FRM01 || snapshot_blob || native_batch_blob`, bounded to 295,849 bytes. Both blobs are exact canonical objects. The snapshot commitment must match the batch; replay validates both mandatory prefixes and the complete preceding Boundary.

The interval must be nonempty and no larger than Policy.max_pending_batches. The current implementation reconstructs all preceding history from the committed allocation. It derives both Controls from actual execution, including bridge supply/burn storage. Missing input, malformed protocol frames, wrong allocation/profile, discontinuous publication or failed credit/invariant abort execution. They cannot become ordinary user rejection outcomes. This is still full-prefix replay, not the later incremental proving implementation.

`interval_inputs` starts at `H("tactus/0.02/proof-inputs", interval_count:u64)` and advances as `H("tactus/0.02/proof-inputs-step", previous32 || frame_length:u64 || exact_frame)` for each interval batch. `outcomes` starts at `H("tactus/0.02/proof-outcomes", interval_count:u64)`. Each step hashes under `tactus/0.02/proof-outcomes-step` the previous hash, credit count:u32, credit outcomes, block count:u32, and block outcomes. A credit outcome is receipt commitment32, gas:u64, log count:u32 and logs; each log is address20, topic count:u32, topics32, data length:u32 and data. A block outcome is number:u64 and Ethereum header hash32. That header's extra data commits every user's fixed success/rejection outcome and the next Boundary. These derivation rules are included in the new execution-rules descriptor.

The local host exposes separate `key` and `execute` commands. It rejects an input Policy that does not pin the actual guest's key and compares the entire public journal with native replay. Neither command generates a proof. Its current JSON importer has a 64 MiB development-file bound; canonical input export and chain authentication remain separate work.
