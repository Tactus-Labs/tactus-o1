# 0.02 development resource review

Scope: the pinned isolated-devnet configuration, not a production throughput or worst-case proving certification. All figures below are measured except the explicitly labelled parser ceilings. Sources are the boundary, envelope, computation and final acceptance records in `specs/test-vectors`.

| Path | Evidence | Measured result / boundary |
| --- | --- | --- |
| Joint genesis and admission | Actual CKB and VM; wrong/missing/duplicate roles rejected | Full configured roles, four lanes with prefunded maximum queue capacity; unrelated legacy dependencies do not provide a role |
| DEPOSIT and APPEND backlog | Canonical 32 deposits and 32 batches | Both 33rd operations rejected; SEAL, WATCH, FREEZE and refund still proceed; SETTLE reaches its proof check |
| SEAL maximum encoded snapshot | Canonical node acceptance and independent Molecule reconstruction | 36,836 complete signed bytes; 29,119,128 CKB cycles |
| APPEND maximum encoded batch | Canonical node acceptance and independent Molecule reconstruction | 264,432 complete signed bytes; 62,941,949 CKB cycles; batch data itself 262,144 bytes |
| WATCH / FREEZE / CLOSE | Canonical transactions and actual-VM negative controls | Both source types, dual relative-block ages, exact live inputs, fixed refund locks and terminal mode gates; no wall-clock liveness guarantee |
| RELEASE deep claim | Actual VM, synthetic settled root | 78,079 transaction bytes; 25,007,192 cycles; 130 explicit trie nodes and 256 non-default nullifier siblings; works at the deposit cap |
| REFUND deep claim | Actual VM; canonical ordinary refunds separately | 9,329 transaction bytes; 7,479,916 cycles; 256 non-default nullifier siblings |
| ESCAPE deep claim | Actual VM, synthetic settled root | 112,609 transaction bytes; 40,381,872 cycles; 194 explicit trie nodes and 256 non-default nullifier siblings |
| SETTLE verifier | Two genuine legacy proofs rejected under the new statement | About 659 million type-script cycles, plus lock groups; uses the explicit 10-billion development block budget. Not a valid new SETTLE cost |
| Guest input bytes | Actual pinned EVM SP1 guest | Maximum-byte case and 32-batch backlog each match all 866 journal bytes |
| Guest computation | Actual pinned EVM SP1 guest | 16 full-gas blocks of interpreter/Keccak loops, 1,024 signed wrong-nonce inputs, four distinct maximum safely funded credits; see computation record for separate SP1 execution gas |
| Claim framing ceiling | Parser test, not a valid proof | Maximum 271,110-byte claim frame accepted structurally; excessive proof/outer lengths reject before allocation |

The deep MPT fixtures use engineered hashed-key neighbours and opaque nullifier sibling roots. They establish valid verifier paths under those roots, not a demonstrated reachable long EVM history. The selected guest cases are stress measurements, not a universal maximum over opcodes, state accesses or prefixes. Do not convert SP1 execution gas into proof seconds or compare it directly with EVM gas or CKB cycles.

The adapter bounds each input/output/dependency list at 64 cells, total resolved data at 2 MiB, proof bytes at 4,096 and operation bytes at the claim-frame ceiling plus its 9-byte tag. These are code constants authenticated by the exact adapter code hash in Config, alongside the encoded Policy hash and guest/rules/profile identities; they are not mutable per-transaction settings. The consensus vector record pins encodings. Merely satisfying parser bounds does not guarantee a miner will include a transaction or that every syntactically maximal MPT is valid.

Recovery uses explicit count/payload ceilings and fails closed rather than pruning rights: 100,000 heights, 1,000,000 scanned transactions, 100,000 live cells/transitions, 10,000 frames, 65,536 claims per kind and reported outcomes, 128 MiB live-cell payload, 24 MiB frame payload, and 128 MiB / 1,000,000 entries of visible live EVM state. Allocator overhead, cached deleted accounts/code, temporary RPC buffers and execution memory are additional. This is not a process-RSS guarantee.

The original real-proof milestone must measure a valid new SETTLE and canonical positive RELEASE/ESCAPE with actual fee signatures and deployment inputs. No corresponding speed or resource result is invented here. Public profile parameters, long-prefix/whole-process bounds and sustained proving economics remain unqualified. Existing ceilings and measurements suffice for the bounded 0.02 development harness, not for opening public custody.
