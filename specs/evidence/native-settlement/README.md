# Native settlement bootstrap and new proof inputs

Retained CKB 0.210.0 run `artifacts/native-settlement-auOtql6c`: 13 actual commits,
68 exact script rejections, real jointly bound native vault/anchor/Tip, two funded
publications/checkpoints and independent Geth checks. The two actual SP1 guest
executions match the complete exported journals for this real deployment.

No new proof has been generated or settled, and no custody payout occurred.
The original Tip remains live and uninitialized. The raw local node database was
retained for later proof settlement; it is not included in this audit archive.
See `specs/NATIVE_SETTLEMENT_REPORT.md` for identities, semantics and open gates.

Original runtime manifest and compressed evidence/logs are preserved. A separate
guest manifest records the already-built ELF/runner/source and exact input hashes.
The later audit manifest fingerprints the final auditors, tests, docs and CI.
These are consistency/provenance checks, not consensus or proof verification.

```sh
(cd specs/evidence/native-settlement && sha256sum --check SHA256SUMS)
python3 -B scripts/check-native-settlement.py specs/evidence/native-settlement/0.210.0
python3 -B scripts/test-native-settlement.py
```
