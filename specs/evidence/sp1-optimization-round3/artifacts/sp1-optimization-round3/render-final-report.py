"""Render one coherent report from measured evidence, without starting work."""
from pathlib import Path
import json,re
ROOT=Path.cwd();B=ROOT/'artifacts/sp1-optimization-round3'
def read(p):return json.loads(p.read_text())
s=read(B/'optimized-proof-pipeline.json');f=read(B/'final-source-progress.json');S=Path(s['source_output']);F=Path(f['output']);P=Path(s['output'])
assert s['status']=='complete'
assert all(c['status']=='passed' for c in f['checks'] if c['name']!='full-real-proof')
full={r['case']:r for r in read(F/'full-qualification/results.json')};adapt={r['case']:r for r in read(B/'adaptive-qualification/results.json')};history=read(Path(s['history_qualification']))
def instructions(p):
 text=p.read_text();part=re.search(r'opcode_counts: \{([^}]*)\}',text).group(1);return sum(map(int,re.findall(r': (\d+)',part)))
def timed(run):
 c=read(run/'completion.json');phase=read(run/'recursive-phase.json');selected=Path((run/'selected-proof-dir.txt').read_text().strip());r=read(selected/'result.json')
 return phase['elapsed_seconds']+r['wrapping_and_verification_seconds'],c['total_seconds_including_fresh_verification'],phase['max_rss_kib']
def row(values):return '| '+' | '.join(str(v) for v in values)+' |'
exec_rows=[]
for name,baseline in [('retained-sealed-chain',1435772),('transfers-32',4074217),('state-512-transfers-32',25094450),('state-512-empty-16',86615888),('storage-1024-writes-8',30839661)]:
 value=full[name]['instructions'];exec_rows.append(row([name,f'{baseline:,}',f'{value:,}',f'{100*(1-value/baseline):.2f}%']))
for label,baseline in [('full',21101594),('prefix',21102096)]:
 value=instructions(F/f'native-{label}/execution-report.txt');exec_rows.append(row(['native-'+label,f'{baseline:,}',f'{value:,}',f'{100*(1-value/baseline):.2f}%']))
matrix=[]
for label in ['threads4','threads8','threads8-shard19']:
 comparable,total,rss=timed(B/('proof-'+label));matrix.append(row([label,f'{comparable:.3f}',f'{total:.3f}',f'{rss:,}']))
sparse_times=[]
for label in ['first','second']:
 comparable,total,rss=timed(P/('proof-'+label));sparse_times.append(row([label,f'{comparable:.3f}',f'{total:.3f}',f'{rss:,}']))
history_rows=[row([r['prefix_batches'],f"{r['replay_instructions']:,}",f"{r['optimized_sparse_instructions']:,}",f"{100*(1-r['optimized_sparse_instructions']/r['replay_instructions']):.2f}%"]) for r in history]
comparison=read(S/'instruction-comparison.json');sparse_rows=[]
for name in ['transfers-32','state-512-transfers-32','storage-1024-writes-8']:
 r=next(r for r in comparison if r['case']==name);sparse_rows.append(row([name,f"{r['adaptive_instructions']:,}",f"{r['initial_sparse_instructions']:,}",f"{r['optimized_sparse_instructions']:,}"]))
if f['status']=='complete':
 if f['full_identical_to_proved_adaptive']:formal_proof='The final full guest is byte-identical to the resource-matrix guest.'
 else:
  comparable,total,rss=timed(F/'full-proof');formal_proof=f'The final full guest also produced a fresh 32-transfer Groth16 proof: **{comparable:.3f} seconds** comparable and **{total:.3f} seconds** including independent fresh SDK verification. All 15 negative controls passed; recursive peak RSS was {rss:,} KiB. This lab input replaces only the guest key and does not authorize an existing deployment.'
 status='Final guest qualification complete; the retained-input timing and evidence archive are pending.'
else:
 formal_proof='The final full ELF differs from the resource-matrix ELF. Its fresh complete 32-transfer proof is running; the old proofs must not be attributed to this binary.'
 status='Incremental qualification complete; the final full-guest proof and final evidence archive are still pending.'
retained_status=read(B/'final-retained-progress.json')
if retained_status['status']=='complete':
 comparable,total,rss=timed(Path(retained_status['output']))
 retained_text=f'The final full guest was also measured on the **same original zero-prefix, nine-batch workload**: **{comparable:.3f} seconds** comparable, **{total:.3f} seconds** including fresh SDK verification; recursive peak RSS {rss:,} KiB. This is **{retained_status["reduction_vs_59min_percent"]:.2f}%** below the previous 3,536.863-second (~59-minute) comparable run. The newer configuration uses eight CPU/four Go threads rather than four/two, so this measures combined code and resource changes, not an isolated code speedup. All 15 negative controls and fresh SDK verification passed. Only the lab guest key changed; the original batches and expected journal were retained.'
 status='Local qualification and same-input proving measurements complete; this remains an experimental profile, not production readiness.'
else:
 retained_text='The original zero-prefix, nine-batch workload is queued for an additional final-guest complete proof. Its new proving time is not yet available; the 32-transfer and sparse interval timings must not substitute for it.'
 status='Incremental qualification passed; final proof measurements and evidence archiving are still in progress.'
report=f'''# SP1 execution and proving optimization — round three

Date: 2026-10-15. **{status}** No CI ran. Existing deployments and native custody authority were not migrated.

## What the measurements establish

The retained approximately 59-minute benchmark already used the crypto-patched
guest and had `prefix_batches = 0`; historical
replay did not explain that original latency. Round two's same-input complete
proof already measured 1,189.921 seconds (19m49.9s) by the comparable phase sum.
This round removes redundant state work, measures prover resources, and implements
an authenticated incremental execution profile. Different workload timings are
reported separately; cycle reductions are not treated as proving-time reductions.

Small local proof workloads do not establish sustainable production TPS or that
settlement can keep pace with L1 ordering. No automatic proof-batch scheduler or
production capacity guarantee is provided by these experiments.

## Implementation

* Reuse completed block state roots and header hashes. Empty blocks still update
  headers, timestamps and base fees; reverted/halted accepted transactions still
  retain gas/nonce effects.
* Parse and validate borrowed transaction slices in one pass. Precompute immutable
  native rules and bridge bytecode from pinned build inputs. The root Cargo.lock
  and execution rules hash remain unchanged.
* Protect batches with rollback guards. Small states use bounded snapshots
  (eight accounts, eight code entries, 32 storage slots); larger states retain
  first-written account/code values. The full backend still copies touched
  accounts' storage. Sparse state is a separate option.
* `verify-pinned` retains independent replay, exact journal binding and a trusted
  guest key while avoiding CPU prover initialization. Existing real proofs verify
  in fresh processes in about 0.20–0.21 seconds; seven negative-control categories
  reject. Original SDK/ELF verification remains an independent qualification path.
* A generic backend supports both full and authenticated sparse state. The sparse
  guest reads only new batches, authenticated MPT paths, hash-checked code and a
  linked header window. Its host deliberately retains independent full replay as
  the qualification oracle; persistent incremental host verification is not added.
* Sparse writes are combined at each block root. Later transactions see pending
  values, including explicit zeroes; account recreation clears the prior storage
  incarnation. Failed batches restore roots/headers. Binary `TO1WIT01` witnesses
  replace guest-side JSON and use bounded framing plus canonical RLP headers.

Unconditional full-backend journaling slightly regressed small-state workloads,
so bounded snapshots remain. Gains below combine several changes and are not
attributed solely to rollback or a particular crypto operation.

## Final formal guest execution

The final full guest matches 25 independently Geth-checked cases / 93 blocks and
the retained chain journal. Both native guest intervals match their retained
940-byte journals. The source manifests were checked before and after compilation
and execution. Native results are execution qualification, not a new custody
proof, settlement or payout.

| Workload | Round-two instructions | Final instructions | Reduction |
|---|---:|---:|---:|
{chr(10).join(exec_rows)}

Relative to the earlier frozen adaptive candidate, final full-guest changes range
from approximately -0.35% to +0.55% in these fixtures. The 32-transfer case changes
by +0.17%; no uniform improvement is claimed for the generic-backend refactor.

## Complete proof resource matrix

All three runs use identical frozen adaptive ELF and 32-transfer input, one
worker/buffer per stage, and real Groth16 proofs. Each passed 15 negative controls
and fresh-process SDK verification. Timings exclude preparation/builds; the
comparable sum includes recursive proving and final wrapping/verification. The
last column is recursive maximum RSS. These are single samples per configuration.

| Configuration | Comparable seconds | Including fresh verify, seconds | Peak RSS, KiB |
|---|---:|---:|---:|
{chr(10).join(matrix)}

Eight CPU/four Go threads reduce comparable time by 27.73% versus four/two.
Halving shard size from 1,048,576 to 524,288 changes time by only 0.84% and raises
peak memory, insufficient evidence of a stable advantage. Follow-up proofs use
eight/four threads and the original shard size. Four-thread adaptive time differs
from round two's 1,607.494 seconds by only 0.44%.

{formal_proof}

The final 32-transfer run is 5.74% slower than the earlier frozen adaptive
eight-thread sample, despite only 0.17% more instructions; it is 23.92% faster
than the round-two four-thread measurement. These single samples do not isolate
the cause of the timing difference or establish a uniform code-only speedup.

{retained_text}

All measured proofs use the retained staged memory handoff: the recursive witness
completes first, then a fresh process wraps and verifies it. The full timings
include both stages. This is not a claim of one uninterrupted prover process.

## Incremental profile: actual proofs and CKB acceptance

`TO1SPF01` is an explicit experimental profile with a distinct guest and optional
settlement build. Exact-key canonical inputs were exported from fresh isolated
CKB deployments; their key was never replaced. A new continuation fixture for
that domain passed independent Geth checks. Both intervals produced exact journals.

| Canonical interval | Comparable seconds | Including fresh verify, seconds | Peak RSS, KiB |
|---|---:|---:|---:|
{chr(10).join(sparse_times)}

Both proofs passed all 15 negative controls and independent fresh SDK verification.
CKB 0.210.0 accepted them consecutively; the two-settlement suite rejected all
**62 controls**, including altered proof/journal fields, replay and rollback.
Independent evidence reconciliation pins the compiled settlement ELF and guest
key; it supplements actual node/SDK verification and does not itself reexecute
cryptography.

A separate real P2P reorg orphaned four blocks. Cold recovery returned settled
batches to zero. The old funding transaction was rejected; the same valid proof
with fresh funding committed again, restoring one settled batch. That experiment
recorded 41 rejections, including the old-funding rejection. It does not establish
native withdrawal authority.

## Where sparse execution helps—and where it does not

The optimized sparse guest passes 25 Geth cases / 93 blocks. These genesis cases
include both deferred trie writes and binary witnesses; their separate effects
have not been isolated.

| Genesis workload | Adaptive full | Initial sparse | Optimized sparse |
|---|---:|---:|---:|
{chr(10).join(sparse_rows)}

Small-state bootstrap remains 10.95% more instructions than adaptive full state;
the larger account and storage cases improve by 21.89% and 26.85%. The sparse
profile therefore remains an explicit option, not a default replacement.

The history experiment appends the same 32 signed transactions after empty
historical batches. Actual frozen replay and optimized sparse guests agree on all
transition fields; their profile identifiers differ intentionally.

| Historical batches | Full replay instructions | Sparse continuation | Reduction |
|---|---:|---:|---:|
{chr(10).join(history_rows)}

Sparse guest inputs contain zero old batches. Between 256 and 1,024 historical
batches, witness sizes remain about 146–147 kB and instruction counts change by
about 0.57%, consistent with the bounded 256-header window. Short histories still
regress. These adjusted history environments are execution-only lab cases checked
against the frozen replay guest, not independently Geth-checked environments and
not measured full proofs. They must not be presented as 85.5% proving-time savings.

## Safety properties and remaining limits

Bootstrap derives state from the committed genesis allocation. Continuations must
bind the starting anchor/state root/header hash to the consumed accepted settlement
tip. A self-consistent prover-chosen boundary or unchecked predecessor journal has
no authority. Domain, allocation, profile, guest identity and canonical contiguous
publication remain bound by the proof and settlement script. Missing nodes/code
are fatal; authenticated absence is distinct from missing evidence. Deletion
requires sibling paths. Batch/block numbers advance; sparse timestamps may remain
equal, matching execution, but cannot decrease.

The sparse state/journal suite passes 12 tests covering trie/reference agreement,
missing/altered witnesses, rollback/retry, continuity, storage overlays, explicit
zeroes, recreation, deletion siblings, framing/truncation and canonical RLP.
Earlier unchanged components passed 92 local Rust tests across execution/native,
checkpoint journal, settlement profiles and devnet driver; the 12-test sparse
suite supersedes its earlier eight-test component. Evidence-checker regressions
also pass. This is not a claim that a fresh 96-test aggregate ran in one command.

Experimental resource caps remain: 16 MiB initial trie witness, 64 MiB node store,
262,144 nodes, 8 MiB aggregate code, 16,384 code entries, protocol-sized individual
code, 40 MiB encoded witness, and 256 headers. Universal workload support is not
claimed. The sparse profile grants no native custody/withdrawal authority; separate
vault identity, deposit, publication and payout invariants remain necessary.
Production gates remain open. No deployment, CI, remote proving or new custody
release is authorized by this evidence.

## Identities and evidence

* Final full guest: `{f['guests']['full']['guest_key']}`;
  SHA-256 `{f['guests']['full']['sha256']}`.
* Final native guest: `{f['guests']['native']['guest_key']}`;
  SHA-256 `{f['guests']['native']['sha256']}`.
* Optimized sparse guest: `{s['guest_key']}`.
* Sparse settlement ELF SHA-256: `{s['two-settlements']['check']['settlement_elf_sha256']}`.
* Frozen optimized source and guest: `{S.relative_to(ROOT)}`.
* Sparse proof/settlement/history evidence: `{P.relative_to(ROOT)}`.
* Final formal source and qualification: `{F.relative_to(ROOT)}`.
* Archive: `specs/evidence/sp1-optimization-round3`, with `archive-index.json`,
  `completion-audit.json` and verified `SHA256SUMS`. Original host binaries and
  circuit files stay in artifacts; their immutable hashes are retained.

The archive is generated only after all final qualification gates pass. The
completion audit distinguishes proof generation, SDK verification, actual local
CKB acceptance, execution-only history tests and native execution-only checks.
'''
(ROOT/'specs/SP1_OPTIMIZATION_ROUND3_REPORT.md').write_text(report)
print(status)
