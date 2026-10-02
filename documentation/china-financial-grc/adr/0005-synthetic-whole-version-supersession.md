# ADR 0005: synthetic whole-version supersession and dual-time reads

- Status: Accepted for the locally verified bounded synthetic slice
- Date: 2026-10-02
- Roadmap task: `CFGRC-P1-SUPERSESSION`
- Scope: one synthetic entity, metadata-only whole-document replacement

## Context and outcome

An analyst must distinguish a new legal version from correcting an existing
recorded belief. The original one-chain selector cannot represent an old
effective version and a known future version simultaneously. Closing the old
`recorded_to` on learning about a future version would incorrectly erase what
was still known about the old law.

The outcome is a coherent, inspectable synthetic version selection, not legal
approval, source authentication, real-law ingestion or compliance assessment.

## Decision and ownership

`backend/regulatory` owns an append-only
`RegulatoryVersionSupersessionEvent`. Additive migration `regulatory.0005`
does not alter earlier migrations, backfill institution data or touch generic
CISO Assistant models. Each event binds:

- the existing document and synthetic entity-document registration;
- exact predecessor and successor version/provision/obligation physical FKs;
- distinct stable legal-version identities and recomputed chain digests;
- an explicitly supplied replacement effective date and server-owned recorded
  event time, with the successor chain starting at that time;
- a named human, rationale, request digest and folder-scoped idempotency key;
- fixed whole-document, non-binding and unpublished markers.

The old rows and their recorded/valid intervals remain byte-for-byte unchanged.
The known outgoing edge supplies a derived, exclusive valid-time upper bound;
it does not rewrite raw source status or `valid_to`. New obligations start as
`machine_proposed` and inherit no review, applicability decision or disposition.

Only `SYNTHETIC-*` entities with their exact live registration are accepted.
Both source versions need resolved effective dates, metadata-only storage and
unreviewed status. Partial amendments, cross-document replacements, repeal,
transition periods, source text and binding/publication are outside this slice.

## Authority and reliability

The internal service requires the dedicated folder-scoped
`supersede_regulatoryversion` permission and an active named human. It reuses
CISO Assistant IAM, actor/entity/folder locks, transactions and auditlog.
Existing roles are not automatically expanded; administrators must separately
grant the narrow permission where appropriate. No public mutation API exists.

Lock order is actor -> entity -> folder -> registration -> document and exact
predecessor chain. The event cutoff is after the aggregate recorded floor,
including prior review/applicability/supersession events, even under clock
rollback. Expected physical revisions and semantic digest are compared before
writing. Exact idempotent retries are reauthorised and return the existing
event; a different payload, actor or rationale cannot reuse its key.

Relations must form one connected, date-increasing linear graph. Source
snapshots and edge invariants are revalidated on every selection. Unknown,
orphaned, forked, cyclic, cross-folder, stale or ambiguous graphs fail closed.
Generic workflow event opt-out remains in force for the new audited model.

Recorded-time correction remains unchanged for documents without edges. A new
correction of any edge-bound document is explicitly refused until a separate
reviewed rebind contract exists; exact prior correction retries can still
return their immutable historical result. This prevents an edge from silently
moving to another source snapshot.

New applicability writes may not extend across a known replacement upper
bound. Previously recorded decisions remain historical evidence and are never
copied to the successor.

## Read and frontend contracts

The existing detail, applicability and applicability-review GETs accept:

- `recorded_as_of`: an aware recorded timestamp, never a future knowledge time;
- `valid_on`: one real `YYYY-MM-DD` date, including preparation queries;
- `version_id`: one portable regulatory version record ID, not a UUID.

Recorded time selects known versions/edges; valid time selects one version
within the known half-open intervals. Both explicit selectors must agree.
Version-only reads are previews and make no valid-time assertion. Without
selectors, a multi-version document uses the recorded selection's UTC date;
legacy single-version draft reads retain their existing behavior.

All three responses retain their existing requested `recorded_as_of` echo and
add the same typed `selection` shape:

```json
{
  "version_id": "TEST-CN-REG-EXAMPLE-v2",
  "version_revision": 1,
  "valid_on": "2027-01-01",
  "recorded_at": "2026-10-02T00:00:00.000001+00:00"
}
```

`valid_on: null` denotes no valid-time assertion, not non-applicability.
The response still contains exactly one complete version/provision/obligation
chain. Unknown or contradictory selectors do not fall back to the newest row.

The frontend accepts the optional anchor for legacy API compatibility, pins
both downstream reads to the detail's exact resolved version/date/recorded
instant, and rejects partial or mismatched anchors. Explicit new selectors
cannot be claimed honoured by a legacy response without an anchor. Existing
GET forms preserve the selectors; no reviewer write controls are introduced.

## Alternatives considered

1. Close or mutate the old version when learning of its replacement: rejected,
   because legal validity and recorded knowledge are different time axes.
2. Append only the new version and return the newest row or all rows: rejected,
   because future sources and unrelated/ambiguous versions could be selected
   accidentally or combined across response panels.
3. Add full amendment/repeal, approval and publication machinery now: deferred;
   these need separate human authority and lifecycle contracts.

## Verification and rollback

Required local gates: focused service/API/frontend tests, all regulatory
regressions, real migration-graph apply, migration drift, artifact/governance
validation, and an independent review. Empty 0005 history may be reversed;
populated supersession history must refuse reversal before table removal.
Reversing populated records requires a reviewed forward preservation plan.

Initial SQLite service tests pass 71 cases; the complete regulatory suite passes 160
with four PostgreSQL-only skips both with migrations disabled and through the
real project migration graph. The frozen final migration-backed run has zero
failures/errors. An independent private full-project SQLite rehearsal verifies
apply, empty rollback/reapply and populated-history reverse refusal with source
rows and the applied migration preserved. Migration drift and Django system
checks pass. Independent source review found no blocking issue.

Initial frontend focused tests pass 94 cases and the complete unit suite passes
789. Its eight owned files have no type diagnostics; that checkpoint's full
checking fails with 2063 errors and 857 warnings. Detailed commands,
source/evidence hashes, failed attempts and residual gates are recorded in
[CFGRC-REC-20261002-01](../../../.notes/china_financial_grc/progress-archive/2026-10.md#cfgrc-rec-20261002-01).

The upgraded candidate subsequently passes 168/168 PostgreSQL regulatory cases,
including four new real multi-connection supersession tests, and one fresh full
graph through 0005. It also passes 208 focused / 789 complete frontend units,
CE/isolated EE builds and 12/12 authenticated Chromium/Firefox cases with frozen
source/build/dependencies and unchanged regulatory rows. Full type checking
still fails with 2061 errors and 857 warnings, zero owned-file diagnostics.
This is bounded synthetic evidence, not a shared IAM-revocation epoch or
whole-project type/backend acceptance. See
[CFGRC-REC-20261002-02](../../../.notes/china_financial_grc/progress-archive/2026-10.md#cfgrc-rec-20261002-02).

The separate PostgreSQL upgrade graph lost its connection, reference grants
failed with a Docker-client SIGBUS, and new-table privilege/backup/restore gates
were not completed. A delayed all-file freeze fails on a generated ignored
runtime signing key while pre-existing code/dependencies remain unchanged.
Repeat that interrupted chain in new owned resources with key output outside
source; preserve the failures. Legacy-0004 operational probing must also be
isolated from the current 0005 source schema before hosted submission.

The exact 5c04 hosted follow-up passes 168 PostgreSQL cases and the isolated
legacy/restore adapter, but its operational supersession table is empty. A new
fully frozen actual-old-code 0004-to-0005 trial preserves prior rows/all 565
existing audit entries and passes empty reversal/reapplication, the precise
populated-0005 reverse refusal and five new-table SQLSTATE/constraint probes.
Backup, restore and reference grants exit zero; the full comparison nevertheless
fails on columns/indexes fingerprints (26 of 28 components match). Operations
exit one, restored v3 and the trial's suite remain unrun. The before/after source,
dependency, harness and private-input manifests match. This failure is retained,
not converted to restore acceptance by excluding schema checks. See
[CFGRC-REC-20261003-01](../../../.notes/china_financial_grc/progress-archive/2026-10.md#cfgrc-rec-20261003-01).
The changed CI/ledger candidate still requires its own hosted checks. Legal
review, real source rights and named production/operations acceptance remain open.

This slice does not claim WORM protection against privileged SQL or cryptographic
authentication of source bytes; semantic SHA-256 is not a source signature.
