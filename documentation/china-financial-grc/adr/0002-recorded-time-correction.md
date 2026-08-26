# ADR 0002: controlled recorded-time correction and historical retrieval

- Status: Accepted for the Phase 1 synthetic vertical slice
- Date: 2026-08-24
- Scope: one metadata-only regulatory chain in one synthetic entity folder
- Extends: [ADR 0001](0001-regulatory-persistence-boundary.md)

## Context

ADR 0001 established an append-mostly regulatory chain and reserved correction
for a later transaction. The first implementation could return only the current
recorded belief. It could not repair metadata without overwriting a row, nor
answer what the organisation had recorded at an earlier time.

A recorded-time correction and a legal/source-version supersession are
different operations:

- a **recorded-time correction** says that the organisation's stored metadata
  or proposed interpretation was incomplete or wrong. It preserves the
  portable DocumentVersion, Provision, and Obligation identities while adding
  new recorded revisions;
- a **legal/source-version supersession** says that an authority issued,
  amended, replaced, repealed, or otherwise changed an instrument. It requires
  distinct source-version identity, source evidence, valid-time and legal-state
  decisions, and human legal review.

Combining them would let a metadata repair manufacture a legal lifecycle event.
This slice therefore needs a narrow correction boundary, coherent historical
reads, and an audit record without adding source intake, applicability,
approval, or publication.

## Decision

### Correction authority and contract

`backend/regulatory` owns one internal domain operation,
`correct_regulatory_chain`. It is not exposed as a public write API. The
operation accepts a typed, complete successor payload plus expected revisions,
the fixed-schema semantic digest of the current chain, an idempotency key, and
a human rationale. It is allowed only when all of the following hold:

- the registered entity has the public-test `SYNTHETIC-*` identity convention;
- the source remains `metadata_only`, provision text remains absent, and source
  legal-review status remains `unreviewed`;
- the authenticated named human has folder-scoped
  `correct_regulatoryrecord`; service accounts cannot act as the corrector;
- the payload preserves the existing portable record IDs and exact chain
  relationship, supplies the current expected revisions and semantic digest,
  and does not claim a source-version supersession;
- revision links and both recorded-time bounds are server-owned.

The request digest binds the actor, entity, document, typed payload, and
rationale. A retry with the same folder-scoped idempotency key and digest
returns the original result; reuse of that key for another request fails. A
semantic no-op is rejected.

### Atomic successor transaction

Correction and review mutations use a shared actor -> folder -> aggregate lock
order. The correction transaction reloads authority-bearing rows, locks the
entity, folder, registration, document, current DocumentVersion, Provision,
Obligation, and their citation link, then validates the expected revision set.
It obtains one server cutoff after the locks are held. The cutoff monotonically
follows every current revision start and review event, even if the host wall
clock moves backwards.

At that cutoff the transaction:

1. compare-and-swap closes all three current recorded intervals;
2. appends successors with the same portable IDs, revision `n + 1`, and direct
   predecessor links;
3. starts all successors at the same cutoff and recreates the exact citation
   link;
4. resets the successor obligation to `machine_proposed`; review events remain
   attached to the predecessor and are not inherited as a current conclusion;
5. appends a `RegulatoryChainCorrectionEvent` containing actor, rationale,
   request digest, exact predecessor/successor references, and canonical
   before/after semantic hashes under the persisted
   `regulatory-chain-correction/v1` digest schema.

Any validation, stale-write, linkage, or event failure rolls back the three
closures and all successor rows. Database constraints preserve one current
revision per portable ID and prevent malformed or empty correction events.

### Recorded-time read contract

The existing document-detail route remains read-only and gains an optional
query parameter:

```text
GET /api/regulatory/v1/documents/{uuid}/?recorded_as_of=<RFC-3339-date-time>
```

An omitted parameter returns the current view at one request-captured time and
keeps the response field `recorded_as_of` null for compatibility. An explicit
value must be one non-empty, timezone-aware, non-future RFC 3339 date-time and
is echoed in the detail response. The list route rejects this detail-only
parameter.

Every temporal row uses the same half-open predicate:

```text
recorded_from <= recorded_as_of
and (recorded_to is null or recorded_to > recorded_as_of)
```

The detail/service read locks the entity folder before capturing its selection
time, and correction locks that same folder before choosing its cutoff. This
linearizes a current read wholly before or after a concurrent correction. A
read uses the later of the wall clock and the aggregate's latest committed
recorded timestamp, so committed state cannot become temporarily "future" after
a clock adjustment. A
single joined citation query must resolve exactly one folder-consistent
DocumentVersion -> Provision -> Obligation revision set; review events are
limited to events recorded by that same selection time. A missing, incomplete,
cross-folder, or ambiguous chain fails closed rather than mixing revisions.

The public route first applies `BaseModelViewSet` object IAM and then preserves
its related-field IAM masking on the custom response. Invalid temporal input is
HTTP 400; a valid time with no complete visible chain is HTTP 404. No correction
event, entity registration, or hidden folder metadata is exposed merely by
document view permission.

## Alternatives considered

### Update the current rows in place

Rejected. It would destroy what the organisation previously recorded, make
review events appear to endorse changed content, and prevent defensible
historical reconstruction.

### Treat every correction as source-version supersession

Rejected. It conflates an internal recording repair with an authority's legal
act, changes source identity semantics, and could imply legal review that this
public metadata slice does not possess.

### Store only correction events and rebuild state by replay

Rejected for this slice. Event replay would add a second reconstruction model
and more complex query/migration contracts. Append-only successor rows plus an
audit event retain direct relational and IAM behaviour while preserving the
same history.

## Consequences

- Current and historical reads share one temporal selector, so the cutoff
  boundary deterministically chooses the successor and a microsecond before it
  chooses the predecessor.
- A correction intentionally invalidates the successor's inherited review
  status. A new named-human review is required before it can progress through
  the existing non-binding review edges.
- The operation is deliberately coarse-grained: all three revisions move
  together even when only one metadata value changes. That cost buys a coherent
  chain and an unambiguous audit event for the first vertical slice.
- Provenance is part of the versioned semantic digest. A provenance-only change
  is therefore an explicit correction, while an unchanged content-and-
  provenance successor is rejected as a no-op.
- The folder lock serializes mutation and current-read boundaries within this
  aggregate. It is not evidence for PostgreSQL throughput or a substitute for
  production database-role and tamper-evident audit controls.
- Review and correction timestamps advance monotonically inside the locked
  aggregate. This preserves reconstructable ordering under small or large wall-
  clock regressions without allowing an arbitrary client-supplied future time.
- This decision implements only recorded-time correction. Source/legal
  supersession, applicability, binding decisions, approval/publication, source
  text, real institution data, UI writes, and agents remain outside scope.

## Contracts and migration

`regulatory.0002_regulatorychaincorrectionevent_and_more` adds:

- the append-only `RegulatoryChainCorrectionEvent` and predecessor/successor,
  idempotency, fixed digest-schema, semantic-change, rationale, and unpublished
  constraints;
- a `(folder, document, occurred_at)` correction-event index;
- a `(folder, document, recorded_from)` DocumentVersion history index; and
- the custom `correct_regulatoryrecord` permission.

The migration does not transform or seed existing regulatory rows. It can be
reversed when no correction history exists. Once a correction event exists,
its reverse guard refuses to drop the audit table; rollback must retain 0002 or
use a separately reviewed archival migration. The optional detail query is
backward compatible with callers that do not send `recorded_as_of`.

## Verification and rollback

Focused model, service, API, IAM, idempotency, stale-write, no-op, temporal
boundary, review-reset, corruption, and migration-contract tests pass on the
project's SQLite test path. An isolated copy of the full project database
verified 0001 -> 0002 apply, empty-history rollback and reapply, and refusal to
reverse after creating an actual correction event. Django system checks and
migration-drift checks also pass.

A brand-new empty-database `manage.py migrate regulatory 0002` rehearsal is
currently blocked before the regulatory migrations by the repository's
pre-existing `iam.0009_create_allauth_emailaddress_objects` dependency looking
for an unregistered `account` app. This is an upstream fresh-empty environment
issue, not evidence that the regulatory migration ran.

Before production acceptance, run the migration on the selected PostgreSQL
version and prove with two independent database connections that a detail read
and correction linearize at the folder lock. Capture `EXPLAIN (ANALYZE,
BUFFERS)` for current and historical selectors at representative volume. Also
verify database-role, backup/restore, audit-retention, and privileged-write
controls. Until those external gates pass, SQLite evidence proves the bounded
contract only.

## References

- [ADR 0001: bounded regulatory persistence](0001-regulatory-persistence-boundary.md)
- [Target architecture](../architecture.md)
- [Regulatory domain model](../domain-model.md)
- [Migration and delivery plan](../migration-plan.md)
- [Phase and verification ledger](../../../.notes/china_financial_grc/progress.md)
