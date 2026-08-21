# ADR 0001: bounded regulatory persistence

- Status: Accepted for the Phase 1 first vertical slice
- Date: 2026-08-21
- Scope: one synthetic-entity regulatory register

## Context

The interchange contract preserves a regulatory chain that the existing CISO
Assistant library and document models do not own:

```text
Document -> DocumentVersion -> Provision -> Obligation
```

The chain needs portable source identities, valid and recorded time,
source/provenance fields, immutable history, folder isolation, and a review
state that cannot become a legal conclusion without a later binding decision.
Flattening it into `Framework`, `RequirementNode`, or editable managed documents
would lose those semantics and increase conflicts with upstream development.

## Decision

Create a bounded Django app named `regulatory`. It owns regulatory records,
chain-ingestion transactions, review transitions, and the versioned read API.
Existing modules keep their current authority:

- `tprm.Entity` remains the legal-entity object;
- `iam.Folder`, roles, and permissions remain the access-control perimeter;
- CISO Assistant libraries remain reviewed projections, not the legal source;
- validation flows, evidence, findings, and audit integrations remain their
  existing owners and are linked only in later gated slices.

Every authoritative regulatory row has the existing UUID database primary key
and a portable `record_id` matching the interchange contract. Temporal records
also have a positive revision number, a predecessor link, and half-open
`valid`/`recorded` intervals where applicable. A conditional unique constraint
allows at most one current recorded revision for a `(folder, record_id)` pair.

The Phase 1 write boundary is append-mostly:

- payload rows are created through one atomic service and are not editable or
  deletable through the API;
- a future correction will close only the predecessor's `recorded_to` and add a
  successor revision rather than overwrite its payload;
- obligation review changes are append-only events linked to the exact
  obligation revision;
- the initial slice permits only `machine_proposed -> analyst_reviewed ->
  legal_reviewed`, with separate permissions and different named humans for the
  two review steps; a service account cannot perform either human review;
- `approved`, `rejected`, `superseded`, publication, and formal source-version
  legal review fail closed until DecisionRecord digest binding, prerequisites,
  maker-checker approval, revocation, and audit controls are implemented.

All four chain models carry a direct `folder` foreign key so the existing IAM
query algorithm can scope them. The foreign key uses `PROTECT`, not the generic
`FolderMixin` cascade, because deleting a folder must not erase regulatory
history. Parent chain foreign keys also use `PROTECT`. Cross-row folder equality
is enforced by the transaction service and tests because a portable SQL check
constraint cannot compare columns in another table.

`EntityDocumentRegistration` associates an existing `tprm.Entity` with a
document for this synthetic pilot. It means "included in this entity's discovery
register", not "legally applicable". Actual entity applicability remains a
future `ApplicabilityDecision` responsibility. The ingestion service reloads
and locks the entity and folder from the database rather than trusting a caller-
mutated object, serialises folder-scoped idempotency claims, and records the
authenticated `ingested_by` separately from payload-declared provenance.

The public API is deliberately read-only:

```text
GET /api/regulatory/v1/documents/
GET /api/regulatory/v1/documents/{uuid}/
```

The list is a summary; detail returns the current recorded
DocumentVersion/Provision/Obligation chain. It uses the repository's
`BaseModelViewSet` IAM filtering and exposes no generic create, update, delete,
approval, publication, cascade-preview, write-object, or batch-action route.
Entity registration identifiers are not exposed by this document permission;
the API therefore does not leak `tprm.Entity` metadata to a caller lacking the
separate entity authority.

## Persistence profile for this slice

Persist now:

- stable document identity, issuer, authority, territories, discovery entity
  scopes, and domains;
- version identity, lifecycle/source metadata, source hash policy, an enforced
  `unreviewed` source marker, valid/recorded time, revision, and provenance;
- provision identity, locator, permitted text, hash, recorded time, revision,
  and provenance;
- obligation identity, normative components, deadlines, evidence expectations,
  valid/recorded time, revision, confidence, provenance, source provisions, and
  append-only review events;
- synthetic entity-to-document register membership.

The first service accepts only current recorded revisions (`recorded_to` is
null) and fixes document coverage to `obligations_proposed`, because it always
creates one provision and one machine proposal. Payload `recorded_from` and
provenance time are preserved as interchange/import facts; registration
`created_at` and `ingested_by` are the server-owned receipt evidence.

Remain target-only:

- applicability facts, rules, and decisions;
- source-version supersession relationships and correction services;
- binding DecisionRecords and publication;
- library/control/policy/evidence/finding projections;
- source bytes, OCR, licensed text storage, WORM retention, and bulk catalog
  ingestion;
- real-institution profiles, UI workflows, agents, or model calls.

## Permissions and transactions

The app is added to the IAM permission allowlist. Reader receives only
`view_regulatorydocument`. Analyst and Domain Manager receive view plus
`ingest_regulatoryrecord` and `transition_regulatoryobligation`, which permits
only the analyst edge. Approver receives view plus the separate
`legal_review_regulatoryobligation`; Administrator receives all four. The legal
edge still requires a second human actor. Generic model write permissions are
not the supported authority path.

`create_regulatory_chain` owns the atomic create transaction, permission check,
portable-ID linkage, folder equality, temporal/source validation, and
non-publication defaults. `transition_obligation_review` owns row locking,
permission and stale-state checks, role separation, and event creation.

## Migration and rollback

`regulatory.0001_initial` adds only new tables, constraints, indexes, and Django
permissions; it does not seed regulations or modify existing records. Rolling it
back removes only the bounded app's tables. Production rollback must first prove
there are no retained regulatory records, because `PROTECT` and append-mostly
history are intentional safety properties rather than disposable cache data.

## Consequences and residual risks

- The design keeps upstream modules stable and provides a narrow migration/API
  surface, at the cost of an explicit bridge in later phases.
- Direct ORM bulk operations or privileged SQL can bypass service validation.
  The supported API is read-only, database constraints cover local invariants,
  and focused tests cover the service path. A custom-through citation link can
  also be deleted through an unsupported M2M/bulk path. Database roles/triggers
  or an external tamper-evident store remain a production decision.
- `django-auditlog` improves traceability but is not WORM storage.
- Full-text storage remains prohibited for metadata-only records and still
  requires a source-rights decision for other policies.
- This ADR establishes an implementation boundary. It is not legal review,
  production acceptance, or Phase 1 completion.
