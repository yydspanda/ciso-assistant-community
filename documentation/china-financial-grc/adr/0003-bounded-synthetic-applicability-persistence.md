# ADR 0003: bounded synthetic applicability persistence

- Status: Accepted and implemented for the bounded Phase 1 synthetic vertical slice
- Implementation status: SQLite-verified and verified by the local synthetic
  PostgreSQL 16 acceptance harness; target production gates remain open
- Date: 2026-08-24
- Scope: one synthetic legal entity, one exact physical obligation revision,
  and one fixed deterministic rule profile
- Extends: [ADR 0001](0001-regulatory-persistence-boundary.md) and
  [ADR 0002](0002-recorded-time-correction.md)

## Context

At decision time, the verified Phase 1 implementation preserved a synthetic
metadata-only Document -> DocumentVersion -> Provision -> Obligation chain,
non-binding review events, controlled recorded-time correction, and coherent
historical reads. It had no persisted institution facts or applicability
result.

The delivered bounded outcome proves that one fact snapshot can be recorded,
deterministically evaluated, corrected without overwriting history, and read at
the same recorded time as its exact source obligation. The delivered slice
preserves these limits:

- synthetic data only; no real institution, customer, product, system, or data
  flow facts;
- a draft, non-binding calculation, not a legal conclusion;
- no rule approval, decision confirmation, publication, public write API,
  source/legal supersession, library projection, or agent;
- missing or unknown facts resolve to `needs_review`, never an inferred
  `not_applicable`; and
- multiple entity registrations for one document must not create an implicit
  or leaking applicability scope.

The portable target schema separates reusable ApplicabilityRules from
ApplicabilityDecisions. Building independent rule, fact-snapshot, decision,
evidence-link, correction-event, and approval tables now would commit the
runtime to a general applicability subsystem before one synthetic flow has
proved its temporal, IAM, and migration contracts.

## Decision

### One append-only aggregate

`backend/regulatory` owns one append-only
`RegulatoryApplicabilityDecision` aggregate. A revision binds:

- one `EntityDocumentRegistration`, which supplies the explicit synthetic
  legal-entity scope and document identity;
- the exact physical `RegulatoryObligation` row evaluated, not only its
  portable record ID;
- the fixed rule snapshot and canonical fact snapshot;
- the service-computed result and structured reasons;
- valid and half-open recorded time, actor, rationale, and provenance; and
- direct predecessor, revision, idempotency, request, rule, fact, and semantic
  digests under versioned digest profiles.

All regulatory, registration, obligation, actor, folder, and predecessor
relationships protect history from cascade deletion. A decision is always
`draft`, non-binding, and unpublished in this slice. It has no confirmation,
approval, rejection, revocation, or publication transition.

The aggregate stores evidence references and observation metadata, not source
or evidence bytes. CISO Assistant remains authoritative for `Evidence` and
`EvidenceRevision`; this slice does not add a foreign-key lifecycle that could
change upstream evidence deletion or retention behaviour.

### Fixed rule and deterministic evaluation

The only enabled rule is:

```text
id:       SYNTHETIC-ENTITY-INSTITUTION-TYPE-BANK-001
version:  1
fact:     entity.institution_type
operator: eq
operand:  "bank"
unknown:  needs_review
```

The service, not the caller, supplies this rule snapshot, its fact definition,
and the deterministic rationale. The caller supplies a complete fact
observation and provenance. The service validates and canonicalises the
payload, then computes:

| Fact state | Result |
| --- | --- |
| known value `"bank"` | `applicable` |
| another known non-matching value | `not_applicable` |
| missing or explicitly unknown | `needs_review` |

A known observation requires the registered fact type, a value, at least one
non-empty evidence reference, and a timezone-aware observation time no later
than the server cutoff. An unknown observation carries no value, evidence
claim, or observation time. The caller cannot choose or override `result`; a
supplied interchange result, if accepted by a boundary adapter, must equal the
service recomputation.

The persisted rule and fact snapshots, their hashes, the deterministic engine
version, and structured rule hits make the result reproducible without storing
model chain-of-thought. No LLM or prompt participates in the calculation.

### Authority, transaction, and correction

Recording and fact correction use an internal atomic domain service; no public
write route is added. The actor must be an authenticated named human on a
`SYNTHETIC-*` entity and hold folder-scoped
`record_regulatoryapplicability`. A service account cannot record this slice.

Mutations follow the established order:

```text
actor -> entity -> registration folder -> registration -> document/current chain
      -> exact obligation -> current applicability decision
```

The immutable registration folder remains the historical IAM and aggregate
concurrency boundary. The service reloads authority-bearing rows, verifies that
the registration and selected current chain use that folder, and rejects a
stale or historical target. An entity rename or later folder move cannot erase
access to authorised history or alter its stable UUID scope. A new decision is
still rejected unless the entity currently remains in the registration folder
and retains the synthetic pilot reference; an exact historical idempotency
retry is resolved before those live-scope checks.

An exact idempotency retry is resolved after authority and scope locks but
before wall-clock-sensitive validation. Its folder-scoped key and request
digest return the original historical decision even if a later revision exists
or the host clock has moved backwards. Reusing a key for another request
fails.

A fact correction is a complete replacement, not a patch. It supplies the
expected current revision and semantic digest. The service rejects a stale
comparison or semantic no-op, chooses one monotonic server cutoff, compare-and-
swap closes the current decision interval, and appends a direct successor at
that cutoff. Any failure rolls back both closure and successor.

Each successor is itself the durable correction record: it retains its exact
predecessor, cutoff, actor, rationale, request binding, and canonical
rule/fact/semantic digests. A separate applicability correction-event table is
therefore unnecessary for this non-binding slice.

### Exact-parent temporal isolation

Applicability selection is subordinate to the existing coherent chain
selection. At one `recorded_as_of`, the service first selects the exact physical
obligation and then considers only a decision with the same registration,
folder, and physical obligation FK whose own half-open interval contains that
time.

The effective recorded interval is:

```text
decision recorded interval intersect exact obligation recorded interval
```

If chain correction closes obligation r1 and creates r2, any r1 decision stays
immutable historical evidence and is neither copied nor attached to r2. Its
own `recorded_to` may remain null because it remains the last recorded belief
about historical r1; exact-parent selection makes it ineligible for r2. At the
chain cutoff, r2 has no applicability result until a fresh evaluation is
recorded and therefore resolves to unevaluated / `needs_review`.

The chain correction does not cascade-close applicability decisions. Cascading
would make its bounded three-row operation mutate an unbounded number of entity
scopes, change its existing correction-event meaning, and add a one-to-many
lock/audit contract without improving read correctness.

### Entity-scoped read action

The existing document detail remains backward compatible and does not choose
or enumerate applicability scopes. A new read-only detail action requires one
explicit entity:

```text
GET /api/regulatory/v1/documents/{uuid}/applicability/
    ?entity=<uuid>&recorded_as_of=<aware-RFC-3339>
```

The entity parameter is required, non-empty, and single-valued. The optional
`recorded_as_of` follows the existing detail rules: one timezone-aware,
non-future RFC 3339 date-time. The action applies document object IAM, Entity
IAM, folder consistency, and the separate Django
`view_regulatoryapplicabilitydecision` permission before returning facts or a
result.

The read locks the entity and immutable registration-folder boundary before
capturing its selection time. Its clock floor includes the selected chain and the selected
registration's latest committed applicability revision, preventing clock
rollback from hiding committed state. Missing or ambiguous parent chains fail
closed. A complete chain with no decision remains readable and returns an
explicit unevaluated / `needs_review` state; it never fabricates a persisted
decision.

## Constraints and indexes

The additive persistence contract includes at least:

- unique `(folder, record_id, revision)` identity;
- one open decision per `(folder, registration, exact obligation)`;
- one successor per predecessor, preventing recorded-history forks;
- unique `(folder, idempotency_key)` request binding;
- positive revision and rule version, valid half-open recorded/valid intervals,
  and fixed draft/non-binding/unpublished checks;
- fixed rule, digest-schema, and three-result checks; and
- a `(folder, registration, obligation, recorded_from)` as-of index.

Folder, registration, parent-obligation, predecessor, and digest coherence that
portable database constraints cannot express are revalidated inside the locked
service. JSON fact shape, registered type, evidence, observation time, exact
rule-fact set, and digest recomputation are also service-owned and covered by
focused adversarial tests.

## Alternatives considered

### Separate Rule, FactSnapshot, Decision, EvidenceLink, and Event models

Deferred. That design is credible when rules are independently reviewed,
reused across many obligations and scopes, facts are shared, evidence links
have an agreed retention lifecycle, or decisions become binding. In this slice
it adds partial-completion states, temporal joins, cross-table correction,
rollback, and deletion semantics without improving the single fixed-rule
outcome.

The embedded snapshots preserve enough identity and digest information for a
future forward migration into normalised models without treating this draft
decision as an approved ApplicabilityRule.

### Store facts or a result on RegulatoryObligation

Rejected. Applicability facts belong to an entity scope, while an obligation is
regulatory knowledge shared across registrations. Updating the obligation
would mix institution facts with legal history and make one entity's result
appear universal.

### Cascade-close decisions during chain correction

Rejected for this slice. Exact physical-parent selection and interval
intersection already prevent inheritance. Cascading broadens the chain
transaction, requires locking every registered entity's decision, and makes the
existing correction event incomplete unless its contract also changes.

### Reuse document view permission for applicability facts

Rejected. Regulatory metadata and entity facts have different sensitivity.
The explicit applicability view permission keeps fact access independently
reviewable and prevents the normal document detail from becoming an entity-fact
enumeration surface.

## Consequences

- The model proves one atomic, reproducible fact-to-result path without
  prematurely creating a general policy engine or approval system.
- Missing evidence and uncertainty stay visible as `needs_review`.
- A correction of regulatory content intentionally invalidates applicability
  by exact-parent isolation; no old result silently endorses the successor.
- The last open decision for a historical obligation is not the current
  decision for its successor. Callers must use the entity-scoped selector, not
  query open rows without the parent interval.
- Evidence references are provenance pointers only. They do not prove the
  evidence is sufficient, current, or approved.
- Draft applicability cannot be projected into frameworks, reported as legal
  scope, or consumed as a binding approval prerequisite.
- General multi-condition rules, reusable fact stores, real scopes, review and
  approval, publication, rejection/revocation, UI writes, agents, and external
  connectors remain future gated work.

## Contracts and migration

Regulatory migration `0003_regulatoryapplicabilitydecision` is additive: it
creates the decision table, constraints, indexes, and permissions without
altering or backfilling 0001 or 0002 records. It inserts no synthetic example
row and no real institution fact.

The migration is intended to reverse cleanly only while no applicability
history exists. A reverse guard placed last in the forward operation order runs
first during reversal and refuses to drop the table after any decision has been
recorded. Retaining or archiving populated history requires a separately
reviewed forward migration.

The read action is additive. Existing document list and detail callers remain
unchanged unless they explicitly use the applicability action and entity
parameter. There is no public POST, PATCH, or DELETE contract.

## Verification and rollback

Local SQLite verification covers the bounded implementation contract:

- known matching, known non-matching, missing, and unknown outcomes;
- wrong fact key/type, missing or whitespace evidence, capacity bounds,
  future/naive observation time, caller-owned field rejection, and fixed-rule
  enforcement;
- exact retry, conflicting idempotency reuse, stale revision/digest, semantic
  no-op, transaction rollback, and host-clock regression;
- decision r1 -> r2 cutoff selection, exact retry after later revisions, and
  aggregate clock monotonicity across applicability, review, and correction;
- obligation r1 -> r2 correction, proving the old decision appears only before
  the chain cutoff and r2 safely returns unevaluated / `needs_review`;
- two entity registrations on one document, sibling-folder isolation, Entity
  IAM, separate view/record permissions, service-account rejection, permission
  revocation, and stable historical scope after entity metadata changes; and
- database constraints, migration drift, full regulatory tests both with
  migrations disabled and through the real migration graph, empty
  apply/rollback/reapply, and refusal to reverse populated applicability
  history.

The full regulatory suite passes all 41 tests in both SQLite modes. An isolated
full-project database rehearsal also applied 0003, reversed and reapplied it
while empty, inserted one synthetic decision, and confirmed that the reverse
guard refuses to discard populated history. Django system and migration-drift
checks pass, and the final independent architecture/security review reports no
remaining critical, high, or medium finding.

This evidence is not production acceptance. The later local synthetic
PostgreSQL 16 harness passed migration, two-connection folder-lock
linearisation, current-index usability, bounded database-role probes, populated
reverse refusal, and backup/restore fingerprint equality. Representative-volume
query plans, deployment PITR/RPO/RTO, complete role integration,
tamper-evident retention, and named operational approval remain external release
gates. See [PostgreSQL and operational acceptance](../postgresql-operational-acceptance.md).

## References

- [ADR 0001: bounded regulatory persistence](0001-regulatory-persistence-boundary.md)
- [ADR 0002: recorded-time correction](0002-recorded-time-correction.md)
- [Target architecture](../architecture.md)
- [Regulatory domain model](../domain-model.md)
- [Migration and delivery plan](../migration-plan.md)
- [Applicability fact registry](../catalogs/applicability-facts.json)
- [Phase and verification ledger](../../../.notes/china_financial_grc/progress.md)
