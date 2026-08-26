# ADR 0004: bounded synthetic applicability review disposition

- Status: Accepted and implemented for the bounded Phase 1 synthetic slice
- Implementation status: Implemented by additive migration `regulatory.0004`,
  an internal named-human recording service, and a separate read-only action;
  verified by the local synthetic PostgreSQL 16 acceptance harness, while
  target production and operational gates remain open
- Date: 2026-08-24
- Scope: named-human review of one exact synthetic applicability-decision
  revision
- Extends: [ADR 0003](0003-bounded-synthetic-applicability-persistence.md)

## Context

ADR 0003 implements one deterministic, draft, non-binding applicability
decision for a synthetic legal entity and an exact physical obligation
revision. It records who supplied the fact snapshot and preserves the rule,
facts, evidence references, provenance, result, rationale, revision, and
semantic digest. It deliberately has no independent human disposition of that
decision.

Today a reviewer can inspect the entity-scoped read response, but any conclusion
that the exact snapshot was checked or needs correction remains outside the
regulatory history. A comment, ticket, or mutable workflow status can drift from
the physical decision revision after a fact or obligation correction. It also
cannot prove that the reviewer saw the same semantic payload later presented to
another user.

The next bounded product outcome is therefore not legal approval. It is to let
an authorised second named human record one auditable disposition against the
exact synthetic decision payload, expose whether that exact revision is
not reviewed, has no correction requested, needs correction, or could not be
reviewed, and ensure every successor decision starts `not_reviewed`.

The accountable users are:

- an analyst or domain manager who records the synthetic fact snapshot;
- an operational applicability reviewer who checks the exact snapshot,
  evidence-reference metadata, provenance, and deterministic recomputation; and
- an administrator or auditor who must reconstruct the event stream.

This removes ambiguous offline reconciliation while preserving the following
limits:

- the source packs remain legally `unreviewed` metadata;
- the applicability result remains draft, non-binding, and unpublished;
- a review disposition is neither legal review nor approval of the obligation,
  rule, evidence sufficiency, compliance, or publication;
- no real institution facts, source text, public mutation route, reviewer UI,
  library projection, generic workflow integration, or agent is added; and
- missing or unknown facts remain `needs_review` even when a human records
  `no_correction_requested` for the record containing that uncertainty.

## Decision

### Regulatory knowledge owns an independent event stream

`backend/regulatory` will own an append-only
`RegulatoryApplicabilityReviewDisposition` event stream. It is separate from
both the deterministic `RegulatoryApplicabilityDecision` revision and the
obligation review stream. Each disposition binds:

- the exact physical applicability-decision FK with `PROTECT` deletion;
- a copied, server-recomputed `decision_semantic_payload_sha256`;
- the immutable entity-document registration folder inherited through the
  decision;
- the decision maker copied from `decision.recorded_by`, plus the distinct
  named-human reviewer, both protected from deletion;
- one sequence, direct predecessor disposition, `from_disposition`,
  `to_disposition`, controlled reason code, required rationale, and server-owned
  `occurred_at`;
- a versioned event-payload digest, request digest, and folder-scoped
  idempotency key; and
- fixed non-binding and unpublished markers.

The deterministic decision remains authoritative for the fact snapshot and
three-value result. The disposition event is authoritative only for what a
human did with that exact stored revision. It does not copy facts, evidence
references, rules, results, or source material into a second mutable owner.

### Disposition semantics and transitions

`not_reviewed` is the derived initial state when an exact decision revision has
no event. It is not stored by mutating the decision. The enabled event targets
are:

- `no_correction_requested`: the checker examined the exact stored synthetic
  fact snapshot, evidence-reference metadata, provenance, and deterministic
  result and did not request a correction to that record;
- `correction_requested`: the checker found that the exact revision should be
  superseded before it is relied upon further; and
- `unable_to_complete`: the checker could not complete the bounded review
  because evidence, scope, authority, or information remained insufficient or
  conflicting.

`no_correction_requested` does not attest that an evidence reference is
authentic or sufficient, that the fact is true, that the rule reflects law, or
that the obligation applies. None of the three dispositions changes the
decision's `result`, `review_status`, `is_binding`, or publication state. A
`needs_review` decision remains `needs_review` under every disposition.
Another disposition event may auditably withdraw a mistaken correction request;
unless that happens, only a new applicability-decision revision resolves the
requested correction.

The append-only transition graph is:

```text
not_reviewed -> no_correction_requested | correction_requested | unable_to_complete

any persisted disposition -> any persisted disposition with a material change
```

An exact repeat of the complete event semantic payload is a no-op and is
rejected. A same-disposition successor is permitted only when its controlled
reason or rationale materially changes and the expected predecessor
compare-and-swap matches. A later event can therefore correct or retract a prior
human disposition without deleting it. The latest event at the selected
recorded time supplies the derived disposition.

The controlled reason code is server-validated:

| Target | Allowed reason code |
| --- | --- |
| `no_correction_requested` | `review_completed` |
| `correction_requested` | `fact_correction_required`, `evidence_correction_required`, `provenance_correction_required`, `scope_or_parent_correction_required`, or `other_correction_required` |
| `unable_to_complete` | `insufficient_evidence`, `conflicting_information`, `insufficient_authority_or_scope`, or `other_unresolved` |

Every event also requires a non-empty human rationale. A reason code routes
work; it is not a new fact, legal finding, or model explanation.

### Exact binding and compare-and-swap

The caller targets, but does not redefine, the subject. A typed command supplies
at least:

```text
entity UUID
document UUID
expected decision physical UUID, portable ID, revision, semantic digest
expected current disposition UUID/sequence/status/event-payload digest, or explicit none
target disposition
reason code
rationale
idempotency key
```

The service reloads and recomputes every server-owned identity and digest. It
rejects a stale decision, a stale current disposition, a mismatched digest, a
complete semantic repeat, an unsupported field, or a caller-supplied actor/
time/binding/publication value. A same-disposition successor is accepted only
when its reason or rationale materially changes under a matching expected-head
CAS. The event-payload digest binds the digest profile,
folder/registration/entity/document scope, reviewer, copied decision maker,
exact decision identity and digest, sequence, predecessor physical identity and
event digest, from/to dispositions, reason code, rationale, `occurred_at`, and
fixed non-binding/unpublished markers.

The separate request digest binds the server-resolved reviewer UUID, immutable
registration-folder/entity/document scope, exact decision identity and semantic
digest, expected disposition head, target disposition, reason code, and
rationale. An exact retry is returned only when that complete request, including
reviewer identity, matches. A profile change mints a new profile identifier
rather than silently changing old hashes.

### Human authority and permission matrix

The internal recording service requires an active authenticated named human.
A service account cannot act as the reviewer. The reviewer must differ from
the exact decision's `recorded_by` actor even when one user holds several
roles. This is the bounded maker/checker rule: the person who recorded the fact
snapshot cannot review that same revision.

A reviewer may append a correction to their own earlier non-binding review
event. This is intentional: the prior event remains immutable and the action is
not a binding approval. A future binding `DecisionRecord` must introduce its own
maker/checker, prerequisite, expiry, revocation, and approval rules and cannot
reuse this exception.

The accepted permissions remain independent:

- `view_regulatoryapplicabilityreviewdisposition` controls access to reviewer
  identity, rationale, and disposition history; and
- `review_regulatoryapplicability` controls the internal recording service.

| Built-in role | View decision | View disposition | Record/correct decision | Review disposition |
| --- | --- | --- | --- | --- |
| Reader | no | no | no | no |
| Analyst | yes | yes | yes | no |
| Domain Manager | yes | yes | yes | no |
| Approver | yes | yes | no | yes |
| Administrator | yes | yes | yes | yes, but never their own decision revision |

The review service requires document view, entity view, decision view,
disposition view, and the separate folder-scoped
`review_regulatoryapplicability` permission. Permission possession never
overrides the actor-separation check. The disposition-view permission is
separate so custom roles do not gain reviewer identity or rationale merely from
document metadata access.

### Transaction, lock order, and recorded time

New dispositions use one atomic internal service and the established authority
order:

```text
actor -> entity -> immutable registration folder -> registration
      -> current document chain -> exact current applicability decision
      -> latest review disposition
```

The service verifies that the targeted decision is the decision selected for
the current physical obligation and registration. New dispositions are rejected if
the entity has moved from the registration folder, lost its `SYNTHETIC-*`
reference, the decision or parent obligation is no longer current, or the
scope is ambiguous.

An exact idempotent retry is resolved after authority and historical-scope locks
but before those live-state checks. It may return its original historical disposition
after a later disposition, decision correction, entity rename, or entity move;
reusing the key with another request fails.

`occurred_at` is server-owned and strictly later than the document aggregate's
latest recorded time, including applicability decisions, obligation review
events, chain corrections, and earlier applicability review dispositions. The
shared document recorded-time floor must include these events so clock rollback
cannot hide them and a later decision correction starts after its review
history.

### Decision and obligation correction isolation

An applicability review disposition belongs to one physical decision revision.
It is never copied to a successor decision and never changes the deterministic
decision row.

When decision d1 is corrected to d2, d1 and all of its review dispositions
remain historical. At the d2 cutoff, d2 has derived disposition
`not_reviewed`. When an obligation correction replaces obligation r1 with r2,
the existing exact-parent selector already prevents d1 from appearing on r2;
no applicability review disposition appears without its exact decision either.

`correction_requested` does not itself create or close a decision revision.
The existing applicability recording service owns fact correction and requires
its own compare-and-swap command. This prevents a review comment from becoming
an alternate decision-write path.

### Read contract remains additive and mutation remains internal

There is no public review POST, PATCH, PUT, or DELETE route. The implementation
adds this separate entity-scoped read-only action:

```text
GET /api/regulatory/v1/documents/{uuid}/applicability-review/
    ?entity=<uuid>&recorded_as_of=<aware-RFC-3339>
```

The action first uses the existing entity-scoped applicability selector, then
selects the latest disposition for that exact decision whose `occurred_at` is
no later than the same recorded timestamp. It requires document, entity,
decision, and disposition-view permissions and reports the computed result
beside the derived disposition, event identity/sequence, reason code,
rationale, and time. The disposition-view permission authorises event access,
but reviewer identity is additionally subject to existing related-User object
IAM. Without that User access the response returns an explicit masked reviewer
marker and no UUID, name, or email. With access it may return only a stable UUID
and the already-approved minimal display field; email is not part of this
contract.

A caller without disposition-view permission receives no review response rather
than a misleading `not_reviewed` value. With permission and no selected event,
the action explicitly reports `not_reviewed`; with no selected applicability
decision it reports `not_reviewable`.

The response keeps `computed_non_binding_result`, `legal_conclusion: false`,
and `is_binding: false` separate from the human disposition. It fixes these two
derived fields:

```text
review_state:
  not_reviewable | not_reviewed | no_correction_requested |
  correction_requested | unable_to_complete

workflow_attention:
  needs_review | reviewed_nonbinding
```

`reviewed_nonbinding` is returned only when an exact decision exists, its
computed result is not `needs_review`, and the latest disposition is
`no_correction_requested`. Every other combination returns `needs_review`.
Neither value grants authority or changes the fixed legal/binding markers. No
list, document-detail, or original applicability route enumerates review state.

### Implemented constraints and indexes

Migration `regulatory.0004` includes:

- unique `(decision, sequence)` identity;
- a partial unique constraint on `decision` where predecessor is null, giving
  one root disposition per exact decision;
- a unique predecessor FK value, giving at most one direct successor per
  disposition;
- unique `(folder, idempotency_key)` request binding;
- a root if and only if sequence is 1, predecessor is null, and
  `from_disposition=not_reviewed`;
- a successor only with sequence at least 2, a non-null predecessor, and a
  persisted `from_disposition`;
- positive sequence, fixed disposition values, and reason/target compatibility;
- reason-code/target pairing, non-empty rationale, fixed digest profile,
  non-binding, and unpublished checks; and
- `(folder, decision, occurred_at)` selection index.

The fixed digest profile is
`regulatory-applicability-review-disposition/v1`. A same-row database check
rejects equality between the reviewer and copied decision-maker snapshot. The
locked service and model validation prove that the snapshot equals the target
decision's `recorded_by`; unsupported bulk/raw writes remain subject to the
production database-role, trigger, or tamper-evident-audit gate.

Cross-row coherence that portable constraints cannot express is revalidated
inside the locked service and model validation: folder and registration scope,
direct predecessor identity, contiguous sequence, prior status, actor
separation, exact decision digest, current parent, and monotonic event time.
All decision, actor, folder, and predecessor relationships protect audit
history from cascade deletion.

## Alternatives considered

### Mutate review fields on RegulatoryApplicabilityDecision

Rejected. It would overwrite what was previously known, make the decision's
semantic digest self-referential or exclude material review state, and let a
new fact revision appear to inherit a prior review.

### Reuse RegulatoryObligationReviewEvent

Rejected. That event reviews normative obligation content, has fixed analyst
and legal-review edges, and is scoped to an obligation rather than an entity's
exact fact/result snapshot. Reuse would conflate legal-content review with
applicability-record checking and would not isolate two entity registrations.

### Attach the current generic ValidationFlow directly

Deferred for future binding approval and publication. The current generic flow
owns a mutable status, uses nullable/set-null actors and cascade event deletion,
and has no regulatory-decision FK or canonical semantic-digest prerequisite.
Adding applicability to its many-to-many target list would not by itself meet
the append-only, exact-parent, historical-selection, and rollback contract.

### Permit only one terminal event per decision

Rejected. A mistaken human disposition would then require deleting history or
minting a semantically identical decision revision, which the applicability
service correctly rejects as a no-op. A small append-only event stream preserves
both the original and its correction.

## Consequences

- Review state becomes reconstructable without changing the deterministic
  applicability result or pretending to approve law.
- A new decision revision automatically returns to `not_reviewed` by exact-FK
  isolation; no reset mutation or cascade is required.
- Analysts receive a durable correction queue while Approvers remain unable to
  create the fact revision they review.
- Event history adds storage and as-of selection work, but its growth is bounded
  to human dispositions and requires no model or external-tool calls.
- `no_correction_requested` remains unusable as a publication, projection,
  compliance, legal, risk-acceptance, regulator, audit-opinion, customer-rights,
  or payment gate.
- General rules, real facts, legal approval, DecisionRecord, workflow UI,
  publication, revocation/expiry, agents, and connectors remain future gated
  work.

## Contracts and migration

Migration `0004` is additive. It creates the review-disposition table, indexes,
constraints, and separate view/review permissions without altering or
backfilling migrations 0001 through 0003. Existing
applicability decisions derive `not_reviewed` from the absence of dispositions.

The migration must reverse cleanly while the event table is empty. A reverse
guard must refuse to drop populated review history. Retaining or archiving
events requires a separately reviewed forward migration. Deployment remains an
expand/contract change: code that can read the optional envelope is deployed
with the schema, and rollback of populated history is not claimed.

The typed internal command and separate read response require explicit
versioned contracts. The current applicability response remains unchanged, so
existing custom roles with decision view but no disposition view retain their
existing decision access without review-detail disclosure.

## Verification and rollback gates

Before reporting implementation complete, verify at least:

- all three dispositions, materially changed same/cross-disposition successors,
  exact semantic no-op rejection, controlled reason pairing, rationale bounds,
  unsupported/caller-owned field rejection, and exact digest recomputation;
- first event, later event, exact retry, conflicting idempotency reuse, stale
  decision, stale predecessor event, semantic no-op, atomic rollback, and host-
  clock regression;
- decision recorder self-review rejection, service-account rejection, revoked
  actor/role rejection, built-in and custom permission matrices, Entity IAM,
  sibling-folder isolation, and related-user masking;
- two registrations for one document, entity rename/move historical access,
  exact retry after a move, and rejection of a new review after live scope
  changes;
- d1 review history before a decision correction, d2 `not_reviewed` at its
  cutoff, obligation r1/r2 exact-parent isolation, and historical as-of
  disposition selection;
- database constraints, append-only model/admin/service paths, migration drift,
  empty apply/rollback/reapply, populated reverse refusal, and absence of public
  mutation routes; and
- focused and full SQLite suites plus local PostgreSQL migration,
  two-connection lock linearisation, current-index usability, bounded
  database-role probes, populated reverse refusal, and synthetic backup/restore
  fingerprint equality.

The bounded implementation has passed local Django system and migration-drift
checks. Its 33-test focused review/migration-contract suite passes, and all 72
regulatory tests pass both with migrations disabled and through the real
project migration graph. An isolated full-project SQLite rehearsal verified
0004 apply, empty rollback/reapply, populated-history reverse refusal, and
post-refusal preservation. A later local synthetic PostgreSQL 16 run passed all
76 regulatory tests and the PostgreSQL-specific gates listed above. These
results do not satisfy representative target-volume plans, deployment
PITR/RPO/RTO, complete role integration, tamper-evident audit retention, named
operational approval, legal review, a real pilot, Phase 1 completion, or
customer acceptance. See
[PostgreSQL and operational acceptance](../postgresql-operational-acceptance.md).

## Product measures for a future reviewed pilot

Synthetic implementation can test integrity but cannot establish a business
baseline. A later named-human pilot should measure:

- time from decision recording to first disposition;
- time from `correction_requested` to a successor decision that later records
  `no_correction_requested`;
- percentage of dispositions bound to the exact physical decision and digest,
  with a required target of 100%;
- self-review, service-identity, cross-folder, stale/replay, and hidden-history
  failures, with a required target of zero; and
- human correction/override rate, `unable_to_complete` rate, and unresolved
  `needs_review` age, with baselines recorded before targets are promoted to
  release gates.

## References

- [ADR 0001: bounded regulatory persistence](0001-regulatory-persistence-boundary.md)
- [ADR 0002: recorded-time correction](0002-recorded-time-correction.md)
- [ADR 0003: bounded synthetic applicability persistence](0003-bounded-synthetic-applicability-persistence.md)
- [Target architecture](../architecture.md)
- [Regulatory domain model](../domain-model.md)
- [Agent governance](../agent-governance.md)
- [Migration and delivery plan](../migration-plan.md)
- [Phase and verification ledger](../../../.notes/china_financial_grc/progress.md)
