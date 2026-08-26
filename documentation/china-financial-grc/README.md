# China Financial GRC extension foundation

This directory turns the initial research for a China-focused financial GRC
assistant into versioned design and machine-readable artifacts for this fork of
CISO Assistant.

The target scope covers:

- external regulation and internal policy lifecycle management;
- banking, insurance, and financial-technology obligations;
- data protection, cross-border data transfer, and privacy operations;
- cybersecurity, MLPS, critical infrastructure, cryptography, and incidents;
- AI and model governance;
- board governance, compliance, internal audit, evidence, and remediation;
- procurement and cost control without bypassing mandatory controls.

## Design position

This is not a plan for an autonomous "super-agent". The target architecture is
a governed system of record with bounded AI capabilities:

1. official source documents and versioned, integrity-protected snapshots where permitted;
2. a temporal `Document -> Provision -> Obligation -> Applicability` model;
3. reviewed mappings from obligations to CISO Assistant controls and evidence;
4. deterministic rules for dates, thresholds, scores, routing, and permissions;
5. human approval for legal conclusions and consequential actions;
6. AI for extraction, comparison, explanation, and drafting only;
7. end-to-end provenance, evaluation, and cost telemetry.

## Contents

- [Target architecture](architecture.md)
- [Domain model](domain-model.md)
- [Regulatory scope and source policy](regulatory-scope.md)
- [Financial regulatory source packs](regulatory-source-packs.md)
- [Agent governance](agent-governance.md)
- [Migration and delivery plan](migration-plan.md)
- [PostgreSQL and operational acceptance](postgresql-operational-acceptance.md)
- [Open-source decisions](open-source-decisions.md)
- [ADR 0001: bounded regulatory persistence](adr/0001-regulatory-persistence-boundary.md)
- [ADR 0002: controlled recorded-time correction and historical retrieval](adr/0002-recorded-time-correction.md)
- [ADR 0003: bounded synthetic applicability persistence](adr/0003-bounded-synthetic-applicability-persistence.md)
- [ADR 0004: bounded synthetic applicability review disposition](adr/0004-bounded-synthetic-applicability-review-disposition.md)
- [`schemas/regulatory-record.schema.json`](schemas/regulatory-record.schema.json):
  the proposed `2.0.0-draft.1` interchange contract for regulatory knowledge
- [`catalogs/regulatory-sources.json`](catalogs/regulatory-sources.json) and the
  [domain source packs](regulatory-source-packs.md): 76 official-source
  document records and 76 version records, metadata-checked as of 2026-08-20;
  legal review remains explicitly `unreviewed`
- [`catalogs/applicability-facts.json`](catalogs/applicability-facts.json):
  56 controlled fact definitions used to scope banking, insurance, payment,
  data, cybersecurity, cloud, and AI rules without guessing missing facts
- [`catalogs/regulatory-pack-index.json`](catalogs/regulatory-pack-index.json):
  hashed pack inventory and discovery-profile composition for common, bank,
  insurance, fintech, and payment views
- [`examples/regulatory-record.example.json`](examples/regulatory-record.example.json):
  an end-to-end example from provision to control mapping

The loadable CISO Assistant foundation is intentionally split into:

- `backend/library/libraries/cn-financial-common-controls.yaml` for stable,
  reusable controls; and
- `backend/library/libraries/cn-financial-baseline.yaml` for the assessment
  framework that depends on those controls.

`COMMON` is the safe default implementation group. `BANK`, `INSURANCE`, and
`FINTECH` must be selected for the relevant profile; selecting a group is an
assessment filter, not a legal-applicability decision.

## What this foundation does not claim

- It is not legal advice or a complete statement of applicable law.
- The source register is not a licensed redistribution of standards or legal
  texts. It stores metadata and official links only.
- A high-level control summary is not a substitute for an official provision.
- Loading the starter library does not prove compliance.
- AI output cannot approve itself, alter audit logs, or make final decisions on
  customer rights, regulatory filings, audit opinions, or board matters.

## Validate the artifacts

From the repository root, with the backend dependencies available:

```bash
python tools/china_financial_grc/validate_artifacts.py
```

The validator checks the regulatory, fact, and pack-index JSON Schemas; source-
pack hashes; global typed-ID uniqueness; official-source hosts; source-check
dates; controlled fact types and evidence; deterministic three-value
applicability results; temporal and approval-chain invariants; the example
record; CISO Assistant library structure; implementation groups; URN
uniqueness; parent relationships; and one-to-one starter-control coverage.
Full application loading remains covered by the backend library tests and
should be run before merging later implementation changes.

It does not fetch source URLs, establish legal status or applicability, verify
dates against an authority, or turn illustrative hashes into legal evidence.
Those checks require a separately controlled source-ingestion and human-review
process.

## Implementation boundary

Phase 1 now persists a bounded synthetic-entity Document -> Version -> Provision
-> Obligation chain and non-binding review events behind the read-only
`/api/regulatory/v1/` API. A folder-scoped, named-human domain service can make
metadata-only recorded-time corrections by atomically closing one current
revision set and appending linked successors. It cannot claim source/legal
supersession, and a corrected obligation restarts at `machine_proposed`.

Document detail supports coherent historical selection through a timezone-aware
`recorded_as_of` value and half-open recorded intervals. The read path locks the
same folder boundary used by correction, resolves one joined chain, time-filters
review events, and preserves CISO Assistant object and related-field IAM
masking. See [ADR 0002](adr/0002-recorded-time-correction.md) for the exact
contract and the split between local PostgreSQL evidence and remaining target-
environment acceptance gates.

The implemented Phase 1 boundary now also includes one synthetic-only,
append-only `RegulatoryApplicabilityDecision` aggregate. It embeds a fixed,
server-owned
single-condition rule snapshot and the exact fact snapshot used to compute a
draft, non-binding `applicable`, `not_applicable`, or `needs_review` result. The
rule checks `entity.institution_type eq "bank"`; missing or unknown input always
produces `needs_review`. Each decision is scoped through an explicit entity
registration and exact physical obligation revision, so a corrected obligation
cannot inherit an earlier applicability result.

An internal, folder-scoped domain service lets an authorised named human record
or correct that snapshot; the caller supplies observations, while the fixed
rule, outcome, revision, digests, and recorded time remain server-owned. The
public surface is limited to the entity-scoped, read-only document action:

```text
GET /api/regulatory/v1/documents/{uuid}/applicability/?entity=<uuid>&recorded_as_of=<aware-RFC-3339>
```

Migration `regulatory.0003` adds the decision table without a data backfill. At
that delivery gate, all 41 then-existing regulatory tests passed both with
migrations disabled and through the real project migration graph. An
independent full-project SQLite migration rehearsal verified 0003 apply,
empty-history rollback and reapply, and refusal to reverse after a synthetic
decision was inserted. Django system checks, migration-drift checks, and an
independent review reporting no critical, high, or medium findings also passed.

This bounded implementation remains draft, non-binding, unpublished, and
synthetic. It has separate view and internal record permissions and no public
write route. It does not add a general `ApplicabilityRule` approval lifecycle,
real institution facts, binding legal conclusions, approval/publication,
source text, source/legal-version supersession, a binding reviewer action/admin
workflow, an agent, or a library projection. Flattening regulatory history into `Framework` and
`RequirementNode` remains prohibited; those objects receive only reviewed
projections in a later gated phase. See
[ADR 0003](adr/0003-bounded-synthetic-applicability-persistence.md) for the
contract and migration guard. PostgreSQL apply, two-connection lock evidence,
index usability, synthetic backup/restore, and a bounded database-role contract
now have repository-local PostgreSQL 16 evidence. Representative-volume query
plans, deployment recovery, full least-privilege integration, and tamper-
evident audit retention remain external production gates.

The bounded implementation also adds a separate append-only
`RegulatoryApplicabilityReviewDisposition` stream for a
second named human to record `no_correction_requested`,
`correction_requested`, or `unable_to_complete` against one exact physical
decision and its recomputed semantic digest. Absence of an event derives
`not_reviewed`; every decision successor starts there and inherits no earlier
disposition.

The implementation separates record and review authority: Analyst and Domain Manager
may record the synthetic decision but cannot review it; Approver may review but
cannot record it; Administrator may hold both permissions but cannot review a
decision they recorded. Service accounts are excluded. Mutation remains an
internal domain service, while a separate entity-scoped GET exposes only the
same-time exact-decision review state with reviewer IAM masking; there is no
public mutation route. None of the dispositions changes the computed result,
creates a legal conclusion, approves evidence, enables publication or
projection, or resolves a `needs_review` fact. See
[ADR 0004](adr/0004-bounded-synthetic-applicability-review-disposition.md) for
the accepted contract and remaining production gates.

The frontend now provides a fork-specific, read-only `/regulatory` register and
`/regulatory/{uuid}` viewer. It displays IAM-scoped metadata lineage, exact
recorded-time context, the fixed-rule non-binding applicability result, and the
separate human disposition. Server-load runtime contracts fail closed on drift,
bind responses to the requested document/entity/obligation revision, and keep
the metadata-only policy from hydrating provision text or free-text version
notes. Official-source links are HTTPS-only. Current applicability and review
panels share one microsecond-precise recorded-time anchor, while decision valid
time is labelled separately. Entity search is only a discovery aid; backend IAM
and registration checks remain authoritative. The viewer provides no create,
correction, review mutation, approval, publication, export, or regulatory-
submission action and is not the later binding reviewer workflow described by
the roadmap.

With the review-disposition slice included, all 72 regulatory tests pass both
with migrations disabled and through the real project migration graph. A fresh
isolated full-project SQLite rehearsal verified 0004 apply, empty rollback and
reapply, refusal to reverse populated review history, and preservation of the
applied migration and recorded event after that refusal. These local results do
not satisfy target-environment operations, legal-review, or real-pilot gates.

A repeatable isolated PostgreSQL 16 run now extends this to 76 passing
regulatory tests, real two-connection folder-lock observations, exact-head
review concurrency, index-usability probes, bounded database-role denial
probes, a synthetic runtime mutation, populated reverse refusal,
component-level backup/restore equality, and a restored-runtime successor
write. See
[PostgreSQL and operational acceptance](postgresql-operational-acceptance.md).
This is local synthetic technical evidence, not production approval.
