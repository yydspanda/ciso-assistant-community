# Migration and delivery plan

## Starting point

Existing workflow exports and implementation assessments remain private and are
not committed to this public fork. Before migration, each organisation should
inventory component versions, prompt variants, retrieval behaviour,
deterministic calculations, source anchors, side effects, permissions, and
approval paths. Only reusable migration principles and target contracts are
published here.

## Migration principles

1. Strangle, do not rewrite: keep existing workflows available while replacing
   shared capabilities behind stable contracts.
2. Move control outward: CISO Assistant permissions, workflow state, rules, and
   approvals govern AI substeps.
3. Preserve source identity: document, version, provision, and exact locator
   survive every transformation.
4. Replace prompt forks with versioned capabilities and typed inputs/outputs.
5. Begin read-only; introduce proposals before any direct write integration.
6. Measure accepted business outcomes and human overrides.

## Capability consolidation

| Migration workstream | Target capability |
| --- | --- |
| regulatory document interpretation | `propose_provisions_and_obligations` |
| internal-policy comparison | `compare_internal_policy_to_obligations` |
| obligation-to-risk analysis | `propose_risks_and_controls` |
| risk classification | fact extraction plus deterministic decision table |
| obligation-to-control mapping | reviewed mapping service |
| state-changing integrations | proposal envelope plus policy and approval gateway |
| prompt and capability lifecycle | append-only registry plus schema and evaluation version |
| regulatory retrieval | source-aware chunks keyed by document version and provision |

## Delivery phases

### Phase 0 — foundation in this branch

Deliver:

- target architecture and governance boundaries;
- regulatory interchange JSON Schema;
- 76-record common, banking, insurance, and fintech/data/AI official-source
  metadata register;
- a controlled registry of 56 applicability facts;
- loadable high-level China financial control foundation;
- artifact validator and documented licensing/source policy.

Exit criteria:

- artifacts pass local validation;
- no proprietary source material is committed;
- library content is clearly marked as a control foundation, not legal advice;
- every included source has an official link, source-check date, metadata
  confidence, and explicit unresolved fields where confirmation is incomplete.

### Phase 1 — one-entity regulatory register

Scope one legal entity and a small set of high-priority instruments. Add Django
models/API for document versions, provisions, obligations, applicability facts,
and review state.

Exit criteria:

- bitemporal history and source hashes are tested;
- analysts can review, reject, correct, and publish proposed obligations;
- every published obligation has an official citation;
- future-effective and superseded versions behave correctly.

Current implemented increment, which does not satisfy the full Phase 1 exit
criteria:

- `regulatory.0001_initial` creates the synthetic, metadata-only Document ->
  DocumentVersion -> Provision -> Obligation aggregate, registration, and
  append-only non-binding review events;
- `regulatory.0002_regulatorychaincorrectionevent_and_more` adds the named-human
  correction permission, history index, and immutable correction-event
  boundary;
- one atomic domain service closes the exact current three-row revision set and
  appends linked successors at a server-owned cutoff; the successor obligation
  resets to `machine_proposed`;
- the existing read-only detail API accepts `recorded_as_of` and resolves a
  single folder-consistent chain through half-open recorded intervals; the read
  and correction paths use the same folder lock as their concurrency boundary;
- object and related-field IAM fail closed, and there is still no public write
  route.

This increment is recorded-time repair only. It cannot represent source/legal
supersession and does not add applicability, binding decisions, rejection,
approval/publication, source text, real entity data, UI writes, a library
projection, or an agent.

Migration-backed focused tests and an isolated SQLite full-project database
copy verify 0001 -> 0002 apply, empty-history rollback/reapply, and refusal to
reverse 0002 after a real correction event exists. A brand-new empty-database
rehearsal is blocked before these migrations by the repository's existing IAM
migration expecting the optional allauth `account` app; this is not counted as
a regulatory migration pass. PostgreSQL apply, two-connection folder-lock
linearization, representative query plans, backup/restore, and audit-retention
evidence remain deployment gates. See
[ADR 0002](adr/0002-recorded-time-correction.md).

### Phase 2 — internal policy and control bridge

Add clause-level internal policy ingestion and reviewed mappings to obligations,
framework requirements, reference controls, owners, and evidence expectations.

Exit criteria:

- mappings preserve clause and version anchors;
- conflict, partial, stricter, and organisation-defined relationships are
  distinguishable;
- assessment creation uses the existing library loader and IAM;
- no inference chain automatically becomes a compliance conclusion.

### Phase 3 — read-only bounded agents

Implement source search, obligation explanation, policy-gap analysis, and audit
preparation using the current chat proposal architecture.

Exit criteria:

- schema-valid outputs and deterministic calculations;
- regression, citation, isolation, injection, and cost tests pass;
- unavailable authority produces `needs_review`, not fabricated citations;
- model/provider use complies with data-location decisions.

### Phase 4 — proposal-based writes

Allow agents to propose obligations, mappings, tasks, findings, and evidence
metadata. Add diff review, policy decisions, maker-checker approval, expiry,
idempotency, and rollback.

Exit criteria:

- no write path bypasses RBAC, policy, and approval requirements;
- approval binds the exact payload digest;
- replay/duplicate/partial-failure tests pass;
- high-risk and reserved actions remain human-only.

### Phase 5 — continuous evidence and reviewed domain depth

Integrate data catalog/privacy tooling, security evidence collectors, supplier
systems, audit feeds, and cost systems. Promote selected banking, insurance,
and fintech source metadata to provision-indexed and human-reviewed obligations
only after the core model proves stable.

Exit criteria:

- connectors are evidence providers, not competing GRC masters;
- ownership, freshness, hashes, classification, and retention are known;
- first-, second-, and third-line identities and workflows are separated;
- cost analysis cannot waive mandatory or customer-protection controls.

## First three vertical slices

### Regulatory change to remediation

Official publication -> source snapshot -> proposed change -> analyst/legal
review -> applicability -> internal-policy/control gap -> owner response ->
approval -> tasks/findings -> evidence -> closure.

### Personal-information transfer assessment

Processing/data-flow facts -> deterministic threshold and exemption checks ->
PIPIA draft -> privacy/legal review -> mechanism decision -> controls and
recipient commitments -> approval -> monitoring.

### Audit evidence request

Audit scope -> control/test selection -> evidence request -> owner submission ->
hash/version/freshness checks -> auditor evaluation -> finding -> remediation ->
independent closure.

## Definition of done for each migrated capability

- typed schema and semantic version;
- named product, legal/compliance, security, and technical owners;
- source/citation and time-version rules;
- permission and data-classification tests;
- deterministic calculation tests where relevant;
- human review and override path;
- golden examples, adversarial cases, and regression thresholds;
- telemetry for latency, cost, errors, override, and accepted outcome;
- rollback, retention, and decommission plan;
- licence/SBOM and external-content rights review.
