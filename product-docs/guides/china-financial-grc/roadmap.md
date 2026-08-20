---
description: Incremental delivery roadmap and exit criteria for the China financial GRC extension.
---

# Delivery roadmap

> **Planning note:** Phases use evidence-based exit criteria rather than
> guaranteed calendar dates.

## Phase 0 — foundation

- architecture, threat boundaries, source policy, and agent prohibitions;
- regulatory interchange Schemas, four official-source packs, and controlled
  applicability facts;
- loadable China financial common controls and assessment baseline;
- artifact and loader tests.

Exit: all artifacts validate, contain no proprietary material, and clearly
separate control summaries from authoritative legal content.

## Phase 1 — one-entity regulatory register

Add temporal regulatory models/API for one legal entity and a deliberately
small official-source set.

Exit: append-only versions, hashes where permitted, reviews, supersession,
effective dates, and future-effective behaviour are tested.

## Phase 2 — internal policy and control bridge

Add clause-level internal-policy records, reviewed obligation mappings, library
projection, control ownership, and evidence expectations.

Exit: partial, conflict, stricter, and organisation-defined relationships are
distinct; mapping never automatically proves compliance.

## Phase 3 — read-only agents

Add cited search, obligation explanation, policy-gap analysis, and audit
preparation using the existing bounded chat architecture.

Exit: citation, schema, calculation, isolation, injection, regression, and cost
gates pass; missing authority produces review, not invention.

## Phase 4 — proposal-based writes

Permit proposed obligations, mappings, tasks, findings, and evidence metadata
through diff review, policy decisions, maker-checker approval, expiry,
idempotency, execution, and rollback.

Exit: no write bypass exists; replay, duplicate, partial-failure, and permission
revocation tests pass; red actions remain human-only.

## Phase 5 — continuous evidence and reviewed domain depth

Integrate data, privacy, security, supplier, audit, and cost evidence. Promote
selected pack sources from metadata to indexed provisions and reviewed
obligations for additional entities and use cases.

Exit: connectors remain evidence providers, three-lines independence is
preserved, evidence freshness/retention is known, and cost optimisation cannot
waive mandatory controls.
