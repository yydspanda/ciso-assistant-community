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
- [Agent governance](agent-governance.md)
- [Migration and delivery plan](migration-plan.md)
- [Open-source decisions](open-source-decisions.md)
- [`schemas/regulatory-record.schema.json`](schemas/regulatory-record.schema.json):
  the proposed `2.0.0-draft.1` interchange contract for regulatory knowledge
- [`catalogs/regulatory-sources.json`](catalogs/regulatory-sources.json):
  a 24-record official-source seed register, link-checked as of 2026-08-20;
  legal review remains explicitly `unreviewed`
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

The validator checks the JSON Schema, typed and temporal references, source
catalog, example record, CISO Assistant library structure, implementation
groups, URN uniqueness, parent relationships, and one-to-one starter-control
coverage. Full application loading remains covered by the backend library tests
and should be run before merging later implementation changes.

It does not fetch source URLs, establish legal status or applicability, verify
dates against an authority, or turn illustrative hashes into legal evidence.
Those checks require a separately controlled source-ingestion and human-review
process.

## Implementation boundary

This branch establishes the contract and a loadable control library before
introducing Django models or migrations. That order is intentional: flattening
regulations directly into `Framework` and `RequirementNode` would lose legal
version, applicability, provenance, and effective-time semantics. The proposed
regulatory models will be added behind a library bridge in a subsequent phase.
