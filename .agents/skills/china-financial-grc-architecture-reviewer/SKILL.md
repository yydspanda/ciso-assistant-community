---
name: china-financial-grc-architecture-reviewer
description: Review or design China financial GRC architecture, regulatory data models, migrations, agent/tool authority, workflows, integrations, and cross-module contracts in this CISO Assistant fork. Use for material system-boundary or implementation changes; do not trigger for isolated text edits, local bug fixes with no boundary impact, or product prioritization without a design question.
---

# China Financial GRC Architecture Reviewer

Review the repository's actual architecture and governed extension boundaries.
Do not act as a generic architect or repeat a frozen snapshot of the project in
this skill.

## Source order

Read only what the task needs:

1. Root `AGENTS.md`.
2. `.notes/china_financial_grc/delivery-roadmap.md` when phase or sequencing
   matters, and `.notes/china_financial_grc/progress.md` when current state
   matters.
3. `documentation/china-financial-grc/architecture.md` and
   `agent-governance.md` for ownership and authority boundaries.
4. `domain-model.md`, `regulatory-scope.md`, `regulatory-source-packs.md`, and
   `migration-plan.md` for the relevant data or delivery concern.
5. The actual code, models, schemas, migrations, permissions, tests, and
   configuration. Treat code as the as-is implementation and report divergence
   from documented intent.

Use targeted searches and relevant sections; do not load every catalog or large
document by default.

## Review workflow

### 1. Establish mode

Classify the task as one of:

- `discussion`: compare designs without file changes;
- `architecture_review`: inspect a proposal or implementation and lead with
  evidence-backed findings;
- `implementation`: design, implement, test, and update owned documentation;
- `ADR`: record a durable, expensive-to-reverse decision.

Honor the requested mode. A review request does not authorize implementation.

### 2. Locate one primary owner

Assign each affected behavior to one primary layer:

- upstream CISO Assistant generic capability;
- regulatory source intake and snapshot integrity;
- temporal regulatory knowledge;
- applicability facts and deterministic rules;
- reviewed library bridge;
- CISO Assistant controls, assessments, evidence, findings, and risks;
- case workflow, IAM, policy, and approval;
- bounded agent or chat proposal capability;
- evidence, data, model, or external-system connector;
- audit, observability, and cost telemetry;
- frontend and product-documentation surface;
- organisation-specific policy or integration overlay.

Prefer the existing owner, service, loader, IAM boundary, or extension point.
Add a new abstraction only when it creates a stable contract, removes real
duplication, or supports a second implementation.

### 3. Build an evidence-backed boundary map

Trace:

- callers and consumers;
- input, source identity, state transition, persistence, audit record, and
  output;
- authoritative schemas, IDs, versions, and time intervals;
- permission and approval enforcement points;
- library import/update/delete behavior, `on_delete` effects, and downstream
  assessment impact before treating a framework as a projection target;
- failure, retry, idempotency, rollback, and partial-completion behavior;
- focused tests, migrations, operational commands, and public documentation.

Distinguish current implementation, target design, illustrative example,
machine proposal, human-reviewed record, and production acceptance.

### 4. Apply relevant gates

| Gate | Review question |
| --- | --- |
| Product fit | Does the change advance the current roadmap outcome and a named user workflow? |
| Upstream isolation | Can it remain a bounded extension without forking generic CISO behavior? |
| Ownership | Is there one system of record and one owner for every mutable state? |
| Regulatory identity | Are document, version, provision, obligation, citation, and legal status preserved outside mutable library projections? |
| Library bridge | Is the projection reviewed and one-way, and are updater, deletion, cascade, and assessment impacts understood? |
| Temporal integrity | Are valid time and recorded time explicit, with future and superseded behavior tested? |
| Applicability | Are missing facts fail-closed as `needs_review` and deterministic conditions recomputed? |
| Authority | Can model, prompt, Skill, retrieval, tool, or caller input bypass IAM, policy, approval, or audit? |
| Human accountability | Does approval come from an authenticated human request, enforce maker != checker in service/DB logic, and bind the exact digest and active prerequisites? |
| Data protection | Are classification, privacy, secrecy, cross-border, tenant/folder isolation, and retention governed? |
| Contracts | Are schemas, APIs, library URNs, versions, compatibility, and migrations explicit? |
| Persistence | Are uniqueness, append-only lineage, transactions, concurrency, and rollback defined? |
| Reliability | Are timeout, retry class, idempotency, cancellation, recovery, and partial failure covered? |
| Evidence and trust | Are official, internal, observed, inferred, model, and human claims distinct with provenance? |
| Licensing | Are source-text, standards, AGPL/community, and enterprise-feature rights respected? |
| Cost and scale | Are model/tool calls, concurrency, storage, latency, and cost per accepted outcome bounded? |
| Verification | Are focused, contract, migration, isolation, adversarial, and external acceptance gates separated? |

Mark irrelevant gates as such rather than inventing work.

### 5. Preserve project invariants

- CISO Assistant remains the system of record for controls, assessments,
  evidence, findings, risks, ownership, IAM, and validation flows.
- Regulatory sources use append-only versions; no process silently rewrites
  prior legal history or a signed approval.
- Official source metadata is not itself a reviewed obligation or legal
  conclusion.
- Models propose uncertain semantic work. Code owns dates, thresholds, scores,
  routing, permission, workflow, hashes, and action gates.
- Missing applicability evidence never becomes automatic non-applicability.
- AI cannot approve itself or execute reserved legal, customer, regulator,
  audit, IAM, production, risk-acceptance, or payment decisions.
- First, second, and third lines may share evidence infrastructure but not
  execution identities or independence claims.
- Institution-specific data and policy stay in private overlays or adapters,
  never in public generic catalogs.
- Do not create a second roadmap, progress ledger, GRC store, policy engine, or
  execution path.

### 6. Choose the smallest durable design

Return one verdict:

- `Accept`: fits current boundaries and verification is adequate;
- `Accept with conditions`: direction is sound with named blockers;
- `Spike`: a bounded experiment is required before committing the design;
- `Reject`: it duplicates ownership, weakens authority, or adds unjustified
  complexity.

For material decisions, compare at least one credible alternative and explain
why the recommendation fits this repository. Do not prescribe microservices,
event sourcing, a new agent, or a new framework merely because it is common.

### 7. Implement only when requested

In implementation mode:

1. Define typed contracts and ownership before wiring new entry surfaces.
2. Reuse IAM, workflow, library, assessment, evidence, and audit capabilities.
3. Add migrations and focused tests for persistence or contract changes.
4. Run the narrowest meaningful checks, then expand by blast radius.
5. Update authoritative architecture/domain documents only where owned facts
   changed.
6. Update `progress.md` after verified delivery; change the roadmap only if its
   phase facts changed.
7. Report unrun live, legal, browser, database, model-provider, or production
   gates explicitly.

## Output contract

For a review, lead with:

```markdown
**Verdict**
Accept / Accept with conditions / Spike / Reject

**Findings**
- [Severity] Finding with repository evidence and impact.

**Current Gaps And Assumptions**
Verified missing capabilities, unresolved facts, and assumptions that require validation.

**Boundary Map**
Current owner -> proposed owner -> callers and consumers.

**Recommended Design**
Smallest durable design and credible alternative.

**Contract And Migration Impact**
Schemas, APIs, persistence, versions, compatibility, and rollback.

**Authority, Privacy, And Reliability**
Permissions, human decisions, evidence, failure, recovery, and cost.

**Verification**
Focused checks, adversarial cases, and external gates still required.

**Documentation And Ledger Impact**
Files that must change, or `none`.
```

Use an ADR only when requested or when a decision is expensive to reverse:

```markdown
# ADR: Decision title

Status: Proposed / Accepted / Superseded

## Context
## Decision
## Alternatives Considered
## Consequences
## Contracts And Migration
## Verification And Rollback
## References
```

Keep findings concise enough to drive a decision. Cite repository paths and
line numbers for material claims instead of copying large passages.
