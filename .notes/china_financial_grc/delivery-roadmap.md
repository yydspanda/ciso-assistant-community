# China Financial GRC Delivery Roadmap / 中国金融 GRC 交付路线

> Status: **Authoritative / 权威阶段顺序**
> Updated: **2026-08-26**

This document owns product outcomes, phase order, dependencies, and entry/exit
gates. `documentation/china-financial-grc/` owns target design and regulatory
scope. `progress.md` owns verified execution status and the current next action.

## Product decision

Build a governed China financial GRC extension inside CISO Assistant, starting
with one reviewable regulatory-change vertical slice. Do not build a universal
legal-answering agent or spread implementation across every banking, insurance,
fintech, privacy, cyber, audit, and cost-control workflow at once.

The product succeeds when accountable users can move from an official source to
a cited, reviewed, applicable obligation, then to internal policy, controls,
evidence, findings, and remediation without losing version, time, ownership, or
approval lineage.

```mermaid
flowchart LR
    P0["Phase 0<br/>Foundation<br/>Complete"]
    P1["Phase 1<br/>Regulatory Register"]
    P2["Phase 2<br/>Policy & Control Bridge"]
    P3["Phase 3<br/>Read-only Bounded Agents"]
    P4["Phase 4<br/>Proposal-based Writes"]
    P5["Phase 5<br/>Continuous Evidence & Domain Depth"]

    P0 -->|contracts and source gates| P1
    P1 -->|reviewed obligations| P2
    P2 -->|traceable gaps| P3
    P3 -->|quality and authority gates| P4
    P4 -->|safe workflow operations| P5
```

Phases are evidence gates, not date promises. Work may prepare a later phase,
but a later capability cannot be described as delivered before the preceding
gate is satisfied.

## Strategic outcomes

| Outcome | User value | Primary measure |
| --- | --- | --- |
| Trusted regulatory change | Analysts review the right source/version without repeated manual reconciliation | source intake to reviewed decision time |
| Defensible applicability | Missing facts and legal uncertainty are visible instead of guessed | false `not_applicable` rate and `needs_review` resolution time |
| Traceable internal alignment | Policy, control, evidence, finding, and remediation retain obligation anchors | accepted mappings with complete lineage |
| Governed AI assistance | AI reduces semantic work without acquiring legal or operational authority | human acceptance/override rate and authority-bypass failures |
| Auditable operations | Reviewers can reconstruct who knew, proposed, approved, changed, and executed what | decisions with complete source/payload/approval lineage |
| Sustainable economics | Model, tool, review, and remediation effort are measurable by accepted outcome | cost and latency per accepted outcome |

## Now / next / later

| Horizon | Initiative | Intended outcome | Confidence |
| --- | --- | --- | --- |
| Now | One-entity regulatory register and review workflow | Persist and review versioned sources, provisions, obligations, applicability facts, and decisions | Committed after architecture gate |
| Now | Small reviewed pilot source set | Prove official-source-to-obligation lineage without claiming broad legal coverage | Requires named human reviewers |
| Next | Internal-policy and control bridge | Produce clause-level, reviewable gaps and CISO control/evidence links | Depends on published obligations |
| Next | Read-only explanation and comparison agents | Reduce analysis time while preserving citations and `needs_review` | Depends on reviewed knowledge and evaluation set |
| Later | Proposal-based writes and case automation | Shorten remediation workflows without bypassing IAM or maker-checker | Depends on adversarial and rollback gates |
| Later | Continuous evidence and specialist domain packs | Improve monitoring depth across selected banking, insurance, fintech, privacy, cyber, audit, and cost workflows | Depends on proven ownership, connectors, and quality metrics |

## Stage registry

These IDs are stable machine-readable pointers to the phase headings below.
They do not promote a phase or replace its entry and exit gates.

| Stage ID | Roadmap stage |
| --- | --- |
| `CFGRC-P0` | Phase 0 — foundation |
| `CFGRC-P1` | Phase 1 — one-entity regulatory register |
| `CFGRC-P2` | Phase 2 — internal policy and control bridge |
| `CFGRC-P3` | Phase 3 — read-only bounded agents |
| `CFGRC-P4` | Phase 4 — proposal-based writes |
| `CFGRC-P5` | Phase 5 — continuous evidence and reviewed domain depth |

## Task registry

The registry gives delivery work a stable identity. It owns intended outcome and
roadmap parent only; execution status, evidence, and completion dates remain in
`progress.md` and its monthly archives. Adding these IDs does not add product
scope or change the phase gates.

| Task ID | Stage ID | Roadmap parent | Intended outcome |
| --- | --- | --- | --- |
| `CFGRC-P0-FOUNDATION` | `CFGRC-P0` | Phase 0 foundation | Establish the public architecture, domain, library, schema, and governance baseline. |
| `CFGRC-P0-SOURCE-PACKS` | `CFGRC-P0` | Phase 0 foundation | Establish bounded official-source metadata packs and deterministic artifact validation. |
| `CFGRC-P0-AGENT-GOVERNANCE` | `CFGRC-P0` | Phase 0 foundation | Establish repository instructions, product/architecture skills, and authoritative delivery memory. |
| `CFGRC-P1-ARCHITECTURE` | `CFGRC-P1` | Epic 1 — architecture and ownership gate | Choose the bounded owner and reuse existing IAM, audit, library, and workflow boundaries. |
| `CFGRC-P1-PERSISTENCE` | `CFGRC-P1` | Epic 2 — temporal regulatory persistence | Persist the bounded synthetic regulatory identity chain with temporal lineage. |
| `CFGRC-P1-READ-REVIEW` | `CFGRC-P1` | Epic 3 — read and review workflow | Provide entity-scoped reads and non-binding named-human review transitions. |
| `CFGRC-P1-TEMPORAL-CORRECTION` | `CFGRC-P1` | Epics 2–3 | Preserve recorded-time correction and coherent historical reads without rewriting history. |
| `CFGRC-P1-SUPERSESSION` | `CFGRC-P1` | Epic 2 — temporal regulatory persistence | Model source/legal-version supersession separately from recorded-time correction. |
| `CFGRC-P1-APPLICABILITY` | `CFGRC-P1` | Epics 2–3 | Record a versioned fact snapshot and deterministic non-binding applicability result. |
| `CFGRC-P1-REVIEW-DISPOSITION-DESIGN` | `CFGRC-P1` | Epic 3 — read and review workflow | Freeze the bounded applicability review-disposition authority and history contract. |
| `CFGRC-P1-REVIEW-DISPOSITION` | `CFGRC-P1` | Epic 3 — read and review workflow | Implement the append-only named-human disposition model, service, migration, and read action. |
| `CFGRC-P1-POSTGRES-ACCEPTANCE` | `CFGRC-P1` | Epic 5 — evaluation and release evidence | Produce local synthetic PostgreSQL migration, concurrency, privilege, backup, and restore evidence. |
| `CFGRC-P1-TARGET-ACCEPTANCE` | `CFGRC-P1` | Epic 5 — evaluation and release evidence | Obtain a versioned target-environment acceptance charter and named operational/control owners. |
| `CFGRC-P1-PILOT-CHARTER` | `CFGRC-P1` | Epic 4 — reviewed pilot source set | Establish accountable pilot scope, reviewers, source rights, and approved data/model location. |
| `CFGRC-P1-PILOT-SOURCES` | `CFGRC-P1` | Epic 4 — reviewed pilot source set | Review a small rights-cleared official-source set without claiming broad coverage. |
| `CFGRC-P1-REVIEWER-UI` | `CFGRC-P1` | Epic 3 — read and review workflow | Provide a reviewer UI/admin path after the review contract is stable. |
| `CFGRC-P2-POLICY-BRIDGE` | `CFGRC-P2` | Phase 2 | Add the private versioned policy/control bridge after published obligations exist. |
| `CFGRC-P3-AGENT-EVALUATION` | `CFGRC-P3` | Phase 3 | Evaluate read-only explanation assistance on reviewed knowledge and a gold set. |
| `CFGRC-GOV-LEDGER` | `CFGRC-P1` | Cross-cutting delivery governance | Keep one current pointer, a bounded active ledger, and canonical monthly archives. |
| `CFGRC-GOV-UPSTREAM` | `CFGRC-P1` | Cross-cutting fork governance | Measure freshly fetched upstream divergence and surface warning/failure thresholds without changing upstream source. |

## Phase 0 — foundation

Status: **Complete for the public foundation branch.** This is not legal review
or production readiness.

Delivered outcome:

- target architecture, domain, source, agent-governance, and migration design;
- loadable high-level China financial controls and assessment baseline;
- metadata-only official-source packs, applicability fact registry, schemas,
  deterministic validation, approval invariants, and mutation tests;
- explicit licensing, private-data, and non-legal-advice boundaries.

Exit gate:

- public artifacts validate and load through the supported library path;
- official links, status, source-check, and confidence metadata are explicit;
- no proprietary texts, secrets, private policies, or institution data are in
  the public branch;
- future-effective, unknown-fact, digest, approval, and pack-integrity attacks
  fail closed.

## Phase 1 — one-entity regulatory register

Execution status is owned by the single machine-readable pointer in
`progress.md`. This phase begins with a synthetic entity profile and public
metadata. A real institution profile and legal conclusions remain private and
require named authorised reviewers.

Outcome hypothesis:

> A regulatory analyst can intake an official version, review extracted
> provisions and obligations, resolve applicability facts, and publish a cited
> decision faster and with fewer lineage errors than a document/spreadsheet
> workflow.

### Epics and sequence

1. **Architecture and ownership gate**
   - choose the bounded Django app/service owner;
   - map reuse of IAM, folders/domains, validation flows, libraries, evidence,
     findings, and audit;
   - define API and migration compatibility before implementation.
2. **Temporal regulatory persistence**
   - persist document, version, provision, obligation, applicability fact/rule/
     decision, control mapping, and decision record identities;
   - preserve valid time, recorded time, provenance, source hashes, and
     append-only history.
3. **Read and review workflow**
   - read-only APIs and reviewer UI/admin path;
   - proposal, reject, correct, approve, revoke, and supersede transitions;
   - maker-checker, payload digest, permission, and audit enforcement.
4. **Reviewed pilot source set**
   - select a small set only after reviewer ownership and source rights are
     explicit;
   - include effective, future-effective, and no-explicit-commencement examples
     to test lifecycle behavior;
   - keep all machine extraction unpublished until human review.
5. **Evaluation and release evidence**
   - reviewed gold set, temporal/migration tests, citation checks, permission and
     cross-entity isolation, source-injection tests, and rollback rehearsal.

### Phase 1 exit gate

- every published obligation resolves to an official document version and
  precise provision locator;
- bitemporal history and supersession are migration- and API-tested;
- unknown facts cannot produce automatic non-applicability;
- future-effective material creates preparation work, never a false current
  violation;
- reviewer corrections and approvals bind identity, role, time, source, and
  exact payload;
- cross-entity/folder access-control failures are zero in the release suite;
- quality, correction, latency, and cost baselines are recorded on a human-
  reviewed pilot set.

## Phase 2 — internal policy and control bridge

Outcome:

- ingest versioned internal-policy clauses in a private organisation overlay;
- map obligations to policy, requirements, reference controls, owners, evidence,
  findings, and remediation with reviewed relationship types;
- distinguish missing, conflicting, partial, stricter, and organisation-defined
  controls.

Exit gate:

- every gap retains source and internal-clause anchors and versions;
- sensitive policies remain tenant/folder scoped and are absent from the public
  fork;
- mappings use existing CISO Assistant libraries, IAM, assessment, evidence, and
  remediation owners;
- no inference chain is automatically published as a compliance conclusion.

## Phase 3 — read-only bounded agents

Outcome:

- provide permission-filtered source search, obligation explanation,
  policy comparison, gap analysis, and audit-preparation drafts;
- models handle bounded semantic uncertainty while deterministic services own
  thresholds, dates, scores, routing, and permissions.

Exit gate:

- citation/version, extraction, mapping, terminology, and table/OCR quality meet
  named thresholds on reviewed data;
- unavailable authority or facts resolve to `needs_review`;
- prompt injection, poisoned-source, cross-entity retrieval, data-egress, cost,
  and degraded-provider tests pass;
- an agent cannot mutate GRC state or approve a proposal.

## Phase 4 — proposal-based writes

Outcome:

- agents may propose obligations, mappings, cases, tasks, findings, and evidence
  metadata through typed diffs and controlled workflows.

Exit gate:

- all writes cross IAM, deterministic policy, schema validation, idempotency,
  maker-checker approval, audit, and rollback;
- approval binds the exact payload digest and active prerequisites;
- replay, duplicate, stale-source, revocation, partial-failure, and confused-
  deputy tests pass;
- reserved legal, customer, regulator, audit, risk, IAM, production, and payment
  decisions remain human-only.

## Phase 5 — continuous evidence and reviewed domain depth

Outcome:

- integrate selected data catalog, privacy, security, supplier, audit, finance,
  and cost evidence providers;
- deepen reviewed banking, insurance, fintech, data, cyber, AI, governance, and
  audit packs according to measured demand and reviewer capacity.

Exit gate:

- connectors provide evidence rather than competing systems of record;
- ownership, freshness, provenance, hash, classification, retention, and failure
  behavior are known;
- first-, second-, and third-line identities and conclusions remain independent;
- cost optimisation cannot waive mandatory, security, privacy, customer, or
  audit controls;
- production rollout has named owners, cohorts, monitoring, rollback thresholds,
  and residual-risk acceptance.

## Dependencies and decision owners

| Dependency | Why it matters | Required owner/evidence |
| --- | --- | --- |
| Pilot entity and licence facts | Applicability cannot be universalised | accountable compliance owner; private evidence |
| Legal-review capacity | Metadata and model proposals cannot publish themselves | named legal/compliance reviewers |
| Source storage rights | Full text and standards may not be redistributable | content-rights/licensing decision |
| Community versus enterprise controls | Audit and service-account capabilities differ by edition | explicit deployment control design |
| Model/data location | Prompts may contain regulated or cross-border data | privacy, security, secrecy, and data-transfer decision |
| Reviewer gold set | Quality cannot be inferred from synthetic examples | approved, versioned evaluation records |
| Integration credentials and systems | Evidence and writes affect external systems | least-privilege owner and acceptance environment |

## Non-goals until their gate is reached

- comprehensive coverage of all Chinese financial regulation;
- autonomous legal advice, compliance certification, audit opinion, customer-
  rights decisions, regulatory filing, risk acceptance, or payments;
- copying confidential internal policies or unlicensed standards into the public
  repository;
- one “super-agent” that owns source ingestion, legal interpretation, workflow,
  control execution, audit, and approval;
- production claims based only on metadata catalogs, prompts, demos, or synthetic
  fixtures.

## Roadmap change control

Change this file only when product outcome, phase order, dependency, metric, or
gate changes, or when a stable stage/task ID must be registered for already
authorised work. ID registration provides traceability and does not by itself
change or reorder scope. A feature implementation or bug fix normally updates
the current dashboard and its monthly archive, not roadmap outcomes. Any phase
promotion must cite verification evidence, unresolved risks, and the accountable
human owner; an agent cannot promote its own work.
