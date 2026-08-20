# China Financial GRC Delivery Roadmap / 中国金融 GRC 交付路线

> Status: **Authoritative / 权威阶段顺序**
> Current phase: **Phase 1 — One-entity regulatory register / 单实体外规台账**
> Updated: **2026-08-20**

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
    P1["Phase 1<br/>Regulatory Register<br/>Current"]
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

Status: **Current.** Begin with a synthetic entity profile and public metadata.
A real institution profile and legal conclusions remain private and require
named authorised reviewers.

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
gate changes. A feature implementation or bug fix normally belongs only in
`progress.md`. Any phase promotion must cite verification evidence, unresolved
risks, and the accountable human owner; an agent cannot promote its own work.
