# China Financial GRC Progress Ledger / 中国金融 GRC 进度台账

> Status: **Authoritative current execution record / 权威当前执行记录**
> Updated: **2026-08-26**
> Branch: `agent/china-financial-grc-foundation`

This file is the bounded current dashboard: one stage pointer, one active task,
current facts, risks, one next action, and recent links. The roadmap owns stable
stage/task identity and phase gates. Canonical completed records and detailed
verification evidence live in `progress-archive/YYYY-MM.md`.

## Current pointer

- Current Stage: `CFGRC-P1` — one-entity regulatory register
- In Progress Task: `CFGRC-GOV-LEDGER` — activate and enforce the hosted governance checks
- Roadmap: [`delivery-roadmap.md`](delivery-roadmap.md)

## Current status

| Item | Current fact |
| --- | --- |
| Phase 0 public foundation | Architecture/governance/domain design, high-level libraries, source metadata packs, applicability facts, and deterministic artifact validation are delivered; they are not legal review or production readiness. |
| Regulatory persistence | A bounded synthetic metadata-only Document/Version/Provision/Obligation chain, recorded-time correction, one fixed-rule non-binding applicability aggregate, and named-human review-disposition services are implemented. |
| Read boundary | Entity/folder-scoped read actions and the fork-specific read-only register/viewer are implemented; binding publication, public mutation APIs, source/legal supersession, and a binding reviewer action/admin workflow remain absent. |
| Database evidence | SQLite suites and a local synthetic PostgreSQL 16.11 acceptance harness passed; target-environment capacity, PITR/RPO/RTO, topology, retention, and operations approval remain open. |
| Regulatory content | The public source seed remains metadata-only and legally unreviewed; no real institution profile or reviewed pilot source set exists. |
| AI and private data | No production agent or private-policy ingestion exists, and no regulated/private data is authorised for an external model. |
| Production acceptance | Legal, privacy, security, records, audit, operations, and production acceptance have not been performed. |

## Current verification summary

- The canonical August evidence is preserved in
  [`progress-archive/2026-08.md`](progress-archive/2026-08.md), including exact
  commands, test counts, residual gates, PostgreSQL fingerprints, and evidence
  digests.
- The latest local PostgreSQL slice passed the isolated PostgreSQL 16.11 harness,
  76 regulatory tests, migration/drift/rollback checks, bounded role probes,
  synthetic backup/restore equality, and a restored successor write. This is
  local synthetic evidence, not a production RPO/RTO or WORM claim.
- The source-pack validator last recorded 56 facts, 76 documents, and 76
  versions; the artifact test suite recorded 25 tests and 12 subtests.
- The read-only frontend slice passed all 254 frontend unit/component/loader
  tests, an 8 GB production build, zero scoped type diagnostics, and two focused
  backend invalid-recorded-time API tests. The 320 px browser reflow gate is
  authored but was not executed against a live stack.
- The project-governance validator passed with six stages, 20 roadmap tasks,
  one matching active task, ten recent links, and 12 archived records; all 49
  governance mutation tests and all nine upstream-checker tests passed locally.
- GitHub-hosted execution of the newly added PostgreSQL and governance workflows
  remains unrun.

## Current limitations and risks

1. **Metadata is not reviewed law.** Discovery records remain legally
   `unreviewed`; no loaded catalog or model output proves compliance.
2. **Persistence is deliberately narrow.** There is no source/legal-version
   supersession, binding DecisionRecord, publication, real source intake, or
   binding reviewer action/admin workflow.
3. **No real pilot facts or owners exist.** Institution, licence, product,
   customer, data-flow, and system facts remain synthetic or absent.
4. **No human gold set exists.** Extraction quality, correction effort, latency,
   and cost baselines cannot be promoted without reviewed data.
5. **No private policy bridge exists.** Internal policy must remain in a private,
   tenant/folder-scoped overlay and has not been ingested.
6. **Edition and audit decisions remain open.** Community and enterprise
   capabilities differ; production needs explicit service-identity and long-
   retention, tamper-evident audit decisions.
7. **External model use is not authorised for regulated data.** Local provider
   connectivity is not privacy, secrecy, security, transfer, or retention
   approval.
8. **Append-mostly is not WORM.** Privileged SQL, direct inserts, the bounded
   `recorded_to` grant, tamper evidence, retention, legal hold/deletion, and
   audit-export privacy require target controls and named owners.
9. **Only local synthetic PostgreSQL evidence exists.** Representative plans,
   complete upstream-table privileges, production topology, monitoring,
   encryption/key custody, PITR/RPO/RTO, and operations approval remain open.
10. **The fork is already materially behind upstream.** After an explicit fetch
   on 2026-08-26, canonical upstream `main` was
   `27e1ac9a2a1f485079b1c67e3048a34e7104d56f`; fork `main` was 14 behind/0
   ahead and this branch was 14 behind/10 ahead. Reconciliation was not attempted
   in this dirty, separately verified delivery slice. The new read-only monitor
   warns at 10 behind and fails at 20 behind.
11. **The CI definitions are authored but not operationally enforced.** On
    2026-08-26 the fork API reported Actions permission enabled and 26 workflow
    files on `main`, but zero registered workflows; `main` also had no branch
    protection or repository ruleset. Scheduled checks require the workflow on
    the default branch and explicit fork activation, and the ledger check cannot
    block changes until a hosted run exists and a required-check rule is active.

## Current next action

After this dirty delivery slice is independently reviewed and committed, land
the governance files on the fork's `main`, explicitly enable the scheduled
upstream workflow, manually dispatch both governance workflows, and retain the
first hosted run evidence. Then create an active `main` ruleset that requires
the `validate-project-governance` job for merges and blocks direct bypass as the
repository ownership policy allows. Do not require the schedule-only upstream
job as a pull-request check. After this gate, return the product-delivery pointer
to the private target-environment acceptance charter; do not merge/rebase
upstream or enable all fork workflows implicitly as a shortcut.

## Active task board

| Task ID | Priority | Slice | Dependency | State |
| --- | --- | --- | --- | --- |
| `CFGRC-GOV-LEDGER` | P0 | Activate hosted ledger CI and require its merge check | Reviewed commit on `main`, first hosted run, repository ruleset decision | In Progress |
| `CFGRC-GOV-UPSTREAM` | P0 | Activate weekly fresh-fetch ahead/behind monitoring | Workflow on default branch and explicit scheduled-workflow enablement | Pending hosted activation |
| `CFGRC-P1-TARGET-ACCEPTANCE` | P0 | Versioned target-environment charter, representative plans, PITR/RPO/RTO, role integration, retention, and audit-export acceptance | Named operations/security/privacy/records/legal owners | Pending external owners |
| `CFGRC-P1-SUPERSESSION` | P0 | Source/legal-version supersession | Reviewed source evidence and legal lifecycle contract | Pending |
| `CFGRC-P1-PILOT-CHARTER` | P0 | Real-pilot ownership charter | Accountable business/legal/content-rights/privacy/security/product owners | Blocked on external ownership |
| `CFGRC-P1-PILOT-SOURCES` | P0 | Small human-reviewed pilot source set | Accepted pilot charter, reviewers, rights, and approved data/model location | Blocked on external ownership |
| `CFGRC-P1-REVIEWER-UI` | P1 | Reviewer UI/admin workflow | Stable binding review/publication contract | Pending |
| `CFGRC-P2-POLICY-BRIDGE` | P1 | Internal-policy/private overlay | Published obligation model and privacy design | Later Phase 2 |
| `CFGRC-P3-AGENT-EVALUATION` | P1 | Read-only explanation-agent evaluation | Reviewed knowledge, gold set, and approved model/data location | Later Phase 3 |

## Recent records

The canonical record is in the linked monthly archive; this index is limited to
the ten most recent records and does not duplicate their evidence.

| Completed | Record | Task IDs | Result |
| --- | --- | --- | --- |
| 2026-08-26 | [CFGRC-REC-20260826-03](progress-archive/2026-08.md#cfgrc-rec-20260826-03) | `CFGRC-P1-READ-REVIEW` | Read-only regulatory register/viewer implemented with fail-closed temporal, metadata, IAM, and non-binding presentation contracts. |
| 2026-08-26 | [CFGRC-REC-20260826-02](progress-archive/2026-08.md#cfgrc-rec-20260826-02) | `CFGRC-GOV-LEDGER`, `CFGRC-GOV-UPSTREAM` | Bounded ledger, monthly archive, reproducible-experiment checks, and upstream monitoring implemented. |
| 2026-08-26 | [CFGRC-REC-20260826-01](progress-archive/2026-08.md#cfgrc-rec-20260826-01) | `CFGRC-P1-POSTGRES-ACCEPTANCE` | Local synthetic PostgreSQL technical acceptance implemented and verified. |
| 2026-08-25 | [CFGRC-REC-20260825-01](progress-archive/2026-08.md#cfgrc-rec-20260825-01) | `CFGRC-P1-REVIEW-DISPOSITION` | ADR 0004 implementation pushed and handed off. |
| 2026-08-24 | [CFGRC-REC-20260824-04](progress-archive/2026-08.md#cfgrc-rec-20260824-04) | `CFGRC-P1-REVIEW-DISPOSITION` | Bounded applicability review disposition implemented. |
| 2026-08-24 | [CFGRC-REC-20260824-03](progress-archive/2026-08.md#cfgrc-rec-20260824-03) | `CFGRC-P1-REVIEW-DISPOSITION-DESIGN` | Review-disposition architecture accepted. |
| 2026-08-24 | [CFGRC-REC-20260824-02](progress-archive/2026-08.md#cfgrc-rec-20260824-02) | `CFGRC-P1-APPLICABILITY` | Bounded synthetic applicability persistence verified. |
| 2026-08-24 | [CFGRC-REC-20260824-01](progress-archive/2026-08.md#cfgrc-rec-20260824-01) | `CFGRC-P1-TEMPORAL-CORRECTION` | Controlled recorded-time correction and historical reads verified. |
| 2026-08-21 | [CFGRC-REC-20260821-01](progress-archive/2026-08.md#cfgrc-rec-20260821-01) | `CFGRC-P1-ARCHITECTURE`, `CFGRC-P1-PERSISTENCE`, `CFGRC-P1-READ-REVIEW` | Architecture owner accepted and first bounded database-backed regulatory chain delivered. |
| 2026-08-20 | [CFGRC-REC-20260820-03](progress-archive/2026-08.md#cfgrc-rec-20260820-03) | `CFGRC-P0-AGENT-GOVERNANCE` | Project-agent operating model established. |

## Ledger update rules

- Register every stage and task in the roadmap before referencing it here, in an
  archive, or in an experiment.
- Keep exactly one stage pointer, one active-task pointer, and one matching
  `In Progress` row. Keep one explicit next action.
- After a material slice is verified, create one canonical completed record in
  the matching monthly archive and keep only a short recent link here.
- Keep this file below 500 lines and the recent index at ten rows or fewer.
- Every empirical model, prompt, retrieval, config, data/evaluation-set,
  hardware, or performance comparison must be labelled as an experiment and
  record its roadmap task, freshly fetched upstream commit, model identifier,
  model/config/data SHA-256 hashes, hardware, reproducible command, and non-empty
  structured metrics. Hosted-model hashes bind the immutable model descriptor/
  manifest, not inaccessible weights.
- Record concrete commands, outcomes, and residual gates without secrets,
  private customer facts, unlicensed source text, private paths, or hidden
  reasoning.
