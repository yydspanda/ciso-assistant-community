# China Financial GRC Progress Ledger / 中国金融 GRC 进度台账

> Status: **Authoritative current execution record / 权威当前执行记录**
> Updated: **2026-08-26**
> Branch: `agent/cfgrc-governance-activation-evidence`

This file is the bounded current dashboard: one stage pointer, one active task,
current facts, risks, one next action, and recent links. The roadmap owns stable
stage/task identity and phase gates. Canonical completed records and detailed
verification evidence live in `progress-archive/YYYY-MM.md`.

## Current pointer

- Current Stage: `CFGRC-P1` — one-entity regulatory register
- In Progress Task: `CFGRC-GOV-UPSTREAM-RECONCILIATION` — reconcile the measured upstream warning in a dedicated clean change
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
| Hosted project governance | PR #1 landed the fork slices on protected `main`; an active no-bypass ruleset requires the GitHub-Actions-sourced `validate-project-governance` check, and the weekly read-only upstream monitor is explicitly enabled. |

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
- Before hosted activation, the project-governance validator passed with six
  stages, 20 roadmap tasks, one matching active task, ten recent links, and 12
  archived records; all 49 governance mutation tests and all nine upstream-
  checker tests passed locally. This dashboard update registers the dedicated
  reconciliation task and its 13th archived record and must pass the same gate.
- Hosted PR runs passed `validate-project-governance`, the PostgreSQL synthetic
  technical acceptance, backend Ruff, frontend unit/coverage/lint, migration,
  startup, and multiple functional checks. The default-branch manual governance
  run `32982655658` passed on merge commit `73e720af21f1665964eb8a0aa2f85ec1b0169ea8`.
- Default-branch manual upstream run `32982660229` passed after fetching
  canonical `c6906fd07bb4b626a156762bbf4c097fc6ab2b11`; it truthfully warned that
  fork `main` was 17 behind and 15 ahead. Warning is success; 20 behind remains
  the enforced failure threshold.

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
10. **The fork is close to the upstream failure threshold.** Hosted fresh-fetch
    evidence on 2026-08-26 resolved canonical upstream `main` to
    `c6906fd07bb4b626a156762bbf4c097fc6ab2b11` and fork `main` to
    `73e720af21f1665964eb8a0aa2f85ec1b0169ea8`: 17 behind and 15 ahead. Only
    three commits remain before the configured 20-behind failure gate. Any
    reconciliation must be a dedicated clean PR with proportional regression;
    it must not be hidden in an extension slice.
11. **Inherited workflow activation still needs an owner policy.** Opening PR #1
    registered inherited validation workflows as well as the three fork jobs.
    The write-scoped CLA and OIDC/security-events Plumber workflows were
    explicitly disabled; no CLA was signed. The unregistered scheduled
    `mirror-images.yml` has `packages: write` and could not be disabled through
    the workflow API because GitHub did not register it. It and inherited
    release workflows require an explicit owner decision before any manual,
    tag, or scheduled activation.

## Current next action

Land this activation-evidence update through the protected-main PR path. Then
fresh-fetch canonical upstream again and reconcile the measured 17-behind state
in a new dedicated clean branch. Review the exact upstream commits and conflicts,
preserve the bounded extension and existing IAM/GRC ownership, run proportional
backend/frontend/governance/PostgreSQL checks, and merge only through a PR whose
required governance check passes. Do not mix target-environment work or new
product features into that reconciliation. After the drift gate is restored,
return the product pointer to `CFGRC-P1-TARGET-ACCEPTANCE`; that charter remains
blocked on named operations, security, privacy, records, legal, and audit owners.

## Active task board

| Task ID | Priority | Slice | Dependency | State |
| --- | --- | --- | --- | --- |
| `CFGRC-GOV-UPSTREAM-RECONCILIATION` | P0 | Dedicated reconciliation of the hosted 17-behind warning | Clean branch, fresh canonical fetch, conflict review, proportional regression, protected-main PR | In Progress |
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
| 2026-08-26 | [CFGRC-REC-20260826-04](progress-archive/2026-08.md#cfgrc-rec-20260826-04) | `CFGRC-GOV-LEDGER`, `CFGRC-GOV-UPSTREAM` | Protected-main ruleset and hosted governance/upstream checks activated with retained run evidence. |
| 2026-08-26 | [CFGRC-REC-20260826-03](progress-archive/2026-08.md#cfgrc-rec-20260826-03) | `CFGRC-P1-READ-REVIEW` | Read-only regulatory register/viewer implemented with fail-closed temporal, metadata, IAM, and non-binding presentation contracts. |
| 2026-08-26 | [CFGRC-REC-20260826-02](progress-archive/2026-08.md#cfgrc-rec-20260826-02) | `CFGRC-GOV-LEDGER`, `CFGRC-GOV-UPSTREAM` | Bounded ledger, monthly archive, reproducible-experiment checks, and upstream monitoring implemented. |
| 2026-08-26 | [CFGRC-REC-20260826-01](progress-archive/2026-08.md#cfgrc-rec-20260826-01) | `CFGRC-P1-POSTGRES-ACCEPTANCE` | Local synthetic PostgreSQL technical acceptance implemented and verified. |
| 2026-08-25 | [CFGRC-REC-20260825-01](progress-archive/2026-08.md#cfgrc-rec-20260825-01) | `CFGRC-P1-REVIEW-DISPOSITION` | ADR 0004 implementation pushed and handed off. |
| 2026-08-24 | [CFGRC-REC-20260824-04](progress-archive/2026-08.md#cfgrc-rec-20260824-04) | `CFGRC-P1-REVIEW-DISPOSITION` | Bounded applicability review disposition implemented. |
| 2026-08-24 | [CFGRC-REC-20260824-03](progress-archive/2026-08.md#cfgrc-rec-20260824-03) | `CFGRC-P1-REVIEW-DISPOSITION-DESIGN` | Review-disposition architecture accepted. |
| 2026-08-24 | [CFGRC-REC-20260824-02](progress-archive/2026-08.md#cfgrc-rec-20260824-02) | `CFGRC-P1-APPLICABILITY` | Bounded synthetic applicability persistence verified. |
| 2026-08-24 | [CFGRC-REC-20260824-01](progress-archive/2026-08.md#cfgrc-rec-20260824-01) | `CFGRC-P1-TEMPORAL-CORRECTION` | Controlled recorded-time correction and historical reads verified. |
| 2026-08-21 | [CFGRC-REC-20260821-01](progress-archive/2026-08.md#cfgrc-rec-20260821-01) | `CFGRC-P1-ARCHITECTURE`, `CFGRC-P1-PERSISTENCE`, `CFGRC-P1-READ-REVIEW` | Architecture owner accepted and first bounded database-backed regulatory chain delivered. |

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
