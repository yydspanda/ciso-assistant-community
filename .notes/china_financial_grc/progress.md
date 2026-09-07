# China Financial GRC Progress Ledger / 中国金融 GRC 进度台账

> Status: **Authoritative current execution record / 权威当前执行记录**
> Updated: **2026-09-07**
> Branch: `agent/cfgrc-platform-authority-preservation-20260907`

This file is the bounded current dashboard: one stage pointer, one active task,
current facts, risks, one next action, and recent links. The roadmap owns stable
stage/task identity and phase gates. Canonical completed records and detailed
verification evidence live in `progress-archive/YYYY-MM.md`.

## Current pointer

- Current Stage: `CFGRC-P1` — one-entity regulatory register
- In Progress Task: `CFGRC-GOV-PLATFORM-AUTHORITY` — preserve and replay platform authority boundaries without replacing upstream owners
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
| Workflow isolation | Regulatory writes remain in `django-auditlog` but are excluded from the generic workflow event catalog, forwarder, and dispatch boundary; future regulatory automation requires a reviewed typed adapter, exact IAM, minimised payload, and human authority. |
| Platform authority preservation | Six ordered commits preserve shared core, IAM/SCIM/service-account, TPRM deletion, integration reconciliation, frontend, and old-base migration work on an isolated branch. The snapshot is locally tested but is not a release candidate until it is replayed against the reconciled upstream tree. |
| Production acceptance | Legal, privacy, security, records, audit, operations, and production acceptance have not been performed. |
| Hosted project governance | PRs #1-#3 landed through protected `main`. PR #4 remains open at exact head `122e5d6963235a47a823bca90aa65c8b78ae7cf0`; its last observed matrix has 165 successful and nine failed checks and is `UNSTABLE`. The separate preservation branch is not attached to that PR. The no-bypass ruleset and weekly read-only upstream monitor remain the merge authority. |

## Current verification summary

- The canonical August evidence is preserved in
  [`progress-archive/2026-08.md`](progress-archive/2026-08.md), including exact
  commands, test counts, residual gates, PostgreSQL fingerprints, and evidence
  digests.
- The 2026-09 preservation checkpoint is recorded in
  [`progress-archive/2026-09.md`](progress-archive/2026-09.md). The frozen code
  head is `b4a40155de251060bfc67be851109144aff95d9c`; focused deletion tests passed
  68 tests plus 31 subtests, and the complete scoped SCIM/service-account run
  passed 97 tests after two independent reviews drove the final fixes.
- Frontend validation for the preserved contracts passed 25 test files and 305
  tests. The full Svelte check remained nonzero at the historical project
  baseline scale (2387 errors, 821 warnings, 507 files), while improving by nine
  errors and one file from the previously recorded baseline; it is not claimed
  as a green type gate. No live Playwright/browser run was performed.
- A fresh canonical fetch on 2026-09-07 resolved upstream to
  `e3b3105df6bd4989e2af170813f80c51627ce3e1`. The frozen preservation code head
  is 34 commits ahead and 41 behind. A merge-tree of the pre-preservation base
  against that upstream found nine conflicted paths (four backend and five
  frontend), in addition to material TPRM shared-enclave, SCIM/JIT, and
  migration-lineage conflicts. The old-base changes therefore require
  contract-level replay rather than a wholesale merge or cherry-pick.
- The latest local PostgreSQL slice passed the isolated PostgreSQL 16.11 harness,
  80 regulatory tests, migration/drift/rollback checks, bounded role probes,
  synthetic backup/restore equality, and a restored successor write. This is
  local synthetic evidence, not a production RPO/RTO or WORM claim.
- The source-pack validator last recorded 56 facts, 76 documents, and 76
  versions; the artifact test suite recorded 25 tests and 12 subtests.
- The read-only frontend slice passed all 254 frontend unit/component/loader
  tests, an 8 GB production build, zero scoped type diagnostics, and two focused
  backend invalid-recorded-time API tests. The 320 px browser reflow gate is
  authored but was not executed against a live stack.
- The current project-governance gate passes with six stages, 22 roadmap tasks,
  one matching active task, ten recent links, 15 archived records, zero
  experiments, and 286 progress lines. Governance/upstream tests passed 58
  tests plus 55 subtests; artifact validation and its 25 tests plus 12 subtests
  also pass.
- Earlier hosted PR #1 runs passed `validate-project-governance`, the PostgreSQL
  synthetic technical acceptance, backend Ruff, frontend unit/coverage/lint,
  migration, startup, and multiple functional checks. The default-branch manual
  governance run `32982655658` passed on merge commit
  `73e720af21f1665964eb8a0aa2f85ec1b0169ea8`.
- Default-branch manual upstream run `32982660229` passed after fetching
  canonical `c6906fd07bb4b626a156762bbf4c097fc6ab2b11`; it truthfully warned that
  fork `main` was 17 behind and 15 ahead. Warning is success; 20 behind remains
  the enforced failure threshold.
- PR #2 used the native pull-request context to pass required governance run
  `33036424852` before merging as
  `430c7d591c698c359fa4c318b1a02495e9ef5d53`; the no-bypass ruleset remained
  active. A fresh local canonical fetch on 2026-08-27 resolved upstream to
  `ec3cf7d0386fd8d328d7f4623032a351538e23ce` and measured fork `main` ahead 17 /
  behind 22, truthfully crossing the configured failure threshold.
- The final workflow-isolation code passed 24 focused event-boundary tests and
  preserves audit registration for all ten regulatory models. It rejects stale,
  queued, identity-stripped, and forged regulatory events before a workflow
  instance is created; Django checks, migration-drift checks, Ruff, and diff
  checks also passed.
- PR #3's first hosted candidate completed 167 checks with 164 passing. Its
  three failures exposed two bounded defects now remediated: Approver's
  accidental generic Entity visibility was replaced by extension-owned
  registration-scope IAM, and the enterprise command-palette button received
  an accessible name. On remediation candidate `ef81a921`, both permission
  jobs and enterprise accessibility passed; 167 of 168 hosted checks passed.
  The sole failure exposed a stale PostgreSQL custom-role fixture still granting
  generic `view_entity`. Replacing its two grants with the narrow registration
  permission passed the complete local PostgreSQL harness, including 80 tests,
  backup/restore fingerprint equality, and a restored successor write. Final
  candidate `fced7716` then passed all 168 checks and all nine workflow runs;
  PR #3 merged without bypass as `d1ff1e461d58f6bb2dff77d312b160d475d2ff3e`.
- The dedicated reconciliation candidate preserves pure merge `11e9e9455`
  against canonical upstream `ec3cf7d03`, separate reviewed security commit
  `f69cec3a2`, and final pure merge `9b8ecfd98` against `9aac30df8`. An isolated
  Git merge-tree replay produced `bc784debdd064922ad04d5b1c8bb0056050e1bdc`,
  exactly matching the final merge tree without a manual conflict resolution.
- On the final merged tree, the 17-file security regression recorded 270/270
  backend tests, zero Django system-check or migration-drift issues, and clean
  scoped Ruff formatting. Frontend validation recorded 92/92 focused tests,
  277/277 complete tests, successful Community and Enterprise builds, and the
  unchanged historical `svelte-check` baseline of 2396 errors / 821 warnings /
  508 files. The latest frontend-only upstream commit introduced no diagnostic
  delta. Playwright against a live stack was not run locally.
- The same final backend tree passed the local synthetic PostgreSQL 16.11
  acceptance harness before the frontend-only final merge: 80 regulatory tests,
  real locking/index probes, migration and backup/restore checks, and evidence-
  index SHA-256 `8255608d8d56a481eb693c086c38a102aeffbb7a5f449e8c30cef80b000c3dd5`.
  Post-merge artifact and governance gates then passed 25 tests plus 12 subtests
  and 58 tests plus 55 subtests respectively.
- PR #4 opened from clean candidate `4fe3efd9a`; required governance run
  `33145956090` / job `98766932904` passed on that opening head. Its inherited
  one-shot version checker failed because it still names removed path
  `ciso_assistant/VERSION`; this stale, non-required check also failed on prior
  PR opening heads and is not accepted as candidate evidence.
- Exact PR #4 head `d80ddfd3e` completed 174 GitHub check runs: 162 succeeded
  and 12 failed. Required governance run `33146149863` / job `98767531521`
  passed. The failures were four API jobs across identical SQLite/PostgreSQL
  failure sets and eight Community/Enterprise functional jobs across TPRM,
  visibility-effects, mappings, and compliance-assessment scenarios.
- Remediation commit `ab1f3b5a6` keeps the caller-aware field projector and
  five-field complete-audit guard fail-closed. It updates stale API expectations
  without changing production backend/IAM behavior, makes unavailable dashboard
  progress explicit instead of coercing it to zero, isolates repeated tree score
  rings from page-level progress locators, and scopes functional locators to a
  visible/identified owner. The two API files passed 59 and 84 tests; three
  related IAM/projection suites passed 31 tests. Frontend validation passed 16
  focused and 293 complete tests, Community and Enterprise builds, scoped
  Prettier/pre-commit, and the unchanged historical `svelte-check` baseline of
  2396 errors / 821 warnings / 508 files. Local PostgreSQL was not rerun because
  production backend behavior did not change; the exact hosted SQLite and
  PostgreSQL jobs remain the release evidence.
- A mandatory pre-push fetch then advanced canonical upstream from `9aac30df8`
  to `b38b72d8f`. Pure merge `76f96a844` has parents `ab1f3b5a6` and
  `b38b72d8f`; its tree `209a2d2e28dc8cf87af48ba23c9a5b6d123dfd5b`
  exactly matches the independently computed merge-tree. The upstream change
  centralises existing safe YAML reads on `CSafeLoader`, with `SafeLoader`
  fallback. Direct validation parsed all 293 built-in YAML files and rejected
  an unsafe Python tag; 23 knowledge-graph tests passed. Artifact validation and
  25 tests plus 12 subtests passed; project governance passed at 263 lines with
  58 tests plus 55 subtests. A 13-test database-backed loader set
  was collected but did not leave the repository's migration setup within the
  three-minute local bound, so no result is claimed for library/document/email
  imports; the hosted backend matrix remains that gate. No local performance
  claim was evaluated. This is functional validation, not a model/config/data
  experiment.

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
10. **Fresh upstream divergence is above the failure threshold.** The explicit
    2026-09-07 fetch resolved canonical upstream to `e3b3105df6bd4989e2af170813f80c51627ce3e1`.
    The frozen preservation code head is 34 ahead / 41 behind, so the 20-behind
    gate correctly fails. No source rewrite or hidden merge was used to make the
    count green; weekly monitoring must continue from freshly fetched refs.
11. **Inherited workflow activation still needs an owner policy.** Opening PR #1
    registered inherited validation workflows as well as the three fork jobs.
    The write-scoped CLA and OIDC/security-events Plumber workflows were
    explicitly disabled; no CLA was signed. The unregistered scheduled
    `mirror-images.yml` has `packages: write` and could not be disabled through
    the workflow API because GitHub did not register it. It and inherited
    release workflows require an explicit owner decision before any manual,
    tag, or scheduled activation.
12. **Historical workflow payloads need a read-only deployment inventory.** New
    regulatory audit entries cannot create generic workflow instances, but no
    target database was inspected for instances created before this boundary.
    Any discovered payload must be handled through named IAM, records, privacy,
    and retention owners; audit history must not be deleted automatically.
13. **Custom applicability roles require an explicit narrow upgrade grant.**
    Built-in roles synchronize `view_entitydocumentregistration` after migrate,
    but existing custom roles are not auto-expanded. An administrator must
    grant that extension-owned permission only where registered applicability
    access is intended; generic `tprm.view_entity` is not a substitute.
14. **Live delivery gates remain for the new assignment-mail boundary.** Mocked
    and injected concurrency tests passed, but real Huey workers, SMTP delivery,
    and PostgreSQL outbox claim competition were not exercised locally. Those
    integrations require environment-scoped credentials, monitoring, and named
    operations/security acceptance; no local result is a production guarantee.
15. **The inherited one-shot version checker is stale.** It checks removed path
    `ciso_assistant/VERSION` only when a PR is opened, so it failed on PR #4's
    opening head just as it did on earlier fork PR opening heads. It is not a
    required ruleset check and must not be made green by fabricating an upstream
    version file. A separate CI-owner change should retire or correctly scope it;
    the exact updated reconciliation head still requires every job it triggers.
16. **The preservation branch is deliberately old-base and non-releasable.**
    Upstream now shares one TPRM enclave across assessment revisions and adds
    SCIM/JIT changes and conflicting migration leaves. The preserved tree fails
    closed for non-exclusive enclaves but does not implement surviving-revision
    IAM union semantics. Core and IAM migration drafts are quarantined and must
    be renumbered/rebuilt after reconciliation; PostgreSQL concurrency, live
    workers/SMTP, external connectors, and browser acceptance remain unrun.

## Current next action

Resume PR #4 from its exact clean branch and remediate the nine hosted failures
without importing the preservation commits. Re-fetch canonical upstream,
prepare compatibility fixes until an independent merge-tree is clean, then use
a pure two-parent upstream merge and protected CI. Only after that merge lands,
replay the six preservation commits contract-by-contract in this order: shared
core; IAM/SCIM/service identity; upstream shared-enclave TPRM; integrations;
frontend; regenerated migrations. Do not cherry-pick the old TPRM or quarantined
migration commits wholesale, and do not mix target-environment or new regulatory
scope into the reconciliation.

## Active task board

| Task ID | Priority | Slice | Dependency | State |
| --- | --- | --- | --- | --- |
| `CFGRC-GOV-PLATFORM-AUTHORITY` | P0 | Preserve and replay platform IAM, aggregate, external-effect, audit-lineage, and frontend/API authority contracts | Clean upstream reconciliation, shared-enclave/JIT composition, regenerated migrations, proportional regression | In Progress |
| `CFGRC-GOV-UPSTREAM-RECONCILIATION` | P0 | Dedicated reconciliation of the fresh-fetch 41-behind failure | Exact clean PR #4 branch, compatibility fixes, pure merge, protected-main CI | Pending clean resume |
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
| 2026-09-07 | [CFGRC-REC-20260907-01](progress-archive/2026-09.md#cfgrc-rec-20260907-01) | `CFGRC-GOV-PLATFORM-AUTHORITY` | Old-base authority work preserved in six isolated commits with explicit replay gates. |
| 2026-08-27 | [CFGRC-REC-20260827-01](progress-archive/2026-08.md#cfgrc-rec-20260827-01) | `CFGRC-P1-READ-REVIEW` | Regulatory audit events isolated from generic workflows without weakening auditlog. |
| 2026-08-26 | [CFGRC-REC-20260826-04](progress-archive/2026-08.md#cfgrc-rec-20260826-04) | `CFGRC-GOV-LEDGER`, `CFGRC-GOV-UPSTREAM` | Protected-main ruleset and hosted governance/upstream checks activated with retained run evidence. |
| 2026-08-26 | [CFGRC-REC-20260826-03](progress-archive/2026-08.md#cfgrc-rec-20260826-03) | `CFGRC-P1-READ-REVIEW` | Read-only regulatory register/viewer implemented with fail-closed temporal, metadata, IAM, and non-binding presentation contracts. |
| 2026-08-26 | [CFGRC-REC-20260826-02](progress-archive/2026-08.md#cfgrc-rec-20260826-02) | `CFGRC-GOV-LEDGER`, `CFGRC-GOV-UPSTREAM` | Bounded ledger, monthly archive, reproducible-experiment checks, and upstream monitoring implemented. |
| 2026-08-26 | [CFGRC-REC-20260826-01](progress-archive/2026-08.md#cfgrc-rec-20260826-01) | `CFGRC-P1-POSTGRES-ACCEPTANCE` | Local synthetic PostgreSQL technical acceptance implemented and verified. |
| 2026-08-25 | [CFGRC-REC-20260825-01](progress-archive/2026-08.md#cfgrc-rec-20260825-01) | `CFGRC-P1-REVIEW-DISPOSITION` | ADR 0004 implementation pushed and handed off. |
| 2026-08-24 | [CFGRC-REC-20260824-04](progress-archive/2026-08.md#cfgrc-rec-20260824-04) | `CFGRC-P1-REVIEW-DISPOSITION` | Bounded applicability review disposition implemented. |
| 2026-08-24 | [CFGRC-REC-20260824-03](progress-archive/2026-08.md#cfgrc-rec-20260824-03) | `CFGRC-P1-REVIEW-DISPOSITION-DESIGN` | Review-disposition architecture accepted. |
| 2026-08-24 | [CFGRC-REC-20260824-02](progress-archive/2026-08.md#cfgrc-rec-20260824-02) | `CFGRC-P1-APPLICABILITY` | Bounded synthetic applicability persistence verified. |

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
