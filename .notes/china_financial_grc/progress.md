# China Financial GRC Progress Ledger / 中国金融 GRC 进度台账

> Status: **Authoritative current execution record / 权威当前执行记录**
> Updated: **2026-09-30**
> Branch: `agent/cfgrc-upstream-reconciliation-20260827`

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
| Workflow isolation | Regulatory writes remain in `django-auditlog` but are excluded from the generic workflow event catalog, forwarder, and dispatch boundary; future regulatory automation requires a reviewed typed adapter, exact IAM, minimised payload, and human authority. |
| Production acceptance | Legal, privacy, security, records, audit, operations, and production acceptance have not been performed. |
| Hosted project governance | PR #4 is open on submitted head `0c4c66820`; governance passed, functional failures require correction, and other triggered checks are running. Local two-parent commits join upstream through `555225678`; attribution-only `df7738176` measured 40 ahead / zero behind after explicit fetch. The local artifact loader/update gate passed; full backend, browser, and complete exact-head hosted gates remain open. The no-bypass ruleset and weekly read-only upstream monitor remain active. |

## Current verification summary

- Local merge `78e546e5b` joins first parent `491130e9` and canonical upstream
  `e6ba85f8`. The separate artifact-only merge `835a8c772` joins its successor
  `555225678` with a tree identical to Git's pure merge result. Attribution-only
  correction `df7738176` leaves all object/content identities unchanged.
  The local loader/update gate passed three PostgreSQL-backed tests. Bounded verified
  evidence is recorded in
  [CFGRC-REC-20260930-03](progress-archive/2026-09.md#cfgrc-rec-20260930-03)
  [CFGRC-REC-20260930-04](progress-archive/2026-09.md#cfgrc-rec-20260930-04),
  [CFGRC-REC-20260930-05](progress-archive/2026-09.md#cfgrc-rec-20260930-05),
  [CFGRC-REC-20260930-06](progress-archive/2026-09.md#cfgrc-rec-20260930-06),
  and [CFGRC-REC-20260930-07](progress-archive/2026-09.md#cfgrc-rec-20260930-07).
- Fresh PostgreSQL technical acceptance passed **82 regulatory tests**, bounded
  role probes, migration/rollback checks, synthetic backup/restore fingerprint
  equality, and a restored successor write. The separate fork-upgrade path
  preserved both migration histories and all ten regulatory publication fields.
  This is local synthetic evidence, not production acceptance.
- PostgreSQL IAM/outbox/three multi-connection Answer regressions passed
  **178 tests with no skips**. Independently rerun frontend validation passed
  **44 files / 622 tests**; Community and isolated Enterprise builds passed.
  Django checks, migration-drift checks, and hosted Ruff formatting passed.
- Answer-parent uniqueness compatibility passed all **13 Answer API tests**;
  caller-scoped mutation-response expectations passed **106 AppliedControl API
  tests**; upstream/relation/Typst regressions passed **58 tests**, all on
  PostgreSQL. Full backend acceptance is **not yet passing**: earlier diagnostic
  runs and their failures are recorded in the archive. A prior run stopped
  at a stale hidden-owner aggregation expectation (378 passed / nine skipped /
  one failed); its test-only correction passed all 59 Commitment API tests.
  A forward-TaskTemplate batch projection fix passed 14 relation-authority
  tests and its original failure node; all 102 Policy API tests passed.
  Real synthetic API/Huey/loopback SMTP delivery and repeat-request deduplication
  passed. These bounded results do not constitute full or production acceptance.
  The full type gate also failed with **2065 errors / 857 warnings / 469 files**;
  scoped changed loaders/helpers have no errors. The first authenticated
  two-engine browser matrix finished with four passed / eight failed / six not
  run; loading, save/history, stale-selector, and private-mail-fixture failures
  remain under correction. A new local backend diagnostic was stopped deliberately
  (exit 143, no JUnit or full pass) to unblock the loading fix; its two new CA
  contract fixtures were corrected without relaxing authority; all 94 CA API
  and immutable-parent tests passed. The mapping-catalog join and empty-mapping
  short circuit passed all 15 mapping graph/catalog tests; live browser reruns
  remain open. Complete backend/browser and
  exact-head hosted acceptance remain open.
- Pre-merge checkpoints remain in
  [CFGRC-REC-20260930-01](progress-archive/2026-09.md#cfgrc-rec-20260930-01)
  and [CFGRC-REC-20260930-02](progress-archive/2026-09.md#cfgrc-rec-20260930-02).
  August PR/check/merge evidence is canonical in
  [CFGRC-REC-20260828-01](progress-archive/2026-08.md#cfgrc-rec-20260828-01)
  and its linked records. Old heads are historical evidence, not the new
  candidate's release approval.

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
10. **The upstream acceptance gate remains open.** Explicit fresh fetch of
    upstream `555225678` measured code head `df7738176` 40 ahead / zero behind.
    Its separate pure merge and source-attribution correction are committed;
    the local artifact loader/update gate passed. Migration paths and bounded regressions passed;
    full backend, browser, and every hosted check on the exact submitted head
    remain open. The task remains active until that branch
    lands through protected `main`; weekly fresh-fetch monitoring stays enabled.
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
14. **Live delivery and authority-concurrency gates remain open.** The local
    PostgreSQL outbox suite and three multi-connection Answer regressions passed,
    and a synthetic local real-Huey/SMTP delivery/deduplication check passed.
    Concurrent IAM-role revocation remains unverified. SMTP holds database locks;
    permission rechecks do not provide a
    shared IAM epoch. The local suite is not production delivery acceptance.
15. **The inherited one-shot version checker is stale.** It checks removed path
    `ciso_assistant/VERSION` only when a PR is opened, so it failed on PR #4's
    opening head just as it did on earlier fork PR opening heads. It is not a
    required ruleset check and must not be made green by fabricating an upstream
    version file. A separate CI-owner change should retire or correctly scope it;
    the exact updated reconciliation head still requires every job it triggers.
16. **Queued integration fingerprints have a bounded guarantee.** They reject
    provider/configuration/credential/settings changes observed before task
    execution. A configuration may still change after the comparison and before
    the external push; no atomic database/external-system authority is claimed.
17. **Frontend upload compensation is best effort.** A rejected upload is
    surfaced as a form error, but a failed compensating DELETE may leave the
    newly created metadata object. No cross-request rollback guarantee is claimed.
18. **GitHub credential rotation is required.** A diagnostic accidentally exposed
    the current CLI OAuth credential in tool output. Owned remote downloads were
    stopped and no credential is recorded here. Credential-owner revocation and
    fresh authorization are required before further authenticated remote checks,
    pushes, or protected-main delivery. Local checkpoint `fd27104e7` is unpushed;
    its immutable full-backend test snapshot is still running, not a full pass.

## Current next action

First require credential-owner rotation and fresh GitHub authorization, then
reconcile freshly fetched canonical upstream in a separate two-parent
merge, preserving upstream interfaces and the existing authority protections.
Verify the fresh and fork-upgrade migration paths on disposable PostgreSQL,
run the proportional merged-tree backend/frontend/browser matrix, and monitor
every hosted check triggered for the submitted PR #4 head. Merge through the
no-bypass protected-main path only after those checks pass. Keep the current
stage/task pointers until reconciliation completes; target-environment and
named-owner acceptance remain subsequent work.

## Active task board

| Task ID | Priority | Slice | Dependency | State |
| --- | --- | --- | --- | --- |
| `CFGRC-GOV-UPSTREAM-RECONCILIATION` | P0 | Dedicated canonical-upstream reconciliation | Clean branch after PR #3, fresh canonical fetch, conflict review, proportional regression, protected-main PR | In Progress |
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
| 2026-09-30 | [CFGRC-REC-20260930-07](progress-archive/2026-09.md#cfgrc-rec-20260930-07) | `CFGRC-GOV-UPSTREAM-RECONCILIATION` | Three artifact/loader/update tests and 94 CA API/immutable-parent tests passed; no complete acceptance claimed. |
| 2026-09-30 | [CFGRC-REC-20260930-06](progress-archive/2026-09.md#cfgrc-rec-20260930-06) | `CFGRC-GOV-UPSTREAM-RECONCILIATION` | Local two-parent merge checkpoints and attribution-only correction committed; freshly fetched upstream behind count is zero, not release approval. |
| 2026-09-30 | [CFGRC-REC-20260930-05](progress-archive/2026-09.md#cfgrc-rec-20260930-05) | `CFGRC-GOV-UPSTREAM-RECONCILIATION` | Forward TaskTemplate projection and Policy contract verified; synthetic real Huey/SMTP delivery passed; full and new-upstream gates remain open. |
| 2026-09-30 | [CFGRC-REC-20260930-04](progress-archive/2026-09.md#cfgrc-rec-20260930-04) | `CFGRC-GOV-UPSTREAM-RECONCILIATION` | Answer-parent validator and caller-scoped mutation-response compatibility verified on PostgreSQL; full acceptance remains open. |
| 2026-09-30 | [CFGRC-REC-20260930-03](progress-archive/2026-09.md#cfgrc-rec-20260930-03) | `CFGRC-GOV-UPSTREAM-RECONCILIATION` | Merged-working-tree migration, PostgreSQL authority, and frontend checkpoint; full backend/browser/hosted gates still open. |
| 2026-09-30 | [CFGRC-REC-20260930-02](progress-archive/2026-09.md#cfgrc-rec-20260930-02) | `CFGRC-GOV-UPSTREAM-RECONCILIATION` | Nested creation bound to route-owned assessment authority; all 370 frontend tests passed before the next upstream merge. |
| 2026-09-30 | [CFGRC-REC-20260930-01](progress-archive/2026-09.md#cfgrc-rec-20260930-01) | `CFGRC-GOV-UPSTREAM-RECONCILIATION` | Pre-merge backend security checkpoint committed with local regression evidence; reconciliation remains active. |
| 2026-08-28 | [CFGRC-REC-20260828-01](progress-archive/2026-08.md#cfgrc-rec-20260828-01) | `CFGRC-GOV-UPSTREAM-RECONCILIATION` | Canonical historical PR #4 reconciliation/check evidence; old failing head is not release approval. |
| 2026-08-27 | [CFGRC-REC-20260827-01](progress-archive/2026-08.md#cfgrc-rec-20260827-01) | `CFGRC-P1-READ-REVIEW` | Regulatory audit events isolated from generic workflows without weakening auditlog. |
| 2026-08-26 | [CFGRC-REC-20260826-04](progress-archive/2026-08.md#cfgrc-rec-20260826-04) | `CFGRC-GOV-LEDGER`, `CFGRC-GOV-UPSTREAM` | Protected-main ruleset and hosted governance/upstream checks activated with retained run evidence. |

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
