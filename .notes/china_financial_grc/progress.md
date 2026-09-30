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
| Hosted project governance | PR #4 remains open on submitted head `0c4c66820`: 190 checks passed, 25 failed, and one skipped. The authenticated CLI session is restored. A fresh canonical HTTPS fetch resolved `dcce0c55d`; dedicated pure merge `426d685da` measures 45 ahead / zero behind. Bounded authority regressions passed; immutable full backend/browser and exact-head hosted gates remain open. Ruleset 21569001 was independently verified active with zero bypass actors and strict governance checks; the weekly read-only monitor remains active. |

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
- The next bounded PostgreSQL checkpoint passed separate 147-case export/tree,
  178-case inverse, 20-case dashboard/locking/projection, 159-case fixture,
  93-case score-preset, and 106-case quick-form/import/transition/API suites,
  with no skips. Counts overlap and are not full-suite acceptance. Evidence and
  still-open quick-form write/upstream deletion review findings are canonical in
  [CFGRC-REC-20260930-08](progress-archive/2026-09.md#cfgrc-rec-20260930-08).
- A separate pure two-parent merge now incorporates canonical `dcce0c55d`,
  with exactly Git's computed merge tree and fresh behind count zero. The
  pre-merge frontend passed all **46 files / 640 tests** with unchanged source.
  The merged-tree full **640-test** suite and Community/isolated Enterprise CI
  builds passed; final browser/full-backend/hosted gates remain open. Separate
  PostgreSQL deletion/preview/rollback regressions passed **31 tests**, and the
  explicitly unassigned test-only browser role seed passed **ten tests**.
  Evidence is in
  [CFGRC-REC-20260930-10](progress-archive/2026-09.md#cfgrc-rec-20260930-10)
  and
  [CFGRC-REC-20260930-09](progress-archive/2026-09.md#cfgrc-rec-20260930-09).
- Final quick-form authority regressions passed **37 focused / 93 related tests**
  with zero skips, preserving the separate CA authority path and unchanged-null
  contract. Independent review accepted the bounded parent/action/folder/locked
  recheck implementation; wider status-writer and permission-revocation races
  remain explicit. See
  [CFGRC-REC-20260930-11](progress-archive/2026-09.md#cfgrc-rec-20260930-11).
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
- The unexcluded immutable PostgreSQL diagnostic at `fd27104e7` collected
  6534 tests and stopped at its configured 20-failure limit: **3552 passed /
  nine skipped / 20 failed** in 3095.68 seconds. Both before/after snapshot
  diffs are empty. Fixture-contract mismatches, a missing dashboard import,
  nullable-join locking, and query-budget regressions received bounded passing
  reruns in record 08; additional authority review remains open;
  the unexecuted remainder and the failed run are not full acceptance.
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
    canonical upstream `dcce0c55d` and pure two-parent merge `426d685da`
    measured 45 ahead / zero behind. The previously reviewed merge through
    `555225678` and attribution correction remain intact; the new three-commit
    successor was incorporated without hiding extension fixes in the merge.
    The local artifact loader/update gate passed. Migration paths and bounded regressions passed;
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
18. **Credential handling remains owner-controlled.** After the diagnostic
    exposure, owned remote downloads were stopped. The owner completed the
    guided GitHub reauthorization and the active CLI session was independently
    verified; server-side invalidation of the old credential is not independently
    attested here. No secret is stored in the ledger or candidate diff. Local
    checkpoint `fd27104e7` remains unpushed and its immutable full-backend
    diagnostic failed; it is not a full pass.
19. **Wider questionnaire/deletion concurrency remains open.** Bounded
    quick-form creation/action IAM, moved-parent read/write consistency, and
    locked-save rechecks passed. QFR submit/status writers still do not share
    that lock protocol; concurrent team/IAM revocation has no shared epoch.
    TPRM ownership/history/preview/SET_NULL regressions passed, but concurrent
    clone/link/delete ownership is not claimed safe.

## Current next action

Run the unexcluded immutable PostgreSQL suite and the proportional frozen-
candidate browser matrix, preserving native IAM and aggregate ownership. Monitor
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
| 2026-09-30 | [CFGRC-REC-20260930-11](progress-archive/2026-09.md#cfgrc-rec-20260930-11) | `CFGRC-GOV-UPSTREAM-RECONCILIATION` | Quick-form authority 37 focused / 93 related regressions passed and bounded independent review accepted; wider races and release gates remain open. |
| 2026-09-30 | [CFGRC-REC-20260930-10](progress-archive/2026-09.md#cfgrc-rec-20260930-10) | `CFGRC-GOV-UPSTREAM-RECONCILIATION` | Merged frontend 640 tests and both CI builds passed; 31 deletion/rollback and ten test-only seed regressions passed; final gates remain open. |
| 2026-09-30 | [CFGRC-REC-20260930-09](progress-archive/2026-09.md#cfgrc-rec-20260930-09) | `CFGRC-GOV-UPSTREAM-RECONCILIATION` | Pure canonical successor merge matches computed tree; fresh behind zero and pre-merge 640 frontend tests passed; final acceptance remains open. |
| 2026-09-30 | [CFGRC-REC-20260930-08](progress-archive/2026-09.md#cfgrc-rec-20260930-08) | `CFGRC-GOV-UPSTREAM-RECONCILIATION` | Bounded PostgreSQL compatibility/fixture suites passed; further authority review and full acceptance remain open. |
| 2026-09-30 | [CFGRC-REC-20260930-07](progress-archive/2026-09.md#cfgrc-rec-20260930-07) | `CFGRC-GOV-UPSTREAM-RECONCILIATION` | Three artifact/loader/update tests and 94 CA API/immutable-parent tests passed; no complete acceptance claimed. |
| 2026-09-30 | [CFGRC-REC-20260930-06](progress-archive/2026-09.md#cfgrc-rec-20260930-06) | `CFGRC-GOV-UPSTREAM-RECONCILIATION` | Local two-parent merge checkpoints and attribution-only correction committed; freshly fetched upstream behind count is zero, not release approval. |
| 2026-09-30 | [CFGRC-REC-20260930-05](progress-archive/2026-09.md#cfgrc-rec-20260930-05) | `CFGRC-GOV-UPSTREAM-RECONCILIATION` | Forward TaskTemplate projection and Policy contract verified; synthetic real Huey/SMTP delivery passed; full and new-upstream gates remain open. |
| 2026-09-30 | [CFGRC-REC-20260930-04](progress-archive/2026-09.md#cfgrc-rec-20260930-04) | `CFGRC-GOV-UPSTREAM-RECONCILIATION` | Answer-parent validator and caller-scoped mutation-response compatibility verified on PostgreSQL; full acceptance remains open. |
| 2026-09-30 | [CFGRC-REC-20260930-03](progress-archive/2026-09.md#cfgrc-rec-20260930-03) | `CFGRC-GOV-UPSTREAM-RECONCILIATION` | Merged-working-tree migration, PostgreSQL authority, and frontend checkpoint; full backend/browser/hosted gates still open. |
| 2026-09-30 | [CFGRC-REC-20260930-02](progress-archive/2026-09.md#cfgrc-rec-20260930-02) | `CFGRC-GOV-UPSTREAM-RECONCILIATION` | Nested creation bound to route-owned assessment authority; all 370 frontend tests passed before the next upstream merge. |

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
