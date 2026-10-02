# China Financial GRC Progress Ledger / 中国金融 GRC 进度台账

> Status: **Authoritative current execution record / 权威当前执行记录**
> Updated: **2026-10-03**
> Branch: `agent/cfgrc-reconciliation-closure-20261003`

This file is the bounded current dashboard: one stage pointer, one active task,
current facts, risks, one next action, and recent links. The roadmap owns stable
stage/task identity and phase gates. Canonical completed records and detailed
verification evidence live in `progress-archive/YYYY-MM.md`.

## Current pointer

- Current Stage: `CFGRC-P1` — one-entity regulatory register
- In Progress Task: `CFGRC-GOV-UPSTREAM` — retain weekly fresh-fetch monitoring after protected-main reconciliation
- Roadmap: [`delivery-roadmap.md`](delivery-roadmap.md)

## Current status

| Item | Current fact |
| --- | --- |
| Phase 0 public foundation | Architecture/governance/domain design, high-level libraries, source metadata packs, applicability facts, and deterministic artifact validation are delivered; they are not legal review or production readiness. |
| Regulatory persistence | A bounded synthetic metadata-only chain, recorded-time correction, whole-version replacement edges, fixed-rule non-binding applicability, and named-human review-disposition services are implemented. Replacement preserves old source rows and transfers no decisions/reviews. |
| Read boundary | Entity/folder-scoped read actions and the read-only register/viewer support one shared version/valid-date/recorded-time selection; binding publication, public mutation APIs, real-law lifecycle and a binding reviewer workflow remain absent. |
| Database evidence | Merged candidate `0ac288eed` hosted PG 16.15 passes 168 tests but has empty operational supersession history. An initial frozen private recovery comparison fails and is retained. A distinct new PG 16.11 logical-profile run passes real-0004 upgrade, old rows/all 565 audit entries, rollback guards, five SQL probes, 30-component backup/restore, restored v3, all 168 tests and complete bounded input freeze. Raw physical differences and prior failures remain recorded; target/production approval stays open. |
| Regulatory content | The public source seed remains metadata-only and legally unreviewed; no real institution profile or reviewed pilot source set exists. |
| AI and private data | No production agent or private-policy ingestion exists, and no regulated/private data is authorised for an external model. |
| Workflow isolation | Regulatory writes remain in `django-auditlog` but are excluded from the generic workflow event catalog, forwarder, and dispatch boundary; future regulatory automation requires a reviewed typed adapter, exact IAM, minimised payload, and human authority. |
| Production acceptance | Legal, privacy, security, records, audit, operations, and production acceptance have not been performed. |
| Hosted project governance | PR #4 merged normally at 2026-10-02 21:31:54 UTC as `9a7c5b7b4`, preserving candidate `0ac288eed` tree and upstream history. Freshly fetched canonical `fb3537c287` is included: main is 63 ahead / zero behind. All 17 candidate workflows pass; 217 checks are 216 success and one tag-only skip. Strict protection remains active. All eight merge-push workflows finish: seven success and the guarded Helm publisher skipped. Weekly monitoring retains warning/failure thresholds of 10/20 behind. |

## Current verification summary

- The distinct new private logical-profile recovery passes every phase naturally
  zero: actual-old-code upgrade, empty rollback/reapply, exact populated guard,
  five SQL probes, all 30 logical restore components, restored runtime v3 and
  **168/168 PostgreSQL cases**, including all four new multi-connection cases.
  All 565 old audit entries and old regulatory rows are preserved. Complete
  bounded freeze matches **1690/1685 source files, 41100 dependency files/four
  links and seven harness inputs**. Profile controls pass **21 tests / 95
  subtests**, retaining initial type-check failures; raw physical column/index
  and five older CHECK cast differences remain retained, not byte equality.
  No native MFA/DDL/privilege change or production approval. See
  [CFGRC-REC-20261003-03](progress-archive/2026-10.md#cfgrc-rec-20261003-03).
- The local upstream upgrade passes frozen PostgreSQL **148 permission/folder
  cases and 82 pure-baseline regulatory cases**, including its four existing
  PostgreSQL cases. The extension then passes **168/168 PostgreSQL regulatory
  cases**, including four new real multi-connection supersession cases. One
  fresh full graph/check/drift/plan passes; the separate upgrade/grants/restore
  chain and delayed all-file freeze in that earlier attempt remain failed or
  incomplete, not accepted. The fresh frozen trial is recorded separately below.
- The upgraded extension passes **208 focused / 789 complete frontend units**,
  CE/isolated native EE builds, private dependency/link/overlay checks and
  **12/12 authenticated Chromium/Firefox cases**, zero retries/skips/flaky.
  All 3096 browser source inputs, build/dependency/harness bytes and regulatory
  rows match before/after. Full types remain failed: **2061 errors / 857
  warnings / 467 files**, zero diagnostics in ten owned files. Earlier failed
  dependency, fixture, browser and freeze attempts are retained. See
  [CFGRC-REC-20261002-02](progress-archive/2026-10.md#cfgrc-rec-20261002-02).
- Merged candidate `0ac288eed` passes all **17 hosted workflows / 216 successful
  checks**, plus one tag-only skip, each workflow on attempt one. Coverage
  records **4779 passed / 11 skipped**, **77%**, with API files excluded;
  the independent API matrix passes **116 jobs**, functional tests **76 jobs**.
  These are separate scopes, not one unexcluded full-backend run or evidence
  of zero individual browser retries. The canonical PG artifact passes
  **168/168**, including four supersession concurrency cases; **60/60**
  shareable checksums and its 1690-file source digest match. Source/restore
  fingerprints agree, with no populated supersession history in that hosted
  operational trial. The end-of-run snapshot is not a before/after freeze.
  The actual main merge has the candidate tree, and all merge-push workflows
  are successful or intentionally skipped. See
  [CFGRC-REC-20261003-04](progress-archive/2026-10.md#cfgrc-rec-20261003-04).
- Owner-approved retirement of the obsolete root `ciso_assistant/VERSION`
  requirement passes **four new tests**, including actual unchanged CE/EE
  tag/branch-fallback generation scripts, **56 stdlib governance tests** and **103
  tool tests / 126 subtests**. The tracked backend VERSION file, native runtime
  metadata, publishers, branch protection and monitoring remain unchanged.
  The final candidate's separate hosted validation and protected-main merge
  are recorded above; earlier failures remain historical failures.
  See [CFGRC-REC-20261002-04](progress-archive/2026-10.md#cfgrc-rec-20261002-04).
- A fresh private actual-0004-to-0005 run verifies the real full graph, old
  regulatory rows/all 565 pre-existing audit entries, empty reverse/reapply,
  populated-0005 exact reverse refusal and five new-table SQL probes. Backup,
  restore and reference grants exit zero; the full bounded comparison fails
  on columns/indexes (**26/28 components match**). Operations exit one,
  restored v3 and its suite are unrun. Before/after freeze manifests match
  **1690 current / 1685 prior source files, 41100 dependency files/four links**
  and all harness/SQL/private input hashes. Independent audit confirms it.
  A scoped CI regression refinement allows legitimate backend VERSION paths;
  **56 stdlib / 103 tool tests / 129 subtests** pass. Fresh `dc85f15acd`
  checkpoint measures **60 ahead / zero behind**, not protected-main acceptance.
  See [CFGRC-REC-20261003-01](progress-archive/2026-10.md#cfgrc-rec-20261003-01).
- Separate read-only v2 diagnosis naturally passes on PostgreSQL **16.11**:
  **1451/3321 columns** differ only in absolute ordinal (relative order and
  definitions agree); one of **1827 indexes** differs only in the native MFA
  predicate's exact array-cast pair, with all **2183 index keys** agreeing.
  The original diagnostic SQL alias failure and operations failure remain
  preserved; that failed trial's v3/suite remain unrun. A distinct new private
  logical-profile full chain passes as recorded above; it does not retroactively
  approve this diagnostic checkpoint or the original recovery trial.
  No native MFA or historical DDL is changed. See
  [CFGRC-REC-20261003-02](progress-archive/2026-10.md#cfgrc-rec-20261003-02).
- The bounded synthetic whole-version replacement and dual-time read slice
  passes **71 focused backend cases**, then **160 passed / four PostgreSQL-only
  skips / zero failures/errors** in both complete regulatory runs, including
  the final real-migration run with an unchanged actual source manifest.
  Private full-graph apply, empty rollback/reapply, populated-history reverse
  refusal, migration drift and Django system checks pass. Independent source
  review found no blocking issue. See
  [CFGRC-REC-20261002-01](progress-archive/2026-10.md#cfgrc-rec-20261002-01).
- Its frontend passes **94 focused / 54 files, 789 complete units**, with
  unchanged eight-file source manifests. Those files have zero type diagnostics;
  initial full-project checking fails with **2063 errors / 857 warnings / 468
  files**. Those checkpoint results precede the upgraded follow-up above;
  neither record claims hosted or production acceptance. Earlier failed
  service/harness/type attempts remain in the archive.
- Owner-approved publication policy is now on main: the entire Helm
  publisher requires exact canonical repository identity; fork image mirroring
  remains repository-scoped and unchanged. Three new dependency-free tests and
  seven negative controls join the existing CI test entrypoint; local YAML
  semantics and unchanged mirror/test/monitor bytes are verified. The actual
  merge-push Helm job skips all steps; fork mirroring succeeds. Old remote
  refs are outside this guard. See
  [CFGRC-REC-20261001-10](progress-archive/2026-10.md#cfgrc-rec-20261001-10).
- Prior exact local candidate `35b76ed2e` passed **68 focused / 54 files,
  749 complete frontend units**, scoped types/format, CE and isolated native
  EE builds with all 100 overlay files matching. Actual source/build hashes
  before and after match; existing browser4 services/artifacts were preserved.
  These local results are not new-head hosted or protected-main approval.
- Its actual authenticated four-file browser matrix passed **24 of 24**:
  Chromium 12 / Firefox 12, zero failures/skips/flaky retries/global errors,
  one worker and unchanged default budgets, with a natural zero exit. All 3263
  source files, 5554 frontend build files, seven private harness inputs and
  owned service identities match before/after and service launch inputs.
  Both engines pass first/repeat inbound mapping and all three TPRM workflows
  with the original cleanup. Native product/IAM/settings/cache semantics were
  not changed. See [CFGRC-REC-20261001-08](progress-archive/2026-10.md#cfgrc-rec-20261001-08).
- Historical `54fc8c944` browser **18/2/2** remains failed. The readiness
  contract tests the existing workflow after its initial real table response;
  it does not prove reliable clicks while that table is still loading or the
  historical layout/cache mechanism. Both bounded experiments and their
  original failed cleanup evidence remain unchanged. Prior light/dark 320px
  automation is checkpoint evidence, not complete/manual accessibility review.
- A separate EE supplement passed locked public-dependency acquisition and
  the native offline build with effective and actual private pnpm-store settings,
  all 100 overlays and frozen source/artifacts. Its overall exit is still one:
  a missing optional native dependency leaves a dangling link, so strict
  dependency isolation failed. Earlier global-cache metadata and offline-cache
  failures remain recorded. No hermetic packaging acceptance is claimed. See
  [CFGRC-REC-20261001-09](progress-archive/2026-10.md#cfgrc-rec-20261001-09).
- Exact local full type checking failed with **2061 errors / 857 warnings /
  467 files**; its auditee route retains **11 errors / three warnings**, with no
  new owned-file diagnostic messages/multiplicities. No passing full-type
  result is claimed. Pure canonical merge `cd09e055d` matches its computed
  two-parent tree; frozen PostgreSQL **156 related / 69 native IAM-notification
  tests** passed with zero skips. See
  [CFGRC-REC-20261001-02](progress-archive/2026-10.md#cfgrc-rec-20261001-02).
- The immutable, unexcluded PostgreSQL run at `d1ee20591` ended **6636
  collected / 6615 passed / 20 skipped / one xfailed / zero failures or errors**.
  All 1679 actual backend inputs matched the prior candidate's unchanged
  backend content, retained by committed base `caf9ace50`. The committed
  supersession/new-lock changes invalidate that equivalence for this candidate;
  this is historical content evidence, not a current full-backend rerun.
  A separate native RiskMatrix fixture supplement passed the unchanged metrics
  node once, without rewriting the full run's skip count. The restore xfail
  remains a 500 response, not a pass. The reboot-lost previous run is unverified;
  historical terminal failures and test-only corrections remain in
  [CFGRC-REC-20261001-01](progress-archive/2026-10.md#cfgrc-rec-20261001-01)
  and the [September archive](progress-archive/2026-09.md).
- Prior local synthetic regulatory persistence/IAM, migration/rollback,
  backup/restore fingerprint and Huey/SMTP/deduplication gates passed in the
  monthly records. They are not protected-main, real-institution,
  legal/privacy/operations, production or universal concurrency acceptance.

## Current limitations and risks

1. **Metadata is not reviewed law.** Discovery records remain legally
   `unreviewed`; no loaded catalog or model output proves compliance.
2. **Persistence is deliberately narrow.** Whole-version replacement is only
   synthetic, metadata-only, unreviewed and non-binding. Partial amendments,
   repeal/transition, real-law review, binding DecisionRecord, publication,
   real source intake and a binding reviewer workflow remain absent. New
   correction of an edge-bound document is refused pending a rebind contract.
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
9. **Only synthetic technical PostgreSQL evidence exists.** Representative plans,
   complete upstream-table privileges, production topology, monitoring,
   encryption/key custody, PITR/RPO/RTO, and operations approval remain open.
10. **Upstream reconciliation is complete; monitoring continues.** Main
    `9a7c5b7b4` includes fresh canonical `fb3537c287` through pure two-parent
    `cbb7b96b1` and PR #4, measuring **63 ahead / zero behind**. The old weekly
    failure at 173 behind remains historical. Weekly fresh-fetch monitoring
    and unchanged 10/20 thresholds remain enabled. Coverage/API evidence has
    separate scopes; a current unexcluded full-backend run remains unperformed.
    The current-user permission response format is breaking: backend/frontend
    must be released together. This merge does not close full-project types,
    target acceptance or legal gates.
11. **Publication evidence is limited to the observed merge.** The owner chose
    Helm-only protection and allowed repository-scoped fork image mirroring.
    Main's entire Helm job requires `intuitem/ciso-assistant-community` before
    checkout/login; merge-push run `37067401666` skips the job with no steps.
    Fork mirror run `37067401626` succeeds with repository-scoped destinations;
    its daily schedule and `packages: write` remain enabled. Old refs/runs and
    other publishers are not covered by the Helm guard. The previously disabled
    write-scoped CLA and OIDC/security-events Plumber remain disabled; the CLA
    distribution test is a separate validation workflow. No release tag or
    manual publisher dispatch was used.
12. **Historical workflow payloads need a read-only deployment inventory.** New
    regulatory audit entries cannot create generic workflow instances, but no
    target database was inspected for instances created before this boundary.
    Any discovered payload must be handled through named IAM, records, privacy,
    and retention owners; audit history must not be deleted automatically.
13. **Custom applicability roles require an explicit narrow upgrade grant.**
    Built-in roles synchronize `view_entitydocumentregistration` after migrate,
    but existing custom roles are not auto-expanded. An administrator must
    grant that extension-owned permission only where registered applicability
    access is intended; generic `tprm.view_entity` is not a substitute. The new
    `supersede_regulatoryversion` permission is a separate explicit grant and
    is not automatically added to any existing built-in or custom role.
14. **Live delivery and authority-concurrency gates remain open.** The local
    PostgreSQL outbox suite and three multi-connection Answer regressions passed,
    and a synthetic local real-Huey/SMTP delivery/deduplication check passed.
    Concurrent IAM-role revocation remains unverified. SMTP holds database locks;
    permission rechecks do not provide a
    shared IAM epoch. The local suite is not production delivery acceptance.
15. **Obsolete version-check retirement is now on main.** The owner
    authorised a separate CI fix. Its one-shot root-path requirement is removed;
    native version authority remains tag -> build metadata -> runtime
    environment. The tracked `backend/ciso_assistant/VERSION` is untouched.
    Four regressions are collected by the existing governance entrypoint; no
    fake root VERSION, native version bump or other check weakening is added.
    Historical opening-head failures remain failures. The separate documentation
    closure PR must still verify its own opening-head workflow behaviour.
16. **Queued integration fingerprints have a bounded guarantee.** They reject
    provider/configuration/credential/settings changes observed before task
    execution. A configuration may still change after the comparison and before
    the external push; no atomic database/external-system authority is claimed.
17. **Frontend upload compensation is best effort.** A rejected upload is
    surfaced as a form error, but a failed compensating DELETE may leave the
    newly created metadata object. No cross-request rollback guarantee is claimed.
18. **Credential handling remains owner-controlled.** The owner completed
    guided GitHub reauthorization and the active CLI session was independently
    verified; server-side invalidation of the old credential is not independently
    attested. A separate diagnostic process listing displayed a local editor
    connection credential; broad process argument/environment output is now
    prohibited and owner-controlled rotation remains pending. No credential
    value is stored in the ledger/candidate, and no editor/user service was
    restarted or killed. Failed historical checkpoints remain failures, not
    current acceptance.
19. **Wider questionnaire/deletion concurrency remains open.** Bounded
    quick-form creation/action IAM, moved-parent read/write consistency, and
    locked-save rechecks passed. QFR submit/status writers still do not share
    that lock protocol; concurrent team/IAM revocation has no shared epoch.
    TPRM ownership/history/preview/SET_NULL regressions passed, but concurrent
    clone/link/delete ownership is not claimed safe.

## Current next action

Verify the documentation-only closure PR's own checks and opening-head version
policy, then complete its protected review workflow while retaining the weekly
fresh-fetch monitor and existing warning/failure thresholds.

## Active task board

| Task ID | Priority | Slice | Dependency | State |
| --- | --- | --- | --- | --- |
| `CFGRC-GOV-UPSTREAM` | P0 | Weekly upstream divergence monitoring and reconciliation evidence closure | Fresh canonical fetch, unchanged 10/20 warning/failure thresholds, protected documentation review | In Progress |
| `CFGRC-P1-TARGET-ACCEPTANCE` | P0 | Versioned target-environment charter, representative plans, PITR/RPO/RTO, role integration, retention, and audit-export acceptance | Named operations/security/privacy/records/legal owners | Pending external owners |
| `CFGRC-P1-SUPERSESSION` | P0 | Source/legal-version supersession | Reviewed source evidence and legal lifecycle contract | Synthetic service/168 hosted PG/12 browser and frozen old-code upgrade/30-component logical restore/v3/168 PG pass, now on main; prior failed recovery retained; real-law/rebind/target gates open |
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
| 2026-10-03 | [CFGRC-REC-20261003-04](progress-archive/2026-10.md#cfgrc-rec-20261003-04) | `CFGRC-GOV-UPSTREAM-RECONCILIATION`, `CFGRC-GOV-UPSTREAM` | Exact candidate passes 17 workflows, 216 successful checks/one tag-only skip and PG168 artifact audit. Protected PR #4 merged as 9a7c5b7b4 with candidate tree; main 63/0. Merge-push Helm skips and fork mirror succeeds. Phase 1/legal/target gates remain open. |
| 2026-10-03 | [CFGRC-REC-20261003-03](progress-archive/2026-10.md#cfgrc-rec-20261003-03) | `CFGRC-GOV-UPSTREAM-RECONCILIATION`, `CFGRC-P1-SUPERSESSION` | Distinct strict logical-profile run passes old-code upgrade, rollback/SQL guards, 30-component recovery/v3, 168 PG and seven-input freeze; raw differences and old failures preserved. New-head/main/legal gates open. |
| 2026-10-03 | [CFGRC-REC-20261003-02](progress-archive/2026-10.md#cfgrc-rec-20261003-02) | `CFGRC-GOV-UPSTREAM-RECONCILIATION`, `CFGRC-P1-SUPERSESSION` | Separate v2 readonly diagnosis passes: columns differ only in absolute ordinal; one native MFA predicate exact cast pair, all index keys agree. Original failures retained; new logical profile/full rerun/new-head/main pending. |
| 2026-10-03 | [CFGRC-REC-20261003-01](progress-archive/2026-10.md#cfgrc-rec-20261003-01) | `CFGRC-GOV-UPSTREAM-RECONCILIATION`, `CFGRC-P1-SUPERSESSION` | Real 0004 upgrade/old audit preservation, empty rollback, populated-0005 refusal, five SQL probes and full freeze pass. Restore schema comparison fails; v3/suite unrun. Narrow version-policy regressions pass 56/103 tests; new-head/main gates open. |
| 2026-10-02 | [CFGRC-REC-20261002-04](progress-archive/2026-10.md#cfgrc-rec-20261002-04) | `CFGRC-GOV-UPSTREAM-RECONCILIATION`, `CFGRC-P1-SUPERSESSION` | Exact 5c04 hosted 17 workflows/216 checks/one tag-only skip pass; PG168 artifact and legacy/restore evidence audited. Owner-approved obsolete root-version gate retirement passes 4 new/56 stdlib/103 tool tests. New CI/ledger head, new-table operations and protected main remain pending. |
| 2026-10-02 | [CFGRC-REC-20261002-03](progress-archive/2026-10.md#cfgrc-rec-20261002-03) | `CFGRC-GOV-UPSTREAM-RECONCILIATION`, `CFGRC-P1-SUPERSESSION` | Dedicated historical clone preserves source 0005; exact old guard/table/migration/fingerprint checks and private PEM exclusion pass 13 deterministic tests. Hosted collection added; real canonical PG/restore, new-table operations and exact-head/main gates open. |
| 2026-10-02 | [CFGRC-REC-20261002-02](progress-archive/2026-10.md#cfgrc-rec-20261002-02) | `CFGRC-GOV-UPSTREAM-RECONCILIATION`, `CFGRC-P1-SUPERSESSION` | Separate pure upstream merge/fixture adaptation; 148/82 baseline PG, 168 extension PG, 208/789 units, CE/EE and frozen 12/12 browsers pass. Upgrade/grants/full-file freeze failed; restore unrun, full types failed, new-head/main gates open. |
| 2026-10-02 | [CFGRC-REC-20261002-01](progress-archive/2026-10.md#cfgrc-rec-20261002-01) | `CFGRC-P1-SUPERSESSION` | Synthetic append-only whole-version replacement and shared dual-time read anchors implemented. Regulatory 160 passed/four PostgreSQL-only skips with and without real migrations; frontend 94/789 passed, migration/rollback/drift checks passed. Full types remain failed; new PostgreSQL/browser/hosted/legal gates open. |
| 2026-10-01 | [CFGRC-REC-20261001-10](progress-archive/2026-10.md#cfgrc-rec-20261001-10) | `CFGRC-GOV-UPSTREAM-RECONCILIATION` | Owner chose Helm-only canonical guard and allowed fork image mirroring. Minimal local publisher guard, three CI-discovered tests/seven negative controls and YAML/source-isolation checks passed; no publication/push/main merge. Existing type/packaging failures remain open. |
| 2026-10-01 | [CFGRC-REC-20261001-09](progress-archive/2026-10.md#cfgrc-rec-20261001-09) | `CFGRC-GOV-UPSTREAM-RECONCILIATION` | Locked public-dependency acquisition, offline native EE build, actual private store, 100 overlays and source/build freeze passed. Strict dependency-link audit failed on a missing optional native package; overall exit one remains failed, publisher/new-head/main gates remain open. |

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
