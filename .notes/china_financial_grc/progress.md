# China Financial GRC Progress Ledger / 中国金融 GRC 进度台账

> Status: **Authoritative current execution record / 权威当前执行记录**
> Updated: **2026-10-01**
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
| Hosted project governance | PR #4 remains open at audited checkpoint `54fc8c944`. All 16 workflows succeeded; all 216 checks are terminal: 215 successful / one tag-only skipped, with no failures/cancellations; backend coverage passed naturally. Explicit canonical fetch on 2026-10-01 resolves `a88f2c2db`, 53 ahead / zero behind at that checkpoint. Pure merges `cd09e055d` and `426d685da` remain intact. Local browser acceptance still fails 18/2/2. A local two-test follow-up passed isolated verification, not new-candidate browser acceptance. Publication-owner policy and protected-main merge remain open. Ruleset 21569001 remains active with zero bypass actors and strict governance; the weekly read-only monitor remains active. |

## Current verification summary

- Exact `54fc8c944` CE and isolated native EE builds passed; its complete
  frontend unit suite passed **54 files / 749 tests**. Frozen authenticated
  Chromium/Firefox execution ended **18 passed / two failed / two not run**;
  Chromium passes all 11, Firefox passes seven and skips two TPRM dependencies.
  Light/dark 320px register automation found zero axe violations or horizontal
  overflow, with one manual-review item each. These are not future-candidate
  browser or full accessibility acceptance.
- Both engines pass source persistence and non-default outbound mapping.
  Firefox inbound first-pull passes, but its idempotent repeat exceeds the
  whole-test deadline; assertions after that deadline do not establish a pass.
  A separate private five-scenario split preserves all eight steps, 23 business
  assertions and 98 original awaits, adding exact target-URL bindings and a
  fresh-page reopen. It passed **68 focused / 749 complete units**, scoped
  types/format, **24-case collection** and independent frozen-source/AST review.
  Default budgets/retries stay unchanged. That split and a scoped initial-table
  readiness contract are now copied into the local candidate's two test files,
  after **68 focused / 749 complete units** and **24-case collection** passed.
  The final TPRM navigation clicks the verified own-Name row directly; fresh
  frozen checks and independent five-negative-control review passed again.
  TPRM retains all three cases / 22 steps and its original cleanup. Actual
  new-candidate builds/browser/hosted acceptance remain open.
- Firefox TPRM again fails at the Solutions workflow: its page/component is
  hydrated, but the clicked tab remains unselected and Add solution is absent.
  Cleanup independently returns native 204 for two distinct correctly selected
  domains, yet paginated responses/the DOM retain the workaround domain.
  This is not the earlier substring-first repeated deletion. The original
  trace also shows placeholder removal and a 245px scroll change during the
  tab click; actual mouse-event targets and the mechanism remain unproven.
  A fresh-context read-only cache-config experiment observes current authorised
  native and frontend absence, not historical cache cause or repaired browser
  acceptance. A new n=1-per-condition click experiment selected the tab in
  both conditions, but exited one at an unreachable Actor cleanup detail.
  Separate exact native cleanup succeeded without changing settings or IAM;
  the failed experiment remains immutable. This does not prove the original
  mechanism or initial-load click reliability. Canonical evidence is in
  [CFGRC-REC-20261001-07](progress-archive/2026-10.md#cfgrc-rec-20261001-07).
- Exact-checkpoint full type checking failed with **2061 errors / 857 warnings /
  467 files**; its auditee route retains **11 errors / three warnings**, with no
  new owned-file diagnostic messages/multiplicities. No passing full-type
  result is claimed. Pure canonical merge `cd09e055d` matches its computed
  two-parent tree; frozen PostgreSQL **156 related / 69 native IAM-notification
  tests** passed with zero skips. See
  [CFGRC-REC-20261001-02](progress-archive/2026-10.md#cfgrc-rec-20261001-02).
- The immutable, unexcluded PostgreSQL run at `d1ee20591` ended **6636
  collected / 6615 passed / 20 skipped / one xfailed / zero failures or errors**.
  All 1679 actual backend inputs equal the current candidate's unchanged
  backend content; this is content equivalence, not a later-head rerun.
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
10. **The upstream acceptance gate remains open.** Explicit fresh fetch resolves
    canonical `a88f2c2db`; submitted checkpoint `54fc8c944` measures **53 ahead /
    zero behind** and every runnable exact-head hosted check passed, but its
    local browser run still has two failures and two dependent cases not run.
    Separate pure two-parent
    merges `cd09e055d` and `426d685da` preserve canonical ancestry and computed
    trees; extension fixes are not hidden in them. Unexcluded backend-content
    evidence is verified; the locally verified two-test follow-up is not a
    submitted or browser-accepted candidate. Its new-head unit/build, authenticated browser
    and every triggered exact-head hosted gate remain open. The task stays active until protected
    `main` merge, and weekly fresh-fetch monitoring remains enabled.
11. **Inherited workflow activation still needs an owner policy.** Opening PR #1
    registered inherited validation workflows as well as the three fork jobs.
    The write-scoped CLA and OIDC/security-events Plumber workflows were
    explicitly disabled; no CLA was signed. A fresh read-only inventory now
    confirms `mirror-images.yml` is registered and active, with `packages: write`.
    Protected main uses a weekly schedule; this PR changes it to daily. Five
    past weekly runs have successful metadata, not independently verified
    package-write contents. Its earlier unregistered API result is historical.
    The Helm publisher targets official `ghcr.io/intuitem/helm-charts/ce`, not
    the fork; its direct API 404 does not prove post-merge inactivity. This PR
    changes both publishers' main-push path selectors. Explicit owner choice
    must guard both publishers to the canonical repository, or guard Helm and
    expressly allow fork mirror writes, or defer main merge. Neither
    publisher has been dispatched or disabled during this audit.
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

Freeze the final local two-test follow-up and verify its candidate with fresh
CE/isolated EE builds, complete frontend units, all 24 authenticated Chromium/
Firefox cases and every exact-head hosted check. Preserve any residual initial-
load click or native cleanup failure instead of claiming its old mechanism fixed.
Bind the complete unexcluded backend evidence to unchanged actual backend bytes.
Resolve the outstanding publication-owner decision before merging the precisely verified candidate
through protected main. Keep the stage/task pointers; named-owner and production
acceptance remain later work.

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
| 2026-10-01 | [CFGRC-REC-20261001-07](progress-archive/2026-10.md#cfgrc-rec-20261001-07) | `CFGRC-GOV-UPSTREAM-RECONCILIATION` | Two-test follow-up passed 68/749 and 24-case collection with original business/cleanup preserved. Click experiment measured two selected tabs but failed its Actor cleanup assumption; separate exact cleanup passed. Original 18/2/2 and new-candidate/owner gates remain open. |
| 2026-10-01 | [CFGRC-REC-20261001-06](progress-archive/2026-10.md#cfgrc-rec-20261001-06) | `CFGRC-GOV-UPSTREAM-RECONCILIATION` | Exact 749 units / CE / EE passed; hosted checks: 215 success / one tag-only skip / zero failures. Local browser failed 18/2/2. Private inbound correction passed 68/749 and 24-case collection; cache-config experiment records current authorised-read absence, not historical cause. Release/owner gates remain open. |
| 2026-10-01 | [CFGRC-REC-20261001-05](progress-archive/2026-10.md#cfgrc-rec-20261001-05) | `CFGRC-GOV-UPSTREAM-RECONCILIATION` | Exact 732 units / CE / EE and backend-content evidence passed; browser failed 15/3/0, hosted 213/2/1; separate test-only correction passed 88/749 and 22-case collection; final gates and publication-owner decision remain open. |
| 2026-10-01 | [CFGRC-REC-20261001-04](progress-archive/2026-10.md#cfgrc-rec-20261001-04) | `CFGRC-GOV-UPSTREAM-RECONCILIATION` | Exact checkpoint CE/EE and 703 units passed; browser failed 8/6/4, full types remain failed; separate test-only correction passed 71 focused / 732 complete units, final gates remain open. |
| 2026-10-01 | [CFGRC-REC-20261001-03](progress-archive/2026-10.md#cfgrc-rec-20261001-03) | `CFGRC-GOV-UPSTREAM-RECONCILIATION` | Checkpoint CE/EE and 682 units passed; browser diagnosis and 42 final focused correction tests verified; final-candidate full/browser/hosted gates remain open. |
| 2026-10-01 | [CFGRC-REC-20261001-02](progress-archive/2026-10.md#cfgrc-rec-20261001-02) | `CFGRC-GOV-UPSTREAM-RECONCILIATION` | Pure canonical successor merge verified; frozen PostgreSQL 156/69 and merged frontend 682 tests passed; build, type, full backend/browser and hosted release gates remain open. |
| 2026-10-01 | [CFGRC-REC-20261001-01](progress-archive/2026-10.md#cfgrc-rec-20261001-01) | `CFGRC-GOV-UPSTREAM-RECONCILIATION` | Fresh frontend 661 tests passed; exact E3 hosted checks ended 203 passed / 12 failed / one skipped; rebooted full-backend outcome unverified, successor and release gates open. |
| 2026-09-30 | [CFGRC-REC-20260930-11](progress-archive/2026-09.md#cfgrc-rec-20260930-11) | `CFGRC-GOV-UPSTREAM-RECONCILIATION` | Quick-form authority 37 focused / 93 related regressions passed and bounded independent review accepted; wider races and release gates remain open. |
| 2026-09-30 | [CFGRC-REC-20260930-10](progress-archive/2026-09.md#cfgrc-rec-20260930-10) | `CFGRC-GOV-UPSTREAM-RECONCILIATION` | Merged frontend 640 tests and both CI builds passed; 31 deletion/rollback and ten test-only seed regressions passed; final gates remain open. |
| 2026-09-30 | [CFGRC-REC-20260930-09](progress-archive/2026-09.md#cfgrc-rec-20260930-09) | `CFGRC-GOV-UPSTREAM-RECONCILIATION` | Pure canonical successor merge matches computed tree; fresh behind zero and pre-merge 640 frontend tests passed; final acceptance remains open. |

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
