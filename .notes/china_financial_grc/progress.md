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
| Hosted project governance | PR #4 remains open. Submitted checkpoint `d1ee20591` has all 216 checks terminal: 209 passed, six functional-browser failures, one tag-only release skipped; it is not release approval. Fresh canonical fetch on 2026-10-01 resolves `a88f2c2db`, 50 ahead / zero behind at that checkpoint. Pure merge `cd09e055d` and earlier merge `426d685da` remain intact. A bounded seven-file navigation/fixture correction is verified in isolation and prepared separately; the final candidate's builds, full backend/browser and exact-head hosted acceptance remain open. Ruleset 21569001 remains active with zero bypass actors and strict governance; the weekly read-only monitor remains active. |

## Current verification summary

- Fresh submitted-checkpoint CE and isolated native EE builds passed; its
  complete frontend unit suite passed **50 files / 682 tests**. Frozen
  authenticated Chromium/Firefox execution ended **seven passed / six failed /
  five not run**. Light/dark 320px register automation found zero axe violations
  or horizontal overflow, with one manual-review item each. These are not new
  candidate browser or full accessibility acceptance.
- The six exact-head hosted failures are CE/EE scoring, directional mapping,
  and auditee navigation. Native rollback-only diagnostics verified the real
  **ISO -> Adobe -> NIST** path and non-default mapped result, and the
  same-framework clone's hidden-documentation-score rejection versus explicit
  synthetic auditor-only visibility. No production IAM/copy guard or default
  visibility was relaxed.
- The final seven-file bounded correction passed **42 focused tests**, scoped
  strict types, formatting and frozen-source checks. An earlier source snapshot
  passed **52 files / 703 tests** and CE build before its functional assertions
  were further strengthened; full final-candidate unit/build/browser gates
  remain open. Canonical detail and exact hashes are in
  [CFGRC-REC-20261001-03](progress-archive/2026-10.md#cfgrc-rec-20261001-03).
- Pure canonical merge `cd09e055d` matches its computed two-parent tree;
  frozen PostgreSQL **156 related / 69 native IAM-notification tests** passed
  with zero skips. Full type checking failed with **2063 errors / 857 warnings /
  468 files**; no passing full-type result is claimed. See
  [CFGRC-REC-20261001-02](progress-archive/2026-10.md#cfgrc-rec-20261001-02).
- The immutable, unexcluded PostgreSQL run at `d1ee20591` collected **6636
  tests** and is still running; there is no terminal full-suite result. Its
  backend content is unchanged by the new frontend-only correction. The
  reboot-lost previous run is unverified, not a pass; historical terminal
  failures and test-only corrections remain in
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
    canonical `a88f2c2db`; submitted checkpoint `d1ee20591` measures **50 ahead /
    zero behind**, but has six failed browser checks. Separate pure two-parent
    merges `cd09e055d` and `426d685da` preserve canonical ancestry and computed
    trees; extension fixes are not hidden in them. Final-candidate unit/build,
    immutable unexcluded backend, authenticated browser, and every triggered
    exact-head hosted gate remain open. The task stays active until protected
    `main` merge, and weekly fresh-fetch monitoring remains enabled.
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
    checkpoint `fd27104e7` is historical and its immutable full-backend diagnostic
    failed; it is not a full pass. The audited submitted checkpoint is `d1ee20591`.
19. **Wider questionnaire/deletion concurrency remains open.** Bounded
    quick-form creation/action IAM, moved-parent read/write consistency, and
    locked-save rechecks passed. QFR submit/status writers still do not share
    that lock protocol; concurrent team/IAM revocation has no shared epoch.
    TPRM ownership/history/preview/SET_NULL regressions passed, but concurrent
    clone/link/delete ownership is not claimed safe.

## Current next action

Verify the new bounded navigation/fixture candidate with fresh CE/isolated EE
builds, complete frontend units, authenticated Chromium/Firefox and every exact-head
hosted check; let the immutable unexcluded PostgreSQL run finish naturally and
verify its unchanged backend content. Merge only the precisely verified candidate
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
| 2026-10-01 | [CFGRC-REC-20261001-03](progress-archive/2026-10.md#cfgrc-rec-20261001-03) | `CFGRC-GOV-UPSTREAM-RECONCILIATION` | Checkpoint CE/EE and 682 units passed; browser diagnosis and 42 final focused correction tests verified; final-candidate full/browser/hosted gates remain open. |
| 2026-10-01 | [CFGRC-REC-20261001-02](progress-archive/2026-10.md#cfgrc-rec-20261001-02) | `CFGRC-GOV-UPSTREAM-RECONCILIATION` | Pure canonical successor merge verified; frozen PostgreSQL 156/69 and merged frontend 682 tests passed; build, type, full backend/browser and hosted release gates remain open. |
| 2026-10-01 | [CFGRC-REC-20261001-01](progress-archive/2026-10.md#cfgrc-rec-20261001-01) | `CFGRC-GOV-UPSTREAM-RECONCILIATION` | Fresh frontend 661 tests passed; exact E3 hosted checks ended 203 passed / 12 failed / one skipped; rebooted full-backend outcome unverified, successor and release gates open. |
| 2026-09-30 | [CFGRC-REC-20260930-11](progress-archive/2026-09.md#cfgrc-rec-20260930-11) | `CFGRC-GOV-UPSTREAM-RECONCILIATION` | Quick-form authority 37 focused / 93 related regressions passed and bounded independent review accepted; wider races and release gates remain open. |
| 2026-09-30 | [CFGRC-REC-20260930-10](progress-archive/2026-09.md#cfgrc-rec-20260930-10) | `CFGRC-GOV-UPSTREAM-RECONCILIATION` | Merged frontend 640 tests and both CI builds passed; 31 deletion/rollback and ten test-only seed regressions passed; final gates remain open. |
| 2026-09-30 | [CFGRC-REC-20260930-09](progress-archive/2026-09.md#cfgrc-rec-20260930-09) | `CFGRC-GOV-UPSTREAM-RECONCILIATION` | Pure canonical successor merge matches computed tree; fresh behind zero and pre-merge 640 frontend tests passed; final acceptance remains open. |
| 2026-09-30 | [CFGRC-REC-20260930-08](progress-archive/2026-09.md#cfgrc-rec-20260930-08) | `CFGRC-GOV-UPSTREAM-RECONCILIATION` | Bounded PostgreSQL compatibility/fixture suites passed; further authority review and full acceptance remain open. |
| 2026-09-30 | [CFGRC-REC-20260930-07](progress-archive/2026-09.md#cfgrc-rec-20260930-07) | `CFGRC-GOV-UPSTREAM-RECONCILIATION` | Three artifact/loader/update tests and 94 CA API/immutable-parent tests passed; no complete acceptance claimed. |
| 2026-09-30 | [CFGRC-REC-20260930-06](progress-archive/2026-09.md#cfgrc-rec-20260930-06) | `CFGRC-GOV-UPSTREAM-RECONCILIATION` | Local two-parent merge checkpoints and attribution-only correction committed; freshly fetched upstream behind count is zero, not release approval. |
| 2026-09-30 | [CFGRC-REC-20260930-05](progress-archive/2026-09.md#cfgrc-rec-20260930-05) | `CFGRC-GOV-UPSTREAM-RECONCILIATION` | Forward TaskTemplate projection and Policy contract verified; synthetic real Huey/SMTP delivery passed; full and new-upstream gates remain open. |

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
