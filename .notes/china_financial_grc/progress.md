# China Financial GRC Progress Ledger / 中国金融 GRC 进度台账

> Status: **Authoritative execution record / 权威执行记录**
> Updated: **2026-08-24**
> Branch: `agent/china-financial-grc-foundation`
> Current phase: **Phase 1 — temporal regulatory persistence**

This file records verified current state, evidence, blockers, and the next
action. It contains no private institution data, internal policy content,
credentials, or local model-provider values. Phase ordering and exit criteria
live in `delivery-roadmap.md`.

## Current status

| Item | State |
| --- | --- |
| Public fork and working branch | Complete and pushed |
| Phase 0 architecture/governance/domain design | Complete as a draft target design |
| Loadable China financial control foundation | Complete; high-level foundation only |
| Official-source metadata packs | Complete for the current non-exhaustive seed; legal review remains unreviewed |
| Applicability fact registry and deterministic artifact validation | Complete for draft interchange artifacts |
| Project-level `AGENTS.md`, product skill, architecture skill, roadmap, and progress ledger | Complete and independently forward-tested in this change |
| Django regulatory persistence, migrations, APIs, and reviewer workflow | Synthetic metadata-only chain, non-binding review, controlled recorded-time correction, and current/historical detail retrieval implemented and SQLite-tested; applicability, source/legal supersession, binding decisions, and UI remain open |
| Reviewed provisions and obligations from the source packs | Not implemented; the end-to-end record is illustrative only |
| Private internal-policy ingestion and mapping | Not implemented |
| Read-only production agent, proposal writes, or continuous evidence connectors | Not implemented |
| Legal, privacy, security, audit, and production acceptance | Not performed |

## Verified Phase 0 deliveries

### Foundation commit

- Commit: `c4f3b5c73` — `add China financial GRC foundation`
- Added original high-level common controls and a dependent assessment baseline.
- Added target architecture, domain model, source policy, governance, migration,
  open-source decisions, draft interchange schema, example, and validator.
- Current library shape is 18 controls, 26 framework nodes, 18 assessable nodes,
  and four implementation groups. This is a readiness baseline, not complete
  banking or insurance coverage.

### Regulatory-source expansion commit

- Commit: `7ba54e2c6` — `expand China financial regulatory source packs`
- Added common, banking, insurance, and fintech/data/AI discovery packs with a
  hashed pack index.
- Current seed contains 76 documents and 76 versions plus 56 controlled
  applicability facts. These counts are execution facts, not permanent product
  requirements.
- Added deterministic three-value applicability evaluation, temporal containment,
  global typed-ID checks, canonical payload digests, maker-checker separation,
  prerequisite approvals, terminal disposition checks, and attack-oriented
  mutation tests.
- Corrected discovery scope for the 2026 financial-sector AI guidance and
  isolated future-effective and no-explicit-commencement states.

### Local model configuration boundary

- Local OpenAI-compatible providers are configured only in ignored CISO
  Assistant settings.
- No model API key, external-project configuration, private database, or local path was
  committed.
- Local provider availability is not a production data-location or legal-
  transfer approval.

## Verification evidence

Latest verified commands for the source-pack delivery:

```text
backend/.venv/bin/python tools/china_financial_grc/validate_artifacts.py
  PASS — 56 facts; 76 documents; 76 versions; four indexed source catalogs

backend/.venv/bin/python -m pytest tools/china_financial_grc/tests/test_validate_artifacts.py -q
  PASS — 25 tests and 12 subtests

pre-commit run --files <25 changed files>
  PASS

git diff --cached --check
  PASS

targeted secret/private-path scan
  PASS — no credential, external-project reference, private messaging export,
  local-path, or database content in the commit
```

Independent attack replay confirmed rejection of:

- unindexed source catalogs and pack-ID/file swaps;
- blank evidence and blank human approval identities;
- applicability intervals outside their upstream rules/obligations;
- draft, unknown, or not-yet-effective source approval chains;
- provision approval without prior source-version approval;
- terminal review states without matching `reject` or `revoke` decisions.

Project-agent operating-model validation:

```text
skill-creator quick_validate.py .agents/skills/china-financial-grc-product-manager
  PASS

skill-creator quick_validate.py .agents/skills/china-financial-grc-architecture-reviewer
  PASS

targeted pre-commit and git diff --check
  PASS

independent product and architecture forward tests
  PASS — no blocker; recommended output-contract hardening incorporated
```

The CISO library loader was also exercised against an isolated database copy for
dependency loading, node/group counts, evidence, and control references. The
repository's fixed shared SQLite test database produced an environmental I/O/WAL
conflict during an earlier direct pytest attempt; the isolated loader assertions
passed and no user database was modified.

Phase 1 first-persistence-slice verification:

```text
backend/.venv/bin/python manage.py check
  PASS — no system-check issues

backend/.venv/bin/python manage.py makemigrations regulatory --check --dry-run
  PASS — no migration drift

backend/.venv/bin/pytest regulatory/tests -q --create-db
  PASS — 17 migration-backed focused tests at the final schema boundary

backend/.venv/bin/pytest regulatory/tests -q --nomigrations --create-db --reuse-db
  PASS — 19 final model, transaction, IAM, state, API, and constraint tests

isolated SQLite full project base + final regulatory zero -> 0001 reapply
  PASS — initial migration is reversible and reapplies without touching user data

regulatory router introspection
  PASS — list/detail only; inherited batch, object, and cascade actions absent
```

Independent model and security reviews identified and drove fail-closed fixes
for non-current ingestion, binding-state DB bypass, source-text storage,
caller-mutated or revoked authority objects, service-account review,
analyst/legal permission separation, aggregate child folders, entity metadata
disclosure, and inherited generic actions. The final static review found no
remaining merge blocker.

Phase 1 recorded-time-correction verification:

```text
backend/.venv/bin/pytest backend/regulatory/tests -q --nomigrations --reuse-db
  PASS — 25 focused model, service, API, IAM, temporal-boundary, review-reset,
  stale-write, no-op, idempotency, corruption, and constraint tests

backend/.venv/bin/pytest backend/regulatory/tests -q --create-db
  PASS — 25 tests against the real migration boundary through 0002, including
  current-read and exact-retry behavior under wall-clock regression

backend/.venv/bin/python manage.py check
  PASS — no system-check issues

backend/.venv/bin/python manage.py makemigrations regulatory --check --dry-run
  PASS — no migration drift

isolated SQLite full-project database: regulatory 0001 -> 0002
  PASS — apply; empty-history rollback to 0001; reapply to 0002

isolated SQLite full-project database with an actual correction event
  PASS — reverse to 0001 refused by the intended audit-history guard

independent temporal, migration, API/IAM, and architecture reviews
  PASS — no remaining Critical, High, or Medium finding
```

The migration and API checks cover one synthetic metadata-only aggregate. A
separate brand-new empty SQLite `manage.py migrate regulatory 0002` rehearsal
did not reach the regulatory app: the repository's pre-existing
`iam.0009_create_allauth_emailaddress_objects` migration expected an installed
allauth `account` app that was absent in that command environment. This is
tracked as a fresh-empty environment limitation, not counted as regulatory
migration evidence. No user database was modified.

## Current limitations and risks

1. **Metadata is not reviewed law.** Source records are metadata-only discovery
   entries; included legal-review statuses remain `unreviewed`.
2. **Persistence remains deliberately narrow.** The application stores a
   synthetic metadata-only Document/Version/Provision/Obligation chain,
   non-binding review events, controlled recorded-time correction, and coherent
   current/historical detail retrieval. It has no source/legal-version
   supersession, applicability records, binding DecisionRecord, reviewer UI,
   approval/publication, source-text intake, or real source ingestion.
3. **No pilot entity facts.** Public artifacts cannot decide applicability for a
   real institution, licence, product, customer, data flow, or system.
4. **No gold set or baseline.** Extraction, mapping, reviewer effort, latency,
   and cost targets cannot be promoted until humans review a bounded dataset.
5. **No private policy bridge.** Internal policies must remain in a private,
   access-controlled overlay and have not been ingested.
6. **Edition and audit decisions remain open.** Community and enterprise
   capabilities differ; production needs an explicit long-retention,
   tamper-evident audit and service-identity design.
7. **External model use is not authorised for regulated data.** Local provider
   connectivity does not satisfy privacy, secrecy, security, data-transfer, or
   retention requirements.
8. **Append-mostly is not WORM.** The supported service/API path and local DB
   constraints fail closed, but privileged SQL and unsupported ORM bulk/M2M
   operations still require production database-role, trigger, or tamper-
   evident-storage decisions.
9. **Production database evidence is pending.** Final focused tests use the
   project's SQLite path. PostgreSQL apply/rollback plus two-connection
   correction/read linearization on the shared folder lock, representative
   current/history query plans, backup/restore, and audit-retention evidence
   remain external release gates.

## Current next action

Persist one synthetic obligation's versioned applicability fact snapshot and a
deterministic, non-binding three-value decision: `applicable`,
`not_applicable`, or `needs_review`. Missing or unknown facts must
deterministically resolve to `needs_review`; retain evidence references,
provenance, and recorded-time retrieval. Do not add source/legal supersession,
approval, publication, real institution facts, source text, a public write API,
library projection, or an agent in that slice.

## Near-term backlog

| Priority | Slice | Dependency | State |
| --- | --- | --- | --- |
| P0 | Phase 1 architecture/ownership decision | Current repository model and IAM review | Complete |
| P0 | First regulatory chain models and initial migration | Accepted ownership decision | Complete for current synthetic slice |
| P0 | Read-only API plus non-binding review-state service | Models, permissions, transaction design | Complete for current synthetic slice |
| P0 | Controlled recorded-time correction and `recorded_as_of` retrieval | First current-chain slice | Complete for current synthetic slice |
| P0 | Source/legal-version supersession | Reviewed source evidence and legal lifecycle contract | Pending; separate from recorded correction |
| P0 | One versioned fact snapshot and deterministic non-binding applicability decision | Stable bitemporal correction semantics | Next |
| P0 | Small human-reviewed pilot source set | Named reviewer and source rights | Blocked on external ownership |
| P1 | Reviewer UI/admin workflow | Stable API and review contract | Pending |
| P1 | Internal-policy/private overlay model | Published obligation model and privacy design | Later Phase 2 |
| P1 | Read-only source/explanation agent evaluation | Reviewed knowledge and gold set | Later Phase 3 |

## Activity log

### 2026-08-24 — Controlled recorded-time correction and historical reads

- Accepted ADR 0002 and kept recorded-time repair distinct from an authority's
  source/legal-version supersession.
- Added a folder-scoped, named-human correction operation for the synthetic,
  metadata-only chain. It compare-and-swap closes one exact current revision
  set, appends direct successors at a single server cutoff, resets obligation
  review to `machine_proposed`, and records idempotent actor/rationale and
  semantic before/after digests.
- Added coherent `recorded_as_of` document detail selection with half-open
  intervals, one joined citation chain, time-filtered review events, shared
  folder-lock linearization, monotonic aggregate recorded time under wall-clock
  rollback, and fail-closed object/related-field IAM.
- Added migration 0002 with history indexes, correction permission, durable
  correction-event constraints, and a reverse guard that refuses to discard
  existing correction audit history.
- Verified focused SQLite behaviour, migration-backed tests, empty-history
  rollback/reapply, populated-history rollback refusal, system checks, and no
  migration drift. PostgreSQL migration, two-connection locking, and query-plan
  evidence remain explicit external gates.

### 2026-08-21 — First database-backed regulatory chain

- Implementation commit: `c52bffb26` — `add first regulatory persistence slice`.
- Accepted ADR 0001 and created the bounded `backend/regulatory` owner instead
  of flattening legal facts into mutable library or document models.
- Added the initial migration and an atomic, idempotent synthetic chain service
  for Document -> Version -> Provision -> Obligation, preserving portable IDs,
  source identity, valid/recorded time, provenance, and the authenticated
  ingester identity.
- Added folder-scoped, read-only list/detail APIs and an append-only proposal
  review service. Analyst and legal review use separate permissions and named
  humans; no route or state can approve or publish a legal conclusion.
- Added database constraints for unpublished/current metadata-only records,
  no source text, lifecycle consistency, machine-proposal initial state, and
  exactly the two non-binding review edges.
- Verified IAM isolation, caller-object reloading, idempotency, atomic rollback,
  invalid lifecycle/state rejection, service-account exclusion, hidden generic
  actions, migration reversibility, and fail-closed aggregate serialization on
  synthetic data only.

### 2026-08-20 — Project-agent operating model

- Confirmed the target repository previously had no root `AGENTS.md` and no
  Codex `.agents/skills` packages.
- Adapted a repository-level product-manager and architecture-reviewer mechanism
  to China financial GRC without copying another project's private notes, model
  configuration, or credentials.
- Established this roadmap/progress pair as the product-management memory for
  the extension: roadmap owns sequencing; progress owns verified facts and the
  next action.
- Independently exercised the product skill against a proposed autonomous
  compliance/reporting agent and the architecture skill against flattening
  regulatory history into mutable library models. Both rejected the unsafe
  framing, preserved Phase 1 boundaries, and produced a bounded next slice.

### 2026-08-20 — Regulatory source packs and validator hardening

- Completed and pushed commit `7ba54e2c6`.
- Independent content and security review found and corrected issuer/scope,
  pack-integrity, applicability, approval, temporal, and disposition gaps before
  push.
- Remote branch SHA matched local SHA after push and the worktree was clean.

### 2026-08-19 to 2026-08-20 — Foundation

- Forked and branched CISO Assistant Community.
- Added commit `c4f3b5c73` and configured ignored local model providers.
- Verified the public branch excludes customer data, private workflow exports,
  model keys, and local databases.

## Ledger update rules

- Add an entry only for material verified work, a gate decision, or a changed
  blocker.
- Include concrete commit/artifact/test evidence and name unrun external gates.
- Keep one explicit next action; move completed work to the activity log.
- Do not rewrite historical entries to make later results appear earlier.
- Never place confidential organisation facts, source texts without rights,
  credentials, or private paths in this public ledger.
