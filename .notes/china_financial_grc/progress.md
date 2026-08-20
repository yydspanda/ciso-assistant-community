# China Financial GRC Progress Ledger / 中国金融 GRC 进度台账

> Status: **Authoritative execution record / 权威执行记录**
> Updated: **2026-08-20**
> Branch: `agent/china-financial-grc-foundation`
> Current phase: **Phase 1 — architecture and ownership gate**

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
| Django regulatory persistence, migrations, APIs, and reviewer workflow | Not implemented |
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

## Current limitations and risks

1. **Metadata is not reviewed law.** Source records are metadata-only discovery
   entries; included legal-review statuses remain `unreviewed`.
2. **No application persistence.** The temporal regulatory contract is not yet a
   Django model, migration, API, or user workflow.
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

## Current next action

Run `$china-financial-grc-architecture-reviewer` in implementation-planning mode
for the Phase 1 ownership gate, then implement the first database-backed vertical
slice.

The architecture decision must establish:

- whether a bounded new Django app owns regulatory records;
- exact reuse of folder/domain IAM, validation flows, audit, library, evidence,
  and findings;
- model names, keys, uniqueness, valid/recorded time, supersession, and
  append-only behavior;
- transaction ownership, migration/rollback, API versioning, and review states;
- which current JSON contract fields enter persistence now and which remain
  target-only;
- focused model, migration, permission, temporal, and approval tests.

The first implementation slice is complete only when a synthetic entity can
persist and retrieve one document/version/provision/obligation chain, preserve
its source and bitemporal identity, reject invalid state transitions, and pass
focused migration and permission tests. It must not publish a legal conclusion.

## Near-term backlog

| Priority | Slice | Dependency | State |
| --- | --- | --- | --- |
| P0 | Phase 1 architecture/ownership decision | Current repository model and IAM review | Next |
| P0 | Regulatory Django models and initial migration | Accepted ownership decision | Pending |
| P0 | Read-only API plus review-state service | Models, permissions, transaction design | Pending |
| P0 | Small human-reviewed pilot source set | Named reviewer and source rights | Blocked on external ownership |
| P1 | Reviewer UI/admin workflow | Stable API and review contract | Pending |
| P1 | Internal-policy/private overlay model | Published obligation model and privacy design | Later Phase 2 |
| P1 | Read-only source/explanation agent evaluation | Reviewed knowledge and gold set | Later Phase 3 |

## Activity log

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
