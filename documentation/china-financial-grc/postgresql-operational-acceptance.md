# PostgreSQL and operational acceptance

Status: **executable local synthetic gate; target-environment acceptance pending**

This document defines the external database and operational gate for the bounded
Phase 1 regulatory implementation. It does not change the implementation, the
roadmap, or the progress ledger, and it must not be used to claim legal review,
regulatory compliance, production readiness, or suitability for real
institution data.

The repository includes a repeatable PostgreSQL 16 harness for the synthetic,
draft, non-binding slice. A local run has verified the full migration graph,
independent-connection locking, index usability, backup and restore, and a
bounded database-role contract. This is repository-local technical evidence,
not target-environment operations evidence. Representative production-volume
plans, deployment-standard recovery, tamper-evident retention, audit-export
privacy, and named owner approval remain external gates. See
[ADR 0004](adr/0004-bounded-synthetic-applicability-review-disposition.md) and
the [current implementation boundary](README.md#implementation-boundary).

## Decision and scope

**Accept with conditions:** use one evidence package to test the current
`regulatory` migration and transaction contracts on the intended PostgreSQL
version. A technical pass means only that the named environment satisfied the
recorded tests at the recorded application revision. It does not:

- convert source metadata into reviewed law;
- establish applicability for a real entity, licence, product, customer, data
  flow, system, or AI use case;
- approve a legal conclusion, publication, library projection, or public write
  API;
- authorise regulated or private data in the test environment, logs, backups,
  exports, or an external model; or
- replace named legal, compliance, privacy, security, operations, or risk
  acceptance.

Run destructive migration reversal and restore exercises only against a
disposable database or an approved isolated restore target. Never rehearse them
against a user or production database.

## Repository-local harness

From the repository root, with the locked backend environment and Docker
available, run:

```bash
./tools/china_financial_grc/postgresql/run_acceptance.sh
```

The harness uses an acceptance-only Compose project, a localhost-bound
PostgreSQL 16 container with temporary storage, random per-run credentials, and
fixture writes restricted to the exact source and restored acceptance database
names. It always removes the container and network on exit. The default evidence
parent is `/tmp`; override only with
`CHINA_GRC_ACCEPTANCE_EVIDENCE_PARENT` pointing to an approved, existing,
non-symlink local parent outside the repository and not equal to the user-home
root. The harness always creates a new private child with `mktemp` and never
reuses an existing evidence directory. Never commit or upload the generated
database dump.

One verified local run on 2026-08-26 produced these bounded facts:

- PostgreSQL `16.11` completed a fresh full-project migration, Django checks,
  migration-drift check, and two empty-history `0004 -> 0003 -> 0004` cycles;
- 76 regulatory tests passed, including two real connection-blocking tests,
  concurrent exact-head review, and three existing-index usability probes;
- migrator, runtime, and backup roles were all non-superuser, without
  `CREATEDB`, `CREATEROLE`, replication, `BYPASSRLS`, or inherited membership;
- runtime DDL, regulatory delete/arbitrary update/truncate, migration writes,
  and audit deletion returned SQLSTATE `42501`; the allowed temporal-close
  column and a real synthetic domain-service mutation succeeded;
- populated review history refused reverse migration and remained present;
- the read-only role created a custom-format synthetic backup, restore completed
  in a single transaction, and restored regulatory/audit rows, migration leaf,
  constraints, indexes, sequences, and bounded grant components matched the
  exact pre-backup source state;
- PostgreSQL renders four CHECK expressions differently after dump/restore even
  though `ARRAY[varchar]::text[]` and `ARRAY[varchar::text]` are equivalent. The
  recorded normalisation profile handles only that cast representation; names,
  types, validation, deferral, foreign-key actions, and every other definition
  remain exact-match inputs;
- after equality, the restored runtime appended review successor sequence 2 and
  selected its committed state; and
- observed local backup/restore times were 3/4 seconds. These are run facts, not
  target RPO/RTO or performance commitments.

The manifest records the base commit, dirty state, tested backend/harness source
tree digest, PostgreSQL server version and image ID, and unresolved external
gates. `SHA256SUMS` uses portable relative paths and covers the private dump;
`SHAREABLE_SHA256SUMS` excludes the dump. The GitHub workflow executes this
complete harness for backend or harness changes and uploads only the synthetic
shareable evidence. A local pass does not assert that the hosted CI job ran.

The runtime grant file is a bounded reference profile, not a complete
least-privilege policy for every upstream CISO Assistant table. It deliberately
keeps broad upstream-compatible DML outside authority-bearing regulatory,
audit-log, and migration tables. Its column-level `recorded_to` compatibility
grant can also be retimed or reopened through direct SQL by a compromised
runtime identity; it does not enforce a one-way temporal transition. Production
must inventory all actual runtime queries, constrain that transition at the
database boundary if required, and split deployment, background-task, backup,
monitoring, retention, and audit-export identities before adopting it. Runtime
can append regulatory and audit rows, so this profile alone is not WORM or
protection against forged inserts by a compromised application identity.

## Evidence classes

Keep these claims separate in reports, dashboards, and release notes:

| Evidence class | What it may prove | What it cannot prove |
| --- | --- | --- |
| Django synthetic baseline | The bounded Django contract behaves as tested by the ordinary local suite, including its SQLite path | PostgreSQL-specific concurrency, production controls, law, privacy approval, or real-world applicability |
| Local PostgreSQL synthetic technical verification | The recorded harness revision satisfied migration, locking, current-index usability, synthetic restore, and bounded privilege probes | Representative-volume plans, deployment recovery, complete role integration, law, privacy approval, or real-world applicability |
| Target-environment database and operational acceptance | Named owners accepted representative plans, backup, recovery, access, monitoring, retention, and incident procedures for the exact target deployment | Legal interpretation, regulatory filing authority, or a compliance conclusion |
| Legal/privacy/security approval | Named humans approved the stated source, data, purpose, location, retention, and residual-risk scope | A broader entity, dataset, use case, environment, or later application/source version |

An automated test, AI output, unsigned checklist, or artifact digest cannot
promote evidence from one class to another.

## Owners and separation of duties

Record named people, not only teams or service identities, for these roles:

| Role | Accountable decision |
| --- | --- |
| Engineering owner | Application revision, test harness, expected transaction and migration behavior |
| DBA / database operations owner | PostgreSQL version, configuration, migration execution, query plans, backup, and restore evidence |
| Service operations owner | Capacity budget, availability target, RPO/RTO, monitoring, incident response, and rollback runbook |
| Security owner | Network boundary, credentials, database grants, privileged access, keys, tamper evidence, and security residual risk |
| Privacy or data-protection owner | Audit/export fields, purpose, minimisation, recipients, location, retention, and data-subject impact |
| Legal/compliance owner | Source rights and the explicit boundary between technical records and reviewed legal decisions |
| Records-management owner | Retention schedule, legal hold, expiry, disposal, and evidence of disposal |
| Independent assurance owner | Independent review without operating the first-line control or approving their own work |

The database migrator, application runtime, backup operator, audit consumer, and
human approver must not be collapsed into one permanently privileged identity.
Where the selected CISO Assistant edition or deployment cannot enforce this
directly, document the compensating control and its residual-risk owner rather
than marking the gate passed.

## Acceptance dossier

Create a private evidence package for each run. Record only non-sensitive
digests and outcomes in the public progress ledger after the material slice is
verified. The dossier contains:

- application commit and image or package digest;
- full Django migration plan and current `regulatory` migration leaf (currently
  `0004`, but the run must record the actual leaf rather than assume it);
- PostgreSQL product, major/minor version, deployment topology, relevant
  transaction/locking settings, and configuration digest;
- synthetic dataset generator version, size profile, and data classification;
- start/end time, test owner, operator, checker, and evidence locations;
- commands or automation version, exit status, sanitized output, and artifact
  digests;
- every failed, skipped, or unrun scenario and its owner;
- approved performance, lock-wait, RPO, RTO, retention, and rollback thresholds;
- residual risks, scope limitations, expiry/retest trigger, and final human
  dispositions.

Do not place passwords, connection strings, private hostnames, database dumps,
real institution facts, personal data, internal policy text, source text without
rights, or raw audit exports in this repository.

## 1. Environment and preflight

Use an isolated PostgreSQL database whose lifecycle and data class are approved
for acceptance testing. Configure Django through its supported PostgreSQL
settings (`POSTGRES_NAME`, `POSTGRES_USER`, `POSTGRES_PASSWORD`, `DB_HOST`, and
the optional `DB_PORT` and `POSTGRES_SSL_MODE`) without writing values to the
repository or command output.

Before mutation:

1. Resolve and record the exact database and application target without using a
   wildcard, implicit default, or production alias.
2. Prove that the dataset is synthetic and contains no customer, employee,
   transaction, internal-policy, credential, or unlicensed source content.
3. Record the approved backup/restore point and rollback owner.
4. Run Django system checks, migration-drift checks, and the migration plan.
5. Confirm that monitoring can observe lock waits, transaction failures,
   connection exhaustion, storage growth, backup failures, and audit-export
   failures without logging regulated payloads.
6. Stop if the target, data class, backup state, operator authority, or evidence
   destination is ambiguous.

Representative repository checks, run with environment-owned secret injection,
are:

```bash
backend/.venv/bin/python backend/manage.py check
backend/.venv/bin/python backend/manage.py makemigrations regulatory --check --dry-run
backend/.venv/bin/python backend/manage.py migrate --plan
backend/.venv/bin/pytest backend/regulatory/tests -q --create-db
```

Use a dedicated acceptance/test identity for commands that create a disposable
test database. Do not grant `CREATEDB` to the deployed application runtime merely
to run this suite; test that runtime identity separately under the grant matrix
in section 6.

These commands do not by themselves satisfy any gate below.

## 2. Migration acceptance

Test both a fresh full-project install and an upgrade from the immediately prior
accepted application state. The full project graph is required; a targeted app-
only blank-database attempt is not equivalent.

### Required scenarios

1. Apply the full project migration graph through the recorded regulatory leaf
   on a fresh disposable database.
2. Upgrade a representative prior schema through migrations `0001` to `0004`,
   preserving existing synthetic regulatory rows and migration history.
3. Verify the expected tables, indexes, constraints, custom permissions, foreign
   key protection, and absence of unintended data backfill.
4. On an empty disposable schema, reverse and reapply each supported empty-
   history boundary.
5. Populate correction, applicability-decision, and applicability-review history
   and prove that the intended reverse guards refuse to discard it.
6. After each refused reverse, verify that the migration remains applied and
   that rows, event order, identifiers, predecessor links, and digests are
   unchanged.
7. Inject an approved, controlled migration failure in the acceptance harness
   and prove there is no partially accepted schema or falsely advanced migration
   record.
8. Re-run the focused regulatory suite and migration-drift check against the
   final schema.

### Pass criteria

- Fresh apply and the supported upgrade complete without drift.
- Empty-history rollback/reapply behaves exactly as the migration contract
  states.
- Populated audit history cannot be silently dropped or rewritten.
- A failed migration has a documented, tested recovery path and does not result
  in a false success record.
- Schema evidence is checked against the Django migration state rather than a
  hand-written table inventory alone.

Passing this section does not authorise reversal of populated production
history. Retention or removal requires a separately reviewed forward archival
migration.

## 3. Concurrency and linearisation

The harness must use at least two genuinely independent PostgreSQL connections
or worker processes. Two cursors sharing one connection, a mocked lock, or a
serial test does not provide concurrency evidence.

### Required scenarios

- **Current detail read versus chain correction:** force overlap at the shared
  folder lock. The read must return one coherent pre-cutoff or post-cutoff chain,
  never mixed revisions.
- **Two chain corrections:** with the same expected head, at most one material
  successor commits; the other request must resolve as an exact idempotent retry
  or fail closed as stale/conflicting.
- **Two applicability recordings:** exercise exact retry, conflicting reuse of an
  idempotency key, stale revision/digest, and two entities registered to the same
  document.
- **Decision correction versus review disposition:** a disposition must bind the
  exact physical decision selected under the lock. A successor decision starts
  `not_reviewed` and cannot inherit the earlier disposition.
- **Obligation correction versus applicability/review read:** the old decision
  and review may appear only on the old obligation revision and historical time.
- **Wall-clock regression:** committed recorded/event times remain strictly
  ordered through the server-owned document aggregate floor.
- **Folder scope:** unrelated folders must not acquire a global regulatory lock;
  record observed blocking and throughput at the agreed representative volume.
- **Failure during transaction:** terminate or fail one controlled worker before
  commit and prove atomic rollback, retry classification, and absence of an
  orphan successor or event.

### Evidence and pass criteria

Record worker/connection identity, barrier points, transaction result, relevant
SQLSTATE, lock-wait duration, selected physical IDs, revisions, sequence,
cutoff/event times, and digests. Sanitize all scope and actor values.

Pass requires zero mixed-time chains, lost updates, duplicate successors,
orphan events, stale-review carry-over, cross-entity results, and unauthorized
writes. Lock waits and throughput must remain inside thresholds approved by the
operations owner; the repository does not invent those production thresholds.

## 4. Representative query plans

Run query-plan acceptance on an isolated environment or approved replica with a
representative data distribution. A handful of synthetic rows can validate
correctness but cannot establish a capacity or latency claim.

Capture `EXPLAIN (ANALYZE, BUFFERS)` for at least:

- regulatory document list and filtered list;
- current document detail and joined citation chain;
- historical `recorded_as_of` detail near and far from a correction cutoff;
- current and historical entity-scoped applicability;
- current and historical applicability-review selection; and
- correction/review head lookup and document recorded-time floor selection used
  inside locked writes.

For each plan, record the dataset profile, parameter shape, cold/warm-cache
condition, returned rows, planning/execution time, buffers, lock observations,
and a sanitized plan digest. Do not publish SQL literals that disclose entity,
user, rationale, evidence, or private source information.

The DBA and service owner set the latency, concurrency, and resource budgets
before the run. Pass requires plans to stay within those budgets and to avoid an
unbounded scan, sort, row explosion, or lock scope at representative growth.
A sequential scan is not automatically a failure on a small relation; acceptance
is based on measured cardinality and the approved budget, not a brittle textual
plan match. Preserve the baseline so a later schema, PostgreSQL, or query-shape
change triggers comparison and retest.

## 5. Backup, restore, and recovery

Use deployment-standard encrypted backup tooling and a separate empty restore
target. A successful backup command without a completed restore and application-
level verification is not acceptance.

### Required scenarios

1. Create a synthetic dataset containing current and historical document chains,
   correction events, applicability revisions, each review disposition, and at
   least two Folder/Entity scopes.
2. Take a full backup and, if the target design uses it, exercise the approved
   point-in-time recovery path.
3. Restore to an isolated target with separate credentials and network scope.
4. Verify migration state, schema constraints, row counts by governed scope,
   source/semantic/event digests, predecessor sequences, and protected
   relationships.
5. Replay representative current and historical API/service reads at exact
   cutoff boundaries and compare canonical sanitized results with the source
   environment.
6. Append a new authorised synthetic event after restore to prove that the
   restored database is operational and its recorded-time floor remains valid.
7. Exercise backup corruption or unavailability detection, alerting,
   escalation, and the documented fallback path.
8. Record observed recovery point and recovery time against the values approved
   by the service owner.

Backup encryption, key custody, storage location, replica/export recipients,
retention, legal hold, and deletion evidence require named security, privacy,
and records-management decisions. A technically recoverable copy may still be
unlawful or outside the approved secrecy or cross-border boundary.

## 6. Least-privilege database roles

Document and test a grant matrix for, at minimum:

- schema owner/migrator, enabled only through the controlled deployment path;
- application runtime;
- backup/restore operator;
- monitoring identity with metadata-only access where possible; and
- audit/export producer and consumer, preferably through a scoped export rather
  than unrestricted database reads.

The runtime identity must not be a superuser and must not have `BYPASSRLS`,
`CREATEDB`, `CREATEROLE`, schema ownership, migration DDL, trigger-disable,
truncate, or grant authority. Test the actual deployed identity, not only the
intended SQL manifest. Confirm that sanctioned domain-service operations work
and that unsupported raw update/delete, bulk mutation, history removal, and
permission escalation fail or produce the approved independent tamper alert.

The current application-level Folder/Entity IAM remains authoritative for user
access. Database grants do not replace it. Conversely, a broadly privileged
database or backup identity can bypass application IAM, so it must be separately
controlled, monitored, time-bound where practical, and excluded from ordinary
user/API execution.

If the community deployment cannot deny all privileged direct writes while
supporting the upstream application, acceptance requires a documented
compensating design such as restricted administrative access plus an external
tamper-evident audit stream. “The ORM normally prevents it” is not a production
control.

## 7. Audit retention and export privacy

The current append-only service/model path and database constraints are not
WORM protection. A privileged SQL identity remains a separate threat and must
be addressed by database privileges, database-side controls, or an independent
tamper-evident export selected for the deployment.

### Integrity requirements

- retain event identity, predecessor/sequence, source and semantic digests,
  actor/reviewer references, server time, reason code, rationale, permission and
  execution outcome needed to reconstruct the governed event;
- bind export batches to an integrity digest and protected timestamp/signature
  or equivalent independently verifiable mechanism;
- monitor missing, reordered, duplicate, altered, late, and failed export
  records;
- separate audit administration from the actors whose activity is recorded;
- restore and periodically verify the audit evidence, not only the application
  tables; and
- document retention, legal hold, expiry, deletion, and cryptographic-key
  consequences without rewriting signed history.

### Privacy and secrecy requirements

Review the export field by field. Reviewer identity and free-text rationale may
be personal or sensitive operational data. Folder/entity scope, evidence
references, source excerpts, hostnames, and incident context may disclose
regulated, confidential, or institution-specific information.

The approved export contract must state:

- purpose and lawful/internal authority;
- minimum fields and whether a stable pseudonymous identifier is sufficient;
- who may produce, receive, search, re-export, and approve access;
- storage and processing location, including any cross-border transfer;
- encryption, key owner, retention, legal hold, deletion, and access-review
  cadence;
- whether free-text rationale must be redacted, tokenized, or retained in a more
  restricted tier; and
- incident response for misdelivery, over-collection, tampering, or export
  failure.

Do not export email addresses merely because a related User exists; the current
read contract deliberately omits email and masks reviewer identity without
separate User access. Do not export credentials, hidden chain-of-thought, raw
prompts, unnecessary regulated data, private chat content, or source text whose
storage rights are unresolved.

### Pass criteria

- The integrity mechanism detects the approved mutation, omission, reordering,
  replay, and export-failure test cases.
- Access and export attempts are themselves audited.
- The privacy/security/records owners approve a versioned field schema,
  retention schedule, recipients, location, and residual risk.
- Restore verification proves that application history and independent audit
  evidence remain reconcilable.

A technical integrity pass is not legal approval of retention or export.

## Human gates outside technical acceptance

The following remain blocked until a named authorised human records the decision
and evidence. Code, tests, documentation, or an AI-generated recommendation
cannot satisfy them:

1. **Production operations:** target topology, capacity, availability, RPO/RTO,
   maintenance window, monitoring, on-call, incident, rollback, and recovery
   acceptance.
2. **Security:** network and trust zones, credential lifecycle, database and
   backup privileges, keys, vulnerability management, tamper evidence, and
   residual security risk.
3. **Privacy, secrecy, and data location:** test and production data classes,
   purpose, minimisation, model/tool destinations, audit/export recipients,
   retention, deletion, and cross-border treatment.
4. **Legal/content rights:** authority and rights to retain or display source
   bytes, standards, internal policies, evidence, and rationale.
5. **Regulatory/legal review:** document status, supersession, provision,
   obligation, applicability, and any binding conclusion for a real entity.
6. **Independent assurance:** separation of first-line operation, second-line
   challenge, and third-line audit identity and approval paths.
7. **Release and residual risk:** explicit scope, unresolved failures, expiry,
   rollback triggers, and the decision whether this evidence supports only a
   pilot, a production candidate, or no promotion.

Until those gates pass, use synthetic data only and keep the existing result
descriptions `draft`, `non-binding`, `unpublished`, and `needs_review` where
authority or facts are absent.

## Acceptance record

Use this minimum decision record in the private acceptance dossier:

```text
acceptance_id:
application_commit_and_digest:
postgresql_version_and_configuration_digest:
environment_and_data_classification:
migration_leaf_and_plan_digest:
synthetic_dataset_profile:
migration_result: pass | fail | not_run
concurrency_result: pass | fail | not_run
query_plan_result: pass | fail | not_run
backup_restore_result: pass | fail | not_run
least_privilege_result: pass | fail | not_run
audit_integrity_result: pass | fail | not_run
audit_export_privacy_result: approved | rejected | pending
legal_and_source_rights_result: approved | rejected | pending | out_of_scope
real_pilot_result: approved | rejected | pending | out_of_scope
failed_or_unrun_gates:
residual_risks_and_owner:
rollback_or_recovery_evidence:
engineering_owner_and_time:
dba_operations_owner_and_time:
security_owner_and_time:
privacy_records_owner_and_time:
legal_compliance_owner_and_time:
independent_assurance_owner_and_time:
decision_scope_and_expiry:
```

No field may be inferred as `pass` from another field. `pending`, `not_run`, and
`out_of_scope` remain explicit and cannot be presented as successful acceptance.

## Stop and rollback conditions

Stop the run and preserve sanitized failure evidence when:

- the resolved target may contain user or production data;
- backup/restore authority or the isolated recovery target is unavailable;
- a migration partially applies, a populated reverse succeeds unexpectedly, or
  history/digests differ after failure or restore;
- concurrent operations produce a mixed revision, lost update, duplicate,
  orphan, stale-review carry-over, or unexplained lock scope;
- a query exceeds its approved budget or cannot be measured safely;
- the runtime role has unexplained privileged authority;
- audit integrity does not detect the injected failure; or
- export fields, recipients, location, retention, or evidence storage lack the
  required privacy/security/records approval.

Recover only through the pre-approved staging/acceptance rollback or restore
runbook. Do not delete or rewrite regulatory or audit history to make a failed
run pass. Retest at a new acceptance ID after remediation.

## Completion statement

The strongest permitted statement after every technical and operational item in
this document passes is:

> The bounded synthetic Phase 1 regulatory database contract passed the recorded
> PostgreSQL and operational acceptance scope for the named application revision
> and environment. This evidence is not legal review, a compliance conclusion,
> approval for real institution data, customer acceptance, or unrestricted
> production readiness.

Phase promotion and any broader claim require the authoritative progress/roadmap
process, named human owners, and the separate gates above.
