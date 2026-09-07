---
description: Integrate CISO Assistant with third-party providers
---

# Third-party integrations

## Durable synchronization and operator review

Third-party writes are persisted as durable jobs in the same database
transaction as the local change. The background queue carries only a job ID;
the worker revalidates the configuration, provider, folder, mapping, local
object, and signed payload before an effect. Provider network calls run without
database row locks. Webhook events are accepted only from each provider's
explicit event allowlist and are applied through the local model validation
boundary. A durable job authorizes at most one provider mutation; Jira field
updates and workflow transitions are therefore recorded as separate FIFO jobs,
and the authority-bearing Jira client disables SDK retries for writes. When a
checker chooses **keep local**, every Jira corrective job is created atomically,
carries the same immutable reconciliation-decision ID, and records its signed
FIFO sequence and group size. If any member cannot be persisted, neither the
decision nor a partial corrective group is committed.

If a process loses contact after a provider call starts, CISO Assistant does
not retry blindly. It records the job as uncertain and requires a separately
authorized, named human checker to attest either that the exact operation was
applied or that it was not applied, using referenced provider evidence. This is
a checker attestation recorded and signed by CISO Assistant; it is not a
provider-signed receipt unless the provider evidence itself offers that proof.
Retrying the same operation is allowed only when that provider explicitly
guarantees the bound idempotency key. Manual incoming conflicts likewise
require a checker to accept the validated remote proposal or keep the current
local value. These decisions record the distinct maker/checker, reason, state
digests, evidence digest, and timestamp; they do not make an autonomous
compliance or legal decision.

Accepted remote versions are monotonic. A checker cannot confirm an applied
snapshot older than the mapping's accepted provider version, and an accepted
remote deletion leaves only a minimal identity/version tombstone so that a
delayed pre-deletion webhook cannot restore stale state. During upgrades,
legacy `last_synced_at` values are trusted only when a successful, coherent
`SyncEvent` proves the same mapping/configuration/object graph. Otherwise the
watermark becomes unknown and the next changed remote state is routed to human
review instead of silently overwriting local data.

Self-hosted deployments should configure an independently rotatable signing
key ring:

```text
INTEGRATION_SIGNING_KEYS_JSON={"2026-q3":"replace-with-at-least-32-secret-characters"}
INTEGRATION_SIGNING_PRIMARY_KEY_ID=2026-q3
```

To rotate a key, deploy the new key alongside the old key and select the new
primary ID. Keep every retired key available for verification for the complete
audit-retention period of every job, attempt, receipt attestation, and decision
that references it, or until those records and their verification material have
been transferred to an approved tamper-evident archive. A terminal job alone is
not permission to delete its verification key. Before removing a key, inventory
all persisted signing-key references and prove that none remains dependent on
it. Removing an execution key early sends affected queued work to review; it can
also make historical evidence unverifiable. Never commit key values to the
repository.
