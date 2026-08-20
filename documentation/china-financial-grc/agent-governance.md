# Agent governance and execution boundaries

## Baseline

The existing embedded-chat rule — **proposals, not actions** — is the minimum
control baseline for this extension. AI may prepare a change, but a permissioned
and accountable workflow decides whether that change is executed.

## Action classes

| Class | Examples | Default treatment |
| --- | --- | --- |
| Green: read and draft | search approved sources, summarise with citations, compare clauses, calculate via an approved tool, draft an assessment | may run automatically within authorised scope; log sources and versions |
| Amber: proposed state change | propose an obligation, mapping, owner, task, evidence metadata, finding, internal-policy edit, or report | show a structured diff; require confirmation and, where configured, maker-checker approval |
| Red: consequential or reserved | declare legal compliance, accept risk, approve own output, delete source history, change IAM, stop production, submit to a regulator, decide customer rights, approve payment | agent execution prohibited; route to named human authority and a controlled integration |

The classification is based on impact, data sensitivity, customer effect,
reversibility, and legal authority, not on the name of the tool.

## Deterministic versus model responsibilities

### Model-assisted

- identify candidate documents and provisions;
- extract proposed obligation components;
- compare external rules and internal policy;
- suggest controls, evidence, tests, and remediation;
- explain findings using approved citations;
- draft notices, reports, minutes, and board materials;
- classify uncertain content for human review.

### Deterministic

- date and statutory-deadline arithmetic;
- monetary, population, materiality, and reporting thresholds;
- risk formulas and rating tables;
- identity, access, tenant/folder, and data-classification enforcement;
- workflow transition and approval routing;
- duplicate/idempotency checks;
- signature/hash verification and retention locks;
- allow/deny/escalate policy decisions.

The application re-computes every formula. A JSON value produced by a model is
untrusted input until schema validation and deterministic computation pass.

## Required proposal envelope

Every amber proposal includes:

```json
{
  "proposal_id": "uuid",
  "case_id": "uuid",
  "actor_id": "human-or-workload-id",
  "agent_version": "name@version",
  "prompt_version": "immutable-id",
  "schema_version": "2.0.0-draft.1",
  "action": "create_obligation",
  "scope": {"domain_id": "uuid", "legal_entity_id": "uuid"},
  "source_refs": ["document-version/provision"],
  "payload": {},
  "payload_sha256": "hex",
  "confidence": 0.0,
  "uncertainties": [],
  "idempotency_key": "opaque-key",
  "expires_at": "RFC3339 timestamp"
}
```

The UI displays a field-level diff and citations. Confirmation signs the exact
payload digest; changing the proposal invalidates the approval.

The draft interchange profile
`cn-financial-grc-canonical-json-v1` binds an approval to an envelope containing
the profile, schema version, subject type, subject ID, and subject payload. It
uses UTF-8 JSON with lexicographically sorted object keys, no insignificant
whitespace, unescaped Unicode, preserved array order, and rejection of
NaN/Infinity. Approval-derived status, reviewer, confirmation, and close-time
fields are excluded so that applying an approval does not invalidate its own
digest; all substantive, provenance, fact, source, and valid-time fields remain
bound. Any cross-language implementation must pass shared conformance vectors;
a later canonicalisation change must mint a new profile rather than silently
changing this one.

## Approval rules

- The initiating agent is never an approver.
- A service account cannot stand in for a named legal, compliance, risk, audit,
  privacy, security, finance, or business decision owner.
- Maker and checker are different identities for high-risk actions.
- Approval records include role, scope, reason, conditions, and expiry.
- Binding decisions require a named human checker, a recomputed payload digest,
  and an active prerequisite chain from reviewed source version and provision
  through obligation, applicability rule/decision, or control mapping.
- A stale proposal or changed source version requires re-review.
- Emergency access is time-bound, independently approved, and reviewed after
  use.

## Tool and MCP controls

- Default to a read-only allowlist.
- Resolve user and workload identity on every request; do not share API keys.
- Apply CISO Assistant RBAC before retrieval and again before mutation.
- Constrain tool arguments with JSON Schema and server-side validation.
- Require action-policy decisions, case/approval IDs, and idempotency keys for
  writes.
- Separate read and write credentials; issue short-lived credentials only after
  approval.
- Restrict outbound network destinations and block link-local/cloud metadata
  endpoints.
- Treat tool output, source documents, web pages, and retrieved text as data,
  never system instructions.
- Keep environment-token shortcuts disabled in production. `stdio` transport is
  not itself a security or read-only boundary.

## Data and prompt controls

- Classify prompts, retrieved chunks, tool arguments, and outputs.
- Minimise and redact personal, transaction, secret, and restricted data.
- Prohibit training on organisational data unless separately approved.
- Pin approved model/provider/deployment combinations per data class.
- Record retention and deletion policy for trace data.
- Keep regulatory sources in a separately trusted retrieval partition.
- Prevent a retrieved document from altering system policy or tool scope.

## Logging and evidence

Record:

- case, user/workload identity, tenant/domain/folder, and legal entity;
- source/version/provision citations and hashes;
- model, prompt, schema, retrieval, tool, and policy versions;
- structured input/output digests and validation results;
- rule hits, authorisation decision, approval, execution, and rollback;
- latency, tokens, model/tool cost, errors, and outcome quality;
- resulting CISO Assistant object IDs and evidence revisions.

Do not record hidden chain-of-thought, raw credentials, or unnecessary regulated
data. Community and commercial editions have different audit/service-account
capabilities; production design must explicitly choose an edition or implement
an equivalent external, long-retention, tamper-evident audit path.

## Evaluation gates

Before release, evaluate at least:

- citation correctness and source-version accuracy;
- obligation extraction precision/recall by domain;
- false `not_applicable` rate, with special focus on missing facts;
- mapping accuracy and human override rate;
- threshold, deadline, and score determinism;
- cross-tenant/folder/entity data isolation;
- prompt injection and poisoned-source resistance;
- tool-policy bypass, approval replay, and confused-deputy attacks;
- rollback, retry, duplicate write, and partial-failure behaviour;
- Chinese financial terminology and OCR/table robustness;
- latency and cost per accepted outcome, not merely per model call.

Production promotion requires named owners, minimum thresholds, a regression
dataset, red-team results, rollback criteria, and documented residual risk.
