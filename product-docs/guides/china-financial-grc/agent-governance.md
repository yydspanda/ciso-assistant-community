---
description: Proposed AI action classes, proposal controls, approvals, and evaluation gates.
---

# Agent governance and boundaries

> **Control baseline:** Preserve the embedded assistant's
> **proposals, not actions** design and server-side RBAC.

## Action classes

| Class | Examples | Treatment |
| --- | --- | --- |
| Green | authorised search, cited summary, comparison, statistics, draft | automatic within scope, with provenance |
| Amber | proposed obligation, mapping, owner, task, evidence metadata, finding, or policy edit | structured diff plus confirmation and configured approval |
| Red | declare compliance, accept risk, approve own output, delete source history, change IAM, stop production, submit to a regulator, decide customer rights, approve payment | agent execution prohibited |

## Non-model controls

Use code or approved decision tables for:

- statutory and workflow deadlines;
- monetary, population, materiality, and reporting thresholds;
- scoring and grade mappings;
- identity, IAM, data classification, and tool policy;
- workflow transitions, approval routes, idempotency, and signatures.

Model values are untrusted until schema validation and deterministic
recalculation pass.

## Proposal and approval

An amber proposal contains case, identity, agent/prompt/schema versions, exact
scope, source references, payload, payload hash, confidence, uncertainties,
idempotency key, and expiry. Approval binds the payload hash; changing the
proposal invalidates approval.

The initiating agent cannot be an approver. High-risk actions require different
maker and checker identities. An agent or service account cannot replace a
named accountable decision owner.

The draft repository validator also recomputes a canonical subject-payload
digest, requires a named human checker, rejects maker/checker identity reuse,
and checks the active approval chain from reviewed source and provision to the
dependent obligation, rule, applicability decision, or control mapping.

## Tool and MCP controls

- default to read-only tools;
- apply IAM on every read and write;
- validate arguments server-side;
- use separate, short-lived write credentials after approval;
- restrict outbound destinations and metadata endpoints;
- keep environment-token shortcuts disabled in production;
- remember that `stdio` is not automatically safe or read-only.

## Evaluation gates

Test citation/version accuracy, extraction and mapping accuracy, false
`not_applicable` results, deterministic calculations, cross-scope isolation,
prompt injection, poisoned sources, tool-policy bypass, approval replay,
duplicate writes, rollback, Chinese OCR/terminology, latency, and cost per
accepted outcome.
