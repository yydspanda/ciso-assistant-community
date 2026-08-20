---
description: Proposed blueprint for extending CISO Assistant into a governed China financial GRC platform.
---

# China financial GRC blueprint

> **Blueprint status:** This section documents a fork-specific target design.
> It does not imply that every described capability is shipped. AI output is a
> proposal; official sources and accountable legal, compliance, risk, audit,
> privacy, security, finance, and business owners remain authoritative.

This blueprint covers external and internal regulation, banking, insurance,
financial technology, privacy, data security, cybersecurity, AI/model risk,
governance, audit, remediation, and cost control.

The design extends CISO Assistant as a governed system of record rather than
building an autonomous super-agent.

The starter assessment selects `COMMON` by default. Industry groups are added
explicitly, and their selection remains a profile filter rather than a legal
applicability conclusion.

## Delivery status

| Capability | Status | Notes |
| --- | --- | --- |
| Frameworks, controls, assessments, evidence, findings, tasks | Upstream capability | Reuse the existing [concepts](../../concepts/frameworks.md) |
| Folder-scoped IAM and validation flows | Upstream capability | Continue to enforce server-side IAM; UI filtering is not authorisation |
| Embedded AI proposals | Upstream capability | Preserve the existing proposals-not-actions boundary |
| China financial common controls and baseline | Added in this fork | High-level original control summaries; not legal text or a compliance opinion |
| Regulatory JSON Schemas and official-source registers | Added in this fork | Explicitly draft contract; 76 metadata records across four packs remain legally unreviewed |
| Controlled applicability-fact registry | Added in this fork | 56 fact definitions; unknown values route to review rather than non-applicability |
| Temporal regulatory Django models and APIs | Proposed | Required before regulations become authoritative application records |
| Reviewed regulatory-to-library projection | Proposed | Projects approved obligations into frameworks and requirements |
| Deterministic applicability and action policy | Proposed | Unknown facts must route to review |
| Continuous evidence and privacy/data integrations | Proposed external integration | Evidence providers must not become competing GRC masters |

## Blueprint pages

- [Regulatory scope](regulatory-scope.md)
- [Regulatory source packs](regulatory-source-packs.md)
- [Reference architecture](reference-architecture.md)
- [Domain model](domain-model.md)
- [Agent governance and boundaries](agent-governance.md)
- [Open-source component decisions](open-source-components.md)
- [Delivery roadmap](roadmap.md)

## Existing CISO Assistant concepts reused

- [Frameworks](../../concepts/frameworks.md) and
  [mappings](../../concepts/mappings.md)
- [Applied controls](../../concepts/applied-controls.md)
- [Audits](../../concepts/audits.md),
  [evidence](../../concepts/evidence.md), and
  [findings assessments](../../concepts/findings-assessments.md)
- [Tasks](../../concepts/tasks.md) and
  [validation flows](../../concepts/validation-flows.md)
- [Privacy register](../../concepts/privacy-register.md)
- [IAM and scoping](../../concepts/iam-and-scoping.md)
- [MCP integration](../../integrations/mcp.md)
- [Audit log](../../features/audit-log.md), subject to edition and retention
  design

## Non-goals

- copying unlicensed legal or standards text into the repository;
- treating a loaded library or completed checklist as proof of compliance;
- letting an LLM calculate binding thresholds, approve itself, submit to a
  regulator, decide customer rights, alter IAM, or erase audit history;
- exposing internal policies, prompts, workflow exports, or customer data in
  this public fork.
