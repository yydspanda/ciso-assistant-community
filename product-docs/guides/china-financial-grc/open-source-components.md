---
description: Adopt, assess, and defer decisions for open-source components around CISO Assistant.
---

# Open-source component decisions

> **Decision record:** Review code licence and content licence separately. A
> repository, loader, or integration does not grant rights to regulatory or
> standards content.

| Component | Decision | Boundary |
| --- | --- | --- |
| CISO Assistant | Adopt | GRC system of record, IAM, controls, assessments, evidence, findings, UI |
| OSCAL and Compliance Trestle | Adopt concepts; assess tooling | portable control/assessment/remediation exchange, not legal applicability |
| Docling | Assess early | page/layout/table extraction with source anchors |
| PostgreSQL temporal fields | Adopt first | valid-time and recorded-time regulatory records |
| XTDB | Defer | reconsider only when bitemporal query scale justifies another database |
| Existing chat workflows and proposal pattern | Adopt | bounded analysis; avoid an additional agent framework initially |
| Existing validation flows and tasks | Adopt first | simple review; assess gaps before adding Flowable or Temporal |
| OPA | Assess for write phase | tool-action `allow/deny/escalate`, not legal interpretation |
| Existing CISO Assistant IAM | Adopt | avoid adding a second authorisation master initially |
| OpenMetadata, Fides, Presidio | Assess integration | data/privacy fact and workflow providers |
| Prowler and ComplianceAsCode | Assess integration | deterministic technical evidence providers |
| Promptfoo | Adopt for CI | prompt, RAG, and agent regression |
| Inspect AI, PyRIT, garak | Assess/adopt before write phase | independent evaluation and red team |
| OpenTelemetry | Adopt | neutral trace/metric/log export with redaction |

Probo, Openlane, and similar platforms remain product references rather than
additional systems of record. GRCX and vendor agent samples are design examples,
not banking-production foundations.

CISO Assistant code outside `enterprise/` is AGPLv3; the `enterprise/`
directory has a commercial licence. Review network-use, modification, and
distribution obligations before offering a closed commercial service.
