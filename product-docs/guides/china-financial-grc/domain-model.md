---
description: Proposed regulatory entities and their projection into existing CISO Assistant objects.
---

# Domain model

> **Proposed extension:** `Framework` and `RequirementNode` remain assessment
> projections. They are not the authoritative representation of regulations.

## Proposed regulatory entities

```text
RegulatoryDocument
  └─ RegulatoryDocumentVersion
       └─ Provision
            └─ Obligation
                 ├─ ApplicabilityRule
                 ├─ ApplicabilityDecision
                 └─ ControlMapping
```

- `RegulatoryDocument` provides stable identity, issuer, authority, territory,
  and official identifier.
- `RegulatoryDocumentVersion` stores append-only source revisions, separate
  issue/publication/effective dates, metadata confidence, legal-review state,
  source URL, hashes where permitted, and supersession.
- `Provision` stores source-faithful article/paragraph/table anchors, page or
  bounding-box location, and text hash.
- `Obligation` stores reviewed subject, modality, action, object, conditions,
  exceptions, deadline, consequence, evidence expectation, and provenance.
- `ApplicabilityRule` is deterministic and versioned; each material revision
  has a new record ID and an explicit predecessor.
- `ApplicabilityDecision` stores facts, rule version, result, rationale,
  evidence, and accountable confirmation.
- Applicability evaluation uses three-value logic: false can short-circuit AND,
  true can short-circuit OR, and an unresolved outcome becomes `needs_review`.
  Known facts must match the controlled type and carry evidence and time.
- `ControlMapping` links a reviewed obligation to a reusable control with
  coverage, rationale, owner, reviewer, test, and evidence expectations.

## Existing-object projection

| Regulatory concept | CISO Assistant projection |
| --- | --- |
| reviewed obligation set/version | `Framework` |
| heading or source structure | non-assessable `RequirementNode` |
| approved atomic obligation | assessable `RequirementNode` |
| reusable safeguard | `ReferenceControl` |
| organisational implementation | `AppliedControl` and policy objects |
| implementation assessment | `ComplianceAssessment` and `RequirementAssessment` |
| proof | `Evidence` and `EvidenceRevision` |
| gap | `Finding` and remediation tasks |
| reviewed relationship | `RequirementMappingSet` plus regulatory mapping record |

Every projection retains the external regulatory ID. Re-running projection is
idempotent, and a new legal version must not mutate a historical assessment.

## Required provenance

Keep source/version/provision, locator, content hash, parser, model, prompt,
retrieval configuration, schema, time, initiating identity, confidence,
validation, reviewer, and decision. Store structured reasons and citations,
not private model chain-of-thought.
