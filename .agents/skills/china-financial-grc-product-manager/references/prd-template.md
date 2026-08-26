# China Financial GRC PRD Template

Use this only for an implementation-ready product slice. Keep statements about
law, applicability, and current implementation tied to evidence.

## Decision summary

- Verdict:
- Roadmap phase:
- Accountable product owner:
- Accountable legal/compliance reviewer:

## Verified current state

Separate repository-verified implementation, target design, illustrative data,
and external blockers. Cite the files, tests, or acceptance evidence supporting
each material claim.

## Problem and outcome

Describe the current workflow, its frequency, delay, rework, error cost, and the
observable outcome to improve.

## Users and authority

- Primary user:
- Secondary users:
- Human decision owner:
- People affected by an incorrect result:
- Decisions explicitly reserved to humans:

## Current workflow

1. Trigger:
2. Source and facts collected:
3. Review and decision:
4. Downstream action:
5. Evidence retained:
6. Pain or failure point:

## Proposed vertical slice

Describe the smallest end-to-end workflow and where it fits in existing CISO
Assistant surfaces. Distinguish deterministic, model-assisted, and human steps.

## MVP scope

- Must have:
- May have:
- Deferred:

## Non-goals

List attractive capabilities, domains, autonomous actions, integrations, and
legal conclusions deliberately excluded from this release.

## Applicability and source scope

- Legal entities, licences, jurisdictions, products, and customers:
- Data and system scope:
- Official sources and versions:
- Required applicability facts:
- Unknown-fact behavior:
- Legal-review status required for release:

## User stories

```text
As a <GRC role>,
I want <reviewable capability>,
so that <measurable governed outcome>.
```

## Acceptance criteria

```text
Given <authorised scope and initial state>,
When <event or action>,
Then <observable result, citation, audit record, and workflow state>.
```

Include:

- correct and incorrect source versions;
- unknown applicability facts;
- future-effective and superseded material;
- permission denial and cross-entity isolation;
- self-approval, stale approval, and changed-payload rejection;
- duplicate, retry, rollback, and partial-failure behavior;
- unavailable model or connector degradation.

## Data, contracts, and interfaces

- Inputs and classification:
- Outputs and confidence/uncertainty:
- Models, schemas, and versions:
- APIs, UI, jobs, or library bridge:
- Source and evidence retention:
- Audit and telemetry:

## Metrics and release gates

| Metric | Baseline | Target | Sample | Data source | Gate owner |
| --- | --- | --- | --- | --- | --- |
| Accepted outcome time | | | | | |
| Citation/version correctness | | | | | |
| Quality or override rate | | | | | |
| Safety/isolation failures | | | | | |
| Cost per accepted outcome | | | | | |

## Risks and mitigations

| Risk | Impact | Mitigation | Residual-risk owner |
| --- | --- | --- | --- |
| Missed or mis-scoped obligation | | | |
| False compliance conclusion | | | |
| Stale or poisoned source | | | |
| Privacy, secrecy, or cross-border breach | | | |
| Approval or authority bypass | | | |
| Audit-independence failure | | | |
| Operational or model failure | | | |

## Rollout and rollback

- Feature flag or pilot scope:
- Synthetic versus reviewed data boundary:
- Human review gate:
- Rollback trigger and procedure:
- Evidence required before phase promotion:

## Dependencies and open decisions

Name external data rights, reviewers, edition capabilities, integrations,
migrations, and unresolved choices that can block the slice.
