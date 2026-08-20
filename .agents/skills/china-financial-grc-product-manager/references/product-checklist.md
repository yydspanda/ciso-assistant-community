# China Financial GRC Product Checklist

Use this when reviewing whether a proposed capability is valuable and safe
enough for its roadmap phase.

## User and workflow

- Who performs the work today, and who signs the final decision?
- What trigger starts the workflow and how often does it occur?
- Which manual reconciliation, delay, or rework should disappear?
- What evidence and context exist outside CISO Assistant?
- What happens to a customer, employee, business owner, auditor, or regulator if
  the result is wrong?

## Regulatory and entity scope

- Is the requirement external law/regulation, a standard, an interpretation, an
  enforcement signal, or organisation-defined policy?
- Which legal entity, licence, jurisdiction, product, customer, data class,
  system, and time period determine applicability?
- Are official source/version/provision anchors available?
- Does the workflow make unknown and future-effective states visible?
- Who is authorised to complete legal or compliance review?

## Product value

- Does it shorten intake-to-decision time, improve correctness, reduce repeated
  mapping, improve evidence, or accelerate remediation?
- Is the benefit repeatable across cases or only a one-off demonstration?
- Can value be measured from governed records rather than anecdote?
- Can one narrow vertical slice prove value before more domains are added?

## Authority and safety

- Can any model, prompt, document, tool, integration, or user input bypass IAM,
  deterministic policy, approval, or audit?
- Are maker, checker, legal reviewer, control owner, and auditor roles separated?
- Are customer rights, regulatory filings, risk acceptance, audit opinions,
  production changes, and payments reserved to humans?
- Is every material conclusion traceable to reviewed evidence and a version?
- Can the effect be expired, revoked, rolled back, and independently reviewed?

## Data protection and trust

- What personal, sensitive, secret, transaction, model, or internal-policy data
  enters prompts, tools, logs, vector stores, and external services?
- Are data minimisation, retention, tenant/folder/entity isolation, and outbound
  destinations explicit?
- Are official, internal, observed, inferred, model, and human claims kept
  distinct?
- Are content rights and licences known?

## MVP boundary

- Can read-only search or a proposal/diff create value before direct writes?
- Can existing CISO Assistant controls, assessments, evidence, findings, IAM,
  and workflows own the result?
- What is the smallest reviewed source set and pilot entity profile?
- Which UI, connector, domain pack, automation, or dashboard can wait?
- Does the MVP have deterministic behavior when the model is unavailable?

## Metrics

- Intake-to-reviewed-decision time.
- Citation and source-version correctness.
- Extraction or mapping precision/recall on a reviewed set.
- False `not_applicable` and unresolved `needs_review` rates.
- Human acceptance, correction, and override rates.
- Evidence completeness/freshness and remediation cycle time.
- Permission, isolation, approval-bypass, and audit-integrity failures.
- Cost and latency per accepted outcome.

## Red flags

- “Cover all regulations” without a pilot entity or reviewed source set.
- A dashboard with no named decision or owner.
- Autonomous legal conclusions or writes before review and rollback exist.
- Treating a recommendation standard, source catalog, or model answer as law.
- Solving deterministic dates, thresholds, or scores with prompting.
- Building a second IAM, workflow, evidence, audit, or GRC database.
- Declaring production readiness from synthetic fixtures or metadata-only
  catalogs.
