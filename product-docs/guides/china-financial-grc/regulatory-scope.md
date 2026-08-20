---
description: Proposed authority, applicability, and domain boundaries for the China financial GRC blueprint.
---

# Regulatory scope

> **Proposed design:** The 76-record common, banking, insurance, and
> fintech/data/AI source packs were metadata-checked as of 2026-08-20 and are
> intentionally non-exhaustive. Their legal-review state is `unreviewed`;
> unresolved metadata remains explicit. Applicability must be confirmed for
> each legal entity, licence, product, process, data flow, system, and AI use
> case.

## Authority levels

Keep these source classes separate:

1. laws;
2. State Council administrative regulations;
3. departmental rules;
4. regulatory normative documents, which must not be automatically treated as
   departmental rules;
5. mandatory and recommended standards;
6. internal policies and procedures;
7. interpretive and enforcement material.

Draft, future-effective, effective, active-without-an-explicit-commencement,
superseded, repealed, and unknown versions have different operational effects.
A future rule can create a readiness task but cannot create a current
non-compliance finding; an absent commencement clause must not be replaced with
a guessed date.

## Initial domains

- banking, insurance, payments, and financial technology;
- governance, compliance management, the three lines of defence, internal
  control, and audit;
- AML/KYC, beneficial ownership, sanctions, and transaction monitoring;
- products, suitability, marketing, disclosure, and customer rights;
- privacy, data classification, important data, and cross-border transfers;
- cybersecurity, MLPS, critical infrastructure, cryptography, incidents,
  outsourcing, and operational resilience;
- models, algorithms, generative AI, and agent governance;
- budget, procurement, expenses, contracts, cloud/model cost, and accounting
  evidence.

## Applicability facts

The system must capture, not guess:

- legal entity, territory, licence, regulator, ownership, and listing status;
- product, channel, customer, transaction, and decision impact;
- data category, sensitivity, volume, subjects, location, and recipient;
- system criticality, MLPS, critical-infrastructure, cryptography, and cloud
  facts;
- AI use, autonomy, explainability, customer/financial impact, and deployment;
- outsourcing role, materiality, concentration, continuity, and exit.

The current controlled registry defines 56 such facts. Missing facts return
`needs_review`, never an implicit `not_applicable`.

The fintech/data/AI pack includes the specialised 2026 rules for public
anthropomorphic interaction services. Applicability requires facts such as a
simulated persona and sustained emotional interaction; an ordinary customer-
service, knowledge-answering, or work assistant is not automatically in scope.

## Source policy

Production authority comes from official government and regulator sources.
Store the resolved URL, issue/publication/effective dates, metadata confidence,
source-check time, legal-review state, and an integrity-protected snapshot and
hash where permitted. Search engines, news, law-firm summaries, vendor blogs,
and GitHub collections are discovery sources only.

Open-source application code does not grant rights to redistribute ISO, CIS,
PCI, JR/T, or other protected standards. Maintain code and content licences as
separate records.
