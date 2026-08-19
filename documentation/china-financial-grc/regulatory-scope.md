# Regulatory scope and source policy

Official-link and source-metadata review date: **2026-08-20**.

The machine-readable seed list is maintained in
[`catalogs/regulatory-sources.json`](catalogs/regulatory-sources.json). This
document defines how sources are classified and used. The 24 seed records are
all marked `legal_review_status: unreviewed`. Two records deliberately retain a
`null` publication date because the first official publication date could not
be strictly confirmed. The future online-marketing measure is also marked
`metadata_confidence: partial` because official channels classify its authority
level inconsistently. Link review is not legal review or an applicability
conclusion.

## Authority hierarchy

1. **Laws** — National People's Congress and its Standing Committee.
2. **Administrative regulations** — State Council.
3. **Departmental rules** — instruments issued with the formal authority and
   procedure applicable to departmental rules.
4. **Regulatory normative documents** — supervisory notices, guidance, and
   other normative instruments from authorities including NFRA, PBOC, and CAC.
   They must not be automatically promoted to departmental-rule status.
5. **Standards** — distinguish mandatory `GB` from recommended `GB/T` and
   financial-industry `JR/T`. A recommended standard can become an operational
   baseline when incorporated by regulation, contract, supervisory practice, or
   internal policy; that does not turn every recommendation into a statute.
6. **Internal rules** — articles of association, delegations, policies,
   procedures, standards, and control descriptions. They may be stricter than
   external obligations but cannot weaken them.
7. **Interpretive and enforcement material** — official Q&A, enforcement
   decisions, and supervisory communications inform interpretation and risk;
   they must not be stored at the same authority level as binding text.

Draft, future-effective, effective, active-without-an-explicit-commencement,
superseded, repealed, and unknown states are separate. Future-effective material
may trigger preparation work but must not produce a current breach conclusion;
an absent commencement clause must not be replaced with a guessed date.

## Applicability dimensions

No global checklist applies uniformly across a financial group. At minimum,
the system asks about:

- legal entity, licence, regulator, jurisdiction, ownership and listing status;
- banking, insurance, payment, fintech, technology-provider, and outsourced
  service roles;
- product, customer type, sales channel, and customer-impacting decision;
- data type, sensitivity, volume, data-subject population, location, and
  cross-border route;
- system criticality, MLPS level, critical-information-infrastructure status,
  cryptography, and cloud deployment;
- AI use case, model type, autonomy, explainability, financial/customer impact,
  and whether the service is public-facing;
- transaction, counterparty, AML, sanctions, and fraud risk;
- material outsourcing, concentration, business continuity, and exit plan.

## Initial domain packs

### Governance, compliance, audit, and cost

- board and senior-management accountability;
- three lines of defence and independence;
- chief compliance officer and compliance-management responsibilities;
- delegations, conflicts, related parties, and segregation of duties;
- internal control, audit universe, evidence, findings, and remediation;
- procurement, expenses, duplicate invoices, split purchases, total cost of
  ownership, and budget variance.

Cost optimisation must never bypass mandatory approval, information security,
consumer protection, accounting, retention, or audit controls.

### Banking, insurance, and fintech

- licensed activity and prudential boundaries;
- product governance, suitability, disclosure, and consumer protection;
- AML/KYC, beneficial ownership, sanctions, large/suspicious transaction work;
- credit, underwriting, claims, valuation, capital, provision, and model
  governance;
- operational risk, technology outsourcing, resilience, and incident duties;
- financial data lifecycle and reporting obligations.

Automation may prepare checks and drafts. Final credit, underwriting, claim
denial, suspicious-transaction filing, material pricing, regulatory filing,
capital, and board decisions require accountable human authority.

### Data protection and cross-border transfer

- lawfulness, fairness, necessity, transparency, and minimisation;
- consent and separate consent, sensitive personal information, minors, and
  individual rights;
- processor, joint processing, disclosure, recipient, retention, deletion, and
  incident response;
- personal-information protection impact assessment and compliance audit;
- data classification, important/core data, and data asset/lineage records;
- security assessment, standard contract, certification, statutory exemptions,
  and free-trade-zone rules for transfers.

A transfer-mechanism exemption does not remove the underlying PIPL duties.
Sending prompts or retrieved context to an overseas model endpoint may itself
be a cross-border transfer.

### Cybersecurity, MLPS, critical infrastructure, and cryptography

- network operator duties and security management;
- MLPS classification, filing, construction/remediation, and assessment;
- critical-information-infrastructure and supply-chain review triggers;
- vulnerability, configuration, software supply chain, event classification,
  evidence preservation, and multi-regulator reporting;
- commercial cryptography inventory, use, assessment, keys, and records.

An organisation may identify a candidate critical system, but it cannot replace
formal authority determinations or qualified assessments.

### AI and model governance

There is no single effective comprehensive China AI law in this baseline. The
system composes obligations from personal-information automated-decision rules,
algorithm/deep-synthesis/generative-AI measures, content-labelling rules,
cyber/data law, and financial-sector requirements.

The control pack covers:

- model, data, prompt, tool, provider, and use-case inventory;
- risk classification and pre-production approval;
- data provenance, authorisation, quality, bias, robustness, security,
  explainability, drift, and exit testing;
- human review for customer rights and material financial matters;
- logging, monitoring, incident response, reporting, and emergency takeover;
- generated-content labelling where applicable.

An agent cannot review or approve its own model, grant itself an exception, or
change its audit history.

The non-exhaustive seed does not yet include the 2026
[Interim Measures for AI Anthropomorphic Interaction Services](https://www.cac.gov.cn/2026-04/10/c_1777558395078289.htm).
A later public-facing AI pack must capture whether a service simulates a persona
and sustains emotional interaction. It must not assume that an ordinary customer
service, knowledge-answering, or work assistant falls into that specialised
scope.

## Source acceptance policy

### Production authority

Use official government and regulator domains as the production authority.
Capture the resolved URL, source-check time, issued/published/effective dates,
metadata confidence, legal-review status, and, where permitted, bytes and hash.
Where the official source is a PDF, preserve both the original file and
page-level anchors. Never treat a date embedded in a URL or file path as proof
of publication.

### Discovery-only sources

Search engines, news sites, law-firm summaries, GitHub aggregations, and vendor
blogs can identify possible changes. They cannot publish an obligation without
an official-source match and review.

Many GitHub Chinese-law collections have no explicit licence. A public
repository is not permission to redistribute its content. Do not import such a
repository into a production or commercial knowledge base without a separate
rights assessment.

### Standards copyright

Application code and standards content have separate licences. An open-source
loader does not grant rights to redistribute ISO, CIS, PCI, or other protected
texts. Prefer metadata, identifiers, licensed copies, and organisation-authored
control summaries unless redistribution rights are documented.

## Review cadence

- event-driven monitoring for regulator publication feeds and source changes;
- daily verification of failed or changed monitored URLs;
- human review before any status, supersession, applicability, or obligation is
  published;
- periodic re-verification based on authority and business criticality;
- immediate review after incidents, supervisory findings, or material product,
  entity, data-flow, system, or model changes.
