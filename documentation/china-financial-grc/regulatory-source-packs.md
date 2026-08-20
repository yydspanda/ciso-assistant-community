# Financial regulatory source packs

Metadata and official-link verification cut-off: **2026-08-20**.

The source register is now split by domain so that a bank, insurer, payment
institution, or technology provider does not inherit a single undifferentiated
checklist. The packs contain metadata and original selection notes only. They
do not redistribute regulatory or standards text, and every version remains
`legal_review_status: unreviewed`.

[`catalogs/regulatory-pack-index.json`](catalogs/regulatory-pack-index.json)
binds each catalog to a SHA-256 digest and defines discovery unions. A bank
loads common + banking + fintech/data/AI; insurance also loads the banking pack
because that pack currently contains shared licence, related-party, consumer
and reporting instruments. Fintech and payment profiles load common +
fintech/data/AI. These unions prevent silent catalog omission; they still do
not establish legal applicability.

## Current coverage

| Pack | Documents | Purpose |
| --- | ---: | --- |
| [Common financial and cross-sector](catalogs/regulatory-sources.json) | 26 | laws, governance, AML/CDD, data, privacy, cyber, common NFRA requirements |
| [Banking](catalogs/banking-regulatory-sources.json) | 16 | licence, capital, liquidity, classification, lending, exposure, provision, market risk, consumer and reporting |
| [Insurance](catalogs/insurance-regulatory-sources.json) | 14 | Insurance Law, solvency, C-ROSS II, ALM, funds, products, sales, intermediaries, reinsurance, reserves and fraud |
| [Fintech, payment, data and AI](catalogs/fintech-data-regulatory-sources.json) | 20 | payment licence and reserves, financial data standards, outbound transfer mechanisms, public AI, CII, cryptography and cloud |
| **Total** | **76** | 76 stable documents and 76 version records |

The version register contains 72 effective records, three active instruments
without an explicit commencement date, and one published future-effective
record. Metadata confidence is `confirmed` for 70 versions and `partial` for
six; partial metadata is preserved rather than guessed.

The authority mix is also explicit: six laws, three administrative regulations,
45 departmental rules, 17 regulatory normative documents, one mandatory
standard, and four recommended financial-industry standards. Recommended
standards do not independently generate a legal-breach conclusion.

## What is new in the domain packs

### Banking

The first banking pack captures the current capital rule, liquidity framework,
financial-asset risk classification, the three 2024 loan measures, internet
lending and loan-assistance overlays, large exposure, loan-loss provision,
market risk, related-party transactions, consumer protection, regulatory
statistics, company-law governance alignment, and the 2026 licence rule.

Important distinctions are recorded in metadata rather than flattened:

- liquidity metrics depend on institution and asset-size facts;
- overdue days are an input, not an automatic final asset classification;
- large-exposure connected clients and related parties use different legal
  perimeters even when they share an ownership graph;
- regulatory provisions, accounting expected credit loss, and fiscal reserves
  remain distinct systems;
- the 2025 market-risk rule does not cover banking-book interest-rate risk;
- an accepted regulatory file proves technical receipt, not data truth.

### Insurance

The insurance pack covers the Insurance Law, solvency management, C-ROSS II and
its 2023 optimisation overlay, asset-liability management, insurance-fund use,
property and life product terms and rates, sales conduct, life-product
disclosure, agents, reinsurance, non-life reserves, and anti-insurance fraud.

The metadata preserves several easy-to-miss boundaries:

- the 2023 solvency notice adjusts selected C-ROSS II treatments; it does not
  replace the entire rule set;
- the later draft asset-liability rule is not yet a current requirement;
- sales-conduct and financial-product suitability rules can apply cumulatively;
- personal life-product disclosure does not automatically cover group life
  insurance;
- agent, broker, and assessor perimeters are separate;
- model flags are investigation leads, not final fraud or claim decisions.

### Payment, data, cybersecurity, and AI

The fintech pack adds the non-bank payment regulation and implementation rule,
customer reserve funds, network payment, three financial-data standards and a
financial-cloud standard, the three outbound-data mechanisms, algorithm
recommendation, deep synthesis, the mandatory AI-labelling standard, CII,
commercial cryptography, cybersecurity review, and the 2026 anthropomorphic-AI
rule.

It also records the `网络数据安全风险评估办法`, which became effective on
the cut-off date itself. Historical evaluations must therefore retain the rule
version, fact snapshot, and decision time.

Cross-border mechanism selection must compose the security-assessment,
standard-contract and certification instruments with the later 2024 threshold
and exemption overlay. A mechanism exemption does not remove underlying PIPL
notice, separate-consent, impact-assessment or recipient-governance duties.

## Applicability facts

[`catalogs/applicability-facts.json`](catalogs/applicability-facts.json)
defines 56 controlled fact keys under
[`schemas/applicability-fact.schema.json`](schemas/applicability-fact.schema.json).
Each fact has a type, accountable owner, evidence examples, sensitivity and a
fixed unknown result of `needs_review`.

The registry covers:

- legal entity, licence, regulator, asset size, group, listing, systemic
  designation, and third-party data-security assessment role;
- bank business, consolidated scope, loan, exposure and trading-book facts;
- insurance company, product, channel, intermediary, funds, reinsurance and
  non-life facts;
- payment institution, payment business and customer reserve funds;
- personal-information counts, outbound transfers, important data, MLPS and
  formal CII status;
- public internet, algorithm, deep synthesis, generative and anthropomorphic AI,
  user counts, customer impact, cloud, outsourcing and incident scope.

Source-pack documents refer only to registered keys. This creates a stable
vocabulary for later deterministic rules without claiming that a fact or an
instrument applies to a particular institution.

## Coverage stages

`coverage_stage` separates research progress from legal authority:

1. `source_metadata` — official source, version and candidate facts collected;
2. `provision_indexed` — source locators and integrity evidence captured;
3. `obligations_proposed` — structured propositions proposed but not approved;
4. `obligations_reviewed` — accountable human review completed.

The 50 records added in the sector packs are intentionally at
`source_metadata`; the two common-catalog additions use the same stage. These
52 newly added records extend the 24-record common foundation. The next step is
not to ask an LLM to turn all 76 documents into a checklist. It is to select a
legal entity and extract a small number of high-impact provisions with page/
article anchors, hashes, version relationships and maker-checker review.

## Recommended first extraction slices

1. **Bank financial-asset classification** — borrower facts, classification
   evidence, quarterly review, restructuring and manual judgment.
2. **Insurance sales and claims** — product/customer/channel facts, disclosure,
   traceability, claim timeline, refusal rationale and human authority.
3. **Payment reserve funds** — licence mapping, segregated accounts, source-to-
   ledger reconciliation, exception handling and regulator reporting.
4. **Outbound data routing** — CII, important data, ordinary/sensitive personal
   information counts, exemptions and PIPIA evidence.
5. **Financial AI inventory** — public-service status, algorithm/deep-synthesis
   function, customer impact, high-risk use, labels and human takeover.

## Observation and quarantine queue

The following should be monitored but must not silently generate current
violations:

- the 2026 consultation draft for financial-sector cybersecurity management;
- the 2025 draft replacement for insurance asset-liability management;
- the 2026-09-01 future-effective simplified measures for small personal-
  information processors;
- the financial-information-service data-classification guide, whose direct
  scope is not every financial institution;
- the bank banking-book interest-rate-risk guidance whose central official
  metadata is not yet complete in this pack;
- the bank/insurance emergency-information-reporting instrument whose full
  central source and dates still require verification.

Drafts can create preparation tasks and comparison reports. They cannot create
a present-tense breach finding.

## Validation

The artifact validator now:

- discovers every `*-sources.json` pack;
- verifies the versioned pack index, catalog digests, and profile composition;
- rejects duplicate JSON keys and duplicate document/version IDs across packs;
- requires official `*.gov.cn` source hosts for production catalogs;
- validates legal status, dates, bitemporal intervals and supersession;
- requires priority, coverage stage, rationale and fact keys for all sector-
  pack records (the 24 legacy common records predate these optional fields);
- rejects fact keys absent from the controlled registry;
- validates fact types/evidence and recomputes three-value applicability
  results instead of trusting a supplied result string;
- binds approvals to canonical payload digests, requires human maker-checker
  separation, and checks prerequisite approvals;
- continues to validate control-library, documentation and approval invariants.
