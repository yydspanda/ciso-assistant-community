---
description: Current coverage and boundaries of the China financial regulatory metadata packs.
---

# Regulatory source packs

> These packs are legally unreviewed metadata and discovery artifacts. They do
> not establish that an instrument applies to an organisation and do not prove
> compliance.

The fork currently contains 76 official-source document records and 76 version
records, checked as of 2026-08-20:

| Pack | Records | Main coverage |
| --- | ---: | --- |
| Common | 26 | laws, AML/CDD, governance, data, privacy, cyber and common NFRA rules |
| Banking | 16 | licences, capital, liquidity, asset classification, lending, exposure, provision, market risk and reporting |
| Insurance | 14 | Insurance Law, solvency, ALM, funds, products, sales, reinsurance, reserves and fraud |
| Fintech/data/AI | 20 | payment, reserve funds, outbound data, public AI, CII, cryptography and financial cloud |

Seventy-two versions are effective, three are active without an explicit
commencement date, and one is published but future-effective. Six retain
partial metadata rather than guessed values.

The machine-readable pack index binds these files to reviewed hashes and
defines discovery unions: bank = common + banking + fintech/data/AI; insurance
adds the insurance pack while retaining banking because several shared bank-
and-insurance instruments are stored there; fintech/payment = common +
fintech/data/AI. Profile selection is still not an applicability decision.

## Deterministic applicability vocabulary

Fifty-six controlled fact keys cover legal entity and licence, bank and
insurance activity, payment business, data counts and transfers, MLPS/CII,
third-party data-security assessment, public AI functionality, customer impact,
cloud, outsourcing and incidents.
Every unknown rule fact must route to `needs_review`.

The fact registry does not decide applicability by itself. Each value needs an
as-of date, evidence and accountable owner.

## Knowledge-production stages

The 50 sector-pack records and two common-catalog additions (52 new records in
total) are at `source_metadata`:

1. official metadata collected;
2. provisions indexed with locators and integrity evidence;
3. obligations proposed;
4. obligations reviewed by accountable people.

An LLM must not skip directly from a source link to an approved compliance
requirement. The recommended first slices are bank asset classification,
insurance sales and claims, payment reserve funds, outbound-data routing and a
financial AI inventory.

Draft financial cybersecurity and insurance ALM instruments remain in the
observation queue. They may trigger preparation work, not current violation
findings.
