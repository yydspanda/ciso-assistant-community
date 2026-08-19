# Open-source component decisions

Review date: **2026-08-19**.

These decisions optimise for an incremental extension of CISO Assistant. They
do not recommend replacing working repository capabilities merely because
another component exists.

| Component | Decision | Intended boundary | Licence / caution |
| --- | --- | --- | --- |
| [CISO Assistant](https://github.com/intuitem/ciso-assistant-community) | Adopt | GRC system of record, IAM, assessments, controls, evidence, findings, UI | code outside `enterprise/` is AGPLv3; enterprise directory is commercial |
| [NIST OSCAL](https://github.com/usnistgov/OSCAL) | Adopt concepts and interchange | control, implementation, assessment, result, and remediation exchange | US public domain/CC0; extend for China legal obligation/applicability semantics |
| [Compliance Trestle](https://github.com/oscal-compass/compliance-trestle) | Assess | OSCAL authoring, validation, transforms, signing, Git review | Apache-2.0; not a GRC portal or regulatory-intake system |
| [Docling](https://github.com/docling-project/docling) | Assess early | PDF/layout/table extraction with page anchors | MIT; extracted content still has its original rights and trust level |
| PostgreSQL temporal tables in this app | Adopt first | valid-time and recorded-time regulatory records | avoid a second database until scale/query evidence justifies it |
| [XTDB](https://github.com/xtdb/xtdb) | Defer | optional dedicated bitemporal store | MPL-2.0; operational complexity and dual-master risk |
| Existing chat workflows and proposal pattern | Adopt | bounded AI analysis and user-confirmed changes | keep deterministic pre-routing and permission-filtered retrieval |
| [LangGraph](https://github.com/langchain-ai/langgraph) or another agent framework | Defer | only for future subgraphs that current workflows cannot express | do not create a second control plane or framework zoo |
| Existing validation flows/tasks | Adopt first | review and simple approvals | assess edition boundaries and advanced case/SLA needs |
| [Flowable](https://github.com/flowable/flowable-engine) | Assess later | complex BPMN/CMMN/DMN and long-running regulated cases | Apache-2.0; avoid duplicated workflow state until there is a proven gap |
| [Open Policy Agent](https://github.com/open-policy-agent/opa) | Assess for write phase | tool action `allow/deny/escalate` | Apache-2.0; it enforces authored policy, not natural-language law |
| Existing folder-scoped IAM | Adopt | application authorisation source | never treat focus mode or UI filtering as authorisation |
| [OpenFGA](https://github.com/openfga/openfga) | Defer | optional relationship authorisation at larger scale | Apache-2.0; avoid two inconsistent authorisation masters |
| [OpenMetadata](https://github.com/open-metadata/OpenMetadata) | Assess integration | data catalog, ownership, classification, lineage | Apache-2.0; evidence/facts provider, not the legal decision engine |
| [Fides](https://github.com/ethyca/fides) | Assess integration | privacy operations and data-subject requests | Apache-2.0; extend and test for PIPL and financial data semantics |
| [Presidio](https://github.com/data-privacy-stack/presidio) | Assess integration | PII detection and redaction | MIT; detection does not establish legal classification or lawfulness |
| [Prowler](https://github.com/prowler-cloud/prowler) | Assess integration | cloud/Kubernetes technical evidence | Apache-2.0; a passing scan is not a full control-effectiveness opinion |
| [ComplianceAsCode/content](https://github.com/ComplianceAsCode/content) | Assess integration | deterministic host/container baselines | BSD-3-Clause; primarily technical controls |
| [Promptfoo](https://github.com/promptfoo/promptfoo) | Adopt for CI evaluation | prompt/RAG/agent regression and adversarial suites | MIT |
| [Inspect AI](https://github.com/UKGovernmentBEIS/inspect_ai) | Assess | framework-independent agent evaluation | MIT |
| [PyRIT](https://github.com/microsoft/PyRIT) and [garak](https://github.com/NVIDIA/garak) | Adopt before write phase | red-team and model/endpoint probes | MIT / Apache-2.0; complement, not replace, application threat modelling |
| [OpenTelemetry Collector](https://github.com/open-telemetry/opentelemetry-collector) | Adopt | neutral trace/metric/log export | Apache-2.0; redact regulated payloads |
| [OpenLIT](https://github.com/openlit/openlit) | Assess | self-hosted AI cost and quality views | Apache-2.0; telemetry store needs classification and retention controls |

## Components used as references only

- [Probo](https://github.com/getprobo/probo): strong AI-native GRC and MCP
  reference, but adopting it alongside CISO Assistant would create two GRC
  systems of record.
- [Openlane Core](https://github.com/theopenlane/core): useful Apache-2.0 GRC
  reference, with the same dual-master concern.
- [GRCX](https://github.com/grcx-dev/grcx): useful regulatory-source and
  hash-chain experiment; too young and narrow for a production banking core.
- [AWS sample compliance assistant](https://github.com/aws-samples/sample-compliance-assistant-with-agents):
  useful multi-agent demonstration, not a production governance design.

## Licence and content rules

1. Record code licence and content licence separately.
2. Run legal review for AGPL network-use and modification obligations before a
   closed commercial offering.
3. Do not copy files from the commercial `enterprise/` directory without an
   applicable contract.
4. Do not assume an open-source application grants redistribution rights for
   ISO, CIS, PCI, JR/T, or other standards content.
5. A GitHub repository without a licence grants no general reuse permission.
6. Maintain SBOM, source, version, hash, maintainer health, CVE, and exit-plan
   records for every adopted dependency.
