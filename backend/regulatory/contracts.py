from typing import Any, Literal, NotRequired, TypedDict


class RegulatoryDocumentPayload(TypedDict):
    id: str
    title_zh: str
    issuer: str
    authority_level: str
    territories: list[str]
    regulated_entity_scopes: list[str]
    domains: list[str]
    title_en: NotRequired[str]
    coverage_priority: NotRequired[str]
    coverage_stage: NotRequired[str]
    applicability_fact_keys: NotRequired[list[str]]
    selection_rationale: NotRequired[str]


class RegulatoryDocumentVersionPayload(TypedDict):
    id: str
    document_id: str
    version_label: str
    document_no: str | None
    status: str
    status_as_of: str
    effective_basis: str
    issued_date: str | None
    published_date: str | None
    effective_date: str | None
    transition_end: str | None
    repeal_date: str | None
    supersedes_version_ids: list[str]
    source_url: str
    source_hash: str | None
    content_storage_policy: str
    source_checked_on: str
    metadata_confidence: str
    legal_review_status: str
    legal_reviewed_at: str | None
    legal_reviewed_by: str | None
    valid_from: str | None
    valid_to: str | None
    recorded_from: str
    recorded_to: str | None
    provenance: dict[str, Any]
    notes: NotRequired[str]


class RegulatoryProvisionPayload(TypedDict):
    id: str
    document_id: str
    version_id: str
    article: str
    source_locator: dict[str, str]
    content_hash: str
    recorded_from: str
    recorded_to: str | None
    provenance: dict[str, Any]
    heading: NotRequired[str | None]
    text: NotRequired[str | None]


class RegulatoryObligationPayload(TypedDict):
    id: str
    title_zh: str
    provision_ids: list[str]
    authority_level: str
    modality: str
    subject: str
    action: str
    conditions: list[str]
    deadline: dict[str, Any]
    valid_from: str | None
    valid_to: str | None
    recorded_from: str
    recorded_to: str | None
    review_status: str
    confidence: float
    provenance: dict[str, Any]
    object: NotRequired[str | None]
    exceptions: NotRequired[list[str]]
    expected_evidence: NotRequired[list[str]]
    penalty_or_consequence: NotRequired[str | None]
    uncertainties: NotRequired[list[str]]


class RegulatoryChainPayload(TypedDict):
    document: RegulatoryDocumentPayload
    document_version: RegulatoryDocumentVersionPayload
    provision: RegulatoryProvisionPayload
    obligation: RegulatoryObligationPayload


class RegulatoryRevisionExpectations(TypedDict):
    document_version: int
    provision: int
    obligation: int
    semantic_payload_sha256: str


class RegulatoryDocumentVersionCorrectionPayload(TypedDict):
    """Complete successor payload; recorded time is owned by the service."""

    id: str
    document_id: str
    version_label: str
    document_no: str | None
    status: str
    status_as_of: str
    effective_basis: str
    issued_date: str | None
    published_date: str | None
    effective_date: str | None
    transition_end: str | None
    repeal_date: str | None
    supersedes_version_ids: list[str]
    source_url: str
    source_hash: str | None
    content_storage_policy: str
    source_checked_on: str
    metadata_confidence: str
    legal_review_status: str
    legal_reviewed_at: str | None
    legal_reviewed_by: str | None
    valid_from: str | None
    valid_to: str | None
    provenance: dict[str, Any]
    notes: str


class RegulatoryProvisionCorrectionPayload(TypedDict):
    """Complete successor payload; recorded time is owned by the service."""

    id: str
    document_id: str
    version_id: str
    article: str
    source_locator: dict[str, str]
    content_hash: str
    provenance: dict[str, Any]
    heading: str | None
    text: str | None


class RegulatoryObligationCorrectionPayload(TypedDict):
    """Complete successor payload; recorded time is owned by the service."""

    id: str
    title_zh: str
    provision_ids: list[str]
    authority_level: str
    modality: str
    subject: str
    action: str
    conditions: list[str]
    deadline: dict[str, Any]
    valid_from: str | None
    valid_to: str | None
    review_status: str
    confidence: float
    provenance: dict[str, Any]
    object: str | None
    exceptions: list[str]
    expected_evidence: list[str]
    penalty_or_consequence: str | None
    uncertainties: list[str]


class RegulatoryChainCorrectionPayload(TypedDict):
    expected_revisions: RegulatoryRevisionExpectations
    document_version: RegulatoryDocumentVersionCorrectionPayload
    provision: RegulatoryProvisionCorrectionPayload
    obligation: RegulatoryObligationCorrectionPayload


class RegulatoryProvenancePayload(TypedDict):
    method: Literal["human", "parser", "model_proposal", "import"]
    created_at: str
    created_by: str
    parser_version: str | None
    model: str | None
    prompt_version: str | None
    retrieval_version: str | None


class RegulatoryKnownInstitutionTypeObservation(TypedDict):
    fact: Literal["entity.institution_type"]
    known: Literal[True]
    value: str
    source_refs: list[str]
    observed_at: str


class RegulatoryUnknownInstitutionTypeObservation(TypedDict):
    fact: Literal["entity.institution_type"]
    known: Literal[False]
    source_refs: list[str]
    observed_at: None


RegulatoryApplicabilityObservation = (
    RegulatoryKnownInstitutionTypeObservation
    | RegulatoryUnknownInstitutionTypeObservation
)


class RegulatoryApplicabilityExpectedCurrentPayload(TypedDict):
    decision_revision: int | None
    semantic_payload_sha256: str | None


class RegulatoryApplicabilityExpectedObligationPayload(TypedDict):
    physical_id: str
    record_id: str
    revision: int
    chain_semantic_payload_sha256: str


class RegulatoryApplicabilityPayload(TypedDict):
    """Fact-only command; rule, result, and recorded time are server-owned."""

    record_id: str
    fact_snapshot_id: str
    expected_current: RegulatoryApplicabilityExpectedCurrentPayload
    expected_obligation: RegulatoryApplicabilityExpectedObligationPayload
    observations: list[RegulatoryApplicabilityObservation]
    valid_from: str | None
    valid_to: str | None
    provenance: RegulatoryProvenancePayload
