export type RegulatoryReadState =
	'ok' | 'idle' | 'invalid' | 'unauthenticated' | 'restricted' | 'unavailable';

export interface RegulatoryReadPanel<T> {
	state: RegulatoryReadState;
	data: T | null;
}

export interface RegulatoryProvenance {
	method: 'human' | 'parser' | 'model_proposal' | 'import';
	created_at: string;
	created_by: string;
	parser_version: string | null;
	model: string | null;
	prompt_version: string | null;
	retrieval_version: string | null;
}

export interface RegulatoryDocumentSummary {
	id: string;
	record_id: string;
	title_zh: string;
	title_en: string;
	issuer: string;
	authority_level: string;
	territories: string[];
	regulated_entity_scopes: string[];
	domains: string[];
	coverage_priority: string;
	coverage_stage: string;
	applicability_fact_keys: string[];
	selection_rationale: string;
	folder: Record<string, never>;
}

export interface RegulatoryObligation {
	id: string;
	record_id: string;
	revision: number;
	title_zh: string;
	authority_level: string;
	modality: string;
	subject: string;
	action: string;
	object: string | null;
	conditions: string[];
	exceptions: string[];
	deadline: {
		kind: string;
		value: string | null;
		rule_id: string | null;
	};
	expected_evidence: string[];
	penalty_or_consequence: string | null;
	valid_from: string | null;
	valid_to: string | null;
	recorded_from: string;
	recorded_to: string | null;
	review_status: string;
	confidence: string | number;
	uncertainties: string[];
	provenance: RegulatoryProvenance;
	provision_ids: string[];
	legal_conclusion: false;
}

export interface RegulatoryProvision {
	id: string;
	record_id: string;
	revision: number;
	article: string;
	heading: string | null;
	text: '' | null;
	source_locator: {
		kind: string;
		value: string;
	};
	content_hash: string;
	recorded_from: string;
	recorded_to: string | null;
	provenance: RegulatoryProvenance;
	obligations: RegulatoryObligation[];
}

export interface RegulatoryDocumentVersion {
	id: string;
	record_id: string;
	revision: number;
	version_label: string;
	document_no: string | null;
	status: string;
	status_as_of: string;
	effective_basis: string;
	issued_date: string | null;
	published_date: string | null;
	effective_date: string | null;
	transition_end: string | null;
	repeal_date: string | null;
	supersedes_version_ids: string[];
	source_url: string;
	/** Empty string and null are both valid Phase 1 no-hash representations. */
	source_hash: string | null;
	content_storage_policy: 'metadata_only';
	notes: string;
	source_checked_on: string;
	metadata_confidence: string;
	legal_review_status: string;
	legal_reviewed_at: string | null;
	legal_reviewed_by: string | null;
	valid_from: string | null;
	valid_to: string | null;
	recorded_from: string;
	recorded_to: string | null;
	provenance: RegulatoryProvenance;
	provisions: RegulatoryProvision[];
}

export interface RegulatoryDocumentDetail extends RegulatoryDocumentSummary {
	contract_status: 'draft';
	legal_conclusion: false;
	recorded_as_of: string | null;
	document_versions: RegulatoryDocumentVersion[];
}

export type RegulatoryApplicabilityResult = 'applicable' | 'not_applicable' | 'needs_review';
export type RegulatoryDecisionReason =
	'rule_satisfied' | 'rule_not_satisfied' | 'missing_or_unknown_fact';

export interface RegulatoryKnownInstitutionTypeFact {
	fact: 'entity.institution_type';
	known: true;
	value: string;
	source_refs: string[];
	observed_at: string;
}

export interface RegulatoryUnknownInstitutionTypeFact {
	fact: 'entity.institution_type';
	known: false;
	source_refs: [];
	observed_at: null;
}

export type RegulatoryInstitutionTypeFact =
	RegulatoryKnownInstitutionTypeFact | RegulatoryUnknownInstitutionTypeFact;

export interface RegulatoryApplicabilityDecision {
	id: string;
	record_id: string;
	revision: number;
	fact_snapshot_id: string;
	scope: { type: 'legal_entity'; id: string };
	rule: {
		id: 'SYNTHETIC-ENTITY-INSTITUTION-TYPE-BANK-001';
		version: 1;
		all: [
			{
				fact: 'entity.institution_type';
				operator: 'eq';
				value: 'bank';
			}
		];
		any: [];
		unknown_result: 'needs_review';
	};
	facts: [RegulatoryInstitutionTypeFact];
	missing_fact_keys: [] | ['entity.institution_type'];
	result: RegulatoryApplicabilityResult;
	rationale_code: RegulatoryDecisionReason;
	rationale: string;
	valid_from: string | null;
	valid_to: string | null;
	recorded_from: string;
	recorded_to: string | null;
	review_status: 'draft';
	is_binding: false;
	digest_schema: 'regulatory-applicability-evaluation/v1';
	evaluator_profile: 'synthetic-single-condition/v1';
	rule_snapshot_sha256: string;
	fact_snapshot_sha256: string;
	semantic_payload_sha256: string;
	provenance: RegulatoryProvenance;
	legal_conclusion: false;
}

export interface RegulatoryApplicability {
	contract_status: 'draft';
	legal_conclusion: false;
	is_binding: false;
	scope: { type: 'legal_entity'; id: string };
	document_id: string;
	obligation_id: string;
	obligation_revision: number;
	recorded_as_of: string | null;
	selected_recorded_at: string;
	evaluation_status: 'evaluated' | 'not_evaluated';
	non_binding_result: RegulatoryApplicabilityResult;
	reason_code: RegulatoryDecisionReason | 'no_decision_for_selected_obligation_revision';
	decision: RegulatoryApplicabilityDecision | null;
}

export interface RegulatoryReviewDisposition {
	id: string;
	sequence: number;
	from_disposition:
		'not_reviewed' | 'no_correction_requested' | 'correction_requested' | 'unable_to_complete';
	to_disposition: 'no_correction_requested' | 'correction_requested' | 'unable_to_complete';
	reason_code:
		| 'review_completed'
		| 'fact_correction_required'
		| 'evidence_correction_required'
		| 'provenance_correction_required'
		| 'scope_or_parent_correction_required'
		| 'other_correction_required'
		| 'insufficient_evidence'
		| 'conflicting_information'
		| 'insufficient_authority_or_scope'
		| 'other_unresolved';
	rationale: string;
	occurred_at: string;
	digest_profile: 'regulatory-applicability-review-disposition/v1';
	decision_semantic_payload_sha256: string;
	event_payload_sha256: string;
	reviewer: { masked: true } | { masked: false; id: string; display_name: string | null };
}

export interface RegulatoryApplicabilityReview {
	contract_status: 'draft';
	legal_conclusion: false;
	is_binding: false;
	scope: { type: 'legal_entity'; id: string };
	document_id: string;
	obligation_id: string;
	obligation_revision: number;
	recorded_as_of: string | null;
	selected_recorded_at: string;
	evaluation_status: 'evaluated' | 'not_evaluated';
	computed_non_binding_result: RegulatoryApplicabilityResult;
	decision: RegulatoryApplicabilityDecision | null;
	review_state:
		| 'not_reviewable'
		| 'not_reviewed'
		| 'no_correction_requested'
		| 'correction_requested'
		| 'unable_to_complete';
	workflow_attention: 'needs_review' | 'reviewed_nonbinding';
	latest_disposition: RegulatoryReviewDisposition | null;
}

export interface RegulatoryEntityOption {
	id: string;
	name: string;
	ref_id?: string;
}

export interface PaginatedResponse<T> {
	count: number;
	next: string | null;
	previous: string | null;
	results: T[];
}
