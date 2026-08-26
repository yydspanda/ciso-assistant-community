import { z } from 'zod';

import type {
	PaginatedResponse,
	RegulatoryApplicability,
	RegulatoryApplicabilityReview,
	RegulatoryDocumentDetail,
	RegulatoryDocumentSummary,
	RegulatoryEntityOption
} from './types';
import { compareRfc3339Instants, isAwareRfc3339 } from './presentation';

const nullableString = z.string().nullable();
const stringArray = z.array(z.string());
const authorityLevelSchema = z.enum([
	'law',
	'administrative_regulation',
	'departmental_rule',
	'regulatory_normative_document',
	'mandatory_standard',
	'recommended_standard',
	'internal_policy',
	'interpretive_material',
	'enforcement_material'
]);
const applicabilityResultSchema = z.enum(['applicable', 'not_applicable', 'needs_review']);
const decisionReasonSchema = z.enum([
	'rule_satisfied',
	'rule_not_satisfied',
	'missing_or_unknown_fact'
]);
const INSTITUTION_TYPE_FACT = 'entity.institution_type' as const;
const PILOT_RULE_ID = 'SYNTHETIC-ENTITY-INSTITUTION-TYPE-BANK-001' as const;
const PILOT_EXPECTED_VALUE = 'bank' as const;
const RATIONALE_MATCH = 'The known institution type matches the fixed synthetic bank rule.';
const RATIONALE_NO_MATCH =
	'The known institution type does not match the fixed synthetic bank rule.';
const RATIONALE_MISSING =
	'The required institution-type fact was missing and was recorded as unknown.';
const RATIONALE_UNKNOWN = 'The required institution-type fact is explicitly unknown.';

const recordedTimestampSchema = z
	.string()
	.refine(isAwareRfc3339, { message: 'Expected a timezone-aware RFC 3339 date-time' });
const sha256Schema = z.string().regex(/^[0-9a-f]{64}$/);
export const regulatorySourceHashSchema = z.union([sha256Schema, z.literal(''), z.null()]);
const phaseOneProvisionTextSchema = z.union([z.literal(''), z.null()]);

const officialSourceUrlSchema = z.string().transform((value, context) => {
	let parsed: URL;
	try {
		parsed = new URL(value);
	} catch {
		context.addIssue({ code: 'custom', message: 'Official source URL is invalid' });
		return z.NEVER;
	}
	if (parsed.protocol !== 'https:') {
		context.addIssue({ code: 'custom', message: 'Official source URL must use HTTPS' });
		return z.NEVER;
	}
	const rawAuthority = value.trim().match(/^[a-z][a-z\d+.-]*:\/\/([^/?#]*)/i)?.[1];
	if (rawAuthority?.includes('@') || parsed.username !== '' || parsed.password !== '') {
		context.addIssue({ code: 'custom', message: 'Official source URL must not contain userinfo' });
		return z.NEVER;
	}
	// Only the URL parser's canonical HTTPS representation reaches PageData.
	return parsed.href;
});
const provenanceSchema = z.object({
	method: z.enum(['human', 'parser', 'model_proposal', 'import']),
	created_at: recordedTimestampSchema,
	created_by: z.string(),
	parser_version: nullableString,
	model: nullableString,
	prompt_version: nullableString,
	retrieval_version: nullableString
});

const obligationSchema = z.object({
	id: z.string().uuid(),
	record_id: z.string(),
	revision: z.number().int().positive(),
	title_zh: z.string(),
	authority_level: authorityLevelSchema,
	modality: z.enum(['must', 'must_not', 'should', 'may', 'organisation_defined']),
	subject: z.string(),
	action: z.string(),
	object: nullableString,
	conditions: stringArray,
	exceptions: stringArray,
	deadline: z.object({
		kind: z.enum([
			'none',
			'fixed_date',
			'duration_after_trigger',
			'periodic',
			'without_undue_delay',
			'needs_review'
		]),
		value: nullableString,
		rule_id: nullableString
	}),
	expected_evidence: stringArray,
	penalty_or_consequence: nullableString,
	valid_from: nullableString,
	valid_to: nullableString,
	recorded_from: recordedTimestampSchema,
	recorded_to: nullableString,
	review_status: z.enum([
		'machine_proposed',
		'analyst_reviewed',
		'legal_reviewed',
		'approved',
		'rejected',
		'superseded'
	]),
	confidence: z.union([z.string(), z.number()]),
	uncertainties: stringArray,
	provenance: provenanceSchema,
	provision_ids: stringArray.min(1).max(1),
	legal_conclusion: z.literal(false)
});

const provisionSchema = z.object({
	id: z.string().uuid(),
	record_id: z.string(),
	revision: z.number().int().positive(),
	article: z.string(),
	heading: nullableString,
	text: phaseOneProvisionTextSchema,
	source_locator: z.object({
		kind: z.enum(['article', 'page', 'page_bbox', 'dom_selector', 'annex', 'table_cell', 'other']),
		value: z.string()
	}),
	content_hash: sha256Schema,
	recorded_from: recordedTimestampSchema,
	recorded_to: nullableString,
	provenance: provenanceSchema,
	obligations: z.array(obligationSchema).min(1).max(1)
});

const versionSchema = z.object({
	id: z.string().uuid(),
	record_id: z.string(),
	revision: z.number().int().positive(),
	version_label: z.string(),
	document_no: nullableString,
	status: z.enum([
		'draft',
		'published_future_effective',
		'effective',
		'active_no_explicit_commencement',
		'superseded',
		'repealed',
		'unknown'
	]),
	status_as_of: z.string(),
	effective_basis: z.enum([
		'explicit_date',
		'publication_clause',
		'no_explicit_commencement_clause',
		'unresolved'
	]),
	issued_date: nullableString,
	published_date: nullableString,
	effective_date: nullableString,
	transition_end: nullableString,
	repeal_date: nullableString,
	supersedes_version_ids: stringArray,
	source_url: officialSourceUrlSchema,
	source_hash: regulatorySourceHashSchema,
	content_storage_policy: z.literal('metadata_only'),
	// The current synthetic browser projection has no accepted rights/IAM policy
	// for free-form selection notes. Validate the backend shape, then strip it.
	notes: z.string().transform(() => ''),
	source_checked_on: z.string(),
	metadata_confidence: z.enum(['confirmed', 'partial', 'unresolved']),
	legal_review_status: z.enum(['unreviewed', 'reviewed']),
	legal_reviewed_at: nullableString,
	legal_reviewed_by: nullableString,
	valid_from: nullableString,
	valid_to: nullableString,
	recorded_from: recordedTimestampSchema,
	recorded_to: nullableString,
	provenance: provenanceSchema,
	provisions: z.array(provisionSchema).min(1).max(1)
});

export const regulatoryDocumentSummarySchema = z.object({
	id: z.string().uuid(),
	record_id: z.string(),
	title_zh: z.string(),
	title_en: z.string(),
	issuer: z.string(),
	authority_level: authorityLevelSchema,
	territories: stringArray,
	regulated_entity_scopes: stringArray,
	domains: stringArray,
	coverage_priority: z.enum(['', 'P0', 'P1', 'P2']),
	coverage_stage: z.enum([
		'source_metadata',
		'provision_indexed',
		'obligations_proposed',
		'obligations_reviewed'
	]),
	applicability_fact_keys: stringArray,
	selection_rationale: z.string(),
	// Accept the backend's IAM-dependent related-object shape, but strip it from
	// the frontend projection so folder metadata cannot enter PageData.
	folder: z.object({})
});

export const regulatoryDocumentDetailSchema = regulatoryDocumentSummarySchema
	.extend({
		contract_status: z.literal('draft'),
		legal_conclusion: z.literal(false),
		recorded_as_of: nullableString,
		document_versions: z.array(versionSchema).min(1).max(1)
	})
	.superRefine((document, context) => {
		const provision = document.document_versions[0]?.provisions[0];
		const obligation = provision?.obligations[0];
		if (
			provision !== undefined &&
			obligation !== undefined &&
			obligation.provision_ids[0] !== provision.record_id
		) {
			context.addIssue({
				code: 'custom',
				path: ['document_versions', 0, 'provisions', 0, 'obligations', 0, 'provision_ids'],
				message: 'The selected obligation must reference the selected provision'
			});
		}
		const version = document.document_versions[0];
		if (
			version !== undefined &&
			provision !== undefined &&
			obligation !== undefined &&
			(compareRfc3339Instants(version.recorded_from, provision.recorded_from) !== 0 ||
				compareRfc3339Instants(provision.recorded_from, obligation.recorded_from) !== 0)
		) {
			context.addIssue({
				code: 'custom',
				path: ['document_versions', 0, 'provisions'],
				message: 'The selected chain must share one recorded-from instant'
			});
		}
	});

const nonBlankFactValueSchema = z
	.string()
	.max(100)
	.refine((value) => value.trim().length > 0, { message: 'Known fact value must not be blank' });
const evidenceReferenceSchema = z
	.string()
	.max(500)
	.refine((value) => value.trim().length > 0, {
		message: 'Evidence reference must not be blank'
	});
const knownEvidenceReferencesSchema = z
	.array(evidenceReferenceSchema)
	.min(1)
	.max(20)
	.superRefine((references, context) => {
		if (new Set(references).size !== references.length) {
			context.addIssue({ code: 'custom', message: 'Evidence references must be unique' });
		}
	});
const knownInstitutionTypeFactSchema = z
	.object({
		fact: z.literal(INSTITUTION_TYPE_FACT),
		known: z.literal(true),
		value: nonBlankFactValueSchema,
		source_refs: knownEvidenceReferencesSchema,
		observed_at: recordedTimestampSchema
	})
	.strict();
const unknownInstitutionTypeFactSchema = z
	.object({
		fact: z.literal(INSTITUTION_TYPE_FACT),
		known: z.literal(false),
		source_refs: z.tuple([]),
		observed_at: z.null()
	})
	.strict();
const applicabilityFactSchema = z.discriminatedUnion('known', [
	knownInstitutionTypeFactSchema,
	unknownInstitutionTypeFactSchema
]);

const applicabilityRuleSchema = z.object({
	id: z.literal(PILOT_RULE_ID),
	version: z.literal(1),
	all: z.tuple([
		z.object({
			fact: z.literal(INSTITUTION_TYPE_FACT),
			operator: z.literal('eq'),
			value: z.literal(PILOT_EXPECTED_VALUE)
		})
	]),
	any: z.tuple([]),
	unknown_result: z.literal('needs_review')
});

const applicabilityDecisionSchema = z
	.object({
		id: z.string().uuid(),
		record_id: z.string(),
		revision: z.number().int().positive(),
		fact_snapshot_id: z.string(),
		scope: z.object({ type: z.literal('legal_entity'), id: z.string().uuid() }),
		rule: applicabilityRuleSchema,
		facts: z.tuple([applicabilityFactSchema]),
		missing_fact_keys: z.union([z.tuple([]), z.tuple([z.literal(INSTITUTION_TYPE_FACT)])]),
		result: applicabilityResultSchema,
		rationale_code: decisionReasonSchema,
		rationale: z.string(),
		valid_from: nullableString,
		valid_to: nullableString,
		recorded_from: recordedTimestampSchema,
		recorded_to: nullableString,
		review_status: z.literal('draft'),
		is_binding: z.literal(false),
		digest_schema: z.literal('regulatory-applicability-evaluation/v1'),
		evaluator_profile: z.literal('synthetic-single-condition/v1'),
		rule_snapshot_sha256: sha256Schema,
		fact_snapshot_sha256: sha256Schema,
		semantic_payload_sha256: sha256Schema,
		provenance: provenanceSchema,
		legal_conclusion: z.literal(false)
	})
	.superRefine((decision, context) => {
		const [fact] = decision.facts;
		const factWasMissing = decision.missing_fact_keys.length === 1;
		const expectedResult = !fact.known
			? 'needs_review'
			: fact.value === PILOT_EXPECTED_VALUE
				? 'applicable'
				: 'not_applicable';
		const expectedReason = !fact.known
			? 'missing_or_unknown_fact'
			: fact.value === PILOT_EXPECTED_VALUE
				? 'rule_satisfied'
				: 'rule_not_satisfied';
		const expectedRationale = !fact.known
			? factWasMissing
				? RATIONALE_MISSING
				: RATIONALE_UNKNOWN
			: fact.value === PILOT_EXPECTED_VALUE
				? RATIONALE_MATCH
				: RATIONALE_NO_MATCH;

		if (fact.known && factWasMissing) {
			context.addIssue({
				code: 'custom',
				path: ['missing_fact_keys'],
				message: 'Known facts cannot be declared missing'
			});
		}
		if (fact.known && compareRfc3339Instants(fact.observed_at, decision.recorded_from) === 1) {
			context.addIssue({
				code: 'custom',
				path: ['facts', 0, 'observed_at'],
				message: 'Fact observation cannot postdate the decision'
			});
		}
		if (decision.result !== expectedResult || decision.rationale_code !== expectedReason) {
			context.addIssue({
				code: 'custom',
				message: 'Decision result and reason must be recomputed from the fact snapshot'
			});
		}
		if (decision.rationale !== expectedRationale) {
			context.addIssue({
				code: 'custom',
				path: ['rationale'],
				message: 'Decision rationale must match the deterministic fact outcome'
			});
		}
	});

const applicabilityBaseSchema = z.object({
	contract_status: z.literal('draft'),
	legal_conclusion: z.literal(false),
	is_binding: z.literal(false),
	scope: z.object({ type: z.literal('legal_entity'), id: z.string().uuid() }),
	document_id: z.string().uuid(),
	obligation_id: z.string(),
	obligation_revision: z.number().int().positive(),
	recorded_as_of: nullableString,
	selected_recorded_at: recordedTimestampSchema,
	evaluation_status: z.enum(['evaluated', 'not_evaluated']),
	decision: applicabilityDecisionSchema.nullable()
});

export const regulatoryApplicabilitySchema = applicabilityBaseSchema
	.extend({
		non_binding_result: applicabilityResultSchema,
		reason_code: z.union([
			decisionReasonSchema,
			z.literal('no_decision_for_selected_obligation_revision')
		])
	})
	.superRefine((value, context) => {
		if (value.evaluation_status === 'not_evaluated') {
			if (
				value.decision !== null ||
				value.non_binding_result !== 'needs_review' ||
				value.reason_code !== 'no_decision_for_selected_obligation_revision'
			) {
				context.addIssue({
					code: 'custom',
					message: 'not_evaluated responses must remain non-binding needs_review without a decision'
				});
			}
		} else if (
			value.decision === null ||
			value.decision.result !== value.non_binding_result ||
			value.decision.rationale_code !== value.reason_code
		) {
			context.addIssue({
				code: 'custom',
				message: 'evaluated responses must include the matching decision result'
			});
		}
	});

const reviewDispositionSchema = z
	.object({
		id: z.string().uuid(),
		sequence: z.number().int().positive(),
		from_disposition: z.enum([
			'not_reviewed',
			'no_correction_requested',
			'correction_requested',
			'unable_to_complete'
		]),
		to_disposition: z.enum([
			'no_correction_requested',
			'correction_requested',
			'unable_to_complete'
		]),
		reason_code: z.enum([
			'review_completed',
			'fact_correction_required',
			'evidence_correction_required',
			'provenance_correction_required',
			'scope_or_parent_correction_required',
			'other_correction_required',
			'insufficient_evidence',
			'conflicting_information',
			'insufficient_authority_or_scope',
			'other_unresolved'
		]),
		rationale: z.string(),
		occurred_at: recordedTimestampSchema,
		digest_profile: z.literal('regulatory-applicability-review-disposition/v1'),
		decision_semantic_payload_sha256: sha256Schema,
		event_payload_sha256: sha256Schema,
		reviewer: z.union([
			z.object({ masked: z.literal(true) }),
			z.object({
				masked: z.literal(false),
				id: z.string().uuid(),
				display_name: nullableString
			})
		])
	})
	.superRefine((disposition, context) => {
		const reasonMatches =
			(disposition.to_disposition === 'no_correction_requested' &&
				disposition.reason_code === 'review_completed') ||
			(disposition.to_disposition === 'correction_requested' &&
				disposition.reason_code.endsWith('_correction_required')) ||
			(disposition.to_disposition === 'unable_to_complete' &&
				[
					'insufficient_evidence',
					'conflicting_information',
					'insufficient_authority_or_scope',
					'other_unresolved'
				].includes(disposition.reason_code));
		if (!reasonMatches) {
			context.addIssue({
				code: 'custom',
				message: 'review disposition reason must match the target disposition'
			});
		}
	});

export const regulatoryApplicabilityReviewSchema = applicabilityBaseSchema
	.extend({
		computed_non_binding_result: applicabilityResultSchema,
		review_state: z.enum([
			'not_reviewable',
			'not_reviewed',
			'no_correction_requested',
			'correction_requested',
			'unable_to_complete'
		]),
		workflow_attention: z.enum(['needs_review', 'reviewed_nonbinding']),
		latest_disposition: reviewDispositionSchema.nullable()
	})
	.superRefine((value, context) => {
		if (value.evaluation_status === 'not_evaluated') {
			if (
				value.decision !== null ||
				value.computed_non_binding_result !== 'needs_review' ||
				value.review_state !== 'not_reviewable' ||
				value.workflow_attention !== 'needs_review' ||
				value.latest_disposition !== null
			) {
				context.addIssue({
					code: 'custom',
					message: 'not_evaluated review state must remain not_reviewable and needs_review'
				});
			}
			return;
		}

		if (
			value.decision === null ||
			value.computed_non_binding_result !== value.decision.result ||
			(value.latest_disposition === null && value.review_state !== 'not_reviewed') ||
			(value.latest_disposition !== null &&
				(value.review_state !== value.latest_disposition.to_disposition ||
					value.latest_disposition.decision_semantic_payload_sha256 !==
						value.decision.semantic_payload_sha256))
		) {
			context.addIssue({
				code: 'custom',
				message: 'evaluated review state must match its decision and latest disposition'
			});
		}

		const expectedAttention =
			value.latest_disposition?.to_disposition === 'no_correction_requested' &&
			value.computed_non_binding_result !== 'needs_review'
				? 'reviewed_nonbinding'
				: 'needs_review';
		if (value.workflow_attention !== expectedAttention) {
			context.addIssue({
				code: 'custom',
				message: 'workflow attention must follow the non-binding review state matrix'
			});
		}
	});

export const regulatoryEntityOptionSchema = z.object({
	id: z.string().uuid(),
	name: z.string(),
	ref_id: z.string().optional()
});

function paginatedSchema<T extends z.ZodType>(item: T) {
	return z.object({
		count: z.number().int().nonnegative(),
		next: z.string().nullable(),
		previous: z.string().nullable(),
		results: z.array(item)
	});
}

const regulatoryDocumentPageSchema = paginatedSchema(regulatoryDocumentSummarySchema);
const regulatoryEntityPageSchema = paginatedSchema(regulatoryEntityOptionSchema);

export function parseRegulatoryDocumentPage(
	payload: unknown
): PaginatedResponse<RegulatoryDocumentSummary> {
	return regulatoryDocumentPageSchema.parse(
		payload
	) as PaginatedResponse<RegulatoryDocumentSummary>;
}

export function parseRegulatoryEntityPage(
	payload: unknown
): PaginatedResponse<RegulatoryEntityOption> {
	return regulatoryEntityPageSchema.parse(payload) as PaginatedResponse<RegulatoryEntityOption>;
}

export function parseRegulatoryDocumentDetail(payload: unknown): RegulatoryDocumentDetail {
	return regulatoryDocumentDetailSchema.parse(payload) as RegulatoryDocumentDetail;
}

export function parseRegulatoryApplicability(payload: unknown): RegulatoryApplicability {
	return regulatoryApplicabilitySchema.parse(payload) as RegulatoryApplicability;
}

export function parseRegulatoryApplicabilityReview(
	payload: unknown
): RegulatoryApplicabilityReview {
	return regulatoryApplicabilityReviewSchema.parse(payload) as RegulatoryApplicabilityReview;
}
