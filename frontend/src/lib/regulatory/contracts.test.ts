import { describe, expect, it } from 'vitest';

import {
	parseRegulatoryApplicability,
	parseRegulatoryApplicabilityReview,
	parseRegulatoryDocumentDetail,
	parseRegulatoryDocumentPage,
	parseRegulatoryEntityPage,
	regulatorySourceHashSchema
} from './contracts';

const summary = {
	id: '4819de76-fce4-4a1c-bb3b-e97d80b61ab7',
	record_id: 'SYNTHETIC-DOC-001',
	title_zh: '合成外规',
	title_en: 'Synthetic regulation',
	issuer: 'Synthetic issuer',
	authority_level: 'departmental_rule',
	territories: ['CN'],
	regulated_entity_scopes: ['bank'],
	domains: ['banking'],
	coverage_priority: 'P0',
	coverage_stage: 'obligations_proposed',
	applicability_fact_keys: ['entity.institution_type'],
	selection_rationale: 'Synthetic test only',
	folder: {}
};

const hash = 'a'.repeat(64);
const selectedRecordedAt = '2026-08-26T09:30:00+08:00';
const entityId = '3dd2af97-4c34-4e51-82b8-ceb92645e784';
const documentId = summary.id;
const provenance = {
	method: 'human',
	created_at: selectedRecordedAt,
	created_by: 'synthetic-test',
	parser_version: null,
	model: null,
	prompt_version: null,
	retrieval_version: null
};
const obligation = {
	id: 'aa9043ef-cf3b-4a5d-8b91-035b58331b55',
	record_id: 'SYNTHETIC-OBLIGATION-001',
	revision: 1,
	title_zh: '合成义务',
	authority_level: 'departmental_rule',
	modality: 'must',
	subject: '合成银行',
	action: '执行合成控制',
	object: null,
	conditions: [],
	exceptions: [],
	deadline: { kind: 'none', value: null, rule_id: null },
	expected_evidence: [],
	penalty_or_consequence: null,
	valid_from: null,
	valid_to: null,
	recorded_from: selectedRecordedAt,
	recorded_to: null,
	review_status: 'machine_proposed',
	confidence: '0.6500',
	uncertainties: [],
	provenance,
	provision_ids: ['SYNTHETIC-PROVISION-001'],
	legal_conclusion: false
};
const provision = {
	id: 'f603a90b-2803-4c3e-b5f4-458e4ff5c560',
	record_id: 'SYNTHETIC-PROVISION-001',
	revision: 1,
	article: '第一条',
	heading: null,
	text: null,
	source_locator: { kind: 'article', value: '第一条' },
	content_hash: hash,
	recorded_from: selectedRecordedAt,
	recorded_to: null,
	provenance,
	obligations: [obligation]
};
const version = {
	id: '4af48d0d-4be4-48ff-8d29-37c27df38513',
	record_id: 'SYNTHETIC-VERSION-001',
	revision: 1,
	version_label: 'v1',
	document_no: null,
	status: 'effective',
	status_as_of: '2026-08-26',
	effective_basis: 'explicit_date',
	issued_date: null,
	published_date: null,
	effective_date: '2026-08-26',
	transition_end: null,
	repeal_date: null,
	supersedes_version_ids: [],
	source_url: 'https://regulator.example/source',
	source_hash: null,
	content_storage_policy: 'metadata_only',
	notes: 'Synthetic metadata only.',
	source_checked_on: '2026-08-26',
	metadata_confidence: 'confirmed',
	legal_review_status: 'unreviewed',
	legal_reviewed_at: null,
	legal_reviewed_by: null,
	valid_from: '2026-08-26',
	valid_to: null,
	recorded_from: selectedRecordedAt,
	recorded_to: null,
	provenance,
	provisions: [provision]
};
const detail = {
	...summary,
	contract_status: 'draft',
	legal_conclusion: false,
	recorded_as_of: null,
	document_versions: [version]
};
const decision = {
	id: 'b802312e-4d22-428e-b8fa-6612db4bfb4e',
	record_id: 'SYNTHETIC-DECISION-001',
	revision: 1,
	fact_snapshot_id: 'SYNTHETIC-FACT-SNAPSHOT-001',
	scope: { type: 'legal_entity', id: entityId },
	rule: {
		id: 'SYNTHETIC-ENTITY-INSTITUTION-TYPE-BANK-001',
		version: 1,
		all: [{ fact: 'entity.institution_type', operator: 'eq', value: 'bank' }],
		any: [],
		unknown_result: 'needs_review'
	},
	facts: [
		{
			fact: 'entity.institution_type',
			known: false,
			source_refs: [],
			observed_at: null
		}
	],
	missing_fact_keys: ['entity.institution_type'],
	result: 'needs_review',
	rationale_code: 'missing_or_unknown_fact',
	rationale: 'The required institution-type fact was missing and was recorded as unknown.',
	valid_from: null,
	valid_to: null,
	recorded_from: selectedRecordedAt,
	recorded_to: null,
	review_status: 'draft',
	is_binding: false,
	digest_schema: 'regulatory-applicability-evaluation/v1',
	evaluator_profile: 'synthetic-single-condition/v1',
	rule_snapshot_sha256: hash,
	fact_snapshot_sha256: hash,
	semantic_payload_sha256: hash,
	provenance,
	legal_conclusion: false
};
const applicabilityBase = {
	contract_status: 'draft',
	legal_conclusion: false,
	is_binding: false,
	scope: { type: 'legal_entity', id: entityId },
	document_id: documentId,
	obligation_id: 'SYNTHETIC-OBLIGATION-001',
	obligation_revision: 1,
	recorded_as_of: null,
	selected_recorded_at: selectedRecordedAt,
	evaluation_status: 'evaluated',
	decision
};

describe('regulatory runtime contracts', () => {
	it('accepts a complete paginated document summary', () => {
		expect(
			parseRegulatoryDocumentPage({ count: 1, next: null, previous: null, results: [summary] })
		).toEqual({ count: 1, next: null, previous: null, results: [summary] });
	});

	it('projects every backend folder representation to an empty PageData object', () => {
		const page = parseRegulatoryDocumentPage({
			count: 1,
			next: null,
			previous: null,
			results: [
				{
					...summary,
					folder: {
						id: '3dd2af97-4c34-4e51-82b8-ceb92645e784',
						name: 'must not reach PageData',
						unsafe_markup: '<script>must-not-reach-page-data</script>'
					}
				}
			]
		});

		expect(page.results[0].folder).toEqual({});
		expect(JSON.stringify(page)).not.toContain('must-not-reach-page-data');
	});

	it('rejects malformed pagination and incomplete document items', () => {
		expect(() =>
			parseRegulatoryDocumentPage({ count: 1, next: null, previous: null, results: [] })
		).not.toThrow();
		expect(() =>
			parseRegulatoryDocumentPage({ count: '1', next: null, previous: null, results: [summary] })
		).toThrow();
		expect(() =>
			parseRegulatoryDocumentPage({
				count: 1,
				next: null,
				previous: null,
				results: [{ id: summary.id, title_zh: summary.title_zh }]
			})
		).toThrow();
	});

	it('accepts every source-hash shape allowed by the backend model', () => {
		expect(regulatorySourceHashSchema.parse(null)).toBeNull();
		expect(regulatorySourceHashSchema.parse('')).toBe('');
		expect(regulatorySourceHashSchema.parse(hash)).toBe(hash);
		expect(() => regulatorySourceHashSchema.parse('not-a-sha256')).toThrow();
		expect(() => regulatorySourceHashSchema.parse('A'.repeat(64))).toThrow();
	});

	it.each([null, '', hash])('accepts the Phase 1 detail source_hash shape %#', (sourceHash) => {
		const parsed = parseRegulatoryDocumentDetail({
			...detail,
			document_versions: [{ ...version, source_hash: sourceHash }]
		});

		expect(parsed.document_versions[0].source_hash).toBe(sourceHash);
	});

	it.each([null, ''])('accepts only an empty Phase 1 provision body %#', (text) => {
		const parsed = parseRegulatoryDocumentDetail({
			...detail,
			document_versions: [{ ...version, provisions: [{ ...provision, text }] }]
		});

		expect(parsed.document_versions[0].provisions[0].text).toBe(text);
	});

	it('rejects hydrated provision text from a successful detail response', () => {
		expect(() =>
			parseRegulatoryDocumentDetail({
				...detail,
				document_versions: [
					{
						...version,
						provisions: [{ ...provision, text: 'Unlicensed official source text' }]
					}
				]
			})
		).toThrow();
	});

	it.each(['official_snapshot', 'licensed_copy'])('rejects non-metadata policy %s', (policy) => {
		expect(() =>
			parseRegulatoryDocumentDetail({
				...detail,
				document_versions: [{ ...version, content_storage_policy: policy }]
			})
		).toThrow();
	});

	it('strips free-text version notes before they enter PageData', () => {
		const parsed = parseRegulatoryDocumentDetail({
			...detail,
			document_versions: [{ ...version, notes: 'must-not-reach-page-data' }]
		});
		expect(parsed.document_versions[0].notes).toBe('');
		expect(JSON.stringify(parsed)).not.toContain('must-not-reach-page-data');
	});

	it.each([['  https://regulator.example  ', 'https://regulator.example/']])(
		'canonicalizes official HTTPS URL %s before it enters PageData',
		(input, canonical) => {
			const parsed = parseRegulatoryDocumentDetail({
				...detail,
				document_versions: [{ ...version, source_url: input }]
			});

			expect(parsed.document_versions[0].source_url).toBe(canonical);
		}
	);

	it.each([
		'http://regulator.example/source',
		'https://user:secret@regulator.example/source',
		'https://@regulator.example/source',
		'javascript:alert(document.domain)',
		'data:text/html,<script>alert(1)</script>',
		'ftp://regulator.example/source'
	])('rejects unsafe official source URL %s', (sourceUrl) => {
		expect(() =>
			parseRegulatoryDocumentDetail({
				...detail,
				document_versions: [{ ...version, source_url: sourceUrl }]
			})
		).toThrow();
	});

	it('fails closed when a successful detail response omits the citation chain', () => {
		expect(() =>
			parseRegulatoryDocumentDetail({
				...summary,
				contract_status: 'draft',
				legal_conclusion: false,
				recorded_as_of: null,
				document_versions: []
			})
		).toThrow();
	});

	it.each([
		[
			'extra provision',
			{
				...version,
				provisions: [provision, { ...provision, record_id: 'SYNTHETIC-PROVISION-002' }]
			}
		],
		[
			'extra obligation',
			{
				...version,
				provisions: [
					{
						...provision,
						obligations: [obligation, { ...obligation, record_id: 'SYNTHETIC-OBLIGATION-002' }]
					}
				]
			}
		],
		[
			'mismatched provision reference',
			{
				...version,
				provisions: [
					{
						...provision,
						obligations: [{ ...obligation, provision_ids: ['SYNTHETIC-PROVISION-OTHER'] }]
					}
				]
			}
		],
		[
			'mismatched recorded epoch',
			{
				...version,
				provisions: [
					{
						...provision,
						recorded_from: '2026-08-26T09:30:00.000001+08:00'
					}
				]
			}
		]
	])('rejects a response-spliced detail chain with %s', (_case, splicedVersion) => {
		expect(() =>
			parseRegulatoryDocumentDetail({ ...detail, document_versions: [splicedVersion] })
		).toThrow();
	});

	it('projects only the safe entity option fields', () => {
		const page = parseRegulatoryEntityPage({
			count: 1,
			next: null,
			previous: null,
			results: [
				{
					id: '3dd2af97-4c34-4e51-82b8-ceb92645e784',
					name: 'Synthetic bank',
					ref_id: 'SYNTHETIC-BANK',
					description: 'must not reach the page data'
				}
			]
		});
		expect(page.results).toEqual([
			{
				id: '3dd2af97-4c34-4e51-82b8-ceb92645e784',
				name: 'Synthetic bank',
				ref_id: 'SYNTHETIC-BANK'
			}
		]);
	});

	it('rejects an applicability response that claims binding authority', () => {
		expect(() =>
			parseRegulatoryApplicability({
				contract_status: 'draft',
				legal_conclusion: false,
				is_binding: true
			})
		).toThrow();
	});

	it('accepts unknown facts only as a non-binding needs-review result', () => {
		expect(
			parseRegulatoryApplicability({
				...applicabilityBase,
				non_binding_result: 'needs_review',
				reason_code: 'missing_or_unknown_fact'
			}).non_binding_result
		).toBe('needs_review');

		expect(() =>
			parseRegulatoryApplicability({
				...applicabilityBase,
				non_binding_result: 'not_applicable',
				reason_code: 'rule_not_satisfied'
			})
		).toThrow();

		expect(() =>
			parseRegulatoryApplicability({
				...applicabilityBase,
				decision: {
					...decision,
					result: 'not_applicable',
					rationale_code: 'rule_not_satisfied'
				},
				non_binding_result: 'not_applicable',
				reason_code: 'rule_not_satisfied'
			})
		).toThrow();
	});

	it('distinguishes an explicit unknown institution fact from a missing fact', () => {
		const explicitUnknownDecision = {
			...decision,
			missing_fact_keys: [],
			rationale: 'The required institution-type fact is explicitly unknown.'
		};

		expect(
			parseRegulatoryApplicability({
				...applicabilityBase,
				decision: explicitUnknownDecision,
				non_binding_result: 'needs_review',
				reason_code: 'missing_or_unknown_fact'
			}).decision?.missing_fact_keys
		).toEqual([]);

		expect(() =>
			parseRegulatoryApplicability({
				...applicabilityBase,
				decision: { ...explicitUnknownDecision, rationale: decision.rationale },
				non_binding_result: 'needs_review',
				reason_code: 'missing_or_unknown_fact'
			})
		).toThrow();
	});

	it('recomputes applicable from the exact known bank fact', () => {
		const knownBankDecision = {
			...decision,
			facts: [
				{
					fact: 'entity.institution_type',
					known: true,
					value: 'bank',
					source_refs: ['official:synthetic-register'],
					observed_at: '2026-08-26T09:00:00+08:00'
				}
			],
			missing_fact_keys: [],
			result: 'applicable',
			rationale_code: 'rule_satisfied',
			rationale: 'The known institution type matches the fixed synthetic bank rule.'
		};

		expect(
			parseRegulatoryApplicability({
				...applicabilityBase,
				decision: knownBankDecision,
				non_binding_result: 'applicable',
				reason_code: 'rule_satisfied'
			}).non_binding_result
		).toBe('applicable');

		for (const candidateDecision of [
			{ ...knownBankDecision, missing_fact_keys: ['entity.institution_type'] },
			{
				...knownBankDecision,
				result: 'not_applicable',
				rationale_code: 'rule_not_satisfied',
				rationale: 'The known institution type does not match the fixed synthetic bank rule.'
			}
		]) {
			expect(() =>
				parseRegulatoryApplicability({
					...applicabilityBase,
					decision: candidateDecision,
					non_binding_result: candidateDecision.result,
					reason_code: candidateDecision.rationale_code
				})
			).toThrow();
		}
	});

	it('recomputes not-applicable from an exact known non-bank fact', () => {
		const knownNonBankDecision = {
			...decision,
			facts: [
				{
					fact: 'entity.institution_type',
					known: true,
					value: 'insurance',
					source_refs: ['official:synthetic-register'],
					observed_at: '2026-08-26T09:00:00+08:00'
				}
			],
			missing_fact_keys: [],
			result: 'not_applicable',
			rationale_code: 'rule_not_satisfied',
			rationale: 'The known institution type does not match the fixed synthetic bank rule.'
		};

		expect(
			parseRegulatoryApplicability({
				...applicabilityBase,
				decision: knownNonBankDecision,
				non_binding_result: 'not_applicable',
				reason_code: 'rule_not_satisfied'
			}).non_binding_result
		).toBe('not_applicable');
	});

	it('requires one exact institution_type fact', () => {
		for (const facts of [
			[],
			[...decision.facts, ...decision.facts],
			[{ ...decision.facts[0], fact: 'entity.country' }]
		]) {
			expect(() =>
				parseRegulatoryApplicability({
					...applicabilityBase,
					decision: { ...decision, facts },
					non_binding_result: 'needs_review',
					reason_code: 'missing_or_unknown_fact'
				})
			).toThrow();
		}
	});

	it('enforces the known fact evidence and observation contract', () => {
		const knownFact = {
			fact: 'entity.institution_type',
			known: true,
			value: 'bank',
			source_refs: ['official:synthetic-register'],
			observed_at: '2026-08-26T09:00:00+08:00'
		};
		const knownDecision = {
			...decision,
			facts: [knownFact],
			missing_fact_keys: [],
			result: 'applicable',
			rationale_code: 'rule_satisfied',
			rationale: 'The known institution type matches the fixed synthetic bank rule.'
		};

		for (const fact of [
			{ ...knownFact, source_refs: [] },
			{ ...knownFact, source_refs: ['official:duplicate', 'official:duplicate'] },
			{ ...knownFact, source_refs: ['   '] },
			{ ...knownFact, observed_at: null },
			{ ...knownFact, observed_at: '2026-08-26T09:00:00' },
			{ ...knownFact, observed_at: '2026-08-26T09:31:00+08:00' }
		]) {
			expect(() =>
				parseRegulatoryApplicability({
					...applicabilityBase,
					decision: { ...knownDecision, facts: [fact] },
					non_binding_result: 'applicable',
					reason_code: 'rule_satisfied'
				})
			).toThrow();
		}

		expect(() =>
			parseRegulatoryApplicability({
				...applicabilityBase,
				decision: {
					...knownDecision,
					recorded_from: '2026-08-26T01:30:00.000400Z',
					facts: [{ ...knownFact, observed_at: '2026-08-26T01:30:00.000500Z' }]
				},
				non_binding_result: 'applicable',
				reason_code: 'rule_satisfied'
			})
		).toThrow();
	});

	it('forbids values, evidence, or observation times on unknown facts', () => {
		for (const fact of [
			{ ...decision.facts[0], value: 'bank' },
			{ ...decision.facts[0], source_refs: ['official:forged'] },
			{ ...decision.facts[0], observed_at: '2026-08-26T09:00:00+08:00' }
		]) {
			expect(() =>
				parseRegulatoryApplicability({
					...applicabilityBase,
					decision: { ...decision, facts: [fact] },
					non_binding_result: 'needs_review',
					reason_code: 'missing_or_unknown_fact'
				})
			).toThrow();
		}
	});

	it('does not let no-correction disposition clear unresolved workflow attention', () => {
		const payload = {
			...applicabilityBase,
			computed_non_binding_result: 'needs_review',
			review_state: 'no_correction_requested',
			workflow_attention: 'needs_review',
			latest_disposition: {
				id: '725d5f66-81bb-4796-81bc-a630e46e6391',
				sequence: 1,
				from_disposition: 'not_reviewed',
				to_disposition: 'no_correction_requested',
				reason_code: 'review_completed',
				rationale: 'No correction was requested for this exact synthetic record.',
				occurred_at: selectedRecordedAt,
				digest_profile: 'regulatory-applicability-review-disposition/v1',
				decision_semantic_payload_sha256: hash,
				event_payload_sha256: hash,
				reviewer: { masked: true }
			}
		};

		expect(parseRegulatoryApplicabilityReview(payload).workflow_attention).toBe('needs_review');
		expect(() =>
			parseRegulatoryApplicabilityReview({ ...payload, workflow_attention: 'reviewed_nonbinding' })
		).toThrow();
	});

	it('requires the explicit not-evaluated review matrix', () => {
		const payload = {
			...applicabilityBase,
			evaluation_status: 'not_evaluated',
			decision: null,
			computed_non_binding_result: 'needs_review',
			review_state: 'not_reviewable',
			workflow_attention: 'needs_review',
			latest_disposition: null
		};

		expect(parseRegulatoryApplicabilityReview(payload).review_state).toBe('not_reviewable');
		expect(() =>
			parseRegulatoryApplicabilityReview({ ...payload, review_state: 'not_reviewed' })
		).toThrow();
	});
});
