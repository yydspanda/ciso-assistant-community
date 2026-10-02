import { describe, expect, it, vi } from 'vitest';

import { load } from './+page.server';

const documentId = '4819de76-fce4-4a1c-bb3b-e97d80b61ab7';
const selectedEntityId = '3dd2af97-4c34-4e51-82b8-ceb92645e784';
const selectedRecordedAt = '2026-08-26T01:30:00Z';
const hash = 'a'.repeat(64);
const userWithSecondaryReadPermissions = {
	permission_sets: [['view_entity', 'view_regulatoryapplicabilitydecision']],
	domain_permissions: {
		'synthetic-folder': 0
	}
};

const provenance = {
	method: 'human',
	created_at: selectedRecordedAt,
	created_by: 'synthetic-test',
	parser_version: null,
	model: null,
	prompt_version: null,
	retrieval_version: null
};

const document = {
	id: documentId,
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
	folder: {},
	contract_status: 'draft',
	legal_conclusion: false,
	recorded_as_of: null,
	document_versions: [
		{
			id: 'f4f9b623-e146-4132-8412-a15a55e2af8d',
			record_id: 'SYNTHETIC-VERSION-001',
			revision: 1,
			version_label: 'v1',
			document_no: null,
			status: 'effective',
			status_as_of: '2026-08-25',
			effective_basis: 'explicit_date',
			issued_date: '2026-08-25',
			published_date: '2026-08-25',
			effective_date: '2026-08-25',
			transition_end: null,
			repeal_date: null,
			supersedes_version_ids: [],
			source_url: 'https://example.test/regulation',
			source_hash: null,
			content_storage_policy: 'metadata_only',
			notes: 'Synthetic test only',
			source_checked_on: '2026-08-25',
			metadata_confidence: 'confirmed',
			legal_review_status: 'unreviewed',
			legal_reviewed_at: null,
			legal_reviewed_by: null,
			valid_from: '2026-08-25',
			valid_to: null,
			recorded_from: '2026-08-25T00:00:00Z',
			recorded_to: null,
			provenance,
			provisions: [
				{
					id: '2c4d9ba2-4e12-42e4-b25a-2fd4dc24c11c',
					record_id: 'SYNTHETIC-PROVISION-001',
					revision: 1,
					article: 'Article 1',
					heading: null,
					text: null,
					source_locator: { kind: 'article', value: 'Article 1' },
					content_hash: hash,
					recorded_from: '2026-08-25T00:00:00Z',
					recorded_to: null,
					provenance,
					obligations: [
						{
							id: '5adbbdd8-33f5-4e35-8bb4-d87dd17cc94b',
							record_id: 'SYNTHETIC-OBLIGATION-001',
							revision: 1,
							title_zh: '合成义务',
							authority_level: 'departmental_rule',
							modality: 'must',
							subject: 'bank',
							action: 'review',
							object: null,
							conditions: [],
							exceptions: [],
							deadline: { kind: 'none', value: null, rule_id: null },
							expected_evidence: [],
							penalty_or_consequence: null,
							valid_from: '2026-08-25',
							valid_to: null,
							recorded_from: '2026-08-25T00:00:00Z',
							recorded_to: null,
							review_status: 'machine_proposed',
							confidence: '0.9',
							uncertainties: [],
							provenance,
							provision_ids: ['SYNTHETIC-PROVISION-001'],
							legal_conclusion: false
						}
					]
				}
			]
		}
	]
};

const applicability = {
	contract_status: 'draft',
	legal_conclusion: false,
	is_binding: false,
	scope: { type: 'legal_entity', id: selectedEntityId },
	document_id: documentId,
	obligation_id: 'SYNTHETIC-OBLIGATION-001',
	obligation_revision: 1,
	recorded_as_of: null,
	selected_recorded_at: selectedRecordedAt,
	evaluation_status: 'not_evaluated',
	non_binding_result: 'needs_review',
	reason_code: 'no_decision_for_selected_obligation_revision',
	decision: null
};

const review = {
	contract_status: 'draft',
	legal_conclusion: false,
	is_binding: false,
	scope: { type: 'legal_entity', id: selectedEntityId },
	document_id: documentId,
	obligation_id: 'SYNTHETIC-OBLIGATION-001',
	obligation_revision: 1,
	recorded_as_of: selectedRecordedAt,
	selected_recorded_at: selectedRecordedAt,
	evaluation_status: 'not_evaluated',
	computed_non_binding_result: 'needs_review',
	decision: null,
	review_state: 'not_reviewable',
	workflow_attention: 'needs_review',
	latest_disposition: null
};

const jsonResponse = (payload: unknown) =>
	new Response(JSON.stringify(payload), {
		status: 200,
		headers: { 'Content-Type': 'application/json' }
	});

const callLoad = async ({
	url = `http://localhost/regulatory/${documentId}`,
	fetchFn
}: {
	url?: string;
	fetchFn: typeof fetch;
}) =>
	await (load as (event: unknown) => Promise<Record<string, unknown>>)({
		fetch: fetchFn,
		params: { id: documentId },
		url: new URL(url),
		locals: { user: userWithSecondaryReadPermissions }
	});

describe('regulatory detail server loader fail-closed gates', () => {
	it('rejects repeated or timezone-naive recorded selections without calling APIs', async () => {
		for (const query of [
			'recorded_as_of=2026-08-26T09%3A30%3A00',
			'recorded_as_of=2026-02-30T09%3A30%3A00Z',
			'recorded_as_of=2026-08-26T09%3A30%3A00%2B08%3A00&recorded_as_of=2026-08-25T09%3A30%3A00%2B08%3A00'
		]) {
			const fetchFn = vi.fn() as unknown as typeof fetch;
			await expect(
				callLoad({
					fetchFn,
					url: `http://localhost/regulatory/${documentId}?${query}`
				})
			).resolves.toMatchObject({
				documentState: 'invalid',
				document: null,
				recordedAsOf: ''
			});
			expect(fetchFn).not.toHaveBeenCalled();
		}
	});

	it('does not hydrate or call APIs for invalid and oversized selection values', async () => {
		for (const query of [
			'entity=not-a-uuid',
			`entity=${'a'.repeat(4000)}`,
			`recorded_as_of=${'2'.repeat(4000)}`
		]) {
			const fetchFn = vi.fn() as unknown as typeof fetch;
			await expect(
				callLoad({
					fetchFn,
					url: `http://localhost/regulatory/${documentId}?${query}`
				})
			).resolves.toMatchObject({
				documentState: 'invalid',
				selectedEntity: '',
				recordedAsOf: ''
			});
			expect(fetchFn).not.toHaveBeenCalled();
		}
	});

	it.each([
		[401, 'unauthenticated'],
		[404, 'restricted'],
		[503, 'unavailable']
	] as const)(
		'keeps a document HTTP %s opaque and does not enumerate entities',
		async (status, state) => {
			const fetchFn = vi.fn(async () => new Response(null, { status })) as unknown as typeof fetch;
			await expect(callLoad({ fetchFn })).resolves.toMatchObject({
				documentState: state,
				document: null,
				entities: []
			});
			expect(fetchFn).toHaveBeenCalledOnce();
			expect(String(vi.mocked(fetchFn).mock.calls[0][0])).toBe(
				`http://localhost:8000/api/regulatory/v1/documents/${documentId}/`
			);
		}
	);

	it('does not enumerate entities after a malformed successful document response', async () => {
		const fetchFn = vi.fn(
			async () =>
				new Response(JSON.stringify({ id: documentId, contract_status: 'draft' }), { status: 200 })
		) as unknown as typeof fetch;

		await expect(callLoad({ fetchFn })).resolves.toMatchObject({
			documentState: 'unavailable',
			document: null,
			entities: []
		});
		expect(fetchFn).toHaveBeenCalledOnce();
	});

	it('calls backend actions for an off-page entity and keeps a standalone review 403 isolated', async () => {
		const fetchFn = vi.fn(async (input: RequestInfo | URL) => {
			const requestedUrl = String(input);
			if (requestedUrl.endsWith(`/regulatory/v1/documents/${documentId}/`)) {
				return jsonResponse(document);
			}
			if (requestedUrl.includes('/entities/?')) return new Response(null, { status: 403 });
			if (requestedUrl.includes('/applicability-review/?')) {
				return new Response(null, { status: 403 });
			}
			if (requestedUrl.includes('/applicability/?')) {
				return jsonResponse(applicability);
			}
			return new Response(null, { status: 500 });
		}) as unknown as typeof fetch;

		const loaded = await callLoad({
			fetchFn,
			url: `http://localhost/regulatory/${documentId}?entity=${selectedEntityId}`
		});

		expect(loaded).toMatchObject({
			documentState: 'ok',
			entityState: 'restricted',
			selectedEntity: selectedEntityId,
			applicability: { state: 'ok' },
			review: { state: 'restricted', data: null }
		});
		expect(loaded.entities).toContainEqual({ id: selectedEntityId, name: selectedEntityId });

		const requestedUrls = vi.mocked(fetchFn).mock.calls.map(([input]) => String(input));
		expect(requestedUrls).toContain(
			`http://localhost:8000/api/regulatory/v1/documents/${documentId}/applicability/?entity=${selectedEntityId}`
		);
		expect(requestedUrls).toContain(
			`http://localhost:8000/api/regulatory/v1/documents/${documentId}/applicability-review/?entity=${selectedEntityId}&recorded_as_of=2026-08-26T01%3A30%3A00Z`
		);
		expect(requestedUrls.some((url) => url.includes(`/entities/${selectedEntityId}`))).toBe(false);
	});

	it('anchors a successful current review to the applicability selection instant', async () => {
		const fetchFn = vi.fn(async (input: RequestInfo | URL) => {
			const requestedUrl = String(input);
			if (requestedUrl.endsWith(`/regulatory/v1/documents/${documentId}/`)) {
				return jsonResponse(document);
			}
			if (requestedUrl.includes('/entities/?')) {
				return jsonResponse({
					count: 1,
					next: null,
					previous: null,
					results: [{ id: selectedEntityId, name: 'Selected entity' }]
				});
			}
			if (requestedUrl.includes('/applicability-review/?')) return jsonResponse(review);
			if (requestedUrl.includes('/applicability/?')) return jsonResponse(applicability);
			return new Response(null, { status: 500 });
		}) as unknown as typeof fetch;

		await expect(
			callLoad({
				fetchFn,
				url: `http://localhost/regulatory/${documentId}?entity=${selectedEntityId.toUpperCase()}&entity_search=%E5%90%88%E6%88%90+%E9%93%B6%E8%A1%8C`
			})
		).resolves.toMatchObject({
			documentState: 'ok',
			selectedEntity: selectedEntityId,
			currentViewHref: `?entity=${selectedEntityId}&entity_search=%E5%90%88%E6%88%90+%E9%93%B6%E8%A1%8C&mode=apply`,
			applicability: { state: 'ok' },
			review: { state: 'ok' }
		});

		const requestedUrls = vi.mocked(fetchFn).mock.calls.map(([input]) => String(input));
		expect(requestedUrls).toContain(
			`http://localhost:8000/api/regulatory/v1/documents/${documentId}/applicability-review/?entity=${selectedEntityId}&recorded_as_of=2026-08-26T01%3A30%3A00Z`
		);
	});

	it.each([
		{ query: '', validOn: '2026-08-26' },
		{
			query: 'version_id=SYNTHETIC-VERSION-001&valid_on=2026-08-26',
			validOn: '2026-08-26'
		},
		{ query: 'version_id=SYNTHETIC-VERSION-001', validOn: null }
	])('pins both dependent reads to the detail selection for %j', async ({ query, validOn }) => {
		const selection = {
			version_id: 'SYNTHETIC-VERSION-001',
			version_revision: 1,
			valid_on: validOn,
			recorded_at: selectedRecordedAt
		};
		const selectedDocument = structuredClone(document);
		if (validOn === null) {
			selectedDocument.document_versions[0].status = 'published_future_effective';
			selectedDocument.document_versions[0].effective_date = '2027-01-01';
			selectedDocument.document_versions[0].valid_from = '2027-01-01';
		}
		const fetchFn = vi.fn(async (input: RequestInfo | URL) => {
			const requestedUrl = new URL(String(input));
			if (requestedUrl.pathname.endsWith(`/documents/${documentId}/`)) {
				return jsonResponse({ ...selectedDocument, selection });
			}
			if (requestedUrl.pathname.endsWith('/entities/')) {
				return jsonResponse({ count: 0, next: null, previous: null, results: [] });
			}
			if (requestedUrl.pathname.endsWith('/applicability/')) {
				return jsonResponse({ ...applicability, recorded_as_of: selectedRecordedAt, selection });
			}
			if (requestedUrl.pathname.endsWith('/applicability-review/')) {
				return jsonResponse({ ...review, selection });
			}
			return new Response(null, { status: 500 });
		}) as unknown as typeof fetch;
		const loaded = await callLoad({
			fetchFn,
			url: `http://localhost/regulatory/${documentId}?entity=${selectedEntityId}${query ? `&${query}` : ''}`
		});
		expect(loaded).toMatchObject({
			documentState: 'ok',
			document: { selection, legal_conclusion: false },
			applicability: { state: 'ok', data: { selection, is_binding: false } },
			review: { state: 'ok', data: { selection, is_binding: false } }
		});
		const urls = vi.mocked(fetchFn).mock.calls.map(([input]) => new URL(String(input)));
		expect(urls[0].searchParams.get('version_id')).toBe(query ? selection.version_id : null);
		expect(urls[0].searchParams.get('valid_on')).toBe(query.includes('valid_on') ? validOn : null);
		const dependentUrls = urls.filter((requestedUrl) =>
			/\/applicability(?:-review)?\/$/.test(requestedUrl.pathname)
		);
		expect(dependentUrls).toHaveLength(2);
		for (const requestedUrl of dependentUrls) {
			expect(requestedUrl.searchParams.get('entity')).toBe(selectedEntityId);
			expect(requestedUrl.searchParams.get('version_id')).toBe(selection.version_id);
			expect(requestedUrl.searchParams.get('valid_on')).toBe(validOn);
			expect(requestedUrl.searchParams.get('recorded_as_of')).toBe(selectedRecordedAt);
		}
		if (validOn === null) {
			expect(loaded).toMatchObject({
				document: { document_versions: [{ status: 'published_future_effective' }] },
				applicability: { data: { non_binding_result: 'needs_review' } },
				review: { data: { workflow_attention: 'needs_review' } }
			});
		}
	});

	it('uses the backend UTC legal date rather than deriving it from the request timezone', async () => {
		const recordedAsOf = '2026-08-26T00:30:00+14:00';
		const selectedAt = '2026-08-25T10:30:00Z';
		const selection = {
			version_id: 'SYNTHETIC-VERSION-001',
			version_revision: 1,
			valid_on: '2026-08-25',
			recorded_at: selectedAt
		};
		const fetchFn = vi.fn(async (input: RequestInfo | URL) => {
			const requestedUrl = new URL(String(input));
			if (requestedUrl.pathname.endsWith(`/documents/${documentId}/`)) {
				return jsonResponse({ ...document, recorded_as_of: recordedAsOf, selection });
			}
			if (requestedUrl.pathname.endsWith('/entities/')) {
				return jsonResponse({ count: 0, next: null, previous: null, results: [] });
			}
			if (requestedUrl.pathname.endsWith('/applicability/')) {
				return jsonResponse({
					...applicability,
					recorded_as_of: selectedAt,
					selected_recorded_at: selectedAt,
					selection
				});
			}
			return jsonResponse({
				...review,
				recorded_as_of: selectedAt,
				selected_recorded_at: selectedAt,
				selection
			});
		}) as unknown as typeof fetch;
		expect(
			await callLoad({
				fetchFn,
				url: `http://localhost/regulatory/${documentId}?entity=${selectedEntityId}&recorded_as_of=${encodeURIComponent(recordedAsOf)}`
			})
		).toMatchObject({
			documentState: 'ok',
			applicability: { state: 'ok' },
			review: { state: 'ok' }
		});
		const urls = vi.mocked(fetchFn).mock.calls.map(([input]) => new URL(String(input)));
		for (const requestedUrl of urls.filter((url) =>
			/\/applicability(?:-review)?\/$/.test(url.pathname)
		)) {
			expect(requestedUrl.searchParams.get('valid_on')).toBe('2026-08-25');
			expect(requestedUrl.searchParams.get('recorded_as_of')).toBe(selectedAt);
		}
	});

	it.each([
		'valid_on=',
		'valid_on=2026-02-30',
		'valid_on=2026-08-26&valid_on=2026-08-27',
		'version_id=',
		'version_id=bad%20version',
		`version_id=${'a'.repeat(161)}`,
		'version_id=SYNTHETIC-VERSION-001&version_id=SYNTHETIC-VERSION-002'
	])('rejects invalid or repeated dual-time selectors without fetching: %s', async (query) => {
		const fetchFn = vi.fn() as unknown as typeof fetch;
		expect(
			await callLoad({ fetchFn, url: `http://localhost/regulatory/${documentId}?${query}` })
		).toMatchObject({ documentState: 'invalid', document: null });
		expect(fetchFn).not.toHaveBeenCalled();
	});

	it('does not silently honour an explicit selector against a legacy response without selection', async () => {
		const fetchFn = vi.fn(async () => jsonResponse(document)) as unknown as typeof fetch;
		expect(
			await callLoad({
				fetchFn,
				url: `http://localhost/regulatory/${documentId}?version_id=SYNTHETIC-VERSION-001`
			})
		).toMatchObject({ documentState: 'unavailable', document: null });
		expect(fetchFn).toHaveBeenCalledOnce();
	});
});
