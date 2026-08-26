import { describe, expect, it, vi } from 'vitest';

import { load } from './+page.server';

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

const userWithDocumentPermission = {
	domain_permissions: { 'synthetic-folder': ['view_regulatorydocument'] }
};

const callLoad = async ({
	url = 'http://localhost/regulatory',
	fetchFn,
	user = userWithDocumentPermission
}: {
	url?: string;
	fetchFn: typeof fetch;
	user?: Record<string, unknown>;
}) =>
	await (load as (event: unknown) => Promise<Record<string, unknown>>)({
		fetch: fetchFn,
		url: new URL(url),
		locals: { user }
	});

describe('regulatory register server loader', () => {
	it('does not call the API when the local navigation permission is absent', async () => {
		const fetchFn = vi.fn() as unknown as typeof fetch;

		await expect(callLoad({ fetchFn, user: { domain_permissions: {} } })).resolves.toMatchObject({
			state: 'restricted',
			documents: [],
			count: 0
		});
		expect(fetchFn).not.toHaveBeenCalled();
	});

	it('forwards only supported filters with bounded pagination', async () => {
		const fetchFn = vi.fn(
			async () =>
				new Response(JSON.stringify({ count: 1, next: null, previous: null, results: [summary] }), {
					status: 200,
					headers: { 'Content-Type': 'application/json' }
				})
		) as unknown as typeof fetch;

		const result = await callLoad({
			fetchFn,
			url: 'http://localhost/regulatory?search=%E6%95%B0%E6%8D%AE&authority_level=departmental_rule&coverage_stage=obligations_proposed&page=2&recorded_as_of=must-not-forward'
		});

		expect(result).toMatchObject({ state: 'ok', count: 1, documents: [summary] });
		expect(fetchFn).toHaveBeenCalledOnce();
		const [requestUrl, init] = vi.mocked(fetchFn).mock.calls[0];
		expect(String(requestUrl)).toBe(
			'http://localhost:8000/api/regulatory/v1/documents/?limit=25&offset=25&ordering=record_id&search=%E6%95%B0%E6%8D%AE&authority_level=departmental_rule&coverage_stage=obligations_proposed'
		);
		expect(init).toEqual({ method: 'GET', headers: { Accept: 'application/json' } });
	});

	it.each([
		[401, 'unauthenticated'],
		[403, 'restricted'],
		[404, 'unavailable'],
		[503, 'unavailable']
	] as const)('maps list HTTP %s to %s rather than an empty register', async (status, state) => {
		const fetchFn = vi.fn(async () => new Response(null, { status })) as unknown as typeof fetch;
		await expect(callLoad({ fetchFn })).resolves.toMatchObject({ state, documents: [], count: 0 });
	});

	it('fails closed when a 200 response drifts from the runtime contract', async () => {
		const fetchFn = vi.fn(
			async () => new Response(JSON.stringify({ count: 1, results: [summary] }), { status: 200 })
		) as unknown as typeof fetch;

		await expect(callLoad({ fetchFn })).resolves.toMatchObject({
			state: 'unavailable',
			documents: [],
			count: 0
		});
	});
});
