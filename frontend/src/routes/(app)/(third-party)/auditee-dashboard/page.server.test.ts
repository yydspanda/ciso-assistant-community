import { describe, expect, it, vi } from 'vitest';

vi.mock('$lib/utils/constants', () => ({
	BASE_API_URL: 'http://localhost:8000/api'
}));

vi.mock('$paraglide/messages', () => ({
	m: { auditDashboard: () => 'Audit dashboard' }
}));

import { load } from './+page.server';

const dashboardItem = {
	id: '3dd2af97-4c34-4e51-82b8-ceb92645e784',
	assignment_id: '4819de76-fce4-4a1c-bb3b-e97d80b61ab7',
	name: 'Third-party questionnaire',
	folder: 'Suppliers',
	framework: 'Questionnaire',
	status: 'in_progress',
	assignment_status: 'in_progress',
	actor: 'Supplier representative',
	total_requirements: 4,
	assessed_requirements: 2,
	progress_percent: 50
};

function callLoad(fetchFn: typeof fetch) {
	return (load as (event: { fetch: typeof fetch }) => Promise<Record<string, unknown>>)({
		fetch: fetchFn
	});
}

describe('auditee dashboard loader contract', () => {
	it('returns a validated dashboard array', async () => {
		const fetchFn = vi.fn(async () =>
			Response.json([{ ...dashboardItem, ignored: true }])
		) as unknown as typeof fetch;

		await expect(callLoad(fetchFn)).resolves.toEqual({
			dashboard: [dashboardItem],
			title: 'Audit dashboard'
		});
		expect(fetchFn).toHaveBeenCalledWith(
			'http://localhost:8000/api/compliance-assessments/auditee-dashboard/'
		);
	});

	it.each([401, 403, 500])('preserves backend error status %s', async (status) => {
		const fetchFn = vi.fn(async () =>
			Response.json({ detail: 'failure' }, { status })
		) as unknown as typeof fetch;

		await expect(callLoad(fetchFn)).rejects.toMatchObject({ status });
	});

	it('maps a network failure to a controlled bad-gateway error', async () => {
		const fetchFn = vi.fn(async () => {
			throw new TypeError('fetch failed');
		}) as unknown as typeof fetch;

		await expect(callLoad(fetchFn)).rejects.toMatchObject({ status: 502 });
	});

	it('rejects malformed JSON from a successful response', async () => {
		const fetchFn = vi.fn(
			async () => new Response('<html>failure</html>', { status: 200 })
		) as unknown as typeof fetch;

		await expect(callLoad(fetchFn)).rejects.toMatchObject({ status: 502 });
	});

	it.each([
		{ detail: 'backend error object' },
		[{ ...dashboardItem, assignment_id: 'not-a-uuid' }],
		[{ ...dashboardItem, assignment_status: 'unknown' }],
		[{ ...dashboardItem, assessed_requirements: 5 }],
		[{ ...dashboardItem, progress_percent: null }]
	])('rejects a malformed successful payload', async (payload) => {
		const fetchFn = vi.fn(async () => Response.json(payload)) as unknown as typeof fetch;

		await expect(callLoad(fetchFn)).rejects.toMatchObject({ status: 502 });
	});
});
