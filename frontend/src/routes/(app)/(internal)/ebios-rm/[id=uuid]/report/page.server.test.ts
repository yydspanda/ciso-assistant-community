import { describe, expect, it, vi } from 'vitest';

import { load } from './+page.server';

const studyId = '9f707f22-ecb2-4fe3-a9cc-3c95c34f30d0';

const callLoad = async (fetchFn: typeof fetch, parent = vi.fn().mockResolvedValue({})) =>
	await (load as (event: unknown) => Promise<Record<string, unknown>>)({
		fetch: fetchFn,
		params: { id: studyId },
		parent
	});

describe('EBIOS RM report server loader', () => {
	it.each([401, 403, 404, 503])('preserves a report API %s response', async (status) => {
		const fetchFn = vi.fn().mockResolvedValue(
			new Response(JSON.stringify({ detail: 'unavailable' }), {
				status,
				headers: { 'Content-Type': 'application/json' }
			})
		) as unknown as typeof fetch;
		const parent = vi.fn().mockResolvedValue({});

		await expect(callLoad(fetchFn, parent)).rejects.toMatchObject({ status });
		expect(fetchFn).toHaveBeenCalledTimes(1);
		expect(parent).not.toHaveBeenCalled();
	});

	it('returns report, interface, and feature-flag data after successful reads', async () => {
		const reportData = { study: { id: studyId, name: 'Visible study' } };
		const fetchFn = vi.fn().mockImplementation(async (input: string | URL | Request) => {
			const url = String(input);
			const payload = url.includes('/report-data/')
				? reportData
				: { interface_agg_scenario_matrix: true };
			return new Response(JSON.stringify(payload), {
				status: 200,
				headers: { 'Content-Type': 'application/json' }
			});
		}) as unknown as typeof fetch;

		await expect(
			callLoad(fetchFn, vi.fn().mockResolvedValue({ featureflags: { inherent_risk: true } }))
		).resolves.toEqual({
			reportData,
			useBubbles: true,
			inherentRiskEnabled: true
		});
	});
});
