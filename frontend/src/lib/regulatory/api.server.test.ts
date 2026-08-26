import { describe, expect, it, vi } from 'vitest';

import { fetchRegulatoryReadPanel } from './api.server';

describe('fetchRegulatoryReadPanel', () => {
	it('uses GET and returns a parsed independent panel', async () => {
		const fetchFn = vi.fn(
			async () =>
				new Response(JSON.stringify({ value: 'synthetic' }), {
					status: 200,
					headers: { 'Content-Type': 'application/json' }
				})
		) as unknown as typeof fetch;

		await expect(
			fetchRegulatoryReadPanel(fetchFn, 'http://localhost/api/panel/', (payload) => {
				if (!payload || typeof payload !== 'object' || !('value' in payload)) {
					throw new TypeError('invalid payload');
				}
				return String(payload.value);
			})
		).resolves.toEqual({ state: 'ok', data: 'synthetic' });
		expect(fetchFn).toHaveBeenCalledWith('http://localhost/api/panel/', {
			method: 'GET',
			headers: { Accept: 'application/json' }
		});
	});

	it('fails closed on malformed 200 payloads', async () => {
		const fetchFn = vi.fn(
			async () => new Response('{}', { status: 200 })
		) as unknown as typeof fetch;

		await expect(
			fetchRegulatoryReadPanel(fetchFn, 'http://localhost/api/panel/', () => {
				throw new TypeError('contract drift');
			})
		).resolves.toEqual({ state: 'unavailable', data: null });
	});

	it('maps access and session failures without parsing response bodies', async () => {
		for (const [status, state] of [
			[401, 'unauthenticated'],
			[403, 'restricted'],
			[404, 'restricted'],
			[503, 'unavailable']
		] as const) {
			const parse = vi.fn();
			const fetchFn = vi.fn(async () => new Response(null, { status })) as unknown as typeof fetch;
			await expect(
				fetchRegulatoryReadPanel(fetchFn, 'http://localhost/api/panel/', parse)
			).resolves.toEqual({ state, data: null });
			expect(parse).not.toHaveBeenCalled();
		}
	});
});
