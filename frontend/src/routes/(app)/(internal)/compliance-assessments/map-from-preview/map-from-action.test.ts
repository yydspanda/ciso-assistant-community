import { describe, expect, it, vi } from 'vitest';

import { applyMapFrom } from './map-from-action';

const sourceId = '3dd2af97-4c34-4e51-82b8-ceb92645e784';
const targetId = '4819de76-fce4-4a1c-bb3b-e97d80b61ab7';

describe('applyMapFrom', () => {
	it('keeps a committed update successful when destination navigation fails', async () => {
		const fetcher = vi.fn(
			async () =>
				new Response(JSON.stringify({ updated_count: 4 }), {
					status: 200,
					headers: { 'Content-Type': 'application/json' }
				})
		);
		const navigate = vi.fn(async () => {
			throw new Error('navigation failed');
		});

		await expect(applyMapFrom({ sourceId, targetId, fetcher, navigate })).resolves.toEqual({
			status: 'applied',
			updatedCount: 4,
			navigated: false
		});
		expect(fetcher).toHaveBeenCalledWith(`/compliance-assessments/${targetId}/map-from`, {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({ source_audit_id: sourceId })
		});
	});

	it('keeps an API rejection distinct and does not navigate', async () => {
		const fetcher = vi.fn(
			async () =>
				new Response(JSON.stringify({ error: 'Mapping is not permitted.' }), {
					status: 403,
					headers: { 'Content-Type': 'application/json' }
				})
		);
		const navigate = vi.fn(async () => {});

		await expect(applyMapFrom({ sourceId, targetId, fetcher, navigate })).resolves.toEqual({
			status: 'failed',
			message: 'Mapping is not permitted.'
		});
		expect(navigate).not.toHaveBeenCalled();
	});
});
