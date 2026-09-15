import { describe, expect, it, vi } from 'vitest';

vi.mock('$lib/utils/constants', () => ({
	BASE_API_URL: 'http://localhost:8000/api'
}));

import { GET, POST } from './+server';

const targetId = '4819de76-fce4-4a1c-bb3b-e97d80b61ab7';

function eventFor(response: Response) {
	return {
		params: { id: targetId },
		request: new Request(`http://localhost/compliance-assessments/${targetId}/map-from`, {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({ source_audit_id: '3dd2af97-4c34-4e51-82b8-ceb92645e784' })
		}),
		fetch: vi.fn(async () => response)
	};
}

describe('map-from proxy', () => {
	it('validates and encodes the preview source before calling the API', async () => {
		const sourceId = '3dd2af97-4c34-4e51-82b8-ceb92645e784';
		const fetchFn = vi.fn(async () => Response.json({ ok: true }));
		const response = await GET({
			params: { id: targetId },
			url: new URL(
				`http://localhost/compliance-assessments/${targetId}/map-from?source_audit_id=${sourceId}`
			),
			fetch: fetchFn
		} as never);

		expect(response.status).toBe(200);
		expect(fetchFn).toHaveBeenCalledWith(
			`http://localhost:8000/api/compliance-assessments/${targetId}/map_from_preview/?source_audit_id=${sourceId}`
		);
	});

	it('rejects malformed preview and mutation inputs without calling the API', async () => {
		const fetchFn = vi.fn();
		const getResponse = await GET({
			params: { id: targetId },
			url: new URL(
				`http://localhost/compliance-assessments/${targetId}/map-from?source_audit_id=not-a-uuid`
			),
			fetch: fetchFn
		} as never);
		const postResponse = await POST({
			params: { id: targetId },
			request: new Request(`http://localhost/compliance-assessments/${targetId}/map-from`, {
				method: 'POST',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify({
					source_audit_id: '3dd2af97-4c34-4e51-82b8-ceb92645e784',
					forged: true
				})
			}),
			fetch: fetchFn
		} as never);

		expect(getResponse.status).toBe(400);
		expect(postResponse.status).toBe(400);
		expect(fetchFn).not.toHaveBeenCalled();
	});

	it('preserves a successful empty response without trying to decode JSON', async () => {
		const event = eventFor(new Response(null, { status: 204 }));
		const response = await POST(event as never);

		expect(response.status).toBe(204);
		expect(await response.text()).toBe('');
		expect(event.fetch).toHaveBeenCalledWith(
			`http://localhost:8000/api/compliance-assessments/${targetId}/map_from/`,
			expect.objectContaining({ method: 'POST' })
		);
	});

	it('forwards a committed non-JSON body and content type verbatim', async () => {
		const event = eventFor(
			new Response('committed', {
				status: 200,
				headers: { 'Content-Type': 'text/plain' }
			})
		);
		const response = await POST(event as never);

		expect(response.status).toBe(200);
		expect(response.headers.get('content-type')).toBe('text/plain');
		expect(await response.text()).toBe('committed');
	});

	it('forwards an API denial without logging or reshaping its body', async () => {
		const event = eventFor(
			new Response('{"detail":"Permission denied"}', {
				status: 403,
				headers: { 'Content-Type': 'application/json' }
			})
		);
		const response = await POST(event as never);

		expect(response.status).toBe(403);
		expect(await response.json()).toEqual({ detail: 'Permission denied' });
	});
});
