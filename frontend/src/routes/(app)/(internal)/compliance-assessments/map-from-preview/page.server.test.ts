import { describe, expect, it, vi } from 'vitest';

vi.mock('$lib/utils/constants', () => ({
	BASE_API_URL: 'http://localhost:8000/api'
}));

import { load } from './+page.server';

const sourceId = '3dd2af97-4c34-4e51-82b8-ceb92645e784';
const targetId = '4819de76-fce4-4a1c-bb3b-e97d80b61ab7';

function callLoad(fetchFn: typeof fetch, source = sourceId, target = targetId) {
	return (load as (event: unknown) => Promise<Record<string, unknown>>)({
		fetch: fetchFn,
		url: new URL(`http://localhost/map-from-preview?source=${source}&target=${target}`)
	});
}

describe('map-from preview loader binding', () => {
	it('returns only a preview whose identities match the requested audits', async () => {
		const preview = {
			source_audit: { id: sourceId, name: 'Source', framework: 'A' },
			target_audit: { id: targetId, name: 'Target', framework: 'B' },
			updated_count: 1
		};
		const fetchFn = vi.fn(async () => Response.json(preview)) as unknown as typeof fetch;

		await expect(callLoad(fetchFn)).resolves.toMatchObject({
			previewData: preview,
			sourceId,
			targetId
		});
	});

	it('rejects malformed query IDs before calling the API', async () => {
		const fetchFn = vi.fn() as unknown as typeof fetch;

		await expect(callLoad(fetchFn, 'not-a-uuid')).rejects.toMatchObject({ status: 400 });
		expect(fetchFn).not.toHaveBeenCalled();
	});

	it('rejects a preview bound to different source or target identities', async () => {
		const fetchFn = vi.fn(async () =>
			Response.json({
				source_audit: {
					id: '80114295-51b3-4d48-a2ac-1eabc6934e9b',
					name: 'Wrong source',
					framework: 'A'
				},
				target_audit: { id: targetId, name: 'Target', framework: 'B' }
			})
		) as unknown as typeof fetch;

		await expect(callLoad(fetchFn)).rejects.toMatchObject({ status: 409 });
	});

	it('rejects malformed successful API payloads', async () => {
		const fetchFn = vi.fn(async () =>
			Response.json({ target_audit: null })
		) as unknown as typeof fetch;

		await expect(callLoad(fetchFn)).rejects.toMatchObject({ status: 502 });
	});
});
