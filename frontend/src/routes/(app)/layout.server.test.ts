import { describe, expect, it, vi } from 'vitest';

import { load } from './+layout.server';

const user = {
	id: '0c239be2-c05e-4db6-ad90-d2c960cd2e9e',
	is_sso: false,
	is_local: true,
	is_superuser: false,
	has_mfa_enabled: true
};

describe('app layout cookie timing', () => {
	it('consumes a navigation flash before concurrent child loads can finish the response', async () => {
		let releaseSettings!: (settings: Record<string, unknown>) => void;
		const settings = new Promise<Record<string, unknown>>((resolve) => {
			releaseSettings = resolve;
		});
		let responseStarted = false;
		const deletes: string[] = [];
		const fixtureEvent = {
			locals: {
				getUser: vi.fn(async () => user),
				getSettings: vi.fn(() => settings),
				getFeatureFlags: vi.fn(async () => ({}))
			},
			url: new URL('http://localhost:5173/calendar'),
			request: new Request('http://localhost:5173/calendar', {
				headers: { accept: 'text/html' }
			}),
			isDataRequest: false,
			cookies: {
				get: (name: string) => (name === 'flash' ? JSON.stringify({ type: 'info' }) : undefined),
				delete: (name: string) => {
					if (responseStarted) throw new Error('late cookie delete');
					deletes.push(name);
				}
			}
		};

		const pendingLayout = (
			load as unknown as (loadEvent: typeof fixtureEvent) => Promise<Record<string, unknown>>
		)(fixtureEvent);

		// loadFlash reads and clears the cookie synchronously, before the
		// layout's settings/feature-flag awaits or a sibling's failing load.
		expect(deletes).toEqual(['flash']);
		responseStarted = true;
		releaseSettings({ enforce_mfa: false });

		await expect(pendingLayout).resolves.toMatchObject({ user });
	});
});
