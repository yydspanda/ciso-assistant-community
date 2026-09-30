import { isRedirect } from '@sveltejs/kit';
import { afterEach, describe, expect, it, vi } from 'vitest';

// $lib/server/logger reads $env/dynamic/private, a SvelteKit virtual module
// vitest cannot resolve; mocking it keeps hooks.server.ts importable here.
vi.mock('$lib/server/logger', () => ({
	installJsonConsole: () => {},
	logger: { debug: () => {}, info: () => {}, warning: () => {}, error: () => {} }
}));

vi.mock('$paraglide/server', () => ({
	paraglideMiddleware: async (
		request: Request,
		callback: (localized: { request: Request; locale: string }) => Promise<Response>
	) => callback({ request, locale: 'en' })
}));

// SvelteKit's production sequence helper binds the active RequestEvent through
// its async-local request store. A unit test calls the hook directly, outside
// that runtime, so use the equivalent composition without that framework-only
// binding.
vi.mock('@sveltejs/kit/hooks', () => ({
	sequence:
		(
			...handlers: Array<
				(input: {
					event: unknown;
					resolve: (event: unknown, options?: Record<string, unknown>) => Promise<Response>;
				}) => Promise<Response>
			>
		) =>
		async ({
			event,
			resolve
		}: {
			event: unknown;
			resolve: (event: unknown, options?: Record<string, unknown>) => Promise<Response>;
		}) => {
			const run = (
				index: number,
				currentEvent: unknown,
				options?: Record<string, unknown>
			): Promise<Response> => {
				const handler = handlers[index];
				if (!handler) return resolve(currentEvent, options);
				return handler({
					event: currentEvent,
					resolve: (nextEvent: unknown, nextOptions?: Record<string, unknown>) =>
						run(index + 1, nextEvent, nextOptions ?? options)
				});
			};
			return run(0, event);
		}
}));

const { handle, handleFetch } = await import('./hooks.server');
const { ALLAUTH_API_URL } = await import('$lib/utils/constants');

const SSO_USER = { is_sso: true };
const LOCAL_USER = { is_sso: false };

const SESSION_COOKIES = ['token', 'allauth_session_token'];

const REAUTHENTICATION_REQUIRED = {
	status: 401,
	data: { flows: [{ id: 'reauthenticate' }] },
	meta: { is_authenticated: true }
};
const SESSION_GONE = { status: 401, meta: { is_authenticated: false } };

const AUTHENTICATED_USER = {
	id: '0c239be2-c05e-4db6-ad90-d2c960cd2e9e',
	is_sso: false,
	preferences: { lang: 'fr', ui: { theme: 'dark' } }
};

afterEach(() => {
	vi.unstubAllGlobals();
});

function handleEvent({
	url = 'http://localhost:5173/calendar',
	method = 'GET',
	headers = { accept: 'text/html' },
	isDataRequest = false
}: {
	url?: string;
	method?: string;
	headers?: Record<string, string>;
	isDataRequest?: boolean;
} = {}) {
	const jar = new Map([
		['LOCALE', 'en'],
		['csrftoken', 'csrf-token'],
		['token', 'access-token'],
		['allauth_session_token', 'session-token']
	]);
	const writes: string[] = [];
	const deletes: string[] = [];
	let responseStarted = false;
	const assertResponseIsOpen = () => {
		if (responseStarted) {
			throw new Error('Cannot use `cookies.set(...)` after the response has been generated');
		}
	};
	const request = new Request(url, { method, headers });
	const event = {
		url: new URL(url),
		request,
		cookies: {
			get: (name: string) => jar.get(name),
			set: (name: string, value: string) => {
				assertResponseIsOpen();
				writes.push(name);
				jar.set(name, value);
			},
			delete: (name: string) => {
				assertResponseIsOpen();
				deletes.push(name);
				jar.delete(name);
			}
		},
		locals: {} as App.Locals,
		route: { id: '/calendar' },
		isDataRequest,
		isSubRequest: false
	};

	return {
		event,
		jar,
		writes,
		deletes,
		startResponse: () => {
			responseStarted = true;
		}
	};
}

async function callHandle(
	event: ReturnType<typeof handleEvent>['event'],
	resolve: (resolvedEvent: ReturnType<typeof handleEvent>['event']) => Promise<Response>
) {
	return handle({ event, resolve } as never);
}

describe('handle, page identity preflight', () => {
	it('finishes locale and login-marker writes before a concurrent page error responds', async () => {
		const fetchCurrentUser = vi.fn(async () => Response.json(AUTHENTICATED_USER));
		vi.stubGlobal('fetch', fetchCurrentUser);
		const fixture = handleEvent({
			headers: {
				accept: 'text/html',
				referer: 'http://localhost:5173/login'
			}
		});
		const lateErrors: unknown[] = [];

		const response = await callHandle(fixture.event, async (event) => {
			expect(event.locals.user).toEqual(AUTHENTICATED_USER);
			fixture.startResponse();
			void event.locals.getUser().catch((error: unknown) => lateErrors.push(error));
			return new Response('child load failed', { status: 500 });
		});
		await Promise.resolve();

		expect(response.status).toBe(500);
		expect(fetchCurrentUser).toHaveBeenCalledTimes(1);
		expect(fixture.writes).toEqual(['LOCALE', 'from_login']);
		expect(fixture.jar.get('LOCALE')).toBe('fr');
		expect(fixture.jar.get('from_login')).toBe('true');
		expect(lateErrors).toEqual([]);
	});

	it.each([
		['SvelteKit data request', { headers: { accept: '*/*' }, isDataRequest: true }],
		[
			'enhanced form action',
			{
				method: 'POST',
				headers: { accept: 'application/json', 'x-sveltekit-action': 'true' }
			}
		]
	])('preloads the user for a %s', async (_name, options) => {
		const fetchCurrentUser = vi.fn(async () => Response.json(AUTHENTICATED_USER));
		vi.stubGlobal('fetch', fetchCurrentUser);
		const fixture = handleEvent(options);

		await callHandle(fixture.event, async (event) => {
			expect(event.locals.user).toEqual(AUTHENTICATED_USER);
			fixture.startResponse();
			return new Response();
		});

		expect(fetchCurrentUser).toHaveBeenCalledTimes(1);
		expect(fixture.writes).toEqual(['LOCALE']);
	});

	it('leaves JSON endpoint identity lookup lazy', async () => {
		const fetchCurrentUser = vi.fn(async () => Response.json(AUTHENTICATED_USER));
		vi.stubGlobal('fetch', fetchCurrentUser);
		const fixture = handleEvent({
			url: 'http://localhost:5173/fe-api/notifications/unread-count',
			headers: { accept: 'application/json' }
		});

		const response = await callHandle(fixture.event, async (event) => {
			expect(event.locals.user).toBeUndefined();
			fixture.startResponse();
			return Response.json({ count: 0 });
		});

		expect(fetchCurrentUser).not.toHaveBeenCalled();
		expect(fixture.writes).toEqual([]);
		expect(response.headers.get('cache-control')).toBe('no-store');
	});

	it('keeps the SSO authenticate page exempt from current-user validation', async () => {
		const fetchCurrentUser = vi.fn(async () => Response.json(AUTHENTICATED_USER));
		vi.stubGlobal('fetch', fetchCurrentUser);
		const fixture = handleEvent({
			url: 'http://localhost:5173/sso/authenticate',
			headers: {
				accept: 'text/html',
				referer: 'http://localhost:5173/login'
			}
		});

		await callHandle(fixture.event, async (event) => {
			expect(await event.locals.getUser()).toBeNull();
			fixture.startResponse();
			return new Response();
		});

		expect(fetchCurrentUser).not.toHaveBeenCalled();
		expect(fixture.writes).toEqual([]);
	});

	it('clears an invalid page session before resolve starts', async () => {
		vi.stubGlobal(
			'fetch',
			vi.fn(async () => new Response(null, { status: 401 }))
		);
		const fixture = handleEvent();
		const resolve = vi.fn(async () => new Response());

		await expect(callHandle(fixture.event, resolve)).rejects.toSatisfy(isRedirect);

		expect(resolve).not.toHaveBeenCalled();
		expect(fixture.deletes).toEqual(['token', 'allauth_session_token']);
	});
});

function callWith(getUser: () => Promise<Record<string, unknown> | null>, body: unknown) {
	const jar = new Map(SESSION_COOKIES.map((name) => [name, `${name}-value`]));
	const response = handleFetch({
		request: new Request(`${ALLAUTH_API_URL}/account/authenticators`),
		fetch: vi.fn(
			async () =>
				new Response(JSON.stringify(body), {
					status: 401,
					headers: { 'content-type': 'application/json' }
				})
		),
		event: {
			url: new URL('http://localhost:5173/my-profile/settings'),
			cookies: {
				get: (name: string) => jar.get(name),
				set: (name: string, value: string) => jar.set(name, value),
				delete: (name: string) => jar.delete(name)
			},
			// Only getUser, never locals.user: a form action runs before any load,
			// so nothing has resolved it by the time handleFetch decides.
			locals: { getUser }
		}
	} as never);
	return { response, jar };
}

describe('handleFetch, 401 from an allauth account endpoint', () => {
	it('signs out a local user so they can re-enter their password', async () => {
		await expect(
			callWith(async () => LOCAL_USER, REAUTHENTICATION_REQUIRED).response
		).rejects.toSatisfy(isRedirect);
	});

	it('keeps an SSO user, who has no password to re-enter', async () => {
		const { response, jar } = callWith(async () => SSO_USER, REAUTHENTICATION_REQUIRED);

		expect((await response).status).toBe(401);
		// Exact set: the session cookies survive, and no flash cookie is added.
		// A logout that deleted them without redirecting would still return 401.
		expect([...jar.keys()]).toEqual(SESSION_COOKIES);
	});

	it('signs out an SSO user whose allauth session is gone', async () => {
		await expect(callWith(async () => SSO_USER, SESSION_GONE).response).rejects.toSatisfy(
			isRedirect
		);
	});

	it('keeps the session when the current-user lookup fails', async () => {
		const { response, jar } = callWith(async () => {
			throw new TypeError('fetch failed');
		}, REAUTHENTICATION_REQUIRED);

		expect((await response).status).toBe(401);
		expect([...jar.keys()]).toEqual(SESSION_COOKIES);
	});
});
