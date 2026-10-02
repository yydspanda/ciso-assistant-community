import type { LayoutServerLoad } from './$types';
import { redirect } from '@sveltejs/kit';
import { loadFlash } from 'sveltekit-flash-message/server';

export const load = loadFlash(async ({ locals, url }) => {
	const user = await locals.getUser();
	if (!user && !url.pathname.includes('/login')) {
		redirect(302, `/login?next=${url.pathname}`);
	}

	const [settings, featureflags] = await Promise.all([
		locals.getSettings(),
		locals.getFeatureFlags()
	]);

	if (
		user &&
		settings?.enforce_mfa &&
		!user.has_mfa_enabled &&
		!user.is_superuser &&
		user.is_local &&
		!user.is_sso &&
		!url.pathname.startsWith('/setup-mfa')
	) {
		redirect(302, '/setup-mfa');
	}

	return { user, settings, featureflags };
}) satisfies LayoutServerLoad;
