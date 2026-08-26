import { describe, expect, it, vi } from 'vitest';

vi.mock('$lib/utils/crud', () => ({
	URL_MODEL_MAP: { perimeters: { name: 'perimeter' } }
}));

import type { User } from '$lib/utils/types';
import { getNavigationLinks, isNavigationLinkFeatureVisible } from './paletteData';
import { isNavigationItemVisible } from '../SideBar/navigationVisibility';

const user = (overrides: Partial<User> = {}) =>
	({
		is_admin: false,
		roles: ['USER'] as unknown as User['roles'],
		domain_permissions: { root: [] },
		...overrides
	}) as User;

describe('navigation visibility shared by sidebar and command palette', () => {
	it('does not advertise the regulatory register without document view permission', () => {
		expect(getNavigationLinks(user()).some((link) => link.href === '/regulatory')).toBe(false);
	});

	it('advertises the regulatory register when the permission exists anywhere', () => {
		const links = getNavigationLinks(
			user({ domain_permissions: { root: [], delegated: ['view_regulatorydocument'] } })
		);
		const regulatoryLink = links.find((link) => link.href === '/regulatory');
		expect(regulatoryLink).toMatchObject({
			label: 'regulatoryRegister',
			categoryVisibilityKey: 'compliance'
		});
		expect(
			isNavigationLinkFeatureVisible(regulatoryLink!, {
				compliance: true,
				regulatoryRegister: true
			})
		).toBe(true);
	});

	it('applies both parent-category and child feature visibility', () => {
		const regulatoryLink = getNavigationLinks(
			user({ domain_permissions: { delegated: ['view_regulatorydocument'] } })
		).find((link) => link.href === '/regulatory')!;

		expect(
			isNavigationLinkFeatureVisible(regulatoryLink, {
				compliance: false,
				regulatoryRegister: true
			})
		).toBe(false);
		expect(
			isNavigationLinkFeatureVisible(regulatoryLink, {
				compliance: true,
				regulatoryRegister: false
			})
		).toBe(false);
		expect(isNavigationLinkFeatureVisible(regulatoryLink, { compliance: true })).toBe(true);
	});

	it('preserves admin-only and role-exclusion rules', () => {
		expect(isNavigationItemVisible({ href: '/admin', adminOnly: true }, user())).toBe(false);
		expect(
			isNavigationItemVisible({ href: '/admin', adminOnly: true }, user({ is_admin: true }))
		).toBe(true);
		expect(
			isNavigationItemVisible(
				{ href: '/role-scoped', exclude: ['EXCLUDED'] },
				user({ roles: ['EXCLUDED'] as unknown as User['roles'] })
			)
		).toBe(false);
	});

	it('keeps the existing model-derived view permission fallback', () => {
		expect(isNavigationItemVisible({ href: '/perimeters' }, user())).toBe(false);
		expect(
			isNavigationItemVisible(
				{ href: '/perimeters' },
				user({ domain_permissions: { root: ['view_perimeter'] } })
			)
		).toBe(true);
	});
});
