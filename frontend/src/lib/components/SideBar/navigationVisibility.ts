import { hasPermissionAnywhere } from '$lib/utils/access-control';
import { URL_MODEL_MAP } from '$lib/utils/crud';
import type { User } from '$lib/utils/types';

export interface NavigationAccessItem {
	href: string;
	adminOnly?: boolean;
	exclude?: readonly string[];
	permissions?: readonly string[];
}

/**
 * Shared navigation authorization rule for every surface that exposes navData.
 * Backend IAM remains authoritative; this only prevents inaccessible routes
 * from being advertised by the sidebar or command palette.
 */
export function isNavigationItemVisible(
	item: NavigationAccessItem,
	user: User | null | undefined
): boolean {
	if (item.adminOnly) {
		return Boolean(user?.is_admin);
	}

	if (item.exclude) {
		const roles = (user?.roles ?? []) as unknown as string[];
		return roles.some((role) => !item.exclude?.includes(role));
	}

	if (item.permissions) {
		return item.permissions.some((permission) => hasPermissionAnywhere(user as User, permission));
	}

	const urlModel = item.href.split('/')[1];
	if (Object.hasOwn(URL_MODEL_MAP, urlModel)) {
		return hasPermissionAnywhere(user as User, `view_${URL_MODEL_MAP[urlModel].name}`);
	}

	return false;
}
