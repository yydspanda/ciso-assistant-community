import { navData } from '../SideBar/navData';
import {
	isNavigationItemVisible,
	type NavigationAccessItem
} from '../SideBar/navigationVisibility';
import type { User } from '$lib/utils/types';

export interface NavigationLink {
	label: string;
	href: string;
	icon?: string;
	categoryVisibilityKey?: string;
}

interface NavigationSourceItem extends NavigationAccessItem {
	name?: string;
	fa_icon?: string;
}

interface NavigationSource {
	items?: readonly {
		name?: string;
		items?: readonly NavigationSourceItem[];
	}[];
}

export function isNavigationLinkFeatureVisible(
	link: Pick<NavigationLink, 'label' | 'categoryVisibilityKey'>,
	visibleItems: Record<string, boolean | undefined>
): boolean {
	return (
		(link.categoryVisibilityKey === undefined ||
			visibleItems[link.categoryVisibilityKey] !== false) &&
		visibleItems[link.label] !== false
	);
}

export function getNavigationLinks(
	user: User | null | undefined,
	source: NavigationSource = navData
): NavigationLink[] {
	const result: NavigationLink[] = [];

	if (source?.items) {
		for (const section of source.items) {
			if (!section.items) continue;

			for (const item of section.items) {
				if (!item.name || !item.href || !isNavigationItemVisible(item, user)) continue;
				result.push({
					label: item.name,
					href: item.href,
					icon: item.fa_icon,
					categoryVisibilityKey: section.name
				});
			}
		}
	}

	result.push({
		label: 'myProfile',
		href: '/my-profile',
		icon: 'fa-solid fa-user'
	});

	return result;
}

// we can use the same trick later on for dynamic actions
