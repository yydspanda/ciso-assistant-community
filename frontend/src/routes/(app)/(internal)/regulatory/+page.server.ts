import { BASE_API_URL } from '$lib/utils/constants';
import {
	buildRegulatoryListApiQuery,
	buildRegulatoryListHref,
	readRegulatoryListFilters,
	REGULATORY_MAX_PAGE,
	REGULATORY_PAGE_SIZE,
	responseListReadState
} from '$lib/regulatory/presentation';
import type { RegulatoryDocumentSummary, RegulatoryReadState } from '$lib/regulatory/types';
import { hasPermissionAnywhere } from '$lib/utils/access-control';
import type { PageServerLoad } from './$types';
import { redirect } from '@sveltejs/kit';
import { parseRegulatoryDocumentPage } from '$lib/regulatory/contracts';

export const load: PageServerLoad = async ({ fetch, url, locals }) => {
	const filters = readRegulatoryListFilters(url.searchParams);
	const query = buildRegulatoryListApiQuery(filters);
	let state: RegulatoryReadState = 'ok';
	let documents: RegulatoryDocumentSummary[] = [];
	let count = 0;

	if (!hasPermissionAnywhere(locals.user, 'view_regulatorydocument')) {
		return {
			title: 'regulatoryRegister',
			modelDescriptionKey: 'regulatoryRegisterDescription',
			state: 'restricted' as const,
			documents,
			count,
			filters
		};
	}

	try {
		const response = await fetch(`${BASE_API_URL}/regulatory/v1/documents/?${query}`, {
			method: 'GET',
			headers: { Accept: 'application/json' }
		});
		if (response.ok) {
			const page = parseRegulatoryDocumentPage(await response.json());
			documents = page.results;
			count = page.count;
		} else {
			state = responseListReadState(response.status);
		}
	} catch {
		state = 'unavailable';
	}

	if (state === 'ok' && count > 0 && documents.length === 0) {
		const finalPage = Math.min(
			REGULATORY_MAX_PAGE,
			Math.max(1, Math.ceil(count / REGULATORY_PAGE_SIZE))
		);
		if (filters.page > finalPage) {
			redirect(
				302,
				buildRegulatoryListHref(
					{
						search: filters.search,
						authorityLevel: filters.authorityLevel,
						coverageStage: filters.coverageStage
					},
					finalPage
				)
			);
		}
		state = 'unavailable';
	}

	return {
		title: 'regulatoryRegister',
		modelDescriptionKey: 'regulatoryRegisterDescription',
		state,
		documents,
		count,
		filters
	};
};
