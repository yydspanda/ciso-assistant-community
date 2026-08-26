import { BASE_API_URL } from '$lib/utils/constants';
import { fetchRegulatoryReadPanel } from '$lib/regulatory/api.server';
import {
	enforceRegulatoryPanelCoherence,
	isRegulatoryDocumentResponseCoherent
} from '$lib/regulatory/coherence';
import {
	buildRegulatorySelectionQuery,
	buildRegulatoryCurrentViewHref,
	isAwareRfc3339,
	isUuid,
	responseReadState
} from '$lib/regulatory/presentation';
import type {
	RegulatoryApplicability,
	RegulatoryApplicabilityReview,
	RegulatoryDocumentDetail,
	RegulatoryEntityOption,
	RegulatoryReadPanel,
	RegulatoryReadState
} from '$lib/regulatory/types';
import type { PageServerLoad } from './$types';
import { hasPermissionAnywhere } from '$lib/utils/access-control';
import {
	parseRegulatoryApplicability,
	parseRegulatoryApplicabilityReview,
	parseRegulatoryDocumentDetail,
	parseRegulatoryEntityPage
} from '$lib/regulatory/contracts';

const idlePanel = <T>(): RegulatoryReadPanel<T> => ({ state: 'idle', data: null });
const emptyPanel = <T = never>(state: RegulatoryReadState): RegulatoryReadPanel<T> => ({
	state,
	data: null
});

export const load: PageServerLoad = async ({ fetch, params, url, locals }) => {
	const entityValues = url.searchParams.getAll('entity');
	const recordedValues = url.searchParams.getAll('recorded_as_of');
	const mode = url.searchParams.get('mode') ?? 'apply';
	const rawRequestedEntity = entityValues.length === 1 ? entityValues[0].trim() : '';
	const requestedEntity = isUuid(rawRequestedEntity) ? rawRequestedEntity.toLowerCase() : '';
	const selectedEntity = mode === 'search' ? '' : requestedEntity;
	const entitySearch = (url.searchParams.get('entity_search') ?? '').trim().slice(0, 200);
	const rawRecordedAsOf = recordedValues.length === 1 ? recordedValues[0].trim() : '';
	const recordedAsOfIsValid =
		rawRecordedAsOf === '' || (rawRecordedAsOf.length <= 80 && isAwareRfc3339(rawRecordedAsOf));
	const recordedAsOf = recordedAsOfIsValid ? rawRecordedAsOf : '';
	const selectionIsInvalid =
		entityValues.length > 1 ||
		(rawRequestedEntity !== '' && requestedEntity === '') ||
		recordedValues.length > 1 ||
		!recordedAsOfIsValid;

	let document: RegulatoryDocumentDetail | null = null;
	let documentState: RegulatoryReadState = selectionIsInvalid ? 'invalid' : 'ok';
	let entityState: RegulatoryReadState = 'idle';
	let entities: RegulatoryEntityOption[] = [];
	let applicability = idlePanel<RegulatoryApplicability>();
	let review = idlePanel<RegulatoryApplicabilityReview>();

	const canViewEntities = hasPermissionAnywhere(locals.user, 'view_entity');
	const canViewApplicability = hasPermissionAnywhere(
		locals.user,
		'view_regulatoryapplicabilitydecision'
	);
	const canSelectApplicability = canViewEntities && canViewApplicability;
	if (!canSelectApplicability) entityState = 'restricted';

	const detailQuery = buildRegulatorySelectionQuery({
		entity: '',
		recordedAsOf,
		includeEntity: false
	});
	const detailUrl = `${BASE_API_URL}/regulatory/v1/documents/${params.id}/${
		detailQuery.size ? `?${detailQuery}` : ''
	}`;

	if (!selectionIsInvalid) {
		try {
			const detailResponse = await fetch(detailUrl, {
				method: 'GET',
				headers: { Accept: 'application/json' }
			});
			if (!detailResponse.ok) {
				documentState = responseReadState(detailResponse.status);
			} else {
				const candidate = parseRegulatoryDocumentDetail(await detailResponse.json());
				if (
					isRegulatoryDocumentResponseCoherent(candidate, {
						documentId: params.id,
						recordedAsOf
					})
				) {
					document = candidate;
				} else {
					documentState = 'unavailable';
				}
			}
		} catch {
			documentState = 'unavailable';
		}
	}

	// Entity discovery is a secondary capability. It is attempted only after the
	// document has passed its own IAM and runtime-contract checks.
	if (documentState === 'ok' && document && canSelectApplicability) {
		const entityQuery = new URLSearchParams({ limit: '25', ordering: 'name', is_active: 'true' });
		if (entitySearch) entityQuery.set('search', entitySearch);
		try {
			const entityResponse = await fetch(`${BASE_API_URL}/entities/?${entityQuery}`, {
				method: 'GET',
				headers: { Accept: 'application/json' }
			});
			if (!entityResponse.ok) {
				entityState = responseReadState(entityResponse.status);
			} else {
				const entityPage = parseRegulatoryEntityPage(await entityResponse.json());
				entities = entityPage.results;
				entityState = 'ok';
			}
		} catch {
			entityState = 'unavailable';
		}
	}

	if (!selectedEntity && documentState === 'ok' && document) {
		if (entityState === 'unauthenticated' || entityState === 'unavailable') {
			applicability = emptyPanel(entityState);
			review = emptyPanel(entityState);
		} else if (entityState === 'restricted' || (entityState === 'ok' && entities.length === 0)) {
			applicability = emptyPanel('restricted');
			review = emptyPanel('restricted');
		}
	}

	if (selectedEntity) {
		if (documentState !== 'ok' || !document) {
			const dependentState: RegulatoryReadState =
				documentState === 'invalid' ? 'invalid' : documentState;
			applicability = emptyPanel(dependentState);
			review = emptyPanel(dependentState);
		} else {
			if (!isUuid(selectedEntity) || !canSelectApplicability) {
				const state = canSelectApplicability ? 'invalid' : 'restricted';
				applicability = emptyPanel(state);
				review = emptyPanel(state);
			} else {
				const selectionQuery = buildRegulatorySelectionQuery({
					entity: selectedEntity,
					recordedAsOf
				});
				const applicabilityResponse = await fetchRegulatoryReadPanel<RegulatoryApplicability>(
					fetch,
					`${BASE_API_URL}/regulatory/v1/documents/${params.id}/applicability/?${selectionQuery}`,
					parseRegulatoryApplicability
				);
				const currentSelectionAnchor =
					recordedAsOf === '' && applicabilityResponse.state === 'ok'
						? applicabilityResponse.data?.selected_recorded_at
						: undefined;
				const reviewQuery = buildRegulatorySelectionQuery({
					entity: selectedEntity,
					recordedAsOf: currentSelectionAnchor ?? recordedAsOf
				});
				const reviewResponse = await fetchRegulatoryReadPanel<RegulatoryApplicabilityReview>(
					fetch,
					`${BASE_API_URL}/regulatory/v1/documents/${params.id}/applicability-review/?${reviewQuery}`,
					parseRegulatoryApplicabilityReview
				);
				({ applicability, review } = enforceRegulatoryPanelCoherence({
					document,
					request: {
						documentId: params.id,
						entityId: selectedEntity,
						recordedAsOf,
						currentSelectionAnchor
					},
					applicability: applicabilityResponse,
					review: reviewResponse
				}));

				if (
					(applicability.state === 'ok' || review.state === 'ok') &&
					!entities.some((entity) => entity.id.toLowerCase() === selectedEntity.toLowerCase())
				) {
					entities = [...entities, { id: selectedEntity, name: selectedEntity }];
				}
			}
		}
	}

	return {
		title: document?.title_zh ?? 'regulatoryDocumentDetail',
		modelVerboseName: 'regulatoryRegister',
		document,
		documentState,
		entities,
		entityState,
		selectedEntity,
		entitySearch,
		recordedAsOf,
		currentViewHref: buildRegulatoryCurrentViewHref({
			entity: selectedEntity,
			entitySearch
		}),
		applicability,
		review
	};
};
