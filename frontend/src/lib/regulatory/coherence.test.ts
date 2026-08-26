import { describe, expect, it } from 'vitest';

import {
	enforceRegulatoryPanelCoherence,
	isRegulatoryDocumentResponseCoherent,
	type RegulatoryRequestIdentity
} from './coherence';
import type {
	RegulatoryApplicability,
	RegulatoryApplicabilityReview,
	RegulatoryDocumentDetail,
	RegulatoryReadPanel
} from './types';

const documentId = '4819de76-fce4-4a1c-bb3b-e97d80b61ab7';
const otherDocumentId = '5f577c45-ec6c-4f76-9b30-6770ef8ed95d';
const entityId = '3dd2af97-4c34-4e51-82b8-ceb92645e784';
const otherEntityId = '8a2ce0ce-2aef-444f-810f-b9877fcaee3d';
const selectedAt = '2026-08-26T01:30:00Z';
const laterSelectedAt = '2026-08-26T01:30:00.250Z';
const hash = 'a'.repeat(64);

const document = {
	id: documentId,
	recorded_as_of: null,
	document_versions: [
		{
			recorded_from: '2026-08-25T00:00:00Z',
			recorded_to: null,
			provisions: [
				{
					record_id: 'SYNTHETIC-PROVISION-001',
					recorded_from: '2026-08-25T00:00:00Z',
					recorded_to: null,
					obligations: [
						{
							record_id: 'SYNTHETIC-OBLIGATION-001',
							revision: 1,
							provision_ids: ['SYNTHETIC-PROVISION-001'],
							recorded_from: '2026-08-25T00:00:00Z',
							recorded_to: null
						}
					]
				}
			]
		}
	]
} as unknown as RegulatoryDocumentDetail;

const request: RegulatoryRequestIdentity = {
	documentId,
	entityId,
	recordedAsOf: '',
	currentSelectionAnchor: selectedAt
};

function decisionData(): NonNullable<RegulatoryApplicability['decision']> {
	return {
		id: 'b802312e-4d22-428e-b8fa-6612db4bfb4e',
		record_id: 'SYNTHETIC-DECISION-001',
		revision: 1,
		scope: { type: 'legal_entity', id: entityId },
		recorded_from: '2026-08-25T00:00:00Z',
		recorded_to: null,
		semantic_payload_sha256: hash
	} as NonNullable<RegulatoryApplicability['decision']>;
}

function applicabilityData(): RegulatoryApplicability {
	return {
		document_id: documentId,
		scope: { type: 'legal_entity', id: entityId },
		obligation_id: 'SYNTHETIC-OBLIGATION-001',
		obligation_revision: 1,
		recorded_as_of: null,
		selected_recorded_at: selectedAt,
		evaluation_status: 'evaluated',
		non_binding_result: 'needs_review',
		decision: decisionData()
	} as RegulatoryApplicability;
}

function reviewData(): RegulatoryApplicabilityReview {
	return {
		document_id: documentId,
		scope: { type: 'legal_entity', id: entityId },
		obligation_id: 'SYNTHETIC-OBLIGATION-001',
		obligation_revision: 1,
		recorded_as_of: selectedAt,
		selected_recorded_at: selectedAt,
		evaluation_status: 'evaluated',
		computed_non_binding_result: 'needs_review',
		decision: decisionData(),
		latest_disposition: null
	} as RegulatoryApplicabilityReview;
}

function panels(): {
	applicability: RegulatoryReadPanel<RegulatoryApplicability>;
	review: RegulatoryReadPanel<RegulatoryApplicabilityReview>;
} {
	return {
		applicability: { state: 'ok', data: applicabilityData() },
		review: { state: 'ok', data: reviewData() }
	};
}

function expectBothUnavailable(result: ReturnType<typeof enforceRegulatoryPanelCoherence>) {
	expect(result).toEqual({
		applicability: { state: 'unavailable', data: null },
		review: { state: 'unavailable', data: null }
	});
}

describe('regulatory response coherence', () => {
	it('accepts timezone-equivalent historical request echoes and a matching chain', () => {
		const historicalDocument = {
			...document,
			recorded_as_of: '2026-08-26T09:30:00+08:00'
		};
		expect(
			isRegulatoryDocumentResponseCoherent(historicalDocument, {
				documentId,
				recordedAsOf: selectedAt
			})
		).toBe(true);
		expect(
			isRegulatoryDocumentResponseCoherent(
				{ ...historicalDocument, id: otherDocumentId },
				{ documentId, recordedAsOf: selectedAt }
			)
		).toBe(false);
	});

	it('preserves microsecond precision at a half-open recorded-time boundary', () => {
		const recordedFrom = '2026-08-26T01:30:00.000100Z';
		const requestedWithExtraPrecision = '2026-08-26T01:30:00.0007991234Z';
		const selectedOneMicrosecondBeforeEnd = '2026-08-26T01:30:00.000799Z';
		const timezoneEquivalentSelection = '2026-08-26T09:30:00.000799+08:00';
		const recordedTo = '2026-08-26T01:30:00.000800Z';
		const microDocument = structuredClone(document);
		microDocument.recorded_as_of = timezoneEquivalentSelection;
		const version = microDocument.document_versions[0];
		const provision = version.provisions[0];
		const obligation = provision.obligations[0];
		for (const record of [version, provision, obligation]) {
			record.recorded_from = recordedFrom;
			record.recorded_to = recordedTo;
		}

		const microPanels = panels();
		for (const panel of [microPanels.applicability.data!, microPanels.review.data!]) {
			panel.recorded_as_of = selectedOneMicrosecondBeforeEnd;
			panel.selected_recorded_at = timezoneEquivalentSelection;
			panel.decision!.recorded_from = recordedFrom;
			panel.decision!.recorded_to = recordedTo;
		}
		const microRequest: RegulatoryRequestIdentity = {
			...request,
			recordedAsOf: requestedWithExtraPrecision,
			currentSelectionAnchor: undefined
		};

		expect(
			enforceRegulatoryPanelCoherence({
				document: microDocument,
				request: microRequest,
				...microPanels
			}).applicability.state
		).toBe('ok');

		microDocument.recorded_as_of = recordedTo;
		const endBoundaryPanels = panels();
		for (const panel of [endBoundaryPanels.applicability.data!, endBoundaryPanels.review.data!]) {
			panel.recorded_as_of = recordedTo;
			panel.selected_recorded_at = recordedTo;
			panel.decision!.recorded_from = recordedFrom;
			panel.decision!.recorded_to = recordedTo;
		}
		expectBothUnavailable(
			enforceRegulatoryPanelCoherence({
				document: microDocument,
				request: { ...microRequest, recordedAsOf: recordedTo },
				...endBoundaryPanels
			})
		);
	});

	it('rejects a closed chain from an unqualified current detail response', () => {
		const closedCurrentDocument = structuredClone(document);
		closedCurrentDocument.document_versions[0].provisions[0].obligations[0].recorded_to =
			selectedAt;
		expect(
			isRegulatoryDocumentResponseCoherent(closedCurrentDocument, {
				documentId,
				recordedAsOf: ''
			})
		).toBe(false);
	});

	it('requires both successful current reads to bind the applicability selection anchor', () => {
		const pair = panels();
		const result = enforceRegulatoryPanelCoherence({ document, request, ...pair });
		expect(result.applicability).toBe(pair.applicability);
		expect(result.review).toBe(pair.review);

		const laterReview = panels();
		laterReview.review.data!.selected_recorded_at = laterSelectedAt;
		expectBothUnavailable(enforceRegulatoryPanelCoherence({ document, request, ...laterReview }));

		const unanchoredReviewEcho = panels();
		unanchoredReviewEcho.review.data!.recorded_as_of = null;
		expectBothUnavailable(
			enforceRegulatoryPanelCoherence({ document, request, ...unanchoredReviewEcho })
		);

		const anchoredApplicabilityEcho = panels();
		anchoredApplicabilityEcho.applicability.data!.recorded_as_of = selectedAt;
		expectBothUnavailable(
			enforceRegulatoryPanelCoherence({ document, request, ...anchoredApplicabilityEcho })
		);
	});

	it('does not let a standalone review 403 discard a coherent applicability result', () => {
		const applicability: RegulatoryReadPanel<RegulatoryApplicability> = {
			state: 'ok',
			data: applicabilityData()
		};
		const review: RegulatoryReadPanel<RegulatoryApplicabilityReview> = {
			state: 'restricted',
			data: null
		};
		const result = enforceRegulatoryPanelCoherence({ document, request, applicability, review });
		expect(result.applicability).toBe(applicability);
		expect(result.review).toBe(review);
	});

	it('fails both panels closed when a successful response mismatches request or nested scope', () => {
		const wrongDocument = panels();
		wrongDocument.applicability.data!.document_id = otherDocumentId;
		expectBothUnavailable(enforceRegulatoryPanelCoherence({ document, request, ...wrongDocument }));

		const wrongEntity = panels();
		wrongEntity.review.data!.scope.id = otherEntityId;
		expectBothUnavailable(enforceRegulatoryPanelCoherence({ document, request, ...wrongEntity }));

		const wrongNestedScope = panels();
		wrongNestedScope.applicability.data!.decision!.scope.id = otherEntityId;
		expectBothUnavailable(
			enforceRegulatoryPanelCoherence({ document, request, ...wrongNestedScope })
		);
	});

	it('fails both panels closed when obligation revision or selected time leaves the detail chain', () => {
		const wrongRevision = panels();
		wrongRevision.review.data!.obligation_revision = 2;
		expectBothUnavailable(enforceRegulatoryPanelCoherence({ document, request, ...wrongRevision }));

		const outsideInterval = panels();
		outsideInterval.applicability.data!.selected_recorded_at = '2026-08-24T23:59:59Z';
		expectBothUnavailable(
			enforceRegulatoryPanelCoherence({ document, request, ...outsideInterval })
		);
	});

	it('requires an explicit recorded selection to bind every successful panel', () => {
		const pair = panels();
		const historicalDocument = { ...document, recorded_as_of: selectedAt };
		pair.applicability.data!.recorded_as_of = selectedAt;
		pair.review.data!.recorded_as_of = selectedAt;
		pair.review.data!.selected_recorded_at = selectedAt;
		const historicalRequest = {
			...request,
			recordedAsOf: selectedAt,
			currentSelectionAnchor: undefined
		};
		expect(
			enforceRegulatoryPanelCoherence({
				document: historicalDocument,
				request: historicalRequest,
				...pair
			}).applicability.state
		).toBe('ok');

		pair.review.data!.selected_recorded_at = laterSelectedAt;
		expectBothUnavailable(
			enforceRegulatoryPanelCoherence({
				document: historicalDocument,
				request: historicalRequest,
				...pair
			})
		);
	});

	it('requires the selected decision and latest review disposition to exist at the anchor', () => {
		const decisionOutsideSelection = panels();
		decisionOutsideSelection.applicability.data!.decision!.recorded_from = laterSelectedAt;
		expectBothUnavailable(
			enforceRegulatoryPanelCoherence({ document, request, ...decisionOutsideSelection })
		);

		const dispositionAfterSelection = panels();
		dispositionAfterSelection.review.data!.latest_disposition = {
			occurred_at: laterSelectedAt
		} as NonNullable<RegulatoryApplicabilityReview['latest_disposition']>;
		expectBothUnavailable(
			enforceRegulatoryPanelCoherence({ document, request, ...dispositionAfterSelection })
		);
	});

	it('requires two successful panels to agree on evaluation, result, and decision identity hash', () => {
		const wrongEvaluation = panels();
		wrongEvaluation.review.data!.evaluation_status = 'not_evaluated';
		expectBothUnavailable(
			enforceRegulatoryPanelCoherence({ document, request, ...wrongEvaluation })
		);

		const wrongResult = panels();
		wrongResult.review.data!.computed_non_binding_result = 'applicable';
		expectBothUnavailable(enforceRegulatoryPanelCoherence({ document, request, ...wrongResult }));

		const wrongHash = panels();
		wrongHash.review.data!.decision!.semantic_payload_sha256 = 'b'.repeat(64);
		expectBothUnavailable(enforceRegulatoryPanelCoherence({ document, request, ...wrongHash }));
	});
});
