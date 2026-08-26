import { compareRfc3339Instants, rfc3339TimestampMicroseconds } from './presentation';
import type {
	RegulatoryApplicability,
	RegulatoryApplicabilityReview,
	RegulatoryDocumentDetail,
	RegulatoryReadPanel
} from './types';

export interface RegulatoryRequestIdentity {
	documentId: string;
	entityId: string;
	recordedAsOf: string;
	currentSelectionAnchor?: string;
}

export interface RegulatoryPanelPair {
	applicability: RegulatoryReadPanel<RegulatoryApplicability>;
	review: RegulatoryReadPanel<RegulatoryApplicabilityReview>;
}

interface RegulatoryPanelIdentity {
	document_id: string;
	scope: { type: string; id: string };
	obligation_id: string;
	obligation_revision: number;
	recorded_as_of: string | null;
	selected_recorded_at: string;
	evaluation_status: string;
	decision: RegulatoryApplicability['decision'];
}

function sameUuid(left: string, right: string): boolean {
	return left.toLowerCase() === right.toLowerCase();
}

function sameInstant(left: string, right: string): boolean {
	return compareRfc3339Instants(left, right) === 0;
}

function matchesRequestedRecordedAsOf(actual: string | null, requested: string): boolean {
	if (requested === '') return actual === null;
	return actual !== null && sameInstant(actual, requested);
}

function intervalContains(
	recordedFrom: string,
	recordedTo: string | null,
	selectedMicroseconds: bigint
): boolean {
	const fromMicroseconds = rfc3339TimestampMicroseconds(recordedFrom);
	if (fromMicroseconds === null || selectedMicroseconds < fromMicroseconds) return false;
	if (recordedTo === null) return true;
	const toMicroseconds = rfc3339TimestampMicroseconds(recordedTo);
	return toMicroseconds !== null && selectedMicroseconds < toMicroseconds;
}

function documentHasCurrentChain(document: RegulatoryDocumentDetail): boolean {
	const version = document.document_versions[0];
	const provision = version?.provisions[0];
	const obligation = provision?.obligations[0];
	return (
		version !== undefined &&
		provision !== undefined &&
		obligation !== undefined &&
		sameInstant(version.recorded_from, provision.recorded_from) &&
		sameInstant(provision.recorded_from, obligation.recorded_from) &&
		version.recorded_to === null &&
		provision.recorded_to === null &&
		obligation.recorded_to === null &&
		rfc3339TimestampMicroseconds(version.recorded_from) !== null &&
		rfc3339TimestampMicroseconds(provision.recorded_from) !== null &&
		rfc3339TimestampMicroseconds(obligation.recorded_from) !== null &&
		obligation.provision_ids.length === 1 &&
		obligation.provision_ids[0] === provision.record_id
	);
}

function documentHasChainAt(
	document: RegulatoryDocumentDetail,
	selectedMicroseconds: bigint
): boolean {
	return document.document_versions.some(
		(version) =>
			intervalContains(version.recorded_from, version.recorded_to, selectedMicroseconds) &&
			version.provisions.some(
				(provision) =>
					sameInstant(version.recorded_from, provision.recorded_from) &&
					intervalContains(provision.recorded_from, provision.recorded_to, selectedMicroseconds) &&
					provision.obligations.some(
						(obligation) =>
							sameInstant(provision.recorded_from, obligation.recorded_from) &&
							obligation.provision_ids.length === 1 &&
							obligation.provision_ids[0] === provision.record_id &&
							intervalContains(
								obligation.recorded_from,
								obligation.recorded_to,
								selectedMicroseconds
							)
					)
			)
	);
}

function documentHasObligationAt(
	document: RegulatoryDocumentDetail,
	panel: RegulatoryPanelIdentity,
	selectedMicroseconds: bigint
): boolean {
	return document.document_versions.some(
		(version) =>
			intervalContains(version.recorded_from, version.recorded_to, selectedMicroseconds) &&
			version.provisions.some(
				(provision) =>
					sameInstant(version.recorded_from, provision.recorded_from) &&
					intervalContains(provision.recorded_from, provision.recorded_to, selectedMicroseconds) &&
					provision.obligations.some(
						(obligation) =>
							sameInstant(provision.recorded_from, obligation.recorded_from) &&
							obligation.provision_ids.length === 1 &&
							obligation.provision_ids[0] === provision.record_id &&
							obligation.record_id === panel.obligation_id &&
							obligation.revision === panel.obligation_revision &&
							intervalContains(
								obligation.recorded_from,
								obligation.recorded_to,
								selectedMicroseconds
							)
					)
			)
	);
}

export function isRegulatoryDocumentResponseCoherent(
	document: RegulatoryDocumentDetail,
	request: Pick<RegulatoryRequestIdentity, 'documentId' | 'recordedAsOf' | 'currentSelectionAnchor'>
): boolean {
	if (
		!sameUuid(document.id, request.documentId) ||
		!matchesRequestedRecordedAsOf(document.recorded_as_of, request.recordedAsOf)
	) {
		return false;
	}

	if (request.recordedAsOf === '') return documentHasCurrentChain(document);
	const requestedMicroseconds = rfc3339TimestampMicroseconds(request.recordedAsOf);
	return requestedMicroseconds !== null && documentHasChainAt(document, requestedMicroseconds);
}

function panelIdentityIsCoherent(
	panel: RegulatoryPanelIdentity,
	document: RegulatoryDocumentDetail,
	request: RegulatoryRequestIdentity,
	kind: 'applicability' | 'review'
): boolean {
	const expectedRecordedAsOf =
		request.recordedAsOf !== ''
			? request.recordedAsOf
			: kind === 'review'
				? (request.currentSelectionAnchor ?? '')
				: '';
	if (
		!sameUuid(panel.document_id, request.documentId) ||
		panel.scope.type !== 'legal_entity' ||
		!sameUuid(panel.scope.id, request.entityId) ||
		!matchesRequestedRecordedAsOf(panel.recorded_as_of, expectedRecordedAsOf)
	) {
		return false;
	}

	if (
		panel.decision !== null &&
		(panel.decision.scope.type !== panel.scope.type ||
			!sameUuid(panel.decision.scope.id, panel.scope.id))
	) {
		return false;
	}

	const selectedMicroseconds = rfc3339TimestampMicroseconds(panel.selected_recorded_at);
	if (selectedMicroseconds === null) return false;
	if (
		request.recordedAsOf !== '' &&
		!sameInstant(panel.selected_recorded_at, request.recordedAsOf)
	) {
		return false;
	}
	if (
		request.recordedAsOf === '' &&
		request.currentSelectionAnchor !== undefined &&
		!sameInstant(panel.selected_recorded_at, request.currentSelectionAnchor)
	) {
		return false;
	}
	if (
		panel.decision !== null &&
		!intervalContains(
			panel.decision.recorded_from,
			panel.decision.recorded_to,
			selectedMicroseconds
		)
	) {
		return false;
	}

	return documentHasObligationAt(document, panel, selectedMicroseconds);
}

function reviewDispositionIsCoherent(review: RegulatoryApplicabilityReview): boolean {
	if (review.latest_disposition === null) return true;
	const selectedMicroseconds = rfc3339TimestampMicroseconds(review.selected_recorded_at);
	const occurredMicroseconds = rfc3339TimestampMicroseconds(review.latest_disposition.occurred_at);
	if (
		selectedMicroseconds === null ||
		occurredMicroseconds === null ||
		occurredMicroseconds > selectedMicroseconds
	) {
		return false;
	}
	return (
		review.decision !== null &&
		intervalContains(
			review.decision.recorded_from,
			review.decision.recorded_to,
			occurredMicroseconds
		)
	);
}

function successfulPanelsAgree(
	applicability: RegulatoryApplicability,
	review: RegulatoryApplicabilityReview
): boolean {
	if (
		applicability.obligation_id !== review.obligation_id ||
		applicability.obligation_revision !== review.obligation_revision ||
		applicability.evaluation_status !== review.evaluation_status ||
		applicability.non_binding_result !== review.computed_non_binding_result ||
		(applicability.decision === null) !== (review.decision === null)
	) {
		return false;
	}

	if (applicability.decision === null || review.decision === null) return true;
	return (
		sameUuid(applicability.decision.id, review.decision.id) &&
		applicability.decision.record_id === review.decision.record_id &&
		applicability.decision.revision === review.decision.revision &&
		applicability.decision.semantic_payload_sha256.toLowerCase() ===
			review.decision.semantic_payload_sha256.toLowerCase()
	);
}

function unavailablePair(): RegulatoryPanelPair {
	return {
		applicability: { state: 'unavailable', data: null },
		review: { state: 'unavailable', data: null }
	};
}

export function enforceRegulatoryPanelCoherence({
	document,
	request,
	applicability,
	review
}: {
	document: RegulatoryDocumentDetail;
	request: RegulatoryRequestIdentity;
	applicability: RegulatoryReadPanel<RegulatoryApplicability>;
	review: RegulatoryReadPanel<RegulatoryApplicabilityReview>;
}): RegulatoryPanelPair {
	if (!isRegulatoryDocumentResponseCoherent(document, request)) return unavailablePair();

	if (
		applicability.state === 'ok' &&
		(applicability.data === null ||
			!panelIdentityIsCoherent(applicability.data, document, request, 'applicability'))
	) {
		return unavailablePair();
	}
	if (
		review.state === 'ok' &&
		(review.data === null ||
			!panelIdentityIsCoherent(review.data, document, request, 'review') ||
			!reviewDispositionIsCoherent(review.data))
	) {
		return unavailablePair();
	}

	if (
		applicability.state === 'ok' &&
		applicability.data !== null &&
		review.state === 'ok' &&
		review.data !== null &&
		!successfulPanelsAgree(applicability.data, review.data)
	) {
		return unavailablePair();
	}

	return { applicability, review };
}
