import { render, screen } from '@testing-library/svelte';
import '@testing-library/jest-dom/vitest';
import { describe, expect, it } from 'vitest';

import type {
	RegulatoryApplicability,
	RegulatoryApplicabilityDecision,
	RegulatoryApplicabilityReview,
	RegulatoryReadPanel
} from '$lib/regulatory/types';
import RegulatoryApplicabilityPanel from './RegulatoryApplicabilityPanel.svelte';

const entityId = '3dd2af97-4c34-4e51-82b8-ceb92645e784';
const documentId = '4819de76-fce4-4a1c-bb3b-e97d80b61ab7';
const hash = 'a'.repeat(64);
const selectedRecordedAt = '2026-08-26T09:30:00+08:00';

const decision: RegulatoryApplicabilityDecision = {
	id: 'b802312e-4d22-428e-b8fa-6612db4bfb4e',
	record_id: 'SYNTHETIC-DECISION-001',
	revision: 1,
	fact_snapshot_id: 'SYNTHETIC-FACT-SNAPSHOT-001',
	scope: { type: 'legal_entity', id: entityId },
	rule: {
		id: 'SYNTHETIC-ENTITY-INSTITUTION-TYPE-BANK-001',
		version: 1,
		all: [{ fact: 'entity.institution_type', operator: 'eq', value: 'bank' }],
		any: [],
		unknown_result: 'needs_review'
	},
	facts: [
		{
			fact: 'entity.institution_type',
			known: false,
			source_refs: [],
			observed_at: null
		}
	],
	missing_fact_keys: ['entity.institution_type'],
	result: 'needs_review',
	rationale_code: 'missing_or_unknown_fact',
	rationale: 'The required institution type fact is unknown.',
	valid_from: null,
	valid_to: null,
	recorded_from: selectedRecordedAt,
	recorded_to: null,
	review_status: 'draft',
	is_binding: false,
	digest_schema: 'regulatory-applicability-evaluation/v1',
	evaluator_profile: 'synthetic-single-condition/v1',
	rule_snapshot_sha256: hash,
	fact_snapshot_sha256: hash,
	semantic_payload_sha256: hash,
	provenance: {
		method: 'human',
		created_at: selectedRecordedAt,
		created_by: 'synthetic-test',
		parser_version: null,
		model: null,
		prompt_version: null,
		retrieval_version: null
	},
	legal_conclusion: false
};

const applicability: RegulatoryReadPanel<RegulatoryApplicability> = {
	state: 'ok',
	data: {
		contract_status: 'draft',
		legal_conclusion: false,
		is_binding: false,
		scope: { type: 'legal_entity', id: entityId },
		document_id: documentId,
		obligation_id: 'SYNTHETIC-OBLIGATION-001',
		obligation_revision: 1,
		recorded_as_of: null,
		selected_recorded_at: selectedRecordedAt,
		evaluation_status: 'evaluated',
		non_binding_result: 'needs_review',
		reason_code: 'missing_or_unknown_fact',
		decision
	}
};

const review: RegulatoryReadPanel<RegulatoryApplicabilityReview> = {
	state: 'ok',
	data: {
		contract_status: 'draft',
		legal_conclusion: false,
		is_binding: false,
		scope: { type: 'legal_entity', id: entityId },
		document_id: documentId,
		obligation_id: 'SYNTHETIC-OBLIGATION-001',
		obligation_revision: 1,
		recorded_as_of: null,
		selected_recorded_at: selectedRecordedAt,
		evaluation_status: 'evaluated',
		computed_non_binding_result: 'needs_review',
		decision,
		review_state: 'no_correction_requested',
		workflow_attention: 'needs_review',
		latest_disposition: {
			id: '725d5f66-81bb-4796-81bc-a630e46e6391',
			sequence: 1,
			from_disposition: 'not_reviewed',
			to_disposition: 'no_correction_requested',
			reason_code: 'review_completed',
			rationale: 'No correction was requested for this exact synthetic record.',
			occurred_at: selectedRecordedAt,
			digest_profile: 'regulatory-applicability-review-disposition/v1',
			decision_semantic_payload_sha256: hash,
			event_payload_sha256: hash,
			reviewer: { masked: true }
		}
	}
};

describe('RegulatoryApplicabilityPanel', () => {
	it('keeps unknown facts in needs-review state after no-correction disposition', () => {
		render(RegulatoryApplicabilityPanel, { applicability, review });

		expect(screen.getAllByText('Needs review').length).toBeGreaterThan(0);
		expect(screen.getAllByText('entity.institution_type')).toHaveLength(2);
		expect(screen.getByText('Unknown')).toBeInTheDocument();
		expect(screen.getByText('entity.institution_type eq bank')).toBeInTheDocument();
		expect(
			screen.getByText('The required institution-type fact is missing or unknown.')
		).toBeInTheDocument();
		expect(
			screen.getByText(
				/No correction requested means only that this reviewer did not request correction/
			)
		).toBeInTheDocument();
		expect(screen.getByText('Identity masked by IAM')).toBeInTheDocument();
		expect(screen.getByText('Disposition sequence')).toBeInTheDocument();
		expect(screen.getByText('Previous disposition')).toBeInTheDocument();
		expect(screen.getByText('Bound decision semantic SHA-256')).toBeInTheDocument();
		expect(screen.getByText('Disposition event SHA-256')).toBeInTheDocument();
		expect(screen.getByText('Valid-time interval')).toBeInTheDocument();
		expect(screen.getByText(/Valid time is distinct from recorded time/)).toBeInTheDocument();
		expect(screen.queryByRole('button')).not.toBeInTheDocument();
	});

	it('offers an explicit retry when applicability is unavailable', () => {
		render(RegulatoryApplicabilityPanel, {
			applicability: { state: 'unavailable', data: null },
			review: { state: 'idle', data: null },
			retryHref: '/regulatory/synthetic?entity=synthetic'
		});

		expect(screen.getByRole('link', { name: 'Retry' })).toHaveAttribute(
			'href',
			'/regulatory/synthetic?entity=synthetic'
		);
	});

	it('offers an explicit retry when only human review is unavailable', () => {
		render(RegulatoryApplicabilityPanel, {
			applicability,
			review: { state: 'unavailable', data: null },
			retryHref: '/regulatory/synthetic?entity=synthetic'
		});

		expect(screen.getByRole('link', { name: 'Retry' })).toHaveAttribute(
			'href',
			'/regulatory/synthetic?entity=synthetic'
		);
	});
});
