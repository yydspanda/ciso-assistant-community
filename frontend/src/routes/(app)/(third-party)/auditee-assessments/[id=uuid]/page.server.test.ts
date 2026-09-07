import { describe, expect, it, vi } from 'vitest';
import { superValidate } from 'sveltekit-superforms';

vi.mock('$lib/utils/actions', () => ({
	defaultWriteFormAction: vi.fn(),
	handleErrorResponse: vi.fn()
}));

vi.mock('$lib/utils/crud', () => ({
	getModelInfo: (name: string) => ({ name, localName: name })
}));

vi.mock('$lib/utils/schemas', () => ({
	modelSchema: (name: string) => ({ name }),
	RequirementAssessmentRelationSchema: { name: 'requirement-assessment-relations' }
}));

vi.mock('$lib/utils/i18n', () => ({
	safeTranslate: (value: string) => value
}));

vi.mock('sveltekit-superforms/adapters', () => ({
	zod4: (schema: unknown) => ({ schema })
}));

vi.mock('sveltekit-superforms', () => ({
	message: vi.fn(),
	superValidate: vi.fn()
}));

vi.mock('sveltekit-flash-message/server', () => ({
	setFlash: vi.fn()
}));

import { actions, load } from './+page.server';
import { defaultWriteFormAction } from '$lib/utils/actions';

const assignmentId = '4819de76-fce4-4a1c-bb3b-e97d80b61ab7';
const requirementAssessmentId = '7fe956d8-a98e-43f2-bdd6-2d48922c41f7';

describe('auditee assignment mutation boundary', () => {
	it('maps multiple requirement assessments by their nested requirement IDs', async () => {
		const complianceAssessmentId = '71345631-ec7d-4f9f-ae60-779f58be9340';
		const requirementNodeIds = [
			'55069928-73bb-47d1-a04e-4293f624f4e7',
			'b5be5c69-4254-49cf-a197-8b578cc72a73'
		];
		const assessmentIds = [
			'31e268f6-dae9-42c9-b6af-55eecae6fb28',
			'4523f792-d80f-4476-b1d3-3298f3e0819e'
		];
		const fetchFn = vi.fn(async (input: string) => {
			if (input.endsWith(`/requirement-assignments/${assignmentId}/`)) {
				return Response.json({
					id: assignmentId,
					status: 'in_progress',
					compliance_assessment: { id: complianceAssessmentId }
				});
			}
			if (input.endsWith(`/compliance-assessments/${complianceAssessmentId}/`)) {
				return Response.json({
					id: complianceAssessmentId,
					name: 'Delegated audit',
					framework: null
				});
			}
			if (input.endsWith(`/requirement-assignments/${assignmentId}/requirements_list/`)) {
				return Response.json({
					viewer_role: 'respondent',
					requirements: requirementNodeIds.map((id) => ({ id, kind: 'node' })),
					requirement_assessments: requirementNodeIds.map((id, index) => ({
						id: assessmentIds[index],
						requirement: { id },
						compliance_assessment: { id: complianceAssessmentId },
						folder: { id: '0a621a1b-a640-4796-aa43-61979a77712c' },
						evidences: [],
						applied_controls: []
					}))
				});
			}
			throw new Error(`Unexpected fetch: ${input}`);
		});

		const result = await load({
			params: { id: assignmentId },
			fetch: fetchFn
		} as never);

		expect(result.requirements.map((item: { id: string }) => item.id)).toEqual(assessmentIds);
	});

	it('updates a row through its assignment-scoped endpoint', async () => {
		const payload = { id: requirementAssessmentId, result: 'compliant' };
		const fetchFn = vi.fn(async () => Response.json({ id: requirementAssessmentId }));
		const action = actions.updateRequirementAssessment;
		if (!action) throw new Error('updateRequirementAssessment action is unavailable');

		const result = await action({
			params: { id: assignmentId },
			request: new Request('http://localhost/auditee-assessments', {
				method: 'POST',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify(payload)
			}),
			fetch: fetchFn
		} as never);

		expect(fetchFn).toHaveBeenCalledOnce();
		expect(fetchFn).toHaveBeenCalledWith(
			`http://localhost:8000/api/requirement-assignments/${assignmentId}/requirement-assessments/${requirementAssessmentId}/`,
			{
				method: 'PATCH',
				body: JSON.stringify({ result: 'compliant' })
			}
		);
		expect(result).toEqual({
			status: 200,
			body: { id: requirementAssessmentId }
		});
	});

	it.each([
		['updateRequirementAssessment', '../evidences/target'],
		['updateRequirementAssessment', null]
	])('rejects an invalid row id before %s can fetch', async (actionName, id) => {
		const fetchFn = vi.fn();
		const action = actions[actionName];
		if (!action) throw new Error(`${actionName} action is unavailable`);

		const result = await action({
			params: { id: assignmentId },
			request: new Request('http://localhost/auditee-assessments', {
				method: 'POST',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify({ id, result: 'compliant' })
			}),
			fetch: fetchFn
		} as never);

		expect(fetchFn).not.toHaveBeenCalled();
		expect(result).toMatchObject({ status: 400 });
	});

	it('rejects a dot-segment relation id before the server proxy can fetch', async () => {
		const fetchFn = vi.fn();
		const action = actions.update;
		if (!action) throw new Error('update action is unavailable');

		const result = await action({
			params: { id: assignmentId },
			url: new URL(
				'http://localhost/auditee-assessments?/update&id=../evidences/target&field=evidences'
			),
			request: new Request('http://localhost/auditee-assessments', {
				method: 'POST',
				body: new FormData()
			}),
			fetch: fetchFn
		} as never);

		expect(fetchFn).not.toHaveBeenCalled();
		expect(result).toMatchObject({ status: 400 });
	});

	it.each([
		['createEvidence', 'evidences'],
		['createAppliedControl', 'applied-controls']
	])('pins %s to its named backend model', async (actionName, urlModel) => {
		vi.mocked(defaultWriteFormAction).mockResolvedValueOnce({} as never);
		const formData = new FormData();
		formData.set('urlmodel', '../users');
		const fetchFn = vi.fn();
		const event = {
			params: { id: assignmentId },
			request: new Request('http://localhost/auditee-assessments', {
				method: 'POST',
				body: formData
			}),
			fetch: fetchFn
		};
		const action = actions[actionName];
		if (!action) throw new Error(`${actionName} action is unavailable`);

		await action(event as never);

		expect(defaultWriteFormAction).toHaveBeenCalledWith({
			event,
			urlModel,
			action: 'create',
			doRedirect: false
		});
		expect(fetchFn).not.toHaveBeenCalled();
	});

	it('loads a redacted requirement folder without creating cross-domain forms', async () => {
		const complianceAssessmentId = '71345631-ec7d-4f9f-ae60-779f58be9340';
		const requirementNodeId = '55069928-73bb-47d1-a04e-4293f624f4e7';
		const fetchFn = vi.fn(async (input: string) => {
			if (input.endsWith(`/requirement-assignments/${assignmentId}/`)) {
				return Response.json({
					id: assignmentId,
					status: 'in_progress',
					compliance_assessment: { id: complianceAssessmentId }
				});
			}
			if (input.endsWith(`/compliance-assessments/${complianceAssessmentId}/`)) {
				return Response.json({
					id: complianceAssessmentId,
					name: 'Least-privilege audit',
					framework: null
				});
			}
			if (input.endsWith(`/requirement-assignments/${assignmentId}/requirements_list/`)) {
				return Response.json({
					viewer_role: 'respondent',
					requirements: [{ id: requirementNodeId, kind: 'node' }],
					requirement_assessments: [
						{
							id: requirementAssessmentId,
							requirement: { id: requirementNodeId },
							compliance_assessment: { id: complianceAssessmentId },
							folder: null,
							evidences: [],
							applied_controls: []
						}
					]
				});
			}
			throw new Error(`Unexpected fetch: ${input}`);
		});

		const result = await load({
			params: { id: assignmentId },
			fetch: fetchFn
		} as never);
		const row = result.requirement_assessments[0];

		expect(row.folder).toBeNull();
		expect(row.measureCreateForm).toBeNull();
		expect(row.evidenceCreateForm).toBeNull();
		expect(row.object.folder).toBeNull();
	});

	it.each([
		['evidences', ['evidence-1']],
		['applied_controls', ['control-1']]
	])('sends only the selected %s relation from a complete modal form', async (field, value) => {
		vi.mocked(superValidate).mockResolvedValueOnce({
			valid: true,
			data: {
				id: requirementAssessmentId,
				evidences: ['evidence-1'],
				applied_controls: ['control-1'],
				folder: '../folders/target',
				compliance_assessment: '../compliance-assessments/target',
				status: 'done',
				result: 'compliant',
				score: 100,
				observation: 'stale'
			}
		} as never);
		const fetchFn = vi.fn(async () => Response.json({ id: requirementAssessmentId }));
		const action = actions.update;
		if (!action) throw new Error('update action is unavailable');

		await action({
			params: { id: assignmentId },
			url: new URL(
				`http://localhost/auditee-assessments?/update&id=${requirementAssessmentId}&field=${field}`
			),
			request: new Request('http://localhost/auditee-assessments', {
				method: 'POST',
				body: new FormData()
			}),
			fetch: fetchFn
		} as never);

		expect(fetchFn).toHaveBeenCalledWith(
			`http://localhost:8000/api/requirement-assignments/${assignmentId}/requirement-assessments/${requirementAssessmentId}/`,
			{
				method: 'PATCH',
				body: JSON.stringify({ [field]: value })
			}
		);
	});
});
