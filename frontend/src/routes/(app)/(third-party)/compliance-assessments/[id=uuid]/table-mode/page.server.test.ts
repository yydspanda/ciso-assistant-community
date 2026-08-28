import { describe, expect, it, vi } from 'vitest';

vi.mock('$lib/utils/actions', () => ({
	handleErrorResponse: vi.fn(),
	nestedWriteFormAction: vi.fn()
}));

vi.mock('$lib/utils/crud', () => ({
	getModelInfo: (name: string) => ({ name, localName: name })
}));

vi.mock('$lib/utils/schemas', () => ({
	modelSchema: (name: string) => ({ name })
}));

vi.mock('$lib/utils/i18n', () => ({
	safeTranslate: (value: string) => value
}));

vi.mock('sveltekit-superforms/adapters', () => ({
	zod4: (schema: unknown) => ({ schema, syntheticAdapter: true })
}));

vi.mock('sveltekit-superforms', () => ({
	fail: (status: number, data: unknown) => ({ status, data }),
	superValidate: async (dataOrAdapter: Record<string, unknown>) => ({
		valid: true,
		data: dataOrAdapter?.syntheticAdapter ? {} : dataOrAdapter,
		errors: {}
	})
}));

import { load } from './+page.server';

const assessmentId = '4819de76-fce4-4a1c-bb3b-e97d80b61ab7';
const requirementAssessmentId = '7fe956d8-a98e-43f2-bdd6-2d48922c41f7';
const requirementId = '84ac7fdd-a01f-421d-bb76-d3cc783d9876';
const endpoint = `http://localhost:8000/api/compliance-assessments/${assessmentId}/`;

describe('table-mode server loader authorization boundary', () => {
	it('preserves a hidden folder as null and disables folder-bound create forms', async () => {
		const fetchFn = vi.fn(async (input: RequestInfo | URL) => {
			const url = String(input);
			if (url === endpoint) {
				return Response.json({
					id: assessmentId,
					name: 'Least-privilege assessment',
					folder: null,
					framework: null
				});
			}
			if (url === `${endpoint}requirements_list/`) {
				return Response.json({
					viewer_role: 'respondent',
					requirements: [{ id: requirementId }],
					requirement_assessments: [
						{
							id: requirementAssessmentId,
							folder: null,
							requirement: { id: requirementId },
							compliance_assessment: { id: assessmentId },
							observation: '',
							is_scored: false,
							score: null,
							documentation_score: null,
							evidences: [],
							applied_controls: []
						}
					]
				});
			}
			if (url === `${endpoint}global_score/`) return Response.json({ scoring_enabled: false });
			throw new Error(`Unexpected request: ${url}`);
		}) as unknown as typeof fetch;

		const result = await (load as (event: unknown) => Promise<Record<string, any>>)({
			fetch: fetchFn,
			params: { id: assessmentId }
		});

		expect(result.viewerRole).toBe('respondent');
		expect(result.compliance_assessment.folder).toBeNull();
		expect(result.requirement_assessments).toHaveLength(1);
		const row = result.requirement_assessments[0];
		expect(row.folder).toBeNull();
		expect(row.measureCreateForm).toBeNull();
		expect(row.evidenceCreateForm).toBeNull();
		expect(row.object).not.toHaveProperty('folder');
	});
});
