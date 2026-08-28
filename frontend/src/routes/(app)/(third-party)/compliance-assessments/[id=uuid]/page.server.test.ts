import { describe, expect, it, vi } from 'vitest';

const modelCatalog = vi.hoisted(() => ({
	complianceAssessment: {
		name: 'complianceassessment',
		localName: 'complianceAssessment',
		localNamePlural: 'complianceAssessments',
		verboseName: 'Compliance assessment',
		selectFields: [{ field: 'status' }, { field: 'score_calculation_method' }]
	},
	validationFlow: {
		name: 'validationflow',
		localName: 'validationFlow',
		localNamePlural: 'validationFlows',
		verboseName: 'Validation flow',
		selectFields: [{ field: 'status' }, { field: 'approver' }]
	}
}));

vi.mock('$lib/utils/crud', () => ({
	getModelInfo: (model: string) =>
		model === 'validation-flows' ? modelCatalog.validationFlow : modelCatalog.complianceAssessment
}));

vi.mock('$lib/utils/load', () => ({
	formatSelectFieldData: (responseData: Record<string, string>) =>
		Object.entries(responseData).map(([value, label]) => ({ label, value }))
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
import { viewerRoleFromTreeResponse } from './viewer-role';

const assessmentId = '4819de76-fce4-4a1c-bb3b-e97d80b61ab7';
const folderId = '7fe956d8-a98e-43f2-bdd6-2d48922c41f7';
const frameworkId = '84ac7fdd-a01f-421d-bb76-d3cc783d9876';
const perimeterId = '19115d29-e724-4675-a94b-950f559d2a01';
const endpoint = `http://localhost:8000/api/compliance-assessments/${assessmentId}/`;

const complianceAssessment = {
	id: assessmentId,
	name: 'Synthetic assessment',
	folder: { id: folderId },
	framework: { id: frameworkId },
	perimeter: { id: perimeterId }
};

const jsonResponse = (
	payload: unknown,
	{ status = 200, viewerRole }: { status?: number; viewerRole?: string } = {}
) =>
	new Response(JSON.stringify(payload), {
		status,
		headers: {
			'Content-Type': 'application/json',
			...(viewerRole === undefined ? {} : { 'X-Viewer-Role': viewerRole })
		}
	});

const makeFetch = ({
	viewerRole,
	optionalStatus = 200,
	folder = complianceAssessment.folder
}: {
	viewerRole?: string;
	optionalStatus?: number;
	folder?: { id: string } | null;
}) =>
	vi.fn(async (input: RequestInfo | URL) => {
		const url = String(input);
		if (url === endpoint) return jsonResponse({ ...complianceAssessment, folder });
		if (url === `${endpoint}tree/`) {
			return jsonResponse({ synthetic: { id: 'synthetic' } }, { viewerRole });
		}
		if (url === `${endpoint}donut_data/`) {
			return jsonResponse({ viewer_role: viewerRole ?? 'respondent' });
		}
		if (url === `${endpoint}global_score/`) {
			return jsonResponse({ viewer_role: viewerRole ?? 'respondent', scoring_enabled: false });
		}
		if (url === `${endpoint}object/`) {
			return jsonResponse({ id: assessmentId, write_data: true }, { status: optionalStatus });
		}
		if (url === `${endpoint}threats_metrics/`) {
			return jsonResponse(
				{ threats: [], total_unique_threats: 1, graph: { nodes: [{ name: 'synthetic' }] } },
				{ status: optionalStatus }
			);
		}
		if (url === `${endpoint}frameworks/`) {
			return jsonResponse([{ id: frameworkId }], { status: optionalStatus });
		}
		if (url === 'http://localhost:8000/api/compliance-assessments/status/') {
			return jsonResponse({ planned: 'Planned' });
		}
		if (url === 'http://localhost:8000/api/compliance-assessments/score_calculation_method/') {
			return jsonResponse({ average: 'Average' });
		}
		if (url === 'http://localhost:8000/api/validation-flows/status/') {
			return jsonResponse({ pending: 'Pending review' });
		}
		if (url === 'http://localhost:8000/api/validation-flows/approver/') {
			return jsonResponse({ 'approver-id': 'Named approver' });
		}
		throw new Error(`Unexpected request: ${url}`);
	}) as unknown as typeof fetch;

const callLoad = async (fetchFn: typeof fetch, requestViewerRole?: string) =>
	await (load as (event: unknown) => Promise<Record<string, any>>)({
		fetch: fetchFn,
		params: { id: assessmentId },
		cookies: { get: vi.fn() },
		locals: { featureflags: {} },
		request: new Request(`http://localhost/compliance-assessments/${assessmentId}`, {
			headers: requestViewerRole === undefined ? undefined : { 'X-Viewer-Role': requestViewerRole }
		})
	});

const responseWithViewerRole = (viewerRole?: string) =>
	new Response(null, {
		headers: viewerRole === undefined ? undefined : { 'X-Viewer-Role': viewerRole }
	});

describe('compliance assessment viewer role', () => {
	it('accepts the backend auditor classification', () => {
		expect(viewerRoleFromTreeResponse(responseWithViewerRole('auditor'))).toBe('auditor');
	});

	it.each([undefined, '', 'respondent', 'Auditor', 'administrator'])(
		'fails closed to respondent for %s',
		(viewerRole) => {
			expect(viewerRoleFromTreeResponse(responseWithViewerRole(viewerRole))).toBe('respondent');
		}
	);
});

describe('compliance assessment server loader authorization boundary', () => {
	it('ignores a client-supplied role header and skips every auditor-only request', async () => {
		const fetchFn = makeFetch({});

		const result = await callLoad(fetchFn, 'auditor');
		const urls = vi.mocked(fetchFn).mock.calls.map(([input]) => String(input));

		expect(result).toMatchObject({
			viewerRole: 'respondent',
			object: null,
			frameworksMappings: [],
			threats: { threats: [], total_unique_threats: 0, graph: { nodes: [] } },
			auditModel: { selectOptions: {} },
			validationFlowModel: null
		});
		expect(result.validationFlowForm).toBeNull();
		expect(urls).toEqual([
			endpoint,
			`${endpoint}tree/`,
			`${endpoint}donut_data/`,
			`${endpoint}global_score/`
		]);
		expect(urls).not.toEqual(
			expect.arrayContaining([
				`${endpoint}object/`,
				`${endpoint}threats_metrics/`,
				`${endpoint}frameworks/`
			])
		);
		expect(urls.some((url) => url.includes('/validation-flows/'))).toBe(false);
	});

	it('preserves the fully authorized auditor payload and request contract', async () => {
		const fetchFn = makeFetch({ viewerRole: 'auditor' });

		const result = await callLoad(fetchFn);
		const urls = vi.mocked(fetchFn).mock.calls.map(([input]) => String(input));

		expect(result.viewerRole).toBe('auditor');
		expect(result.object).toEqual({ id: assessmentId, write_data: true });
		expect(result.frameworksMappings).toEqual([{ id: frameworkId }]);
		expect(result.threats.total_unique_threats).toBe(1);
		expect(result.validationFlowForm).not.toBeNull();
		expect(result.validationFlowModel.selectOptions).toEqual({
			status: [{ label: 'Pending review', value: 'pending' }],
			approver: [{ label: 'Named approver', value: 'approver-id' }]
		});
		expect(result.auditModel.selectOptions).toEqual({
			status: [{ label: 'Planned', value: 'planned' }],
			score_calculation_method: [{ label: 'Average', value: 'average' }]
		});
		expect(urls).toEqual(
			expect.arrayContaining([
				`${endpoint}object/`,
				`${endpoint}threats_metrics/`,
				`${endpoint}frameworks/`,
				'http://localhost:8000/api/compliance-assessments/status/',
				'http://localhost:8000/api/compliance-assessments/score_calculation_method/',
				'http://localhost:8000/api/validation-flows/status/',
				'http://localhost:8000/api/validation-flows/approver/'
			])
		);
	});

	it('keeps a least-privilege respondent page renderable without inventing a folder', async () => {
		const fetchFn = makeFetch({ folder: null });

		const result = await callLoad(fetchFn);
		const urls = vi.mocked(fetchFn).mock.calls.map(([input]) => String(input));

		expect(result.viewerRole).toBe('respondent');
		expect(result.compliance_assessment.folder).toBeNull();
		expect(result.validationFlowForm).toBeNull();
		expect(result.validationFlowModel).toBeNull();
		expect(urls).toEqual([
			endpoint,
			`${endpoint}tree/`,
			`${endpoint}donut_data/`,
			`${endpoint}global_score/`
		]);
	});

	it('does not leak auditor select options into a later respondent SSR load', async () => {
		const auditorResult = await callLoad(makeFetch({ viewerRole: 'auditor' }));
		const respondentResult = await callLoad(makeFetch({}));

		expect(Object.keys(auditorResult.auditModel.selectOptions)).toHaveLength(2);
		expect(Object.keys(auditorResult.validationFlowModel.selectOptions)).toHaveLength(2);
		expect(respondentResult.auditModel.selectOptions).toEqual({});
		expect(respondentResult.validationFlowModel).toBeNull();
		expect(auditorResult.auditModel).not.toBe(respondentResult.auditModel);
		expect(auditorResult.auditModel).not.toBe(modelCatalog.complianceAssessment);
		expect(auditorResult.validationFlowModel).not.toBe(modelCatalog.validationFlow);
		expect(modelCatalog.complianceAssessment).not.toHaveProperty('selectOptions');
		expect(modelCatalog.validationFlow).not.toHaveProperty('selectOptions');
	});

	it('keeps optional auditor analytics failures from crashing the assessment page', async () => {
		const result = await callLoad(makeFetch({ viewerRole: 'auditor', optionalStatus: 403 }));

		expect(result).toMatchObject({
			viewerRole: 'auditor',
			object: null,
			frameworksMappings: [],
			threats: { threats: [], total_unique_threats: 0, graph: { nodes: [] } }
		});
	});

	it('rejects a failed tree response before trusting its forged auditor header', async () => {
		const fetchFn = vi.fn(async (input: RequestInfo | URL) => {
			const url = String(input);
			if (url === endpoint) return jsonResponse(complianceAssessment);
			if (url === `${endpoint}tree/`) {
				return jsonResponse({ detail: 'forbidden' }, { status: 403, viewerRole: 'auditor' });
			}
			throw new Error(`Auditor-only request escaped after failed tree: ${url}`);
		}) as unknown as typeof fetch;

		await expect(callLoad(fetchFn)).rejects.toMatchObject({ status: 403 });
		expect(fetchFn).toHaveBeenCalledTimes(2);
	});
});
