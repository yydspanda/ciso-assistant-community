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
	message: (form: Record<string, unknown>, value: unknown) => {
		form.message = value;
		return { form };
	},
	setError: (form: { errors: Record<string, string[]> }, field: string, value: string) => {
		form.errors[field] = [value];
	},
	superValidate: async (dataOrAdapter: Record<string, unknown>) => ({
		valid: true,
		data: dataOrAdapter?.syntheticAdapter ? {} : dataOrAdapter,
		errors: {}
	})
}));

import { actions, load } from './+page.server';

const assessmentId = '4819de76-fce4-4a1c-bb3b-e97d80b61ab7';
const requirementAssessmentId = '7fe956d8-a98e-43f2-bdd6-2d48922c41f7';
const requirementId = '84ac7fdd-a01f-421d-bb76-d3cc783d9876';
const endpoint = `http://localhost:8000/api/compliance-assessments/${assessmentId}/`;
const requirementAssessmentEndpoint = `http://localhost:8000/api/requirement-assessments/${requirementAssessmentId}/`;

function boundRequirementAssessment(overrides: Record<string, unknown> = {}) {
	return {
		id: requirementAssessmentId,
		compliance_assessment: { id: assessmentId },
		...overrides
	};
}

function routeBoundFetch(
	patchResponse: () => Response,
	boundObject: Record<string, unknown> = boundRequirementAssessment()
) {
	return vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
		if (init?.method === 'PATCH') return patchResponse();
		return Response.json(boundObject);
	});
}

function scalarRequest(body: unknown): Request {
	return new Request('http://localhost/table-mode?/updateRequirementAssessment', {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify(body)
	});
}

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

describe('table-mode update action', () => {
	it.each([
		['evidences', ['a79f2603-b180-4a1c-9c82-f4a1ff9a324d']],
		['applied_controls', ['99fd4ef2-8f17-46d9-9460-9de3860f0c1f']]
	] as const)('PATCHes only the allowlisted %s relationship', async (field, ids) => {
		const writtenObject = boundRequirementAssessment({ [field]: [...ids] });
		const fetchFn = routeBoundFetch(() => Response.json(writtenObject));
		// This guards unrelated fields only. Same-field concurrent writes do not have
		// an ordering guarantee until the API offers a version/delta contract.
		const requestData = {
			[field]: [...ids],
			status: 'done',
			comment: 'must not be forwarded from a stale modal'
		};

		const result = await actions.update({
			request: requestData,
			url: new URL(
				`http://localhost/table-mode?/update&id=${requirementAssessmentId}&field=${field}`
			),
			fetch: fetchFn,
			params: { id: assessmentId },
			cookies: { set: vi.fn() }
		} as never);

		expect(fetchFn).toHaveBeenNthCalledWith(1, requirementAssessmentEndpoint);
		expect(fetchFn).toHaveBeenNthCalledWith(2, requirementAssessmentEndpoint, {
			method: 'PATCH',
			body: JSON.stringify({ [field]: [...ids] })
		});
		expect(result).toMatchObject({
			form: {
				valid: true,
				message: {
					object: writtenObject,
					field,
					toast: { type: 'success' }
				}
			}
		});
	});

	it('fails closed when the API does not apply the requested relationship field', async () => {
		const requestedEvidence = 'a79f2603-b180-4a1c-9c82-f4a1ff9a324d';
		const fetchFn = routeBoundFetch(() =>
			Response.json(boundRequirementAssessment({ evidences: [] }))
		);
		const result = await actions.update({
			request: { evidences: [requestedEvidence] },
			url: new URL(
				`http://localhost/table-mode?/update&id=${requirementAssessmentId}&field=evidences`
			),
			fetch: fetchFn,
			params: { id: assessmentId },
			cookies: { set: vi.fn() }
		} as never);

		expect(result).toMatchObject({
			status: 409,
			data: {
				form: {
					errors: {
						evidences: ['The relationship update was not applied by the authoritative API.']
					}
				}
			}
		});
	});

	it('keeps an API denial in the modal as a field-scoped error', async () => {
		const fetchFn = routeBoundFetch(() =>
			Response.json({ detail: 'Permission denied' }, { status: 403, statusText: 'Forbidden' })
		);
		const result = await actions.update({
			request: { evidences: [] },
			url: new URL(
				`http://localhost/table-mode?/update&id=${requirementAssessmentId}&field=evidences`
			),
			fetch: fetchFn,
			params: { id: assessmentId },
			cookies: { set: vi.fn() }
		} as never);

		expect(fetchFn).toHaveBeenNthCalledWith(2, requirementAssessmentEndpoint, {
			method: 'PATCH',
			body: JSON.stringify({ evidences: [] })
		});
		expect(result).toMatchObject({
			status: 403,
			data: { form: { errors: { evidences: ['Permission denied'] } } }
		});
	});

	it.each([
		[`http://localhost/table-mode?/update&field=evidences`, 'missing id'],
		[`http://localhost/table-mode?/update&id=not-a-uuid&field=evidences`, 'malformed id'],
		[`http://localhost/table-mode?/update&id=${requirementAssessmentId}`, 'missing field'],
		[
			`http://localhost/table-mode?/update&id=${requirementAssessmentId}&field=status`,
			'unsupported field'
		]
	])('rejects %s without calling the API (%s)', async (url) => {
		const fetchFn = vi.fn();
		const result = await actions.update({
			request: { evidences: [] },
			url: new URL(url),
			fetch: fetchFn,
			params: { id: assessmentId },
			cookies: { set: vi.fn() }
		} as never);

		expect(fetchFn).not.toHaveBeenCalled();
		expect(result).toMatchObject({ status: 400 });
	});

	it.each([
		[
			'mismatched object id',
			() =>
				Response.json({
					id: '468fd310-197e-4763-87a1-f0f18a7ed8af',
					compliance_assessment: { id: assessmentId },
					evidences: []
				})
		],
		['non-JSON body', () => new Response('not json')]
	])('rejects an invalid authoritative response: %s', async (_label, responseFactory) => {
		const fetchFn = routeBoundFetch(responseFactory);
		const result = await actions.update({
			request: { evidences: [] },
			url: new URL(
				`http://localhost/table-mode?/update&id=${requirementAssessmentId}&field=evidences`
			),
			fetch: fetchFn,
			params: { id: assessmentId },
			cookies: { set: vi.fn() }
		} as never);

		expect(result).toMatchObject({
			status: 502,
			data: {
				form: {
					errors: {
						evidences: ['The authoritative API returned an invalid relationship response.']
					}
				}
			}
		});
	});

	it('requires the selected relationship field in the submitted form', async () => {
		const fetchFn = vi.fn();
		const result = await actions.update({
			request: { applied_controls: [], status: 'done' },
			url: new URL(
				`http://localhost/table-mode?/update&id=${requirementAssessmentId}&field=evidences`
			),
			fetch: fetchFn,
			params: { id: assessmentId },
			cookies: { set: vi.fn() }
		} as never);

		expect(fetchFn).not.toHaveBeenCalled();
		expect(result).toMatchObject({ status: 400 });
	});

	it('rejects a relationship id bound to another route assessment without PATCHing', async () => {
		const fetchFn = routeBoundFetch(
			() => Response.json(boundRequirementAssessment({ evidences: [] })),
			boundRequirementAssessment({
				compliance_assessment: { id: '58e12951-75c3-42f3-a49d-8373a30a159b' }
			})
		);
		const result = await actions.update({
			request: { evidences: [] },
			url: new URL(
				`http://localhost/table-mode?/update&id=${requirementAssessmentId}&field=evidences`
			),
			fetch: fetchFn,
			params: { id: assessmentId },
			cookies: { set: vi.fn() }
		} as never);

		expect(fetchFn).toHaveBeenCalledTimes(1);
		expect(fetchFn).toHaveBeenCalledWith(requirementAssessmentEndpoint);
		expect(result).toMatchObject({ status: 403 });
	});
});

describe('table-mode scalar update action', () => {
	it('PATCHes only a strict allowlisted scalar field after binding it to the route', async () => {
		const writtenObject = boundRequirementAssessment({ status: 'done' });
		const fetchFn = routeBoundFetch(() => Response.json(writtenObject));
		const result = await actions.updateRequirementAssessment({
			request: scalarRequest({
				id: requirementAssessmentId,
				status: 'done'
			}),
			fetch: fetchFn,
			params: { id: assessmentId }
		} as never);

		expect(fetchFn).toHaveBeenNthCalledWith(1, requirementAssessmentEndpoint);
		expect(fetchFn).toHaveBeenNthCalledWith(2, requirementAssessmentEndpoint, {
			method: 'PATCH',
			body: JSON.stringify({ status: 'done' })
		});
		expect(result).toEqual({ object: writtenObject });
	});

	it.each([
		[
			'forged field',
			{
				id: requirementAssessmentId,
				status: 'done',
				folder: 'b19ca2be-f8a8-4e05-aade-490c97374fd4'
			}
		],
		['malformed id', { id: 'not-a-uuid', status: 'done' }],
		['unsupported enum value', { id: requirementAssessmentId, status: 'approved' }]
	])('rejects %s before any API request', async (_label, body) => {
		const fetchFn = vi.fn();
		const result = await actions.updateRequirementAssessment({
			request: scalarRequest(body),
			fetch: fetchFn,
			params: { id: assessmentId }
		} as never);

		expect(fetchFn).not.toHaveBeenCalled();
		expect(result).toMatchObject({ status: 400 });
	});

	it('rejects an id bound to another route assessment without PATCHing', async () => {
		const fetchFn = routeBoundFetch(
			() => Response.json(boundRequirementAssessment({ status: 'done' })),
			boundRequirementAssessment({
				compliance_assessment: { id: '58e12951-75c3-42f3-a49d-8373a30a159b' }
			})
		);
		const result = await actions.updateRequirementAssessment({
			request: scalarRequest({ id: requirementAssessmentId, status: 'done' }),
			fetch: fetchFn,
			params: { id: assessmentId }
		} as never);

		expect(fetchFn).toHaveBeenCalledTimes(1);
		expect(fetchFn).toHaveBeenCalledWith(requirementAssessmentEndpoint);
		expect(result).toMatchObject({ status: 403 });
	});

	it('preserves an authoritative PATCH 403 response', async () => {
		const fetchFn = routeBoundFetch(() =>
			Response.json({ detail: 'Permission denied' }, { status: 403, statusText: 'Forbidden' })
		);
		const result = await actions.updateRequirementAssessment({
			request: scalarRequest({ id: requirementAssessmentId, observation: 'new note' }),
			fetch: fetchFn,
			params: { id: assessmentId }
		} as never);

		expect(fetchFn).toHaveBeenNthCalledWith(2, requirementAssessmentEndpoint, {
			method: 'PATCH',
			body: JSON.stringify({ observation: 'new note' })
		});
		expect(result).toMatchObject({
			status: 403,
			data: { error: 'Permission denied' }
		});
	});

	it.each([
		['empty 204 response', () => new Response(null, { status: 204 })],
		['non-JSON response', () => new Response('not json')]
	])('fails closed on a successful %s', async (_label, responseFactory) => {
		const fetchFn = routeBoundFetch(responseFactory);
		const result = await actions.updateRequirementAssessment({
			request: scalarRequest({ id: requirementAssessmentId, score: 42 }),
			fetch: fetchFn,
			params: { id: assessmentId }
		} as never);

		expect(fetchFn).toHaveBeenCalledTimes(2);
		expect(result).toMatchObject({ status: 502 });
	});

	it('fails closed when the authoritative API silently ignores the field', async () => {
		const fetchFn = routeBoundFetch(() =>
			Response.json(boundRequirementAssessment({ status: 'to_do' }))
		);
		const result = await actions.updateRequirementAssessment({
			request: scalarRequest({ id: requirementAssessmentId, status: 'done' }),
			fetch: fetchFn,
			params: { id: assessmentId }
		} as never);

		expect(result).toMatchObject({ status: 409 });
	});
});
