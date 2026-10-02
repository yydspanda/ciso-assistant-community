import { beforeEach, describe, expect, it, vi } from 'vitest';

const { setFlashMock } = vi.hoisted(() => ({ setFlashMock: vi.fn() }));

vi.mock('sveltekit-flash-message/server', () => ({
	setFlash: setFlashMock
}));

vi.mock('$lib/utils/crud', () => ({
	getModelInfo: (name: string) => ({ name, localName: name, urlModel: name }),
	urlParamModelVerboseName: (name: string) => name
}));

vi.mock('$lib/utils/schemas', () => ({
	modelSchema: (name: string) => ({ name, shape: {} })
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
		return form.valid ? { form } : { status: 400, data: { form } };
	},
	setError: (
		form: { valid: boolean; errors: Record<string, string[]> },
		field: string,
		value: string
	) => {
		form.valid = false;
		form.errors[field] = [value];
	},
	superValidate: async (dataOrAdapter: unknown) => {
		let data: Record<string, unknown>;
		if (
			dataOrAdapter !== null &&
			typeof dataOrAdapter === 'object' &&
			typeof (dataOrAdapter as { getAll?: unknown }).getAll === 'function' &&
			typeof (dataOrAdapter as { keys?: unknown }).keys === 'function'
		) {
			const formData = dataOrAdapter as FormData;
			data = {};
			for (const key of new Set(formData.keys())) {
				if (key === 'urlmodel' || key.startsWith('__superform_')) continue;
				const values = formData.getAll(key);
				data[key] = key === 'requirement_assessments' ? values : values.at(-1);
			}
		} else if (dataOrAdapter !== null && typeof dataOrAdapter === 'object') {
			const record = dataOrAdapter as Record<string, unknown>;
			data = record.syntheticAdapter ? {} : record;
		} else {
			data = {};
		}
		return { valid: true, data, errors: {} };
	}
}));

import { actions, load } from './+page.server';

const assessmentId = '4819de76-fce4-4a1c-bb3b-e97d80b61ab7';
const requirementAssessmentId = '7fe956d8-a98e-43f2-bdd6-2d48922c41f7';
const forgedRequirementAssessmentId = '468fd310-197e-4763-87a1-f0f18a7ed8af';
const requirementId = '84ac7fdd-a01f-421d-bb76-d3cc783d9876';
const otherAssessmentId = '58e12951-75c3-42f3-a49d-8373a30a159b';
const evidenceId = 'c8ac9b69-5c9e-42d2-b74b-3f64fa53e276';
const controlId = '3855f6c7-4692-4d37-995a-4bc56374ad07';
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

function nestedCreateRequest(
	urlModel: string,
	requirementAssessmentIds: string[] = [requirementAssessmentId]
): Request {
	const data = new FormData();
	data.set('urlmodel', urlModel);
	data.set('name', `New ${urlModel}`);
	for (const id of requirementAssessmentIds) data.append('requirement_assessments', id);
	return new Request(`http://localhost/table-mode?/create-${urlModel}`, {
		method: 'POST',
		body: data
	});
}

function nestedCreateEvent(request: Request, fetchFn: typeof fetch) {
	return {
		request,
		fetch: fetchFn,
		params: { id: assessmentId },
		url: new URL(request.url),
		cookies: { set: vi.fn() }
	} as never;
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

describe('table-mode governed nested creates', () => {
	const createCases = [
		{
			label: 'evidence',
			action: 'createEvidence' as const,
			urlModel: 'evidences',
			createdId: evidenceId,
			resultField: 'newEvidence'
		},
		{
			label: 'applied control',
			action: 'createAppliedControl' as const,
			urlModel: 'applied-controls',
			createdId: controlId,
			resultField: null
		}
	];

	beforeEach(() => {
		setFlashMock.mockClear();
	});

	it.each(createCases)(
		'binds a valid $label create to the submitted route-owned requirement assessment',
		async ({ action, urlModel, createdId, resultField }) => {
			const createEndpoint = `http://localhost:8000/api/${urlModel}/`;
			const fetchFn = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
				const url = String(input);
				if (url === requirementAssessmentEndpoint && !init) {
					return Response.json(boundRequirementAssessment());
				}
				if (url === createEndpoint && init?.method === 'POST') {
					expect(JSON.parse(String(init.body))).toMatchObject({
						requirement_assessments: [requirementAssessmentId]
					});
					return Response.json({ id: createdId });
				}
				throw new Error(`Unexpected request: ${url}`);
			}) as unknown as typeof fetch;

			const result = await actions[action]!(
				nestedCreateEvent(nestedCreateRequest(urlModel), fetchFn)
			);

			expect(fetchFn).toHaveBeenNthCalledWith(1, requirementAssessmentEndpoint);
			expect(fetchFn).toHaveBeenNthCalledWith(
				2,
				createEndpoint,
				expect.objectContaining({ method: 'POST' })
			);
			expect(result).toMatchObject({ form: { message: { object: { id: createdId } } } });
			if (resultField) expect(result).toHaveProperty(resultField, { id: createdId });
		}
	);

	it.each(createCases)(
		'rejects a forged urlmodel for $label before any API request',
		async ({ action, urlModel }) => {
			const forgedUrlModel = urlModel === 'evidences' ? 'applied-controls' : 'evidences';
			const fetchFn = vi.fn() as unknown as typeof fetch;

			const result = await actions[action]!(
				nestedCreateEvent(nestedCreateRequest(forgedUrlModel), fetchFn)
			);

			expect(fetchFn).not.toHaveBeenCalled();
			expect(result).toMatchObject({
				status: 400,
				data: { form: { errors: { urlmodel: ['Error'] } } }
			});
		}
	);

	it.each(createCases)(
		'rejects a malformed or ambiguous requirement assessment for $label before any API request',
		async ({ action, urlModel }) => {
			for (const submittedIds of [
				['not-a-uuid'],
				[requirementAssessmentId, '468fd310-197e-4763-87a1-f0f18a7ed8af']
			]) {
				const fetchFn = vi.fn() as unknown as typeof fetch;
				const result = await actions[action]!(
					nestedCreateEvent(nestedCreateRequest(urlModel, submittedIds), fetchFn)
				);

				expect(fetchFn).not.toHaveBeenCalled();
				expect(result).toMatchObject({
					status: 400,
					data: { form: { errors: { requirement_assessments: ['Error'] } } }
				});
			}
		}
	);

	it.each(createCases)(
		'rejects a forged requirement assessment UUID before creating a $label',
		async ({ action, urlModel }) => {
			const forgedEndpoint = `http://localhost:8000/api/requirement-assessments/${forgedRequirementAssessmentId}/`;
			const fetchFn = vi.fn(async () =>
				Response.json({ detail: 'Not found' }, { status: 404, statusText: 'Not Found' })
			) as unknown as typeof fetch;

			const result = await actions[action]!(
				nestedCreateEvent(nestedCreateRequest(urlModel, [forgedRequirementAssessmentId]), fetchFn)
			);

			expect(fetchFn).toHaveBeenCalledTimes(1);
			expect(fetchFn).toHaveBeenCalledWith(forgedEndpoint);
			expect(result).toMatchObject({
				status: 404,
				data: { form: { errors: { requirement_assessments: ['Not found'] } } }
			});
		}
	);

	it.each(createCases)(
		'rejects a cross-assessment requirement assessment before creating a $label',
		async ({ action, urlModel }) => {
			const fetchFn = vi.fn(async () =>
				Response.json(
					boundRequirementAssessment({ compliance_assessment: { id: otherAssessmentId } })
				)
			) as unknown as typeof fetch;

			const result = await actions[action]!(
				nestedCreateEvent(nestedCreateRequest(urlModel), fetchFn)
			);

			expect(fetchFn).toHaveBeenCalledTimes(1);
			expect(fetchFn).toHaveBeenCalledWith(requirementAssessmentEndpoint);
			expect(result).toMatchObject({ status: 403 });
		}
	);

	it.each(createCases)(
		'preserves a backend denial as a form failure for $label without throwing',
		async ({ action, urlModel }) => {
			const fetchFn = vi
				.fn()
				.mockResolvedValueOnce(Response.json(boundRequirementAssessment()))
				.mockResolvedValueOnce(
					Response.json({ detail: 'Permission denied' }, { status: 403, statusText: 'Forbidden' })
				) as unknown as typeof fetch;

			const result = await actions[action]!(
				nestedCreateEvent(nestedCreateRequest(urlModel), fetchFn)
			);

			expect(fetchFn).toHaveBeenCalledTimes(2);
			expect(result).toMatchObject({
				status: 400,
				data: { form: { message: { error: 'Permission denied' } } }
			});
		}
	);

	it.each(createCases)(
		'returns a form failure when the $label create request has a network error',
		async ({ action, urlModel }) => {
			const fetchFn = vi
				.fn()
				.mockResolvedValueOnce(Response.json(boundRequirementAssessment()))
				.mockRejectedValueOnce(new TypeError('connection closed')) as unknown as typeof fetch;

			const result = await actions[action]!(
				nestedCreateEvent(nestedCreateRequest(urlModel), fetchFn)
			);

			expect(fetchFn).toHaveBeenCalledTimes(2);
			expect(result).toMatchObject({
				status: 400,
				data: { form: { message: { error: 'Error' } } }
			});
		}
	);

	it.each(createCases)(
		'fails closed on a malformed successful $label response',
		async ({ action, urlModel }) => {
			const fetchFn = vi
				.fn()
				.mockResolvedValueOnce(Response.json(boundRequirementAssessment()))
				.mockResolvedValueOnce(
					Response.json({ name: 'Missing canonical id' })
				) as unknown as typeof fetch;

			const result = await actions[action]!(
				nestedCreateEvent(nestedCreateRequest(urlModel), fetchFn)
			);

			expect(fetchFn).toHaveBeenCalledTimes(2);
			expect(result).toMatchObject({
				status: 400,
				data: { form: { message: { error: 'Error' } } }
			});
		}
	);
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
