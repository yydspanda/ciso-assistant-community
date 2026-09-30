import { beforeEach, describe, expect, it, vi } from 'vitest';

const { setFlashMock, submittedForm } = vi.hoisted(() => ({
	setFlashMock: vi.fn(),
	submittedForm: {
		valid: true,
		data: {
			noRedirect: true,
			nextRequirementAssessmentId: 'a4f77517-6875-4566-b14c-49066d08643e',
			score: 3
		},
		errors: {},
		message: undefined as unknown
	} as {
		valid: boolean;
		data: Record<string, unknown>;
		errors: Record<string, string[]>;
		message?: unknown;
	}
}));

vi.mock('$lib/utils/crud', () => ({
	getModelInfo: vi.fn((urlModel: string) => ({
		urlModel,
		localName: urlModel,
		fileFields: urlModel === 'evidences' ? ['attachment'] : []
	})),
	urlParamModelVerboseName: () => 'Requirement assessment'
}));

vi.mock('$lib/utils/i18n', () => ({
	safeTranslate: (value: string) => value
}));

vi.mock('$lib/utils/helpers', () => ({
	getSecureRedirect: (value: string | null) => value
}));

vi.mock('$lib/utils/load', () => ({
	formatSelectFieldData: vi.fn()
}));

vi.mock('$lib/utils/schemas', () => ({
	modelSchema: () => ({ syntheticSchema: true })
}));

vi.mock('$lib/utils/table', () => ({
	headData: vi.fn(() => [])
}));

vi.mock('$paraglide/messages', () => ({
	m: {
		error: () => 'Error',
		successfullyCreatedObject: ({ object }: { object: string }) =>
			`The ${object} object has been successfully created`,
		successfullySavedObject: ({ object }: { object: string }) =>
			`The ${object} object has been successfully saved`
	}
}));

vi.mock('sveltekit-flash-message/server', () => ({
	setFlash: setFlashMock
}));

vi.mock('sveltekit-superforms/adapters', () => ({
	zod4: (schema: unknown) => schema
}));

vi.mock('sveltekit-superforms', () => ({
	message: (form: Record<string, unknown>, value: unknown) => {
		form.message = value;
		return form.valid ? { form } : { status: 400, data: { form } };
	},
	setError: (
		form: { valid: boolean; errors: Record<string, string[]> },
		key: string,
		value: string
	) => {
		form.valid = false;
		form.errors[key] = [...(form.errors[key] ?? []), value];
	},
	superValidate: vi.fn(async () => ({
		...submittedForm,
		data: { ...submittedForm.data },
		errors: { ...submittedForm.errors }
	}))
}));

import { nestedWriteFormAction } from '$lib/utils/actions';
import { actions } from './+page.server';

const requirementAssessmentId = '7fe956d8-a98e-43f2-bdd6-2d48922c41f7';
const nextRequirementAssessmentId = 'a4f77517-6875-4566-b14c-49066d08643e';
const endpoint = `http://localhost:8000/api/requirement-assessments/${requirementAssessmentId}/`;

function actionEvent(fetchFn: ReturnType<typeof vi.fn>) {
	return {
		request: new Request('http://localhost/save', { method: 'POST' }),
		params: { id: requirementAssessmentId },
		url: new URL(`http://localhost/requirement-assessments/${requirementAssessmentId}/edit`),
		fetch: fetchFn,
		cookies: { set: vi.fn() }
	} as never;
}

function nestedActionEvent(
	fetchFn: ReturnType<typeof vi.fn>,
	urlModel: string,
	boundRequirementAssessmentId = requirementAssessmentId
) {
	const formData = new FormData();
	formData.set('urlmodel', urlModel);
	return {
		request: new Request('http://localhost/save', { method: 'POST', body: formData }),
		params: { id: boundRequirementAssessmentId },
		url: new URL(`http://localhost/requirement-assessments/${boundRequirementAssessmentId}/edit`),
		fetch: fetchFn,
		cookies: { set: vi.fn() }
	} as never;
}

describe('requirement-assessment save-and-stay action', () => {
	beforeEach(() => {
		setFlashMock.mockClear();
		submittedForm.valid = true;
		submittedForm.data = {
			noRedirect: true,
			nextRequirementAssessmentId,
			score: 3
		};
		submittedForm.errors = {};
		submittedForm.message = undefined;
	});

	it('returns a submission message, resets stay mode, and omits UI-only API fields', async () => {
		Object.assign(submittedForm.data, {
			folder: '468fd310-197e-4763-87a1-f0f18a7ed8af',
			requirement: '468fd310-197e-4763-87a1-f0f18a7ed8af',
			compliance_assessment: '468fd310-197e-4763-87a1-f0f18a7ed8af',
			selected: false,
			target_score: 99,
			unknown_future_field: 'must not cross the route boundary'
		});
		const fetchFn = vi
			.fn()
			.mockResolvedValueOnce(Response.json({ id: requirementAssessmentId, score: 1 }))
			// A 2xx write is authoritative even when a proxy strips the body. The
			// action must not turn a completed mutation into a misleading failure.
			.mockResolvedValueOnce(new Response(null, { status: 204 }));

		const result = await actions.updateRequirementAssessment(actionEvent(fetchFn));

		expect(fetchFn).toHaveBeenNthCalledWith(1, endpoint);
		expect(fetchFn).toHaveBeenNthCalledWith(2, endpoint, {
			method: 'PATCH',
			body: JSON.stringify({ score: 3 })
		});
		expect(result).toMatchObject({
			form: {
				valid: true,
				data: { noRedirect: false },
				message: {
					toast: {
						type: 'success',
						message: 'The Requirement assessment object has been successfully saved'
					}
				}
			}
		});
		expect(setFlashMock).not.toHaveBeenCalled();
	});

	it('uses one flash and redirects when a later submission selects Save/Next', async () => {
		submittedForm.data.noRedirect = false;
		const fetchFn = vi
			.fn()
			.mockResolvedValueOnce(Response.json({ id: requirementAssessmentId, score: 3 }))
			.mockResolvedValueOnce(
				Response.json({
					id: requirementAssessmentId,
					compliance_assessment: '4819de76-fce4-4a1c-bb3b-e97d80b61ab7'
				})
			);

		await expect(actions.updateRequirementAssessment(actionEvent(fetchFn))).rejects.toMatchObject({
			status: 302,
			location: `/requirement-assessments/${nextRequirementAssessmentId}/edit`
		});
		expect(fetchFn).toHaveBeenNthCalledWith(2, endpoint, {
			method: 'PATCH',
			body: JSON.stringify({ score: 3 })
		});
		expect(setFlashMock).toHaveBeenCalledTimes(1);
	});

	it('returns a pre-update read denial as a single non-flash failure toast', async () => {
		const fetchFn = vi
			.fn()
			.mockResolvedValueOnce(
				Response.json({ detail: 'Permission denied' }, { status: 403, statusText: 'Forbidden' })
			);

		const result = await actions.updateRequirementAssessment(actionEvent(fetchFn));

		expect(result).toMatchObject({
			status: 403,
			data: {
				form: {
					valid: false,
					message: {
						toast: { type: 'error', message: 'Permission denied', timeout: 10000 }
					}
				}
			}
		});
		expect(setFlashMock).not.toHaveBeenCalled();
	});

	it('returns a PATCH denial as a single non-flash failure toast', async () => {
		const fetchFn = vi
			.fn()
			.mockResolvedValueOnce(Response.json({ id: requirementAssessmentId, score: 1 }))
			.mockResolvedValueOnce(
				Response.json({ detail: 'Permission denied' }, { status: 403, statusText: 'Forbidden' })
			);

		const result = await actions.updateRequirementAssessment(actionEvent(fetchFn));

		expect(fetchFn).toHaveBeenNthCalledWith(2, endpoint, {
			method: 'PATCH',
			body: JSON.stringify({ score: 3 })
		});
		expect(result).toMatchObject({
			status: 403,
			data: {
				form: {
					valid: false,
					message: {
						toast: { type: 'error', message: 'Permission denied', timeout: 10000 }
					}
				}
			}
		});
		expect(setFlashMock).not.toHaveBeenCalled();
	});

	it('fails visibly and closed when the pre-update read cannot be parsed', async () => {
		const fetchFn = vi
			.fn()
			.mockResolvedValueOnce(
				new Response('<html>failure</html>', { status: 502, statusText: 'Bad Gateway' })
			);

		const result = await actions.updateRequirementAssessment(actionEvent(fetchFn));

		expect(result).toMatchObject({
			status: 502,
			data: {
				form: {
					valid: false,
					message: { toast: { type: 'error', message: 'Bad Gateway' } }
				}
			}
		});
		expect(fetchFn).toHaveBeenCalledTimes(1);
		expect(setFlashMock).not.toHaveBeenCalled();
	});

	it('fails closed on a successful pre-update response with a non-object payload', async () => {
		const fetchFn = vi.fn().mockResolvedValueOnce(Response.json(null));

		const result = await actions.updateRequirementAssessment(actionEvent(fetchFn));

		expect(result).toMatchObject({
			status: 502,
			data: {
				form: {
					valid: false,
					message: { toast: { type: 'error', message: 'Error' } }
				}
			}
		});
		expect(fetchFn).toHaveBeenCalledTimes(1);
		expect(setFlashMock).not.toHaveBeenCalled();
	});

	it('fails closed when the pre-update response is bound to a different object id', async () => {
		const fetchFn = vi.fn().mockResolvedValueOnce(
			Response.json({
				id: '468fd310-197e-4763-87a1-f0f18a7ed8af',
				score: 1
			})
		);

		const result = await actions.updateRequirementAssessment(actionEvent(fetchFn));

		expect(result).toMatchObject({ status: 502 });
		expect(fetchFn).toHaveBeenCalledTimes(1);
		expect(setFlashMock).not.toHaveBeenCalled();
	});

	it('rejects a malformed next requirement-assessment id before issuing the PATCH', async () => {
		submittedForm.data.noRedirect = false;
		submittedForm.data.nextRequirementAssessmentId = 'not-a-uuid';
		const fetchFn = vi.fn().mockResolvedValueOnce(
			Response.json({
				id: requirementAssessmentId,
				compliance_assessment: '4819de76-fce4-4a1c-bb3b-e97d80b61ab7'
			})
		);

		const result = await actions.updateRequirementAssessment(actionEvent(fetchFn));

		expect(result).toMatchObject({ status: 502 });
		expect(fetchFn).toHaveBeenCalledTimes(1);
		expect(setFlashMock).not.toHaveBeenCalled();
	});

	it('validates the fallback assessment redirect before issuing the PATCH', async () => {
		submittedForm.data.noRedirect = false;
		submittedForm.data.nextRequirementAssessmentId = null;
		const fetchFn = vi.fn().mockResolvedValueOnce(
			Response.json({
				id: requirementAssessmentId,
				score: 3,
				compliance_assessment: 'not-a-uuid'
			})
		);

		const result = await actions.updateRequirementAssessment(actionEvent(fetchFn));

		expect(result).toMatchObject({ status: 502 });
		expect(fetchFn).toHaveBeenCalledTimes(1);
		expect(setFlashMock).not.toHaveBeenCalled();
	});

	it('fails visibly and closed on a PATCH network exception', async () => {
		const fetchFn = vi
			.fn()
			.mockResolvedValueOnce(Response.json({ id: requirementAssessmentId, score: 3 }))
			.mockRejectedValueOnce(new TypeError('connection closed'));

		const result = await actions.updateRequirementAssessment(actionEvent(fetchFn));

		expect(result).toMatchObject({
			status: 502,
			data: {
				form: {
					valid: false,
					message: { toast: { type: 'error', message: 'Error' } }
				}
			}
		});
		expect(setFlashMock).not.toHaveBeenCalled();
	});
});

describe('requirement-assessment governed nested creates', () => {
	const evidenceId = 'c8ac9b69-5c9e-42d2-b74b-3f64fa53e276';
	const securityExceptionId = '8722845f-a8f7-46bd-a13c-66af4f859598';
	const folderId = '468fd310-197e-4763-87a1-f0f18a7ed8af';

	beforeEach(() => {
		setFlashMock.mockClear();
		submittedForm.valid = true;
		submittedForm.data = {};
		submittedForm.errors = {};
		submittedForm.message = undefined;
	});

	it('creates evidence with the server-bound relationship, then uploads its file', async () => {
		const attachment = new File(['evidence'], 'evidence.txt', { type: 'text/plain' });
		submittedForm.data = {
			folder: folderId,
			name: 'Evidence',
			attachment,
			requirement_assessments: ['4819de76-fce4-4a1c-bb3b-e97d80b61ab7']
		};
		const fetchFn = vi
			.fn()
			.mockResolvedValueOnce(Response.json({ id: evidenceId, name: 'Evidence' }))
			.mockResolvedValueOnce(new Response(null, { status: 204 }));

		const result = await actions.createEvidence(nestedActionEvent(fetchFn, 'evidences'));

		expect(fetchFn).toHaveBeenCalledTimes(2);
		expect(fetchFn).toHaveBeenNthCalledWith(1, 'http://localhost:8000/api/evidences/', {
			method: 'POST',
			body: JSON.stringify({
				folder: folderId,
				name: 'Evidence',
				requirement_assessments: [requirementAssessmentId]
			})
		});
		expect(fetchFn).toHaveBeenNthCalledWith(
			2,
			`http://localhost:8000/api/evidences/${evidenceId}/upload/`,
			{
				headers: { 'Content-Disposition': 'attachment; filename=evidence.txt' },
				method: 'POST',
				body: attachment
			}
		);
		expect(result).toMatchObject({
			newEvidence: evidenceId,
			form: {
				valid: true,
				data: {
					attachment: undefined,
					requirement_assessments: [requirementAssessmentId]
				}
			}
		});
		expect(setFlashMock).toHaveBeenCalledTimes(1);
		expect(setFlashMock).toHaveBeenCalledWith(
			{
				type: 'success',
				message: 'The requirement assessment object has been successfully created'
			},
			expect.anything()
		);
	});

	it('creates a security exception and its server-bound relationship in one request', async () => {
		submittedForm.data = {
			folder: folderId,
			name: 'Exception',
			requirement_assessments: [requirementAssessmentId]
		};
		const fetchFn = vi.fn().mockResolvedValueOnce(Response.json({ id: securityExceptionId }));

		const result = await actions.createSecurityException(
			nestedActionEvent(fetchFn, 'security-exceptions')
		);

		expect(fetchFn).toHaveBeenCalledTimes(1);
		expect(fetchFn).toHaveBeenNthCalledWith(1, 'http://localhost:8000/api/security-exceptions/', {
			method: 'POST',
			body: JSON.stringify({
				folder: folderId,
				name: 'Exception',
				requirement_assessments: [requirementAssessmentId]
			})
		});
		expect(result).toMatchObject({
			newSecurityException: securityExceptionId,
			form: { valid: true }
		});
		expect(setFlashMock).toHaveBeenCalledTimes(1);
	});

	it('creates an applied control and its server-bound relationship in one request', async () => {
		const controlId = '3855f6c7-4692-4d37-995a-4bc56374ad07';
		submittedForm.data = {
			folder: folderId,
			name: 'Control',
			requirement_assessments: ['4819de76-fce4-4a1c-bb3b-e97d80b61ab7']
		};
		const fetchFn = vi.fn().mockResolvedValueOnce(Response.json({ id: controlId }));

		const result = await actions.createAppliedControl(
			nestedActionEvent(fetchFn, 'applied-controls')
		);

		expect(fetchFn).toHaveBeenCalledTimes(1);
		expect(fetchFn).toHaveBeenCalledWith('http://localhost:8000/api/applied-controls/', {
			method: 'POST',
			body: JSON.stringify({
				folder: folderId,
				name: 'Control',
				requirement_assessments: [requirementAssessmentId]
			})
		});
		expect(result).toMatchObject({
			newControls: [controlId],
			form: { valid: true }
		});
		expect(setFlashMock).toHaveBeenCalledTimes(1);
	});

	it('does not dereference a missing object when validation fails before POST', async () => {
		submittedForm.valid = false;
		submittedForm.errors = { name: ['Required'] };
		const fetchFn = vi.fn();

		const result = await actions.createEvidence(nestedActionEvent(fetchFn, 'evidences'));

		expect(fetchFn).not.toHaveBeenCalled();
		expect(result).toMatchObject({ status: 400, data: { form: { valid: false } } });
		expect(result).not.toHaveProperty('newEvidence');
		expect(setFlashMock).not.toHaveBeenCalled();
	});

	it('fails visibly without constructing a target URL from a non-UUID create response', async () => {
		submittedForm.data = {
			folder: folderId,
			name: 'Evidence',
			requirement_assessments: [requirementAssessmentId]
		};
		const fetchFn = vi.fn().mockResolvedValueOnce(Response.json({ id: '../not-an-object' }));

		const result = await actions.createEvidence(nestedActionEvent(fetchFn, 'evidences'));

		expect(fetchFn).toHaveBeenCalledTimes(1);
		expect(result).toMatchObject({
			status: 400,
			data: {
				form: {
					valid: false,
					message: { error: 'Error' }
				}
			}
		});
		expect(result).not.toHaveProperty('newEvidence');
		expect(setFlashMock).toHaveBeenCalledTimes(1);
		expect(setFlashMock).toHaveBeenCalledWith(
			{ type: 'error', message: 'Error', timeout: 10000 },
			expect.anything()
		);
	});

	it('rejects a non-UUID canonical relationship before creating an object', async () => {
		submittedForm.data = {
			folder: folderId,
			name: 'Evidence',
			requirement_assessments: [requirementAssessmentId]
		};
		const fetchFn = vi.fn();

		const result = await actions.createEvidence(
			nestedActionEvent(fetchFn, 'evidences', 'not-a-uuid')
		);

		expect(fetchFn).not.toHaveBeenCalled();
		expect(result).toMatchObject({
			status: 400,
			data: {
				form: {
					valid: false,
					message: { error: 'Error' }
				}
			}
		});
		expect(result).not.toHaveProperty('newEvidence');
		expect(setFlashMock).toHaveBeenCalledTimes(1);
	});

	it('rejects a forged evidence urlmodel before any fetch', async () => {
		submittedForm.data = {
			folder: folderId,
			name: 'Evidence',
			requirement_assessments: [requirementAssessmentId]
		};
		const fetchFn = vi.fn();

		const result = await actions.createEvidence(nestedActionEvent(fetchFn, 'security-exceptions'));

		expect(fetchFn).not.toHaveBeenCalled();
		expect(result).toMatchObject({
			status: 400,
			data: {
				form: {
					valid: false,
					errors: { urlmodel: ['Error'] },
					message: { error: 'Error' }
				}
			}
		});
		expect(result).not.toHaveProperty('newEvidence');
		expect(setFlashMock).toHaveBeenCalledTimes(1);
	});

	it('rejects a relative-path security-exception urlmodel before any fetch', async () => {
		submittedForm.data = {
			folder: folderId,
			name: 'Exception',
			requirement_assessments: [requirementAssessmentId]
		};
		const fetchFn = vi.fn();

		const result = await actions.createSecurityException(
			nestedActionEvent(fetchFn, '../evidences')
		);

		expect(fetchFn).not.toHaveBeenCalled();
		expect(result).toMatchObject({
			status: 400,
			data: {
				form: {
					valid: false,
					errors: { urlmodel: ['Error'] },
					message: { error: 'Error' }
				}
			}
		});
		expect(result).not.toHaveProperty('newSecurityException');
		expect(setFlashMock).toHaveBeenCalledTimes(1);
	});

	it('returns an invalid ActionFailure without cleanup when the initial POST is denied', async () => {
		submittedForm.data = {
			folder: folderId,
			name: 'Exception',
			requirement_assessments: [requirementAssessmentId]
		};
		const fetchFn = vi
			.fn()
			.mockResolvedValueOnce(
				Response.json({ detail: 'Create denied' }, { status: 403, statusText: 'Forbidden' })
			);

		const result = await actions.createSecurityException(
			nestedActionEvent(fetchFn, 'security-exceptions')
		);

		expect(fetchFn).toHaveBeenCalledTimes(1);
		expect(fetchFn).toHaveBeenCalledWith('http://localhost:8000/api/security-exceptions/', {
			method: 'POST',
			body: JSON.stringify({
				folder: folderId,
				name: 'Exception',
				requirement_assessments: [requirementAssessmentId]
			})
		});
		expect(result).toMatchObject({
			status: 400,
			data: {
				form: {
					valid: false,
					message: { error: 'Create denied' }
				}
			}
		});
		expect(result).not.toHaveProperty('newSecurityException');
		expect(setFlashMock).toHaveBeenCalledTimes(1);
		expect(setFlashMock).toHaveBeenCalledWith(
			{ type: 'error', message: 'Create denied', timeout: 10000 },
			expect.anything()
		);
	});

	it('returns an invalid ActionFailure when the initial POST has a network error', async () => {
		submittedForm.data = {
			folder: folderId,
			name: 'Exception',
			requirement_assessments: [requirementAssessmentId]
		};
		const fetchFn = vi.fn().mockRejectedValueOnce(new TypeError('create connection closed'));

		const result = await actions.createSecurityException(
			nestedActionEvent(fetchFn, 'security-exceptions')
		);

		expect(fetchFn).toHaveBeenCalledTimes(1);
		expect(result).toMatchObject({
			status: 400,
			data: {
				form: {
					valid: false,
					message: { error: 'Error' }
				}
			}
		});
		expect(result).not.toHaveProperty('newSecurityException');
		expect(setFlashMock).toHaveBeenCalledTimes(1);
		expect(setFlashMock).toHaveBeenCalledWith(
			{ type: 'error', message: 'Error', timeout: 10000 },
			expect.anything()
		);
		expect(setFlashMock).not.toHaveBeenCalledWith(
			expect.objectContaining({ type: 'success' }),
			expect.anything()
		);
	});

	it('returns an invalid ActionFailure for a non-JSON successful initial POST', async () => {
		submittedForm.data = {
			folder: folderId,
			name: 'Exception',
			requirement_assessments: [requirementAssessmentId]
		};
		const fetchFn = vi
			.fn()
			.mockResolvedValueOnce(new Response('created without an object body', { status: 201 }));

		const result = await actions.createSecurityException(
			nestedActionEvent(fetchFn, 'security-exceptions')
		);

		expect(fetchFn).toHaveBeenCalledTimes(1);
		expect(result).toMatchObject({
			status: 400,
			data: {
				form: {
					valid: false,
					message: { error: 'Error' }
				}
			}
		});
		expect(result).not.toHaveProperty('newSecurityException');
		expect(setFlashMock).toHaveBeenCalledTimes(1);
		expect(setFlashMock).toHaveBeenCalledWith(
			{ type: 'error', message: 'Error', timeout: 10000 },
			expect.anything()
		);
		expect(setFlashMock).not.toHaveBeenCalledWith(
			expect.objectContaining({ type: 'success' }),
			expect.anything()
		);
	});

	it('cleans up and fails closed when file upload is denied with an empty body', async () => {
		const attachment = new File(['evidence'], 'evidence.txt', { type: 'text/plain' });
		submittedForm.data = {
			folder: folderId,
			name: 'Evidence',
			attachment,
			requirement_assessments: [requirementAssessmentId]
		};
		const fetchFn = vi
			.fn()
			.mockResolvedValueOnce(Response.json({ id: evidenceId }))
			.mockResolvedValueOnce(new Response(null, { status: 502, statusText: 'Bad Gateway' }))
			.mockResolvedValueOnce(new Response(null, { status: 204 }));

		const result = await actions.createEvidence(nestedActionEvent(fetchFn, 'evidences'));

		expect(fetchFn).toHaveBeenCalledTimes(3);
		expect(fetchFn).toHaveBeenNthCalledWith(
			2,
			`http://localhost:8000/api/evidences/${evidenceId}/upload/`,
			expect.objectContaining({ method: 'POST', body: attachment })
		);
		expect(fetchFn).toHaveBeenNthCalledWith(
			3,
			`http://localhost:8000/api/evidences/${evidenceId}/`,
			{ method: 'DELETE' }
		);
		expect(result).toMatchObject({
			status: 400,
			data: {
				form: {
					valid: false,
					message: { error: 'Error' }
				}
			}
		});
		expect(result).not.toHaveProperty('newEvidence');
		expect(setFlashMock).toHaveBeenCalledTimes(1);
		expect(setFlashMock).toHaveBeenCalledWith(
			{ type: 'error', message: 'Error', timeout: 10000 },
			expect.anything()
		);
	});

	it('cleans up and returns an invalid ActionFailure when file upload has a network error', async () => {
		const attachment = new File(['evidence'], 'evidence.txt', { type: 'text/plain' });
		submittedForm.data = {
			folder: folderId,
			name: 'Evidence',
			attachment,
			requirement_assessments: [requirementAssessmentId]
		};
		const fetchFn = vi
			.fn()
			.mockResolvedValueOnce(Response.json({ id: evidenceId }))
			.mockRejectedValueOnce(new TypeError('upload connection closed'))
			.mockResolvedValueOnce(new Response(null, { status: 204 }));

		const result = await actions.createEvidence(nestedActionEvent(fetchFn, 'evidences'));

		expect(fetchFn).toHaveBeenCalledTimes(3);
		expect(fetchFn).toHaveBeenNthCalledWith(
			2,
			`http://localhost:8000/api/evidences/${evidenceId}/upload/`,
			expect.objectContaining({ method: 'POST', body: attachment })
		);
		expect(fetchFn).toHaveBeenNthCalledWith(
			3,
			`http://localhost:8000/api/evidences/${evidenceId}/`,
			{ method: 'DELETE' }
		);
		expect(result).toMatchObject({
			status: 400,
			data: {
				form: {
					valid: false,
					message: { error: 'Error' }
				}
			}
		});
		expect(result).not.toHaveProperty('newEvidence');
		expect(setFlashMock).toHaveBeenCalledTimes(1);
		expect(setFlashMock).toHaveBeenCalledWith(
			{ type: 'error', message: 'Error', timeout: 10000 },
			expect.anything()
		);
		expect(setFlashMock).not.toHaveBeenCalledWith(
			expect.objectContaining({ type: 'success' }),
			expect.anything()
		);
	});

	it('leaves ordinary nested creates on their existing unbound path', async () => {
		submittedForm.data = {
			folder: folderId,
			name: 'Ordinary nested object',
			requirement_assessments: [requirementAssessmentId]
		};
		const fetchFn = vi.fn().mockResolvedValueOnce(Response.json({ id: 'legacy-object-id' }));

		const result = await nestedWriteFormAction({
			event: nestedActionEvent(fetchFn, 'security-exceptions'),
			action: 'create'
		});

		expect(fetchFn).toHaveBeenCalledTimes(1);
		expect(fetchFn).toHaveBeenCalledWith('http://localhost:8000/api/security-exceptions/', {
			method: 'POST',
			body: JSON.stringify(submittedForm.data)
		});
		expect(result).toMatchObject({
			form: {
				valid: true,
				message: { object: { id: 'legacy-object-id' } }
			}
		});
		expect(setFlashMock).toHaveBeenCalledTimes(1);
	});
});
