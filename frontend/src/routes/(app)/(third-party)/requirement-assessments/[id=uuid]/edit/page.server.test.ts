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

vi.mock('$lib/utils/actions', () => ({
	handleErrorResponse: vi.fn(),
	nestedWriteFormAction: vi.fn()
}));

vi.mock('$lib/utils/crud', () => ({
	getModelInfo: vi.fn(),
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
		return { form };
	},
	setError: (
		form: { valid: boolean; errors: Record<string, string[]> },
		key: string,
		value: string
	) => {
		form.valid = false;
		form.errors[key] = [...(form.errors[key] ?? []), value];
	},
	superValidate: vi.fn(async () => structuredClone(submittedForm))
}));

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
