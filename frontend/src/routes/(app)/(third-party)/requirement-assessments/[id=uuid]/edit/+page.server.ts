import { nestedWriteFormAction } from '$lib/utils/actions';
import { BASE_API_URL } from '$lib/utils/constants';
import { getModelInfo, urlParamModelVerboseName } from '$lib/utils/crud';
import { safeTranslate } from '$lib/utils/i18n';
import { getSecureRedirect } from '$lib/utils/helpers';
import { formatSelectFieldData } from '$lib/utils/load';
import { modelSchema } from '$lib/utils/schemas';
import { headData } from '$lib/utils/table';
import { m } from '$paraglide/messages';
import { type TableSource } from '@skeletonlabs/skeleton-svelte';
import type { Actions } from '@sveltejs/kit';
import { fail, redirect } from '@sveltejs/kit';
import { setFlash } from 'sveltekit-flash-message/server';
import { message, setError, superValidate } from 'sveltekit-superforms';
import { zod4 as zod } from 'sveltekit-superforms/adapters';
import type { PageServerLoad } from './$types';
import { z } from 'zod';

function failUpdateWithToast(
	form: Record<string, any>,
	messageText: string,
	status = 502,
	type: 'error' | 'warning' = 'error'
) {
	form.valid = false;
	form.message = {
		toast: {
			type,
			message: messageText,
			...(type === 'error' ? { timeout: 10000 } : {})
		}
	};
	return fail(status >= 400 && status <= 599 ? status : 502, { form });
}

async function handleUpdateErrorResponse(response: Response, form: Record<string, any>) {
	let payload: Record<string, unknown>;
	try {
		const parsed = await response.json();
		if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
			throw new TypeError('Expected an object error response');
		}
		payload = parsed as Record<string, unknown>;
	} catch (error) {
		console.error('Failed to parse requirement assessment update error', error);
		return failUpdateWithToast(form, response.statusText || m.error(), response.status);
	}

	if (payload.label) payload.filtering_labels = payload.label;
	if (payload.warning) {
		const warning = Array.isArray(payload.warning) ? payload.warning[0] : payload.warning;
		return failUpdateWithToast(
			form,
			typeof warning === 'string' ? safeTranslate(warning) : m.error(),
			response.status,
			'warning'
		);
	}
	if (payload.error || payload.detail) {
		const rawError = payload.error || payload.detail;
		const errorText = Array.isArray(rawError) ? rawError[0] : rawError;
		return failUpdateWithToast(
			form,
			typeof errorText === 'string' ? safeTranslate(errorText) : m.error(),
			response.status
		);
	}

	let firstFieldError: string | undefined;
	for (const [key, value] of Object.entries(payload)) {
		const errors = Array.isArray(value) ? value : [value];
		for (const error of errors) {
			if (typeof error !== 'string') continue;
			const translated = safeTranslate(error);
			firstFieldError ??= translated;
			setError(form, key, translated);
		}
	}
	return failUpdateWithToast(form, firstFieldError || m.error(), response.status);
}

function uuidId(value: unknown): string | null {
	return typeof value === 'string' && z.string().uuid().safeParse(value).success ? value : null;
}

function complianceAssessmentId(value: unknown): string | null {
	if (typeof value === 'string') return uuidId(value);
	if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
	const id = (value as Record<string, unknown>).id;
	return uuidId(id);
}

const requirementAssessmentUpdateFields = new Set([
	'answers',
	'status',
	'result',
	'extended_result',
	'score',
	'is_scored',
	'is_score_overridden',
	'documentation_score',
	'observation',
	'evidences',
	'applied_controls',
	'security_exceptions'
]);

export const load = (async ({ fetch, params }) => {
	const URLModel = 'requirement-assessments';
	const baseUrl = BASE_API_URL;
	const endpoint = `${baseUrl}/${URLModel}/${params.id}/`;

	async function fetchJson(url: string) {
		const res = await fetch(url);
		if (!res.ok) {
			console.error(`Failed to fetch data from ${url}: ${res.statusText}`);
			return null;
		}
		return res.json();
	}

	const requirementAssessment = await fetchJson(endpoint);
	const requirement = requirementAssessment.requirement;
	const compliance_assessment_score = await fetchJson(
		`${baseUrl}/compliance-assessments/${requirementAssessment.compliance_assessment.id}/global_score/`
	);

	const parent = requirementAssessment.requirement.parent_requirement;

	const model = getModelInfo(URLModel);
	const object = { ...requirementAssessment };
	Object.keys(object).forEach((key) => {
		if (object[key] instanceof Object && 'id' in object[key]) {
			object[key] = object[key].id;
		}
	});

	// Fetch ordered assessable requirement assessments to find next/previous
	const requirementsListData = await fetchJson(
		`${baseUrl}/compliance-assessments/${requirementAssessment.compliance_assessment.id}/requirements_list/?assessable=true`
	);
	let nextRequirementAssessmentId: string | null = null;
	if (requirementsListData?.requirement_assessments) {
		const raIds = requirementsListData.requirement_assessments.map((ra: any) => ra.id);
		const currentIndex = raIds.indexOf(params.id);
		if (currentIndex !== -1 && currentIndex < raIds.length - 1) {
			nextRequirementAssessmentId = raIds[currentIndex + 1];
		}
	}

	const schema = modelSchema(URLModel);
	object.evidences = object.evidences?.map((evidence) => evidence.id) ?? [];
	object.applied_controls =
		object.applied_controls?.map((applied_control) => applied_control.id) ?? [];
	object.security_exceptions =
		object.security_exceptions?.map((security_exception) => security_exception.id) ?? [];
	object.nextRequirementAssessmentId = nextRequirementAssessmentId;
	const form = await superValidate(object, zod(schema), { errors: true });

	const selectOptions: Record<string, any> = {};
	if (model.selectFields) {
		await Promise.all(
			model.selectFields.map(async (selectField) => {
				const url = `${baseUrl}/${URLModel}/${selectField.field}/`;
				const data = await fetchJson(url);
				if (data) {
					selectOptions[selectField.field] = formatSelectFieldData(data, selectField);
				}
			})
		);
	}
	model.selectOptions = selectOptions;

	const measureCreateSchema = modelSchema('applied-controls');
	const measureCreateForm = await superValidate(
		{ folder: requirementAssessment.folder.id },
		zod(measureCreateSchema),
		{ errors: false }
	);

	const measureModel = getModelInfo('applied-controls');

	const measureSelectOptions: Record<string, any> = {};
	if (measureModel.selectFields) {
		await Promise.all(
			measureModel.selectFields.map(async (selectField) => {
				const url = `${baseUrl}/applied-controls/${selectField.field}/`;
				const data = await fetchJson(url);
				if (data) {
					measureSelectOptions[selectField.field] = formatSelectFieldData(data, selectField);
				} else {
					console.error(`Failed to fetch data for ${selectField.field}: ${response.statusText}`);
				}
			})
		);
	}

	measureModel['selectOptions'] = measureSelectOptions;

	const tables: Record<string, any> = {};

	await Promise.all(
		['applied-controls', 'evidences', 'security-exceptions'].map(async (key) => {
			const table: TableSource = {
				head: headData(key),
				body: [],
				meta: []
			};
			tables[key] = table;
		})
	);

	const evidenceModel = getModelInfo('evidences');
	const evidenceCreateSchema = modelSchema('evidences');
	const evidenceCreateForm = await superValidate(
		{ requirement_assessments: [params.id], folder: requirementAssessment.folder.id },
		zod(evidenceCreateSchema),
		{ errors: false }
	);

	const evidenceSelectOptions: Record<string, any> = {};
	if (evidenceModel.selectFields) {
		await Promise.all(
			evidenceModel.selectFields.map(async (selectField) => {
				const url = `${baseUrl}/evidences/${selectField.field}/`;
				const data = await fetchJson(url);
				if (data) {
					evidenceSelectOptions[selectField.field] = formatSelectFieldData(data, selectField);
				}
			})
		);
	}
	evidenceModel.selectOptions = evidenceSelectOptions;

	const securityExceptionModel = getModelInfo('security-exceptions');
	const securityExceptionCreateSchema = modelSchema('security-exceptions');
	const securityExceptionCreateForm = await superValidate(
		{ requirement_assessments: [params.id], folder: requirementAssessment.folder.id },
		zod(securityExceptionCreateSchema),
		{ errors: false }
	);

	const securityExceptionSelectOptions: Record<string, any> = {};
	if (securityExceptionModel.selectFields) {
		await Promise.all(
			securityExceptionModel.selectFields.map(async (selectField) => {
				const url = `${baseUrl}/security-exceptions/${selectField.field}/`;
				const data = await fetchJson(url);
				if (data) {
					securityExceptionSelectOptions[selectField.field] = formatSelectFieldData(
						data,
						selectField
					);
				}
			})
		);
	}
	securityExceptionModel.selectOptions = securityExceptionSelectOptions;

	return {
		URLModel,
		title: requirementAssessment.name,
		requirementAssessment,
		compliance_assessment_score,
		requirement,
		parent,
		model,
		form,
		measureCreateForm,
		measureModel,
		evidenceModel,
		evidenceCreateForm,
		securityExceptionModel,
		securityExceptionCreateForm,
		tables,
		nextRequirementAssessmentId,
		viewerRole: requirementsListData?.viewer_role === 'auditor' ? 'auditor' : 'respondent'
	};
}) satisfies PageServerLoad;

export const actions: Actions = {
	updateRequirementAssessment: async (event) => {
		const URLModel = 'requirement-assessments';
		const schema = modelSchema(URLModel);
		const endpoint = `${BASE_API_URL}/${URLModel}/${event.params.id}/`;
		const form = await superValidate(event.request, zod(schema));

		if (!form.valid) {
			return fail(400, { form: form });
		}

		const noRedirect = form.data.noRedirect === true;
		const nextRequirementAssessmentId = form.data.nextRequirementAssessmentId;
		// This route edits only fields rendered by its assessment form. Parent,
		// folder, lifecycle and future schema fields are never forwarded merely
		// because a forged or stale SuperForm payload contains them.
		const formData: Record<string, any> = Object.fromEntries(
			Object.entries(form.data).filter(([key]) => requirementAssessmentUpdateFields.has(key))
		);

		// Strip fields the backend hid from the GET response. Sending them back as
		// empty arrays / null would silently wipe data the user could not see.
		// Fail closed: if we cannot fetch the current state, abort rather than risk
		// a PATCH that clears hidden relations.
		let currentRa: Record<string, any>;
		try {
			const currentRaResponse = await event.fetch(endpoint);
			if (!currentRaResponse.ok) {
				return handleUpdateErrorResponse(currentRaResponse, form);
			}
			const parsedCurrentRa = await currentRaResponse.json();
			if (
				!parsedCurrentRa ||
				typeof parsedCurrentRa !== 'object' ||
				Array.isArray(parsedCurrentRa) ||
				(parsedCurrentRa as Record<string, unknown>).id !== event.params.id
			) {
				throw new TypeError('Expected the requested requirement-assessment response');
			}
			currentRa = parsedCurrentRa as Record<string, any>;
		} catch (error) {
			console.error('Failed to fetch requirement assessment before update', error);
			return failUpdateWithToast(form, m.error());
		}

		// Resolve the redirect before mutating. A malformed read response must not
		// allow the PATCH to commit and then strand the browser on a failed redirect.
		let postUpdateRedirect: string | null = null;
		if (!noRedirect) {
			const secureNext = getSecureRedirect(event.url.searchParams.get('next'));
			if (nextRequirementAssessmentId) {
				const nextId = uuidId(nextRequirementAssessmentId);
				if (!nextId) return failUpdateWithToast(form, m.error());
				postUpdateRedirect = `/requirement-assessments/${nextId}/edit${secureNext ? `?next=${secureNext}` : ''}`;
			} else if (secureNext) {
				postUpdateRedirect = secureNext;
			} else {
				const assessmentId = complianceAssessmentId(currentRa.compliance_assessment);
				if (!assessmentId) return failUpdateWithToast(form, m.error());
				postUpdateRedirect = `/compliance-assessments/${assessmentId}/`;
			}
		}

		const visibilityControlled = [
			'result',
			'status',
			'score',
			'is_scored',
			'is_score_overridden',
			'documentation_score',
			'observation',
			'answers',
			'evidences',
			'applied_controls',
			'security_exceptions'
		];
		for (const key of visibilityControlled) {
			if (!(key in currentRa)) {
				delete formData[key];
			}
		}
		// extended_result is a qualifier on result — strip it alongside a hidden result.
		if (!('result' in currentRa)) {
			delete formData.extended_result;
		}
		// The Select component's default option renders as <option value={null}>--</option>;
		// Svelte omits the null attribute so the browser falls back to the text "--",
		// which the backend rejects as an invalid enum choice. Normalize to null.
		if (formData.extended_result === '--' || formData.extended_result === '') {
			formData.extended_result = null;
		}

		const requestInitOptions: RequestInit = {
			method: 'PATCH',
			body: JSON.stringify(formData)
		};

		let response: Response;
		try {
			response = await event.fetch(endpoint, requestInitOptions);
		} catch (error) {
			console.error('Failed to update requirement assessment', error);
			return failUpdateWithToast(form, m.error());
		}

		if (!response.ok) return handleUpdateErrorResponse(response, form);

		const model: string = safeTranslate(urlParamModelVerboseName(URLModel));
		const successToast = {
			type: 'success' as const,
			message: m.successfullySavedObject({ object: model })
		};
		if (noRedirect) {
			// Keep the button choice submission-local. A later Save/Next must not
			// inherit Save-and-stay from this successful response.
			form.data.noRedirect = false;
			return message(form, { toast: successToast });
		}
		setFlash(successToast, event);

		redirect(302, postUpdateRedirect!);
	},
	createAppliedControl: async (event) => {
		const result = await nestedWriteFormAction({
			event,
			action: 'create',
			expectedUrlModel: 'applied-controls',
			boundRelationship: {
				field: 'requirement_assessments',
				value: [event.params.id ?? '']
			}
		});
		if (!('form' in result)) return result;
		const newControl = uuidId(result.form.message?.object?.id);
		return newControl ? { form: result.form, newControls: [newControl] } : { form: result.form };
	},
	createEvidence: async (event) => {
		const result = await nestedWriteFormAction({
			event,
			action: 'create',
			expectedUrlModel: 'evidences',
			boundRelationship: {
				field: 'requirement_assessments',
				value: [event.params.id ?? '']
			}
		});
		if (!('form' in result)) return result;
		const newEvidence = uuidId(result.form.message?.object?.id);
		return newEvidence ? { form: result.form, newEvidence } : { form: result.form };
	},
	createSecurityException: async (event) => {
		const result = await nestedWriteFormAction({
			event,
			action: 'create',
			expectedUrlModel: 'security-exceptions',
			boundRelationship: {
				field: 'requirement_assessments',
				value: [event.params.id ?? '']
			}
		});
		if (!('form' in result)) return result;
		const newSecurityException = uuidId(result.form.message?.object?.id);
		return newSecurityException
			? { form: result.form, newSecurityException }
			: { form: result.form };
	},
	createSuggestedControls: async (event) => {
		const formData = await event.request.formData();

		if (!formData) {
			return fail(400, { form: null });
		}

		const schema = z.object({ id: z.string().uuid() });
		const form = await superValidate(formData, zod(schema));

		const response = await event.fetch(
			`/requirement-assessments/${event.params.id}/suggestions/applied-controls`,
			{
				method: 'POST',
				headers: {
					'Content-Type': 'application/json'
				}
			}
		);
		if (response.ok) {
			setFlash(
				{
					type: 'success',
					message: m.createAppliedControlsFromSuggestionsSuccess()
				},
				event
			);
		} else {
			setFlash(
				{
					type: 'error',
					message: m.createAppliedControlsFromSuggestionsError()
				},
				event
			);
			return fail(400, { form });
		}
		const newControls = await response.json().then((data) => data.map((e) => e.id));
		return { form, newControls };
	}
};
