import { BASE_API_URL } from '$lib/utils/constants';
import { getModelInfo, urlParamModelVerboseName } from '$lib/utils/crud';

import { m } from '$paraglide/messages';

import { safeTranslate } from '$lib/utils/i18n';
import { modelSchema } from '$lib/utils/schemas';
import { fail, redirect, type RequestEvent } from '@sveltejs/kit';
import { setFlash } from 'sveltekit-flash-message/server';
import { message, setError, superValidate, type SuperValidated } from 'sveltekit-superforms';
import { zod4 as zod } from 'sveltekit-superforms/adapters';
import { z } from 'zod';
import { getSecureRedirect } from './helpers';

type FormAction = 'create' | 'edit';

type BoundRelationshipWrite = {
	field: 'requirement_assessments';
	value: string[];
};

function getHTTPMethod({
	action,
	fileFields
}: {
	action: FormAction;
	fileFields: Record<string, File>;
}) {
	if (action === 'create') return 'POST';
	return Object.keys(fileFields).length > 0 ? 'PATCH' : 'PUT';
}

function getSuccessMessage({ action, urlModel }: { action: FormAction; urlModel: string }) {
	const modelVerboseName: string = urlModel ? urlParamModelVerboseName(urlModel) : '';
	if (action === 'create') {
		return m.successfullyCreatedObject({
			object: safeTranslate(modelVerboseName).toLowerCase()
		});
	}
	if (action === 'edit') {
		return m.successfullyUpdatedObject({
			object: safeTranslate(modelVerboseName).toLowerCase()
		});
	}
}

function getEndpoint({
	action,
	urlModel,
	event
}: {
	action: FormAction;
	urlModel: string;
	event: RequestEvent;
}) {
	const model = getModelInfo(urlModel);
	if (action === 'create') {
		return model.endpointUrl
			? `${BASE_API_URL}/${model.endpointUrl}/`
			: `${BASE_API_URL}/${urlModel}/`;
	}
	const id = event.url.searchParams.get('id') || event.params.id;
	return model.endpointUrl
		? `${BASE_API_URL}/${model.endpointUrl}/${id}/`
		: `${BASE_API_URL}/${urlModel}/${id}/`;
}

export async function handleErrorResponse({
	event,
	response,
	form
}: {
	event: RequestEvent;
	response: Response;
	form: SuperValidated;
}) {
	const res: Record<string, string> = await response.json();
	console.error(res);
	if (res.label) {
		res['filtering_labels'] = res.label;
	}
	if (res.warning) {
		setFlash({ type: 'warning', message: safeTranslate(res.warning) }, event);
		return message(form, { warning: res.warning });
	}
	if (res.error || res.detail) {
		const rawError = res.error || res.detail;
		const errorKey = Array.isArray(rawError) ? rawError[0] : rawError;
		setFlash({ type: 'error', message: safeTranslate(errorKey), timeout: 10000 }, event);
		return message(form, { error: rawError });
	}
	Object.entries(res).forEach(([key, value]) => {
		if (Array.isArray(value)) {
			value.forEach((item: string) => setError(form, key, safeTranslate(item)));
		} else {
			setError(form, key, safeTranslate(value));
		}
	});
	return message(form, { status: response.status });
}

export async function defaultWriteFormAction({
	event,
	urlModel,
	action,
	doRedirect = true,
	redirectToWrittenObject = false,
	boundRelationship,
	expectedUrlModel
}: {
	event: RequestEvent;
	urlModel: string;
	action: FormAction;
	doRedirect?: boolean;
	redirectToWrittenObject?: boolean;
	boundRelationship?: BoundRelationshipWrite;
	expectedUrlModel?: string;
}) {
	if (boundRelationship && action !== 'create') {
		throw new TypeError('Bound relationship writes are only supported for create actions');
	}

	const formData = await event.request.formData();
	if (!formData) {
		return fail(400, { form: null });
	}

	const schema = modelSchema(urlModel!);
	const form = await superValidate(formData, zod(schema));
	if (expectedUrlModel && formData.get('urlmodel') !== expectedUrlModel) {
		return writeFailure({
			event,
			form,
			field: 'urlmodel',
			error: new TypeError('Submitted model does not match the server-bound model')
		});
	}

	if (!form.valid) {
		console.error(form.errors);
		return message(form, { status: 400 });
	}
	let normalizedBoundRelationship = boundRelationship;
	if (boundRelationship) {
		const parsedRelationshipValue = z
			.array(z.string().uuid())
			.length(1)
			.safeParse(boundRelationship.value);
		if (!parsedRelationshipValue.success) {
			return writeFailure({
				event,
				form,
				field: boundRelationship.field,
				error: parsedRelationshipValue.error
			});
		}
		normalizedBoundRelationship = {
			...boundRelationship,
			value: parsedRelationshipValue.data
		};
		form.data[boundRelationship.field] = parsedRelationshipValue.data;
	}

	// `dataType: 'form'` submissions (models with a file field, e.g. Evidence) can't
	// encode an empty array: a cleared multiselect renders no inputs, so superValidate
	// drops the field and the relation would never be cleared. AutocompleteSelect emits
	// `__empty_arrays` markers for such fields — restore them as explicit empty arrays.
	const schemaShape = (schema as any).shape ?? {};
	for (const emptyField of formData.getAll('__empty_arrays')) {
		if (
			typeof emptyField === 'string' &&
			emptyField in schemaShape &&
			form.data[emptyField] === undefined
		) {
			form.data[emptyField] = [];
		}
	}

	if (urlModel === 'service-accounts') {
		normalizeServiceAccountAuthorization(form.data);
	}

	const endpoint = getEndpoint({ action, urlModel, event });
	const model = getModelInfo(urlModel!);

	const fileFields = Object.fromEntries(
		Object.entries(form.data).filter(([key]) => model.fileFields?.includes(key) ?? false)
	) as Record<string, File>;
	const writeData = normalizedBoundRelationship ? { ...form.data } : form.data;

	Object.keys(fileFields).forEach((key) => {
		form.data[key] = undefined;
		writeData[key] = undefined;
	});

	const requestInitOptions: RequestInit = {
		method: getHTTPMethod({ action, fileFields }),
		body: JSON.stringify(writeData)
	};

	let res: Response;
	try {
		res = await event.fetch(endpoint, requestInitOptions);
	} catch (error) {
		if (!normalizedBoundRelationship) throw error;
		return writeFailure({ event, form, field: normalizedBoundRelationship.field, error });
	}

	if (!res.ok) {
		if (!normalizedBoundRelationship) {
			return await handleErrorResponse({ event, response: res, form });
		}
		setError(form, normalizedBoundRelationship.field, m.error());
		try {
			return await handleErrorResponse({ event, response: res, form });
		} catch (error) {
			return writeFailure({
				event,
				form,
				field: normalizedBoundRelationship.field,
				error
			});
		}
	}

	let writtenObject: Record<string, unknown>;
	try {
		writtenObject = await res.json();
	} catch (error) {
		if (!normalizedBoundRelationship) throw error;
		return writeFailure({ event, form, field: normalizedBoundRelationship.field, error });
	}
	let boundObjectId: string | null = null;
	if (normalizedBoundRelationship) {
		const parsedWrittenObjectId = z.string().uuid().safeParse(writtenObject?.id);
		if (!parsedWrittenObjectId.success) {
			return writeFailure({
				event,
				form,
				field: normalizedBoundRelationship.field,
				error: new TypeError('Create response did not contain a UUID object id')
			});
		}
		boundObjectId = parsedWrittenObjectId.data;
	}
	const writtenObjectId = normalizedBoundRelationship ? boundObjectId! : writtenObject.id;

	if (fileFields) {
		for (const [, file] of Object.entries(fileFields)) {
			if (!file) continue;
			if (file.size <= 0) continue;
			const fileUploadEndpoint = `${BASE_API_URL}/${urlModel}/${writtenObjectId}/upload/`;
			const fileUploadRequestInitOptions: RequestInit = {
				headers: {
					'Content-Disposition': `attachment; filename=${encodeURIComponent(file.name)}`
				},
				method: 'POST',
				body: file
			};
			let fileUploadRes: Response;
			try {
				fileUploadRes = await event.fetch(fileUploadEndpoint, fileUploadRequestInitOptions);
			} catch (error) {
				if (!normalizedBoundRelationship) throw error;
				await bestEffortDeleteCreatedObject({ event, endpoint, objectId: boundObjectId! });
				return writeFailure({
					event,
					form,
					field: normalizedBoundRelationship.field,
					error
				});
			}
			if (!fileUploadRes.ok) {
				// Clean up the created object if file upload fails during creation
				if (action === 'create') {
					if (normalizedBoundRelationship) {
						await bestEffortDeleteCreatedObject({
							event,
							endpoint,
							objectId: boundObjectId!
						});
					} else {
						const deleteEndpoint = `${BASE_API_URL}/${urlModel}/${writtenObjectId}/`;
						await event.fetch(deleteEndpoint, { method: 'DELETE' });
					}
				}
				if (!normalizedBoundRelationship) {
					return await handleErrorResponse({ event, response: fileUploadRes, form });
				}
				setError(form, normalizedBoundRelationship.field, m.error());
				try {
					return await handleErrorResponse({ event, response: fileUploadRes, form });
				} catch (error) {
					return writeFailure({
						event,
						form,
						field: normalizedBoundRelationship.field,
						error
					});
				}
			}
		}
	}

	let flashParams = {
		type: 'success',
		message: getSuccessMessage({ urlModel, action }) as string
	};

	if (urlModel == 'users') {
		((flashParams.type = 'warning'), (flashParams.message += safeTranslate('userHasNoRights')));
	}
	setFlash(flashParams, event);

	const next = getSecureRedirect(event.url.searchParams.get('next'));
	if (next && doRedirect) redirect(302, next);

	if (redirectToWrittenObject) {
		return message(form, { redirect: `/${urlModel}/${writtenObject.id}` });
	}
	return message(form, { object: writtenObject });
}

async function bestEffortDeleteCreatedObject({
	event,
	endpoint,
	objectId
}: {
	event: RequestEvent;
	endpoint: string;
	objectId: string;
}) {
	try {
		const cleanupResponse = await event.fetch(`${endpoint}${objectId}/`, { method: 'DELETE' });
		if (!cleanupResponse.ok) {
			console.error('Failed to clean up object after follow-up file upload failure', {
				status: cleanupResponse.status
			});
		}
	} catch (error) {
		console.error('Failed to clean up object after follow-up file upload failure', error);
	}
}

function writeFailure({
	event,
	form,
	field,
	error
}: {
	event: RequestEvent;
	form: SuperValidated<Record<string, unknown>>;
	field: string;
	error: unknown;
}) {
	console.error('Write failed closed', error);
	const errorMessage = m.error();
	setError(form, field, errorMessage);
	setFlash({ type: 'error', message: errorMessage, timeout: 10000 }, event);
	return message(form, { error: errorMessage });
}

export function normalizeServiceAccountAuthorization(data: Record<string, any>): void {
	const mode = data.authorization_mode;
	delete data.authorization_mode;
	// 'role' and 'global_admin' both link a builtin role; global_admin is the
	// explicit BI-RL-ADM case (form forces role + Global perimeter, recursive).
	if (mode === 'custom') delete data.role;
	else delete data.permissions;
}

export async function nestedWriteFormAction({
	event,
	action,
	redirectToWrittenObject = false,
	boundRelationship,
	expectedUrlModel
}: {
	event: RequestEvent;
	action: FormAction;
	redirectToWrittenObject?: boolean;
	boundRelationship?: BoundRelationshipWrite;
	expectedUrlModel?: string;
}) {
	const request = event.request.clone();
	const formData = await request.formData();
	const submittedUrlModel = formData.get('urlmodel');
	const urlModel = expectedUrlModel ?? (submittedUrlModel as string);
	return defaultWriteFormAction({
		event,
		urlModel,
		action,
		doRedirect: false,
		redirectToWrittenObject,
		boundRelationship,
		expectedUrlModel
	});
}

export async function defaultDeleteFormAction({
	event,
	urlModel
}: {
	event: RequestEvent;
	urlModel: string;
}) {
	const formData = await event.request.formData();
	const schema = z.object({ id: z.string().uuid() });
	const deleteForm = await superValidate(formData, zod(schema));
	const model = getModelInfo(urlModel);

	const id = deleteForm.data.id;
	const endpoint = model.endpointUrl
		? `${BASE_API_URL}/${model.endpointUrl}/${id}/`
		: `${BASE_API_URL}/${model.urlModel}/${id}/`;

	if (!deleteForm.valid) {
		console.error(deleteForm.errors);
		return message(deleteForm, { status: 400 });
	}

	const requestInitOptions: RequestInit = {
		method: 'DELETE'
	};
	const res = await event.fetch(endpoint, requestInitOptions);
	if (!res.ok) {
		const response = await res.json();
		// 409 Conflict: backend blocks deletion (e.g. Entity referenced as
		// subcontractor). Body shape: { detail: "...", blocking_subcontracts: [...] }.
		// Surface the detail message so the user sees why deletion was refused.
		if (res.status === 409 && response.detail) {
			setFlash({ type: 'error', message: response.detail }, event);
			return message(deleteForm, { status: res.status });
		}
		if (response.error) {
			const errorMessages = Array.isArray(response.error) ? response.error : [response.error];
			errorMessages.forEach((error) => {
				setFlash({ type: 'error', message: safeTranslate(error) }, event);
			});
			return message(deleteForm, { status: res.status });
		}
		if (response.non_field_errors) {
			setError(deleteForm, 'non_field_errors', response.non_field_errors);
		}
		return message(deleteForm, { status: res.status });
	}
	setFlash(
		{
			type: 'success',
			message: m.successfullyDeletedObject({
				object: safeTranslate(model.localName).toLowerCase()
			})
		},
		event
	);

	return message(deleteForm, { status: res.status });
}

export async function nestedDeleteFormAction({ event }: { event: RequestEvent }) {
	const request = event.request.clone();
	const formData = await request.formData();
	const urlModel = formData.get('urlmodel') as string;
	return defaultDeleteFormAction({ event, urlModel });
}
