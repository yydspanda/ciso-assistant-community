import { nestedWriteFormAction } from '$lib/utils/actions';
import { BASE_API_URL } from '$lib/utils/constants';
import { getModelInfo } from '$lib/utils/crud';
import { modelSchema, type FormDataShape } from '$lib/utils/schemas';
import { m } from '$paraglide/messages';
import { safeTranslate } from '$lib/utils/i18n';
import { fail, type Actions, type RequestEvent } from '@sveltejs/kit';
import { message, setError, superValidate, type SuperValidated } from 'sveltekit-superforms';
import { zod4 as zod } from 'sveltekit-superforms/adapters';
import type { ModelInfo } from '$lib/utils/types';
import type { PageServerLoad } from './$types';
import { z } from 'zod';

const relationshipUpdateFields = ['evidences', 'applied_controls'] as const;
type RelationshipUpdateField = (typeof relationshipUpdateFields)[number];

const uuidSchema = z.string().uuid();
const scoreValueSchema = z.number().finite().nullable();
const answerValueSchema = z.union([
	z.string(),
	z.number().finite(),
	z.boolean(),
	z.null(),
	z.array(z.string())
]);
const scalarUpdateSchema = z.union([
	z
		.object({ id: uuidSchema, status: z.enum(['to_do', 'in_progress', 'in_review', 'done']) })
		.strict(),
	z
		.object({
			id: uuidSchema,
			result: z.enum([
				'not_assessed',
				'partially_compliant',
				'non_compliant',
				'compliant',
				'not_applicable'
			])
		})
		.strict(),
	z
		.object({
			id: uuidSchema,
			extended_result: z
				.enum([
					'major_nonconformity',
					'minor_nonconformity',
					'observation_sensitive_point',
					'opportunity_for_improvement',
					'good_practice'
				])
				.nullable()
		})
		.strict(),
	z.object({ id: uuidSchema, answers: z.record(z.string(), answerValueSchema) }).strict(),
	z
		.object({
			id: uuidSchema,
			respondent_alignment: z.enum(['yes', 'no', 'in_progress', 'not_applicable']).nullable()
		})
		.strict(),
	z.object({ id: uuidSchema, is_scored: z.boolean() }).strict(),
	z.object({ id: uuidSchema, score: scoreValueSchema }).strict(),
	z.object({ id: uuidSchema, documentation_score: scoreValueSchema }).strict(),
	z.object({ id: uuidSchema, observation: z.string().nullable() }).strict()
]);

type RouteBoundRequirementAssessment =
	{ ok: true; object: Record<string, unknown> } | { ok: false; status: number; message: string };

type RouteBoundNestedCreate =
	{ ok: true; requirementAssessmentId: string } | { ok: false; result: ReturnType<typeof fail> };

type RelatedObject = { id: string } & Record<string, unknown>;

type TableModeRequirementAssessment = {
	id: string;
	folder?: RelatedObject | null;
	observation?: unknown;
	requirement: RelatedObject;
	compliance_assessment: RelatedObject;
	evidences?: RelatedObject[];
	applied_controls?: RelatedObject[];
} & Record<string, unknown>;

function apiFailureStatus(status: number): number {
	return status >= 400 && status <= 599 ? status : 502;
}

function relatedId(value: unknown): string | null {
	if (typeof value === 'string') return value;
	if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
	const id = (value as Record<string, unknown>).id;
	return typeof id === 'string' ? id : null;
}

async function apiErrorMessage(response: Response): Promise<string> {
	let messageText = response.statusText || m.error();
	try {
		const payload: unknown = await response.json();
		if (payload && typeof payload === 'object' && !Array.isArray(payload)) {
			const errorPayload = payload as Record<string, unknown>;
			const rawMessage = errorPayload.warning ?? errorPayload.error ?? errorPayload.detail;
			const firstMessage = Array.isArray(rawMessage) ? rawMessage[0] : rawMessage;
			if (typeof firstMessage === 'string') messageText = safeTranslate(firstMessage);
		}
	} catch {
		// The status remains authoritative when an intermediary returns non-JSON.
	}
	return messageText;
}

async function fetchRouteBoundRequirementAssessment(
	event: RequestEvent,
	requirementAssessmentId: string
): Promise<RouteBoundRequirementAssessment> {
	const complianceAssessmentId = event.params.id;
	if (
		!uuidSchema.safeParse(requirementAssessmentId).success ||
		!uuidSchema.safeParse(complianceAssessmentId).success
	) {
		return { ok: false, status: 400, message: m.error() };
	}

	const endpoint = `${BASE_API_URL}/requirement-assessments/${requirementAssessmentId}/`;
	let response: Response;
	try {
		response = await event.fetch(endpoint);
	} catch {
		return { ok: false, status: 502, message: m.error() };
	}
	if (!response.ok) {
		return {
			ok: false,
			status: apiFailureStatus(response.status),
			message: await apiErrorMessage(response)
		};
	}

	let object: unknown;
	try {
		object = await response.json();
	} catch {
		return { ok: false, status: 502, message: m.error() };
	}
	if (!object || typeof object !== 'object' || Array.isArray(object)) {
		return { ok: false, status: 502, message: m.error() };
	}
	const record = object as Record<string, unknown>;
	if (
		record.id !== requirementAssessmentId ||
		relatedId(record.compliance_assessment) !== complianceAssessmentId
	) {
		return { ok: false, status: 403, message: m.error() };
	}
	return { ok: true, object: record };
}

async function prepareRouteBoundNestedCreate(
	event: RequestEvent,
	expectedUrlModel: 'evidences' | 'applied-controls'
): Promise<RouteBoundNestedCreate> {
	let formData: FormData;
	try {
		formData = await event.request.clone().formData();
	} catch {
		return { ok: false, result: fail(400, { form: null }) };
	}

	let form: SuperValidated<FormDataShape>;
	try {
		form = (await superValidate(
			formData,
			zod(modelSchema(expectedUrlModel))
		)) as SuperValidated<FormDataShape>;
	} catch {
		return { ok: false, result: fail(400, { form: null }) };
	}

	if (formData.get('urlmodel') !== expectedUrlModel) {
		setError(form, 'urlmodel', m.error());
		return { ok: false, result: fail(400, { form }) };
	}
	if (!form.valid) return { ok: false, result: fail(400, { form }) };

	const relationship = z.array(uuidSchema).length(1).safeParse(form.data.requirement_assessments);
	if (!relationship.success) {
		setError(form, 'requirement_assessments', m.error());
		return { ok: false, result: fail(400, { form }) };
	}

	const requirementAssessmentId = relationship.data[0];
	const binding = await fetchRouteBoundRequirementAssessment(event, requirementAssessmentId);
	if (!binding.ok) {
		setError(form, 'requirement_assessments', binding.message);
		return { ok: false, result: fail(binding.status, { form }) };
	}
	return { ok: true, requirementAssessmentId };
}

function createdObject(result: unknown): Record<string, unknown> | null {
	if (!result || typeof result !== 'object' || !('form' in result)) return null;
	const form = (result as { form?: Record<string, any> }).form;
	const object: unknown = form?.message?.object;
	if (!object || typeof object !== 'object' || Array.isArray(object)) return null;
	const parsed = uuidSchema.safeParse((object as Record<string, unknown>).id);
	return parsed.success ? (object as Record<string, unknown>) : null;
}

function jsonValuesEqual(expected: unknown, actual: unknown): boolean {
	if (Array.isArray(expected) && Array.isArray(actual)) {
		if (expected.length !== actual.length) return false;
		if (
			expected.every((value) => typeof value === 'string') &&
			actual.every((value) => typeof value === 'string')
		) {
			const actualValues = new Set(actual);
			return expected.every((value) => actualValues.has(value));
		}
		return expected.every((value, index) => jsonValuesEqual(value, actual[index]));
	}
	return Object.is(expected, actual);
}

function responseReflectsScalarPatch(
	object: Record<string, unknown>,
	patch: Record<string, unknown>
): boolean {
	return Object.entries(patch).every(([field, expected]) => {
		if (field !== 'answers') return jsonValuesEqual(expected, object[field]);
		if (!expected || typeof expected !== 'object' || Array.isArray(expected)) return false;
		const returnedAnswers = object.answers;
		if (!returnedAnswers || typeof returnedAnswers !== 'object' || Array.isArray(returnedAnswers)) {
			return false;
		}
		return Object.entries(expected as Record<string, unknown>).every(([urn, value]) =>
			jsonValuesEqual(value, (returnedAnswers as Record<string, unknown>)[urn])
		);
	});
}

function isRelationshipUpdateField(value: string | null): value is RelationshipUpdateField {
	return relationshipUpdateFields.some((field) => field === value);
}

function relationshipIds(value: unknown): Set<string> | null {
	if (!Array.isArray(value)) return null;
	const ids = value.map((relationship) => {
		if (typeof relationship === 'string') return relationship;
		if (!relationship || typeof relationship !== 'object') return null;
		return (relationship as Record<string, unknown>).id;
	});
	if (
		!ids.every(
			(id): id is string => typeof id === 'string' && z.string().uuid().safeParse(id).success
		)
	)
		return null;
	return new Set(ids);
}

function submittedRelationshipIds(value: unknown): Set<string> | null {
	if (
		!Array.isArray(value) ||
		!value.every(
			(relationship) =>
				typeof relationship === 'string' && z.string().uuid().safeParse(relationship).success
		)
	)
		return null;
	return new Set(value);
}

function sameRelationshipIds(left: Set<string>, right: Set<string>): boolean {
	return left.size === right.size && [...left].every((id) => right.has(id));
}

async function failRelationshipUpdate(
	response: Response,
	form: SuperValidated<FormDataShape>,
	field: RelationshipUpdateField
) {
	let messageText = response.statusText || m.error();
	try {
		const payload: unknown = await response.json();
		if (payload && typeof payload === 'object' && !Array.isArray(payload)) {
			const errorPayload = payload as Record<string, unknown>;
			const rawMessage =
				errorPayload.warning ?? errorPayload.error ?? errorPayload.detail ?? errorPayload[field];
			const firstMessage = Array.isArray(rawMessage) ? rawMessage[0] : rawMessage;
			if (typeof firstMessage === 'string') messageText = safeTranslate(firstMessage);
		}
	} catch {
		// The HTTP status remains authoritative when an intermediary returns a
		// non-JSON body. Surface a bounded field error and keep the modal open.
	}
	setError(form, field, messageText);
	return fail(response.status >= 400 && response.status <= 599 ? response.status : 502, { form });
}

export const load = (async ({ fetch, params }) => {
	const URLModel = 'compliance-assessments';
	const endpoint = `${BASE_API_URL}/${URLModel}/${params.id}/`;

	const [compliance_assessment, tableMode, scores] = await Promise.all(
		[endpoint, `${endpoint}requirements_list/`, `${endpoint}global_score/`].map((endpoint) =>
			fetch(endpoint).then((res) => res.json())
		)
	);

	const frameworkId = compliance_assessment.framework?.id;
	if (frameworkId) {
		const frameworkEndpoint = `${BASE_API_URL}/frameworks/${frameworkId}/`;
		const framework = await fetch(frameworkEndpoint).then((res) => res.json());
		compliance_assessment.framework = framework;
	}

	const measureModel = getModelInfo('applied-controls');
	const measureCreateSchema = modelSchema('applied-controls');
	const evidenceModel = getModelInfo('evidences');
	const evidenceCreateSchema = modelSchema('evidences');

	const requirement_assessments = await Promise.all(
		tableMode.requirement_assessments.map(
			async (requirementAssessment: TableModeRequirementAssessment) => {
				// TODO: merge initial data ?
				const { folder, ...requirementAssessmentWithoutFolder } = requirementAssessment;
				const folderId = folder?.id;
				const measureCreateForm = folderId
					? await superValidate(
							{
								requirement_assessments: [requirementAssessment.id],
								folder: folderId
							},
							zod(measureCreateSchema),
							{ errors: false }
						)
					: null;
				const evidenceCreateForm = folderId
					? await superValidate(
							{
								requirement_assessments: [requirementAssessment.id],
								folder: folderId
							},
							zod(evidenceCreateSchema),
							{ errors: false }
						)
					: null;
				const observationBuffer = requirementAssessment.observation;
				const updateSchema = modelSchema('requirement-assessments');
				const updatedModel: ModelInfo = getModelInfo('requirement-assessments');
				const object = {
					...requirementAssessmentWithoutFolder,
					...(folderId ? { folder: folderId } : {}),
					requirement: requirementAssessment.requirement.id,
					compliance_assessment: requirementAssessment.compliance_assessment.id,
					...(requirementAssessment.evidences !== undefined && {
						evidences: requirementAssessment.evidences.map((evidence) => evidence.id)
					}),
					...(requirementAssessment.applied_controls !== undefined && {
						applied_controls: requirementAssessment.applied_controls.map((ac) => ac.id)
					})
				};
				const updateForm = await superValidate(object, zod(updateSchema), { errors: false });
				return {
					...requirementAssessment,
					measureCreateForm,
					evidenceCreateForm,
					observationBuffer,
					updateForm,
					updatedModel,
					object
				};
			}
		)
	);

	const requirementAssessmentsById = requirement_assessments.reduce(
		(acc, requirementAssessment) => {
			acc[requirementAssessment.requirement.id] = requirementAssessment;
			return acc;
		},
		{} as Record<string, (typeof requirement_assessments)[number]>
	);

	const requirements = tableMode.requirements.map((requirement: RelatedObject) => {
		if (requirementAssessmentsById[requirement.id]) {
			return requirementAssessmentsById[requirement.id];
		}
		return requirement;
	});

	return {
		URLModel,
		compliance_assessment,
		scores,
		requirement_assessments,
		requirements,
		measureModel,
		evidenceModel,
		viewerRole: tableMode.viewer_role === 'auditor' ? 'auditor' : 'respondent',
		title: m.tableMode()
	};
}) satisfies PageServerLoad;

export const actions: Actions = {
	updateRequirementAssessment: async (event) => {
		let data: unknown;
		try {
			data = await event.request.json();
		} catch {
			return fail(400, { error: m.error() });
		}
		const parsed = scalarUpdateSchema.safeParse(data);
		if (!parsed.success) return fail(400, { error: m.error() });

		const { id, ...patch } = parsed.data;
		const binding = await fetchRouteBoundRequirementAssessment(event, id);
		if (!binding.ok) return fail(binding.status, { error: binding.message });

		const URLModel = 'requirement-assessments';
		const endpoint = `${BASE_API_URL}/${URLModel}/${id}/`;

		const requestInitOptions: RequestInit = {
			method: 'PATCH',
			body: JSON.stringify(patch)
		};

		let response: Response;
		try {
			response = await event.fetch(endpoint, requestInitOptions);
		} catch {
			return fail(502, { error: m.error() });
		}
		if (!response.ok) {
			return fail(apiFailureStatus(response.status), {
				error: await apiErrorMessage(response)
			});
		}

		let body: unknown;
		try {
			body = await response.json();
		} catch {
			return fail(502, { error: m.error() });
		}
		if (!body || typeof body !== 'object' || Array.isArray(body)) {
			return fail(502, { error: m.error() });
		}
		const object = body as Record<string, unknown>;
		if (
			object.id !== id ||
			relatedId(object.compliance_assessment) !== event.params.id ||
			!responseReflectsScalarPatch(object, patch)
		) {
			return fail(409, { error: m.error() });
		}
		return { object };
	},
	createEvidence: async (event) => {
		const binding = await prepareRouteBoundNestedCreate(event, 'evidences');
		if (!binding.ok) return binding.result;

		const result = await nestedWriteFormAction({
			event,
			action: 'create',
			expectedUrlModel: 'evidences',
			boundRelationship: {
				field: 'requirement_assessments',
				value: [binding.requirementAssessmentId]
			}
		});
		const newEvidence = createdObject(result);
		return newEvidence && 'form' in result ? { form: result.form, newEvidence } : result;
	},
	createAppliedControl: async (event) => {
		const binding = await prepareRouteBoundNestedCreate(event, 'applied-controls');
		if (!binding.ok) return binding.result;

		return nestedWriteFormAction({
			event,
			action: 'create',
			expectedUrlModel: 'applied-controls',
			boundRelationship: {
				field: 'requirement_assessments',
				value: [binding.requirementAssessmentId]
			}
		});
	},
	update: async (event) => {
		// This action is used only by the relationship pickers in table mode. Keep
		// the PATCH field-scoped so a stale modal cannot overwrite unrelated fields.
		// Concurrent edits to that same field still need a future versioned/delta API
		// contract; this route makes no ordering guarantee. The API remains the authority
		// for IAM and field-visibility enforcement.
		const URLModel = 'requirement-assessments';
		const schema = modelSchema(URLModel);
		const id = event.url.searchParams.get('id');
		const field = event.url.searchParams.get('field');
		const form = await superValidate(event.request, zod(schema));

		if (!id || !z.string().uuid().safeParse(id).success || !isRelationshipUpdateField(field)) {
			return fail(400, { form });
		}
		const submittedIds = submittedRelationshipIds(form.data[field]);
		if (!Object.hasOwn(form.data, field) || !submittedIds) {
			return fail(400, { form });
		}

		if (!form.valid) {
			return fail(400, { form });
		}

		const binding = await fetchRouteBoundRequirementAssessment(event, id);
		if (!binding.ok) {
			setError(form, field, binding.message);
			return fail(binding.status, { form });
		}

		const endpoint = `${BASE_API_URL}/${URLModel}/${id}/`;
		let response: Response;
		try {
			response = await event.fetch(endpoint, {
				method: 'PATCH',
				body: JSON.stringify({ [field]: [...submittedIds] })
			});
		} catch {
			setError(form, field, m.error());
			return fail(502, { form });
		}

		if (!response.ok) return failRelationshipUpdate(response, form, field);

		let object: Record<string, unknown>;
		try {
			const responseBody: unknown = await response.json();
			if (!responseBody || typeof responseBody !== 'object' || Array.isArray(responseBody)) {
				throw new TypeError('Invalid relationship update response');
			}
			object = responseBody as Record<string, unknown>;
		} catch {
			setError(form, field, 'The authoritative API returned an invalid relationship response.');
			return fail(502, { form });
		}
		if (object.id !== id || relatedId(object.compliance_assessment) !== event.params.id) {
			setError(form, field, 'The authoritative API returned an invalid relationship response.');
			return fail(502, { form });
		}
		const returnedIds = relationshipIds(object[field]);
		if (!returnedIds || !sameRelationshipIds(submittedIds, returnedIds)) {
			setError(form, field, 'The relationship update was not applied by the authoritative API.');
			return fail(409, { form });
		}
		return message(form, {
			object,
			field,
			toast: {
				type: 'success',
				message: m.successfullySavedObject({
					object: safeTranslate('requirementAssessment').toLowerCase()
				})
			}
		});
	}
};
