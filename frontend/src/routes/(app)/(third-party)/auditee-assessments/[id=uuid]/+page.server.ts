import { defaultWriteFormAction, handleErrorResponse } from '$lib/utils/actions';
import { BASE_API_URL } from '$lib/utils/constants';
import { getModelInfo } from '$lib/utils/crud';
import { safeTranslate } from '$lib/utils/i18n';
import { modelSchema, RequirementAssessmentRelationSchema } from '$lib/utils/schemas';
import { m } from '$paraglide/messages';
import { error, fail, type Actions } from '@sveltejs/kit';
import { setFlash } from 'sveltekit-flash-message/server';
import { message, superValidate } from 'sveltekit-superforms';
import { zod4 as zod } from 'sveltekit-superforms/adapters';
import { z } from 'zod';
import type { ModelInfo } from '$lib/utils/types';
import type { PageServerLoad } from './$types';

const assignmentRequirementMutableFields = new Set([
	'answers',
	'documentation_score',
	'evidences',
	'extended_result',
	'is_score_overridden',
	'is_scored',
	'observation',
	'respondent_alignment',
	'result',
	'score',
	'status'
]);
const relationUpdateFields = ['evidences', 'applied_controls'] as const;
type RelationUpdateField = (typeof relationUpdateFields)[number];

function isRelationUpdateField(value: string | null): value is RelationUpdateField {
	return value !== null && relationUpdateFields.some((field) => field === value);
}

function assignmentPatch(data: Record<string, unknown>) {
	return Object.fromEntries(
		Object.entries(data).filter(([fieldName]) => assignmentRequirementMutableFields.has(fieldName))
	);
}

export const load = (async ({ fetch, params }) => {
	// params.id is the assignment ID
	const assignmentId = params.id;

	// Fetch the assignment
	const assignmentRes = await fetch(`${BASE_API_URL}/requirement-assignments/${assignmentId}/`);
	if (!assignmentRes.ok) {
		throw error(assignmentRes.status, assignmentRes.statusText);
	}
	const assignmentResult = await assignmentRes.json();
	const assignment = {
		id: assignmentResult.id,
		status: assignmentResult.status,
		events: assignmentResult.events ?? [],
		actor: assignmentResult.actor ?? []
	};

	// Derive the compliance assessment from the assignment
	const caId = assignmentResult.compliance_assessment.id;
	const URLModel = 'compliance-assessments';
	const endpoint = `${BASE_API_URL}/${URLModel}/${caId}/`;

	const res = await fetch(endpoint);
	if (!res.ok) {
		throw error(res.status, await res.text());
	}
	const compliance_assessment = await res.json();

	const tableModeRes = await fetch(
		`${BASE_API_URL}/requirement-assignments/${assignmentId}/requirements_list/`
	);
	if (!tableModeRes.ok) {
		throw error(tableModeRes.status, tableModeRes.statusText);
	}
	const tableMode = await tableModeRes.json();

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
	const scoreSchema = z.object({
		is_scored: z.boolean().optional(),
		score: z.number().optional().nullable(),
		documentation_score: z.number().optional().nullable()
	});

	const requirement_assessments = await Promise.all(
		tableMode.requirement_assessments.map(async (requirementAssessment: any) => {
			const folderId = requirementAssessment.folder?.id ?? null;
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
			const scoreForm = await superValidate(
				{
					is_scored: requirementAssessment.is_scored,
					score: requirementAssessment.score,
					documentation_score: requirementAssessment.documentation_score
				},
				zod(scoreSchema)
			);
			const updatedModel: ModelInfo = getModelInfo('requirement-assessments');
			const object = {
				...requirementAssessment,
				folder: folderId,
				requirement: requirementAssessment.requirement.id,
				compliance_assessment: requirementAssessment.compliance_assessment.id,
				...(requirementAssessment.evidences !== undefined && {
					evidences: requirementAssessment.evidences.map((evidence: any) => evidence.id)
				}),
				...(requirementAssessment.applied_controls !== undefined && {
					applied_controls: requirementAssessment.applied_controls.map((ac: any) => ac.id)
				})
			};
			const updateForm = await superValidate(
				{
					evidences: object.evidences ?? [],
					applied_controls: object.applied_controls ?? []
				},
				zod(RequirementAssessmentRelationSchema),
				{ errors: false }
			);
			return {
				...requirementAssessment,
				measureCreateForm,
				evidenceCreateForm,
				observationBuffer,
				scoreForm,
				updateForm,
				updatedModel,
				object
			};
		})
	);

	const requirementAssessmentsById = requirement_assessments.reduce(
		(acc: Record<string, any>, requirementAssessment: any) => {
			acc[requirementAssessment.requirement.id] = requirementAssessment;
			return acc;
		},
		{} as Record<string, any>
	);

	const requirements = tableMode.requirements.map((requirement: any) => {
		if (requirementAssessmentsById[requirement.id]) {
			return requirementAssessmentsById[requirement.id];
		}
		return requirement;
	});

	return {
		URLModel,
		compliance_assessment,
		requirement_assessments,
		requirements,
		measureModel,
		evidenceModel,
		assignment,
		viewerRole: tableMode.viewer_role ?? 'respondent',
		title: compliance_assessment.name
	};
}) satisfies PageServerLoad;

export const actions: Actions = {
	updateRequirementAssessment: async (event) => {
		const data = await event.request.json();
		const value = z.object({ id: z.string().uuid() }).passthrough().safeParse(data);
		if (!value.success) {
			return fail(400, { error: 'Invalid requirement assessment identifier.' });
		}
		const endpoint = `${BASE_API_URL}/requirement-assignments/${event.params.id}/requirement-assessments/${value.data.id}/`;

		const requestInitOptions: RequestInit = {
			method: 'PATCH',
			body: JSON.stringify(assignmentPatch(value.data))
		};

		const res = await event.fetch(endpoint, requestInitOptions);
		return { status: res.status, body: await res.json() };
	},
	createEvidence: async (event) => {
		const result = await defaultWriteFormAction({
			event,
			urlModel: 'evidences',
			action: 'create',
			doRedirect: false
		});
		if ('form' in result && result.form) {
			return { form: result.form, newEvidence: result.form.message.object };
		}
		return result;
	},
	createAppliedControl: async (event) => {
		return defaultWriteFormAction({
			event,
			urlModel: 'applied-controls',
			action: 'create',
			doRedirect: false
		});
	},
	update: async (event) => {
		const schema = RequirementAssessmentRelationSchema;
		const id = event.url.searchParams.get('id');
		const field = event.url.searchParams.get('field');
		const requirementAssessmentId = z.string().uuid().safeParse(id);
		if (!requirementAssessmentId.success) {
			return fail(400, { form: await superValidate(event.request, zod(schema)) });
		}
		if (!isRelationUpdateField(field)) {
			return fail(400, { error: 'Unsupported assignment relation update.' });
		}

		const form = await superValidate(event.request, zod(schema));
		if (!form.valid) return fail(400, { form });

		const relationValue = form.data[field];
		if (!Array.isArray(relationValue)) return fail(400, { form });
		const formData = { [field]: relationValue };

		const endpoint = `${BASE_API_URL}/requirement-assignments/${event.params.id}/requirement-assessments/${requirementAssessmentId.data}/`;
		const response = await event.fetch(endpoint, {
			method: 'PATCH',
			body: JSON.stringify(formData)
		});
		if (!response.ok) return handleErrorResponse({ event, response, form });

		const object = await response.json();
		setFlash(
			{
				type: 'success',
				message: m.successfullySavedObject({
					object: safeTranslate('requirementAssessment').toLowerCase()
				})
			},
			event
		);
		return message(form, { object });
	},
	submitAssignment: async (event) => {
		const endpoint = `${BASE_API_URL}/requirement-assignments/${event.params.id}/set_status/`;
		const res = await event.fetch(endpoint, {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({ status: 'submitted' })
		});
		let body;
		try {
			body = await res.json();
		} catch {
			body = { error: res.statusText };
		}
		return { submitStatus: res.status, submitBody: body };
	}
};
