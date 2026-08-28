import { nestedWriteFormAction } from '$lib/utils/actions';
import { BASE_API_URL } from '$lib/utils/constants';
import { getModelInfo } from '$lib/utils/crud';
import { formatSelectFieldData } from '$lib/utils/load';
import { ComplianceAssessmentSchema, modelSchema } from '$lib/utils/schemas';
import { error, redirect, type Actions } from '@sveltejs/kit';
import { fail, superValidate } from 'sveltekit-superforms';
import { zod4 as zod } from 'sveltekit-superforms/adapters';
import type { PageServerLoad } from './$types';
import { z } from 'zod';
import { setFlash } from 'sveltekit-flash-message/server';
import { m } from '$paraglide/messages';
import { viewerRoleFromTreeResponse } from './viewer-role';

const EMPTY_THREATS = {
	threats: [],
	total_unique_threats: 0,
	graph: { nodes: [] }
};

const readRequiredJson = async (response: Response, label: string) => {
	if (!response.ok) {
		throw error(response.status, response.statusText || `Failed to load ${label}`);
	}
	return response.json();
};

const readOptionalJson = async <T>(response: Response, fallback: T): Promise<T> => {
	if (!response.ok) return fallback;
	return response.json();
};

export const load = (async ({ fetch, params, cookies, locals }) => {
	const URLModel = 'compliance-assessments';
	const endpoint = `${BASE_API_URL}/${URLModel}/${params.id}/`;
	const objectEndpoint = `${endpoint}object/`;

	const res = await fetch(endpoint);
	if (!res.ok) {
		if (res.status === 404) {
			// Check if focus mode is active
			const focusFolderId = cookies.get('focus_folder_id');
			const focusModeEnabled = locals.featureflags?.focus_mode ?? false;
			const isFocusModeActive = focusFolderId && focusModeEnabled;

			const message = isFocusModeActive
				? m.objectNotReachableFromCurrentFocus()
				: m.objectNotFound();
			setFlash({ type: 'warning', message }, cookies);
			throw redirect(302, '/compliance-assessments');
		}
		throw error(res.status, res.statusText || 'Failed to load compliance assessment');
	}
	const compliance_assessment = await res.json();

	// The role is authority-bearing for the rest of this loader.  It comes only
	// from the fixed backend tree response; a client request header is never
	// consulted.  Reject an unsuccessful tree response before trusting any of
	// its headers or starting an auditor-only request.
	const treeResponse = await fetch(`${endpoint}tree/`);
	const tree = await readRequiredJson(treeResponse, 'compliance assessment tree');
	const viewerRole = viewerRoleFromTreeResponse(treeResponse);
	const isAuditor = viewerRole === 'auditor';

	const baseAuditModel = getModelInfo('compliance-assessments');
	const selectOptions: Record<string, any> = {};
	const baseValidationFlowModel = getModelInfo('validation-flows');
	const validationFlowSelectOptions: Record<string, any> = {};

	// These options feed auditor-only create/clone actions.  Do not make their
	// backing requests for assignment-scoped respondents.
	const selectFieldPromises = isAuditor
		? (baseAuditModel.selectFields || []).map(async (selectField) => {
				const url = `${BASE_API_URL}/compliance-assessments/${selectField.field}/`;
				const response = await fetch(url);

				if (response.ok) {
					const responseData = await response.json();
					selectOptions[selectField.field] = formatSelectFieldData(responseData, selectField);
				} else {
					console.error(`Failed to fetch data for ${selectField.field}: ${response.statusText}`);
				}
			})
		: [];

	// Form construction is local and keeps the historical PageData shape for
	// both roles.  The respondent path intentionally omits the former select-
	// option API hydration; the action remains hidden and backend-authorized.
	const assessmentFolderId = compliance_assessment.folder?.id;
	const validationFlowSelectFieldPromises =
		isAuditor && assessmentFolderId
			? (baseValidationFlowModel.selectFields || []).map(async (selectField) => {
					const url = `${BASE_API_URL}/validation-flows/${selectField.field}/`;
					const response = await fetch(url);

					if (response.ok) {
						const responseData = await response.json();
						validationFlowSelectOptions[selectField.field] = formatSelectFieldData(
							responseData,
							selectField
						);
					} else {
						console.error(
							`Failed to fetch validation flow data for ${selectField.field}: ${response.statusText}`
						);
					}
				})
			: [];
	const validationFlowFormPromise =
		isAuditor && assessmentFolderId
			? superValidate(
					{
						folder: assessmentFolderId,
						compliance_assessments: [params.id],
						ref_id: ''
					},
					zod(modelSchema('validation-flows')),
					{ errors: false }
				)
			: Promise.resolve(null);

	const [
		object,
		compliance_assessment_donut_values,
		global_score,
		threats,
		frameworksMappings,
		auditCreateForm,
		auditCloneForm,
		form,
		validationFlowForm
	] = await Promise.all([
		isAuditor
			? fetch(objectEndpoint).then((response) => readOptionalJson(response, null))
			: Promise.resolve(null),
		fetch(`${endpoint}donut_data/`).then((response) =>
			readRequiredJson(response, 'compliance assessment donut data')
		),
		fetch(`${endpoint}global_score/`).then((response) =>
			readRequiredJson(response, 'compliance assessment global score')
		),
		isAuditor
			? fetch(`${endpoint}threats_metrics/`).then((response) =>
					readOptionalJson(response, EMPTY_THREATS)
				)
			: Promise.resolve(EMPTY_THREATS),
		isAuditor
			? fetch(`${endpoint}frameworks/`).then((response) => readOptionalJson(response, []))
			: Promise.resolve([]),
		superValidate({ baseline: compliance_assessment.id }, zod(ComplianceAssessmentSchema), {
			errors: false
		}),
		superValidate(
			{
				baseline: compliance_assessment.id,
				framework: compliance_assessment.framework?.id,
				perimeter: compliance_assessment.perimeter?.id
			},
			zod(ComplianceAssessmentSchema),
			{ errors: false }
		),
		superValidate(zod(z.object({ id: z.string().uuid() }))),
		validationFlowFormPromise,
		...selectFieldPromises,
		...validationFlowSelectFieldPromises
	]);

	// getModelInfo returns a module-level catalog entry.  Never mutate it with
	// request-scoped options or a later SSR request could inherit another
	// caller's authorized data.
	const auditModel = { ...baseAuditModel, selectOptions };
	const validationFlowModel =
		isAuditor && assessmentFolderId
			? { ...baseValidationFlowModel, selectOptions: validationFlowSelectOptions }
			: null;

	return {
		URLModel,
		compliance_assessment,
		auditCreateForm,
		auditCloneForm,
		auditModel,
		object,
		tree,
		viewerRole,
		compliance_assessment_donut_values,
		global_score,
		threats,
		form,
		frameworksMappings,
		validationFlowForm,
		validationFlowModel,
		title: compliance_assessment.name
	};
}) satisfies PageServerLoad;

export const actions: Actions = {
	create: async (event) => {
		const request = event.request.clone();
		const formData = await request.formData();
		const form = await superValidate(formData, zod(ComplianceAssessmentSchema));
		const redirectToWrittenObject = Boolean(form.data.baseline);
		return nestedWriteFormAction({ event, action: 'create', redirectToWrittenObject });
	},
	createSuggestedControls: async (event) => {
		const formData = await event.request.formData();

		if (!formData) {
			return fail(400, { form: null });
		}

		const schema = z.object({ id: z.string().uuid() });
		const form = await superValidate(formData, zod(schema));

		const response = await event.fetch(
			`/compliance-assessments/${event.params.id}/suggestions/applied-controls`,
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
		}
		return { form };
	},
	syncToActions: async (event) => {
		const formData = await event.request.formData();

		if (!formData) {
			return fail(400, { form: null });
		}

		const schema = z.object({ id: z.string().uuid() });
		const form = await superValidate(formData, zod(schema));

		const response = await event.fetch(
			`${BASE_API_URL}/compliance-assessments/${event.params.id}/syncToActions/?dry_run=false`,
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
					message: m.syncToAppliedControlsSuccess()
				},
				event
			);
		} else {
			setFlash(
				{
					type: 'error',
					message: m.syncToAppliedControlsError()
				},
				event
			);
		}
		return { form, message: { requirementAssessmentsSync: await response.json() } };
	}
};
