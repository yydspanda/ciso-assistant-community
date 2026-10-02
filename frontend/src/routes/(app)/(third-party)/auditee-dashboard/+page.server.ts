import { BASE_API_URL } from '$lib/utils/constants';
import { discardBody } from '$lib/utils/responses';
import { m } from '$paraglide/messages';
import { error, type NumericRange } from '@sveltejs/kit';
import { z } from 'zod';
import type { PageServerLoad } from './$types';

const dashboardItemSchema = z
	.object({
		id: z.string().uuid(),
		assignment_id: z.string().uuid(),
		name: z.string(),
		folder: z.string().nullable(),
		framework: z.string().nullable(),
		status: z.string().nullable(),
		assignment_status: z.enum(['draft', 'in_progress', 'submitted', 'closed', 'changes_requested']),
		actor: z.string(),
		total_requirements: z.number().int().nonnegative(),
		assessed_requirements: z.number().int().nonnegative().nullable(),
		progress_percent: z.number().min(0).max(100).nullable()
	})
	.superRefine((item, context) => {
		if (
			item.assessed_requirements !== null &&
			item.assessed_requirements > item.total_requirements
		) {
			context.addIssue({
				code: 'custom',
				message: 'assessed requirements exceed the total',
				path: ['assessed_requirements']
			});
		}
		if ((item.assessed_requirements === null) !== (item.progress_percent === null)) {
			context.addIssue({
				code: 'custom',
				message: 'progress fields must be disclosed together',
				path: ['progress_percent']
			});
		}
	});

const dashboardSchema = z.array(dashboardItemSchema);
export type AuditeeDashboardItem = z.infer<typeof dashboardItemSchema>;

function backendErrorStatus(status: number): NumericRange<400, 599> {
	return (status >= 400 && status <= 599 ? status : 502) as NumericRange<400, 599>;
}

export const load: PageServerLoad = async ({ fetch }) => {
	const res = await fetch(`${BASE_API_URL}/compliance-assessments/auditee-dashboard/`).catch(() =>
		error(502, 'Audit dashboard is unavailable')
	);
	if (!res.ok) {
		await discardBody(res);
		error(backendErrorStatus(res.status), 'Unable to load audit dashboard');
	}

	let payload: unknown;
	try {
		payload = await res.json();
	} catch {
		error(502, 'Audit dashboard returned an invalid response');
	}
	const parsedDashboard = dashboardSchema.safeParse(payload);
	if (!parsedDashboard.success) {
		error(502, 'Audit dashboard returned an invalid response');
	}

	return {
		dashboard: parsedDashboard.data,
		title: m.auditDashboard()
	};
};
