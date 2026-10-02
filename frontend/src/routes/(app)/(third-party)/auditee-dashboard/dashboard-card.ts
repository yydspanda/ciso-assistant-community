export type DashboardProgress = {
	assignment_status?: string | null;
	assessed_requirements: number | null;
	total_requirements: number | null;
	progress_percent: number | null;
};

export type DashboardCtaMode = 'awaiting-start' | 'start' | 'continue' | 'review';

export function hasDisplayableProgress(audit: DashboardProgress): audit is DashboardProgress & {
	assessed_requirements: number;
	total_requirements: number;
	progress_percent: number;
} {
	const { assessed_requirements, total_requirements, progress_percent } = audit;
	return (
		typeof assessed_requirements === 'number' &&
		typeof total_requirements === 'number' &&
		typeof progress_percent === 'number' &&
		Number.isFinite(assessed_requirements) &&
		Number.isFinite(total_requirements) &&
		Number.isFinite(progress_percent) &&
		assessed_requirements >= 0 &&
		total_requirements >= 0 &&
		assessed_requirements <= total_requirements &&
		progress_percent >= 0 &&
		progress_percent <= 100
	);
}

export function ctaModeForAudit(audit: DashboardProgress): DashboardCtaMode {
	if (audit.assignment_status === 'draft') return 'awaiting-start';
	if (audit.assignment_status === 'submitted' || audit.assignment_status === 'closed') {
		return 'review';
	}
	if (
		(audit.assignment_status === 'in_progress' || !audit.assignment_status) &&
		hasDisplayableProgress(audit) &&
		audit.progress_percent === 0
	) {
		return 'start';
	}
	return 'continue';
}
