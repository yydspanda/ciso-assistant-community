import { describe, expect, it } from 'vitest';
import { ctaModeForAudit, hasDisplayableProgress } from './dashboard-card';

describe('auditee dashboard progress disclosure', () => {
	it('shows progress only when the whole projection is known and coherent', () => {
		expect(
			hasDisplayableProgress({
				assignment_status: 'in_progress',
				assessed_requirements: 2,
				total_requirements: 4,
				progress_percent: 50
			})
		).toBe(true);
	});

	it('accepts question-level progress that is intentionally finer-grained than the RA count', () => {
		expect(
			hasDisplayableProgress({
				assignment_status: 'in_progress',
				assessed_requirements: 0,
				total_requirements: 1,
				progress_percent: 50
			})
		).toBe(true);
	});

	it.each([
		{ assessed_requirements: null, total_requirements: null, progress_percent: null },
		{ assessed_requirements: 0, total_requirements: 1, progress_percent: Number.NaN },
		{ assessed_requirements: 2, total_requirements: 1, progress_percent: 100 },
		{ assessed_requirements: 0, total_requirements: 1, progress_percent: 101 }
	])('fails closed for an unavailable or incoherent projection: %o', (progress) => {
		expect(hasDisplayableProgress({ assignment_status: 'in_progress', ...progress })).toBe(false);
	});
});

describe('auditee dashboard CTA', () => {
	const audit = (assignment_status: string | undefined, progress_percent: number | null) => ({
		assignment_status,
		assessed_requirements: progress_percent === null ? null : 0,
		total_requirements: progress_percent === null ? null : 1,
		progress_percent
	});

	it.each([
		{ row: audit('draft', 0), expected: 'awaiting-start' },
		{ row: audit('in_progress', 0), expected: 'start' },
		{ row: audit(undefined, 0), expected: 'start' },
		{ row: audit('in_progress', 50), expected: 'continue' },
		{ row: audit('changes_requested', 0), expected: 'continue' },
		{ row: audit('submitted', 0), expected: 'review' },
		{ row: audit('closed', 0), expected: 'review' },
		{ row: audit('future_status', 0), expected: 'continue' }
	] as const)('derives $expected from assignment state and known progress', ({ row, expected }) => {
		expect(ctaModeForAudit(row)).toBe(expected);
	});

	it('does not turn an unavailable projection into a zero-progress start state', () => {
		expect(ctaModeForAudit(audit('in_progress', null))).toBe('continue');
	});
});
