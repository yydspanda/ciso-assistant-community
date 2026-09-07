import { describe, expect, it } from 'vitest';

import { RequirementAssessmentRelationSchema } from './schemas';

describe('RequirementAssessmentRelationSchema', () => {
	it('validates a redacted relation-only payload without audit ownership fields', () => {
		const result = RequirementAssessmentRelationSchema.safeParse({
			evidences: ['7fe956d8-a98e-43f2-bdd6-2d48922c41f7']
		});

		expect(result.success).toBe(true);
		if (result.success) {
			expect(result.data).toEqual({
				evidences: ['7fe956d8-a98e-43f2-bdd6-2d48922c41f7']
			});
			expect(result.data).not.toHaveProperty('folder');
		}
	});

	it('rejects malformed relation identifiers', () => {
		expect(
			RequirementAssessmentRelationSchema.safeParse({ applied_controls: ['not-a-uuid'] }).success
		).toBe(false);
	});
});
