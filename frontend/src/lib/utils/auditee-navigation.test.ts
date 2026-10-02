import { describe, expect, it } from 'vitest';
import { resolveAuthorizedParent, withAuthorizedParentSections } from './auditee-navigation';

const section = {
	id: 'section-ac',
	urn: 'urn:test:requirement:ac',
	name: 'ACCESS CONTROL',
	assessable: false,
	display_mode: 'default'
};
const child = {
	id: 'question-ac-1',
	urn: 'urn:test:requirement:ac-1',
	name: 'Authorized Access Control',
	assessable: true,
	parent_urn: section.urn
};
const firstQuestion: {
	type: 'assessment';
	data: { id: string; requirement: string | { id: string } };
} = {
	type: 'assessment',
	data: { id: 'assessment-ac-1', requirement: { id: child.id } }
};

describe('authorized auditee navigation', () => {
	it.each([section.id, section.urn, { id: section.id }, { urn: section.urn }])(
		'resolves existing parents by exact string or nested identity: %j',
		(reference) => expect(resolveAuthorizedParent(reference, [section, child])).toBe(section)
	);

	it('starts at the real section then the first question for the mixed read projection', () => {
		// The full RequirementNode projection uses parent_urn, while each RA's
		// requirement reference is nested. This is the actual assignment API shape.
		const items = withAuthorizedParentSections([firstQuestion], [section, child]);
		expect(items).toEqual([{ type: 'section', data: section }, firstQuestion]);
		expect(items[0]?.type).toBe('section');
		expect(items[1]?.type).toBe('assessment');
	});

	it.each([section.id, section.urn, { id: section.id, urn: section.urn }])(
		'preserves legacy parent_requirement representations: %j',
		(reference) => {
			const requirements = [section, { ...child, parent_requirement: reference }];
			expect(withAuthorizedParentSections([firstQuestion], requirements)).toEqual([
				{ type: 'section', data: section },
				firstQuestion
			]);
		}
	);

	it('falls back from a null nested parent to the provided parent_urn', () => {
		expect(
			withAuthorizedParentSections(
				[firstQuestion],
				[section, { ...child, parent_requirement: null }]
			)
		).toEqual([{ type: 'section', data: section }, firstQuestion]);
	});

	it('does not invent or fetch a missing or hidden parent even if its identity is referenced', () => {
		expect(resolveAuthorizedParent({ id: section.id, urn: section.urn }, [child])).toBeUndefined();
		expect(withAuthorizedParentSections([firstQuestion], [child])).toEqual([firstQuestion]);
		expect(resolveAuthorizedParent('urn:test:requirement:ac-lookalike', [section])).toBeUndefined();
	});

	it('inserts a shared parent once without reordering its questions', () => {
		const secondChild = { ...child, id: 'question-ac-2', urn: 'urn:test:requirement:ac-2' };
		const secondQuestion: typeof firstQuestion = {
			type: 'assessment',
			data: { id: 'assessment-ac-2', requirement: secondChild.id }
		};
		expect(
			withAuthorizedParentSections([firstQuestion, secondQuestion], [section, child, secondChild])
		).toEqual([{ type: 'section', data: section }, firstQuestion, secondQuestion]);
	});

	it('uses the same authorized parent_urn fallback for splash items', () => {
		const splash = { ...child, id: 'splash-ac', display_mode: 'splash' };
		const item = { type: 'splash' as const, data: splash };
		expect(withAuthorizedParentSections([item], [section, splash])).toEqual([
			{ type: 'section', data: section },
			item
		]);
	});

	it.each([
		{ ...section, assessable: true },
		{ ...section, display_mode: 'splash' }
	])('does not insert an assessable or splash parent as a section', (parent) => {
		expect(withAuthorizedParentSections([firstQuestion], [parent, child])).toEqual([firstQuestion]);
	});
});
