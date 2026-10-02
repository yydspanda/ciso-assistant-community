import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import testData from '../../../tests/utils/test-data';

const library = readFileSync(
	resolve(process.cwd(), '../backend/library/libraries/key-reference-controls.yaml'),
	'utf8'
);

// These two plain-scalar library entries are the positive AppliedControl fixtures.
// Bind their exact metadata to the checked-in source without adding a YAML parser
// dependency or changing the separate Policy API's authority contract.
const referenceControlBlocks = library.split(/^ {4}- urn: /m).slice(1);

describe('positive browser reference-control fixtures', () => {
	it.each([testData.referenceControl, testData.referenceControl2])(
		'uses the exact non-Policy library entry for $name',
		(fixture) => {
			const matches = referenceControlBlocks.filter(
				(block) => block.split('\n')[0] === fixture.urn
			);
			expect(matches).toHaveLength(1);
			const block = matches[0]!;
			const refId = block.match(/^ {6}ref_id: (.+)$/m)?.[1];
			const name = block.match(/^ {6}name: (.+)$/m)?.[1];
			expect(refId).toBeDefined();
			expect(name).toBeDefined();
			expect(fixture.name).toBe(`${refId} - ${name}`);
			expect(block.match(/^ {6}category: (.+)$/m)?.[1]).toBe('process');
			expect(library).toContain(`\nurn: ${fixture.library.urn}\n`);
			expect(library).toContain(`\nref_id: ${fixture.library.ref}\n`);
			expect(library).toContain(`\nname: ${fixture.library.name}\n`);
		}
	);

	it('keeps distinct positive references for the create and edit assertions', () => {
		expect(testData.referenceControl.urn).not.toBe(testData.referenceControl2.urn);
		expect(testData.referenceControl.name).not.toBe(testData.referenceControl2.name);
	});
});
