import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import { questionnaire } from '../../../tests/utils/test-data';

const library = readFileSync(
	resolve(process.cwd(), '../backend/library/libraries/cmmc-2.0.yaml'),
	'utf8'
);
// Bind only these plain scalar metadata fields, not a general YAML parser.
const nodes = library.split(/^ {6}- urn: /m).slice(1);
const field = (block: string, name: string) =>
	block.match(new RegExp(`^ {8}${name}: (.+)$`, 'm'))?.[1];

describe('native CMMC questionnaire browser fixture', () => {
	it('binds the loaded framework name, reference and canonical URN', () => {
		expect(library.match(/^urn: (.+)$/m)?.[1]).toBe('urn:intuitem:risk:library:cmmc-2.0');
		expect(library).toContain(`\nref_id: ${questionnaire.ref}\n`);
		expect(library).toContain(`\nname: ${questionnaire.name}\n`);
		expect(library).toContain(`\n    urn: ${questionnaire.urn}\n`);
	});

	it('binds the first assessable requirement exact ref and name used by the heading', () => {
		const first = nodes.find((block) => field(block, 'assessable') === 'true');
		expect(first).toBeDefined();
		expect(first!.split('\n')[0]).toBe(questionnaire.firstRequirement.urn);
		expect(field(first!, 'ref_id')).toBe(questionnaire.firstRequirement.ref);
		expect(field(first!, 'name')).toBe(questionnaire.firstRequirement.name);
		expect(field(first!, 'parent_urn')).toBe(questionnaire.firstRequirement.parentUrn);
	});

	it('keeps its real non-assessable ACCESS CONTROL parent before the first question', () => {
		const parent = nodes.find(
			(block) => block.split('\n')[0] === questionnaire.firstRequirement.parentUrn
		);
		expect(parent).toBeDefined();
		expect(nodes[0]).toBe(parent);
		expect(field(parent!, 'assessable')).toBe('false');
		expect(field(parent!, 'name')).toBe('ACCESS CONTROL');
	});
});
