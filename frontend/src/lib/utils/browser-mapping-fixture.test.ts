import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import { mappingPrerequisites } from '../../../tests/utils/test-data';

const readArtifact = (file: string) =>
	readFileSync(resolve(process.cwd(), '../backend/library/libraries', file), 'utf8');
const prerequisites = mappingPrerequisites;
const mappingArtifacts = prerequisites.libraries.map((fixture) => ({
	fixture,
	artifact: readArtifact(fixture.file)
}));

// These artifacts use plain scalars at these exact schema positions. The
// declared revert entries, not an inferred inverse, authorize the two hops.
function declaredEdges(artifact: string): string[][] {
	return artifact
		.split(/^ {2}- urn: /m)
		.slice(1)
		.map((block) => [
			block.match(/^ {4}source_framework_urn: (.+)$/m)![1],
			block.match(/^ {4}target_framework_urn: (.+)$/m)![1]
		]);
}

describe('browser mapping-library prerequisites', () => {
	it('loads the exact native intermediate framework', () => {
		const artifact = readArtifact(prerequisites.framework.file);
		expect(artifact.match(/^urn: (.+)$/m)?.[1]).toBe(prerequisites.framework.urn);
		expect(artifact.match(/^name: (.+)$/m)?.[1]).toBe(prerequisites.framework.name);
		expect(artifact.match(/^ {4}urn: (.+)$/m)?.[1]).toBe(prerequisites.framework.frameworkUrn);
	});

	it.each(mappingArtifacts)(
		'binds the exact mapping owner and dependencies: $fixture.file',
		({ fixture, artifact }) => {
			expect(artifact.match(/^urn: (.+)$/m)?.[1]).toBe(fixture.urn);
			expect(artifact.match(/^name: (.+)$/m)?.[1]).toBe(fixture.name);
			const dependencies = artifact.match(/^dependencies:\n((?:- .+\n)+)/m)?.[1];
			expect(dependencies).toBeDefined();
			expect(
				dependencies!
					.trim()
					.split('\n')
					.map((line) => line.slice(2))
			).toEqual(fixture.dependencies);
		}
	);

	it.each(mappingArtifacts)(
		'requires both explicitly declared directions: $fixture.file',
		({ fixture, artifact }) => {
			const mappingUrns = [...artifact.matchAll(/^ {2}- urn: (.+)$/gm)].map((match) => match[1]);
			expect(mappingUrns).toHaveLength(2);
			expect(mappingUrns[1]).toBe(`${mappingUrns[0]}-revert`);
			expect(declaredEdges(artifact)).toEqual([
				fixture.frameworkUrns,
				[fixture.frameworkUrns[1], fixture.frameworkUrns[0]]
			]);
		}
	);

	it('provides the original ISO -> Adobe -> NIST path at depth three', () => {
		const edges = mappingArtifacts.flatMap(({ artifact }) => declaredEdges(artifact));
		const path = [
			'urn:intuitem:risk:framework:iso27001-2022',
			prerequisites.framework.frameworkUrn,
			'urn:intuitem:risk:framework:nist-csf-1.1'
		];
		expect(path).toHaveLength(3);
		for (let index = 1; index < path.length; index++) {
			expect(edges).toContainEqual([path[index - 1], path[index]]);
		}
	});

	it('does not invent a reverse edge for the standalone NIST -> ISO artifact', () => {
		const artifact = readArtifact('map-nist-csf-1.1-iso27001-2022.yaml');
		const sources = [...artifact.matchAll(/^ {4}source_framework_urn: (.+)$/gm)].map((m) => m[1]);
		expect(sources).toEqual(['urn:intuitem:risk:framework:nist-csf-1.1']);
		expect(artifact.match(/^ {4}target_framework_urn: (.+)$/m)?.[1]).toBe(
			'urn:intuitem:risk:framework:iso27001-2022'
		);
	});
});
