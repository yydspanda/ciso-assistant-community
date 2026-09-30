import { describe, expect, it, vi } from 'vitest';
import {
	fetchBaselineScoreScale,
	getPreset,
	previewLevels,
	scaleLevels,
	scaleOptions,
	seedLevels,
	type ScoreLevel
} from './score-scales';

const frameworkLevels: ScoreLevel[] = [
	{
		score: 1,
		name: 'Initial',
		description: 'Standard process does not exist.',
		description_doc: 'No process documentation.',
		translations: { fr: { name: 'Initial', description: 'Pas de processus.' } }
	},
	{ score: 2, name: 'Repeatable', description: 'Some process.' }
];

const baselineId = '7fe956d8-a98e-43f2-bdd6-2d48922c41f7';
const frameworkId = '4819de76-fce4-4a1c-bb3b-e97d80b61ab7';

function visibleBaselineScale() {
	return {
		scoring_enabled: true,
		score_scale_preset: '1-5',
		min_score: 1,
		max_score: 5,
		scores_definition: []
	};
}

describe('fetchBaselineScoreScale', () => {
	it('loads a visible scale only after proving that the baseline uses the selected framework', async () => {
		const fetcher = vi.fn().mockResolvedValueOnce(Response.json(visibleBaselineScale()));

		await expect(
			fetchBaselineScoreScale(fetcher, baselineId, frameworkId, {
				id: baselineId,
				framework: { id: frameworkId }
			})
		).resolves.toEqual({
			score_scale_preset: '1-5',
			min_score: 1,
			max_score: 5,
			scores_definition: []
		});
		expect(fetcher).toHaveBeenCalledWith(
			`/compliance-assessments/${baselineId}/global-score`,
			undefined
		);
	});

	it.each([
		['a different framework', { id: baselineId, framework: { id: crypto.randomUUID() } }],
		['a missing framework', { id: baselineId }],
		['a different assessment', { id: crypto.randomUUID(), framework: { id: frameworkId } }]
	])('fails closed before reading scores for %s', async (_case, assessment) => {
		const fetcher = vi.fn();

		await expect(
			fetchBaselineScoreScale(fetcher, baselineId, frameworkId, assessment)
		).resolves.toBeNull();
		expect(fetcher).not.toHaveBeenCalled();
	});

	it.each([
		['unauthorized', new Response(null, { status: 401 })],
		['forbidden', new Response(null, { status: 403 })],
		['missing', new Response(null, { status: 404 })],
		['hidden', Response.json({ scoring_enabled: false })],
		['malformed', Response.json({ scoring_enabled: true, min_score: 1, max_score: 5 })],
		[
			'a null level',
			Response.json({
				...visibleBaselineScale(),
				score_scale_preset: null,
				scores_definition: [null]
			})
		],
		[
			'a non-numeric level score',
			Response.json({
				...visibleBaselineScale(),
				score_scale_preset: null,
				scores_definition: [{ score: '1', name: 'Initial' }]
			})
		],
		[
			'malformed translations',
			Response.json({
				...visibleBaselineScale(),
				score_scale_preset: null,
				scores_definition: [{ score: 1, translations: { en: { name: 42 } } }]
			})
		]
	])('rejects a %s score response', async (_case, scoreResponse) => {
		const fetcher = vi.fn().mockResolvedValueOnce(scoreResponse);

		await expect(
			fetchBaselineScoreScale(fetcher, baselineId, frameworkId, {
				id: baselineId,
				framework: frameworkId
			})
		).resolves.toBeNull();
	});

	it('does not publish a superseded request after its score response arrives', async () => {
		let releaseFirstScore!: (response: Response) => void;
		const firstScore = new Promise<Response>((resolve) => {
			releaseFirstScore = resolve;
		});
		let scoreCalls = 0;
		const fetcher = vi.fn(async () => {
			scoreCalls += 1;
			return scoreCalls === 1 ? firstScore : Response.json(visibleBaselineScale());
		});
		const assessment = { id: baselineId, framework: { id: frameworkId } };
		const staleController = new AbortController();
		const stale = fetchBaselineScoreScale(
			fetcher,
			baselineId,
			frameworkId,
			assessment,
			staleController.signal
		);
		staleController.abort();
		const current = fetchBaselineScoreScale(fetcher, baselineId, frameworkId, assessment);

		await expect(current).resolves.toMatchObject({ min_score: 1, max_score: 5 });
		releaseFirstScore(Response.json(visibleBaselineScale()));
		await expect(stale).resolves.toBeNull();
		expect(fetcher).toHaveBeenCalledTimes(2);
	});
});

describe('seedLevels', () => {
	it('keeps descriptions when seeding a custom scale from framework levels', () => {
		const seeded = seedLevels(frameworkLevels, undefined, 1, 2, ['en']);
		expect(seeded[0]).toMatchObject({
			score: 1,
			name: 'Initial',
			description: 'Standard process does not exist.',
			description_doc: 'No process documentation.'
		});
		expect(seeded[0].translations?.fr).toEqual({
			name: 'Initial',
			description: 'Pas de processus.'
		});
		expect(seeded[1].description).toBe('Some process.');
	});

	it('does not mutate the source levels', () => {
		const source = structuredClone(frameworkLevels);
		seedLevels(source, undefined, 1, 2, ['en', 'de']);
		expect(source).toEqual(frameworkLevels);
	});

	it('drops preset tags so a custom scale never resolves catalog labels', () => {
		const tagged: ScoreLevel[] = [{ score: 0, preset: '0-5', translations: {} }];
		const [level] = seedLevels(tagged, getPreset('0-5'), 0, 5, ['en']);
		expect(level).not.toHaveProperty('preset');
		expect(level.name).toBeTruthy();
	});

	it('accepts proxied levels, as handed over by Svelte state', () => {
		const proxied = frameworkLevels.map((l) => new Proxy(structuredClone(l), {}));
		const seeded = seedLevels(new Proxy(proxied, {}), undefined, 1, 2, ['en']);
		expect(seeded[0].description).toBe('Standard process does not exist.');
		expect(() => structuredClone(seeded)).not.toThrow();
	});

	it('fills every score of the range', () => {
		expect(seedLevels([], undefined, 1, 4, ['en']).map((l) => l.score)).toEqual([1, 2, 3, 4]);
	});

	it('returns no levels for ranges too wide to label', () => {
		expect(seedLevels(frameworkLevels, undefined, 0, 100, ['en'])).toEqual([]);
	});
});

describe('scaleLevels', () => {
	it('accepts bare lists and the wrapped {scale} form', () => {
		expect(scaleLevels(frameworkLevels)).toBe(frameworkLevels);
		expect(scaleLevels({ scale: frameworkLevels })).toBe(frameworkLevels);
		expect(scaleLevels(null)).toEqual([]);
		expect(scaleLevels({ alternatives: {} })).toEqual([]);
	});
});

describe('scaleOptions', () => {
	const unscaled = { min_score: 0, max_score: 100, scores_definition: null };
	const cmmi = { min_score: 1, max_score: 5, scores_definition: frameworkLevels };
	const org15 = {
		score_scale_preset: '1-5',
		min_score: 1,
		max_score: 5,
		scores_definition: []
	};
	const ids = (r: { options: { id: string }[] }) => r.options.map((o) => o.id);

	it('proposes the organisation scale for frameworks without their own', () => {
		const r = scaleOptions({ framework: unscaled, organisation: org15 });
		expect(r.selected).toBe('organisation');
		expect(r.options.find((o) => o.id === 'organisation')?.value).toMatchObject({
			score_scale_preset: '1-5',
			min_score: 1,
			max_score: 5
		});
	});

	it("keeps the framework's scale when it ships one", () => {
		expect(scaleOptions({ framework: cmmi, organisation: org15 }).selected).toBe('framework');
	});

	it('hides the preset the organisation option already stands for', () => {
		const r = scaleOptions({ framework: unscaled, organisation: org15 });
		expect(ids(r)).not.toContain('1-5');
		expect(ids(r)).toEqual(['organisation', '0-100', '0-5', '1-4', '0-3']);
	});

	it('offers only the framework for scale-bound frameworks', () => {
		const r = scaleOptions({
			framework: { ...unscaled, is_scale_bound: true },
			organisation: org15
		});
		expect(ids(r)).toEqual(['framework']);
		expect(r.selected).toBe('framework');
	});

	it('pre-selects the baseline audit in copy forms', () => {
		const baseline = {
			score_scale_preset: null,
			min_score: 0,
			max_score: 100,
			scores_definition: []
		};
		const r = scaleOptions({ framework: unscaled, organisation: org15, baseline });
		expect(r.selected).toBe('baseline');
	});

	it('the framework option lets the backend copy the framework scale', () => {
		expect(scaleOptions({ framework: cmmi }).options[0].value).toBeNull();
	});

	it('matches an existing audit to its option', () => {
		const onFramework = {
			score_scale_preset: null,
			min_score: 1,
			max_score: 5,
			scores_definition: frameworkLevels
		};
		expect(
			scaleOptions({ framework: cmmi, organisation: org15, current: onFramework }).selected
		).toBe('framework');
		const onPreset = {
			score_scale_preset: '0-3',
			min_score: 0,
			max_score: 3,
			scores_definition: []
		};
		expect(scaleOptions({ framework: cmmi, organisation: org15, current: onPreset }).selected).toBe(
			'0-3'
		);
		const onOrg = { ...org15 };
		expect(
			scaleOptions({ framework: unscaled, organisation: org15, current: onOrg }).selected
		).toBe('organisation');
	});

	it('shows an existing scale that matches nothing as the current scale', () => {
		const legacy = {
			score_scale_preset: null,
			min_score: 1,
			max_score: 3,
			scores_definition: [{ score: 1, name: 'Mine' }]
		};
		const r = scaleOptions({ framework: unscaled, organisation: org15, current: legacy });
		expect(r.selected).toBe('current');
		expect(r.options[0]).toMatchObject({ id: 'current', min: 1, max: 3 });
	});

	it('an existing 0-100 audit on an unscaled framework shows as the 0-100 preset', () => {
		const legacy = {
			score_scale_preset: null,
			min_score: 0,
			max_score: 100,
			scores_definition: null
		};
		expect(
			scaleOptions({ framework: unscaled, organisation: org15, current: legacy as never }).selected
		).toBe('0-100');
	});

	it('an unlabelled legacy audit never borrows a labelled preset', () => {
		const legacy = {
			score_scale_preset: null,
			min_score: 0,
			max_score: 5,
			scores_definition: []
		};
		expect(
			scaleOptions({ framework: unscaled, organisation: org15, current: legacy }).selected
		).toBe('current');
	});

	it('offers no framework option when the framework has no scale of its own', () => {
		expect(ids(scaleOptions({ framework: unscaled, organisation: org15 }))).not.toContain(
			'framework'
		);
	});
});

describe('previewLevels', () => {
	it('uses catalog labels for presets and own labels otherwise', () => {
		const preset = getPreset('1-4')!;
		const catalog = previewLevels({ min: 1, max: 4, preset, levels: [] }, 'en');
		expect(catalog.map((l) => l.score)).toEqual([1, 2, 3, 4]);
		expect(catalog.every((l) => l.name)).toBe(true);
		const own = previewLevels({ min: 1, max: 2, preset: undefined, levels: frameworkLevels }, 'fr');
		expect(own[0]).toEqual({ score: 1, name: 'Initial' });
	});
});
