import { describe, expect, it } from 'vitest';

import {
	buildRegulatoryListApiQuery,
	buildRegulatoryListHref,
	buildRegulatoryCurrentViewHref,
	buildRegulatorySelectionQuery,
	isAwareRfc3339,
	isRegulatoryRecordedAsOfQueryInvalid,
	normalizePaginated,
	parsePage,
	readRegulatoryListFilters,
	regulatoryLabelKey,
	regulatoryTone,
	responseListReadState,
	responseReadState,
	safeOfficialSourceHost
} from './presentation';

describe('regulatory read-only presentation contract', () => {
	it('accepts only registered list filters and computes a bounded offset', () => {
		const filters = readRegulatoryListFilters(
			new URLSearchParams({
				search: '  数据安全  ',
				authority_level: 'law',
				coverage_stage: 'obligations_proposed',
				page: '3',
				ignored: 'must-not-forward'
			})
		);

		expect(filters).toEqual({
			search: '数据安全',
			authorityLevel: 'law',
			coverageStage: 'obligations_proposed',
			page: 3
		});
		expect(buildRegulatoryListApiQuery(filters).toString()).toBe(
			'limit=25&offset=50&ordering=record_id&search=%E6%95%B0%E6%8D%AE%E5%AE%89%E5%85%A8&authority_level=law&coverage_stage=obligations_proposed'
		);
	});

	it('drops invalid filters and page values', () => {
		expect(
			readRegulatoryListFilters(
				new URLSearchParams({
					authority_level: 'legal_opinion',
					coverage_stage: 'published',
					page: '-2'
				})
			)
		).toEqual({ search: '', authorityLevel: '', coverageStage: '', page: 1 });
		expect(parsePage('1e3')).toBe(1);
		expect(parsePage('2')).toBe(2);
	});

	it('normalizes paginated and unpaginated backend responses', () => {
		expect(() => normalizePaginated([{ id: 'a' }])).toThrow('Invalid paginated response');
		expect(
			normalizePaginated({ count: 7, next: '/next', previous: null, results: [{ id: 'b' }] })
		).toEqual({ count: 7, next: '/next', previous: null, results: [{ id: 'b' }] });
		expect(() => normalizePaginated({ count: 2 })).toThrow('Invalid paginated response');
	});

	it('constructs explicit list and temporal-selection links', () => {
		expect(
			buildRegulatoryListHref(
				{ search: '金融', authorityLevel: 'departmental_rule', coverageStage: '' },
				2
			)
		).toBe('/regulatory?search=%E9%87%91%E8%9E%8D&authority_level=departmental_rule&page=2');
		expect(
			buildRegulatorySelectionQuery({
				entity: '4819de76-fce4-4a1c-bb3b-e97d80b61ab7',
				recordedAsOf: '2026-08-26T09:30:00+08:00'
			}).toString()
		).toBe(
			'entity=4819de76-fce4-4a1c-bb3b-e97d80b61ab7&recorded_as_of=2026-08-26T09%3A30%3A00%2B08%3A00'
		);
		expect(
			buildRegulatoryCurrentViewHref({
				entity: '4819de76-fce4-4a1c-bb3b-e97d80b61ab7',
				entitySearch: '合成 银行'
			})
		).toBe(
			'?entity=4819de76-fce4-4a1c-bb3b-e97d80b61ab7&entity_search=%E5%90%88%E6%88%90+%E9%93%B6%E8%A1%8C&mode=apply'
		);
		expect(buildRegulatoryCurrentViewHref({ entity: '' })).toBe('?mode=apply');
	});

	it('requires a timezone-aware RFC 3339 timestamp', () => {
		expect(isAwareRfc3339('2026-08-26T09:30:00+08:00')).toBe(true);
		expect(isAwareRfc3339('2026-08-26T01:30:00Z')).toBe(true);
		expect(isAwareRfc3339('2026-08-26T01:30:00.123456789Z')).toBe(true);
		expect(isAwareRfc3339('2026-08-26T01:30:00.1234567890Z')).toBe(true);
		expect(isAwareRfc3339('2026-02-30T01:30:00Z')).toBe(false);
		expect(isAwareRfc3339('2025-02-29T01:30:00Z')).toBe(false);
		expect(isAwareRfc3339('2024-02-29T01:30:00Z')).toBe(true);
		expect(isAwareRfc3339('2026-08-26T09:30:00')).toBe(false);
		expect(isAwareRfc3339('2026-08-26')).toBe(false);
	});

	it('treats one empty recorded-time form value as the current view', () => {
		const now = Date.parse('2026-08-26T02:00:00Z');
		expect(isRegulatoryRecordedAsOfQueryInvalid([], now)).toBe(false);
		expect(isRegulatoryRecordedAsOfQueryInvalid([''], now)).toBe(false);
		expect(isRegulatoryRecordedAsOfQueryInvalid(['   '], now)).toBe(false);
		expect(isRegulatoryRecordedAsOfQueryInvalid(['2026-02-30T00:00:00Z'], now)).toBe(true);
		expect(
			isRegulatoryRecordedAsOfQueryInvalid(['2026-08-26T01:30:00Z', '2026-08-26T01:30:00Z'], now)
		).toBe(true);
	});

	it('strictly parses and clamps page numbers', () => {
		expect(parsePage('2abc')).toBe(1);
		expect(parsePage('1000000000000')).toBe(10_000);
	});

	it('does not style applicability as a compliance approval', () => {
		expect(regulatoryTone('applicable')).toBe('info');
		expect(regulatoryTone('not_applicable')).toBe('info');
		expect(regulatoryTone('needs_review')).toBe('warning');
		expect(regulatoryTone('correction_requested')).toBe('danger');
		expect(regulatoryLabelKey('needs_review')).toBe('regulatoryValueNeedsReview');
		expect(regulatoryLabelKey('explicit_date')).toBe('regulatoryValueExplicitDate');
		expect(regulatoryLabelKey('page_bbox')).toBe('regulatoryValuePageBoundingBox');
		expect(regulatoryLabelKey('periodic')).toBe('regulatoryValuePeriodic');
	});

	it('collapses access-sensitive failures and separates invalid input', () => {
		expect(responseReadState(400)).toBe('invalid');
		expect(responseReadState(401)).toBe('unauthenticated');
		expect(responseReadState(403)).toBe('restricted');
		expect(responseReadState(404)).toBe('restricted');
		expect(responseReadState(503)).toBe('unavailable');
		expect(responseListReadState(401)).toBe('unauthenticated');
		expect(responseListReadState(403)).toBe('restricted');
		expect(responseListReadState(404)).toBe('unavailable');
	});

	it('allows only HTTP(S) official-source links', () => {
		expect(safeOfficialSourceHost('https://www.pbc.gov.cn/example')).toBe('www.pbc.gov.cn');
		expect(safeOfficialSourceHost('http://example.cn/rule')).toBeNull();
		expect(safeOfficialSourceHost('https://user:secret@example.cn/rule')).toBeNull();
		expect(safeOfficialSourceHost('https://@example.cn/rule')).toBeNull();
		expect(safeOfficialSourceHost('javascript:alert(1)')).toBeNull();
		expect(safeOfficialSourceHost('data:text/html,unsafe')).toBeNull();
		expect(safeOfficialSourceHost('not a url')).toBeNull();
	});
});
