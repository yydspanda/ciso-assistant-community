import type { PaginatedResponse, RegulatoryDocumentVersion, RegulatoryReadState } from './types';

export const REGULATORY_PAGE_SIZE = 25;
export const REGULATORY_MAX_PAGE = 10_000;

export const REGULATORY_AUTHORITY_LEVELS = [
	'law',
	'administrative_regulation',
	'departmental_rule',
	'regulatory_normative_document',
	'mandatory_standard',
	'recommended_standard',
	'internal_policy',
	'interpretive_material',
	'enforcement_material'
] as const;

export const REGULATORY_COVERAGE_STAGES = [
	'source_metadata',
	'provision_indexed',
	'obligations_proposed',
	'obligations_reviewed'
] as const;

const LABEL_KEYS: Record<string, string> = {
	law: 'regulatoryValueLaw',
	administrative_regulation: 'regulatoryValueAdministrativeRegulation',
	departmental_rule: 'regulatoryValueDepartmentalRule',
	regulatory_normative_document: 'regulatoryValueNormativeDocument',
	mandatory_standard: 'regulatoryValueMandatoryStandard',
	recommended_standard: 'regulatoryValueRecommendedStandard',
	internal_policy: 'regulatoryValueInternalPolicy',
	interpretive_material: 'regulatoryValueInterpretiveMaterial',
	enforcement_material: 'regulatoryValueEnforcementMaterial',
	source_metadata: 'regulatoryValueSourceMetadata',
	provision_indexed: 'regulatoryValueProvisionIndexed',
	obligations_proposed: 'regulatoryValueObligationsProposed',
	obligations_reviewed: 'regulatoryValueObligationsReviewed',
	draft: 'regulatoryValueDraft',
	published_future_effective: 'regulatoryValueFutureEffective',
	effective: 'regulatoryValueEffective',
	active_no_explicit_commencement: 'regulatoryValueNoExplicitCommencement',
	superseded: 'regulatoryValueSuperseded',
	repealed: 'regulatoryValueRepealed',
	unknown: 'regulatoryValueUnknown',
	unreviewed: 'regulatoryValueUnreviewed',
	reviewed: 'regulatoryValueReviewed',
	confirmed: 'regulatoryValueConfirmed',
	partial: 'regulatoryValuePartial',
	unresolved: 'regulatoryValueUnresolved',
	metadata_only: 'regulatoryValueMetadataOnly',
	official_snapshot: 'regulatoryValueOfficialSnapshot',
	licensed_copy: 'regulatoryValueLicensedCopy',
	explicit_date: 'regulatoryValueExplicitDate',
	publication_clause: 'regulatoryValuePublicationClause',
	no_explicit_commencement_clause: 'regulatoryValueNoExplicitCommencementClause',
	article: 'regulatoryValueArticle',
	page: 'regulatoryValuePage',
	page_bbox: 'regulatoryValuePageBoundingBox',
	dom_selector: 'regulatoryValueDomSelector',
	annex: 'regulatoryValueAnnex',
	table_cell: 'regulatoryValueTableCell',
	other: 'regulatoryValueOther',
	none: 'regulatoryValueNone',
	fixed_date: 'regulatoryValueFixedDate',
	duration_after_trigger: 'regulatoryValueDurationAfterTrigger',
	periodic: 'regulatoryValuePeriodic',
	without_undue_delay: 'regulatoryValueWithoutUndueDelay',
	must: 'regulatoryValueMust',
	must_not: 'regulatoryValueMustNot',
	should: 'regulatoryValueShould',
	may: 'regulatoryValueMay',
	organisation_defined: 'regulatoryValueOrganisationDefined',
	machine_proposed: 'regulatoryValueMachineProposed',
	analyst_reviewed: 'regulatoryValueAnalystReviewed',
	legal_reviewed: 'regulatoryValueLegalReviewed',
	approved: 'regulatoryValueApproved',
	rejected: 'regulatoryValueRejected',
	applicable: 'regulatoryValueApplicable',
	not_applicable: 'regulatoryValueNotApplicable',
	needs_review: 'regulatoryValueNeedsReview',
	evaluated: 'regulatoryValueEvaluated',
	not_evaluated: 'regulatoryValueNotEvaluated',
	not_reviewable: 'regulatoryValueNotReviewable',
	not_reviewed: 'regulatoryValueNotReviewed',
	no_correction_requested: 'regulatoryValueNoCorrectionRequested',
	correction_requested: 'regulatoryValueCorrectionRequested',
	unable_to_complete: 'regulatoryValueUnableToComplete',
	reviewed_nonbinding: 'regulatoryValueReviewedNonBinding',
	human: 'regulatoryValueHuman',
	parser: 'regulatoryValueParser',
	model_proposal: 'regulatoryValueModelProposal',
	import: 'regulatoryValueImport',
	rule_satisfied: 'regulatoryReasonRuleSatisfied',
	rule_not_satisfied: 'regulatoryReasonRuleNotSatisfied',
	missing_or_unknown_fact: 'regulatoryReasonMissingOrUnknownFact',
	no_decision_for_selected_obligation_revision: 'regulatoryReasonNoDecisionForRevision'
};

export type RegulatoryTone = 'danger' | 'warning' | 'success' | 'info' | 'neutral';

const DANGER_VALUES = new Set(['rejected', 'correction_requested', 'repealed']);
const WARNING_VALUES = new Set([
	'needs_review',
	'not_evaluated',
	'not_reviewed',
	'not_reviewable',
	'unable_to_complete',
	'unreviewed',
	'unknown',
	'unresolved',
	'partial',
	'machine_proposed',
	'draft'
]);
const SUCCESS_VALUES = new Set(['effective', 'reviewed', 'confirmed', 'approved']);
const INFO_VALUES = new Set([
	'applicable',
	'not_applicable',
	'evaluated',
	'published_future_effective',
	'analyst_reviewed',
	'legal_reviewed',
	'no_correction_requested',
	'reviewed_nonbinding'
]);

export function regulatoryLabelKey(value: string | null | undefined): string {
	if (!value) return 'regulatoryValueNotProvided';
	return LABEL_KEYS[value] ?? value;
}

export function regulatoryTone(value: string | null | undefined): RegulatoryTone {
	if (!value) return 'neutral';
	if (DANGER_VALUES.has(value)) return 'danger';
	if (WARNING_VALUES.has(value)) return 'warning';
	if (SUCCESS_VALUES.has(value)) return 'success';
	if (INFO_VALUES.has(value)) return 'info';
	return 'neutral';
}

export function parsePage(value: string | null): number {
	if (!value || !/^\d+$/.test(value)) return 1;
	const parsed = Number(value);
	if (!Number.isSafeInteger(parsed) || parsed < 1) return 1;
	return Math.min(parsed, REGULATORY_MAX_PAGE);
}

export interface RegulatoryListFilters {
	search: string;
	authorityLevel: string;
	coverageStage: string;
	page: number;
}

export function readRegulatoryListFilters(params: URLSearchParams): RegulatoryListFilters {
	const authority = params.get('authority_level') ?? '';
	const stage = params.get('coverage_stage') ?? '';
	return {
		search: (params.get('search') ?? '').trim().slice(0, 200),
		authorityLevel: REGULATORY_AUTHORITY_LEVELS.includes(authority as never) ? authority : '',
		coverageStage: REGULATORY_COVERAGE_STAGES.includes(stage as never) ? stage : '',
		page: parsePage(params.get('page'))
	};
}

export function buildRegulatoryListApiQuery(filters: RegulatoryListFilters): URLSearchParams {
	const query = new URLSearchParams({
		limit: String(REGULATORY_PAGE_SIZE),
		offset: String((filters.page - 1) * REGULATORY_PAGE_SIZE),
		ordering: 'record_id'
	});
	if (filters.search) query.set('search', filters.search);
	if (filters.authorityLevel) query.set('authority_level', filters.authorityLevel);
	if (filters.coverageStage) query.set('coverage_stage', filters.coverageStage);
	return query;
}

export function buildRegulatoryListHref(
	filters: Omit<RegulatoryListFilters, 'page'>,
	page: number
): string {
	const query = new URLSearchParams();
	if (filters.search) query.set('search', filters.search);
	if (filters.authorityLevel) query.set('authority_level', filters.authorityLevel);
	if (filters.coverageStage) query.set('coverage_stage', filters.coverageStage);
	if (page > 1) query.set('page', String(page));
	const suffix = query.toString();
	return suffix ? `/regulatory?${suffix}` : '/regulatory';
}

export function normalizePaginated<T>(payload: unknown): PaginatedResponse<T> {
	if (payload && typeof payload === 'object') {
		const candidate = payload as Partial<PaginatedResponse<T>>;
		if (
			Number.isSafeInteger(candidate.count) &&
			(candidate.count as number) >= 0 &&
			Array.isArray(candidate.results) &&
			(candidate.next === null || typeof candidate.next === 'string') &&
			(candidate.previous === null || typeof candidate.previous === 'string')
		) {
			return {
				count: candidate.count as number,
				next: candidate.next,
				previous: candidate.previous,
				results: candidate.results
			};
		}
	}
	throw new TypeError('Invalid paginated response');
}

export function responseReadState(status: number): Exclude<RegulatoryReadState, 'ok' | 'idle'> {
	if (status === 400) return 'invalid';
	if (status === 401) return 'unauthenticated';
	if (status === 403 || status === 404) return 'restricted';
	return 'unavailable';
}

export function responseListReadState(status: number): Exclude<RegulatoryReadState, 'ok' | 'idle'> {
	if (status === 400) return 'invalid';
	if (status === 401) return 'unauthenticated';
	if (status === 403) return 'restricted';
	return 'unavailable';
}

export function isAwareRfc3339(value: string): boolean {
	const match = value.match(
		/^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?(Z|([+-])(\d{2}):(\d{2}))$/
	);
	if (match === null) return false;
	const year = Number(match[1]);
	const month = Number(match[2]);
	const day = Number(match[3]);
	const hour = Number(match[4]);
	const minute = Number(match[5]);
	const second = Number(match[6]);
	const offsetHour = match[8] === 'Z' ? 0 : Number(match[10]);
	const offsetMinute = match[8] === 'Z' ? 0 : Number(match[11]);
	const leapYear = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
	const daysInMonth = [31, leapYear ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
	if (
		year < 1 ||
		month < 1 ||
		month > 12 ||
		day < 1 ||
		day > daysInMonth[month - 1] ||
		hour > 23 ||
		minute > 59 ||
		second > 59 ||
		offsetHour > 23 ||
		offsetMinute > 59
	) {
		return false;
	}
	return !Number.isNaN(Date.parse(value));
}

export function rfc3339TimestampMicroseconds(value: string): bigint | null {
	if (!isAwareRfc3339(value)) return null;
	const match = value.match(
		/^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d+))?(Z|[+-]\d{2}:\d{2})$/
	);
	if (match === null) return null;
	const wholeSecondMilliseconds = Date.parse(`${match[1]}${match[3]}`);
	if (Number.isNaN(wholeSecondMilliseconds)) return null;
	const fractionalMicroseconds = BigInt((match[2] ?? '').slice(0, 6).padEnd(6, '0') || '0');
	return BigInt(wholeSecondMilliseconds) * 1_000n + fractionalMicroseconds;
}

export function isRegulatoryRecordedAsOfQueryInvalid(
	values: readonly string[],
	nowMilliseconds = Date.now()
): boolean {
	if (values.length === 0) return false;
	if (values.length !== 1) return true;
	const candidate = values[0].trim();
	if (candidate === '') return false;
	return !isAwareRfc3339(candidate) || Date.parse(candidate) > nowMilliseconds;
}

export function compareRfc3339Instants(left: string, right: string): -1 | 0 | 1 | null {
	const leftMicroseconds = rfc3339TimestampMicroseconds(left);
	const rightMicroseconds = rfc3339TimestampMicroseconds(right);
	if (leftMicroseconds === null || rightMicroseconds === null) return null;
	if (leftMicroseconds < rightMicroseconds) return -1;
	if (leftMicroseconds > rightMicroseconds) return 1;
	return 0;
}

export function isUuid(value: string): boolean {
	return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value);
}

export function buildRegulatorySelectionQuery({
	entity,
	recordedAsOf,
	includeEntity = true
}: {
	entity: string;
	recordedAsOf: string;
	includeEntity?: boolean;
}): URLSearchParams {
	const query = new URLSearchParams();
	if (includeEntity && entity) query.set('entity', entity);
	if (recordedAsOf) query.set('recorded_as_of', recordedAsOf);
	return query;
}

export function buildRegulatoryCurrentViewHref({
	entity,
	entitySearch = ''
}: {
	entity: string;
	entitySearch?: string;
}): string {
	const query = new URLSearchParams();
	if (entity) query.set('entity', entity);
	if (entitySearch) query.set('entity_search', entitySearch);
	query.set('mode', 'apply');
	return `?${query}`;
}

export function isFutureEffective(version: RegulatoryDocumentVersion): boolean {
	return version.status === 'published_future_effective';
}

export function safeOfficialSourceHost(value: string): string | null {
	try {
		const parsed = new URL(value);
		if (parsed.protocol !== 'https:') return null;
		const rawAuthority = value.trim().match(/^[a-z][a-z\d+.-]*:\/\/([^/?#]*)/i)?.[1];
		if (rawAuthority?.includes('@') || parsed.username || parsed.password || !parsed.hostname) {
			return null;
		}
		return parsed.hostname;
	} catch {
		return null;
	}
}
