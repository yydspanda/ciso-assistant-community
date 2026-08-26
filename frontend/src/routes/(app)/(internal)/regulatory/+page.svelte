<script lang="ts">
	import { m } from '$paraglide/messages';
	import { safeTranslate } from '$lib/utils/i18n';
	import RegulatoryBadge from '$lib/components/Regulatory/RegulatoryBadge.svelte';
	import RegulatoryBoundaryNotice from '$lib/components/Regulatory/RegulatoryBoundaryNotice.svelte';
	import {
		buildRegulatoryListHref,
		REGULATORY_AUTHORITY_LEVELS,
		REGULATORY_COVERAGE_STAGES,
		REGULATORY_MAX_PAGE,
		REGULATORY_PAGE_SIZE,
		regulatoryLabelKey
	} from '$lib/regulatory/presentation';
	import type { PageData } from './$types';

	let { data }: { data: PageData } = $props();

	let pageCount = $derived(
		Math.min(REGULATORY_MAX_PAGE, Math.max(1, Math.ceil(data.count / REGULATORY_PAGE_SIZE)))
	);
	let hasFilters = $derived(
		Boolean(data.filters.search || data.filters.authorityLevel || data.filters.coverageStage)
	);
	const pageHref = (page: number) =>
		buildRegulatoryListHref(
			{
				search: data.filters.search,
				authorityLevel: data.filters.authorityLevel,
				coverageStage: data.filters.coverageStage
			},
			page
		);
</script>

<div class="mx-auto max-w-7xl space-y-6">
	<header class="flex flex-wrap items-start justify-between gap-4">
		<div>
			<p class="text-xs font-semibold uppercase tracking-[0.18em] text-primary-600">
				{m.regulatoryChinaFinancialGrc()}
			</p>
			<h1 class="mt-1 text-3xl font-bold tracking-tight">{m.regulatoryRegister()}</h1>
			<p class="mt-2 max-w-3xl text-sm leading-6 text-surface-600-400">
				{m.regulatoryRegisterDescription()}
			</p>
		</div>
		{#if data.state === 'ok'}
			<div class="rounded-lg border border-surface-200-800 bg-surface-50-950 px-4 py-3 text-right">
				<p class="text-xs text-surface-500">{m.regulatoryVisibleRecords()}</p>
				<p class="text-2xl font-semibold tabular-nums">{data.count}</p>
			</div>
		{/if}
	</header>

	<RegulatoryBoundaryNotice />

	<form
		method="GET"
		class="grid gap-4 rounded-xl border border-surface-200-800 bg-surface-50-950 p-5 md:grid-cols-2 xl:grid-cols-[2fr_1fr_1fr_auto] xl:items-end"
		aria-label={m.regulatoryFilters()}
	>
		<div>
			<label for="regulatory-search" class="label">{m.regulatorySearchLabel()}</label>
			<input
				id="regulatory-search"
				name="search"
				type="search"
				value={data.filters.search}
				class="input mt-1 w-full"
				placeholder={m.regulatorySearchPlaceholder()}
			/>
		</div>
		<div>
			<label for="regulatory-authority" class="label">{m.regulatoryAuthorityLevel()}</label>
			<select id="regulatory-authority" name="authority_level" class="select mt-1 w-full">
				<option value="">{m.regulatoryAllAuthorityLevels()}</option>
				{#each REGULATORY_AUTHORITY_LEVELS as authority}
					<option value={authority} selected={data.filters.authorityLevel === authority}>
						{safeTranslate(regulatoryLabelKey(authority))}
					</option>
				{/each}
			</select>
		</div>
		<div>
			<label for="regulatory-stage" class="label">{m.regulatoryCoverageStage()}</label>
			<select id="regulatory-stage" name="coverage_stage" class="select mt-1 w-full">
				<option value="">{m.regulatoryAllCoverageStages()}</option>
				{#each REGULATORY_COVERAGE_STAGES as stage}
					<option value={stage} selected={data.filters.coverageStage === stage}>
						{safeTranslate(regulatoryLabelKey(stage))}
					</option>
				{/each}
			</select>
		</div>
		<div class="flex gap-2">
			<button type="submit" class="btn variant-filled-primary">
				<i class="fa-solid fa-filter mr-2" aria-hidden="true"></i>{m.regulatoryApplyFilters()}
			</button>
			{#if hasFilters}
				<a href="/regulatory" class="btn variant-soft">{m.clearFilters()}</a>
			{/if}
		</div>
	</form>

	{#if data.state === 'unauthenticated'}
		<section class="rounded-xl border border-error-500/30 bg-error-500/10 p-6" role="alert">
			<h2 class="font-semibold">{m.regulatorySessionExpiredTitle()}</h2>
			<p class="mt-2 text-sm">{m.regulatorySessionExpiredBody()}</p>
			<a href="/login" class="btn variant-soft mt-4">{m.regulatorySignInAgain()}</a>
		</section>
	{:else if data.state === 'restricted'}
		<section
			class="rounded-xl border border-surface-300-700 bg-surface-50-950 p-8 text-center"
			role="status"
		>
			<i class="fa-solid fa-lock mb-3 text-3xl text-surface-500" aria-hidden="true"></i>
			<h2 class="font-semibold">{m.regulatoryRegisterRestrictedTitle()}</h2>
			<p class="mt-2 text-sm text-surface-600-400">{m.regulatoryRegisterRestrictedBody()}</p>
		</section>
	{:else if data.state === 'invalid'}
		<section class="rounded-xl border border-error-500/30 bg-error-500/10 p-6" role="alert">
			<h2 class="font-semibold">{m.regulatoryInvalidSelectionTitle()}</h2>
			<p class="mt-2 text-sm">{m.regulatoryInvalidSelectionBody()}</p>
		</section>
	{:else if data.state === 'unavailable'}
		<section class="rounded-xl border border-error-500/30 bg-error-500/10 p-6" role="alert">
			<h2 class="font-semibold">{m.regulatoryServiceUnavailableTitle()}</h2>
			<p class="mt-2 text-sm">{m.regulatoryServiceUnavailableBody()}</p>
			<a href={pageHref(data.filters.page)} class="btn variant-soft mt-4">{m.regulatoryRetry()}</a>
		</section>
	{:else if data.documents.length === 0}
		<section class="rounded-xl border border-dashed border-surface-300-700 p-12 text-center">
			<i class="fa-solid fa-folder-open mb-3 text-3xl text-surface-400" aria-hidden="true"></i>
			<h2 class="font-semibold">
				{hasFilters ? m.regulatoryNoMatchingRecords() : m.regulatoryNoVisibleRecords()}
			</h2>
			<p class="mt-2 text-sm text-surface-600-400">
				{hasFilters ? m.regulatoryNoMatchingRecordsHelp() : m.regulatoryNoVisibleRecordsHelp()}
			</p>
			{#if hasFilters}<a href="/regulatory" class="btn variant-soft mt-4">{m.clearFilters()}</a
				>{/if}
		</section>
	{:else}
		<section
			class="overflow-hidden rounded-xl border border-surface-200-800 bg-surface-50-950"
			aria-labelledby="regulatory-results-title"
		>
			<div class="border-b border-surface-200-800 px-5 py-4">
				<h2 id="regulatory-results-title" class="font-semibold">{m.regulatorySearchResults()}</h2>
			</div>
			<!-- svelte-ignore a11y_no_noninteractive_tabindex (The overflowing data-table region must be keyboard-scrollable.) -->
			<div
				class="overflow-x-auto focus-visible:outline-2 focus-visible:outline-offset-[-2px] focus-visible:outline-primary-500"
				role="region"
				tabindex="0"
				aria-labelledby="regulatory-results-title"
			>
				<table class="w-full min-w-[900px] text-left text-sm">
					<thead class="bg-surface-100-900 text-xs uppercase tracking-wide text-surface-500">
						<tr>
							<th scope="col" class="px-5 py-3">{m.regulatoryDocument()}</th>
							<th scope="col" class="px-5 py-3">{m.regulatoryIssuer()}</th>
							<th scope="col" class="px-5 py-3">{m.regulatoryAuthorityLevel()}</th>
							<th scope="col" class="px-5 py-3">{m.regulatoryCoverageStage()}</th>
							<th scope="col" class="px-5 py-3">{m.regulatoryScope()}</th>
						</tr>
					</thead>
					<tbody class="divide-y divide-surface-200-800">
						{#each data.documents as document (document.id)}
							<tr class="align-top transition-colors hover:bg-surface-100-900/60">
								<td class="px-5 py-4">
									<a
										href={`/regulatory/${document.id}`}
										class="font-semibold text-primary-700-300 hover:underline"
									>
										{document.title_zh}
									</a>
									{#if document.title_en}<p class="mt-1 text-xs text-surface-500">
											{document.title_en}
										</p>{/if}
									<p class="mt-2 break-all font-mono text-xs text-surface-500">
										{document.record_id}
									</p>
								</td>
								<td class="px-5 py-4">{document.issuer}</td>
								<td class="px-5 py-4"><RegulatoryBadge value={document.authority_level} /></td>
								<td class="px-5 py-4"><RegulatoryBadge value={document.coverage_stage} /></td>
								<td class="px-5 py-4 text-xs text-surface-600-400">
									<p>{document.territories.join(' · ') || '—'}</p>
									<p class="mt-1">{document.regulated_entity_scopes.join(' · ') || '—'}</p>
								</td>
							</tr>
						{/each}
					</tbody>
				</table>
			</div>
		</section>

		{#if pageCount > 1}
			<nav
				class="flex flex-col items-stretch gap-4 sm:flex-row sm:items-center sm:justify-between"
				aria-label={m.regulatoryPagination()}
			>
				<span class="text-sm text-surface-600-400">
					{m.regulatoryPageOf({ page: data.filters.page, pages: pageCount })}
				</span>
				<div class="flex flex-wrap gap-2">
					{#if data.filters.page > 1}<a
							class="btn variant-soft"
							href={pageHref(data.filters.page - 1)}>{m.previous()}</a
						>{/if}
					{#if data.filters.page < pageCount}<a
							class="btn variant-soft"
							href={pageHref(data.filters.page + 1)}>{m.next()}</a
						>{/if}
				</div>
			</nav>
		{/if}
	{/if}
</div>
