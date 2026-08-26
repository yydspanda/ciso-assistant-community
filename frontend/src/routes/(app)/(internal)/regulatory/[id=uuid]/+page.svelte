<script lang="ts">
	import { m } from '$paraglide/messages';
	import RegulatoryApplicabilityPanel from '$lib/components/Regulatory/RegulatoryApplicabilityPanel.svelte';
	import RegulatoryBadge from '$lib/components/Regulatory/RegulatoryBadge.svelte';
	import RegulatoryBoundaryNotice from '$lib/components/Regulatory/RegulatoryBoundaryNotice.svelte';
	import RegulatoryChain from '$lib/components/Regulatory/RegulatoryChain.svelte';
	import { isRegulatoryRecordedAsOfQueryInvalid } from '$lib/regulatory/presentation';
	import { page } from '$app/state';
	import type { PageData } from './$types';

	let { data }: { data: PageData } = $props();
	let retryHref = $derived(`${page.url.pathname}${page.url.search}`);
	let entitySearchDisabled = $derived(
		data.entityState === 'restricted' || data.entityState === 'unauthenticated'
	);
	let entitySelectDisabled = $derived(data.entityState !== 'ok' || data.entities.length === 0);
	let selectedEntityIsBound = $derived(
		data.applicability.state === 'ok' || data.review.state === 'ok'
	);
	let recordedAsOfInvalid = $derived.by(() => {
		const recordedValues = page.url.searchParams.getAll('recorded_as_of');
		if (isRegulatoryRecordedAsOfQueryInvalid(recordedValues)) return true;
		if (recordedValues.length === 0 || recordedValues[0].trim() === '') return false;

		// A detail 400 can only be caused by its recorded-time query. Repeated
		// entity parameters are rejected before that request and are reported by
		// the general selection error instead.
		return data.documentState === 'invalid' && page.url.searchParams.getAll('entity').length <= 1;
	});
	let recordedAsOfDescription = $derived(
		recordedAsOfInvalid
			? 'regulatory-recorded-help regulatory-recorded-error'
			: 'regulatory-recorded-help'
	);
</script>

<div class="mx-auto max-w-7xl space-y-6">
	<a
		href="/regulatory"
		class="inline-flex items-center gap-2 text-sm text-primary-700-300 hover:underline"
	>
		<i class="fa-solid fa-arrow-left" aria-hidden="true"></i>{m.regulatoryBackToRegister()}
	</a>

	{#if data.document}
		<header class="rounded-xl border border-surface-200-800 bg-surface-50-950 p-6">
			<div class="flex flex-wrap items-start justify-between gap-4">
				<div class="max-w-4xl">
					<p class="font-mono text-xs text-surface-500">{data.document.record_id}</p>
					<h1 class="mt-2 text-3xl font-bold tracking-tight">{data.document.title_zh}</h1>
					{#if data.document.title_en}<p class="mt-2 text-sm text-surface-600-400">
							{data.document.title_en}
						</p>{/if}
				</div>
				<div class="flex flex-wrap gap-2">
					<RegulatoryBadge value={data.document.authority_level} />
					<RegulatoryBadge value={data.document.coverage_stage} />
					<RegulatoryBadge value={data.document.contract_status} />
				</div>
			</div>

			<dl
				class="mt-6 grid gap-4 border-t border-surface-200-800 pt-5 text-sm sm:grid-cols-2 lg:grid-cols-4"
			>
				<div>
					<dt class="text-xs uppercase tracking-wide text-surface-500">{m.regulatoryIssuer()}</dt>
					<dd class="mt-1">{data.document.issuer}</dd>
				</div>
				<div>
					<dt class="text-xs uppercase tracking-wide text-surface-500">
						{m.regulatoryTerritories()}
					</dt>
					<dd class="mt-1">{data.document.territories.join(' · ') || '—'}</dd>
				</div>
				<div>
					<dt class="text-xs uppercase tracking-wide text-surface-500">
						{m.regulatoryEntityScopes()}
					</dt>
					<dd class="mt-1">{data.document.regulated_entity_scopes.join(' · ') || '—'}</dd>
				</div>
				<div>
					<dt class="text-xs uppercase tracking-wide text-surface-500">{m.regulatoryDomains()}</dt>
					<dd class="mt-1">{data.document.domains.join(' · ') || '—'}</dd>
				</div>
				<div>
					<dt class="text-xs uppercase tracking-wide text-surface-500">
						{m.regulatoryCoveragePriority()}
					</dt>
					<dd class="mt-1">{data.document.coverage_priority || '—'}</dd>
				</div>
				<div>
					<dt class="text-xs uppercase tracking-wide text-surface-500">
						{m.regulatoryRequestedRecordedAt()}
					</dt>
					<dd class="mt-1 break-all font-mono text-xs">
						{data.document.recorded_as_of || m.regulatoryCurrentRecordedState()}
					</dd>
				</div>
			</dl>
			{#if data.document.selection_rationale}<p class="mt-5 text-sm leading-6 text-surface-700-300">
					<span class="font-semibold">{m.regulatorySelectionRationale()}:</span>
					{data.document.selection_rationale}
				</p>{/if}
		</header>
	{:else}
		<header>
			<h1 class="text-3xl font-bold tracking-tight">
				{data.documentState === 'invalid'
					? m.regulatoryInvalidSelectionTitle()
					: data.documentState === 'unauthenticated'
						? m.regulatorySessionExpiredTitle()
						: data.documentState === 'restricted'
							? m.regulatoryDocumentUnavailableTitle()
							: m.regulatoryServiceUnavailableTitle()}
			</h1>
		</header>
	{/if}

	<RegulatoryBoundaryNotice compact />

	<section
		class="rounded-xl border border-surface-200-800 bg-surface-50-950 p-5"
		aria-labelledby="regulatory-selection-title"
	>
		<div class="flex flex-wrap items-start justify-between gap-3">
			<div>
				<h2 id="regulatory-selection-title" class="font-semibold">
					{m.regulatorySelectionContext()}
				</h2>
				<p class="mt-1 text-xs text-surface-500">{m.regulatorySelectionContextHelp()}</p>
			</div>
			{#if data.recordedAsOf}<RegulatoryBadge
					value="regulatoryHistoricalView"
				/>{:else}<RegulatoryBadge value="regulatoryCurrentView" />{/if}
		</div>

		<div class="mt-4 grid gap-4 lg:grid-cols-2">
			<form method="GET" class="rounded-lg border border-surface-200-800 p-4">
				<label for="regulatory-entity-search" class="label">{m.regulatoryEntitySearch()}</label>
				<div class="mt-1 flex gap-2">
					<input
						id="regulatory-entity-search"
						name="entity_search"
						type="search"
						value={data.entitySearch}
						class="input min-w-0 flex-1"
						placeholder={m.regulatoryEntitySearchPlaceholder()}
						disabled={entitySearchDisabled}
					/>
					<input type="hidden" name="recorded_as_of" value={data.recordedAsOf} />
					<input type="hidden" name="mode" value="search" />
					<button
						type="submit"
						class="btn variant-soft disabled:cursor-not-allowed disabled:opacity-50"
						disabled={entitySearchDisabled}>{m.search()}</button
					>
				</div>
			</form>

			<form
				method="GET"
				class="grid gap-4 rounded-lg border border-surface-200-800 p-4 xl:grid-cols-[1fr_1fr_auto] xl:items-end"
			>
				<input type="hidden" name="entity_search" value={data.entitySearch} />
				<input type="hidden" name="mode" value="apply" />
				{#if entitySelectDisabled && selectedEntityIsBound && data.selectedEntity}
					<input type="hidden" name="entity" value={data.selectedEntity} />
				{/if}
				<div>
					<label for="regulatory-entity" class="label">{m.regulatoryLegalEntity()}</label>
					<select
						id="regulatory-entity"
						name="entity"
						class="select mt-1 w-full"
						disabled={entitySelectDisabled}
					>
						<option value="">{m.regulatoryNoEntitySelected()}</option>
						{#each data.entities as entity (entity.id)}
							<option value={entity.id} selected={data.selectedEntity === entity.id}>
								{entity.name}{entity.ref_id ? ` · ${entity.ref_id}` : ''}
							</option>
						{/each}
					</select>
					{#if data.entityState === 'restricted'}
						<p class="mt-1 text-xs text-surface-500">{m.regulatoryEntityListRestricted()}</p>
					{:else if data.entityState === 'unauthenticated'}
						<p class="mt-1 text-xs text-error-600">{m.regulatorySessionExpiredBody()}</p>
					{:else if data.entityState === 'unavailable'}
						<p class="mt-1 text-xs text-error-600">{m.regulatoryEntityListUnavailable()}</p>
					{:else if data.entityState === 'idle'}
						<p class="mt-1 text-xs text-surface-500">{m.regulatoryEntityDeferred()}</p>
					{:else if data.entities.length === 0}
						<p class="mt-1 text-xs text-surface-500">{m.regulatoryNoVisibleEntities()}</p>
					{:else}
						<p class="mt-1 text-xs text-surface-500">{m.regulatoryEntitySelectionHelp()}</p>
					{/if}
				</div>
				<div>
					<label for="regulatory-recorded-as-of" class="label">{m.regulatoryRecordedAsOf()}</label>
					<input
						id="regulatory-recorded-as-of"
						name="recorded_as_of"
						type="text"
						value={data.recordedAsOf}
						class="input mt-1 w-full font-mono text-sm"
						placeholder="2026-08-26T09:30:00+08:00"
						aria-invalid={recordedAsOfInvalid}
						aria-describedby={recordedAsOfDescription}
						aria-errormessage={recordedAsOfInvalid ? 'regulatory-recorded-error' : undefined}
					/>
					<p id="regulatory-recorded-help" class="mt-1 text-xs text-surface-500">
						{m.regulatoryRecordedAsOfHelp()}
					</p>
					{#if recordedAsOfInvalid}
						<p id="regulatory-recorded-error" class="mt-1 text-xs text-error-600" role="alert">
							{m.regulatoryRecordedAsOfInvalid()}
						</p>
					{/if}
				</div>
				<div class="flex flex-wrap gap-2">
					<button type="submit" class="btn variant-filled-primary"
						>{m.regulatoryApplySelection()}</button
					>
					<a href={data.currentViewHref} class="btn variant-soft">{m.regulatoryCurrentView()}</a>
				</div>
			</form>
		</div>
	</section>

	{#if data.documentState === 'invalid'}
		<section class="rounded-xl border border-error-500/30 bg-error-500/10 p-6" role="alert">
			<h2 class="text-xl font-semibold">{m.regulatoryInvalidSelectionTitle()}</h2>
			<p class="mt-2 text-sm">{m.regulatoryInvalidSelectionBody()}</p>
		</section>
	{:else if data.documentState === 'unauthenticated'}
		<section class="rounded-xl border border-error-500/30 bg-error-500/10 p-6" role="alert">
			<h2 class="text-xl font-semibold">{m.regulatorySessionExpiredTitle()}</h2>
			<p class="mt-2 text-sm">{m.regulatorySessionExpiredBody()}</p>
			<a href="/login" class="btn variant-soft mt-4">{m.regulatorySignInAgain()}</a>
		</section>
	{:else if data.documentState === 'restricted'}
		<section
			class="rounded-xl border border-surface-300-700 bg-surface-50-950 p-8 text-center"
			role="status"
		>
			<i class="fa-solid fa-lock mb-3 text-3xl text-surface-500" aria-hidden="true"></i>
			<h2 class="text-xl font-semibold">{m.regulatoryDocumentUnavailableTitle()}</h2>
			<p class="mt-2 text-sm text-surface-600-400">{m.regulatoryDocumentUnavailableBody()}</p>
		</section>
	{:else if data.documentState === 'unavailable' || !data.document}
		<section class="rounded-xl border border-error-500/30 bg-error-500/10 p-6" role="alert">
			<h2 class="text-xl font-semibold">{m.regulatoryServiceUnavailableTitle()}</h2>
			<p class="mt-2 text-sm">{m.regulatoryServiceUnavailableBody()}</p>
			<a href={retryHref} class="btn variant-soft mt-4">{m.regulatoryRetry()}</a>
		</section>
	{:else}
		<RegulatoryChain document={data.document} />

		<RegulatoryApplicabilityPanel
			applicability={data.applicability}
			review={data.review}
			{retryHref}
		/>
	{/if}
</div>
