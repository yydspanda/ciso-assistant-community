<script lang="ts">
	import { m } from '$paraglide/messages';
	import { safeTranslate } from '$lib/utils/i18n';
	import type { RegulatoryDocumentDetail } from '$lib/regulatory/types';
	import {
		isFutureEffective,
		regulatoryLabelKey,
		safeOfficialSourceHost
	} from '$lib/regulatory/presentation';
	import RegulatoryBadge from './RegulatoryBadge.svelte';

	let { document }: { document: RegulatoryDocumentDetail } = $props();

	const value = (raw: string | number | null | undefined) =>
		raw === null || raw === undefined || raw === '' ? '—' : String(raw);
	const confidence = (raw: string | number) => {
		const parsed = Number(raw);
		return Number.isFinite(parsed) ? `${Math.round(parsed * 100)}%` : value(raw);
	};
	const officialHost = (url: string) => safeOfficialSourceHost(url);
</script>

<div class="space-y-6">
	{#each document.document_versions as version (version.id)}
		<article class="overflow-hidden rounded-xl border border-surface-200-800 bg-surface-50-950">
			<header class="border-b border-surface-200-800 bg-surface-100-900/70 p-5">
				<div class="flex flex-wrap items-start justify-between gap-3">
					<div>
						<p class="font-mono text-xs text-surface-500">
							{version.record_id} · r{version.revision}
						</p>
						<h2 class="mt-1 text-xl font-semibold">{version.version_label}</h2>
					</div>
					<div class="flex flex-wrap gap-2">
						<RegulatoryBadge value={version.status} />
						<RegulatoryBadge value={version.legal_review_status} />
						<RegulatoryBadge value={version.content_storage_policy} />
					</div>
				</div>
			</header>

			{#if isFutureEffective(version)}
				<div class="border-b border-blue-500/20 bg-blue-500/10 px-5 py-3 text-sm text-blue-900-100">
					<i class="fa-solid fa-calendar-plus mr-2" aria-hidden="true"></i>
					{m.regulatoryFutureEffectiveNotice()}
				</div>
			{/if}
			{#if version.legal_review_status !== 'reviewed'}
				<div
					class="border-b border-amber-500/20 bg-amber-500/10 px-5 py-3 text-sm text-amber-900-100"
				>
					<i class="fa-solid fa-user-check mr-2" aria-hidden="true"></i>
					{m.regulatoryUnreviewedSourceNotice()}
				</div>
			{/if}

			<div class="space-y-6 p-5">
				<dl class="grid gap-4 text-sm sm:grid-cols-2 lg:grid-cols-4">
					<div>
						<dt class="text-xs font-medium uppercase tracking-wide text-surface-500">
							{m.regulatoryDocumentNumber()}
						</dt>
						<dd class="mt-1">{value(version.document_no)}</dd>
					</div>
					<div>
						<dt class="text-xs font-medium uppercase tracking-wide text-surface-500">
							{m.regulatoryStatusAsOf()}
						</dt>
						<dd class="mt-1 font-mono">{value(version.status_as_of)}</dd>
					</div>
					<div>
						<dt class="text-xs font-medium uppercase tracking-wide text-surface-500">
							{m.regulatoryIssuedDate()}
						</dt>
						<dd class="mt-1 font-mono">{value(version.issued_date)}</dd>
					</div>
					<div>
						<dt class="text-xs font-medium uppercase tracking-wide text-surface-500">
							{m.publishedDate()}
						</dt>
						<dd class="mt-1 font-mono">{value(version.published_date)}</dd>
					</div>
					<div>
						<dt class="text-xs font-medium uppercase tracking-wide text-surface-500">
							{m.regulatoryEffectiveDate()}
						</dt>
						<dd class="mt-1 font-mono">{value(version.effective_date)}</dd>
					</div>
					<div>
						<dt class="text-xs font-medium uppercase tracking-wide text-surface-500">
							{m.regulatoryTransitionEnd()}
						</dt>
						<dd class="mt-1 font-mono">{value(version.transition_end)}</dd>
					</div>
					<div>
						<dt class="text-xs font-medium uppercase tracking-wide text-surface-500">
							{m.regulatoryRepealDate()}
						</dt>
						<dd class="mt-1 font-mono">{value(version.repeal_date)}</dd>
					</div>
					<div>
						<dt class="text-xs font-medium uppercase tracking-wide text-surface-500">
							{m.regulatorySupersedesVersions()}
						</dt>
						<dd class="mt-1 break-all font-mono text-xs">
							{version.supersedes_version_ids.join(', ') || '—'}
						</dd>
					</div>
					<div>
						<dt class="text-xs font-medium uppercase tracking-wide text-surface-500">
							{m.regulatoryValidInterval()}
						</dt>
						<dd class="mt-1 font-mono">{value(version.valid_from)} → {value(version.valid_to)}</dd>
					</div>
					<div>
						<dt class="text-xs font-medium uppercase tracking-wide text-surface-500">
							{m.regulatoryRecordedInterval()}
						</dt>
						<dd class="mt-1 break-all font-mono text-xs">
							{value(version.recorded_from)} → {value(version.recorded_to)}
						</dd>
					</div>
					<div>
						<dt class="text-xs font-medium uppercase tracking-wide text-surface-500">
							{m.regulatoryEffectiveBasis()}
						</dt>
						<dd class="mt-1">{safeTranslate(regulatoryLabelKey(version.effective_basis))}</dd>
					</div>
					<div>
						<dt class="text-xs font-medium uppercase tracking-wide text-surface-500">
							{m.regulatorySourceCheckedOn()}
						</dt>
						<dd class="mt-1 font-mono">{value(version.source_checked_on)}</dd>
					</div>
					<div>
						<dt class="text-xs font-medium uppercase tracking-wide text-surface-500">
							{m.regulatoryMetadataConfidence()}
						</dt>
						<dd class="mt-1"><RegulatoryBadge value={version.metadata_confidence} /></dd>
					</div>
				</dl>

				<div class="rounded-lg border border-surface-200-800 p-4">
					<h3 class="text-sm font-semibold">{m.regulatoryOfficialSource()}</h3>
					{#if officialHost(version.source_url)}
						<a
							href={version.source_url}
							target="_blank"
							rel="noopener noreferrer"
							class="mt-2 inline-flex max-w-full items-center gap-2 break-all text-sm text-primary-600 hover:underline"
						>
							<span>{officialHost(version.source_url)} · {version.source_url}</span>
							<span class="sr-only">({m.regulatoryOpensNewWindow()})</span>
							<i class="fa-solid fa-arrow-up-right-from-square shrink-0" aria-hidden="true"></i>
						</a>
					{:else}
						<p class="mt-2 text-sm text-error-700-300">{m.regulatoryUnsafeSourceUrl()}</p>
					{/if}
					<p class="mt-3 break-all font-mono text-xs text-surface-500">
						{m.regulatorySourceHash()}: {value(version.source_hash)}
					</p>
				</div>

				<details class="rounded-lg border border-surface-200-800 p-4">
					<summary class="cursor-pointer text-sm font-semibold">{m.regulatoryProvenance()}</summary>
					<dl class="mt-4 grid gap-3 text-xs sm:grid-cols-2 lg:grid-cols-3">
						<div>
							<dt class="text-surface-500">{m.regulatoryMethod()}</dt>
							<dd>{safeTranslate(regulatoryLabelKey(version.provenance.method))}</dd>
						</div>
						<div>
							<dt class="text-surface-500">{m.regulatoryCreatedAt()}</dt>
							<dd class="break-all font-mono">{value(version.provenance.created_at)}</dd>
						</div>
						<div>
							<dt class="text-surface-500">{m.regulatoryCreatedBy()}</dt>
							<dd class="break-all">{value(version.provenance.created_by)}</dd>
						</div>
						<div>
							<dt class="text-surface-500">{m.regulatoryParserVersion()}</dt>
							<dd>{value(version.provenance.parser_version)}</dd>
						</div>
						<div>
							<dt class="text-surface-500">{m.regulatoryModel()}</dt>
							<dd>{value(version.provenance.model)}</dd>
						</div>
						<div>
							<dt class="text-surface-500">{m.regulatoryRetrievalVersion()}</dt>
							<dd>{value(version.provenance.retrieval_version)}</dd>
						</div>
					</dl>
				</details>

				<section class="space-y-4" aria-labelledby={`provisions-${version.id}`}>
					<div class="flex items-center gap-3">
						<h3 id={`provisions-${version.id}`} class="text-lg font-semibold">
							{m.regulatoryProvisions()}
						</h3>
						<span class="badge preset-tonal-surface text-xs">{version.provisions.length}</span>
					</div>

					{#if version.provisions.length === 0}
						<p
							class="rounded-lg border border-dashed border-surface-300-700 p-6 text-center text-sm text-surface-500"
						>
							{m.regulatoryNoProvisions()}
						</p>
					{/if}

					{#each version.provisions as provision (provision.id)}
						<article class="rounded-lg border border-surface-200-800 bg-surface-100-900/40 p-4">
							<div class="flex flex-wrap items-start justify-between gap-3">
								<div>
									<p class="font-mono text-xs text-surface-500">
										{provision.record_id} · r{provision.revision}
									</p>
									<h4 class="mt-1 font-semibold">
										{provision.article}{provision.heading ? ` · ${provision.heading}` : ''}
									</h4>
								</div>
								<span
									class="badge preset-tonal-surface max-w-full whitespace-normal break-all text-left text-xs"
									>{safeTranslate(regulatoryLabelKey(provision.source_locator.kind))}: {provision
										.source_locator.value}</span
								>
							</div>
							<p class="mt-3 break-all font-mono text-xs text-surface-500">
								{m.regulatoryContentHash()}: {provision.content_hash}
							</p>
							{#if !provision.text}
								<p class="mt-3 text-xs italic text-surface-500">
									{m.regulatoryMetadataOnlyNoText()}
								</p>
							{:else}
								<p class="mt-3 text-xs italic text-amber-700-300">
									{m.regulatorySourceTextWithheld()}
								</p>
							{/if}

							<div class="mt-4 space-y-3">
								{#each provision.obligations as obligation (obligation.id)}
									<section class="rounded-lg border border-primary-500/20 bg-surface-50-950 p-4">
										<div class="flex flex-wrap items-start justify-between gap-3">
											<div>
												<p class="font-mono text-xs text-surface-500">
													{obligation.record_id} · r{obligation.revision}
												</p>
												<h5 class="mt-1 font-semibold">{obligation.title_zh}</h5>
											</div>
											<div class="flex flex-wrap gap-2">
												<RegulatoryBadge value={obligation.review_status} />
												<RegulatoryBadge value={obligation.modality} />
											</div>
										</div>
										<div class="mt-4 grid gap-4 text-sm lg:grid-cols-2">
											<div>
												<p class="text-xs font-medium uppercase tracking-wide text-surface-500">
													{m.regulatorySubject()}
												</p>
												<p class="mt-1 whitespace-pre-wrap">{value(obligation.subject)}</p>
											</div>
											<div>
												<p class="text-xs font-medium uppercase tracking-wide text-surface-500">
													{m.regulatoryAction()}
												</p>
												<p class="mt-1 whitespace-pre-wrap">{value(obligation.action)}</p>
											</div>
											<div>
												<p class="text-xs font-medium uppercase tracking-wide text-surface-500">
													{m.regulatoryObject()}
												</p>
												<p class="mt-1 whitespace-pre-wrap">{value(obligation.object)}</p>
											</div>
											<div>
												<p class="text-xs font-medium uppercase tracking-wide text-surface-500">
													{m.regulatoryDeadline()}
												</p>
												<p class="mt-1">
													{safeTranslate(regulatoryLabelKey(obligation.deadline.kind))} · {value(
														obligation.deadline.value
													)}
												</p>
											</div>
											<div>
												<p class="text-xs font-medium uppercase tracking-wide text-surface-500">
													{m.regulatoryValidInterval()}
												</p>
												<p class="mt-1 font-mono">
													{value(obligation.valid_from)} → {value(obligation.valid_to)}
												</p>
											</div>
											<div>
												<p class="text-xs font-medium uppercase tracking-wide text-surface-500">
													{m.regulatoryConfidence()}
												</p>
												<p class="mt-1">{confidence(obligation.confidence)}</p>
											</div>
										</div>
										{#if obligation.conditions.length || obligation.exceptions.length || obligation.expected_evidence.length || obligation.uncertainties.length}
											<div class="mt-4 grid gap-4 text-xs md:grid-cols-2">
												{#if obligation.conditions.length}<div>
														<p class="font-semibold">{m.regulatoryConditions()}</p>
														<ul class="mt-1 list-disc space-y-1 pl-5">
															{#each obligation.conditions as item}<li>{item}</li>{/each}
														</ul>
													</div>{/if}
												{#if obligation.exceptions.length}<div>
														<p class="font-semibold">{m.regulatoryExceptions()}</p>
														<ul class="mt-1 list-disc space-y-1 pl-5">
															{#each obligation.exceptions as item}<li>{item}</li>{/each}
														</ul>
													</div>{/if}
												{#if obligation.expected_evidence.length}<div>
														<p class="font-semibold">{m.regulatoryExpectedEvidence()}</p>
														<ul class="mt-1 list-disc space-y-1 pl-5">
															{#each obligation.expected_evidence as item}<li>{item}</li>{/each}
														</ul>
													</div>{/if}
												{#if obligation.uncertainties.length}<div>
														<p class="font-semibold text-amber-700-300">
															{m.regulatoryUncertainties()}
														</p>
														<ul class="mt-1 list-disc space-y-1 pl-5">
															{#each obligation.uncertainties as item}<li>{item}</li>{/each}
														</ul>
													</div>{/if}
											</div>
										{/if}
										{#if obligation.penalty_or_consequence}<div class="mt-4 text-sm">
												<p class="text-xs font-medium uppercase tracking-wide text-surface-500">
													{m.regulatoryConsequence()}
												</p>
												<p class="mt-1 whitespace-pre-wrap">{obligation.penalty_or_consequence}</p>
											</div>{/if}
										<p class="mt-4 border-t border-surface-200-800 pt-3 text-xs text-surface-500">
											<i class="fa-solid fa-scale-balanced mr-2" aria-hidden="true"
											></i>{m.regulatoryObligationNotLegalConclusion()}
										</p>
									</section>
								{/each}
							</div>
						</article>
					{/each}
				</section>
			</div>
		</article>
	{/each}
</div>
