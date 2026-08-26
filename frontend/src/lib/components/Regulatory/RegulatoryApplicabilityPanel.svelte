<script lang="ts">
	import { m } from '$paraglide/messages';
	import { safeTranslate } from '$lib/utils/i18n';
	import type {
		RegulatoryApplicability,
		RegulatoryApplicabilityReview,
		RegulatoryInstitutionTypeFact,
		RegulatoryReadPanel
	} from '$lib/regulatory/types';
	import { regulatoryLabelKey } from '$lib/regulatory/presentation';
	import RegulatoryBadge from './RegulatoryBadge.svelte';

	let {
		applicability,
		review,
		retryHref = ''
	}: {
		applicability: RegulatoryReadPanel<RegulatoryApplicability>;
		review: RegulatoryReadPanel<RegulatoryApplicabilityReview>;
		retryHref?: string;
	} = $props();

	const value = (raw: unknown) =>
		raw === null || raw === undefined || raw === '' ? '—' : String(raw);
	const factValue = (fact: RegulatoryInstitutionTypeFact) =>
		fact.known === false ? safeTranslate(regulatoryLabelKey('unknown')) : value(fact.value);
</script>

<section class="space-y-5" aria-labelledby="regulatory-applicability-title">
	<div>
		<h2 id="regulatory-applicability-title" class="text-xl font-semibold">
			{m.regulatoryApplicabilityAndReview()}
		</h2>
		<p class="mt-1 text-sm text-surface-600-400">{m.regulatoryApplicabilityScopeHelp()}</p>
	</div>

	{#if applicability.state === 'idle'}
		<div
			class="rounded-xl border border-dashed border-surface-300-700 p-8 text-center text-sm text-surface-600-400"
		>
			<i class="fa-solid fa-building-circle-check mb-3 block text-2xl" aria-hidden="true"></i>
			{m.regulatorySelectEntityPrompt()}
		</div>
	{:else if applicability.state === 'invalid'}
		<div class="rounded-xl border border-error-500/30 bg-error-500/10 p-4 text-sm" role="alert">
			<h3 class="font-semibold text-error-800-200">{m.regulatoryInvalidSelectionTitle()}</h3>
			<p class="mt-1 text-surface-700-300">{m.regulatoryInvalidSelectionBody()}</p>
		</div>
	{:else if applicability.state === 'unauthenticated'}
		<div class="rounded-xl border border-error-500/30 bg-error-500/10 p-4 text-sm" role="alert">
			<h3 class="font-semibold text-error-800-200">{m.regulatorySessionExpiredTitle()}</h3>
			<p class="mt-1 text-surface-700-300">{m.regulatorySessionExpiredBody()}</p>
		</div>
	{:else if applicability.state === 'restricted'}
		<div
			class="rounded-xl border border-surface-300-700 bg-surface-100-900 p-4 text-sm"
			role="status"
		>
			<h3 class="font-semibold">{m.regulatoryScopeUnavailableTitle()}</h3>
			<p class="mt-1 text-surface-600-400">{m.regulatoryScopeUnavailableBody()}</p>
		</div>
	{:else if applicability.state === 'unavailable'}
		<div class="rounded-xl border border-error-500/30 bg-error-500/10 p-4 text-sm" role="alert">
			<h3 class="font-semibold text-error-800-200">{m.regulatoryServiceUnavailableTitle()}</h3>
			<p class="mt-1 text-surface-700-300">{m.regulatoryServiceUnavailableBody()}</p>
			<a href={retryHref} class="btn variant-soft mt-3">{m.regulatoryRetry()}</a>
		</div>
	{:else if applicability.data}
		<div class="rounded-xl border border-primary-500/25 bg-surface-50-950 p-5">
			<div class="flex flex-wrap items-start justify-between gap-4">
				<div>
					<p class="text-xs font-medium uppercase tracking-wide text-surface-500">
						{m.regulatoryComputedResult()}
					</p>
					<div class="mt-2 flex flex-wrap items-center gap-2">
						<RegulatoryBadge value={applicability.data.non_binding_result} />
						<RegulatoryBadge value={applicability.data.evaluation_status} />
						<RegulatoryBadge value={applicability.data.contract_status} />
					</div>
				</div>
				<div
					class="rounded-lg border border-amber-500/30 bg-amber-500/10 px-3 py-2 text-xs text-amber-900-100"
				>
					<i class="fa-solid fa-scale-balanced mr-1" aria-hidden="true"></i>
					{m.regulatoryNonBindingResultLabel()}
				</div>
			</div>

			<p class="mt-4 text-sm leading-6 text-surface-700-300">
				{#if applicability.data.non_binding_result === 'not_applicable'}
					{m.regulatoryNotApplicableCaveat()}
				{:else if applicability.data.non_binding_result === 'applicable'}
					{m.regulatoryApplicableCaveat()}
				{:else}
					{m.regulatoryNeedsReviewCaveat()}
				{/if}
			</p>

			<dl class="mt-5 grid gap-4 text-sm sm:grid-cols-2 lg:grid-cols-4">
				<div>
					<dt class="text-xs text-surface-500">{m.regulatoryEntityId()}</dt>
					<dd class="mt-1 break-all font-mono text-xs">{applicability.data.scope.id}</dd>
				</div>
				<div>
					<dt class="text-xs text-surface-500">{m.regulatoryObligationId()}</dt>
					<dd class="mt-1 break-all font-mono text-xs">
						{applicability.data.obligation_id} · r{applicability.data.obligation_revision}
					</dd>
				</div>
				<div>
					<dt class="text-xs text-surface-500">{m.regulatoryRequestedRecordedAt()}</dt>
					<dd class="mt-1 break-all font-mono text-xs">
						{value(applicability.data.recorded_as_of)}
					</dd>
				</div>
				<div>
					<dt class="text-xs text-surface-500">{m.regulatorySelectedRecordedAt()}</dt>
					<dd class="mt-1 break-all font-mono text-xs">
						{applicability.data.selected_recorded_at}
					</dd>
				</div>
				<div>
					<dt class="text-xs text-surface-500">{m.regulatoryReasonCode()}</dt>
					<dd class="mt-1 break-all font-mono text-xs">{applicability.data.reason_code}</dd>
				</div>
			</dl>

			{#if applicability.data.decision}
				<div class="mt-5 space-y-4 border-t border-surface-200-800 pt-5">
					<div>
						<h3 class="text-sm font-semibold">{m.regulatoryDecisionRationale()}</h3>
						<p class="mt-1 text-sm leading-6">
							{safeTranslate(regulatoryLabelKey(applicability.data.decision.rationale_code))}
						</p>
						<p class="mt-1 font-mono text-xs text-surface-500">
							{applicability.data.decision.rationale_code}
						</p>
					</div>
					<div class="rounded-lg border border-amber-500/30 bg-amber-500/10 p-3 text-sm">
						<h3 class="font-semibold">{m.regulatoryValidInterval()}</h3>
						<p class="mt-1 break-all font-mono text-xs">
							{value(applicability.data.decision.valid_from)} → {value(
								applicability.data.decision.valid_to
							)}
						</p>
						<p class="mt-2 text-xs leading-5">{m.regulatoryDecisionValidTimeCaveat()}</p>
					</div>
					<div class="rounded-lg border border-surface-200-800 p-3 text-sm">
						<h3 class="font-semibold">{m.regulatoryRuleSummary()}</h3>
						<p class="mt-1 break-all font-mono text-xs text-surface-500">
							{applicability.data.decision.rule.id} · v{applicability.data.decision.rule.version}
						</p>
						<ul class="mt-3 list-disc space-y-1 break-all pl-5 font-mono text-xs">
							{#each applicability.data.decision.rule.all as condition}
								<li>{condition.fact} {condition.operator} {condition.value}</li>
							{/each}
						</ul>
						<p class="mt-3 text-xs text-surface-500">
							{m.regulatoryUnknownFactResult()}:
							{safeTranslate(regulatoryLabelKey(applicability.data.decision.rule.unknown_result))}
						</p>
					</div>
					{#if applicability.data.decision.missing_fact_keys.length}
						<div class="rounded-lg border border-amber-500/30 bg-amber-500/10 p-3 text-sm">
							<h3 class="font-semibold">{m.regulatoryMissingFacts()}</h3>
							<ul class="mt-2 list-disc space-y-1 break-all pl-5 font-mono text-xs">
								{#each applicability.data.decision.missing_fact_keys as factKey}<li>
										{factKey}
									</li>{/each}
							</ul>
						</div>
					{/if}
					<div>
						<h3 class="text-sm font-semibold">{m.regulatoryFactSnapshot()}</h3>
						<div class="mt-2 grid gap-3 md:grid-cols-2">
							{#each applicability.data.decision.facts as fact, index (`${value(fact.fact)}-${index}`)}
								<div class="rounded-lg border border-surface-200-800 p-3 text-xs">
									<p class="font-mono font-semibold">{value(fact.fact)}</p>
									<p class="mt-2">
										<span class="text-surface-500">{m.regulatoryFactValue()}:</span>
										{factValue(fact)}
									</p>
									<p class="mt-1">
										<span class="text-surface-500">{m.regulatoryObservedAt()}:</span>
										<span class="font-mono">{value(fact.observed_at)}</span>
									</p>
									{#if Array.isArray(fact.source_refs) && fact.source_refs.length}
										<p class="mt-2 text-surface-500">{m.regulatoryEvidenceReferences()}</p>
										<ul class="mt-1 list-disc space-y-1 break-all pl-4">
											{#each fact.source_refs as reference}<li>{value(reference)}</li>{/each}
										</ul>
									{/if}
								</div>
							{/each}
						</div>
					</div>
					<details class="rounded-lg border border-surface-200-800 p-3 text-xs">
						<summary class="cursor-pointer font-semibold">{m.regulatoryDecisionIntegrity()}</summary
						>
						<dl class="mt-3 grid gap-3 sm:grid-cols-2">
							<div>
								<dt class="text-surface-500">{m.regulatoryDecisionId()}</dt>
								<dd class="break-all font-mono">
									{applicability.data.decision.record_id} · r{applicability.data.decision.revision}
								</dd>
							</div>
							<div>
								<dt class="text-surface-500">{m.regulatoryEvaluatorProfile()}</dt>
								<dd class="break-all font-mono">{applicability.data.decision.evaluator_profile}</dd>
							</div>
							<div>
								<dt class="text-surface-500">{m.regulatoryRuleHash()}</dt>
								<dd class="break-all font-mono">
									{applicability.data.decision.rule_snapshot_sha256}
								</dd>
							</div>
							<div>
								<dt class="text-surface-500">{m.regulatoryFactHash()}</dt>
								<dd class="break-all font-mono">
									{applicability.data.decision.fact_snapshot_sha256}
								</dd>
							</div>
							<div class="sm:col-span-2">
								<dt class="text-surface-500">{m.regulatorySemanticHash()}</dt>
								<dd class="break-all font-mono">
									{applicability.data.decision.semantic_payload_sha256}
								</dd>
							</div>
						</dl>
					</details>
				</div>
			{:else}
				<p class="mt-5 rounded-lg border border-amber-500/30 bg-amber-500/10 p-3 text-sm">
					{m.regulatoryNoDecisionForRevision()}
				</p>
			{/if}
		</div>

		<section
			class="rounded-xl border border-surface-200-800 bg-surface-50-950 p-5"
			aria-labelledby="regulatory-review-title"
		>
			<h3 id="regulatory-review-title" class="font-semibold">{m.regulatoryHumanReviewState()}</h3>
			<p class="mt-1 text-xs text-surface-500">{m.regulatoryReviewSeparateHelp()}</p>

			{#if review.state === 'unauthenticated'}
				<p class="mt-4 rounded-lg bg-error-500/10 p-3 text-sm" role="alert">
					{m.regulatorySessionExpiredBody()}
				</p>
			{:else if review.state === 'restricted'}
				<p class="mt-4 rounded-lg bg-surface-100-900 p-3 text-sm" role="status">
					{m.regulatoryReviewRestricted()}
				</p>
			{:else if review.state === 'invalid'}
				<p class="mt-4 rounded-lg bg-error-500/10 p-3 text-sm" role="alert">
					{m.regulatoryInvalidSelectionBody()}
				</p>
			{:else if review.state === 'unavailable'}
				<div class="mt-4 rounded-lg bg-error-500/10 p-3 text-sm" role="alert">
					<p>{m.regulatoryReviewUnavailable()}</p>
					<a href={retryHref} class="btn variant-soft mt-3">{m.regulatoryRetry()}</a>
				</div>
			{:else if review.data}
				<div class="mt-4 flex flex-wrap gap-2">
					<RegulatoryBadge value={review.data.review_state} />
					<RegulatoryBadge value={review.data.workflow_attention} />
					<RegulatoryBadge value={review.data.computed_non_binding_result} />
				</div>
				{#if review.data.latest_disposition}
					<div class="mt-4 rounded-lg border border-surface-200-800 p-4 text-sm">
						<dl class="grid gap-3 sm:grid-cols-2">
							<div>
								<dt class="text-xs text-surface-500">{m.regulatoryDisposition()}</dt>
								<dd class="mt-1">
									{safeTranslate(regulatoryLabelKey(review.data.latest_disposition.to_disposition))}
								</dd>
							</div>
							<div>
								<dt class="text-xs text-surface-500">{m.regulatoryDispositionSequence()}</dt>
								<dd class="mt-1 font-mono text-xs">
									{review.data.latest_disposition.sequence}
								</dd>
							</div>
							<div>
								<dt class="text-xs text-surface-500">{m.regulatoryFromDisposition()}</dt>
								<dd class="mt-1">
									{safeTranslate(
										regulatoryLabelKey(review.data.latest_disposition.from_disposition)
									)}
								</dd>
							</div>
							<div>
								<dt class="text-xs text-surface-500">{m.regulatoryOccurredAt()}</dt>
								<dd class="mt-1 font-mono text-xs">{review.data.latest_disposition.occurred_at}</dd>
							</div>
							<div>
								<dt class="text-xs text-surface-500">{m.regulatoryReasonCode()}</dt>
								<dd class="mt-1 font-mono text-xs">{review.data.latest_disposition.reason_code}</dd>
							</div>
							<div>
								<dt class="text-xs text-surface-500">{m.regulatoryReviewer()}</dt>
								<dd class="mt-1">
									{review.data.latest_disposition.reviewer.masked
										? m.regulatoryReviewerMasked()
										: (review.data.latest_disposition.reviewer.display_name ??
											m.regulatoryNamedReviewer())}
								</dd>
							</div>
							<div class="sm:col-span-2">
								<dt class="text-xs text-surface-500">{m.regulatoryReviewRationale()}</dt>
								<dd class="mt-1 whitespace-pre-wrap">{review.data.latest_disposition.rationale}</dd>
							</div>
						</dl>
						<details class="mt-4 border-t border-surface-200-800 pt-3 text-xs">
							<summary class="cursor-pointer font-semibold"
								>{m.regulatoryDecisionIntegrity()}</summary
							>
							<dl class="mt-3 grid gap-3 sm:grid-cols-2">
								<div>
									<dt class="text-surface-500">{m.regulatoryDigestProfile()}</dt>
									<dd class="break-all font-mono">
										{review.data.latest_disposition.digest_profile}
									</dd>
								</div>
								<div>
									<dt class="text-surface-500">{m.regulatoryBoundDecisionHash()}</dt>
									<dd class="break-all font-mono">
										{review.data.latest_disposition.decision_semantic_payload_sha256}
									</dd>
								</div>
								<div class="sm:col-span-2">
									<dt class="text-surface-500">{m.regulatoryEventHash()}</dt>
									<dd class="break-all font-mono">
										{review.data.latest_disposition.event_payload_sha256}
									</dd>
								</div>
							</dl>
						</details>
						{#if review.data.latest_disposition.to_disposition === 'no_correction_requested'}
							<p class="mt-4 border-t border-surface-200-800 pt-3 text-xs text-surface-500">
								{m.regulatoryNoCorrectionIsNotApproval()}
							</p>
						{/if}
					</div>
				{:else}
					<p class="mt-4 text-sm text-surface-600-400">{m.regulatoryNoHumanDisposition()}</p>
				{/if}
			{/if}
		</section>
	{/if}
</section>
