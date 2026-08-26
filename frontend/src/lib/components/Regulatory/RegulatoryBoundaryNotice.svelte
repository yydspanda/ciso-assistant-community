<script lang="ts">
	import { m } from '$paraglide/messages';

	let { compact = false }: { compact?: boolean } = $props();
</script>

<aside
	class="rounded-xl border border-amber-500/30 bg-amber-500/10 {compact ? 'p-4' : 'p-5'}"
	aria-labelledby="regulatory-boundary-title"
>
	<div class="flex items-start gap-3">
		<i class="fa-solid fa-shield-halved mt-0.5 text-amber-600" aria-hidden="true"></i>
		<div class="space-y-2">
			<h2 id="regulatory-boundary-title" class="font-semibold text-amber-900-100">
				{m.regulatoryBoundaryTitle()}
			</h2>
			<p class="text-sm leading-6 text-surface-800-200">{m.regulatoryBoundaryBody()}</p>
			<ul class="list-disc space-y-1 pl-5 text-xs leading-5 text-surface-700-300">
				<li>{m.regulatoryBoundaryMetadataOnly()}</li>
				<li>{m.regulatoryBoundaryNeedsHumanReview()}</li>
				<li>{m.regulatoryBoundaryNoWrite()}</li>
			</ul>
		</div>
	</div>
</aside>
