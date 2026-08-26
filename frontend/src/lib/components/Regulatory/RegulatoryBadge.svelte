<script lang="ts">
	import { safeTranslate } from '$lib/utils/i18n';
	import { regulatoryLabelKey, regulatoryTone } from '$lib/regulatory/presentation';

	let { value, monospace = false }: { value: string | null | undefined; monospace?: boolean } =
		$props();

	let tone = $derived(regulatoryTone(value));
	let toneClass = $derived(
		tone === 'danger'
			? 'border-error-500/30 bg-error-500/10 text-error-700-300'
			: tone === 'warning'
				? 'border-warning-500/30 bg-warning-500/10 text-warning-800-200'
				: tone === 'success'
					? 'border-success-500/30 bg-success-500/10 text-success-800-200'
					: tone === 'info'
						? 'border-primary-500/30 bg-primary-500/10 text-primary-800-200'
						: 'border-surface-300-700 bg-surface-100-900 text-surface-700-300'
	);
</script>

<span
	class="inline-flex items-center rounded-full border px-2.5 py-1 text-xs font-semibold {toneClass} {monospace
		? 'font-mono'
		: ''}"
>
	{safeTranslate(regulatoryLabelKey(value))}
</span>
