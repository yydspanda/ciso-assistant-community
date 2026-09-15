import { BASE_API_URL } from '$lib/utils/constants';
import { error } from '@sveltejs/kit';
import { z } from 'zod';
import type { PageServerLoad } from './$types';

const auditIdentitySchema = z
	.object({
		id: z.string().uuid(),
		name: z.string(),
		framework: z.unknown()
	})
	.passthrough();

const previewSchema = z
	.object({
		source_audit: auditIdentitySchema,
		target_audit: auditIdentitySchema
	})
	.passthrough();

export const load = (async ({ fetch, url }) => {
	const targetId = url.searchParams.get('target');
	const sourceId = url.searchParams.get('source');

	if (
		!targetId ||
		!sourceId ||
		!z.string().uuid().safeParse(targetId).success ||
		!z.string().uuid().safeParse(sourceId).success
	) {
		throw error(400, 'Both target and source audit IDs are required');
	}

	const previewEndpoint = `${BASE_API_URL}/compliance-assessments/${targetId}/map_from_preview/?source_audit_id=${encodeURIComponent(sourceId)}`;

	const previewResponse = await fetch(previewEndpoint);
	if (!previewResponse.ok) {
		if (previewResponse.status === 404) throw error(404, 'One or both audits not found');
		if (previewResponse.status === 403) throw error(403, 'Permission denied');
		if (previewResponse.status === 400)
			throw error(400, 'No mapping path found between these frameworks');
		throw error(502, 'Failed to load mapping preview');
	}

	let previewPayload: unknown;
	try {
		previewPayload = await previewResponse.json();
	} catch {
		throw error(502, 'The mapping preview response is invalid');
	}
	const parsedPreview = previewSchema.safeParse(previewPayload);
	if (!parsedPreview.success) {
		throw error(502, 'The mapping preview response is invalid');
	}
	if (
		parsedPreview.data.target_audit.id !== targetId ||
		parsedPreview.data.source_audit.id !== sourceId
	) {
		throw error(409, 'The mapping preview does not match the requested audits');
	}
	// Preserve the complete backend preview contract for the page after the
	// authority-bearing identities have been validated above.
	const previewData = previewPayload as Record<string, any>;

	return {
		previewData,
		targetId,
		sourceId,
		title: `Mapping preview: ${previewData.target_audit.name}`
	};
}) satisfies PageServerLoad;
