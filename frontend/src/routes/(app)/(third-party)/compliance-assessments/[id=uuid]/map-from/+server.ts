import { BASE_API_URL } from '$lib/utils/constants';
import { z } from 'zod';
import type { RequestHandler } from './$types';

const mapFromRequestSchema = z
	.object({
		source_audit_id: z.string().uuid()
	})
	.strict();

function invalidRequest(): Response {
	return Response.json({ error: 'A valid source audit ID is required.' }, { status: 400 });
}

function forwardApiResponse(response: Response): Response {
	const contentType = response.headers.get('content-type');
	return new Response(response.body, {
		status: response.status,
		statusText: response.statusText,
		headers: contentType ? { 'Content-Type': contentType } : undefined
	});
}

// Preflight preview: lets the selection modal validate that a mapping path
// exists (and show the error inline) before navigating to the preview page.
export const GET: RequestHandler = async (event) => {
	const sourceAuditId = event.url.searchParams.get('source_audit_id') ?? '';
	if (!z.string().uuid().safeParse(sourceAuditId).success) return invalidRequest();
	const endpoint = `${BASE_API_URL}/compliance-assessments/${event.params.id}/map_from_preview/?source_audit_id=${encodeURIComponent(sourceAuditId)}`;
	const res = await event.fetch(endpoint);

	return forwardApiResponse(res);
};

export const POST: RequestHandler = async (event) => {
	let payload: unknown;
	try {
		payload = await event.request.json();
	} catch {
		return invalidRequest();
	}
	const parsedRequest = mapFromRequestSchema.safeParse(payload);
	if (!parsedRequest.success) return invalidRequest();
	const endpoint = `${BASE_API_URL}/compliance-assessments/${event.params.id}/map_from/`;
	const res = await event.fetch(endpoint, {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify(parsedRequest.data)
	});

	// Preserve the upstream status and body verbatim. In particular, a successful
	// mutation must not be recast as a failure merely because its response body is
	// empty or not JSON; the preview page handles optional response metadata.
	return forwardApiResponse(res);
};
