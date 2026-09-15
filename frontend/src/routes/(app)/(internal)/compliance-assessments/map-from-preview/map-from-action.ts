type MapFromFetcher = (input: string, init: RequestInit) => Promise<Pick<Response, 'ok' | 'json'>>;

type MapFromNavigator = (destination: string) => Promise<unknown>;

export type MapFromOutcome =
	| { status: 'failed'; message?: string }
	| { status: 'applied'; updatedCount?: number; navigated: boolean };

export async function applyMapFrom({
	sourceId,
	targetId,
	fetcher,
	navigate
}: {
	sourceId: string;
	targetId: string;
	fetcher: MapFromFetcher;
	navigate: MapFromNavigator;
}): Promise<MapFromOutcome> {
	let response: Pick<Response, 'ok' | 'json'>;
	try {
		response = await fetcher(`/compliance-assessments/${targetId}/map-from`, {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({ source_audit_id: sourceId })
		});
	} catch {
		return { status: 'failed' };
	}

	if (!response.ok) {
		try {
			const payload: unknown = await response.json();
			if (payload && typeof payload === 'object' && !Array.isArray(payload)) {
				const message = (payload as Record<string, unknown>).error;
				if (typeof message === 'string') return { status: 'failed', message };
			}
		} catch {
			// The HTTP failure remains authoritative when the response body is not JSON.
		}
		return { status: 'failed' };
	}

	// A successful HTTP response means the mutation has crossed the API boundary.
	// Response decoding and client-side navigation must not recast it as a write failure.
	let updatedCount: number | undefined;
	try {
		const payload: unknown = await response.json();
		if (payload && typeof payload === 'object' && !Array.isArray(payload)) {
			const candidate = (payload as Record<string, unknown>).updated_count;
			if (typeof candidate === 'number' && Number.isFinite(candidate) && candidate >= 0) {
				updatedCount = candidate;
			}
		}
	} catch {
		// The update is already committed; omit the count if the response is malformed.
	}

	let navigated = true;
	try {
		await navigate(`/compliance-assessments/${targetId}`);
	} catch {
		navigated = false;
	}

	return { status: 'applied', updatedCount, navigated };
}
