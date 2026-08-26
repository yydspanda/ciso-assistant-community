import { responseReadState } from './presentation';
import type { RegulatoryReadPanel } from './types';

export async function fetchRegulatoryReadPanel<T>(
	fetchFn: typeof fetch,
	url: string,
	parse: (payload: unknown) => T
): Promise<RegulatoryReadPanel<T>> {
	try {
		const response = await fetchFn(url, {
			method: 'GET',
			headers: { Accept: 'application/json' }
		});
		if (!response.ok) {
			return { state: responseReadState(response.status), data: null };
		}
		return { state: 'ok', data: parse(await response.json()) };
	} catch {
		return { state: 'unavailable', data: null };
	}
}
