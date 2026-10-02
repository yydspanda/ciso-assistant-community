import { cleanup, render, waitFor } from '@testing-library/svelte';
import { get, writable } from 'svelte/store';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { page } from '$app/state';
import { goto } from '$lib/utils/breadcrumbs';
import { tableHandlers, tableRefreshers } from '$lib/utils/stores';
import { loadTableData } from './handler';
import ModelTable from './ModelTable.svelte';

const fixture = vi.hoisted(() => ({ rows: [] as Record<string, unknown>[] }));

vi.mock('$lib/utils/breadcrumbs', () => ({
	breadcrumbs: { push: vi.fn(), replace: vi.fn(), update: vi.fn() },
	goto: vi.fn()
}));

vi.mock('./handler', async (importOriginal) => ({
	...(await importOriginal<typeof import('./handler')>()),
	loadTableData: vi.fn(async () => fixture.rows)
}));

const sourceId = '12345678-1234-1234-1234-123456789abc';
const targetId = '87654321-4321-4321-4321-cba987654321';
const modifiedClicks: [string, MouseEventInit][] = [
	['command', { metaKey: true }],
	['control', { ctrlKey: true }]
];

async function rowFixture(
	URLModel: 'assets' | 'notifications',
	meta: Record<string, unknown>,
	detailQueryParameter = ''
) {
	fixture.rows = [{ name: 'Synthetic row', meta }];
	const context = new Map<string, unknown>([
		['modalStore', writable([])],
		['toastStore', Object.assign(writable([]), { trigger: vi.fn() })]
	]);
	const view = render(ModelTable, {
		context,
		props: {
			URLModel,
			source: {
				head: { name: 'Name' },
				body: [{ name: 'Synthetic row' }],
				meta: [meta],
				filters: {}
			},
			fields: ['name'],
			detailQueryParameter,
			search: false,
			hideFilters: true,
			pagination: false,
			rowsPerPage: false,
			rowCount: false,
			displayActions: false,
			disableCreate: true,
			disableEdit: true,
			disableDelete: true,
			columnSelector: false
		}
	});
	await waitFor(() => expect(loadTableData).toHaveBeenCalled());
	const row = view.getByText('Synthetic row').closest('tr')!;
	const handler = get(tableHandlers)[`/${URLModel}`]!;
	const invalidate = vi.spyOn(handler, 'invalidate');
	return { row, invalidate };
}

function clickRow(row: HTMLTableRowElement, init: MouseEventInit = {}) {
	row.dispatchEvent(
		new MouseEvent('click', { bubbles: true, cancelable: true, button: 0, ...init })
	);
}

describe('ModelTable row navigation ownership', () => {
	beforeEach(() => {
		vi.clearAllMocks();
		Object.assign(page.data, { user: { domain_permissions: {} }, featureflags: {} });
		tableHandlers.set({});
		tableRefreshers.set({});
		vi.spyOn(window, 'open').mockReturnValue(null);
	});

	afterEach(() => {
		cleanup();
		vi.restoreAllMocks();
		vi.unstubAllGlobals();
	});

	it('keeps an ordinary primary row click in the current tab with its label and query', async () => {
		const { row } = await rowFixture(
			'assets',
			{ id: sourceId, str: 'Source asset' },
			'tab=details'
		);
		clickRow(row);
		expect(goto).toHaveBeenCalledExactlyOnceWith(`/assets/${sourceId}?tab=details`, {
			label: 'Source asset',
			breadcrumbAction: 'push'
		});
		expect(window.open).not.toHaveBeenCalled();
	});

	it.each(modifiedClicks)(
		'%s row click opens only the exact detail in a protected new tab',
		async (_, init) => {
			const { row } = await rowFixture(
				'assets',
				{ id: sourceId, str: 'Source asset' },
				'tab=details'
			);
			clickRow(row, init);
			expect(window.open).toHaveBeenCalledExactlyOnceWith(
				`/assets/${sourceId}?tab=details`,
				'_blank',
				'noopener'
			);
			expect(goto).not.toHaveBeenCalled();
		}
	);

	it.each(modifiedClicks)(
		'%s notification click opens its target without waiting for mark-read, then refreshes',
		async (_, init) => {
			let finishMark!: (response: Response) => void;
			const mark = new Promise<Response>((resolve) => {
				finishMark = resolve;
			});
			const fetch = vi.fn().mockReturnValue(mark);
			vi.stubGlobal('fetch', fetch);
			const { row, invalidate } = await rowFixture('notifications', {
				id: sourceId,
				target_model: 'asset',
				object_id: targetId,
				is_read: false
			});
			clickRow(row, init);
			expect(window.open).toHaveBeenCalledExactlyOnceWith(
				`/assets/${targetId}`,
				'_blank',
				'noopener'
			);
			expect(goto).not.toHaveBeenCalled();
			expect(fetch).toHaveBeenCalledExactlyOnceWith(`/notifications/${sourceId}/is_read`, {
				method: 'PATCH',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify({ is_read: true })
			});
			expect(invalidate).not.toHaveBeenCalled();
			finishMark(new Response(JSON.stringify({ unread_count: 0 }), { status: 200 }));
			await waitFor(() => expect(invalidate).toHaveBeenCalledOnce());
		}
	);

	it('keeps an unmapped notification target non-navigable while finishing mark-read', async () => {
		const fetch = vi
			.fn()
			.mockResolvedValue(new Response(JSON.stringify({ unread_count: 0 }), { status: 200 }));
		vi.stubGlobal('fetch', fetch);
		const { row, invalidate } = await rowFixture('notifications', {
			id: sourceId,
			target_model: 'unknown-model',
			object_id: targetId,
			is_read: false
		});
		clickRow(row, { ctrlKey: true });
		await waitFor(() => expect(invalidate).toHaveBeenCalledOnce());
		expect(fetch).toHaveBeenCalledOnce();
		expect(window.open).not.toHaveBeenCalled();
		expect(goto).not.toHaveBeenCalled();
	});
});
