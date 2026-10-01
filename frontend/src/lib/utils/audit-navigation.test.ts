import { describe, expect, it, vi } from 'vitest';
import type { Locator, Page } from '@playwright/test';
import {
	ensureAuditTreeExpanded,
	expandedAuditTreeItem,
	isAuditDetailUrl,
	reopenAuditDetail,
	waitForAuditDetail
} from '../../../tests/utils/audit-navigation';

const detailUrl =
	'http://localhost:4173/compliance-assessments/12345678-1234-1234-1234-123456789abc';

function fixture(expanded = false) {
	const hydrated = { waitFor: vi.fn().mockResolvedValue(undefined) };
	const ready = { waitFor: vi.fn().mockResolvedValue(undefined) };
	const collapse = { waitFor: vi.fn().mockResolvedValue(undefined), click: vi.fn() };
	const expand = {
		or: vi.fn().mockReturnValue(ready),
		isVisible: vi.fn().mockResolvedValue(!expanded),
		click: vi.fn().mockResolvedValue(undefined)
	};
	const leaf = { waitFor: vi.fn().mockResolvedValue(undefined) };
	const filter = vi.fn().mockReturnValue(leaf);
	const goto = vi.fn().mockResolvedValue({ ok: () => true, status: () => 200 });
	const page = {
		locator: vi.fn().mockReturnValue(hydrated),
		getByRole: vi.fn((_role: string, options: { name: string }) =>
			options.name === 'Expand all' ? expand : collapse
		),
		getByTestId: vi.fn().mockReturnValue({ filter }),
		goto,
		waitForURL: vi.fn().mockResolvedValue(undefined),
		url: vi.fn().mockReturnValue(detailUrl)
	} as unknown as Page;
	return { page, hydrated, ready, collapse, expand, leaf, filter, goto };
}

describe('functional audit navigation', () => {
	it.each([detailUrl, `${detailUrl}?tab=requirements`, new URL(detailUrl)])(
		'accepts an exact audit detail pathname: %s',
		(url) => expect(isAuditDetailUrl(url)).toBe(true)
	);

	it.each([
		`${detailUrl}/edit?next=${new URL(detailUrl).pathname}`,
		`${detailUrl}/map-from-preview?next=${new URL(detailUrl).pathname}`,
		`${detailUrl}/`,
		'http://localhost:4173/compliance-assessments/not-a-uuid',
		'http://localhost:4173/compliance-assessments',
		'not a URL'
	])('rejects edit/query lookalikes and non-detail routes: %s', (url) => {
		expect(isAuditDetailUrl(url)).toBe(false);
	});

	it('waits on parsed pathname rather than a detail URL hidden inside next', async () => {
		const { page, hydrated } = fixture();
		expect(await waitForAuditDetail(page)).toBe(detailUrl);
		const predicate = vi.mocked(page.waitForURL).mock.calls[0]![0] as (url: URL) => boolean;
		expect(predicate(new URL(`${detailUrl}/edit?next=${new URL(detailUrl).pathname}`))).toBe(false);
		expect(predicate(new URL(detailUrl))).toBe(true);
		expect(hydrated.waitFor).toHaveBeenCalledWith({ state: 'attached' });
	});

	it('hydrates before expanding and proves the collapse state and visible leaf', async () => {
		const { page, hydrated, expand, collapse, leaf } = fixture();
		await ensureAuditTreeExpanded(page, leaf as unknown as Locator);
		expect(expand.click).toHaveBeenCalledOnce();
		expect(hydrated.waitFor.mock.invocationCallOrder[0]).toBeLessThan(
			expand.click.mock.invocationCallOrder[0]!
		);
		expect(collapse.waitFor).toHaveBeenCalledWith({ state: 'visible' });
		expect(leaf.waitFor).toHaveBeenCalledWith({ state: 'visible' });
	});

	it('does not toggle an already expanded tree closed', async () => {
		const { page, expand, collapse } = fixture(true);
		await ensureAuditTreeExpanded(page);
		expect(expand.click).not.toHaveBeenCalled();
		expect(collapse.click).not.toHaveBeenCalled();
		expect(collapse.waitFor).toHaveBeenCalledWith({ state: 'visible' });
	});

	it('does not accept a click whose tree remains collapsed', async () => {
		const { page, collapse } = fixture();
		collapse.waitFor.mockRejectedValue(new Error('tree is still collapsed'));
		await expect(ensureAuditTreeExpanded(page)).rejects.toThrow('tree is still collapsed');
	});

	it('rejects a captured edit/next URL before making another request', async () => {
		const { page, goto } = fixture();
		await expect(
			reopenAuditDetail(page, `${detailUrl}/edit?next=${new URL(detailUrl).pathname}`)
		).rejects.toThrow('Expected an exact audit detail pathname');
		expect(goto).not.toHaveBeenCalled();
	});

	it('preserves a failed detail HTTP status instead of interacting with its page', async () => {
		const { page, goto, expand } = fixture();
		goto.mockResolvedValue({ ok: () => false, status: () => 403 });
		await expect(reopenAuditDetail(page, detailUrl)).rejects.toThrow('status 403');
		expect(expand.click).not.toHaveBeenCalled();
	});

	it('reopens the detail, waits for hydration and leaves the tree expanded', async () => {
		const { page, goto, hydrated, expand } = fixture();
		await reopenAuditDetail(page, detailUrl);
		expect(goto).toHaveBeenCalledWith(detailUrl, { waitUntil: 'domcontentloaded' });
		expect(hydrated.waitFor).toHaveBeenCalled();
		expect(expand.click).toHaveBeenCalledOnce();
	});

	it('checks the exact visible leaf before delegating to the path helper', async () => {
		const { page, leaf, filter } = fixture();
		const item = { content: leaf };
		const detail = { treeViewItem: vi.fn().mockResolvedValue(item) };
		const path = ['ID - Identify', 'ID.AM - Asset Management'];
		expect(await expandedAuditTreeItem(page, detail, 'ID.AM-2', path)).toBe(item);
		expect(detail.treeViewItem).toHaveBeenCalledWith('ID.AM-2', path);
		expect(leaf.waitFor.mock.invocationCallOrder[0]).toBeLessThan(
			detail.treeViewItem.mock.invocationCallOrder[0]!
		);
		const regex = filter.mock.calls[0]![0].hasText as RegExp;
		expect(regex.test('ID.AM-2\nstatus')).toBe(true);
		expect(regex.test('IDxAM-2\nstatus')).toBe(false);
		expect(regex.test('ID.AM-20\nstatus')).toBe(false);
	});

	it('fails a missing leaf without attempting the old parent click path', async () => {
		const { page, leaf } = fixture();
		leaf.waitFor.mockRejectedValue(new Error('leaf is absent'));
		const detail = { treeViewItem: vi.fn() };
		await expect(expandedAuditTreeItem(page, detail, 'ID.AM-2')).rejects.toThrow('leaf is absent');
		expect(detail.treeViewItem).not.toHaveBeenCalled();
	});
});
