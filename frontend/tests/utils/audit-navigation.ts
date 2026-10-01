import type { Locator, Page } from '@playwright/test';

const AUDIT_DETAIL_PATH =
	/^\/compliance-assessments\/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export function isAuditDetailUrl(value: string | URL): boolean {
	try {
		return AUDIT_DETAIL_PATH.test(new URL(value).pathname);
	} catch {
		return false;
	}
}

export async function waitForAuditDetail(page: Page): Promise<string> {
	await page.waitForURL(isAuditDetailUrl);
	await page.locator('body[data-hydrated="true"]').waitFor({ state: 'attached' });
	return page.url();
}

export async function ensureAuditTreeExpanded(page: Page, leaf?: Locator): Promise<void> {
	// The server-rendered toggle can precede its Svelte click handler. Also,
	// expanded state survives navigation, so clicking "Collapse all" is wrong.
	await page.locator('body[data-hydrated="true"]').waitFor({ state: 'attached' });
	const expand = page.getByRole('button', { name: 'Expand all', exact: true });
	const collapse = page.getByRole('button', { name: 'Collapse all', exact: true });
	await expand.or(collapse).waitFor({ state: 'visible' });
	if (await expand.isVisible()) await expand.click();
	await collapse.waitFor({ state: 'visible' });
	if (leaf) await leaf.waitFor({ state: 'visible' });
}

export async function reopenAuditDetail(page: Page, detailUrl: string): Promise<void> {
	if (!isAuditDetailUrl(detailUrl)) throw new Error('Expected an exact audit detail pathname');
	const response = await page.goto(detailUrl, { waitUntil: 'domcontentloaded' });
	if (!response?.ok()) {
		throw new Error(`Audit detail GET failed with status ${response?.status() ?? 'unavailable'}`);
	}
	await waitForAuditDetail(page);
	await ensureAuditTreeExpanded(page);
}

export async function expandedAuditTreeItem<T>(
	page: Page,
	detail: { treeViewItem(value: string, path?: string[]): Promise<T> },
	value: string,
	path: string[] = []
): Promise<T> {
	const escapedValue = value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
	const leaf = page
		.getByTestId('tree-item-content')
		.filter({ hasText: new RegExp(`^${escapedValue}(?:\\s|$)`) });
	// Prove the leaf is visible before the older path helper can toggle a parent.
	await ensureAuditTreeExpanded(page, leaf);
	return detail.treeViewItem(value, path);
}
