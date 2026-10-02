import { expect, type Locator, type Page } from '@playwright/test';

// This function is evaluated against the real table and is also tested with DOM
// fixtures. It must remain self-contained (no captured module dependencies).
export function ownNameColumnIndex(table: Element, nameLabel: string): number {
	if (table.tagName !== 'TABLE' || !nameLabel.trim()) {
		throw new Error('An actual table and a non-empty Name column label are required');
	}
	const heads = Array.from(table.children).filter((node) => node.tagName === 'THEAD');
	if (heads.length !== 1) throw new Error('Expected exactly one direct table head');
	const headerRow = Array.from(heads[0].children).find(
		(node) =>
			node.tagName === 'TR' && Array.from(node.children).some((cell) => cell.tagName === 'TH')
	);
	if (!headerRow) throw new Error('Expected a direct header row');
	const headers = Array.from(headerRow.children);
	const matches = headers.filter(
		(cell) => cell.tagName === 'TH' && cell.textContent?.trim() === nameLabel
	);
	if (matches.length !== 1) throw new Error('Expected exactly one own Name column header');
	// Includes empty checkbox/actions headers. Later filter rows are not columns.
	return headers.indexOf(matches[0]);
}

export function exactOwnNamePattern(name: string): RegExp {
	if (!name.trim() || name !== name.trim()) {
		throw new Error('An exact non-empty object name is required');
	}
	return new RegExp(`^\\s*${name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\s*$`);
}

// Opt-in cleanup helper; shared PageContent.getRow and production UI are unchanged.
export async function exactNamedObjectRow(
	page: Page,
	name: string,
	nameLabel = 'Name'
): Promise<Locator> {
	const exactName = exactOwnNamePattern(name);
	const tables = page.getByRole('table').filter({
		has: page.getByRole('columnheader', { name: nameLabel, exact: true })
	});
	await expect(tables).toHaveCount(1);
	const columnIndex = await tables.evaluate(ownNameColumnIndex, nameLabel);
	const rows = tables.locator(':scope > tbody > tr').filter({
		has: page.locator(`:scope > td:nth-child(${columnIndex + 1})`).filter({ hasText: exactName })
	});
	await expect(rows).toHaveCount(1);
	return rows;
}
