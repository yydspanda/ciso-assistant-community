import { queryAllByRole } from '@testing-library/dom';
import type { Page } from '@playwright/test';
import { afterEach, describe, expect, it, vi } from 'vitest';

// Only the count assertion boundary is substituted. Locator queries/evaluation
// run on rendered DOM and remain live after rows are replaced or removed.
vi.mock('@playwright/test', () => ({
	expect: (locator: DomLocator) => ({
		async toHaveCount(count: number) {
			expect(await locator.count()).toBe(count);
		}
	})
}));
import {
	exactNamedObjectRow,
	exactOwnNamePattern,
	ownNameColumnIndex
} from '../../../tests/utils/exact-named-object-row';

type RoleOptions = { name?: string; exact?: boolean };
class DomLocator {
	constructor(private readonly resolve: (scope: HTMLElement) => HTMLElement[]) {}
	nodes(scope = document.body): HTMLElement[] {
		return this.resolve(scope);
	}
	filter(options: { has?: DomLocator; hasText?: RegExp }): DomLocator {
		return new DomLocator((scope) =>
			this.nodes(scope).filter(
				(node) =>
					(!options.has || options.has.nodes(node).length > 0) &&
					(!options.hasText || options.hasText.test(node.textContent ?? ''))
			)
		);
	}
	locator(selector: string): DomLocator {
		return new DomLocator((scope) =>
			this.nodes(scope).flatMap((node) => Array.from(node.querySelectorAll<HTMLElement>(selector)))
		);
	}
	async evaluate<A, R>(callback: (node: HTMLTableElement, argument: A) => R, argument: A) {
		const nodes = this.nodes();
		expect(nodes).toHaveLength(1);
		return callback(nodes[0] as HTMLTableElement, argument);
	}
	async count() {
		return this.nodes().length;
	}
}
const page = {
	getByRole: (role: Parameters<typeof queryAllByRole>[1], options?: RoleOptions) =>
		new DomLocator((scope) => queryAllByRole(scope, role, options)),
	locator: (selector: string) =>
		new DomLocator((scope) => Array.from(scope.querySelectorAll<HTMLElement>(selector)))
} as unknown as Page;

function renderRows(rows: string, headers = '<th>Name</th><th>Parent domain</th><th></th>') {
	document.body.innerHTML = `<table><thead><tr>${headers}</tr>
		<tr><th><input aria-label="Name filter"></th><th></th><th></th></tr>
		</thead><tbody>${rows}</tbody></table>`;
}
function row(name: string, parent = 'Root', id = name) {
	return `<tr data-object="${id}"><td><div data-testid="model-table-td-array-elem">${name}</div></td>
		<td><a href="/folders/parent">${parent}</a></td><td>
		<a data-testid="tablerow-detail-button" aria-label="View" href="/folders/${id}"></a>
		<button data-testid="tablerow-delete-button" aria-label="Delete"></button></td></tr>`;
}
afterEach(() => document.body.replaceChildren());

describe('opt-in exact own Name row cleanup contract', () => {
	it('selects base, not an earlier base foo or a child whose Parent links to base', async () => {
		renderRows(row('base foo') + row('base') + row('child', 'base'));
		const actual = (await exactNamedObjectRow(page, 'base')) as unknown as DomLocator;
		expect(actual.nodes().map((node) => node.dataset.object)).toEqual(['base']);
	});

	it('selects base foo by its own exact name', async () => {
		renderRows(row('base') + row('base foo') + row('child', 'base foo'));
		const actual = (await exactNamedObjectRow(page, 'base foo')) as unknown as DomLocator;
		expect(actual.nodes().map((node) => node.dataset.object)).toEqual(['base foo']);
	});

	it('uses a reordered Name column and counts an empty checkbox header', async () => {
		renderRows(
			'<tr data-object="child"><td><input type="checkbox"></td><td><a>base</a></td><td>child</td><td></td></tr>' +
				'<tr data-object="base"><td><input type="checkbox"></td><td><a>Root</a></td><td>base</td><td></td></tr>',
			'<th><input type="checkbox" aria-label="Select all"></th><th>Parent domain</th><th><button>Name</button></th><th></th>'
		);
		expect(ownNameColumnIndex(document.querySelector('table')!, 'Name')).toBe(2);
		const actual = (await exactNamedObjectRow(page, 'base')) as unknown as DomLocator;
		expect(actual.nodes().map((node) => node.dataset.object)).toEqual(['base']);
	});

	it('ignores later filter-row cells when resolving the real header column', () => {
		renderRows(row('base'));
		expect(ownNameColumnIndex(document.querySelector('table')!, 'Name')).toBe(0);
	});

	it('fails closed when two tables have their own Name headers', async () => {
		renderRows(row('base'));
		document.body.append(document.querySelector('table')!.cloneNode(true));
		await expect(exactNamedObjectRow(page, 'base')).rejects.toThrow();
	});

	it('fails closed without a matching table', async () => {
		await expect(exactNamedObjectRow(page, 'base')).rejects.toThrow();
	});

	it('fails closed with duplicate Name headers in the real header row', async () => {
		renderRows(row('base'), '<th>Name</th><th>Name</th><th></th>');
		await expect(exactNamedObjectRow(page, 'base')).rejects.toThrow('exactly one own Name');
	});

	it('fails closed if Name is missing from the real header, even if a later row says Name', async () => {
		renderRows(row('base'), '<th>Title</th><th>Parent</th><th></th>');
		document.querySelector('thead tr:last-child th')!.textContent = 'Name';
		await expect(exactNamedObjectRow(page, 'base')).rejects.toThrow('exactly one own Name');
	});

	it('fails closed with duplicate own names', async () => {
		renderRows(row('base', 'Root', 'first') + row('base', 'Root', 'second'));
		await expect(exactNamedObjectRow(page, 'base')).rejects.toThrow();
	});

	it('fails closed when only prefix or Parent matches exist', async () => {
		renderRows(row('base foo') + row('child', 'base'));
		await expect(exactNamedObjectRow(page, 'base')).rejects.toThrow();
	});

	it('keeps a live locator: deleting foo does not falsely prove base was removed', async () => {
		renderRows(row('base foo') + row('base'));
		const base = await exactNamedObjectRow(page, 'base');
		document.querySelector('[data-object="base foo"]')!.remove();
		expect(await base.count()).toBe(1);
	});

	it('does not mistake replacing the old node for successful deletion', async () => {
		renderRows(row('base'));
		const base = await exactNamedObjectRow(page, 'base');
		document.querySelector('tbody')!.innerHTML = row('base', 'Root', 'replacement');
		expect(await base.count()).toBe(1);
		document.querySelector('tbody')!.replaceChildren();
		expect(await base.count()).toBe(0);
	});

	it('escapes name regex metacharacters rather than matching a different object', async () => {
		renderRows(row('a.b+') + row('axb'));
		const actual = (await exactNamedObjectRow(page, 'a.b+')) as unknown as DomLocator;
		expect(actual.nodes().map((node) => node.dataset.object)).toEqual(['a.b+']);
	});

	it.each(['', ' ', ' base', 'base '])('rejects an ambiguous empty/untrimmed name %j', (name) => {
		expect(() => exactOwnNamePattern(name)).toThrow();
	});
});
