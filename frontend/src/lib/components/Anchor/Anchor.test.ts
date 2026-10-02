import { cleanup, render } from '@testing-library/svelte';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { breadcrumbs, goto } from '$lib/utils/breadcrumbs';
import Anchor from './Anchor.svelte';

vi.mock('$lib/utils/breadcrumbs', () => ({
	breadcrumbs: { push: vi.fn(), replace: vi.fn() },
	goto: vi.fn()
}));

const href = '/compliance-assessments/12345678-1234-1234-1234-123456789abc';
const label = 'Audit detail';

function clickFixture(stopPropagation: boolean, init: MouseEventInit = {}) {
	const view = render(Anchor, { href, label, stopPropagation });
	const parentClick = vi.fn();
	// Svelte delegates click handling through its render root. Observe bubbling
	// above that delegation boundary rather than firing a raw container listener
	// before the component's handler has had the chance to stop propagation.
	window.addEventListener('click', parentClick);
	const link = view.getByRole('link', { name: label });
	const event = new MouseEvent('click', { bubbles: true, cancelable: true, button: 0, ...init });
	link.dispatchEvent(event);
	window.removeEventListener('click', parentClick);
	return { event, parentClick };
}

describe('Anchor click ownership', () => {
	beforeEach(() => vi.clearAllMocks());
	afterEach(() => cleanup());

	it('preserves ordinary primary-click breadcrumbs and intercepted navigation', () => {
		const { event, parentClick } = clickFixture(true);
		expect(breadcrumbs.push).toHaveBeenCalledExactlyOnceWith([{ href, label }]);
		expect(goto).toHaveBeenCalledExactlyOnceWith(href, { breadcrumbAction: 'push' });
		expect(event.defaultPrevented).toBe(true);
		expect(parentClick).not.toHaveBeenCalled();
	});

	it('preserves ordinary native primary navigation when interception is disabled', () => {
		const { event, parentClick } = clickFixture(false);
		expect(breadcrumbs.push).toHaveBeenCalledExactlyOnceWith([{ href, label }]);
		expect(goto).not.toHaveBeenCalled();
		expect(event.defaultPrevented).toBe(false);
		expect(parentClick).toHaveBeenCalledOnce();
	});

	it('preserves replace action and prefix crumbs for an ordinary click', () => {
		const prefixCrumbs = [{ href: '/compliance-assessments', label: 'Audits' }];
		const view = render(Anchor, {
			href,
			label,
			stopPropagation: true,
			breadcrumbAction: 'replace',
			prefixCrumbs
		});
		view
			.getByRole('link', { name: label })
			.dispatchEvent(new MouseEvent('click', { bubbles: true, cancelable: true, button: 0 }));
		expect(breadcrumbs.replace).toHaveBeenCalledExactlyOnceWith([...prefixCrumbs, { href, label }]);
		expect(breadcrumbs.push).not.toHaveBeenCalled();
		expect(goto).toHaveBeenCalledExactlyOnceWith(href, { breadcrumbAction: 'replace' });
	});

	const modifiedClicks: [string, MouseEventInit][] = [
		['command', { metaKey: true }],
		['control', { ctrlKey: true }],
		['shift', { shiftKey: true }],
		['alt', { altKey: true }],
		['middle button', { button: 1 }],
		['non-primary button', { button: 2 }]
	];

	describe.each([false, true])('with stopPropagation=%s', (stopPropagation) => {
		it.each(modifiedClicks)(
			'%s click remains browser-owned without parent navigation',
			(_, init) => {
				const { event, parentClick } = clickFixture(stopPropagation, init);
				expect(parentClick).not.toHaveBeenCalled();
				expect(event.defaultPrevented).toBe(false);
				expect(breadcrumbs.push).not.toHaveBeenCalled();
				expect(breadcrumbs.replace).not.toHaveBeenCalled();
				expect(goto).not.toHaveBeenCalled();
			}
		);
	});
});
