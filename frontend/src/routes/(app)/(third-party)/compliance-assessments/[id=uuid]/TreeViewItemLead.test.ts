import { render, screen } from '@testing-library/svelte';
import { describe, expect, it } from 'vitest';

import TreeViewItemLead from './TreeViewItemLead.svelte';

const scoredItem = {
	statusI18n: 'inProgress',
	resultI18n: 'partiallyCompliant',
	statusColor: '#3b82f6',
	resultColor: '#f59e0b',
	assessable: true,
	score: 2,
	documentationScore: null,
	isScored: true,
	showResult: false,
	showScore: true,
	showStatus: false,
	scoringEnabled: true,
	showDocumentationScore: false,
	max_score: 5
};

describe('TreeViewItemLead score progress', () => {
	it('keeps repeated tree score rings out of the primary progress-ring locator', () => {
		render(TreeViewItemLead, scoredItem);
		render(TreeViewItemLead, { ...scoredItem, score: 4 });

		expect(screen.getAllByTestId('tree-item-score-progress-ring')).toHaveLength(2);
		expect(screen.queryByTestId('progress-ring-svg')).not.toBeInTheDocument();
	});
});
