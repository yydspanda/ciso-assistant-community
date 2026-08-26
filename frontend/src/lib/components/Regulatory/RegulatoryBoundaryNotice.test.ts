import { render, screen } from '@testing-library/svelte';
import '@testing-library/jest-dom/vitest';
import { describe, expect, it } from 'vitest';

import RegulatoryBoundaryNotice from './RegulatoryBoundaryNotice.svelte';

describe('RegulatoryBoundaryNotice', () => {
	it('keeps every authority and content-rights boundary visible in compact detail mode', () => {
		render(RegulatoryBoundaryNotice, { compact: true });

		expect(screen.getByText('Read-only, non-binding Phase 1 boundary')).toBeInTheDocument();
		expect(screen.getByText(/does not provide legal advice/)).toBeInTheDocument();
		expect(screen.getByText(/synthetic, metadata-only records/)).toBeInTheDocument();
		expect(screen.getByText(/remain needs review/)).toBeInTheDocument();
		expect(screen.getByText(/no create, edit, correction, approval/)).toBeInTheDocument();
	});
});
