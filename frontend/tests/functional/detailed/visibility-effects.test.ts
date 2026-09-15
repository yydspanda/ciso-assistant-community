/**
 * Functional tests for the effect of the per-role field visibility settings
 * on the audit-overview UI.
 *
 * Field visibility is set via direct PATCH to the backend API rather than
 * through the editor UI. Going through the UI was flaky in CI because of how
 * the editor's Accordion-based "More" dropdown handles repeated re-renders.
 * The editor itself is exercised by visibility-editor.test.ts.
 *
 * Companion tests:
 *   - visibility-editor.test.ts verifies the editor UI (pill state, cascade,
 *     persistence) for one save cycle.
 *   - test_field_visibility.py (backend) covers the resolver helpers.
 */

import { LoginPage } from '../../utils/login-page.js';
import { PageContent } from '../../utils/page-content.js';
import { TestContent, test, expect } from '../../utils/test-utils.js';
import { m } from '$paraglide/messages';
import type { Page, BrowserContext } from '@playwright/test';

const vars = TestContent.generateTestVars();
const testObjectsData: { [k: string]: any } = TestContent.itemBuilder(vars);

/** Per-role visibility pair. */
type Pair = { auditor: 'edit' | 'read' | 'hidden'; respondent: 'edit' | 'read' | 'hidden' };
const EVERYONE: Pair = { auditor: 'edit', respondent: 'edit' };
const READ_ONLY: Pair = { auditor: 'read', respondent: 'read' };
const HIDDEN: Pair = { auditor: 'hidden', respondent: 'hidden' };

/** Resolve the backend base URL the SvelteKit app was built with. */
const BACKEND_API_URL = process.env.PUBLIC_BACKEND_API_URL ?? 'http://localhost:8000/api';

/** Extract the auth token the frontend stored after login. */
async function getAuthToken(context: BrowserContext): Promise<string> {
	const cookies = await context.cookies();
	const token = cookies.find((c) => c.name === 'token')?.value;
	if (!token) throw new Error('No `token` cookie found — is the user logged in?');
	return token;
}

test('field visibility effects: charts and relationship edit gates follow policy', async ({
	logedPage,
	pages,
	complianceAssessmentsPage,
	evidencesPage,
	appliedControlsPage,
	page
}) => {
	test.setTimeout(10 * 60 * 1000);

	// --- Bootstrap: folder + perimeter + CA --------------------------------
	for (const requirement of ['folders', 'perimeters', 'complianceAssessments']) {
		const requiredPage = pages[requirement + 'Page'];
		await requiredPage.goto();
		await requiredPage.hasUrl();
		await requiredPage.createItem(
			testObjectsData[requirement + 'Page'].build,
			'dependency' in testObjectsData[requirement + 'Page']
				? testObjectsData[requirement + 'Page'].dependency
				: null
		);
		await requiredPage.goto();
		await requiredPage.hasUrl();
	}

	const hiddenStatusEvidenceName = `${vars.evidenceName} hidden status`;
	await evidencesPage.goto();
	await evidencesPage.hasUrl();
	await evidencesPage.createItem({
		name: hiddenStatusEvidenceName,
		description: vars.description,
		folder: vars.folderName,
		link: 'https://intuitem.com/'
	});

	await appliedControlsPage.goto();
	await appliedControlsPage.hasUrl();
	await appliedControlsPage.createItem({
		name: vars.appliedControlName,
		folder: vars.folderName
	});

	await complianceAssessmentsPage.goto();
	await complianceAssessmentsPage.hasUrl();
	await complianceAssessmentsPage.viewItemDetail(
		testObjectsData.complianceAssessmentsPage.build.name
	);
	const auditDetailUrl = page.url();
	const auditId = auditDetailUrl.split('/').pop()!.split('?')[0];

	const token = await getAuthToken(page.context());

	/**
	 * PATCH the audit's field_visibility for a single field, then reload the
	 * detail page so the new state is reflected in the DOM. The backend merges
	 * partial field_visibility maps, so sending only the changed field is safe.
	 */
	async function setVisibility(field: string, pair: Pair) {
		const response = await page.request.patch(
			`${BACKEND_API_URL}/compliance-assessments/${auditId}/`,
			{
				data: { field_visibility: { [field]: pair } },
				headers: {
					'Content-Type': 'application/json',
					Authorization: `Token ${token}`
				}
			}
		);
		expect(
			response.ok(),
			`PATCH failed: ${response.status()} ${await response.text()}`
		).toBeTruthy();
		await page.goto(auditDetailUrl);
	}

	// === Matrix: each donut-bearing field hidden then visible ==============
	// Both `result` and `status` always have non-empty donut data on a fresh
	// audit (every RA gets a default value).
	const checks: Array<{ field: string; selector: string }> = [
		{ field: 'result', selector: '#compliance_result_div' },
		{ field: 'status', selector: '#compliance_status_div' }
	];

	for (const check of checks) {
		await setVisibility(check.field, HIDDEN);
		await expect(page.locator(check.selector)).toHaveCount(0);

		await setVisibility(check.field, EVERYONE);
		await expect(page.locator(check.selector)).toHaveCount(1);
	}

	await setVisibility('status', HIDDEN);
	await page.goto(`${auditDetailUrl}/table-mode`);

	const firstRequirementAssessment = page.locator('.table-mode-form:visible').first();
	await expect(firstRequirementAssessment).toBeVisible();
	const evidenceTrigger = firstRequirementAssessment.getByTestId('evidence-accordion-trigger');
	await evidenceTrigger.click();
	const selectEvidenceButton = firstRequirementAssessment.getByTestId('select-evidence-button');
	await expect(selectEvidenceButton).toBeVisible();
	await selectEvidenceButton.click();

	const updateModal = page.getByTestId('modal-component');
	await expect(updateModal.getByTestId('modal-title')).toBeVisible();
	const evidenceField = updateModal.getByTestId('form-input-evidences');
	await evidenceField.click();
	await evidenceField.getByRole('combobox').fill(hiddenStatusEvidenceName);
	const evidenceOption = evidenceField
		.getByRole('option', { name: hiddenStatusEvidenceName })
		.first();
	await expect(evidenceOption).toBeVisible();
	await evidenceOption.click();
	await updateModal.getByTestId('save-button').click();

	await expect(updateModal).not.toBeVisible();
	await expect(firstRequirementAssessment.getByText(hiddenStatusEvidenceName)).toBeVisible();

	const appliedControlTrigger = firstRequirementAssessment.getByTestId(
		'applied-control-accordion-trigger'
	);
	await appliedControlTrigger.click();
	const selectAppliedControlsButton = firstRequirementAssessment.getByTestId(
		'select-applied-controls-button'
	);
	await expect(selectAppliedControlsButton).toBeVisible();
	await selectAppliedControlsButton.click();

	await expect(updateModal.getByTestId('modal-title')).toBeVisible();
	const appliedControlsField = updateModal.getByTestId('form-input-applied_controls');
	await appliedControlsField.click();
	await appliedControlsField.getByRole('combobox').fill(vars.appliedControlName);
	const appliedControlOption = appliedControlsField
		.getByRole('option', { name: vars.appliedControlName })
		.first();
	await expect(appliedControlOption).toBeVisible();
	await appliedControlOption.click();
	await updateModal.getByTestId('save-button').click();

	await expect(updateModal).not.toBeVisible();
	await expect(firstRequirementAssessment.getByText(vars.appliedControlName)).toBeVisible();

	await setVisibility('evidences', READ_ONLY);
	await setVisibility('applied_controls', READ_ONLY);
	await page.goto(`${auditDetailUrl}/table-mode`);

	const readOnlyRequirementAssessment = page.locator('.table-mode-form:visible').first();
	await expect(readOnlyRequirementAssessment).toBeVisible();
	const readOnlyEvidenceTrigger = readOnlyRequirementAssessment.getByTestId(
		'evidence-accordion-trigger'
	);
	await readOnlyEvidenceTrigger.click();
	await expect(
		readOnlyRequirementAssessment.getByTestId('evidence-link').filter({
			hasText: hiddenStatusEvidenceName
		})
	).toBeVisible();
	await expect(readOnlyRequirementAssessment.getByTestId('create-evidence-button')).toHaveCount(0);
	await expect(readOnlyRequirementAssessment.getByTestId('select-evidence-button')).toHaveCount(0);

	const readOnlyAppliedControlTrigger = readOnlyRequirementAssessment.getByTestId(
		'applied-control-accordion-trigger'
	);
	await readOnlyAppliedControlTrigger.click();
	await expect(
		readOnlyRequirementAssessment.getByTestId('applied-control-link').filter({
			hasText: vars.appliedControlName
		})
	).toBeVisible();
	await expect(
		readOnlyRequirementAssessment.getByTestId('create-applied-control-button')
	).toHaveCount(0);
	await expect(
		readOnlyRequirementAssessment.getByTestId('select-applied-controls-button')
	).toHaveCount(0);
});

test.afterAll('cleanup', async ({ browser }) => {
	const page = await browser.newPage();
	const loginPage = new LoginPage(page);
	const foldersPage = new PageContent(page, '/folders', 'Domains');

	await loginPage.goto();
	await loginPage.login();
	await foldersPage.goto();
	await foldersPage.deleteItemButton(vars.folderName).click();
	await expect(foldersPage.deletePromptConfirmTextField()).toBeVisible();
	await foldersPage.deletePromptConfirmTextField().fill(m.yes());
	await foldersPage.deletePromptConfirmButton().click();
	await expect(foldersPage.getRow(vars.folderName)).not.toBeVisible();
});
