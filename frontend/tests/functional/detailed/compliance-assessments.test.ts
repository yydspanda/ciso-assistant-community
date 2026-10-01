import { LoginPage } from '../../utils/login-page.js';
import { PageContent } from '../../utils/page-content.js';
import { TestContent, test, expect } from '../../utils/test-utils.js';
import { m } from '$paraglide/messages';
import type { Locator } from '@playwright/test';
import {
	expandedAuditTreeItem,
	isAuditDetailUrl,
	reopenAuditDetail,
	waitForAuditDetail
} from '../../utils/audit-navigation.js';

let vars = TestContent.generateTestVars();
let testObjectsData: { [k: string]: any } = TestContent.itemBuilder(vars);

const BACKEND_API_URL = process.env.PUBLIC_BACKEND_API_URL ?? 'http://localhost:8000/api';

test.describe.configure({ mode: 'serial' });

test('compliance assessments scoring is working properly', async ({
	logedPage,
	pages,
	complianceAssessmentsPage,
	page
}) => {
	test.setTimeout(10 * 60 * 1000);
	const testRequirements = ['folders', 'perimeters', 'complianceAssessments'];
	const minScore = 1;
	const maxScore = 4;
	const IDAM1Score = {
		ratio: 0.66,
		value: 3
	};
	const IDAM2Score = {
		ratio: 0.33,
		value: 2
	};
	const IDBE1Score = {
		ratio: 0.99,
		value: 4
	};
	const PRAC1Score = {
		ratio: 0.0,
		value: 1
	};
	const scoreProgress = page.getByTestId('score-field').getByTestId('progress-ring-svg');
	const scoreSlider = page.getByTestId('score-field').getByTestId('range-slider-input');
	const openRequirementAssessment = async (link: Locator) => {
		const href = await link.getAttribute('href');
		expect(href).toMatch(/^\/requirement-assessments\/[0-9a-f-]+\/edit(?:\?.*)?$/i);
		const response = await page.goto(href!, { waitUntil: 'domcontentloaded', timeout: 60_000 });
		expect(response?.ok()).toBe(true);
		await expect(page).toHaveURL(/\/requirement-assessments\/[^/]+\/edit(?:\?.*)?$/);
		// The minimum score can already match the SSR value. It must not let us
		// submit before Svelte enhances the form and preserves its structured answers.
		await page.locator('body[data-hydrated="true"]').waitFor({ state: 'attached' });
	};
	// Helper to convert raw score to percentage for tree view assertions
	const toPercent = (score: number) =>
		(((score - minScore) * 100) / (maxScore - minScore)).toString();

	for (let requirement of testRequirements) {
		requirement += 'Page';
		const requiredPage = pages[requirement];

		await requiredPage.goto();
		await requiredPage.hasUrl();

		await requiredPage.createItem(
			testObjectsData[requirement].build,
			'dependency' in testObjectsData[requirement] ? testObjectsData[requirement].dependency : null
		);

		await requiredPage.goto();
		await requiredPage.hasUrl();
	}

	await complianceAssessmentsPage.viewItemDetail(
		testObjectsData.complianceAssessmentsPage.build.name
	);

	// Enable scoring on the compliance assessment via the visibility editor
	// (auditor edit access on the score field).
	await page.getByTestId('edit-button').click();
	await page.getByText('More').click();
	await page.getByTestId('visibility-score-everyone').click();
	await page.getByTestId('save-button').click();
	const complianceAssessmentDetailUrl = await waitForAuditDetail(page);
	const reopenComplianceAssessment = () => reopenAuditDetail(page, complianceAssessmentDetailUrl);

	// Click on the ID.AM-1 tree view item
	const IDAM1TreeViewItem = await expandedAuditTreeItem(
		page,
		complianceAssessmentsPage.itemDetail,
		'ID.AM-1',
		['ID - Identify', 'ID.AM - Asset Management']
	);
	await openRequirementAssessment(IDAM1TreeViewItem.content.getByRole('link'));
	await expect(scoreProgress).toBeVisible({ timeout: 60_000 });
	await expect(scoreProgress).toHaveAttribute('data-value', '1');

	const IDAM1SliderBoundingBox = await scoreSlider.boundingBox();
	IDAM1SliderBoundingBox &&
		(await scoreSlider.click({
			position: {
				x: IDAM1SliderBoundingBox.width * IDAM1Score.ratio,
				y: IDAM1SliderBoundingBox.height / 2
			}
		}));
	await expect(scoreProgress).toHaveAttribute('data-value', IDAM1Score.value.toString());

	const firstRequirementAssessmentUrl = page.url();
	await page.getByTestId('save-no-continue-button').click();
	await complianceAssessmentsPage.isToastVisible('successfully saved', 'i');

	// The stay choice is submission-local. Without remounting this page, the
	// primary Save/Next button must redirect instead of inheriting stay mode.
	const saveNextNavigation = page.waitForURL(
		(url) =>
			/\/requirement-assessments\/[^/]+\/edit(?:\?.*)?$/.test(url.pathname + url.search) &&
			url.href !== firstRequirementAssessmentUrl
	);
	await page.getByTestId('save-button').click();
	await saveNextNavigation;
	await reopenComplianceAssessment();
	await expect(page.getByRole('link', { name: 'ID.AM-1', exact: true })).toBeVisible({
		timeout: 60_000
	});
	const refreshedIDAM1TreeViewItem = await expandedAuditTreeItem(
		page,
		complianceAssessmentsPage.itemDetail,
		'ID.AM-1',
		['ID - Identify', 'ID.AM - Asset Management']
	);
	await expect(refreshedIDAM1TreeViewItem.progressRadial).toHaveAttribute(
		'data-value',
		toPercent(IDAM1Score.value)
	);

	// Click on the ID.AM-2 tree view item
	const IDAM2TreeViewItem = await expandedAuditTreeItem(
		page,
		complianceAssessmentsPage.itemDetail,
		'ID.AM-2',
		['ID - Identify', 'ID.AM - Asset Management']
	);
	await openRequirementAssessment(IDAM2TreeViewItem.content.getByRole('link'));
	await expect(scoreProgress).toBeVisible({ timeout: 60_000 });
	await expect(scoreProgress).toHaveAttribute('data-value', '1');

	const IDAM2SliderBoundingBox = await scoreSlider.boundingBox();
	IDAM2SliderBoundingBox &&
		(await scoreSlider.click({
			position: {
				x: IDAM2SliderBoundingBox.width * IDAM2Score.ratio,
				y: IDAM2SliderBoundingBox.height / 2
			}
		}));
	await expect(scoreProgress).toHaveAttribute('data-value', IDAM2Score.value.toString());

	await page.getByTestId('save-no-continue-button').click();
	await complianceAssessmentsPage.isToastVisible('successfully saved', 'i');
	await reopenComplianceAssessment();
	const refreshedIDAM2TreeViewItem = await expandedAuditTreeItem(
		page,
		complianceAssessmentsPage.itemDetail,
		'ID.AM-2',
		['ID - Identify', 'ID.AM - Asset Management']
	);
	await expect(refreshedIDAM2TreeViewItem.progressRadial).toHaveAttribute(
		'data-value',
		toPercent(IDAM2Score.value)
	);

	// Click on the ID.BE-1 tree view item
	const IDBE1TreeViewItem = await expandedAuditTreeItem(
		page,
		complianceAssessmentsPage.itemDetail,
		'ID.BE-1',
		['ID - Identify', 'ID.BE - Business Environment']
	);
	await openRequirementAssessment(IDBE1TreeViewItem.content.getByRole('link'));
	await expect(scoreProgress).toBeVisible({ timeout: 60_000 });
	await expect(scoreProgress).toHaveAttribute('data-value', '1');

	const IDBE1SliderBoundingBox = await scoreSlider.boundingBox();
	IDBE1SliderBoundingBox &&
		(await scoreSlider.click({
			position: {
				x: IDBE1SliderBoundingBox.width * IDBE1Score.ratio,
				y: IDBE1SliderBoundingBox.height / 2
			}
		}));
	await expect(scoreProgress).toHaveAttribute('data-value', IDBE1Score.value.toString());

	await page.getByTestId('save-no-continue-button').click();
	await complianceAssessmentsPage.isToastVisible('successfully saved', 'i');
	await reopenComplianceAssessment();
	const refreshedIDBE1TreeViewItem = await expandedAuditTreeItem(
		page,
		complianceAssessmentsPage.itemDetail,
		'ID.BE-1',
		['ID - Identify', 'ID.BE - Business Environment']
	);
	await expect(refreshedIDBE1TreeViewItem.progressRadial).toHaveAttribute(
		'data-value',
		toPercent(IDBE1Score.value)
	);

	// Click on the PR.AC-1 tree view item
	const PRAC1TreeViewItem = await expandedAuditTreeItem(
		page,
		complianceAssessmentsPage.itemDetail,
		'PR.AC-1',
		['PR - Protect', 'PR.AC - Identity Management, Authentication and Access Control']
	);
	await openRequirementAssessment(PRAC1TreeViewItem.content.getByRole('link'));
	await expect(scoreProgress).toBeVisible({ timeout: 60_000 });
	await expect(scoreProgress).toHaveAttribute('data-value', '1');

	const PRAC1SliderBoundingBox = await scoreSlider.boundingBox();
	PRAC1SliderBoundingBox &&
		(await scoreSlider.click({
			position: {
				x: PRAC1SliderBoundingBox.width * PRAC1Score.ratio,
				y: PRAC1SliderBoundingBox.height / 2
			}
		}));
	await expect(scoreProgress).toHaveAttribute('data-value', PRAC1Score.value.toString());

	await page.getByTestId('save-no-continue-button').click();
	await complianceAssessmentsPage.isToastVisible('successfully saved', 'i');
	await reopenComplianceAssessment();
	const refreshedPRAC1TreeViewItem = await expandedAuditTreeItem(
		page,
		complianceAssessmentsPage.itemDetail,
		'PR.AC-1',
		['PR - Protect', 'PR.AC - Identity Management, Authentication and Access Control']
	);
	await expect(refreshedPRAC1TreeViewItem.progressRadial).toHaveAttribute(
		'data-value',
		toPercent(PRAC1Score.value)
	);

	// Note: section-level and global score aggregation assertions are not included here
	// because enabling scoring_enabled bulk-sets is_scored=True on ALL requirement
	// assessments in the framework (not just the 4 tested above). Score calculation
	// correctness is covered by backend unit tests in test_compliance_assessment_scoring.py.
});

test('cloning an audit proposes and persists its same-framework custom score scale', async ({
	logedPage,
	complianceAssessmentsPage,
	page,
	context
}) => {
	test.setTimeout(5 * 60 * 1000);
	expect(logedPage).toBeDefined();

	await complianceAssessmentsPage.goto();
	await complianceAssessmentsPage.hasUrl();
	await complianceAssessmentsPage.viewItemDetail(
		testObjectsData.complianceAssessmentsPage.build.name
	);
	await page.locator('body[data-hydrated="true"]').waitFor();

	const baselineUrl = page.url();
	const baselineId = new URL(baselineUrl).pathname.split('/').filter(Boolean).at(-1);
	if (!baselineId) throw new Error(`Could not resolve baseline UUID from ${baselineUrl}`);
	expect(baselineId).toMatch(/^[0-9a-f-]{36}$/i);

	const token = (await context.cookies()).find((cookie) => cookie.name === 'token')?.value;
	if (!token) throw new Error('The logged-in browser did not expose its API token cookie');
	const headers = {
		'Content-Type': 'application/json',
		Authorization: `Token ${token}`
	};
	const customScale = {
		score_scale_preset: null,
		min_score: 1,
		max_score: 3,
		scores_definition: [
			{ score: 1, name: 'Initial' },
			{ score: 2, name: 'Managed' },
			{ score: 3, name: 'Optimized' }
		]
	};
	const everyone = { auditor: 'edit', respondent: 'edit' };
	const auditorOnly = { auditor: 'edit', respondent: 'hidden' };
	const baselineCopyFields = [
		'result',
		'status',
		'score',
		'is_scored',
		'documentation_score',
		'observation',
		'applied_controls',
		'evidences'
	] as const;
	// Only these four fields use the native EVERYONE_EDIT fallback when absent
	// from the snapshot. Score fields default to hidden and must be explicit.
	const defaultEditableCopyFields: readonly string[] = [
		'result',
		'observation',
		'applied_controls',
		'evidences'
	];

	const seedResponse = await page.request.patch(
		`${BACKEND_API_URL}/compliance-assessments/${baselineId}/`,
		{
			headers,
			data: {
				...customScale,
				confirm_rescale: true,
				field_visibility: {
					score: everyone,
					is_scored: everyone,
					// Same-framework copying requires auditor read access on both audits.
					// Keep the synthetic documentation score hidden from respondents.
					documentation_score: auditorOnly
				}
			}
		}
	);
	const baselineBody = await seedResponse.text();
	expect(
		seedResponse.ok(),
		`baseline scale PATCH failed: ${seedResponse.status()} ${baselineBody}`
	).toBeTruthy();
	const baseline = JSON.parse(baselineBody);
	expect(baseline).toMatchObject(customScale);
	expect(baseline.field_visibility).toMatchObject({
		score: everyone,
		is_scored: everyone,
		documentation_score: auditorOnly
	});
	for (const field of baselineCopyFields) {
		const auditorVisibility =
			baseline.field_visibility?.[field]?.auditor ??
			(defaultEditableCopyFields.includes(field) ? 'edit' : undefined);
		expect(['read', 'edit'], `baseline ${field}`).toContain(auditorVisibility);
	}

	const globalScoreResponse = await page.request.get(
		`${BACKEND_API_URL}/compliance-assessments/${baselineId}/global_score/`,
		{ headers }
	);
	const globalScoreBody = await globalScoreResponse.text();
	expect(
		globalScoreResponse.ok(),
		`baseline global_score failed: ${globalScoreResponse.status()} ${globalScoreBody}`
	).toBeTruthy();
	const globalScore = JSON.parse(globalScoreBody);
	expect(globalScore).toMatchObject({ scoring_enabled: true, ...customScale });

	await page.goto(baselineUrl);
	await page.locator('body[data-hydrated="true"]').waitFor();
	await page.getByTestId('clone-audit-button').click();

	const modal = page.getByTestId('modal-component');
	await expect(modal.getByTestId('modal-title')).toHaveText(m.cloneAudit());
	await expect(modal.getByTestId('form-input-framework')).toContainText(vars.framework.name);

	const cloneName = `${vars.assessmentName} custom-scale clone`;
	await modal.getByTestId('form-input-name').fill(cloneName);

	const folderField = modal.getByTestId('form-input-folder');
	if (!(await folderField.getByRole('button').first().innerText()).includes(vars.folderName)) {
		await folderField.getByRole('button').first().click();
		await folderField.getByRole('textbox').fill(vars.folderName);
		await folderField.getByRole('option').filter({ hasText: vars.folderName }).first().click();
	}

	await modal
		.locator('[data-scope="accordion"][data-part="item-trigger"]')
		.filter({ hasText: m.more() })
		.click();
	const scoreEveryone = modal.getByTestId('visibility-score-everyone');
	if ((await scoreEveryone.getAttribute('aria-checked')) !== 'true') await scoreEveryone.click();
	const documentationScoreAuditor = modal.getByTestId('visibility-documentation_score-auditor');
	await expect(documentationScoreAuditor).toBeVisible();
	if ((await documentationScoreAuditor.getAttribute('aria-checked')) !== 'true') {
		await documentationScoreAuditor.click();
	}
	await expect(documentationScoreAuditor).toHaveAttribute('aria-checked', 'true');

	await expect(modal.getByTestId('score-scale-scoring-hidden')).toHaveCount(0);
	const baselineOption = modal.getByTestId('score-scale-baseline');
	await expect(baselineOption).toBeVisible({ timeout: 30_000 });
	await expect(baselineOption).toHaveAttribute('aria-checked', 'true');
	await expect(modal.getByTestId('score-scale-preview')).toContainText(/1\s*Initial/);
	await expect(modal.getByTestId('score-scale-preview')).toContainText(/2\s*Managed/);
	await expect(modal.getByTestId('score-scale-preview')).toContainText(/3\s*Optimized/);

	await Promise.all([
		page.waitForURL((url) => isAuditDetailUrl(url) && !url.pathname.endsWith(`/${baselineId}`), {
			timeout: 60_000
		}),
		modal.getByTestId('save-button').click()
	]);

	const cloneId = new URL(page.url()).pathname.split('/').filter(Boolean).at(-1);
	if (!cloneId) throw new Error(`Could not resolve clone UUID from ${page.url()}`);
	expect(cloneId).toMatch(/^[0-9a-f-]{36}$/i);
	const cloneResponse = await page.request.get(
		`${BACKEND_API_URL}/compliance-assessments/${cloneId}/`,
		{ headers }
	);
	const cloneBody = await cloneResponse.text();
	expect(
		cloneResponse.ok(),
		`clone detail failed: ${cloneResponse.status()} ${cloneBody}`
	).toBeTruthy();
	const clone = JSON.parse(cloneBody);
	expect(clone.name).toBe(cloneName);
	expect(clone.framework?.id).toBe(baseline.framework?.id);
	expect(clone).toMatchObject(customScale);
	expect(clone.field_visibility).toMatchObject({ documentation_score: auditorOnly });
	for (const field of baselineCopyFields) {
		const auditorVisibility =
			clone.field_visibility?.[field]?.auditor ??
			(defaultEditableCopyFields.includes(field) ? 'edit' : undefined);
		expect(['read', 'edit'], `clone ${field}`).toContain(auditorVisibility);
	}
});

// Regression test for CA-1843: clicking the status/result badges used to be a
// dead zone, only the title/description text was clickable. Reuses the audit
// created by the test above.
test('clicking a requirement row status/result badges navigates to it', async ({
	logedPage,
	complianceAssessmentsPage,
	page
}) => {
	await complianceAssessmentsPage.goto();
	await complianceAssessmentsPage.hasUrl();
	await complianceAssessmentsPage.viewItemDetail(
		testObjectsData.complianceAssessmentsPage.build.name
	);

	const IDAM3TreeViewItem = await expandedAuditTreeItem(
		page,
		complianceAssessmentsPage.itemDetail,
		'ID.AM-3',
		['ID - Identify', 'ID.AM - Asset Management']
	);

	await expect(IDAM3TreeViewItem.badges).toBeVisible();
	await IDAM3TreeViewItem.badges.click();

	await page.waitForURL('/requirement-assessments/**');
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
