import type { Page } from '@playwright/test';
import { m } from '$paraglide/messages.js';
import { FormContent, FormFieldType } from '../../utils/form-content.js';
import { LoginPage } from '../../utils/login-page.js';
import { PageContent } from '../../utils/page-content.js';
import { expect, test, TestContent } from '../../utils/test-utils.js';
import { mappingPrerequisites } from '../../utils/test-data.js';
import { exactNamedObjectRow } from '../../utils/exact-named-object-row.js';
import {
	auditFrameworkUuid,
	expandedAuditTreeItem,
	isAuditDetailUrl,
	reopenAuditDetail,
	waitForAuditDetail
} from '../../utils/audit-navigation.js';

const vars = TestContent.generateTestVars();
const testObjectsData: { [k: string]: any } = TestContent.itemBuilder(vars);
const FOLDER_WORKAROUND_SUFFIX = ' foo';
const BACKEND_API_URL = process.env.PUBLIC_BACKEND_API_URL ?? 'http://localhost:8000/api';
// Each serial scenario gets a new page; retain only verified resource URLs.
let sourceAssessmentDetailUrl: string | undefined;
let mappedAssessmentDetailUrl: string | undefined;
let pullTargetAssessmentDetailUrl: string | undefined;

const pullTargetName = 'PullTarget-' + vars.assessmentName;

// The target is excluded from the picker and the mapped source name is unique.
// The serial repeat uses a fresh page, not the first application's UI state.
async function openMapFromPreview(
	page: Page,
	complianceAssessmentsPage: PageContent,
	targetDetailUrl: string
) {
	await complianceAssessmentsPage.goto();
	await complianceAssessmentsPage.hasUrl();
	await complianceAssessmentsPage.viewItemDetail(pullTargetName);
	await expect(page).toHaveURL(targetDetailUrl);
	await page.getByTestId('apply-mapping-button').click();
	await page.getByTestId('map-from-audit-card').click();
	const mapFromForm = new FormContent(page, m.mapFromAudit(), [
		{ name: 'source_audit', type: FormFieldType.SELECT_AUTOCOMPLETE }
	]);
	await mapFromForm.hasTitle();
	await mapFromForm.fill({ source_audit: 'Mapped-' + vars.assessmentName });
	await page.getByTestId('map-from-submit-button').click();
	await page.waitForURL(/map-from-preview/);
}

test.describe.configure({ mode: 'serial' });

test('user can import required libraries and create required objects', async ({
	page,
	logedPage,
	foldersPage,
	librariesPage
}) => {
	await test.step('create required folder', async () => {
		await foldersPage.goto();
		await foldersPage.hasUrl();
		await foldersPage.createItem({
			name: vars.folderName,
			description: vars.description
		});
		// NOTE: creating one more folder not to trip up the autocomplete test utils
		await foldersPage.createItem({
			name: vars.folderName + FOLDER_WORKAROUND_SUFFIX,
			description: vars.description
		});
	});

	await test.step('import iso27001-2022 and csf-1.1', async () => {
		await librariesPage.goto();
		await librariesPage.hasUrl();
		await librariesPage.importLibrary(
			'International standard ISO/IEC 27001:2022',
			'urn:intuitem:risk:framework:iso27001-2022'
		);
		await librariesPage.goto();
		await librariesPage.hasUrl();
		await librariesPage.importLibrary('NIST CSF v1.1', 'urn:intuitem:risk:library:nist-csf-1.1');
		// The standalone NIST -> ISO artifact has no implicit reverse edge.
		// Load the declared bidirectional Adobe artifacts through the native loader
		// to provide the original ISO -> Adobe -> NIST path within depth three.
		for (const library of [mappingPrerequisites.framework, ...mappingPrerequisites.libraries]) {
			await librariesPage.goto();
			await librariesPage.hasUrl();
			await librariesPage.importLibrary(library.name, library.urn);
		}
	});
});

test('user can create and persist a scored iso27001-2022 audit', async ({
	page,
	logedPage,
	complianceAssessmentsPage
}) => {
	const OrgContextScore = {
		value: 75 / 5 + 1,
		progress: '75'
	};

	const scoreProgress = page.getByTestId('score-field').getByTestId('progress-ring-svg');

	await test.step('create and score iso27001-2022 audit', async () => {
		await complianceAssessmentsPage.goto();
		await complianceAssessmentsPage.hasUrl();
		await complianceAssessmentsPage.createItem({
			name: vars.assessmentName,
			description: vars.description,
			folder: vars.folderName,
			framework: 'International standard ISO/IEC 27001:2022'
		});

		// Enable scoring on the compliance assessment
		await page.getByTestId('edit-button').click();
		await page.getByText('More').click();
		for (const spinner of await page.locator('.loading-spinner').all()) {
			await expect(spinner).not.toBeVisible({
				timeout: 10_000
			});
		}
		await page.getByTestId('visibility-score-everyone').click();
		await page.getByTestId('save-button').click();
		sourceAssessmentDetailUrl = await waitForAuditDetail(page);

		await page.waitForTimeout(5000);

		const OrgContextTree = await expandedAuditTreeItem(
			page,
			complianceAssessmentsPage.itemDetail,
			'4.1 - Understanding the organization and its context',
			['core - Clauses', '4 - Context of the organization']
		);
		await OrgContextTree.content.click();

		await page.waitForURL(/\/requirement-assessments\/[^/]+\/edit(?:\?.*)?$/);
		await expect(scoreProgress).toBeVisible();
		await expect(scoreProgress).toHaveAttribute('data-value', '0');

		await page.getByTestId('form-input-result').selectOption('compliant');

		const slider = page.getByTestId('score-field').getByTestId('range-slider-input');
		await expect(slider).toBeVisible();
		await slider.focus();
		for (let i = 1; i < OrgContextScore.value; i++) {
			await slider.press('ArrowRight');
		}
		await expect(scoreProgress).toHaveAttribute('data-value', '75');

		await page.getByTestId('save-no-continue-button').click();
		await complianceAssessmentsPage.isToastVisible('successfully saved', 'i');
		await reopenAuditDetail(page, sourceAssessmentDetailUrl);
		const refreshedOrgContextTree = await expandedAuditTreeItem(
			page,
			complianceAssessmentsPage.itemDetail,
			'4.1 - Understanding the organization and its context',
			['core - Clauses', '4 - Context of the organization']
		);
		await expect(refreshedOrgContextTree.progressRadial).toHaveAttribute(
			'data-value',
			OrgContextScore.progress
		);
	});
});

test('user can map iso27001-2022 audit to a new csf-1.1 audit', async ({
	page,
	logedPage,
	complianceAssessmentsPage
}) => {
	const sourceDetailUrl = sourceAssessmentDetailUrl;
	if (!sourceDetailUrl || !isAuditDetailUrl(sourceDetailUrl)) {
		throw new Error('The preceding serial scenario did not retain an exact source audit URL');
	}
	await reopenAuditDetail(page, sourceDetailUrl);
	const IDAM1Score = {
		ratio: 0.66,
		progress: '75',
		value: 1
	};
	const applyMappingButton = page.getByTestId('apply-mapping-button');
	const scoreProgress = page.getByTestId('score-field').getByTestId('progress-ring-svg');

	//NOTE: The form fields can't be passed to the PageContent constructor because the form is not an usual one
	const applyMappingForm = new FormContent(page, 'Create audit from baseline', [
		{ name: 'name', type: FormFieldType.TEXT },
		{ name: 'description', type: FormFieldType.TEXT },
		{ name: 'folder', type: FormFieldType.SELECT_AUTOCOMPLETE },
		{ name: 'framework', type: FormFieldType.SELECT_AUTOCOMPLETE }
	]);

	await test.step('apply mapping to new csf 1.1 audit', async () => {
		//NOTE: imitates PageContent.createItem(), since our form is not a "classic"" one
		// This could be improved
		await applyMappingButton.click();
		// "Apply mapping" now opens a direction chooser; pick "Map to a framework"
		// (create a new audit) to reach the create form.
		await page.getByTestId('map-to-framework-card').click();
		await applyMappingForm.hasTitle();
		if (page) {
			await page.waitForLoadState('networkidle');
		}
		await applyMappingForm.fill({
			name: 'Mapped-' + vars.assessmentName,
			description: vars.description,
			folder: vars.folderName,
			framework: vars.framework.name
		});
		// Enable scoring on the new CA via the visibility editor in the modal.
		// (The More dropdown is auto-expanded by form.fill() above.)
		await page.getByTestId('visibility-score-everyone').click();
		await applyMappingForm.saveButton.click();
		await expect(applyMappingForm.formTitle).not.toBeVisible();
		await complianceAssessmentsPage.isToastVisible(
			'The audit object has been successfully created',
			'i'
		);
		// A source detail already satisfies the generic pathname predicate while
		// the new target's SPA navigation is still pending. Wait for a new UUID.
		mappedAssessmentDetailUrl = await waitForAuditDetail(page, sourceDetailUrl);
		const mappedId = new URL(mappedAssessmentDetailUrl).pathname.split('/').at(-1);
		expect(mappedId).toMatch(/^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/i);
		const token = (await page.context().cookies()).find((cookie) => cookie.name === 'token')?.value;
		if (!token) throw new Error('The logged-in browser did not expose its API token cookie');
		const headers = { Authorization: `Token ${token}` };
		const targetResponse = await page.request.get(
			`${BACKEND_API_URL}/compliance-assessments/${mappedId}/`,
			{ headers }
		);
		expect(targetResponse.status()).toBe(200);
		const target = await targetResponse.json();
		expect(target.id).toBe(mappedId);
		expect(target.name).toBe('Mapped-' + vars.assessmentName);
		const targetFrameworkId = auditFrameworkUuid(target.framework);
		expect(targetFrameworkId).toMatch(/^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/i);
		expect(target.framework.urn).toBe('urn:intuitem:risk:framework:nist-csf-1.1');
		const frameworkResponse = await page.request.get(
			`${BACKEND_API_URL}/frameworks/${targetFrameworkId}/`,
			{ headers }
		);
		expect(frameworkResponse.status()).toBe(200);
		expect(await frameworkResponse.json()).toMatchObject({
			id: targetFrameworkId,
			urn: 'urn:intuitem:risk:framework:nist-csf-1.1',
			name: vars.framework.name
		});
	});
	const mappedDetailUrl = mappedAssessmentDetailUrl;
	if (!mappedDetailUrl || !isAuditDetailUrl(mappedDetailUrl)) {
		throw new Error('The mapping did not retain an exact target audit URL');
	}
	await test.step('verify that mapping worked correctly', async () => {
		const IDAM1TreeViewItem = await expandedAuditTreeItem(
			page,
			complianceAssessmentsPage.itemDetail,
			'ID.AM-1',
			['ID - Identify', 'ID.AM - Asset Management']
		);
		await IDAM1TreeViewItem.content.click();

		await page.waitForURL(/\/requirement-assessments\/[^/]+\/edit(?:\?.*)?$/);
		for (const spinner of await page.locator('.loading-spinner').all()) {
			await expect(spinner).not.toBeVisible({
				timeout: 10_000
			});
		}

		await expect(scoreProgress).toBeVisible();
		await expect(scoreProgress).toHaveAttribute('data-value', IDAM1Score.value.toString());

		await page.getByTestId('save-no-continue-button').click();
		await complianceAssessmentsPage.isToastVisible('successfully saved', 'i');
		await reopenAuditDetail(page, mappedDetailUrl);

		// ID.AM-1 above is unmapped and retains its default score. Also prove a
		// non-default result actually traversed the declared ISO -> Adobe -> NIST
		// path: ISO 4.1 -> Adobe RM-02 -> NIST ID.RM-1 uses intersect mappings.
		const mappedRiskStrategy = await expandedAuditTreeItem(
			page,
			complianceAssessmentsPage.itemDetail,
			'ID.RM-1'
		);
		await mappedRiskStrategy.content.click();
		await page.waitForURL(/\/requirement-assessments\/[^/]+\/edit(?:\?.*)?$/);
		await expect(page.getByTestId('form-input-result')).toHaveValue('partially_compliant');
		await reopenAuditDetail(page, mappedDetailUrl);
	});
});

test('user can map from an audit into an empty target', async ({
	page,
	logedPage,
	complianceAssessmentsPage
}) => {
	const mappedDetailUrl = mappedAssessmentDetailUrl;
	if (!mappedDetailUrl || !isAuditDetailUrl(mappedDetailUrl)) {
		throw new Error('The preceding serial scenario did not retain an exact mapped audit URL');
	}
	await reopenAuditDetail(page, mappedDetailUrl);

	// Map-from = inbound direction (pull a source audit's results INTO the
	// current one). We create a fresh, empty target audit and pull the
	// previously-mapped audit into it twice: the first pull applies the data
	// (changes exist -> confirm), the second is a no-op (idempotent -> the
	// no-changes notice shows and confirmation is disabled).
	await test.step('create an empty target audit for map-from', async () => {
		await complianceAssessmentsPage.goto();
		await complianceAssessmentsPage.hasUrl();
		await complianceAssessmentsPage.createItem({
			name: pullTargetName,
			description: vars.description,
			folder: vars.folderName,
			framework: vars.framework.name
		});
		pullTargetAssessmentDetailUrl = await waitForAuditDetail(page, mappedDetailUrl);

		// Enable scoring so the target accepts scored data from the source.
		await page.getByTestId('edit-button').click();
		await page.getByText('More').click();
		for (const spinner of await page.locator('.loading-spinner').all()) {
			await expect(spinner).not.toBeVisible({
				timeout: 10_000
			});
		}
		await page.getByTestId('visibility-score-everyone').click();
		await page.getByTestId('save-button').click();
		await page.waitForTimeout(5000);
	});
	const targetDetailUrl = pullTargetAssessmentDetailUrl;
	if (!targetDetailUrl || !isAuditDetailUrl(targetDetailUrl)) {
		throw new Error('Creating the empty target did not retain an exact audit detail URL');
	}

	await test.step('map from into the empty target: changes are applied', async () => {
		await openMapFromPreview(page, complianceAssessmentsPage, targetDetailUrl);
		// The target is empty, so the mapping produces changes and confirm is enabled.
		await expect(page.getByTestId('confirm-mapping-button')).toBeEnabled();
		await page.getByTestId('confirm-mapping-button').click();
		await page.waitForURL(isAuditDetailUrl);
		await expect(page).toHaveURL(targetDetailUrl);
		await complianceAssessmentsPage.isToastVisible('updated successfully', 'i');
	});
});

test('reapplying inbound audit mapping makes no changes', async ({
	page,
	logedPage,
	complianceAssessmentsPage
}) => {
	const targetDetailUrl = pullTargetAssessmentDetailUrl;
	if (!targetDetailUrl || !isAuditDetailUrl(targetDetailUrl)) {
		throw new Error('The preceding serial scenario did not retain an exact pull target audit URL');
	}
	await reopenAuditDetail(page, targetDetailUrl);

	await test.step('map from again: no change (idempotent)', async () => {
		await openMapFromPreview(page, complianceAssessmentsPage, targetDetailUrl);
		// The target now mirrors the source, so nothing would change: the
		// no-changes notice shows and confirmation is disabled.
		await expect(page.getByTestId('map-from-no-changes')).toBeVisible();
		await expect(page.getByTestId('confirm-mapping-button')).toBeDisabled();
	});
});

async function deleteFolder(foldersPage: PageContent, folderName: string) {
	const exactRow = await exactNamedObjectRow(foldersPage.page, folderName, m.name());
	await expect(exactRow).toHaveCount(1);
	await exactRow.getByTestId('tablerow-delete-button').click();
	await expect(foldersPage.deletePromptConfirmTextField()).toBeVisible();
	await foldersPage.deletePromptConfirmTextField().fill(m.yes());
	await foldersPage.deletePromptConfirmButton().click();
	await expect(exactRow).toHaveCount(0);
	return exactRow;
}

test.afterAll('cleanup', async ({ browser }) => {
	const page = await browser.newPage();
	const loginPage = new LoginPage(page);
	const foldersPage = new PageContent(page, '/folders', 'Domains');

	await loginPage.goto();
	await loginPage.login();
	await foldersPage.goto();

	const baseRow = await deleteFolder(foldersPage, vars.folderName);
	const workaroundRow = await deleteFolder(foldersPage, vars.folderName + FOLDER_WORKAROUND_SUFFIX);

	await expect(baseRow).toHaveCount(0);
	await expect(workaroundRow).toHaveCount(0);
	await page.close();
});
