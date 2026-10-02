import type { Locator, Page } from '@playwright/test';
import { LoginPage } from '../../utils/login-page.js';
import { PageContent } from '../../utils/page-content.js';
import { TestContent, test, expect, getUniqueValue } from '../../utils/test-utils.js';
import { m } from '$paraglide/messages';
import { SideBar } from '../../utils/sidebar.js';
import { questionnaire } from '../../utils/test-data.js';
import { exactNamedObjectRow } from '../../utils/exact-named-object-row.js';

let vars = TestContent.generateTestVars();
let testObjectsData: { [k: string]: any } = TestContent.itemBuilder(vars);

test.describe.configure({ mode: 'serial' });

const entityAssessment = {
	name: 'Test entity assessment',
	// folder is inherited from the entity via initialData, no need to specify it
	create_audit: true,
	framework: vars.questionnaire.name,
	representatives: 'third-party@tests.com'
};

const BACKEND_API_URL = process.env.PUBLIC_BACKEND_API_URL ?? 'http://localhost:8000/api';
const TEMPLATE_READER_ROLE = 'CFGRC synthetic TPRM template reader 20260930';
const TEMPLATE_READ_PERMISSIONS = [
	'view_framework',
	'view_requirementnode',
	'view_question',
	'view_questionchoice'
];
const createdRoleAssignmentIds: string[] = [];

async function viewEntityWithReadyInitialTable(
	page: Page,
	entitiesPage: PageContent,
	name: string,
	expectedDetailUrl?: string
) {
	const row = await exactNamedObjectRow(page, name, m.name());
	const href = await row.getByTestId('tablerow-detail-button').getAttribute('href');
	if (!href) throw new Error('Expected the exact entity detail link');
	const detail = new URL(href, page.url());
	const match = detail.pathname.match(
		/^\/entities\/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$/i
	);
	if (
		detail.origin !== new URL(page.url()).origin ||
		!match ||
		detail.search ||
		detail.hash ||
		detail.username ||
		detail.password ||
		(expectedDetailUrl !== undefined && detail.href !== expectedDetailUrl)
	) {
		throw new Error('Expected a same-origin exact entity UUID detail URL');
	}
	async function navigate() {
		await row.getByTestId('tablerow-detail-button').click();
		entitiesPage.itemDetail.setItem(name);
		await page.waitForURL(detail.href);
	}
	// Register before navigation: an absent skeleton alone could mean the
	// first fetch has not started, or failed. Wait for this entity's real page.
	const [response] = await Promise.all([
		page.waitForResponse((response) => {
			const url = new URL(response.url());
			const limit = url.searchParams.get('limit');
			return (
				response.request().method() === 'GET' &&
				url.origin === detail.origin &&
				url.pathname === '/entity-assessments' &&
				url.searchParams.getAll('entity').length === 1 &&
				url.searchParams.get('entity') === match[1] &&
				url.searchParams.getAll('offset').length === 1 &&
				url.searchParams.get('offset') === '0' &&
				url.searchParams.getAll('limit').length === 1 &&
				limit !== null &&
				/^[1-9][0-9]*$/.test(limit)
			);
		}),
		navigate()
	]);
	await expect(page).toHaveURL(detail.href);
	expect(response.status()).toBe(200);
	expect(await response.finished()).toBeNull();
	const payload = await response.json();
	expect(Array.isArray(payload.results)).toBe(true);
	expect(Number.isInteger(payload.count) && payload.count >= 0).toBe(true);
	await page.locator('body[data-hydrated="true"]').waitFor({ state: 'attached' });
	const initialTab = page.getByRole('tab', { name: 'Entity assessments', exact: true });
	await expect(initialTab).toHaveAttribute('aria-selected', 'true');
	const panel = page.getByRole('tabpanel', { name: 'Entity assessments', exact: true });
	await expect(panel).toHaveCount(1);
	await expect(panel).toBeVisible();
	await expect(panel.getByRole('table')).toHaveCount(1);
	await expect(panel.getByTestId('row-skeleton')).toHaveCount(0);
	return detail.href;
}

type ApiList<T> = T[] | { results: T[] };
type RelatedObject = { id: string };
type TemplateReaderRole = {
	id: string;
	name: string;
	builtin: boolean;
	folder: RelatedObject;
	permissions: { str: string }[];
};
type RootFolder = { id: string; builtin: boolean; parent_folder: null };
type Respondent = { id: string; email: string; is_active: boolean; is_third_party: boolean };
type TemplateReadAssignment = {
	id: string;
	user: RelatedObject;
	user_group: null;
	role: RelatedObject;
	folder: RelatedObject;
	perimeter_folders: RelatedObject[];
	is_recursive: boolean;
};

async function adminAuthHeaders(page: Page) {
	const cookies = await page.context().cookies();
	const token = cookies.find((cookie) => cookie.name === 'token')?.value;
	if (!token) throw new Error('Admin session is required for the scoped questionnaire fixture');
	return { 'Content-Type': 'application/json', Authorization: `Token ${token}` };
}

async function fixtureApiGet<T>(page: Page, path: string): Promise<T> {
	const response = await page.request.get(`${BACKEND_API_URL}${path}`, {
		headers: await adminAuthHeaders(page)
	});
	expect(response.ok(), `GET ${path} failed with status ${response.status()}`).toBeTruthy();
	return response.json();
}

function listItems<T>(response: ApiList<T>): T[] {
	return Array.isArray(response) ? response : response.results;
}

async function grantQuestionnaireTemplateRead(page: Page) {
	// The backend test setup seeds this role because Community's role API is
	// read-only. Keep its Root template grant separate from native enclave IAM.
	const roots = listItems(
		await fixtureApiGet<ApiList<RootFolder>>(page, '/folders/?content_type=GL')
	);
	expect(roots).toHaveLength(1);
	const root = roots[0]!;
	expect(root.builtin).toBe(true);
	expect(root.parent_folder).toBeNull();
	const roles = listItems(
		await fixtureApiGet<ApiList<TemplateReaderRole>>(
			page,
			`/roles/?search=${encodeURIComponent(TEMPLATE_READER_ROLE)}`
		)
	).filter((role) => role.name === TEMPLATE_READER_ROLE);
	expect(roles, 'The backend synthetic template-reader fixture must be seeded').toHaveLength(1);
	const role = roles[0]!;
	expect(role.builtin).toBe(false);
	expect(role.folder.id).toBe(root.id);
	expect(role.permissions.map((permission) => permission.str).sort()).toEqual(
		[...TEMPLATE_READ_PERMISSIONS].sort()
	);
	const respondents = listItems(
		await fixtureApiGet<ApiList<Respondent>>(
			page,
			`/users/?search=${encodeURIComponent(entityAssessment.representatives)}`
		)
	).filter((user) => user.email === entityAssessment.representatives);
	expect(respondents).toHaveLength(1);
	const respondent = respondents[0]!;
	expect(respondent.is_active).toBe(true);
	expect(respondent.is_third_party).toBe(true);
	const response = await page.request.post(`${BACKEND_API_URL}/role-assignments/`, {
		headers: await adminAuthHeaders(page),
		data: {
			name: getUniqueValue('TPRM synthetic questionnaire template read'),
			folder: root.id,
			role: role.id,
			user: respondent.id,
			user_group: null,
			is_recursive: false,
			perimeter_folders: [root.id]
		}
	});
	expect(response.ok(), `Template assignment failed with status ${response.status()}`).toBeTruthy();
	const { id } = (await response.json()) as { id: string };
	createdRoleAssignmentIds.push(id);
	const assignment = await fixtureApiGet<TemplateReadAssignment>(page, `/role-assignments/${id}/`);
	expect(assignment.user.id).toBe(respondent.id);
	expect(assignment.user_group).toBeNull();
	expect(assignment.role.id).toBe(role.id);
	expect(assignment.folder.id).toBe(root.id);
	expect(assignment.is_recursive).toBe(false);
	expect(assignment.perimeter_folders.map((folder) => folder.id)).toEqual([root.id]);
}

test('user can create representatives, solutions and entity assessments inside entity', async ({
	logedPage,
	foldersPage,
	perimetersPage,
	entitiesPage,
	representativesPage,
	solutionsPage,
	usersPage,
	entityAssessmentsPage,
	librariesPage,
	complianceAssessmentsPage,
	sideBar,
	mailer,
	page
}) => {
	let entityDetailUrl: string | undefined;
	await test.step('create required folder', async () => {
		await foldersPage.goto();
		await foldersPage.hasUrl();
		await foldersPage.createItem({
			name: vars.folderName,
			description: vars.description
		});
		// NOTE: creating one more folder not to trip up the autocomplete test utils
		await foldersPage.createItem({
			name: vars.folderName + ' foo',
			description: vars.description
		});
	});

	await test.step('create required perimeter', async () => {
		await perimetersPage.goto();
		await perimetersPage.hasUrl();
		await perimetersPage.createItem({
			name: vars.perimeterName,
			description: vars.description,
			folder: vars.folderName,
			ref_id: 'R.1234',
			lc_status: 'Production'
		});
		await perimetersPage.createItem({
			name: vars.perimeterName + ' bar',
			description: vars.description,
			folder: vars.folderName,
			ref_id: 'R.12345',
			lc_status: 'Production'
		});
	});

	await test.step('import questionnaire', async () => {
		await librariesPage.goto();
		await librariesPage.hasUrl();
		await librariesPage.importLibrary(vars.questionnaire.name, vars.framework.urn);
	});

	await test.step('create entity', async () => {
		await entitiesPage.goto();
		await entitiesPage.hasUrl();
		await entitiesPage.createItem(testObjectsData.entitiesPage.build);
		entityDetailUrl = await viewEntityWithReadyInitialTable(
			page,
			entitiesPage,
			testObjectsData.entitiesPage.build.name
		);
	});

	await test.step('create solution', async () => {
		await page.getByRole('tab', { name: 'Solutions' }).click();
		await expect(page.getByRole('tab', { name: 'Solutions' })).toHaveAttribute(
			'aria-selected',
			'true'
		);
		await solutionsPage.createItem(
			{
				name: 'Test solution'
			},
			undefined,
			undefined,
			'solution'
		);
	});

	await test.step('create representative', async () => {
		await page.getByRole('tab', { name: 'Representatives' }).click();
		await expect(page.getByRole('tab', { name: 'Representatives' })).toHaveAttribute(
			'aria-selected',
			'true'
		);
		await representativesPage.createItem(
			{
				email: 'third-party@tests.com',
				entity: testObjectsData.entitiesPage.build.name,
				create_user: true
			},
			undefined,
			undefined,
			'representative'
		);
	});

	await test.step('verify that user was created alongside representative', async () => {
		await page.getByRole('tab', { name: 'Representatives' }).click();
		await expect(page.getByRole('tab', { name: 'Representatives' })).toHaveAttribute(
			'aria-selected',
			'true'
		);
		await representativesPage.viewItemDetail('third-party@tests.com');
		await expect(page.getByTestId('user-field-value')).not.toBeEmpty();
		await page.getByTestId('user-field-value').locator('a').first().click();
		await usersPage.hasUrl();
		await usersPage.hasTitle('third-party@tests.com');
	});

	await test.step('go back to entity detail', async () => {
		await entitiesPage.goto();
		if (!entityDetailUrl) throw new Error('The created entity detail URL was not retained');
		await viewEntityWithReadyInitialTable(
			page,
			entitiesPage,
			testObjectsData.entitiesPage.build.name,
			entityDetailUrl
		);
	});

	await test.step('create entity assessment', async () => {
		await page.getByRole('tab', { name: 'Entity assessments' }).click();
		await expect(page.getByRole('tab', { name: 'Entity assessments' })).toHaveAttribute(
			'aria-selected',
			'true'
		);
		await entityAssessmentsPage.createItem(
			entityAssessment,
			undefined,
			undefined,
			'entity assessment'
		);
	});

	await test.step('verify that user was redirected to newly created entity assessment', async () => {
		await entityAssessmentsPage.hasUrl();
		await entityAssessmentsPage.hasTitle(entityAssessment.name);
	});

	await test.step('check that audit was created', async () => {
		await expect(page.getByTestId('compliance-assessment-field-value')).not.toBeEmpty();
		await page.getByTestId('compliance-assessment-field-value').locator('a').first().click();
		await complianceAssessmentsPage.hasUrl();
		await complianceAssessmentsPage.hasTitle(entityAssessment.name);
	});

	await test.step('grant the respondent read-only access to Root questionnaire templates', async () => {
		await grantQuestionnaireTemplateRead(page);
	});

	await test.step('send questionnaire to third party representatives', async () => {
		await entityAssessmentsPage.goto();
		await entityAssessmentsPage.viewItemDetail(entityAssessment.name);
		await entityAssessmentsPage.hasUrl();
		await page.getByText(m.sendQuestionnaire()).click();
		await page.getByRole('button', { name: m.submit() }).click();
		await entityAssessmentsPage.isToastVisible(m.mailSuccessfullySent() + /.+/.source);
	});

	await test.step('check that third parties overview was updated', async () => {
		await page.goto('/analytics/tprm');
		await page.locator('body[data-hydrated="true"]').waitFor();
		await expect(page.locator('#page-title')).toHaveText('Overview');
		const cards = page.getByTestId('cards-list').locator('div');
		await expect(page.getByTestId('no-data-available')).not.toBeVisible();
		await expect(cards.first().getByTestId('provider')).toContainText(
			testObjectsData.entitiesPage.build.name,
			{
				ignoreCase: true
			}
		);
		await expect(cards.first().getByTestId('baseline')).toContainText(entityAssessment.framework, {
			ignoreCase: true
		});
	});

	await test.step('check that third parties overview cards can be flipped', async () => {
		const cards = page.getByTestId('cards-list').locator('div');
		const firstCard = cards.first();
		await expect(firstCard).toBeVisible();
		await expect(firstCard.getByTestId('flip-button-front')).toBeEnabled();
		await firstCard.getByTestId('flip-button-front').click();
		await expect(firstCard).toHaveClass(/rotate-x-180/);

		// flip back to front
		await firstCard.getByTestId('flip-button-back').click();
		await expect(firstCard).not.toHaveClass(/rotate-x-180/);
	});
});

test('third-party representative can set their password', async ({ sideBar, mailer, page }) => {
	test.slow();
	await test.step('set password and log in as third party representative', async () => {
		const welcomeMail = await mailer.getEmailBySubject('Welcome to CISO Assistant!');
		await welcomeMail.hasWelcomeEmailDetails();
		await welcomeMail.hasEmailRecipient('third-party@tests.com');

		await welcomeMail.open();
		const pagePromise = page.context().waitForEvent('page');
		await expect(mailer.emailContent.setPasswordButton).toBeVisible();
		await mailer.emailContent.setPasswordButton.click();
		const setPasswordPage = await pagePromise;
		await setPasswordPage.waitForLoadState();
		await expect(setPasswordPage).toHaveURL(
			(await mailer.emailContent.setPasswordButton.getAttribute('href')) ||
				'Set password link could not be found'
		);

		const setLoginPage = new LoginPage(setPasswordPage);
		await setLoginPage.newPasswordInput.fill(vars.thirdPartyUser.password);
		await setLoginPage.confirmPasswordInput.fill(vars.thirdPartyUser.password);
		if (
			setLoginPage.newPasswordInput.inputValue() !== vars.thirdPartyUser.password ||
			setLoginPage.confirmPasswordInput.inputValue() !== vars.thirdPartyUser.password
		) {
			await setLoginPage.newPasswordInput.fill(vars.thirdPartyUser.password);
			await setLoginPage.confirmPasswordInput.fill(vars.thirdPartyUser.password);
		}

		const passwordSetToast = setLoginPage.isToastVisible(
			'Your password has been successfully set. Welcome to CISO Assistant!',
			undefined,
			{ optional: true }
		);
		await setLoginPage.setPasswordButton.click();
		await passwordSetToast;

		await setLoginPage.login('third-party@tests.com', vars.thirdPartyUser.password);

		// third party user lands on auditee dashboard page
		await expect(setLoginPage.page).toHaveURL('/auditee-dashboard');

		// logout to prevent sessions conflicts
		const passwordPageSideBar = new SideBar(setPasswordPage);
		await passwordPageSideBar.logout();
	});
});

test('third-party representative can fill their assigned audit', async ({
	thirdPartyAuthenticatedPage,
	page
}) => {
	await test.step('third party representative lands on auditee dashboard', async () => {
		await expect(page).toHaveURL('/auditee-dashboard');
	});

	await test.step('third party representative can open their assigned audit', async () => {
		const assignedAuditCard = page.locator('.audit-card').filter({
			has: page.getByRole('heading', { name: entityAssessment.name, exact: true })
		});
		await expect(assignedAuditCard).toBeVisible();
		const assignmentLink = assignedAuditCard.locator('a[href^="/auditee-assessments/"]');
		await expect(assignmentLink).toBeVisible();
		await expect(assignmentLink).toHaveAttribute('href', /^\/auditee-assessments\/[0-9a-f-]+$/);
		await assignmentLink.click();
		await page.waitForURL('/auditee-assessments/**');
	});

	await test.step('third party respondent can fill questionnaire', async () => {
		const clickAndPause = async (locator: Locator) => {
			await locator.click();
			await page.waitForTimeout(1000); // workaround flakiness due to overlapping calls
		};

		// The API serializes parent_requirement as a nested object. Prove that the
		// client resolves it to the real non-assessable node instead of accidentally
		// skipping straight to the first answerable requirement.
		await expect(page.getByRole('heading', { name: 'ACCESS CONTROL', exact: true })).toBeVisible();
		await expect(page.getByRole('button', { name: 'Yes', exact: true })).toHaveCount(0);
		const nextButton = page.getByRole('button', { name: m.next() });
		await expect(nextButton).toBeVisible();
		await nextButton.click();
		await expect(
			page.getByRole('heading', {
				name: `${questionnaire.firstRequirement.ref} - ${questionnaire.firstRequirement.name}`,
				exact: true
			})
		).toBeVisible();
		await expect(page.getByRole('button', { name: 'Yes', exact: true }).first()).toBeVisible();

		// Card view shows one requirement at a time — fill a few to verify functionality
		// Requirement 1: click Yes
		await clickAndPause(page.getByRole('button', { name: 'Yes' }).first());

		// Navigate to next requirements and set results (fill 5 more)
		for (let i = 0; i < 5 && !(await nextButton.isDisabled()); i++) {
			await nextButton.click();
			await page.waitForTimeout(500);
			await clickAndPause(page.getByRole('button', { name: 'No' }).first());
		}
	});

	await test.step('third party respondent can create evidence', async () => {
		// Go back to first requirement
		const prevButton = page.getByRole('button', { name: m.previous() });
		while (!(await prevButton.isDisabled())) {
			await prevButton.click();
			await page.waitForTimeout(300);
		}
		await page.getByRole('button', { name: m.next() }).click();

		// Open the evidence accordion section (collapsed by default)
		await page.getByTestId('evidence-accordion-trigger').click();
		await page.getByTestId('create-evidence-button').click();
		await page.getByTestId('form-input-name').click();
		await page.getByTestId('form-input-name').fill('tp-evidence');
		await page.getByTestId('form-input-filtering-labels').getByRole('combobox').click();
		let objectCreatedToast = thirdPartyAuthenticatedPage.isToastVisible(
			'The evidence object has been successfully created' + /.+/.source
		);
		await page.getByTestId('save-button').click();
		await objectCreatedToast;
	});

	await test.step('check that evidence count was updated', async () => {
		await expect(page.getByTestId('evidence-count').first()).toContainText('1');
	});

	await test.step('check that selected evidences were updated', async () => {
		await page.getByTestId('select-evidence-button').click();
		await expect(page.getByTestId('modal-title')).toBeVisible();
		await expect(page.getByTestId('form-input-evidences').locator('div.multiselect')).toContainText(
			/.*tp-evidence.*/
		);
		await page.getByTestId('cancel-button').click();
	});
});

test.afterAll('cleanup', async ({ browser }) => {
	const page = await browser.newPage();
	const loginPage = new LoginPage(page);
	const foldersPage = new PageContent(page, '/folders', 'Domains');

	await loginPage.goto();
	await loginPage.login();
	for (const id of createdRoleAssignmentIds) {
		const response = await page.request.delete(`${BACKEND_API_URL}/role-assignments/${id}/`, {
			headers: await adminAuthHeaders(page)
		});
		expect(
			[204, 404],
			`Template assignment cleanup failed with status ${response.status()}`
		).toContain(response.status());
	}
	await foldersPage.goto();

	const deletedRows: Locator[] = [];
	for (const name of [vars.folderName, vars.folderName + ' foo']) {
		const exactRow = await exactNamedObjectRow(page, name, m.name());
		await expect(exactRow).toHaveCount(1);
		await exactRow.getByTestId('tablerow-delete-button').click();
		await expect(foldersPage.deletePromptConfirmTextField()).toBeVisible();
		await foldersPage.deletePromptConfirmTextField().fill(m.yes());
		await foldersPage.deletePromptConfirmButton().click();
		await expect(exactRow).toHaveCount(0);
		deletedRows.push(exactRow);
	}
	for (const exactRow of deletedRows) await expect(exactRow).toHaveCount(0);
});
