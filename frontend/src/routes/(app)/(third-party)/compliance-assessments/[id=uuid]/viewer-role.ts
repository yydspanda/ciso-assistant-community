export type ComplianceAssessmentViewerRole = 'auditor' | 'respondent';

export const viewerRoleFromTreeResponse = (
	response: Pick<Response, 'headers'>
): ComplianceAssessmentViewerRole =>
	response.headers.get('X-Viewer-Role') === 'auditor' ? 'auditor' : 'respondent';
