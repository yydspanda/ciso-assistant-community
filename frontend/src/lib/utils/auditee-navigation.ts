export type RequirementNavigationProjection = {
	id?: string;
	urn?: string | null;
	parent_requirement?: unknown;
	parent_urn?: string | null;
	assessable?: boolean;
	display_mode?: string | null;
};

type AssessmentProjection = { requirement?: unknown };

export type AuditeeNavigationItem<Assessment, Requirement> =
	| { type: 'assessment'; data: Assessment }
	| { type: 'splash'; data: Requirement }
	| { type: 'section'; data: Requirement };

export function resolveAuthorizedParent<Requirement extends RequirementNavigationProjection>(
	parentReference: unknown,
	requirements: readonly Requirement[]
): Requirement | undefined {
	if (!parentReference) return undefined;
	const reference =
		typeof parentReference === 'object'
			? (parentReference as { id?: unknown; urn?: unknown })
			: { id: parentReference, urn: parentReference };
	return requirements.find(
		(node) =>
			(typeof reference.id === 'string' && node.id === reference.id) ||
			(typeof reference.urn === 'string' && node.urn === reference.urn)
	);
}

export function withAuthorizedParentSections<
	Assessment extends AssessmentProjection,
	Requirement extends RequirementNavigationProjection
>(
	sortedItems: readonly (
		{ type: 'assessment'; data: Assessment } | { type: 'splash'; data: NoInfer<Requirement> }
	)[],
	requirements: readonly Requirement[]
): AuditeeNavigationItem<Assessment, Requirement>[] {
	const byId = new Map(requirements.map((node) => [node.id, node]));
	const seenParents = new Set<string>();
	const items: AuditeeNavigationItem<Assessment, Requirement>[] = [];
	for (const item of sortedItems) {
		const reference = item.type === 'assessment' ? item.data.requirement : undefined;
		const requirementId =
			typeof reference === 'object' && reference !== null && 'id' in reference
				? reference.id
				: reference;
		const node =
			item.type === 'splash'
				? item.data
				: typeof requirementId === 'string'
					? byId.get(requirementId)
					: undefined;
		const parent = resolveAuthorizedParent(
			node?.parent_requirement ?? node?.parent_urn,
			requirements
		);
		const parentKey = parent ? (parent.id ?? parent.urn ?? '') : '';
		if (parent && parentKey && !seenParents.has(parentKey)) {
			seenParents.add(parentKey);
			if (parent.display_mode !== 'splash' && !parent.assessable) {
				items.push({ type: 'section', data: parent });
			}
		}
		items.push(item);
	}
	return items;
}
