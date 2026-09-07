"""Bounded RequirementAssignment capability capture and consumption.

The generic library and requirement APIs remain governed by ordinary folder
IAM.  This module represents the narrower capability created by an exact
RequirementAssignment: a named respondent may read its assigned questionnaire
slice and mutate only its currently assessable rows.
"""

from dataclasses import dataclass, field
from typing import Any, Literal
from uuid import UUID

from django.db import transaction
from django.db.models import F, Prefetch, Q
from rest_framework.exceptions import PermissionDenied

from core.questionnaire import (
    NormalizedQuestionAnswer,
    QuestionnaireAnswerError,
    normalize_question_answer,
)
from core.utils import (
    _is_question_visible,
    get_authorized_requirement_assessment_ids,
    has_full_view_compliance_assessment,
    is_field_editable_by,
)

_SCOPE_AUTHORITY = object()
_ACTOR_PROOF_AUTHORITY = object()

_RESPONDENT_MUTABLE_FIELDS = frozenset(
    {
        "answers",
        "documentation_score",
        "evidences",
        "extended_result",
        "is_score_overridden",
        "is_scored",
        "observation",
        "respondent_alignment",
        "result",
        "score",
        "status",
    }
)
_AUDITOR_MUTABLE_FIELDS = _RESPONDENT_MUTABLE_FIELDS | {
    "applied_controls",
    "security_exceptions",
}


class AssignmentAnswerValidationError(ValueError):
    """Raised when an assignment-scoped answer payload fails closed."""


@dataclass(frozen=True, slots=True)
class LockedAssignmentActorProof:
    """Unforgeable proof of a user-to-assignment Actor link held by row locks."""

    user_id: UUID
    assignment_id: UUID
    actor_ids: frozenset[UUID]
    _authority: object = field(repr=False, compare=False)

    def is_bound_to(self, *, user, assignment) -> bool:
        return (
            self._authority is _ACTOR_PROOF_AUTHORITY
            and self.user_id == getattr(user, "id", None)
            and self.assignment_id == getattr(assignment, "id", None)
            and bool(self.actor_ids)
        )


def lock_assignment_actor_authority(*, user, assignment) -> LockedAssignmentActorProof:
    """Lock and re-prove one user's direct or Team Actor assignment authority.

    Callers already hold the compliance-assessment and assignment rows. The
    carrier order below matches Team writes and makes writer-first membership
    revocation visible before the mutation can commit.
    """

    from core.models import Actor, RequirementAssignment, Team

    if not transaction.get_connection().in_atomic_block:
        raise RuntimeError("Assignment actor proof requires an atomic transaction.")

    assignment_through = RequirementAssignment.actor.through
    discovered_actor_ids = list(
        assignment_through.objects.filter(requirementassignment_id=assignment.id)
        .order_by("actor_id")
        .values_list("actor_id", flat=True)
    )
    discovered_actors = list(
        Actor.objects.filter(id__in=discovered_actor_ids)
        .order_by("id")
        .values("id", "team_id")
    )
    discovered_team_ids = sorted(
        {row["team_id"] for row in discovered_actors if row["team_id"] is not None},
        key=str,
    )

    locked_teams = list(
        Team.objects.select_for_update(of=("self",))
        .filter(id__in=discovered_team_ids)
        .order_by("id")
    )
    locked_team_ids = {team.id for team in locked_teams}
    locked_actors = list(
        Actor.objects.select_for_update(of=("self",))
        .filter(id__in=discovered_actor_ids)
        .order_by("id")
    )
    if {actor.id for actor in locked_actors} != set(discovered_actor_ids):
        raise PermissionDenied("The requirement assignment is unavailable.")
    if any(
        actor.team_id is not None and actor.team_id not in locked_team_ids
        for actor in locked_actors
    ):
        raise PermissionDenied("The requirement assignment is unavailable.")

    deputy_links = list(
        Team.deputies.through.objects.select_for_update()
        .filter(team_id__in=locked_team_ids, user_id=user.id)
        .order_by("pk")
        .values_list("team_id", flat=True)
    )
    member_links = list(
        Team.members.through.objects.select_for_update()
        .filter(team_id__in=locked_team_ids, user_id=user.id)
        .order_by("pk")
        .values_list("team_id", flat=True)
    )
    authorized_team_ids = {
        team.id for team in locked_teams if team.leader_id == user.id
    }
    authorized_team_ids.update(deputy_links)
    authorized_team_ids.update(member_links)

    authorized_actor_ids = {
        actor.id
        for actor in locked_actors
        if actor.user_id == user.id
        or (actor.team_id is not None and actor.team_id in authorized_team_ids)
    }
    final_assignment_actor_ids = set(
        assignment_through.objects.select_for_update()
        .filter(requirementassignment_id=assignment.id)
        .order_by("pk")
        .values_list("actor_id", flat=True)
    )
    authorized_actor_ids &= final_assignment_actor_ids
    if not authorized_actor_ids:
        raise PermissionDenied("The requirement assignment is unavailable.")

    return LockedAssignmentActorProof(
        user_id=user.id,
        assignment_id=assignment.id,
        actor_ids=frozenset(authorized_actor_ids),
        _authority=_ACTOR_PROOF_AUTHORITY,
    )


class ComplianceAssessmentRelocationError(ValueError):
    """Raised when an audit tree cannot be moved as one governed unit."""


def assert_assignment_folder_owner(assignment) -> None:
    """Fail closed when a legacy assignment escaped its audit enclave."""

    compliance_assessment = assignment.compliance_assessment
    if assignment.folder_id != compliance_assessment.folder_id:
        raise PermissionDenied(
            "The requirement assignment has an inconsistent audit folder."
        )


def lock_requirement_assessment_relation_scope(
    *,
    user,
    requirement_assessment_ids,
    relation_field: str | None,
    object_folder_id: UUID | None,
    allow_respondent: bool,
    require_change_permission: bool = True,
    enforce_assessment_editable: bool = True,
    respondent_assignment_statuses=None,
    require_questionnaire_scope: bool = True,
):
    """Lock and authorize generic writes that point at audit requirement rows.

    Full-audit users must retain exact change authority on every target row.
    Respondents are accepted only when the caller explicitly opts in and one
    active, locked RequirementAssignment contains the complete target set.  In
    that case the same sealed questionnaire scope used by the exact endpoint is
    captured before the generic object or relationship row may be changed.
    """

    from django.contrib.auth.models import Permission
    from django.db.models import Count

    from iam.models import RoleAssignment

    from core.models import (
        ComplianceAssessment,
        RequirementAssessment,
        RequirementAssignment,
    )

    if not transaction.get_connection().in_atomic_block:
        raise RuntimeError(
            "Requirement-assessment relation authorization requires an atomic transaction."
        )

    target_ids = frozenset(requirement_assessment_ids)
    if not target_ids:
        return [], False

    discovered_rows = list(
        RequirementAssessment.objects.filter(id__in=target_ids)
        .order_by("id")
        .values_list("id", "compliance_assessment_id")
    )
    if {row_id for row_id, _ in discovered_rows} != set(target_ids):
        raise PermissionDenied("One or more requirement assessments are unavailable.")

    compliance_assessment_ids = sorted(
        {assessment_id for _, assessment_id in discovered_rows}, key=str
    )
    compliance_assessments = list(
        ComplianceAssessment.objects.select_for_update(of=("self",))
        .filter(id__in=compliance_assessment_ids)
        .order_by("id")
    )
    if {assessment.id for assessment in compliance_assessments} != set(
        compliance_assessment_ids
    ):
        raise PermissionDenied("One or more compliance assessments are unavailable.")
    assessments_by_id = {
        assessment.id: assessment for assessment in compliance_assessments
    }
    if enforce_assessment_editable and any(
        assessment.is_locked
        or assessment.status == ComplianceAssessment.Status.IN_REVIEW
        for assessment in compliance_assessments
    ):
        raise PermissionDenied("A linked compliance assessment is not editable.")

    full_view = all(
        has_full_view_compliance_assessment(user, assessment)
        for assessment in compliance_assessments
    )
    actor_proof = None
    assignment = None
    if not full_view:
        if not allow_respondent or len(compliance_assessments) != 1:
            raise PermissionDenied(
                "Respondent relationship changes require an exact requirement assignment."
            )
        compliance_assessment = compliance_assessments[0]
        candidate_ids = list(
            RequirementAssignment.objects.filter(
                compliance_assessment_id=compliance_assessment.id,
                requirement_assessments__id__in=target_ids,
            )
            .annotate(
                matched_targets=Count(
                    "requirement_assessments",
                    filter=Q(requirement_assessments__id__in=target_ids),
                    distinct=True,
                )
            )
            .filter(matched_targets=len(target_ids))
            .order_by("id")
            .values_list("id", flat=True)
        )
        allowed_statuses = respondent_assignment_statuses or (
            RequirementAssignment.Status.IN_PROGRESS,
            RequirementAssignment.Status.CHANGES_REQUESTED,
        )
        candidates = list(
            RequirementAssignment.objects.select_for_update(of=("self",))
            .filter(
                id__in=candidate_ids,
                compliance_assessment_id=compliance_assessment.id,
                status__in=allowed_statuses,
            )
            .order_by("id")
        )
        for candidate in candidates:
            candidate.compliance_assessment = compliance_assessment
            try:
                assert_assignment_folder_owner(candidate)
                proof = lock_assignment_actor_authority(
                    user=user,
                    assignment=candidate,
                )
            except PermissionDenied:
                continue
            linked_ids = set(
                RequirementAssignment.requirement_assessments.through.objects.select_for_update()
                .filter(
                    requirementassignment_id=candidate.id,
                    requirementassessment_id__in=target_ids,
                )
                .order_by("pk")
                .values_list("requirementassessment_id", flat=True)
            )
            if linked_ids == set(target_ids):
                assignment = candidate
                actor_proof = proof
                break
        if assignment is None:
            raise PermissionDenied(
                "Respondent relationship changes require an exact requirement assignment."
            )

    locked_rows = list(
        RequirementAssessment.objects.select_for_update(of=("self",))
        .filter(id__in=target_ids)
        .order_by("id")
    )
    if {row.id for row in locked_rows} != set(target_ids):
        raise PermissionDenied("One or more requirement assessments are unavailable.")
    for row in locked_rows:
        compliance_assessment = assessments_by_id.get(row.compliance_assessment_id)
        if (
            compliance_assessment is None
            or row.folder_id != compliance_assessment.folder_id
        ):
            raise PermissionDenied(
                "A requirement assessment has an inconsistent audit folder."
            )
        row.compliance_assessment = compliance_assessment

    if full_view:
        visible_requirement_assessment_ids = set(
            RoleAssignment.get_viewable_object_ids(user, RequirementAssessment)
        )
        if not target_ids.issubset(visible_requirement_assessment_ids):
            raise PermissionDenied(
                "One or more requirement assessments are unavailable."
            )
        if relation_field is not None and any(
            not is_field_editable_by(
                assessment,
                relation_field,
                "auditor",
            )
            for assessment in compliance_assessments
        ):
            raise PermissionDenied(
                "This relationship is not editable for the compliance assessment."
            )
        if require_change_permission:
            try:
                change_permission = Permission.objects.get(
                    content_type__app_label="core",
                    content_type__model="requirementassessment",
                    codename="change_requirementassessment",
                )
            except Permission.DoesNotExist as exc:
                raise PermissionDenied(
                    "Requirement-assessment change authority is unavailable."
                ) from exc
            if any(
                not RoleAssignment.is_access_allowed(
                    user=user,
                    perm=change_permission,
                    folder=row.folder,
                )
                for row in locked_rows
            ):
                raise PermissionDenied(
                    "You cannot change one or more requirement-assessment relationships."
                )
        return locked_rows, False

    if not require_questionnaire_scope:
        visible_requirement_assessment_ids = set(
            RoleAssignment.get_viewable_object_ids(user, RequirementAssessment)
        )
        if not target_ids.issubset(visible_requirement_assessment_ids):
            raise PermissionDenied(
                "One or more requirement assessments are unavailable."
            )
        if object_folder_id is not None and any(
            row.folder_id != object_folder_id for row in locked_rows
        ):
            raise PermissionDenied(
                "Respondent-linked objects must remain in the assignment folder."
            )
        return locked_rows, True

    scope = capture_assignment_questionnaire_scope(
        user=user,
        assignment=assignment,
        lock_questionnaire_bindings=True,
        actor_proof=actor_proof,
    )
    if not target_ids.issubset(scope.mutable_requirement_assessment_ids):
        raise PermissionDenied(
            "One or more requirement assessments are outside the assignment scope."
        )
    if relation_field is not None and relation_field not in scope.mutable_fields:
        raise PermissionDenied(
            "This relationship is not editable for the requirement assignment."
        )
    if object_folder_id is not None and any(
        row.folder_id != object_folder_id for row in locked_rows
    ):
        raise PermissionDenied(
            "Respondent-linked objects must remain in the assignment folder."
        )
    return locked_rows, True


def relocate_compliance_assessment_tree(
    compliance_assessment,
    *,
    source_folder_id: UUID | None,
) -> None:
    """Move every audit-owned row to the audit's already-updated folder.

    The caller must hold the ``ComplianceAssessment`` row lock inside the
    surrounding transaction. Children are then locked in the shared
    ``CA -> Assignment -> RA -> Answer -> RA Comment`` order. Active durable mail intents
    deliberately block relocation: the delivery worker owns those rows in the
    reverse ``Outbox -> Assignment`` order, so trying to lock or rewrite them
    here would introduce a deadlock window and could change an in-flight
    delivery's authority context.
    """

    from core.models import (
        Answer,
        Comment,
        RequirementAssessment,
        RequirementAssignment,
        RequirementAssignmentEvent,
        RequirementAssignmentMailOutbox,
    )

    if not transaction.get_connection().in_atomic_block:
        raise RuntimeError("Audit-tree relocation requires an atomic transaction.")

    target_folder_id = compliance_assessment.folder_id
    if target_folder_id == source_folder_id:
        return

    def has_unexpected_folder(queryset) -> bool:
        if source_folder_id is None:
            return queryset.filter(folder_id__isnull=False).exists()
        return queryset.filter(
            Q(folder_id__isnull=True) | ~Q(folder_id=source_folder_id)
        ).exists()

    assignments = list(
        RequirementAssignment.objects.select_for_update(of=("self",))
        .filter(compliance_assessment_id=compliance_assessment.id)
        .order_by("id")
    )
    assignment_ids = [assignment.id for assignment in assignments]
    assignment_query = RequirementAssignment.objects.filter(id__in=assignment_ids)
    if has_unexpected_folder(assignment_query):
        raise ComplianceAssessmentRelocationError(
            "The audit contains an assignment with an inconsistent folder."
        )

    outbox_query = RequirementAssignmentMailOutbox.objects.filter(
        assignment_id__in=assignment_ids
    )
    if outbox_query.filter(
        status__in=(
            RequirementAssignmentMailOutbox.Status.QUEUED,
            RequirementAssignmentMailOutbox.Status.SENDING,
        )
    ).exists():
        raise ComplianceAssessmentRelocationError(
            "The audit cannot move while assignment mail is queued or sending."
        )
    if has_unexpected_folder(outbox_query):
        raise ComplianceAssessmentRelocationError(
            "The audit contains a mail record with an inconsistent folder."
        )

    event_query = RequirementAssignmentEvent.objects.filter(
        assignment_id__in=assignment_ids
    )
    if has_unexpected_folder(event_query):
        raise ComplianceAssessmentRelocationError(
            "The audit contains an assignment event with an inconsistent folder."
        )

    requirement_assessments = list(
        RequirementAssessment.objects.select_for_update(of=("self",))
        .filter(compliance_assessment_id=compliance_assessment.id)
        .order_by("id")
    )
    requirement_assessment_ids = [row.id for row in requirement_assessments]
    requirement_assessment_query = RequirementAssessment.objects.filter(
        id__in=requirement_assessment_ids
    )
    if has_unexpected_folder(requirement_assessment_query):
        raise ComplianceAssessmentRelocationError(
            "The audit contains a requirement assessment with an inconsistent folder."
        )

    answers = list(
        Answer.objects.select_for_update(of=("self",))
        .filter(requirement_assessment_id__in=requirement_assessment_ids)
        .order_by("id")
    )
    answer_ids = [answer.id for answer in answers]
    answer_query = Answer.objects.filter(id__in=answer_ids)
    if has_unexpected_folder(answer_query):
        raise ComplianceAssessmentRelocationError(
            "The audit contains an answer with an inconsistent folder."
        )

    comments = list(
        Comment.objects.select_for_update(of=("self",))
        .filter(requirement_assessment_id__in=requirement_assessment_ids)
        .order_by("id")
    )
    comment_ids = [comment.id for comment in comments]
    comment_query = Comment.objects.filter(id__in=comment_ids)
    if has_unexpected_folder(comment_query):
        raise ComplianceAssessmentRelocationError(
            "The audit contains a requirement comment with an inconsistent folder."
        )

    # Assignment locks prevent status transitions, new events, and new mail
    # intents while the bulk updates below commit. Only terminal outbox rows
    # reach this point, so they are not worker-owned and their digest remains
    # unchanged.
    event_query.update(folder_id=target_folder_id)
    outbox_query.update(folder_id=target_folder_id)
    assignment_query.update(folder_id=target_folder_id)
    requirement_assessment_query.update(folder_id=target_folder_id)
    answer_query.update(folder_id=target_folder_id)
    comment_query.update(folder_id=target_folder_id)


@dataclass(frozen=True, slots=True)
class AssignmentQuestionnaireScope:
    """Immutable, request-bound projection of one exact assignment."""

    user_id: UUID
    assignment_id: UUID
    compliance_assessment_id: UUID
    framework_id: UUID
    viewer_role: Literal["respondent", "auditor"]
    readable_requirement_assessment_ids: frozenset[UUID]
    mutable_requirement_assessment_ids: frozenset[UUID]
    requirement_assessment_nodes: frozenset[tuple[UUID, UUID]]
    structural_requirement_node_ids: frozenset[UUID]
    question_bindings: frozenset[tuple[UUID, UUID]]
    choice_bindings: frozenset[tuple[UUID, UUID]]
    mutable_fields: frozenset[str]
    _authority: object = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        readable = self.readable_requirement_assessment_ids
        if not self.mutable_requirement_assessment_ids <= readable:
            raise ValueError("Mutable assignment rows must also be readable.")
        bound_rows = {row_id for row_id, _node_id in self.requirement_assessment_nodes}
        if bound_rows != readable:
            raise ValueError("Every readable assignment row must bind one node.")

    def is_authentic(self) -> bool:
        return self._authority is _SCOPE_AUTHORITY

    def is_bound_to_user(self, user) -> bool:
        return self.is_authentic() and getattr(user, "id", None) == self.user_id

    def node_id_for(self, requirement_assessment_id: UUID) -> UUID | None:
        for row_id, node_id in self.requirement_assessment_nodes:
            if row_id == requirement_assessment_id:
                return node_id
        return None

    def allows_requirement_assessment(self, instance, *, mutable=False) -> bool:
        allowed_ids = (
            self.mutable_requirement_assessment_ids
            if mutable
            else self.readable_requirement_assessment_ids
        )
        return (
            self.is_authentic()
            and instance.id in allowed_ids
            and instance.compliance_assessment_id == self.compliance_assessment_id
            and self.node_id_for(instance.id) == instance.requirement_id
        )

    def allows_requirement_node(self, instance) -> bool:
        return (
            self.is_authentic()
            and instance.id in self.structural_requirement_node_ids
            and instance.framework_id == self.framework_id
        )

    def question_ids_for_requirement_assessment(
        self, requirement_assessment_id: UUID
    ) -> frozenset[UUID]:
        return frozenset(
            question_id
            for row_id, question_id in self.question_bindings
            if row_id == requirement_assessment_id
        )

    def question_ids_for_requirement_node(
        self, requirement_node_id: UUID
    ) -> frozenset[UUID]:
        row_ids = {
            row_id
            for row_id, node_id in self.requirement_assessment_nodes
            if node_id == requirement_node_id
        }
        return frozenset(
            question_id
            for row_id, question_id in self.question_bindings
            if row_id in row_ids
        )

    def choice_ids_for_questions(
        self, question_ids: set[UUID] | frozenset[UUID]
    ) -> frozenset[UUID]:
        return frozenset(
            choice_id
            for question_id, choice_id in self.choice_bindings
            if question_id in question_ids
        )


def get_bound_assignment_scope(
    context: dict[str, Any],
    *,
    user,
    requirement_assessment=None,
    requirement_node=None,
    mutable: bool = False,
) -> AssignmentQuestionnaireScope | None:
    """Return a context scope only when all request/object bindings match."""

    scope = context.get("requirement_assignment_scope")
    if not isinstance(scope, AssignmentQuestionnaireScope):
        return None
    if not scope.is_bound_to_user(user):
        return None
    if requirement_assessment is not None and not scope.allows_requirement_assessment(
        requirement_assessment, mutable=mutable
    ):
        return None
    if requirement_node is not None and not scope.allows_requirement_node(
        requirement_node
    ):
        return None
    return scope


def capture_assignment_questionnaire_scope(
    *,
    user,
    assignment,
    lock_questionnaire_bindings: bool = False,
    actor_proof: LockedAssignmentActorProof | None = None,
) -> AssignmentQuestionnaireScope:
    """Capture the exact read/mutation slice for ``assignment`` and ``user``.

    A mutation caller may request row locks for the node/question/choice chain.
    The caller must already be inside a transaction and hold the assessment,
    assignment, exact assignment membership and target assessment locks.
    """

    from iam.models import RoleAssignment

    from core.models import (
        Actor,
        ComplianceAssessment,
        Framework,
        Question,
        QuestionChoice,
        RequirementAssessment,
        RequirementAssignment,
        RequirementNode,
    )

    if assignment.id not in set(
        RoleAssignment.get_viewable_object_ids(user, RequirementAssignment)
    ):
        raise PermissionDenied("The requirement assignment is unavailable.")

    compliance_assessment = assignment.compliance_assessment
    assert_assignment_folder_owner(assignment)
    if compliance_assessment.id not in set(
        RoleAssignment.get_viewable_object_ids(user, ComplianceAssessment)
    ):
        raise PermissionDenied("The compliance assessment is unavailable.")

    is_respondent = not has_full_view_compliance_assessment(user, compliance_assessment)
    if is_respondent:
        if lock_questionnaire_bindings:
            if actor_proof is None or not actor_proof.is_bound_to(
                user=user,
                assignment=assignment,
            ):
                raise PermissionDenied("The requirement assignment is unavailable.")
        else:
            user_actor_ids = {actor.id for actor in Actor.get_all_for_user(user)}
            # Read projections use the current statement-level membership. A
            # mutation must instead provide the locked proof above.
            if not RequirementAssignment.objects.filter(
                id=assignment.id,
                actor__id__in=user_actor_ids,
            ).exists():
                raise PermissionDenied("The requirement assignment is unavailable.")
    else:
        visible_framework_ids = set(
            RoleAssignment.get_viewable_object_ids(user, Framework)
        )
        if compliance_assessment.framework_id not in visible_framework_ids:
            raise PermissionDenied(
                "Complete audit data is unavailable for this caller."
            )

    # A mutation scope derives authority from node properties (CEL, IG,
    # assessable, URN and ancestry), so capture those properties only after
    # locking the complete framework node set in deterministic order.  A CEL
    # expression also consumes whole-audit RA/Answer state; this bounded
    # assignment endpoint intentionally refuses that mutation case rather than
    # pretending that node locks stabilize the full CEL context.
    structural_nodes_query = RequirementNode.objects.filter(
        framework_id=compliance_assessment.framework_id
    ).order_by("pk")
    if lock_questionnaire_bindings:
        structural_nodes_query = structural_nodes_query.select_for_update(of=("self",))
    structural_nodes = list(
        structural_nodes_query.only(
            "id",
            "urn",
            "parent_urn",
            "framework_id",
            "visibility_expression",
            "implementation_groups",
            "assessable",
        )
    )
    nodes_by_id = {node.id: node for node in structural_nodes}
    nodes_by_urn = {node.urn: node for node in structural_nodes}
    has_cel_visibility = any(node.visibility_expression for node in structural_nodes)
    hidden_requirement_urns: set[str] = set()
    if has_cel_visibility:
        if lock_questionnaire_bindings:
            raise PermissionDenied(
                "Assignment-scoped mutation is unavailable when CEL visibility is configured."
            )
        # The resolver owns the proof: callers cannot inject a naked "CEL was
        # authorized" flag or a hand-picked hidden-node set.
        if is_respondent:
            raise PermissionDenied(
                "Complete CEL visibility data is unavailable for this caller."
            )
        from core.cel_service import build_cel_context
        from core.views import ComplianceAssessmentViewSet

        ComplianceAssessmentViewSet._assert_complete_cel_visibility_access(
            user, compliance_assessment
        )
        _context, hidden_requirement_urns = build_cel_context(compliance_assessment)

    # As above, do not consume a caller-supplied related-manager prefetch as an
    # authority source.
    assigned_rows = RequirementAssessment.objects.filter(assignments__id=assignment.id)
    if assigned_rows.exclude(
        compliance_assessment_id=compliance_assessment.id,
        folder_id=compliance_assessment.folder_id,
    ).exists():
        raise PermissionDenied(
            "The requirement assignment contains an inconsistent requirement assessment."
        )
    assigned_ids = assigned_rows.values_list("id", flat=True)
    authorized_ids = get_authorized_requirement_assessment_ids(
        user,
        compliance_assessment,
        respondent_scope=is_respondent,
    )
    rows = list(
        RequirementAssessment.objects.filter(
            id__in=assigned_ids,
            compliance_assessment_id=compliance_assessment.id,
        ).filter(id__in=authorized_ids)
    )

    if not is_respondent:
        visible_node_ids = set(
            RoleAssignment.get_viewable_object_ids(user, RequirementNode)
        )
        rows = [row for row in rows if row.requirement_id in visible_node_ids]

    selected_groups = set(compliance_assessment.selected_implementation_groups or ())
    if selected_groups:
        rows = [
            row
            for row in rows
            if (
                (node := nodes_by_id.get(row.requirement_id)) is not None
                and selected_groups & set(node.implementation_groups or ())
            )
        ]

    rows = [
        row
        for row in rows
        if (
            (node := nodes_by_id.get(row.requirement_id)) is not None
            and node.urn not in hidden_requirement_urns
        )
    ]
    # Structural/non-assessable nodes remain in the ancestor tree but never
    # become response-bearing RequirementAssessment rows.
    rows = [
        row
        for row in rows
        if (
            (node := nodes_by_id.get(row.requirement_id)) is not None
            and bool(node.assessable)
        )
    ]
    readable_ids = frozenset(row.id for row in rows)
    mutable_ids = readable_ids
    row_nodes = frozenset((row.id, row.requirement_id) for row in rows)

    structural_ids: set[UUID] = set()
    for row in rows:
        node = nodes_by_id.get(row.requirement_id)
        while node is not None and node.id not in structural_ids:
            if node.urn in hidden_requirement_urns:
                break
            structural_ids.add(node.id)
            node = nodes_by_urn.get(node.parent_urn)

    row_id_by_node_id = {node_id: row_id for row_id, node_id in row_nodes}
    generic_question_ids = set(RoleAssignment.get_viewable_object_ids(user, Question))
    question_query = (
        Question.objects.filter(requirement_node_id__in=row_id_by_node_id)
        .filter(
            Q(folder_id=F("requirement_node__folder_id"))
            | Q(id__in=generic_question_ids)
        )
        .order_by("pk")
    )
    if lock_questionnaire_bindings:
        question_query = question_query.select_for_update(of=("self",))
    questions = list(question_query.only("id", "requirement_node_id"))
    question_bindings = frozenset(
        (row_id_by_node_id[question.requirement_node_id], question.id)
        for question in questions
    )
    generic_choice_ids = set(
        RoleAssignment.get_viewable_object_ids(user, QuestionChoice)
    )
    choice_query = (
        QuestionChoice.objects.filter(
            question_id__in=[question.id for question in questions]
        )
        .filter(
            Q(
                folder_id=F("question__folder_id"),
                question__folder_id=F("question__requirement_node__folder_id"),
            )
            | Q(id__in=generic_choice_ids)
        )
        .order_by("pk")
    )
    if lock_questionnaire_bindings:
        choice_query = choice_query.select_for_update(of=("self",))
    choices = list(choice_query.only("id", "question_id"))
    choice_bindings = frozenset((choice.question_id, choice.id) for choice in choices)

    viewer_role = "respondent" if is_respondent else "auditor"
    static_mutable_fields = (
        _RESPONDENT_MUTABLE_FIELDS if is_respondent else _AUDITOR_MUTABLE_FIELDS
    )
    mutable_fields = frozenset(
        field_name
        for field_name in static_mutable_fields
        if is_field_editable_by(
            compliance_assessment,
            field_name,
            viewer_role,
        )
    )

    return AssignmentQuestionnaireScope(
        user_id=user.id,
        assignment_id=assignment.id,
        compliance_assessment_id=compliance_assessment.id,
        framework_id=compliance_assessment.framework_id,
        viewer_role=viewer_role,
        readable_requirement_assessment_ids=readable_ids,
        mutable_requirement_assessment_ids=mutable_ids,
        requirement_assessment_nodes=row_nodes,
        structural_requirement_node_ids=frozenset(structural_ids),
        question_bindings=question_bindings,
        choice_bindings=choice_bindings,
        mutable_fields=mutable_fields,
        _authority=_SCOPE_AUTHORITY,
    )


def get_assignment_visible_question_counts(
    *,
    scope: AssignmentQuestionnaireScope,
    user,
    requirement_assessment,
) -> tuple[int, int]:
    """Return conditional question counts within an authenticated scope."""

    from iam.models import RoleAssignment

    from core.models import Answer, Question, QuestionChoice

    if not scope.is_bound_to_user(user) or not scope.allows_requirement_assessment(
        requirement_assessment
    ):
        raise PermissionDenied("The requirement assessment is unavailable.")

    question_ids = scope.question_ids_for_requirement_assessment(
        requirement_assessment.id
    )
    choice_ids = scope.choice_ids_for_questions(question_ids)
    questions = list(
        Question.objects.filter(id__in=question_ids).prefetch_related(
            Prefetch(
                "choices",
                queryset=QuestionChoice.objects.filter(id__in=choice_ids),
            )
        )
    )
    visible_answer_ids = RoleAssignment.get_viewable_object_ids(user, Answer)
    answers = list(
        Answer.objects.filter(
            requirement_assessment_id=requirement_assessment.id,
            question_id__in=question_ids,
            id__in=visible_answer_ids,
        )
        .select_related("question")
        .prefetch_related("selected_choices")
    )
    _, answers_by_urn, questions_by_urn, has_answer_by_qid = (
        build_assignment_answer_context(
            questions=questions,
            answers=answers,
            allowed_choice_ids=choice_ids,
            answer_folder_id=requirement_assessment.folder_id,
        )
    )
    visible = 0
    answered = 0
    for question in questions:
        if not _is_question_visible(question, answers_by_urn, questions_by_urn):
            continue
        visible += 1
        if has_answer_by_qid.get(question.id):
            answered += 1
    return visible, answered


def build_assignment_answer_context(
    *,
    questions,
    answers,
    allowed_choice_ids,
    answer_folder_id=None,
):
    """Build a fail-closed answer snapshot from exact assignment carriers."""

    from core.models import Question

    allowed_choice_ids = set(allowed_choice_ids)
    questions_by_id = {
        question.id: question
        for question in questions
        if isinstance(question.urn, str) and question.urn
    }
    questions_by_urn = {question.urn: question for question in questions_by_id.values()}
    selected_choice_pks_by_qid: dict[UUID, set[UUID]] = {}
    answers_by_urn: dict[str, Any] = {}
    has_answer_by_qid: dict[UUID, bool] = {}

    for stored_answer in answers:
        if answer_folder_id is not None and stored_answer.folder_id != answer_folder_id:
            continue
        question = questions_by_id.get(stored_answer.question_id)
        if question is None:
            continue
        selected_choices = list(stored_answer.selected_choices.all())
        raw_value = stored_answer.value
        if question.type in {
            Question.Type.UNIQUE_CHOICE,
            Question.Type.MULTIPLE_CHOICE,
        }:
            if raw_value not in (None, "") or any(
                choice.id not in allowed_choice_ids
                or choice.question_id != question.id
                or not isinstance(choice.urn, str)
                or not choice.urn
                for choice in selected_choices
            ):
                has_answer_by_qid[question.id] = False
                continue
            if question.type == Question.Type.UNIQUE_CHOICE:
                if len(selected_choices) > 1:
                    has_answer_by_qid[question.id] = False
                    continue
                raw_value = selected_choices[0].urn if selected_choices else None
            else:
                raw_value = [choice.urn for choice in selected_choices]
        elif selected_choices:
            has_answer_by_qid[question.id] = False
            continue

        try:
            normalized = normalize_question_answer(
                question,
                raw_value,
                allowed_choice_ids=allowed_choice_ids,
            )
        except QuestionnaireAnswerError:
            has_answer_by_qid[question.id] = False
            continue

        selected_choice_pks_by_qid[question.id] = {
            choice.id for choice in normalized.choices
        }
        answers_by_urn[question.urn] = normalized.context_value
        if question.type in {
            Question.Type.UNIQUE_CHOICE,
            Question.Type.MULTIPLE_CHOICE,
        }:
            has_answer_by_qid[question.id] = bool(normalized.choices)
        else:
            has_answer_by_qid[question.id] = normalized.value not in (None, "")

    return (
        selected_choice_pks_by_qid,
        answers_by_urn,
        questions_by_urn,
        has_answer_by_qid,
    )


def assert_assignment_recompute_scope_complete(
    *,
    scope: AssignmentQuestionnaireScope,
    user,
    requirement_assessment,
) -> None:
    """Require every recompute carrier to belong to the exact capability."""

    from iam.models import RoleAssignment

    from core.models import Answer, Question

    if not scope.is_bound_to_user(user) or not scope.allows_requirement_assessment(
        requirement_assessment, mutable=True
    ):
        raise PermissionDenied("The assignment questionnaire scope is unavailable.")

    scoped_question_ids = scope.question_ids_for_requirement_assessment(
        requirement_assessment.id
    )
    questions = list(
        Question.objects.filter(
            requirement_node_id=requirement_assessment.requirement_id
        ).prefetch_related("choices")
    )
    if {question.id for question in questions} != set(scoped_question_ids):
        raise PermissionDenied(
            "Questionnaire recompute requires complete assignment carrier access."
        )

    scoped_choice_ids = scope.choice_ids_for_questions(scoped_question_ids)
    choices = [choice for question in questions for choice in question.choices.all()]
    if {choice.id for choice in choices} != set(scoped_choice_ids) or any(
        choice.question_id not in scoped_question_ids
        or not isinstance(choice.urn, str)
        or not choice.urn
        for choice in choices
    ):
        raise PermissionDenied(
            "Questionnaire recompute requires complete assignment carrier access."
        )

    answers = list(
        Answer.objects.filter(requirement_assessment_id=requirement_assessment.id)
        .select_related("question")
        .prefetch_related("selected_choices")
    )
    visible_answer_ids = set(RoleAssignment.get_viewable_object_ids(user, Answer))
    if any(
        answer.id not in visible_answer_ids
        or answer.question_id not in scoped_question_ids
        for answer in answers
    ):
        raise PermissionDenied(
            "Questionnaire recompute requires complete assignment carrier access."
        )

    _selected, answers_by_urn, _questions, _has_answer = (
        build_assignment_answer_context(
            questions=questions,
            answers=answers,
            allowed_choice_ids=scoped_choice_ids,
            answer_folder_id=requirement_assessment.folder_id,
        )
    )
    if any(answer.question.urn not in answers_by_urn for answer in answers):
        raise PermissionDenied(
            "Questionnaire recompute requires valid assignment carrier data."
        )


def validate_assignment_answers(
    *,
    scope: AssignmentQuestionnaireScope,
    user,
    requirement_assessment,
    answers_data: dict[str, Any],
) -> dict[str, NormalizedQuestionAnswer]:
    """Validate types, identifiers and prospective conditional visibility."""

    from iam.models import RoleAssignment

    from core.models import Answer, Question, QuestionChoice

    if not scope.is_bound_to_user(user) or not scope.allows_requirement_assessment(
        requirement_assessment, mutable=True
    ):
        raise PermissionDenied("The requirement assessment is unavailable.")

    question_ids = scope.question_ids_for_requirement_assessment(
        requirement_assessment.id
    )
    choice_ids = scope.choice_ids_for_questions(question_ids)
    questions = list(
        Question.objects.filter(id__in=question_ids).prefetch_related(
            Prefetch(
                "choices",
                queryset=QuestionChoice.objects.filter(id__in=choice_ids),
            )
        )
    )
    questions_by_urn = {question.urn: question for question in questions}
    unknown_questions = set(answers_data) - set(questions_by_urn)
    if unknown_questions:
        raise AssignmentAnswerValidationError(
            "One or more questions are unavailable for this assignment."
        )

    existing_answers = list(
        Answer.objects.filter(
            requirement_assessment_id=requirement_assessment.id,
            question_id__in=question_ids,
        )
        .select_related("question")
        .prefetch_related("selected_choices")
    )
    visible_answer_ids = set(RoleAssignment.get_viewable_object_ids(user, Answer))
    if any(answer.id not in visible_answer_ids for answer in existing_answers):
        raise PermissionDenied("One or more answers are unavailable for this caller.")

    _, answers_by_urn, _questions_by_urn, _has_answer = build_assignment_answer_context(
        questions=questions,
        answers=existing_answers,
        allowed_choice_ids=choice_ids,
        answer_folder_id=requirement_assessment.folder_id,
    )
    normalized: dict[str, NormalizedQuestionAnswer] = {}
    for question_urn, raw_value in answers_data.items():
        question = questions_by_urn[question_urn]
        try:
            answer = normalize_question_answer(
                question,
                raw_value,
                allowed_choice_ids=choice_ids,
            )
        except QuestionnaireAnswerError as exc:
            raise AssignmentAnswerValidationError(str(exc)) from exc
        normalized[question_urn] = answer
        answers_by_urn[question_urn] = answer.context_value

    for question_urn in answers_data:
        question = questions_by_urn[question_urn]
        if not _is_question_visible(
            question,
            answers_by_urn,
            questions_by_urn,
        ):
            raise AssignmentAnswerValidationError(
                "A hidden conditional question cannot be updated."
            )
    return normalized
