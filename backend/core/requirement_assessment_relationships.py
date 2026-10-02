"""Authority boundary for inverse RequirementAssessment relationship writes.

The generic Evidence, AppliedControl, SecurityException and TaskTemplate APIs
expose the reverse side of RequirementAssessment many-to-many fields.  A plain
DRF ``set()`` on those reverse managers is not sufficient: it can remove rows
that the caller could not see and it bypasses the audit's assignment, field
policy and workflow state.

This module is deliberately independent from ``core.serializers``.  Write
serializers opt in by adding :class:`RequirementAssessmentRelationshipAuthorityMixin`
to their bases.  CISO Assistant's existing IAM, assessment and assignment
models remain authoritative; this module only composes their decisions around
one bounded relationship delta.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any, ClassVar, Literal
from uuid import UUID

from django.contrib.auth.models import Permission
from django.core.exceptions import FieldDoesNotExist, ImproperlyConfigured
from django.db import transaction
from django.db.models import F, Model
from django.db.models.manager import BaseManager
from iam.models import Folder, RoleAssignment, User
from rest_framework import serializers
from rest_framework.exceptions import APIException, NotAuthenticated, PermissionDenied

from core.models import (
    Actor,
    AppliedControl,
    Assessment,
    ComplianceAssessment,
    Evidence,
    Framework,
    RequirementAssessment,
    RequirementAssignment,
    RequirementNode,
    SecurityException,
    TaskTemplate,
)
from core.utils import (
    get_full_view_compliance_assessment_ids,
    is_field_editable_by,
    is_field_visible_to,
)

RELATION_FIELD = "requirement_assessments"
BATCH_RELATION_OPERATION_CONTEXT_KEY = "requirement_assessment_relationship_operation"
RelationshipOperation = Literal["replace", "add", "remove"]
TERMINAL_ASSIGNMENT_STATUSES = frozenset(
    {
        RequirementAssignment.Status.SUBMITTED,
        RequirementAssignment.Status.CLOSED,
    }
)


class RequirementAssessmentRelationshipConflict(APIException):
    """The relationship or one of its authority-bearing parents changed."""

    status_code = 409
    default_detail = (
        "The requirement-assessment relationship changed while the request was "
        "being processed. Reload it and try again."
    )
    default_code = "requirement_assessment_relationship_conflict"


@dataclass(frozen=True, slots=True)
class RequirementAssessmentRelationshipPlan:
    """Validation-time snapshot bound to one serializer save operation."""

    target_pk: UUID | None
    operation: RelationshipOperation
    requested_ids: frozenset[UUID]
    baseline_ids: frozenset[UUID]
    visible_baseline_ids: frozenset[UUID]
    parent_links: tuple[tuple[UUID, UUID, UUID, UUID, UUID], ...]
    user_pk: UUID
    actor_ids: tuple[UUID, ...]
    assignment_authority_snapshot: tuple[tuple[UUID, str, UUID], ...]


@dataclass(frozen=True, slots=True)
class _LockedRelationshipContext:
    user: User
    target: Any | None
    rows_by_id: dict[UUID, RequirementAssessment]
    assessments_by_id: dict[UUID, ComplianceAssessment]
    assignment_ids: tuple[UUID, ...]
    assignment_statuses_by_ra: dict[UUID, frozenset[str]]
    full_view_assessment_ids: frozenset[UUID]
    generic_view_assessment_ids: frozenset[UUID]
    generic_view_ra_ids: frozenset[UUID]
    generic_change_ra_ids: frozenset[UUID]
    generic_view_requirement_node_ids: frozenset[UUID]
    generic_view_framework_ids: frozenset[UUID]


_POLICY_FIELD_BY_MODEL: dict[type, str] = {
    Evidence: "evidences",
    AppliedControl: "applied_controls",
    SecurityException: "security_exceptions",
    TaskTemplate: "task_templates",
}


def _relationship_owner_model(model: type) -> type:
    """Normalize proxy serializers to the concrete relationship owner."""

    return model._meta.concrete_model


def _policy_field_for_model(model: type) -> str | None:
    return _POLICY_FIELD_BY_MODEL.get(_relationship_owner_model(model))


def _authenticated_user(request):
    user = getattr(request, "user", None) if request is not None else None
    if user is None or not getattr(user, "is_authenticated", False):
        raise NotAuthenticated(
            "Authentication is required to change requirement-assessment links."
        )
    return user


def _actor_ids_for_user(user) -> tuple[UUID, ...]:
    # Team membership is governed by independently mutable through rows whose
    # writers do not participate in this boundary's lock protocol.  Treating a
    # team Actor as write authority would therefore permit a membership change
    # between reproof and commit.  Inverse RA writes deliberately accept only
    # the caller's direct, user-backed Actor until those writers share an epoch
    # or lock contract.
    return tuple(
        Actor.objects.filter(user_id=user.id)
        .order_by("id")
        .values_list("id", flat=True)
    )


def _read_actor_ids_for_user(user) -> tuple[UUID, ...]:
    """Return the canonical user/team Actor projection used by RA reads."""

    return tuple(sorted({actor.id for actor in Actor.get_all_for_user(user)}, key=str))


def _assignment_authority_snapshot(
    *,
    actor_ids: Iterable[UUID],
    assessment_ids: Iterable[UUID],
    ra_ids: Iterable[UUID],
) -> tuple[tuple[UUID, str, UUID], ...]:
    """Snapshot assignments that currently confer actor scope on these RAs."""

    bounded_actor_ids = tuple(actor_ids)
    bounded_assessment_ids = tuple(assessment_ids)
    bounded_ra_ids = tuple(ra_ids)
    if not bounded_actor_ids or not bounded_assessment_ids or not bounded_ra_ids:
        return ()
    return tuple(
        RequirementAssignment.objects.filter(
            compliance_assessment_id__in=bounded_assessment_ids,
            actor__id__in=bounded_actor_ids,
            requirement_assessments__id__in=bounded_ra_ids,
            compliance_assessment_id=F(
                "requirement_assessments__compliance_assessment_id"
            ),
        )
        .values_list("id", "status", "requirement_assessments__id")
        .order_by("id", "requirement_assessments__id")
        .distinct()
    )


def _through_target_fk_name(through_model: type, target_model: type) -> str:
    for field in through_model._meta.fields:
        remote_model = getattr(getattr(field, "remote_field", None), "model", None)
        if remote_model is target_model:
            return field.name
    raise ImproperlyConfigured(
        f"{through_model._meta.label} has no foreign key to {target_model._meta.label}."
    )


def _target_action_allowed(*, user, target, action: Literal["add", "change"]) -> bool:
    """Re-evaluate the target model's exact folder-scoped IAM permission."""

    target_model = type(target)
    folder = Folder.get_folder(target)
    if folder is None:
        return False
    try:
        permission = Permission.objects.get(
            codename=f"{action}_{target_model._meta.model_name}",
            content_type__app_label=target_model._meta.app_label,
            content_type__model=target_model._meta.model_name,
        )
        return RoleAssignment.is_access_allowed(
            user=user,
            perm=permission,
            folder=folder,
        )
    except Permission.DoesNotExist, Permission.MultipleObjectsReturned:
        return False


def _visible_relationship_rows(
    *,
    user,
    ra_ids: Iterable[UUID],
    policy_field: str,
    actor_ids: Iterable[UUID] | None = None,
) -> dict[UUID, RequirementAssessment]:
    """Return the caller's field-visible RA slice using existing IAM owners."""

    bounded_ids = frozenset(ra_ids)
    if not bounded_ids:
        return {}

    rows = list(
        RequirementAssessment.objects.select_related(
            "compliance_assessment",
            "compliance_assessment__framework",
            "requirement",
            "requirement__framework",
        )
        .filter(id__in=bounded_ids)
        .filter(
            id__in=RoleAssignment.get_viewable_object_ids(user, RequirementAssessment)
        )
        .filter(
            compliance_assessment_id__in=RoleAssignment.get_viewable_object_ids(
                user, ComplianceAssessment
            )
        )
        .filter(
            requirement_id__in=RoleAssignment.get_viewable_object_ids(
                user, RequirementNode
            ),
            requirement__framework_id__in=RoleAssignment.get_viewable_object_ids(
                user, Framework
            ),
            requirement__framework_id=F("compliance_assessment__framework_id"),
        )
    )
    assessment_ids = {row.compliance_assessment_id for row in rows}
    full_view_ids = set(
        ComplianceAssessment.objects.filter(id__in=assessment_ids)
        .filter(id__in=get_full_view_compliance_assessment_ids(user))
        .values_list("id", flat=True)
    )
    bounded_actor_ids = (
        _read_actor_ids_for_user(user) if actor_ids is None else tuple(actor_ids)
    )
    assigned_ids: set[UUID] = set()
    if bounded_actor_ids:
        assigned_ids = set(
            RequirementAssignment.objects.filter(
                compliance_assessment_id__in=assessment_ids,
                actor__id__in=bounded_actor_ids,
                requirement_assessments__id__in=bounded_ids,
                compliance_assessment_id=F(
                    "requirement_assessments__compliance_assessment_id"
                ),
            ).values_list("requirement_assessments__id", flat=True)
        )

    visible: dict[UUID, RequirementAssessment] = {}
    for row in rows:
        is_full_viewer = row.compliance_assessment_id in full_view_ids
        if not is_full_viewer and row.id not in assigned_ids:
            continue
        role = "auditor" if is_full_viewer else "respondent"
        if is_field_visible_to(row.compliance_assessment, policy_field, role):
            visible[row.id] = row
    return visible


def visible_requirement_assessment_rows(
    *,
    user,
    ra_ids: Iterable[UUID],
    policy_field: str,
) -> dict[UUID, RequirementAssessment]:
    """Public read projection for callers that render inverse RA relations."""

    return _visible_relationship_rows(
        user=user,
        ra_ids=ra_ids,
        policy_field=policy_field,
    )


def assert_requirement_assessment_rows_editable(
    *,
    user,
    rows: Iterable[RequirementAssessment],
    policy_field: str,
) -> None:
    """Apply the governed RA write policy to a bounded singular-link change.

    This is the validation boundary for models such as ``Finding`` whose link
    to a requirement assessment is a nullable foreign key rather than the
    inverse many-to-many relation managed by the authority mixin.  It reuses
    the same direct-user assignment, parent-chain, generic IAM, field policy
    and workflow rules.  Callers remain responsible for their host object's
    transaction and locking protocol.
    """

    if user is None or not getattr(user, "is_authenticated", False):
        raise NotAuthenticated(
            "Authentication is required to change requirement-assessment links."
        )

    row_ids = frozenset(row.id for row in rows if row is not None)
    if not row_ids:
        return

    actor_ids = _actor_ids_for_user(user)
    try:
        visible_rows = _visible_relationship_rows(
            user=user,
            ra_ids=row_ids,
            policy_field=policy_field,
            actor_ids=actor_ids,
        )
        changeable_ids = frozenset(
            RequirementAssessment.objects.filter(id__in=row_ids)
            .filter(
                id__in=RoleAssignment.get_changeable_object_ids(
                    user, RequirementAssessment
                )
            )
            .values_list("id", flat=True)
        )
    except (NotImplementedError, Permission.DoesNotExist) as exc:
        raise PermissionDenied(
            "One or more requirement assessments are unavailable for this change."
        ) from exc

    if frozenset(visible_rows) != row_ids or changeable_ids != row_ids:
        raise PermissionDenied(
            "One or more requirement assessments are unavailable for this change."
        )

    assessment_ids = frozenset(
        row.compliance_assessment_id for row in visible_rows.values()
    )
    try:
        full_view_ids = frozenset(
            ComplianceAssessment.objects.filter(id__in=assessment_ids)
            .filter(id__in=get_full_view_compliance_assessment_ids(user))
            .values_list("id", flat=True)
        )
    except (NotImplementedError, Permission.DoesNotExist) as exc:
        raise PermissionDenied(
            "One or more requirement assessments are unavailable for this change."
        ) from exc

    statuses_by_ra: dict[UUID, set[str]] = defaultdict(set)
    for _assignment_id, status, row_id in _assignment_authority_snapshot(
        actor_ids=actor_ids,
        assessment_ids=assessment_ids,
        ra_ids=row_ids,
    ):
        statuses_by_ra[row_id].add(status)

    for row_id, row in visible_rows.items():
        assessment = row.compliance_assessment
        if assessment.is_locked or assessment.status == Assessment.Status.IN_REVIEW:
            raise PermissionDenied(
                "A linked compliance assessment does not accept changes."
            )

        is_full_viewer = assessment.id in full_view_ids
        role = "auditor" if is_full_viewer else "respondent"
        if not is_field_editable_by(assessment, policy_field, role):
            raise PermissionDenied(
                "The requirement-assessment relationship is not editable for this caller."
            )

        if not is_full_viewer:
            statuses = statuses_by_ra.get(row_id)
            if not statuses:
                raise PermissionDenied(
                    "One or more requirement assessments are unavailable for this change."
                )
            if statuses & TERMINAL_ASSIGNMENT_STATUSES:
                raise PermissionDenied(
                    "A linked requirement assignment no longer accepts changes."
                )


def project_requirement_assessment_relationship_ids(
    *,
    user,
    target,
    policy_field: str,
) -> tuple[UUID, ...]:
    """Project only RA IDs that the caller may consume for this field.

    The target's full relationship is intentionally queried first only as a
    server-side candidate set.  Nothing outside the resulting IAM, assignment
    and field-visible slice is returned to the serializer response.
    """

    projected_ids, _projected_rows = _project_requirement_assessment_relationship(
        user=user,
        target=target,
        policy_field=policy_field,
    )
    return projected_ids


def _project_requirement_assessment_relationship(
    *,
    user,
    target,
    policy_field: str,
) -> tuple[tuple[UUID, ...], tuple[RequirementAssessment, ...]]:
    """Return one target's projected IDs and already-authorized rows."""

    if user is None or not getattr(user, "is_authenticated", False):
        return (), ()
    candidate_ids = tuple(
        target.requirement_assessments.order_by("id").values_list("id", flat=True)
    )
    visible = _visible_relationship_rows(
        user=user,
        ra_ids=candidate_ids,
        policy_field=policy_field,
    )
    projected_ids = tuple(row_id for row_id in candidate_ids if row_id in visible)
    return projected_ids, tuple(visible[row_id] for row_id in projected_ids)


def _batch_project_requirement_assessment_relationships(
    *,
    user,
    targets: Iterable[Any],
    policy_field: str,
) -> dict[UUID, tuple[tuple[UUID, ...], tuple[RequirementAssessment, ...]]]:
    """Project an entire serializer page with a fixed number of IAM queries."""

    bounded_targets = tuple(target for target in targets if target.pk is not None)
    target_ids = tuple(dict.fromkeys(target.pk for target in bounded_targets))
    empty_projection = {target_id: ((), ()) for target_id in target_ids}
    if not target_ids or user is None or not getattr(user, "is_authenticated", False):
        return empty_projection

    target_model = _relationship_owner_model(type(bounded_targets[0]))
    if any(
        _relationship_owner_model(type(target)) is not target_model
        for target in bounded_targets
    ):
        raise ImproperlyConfigured(
            "A relationship projection page cannot mix target model types."
        )

    relationship = target_model._meta.get_field(RELATION_FIELD)
    # Reverse M2M descriptors (Evidence/AppliedControl/SecurityException)
    # expose ``through`` directly on ManyToManyRel, while TaskTemplate owns
    # this relation as a forward ManyToManyField and exposes it through its
    # remote_field.  Normalize both metadata shapes before resolving the two
    # foreign-key columns below.
    through_model = getattr(relationship, "through", None)
    if through_model is None:
        through_model = getattr(
            getattr(relationship, "remote_field", None), "through", None
        )
    if through_model is None:
        raise ImproperlyConfigured(
            f"{target_model._meta.label}.{RELATION_FIELD} is not a many-to-many relationship."
        )
    target_fk = _through_target_fk_name(through_model, target_model)
    ra_fk = _through_target_fk_name(through_model, RequirementAssessment)
    links = tuple(
        through_model.objects.filter(**{f"{target_fk}_id__in": target_ids})
        .order_by(f"{target_fk}_id", f"{ra_fk}_id")
        .values_list(f"{target_fk}_id", f"{ra_fk}_id")
    )
    visible = _visible_relationship_rows(
        user=user,
        ra_ids=(ra_id for _target_id, ra_id in links),
        policy_field=policy_field,
    )
    projected_ids_by_target: dict[UUID, list[UUID]] = defaultdict(list)
    for target_id, ra_id in links:
        if ra_id in visible:
            projected_ids_by_target[target_id].append(ra_id)

    return {
        target_id: (
            tuple(projected_ids_by_target[target_id]),
            tuple(visible[ra_id] for ra_id in projected_ids_by_target[target_id]),
        )
        for target_id in target_ids
    }


def visible_requirement_assessment_relationship_ids(
    *,
    user,
    ra_ids: Iterable[UUID],
    policy_field: str,
) -> frozenset[UUID]:
    """Return the caller-visible read/filter slice for a bounded RA set."""

    return frozenset(
        _visible_relationship_rows(
            user=user,
            ra_ids=ra_ids,
            policy_field=policy_field,
        )
    )


def assert_requirement_assessment_filter_visible(
    *,
    user,
    ra_ids: Iterable[UUID],
    policy_field: str,
) -> None:
    """Reject both nonexistent and caller-hidden filter operands identically."""

    bounded_ids = frozenset(ra_ids)
    if (
        not bounded_ids
        or frozenset(
            _visible_relationship_rows(
                user=user,
                ra_ids=bounded_ids,
                policy_field=policy_field,
            )
        )
        != bounded_ids
    ):
        raise PermissionDenied(
            "One or more requirement assessments are unavailable for this filter."
        )


class GovernedRequirementAssessmentPrimaryKeyRelatedField(
    serializers.PrimaryKeyRelatedField
):
    """Resolve RA operands through the same fail-closed projection.

    DRF's default field distinguishes a missing UUID (400) from an existing but
    hidden UUID (a later 403).  This field intentionally maps both cases to the
    same authority failure without calling ``RequirementAssessment.__str__``.
    """

    def __init__(self, *args, policy_field: str | None = None, **kwargs):
        self.policy_field = policy_field
        super().__init__(*args, **kwargs)

    def to_internal_value(self, data):
        try:
            row_id = UUID(str(data))
        except TypeError, ValueError, AttributeError:
            raise PermissionDenied(
                "One or more requirement assessments are unavailable for this change."
            )
        model = self.root.Meta.model
        policy_field = self.policy_field or _policy_field_for_model(model)
        request = self.context.get("request")
        user = _authenticated_user(request)
        if policy_field is None:
            raise ImproperlyConfigured(
                "Unsupported inverse requirement-assessment relationship target."
            )
        row = _visible_relationship_rows(
            user=user,
            ra_ids=(row_id,),
            policy_field=policy_field,
            actor_ids=_actor_ids_for_user(user),
        ).get(row_id)
        if row is None:
            raise PermissionDenied(
                "One or more requirement assessments are unavailable for this change."
            )
        return row

    def to_representation(self, value):
        # An explicit policy field is used by singular relations such as
        # Finding.requirement_assessment. DRF returns the write serializer after
        # POST/PATCH, so the output path must enforce the same read projection as
        # the dedicated read serializer; otherwise an unrelated Finding edit can
        # echo a hidden RA UUID. Inverse plural serializers leave ``policy_field``
        # unset and are projected in one batch by their serializer mixin.
        if self.policy_field is None:
            return super().to_representation(value)
        request = self.context.get("request")
        user = getattr(request, "user", None) if request is not None else None
        if not getattr(user, "is_authenticated", False):
            return None
        row_id = getattr(value, "pk", value)
        visible = _visible_relationship_rows(
            user=user,
            ra_ids=(row_id,),
            policy_field=self.policy_field,
        )
        row = visible.get(row_id)
        if row is None:
            return None
        return super().to_representation(row)


def _snapshot_parent_links(
    ra_ids: Iterable[UUID],
) -> tuple[tuple[UUID, UUID, UUID, UUID, UUID], ...]:
    bounded_ids = frozenset(ra_ids)
    links = tuple(
        RequirementAssessment.objects.filter(id__in=bounded_ids)
        .order_by("id")
        .values_list(
            "id",
            "compliance_assessment_id",
            "requirement_id",
            "requirement__framework_id",
            "compliance_assessment__framework_id",
        )
    )
    if len(links) != len(bounded_ids):
        raise RequirementAssessmentRelationshipConflict()
    if any(
        requirement_framework != assessment_framework
        for *_, requirement_framework, assessment_framework in links
    ):
        raise PermissionDenied(
            "One or more requirement assessments have an invalid parent chain."
        )
    return links


def _lock_relationship_context(
    *,
    user,
    target_model: type,
    target_pk: UUID | None,
    plan: RequirementAssessmentRelationshipPlan,
    policy_field: str,
) -> _LockedRelationshipContext:
    """Acquire locks in this boundary's deterministic parent/child order.

    Unlocked reads are used only to discover the parent IDs that must be
    acquired.  Their identities are compared with the validation snapshot once
    the RA rows are locked; a concurrent parent move therefore aborts instead
    of causing an out-of-order late parent lock.

    The bounded order is Framework -> CA -> Assignment -> RequirementNode -> RA
    -> target -> fixed-order relationship rows -> Actor -> User.  Every queryset
    is ordered by primary key.  Team-derived Actor authority is intentionally
    excluded because Team membership writers do not share this lock protocol.
    The relative order of the shared assignment, assignment-actor relationship,
    Actor and User nodes is compatible with the assignment-mail boundary; this
    is not a claim that every repository writer participates in one globally
    closed lock protocol.
    """

    if getattr(user, "pk", None) != plan.user_pk:
        raise RequirementAssessmentRelationshipConflict()
    relationship_owner = _relationship_owner_model(target_model)
    if _policy_field_for_model(target_model) != policy_field:
        raise ImproperlyConfigured("Target model and assessment field do not match.")
    affected_ids = plan.baseline_ids | plan.requested_ids
    discovered_links = tuple(
        RequirementAssessment.objects.filter(id__in=affected_ids)
        .order_by("id")
        .values_list(
            "id",
            "compliance_assessment_id",
            "requirement_id",
            "requirement__framework_id",
            "compliance_assessment__framework_id",
        )
    )
    if discovered_links != plan.parent_links:
        raise RequirementAssessmentRelationshipConflict()

    assessment_ids = sorted({link[1] for link in discovered_links}, key=str)
    requirement_node_ids = sorted({link[2] for link in discovered_links}, key=str)
    framework_ids = sorted(
        {framework_id for link in discovered_links for framework_id in link[3:5]},
        key=str,
    )

    locked_frameworks = list(
        Framework.objects.select_for_update()
        .filter(id__in=framework_ids)
        .order_by("id")
    )
    if len(locked_frameworks) != len(framework_ids):
        raise RequirementAssessmentRelationshipConflict()

    # Boundary order: Framework -> ComplianceAssessment ->
    # RequirementAssignment -> RequirementNode -> RequirementAssessment ->
    # inverse relationship target.
    locked_assessments = list(
        ComplianceAssessment.objects.select_for_update()
        .filter(id__in=assessment_ids)
        .order_by("id")
    )
    if len(locked_assessments) != len(assessment_ids):
        raise RequirementAssessmentRelationshipConflict()
    assessments_by_id = {assessment.id: assessment for assessment in locked_assessments}

    locked_assignments = list(
        RequirementAssignment.objects.select_for_update()
        .filter(compliance_assessment_id__in=assessment_ids)
        .order_by("id")
    )
    assignment_ids = tuple(assignment.id for assignment in locked_assignments)

    locked_requirement_nodes = list(
        RequirementNode.objects.select_for_update()
        .filter(id__in=requirement_node_ids)
        .order_by("id")
    )
    if len(locked_requirement_nodes) != len(requirement_node_ids):
        raise RequirementAssessmentRelationshipConflict()
    requirement_framework_by_id = {
        node.id: node.framework_id for node in locked_requirement_nodes
    }

    locked_rows = list(
        RequirementAssessment.objects.select_for_update()
        .filter(id__in=affected_ids)
        .order_by("id")
    )
    locked_links = tuple(
        (
            row.id,
            row.compliance_assessment_id,
            row.requirement_id,
            requirement_framework_by_id.get(row.requirement_id),
            assessments_by_id[row.compliance_assessment_id].framework_id,
        )
        for row in locked_rows
    )
    if locked_links != plan.parent_links:
        raise RequirementAssessmentRelationshipConflict()
    rows_by_id = {row.id: row for row in locked_rows}

    target = None
    if target_pk is not None:
        target = (
            target_model.objects.select_for_update()
            .filter(id=target_pk)
            .order_by("id")
            .first()
        )
        if target is None:
            raise RequirementAssessmentRelationshipConflict()
        if not _target_action_allowed(user=user, target=target, action="change"):
            raise PermissionDenied(
                "The relationship target is unavailable for this change."
            )

    # Unlocked reads discover the complete old/new identity candidate set.
    # Only the fixed sequence below acquires locks; membership is re-evaluated
    # after that sequence and again immediately before commit.
    discovered_actor_ids = _actor_ids_for_user(user)
    actor_lock_ids = tuple(
        sorted(set(plan.actor_ids) | set(discovered_actor_ids), key=str)
    )
    # Fixed through-table order: target relationship, assignment-to-RA,
    # then assignment-to-actor.
    if target_pk is not None:
        target_through = relationship_owner.requirement_assessments.through
        target_fk_name = _through_target_fk_name(target_through, relationship_owner)
        list(
            target_through.objects.select_for_update()
            .filter(**{f"{target_fk_name}_id": target_pk})
            .order_by("id")
        )
    list(
        RequirementAssignment.requirement_assessments.through.objects.select_for_update()
        .filter(
            requirementassignment_id__in=assignment_ids,
            requirementassessment_id__in=affected_ids,
        )
        .order_by("id")
    )
    list(
        RequirementAssignment.actor.through.objects.select_for_update()
        .filter(requirementassignment_id__in=assignment_ids)
        .order_by("id")
    )
    list(Actor.objects.select_for_update().filter(id__in=actor_lock_ids).order_by("id"))
    locked_user = (
        User.objects.select_for_update()
        .filter(id=plan.user_pk, is_active=True)
        .order_by("id")
        .first()
    )
    if locked_user is None:
        raise NotAuthenticated(
            "Authentication is required to change requirement-assessment links."
        )

    if target_pk is not None:
        current_ids = frozenset(
            target.requirement_assessments.values_list("id", flat=True)
        )
        if current_ids != plan.baseline_ids:
            raise RequirementAssessmentRelationshipConflict()

    actor_ids = _actor_ids_for_user(locked_user)
    if actor_ids != plan.actor_ids:
        raise RequirementAssessmentRelationshipConflict()
    assignment_authority_snapshot = _assignment_authority_snapshot(
        actor_ids=actor_ids,
        assessment_ids=assessment_ids,
        ra_ids=affected_ids,
    )
    if assignment_authority_snapshot != plan.assignment_authority_snapshot:
        raise RequirementAssessmentRelationshipConflict()

    assignment_statuses_by_ra: dict[UUID, set[str]] = {}
    for _assignment_id, assignment_status, ra_id in assignment_authority_snapshot:
        assignment_statuses_by_ra.setdefault(ra_id, set()).add(assignment_status)

    generic_view_assessment_ids = frozenset(
        ComplianceAssessment.objects.filter(id__in=assessment_ids)
        .filter(
            id__in=RoleAssignment.get_viewable_object_ids(
                locked_user, ComplianceAssessment
            )
        )
        .values_list("id", flat=True)
    )
    full_view_assessment_ids = frozenset(
        ComplianceAssessment.objects.filter(id__in=assessment_ids)
        .filter(id__in=get_full_view_compliance_assessment_ids(locked_user))
        .values_list("id", flat=True)
    )
    generic_view_ra_ids = frozenset(
        RequirementAssessment.objects.filter(id__in=affected_ids)
        .filter(
            id__in=RoleAssignment.get_viewable_object_ids(
                locked_user, RequirementAssessment
            )
        )
        .values_list("id", flat=True)
    )
    generic_change_ra_ids = frozenset(
        RequirementAssessment.objects.filter(id__in=affected_ids)
        .filter(
            id__in=RoleAssignment.get_changeable_object_ids(
                locked_user, RequirementAssessment
            )
        )
        .values_list("id", flat=True)
    )
    generic_view_requirement_node_ids = frozenset(
        RequirementNode.objects.filter(id__in=requirement_node_ids)
        .filter(
            id__in=RoleAssignment.get_viewable_object_ids(locked_user, RequirementNode)
        )
        .values_list("id", flat=True)
    )
    generic_view_framework_ids = frozenset(
        Framework.objects.filter(id__in=framework_ids)
        .filter(id__in=RoleAssignment.get_viewable_object_ids(locked_user, Framework))
        .values_list("id", flat=True)
    )

    return _LockedRelationshipContext(
        user=locked_user,
        target=target,
        rows_by_id=rows_by_id,
        assessments_by_id=assessments_by_id,
        assignment_ids=assignment_ids,
        assignment_statuses_by_ra={
            ra_id: frozenset(statuses)
            for ra_id, statuses in assignment_statuses_by_ra.items()
        },
        full_view_assessment_ids=full_view_assessment_ids,
        generic_view_assessment_ids=generic_view_assessment_ids,
        generic_view_ra_ids=generic_view_ra_ids,
        generic_change_ra_ids=generic_change_ra_ids,
        generic_view_requirement_node_ids=generic_view_requirement_node_ids,
        generic_view_framework_ids=generic_view_framework_ids,
    )


def _revalidate_authority_snapshot(
    context: _LockedRelationshipContext,
    plan: RequirementAssessmentRelationshipPlan,
) -> None:
    """Recheck actor/assignment membership and IAM before transaction commit.

    The bounded assessment aggregates, direct user Actor and User row remain
    locked.  Team-derived Actor authority is not accepted here, and generic
    role assignments are intentionally not absorbed into this aggregate's lock
    graph.  Querying them again narrows the race window and fails closed on an
    observed change, but it does not make IAM revocation commit-stable under
    PostgreSQL READ COMMITTED: a grant can still change after this final query
    and before commit.  Closing that residual requires a shared IAM authority
    epoch/lock (used by both IAM mutators and governed writes), or an equivalent
    serializable protocol with retries.  Do not describe this helper as closing
    that separate IAM-administration race.
    """

    actor_ids = _actor_ids_for_user(context.user)
    if actor_ids != plan.actor_ids:
        raise RequirementAssessmentRelationshipConflict()
    affected_ids = plan.baseline_ids | plan.requested_ids
    assessment_ids = tuple(context.assessments_by_id)
    requirement_node_ids = tuple(
        sorted({row.requirement_id for row in context.rows_by_id.values()}, key=str)
    )
    framework_ids = tuple(
        sorted(
            {
                framework_id
                for row in context.rows_by_id.values()
                for framework_id in (
                    row.requirement.framework_id,
                    context.assessments_by_id[
                        row.compliance_assessment_id
                    ].framework_id,
                )
            },
            key=str,
        )
    )
    if (
        _assignment_authority_snapshot(
            actor_ids=actor_ids,
            assessment_ids=assessment_ids,
            ra_ids=affected_ids,
        )
        != plan.assignment_authority_snapshot
    ):
        raise RequirementAssessmentRelationshipConflict()
    if context.target is not None:
        if not _target_action_allowed(
            user=context.user,
            target=context.target,
            action="change",
        ):
            raise RequirementAssessmentRelationshipConflict()

    current_view_assessment_ids = frozenset(
        ComplianceAssessment.objects.filter(id__in=assessment_ids)
        .filter(
            id__in=RoleAssignment.get_viewable_object_ids(
                context.user, ComplianceAssessment
            )
        )
        .values_list("id", flat=True)
    )
    current_full_view_ids = frozenset(
        ComplianceAssessment.objects.filter(id__in=assessment_ids)
        .filter(id__in=get_full_view_compliance_assessment_ids(context.user))
        .values_list("id", flat=True)
    )
    current_view_ra_ids = frozenset(
        RequirementAssessment.objects.filter(id__in=affected_ids)
        .filter(
            id__in=RoleAssignment.get_viewable_object_ids(
                context.user, RequirementAssessment
            )
        )
        .values_list("id", flat=True)
    )
    current_change_ra_ids = frozenset(
        RequirementAssessment.objects.filter(id__in=affected_ids)
        .filter(
            id__in=RoleAssignment.get_changeable_object_ids(
                context.user, RequirementAssessment
            )
        )
        .values_list("id", flat=True)
    )
    current_view_requirement_node_ids = frozenset(
        RequirementNode.objects.filter(id__in=requirement_node_ids)
        .filter(
            id__in=RoleAssignment.get_viewable_object_ids(context.user, RequirementNode)
        )
        .values_list("id", flat=True)
    )
    current_view_framework_ids = frozenset(
        Framework.objects.filter(id__in=framework_ids)
        .filter(id__in=RoleAssignment.get_viewable_object_ids(context.user, Framework))
        .values_list("id", flat=True)
    )
    current_parent_links = tuple(
        RequirementAssessment.objects.filter(id__in=affected_ids)
        .order_by("id")
        .values_list(
            "id",
            "compliance_assessment_id",
            "requirement_id",
            "requirement__framework_id",
            "compliance_assessment__framework_id",
        )
    )
    if (
        current_view_assessment_ids != context.generic_view_assessment_ids
        or current_full_view_ids != context.full_view_assessment_ids
        or current_view_ra_ids != context.generic_view_ra_ids
        or current_change_ra_ids != context.generic_change_ra_ids
        or current_view_requirement_node_ids
        != context.generic_view_requirement_node_ids
        or current_view_framework_ids != context.generic_view_framework_ids
        or current_parent_links != plan.parent_links
    ):
        raise RequirementAssessmentRelationshipConflict()


def _visible_ids_from_locked_context(
    context: _LockedRelationshipContext,
    *,
    policy_field: str,
) -> frozenset[UUID]:
    visible: set[UUID] = set()
    for ra_id, row in context.rows_by_id.items():
        assessment_id = row.compliance_assessment_id
        if (
            ra_id not in context.generic_view_ra_ids
            or assessment_id not in context.generic_view_assessment_ids
            or row.requirement_id not in context.generic_view_requirement_node_ids
            or row.requirement.framework_id not in context.generic_view_framework_ids
            or row.requirement.framework_id
            != context.assessments_by_id[assessment_id].framework_id
        ):
            continue
        is_full_viewer = assessment_id in context.full_view_assessment_ids
        if not is_full_viewer and ra_id not in context.assignment_statuses_by_ra:
            continue
        assessment = context.assessments_by_id[assessment_id]
        role = "auditor" if is_full_viewer else "respondent"
        if is_field_visible_to(assessment, policy_field, role):
            visible.add(ra_id)
    return frozenset(visible)


def _authorize_delta(
    context: _LockedRelationshipContext,
    *,
    delta_ids: frozenset[UUID],
    policy_field: str,
) -> None:
    for ra_id in delta_ids:
        row = context.rows_by_id.get(ra_id)
        if row is None:
            raise RequirementAssessmentRelationshipConflict()
        assessment_id = row.compliance_assessment_id
        if (
            ra_id not in context.generic_view_ra_ids
            or ra_id not in context.generic_change_ra_ids
            or assessment_id not in context.generic_view_assessment_ids
            or row.requirement_id not in context.generic_view_requirement_node_ids
            or row.requirement.framework_id not in context.generic_view_framework_ids
            or row.requirement.framework_id
            != context.assessments_by_id[assessment_id].framework_id
        ):
            raise PermissionDenied(
                "One or more requirement assessments are unavailable for this change."
            )

        assessment = context.assessments_by_id[assessment_id]
        if assessment.is_locked or assessment.status == Assessment.Status.IN_REVIEW:
            raise PermissionDenied(
                "A linked compliance assessment does not accept changes."
            )

        is_full_viewer = assessment_id in context.full_view_assessment_ids
        role = "auditor" if is_full_viewer else "respondent"
        if not is_field_editable_by(assessment, policy_field, role):
            raise PermissionDenied(
                "The requirement-assessment relationship is not editable for this caller."
            )

        if not is_full_viewer:
            statuses = context.assignment_statuses_by_ra.get(ra_id)
            if not statuses:
                raise PermissionDenied(
                    "One or more requirement assessments are unavailable for this change."
                )
            if statuses & TERMINAL_ASSIGNMENT_STATUSES:
                raise PermissionDenied(
                    "A linked requirement assignment no longer accepts changes."
                )


class RequirementAssessmentRelationshipProjectionMixin:
    """Caller-scoped response projection for inverse RA relationships."""

    def _projection_cache_key(
        self, instance
    ) -> tuple[str, UUID | None, UUID | None, str]:
        request = self.context.get("request")
        user = getattr(request, "user", None) if request is not None else None
        return (
            self.Meta.model._meta.label_lower,
            getattr(instance, "pk", None),
            getattr(user, "pk", None),
            self._policy_field(),
        )

    def _prime_requirement_assessment_projection(self, instances) -> None:
        """Seed caller-scoped ID and row caches once for a serializer page."""

        bounded_instances = tuple(
            instance for instance in instances if isinstance(instance, Model)
        )
        if not bounded_instances:
            return
        request = self.context.get("request")
        user = getattr(request, "user", None) if request is not None else None
        projections = _batch_project_requirement_assessment_relationships(
            user=user,
            targets=bounded_instances,
            policy_field=self._policy_field(),
        )
        id_cache = self.context.setdefault("_inverse_ra_projection_cache", {})
        row_cache = self.context.setdefault("_inverse_ra_projection_rows_cache", {})
        for instance in bounded_instances:
            cache_key = self._projection_cache_key(instance)
            projected_ids, projected_rows = projections.get(instance.pk, ((), ()))
            id_cache[cache_key] = projected_ids
            row_cache[cache_key] = projected_rows

    def _policy_field(self) -> str:
        model = self.Meta.model
        expected = _policy_field_for_model(model)
        configured = getattr(self, "requirement_assessment_policy_field", None)
        if expected is None or (configured is not None and configured != expected):
            raise ImproperlyConfigured(
                "RequirementAssessment relationship projection supports only "
                "Evidence/evidences, AppliedControl/applied_controls and "
                "SecurityException/security_exceptions or "
                "TaskTemplate/task_templates."
            )
        return configured or expected

    def _projected_requirement_assessment_ids(self, instance) -> tuple[UUID, ...]:
        request = self.context.get("request")
        if request is None:
            # Internal/export callers must opt into an authenticated request
            # context.  Contextless serialization intentionally omits this
            # authority-bearing relation and its derived flags.
            return ()
        user = getattr(request, "user", None)
        cache = self.context.setdefault("_inverse_ra_projection_cache", {})
        row_cache = self.context.setdefault("_inverse_ra_projection_rows_cache", {})
        cache_key = self._projection_cache_key(instance)
        if cache_key not in cache or cache_key not in row_cache:
            projected_ids, projected_rows = (
                _project_requirement_assessment_relationship(
                    user=user,
                    target=instance,
                    policy_field=self._policy_field(),
                )
            )
            cache[cache_key] = projected_ids
            row_cache[cache_key] = projected_rows
        return cache[cache_key]

    @staticmethod
    def _represented_relationship_id(value):
        if isinstance(value, dict):
            return value.get("id")
        return value

    def to_representation(self, instance):
        if not isinstance(instance, Model):
            # DRF may represent validated dictionaries for write serializers
            # configured with ``many=True``. They have no database relation to
            # project and must retain the ordinary ListSerializer behavior.
            return super().to_representation(instance)
        if RELATION_FIELD not in self.fields:
            # Some list serializers need only the projected IDs for a derived
            # flag. Do not hydrate relationship rows that cannot be rendered.
            return super().to_representation(instance)

        projected_ids = self._projected_requirement_assessment_ids(instance)
        cache_key = self._projection_cache_key(instance)
        projected_rows = self.context.setdefault(
            "_inverse_ra_projection_rows_cache", {}
        ).get(cache_key, ())
        cache_existed = hasattr(instance, "_prefetched_objects_cache")
        original_cache = getattr(instance, "_prefetched_objects_cache", None)
        prefetched = (original_cache or {}).copy()
        instance._prefetched_objects_cache = prefetched
        prefetched[RELATION_FIELD] = list(projected_rows)
        try:
            # Scope the manager before FieldsRelatedField invokes ``__str__``;
            # filtering only the rendered payload would leak hidden parent data.
            data = super().to_representation(instance)
        finally:
            if cache_existed:
                instance._prefetched_objects_cache = original_cache
            else:
                delattr(instance, "_prefetched_objects_cache")
        if RELATION_FIELD not in data:
            return data
        visible_ids = {str(row_id) for row_id in projected_ids}
        data[RELATION_FIELD] = [
            value
            for value in data.get(RELATION_FIELD, ())
            if str(self._represented_relationship_id(value)) in visible_ids
        ]
        return data


class RequirementAssessmentRelationshipProjectionListSerializer(
    serializers.ListSerializer
):
    """Batch reads, and fail closed before unsupported governed bulk writes."""

    def to_internal_value(self, data):
        if isinstance(data, list) and hasattr(
            self.child, "governed_batch_delta_fields"
        ):
            # One child serializer instance is reused across ``many=True``
            # validation. Its authority plan is intentionally single-target,
            # so accepting a list could overwrite that plan and partially
            # apply heterogeneous items. The explicit batch-action endpoint
            # owns multi-target writes.
            raise serializers.ValidationError(
                {
                    "non_field_errors": (
                        "Bulk writes for governed relationship targets must use the "
                        "governed batch-action endpoint."
                    ),
                }
            )
        return super().to_internal_value(data)

    def to_representation(self, data):
        iterable = data.all() if isinstance(data, BaseManager) else data
        instances = list(iterable)
        self.child._prime_requirement_assessment_projection(instances)
        prime_applied_control_projection = getattr(
            self.child, "_prime_applied_control_request_projections", None
        )
        if prime_applied_control_projection is not None:
            prime_applied_control_projection(instances)
        return super().to_representation(instances)


class RequirementAssessmentRelationshipAuthorityMixin(
    RequirementAssessmentRelationshipProjectionMixin
):
    """Serializer integration for governed inverse RA relationship deltas.

    Add this mixin to the write serializer's bases.  ``Meta.model`` selects the
    matching assessment field automatically; an explicit
    ``requirement_assessment_policy_field`` may be supplied but must match the
    supported model mapping.
    """

    requirement_assessment_policy_field: ClassVar[str | None] = None
    governed_batch_delta_fields: ClassVar[frozenset[str]] = frozenset({RELATION_FIELD})
    _relationship_plan: RequirementAssessmentRelationshipPlan | None = None

    def _relationship_operation(self) -> RelationshipOperation:
        operation = self.context.get(BATCH_RELATION_OPERATION_CONTEXT_KEY, "replace")
        if operation not in {"replace", "add", "remove"}:
            raise ImproperlyConfigured(
                "Unsupported governed requirement-assessment relationship operation."
            )
        return operation

    def _check_m2m_visibility(self, validated_data: dict) -> None:
        """Delegate every relation except the stricter bounded RA relation."""

        if RELATION_FIELD in validated_data:
            _authenticated_user(self.context.get("request"))
        return super()._check_m2m_visibility(
            {
                name: value
                for name, value in validated_data.items()
                if name != RELATION_FIELD
            }
        )

    def _reject_mixed_many_relationships(self, attrs: dict) -> None:
        """Keep the governed lock graph bounded to this one M2M delta."""

        # Creation has no pre-existing target or relationship baseline for a
        # competing writer to mutate.  Its scalar and ordinary M2M fields may
        # therefore be persisted with the governed relation in the same outer
        # transaction.  Existing-object updates stay relation-only.
        if self.instance is None or RELATION_FIELD not in attrs:
            return
        for serializer_name, serializer_field in self.fields.items():
            if serializer_name == RELATION_FIELD:
                continue
            source = serializer_field.source
            if source in (None, "*"):
                source = serializer_name
            source = source.split(".", 1)[0]
            if source not in attrs and serializer_name not in attrs:
                continue
            if getattr(serializer_field, "child_relation", None) is not None:
                raise serializers.ValidationError(
                    {
                        RELATION_FIELD: (
                            "A governed requirement-assessment change cannot be "
                            "combined with another multi-value relationship."
                        )
                    }
                )
            try:
                model_field = self.Meta.model._meta.get_field(source)
            except FieldDoesNotExist:
                continue
            if model_field.many_to_many or model_field.one_to_many:
                raise serializers.ValidationError(
                    {
                        RELATION_FIELD: (
                            "A governed requirement-assessment change cannot be "
                            "combined with another multi-value relationship."
                        )
                    }
                )

    def to_internal_value(self, data):
        # This gate runs before DRF resolves any UUID, foreign key or file.
        # On update, an ordinary edit form may echo the exact caller-visible
        # relationship slice alongside scalar fields.  Treat that unchanged
        # echo as omitted, while rejecting every attempted mixed delta before
        # any submitted UUID/FK/file is resolved.  Creation is safe to combine:
        # there is no existing target/baseline, and create() persists the new
        # target plus all relationships inside the governed transaction.
        if (
            self.instance is not None
            and RELATION_FIELD in data
            and any(field_name != RELATION_FIELD for field_name in data)
        ):
            raw_values = (
                data.getlist(RELATION_FIELD)
                if hasattr(data, "getlist")
                else data.get(RELATION_FIELD)
            )
            if not isinstance(raw_values, (list, tuple)):
                raw_values = (raw_values,)
            try:
                submitted_ids = tuple(UUID(str(value)) for value in raw_values)
            except TypeError, ValueError, AttributeError:
                submitted_ids = ()
            request = self.context.get("request")
            user = getattr(request, "user", None)
            projected_ids = project_requirement_assessment_relationship_ids(
                user=user,
                target=self.instance,
                policy_field=self._policy_field(),
            )
            unchanged_echo = len(submitted_ids) == len(
                set(submitted_ids)
            ) and frozenset(submitted_ids) == frozenset(projected_ids)
            if not unchanged_echo:
                raise serializers.ValidationError(
                    {
                        RELATION_FIELD: (
                            "Requirement-assessment links must be changed alone "
                            "on an existing object."
                        )
                    }
                )
            data = data.copy()
            data.pop(RELATION_FIELD, None)
        # Keep the relation-typed check as a second line of defense if the raw
        # contract is widened in the future.
        self._reject_mixed_many_relationships(data)
        return super().to_internal_value(data)

    def _build_relationship_plan(
        self, validated_data: dict
    ) -> RequirementAssessmentRelationshipPlan:
        request = self.context.get("request")
        user = _authenticated_user(request)
        submitted_rows = tuple(validated_data.get(RELATION_FIELD, ()))
        submitted_ids = tuple(row.id for row in submitted_rows)
        if len(set(submitted_ids)) != len(submitted_ids):
            raise serializers.ValidationError(
                {RELATION_FIELD: "Duplicate requirement assessments are not allowed."}
            )
        requested_ids = frozenset(submitted_ids)

        target_pk = getattr(self.instance, "pk", None)
        operation = self._relationship_operation()
        if target_pk is None and operation != "replace":
            raise ImproperlyConfigured(
                "Delta relationship operations require an existing target."
            )
        baseline_ids = (
            frozenset(
                self.instance.requirement_assessments.values_list("id", flat=True)
            )
            if target_pk is not None
            else frozenset()
        )
        affected_ids = baseline_ids | requested_ids
        parent_links = _snapshot_parent_links(affected_ids)
        assessment_ids = {link[1] for link in parent_links}
        actor_ids = _actor_ids_for_user(user)
        assignment_authority_snapshot = _assignment_authority_snapshot(
            actor_ids=actor_ids,
            assessment_ids=assessment_ids,
            ra_ids=affected_ids,
        )
        policy_field = self._policy_field()
        visible = _visible_relationship_rows(
            user=user,
            ra_ids=affected_ids,
            policy_field=policy_field,
            actor_ids=actor_ids,
        )
        visible_ids = frozenset(visible)
        if not requested_ids <= visible_ids:
            raise PermissionDenied(
                "One or more requirement assessments are unavailable for this change."
            )

        return RequirementAssessmentRelationshipPlan(
            target_pk=target_pk,
            operation=operation,
            requested_ids=requested_ids,
            baseline_ids=baseline_ids,
            visible_baseline_ids=baseline_ids & visible_ids,
            parent_links=parent_links,
            user_pk=user.pk,
            actor_ids=actor_ids,
            assignment_authority_snapshot=assignment_authority_snapshot,
        )

    def validate(self, attrs):
        attrs = super().validate(attrs)
        self._relationship_plan = None
        if RELATION_FIELD in attrs:
            self._reject_mixed_many_relationships(attrs)
            self._relationship_plan = self._build_relationship_plan(attrs)
        return attrs

    def _validated_plan(
        self, validated_data: dict
    ) -> RequirementAssessmentRelationshipPlan:
        plan = self._relationship_plan
        submitted_ids = frozenset(
            row.id for row in validated_data.get(RELATION_FIELD, ())
        )
        target_pk = getattr(self.instance, "pk", None)
        if (
            plan is None
            or submitted_ids != plan.requested_ids
            or target_pk != plan.target_pk
            or self._relationship_operation() != plan.operation
        ):
            raise RequirementAssessmentRelationshipConflict()
        return plan

    def _guarded_relationship_values(
        self,
        *,
        plan: RequirementAssessmentRelationshipPlan,
        target_model: type,
    ) -> tuple[
        _LockedRelationshipContext,
        list[RequirementAssessment] | None,
        frozenset[UUID],
    ]:
        request = self.context.get("request")
        user = _authenticated_user(request)
        context = _lock_relationship_context(
            user=user,
            target_model=target_model,
            target_pk=plan.target_pk,
            plan=plan,
            policy_field=self._policy_field(),
        )
        policy_field = self._policy_field()
        locked_visible_ids = _visible_ids_from_locked_context(
            context,
            policy_field=policy_field,
        )
        if locked_visible_ids & plan.baseline_ids != plan.visible_baseline_ids:
            raise RequirementAssessmentRelationshipConflict()
        if not plan.requested_ids <= locked_visible_ids:
            raise PermissionDenied(
                "One or more requirement assessments are unavailable for this change."
            )

        current_ids = plan.baseline_ids
        visible_current_ids = locked_visible_ids & current_ids
        if plan.operation == "replace":
            desired_visible_ids = plan.requested_ids
        elif plan.operation == "add":
            desired_visible_ids = visible_current_ids | plan.requested_ids
        else:
            desired_visible_ids = visible_current_ids - plan.requested_ids
        delta_ids = frozenset(visible_current_ids ^ desired_visible_ids)
        _authorize_delta(
            context,
            delta_ids=delta_ids,
            policy_field=policy_field,
        )

        # Omission controls only the caller-visible slice.  Existing rows that
        # are outside it remain linked and are never handed to DRF as removals.
        hidden_existing_ids = current_ids - locked_visible_ids
        desired_ids = hidden_existing_ids | desired_visible_ids
        if desired_ids == current_ids:
            return context, None, delta_ids
        return (
            context,
            [context.rows_by_id[row_id] for row_id in sorted(desired_ids, key=str)],
            delta_ids,
        )

    def create(self, validated_data: dict):
        if RELATION_FIELD not in validated_data:
            return super().create(validated_data)
        plan = self._validated_plan(validated_data)
        with transaction.atomic():
            context, desired_rows, delta_ids = self._guarded_relationship_values(
                plan=plan,
                target_model=self.Meta.model,
            )
            if desired_rows is None:
                validated_data.pop(RELATION_FIELD, None)
            else:
                validated_data[RELATION_FIELD] = desired_rows
            instance = super().create(validated_data)
            if not _target_action_allowed(
                user=context.user,
                target=instance,
                action="add",
            ):
                raise RequirementAssessmentRelationshipConflict()
            _revalidate_authority_snapshot(context, plan)
            _authorize_delta(
                context,
                delta_ids=delta_ids,
                policy_field=self._policy_field(),
            )
            expected_ids = plan.requested_ids
            actual_ids = frozenset(
                instance.requirement_assessments.values_list("id", flat=True)
            )
            if actual_ids != expected_ids:
                raise RequirementAssessmentRelationshipConflict()
            return instance

    def update(self, instance, validated_data: dict):
        if RELATION_FIELD not in validated_data:
            return super().update(instance, validated_data)
        plan = self._validated_plan(validated_data)
        with transaction.atomic():
            context, desired_rows, delta_ids = self._guarded_relationship_values(
                plan=plan,
                target_model=self.Meta.model,
            )
            locked_target = context.target
            if locked_target is None:
                raise RequirementAssessmentRelationshipConflict()
            self._governed_locked_scalar_snapshot = {
                field.attname: getattr(locked_target, field.attname)
                for field in locked_target._meta.concrete_fields
            }
            self.instance = locked_target
            if desired_rows is None:
                validated_data.pop(RELATION_FIELD, None)
                expected_ids = plan.baseline_ids
            else:
                validated_data[RELATION_FIELD] = desired_rows
                expected_ids = frozenset(row.id for row in desired_rows)
            updated = super().update(locked_target, validated_data)
            _revalidate_authority_snapshot(context, plan)
            _authorize_delta(
                context,
                delta_ids=delta_ids,
                policy_field=self._policy_field(),
            )
            actual_ids = frozenset(
                updated.requirement_assessments.values_list("id", flat=True)
            )
            if actual_ids != expected_ids:
                raise RequirementAssessmentRelationshipConflict()
            return updated
