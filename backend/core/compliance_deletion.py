"""Governed deletion closure for a complete compliance assessment.

The generic compliance-assessment endpoint and aggregate-owned paths such as
TPRM must authorize the same database graph.  Keeping that graph in ``core``
prevents an extension view from becoming the only place where core cascade,
mail, relationship, and IAM invariants are enforced.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

from django.contrib.auth.models import Permission
from django.db import models, transaction
from django.db.models.deletion import CASCADE
from rest_framework.exceptions import PermissionDenied

from core.deletion_authority import lock_and_assert_no_surviving_reverse_owners
from core.models import (
    Actor,
    Answer,
    Asset,
    Campaign,
    Comment,
    ComplianceAssessment,
    Evidence,
    Framework,
    Perimeter,
    Question,
    QuestionChoice,
    RequirementAssessment,
    RequirementAssignment,
    RequirementAssignmentEvent,
    RequirementAssignmentMailEvidence,
    RequirementAssignmentMailOutbox,
    RequirementNode,
)
from core.relation_locking import (
    lock_questionnaire_owner_graph,
    lock_rows_in_global_model_order,
)
from iam.models import Folder, RoleAssignment, User

CompleteAccessCheck = Callable[[Any, ComplianceAssessment], None]


@dataclass(frozen=True)
class ForwardRelationSpec:
    """One explicitly governed outgoing relation in a deletion graph."""

    field_name: str
    target_model: type[models.Model]
    many_to_many: bool = False


COMPLIANCE_ASSESSMENT_FORWARD_RELATIONS = (
    ForwardRelationSpec("folder", Folder),
    ForwardRelationSpec("perimeter", Perimeter),
    ForwardRelationSpec("reviewers", Actor, many_to_many=True),
    ForwardRelationSpec("authors", Actor, many_to_many=True),
    ForwardRelationSpec("framework", Framework),
    ForwardRelationSpec("assets", Asset, many_to_many=True),
    ForwardRelationSpec("campaign", Campaign),
    ForwardRelationSpec("evidences", Evidence, many_to_many=True),
)
COMPLIANCE_ASSESSMENT_CASCADE_RELATIONS = frozenset(
    {
        ("core.requirementassessment", "compliance_assessment"),
        ("core.requirementassignment", "compliance_assessment"),
    }
)


def assert_compliance_assessment_deletion_manifest() -> None:
    """Fail closed if model metadata outgrows the audited deletion graph."""

    expected_forward = {
        (
            spec.field_name,
            spec.target_model._meta.label_lower,
            spec.many_to_many,
        )
        for spec in COMPLIANCE_ASSESSMENT_FORWARD_RELATIONS
    }
    actual_forward = {
        (field.name, field.related_model._meta.label_lower, field.many_to_many)
        for field in ComplianceAssessment._meta.get_fields()
        if not field.auto_created
        and field.is_relation
        and (field.many_to_many or field.many_to_one or field.one_to_one)
    }
    actual_cascades = {
        (relation.related_model._meta.label_lower, relation.field.name)
        for relation in ComplianceAssessment._meta.related_objects
        if (relation.one_to_many or relation.one_to_one)
        and relation.field.remote_field.on_delete is CASCADE
    }
    if (
        actual_forward != expected_forward
        or actual_cascades != COMPLIANCE_ASSESSMENT_CASCADE_RELATIONS
    ):
        raise PermissionDenied("The audit deletion graph is unsupported.")


@dataclass(frozen=True)
class _M2MSnapshot:
    owner_model: type[models.Model]
    field_name: str
    through: type[models.Model]
    row_filter: dict[str, Any]
    source_attname: str
    target_attname: str
    target_model: type[models.Model]
    rows: tuple[tuple[Any, Any, Any], ...]


def _projection(queryset) -> tuple[dict[str, Any], ...]:
    fields = tuple(field.attname for field in queryset.model._meta.concrete_fields)
    return tuple(queryset.order_by("pk").values(*fields))


def _m2m_snapshot(
    model: type[models.Model], field_name: str, owner_ids: set[Any]
) -> _M2MSnapshot:
    field = model._meta.get_field(field_name)
    through = field.remote_field.through
    source_field = through._meta.get_field(field.m2m_field_name())
    target_field = through._meta.get_field(field.m2m_reverse_field_name())
    row_filter = {f"{source_field.attname}__in": owner_ids}
    rows = tuple(
        through._base_manager.filter(**row_filter)
        .order_by("pk")
        .values_list("pk", source_field.attname, target_field.attname)
    )
    return _M2MSnapshot(
        owner_model=model,
        field_name=field_name,
        through=through,
        row_filter=row_filter,
        source_attname=source_field.attname,
        target_attname=target_field.attname,
        target_model=field.remote_field.model,
        rows=rows,
    )


def _assert_fully_visible(user, model, row_ids: set[Any]) -> None:
    if not row_ids:
        return
    try:
        visible_ids = set(RoleAssignment.get_viewable_object_ids(user, model))
    except (NotImplementedError, Permission.DoesNotExist) as exc:
        raise PermissionDenied(
            "Complete audit data is unavailable for this caller."
        ) from exc
    if not row_ids.issubset(visible_ids):
        raise PermissionDenied("Complete audit data is unavailable for this caller.")


def assert_complete_compliance_assessment_deletion_access(
    user, audit: ComplianceAssessment
) -> None:
    """Require complete, non-redacted visibility for every deleted carrier."""

    # Imported lazily because ``core.views`` imports this module to invoke the
    # graph from its generic delete endpoint.
    from core.utils import has_full_view_compliance_assessment
    from core.views import ComplianceAssessmentViewSet

    if not has_full_view_compliance_assessment(user, audit):
        raise PermissionDenied("Complete audit data is unavailable for this caller.")
    try:
        ComplianceAssessmentViewSet._assert_complete_assessment_read_access(
            user, audit
        )
        ComplianceAssessmentViewSet._assert_baseline_questionnaire_access(user, audit)
    except (NotImplementedError, Permission.DoesNotExist) as exc:
        raise PermissionDenied(
            "Complete audit data is unavailable for this caller."
        ) from exc

    requirement_assessments = RequirementAssessment.objects.filter(
        compliance_assessment_id=audit.id
    )
    ra_ids = set(requirement_assessments.values_list("id", flat=True))
    answers = Answer.objects.filter(requirement_assessment_id__in=ra_ids)

    required_fields = {"status", "result"}
    if audit.has_questions:
        required_fields.add("answers")
    if requirement_assessments.filter(score__isnull=False).exists():
        required_fields.update({"score", "is_scored"})
    if requirement_assessments.filter(documentation_score__isnull=False).exists():
        required_fields.add("documentation_score")
    if requirement_assessments.filter(extended_result__isnull=False).exists():
        required_fields.add("extended_result")
    if requirement_assessments.filter(respondent_alignment__isnull=False).exists():
        required_fields.add("respondent_alignment")
    if requirement_assessments.exclude(observation__in=(None, "")).exists():
        required_fields.add("observation")
    for field_name in ("applied_controls", "evidences", "security_exceptions"):
        field = RequirementAssessment._meta.get_field(field_name)
        source_name = field.m2m_field_name()
        if field.remote_field.through._base_manager.filter(
            **{f"{source_name}_id__in": ra_ids}
        ).exists():
            required_fields.add(field_name)
    ComplianceAssessmentViewSet._assert_auditor_fields_visible(
        audit, *sorted(required_fields)
    )

    visible_models_and_ids = (
        (RequirementAssessment, ra_ids),
        (Answer, set(answers.values_list("id", flat=True))),
        (
            RequirementAssignment,
            set(
                RequirementAssignment.objects.filter(
                    compliance_assessment_id=audit.id
                ).values_list("id", flat=True)
            ),
        ),
        (
            Comment,
            set(
                Comment.objects.filter(
                    requirement_assessment_id__in=ra_ids
                ).values_list("id", flat=True)
            ),
        ),
        (
            RequirementAssignmentEvent,
            set(
                RequirementAssignmentEvent.objects.filter(
                    assignment__compliance_assessment_id=audit.id
                ).values_list("id", flat=True)
            ),
        ),
        (
            RequirementAssignmentMailOutbox,
            set(
                RequirementAssignmentMailOutbox.objects.filter(
                    assignment__compliance_assessment_id=audit.id
                ).values_list("id", flat=True)
            ),
        ),
        (Asset, set(audit.assets.values_list("id", flat=True))),
        (Evidence, set(audit.evidences.values_list("id", flat=True))),
        (Actor, set(audit.authors.values_list("id", flat=True))),
        (Actor, set(audit.reviewers.values_list("id", flat=True))),
    )
    for model, row_ids in visible_models_and_ids:
        _assert_fully_visible(user, model, row_ids)

    # Audit author/reviewer expansion includes the independently governed
    # User/Team/Entity carrier and any users exposed by that carrier.
    try:
        ComplianceAssessmentViewSet._get_word_report_actor_projection(user, audit)
    except (KeyError, NotImplementedError, Permission.DoesNotExist) as exc:
        raise PermissionDenied(
            "Complete audit data is unavailable for this caller."
        ) from exc


def _assert_delete_permissions(
    *,
    user,
    audit: ComplianceAssessment,
    child_models_with_rows: tuple[tuple[type[models.Model], bool], ...],
) -> None:
    """Cascades bypass child viewsets, so bind every child delete permission."""

    for model, has_rows in child_models_with_rows:
        if not has_rows:
            continue
        try:
            permission = Permission.objects.get(
                content_type__app_label=model._meta.app_label,
                content_type__model=model._meta.model_name,
                codename=f"delete_{model._meta.model_name}",
            )
        except Permission.DoesNotExist as exc:
            raise PermissionDenied("Audit subresource authority is unavailable.") from exc
        if not RoleAssignment.is_access_allowed(
            user=user,
            perm=permission,
            folder=audit.folder,
        ):
            raise PermissionDenied(
                "You cannot delete one or more audit subresources."
            )


def lock_compliance_assessment_deletion_graph(
    *,
    user,
    audit: ComplianceAssessment,
    entity_assessment: models.Model | None = None,
    allowed_reverse_owner_ids_by_relation: Mapping[
        tuple[str, str], set[Any]
    ]
    | None = None,
    complete_access_check: CompleteAccessCheck | None = None,
) -> None:
    """Lock, re-prove, and authorize the complete audit deletion closure.

    ``audit`` and its owner folder must already be fresh and row-locked, and
    callers must hold ``Folder._lock_folder_tree()``.  TPRM may allow its exact
    locked EntityAssessment (and already-authorized collection links); the
    generic path passes no exceptions and therefore rejects every surviving
    reverse owner.
    """

    if not transaction.get_connection().in_atomic_block:
        raise RuntimeError("Compliance-assessment deletion requires a transaction.")
    assert_compliance_assessment_deletion_manifest()
    if entity_assessment is not None and (
        getattr(entity_assessment, "compliance_assessment_id", None) != audit.id
    ):
        raise PermissionDenied("The linked audit owner is inconsistent.")

    allowed_reverse_owners = {
        relation_key: set(owner_ids)
        for relation_key, owner_ids in (
            allowed_reverse_owner_ids_by_relation or {}
        ).items()
    }
    if entity_assessment is not None:
        # The aggregate argument itself is the authority boundary.  Never rely
        # on a caller to remember this exception, and never accept a broader EA
        # allow-list than the exact row whose delete path is executing.
        allowed_reverse_owners[
            ("tprm.entityassessment", "compliance_assessment")
        ] = {entity_assessment.id}

    lock_and_assert_no_surviving_reverse_owners(
        instance=audit,
        allowed_owner_ids_by_relation=allowed_reverse_owners,
        relation_error_messages={
            (
                "tprm.entityassessment",
                "compliance_assessment",
            ): "entityAssessmentOwnedAudit",
        },
    )

    framework_queryset = Framework.objects.filter(id=audit.framework_id)
    framework_projection = _projection(framework_queryset)
    node_queryset = RequirementNode.objects.filter(framework_id=audit.framework_id)
    node_projection = _projection(node_queryset)
    node_ids = {row["id"] for row in node_projection}
    question_queryset = Question.objects.filter(requirement_node_id__in=node_ids)
    question_projection = _projection(question_queryset)
    question_ids = {row["id"] for row in question_projection}
    choice_queryset = QuestionChoice.objects.filter(question_id__in=question_ids)
    choice_projection = _projection(choice_queryset)
    choice_ids = {row["id"] for row in choice_projection}

    ra_queryset = RequirementAssessment.objects.filter(
        compliance_assessment_id=audit.id
    )
    ra_projection = _projection(ra_queryset)
    ra_ids = {row["id"] for row in ra_projection}
    answer_queryset = Answer.objects.filter(requirement_assessment_id__in=ra_ids)
    answer_projection = _projection(answer_queryset)
    answer_ids = {row["id"] for row in answer_projection}
    assignment_queryset = RequirementAssignment.objects.filter(
        compliance_assessment_id=audit.id
    )
    assignment_projection = _projection(assignment_queryset)
    assignment_ids = {row["id"] for row in assignment_projection}
    comment_queryset = Comment.objects.filter(requirement_assessment_id__in=ra_ids)
    comment_projection = _projection(comment_queryset)
    event_queryset = RequirementAssignmentEvent.objects.filter(
        assignment_id__in=assignment_ids
    )
    event_projection = _projection(event_queryset)
    outbox_queryset = RequirementAssignmentMailOutbox.objects.filter(
        assignment_id__in=assignment_ids
    )
    outbox_projection = _projection(outbox_queryset)
    mail_evidence_queryset = RequirementAssignmentMailEvidence.objects.filter(
        assignment_id_snapshot__in=assignment_ids
    )
    mail_evidence_projection = _projection(mail_evidence_queryset)

    through_snapshots: list[_M2MSnapshot] = []
    graph_relations: list[
        tuple[type[models.Model], tuple[str, ...], set[Any]]
    ] = [
        (RequirementNode, ("threats", "reference_controls"), node_ids),
        (
            ComplianceAssessment,
            ("authors", "reviewers", "assets", "evidences"),
            {audit.id},
        ),
        (
            RequirementAssessment,
            ("applied_controls", "evidences", "security_exceptions"),
            ra_ids,
        ),
        (Answer, ("selected_choices",), answer_ids),
        (
            RequirementAssignment,
            ("actor", "requirement_assessments"),
            assignment_ids,
        ),
    ]
    for model, field_names, owner_ids in graph_relations:
        for field_name in field_names:
            through_snapshots.append(_m2m_snapshot(model, field_name, owner_ids))

    locked_frameworks = list(
        framework_queryset.select_for_update(of=("self",)).order_by("id")
    )
    if len(locked_frameworks) != 1:
        raise PermissionDenied("The audit framework is unavailable.")
    lock_questionnaire_owner_graph(
        user=user,
        requirement_node_ids=node_ids,
        question_ids=question_ids,
        choice_ids=choice_ids,
    )

    # Mail delivery workers lock Outbox -> Assignment.  Use the identical
    # dependency order before any assignment child to avoid a delete/worker
    # deadlock and to make the external-effect decision stable.
    locked_outboxes = list(
        outbox_queryset.select_for_update(of=("self",)).order_by("id")
    )
    if _projection(outbox_queryset) != outbox_projection:
        raise PermissionDenied("Assignment mail state changed; retry.")
    terminal_mail_statuses = {
        RequirementAssignmentMailOutbox.Status.DELIVERED,
        RequirementAssignmentMailOutbox.Status.FAILED,
    }
    if any(
        outbox.status not in terminal_mail_statuses for outbox in locked_outboxes
    ):
        raise PermissionDenied(
            "The audit has queued or sending assignment mail, or an unresolved "
            "ambiguous delivery outcome."
        )

    locked_assignments = list(
        assignment_queryset.select_for_update(of=("self",)).order_by("id")
    )
    locked_mail_evidence = list(
        mail_evidence_queryset.select_for_update(of=("self",)).order_by("id")
    )
    locked_events = list(
        event_queryset.select_for_update(of=("self",)).order_by("id")
    )
    locked_ras = list(ra_queryset.select_for_update(of=("self",)).order_by("id"))
    locked_answers = list(
        answer_queryset.select_for_update(of=("self",)).order_by("id")
    )
    locked_comments = list(
        comment_queryset.select_for_update(of=("self",)).order_by("id")
    )
    target_ids_by_model: dict[type[models.Model], set[Any]] = defaultdict(set)
    for snapshot in through_snapshots:
        # These owned rows and questionnaire choices are already locked in the
        # dependency order above.  Existing serializers lock independently
        # governed targets before their through rows; use the same order here.
        if snapshot.target_model not in {
            RequirementAssessment,
            QuestionChoice,
        }:
            target_ids_by_model[snapshot.target_model].update(
                row[2] for row in snapshot.rows
            )
    target_ids_by_model[Actor].update(
        row["recipient_actor_id"]
        for row in outbox_projection
        if row["recipient_actor_id"] is not None
    )
    target_ids_by_model[User].update(
        row["requested_by_id"]
        for row in outbox_projection
        if row["requested_by_id"] is not None
    )
    target_ids_by_model[User].update(
        row["event_actor_id"]
        for row in event_projection
        if row["event_actor_id"] is not None
    )
    target_ids_by_model[User].update(
        row["author_id"]
        for row in comment_projection
        if row["author_id"] is not None
    )
    if audit.perimeter_id is not None:
        target_ids_by_model[Perimeter].add(audit.perimeter_id)
    if audit.campaign_id is not None:
        target_ids_by_model[Campaign].add(audit.campaign_id)
    locked_targets = lock_rows_in_global_model_order(target_ids_by_model)

    # Folder's root-row mutex is acquired by this delete path and every
    # authoritative CA/EA/collection/flow relation writer before owner/target
    # locks.  It serializes the broader graph; target -> through then matches
    # those writers once inside that critical section.  The mail worker does
    # not take the mutex, so Outbox -> Assignment remains the earlier explicit
    # dependency order.
    for snapshot in sorted(
        through_snapshots,
        key=lambda item: (item.through._meta.db_table, item.field_name),
    ):
        list(
            snapshot.through._base_manager.select_for_update(of=("self",))
            .filter(**snapshot.row_filter)
            .order_by("pk")
        )

    if (
        _projection(framework_queryset) != framework_projection
        or _projection(node_queryset) != node_projection
        or _projection(question_queryset) != question_projection
        or _projection(choice_queryset) != choice_projection
        or _projection(ra_queryset) != ra_projection
        or _projection(answer_queryset) != answer_projection
        or _projection(assignment_queryset) != assignment_projection
        or _projection(comment_queryset) != comment_projection
        or _projection(event_queryset) != event_projection
        or _projection(outbox_queryset) != outbox_projection
        or _projection(mail_evidence_queryset) != mail_evidence_projection
    ):
        raise PermissionDenied("The linked audit changed; retry.")

    locked_ra_by_id = {row.id: row for row in locked_ras}
    locked_answer_by_id = {row.id: row for row in locked_answers}
    question_owner = {
        row["id"]: row["requirement_node_id"] for row in question_projection
    }
    choice_owner = {row["id"]: row["question_id"] for row in choice_projection}
    if any(
        row.folder_id != audit.folder_id or row.requirement_id not in node_ids
        for row in locked_ras
    ):
        raise PermissionDenied("The linked audit tree is inconsistent.")
    if any(
        row.folder_id != audit.folder_id
        or row.requirement_assessment_id not in ra_ids
        or question_owner.get(row.question_id)
        != locked_ra_by_id[row.requirement_assessment_id].requirement_id
        for row in locked_answers
    ):
        raise PermissionDenied("The linked questionnaire is inconsistent.")
    if any(row.folder_id != audit.folder_id for row in locked_assignments):
        raise PermissionDenied("The audit assignment scope is inconsistent.")
    if any(
        row.folder_id != audit.folder_id or row.assignment_id not in assignment_ids
        for row in locked_events
    ):
        raise PermissionDenied("The audit assignment event scope is inconsistent.")
    if any(
        row.folder_id != audit.folder_id or row.assignment_id not in assignment_ids
        for row in locked_outboxes
    ):
        raise PermissionDenied("The audit mail owner is inconsistent.")
    if any(
        row.folder_id != audit.folder_id
        or row.requirement_assessment_id not in ra_ids
        or row.risk_scenario_id is not None
        or row.applied_control_id is not None
        or row.finding_id is not None
        for row in locked_comments
    ):
        raise PermissionDenied("The audit comment scope is inconsistent.")

    outbox_ids = {row.id for row in locked_outboxes}
    if any(
        row.folder_id_snapshot != audit.folder_id
        or row.assignment_id_snapshot not in assignment_ids
        or row.outbox_id_snapshot not in outbox_ids
        for row in locked_mail_evidence
    ):
        raise PermissionDenied("The retained audit mail evidence is inconsistent.")
    evidence_by_outbox_id: dict[Any, list[RequirementAssignmentMailEvidence]] = (
        defaultdict(list)
    )
    for row in locked_mail_evidence:
        evidence_by_outbox_id[row.outbox_id_snapshot].append(row)
    if any(
        not any(
            evidence.assignment_id_snapshot == outbox.assignment_id
            and evidence.folder_id_snapshot == outbox.folder_id
            and evidence.recipient_actor_id_snapshot == outbox.recipient_actor_id
            and evidence.requested_by_id_snapshot == outbox.requested_by_id
            and evidence.status == outbox.status
            and evidence.attempts == outbox.attempts
            and evidence.payload_digest == outbox.payload_digest
            and evidence.recipient_address_hash == outbox.recipient_address_hash
            and evidence.failure_code == outbox.failure_code
            for evidence in evidence_by_outbox_id[outbox.id]
        )
        for outbox in locked_outboxes
    ):
        raise PermissionDenied(
            "Terminal assignment mail has no matching immutable evidence."
        )

    for snapshot in through_snapshots:
        current_rows = tuple(
            snapshot.through._base_manager.filter(**snapshot.row_filter)
            .order_by("pk")
            .values_list(
                "pk", snapshot.source_attname, snapshot.target_attname
            )
        )
        if current_rows != snapshot.rows:
            raise PermissionDenied("Audit relationships changed; retry.")
        if (
            snapshot.owner_model is Answer
            and snapshot.field_name == "selected_choices"
            and any(
                choice_owner.get(choice_id)
                != locked_answer_by_id[answer_id].question_id
                for _pk, answer_id, choice_id in current_rows
            )
        ):
            raise PermissionDenied("The linked questionnaire is inconsistent.")
        if (
            snapshot.owner_model is RequirementAssignment
            and snapshot.field_name == "requirement_assessments"
            and any(
                requirement_assessment_id not in ra_ids
                for _pk, _assignment_id, requirement_assessment_id in current_rows
            )
        ):
            raise PermissionDenied("The audit assignment scope is inconsistent.")

    # Recompute visibility only after rows and relation targets are stable.
    (complete_access_check or assert_complete_compliance_assessment_deletion_access)(
        user, audit
    )
    for model, rows_by_id in locked_targets.items():
        _assert_fully_visible(user, model, set(rows_by_id))

    _assert_delete_permissions(
        user=user,
        audit=audit,
        child_models_with_rows=(
            (RequirementAssessment, bool(locked_ras)),
            (Answer, bool(locked_answers)),
            (RequirementAssignment, bool(locked_assignments)),
            (RequirementAssignmentEvent, bool(locked_events)),
            (RequirementAssignmentMailOutbox, bool(locked_outboxes)),
            (Comment, bool(locked_comments)),
        ),
    )
