"""Deletion authority for the EntityAssessment aggregate root."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from django.contrib.auth.models import Permission
from django.db import models, transaction
from django.db.models.deletion import CASCADE
from rest_framework.exceptions import PermissionDenied

from core.deletion_authority import lock_and_assert_no_surviving_reverse_owners
from core.models import Actor, ComplianceAssessment, Evidence, Perimeter
from core.relation_locking import lock_rows_in_global_model_order
from iam.models import Folder, RoleAssignment, User
from tprm.models import Entity, EntityAssessment, Representative, Solution


@dataclass(frozen=True)
class ForwardRelationSpec:
    """One explicitly governed outgoing relation in the EA deletion graph."""

    field_name: str
    target_model: type[models.Model]
    many_to_many: bool = False


ENTITY_ASSESSMENT_FORWARD_RELATIONS = (
    ForwardRelationSpec("folder", Folder),
    ForwardRelationSpec("perimeter", Perimeter),
    ForwardRelationSpec("entity", Entity),
    ForwardRelationSpec("compliance_assessment", ComplianceAssessment),
    ForwardRelationSpec("evidence", Evidence),
    ForwardRelationSpec("reviewers", Actor, many_to_many=True),
    ForwardRelationSpec("authors", Actor, many_to_many=True),
    ForwardRelationSpec("representatives", User, many_to_many=True),
    ForwardRelationSpec("solutions", Solution, many_to_many=True),
)
ENTITY_ASSESSMENT_CASCADE_RELATIONS: frozenset[tuple[str, str]] = frozenset()


@dataclass(frozen=True)
class _M2MSnapshot:
    field_name: str
    through: type[models.Model]
    row_filter: dict[str, Any]
    source_attname: str
    target_attname: str
    target_model: type[models.Model]
    rows: tuple[tuple[Any, Any, Any], ...]


def assert_entity_assessment_deletion_manifest() -> None:
    """Fail closed if model metadata outgrows the audited deletion graph."""

    expected_forward = {
        (
            spec.field_name,
            spec.target_model._meta.label_lower,
            spec.many_to_many,
        )
        for spec in ENTITY_ASSESSMENT_FORWARD_RELATIONS
    }
    actual_forward = {
        (field.name, field.related_model._meta.label_lower, field.many_to_many)
        for field in EntityAssessment._meta.get_fields()
        if not field.auto_created
        and field.is_relation
        and (field.many_to_many or field.many_to_one or field.one_to_one)
    }
    actual_cascades = {
        (relation.related_model._meta.label_lower, relation.field.name)
        for relation in EntityAssessment._meta.related_objects
        if (relation.one_to_many or relation.one_to_one)
        and relation.field.remote_field.on_delete is CASCADE
    }
    if (
        actual_forward != expected_forward
        or actual_cascades != ENTITY_ASSESSMENT_CASCADE_RELATIONS
    ):
        raise PermissionDenied("The entity-assessment deletion graph is unsupported.")


def _m2m_snapshot(
    instance: EntityAssessment, field_name: str
) -> _M2MSnapshot:
    field = instance._meta.get_field(field_name)
    through = field.remote_field.through
    source_field = through._meta.get_field(field.m2m_field_name())
    target_field = through._meta.get_field(field.m2m_reverse_field_name())
    row_filter = {source_field.attname: instance.id}
    rows = tuple(
        through._base_manager.filter(**row_filter)
        .order_by("pk")
        .values_list("pk", source_field.attname, target_field.attname)
    )
    return _M2MSnapshot(
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
            "Complete entity-assessment data is unavailable for this caller."
        ) from exc
    if not row_ids.issubset(visible_ids):
        raise PermissionDenied(
            "Complete entity-assessment data is unavailable for this caller."
        )


def lock_entity_assessment_deletion_graph(
    *,
    user,
    entity_assessment: EntityAssessment,
    allowed_reverse_owner_ids_by_relation: Mapping[
        tuple[str, str], set[Any]
    ]
    | None = None,
) -> None:
    """Lock and authorize every relation exposed or unlinked by EA deletion.

    The caller holds Folder's root-row mutex and has already locked the EA and
    its owner folder.  This helper is invoked for both standalone and linked
    assessments; the linked path composes it with core's complete CA graph.
    """

    if not transaction.get_connection().in_atomic_block:
        raise RuntimeError("Entity-assessment deletion requires a transaction.")
    assert_entity_assessment_deletion_manifest()

    expected_owner = (
        EntityAssessment.objects.filter(id=entity_assessment.id)
        .values(
            "id",
            "folder_id",
            "perimeter_id",
            "entity_id",
            "compliance_assessment_id",
            "evidence_id",
        )
        .get()
    )
    if any(
        expected_owner[field_name] != getattr(entity_assessment, field_name)
        for field_name in expected_owner
    ):
        raise PermissionDenied("The entity assessment changed; retry.")

    lock_and_assert_no_surviving_reverse_owners(
        instance=entity_assessment,
        allowed_owner_ids_by_relation=allowed_reverse_owner_ids_by_relation,
    )

    snapshots = tuple(
        _m2m_snapshot(entity_assessment, field_name)
        for field_name in ("authors", "reviewers", "representatives", "solutions")
    )
    target_ids_by_model: dict[type[models.Model], set[Any]] = defaultdict(set)
    for snapshot in snapshots:
        target_ids_by_model[snapshot.target_model].update(
            target_id for _pk, _owner_id, target_id in snapshot.rows
        )
    for field_name, model in (
        ("folder_id", Folder),
        ("perimeter_id", Perimeter),
        ("entity_id", Entity),
        ("compliance_assessment_id", ComplianceAssessment),
        ("evidence_id", Evidence),
    ):
        target_id = expected_owner[field_name]
        if target_id is not None:
            target_ids_by_model[model].add(target_id)

    representative_snapshot = next(
        snapshot for snapshot in snapshots if snapshot.field_name == "representatives"
    )
    representative_user_ids = {
        target_id for _pk, _owner_id, target_id in representative_snapshot.rows
    }
    representative_actor_ids = set(
        Actor.objects.filter(user_id__in=representative_user_ids).values_list(
            "id", flat=True
        )
    )
    representative_rows = tuple(
        Representative.objects.filter(
            entity_id=expected_owner["entity_id"],
            user_id__in=representative_user_ids,
        )
        .order_by("id")
        .values_list("id", "entity_id", "user_id")
    )
    target_ids_by_model[Actor].update(representative_actor_ids)
    target_ids_by_model[Representative].update(row[0] for row in representative_rows)

    # Match authoritative EA writers: independently governed targets first,
    # then relationship rows.  Folder's root mutex serializes owner changes and
    # reverse collection/flow writers before this inner dependency order.
    locked_targets = lock_rows_in_global_model_order(target_ids_by_model)
    for snapshot in sorted(
        snapshots,
        key=lambda item: (item.through._meta.db_table, item.field_name),
    ):
        list(
            snapshot.through._base_manager.select_for_update(of=("self",))
            .filter(**snapshot.row_filter)
            .order_by("pk")
        )

    current_owner = (
        EntityAssessment.objects.filter(id=entity_assessment.id)
        .values(*expected_owner)
        .get()
    )
    if current_owner != expected_owner:
        raise PermissionDenied("The entity assessment changed; retry.")
    for snapshot in snapshots:
        current_rows = tuple(
            snapshot.through._base_manager.filter(**snapshot.row_filter)
            .order_by("pk")
            .values_list("pk", snapshot.source_attname, snapshot.target_attname)
        )
        if current_rows != snapshot.rows:
            raise PermissionDenied(
                "Entity-assessment relationships changed; retry."
            )

    locked_users = locked_targets.get(User, {})
    locked_actors = locked_targets.get(Actor, {})
    actor_user_ids = {
        actor.user_id
        for actor_id, actor in locked_actors.items()
        if actor_id in representative_actor_ids and actor.user_id is not None
    }
    locked_representatives = locked_targets.get(Representative, {})
    bound_user_ids = {
        row.user_id
        for row in locked_representatives.values()
        if row.entity_id == expected_owner["entity_id"] and row.user_id is not None
    }
    if representative_user_ids and (
        actor_user_ids != representative_user_ids
        or bound_user_ids != representative_user_ids
        or len(locked_representatives) != len(representative_user_ids)
        or any(
            not locked_users[user_id].is_active
            or not locked_users[user_id].is_third_party
            for user_id in representative_user_ids
        )
    ):
        raise PermissionDenied("The assessment representative graph is inconsistent.")

    solution_snapshot = next(
        snapshot for snapshot in snapshots if snapshot.field_name == "solutions"
    )
    solution_ids = {
        target_id for _pk, _owner_id, target_id in solution_snapshot.rows
    }
    if any(
        locked_targets[Solution][solution_id].provider_entity_id
        != expected_owner["entity_id"]
        for solution_id in solution_ids
    ):
        raise PermissionDenied("The assessment solution graph is inconsistent.")

    for model, rows_by_id in locked_targets.items():
        _assert_fully_visible(user, model, set(rows_by_id))
