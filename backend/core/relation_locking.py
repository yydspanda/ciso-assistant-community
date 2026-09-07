"""Deterministic row locking for heterogeneous authority-bearing relations.

This module deliberately contains no policy decisions.  Callers still own the
post-lock IAM check; this helper only makes the objects used by that check
stable for the rest of the transaction.
"""

from collections import defaultdict
from collections.abc import Iterable, Mapping
from typing import Any

from django.db import models, transaction
from rest_framework.exceptions import PermissionDenied


def lock_owner_folder_write_scope(
    *,
    model: type[models.Model],
    validated_data: dict,
    instance: models.Model | None = None,
) -> tuple[models.Model | None, models.Model | None, models.Model]:
    """Bind an owner write to fresh, locked current and destination folders.

    The caller takes ``Folder._lock_folder_tree()`` first.  DRF field validation
    happens before the transaction and therefore cannot be the final authority
    for a folder move.  This helper re-reads the owner, locks both folders in a
    stable order, rejects a concurrent owner move, and replaces a submitted
    folder object with the locked row.  The serializer must then repeat its
    current-folder ``change`` and destination-folder ``add`` checks while these
    locks and the root IAM mutex are held.
    """

    from iam.models import Folder

    if not transaction.get_connection().in_atomic_block:
        raise RuntimeError("Owner folder authority requires a transaction.")

    current_folder_id = None
    if instance is not None:
        current_folder_id = (
            model._base_manager.filter(pk=instance.pk)
            .values_list("folder_id", flat=True)
            .first()
        )
        if current_folder_id is None:
            raise PermissionDenied("The object is unavailable.")

    submitted_folder = validated_data.get("folder")
    if "folder" in validated_data and submitted_folder is None:
        raise PermissionDenied("The destination folder is unavailable.")
    if submitted_folder is not None:
        destination_folder_id = getattr(submitted_folder, "pk", None)
        if destination_folder_id is None:
            raise PermissionDenied("The destination folder is unavailable.")
    elif current_folder_id is not None:
        destination_folder_id = current_folder_id
    else:
        destination_folder_id = Folder.get_root_folder().pk

    folder_ids = {destination_folder_id}
    if current_folder_id is not None:
        folder_ids.add(current_folder_id)
    locked_folders = {
        folder.pk: folder
        for folder in Folder.objects.select_for_update(of=("self",))
        .filter(pk__in=folder_ids)
        .order_by("pk")
    }
    if set(locked_folders) != folder_ids:
        raise PermissionDenied("One or more owner folders are unavailable.")

    locked_instance = None
    current_folder = None
    if instance is not None:
        locked_instance = model._base_manager.select_for_update(of=("self",)).get(
            pk=instance.pk
        )
        if locked_instance.folder_id != current_folder_id:
            raise PermissionDenied("The object folder changed; retry.")
        current_folder = locked_folders[current_folder_id]
        locked_instance.folder = current_folder

    destination_folder = locked_folders[destination_folder_id]
    if "folder" in validated_data:
        validated_data["folder"] = destination_folder
    return locked_instance, current_folder, destination_folder


def lock_rows_in_global_model_order(
    target_ids_by_model: Mapping[type[models.Model], Iterable[Any]],
) -> dict[type[models.Model], dict[Any, models.Model]]:
    """Lock heterogeneous targets by one dependency-aware concrete order.

    ``Actor`` IAM is derived from its specific ``User``, ``Team``, or ``Entity``
    row rather than from ``core_actor`` itself.  Capture that binding before
    locking, include the specific row in the same global lock plan, and verify
    the binding again after all locks are held.  A caller can then recompute
    Actor visibility without a concurrent owner-folder move invalidating the
    decision before commit.
    """

    from core.models import Actor, Team
    from iam.models import User
    from tprm.models import Entity

    requested_ids_by_model: dict[type[models.Model], set[Any]] = defaultdict(set)
    canonical_ids_by_model: dict[type[models.Model], set[Any]] = defaultdict(set)
    for model, target_ids in target_ids_by_model.items():
        requested_ids = set(target_ids)
        requested_ids_by_model[model].update(requested_ids)
        canonical_ids_by_model[model._meta.concrete_model].update(requested_ids)

    actor_ids = canonical_ids_by_model.get(Actor, set())
    actor_binding_snapshots: dict[Any, tuple[Any, Any, Any]] = {}
    if actor_ids:
        actor_binding_snapshots = {
            actor_id: (user_id, team_id, entity_id)
            for actor_id, user_id, team_id, entity_id in Actor.objects.filter(
                id__in=actor_ids
            ).values_list("id", "user_id", "team_id", "entity_id")
        }
        if set(actor_binding_snapshots) != actor_ids:
            raise PermissionDenied("One or more related objects are unavailable.")
        for user_id, team_id, entity_id in actor_binding_snapshots.values():
            if user_id is not None:
                canonical_ids_by_model[User].add(user_id)
            elif team_id is not None:
                canonical_ids_by_model[Team].add(team_id)
            elif entity_id is not None:
                canonical_ids_by_model[Entity].add(entity_id)
            else:
                raise PermissionDenied("One or more related objects are unavailable.")

    locked_canonical: dict[type[models.Model], dict[Any, models.Model]] = {}
    for model in sorted(
        canonical_ids_by_model,
        # Specific carriers are updated/deleted before their cascading Actor
        # row.  Keep Actor in a final tier so this helper follows that existing
        # dependency order while retaining label order within each tier.
        key=lambda candidate: (
            candidate is Actor,
            candidate._meta.label_lower,
        ),
    ):
        target_ids = canonical_ids_by_model[model]
        locked_rows = {
            row.id: row
            for row in model.objects.select_for_update(of=("self",))
            .filter(id__in=target_ids)
            .order_by("id")
        }
        if set(locked_rows) != target_ids:
            raise PermissionDenied("One or more related objects are unavailable.")
        locked_canonical[model] = locked_rows

    if actor_binding_snapshots:
        locked_actors = locked_canonical[Actor]
        for actor_id, expected_binding in actor_binding_snapshots.items():
            actor = locked_actors[actor_id]
            if (actor.user_id, actor.team_id, actor.entity_id) != expected_binding:
                raise PermissionDenied("One or more related objects are unavailable.")

    locked_by_model = dict(locked_canonical)
    for model, target_ids in requested_ids_by_model.items():
        concrete_model = model._meta.concrete_model
        if model is concrete_model:
            locked_by_model[model] = {
                target_id: locked_canonical[concrete_model][target_id]
                for target_id in target_ids
            }
            continue
        proxy_rows = {
            row.id: row
            for row in model.objects.filter(id__in=target_ids).order_by("id")
        }
        if set(proxy_rows) != target_ids:
            raise PermissionDenied("One or more related objects are unavailable.")
        locked_by_model[model] = proxy_rows
    return locked_by_model


def lock_assessment_relation_targets(validated_data: dict, *, user=None) -> None:
    """Stabilize CA/EA M2M targets before a collection or flow writes links.

    EntityAssessment relocation also holds the folder-tree mutex.  Requiring
    every authoritative reverse-relation writer to take the same mutex closes
    the phantom-row window where a link could be inserted after relocation had
    observed an empty through table.  Target and owner folders are re-read
    under row locks before the serializer performs its M2M ``set``.
    """

    from core.models import ComplianceAssessment
    from iam.models import Folder, RoleAssignment
    from tprm.models import EntityAssessment

    if not transaction.get_connection().in_atomic_block:
        raise RuntimeError("Assessment relation locking requires a transaction.")

    relation_models = {
        "compliance_assessments": ComplianceAssessment,
        "entity_assessments": EntityAssessment,
    }
    requested_ids: dict[str, set[Any]] = {}
    for field_name in relation_models:
        if field_name not in validated_data:
            continue
        values = list(validated_data[field_name])
        ids = {getattr(value, "pk", None) for value in values}
        if None in ids or len(ids) != len(values):
            raise PermissionDenied("One or more assessment links are unavailable.")
        requested_ids[field_name] = ids
    if not requested_ids:
        return

    direct_ca_ids = requested_ids.get("compliance_assessments", set())
    ea_ids = requested_ids.get("entity_assessments", set())
    ea_snapshots = {
        row_id: (folder_id, compliance_assessment_id)
        for row_id, folder_id, compliance_assessment_id in EntityAssessment.objects.filter(
            id__in=ea_ids
        ).values_list("id", "folder_id", "compliance_assessment_id")
    }
    if set(ea_snapshots) != ea_ids:
        raise PermissionDenied("One or more assessment links are unavailable.")
    ca_ids = set(direct_ca_ids)
    ca_ids.update(
        compliance_assessment_id
        for _folder_id, compliance_assessment_id in ea_snapshots.values()
        if compliance_assessment_id is not None
    )
    ca_folder_snapshots = dict(
        ComplianceAssessment.objects.filter(id__in=ca_ids).values_list(
            "id", "folder_id"
        )
    )
    if set(ca_folder_snapshots) != ca_ids:
        raise PermissionDenied("One or more assessment links are unavailable.")

    folder_ids = set(ca_folder_snapshots.values()) | {
        folder_id for folder_id, _ca_id in ea_snapshots.values()
    }
    if None in folder_ids:
        raise PermissionDenied("One or more assessment owners are unavailable.")
    locked_folder_ids = set(
        Folder.objects.select_for_update(of=("self",))
        .filter(id__in=folder_ids)
        .order_by("id")
        .values_list("id", flat=True)
    )
    if locked_folder_ids != folder_ids:
        raise PermissionDenied("One or more assessment owners are unavailable.")

    locked_cas = {
        row.id: row
        for row in ComplianceAssessment.objects.select_for_update(of=("self",))
        .filter(id__in=ca_ids)
        .order_by("id")
    }
    locked_eas = {
        row.id: row
        for row in EntityAssessment.objects.select_for_update(of=("self",))
        .filter(id__in=ea_ids)
        .order_by("id")
    }
    if set(locked_cas) != ca_ids or set(locked_eas) != ea_ids:
        raise PermissionDenied("One or more assessment links are unavailable.")
    if any(
        locked_cas[row_id].folder_id != folder_id
        for row_id, folder_id in ca_folder_snapshots.items()
    ) or any(
        (
            locked_eas[row_id].folder_id,
            locked_eas[row_id].compliance_assessment_id,
        )
        != snapshot
        for row_id, snapshot in ea_snapshots.items()
    ):
        raise PermissionDenied("An assessment owner changed; retry.")

    if user is not None:
        for model, ids in (
            (ComplianceAssessment, direct_ca_ids),
            (EntityAssessment, ea_ids),
        ):
            if ids and not ids.issubset(
                set(RoleAssignment.get_viewable_object_ids(user, model))
            ):
                raise PermissionDenied("One or more assessment links are unavailable.")

    if "compliance_assessments" in requested_ids:
        validated_data["compliance_assessments"] = [
            locked_cas[row_id] for row_id in sorted(direct_ca_ids, key=str)
        ]
    if "entity_assessments" in requested_ids:
        validated_data["entity_assessments"] = [
            locked_eas[row_id] for row_id in sorted(ea_ids, key=str)
        ]


def lock_questionnaire_owner_graph(
    *,
    user=None,
    requirement_node_ids=(),
    question_ids=(),
    choice_ids=(),
):
    """Lock and validate Framework -> Node -> Question -> Choice ownership.

    Callers acquire ``Folder._lock_folder_tree()`` first.  The helper expands
    every requested descendant to its complete parent chain, locks each model
    in the same order, rejects legacy cross-folder drift, and then re-proves
    independent IAM visibility for every existing carrier.
    """

    from core.models import Framework, Question, QuestionChoice, RequirementNode
    from iam.models import RoleAssignment

    if not transaction.get_connection().in_atomic_block:
        raise RuntimeError("Questionnaire owner locking requires a transaction.")

    requested_choice_ids = set(choice_ids)
    choice_snapshot = {
        row_id: (question_id, folder_id)
        for row_id, question_id, folder_id in QuestionChoice.objects.filter(
            id__in=requested_choice_ids
        ).values_list("id", "question_id", "folder_id")
    }
    if set(choice_snapshot) != requested_choice_ids:
        raise PermissionDenied("One or more questionnaire owners are unavailable.")

    requested_question_ids = set(question_ids)
    requested_question_ids.update(
        question_id for question_id, _folder_id in choice_snapshot.values()
    )
    question_snapshot = {
        row_id: (requirement_node_id, folder_id)
        for row_id, requirement_node_id, folder_id in Question.objects.filter(
            id__in=requested_question_ids
        ).values_list("id", "requirement_node_id", "folder_id")
    }
    if set(question_snapshot) != requested_question_ids:
        raise PermissionDenied("One or more questionnaire owners are unavailable.")

    requested_node_ids = set(requirement_node_ids)
    requested_node_ids.update(
        node_id for node_id, _folder_id in question_snapshot.values()
    )
    node_snapshot = {
        row_id: (framework_id, folder_id)
        for row_id, framework_id, folder_id in RequirementNode.objects.filter(
            id__in=requested_node_ids
        ).values_list("id", "framework_id", "folder_id")
    }
    if set(node_snapshot) != requested_node_ids:
        raise PermissionDenied("One or more questionnaire owners are unavailable.")
    framework_ids = {framework_id for framework_id, _ in node_snapshot.values()}
    if None in framework_ids:
        raise PermissionDenied("A questionnaire requirement has no framework owner.")

    frameworks = {
        row.id: row
        for row in Framework.objects.select_for_update(of=("self",))
        .filter(id__in=framework_ids)
        .order_by("id")
    }
    if set(frameworks) != framework_ids:
        raise PermissionDenied("One or more questionnaire owners are unavailable.")
    nodes = {
        row.id: row
        for row in RequirementNode.objects.select_for_update(of=("self",))
        .filter(id__in=requested_node_ids)
        .order_by("id")
    }
    questions = {
        row.id: row
        for row in Question.objects.select_for_update(of=("self",))
        .filter(id__in=requested_question_ids)
        .order_by("id")
    }
    choices = {
        row.id: row
        for row in QuestionChoice.objects.select_for_update(of=("self",))
        .filter(id__in=requested_choice_ids)
        .order_by("id")
    }
    if (
        set(nodes) != requested_node_ids
        or set(questions) != requested_question_ids
        or set(choices) != requested_choice_ids
    ):
        raise PermissionDenied("One or more questionnaire owners are unavailable.")

    for node_id, (framework_id, folder_id) in node_snapshot.items():
        node = nodes[node_id]
        framework = frameworks[framework_id]
        if (
            node.framework_id != framework_id
            or node.folder_id != folder_id
            or folder_id != framework.folder_id
        ):
            raise PermissionDenied("The questionnaire owner chain is inconsistent.")
        node.framework = framework
    for question_id, (node_id, folder_id) in question_snapshot.items():
        question = questions[question_id]
        node = nodes[node_id]
        if (
            question.requirement_node_id != node_id
            or question.folder_id != folder_id
            or folder_id != node.folder_id
        ):
            raise PermissionDenied("The questionnaire owner chain is inconsistent.")
        question.requirement_node = node
    for choice_id, (question_id, folder_id) in choice_snapshot.items():
        choice = choices[choice_id]
        question = questions[question_id]
        if (
            choice.question_id != question_id
            or choice.folder_id != folder_id
            or folder_id != question.folder_id
        ):
            raise PermissionDenied("The questionnaire owner chain is inconsistent.")
        choice.question = question

    if user is not None:
        for model, row_ids in (
            (Framework, framework_ids),
            (RequirementNode, requested_node_ids),
            (Question, requested_question_ids),
            (QuestionChoice, requested_choice_ids),
        ):
            if row_ids and not row_ids.issubset(
                set(RoleAssignment.get_viewable_object_ids(user, model))
            ):
                raise PermissionDenied(
                    "One or more questionnaire owners are unavailable."
                )

    return {
        "frameworks": frameworks,
        "nodes": nodes,
        "questions": questions,
        "choices": choices,
    }
