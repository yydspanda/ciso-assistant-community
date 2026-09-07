"""Merge N source AppliedControls into 1 target: union direct M2Ms, rewire
reverse relations + FKs + SyncMapping GFKs, hard-delete sources. Traceability
via django-auditlog + webhook dispatches."""

from __future__ import annotations

from collections import defaultdict
from typing import Any
from uuid import UUID

import structlog
from crq.models import QuantitativeRiskHypothesis
from django.contrib.auth.models import Permission
from django.contrib.contenttypes.models import ContentType
from django.db import models, transaction
from django.db.models import ForeignKey, ManyToManyField
from django.db.models.fields.related import ManyToManyRel
from doc_management.models import DocumentContainer
from ebios_rm.models import Stakeholder
from iam.models import Folder, RoleAssignment
from integrations.capabilities import persist_outbound_sync_jobs
from integrations.models import (
    IntegrationConfiguration,
    IntegrationProvider,
    IntegrationSyncJob,
    SyncEvent,
    SyncMapping,
)
from pmbok.models import GenericCollection, ResponsibilityMatrixActivity
from privacy.models import DataBreach, Processing
from resilience.models import AssetAssessment
from rest_framework import status
from rest_framework.exceptions import APIException, PermissionDenied, ValidationError
from threat_modeling.models import ThreatModelNode
from webhooks.service import dispatch_webhook_event

from core.assignment_access import lock_requirement_assessment_relation_scope
from core.models import (
    Actor,
    AppliedControl,
    Comment,
    Finding,
    Incident,
    Policy,
    RequirementAssessment,
    RiskScenario,
    TaskTemplate,
    ValidationFlow,
    Vulnerability,
)
from core.relation_locking import lock_rows_in_global_model_order
from core.serializers import AppliedControlWriteSerializer

logger = structlog.get_logger(__name__)


class AppliedControlSyncMappingBusy(APIException):
    status_code = status.HTTP_409_CONFLICT
    default_detail = "An integration mapping has pending or unresolved work."
    default_code = "applied_control_sync_mapping_busy"


_UNRESOLVED_SYNC_JOB_STATUSES = (
    IntegrationSyncJob.Status.QUEUED,
    IntegrationSyncJob.Status.PROCESSING,
    IntegrationSyncJob.Status.UNCERTAIN,
    IntegrationSyncJob.Status.REVIEW_REQUIRED,
)


# Rewire contract: every reverse M2M on AppliedControl must be listed here.
# Keep aligned with AppliedControlViewSet.get_queryset() in views.py.
def _reverse_m2m_through_tables() -> list[tuple[Any, str]]:
    return [
        (RequirementAssessment.applied_controls.through, "RequirementAssessment"),
        (RiskScenario.applied_controls.through, "RiskScenario"),
        (RiskScenario.existing_applied_controls.through, "RiskScenario_existing"),
        (Finding.applied_controls.through, "Finding"),
        (Vulnerability.applied_controls.through, "Vulnerability"),
        (TaskTemplate.applied_controls.through, "TaskTemplate"),
        (Incident.applied_controls.through, "Incident"),
        (Stakeholder.applied_controls.through, "Stakeholder"),
        (Processing.associated_controls.through, "Processing"),
        (DataBreach.remediation_measures.through, "DataBreach"),
        (
            QuantitativeRiskHypothesis.existing_applied_controls.through,
            "QuantitativeRiskHypothesis_existing",
        ),
        (
            QuantitativeRiskHypothesis.added_applied_controls.through,
            "QuantitativeRiskHypothesis_added",
        ),
        (
            QuantitativeRiskHypothesis.removed_applied_controls.through,
            "QuantitativeRiskHypothesis_removed",
        ),
        (AssetAssessment.associated_controls.through, "AssetAssessment"),
        (
            ResponsibilityMatrixActivity.applied_controls.through,
            "ResponsibilityMatrixActivity",
        ),
        # Through Policy (a proxy of AppliedControl — same table).
        (ValidationFlow.policies.through, "ValidationFlow_policies"),
        (GenericCollection.policies.through, "GenericCollection_policies"),
        # Document links (Stream E.1) — associative, unioned onto the target.
        (DocumentContainer.policies.through, "DocumentContainer_policies"),
        (
            DocumentContainer.applied_controls.through,
            "DocumentContainer_applied_controls",
        ),
        (ThreatModelNode.applied_controls.through, "ThreatModelNode"),
    ]


DIRECT_M2M_FIELDS: tuple[str, ...] = (
    "evidences",
    "assets",
    "owner",
    "security_exceptions",
    "objectives",
    "filtering_labels",
)


_SPECIAL_REVERSE_THROUGHS = {
    # Requirement-assessment links have a stronger CA -> RA capability gate.
    RequirementAssessment.applied_controls.through,
}

# Reverse rows whose mutation authority is owned by an aggregate parent.  The
# child row alone is insufficient: e.g. RiskScenario.is_locked is derived from
# RiskAssessment, and Finding.is_locked from FindingsAssessment.
_REVERSE_PARENT_OWNER_FIELDS: dict[type[models.Model], tuple[str, ...]] = {
    RiskScenario: ("risk_assessment",),
    Finding: ("findings_assessment",),
    Stakeholder: ("ebios_rm_study",),
    QuantitativeRiskHypothesis: ("quantitative_risk_scenario",),
    AssetAssessment: ("bia",),
    ResponsibilityMatrixActivity: ("matrix",),
    ThreatModelNode: ("threat_model",),
}


def _snapshot_through_rows(through_model, control_ids) -> dict:
    """Capture exact through-row ownership for the controlled objects."""

    control_attname, other_attname = _through_fk_attnames(through_model)
    return {
        row_id: (control_id, other_id)
        for row_id, control_id, other_id in (
            through_model.objects.filter(**{f"{control_attname}__in": control_ids})
            .order_by("pk")
            .values_list("pk", control_attname, other_attname)
        )
    }


def _related_model_for_attname(model, attname: str):
    return next(
        field.related_model for field in model._meta.fields if field.attname == attname
    )


def _prepare_merge_relation_scope(
    *,
    control_ids,
    serializer,
    locked_requirement_assessments,
):
    """Snapshot and lock every authority-bearing relation before controls.

    Parent/target rows are locked in one global model order.  The controls and
    through rows are deliberately locked afterwards: an M2M insert needs a
    foreign-key key-share lock on one of those already-locked endpoints, while
    a writer that won the race is detected by the post-lock snapshot check.
    """

    reverse = []
    direct = []
    target_ids_by_model: dict[type[models.Model], set] = defaultdict(set)
    relation_ids_by_model: dict[type[models.Model], set] = defaultdict(set)

    for through_model, key in sorted(
        _reverse_m2m_through_tables(),
        key=lambda item: item[0]._meta.label_lower,
    ):
        if through_model in _SPECIAL_REVERSE_THROUGHS:
            continue
        control_attname, other_attname = _through_fk_attnames(through_model)
        parent_model = _related_model_for_attname(through_model, other_attname)
        snapshot = _snapshot_through_rows(through_model, control_ids)
        parent_ids = {parent_id for _control_id, parent_id in snapshot.values()}
        target_ids_by_model[parent_model].update(parent_ids)
        relation_ids_by_model[parent_model].update(parent_ids)
        reverse.append(
            {
                "through": through_model,
                "key": key,
                "control_attname": control_attname,
                "other_attname": other_attname,
                "model": parent_model,
                "snapshot": snapshot,
            }
        )

    for field_name in DIRECT_M2M_FIELDS:
        field = AppliedControl._meta.get_field(field_name)
        through_model = field.remote_field.through
        control_attname, other_attname = _through_fk_attnames(through_model)
        related_model = field.related_model
        snapshot = _snapshot_through_rows(through_model, control_ids)
        related_ids = {related_id for _control_id, related_id in snapshot.values()}
        target_ids_by_model[related_model].update(related_ids)
        relation_ids_by_model[related_model].update(related_ids)
        direct.append(
            {
                "through": through_model,
                "key": field_name,
                "control_attname": control_attname,
                "other_attname": other_attname,
                "model": related_model,
                "snapshot": snapshot,
            }
        )

    comment_snapshot = {
        comment_id: control_id
        for comment_id, control_id in (
            Comment.objects.filter(applied_control_id__in=control_ids)
            .order_by("id")
            .values_list("id", "applied_control_id")
        )
    }
    target_ids_by_model[Comment].update(comment_snapshot)
    relation_ids_by_model[Comment].update(comment_snapshot)

    requested_reverse = []
    requested_direct = []
    serializer_relations = []
    serializer_scalars = []
    if serializer is not None:
        for input_name, field in serializer.fields.items():
            source_name = field.source or input_name
            if source_name == "*":
                continue
            requested_items = serializer.validated_data.get(source_name)
            if not isinstance(requested_items, list) or not requested_items:
                continue
            if not all(isinstance(item, models.Model) for item in requested_items):
                continue
            related_model = requested_items[0]._meta.model
            requested_ids = [item.id for item in requested_items]
            if related_model is RequirementAssessment:
                locked_by_id = {row.id: row for row in locked_requirement_assessments}
                if not set(requested_ids).issubset(locked_by_id):
                    raise PermissionDenied(
                        "One or more target requirement assessments are unavailable."
                    )
                serializer.validated_data[source_name] = [
                    locked_by_id[item_id] for item_id in requested_ids
                ]
                continue

            target_ids_by_model[related_model].update(requested_ids)
            relation_ids_by_model[related_model].update(requested_ids)
            relation = {
                "input_name": input_name,
                "source_name": source_name,
                "model": related_model,
                "ids": requested_ids,
            }
            serializer_relations.append(relation)
            if source_name in DIRECT_M2M_FIELDS:
                requested_direct.append(relation)
            else:
                requested_reverse.append(relation)

        reference_control = serializer.validated_data.get("reference_control")
        if reference_control is not None:
            reference_model = reference_control._meta.model
            target_ids_by_model[reference_model].add(reference_control.id)
            relation_ids_by_model[reference_model].add(reference_control.id)
            serializer_scalars.append(
                {
                    "source_name": "reference_control",
                    "model": reference_model,
                    "id": reference_control.id,
                }
            )

    owner_bindings = []
    for parent_model, owner_fields in _REVERSE_PARENT_OWNER_FIELDS.items():
        parent_ids = relation_ids_by_model.get(parent_model, set())
        if not parent_ids:
            continue
        for owner_field_name in owner_fields:
            owner_field = parent_model._meta.get_field(owner_field_name)
            owner_model = owner_field.related_model
            owner_attname = owner_field.attname
            snapshot = {
                parent_id: owner_id
                for parent_id, owner_id in parent_model.objects.filter(
                    id__in=parent_ids
                )
                .order_by("id")
                .values_list("id", owner_attname)
            }
            if set(snapshot) != set(parent_ids) or None in snapshot.values():
                raise PermissionDenied("One or more relation owners are unavailable.")
            owner_ids = set(snapshot.values())
            target_ids_by_model[owner_model].update(owner_ids)
            relation_ids_by_model[owner_model].update(owner_ids)
            owner_bindings.append(
                {
                    "parent_model": parent_model,
                    "owner_model": owner_model,
                    "owner_field_name": owner_field_name,
                    "owner_attname": owner_attname,
                    "snapshot": snapshot,
                }
            )

    locked_by_model = lock_rows_in_global_model_order(target_ids_by_model)
    for binding in owner_bindings:
        parents = locked_by_model[binding["parent_model"]]
        owners = locked_by_model[binding["owner_model"]]
        for parent_id, owner_id in binding["snapshot"].items():
            parent = parents[parent_id]
            if getattr(parent, binding["owner_attname"]) != owner_id:
                raise PermissionDenied("A relation owner changed concurrently; retry.")
            setattr(parent, binding["owner_field_name"], owners[owner_id])
    for relation in serializer_relations:
        serializer.validated_data[relation["source_name"]] = [
            locked_by_model[relation["model"]][item_id] for item_id in relation["ids"]
        ]
    for relation in serializer_scalars:
        serializer.validated_data[relation["source_name"]] = locked_by_model[
            relation["model"]
        ][relation["id"]]

    return {
        "reverse": reverse,
        "direct": direct,
        "comments": comment_snapshot,
        "requested_reverse": requested_reverse,
        "requested_direct": requested_direct,
        "owner_bindings": owner_bindings,
        "relation_ids_by_model": relation_ids_by_model,
        "locked_by_model": locked_by_model,
    }


def _lock_and_verify_merge_relation_snapshots(*, scope, control_ids) -> None:
    """Lock exact through rows and reject additions/removals/reparenting."""

    for relation in sorted(
        [*scope["reverse"], *scope["direct"]],
        key=lambda item: item["through"]._meta.label_lower,
    ):
        through_model = relation["through"]
        expected = relation["snapshot"]
        locked = {
            row_id: (control_id, other_id)
            for row_id, control_id, other_id in (
                through_model.objects.select_for_update()
                .filter(pk__in=expected)
                .order_by("pk")
                .values_list(
                    "pk",
                    relation["control_attname"],
                    relation["other_attname"],
                )
            )
        }
        observed = _snapshot_through_rows(through_model, control_ids)
        if locked != expected or observed != expected:
            raise PermissionDenied(
                "Applied-control relations changed concurrently; retry."
            )

    expected_comments = scope["comments"]
    locked_comments = scope["locked_by_model"].get(Comment, {})
    locked_comment_snapshot = {
        comment_id: comment.applied_control_id
        for comment_id, comment in locked_comments.items()
    }
    observed_comments = {
        comment_id: control_id
        for comment_id, control_id in (
            Comment.objects.filter(applied_control_id__in=control_ids)
            .order_by("id")
            .values_list("id", "applied_control_id")
        )
    }
    if (
        locked_comment_snapshot != expected_comments
        or observed_comments != expected_comments
    ):
        raise PermissionDenied("Applied-control comments changed concurrently; retry.")


def _visible_ids_or_deny(*, user, model) -> set:
    try:
        return set(RoleAssignment.get_viewable_object_ids(user, model))
    except (NotImplementedError, Permission.DoesNotExist) as exc:
        raise PermissionDenied("One or more related objects are unavailable.") from exc


def _assert_relation_parent_change(*, user, instance) -> None:
    if getattr(instance, "builtin", False) or getattr(instance, "urn", None):
        raise PermissionDenied("A protected related object cannot be changed.")
    if bool(getattr(instance, "is_locked", False)):
        raise PermissionDenied("A locked related object cannot be changed.")
    if isinstance(instance, ValidationFlow) and (
        instance.status != ValidationFlow.Status.CHANGE_REQUESTED
        or instance.requester_id != user.id
    ):
        # Validation relationships form part of the human decision payload.
        # Only its maker may revise that payload while changes are requested.
        raise PermissionDenied("A validation-flow relationship cannot be changed.")
    model = instance._meta.model
    content_type = ContentType.objects.get_for_model(model)
    try:
        permission = Permission.objects.get(
            codename=f"change_{model._meta.model_name}",
            content_type=content_type,
        )
    except Permission.DoesNotExist as exc:
        raise PermissionDenied(
            "A related-object change authority is unavailable."
        ) from exc
    folder = Folder.get_folder(instance)
    if folder is None or not RoleAssignment.is_access_allowed(
        user=user,
        perm=permission,
        folder=folder,
    ):
        raise PermissionDenied("You cannot change one or more related objects.")


def _assert_merge_relation_authority(
    *,
    scope,
    user,
    control_folder_ids,
    target_folder_id,
) -> None:
    """Reprove independent visibility, mutation authority and owner scope."""

    for model, relation_ids in scope["relation_ids_by_model"].items():
        if relation_ids and not relation_ids.issubset(
            _visible_ids_or_deny(user=user, model=model)
        ):
            raise PermissionDenied("One or more related objects are unavailable.")

    for binding in scope["owner_bindings"]:
        parents = scope["locked_by_model"][binding["parent_model"]]
        owners = scope["locked_by_model"][binding["owner_model"]]
        for parent_id, owner_id in binding["snapshot"].items():
            parent_folder = Folder.get_folder(parents[parent_id])
            owner = owners[owner_id]
            owner_folder = Folder.get_folder(owner)
            if (
                parent_folder is None
                or owner_folder is None
                or parent_folder.id != owner_folder.id
            ):
                raise PermissionDenied("A related-object owner chain is inconsistent.")
            if bool(getattr(owner, "is_locked", False)):
                raise PermissionDenied("A related-object owner is locked.")

    published_descendants_by_folder: dict[Any, set] = {}

    def assert_owner_scope(instance, *, control_id=None):
        folder = Folder.get_folder(instance)
        folder_id = getattr(folder, "id", None)
        expected_source_folder_id = (
            control_folder_ids.get(control_id)
            if control_id is not None
            else target_folder_id
        )
        if folder_id is None or expected_source_folder_id is None:
            raise PermissionDenied(
                "Applied-control relations cannot cross their owner folder."
            )
        if isinstance(instance, Actor):
            # An Actor's carrier folder scopes visibility of the identity; it
            # does not own every object for which that identity is responsible.
            return
        if folder_id == expected_source_folder_id == target_folder_id:
            return
        if getattr(instance, "is_published", False):
            if folder_id not in published_descendants_by_folder:
                published_descendants_by_folder[folder_id] = set(
                    Folder.objects.filter(id=folder_id).values_list(
                        "descendants__id", flat=True
                    )
                )
            descendant_ids = published_descendants_by_folder[folder_id]
            if {expected_source_folder_id, target_folder_id}.issubset(descendant_ids):
                return
        raise PermissionDenied(
            "Applied-control relations cannot cross their owner folder."
        )

    for relation in scope["reverse"]:
        parents = scope["locked_by_model"].get(relation["model"], {})
        for control_id, parent_id in relation["snapshot"].values():
            parent = parents[parent_id]
            assert_owner_scope(parent, control_id=control_id)
            _assert_relation_parent_change(user=user, instance=parent)

    for relation in scope["direct"]:
        targets = scope["locked_by_model"].get(relation["model"], {})
        for control_id, related_id in relation["snapshot"].values():
            assert_owner_scope(targets[related_id], control_id=control_id)

    for comment_id, control_id in scope["comments"].items():
        comment = scope["locked_by_model"][Comment][comment_id]
        assert_owner_scope(comment, control_id=control_id)
        _assert_relation_parent_change(user=user, instance=comment)

    for relation in scope["requested_reverse"]:
        parents = scope["locked_by_model"][relation["model"]]
        for parent_id in relation["ids"]:
            parent = parents[parent_id]
            assert_owner_scope(parent)
            _assert_relation_parent_change(user=user, instance=parent)

    for relation in scope["requested_direct"]:
        targets = scope["locked_by_model"][relation["model"]]
        for target_id in relation["ids"]:
            assert_owner_scope(targets[target_id])


def _registered_reverse_m2m_throughs() -> set:
    return {through for through, _ in _reverse_m2m_through_tables()}


def _expected_reverse_m2m_throughs() -> set:
    """Introspect AppliedControl's reverse M2M relations — any through-table
    here but not in _reverse_m2m_through_tables() would silently orphan its
    rows during merge. Paired with a drift-guard test."""
    return {
        f.through
        for f in AppliedControl._meta.get_fields()
        if isinstance(f, ManyToManyRel)
    }


def _expected_direct_m2m_fields() -> set[str]:
    """Every M2M field declared on AppliedControl — any missing entry in
    DIRECT_M2M_FIELDS means the target won't inherit those relations."""
    return {
        f.name
        for f in AppliedControl._meta.get_fields()
        if isinstance(f, ManyToManyField)
    }


_TARGET_RELATED = (AppliedControl, Policy)


def _through_fk_attnames(through_model) -> tuple[str, str]:
    """Return (target_attname, other_attname). Policy is a proxy of
    AppliedControl, so through-tables on Policy M2Ms carry a Policy FK that
    points at the same underlying table."""
    fk_fields = [
        f for f in through_model._meta.get_fields() if isinstance(f, ForeignKey)
    ]
    ac_field = next(f for f in fk_fields if f.related_model in _TARGET_RELATED)
    other_field = next(f for f in fk_fields if f.related_model not in _TARGET_RELATED)
    return ac_field.attname, other_field.attname


def _rewire_through(through_model, source_ids: list, target_id) -> int:
    """Move through-rows to target, dedupe against existing target pairs."""
    ac_attname, other_attname = _through_fk_attnames(through_model)

    existing_target_others = set(
        through_model.objects.filter(**{ac_attname: target_id}).values_list(
            other_attname, flat=True
        )
    )
    source_others = set(
        through_model.objects.filter(**{f"{ac_attname}__in": source_ids}).values_list(
            other_attname, flat=True
        )
    )
    to_create = source_others - existing_target_others
    if to_create:
        through_model.objects.bulk_create(
            [
                through_model(**{ac_attname: target_id, other_attname: oid})
                for oid in to_create
            ],
            ignore_conflicts=True,
        )
    deleted, _ = through_model.objects.filter(
        **{f"{ac_attname}__in": source_ids}
    ).delete()
    return deleted


def _rewire_fk(fk_model, fk_attname: str, source_ids: list, target_id) -> int:
    qs = fk_model.objects.filter(**{f"{fk_attname}__in": source_ids})
    count = qs.count()
    qs.update(**{fk_attname: target_id})
    return count


def _lock_sync_mapping_graph(*, controlled_ids, owner_folder_ids) -> dict:
    """Lock folders -> configurations -> providers -> mappings before controls."""

    if not transaction.get_connection().in_atomic_block:
        raise RuntimeError("SyncMapping rewiring requires an atomic transaction.")
    content_type = ContentType.objects.get_for_model(AppliedControl)
    snapshot = {
        mapping_id: (configuration_id, local_object_id, folder_id)
        for mapping_id, configuration_id, local_object_id, folder_id in (
            SyncMapping.objects.filter(
                content_type=content_type,
                local_object_id__in=set(controlled_ids),
            )
            .order_by("id")
            .values_list("id", "configuration_id", "local_object_id", "folder_id")
        )
    }
    configuration_ids = {row[0] for row in snapshot.values()}
    configuration_snapshot = {
        configuration_id: (provider_id, folder_id)
        for configuration_id, provider_id, folder_id in (
            IntegrationConfiguration.objects.filter(id__in=configuration_ids)
            .order_by("id")
            .values_list("id", "provider_id", "folder_id")
        )
    }
    if set(configuration_snapshot) != configuration_ids:
        raise PermissionDenied("Integration mappings are unavailable.")
    provider_ids = {row[0] for row in configuration_snapshot.values()}
    provider_folder_snapshot = dict(
        IntegrationProvider.objects.filter(id__in=provider_ids)
        .order_by("id")
        .values_list("id", "folder_id")
    )
    if set(provider_folder_snapshot) != provider_ids:
        raise PermissionDenied("Integration mappings are unavailable.")

    exact_folder_ids = {
        folder_id
        for folder_id in {
            *owner_folder_ids,
            *(row[1] for row in configuration_snapshot.values()),
            *provider_folder_snapshot.values(),
            *(row[2] for row in snapshot.values()),
        }
        if folder_id is not None
    }
    locked_folders = {
        folder.id: folder
        for folder in Folder.objects.select_for_update(of=("self",))
        .filter(id__in=exact_folder_ids)
        .order_by("id")
    }
    if set(locked_folders) != exact_folder_ids:
        raise PermissionDenied("Integration mapping owners are unavailable.")

    configurations = {
        row.id: row
        for row in IntegrationConfiguration.objects.select_for_update(of=("self",))
        .filter(id__in=configuration_ids)
        .order_by("id")
    }
    if set(configurations) != configuration_ids or any(
        (row.provider_id, row.folder_id) != configuration_snapshot[row.id]
        for row in configurations.values()
    ):
        raise PermissionDenied("Integration mappings are unavailable.")
    providers = {
        row.id: row
        for row in IntegrationProvider.objects.select_for_update(of=("self",))
        .filter(id__in=provider_ids)
        .order_by("id")
    }
    if set(providers) != provider_ids or any(
        row.folder_id != provider_folder_snapshot[row.id] for row in providers.values()
    ):
        raise PermissionDenied("Integration mappings are unavailable.")
    mappings = {
        row.id: row
        for row in SyncMapping.objects.select_for_update(of=("self",))
        .filter(id__in=snapshot)
        .order_by("id")
    }
    locked_snapshot = {
        row.id: (row.configuration_id, row.local_object_id, row.folder_id)
        for row in mappings.values()
    }
    observed_snapshot = {
        mapping_id: (configuration_id, local_object_id, folder_id)
        for mapping_id, configuration_id, local_object_id, folder_id in (
            SyncMapping.objects.filter(
                content_type=content_type,
                local_object_id__in=set(controlled_ids),
            )
            .order_by("id")
            .values_list("id", "configuration_id", "local_object_id", "folder_id")
        )
    }
    if locked_snapshot != snapshot or observed_snapshot != snapshot:
        raise PermissionDenied("Integration mappings changed concurrently; retry.")
    return {
        "content_type": content_type,
        "controlled_ids": set(controlled_ids),
        "snapshot": snapshot,
        "configurations": configurations,
        "providers": providers,
        "mappings": mappings,
        "jobs_locked": False,
    }


def _lock_and_reject_merge_sync_jobs(graph: dict) -> None:
    """Lock unresolved jobs only after the mapped local controls are locked."""

    mapping_ids = set(graph["mappings"])
    blocking_jobs = list(
        IntegrationSyncJob.objects.select_for_update(of=("self",))
        .filter(
            mapping_id_snapshot__in=mapping_ids,
            status__in=_UNRESOLVED_SYNC_JOB_STATUSES,
        )
        .order_by("created_at", "id")
        .values_list("id", flat=True)
    )
    if blocking_jobs:
        raise AppliedControlSyncMappingBusy()
    graph["jobs_locked"] = True


def _record_merge_mapping_event(
    *, mapping, user, action: str, before: dict, after: dict
) -> None:
    SyncEvent.objects.create(
        mapping=mapping,
        mapping_id_snapshot=mapping.id,
        configuration_id_snapshot=mapping.configuration_id,
        content_type_id_snapshot=mapping.content_type_id,
        local_object_id_snapshot=mapping.local_object_id,
        remote_id_snapshot=mapping.remote_id,
        job_id_snapshot=None,
        request_digest_snapshot="",
        actor_id_snapshot=getattr(user, "id", None),
        direction=SyncMapping.SyncDirection.PUSH,
        changes={
            "action": action,
            "before": before,
            "after": after,
            "mapping_version": mapping.version,
        },
        triggered_by=SyncEvent.TriggeredBy.USER,
        success=True,
    )


def _rewire_sync_mappings(
    source_ids: list,
    target_id,
    *,
    target_folder_id,
    control_folder_ids: dict,
    user,
    graph: dict,
    mutate: bool = True,
) -> dict[str, int]:
    """Authorize and optionally repoint one already-locked mapping graph."""

    if not graph.get("jobs_locked"):
        raise RuntimeError("SyncMapping jobs must be locked before rewiring.")
    configurations = graph["configurations"]
    providers = graph["providers"]
    mappings = graph["mappings"]
    configuration_ids = set(configurations)

    observed_snapshot = {
        mapping_id: (configuration_id, local_object_id, folder_id)
        for mapping_id, configuration_id, local_object_id, folder_id in (
            SyncMapping.objects.filter(id__in=mappings)
            .order_by("id")
            .values_list("id", "configuration_id", "local_object_id", "folder_id")
        )
    }
    if observed_snapshot != graph["snapshot"]:
        raise PermissionDenied("Integration mappings changed concurrently; retry.")

    try:
        visible_configuration_ids = set(
            RoleAssignment.get_viewable_object_ids(user, IntegrationConfiguration)
        )
        visible_mapping_ids = set(
            RoleAssignment.get_viewable_object_ids(user, SyncMapping)
        )
    except (NotImplementedError, Permission.DoesNotExist) as exc:
        raise PermissionDenied("Integration mappings are unavailable.") from exc
    if (
        configuration_ids - visible_configuration_ids
        or set(mappings) - visible_mapping_ids
    ):
        raise PermissionDenied("Integration mappings are unavailable.")

    source_id_set = set(source_ids)
    for mapping in mappings.values():
        configuration = configurations[mapping.configuration_id]
        provider = providers[configuration.provider_id]
        owner_folder_id = control_folder_ids.get(mapping.local_object_id)
        provider_is_coherent = (
            provider.folder_id == configuration.folder_id
            or Folder.objects.filter(
                id=configuration.folder_id,
                ancestors__id=provider.folder_id,
            ).exists()
        )
        if (
            not provider.is_active
            or not configuration.is_active
            or not provider_is_coherent
            or owner_folder_id is None
            or mapping.folder_id != owner_folder_id
            or configuration.folder_id != owner_folder_id
        ):
            raise PermissionDenied("Integration mappings are unavailable.")
        if (
            mapping.local_object_id in source_id_set
            and configuration.folder_id != target_folder_id
        ):
            raise PermissionDenied("Integration mappings cannot cross folders.")

    target_mappings = {
        mapping.configuration_id: mapping
        for mapping in mappings.values()
        if mapping.local_object_id == target_id
    }
    source_mappings = sorted(
        (
            mapping
            for mapping in mappings.values()
            if mapping.local_object_id in source_id_set
        ),
        key=lambda mapping: str(mapping.id),
    )
    moved = 0
    deleted = 0
    affected_config_ids = set()
    for mapping in source_mappings:
        affected_config_ids.add(mapping.configuration_id)
        before = {
            "local_object_id": str(mapping.local_object_id),
            "remote_id": mapping.remote_id,
            "sync_status": mapping.sync_status,
        }
        if mapping.configuration_id in target_mappings:
            _assert_sync_mapping_permission(user=user, mapping=mapping, action="delete")
            target_mapping = target_mappings[mapping.configuration_id]
            _assert_sync_mapping_permission(
                user=user, mapping=target_mapping, action="change"
            )
            if mutate:
                mapping.version += 1
                mapping.save(update_fields=["version", "updated_at"])
                _record_merge_mapping_event(
                    mapping=mapping,
                    user=user,
                    action="merge_unlink_duplicate",
                    before=before,
                    after={"survivor_mapping_id": str(target_mapping.id)},
                )
                mapping.delete()
            deleted += 1
        else:
            _assert_sync_mapping_permission(user=user, mapping=mapping, action="change")
            if mutate:
                mapping.local_object_id = target_id
                mapping.sync_status = SyncMapping.SyncStatus.PENDING
                mapping.version += 1
                mapping.save(
                    update_fields=[
                        "local_object_id",
                        "sync_status",
                        "version",
                        "updated_at",
                    ]
                )
                _record_merge_mapping_event(
                    mapping=mapping,
                    user=user,
                    action="merge_relink",
                    before=before,
                    after={
                        "local_object_id": str(mapping.local_object_id),
                        "remote_id": mapping.remote_id,
                        "sync_status": mapping.sync_status,
                    },
                )
            target_mappings[mapping.configuration_id] = mapping
            moved += 1

    if mutate and affected_config_ids:
        config_ids = sorted(affected_config_ids, key=str)
        persist_outbound_sync_jobs(
            content_type_id=graph["content_type"].id,
            object_id=target_id,
            configuration_ids=config_ids,
            changed_fields=[],
            origin_principal=f"user:{user.id}",
            requested_by_id=user.id,
        )
    return {"moved": moved, "deleted": deleted}


def _assert_sync_mapping_permission(*, user, mapping, action: str) -> None:
    content_type = ContentType.objects.get_for_model(SyncMapping)
    permission = Permission.objects.get(
        codename=f"{action}_syncmapping", content_type=content_type
    )
    if not RoleAssignment.is_access_allowed(
        user=user, perm=permission, folder=mapping.folder
    ):
        raise PermissionDenied("Integration mappings are unavailable.")


def _union_direct_m2ms(target, sources) -> dict[str, int]:
    counts = {}
    for field_name in DIRECT_M2M_FIELDS:
        related = getattr(target, field_name, None)
        if related is None:
            continue
        for src in sources:
            src_related = getattr(src, field_name, None)
            if src_related is None:
                continue
            related.add(*src_related.all())
        counts[field_name] = related.count()
    return counts


def _check_permissions(
    user,
    source_folders: list,
    target_folder,
    target_is_new: bool,
) -> None:
    # Scope Permission.objects.get by content_type to avoid MultipleObjectsReturned
    # on codename collisions across apps.
    ct = ContentType.objects.get_for_model(AppliedControl)
    change = Permission.objects.get(codename="change_appliedcontrol", content_type=ct)
    delete = Permission.objects.get(codename="delete_appliedcontrol", content_type=ct)
    add = Permission.objects.get(codename="add_appliedcontrol", content_type=ct)

    for folder in source_folders:
        if not RoleAssignment.is_access_allowed(user=user, perm=change, folder=folder):
            raise PermissionDenied(
                f"Missing change permission on source folder '{folder}'."
            )
        if not RoleAssignment.is_access_allowed(user=user, perm=delete, folder=folder):
            raise PermissionDenied(
                f"Missing delete permission on source folder '{folder}'."
            )
    if target_folder is not None:
        if not RoleAssignment.is_access_allowed(
            user=user, perm=change, folder=target_folder
        ):
            raise PermissionDenied(
                f"Missing change permission on target folder '{target_folder}'."
            )
        if target_is_new and not RoleAssignment.is_access_allowed(
            user=user, perm=add, folder=target_folder
        ):
            raise PermissionDenied(
                f"Missing add permission on target folder '{target_folder}'."
            )


def _requested_requirement_assessment_ids(target: dict) -> set[UUID]:
    """Parse reverse RA links carried by a new merge target payload."""

    if target.get("type") != "new":
        return set()
    fields = target.get("fields") or {}
    if "requirement_assessments" not in fields:
        return set()
    raw_values = fields["requirement_assessments"]
    if not isinstance(raw_values, list):
        raise ValidationError(
            {"target.fields.requirement_assessments": "Expected a list of UUIDs."}
        )
    parsed: set[UUID] = set()
    for raw_value in raw_values:
        try:
            parsed.add(UUID(str(raw_value)))
        except (TypeError, ValueError) as exc:
            raise ValidationError(
                {
                    "target.fields.requirement_assessments": (
                        "One or more requirement-assessment IDs are invalid."
                    )
                }
            ) from exc
    return parsed


def merge_applied_controls(
    *,
    source_ids: list,
    target: dict,
    user,
    request=None,
    lookup_queryset=None,
    dry_run: bool = False,
) -> dict:
    """Merge N sources into 1 target. See module docstring for semantics.

    `lookup_queryset` should be the view's IAM-scoped queryset so UUIDs the
    caller can't see are treated as "not found". `request` is passed to the
    write serializer on target=new so its folder-access rules fire. Target
    creation happens inside the atomic block, after permissions and conflict
    checks, so failures never leak an orphan row."""
    lookup_queryset = (
        lookup_queryset if lookup_queryset is not None else AppliedControl.objects.all()
    )

    sources = list(lookup_queryset.filter(id__in=source_ids))
    found_ids = {str(s.id) for s in sources}
    missing = [str(sid) for sid in source_ids if str(sid) not in found_ids]
    if missing:
        raise ValidationError({"source_ids": f"Not found: {missing}"})

    target_is_new = target["type"] == "new"
    target_existing_obj: AppliedControl | None = None

    if target_is_new:
        fields = target.get("fields") or {}
        folder_id = fields.get("folder")
        if not folder_id:
            raise ValidationError(
                {"target": "fields.folder is required when target.type='new'"}
            )
        try:
            target_folder = Folder.objects.get(id=folder_id)
        except Folder.DoesNotExist:
            raise ValidationError({"target.fields.folder": "Folder does not exist."})
    else:
        try:
            existing = lookup_queryset.get(id=target["id"])
        except AppliedControl.DoesNotExist:
            raise ValidationError(
                f"Target applied control {target['id']} does not exist."
            )
        if str(existing.id) in found_ids:
            raise ValidationError(
                "The target applied control must not appear in source_ids."
            )
        target_existing_obj = existing
        target_folder = existing.folder

    source_id_list = [s.id for s in sources]
    controlled_ids = [*source_id_list]
    if target_existing_obj is not None:
        controlled_ids.append(target_existing_obj.id)
    requested_requirement_assessment_ids = _requested_requirement_assessment_ids(target)

    with transaction.atomic():
        Folder._lock_folder_tree()
        target_serializer = None
        if target_is_new:
            # The payload was parsed before the transaction.  Refresh its
            # owner after the tree mutex so permission checks never use a
            # pre-move Folder instance.
            target_folder = Folder.objects.select_for_update(of=("self",)).get(
                id=target_folder.id
            )
            serializer_context = {"request": request} if request is not None else {}
            target_serializer = AppliedControlWriteSerializer(
                data=target.get("fields") or {}, context=serializer_context
            )
            target_serializer.is_valid(raise_exception=True)

        initial_control_folder_ids = {source.id: source.folder_id for source in sources}
        if target_existing_obj is not None:
            initial_control_folder_ids[target_existing_obj.id] = (
                target_existing_obj.folder_id
            )
        sync_graph = _lock_sync_mapping_graph(
            controlled_ids=controlled_ids,
            owner_folder_ids={
                *initial_control_folder_ids.values(),
                target_folder.id,
            },
        )

        # Resolve the complete audit relation set only after the folder-tree
        # mutex.  This set is rechecked again under exact through-row locks.
        ra_through = RequirementAssessment.applied_controls.through
        ac_attname, ra_attname = _through_fk_attnames(ra_through)
        requirement_assessment_link_snapshot = _snapshot_through_rows(
            ra_through, controlled_ids
        )
        linked_requirement_assessment_ids = {
            ra_id
            for _control_id, ra_id in requirement_assessment_link_snapshot.values()
        }
        governed_requirement_assessment_ids = (
            linked_requirement_assessment_ids | requested_requirement_assessment_ids
        )
        # The merge rewires reverse RequirementAssessment relations directly,
        # so it must enter through the same CA -> RA authority gate as ordinary
        # AppliedControl writes.  Respondents may deposit evidence, but may not
        # adjudicate or rewire applied controls.
        locked_requirement_assessments, _ = lock_requirement_assessment_relation_scope(
            user=user,
            requirement_assessment_ids=governed_requirement_assessment_ids,
            relation_field="applied_controls",
            object_folder_id=None,
            allow_respondent=False,
        )

        # Every other direct target and reverse parent is a separate IAM
        # object.  Snapshot and lock those carriers before taking control-row
        # locks so all merge paths share one deterministic authority order.
        relation_scope = _prepare_merge_relation_scope(
            control_ids=controlled_ids,
            serializer=target_serializer,
            locked_requirement_assessments=locked_requirement_assessments,
        )

        # Lock sources + target only after their linked audit rows.  This
        # matches the generic reverse-relation lock order and prevents an
        # AppliedControl lock from deadlocking a concurrent RA-authorized write.
        locked_sources = list(
            AppliedControl.objects.select_for_update(of=("self",))
            .filter(id__in=source_id_list)
            .select_related("folder")
            .order_by("id")
        )
        if len(locked_sources) != len(source_id_list):
            raise ValidationError(
                "One or more source applied controls are no longer available."
            )
        if target_existing_obj is not None:
            target_existing_obj = (
                AppliedControl.objects.select_for_update(of=("self",))
                .select_related("folder")
                .get(id=target_existing_obj.id)
            )
        locked_control_folder_ids = {
            source.id: source.folder_id for source in locked_sources
        }
        if target_existing_obj is not None:
            locked_control_folder_ids[target_existing_obj.id] = (
                target_existing_obj.folder_id
            )
        if locked_control_folder_ids != initial_control_folder_ids:
            raise PermissionDenied(
                "An applied-control integration owner changed concurrently; retry."
            )
        _lock_and_reject_merge_sync_jobs(sync_graph)

        # The first lookup only prevents an immediate identifier leak.  Re-run
        # the caller's complete IAM-scoped queryset after the rows are locked;
        # publication/category/focus predicates may have changed while waiting.
        locked_visible_control_ids = set(
            lookup_queryset.filter(id__in=controlled_ids).values_list("id", flat=True)
        )
        if locked_visible_control_ids != set(controlled_ids):
            raise PermissionDenied(
                "One or more applied controls are no longer available."
            )

        sources = locked_sources
        source_folders = [s.folder for s in sources if s.folder is not None]
        target_folder = (
            target_existing_obj.folder
            if target_existing_obj is not None
            else target_folder
        )
        _check_permissions(user, source_folders, target_folder, target_is_new)
        control_folder_ids = {source.id: source.folder_id for source in sources}
        if target_existing_obj is not None:
            control_folder_ids[target_existing_obj.id] = target_existing_obj.folder_id

        _lock_and_verify_merge_relation_snapshots(
            scope=relation_scope,
            control_ids=controlled_ids,
        )
        _assert_merge_relation_authority(
            scope=relation_scope,
            user=user,
            control_folder_ids=control_folder_ids,
            target_folder_id=target_folder.id,
        )

        # Lock the exact through rows and ensure the pre-lock authorization set
        # is still complete.  A writer-first attach therefore yields a retry,
        # never an unreviewed rewire after its commit.
        locked_requirement_assessment_links = {
            row_id: (control_id, ra_id)
            for row_id, control_id, ra_id in (
                ra_through.objects.select_for_update()
                .filter(pk__in=requirement_assessment_link_snapshot)
                .order_by("pk")
                .values_list("pk", ac_attname, ra_attname)
            )
        }
        observed_requirement_assessment_links = _snapshot_through_rows(
            ra_through, controlled_ids
        )
        if (
            locked_requirement_assessment_links != requirement_assessment_link_snapshot
            or observed_requirement_assessment_links
            != requirement_assessment_link_snapshot
        ):
            raise PermissionDenied(
                "Requirement-assessment links changed concurrently; retry."
            )

        folder_mismatch = any(
            (s.folder_id if s.folder else None)
            != (target_folder.id if target_folder else None)
            for s in sources
        )

        if dry_run:
            sync_preview = _rewire_sync_mappings(
                source_id_list,
                target_existing_obj.id if target_existing_obj is not None else None,
                target_folder_id=target_folder.id,
                control_folder_ids=control_folder_ids,
                user=user,
                graph=sync_graph,
                mutate=False,
            )
            return {
                "target_id": (
                    str(target_existing_obj.id) if target_existing_obj else None
                ),
                "target_is_new": target_is_new,
                "target_folder_id": (str(target_folder.id) if target_folder else None),
                "source_folder_ids": sorted({str(f.id) for f in source_folders}),
                "folder_mismatch": folder_mismatch,
                "rewired_preview": _compute_rewire_preview(source_id_list),
                "unioned_m2m_preview": _compute_union_preview(
                    sources, target_existing_obj, target_is_new
                ),
                "sync_mappings_preview": sync_preview,
                "deleted_sources_preview": [str(s.id) for s in sources],
            }

        if target_is_new:
            target_obj = target_serializer.save()
        elif target_existing_obj is not None:
            target_obj = target_existing_obj
        else:
            # Unreachable: pre-validation above guarantees one branch or the other.
            raise RuntimeError("merge_applied_controls: target state inconsistent")

        unioned = _union_direct_m2ms(target_obj, sources)

        rewired: dict[str, int] = {}
        for through, key in _reverse_m2m_through_tables():
            rewired[key] = _rewire_through(through, source_id_list, target_obj.id)
        rewired["Comment"] = _rewire_fk(
            Comment, "applied_control_id", source_id_list, target_obj.id
        )

        control_folder_ids[target_obj.id] = target_obj.folder_id
        sync_result = _rewire_sync_mappings(
            source_id_list,
            target_obj.id,
            target_folder_id=target_obj.folder_id,
            control_folder_ids=control_folder_ids,
            user=user,
            graph=sync_graph,
        )

        source_snapshots = [
            {"id": str(s.id), "name": s.name, "urn": getattr(s, "urn", None)}
            for s in sources
        ]
        for src in sources:
            try:
                dispatch_webhook_event(src, "deleted")
            except Exception:
                logger.error(
                    "Webhook dispatch failed during merge (deleted)", exc_info=True
                )

        AppliedControl.objects.filter(id__in=source_id_list).delete()

        # Refresh updated_at + re-trigger integration sync. Skip for a new
        # target: its initial save already did both, and M2M additions don't
        # affect any syncable field.
        if not target_is_new:
            target_obj.save()

        try:
            dispatch_webhook_event(target_obj, "updated")
        except Exception:
            logger.error(
                "Webhook dispatch failed during merge (updated)", exc_info=True
            )

    logger.info(
        "Applied controls merged",
        source_ids=[s["id"] for s in source_snapshots],
        target_id=str(target_obj.id),
        target_is_new=target_is_new,
        folder_mismatch=folder_mismatch,
        merged_by=str(getattr(user, "id", None)),
    )

    return {
        "target_id": str(target_obj.id),
        "target_is_new": target_is_new,
        "target_folder_id": str(target_folder.id) if target_folder else None,
        "folder_mismatch": folder_mismatch,
        "rewired": rewired,
        "unioned_m2m": unioned,
        "sync_mappings": sync_result,
        "deleted_sources": source_snapshots,
    }


def _compute_rewire_preview(source_ids: list) -> dict[str, int]:
    counts: dict[str, int] = {}
    for through, key in _reverse_m2m_through_tables():
        ac_attname, _ = _through_fk_attnames(through)
        counts[key] = through.objects.filter(
            **{f"{ac_attname}__in": source_ids}
        ).count()
    counts["Comment"] = Comment.objects.filter(
        applied_control_id__in=source_ids
    ).count()
    return counts


def _compute_union_preview(sources, target_obj, target_is_new: bool) -> dict[str, int]:
    """Count of items the target would gain per direct M2M after union."""
    counts: dict[str, int] = {}
    for field_name in DIRECT_M2M_FIELDS:
        existing: set = set()
        if not target_is_new and target_obj.pk is not None:
            existing = set(getattr(target_obj, field_name).values_list("id", flat=True))
        gained: set = set()
        for src in sources:
            src_related = getattr(src, field_name, None)
            if src_related is None:
                continue
            for obj_id in src_related.values_list("id", flat=True):
                if obj_id not in existing:
                    gained.add(obj_id)
        counts[field_name] = len(gained)
    return counts
