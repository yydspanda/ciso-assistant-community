"""Lock-bound guards for deleting or moving governed aggregate owners.

The helpers in this module operate from Django model metadata instead of
importing TPRM or optional application models.  This keeps the generic CISO
Assistant owner boundary reusable without creating a ``core`` <-> ``tprm``
import cycle.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from django.apps import apps
from django.db import models, transaction
from django.db.models.deletion import CASCADE
from rest_framework.exceptions import PermissionDenied

MANAGED_TPRM_FOLDER_ERROR = "managedTprmAssessmentFolder"
GOVERNED_REVERSE_OWNER_ERROR = "governedReverseOwner"
GOVERNED_FOLDER_CONTENT_ERROR = "governedFolderContent"


@dataclass(frozen=True)
class LockedFolderMutationScope:
    """Fresh rows that define one folder's stable structural mutation scope."""

    folder: models.Model
    proposed_parent: models.Model | None
    subtree_ids: frozenset[Any]
    subtree_contains_enclave: bool


@dataclass(frozen=True)
class _FolderGraphSnapshot:
    """Direct-FK graph facts independently reconciled with the closure table."""

    rows_by_id: dict[Any, tuple[Any | None, str]]
    ancestor_ids: set[Any]
    descendant_ids: set[Any]
    proposed_parent_ancestor_ids: set[Any]


@dataclass(frozen=True)
class FolderDeletionRootSpec:
    """One aggregate root that generic Folder deletion must not cascade."""

    app_label: str
    model_name: str
    folder_field_name: str = "folder"


GOVERNED_FOLDER_DELETION_ROOTS = (
    FolderDeletionRootSpec("core", "ComplianceAssessment"),
    FolderDeletionRootSpec("tprm", "EntityAssessment"),
)


def _walk_parent_lineage(
    rows_by_id: Mapping[Any, tuple[Any | None, str]], folder_id: Any
) -> set[Any]:
    """Return the direct-FK lineage, rejecting cycles or missing parents."""

    lineage: set[Any] = set()
    seen = {folder_id}
    parent_id = rows_by_id[folder_id][0]
    while parent_id is not None:
        if parent_id in seen or parent_id not in rows_by_id:
            raise PermissionDenied("The folder tree is inconsistent.")
        lineage.add(parent_id)
        seen.add(parent_id)
        parent_id = rows_by_id[parent_id][0]
    return lineage


def _walk_fk_descendants(
    children_by_parent: Mapping[Any, set[Any]], folder_id: Any
) -> set[Any]:
    """Return the direct-FK subtree, rejecting a reachable cycle."""

    descendants: set[Any] = set()
    pending = list(children_by_parent.get(folder_id, set()))
    while pending:
        child_id = pending.pop()
        if child_id == folder_id or child_id in descendants:
            raise PermissionDenied("The folder tree is inconsistent.")
        descendants.add(child_id)
        pending.extend(children_by_parent.get(child_id, set()))
    return descendants


def _validated_folder_graph_scope(
    folder_model,
    *,
    folder_id: Any,
    proposed_parent_id: Any | None,
) -> _FolderGraphSnapshot:
    """Cross-check direct parent FKs against all closure rows touching a subtree.

    The closure table is a cache used by IAM and structural mutation code; the
    ``parent_folder`` FK is the database cascade owner.  Trusting only either
    representation can hide an enclave from a generic ancestor delete.  This
    comparison therefore fails closed for a missing, surplus, or cyclic
    relation before the mutation is authorized.
    """

    rows_by_id = {
        row_id: (parent_id, content_type)
        for row_id, parent_id, content_type in folder_model.objects.order_by(
            "id"
        ).values_list("id", "parent_folder_id", "content_type")
    }
    if folder_id not in rows_by_id or (
        proposed_parent_id is not None and proposed_parent_id not in rows_by_id
    ):
        raise PermissionDenied("The folder is unavailable.")

    children_by_parent: dict[Any, set[Any]] = defaultdict(set)
    for row_id, (parent_id, _content_type) in rows_by_id.items():
        if parent_id is not None:
            children_by_parent[parent_id].add(row_id)

    ancestor_ids = _walk_parent_lineage(rows_by_id, folder_id)
    descendant_ids = _walk_fk_descendants(children_by_parent, folder_id)
    subtree_ids = {folder_id, *descendant_ids}
    proposed_parent_ancestor_ids = (
        _walk_parent_lineage(rows_by_id, proposed_parent_id)
        if proposed_parent_id is not None
        else set()
    )

    descendants_by_subtree_id = {
        row_id: _walk_fk_descendants(children_by_parent, row_id)
        for row_id in subtree_ids
    }
    expected_outbound_pairs = {
        (row_id, descendant_id)
        for row_id, row_descendants in descendants_by_subtree_id.items()
        for descendant_id in row_descendants
    }
    expected_inbound_pairs = {
        (ancestor_id, row_id)
        for row_id in subtree_ids
        for ancestor_id in _walk_parent_lineage(rows_by_id, row_id)
    }

    descendants_field = folder_model._meta.get_field("descendants")
    through = descendants_field.remote_field.through
    source_field = through._meta.get_field(descendants_field.m2m_field_name())
    target_field = through._meta.get_field(
        descendants_field.m2m_reverse_field_name()
    )
    pair_fields = (source_field.attname, target_field.attname)
    actual_outbound_pairs = set(
        through._base_manager.filter(
            **{f"{source_field.attname}__in": subtree_ids}
        ).values_list(*pair_fields)
    )
    actual_inbound_pairs = set(
        through._base_manager.filter(
            **{f"{target_field.attname}__in": subtree_ids}
        ).values_list(*pair_fields)
    )
    if (
        actual_outbound_pairs != expected_outbound_pairs
        or actual_inbound_pairs != expected_inbound_pairs
    ):
        raise PermissionDenied("The folder tree is inconsistent.")

    if proposed_parent_id is not None:
        actual_parent_lineage = set(
            through._base_manager.filter(
                **{target_field.attname: proposed_parent_id}
            ).values_list(source_field.attname, flat=True)
        )
        if actual_parent_lineage != proposed_parent_ancestor_ids:
            raise PermissionDenied("The folder tree is inconsistent.")

    return _FolderGraphSnapshot(
        rows_by_id=rows_by_id,
        ancestor_ids=ancestor_ids,
        descendant_ids=descendant_ids,
        proposed_parent_ancestor_ids=proposed_parent_ancestor_ids,
    )


def lock_folder_mutation_scope(
    *, folder_id: Any, proposed_parent_id: Any | None = None
) -> LockedFolderMutationScope:
    """Lock and re-prove a folder, its subtree, and relevant parent lineage.

    Callers must enter ``transaction.atomic``.  The root-folder mutex is taken
    before reading closure-table state, matching ``Folder.save``/``delete``.
    This makes an EN enclave in the target subtree a stable authorization fact
    for the remainder of the transaction.
    """

    if not transaction.get_connection().in_atomic_block:
        raise RuntimeError("Folder mutation authority requires a transaction.")

    # Imported lazily: iam.models imports core during Django application setup.
    from iam.models import Folder

    Folder._lock_folder_tree()
    graph = _validated_folder_graph_scope(
        Folder,
        folder_id=folder_id,
        proposed_parent_id=proposed_parent_id,
    )
    related_ids = {
        folder_id,
        *graph.ancestor_ids,
        *graph.descendant_ids,
        *graph.proposed_parent_ancestor_ids,
    }
    if proposed_parent_id is not None:
        related_ids.add(proposed_parent_id)

    locked = {
        row.id: row
        for row in Folder.objects.select_for_update(of=("self",))
        .filter(id__in=related_ids)
        .order_by("id")
    }
    if set(locked) != related_ids:
        raise PermissionDenied("The folder lineage is unavailable.")

    current_graph = _validated_folder_graph_scope(
        Folder,
        folder_id=folder_id,
        proposed_parent_id=proposed_parent_id,
    )
    if (
        current_graph.ancestor_ids != graph.ancestor_ids
        or current_graph.descendant_ids != graph.descendant_ids
        or current_graph.proposed_parent_ancestor_ids
        != graph.proposed_parent_ancestor_ids
        or any(
            current_graph.rows_by_id[row_id] != graph.rows_by_id[row_id]
            for row_id in related_ids
        )
    ):
        raise PermissionDenied("The folder lineage changed; retry.")

    folder = locked[folder_id]
    proposed_parent = None
    if proposed_parent_id is not None:
        proposed_parent = locked.get(proposed_parent_id)
        if proposed_parent is None:
            raise PermissionDenied("The destination folder changed; retry.")

    subtree_ids = {folder_id, *graph.descendant_ids}
    return LockedFolderMutationScope(
        folder=folder,
        proposed_parent=proposed_parent,
        subtree_ids=frozenset(subtree_ids),
        subtree_contains_enclave=any(
            locked[row_id].content_type == Folder.ContentType.ENCLAVE
            for row_id in subtree_ids
        ),
    )


def assert_generic_folder_structure_mutation_allowed(
    scope: LockedFolderMutationScope,
) -> None:
    """Keep an EN enclave and every containing subtree on its owned path."""

    if scope.subtree_contains_enclave:
        raise PermissionDenied(MANAGED_TPRM_FOLDER_ERROR)


def assert_generic_folder_deletion_has_no_governed_roots(
    scope: LockedFolderMutationScope,
) -> None:
    """Reject folder cascades over CA/EA aggregate roots only.

    A model-owned endpoint is the only place that can authorize the model's
    child delete permissions, independently governed targets, reverse owners,
    append-only evidence, and external-effect state.  The generic Folder path
    cannot safely reproduce the CA/EA deletion graphs.  Other upstream folder
    cascade behavior remains unchanged.

    ``lock_folder_mutation_scope`` has already locked every folder row in the
    subtree.  Database foreign-key checks therefore serialize a concurrent
    aggregate insert or move into the subtree with the eventual folder delete.
    """

    folder_model = type(scope.folder)
    subtree_ids = set(scope.subtree_ids)
    for spec in GOVERNED_FOLDER_DELETION_ROOTS:
        root_model = apps.get_model(spec.app_label, spec.model_name)
        folder_field = root_model._meta.get_field(spec.folder_field_name)
        if (
            not isinstance(folder_field, models.ForeignKey)
            or folder_field.related_model is not folder_model
        ):
            raise PermissionDenied(GOVERNED_FOLDER_CONTENT_ERROR)
        if root_model._base_manager.filter(
            **{f"{folder_field.attname}__in": subtree_ids}
        ).exists():
            raise PermissionDenied(GOVERNED_FOLDER_CONTENT_ERROR)


def lock_and_assert_no_surviving_reverse_owners(
    *,
    instance: models.Model,
    allowed_owner_ids_by_relation: Mapping[tuple[str, str], set[Any]] | None = None,
    relation_error_messages: Mapping[tuple[str, str], str] | None = None,
) -> None:
    """Reject deletion while a reverse owner would survive or be unlinked.

    ``instance`` must already be locked by the caller.  Each surviving owner is
    represented by either its own row (reverse FK/one-to-one) or its through row
    (reverse many-to-many).  Those rows are snapshotted, locked in deterministic
    table order, and re-read.  The optional allow-list supports a single
    aggregate-owned path (currently TPRM deleting its exact EntityAssessment and
    linked audit together); generic deletion passes no allow-list and therefore
    fails closed for every owner.  Many-to-many links are guarded even though
    their through-table foreign keys normally cascade: silently unlinking a
    surviving workflow or collection is itself an authority-bearing mutation.
    """

    if not transaction.get_connection().in_atomic_block:
        raise RuntimeError("Reverse-owner deletion authority requires a transaction.")

    allowed = allowed_owner_ids_by_relation or {}
    messages = relation_error_messages or {}
    relation_snapshots = []

    for relation in instance._meta.related_objects:
        field = relation.field
        relation_key = (relation.related_model._meta.label_lower, field.name)
        if relation.many_to_many:
            through = relation.through
            target_field = through._meta.get_field(field.m2m_reverse_field_name())
            owner_field = through._meta.get_field(field.m2m_field_name())
            queryset = through._base_manager.filter(
                **{target_field.attname: instance.pk}
            )
            value_fields = ("pk", owner_field.attname)
            expected_rows = tuple(
                queryset.order_by("pk").values_list(*value_fields)
            )
            relation_snapshots.append(
                (
                    through._meta.db_table,
                    relation_key,
                    queryset,
                    value_fields,
                    expected_rows,
                )
            )
            continue
        if not (relation.one_to_many or relation.one_to_one):
            continue
        if field.remote_field.on_delete is CASCADE:
            continue
        queryset = relation.related_model._base_manager.filter(
            **{field.attname: instance.pk}
        )
        value_fields = ("pk",)
        expected_rows = tuple(queryset.order_by("pk").values_list(*value_fields))
        relation_snapshots.append(
            (
                relation.related_model._meta.db_table,
                relation_key,
                queryset,
                value_fields,
                expected_rows,
            )
        )

    for _table, relation_key, queryset, value_fields, expected_rows in sorted(
        relation_snapshots, key=lambda item: (item[0], item[1])
    ):
        list(queryset.select_for_update(of=("self",)).order_by("pk"))
        current_rows = tuple(queryset.order_by("pk").values_list(*value_fields))
        if current_rows != expected_rows:
            raise PermissionDenied("Audit relationships changed; retry.")
        owner_ids = {row[-1] for row in current_rows}
        unexpected_ids = owner_ids - set(allowed.get(relation_key, set()))
        if unexpected_ids:
            raise PermissionDenied(
                messages.get(relation_key, GOVERNED_REVERSE_OWNER_ERROR)
            )
