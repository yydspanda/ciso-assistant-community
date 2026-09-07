"""Authority guards for IAM state owned by the TPRM assessment workflow.

An audit enclave is not a general-purpose IAM scope.  Its respondent group,
membership and role-assignment scaffold are replaced as one exact set by the
TPRM assessment service.  Generic IAM writers use these predicates so they do
not become a second, incremental authority for that state.

The functions deliberately inspect model-like objects instead of importing
``iam.models``.  IAM imports ``core`` during Django startup, so keeping this
module dependency-free also avoids a circular model import.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any


TPRM_RESPONDENT_GROUP_CODENAME = "BI-UG-TPR"
TPRM_RESPONDENT_ROLE_CODENAME = "BI-RL-TPR"
TPRM_ENCLAVE_CONTENT_TYPE = "EN"
MANAGED_TPRM_RESPONDENT_IAM_ERROR = "managedTprmRespondentMembership"


class ManagedTprmRespondentIamError(Exception):
    """Raised when a generic writer targets TPRM-owned IAM state."""

    def __init__(self) -> None:
        super().__init__(MANAGED_TPRM_RESPONDENT_IAM_ERROR)


def is_tprm_enclave(folder: Any | None) -> bool:
    return bool(
        folder is not None
        and getattr(folder, "content_type", None) == TPRM_ENCLAVE_CONTENT_TYPE
    )


def is_tprm_reserved_enclave_group(group: Any | None) -> bool:
    """Return whether ``group`` is inside an audit enclave.

    Every group inside an enclave is reserved, including malformed or
    non-builtin rows.  Treating corruption as ordinary IAM state would let a
    caller mutate it until the TPRM service could no longer prove an exact
    scaffold.
    """

    return bool(group is not None and is_tprm_enclave(getattr(group, "folder", None)))


def is_managed_tprm_respondent_group(group: Any | None) -> bool:
    """Return whether ``group`` has the canonical managed respondent identity."""

    return bool(
        is_tprm_reserved_enclave_group(group)
        and getattr(group, "name", None) == TPRM_RESPONDENT_GROUP_CODENAME
    )


def _objects_by_pk(objects: Iterable[Any]) -> dict[str, Any]:
    return {
        str(obj.pk): obj
        for obj in objects
        if obj is not None and getattr(obj, "pk", None) is not None
    }


def assert_tprm_membership_change_allowed(
    *, current_groups: Iterable[Any], proposed_groups: Iterable[Any]
) -> None:
    """Reject an incremental membership or IdP-mapping change in an enclave."""

    current = _objects_by_pk(current_groups)
    proposed = _objects_by_pk(proposed_groups)
    changed_ids = current.keys() ^ proposed.keys()
    if any(
        is_tprm_reserved_enclave_group(current.get(group_id) or proposed.get(group_id))
        for group_id in changed_ids
    ):
        raise ManagedTprmRespondentIamError


def assert_tprm_user_group_write_allowed(
    *, current_group: Any | None = None, proposed_folder: Any | None = None
) -> None:
    """Reject generic create/update/delete of a group inside an enclave."""

    if is_tprm_reserved_enclave_group(current_group) or is_tprm_enclave(
        proposed_folder
    ):
        raise ManagedTprmRespondentIamError


def role_assignment_touches_tprm_scaffold(
    *,
    folder: Any | None,
    role: Any | None,
    user_group: Any | None,
    perimeter_folders: Iterable[Any],
) -> bool:
    """Return whether a role assignment is part of reserved TPRM authority."""

    return bool(
        is_tprm_enclave(folder)
        or is_tprm_reserved_enclave_group(user_group)
        or getattr(role, "name", None) == TPRM_RESPONDENT_ROLE_CODENAME
        or any(is_tprm_enclave(item) for item in perimeter_folders)
    )


def assert_tprm_role_assignment_write_allowed(
    *,
    folder: Any | None,
    role: Any | None,
    user_group: Any | None,
    perimeter_folders: Iterable[Any],
) -> None:
    """Reject a generic role-assignment write touching the TPRM scaffold."""

    if role_assignment_touches_tprm_scaffold(
        folder=folder,
        role=role,
        user_group=user_group,
        perimeter_folders=perimeter_folders,
    ):
        raise ManagedTprmRespondentIamError


def lock_and_assert_no_tprm_idp_group_inheritance(
    *,
    enclave_folder_ids: Iterable[Any] = (),
    idp_group_ids: Iterable[Any] = (),
    proposed_user_group_ids: Iterable[Any] = (),
) -> dict[Any, Any]:
    """Lock the legacy IdP inheritance graph and reject reserved TPRM grants.

    ``IdPGroup -> UserGroup -> RoleAssignment`` is an ordinary IAM inheritance
    path.  It must never become a second writer for the respondent group owned
    by a TPRM audit enclave.  New generic mappings are rejected by the write
    serializers, but an installation may pre-date that guard.  TPRM sync and
    enclave deletion therefore call this helper for an enclave, while SCIM
    calls it for the group whose membership it is about to mutate.  Generic
    IdP mapping writes also pass their proposed user-group IDs so a previously
    unmapped legacy assignment into an enclave cannot be activated later.

    Callers must already be inside ``transaction.atomic()`` and must acquire
    ``Folder._lock_folder_tree()`` first.  That root-folder mutex is shared by
    the generic IAM, TPRM and SCIM mutation paths.  Within it this helper uses
    one order for the complete authority graph: affected folders, IdP groups,
    roles, user groups, role assignments, relationship rows, then users.

    The return value contains the locked requested IdP groups.  Missing IDs are
    intentionally omitted so an API caller can retain its normal 404 contract.
    """

    # Runtime imports keep this dependency-free module safe during IAM model
    # initialization while still centralising the cross-entry-point invariant.
    from django.db import transaction
    from django.db.models import Q

    from iam.models import Folder, IdPGroup, Role, RoleAssignment, User, UserGroup

    if not transaction.get_connection().in_atomic_block:
        raise RuntimeError("Reserved IdP inheritance locking requires a transaction.")

    requested_enclave_ids = set(enclave_folder_ids)
    requested_idp_ids = set(idp_group_ids)
    requested_proposed_group_ids = set(proposed_user_group_ids)
    if (
        not requested_enclave_ids
        and not requested_idp_ids
        and not requested_proposed_group_ids
    ):
        return {}

    mapping_field = IdPGroup._meta.get_field("user_groups")
    mapping_through = mapping_field.remote_field.through
    mapping_source = mapping_field.m2m_field_name()
    mapping_target = mapping_field.m2m_reverse_field_name()

    membership_field = User._meta.get_field("idp_groups")
    membership_through = membership_field.remote_field.through
    membership_source = membership_field.m2m_field_name()
    membership_target = membership_field.m2m_reverse_field_name()

    perimeter_field = RoleAssignment._meta.get_field("perimeter_folders")
    perimeter_through = perimeter_field.remote_field.through
    perimeter_source = perimeter_field.m2m_field_name()
    perimeter_target = perimeter_field.m2m_reverse_field_name()

    # Discover the bounded graph while the root mutex excludes every supported
    # writer.  The exact projections are checked again after row locks are held.
    mapped_group_ids = set()
    if requested_idp_ids:
        mapped_group_ids.update(
            mapping_through.objects.filter(
                **{f"{mapping_source}_id__in": requested_idp_ids}
            ).values_list(f"{mapping_target}_id", flat=True)
        )

    candidate_group_ids = mapped_group_ids | requested_proposed_group_ids
    if requested_enclave_ids:
        candidate_group_ids.update(
            UserGroup.objects.filter(folder_id__in=requested_enclave_ids).values_list(
                "id", flat=True
            )
        )

    assignment_scope = Q()
    has_assignment_scope = False
    if candidate_group_ids:
        assignment_scope |= Q(user_group_id__in=candidate_group_ids)
        has_assignment_scope = True
    if requested_enclave_ids:
        assignment_scope |= (
            Q(folder_id__in=requested_enclave_ids)
            | Q(user_group__folder_id__in=requested_enclave_ids)
            | Q(perimeter_folders__id__in=requested_enclave_ids)
        )
        has_assignment_scope = True
    assignment_ids = set()
    if has_assignment_scope:
        assignment_ids.update(
            RoleAssignment.objects.filter(assignment_scope)
            .distinct()
            .values_list("id", flat=True)
        )

    assignment_snapshot = {
        row_id: (folder_id, user_group_id, role_id)
        for row_id, folder_id, user_group_id, role_id in RoleAssignment.objects.filter(
            id__in=assignment_ids
        ).values_list("id", "folder_id", "user_group_id", "role_id")
    }
    candidate_group_ids.update(
        user_group_id
        for _folder_id, user_group_id, _role_id in assignment_snapshot.values()
        if user_group_id is not None
    )

    group_snapshot = dict(
        UserGroup.objects.filter(id__in=candidate_group_ids).values_list(
            "id", "folder_id"
        )
    )
    perimeter_snapshot = {
        (assignment_id, folder_id)
        for assignment_id, folder_id in perimeter_through.objects.filter(
            **{f"{perimeter_source}_id__in": assignment_ids}
        ).values_list(
            f"{perimeter_source}_id", f"{perimeter_target}_id"
        )
    }

    mapping_scope = Q()
    has_mapping_scope = False
    if requested_idp_ids:
        mapping_scope |= Q(**{f"{mapping_source}_id__in": requested_idp_ids})
        has_mapping_scope = True
    if candidate_group_ids:
        mapping_scope |= Q(**{f"{mapping_target}_id__in": candidate_group_ids})
        has_mapping_scope = True
    mapping_snapshot = set()
    if has_mapping_scope:
        mapping_snapshot = {
            (idp_group_id, user_group_id)
            for idp_group_id, user_group_id in mapping_through.objects.filter(
                mapping_scope
            ).values_list(f"{mapping_source}_id", f"{mapping_target}_id")
        }

    affected_idp_ids = requested_idp_ids | {
        idp_group_id for idp_group_id, _user_group_id in mapping_snapshot
    }
    role_ids = {
        role_id for _folder_id, _user_group_id, role_id in assignment_snapshot.values()
    }
    folder_ids = requested_enclave_ids | set(group_snapshot.values()) | {
        folder_id for folder_id, _user_group_id, _role_id in assignment_snapshot.values()
    } | {folder_id for _assignment_id, folder_id in perimeter_snapshot}

    folder_snapshot = dict(
        Folder.objects.filter(id__in=folder_ids).values_list("id", "content_type")
    )
    role_snapshot = dict(
        Role.objects.filter(id__in=role_ids).values_list("id", "name")
    )

    locked_folders = {
        row.id: row
        for row in Folder.objects.select_for_update(of=("self",))
        .filter(id__in=folder_ids)
        .order_by("id")
    }
    locked_idp_groups = {
        row.id: row
        for row in IdPGroup.objects.select_for_update(of=("self",))
        .filter(id__in=affected_idp_ids)
        .order_by("id")
    }
    locked_roles = {
        row.id: row
        for row in Role.objects.select_for_update(of=("self",))
        .filter(id__in=role_ids)
        .order_by("id")
    }
    locked_groups = {
        row.id: row
        for row in UserGroup.objects.select_for_update(of=("self",))
        .filter(id__in=candidate_group_ids)
        .order_by("id")
    }
    locked_assignments = {
        row.id: row
        for row in RoleAssignment.objects.select_for_update(of=("self",))
        .filter(id__in=assignment_ids)
        .order_by("id")
    }
    locked_perimeters = list(
        perimeter_through.objects.select_for_update()
        .filter(**{f"{perimeter_source}_id__in": assignment_ids})
        .order_by("pk")
    )
    locked_mappings = (
        list(
            mapping_through.objects.select_for_update()
            .filter(mapping_scope)
            .order_by("pk")
        )
        if has_mapping_scope
        else []
    )

    membership_rows = list(
        membership_through.objects.select_for_update()
        .filter(**{f"{membership_target}_id__in": affected_idp_ids})
        .order_by("pk")
    )
    member_user_ids = {
        getattr(row, f"{membership_source}_id") for row in membership_rows
    }
    locked_users = {
        row.id: row
        for row in User.objects.select_for_update(of=("self",))
        .filter(id__in=member_user_ids)
        .order_by("id")
    }

    current_perimeters = {
        (
            getattr(row, f"{perimeter_source}_id"),
            getattr(row, f"{perimeter_target}_id"),
        )
        for row in locked_perimeters
    }
    current_mappings = {
        (
            getattr(row, f"{mapping_source}_id"),
            getattr(row, f"{mapping_target}_id"),
        )
        for row in locked_mappings
    }
    if (
        set(locked_folders) != set(folder_snapshot)
        or any(
            locked_folders[row_id].content_type != content_type
            for row_id, content_type in folder_snapshot.items()
        )
        or set(locked_roles) != set(role_snapshot)
        or any(
            locked_roles[row_id].name != name
            for row_id, name in role_snapshot.items()
        )
        or set(locked_groups) != set(group_snapshot)
        or not requested_proposed_group_ids.issubset(group_snapshot)
        or any(
            locked_groups[row_id].folder_id != folder_id
            for row_id, folder_id in group_snapshot.items()
        )
        or set(locked_assignments) != set(assignment_snapshot)
        or any(
            (
                locked_assignments[row_id].folder_id,
                locked_assignments[row_id].user_group_id,
                locked_assignments[row_id].role_id,
            )
            != expected
            for row_id, expected in assignment_snapshot.items()
        )
        or current_perimeters != perimeter_snapshot
        or current_mappings != mapping_snapshot
        or set(locked_users) != member_user_ids
    ):
        raise ManagedTprmRespondentIamError

    enclave_ids = {
        folder_id
        for folder_id, content_type in folder_snapshot.items()
        if content_type == TPRM_ENCLAVE_CONTENT_TYPE
    }
    dangerous_group_ids = {
        group_id
        for group_id, folder_id in group_snapshot.items()
        if folder_id in enclave_ids
    }
    perimeter_ids_by_assignment: dict[Any, set[Any]] = {}
    for assignment_id, folder_id in current_perimeters:
        perimeter_ids_by_assignment.setdefault(assignment_id, set()).add(folder_id)
    for assignment_id, assignment in locked_assignments.items():
        if assignment.user_group_id is None:
            continue
        group = locked_groups.get(assignment.user_group_id)
        role = locked_roles.get(assignment.role_id)
        if group is None or role is None:
            raise ManagedTprmRespondentIamError
        if (
            group.folder_id in enclave_ids
            or assignment.folder_id in enclave_ids
            or role.name == TPRM_RESPONDENT_ROLE_CODENAME
            or perimeter_ids_by_assignment.get(assignment_id, set()) & enclave_ids
        ):
            dangerous_group_ids.add(group.id)

    if dangerous_group_ids & requested_proposed_group_ids or any(
        user_group_id in dangerous_group_ids
        for _idp_group_id, user_group_id in current_mappings
    ):
        raise ManagedTprmRespondentIamError

    return {
        idp_group_id: locked_idp_groups[idp_group_id]
        for idp_group_id in requested_idp_ids
        if idp_group_id in locked_idp_groups
    }
