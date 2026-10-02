"""Canonical-upstream IAM aggregation and notification-seat compatibility.

These tests use explicit synthetic grants; a seat-classification exclusion must
never become a grant, and recursive aggregation must preserve folder boundaries.
"""

import pytest
from django.contrib.auth.models import AnonymousUser, Permission

from core.startup import startup
from iam.models import Folder, Role, RoleAssignment, User, UserGroup

pytestmark = pytest.mark.django_db


@pytest.fixture
def root():
    startup(sender=None)
    return Folder.get_root_folder()


def _grant(*, root, principal, folder, name, codenames, recursive=False):
    role = Role.objects.create(name=name, folder=root)
    permissions = list(Permission.objects.filter(codename__in=codenames))
    assert {permission.codename for permission in permissions} == set(codenames)
    role.permissions.set(permissions)
    assignment = RoleAssignment.objects.create(
        name=name,
        folder=root,
        role=role,
        user=principal if isinstance(principal, User) else None,
        user_group=principal if isinstance(principal, UserGroup) else None,
        is_recursive=recursive,
    )
    if folder is not None:
        assignment.perimeter_folders.set([folder])
    return assignment


@pytest.mark.parametrize("principal_kind", ["user", "group"])
@pytest.mark.parametrize("include_descendants", [False, True])
def test_permission_aggregation_preserves_mixed_recursion_and_sibling_scope(
    root, principal_kind, include_descendants
):
    parent = Folder.objects.create(
        name="Synthetic aggregation parent", parent_folder=root
    )
    child = Folder.objects.create(
        name="Synthetic aggregation child", parent_folder=parent
    )
    grandchild = Folder.objects.create(
        name="Synthetic aggregation grandchild", parent_folder=child
    )
    sibling = Folder.objects.create(
        name="Synthetic aggregation sibling", parent_folder=root
    )
    user = User.objects.create_user("permission-aggregation@example.test")
    if principal_kind == "group":
        principal = UserGroup.objects.create(
            name="Synthetic aggregation custom group", folder=root, builtin=False
        )
        principal.user_set.add(user)
    else:
        principal = user
    recursive_permissions = {"view_appliedcontrol", "change_appliedcontrol"}
    _grant(
        root=root,
        principal=principal,
        folder=parent,
        name="Synthetic recursive parent",
        codenames=recursive_permissions,
        recursive=True,
    )
    _grant(
        root=root,
        principal=principal,
        folder=child,
        name="Synthetic direct child",
        codenames={"delete_appliedcontrol"},
    )
    _grant(
        root=root,
        principal=principal,
        folder=sibling,
        name="Synthetic direct sibling",
        codenames={"view_evidence"},
    )
    # Neither an empty role nor a grant without a perimeter introduces a key.
    _grant(
        root=root,
        principal=principal,
        folder=root,
        name="Synthetic empty role",
        codenames=set(),
    )
    _grant(
        root=root,
        principal=principal,
        folder=None,
        name="Synthetic empty perimeter",
        codenames={"delete_evidence"},
        recursive=True,
    )
    expected = {
        str(parent.pk): recursive_permissions,
        str(child.pk): {"delete_appliedcontrol"},
        str(sibling.pk): {"view_evidence"},
    }
    if include_descendants:
        expected[str(child.pk)] |= recursive_permissions
        expected[str(grandchild.pk)] = recursive_permissions
    actual = RoleAssignment.get_permissions_per_folder(
        principal, is_recursive=include_descendants
    )
    assert dict(actual) == expected
    assert str(root.pk) not in actual
    assert "delete_appliedcontrol" not in actual.get(str(grandchild.pk), set())
    assert "delete_evidence" not in set().union(*actual.values())


def test_permission_aggregation_does_not_restore_an_inactive_users_grant(root):
    user = User.objects.create_user("inactive-aggregation@example.test")
    _grant(
        root=root,
        principal=user,
        folder=root,
        name="Synthetic inactive grant",
        codenames={"view_appliedcontrol"},
        recursive=True,
    )
    assert RoleAssignment.get_permissions_per_folder(user, is_recursive=True)
    user.is_active = False
    user.save(update_fields=["is_active"])
    assert (
        dict(RoleAssignment.get_permissions_per_folder(user, is_recursive=True)) == {}
    )


@pytest.mark.parametrize("principal", [None, "not-an-identity", AnonymousUser()])
def test_permission_aggregation_rejects_non_principals(root, principal):
    assert (
        dict(RoleAssignment.get_permissions_per_folder(principal, is_recursive=True))
        == {}
    )


def test_notification_seat_exclusions_are_not_permissions(root):
    user = User.objects.create_user("notification-no-grant@example.test")
    assert {"change_notification", "delete_notification"} <= User.NON_SEAT_PERMISSIONS
    assert RoleAssignment.get_permissions(user) == {}
    for codename in ("change_notification", "delete_notification"):
        permission = Permission.objects.get(
            content_type__app_label="notifications", codename=codename
        )
        assert not RoleAssignment.is_access_allowed(user, permission, root)
    assert user.is_editor is False
    assert user not in User.get_editors()


def test_notification_only_grants_do_not_consume_an_editor_seat(root):
    user = User.objects.create_user("notification-seat@example.test")
    codenames = {"view_notification", "change_notification", "delete_notification"}
    _grant(
        root=root,
        principal=user,
        folder=root,
        name="Synthetic notification grant",
        codenames=codenames,
    )
    assert set(RoleAssignment.get_permissions(user)) == codenames
    assert user.is_editor is False
    assert user not in User.get_editors()
    permission_before = set(RoleAssignment.get_permissions(user))
    _grant(
        root=root,
        principal=user,
        folder=root,
        name="Synthetic actual editor grant",
        codenames={"change_appliedcontrol"},
    )
    assert set(RoleAssignment.get_permissions(user)) == permission_before | {
        "change_appliedcontrol"
    }
    assert user.is_editor is True
    assert user in User.get_editors()


def test_baseline_default_role_does_not_grant_notification_writes(root):
    baseline = Role.objects.get(name="BI-RL-BSL", builtin=True)
    assert "view_notification" in set(
        baseline.permissions.values_list("codename", flat=True)
    )
    assert not baseline.permissions.filter(
        codename__in={"change_notification", "delete_notification"}
    ).exists()
