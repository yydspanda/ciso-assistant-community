"""Explicit synthetic browser roles/grants never change builtin or default IAM."""

import pytest
from django.contrib.auth.models import Permission

from app_tests.browser_fixtures import (
    TPRM_FIXTURE_ADMIN_GRANT,
    TPRM_FIXTURE_ADMIN_PERMISSIONS,
    TPRM_FIXTURE_ADMIN_ROLE,
    TPRM_TEMPLATE_READ_PERMISSIONS,
    TPRM_TEMPLATE_READER_ROLE,
    seed_tprm_template_reader,
    seed_tprm_browser_admin_grant,
)
from core.startup import startup
from iam.models import Folder, Role, RoleAssignment, User, UserGroup
from rest_framework.test import APIClient

pytestmark = pytest.mark.django_db


@pytest.fixture
def root():
    startup(sender=None, **{})
    return Folder.get_root_folder()


def _permission_ids():
    return {
        Permission.objects.get(
            content_type__app_label="core",
            content_type__model=model,
            codename=codename,
        ).pk
        for model, codename in TPRM_TEMPLATE_READ_PERMISSIONS
    }


def _unrelated_iam_state():
    return (
        list(RoleAssignment.objects.order_by("pk").values()),
        list(UserGroup.objects.order_by("pk").values()),
        list(Folder.objects.order_by("pk").values("pk", "default_role_id")),
        list(
            Role.permissions.through.objects.exclude(
                role__name=TPRM_TEMPLATE_READER_ROLE
            )
            .order_by("pk")
            .values()
        ),
    )


def test_seed_is_exact_idempotent_and_never_assigns_or_changes_defaults(root):
    before = _unrelated_iam_state()
    role = seed_tprm_template_reader(synthetic_test_database=True)
    assert role.folder_id == root.pk
    assert role.builtin is False
    assert set(role.permissions.values_list("pk", flat=True)) == _permission_ids()
    assert seed_tprm_template_reader(synthetic_test_database=True).pk == role.pk
    assert Role.objects.filter(name=TPRM_TEMPLATE_READER_ROLE).count() == 1
    assert not RoleAssignment.objects.filter(role=role).exists()
    assert not Folder.objects.filter(default_role=role).exists()
    assert _unrelated_iam_state() == before


@pytest.mark.parametrize("opt_in", [False, None, 1])
def test_seed_requires_explicit_boolean_opt_in_without_writing(root, opt_in):
    before = Role.objects.count()
    with pytest.raises(ValueError, match="synthetic test database"):
        seed_tprm_template_reader(synthetic_test_database=opt_in)
    assert Role.objects.count() == before


@pytest.mark.parametrize(
    "collision",
    ["builtin", "folder", "extra_permission", "missing_permission", "duplicate"],
)
def test_seed_refuses_colliding_contract_without_repair(root, collision):
    role = seed_tprm_template_reader(synthetic_test_database=True)
    if collision == "builtin":
        role.builtin = True
        role.save(update_fields=["builtin"])
    elif collision == "folder":
        role.folder = Folder.objects.create(name="Synthetic other fixture domain")
        role.save(update_fields=["folder"])
    elif collision == "extra_permission":
        role.permissions.add(
            Permission.objects.get(
                content_type__app_label="core", codename="change_framework"
            )
        )
    elif collision == "missing_permission":
        role.permissions.remove(min(_permission_ids()))
    else:
        # Names are unique only within one folder; an identically named role
        # in another folder is a real cross-scope catalog collision.
        other = Folder.objects.create(name="Synthetic duplicate fixture domain")
        Role.objects.create(name=TPRM_TEMPLATE_READER_ROLE, folder=other)
    before = (
        list(Role.objects.order_by("pk").values()),
        list(Role.permissions.through.objects.order_by("pk").values()),
    )
    with pytest.raises(ValueError, match="contract mismatch|Duplicate"):
        seed_tprm_template_reader(synthetic_test_database=True)
    assert (
        list(Role.objects.order_by("pk").values()),
        list(Role.permissions.through.objects.order_by("pk").values()),
    ) == before
    assert not RoleAssignment.objects.filter(role=role).exists()


def test_missing_native_permission_does_not_create_partial_role(root):
    Permission.objects.get(
        content_type__app_label="core", codename="view_questionchoice"
    ).delete()
    before = Role.objects.count()
    with pytest.raises(Permission.DoesNotExist):
        seed_tprm_template_reader(synthetic_test_database=True)
    assert Role.objects.count() == before
    assert not Role.objects.filter(name=TPRM_TEMPLATE_READER_ROLE).exists()


def _builtin_permissions():
    return {
        role.pk: set(role.permissions.values_list("pk", flat=True))
        for role in Role.objects.filter(builtin=True)
    }


def test_explicit_admin_fixture_uses_native_api_without_changing_builtin_iam(root):
    admin = User.objects.create_superuser("admin@tests.com")
    respondent = User.objects.create_user("synthetic-respondent@tests.invalid")
    role = seed_tprm_template_reader(synthetic_test_database=True)
    client = APIClient()
    client.force_authenticate(admin)
    payload = {
        "name": "Synthetic respondent template grant",
        "user": str(respondent.pk),
        "user_group": None,
        "role": str(role.pk),
        "folder": str(root.pk),
        "is_recursive": False,
        "perimeter_folders": [str(root.pk)],
    }
    denied = client.post("/api/role-assignments/", payload, format="json")
    assert denied.status_code == 403
    assert not RoleAssignment.objects.filter(user=respondent).exists()
    builtin_before = _builtin_permissions()
    defaults_before = list(Folder.objects.values_list("pk", "default_role_id"))
    assignment = seed_tprm_browser_admin_grant(
        synthetic_admin_email=admin.email, synthetic_test_database=True
    )
    assert assignment.user_id == admin.pk
    assert assignment.user_group_id is None
    assert assignment.folder_id == root.pk
    assert assignment.is_recursive is False
    assert assignment.builtin is False
    assert set(assignment.perimeter_folders.values_list("pk", flat=True)) == {root.pk}
    assert set(assignment.role.permissions.values_list("codename", flat=True)) == set(
        TPRM_FIXTURE_ADMIN_PERMISSIONS
    )
    assert (
        seed_tprm_browser_admin_grant(
            synthetic_admin_email=admin.email, synthetic_test_database=True
        ).pk
        == assignment.pk
    )
    granted = client.post("/api/role-assignments/", payload, format="json")
    assert granted.status_code == 201, granted.content
    created = RoleAssignment.objects.get(pk=granted.json()["id"])
    assert created.user_id == respondent.pk
    assert created.role_id == role.pk
    assert not created.is_recursive
    assert set(created.perimeter_folders.values_list("pk", flat=True)) == {root.pk}
    deleted = client.delete(f"/api/role-assignments/{created.pk}/")
    assert deleted.status_code == 204, deleted.content
    assert not RoleAssignment.objects.filter(pk=created.pk).exists()
    assert not RoleAssignment.objects.filter(user=respondent).exists()
    assert _builtin_permissions() == builtin_before
    assert list(Folder.objects.values_list("pk", "default_role_id")) == defaults_before


@pytest.mark.parametrize(
    "identity", ["missing", "inactive", "not_superuser", "not_synthetic"]
)
def test_admin_fixture_refuses_an_unavailable_named_identity_without_writes(
    root, identity
):
    email = "admin@tests.com"
    if identity != "missing":
        if identity == "not_synthetic":
            email = "not-a-fixture@example.invalid"
        user = User.objects.create_user(email, is_superuser=identity != "not_superuser")
        if identity == "inactive":
            # User.save intentionally prevents normal superuser deactivation.
            # Simulate a legacy/direct-DB inactive row, not an API transition.
            User.objects.filter(pk=user.pk).update(is_active=False)
    before = _unrelated_iam_state(), Role.objects.count()
    with pytest.raises(ValueError, match="synthetic browser administrator"):
        seed_tprm_browser_admin_grant(
            synthetic_admin_email=email, synthetic_test_database=True
        )
    assert (_unrelated_iam_state(), Role.objects.count()) == before
    assert not Role.objects.filter(name=TPRM_FIXTURE_ADMIN_ROLE).exists()


def test_admin_fixture_requires_explicit_opt_in(root):
    before = _unrelated_iam_state(), Role.objects.count()
    with pytest.raises(ValueError, match="synthetic test database"):
        seed_tprm_browser_admin_grant(synthetic_admin_email="admin@tests.com")
    assert (_unrelated_iam_state(), Role.objects.count()) == before


def test_missing_admin_native_permission_cannot_create_partial_role_or_grant(root):
    admin = User.objects.create_superuser("admin@tests.com")
    Permission.objects.get(
        content_type__app_label="iam",
        content_type__model="roleassignment",
        codename="delete_roleassignment",
    ).delete()
    before = _unrelated_iam_state(), Role.objects.count()
    with pytest.raises(Permission.DoesNotExist):
        seed_tprm_browser_admin_grant(
            synthetic_admin_email=admin.email, synthetic_test_database=True
        )
    assert (_unrelated_iam_state(), Role.objects.count()) == before
    assert not Role.objects.filter(name=TPRM_FIXTURE_ADMIN_ROLE).exists()
    assert not RoleAssignment.objects.filter(name=TPRM_FIXTURE_ADMIN_GRANT).exists()


@pytest.mark.parametrize(
    "corruption", ["role_permissions", "recipient", "recursive", "perimeter", "builtin"]
)
def test_admin_fixture_rejects_existing_contract_drift_without_repair(root, corruption):
    admin = User.objects.create_superuser("admin@tests.com")
    assignment = seed_tprm_browser_admin_grant(
        synthetic_admin_email=admin.email, synthetic_test_database=True
    )
    if corruption == "role_permissions":
        assignment.role.permissions.add(
            Permission.objects.get(
                content_type__app_label="core", codename="change_framework"
            )
        )
    elif corruption == "recipient":
        assignment.user = User.objects.create_user("other-fixture@tests.invalid")
        assignment.save(update_fields=["user"])
    elif corruption == "recursive":
        assignment.is_recursive = True
        assignment.save(update_fields=["is_recursive"])
    elif corruption == "perimeter":
        assignment.perimeter_folders.set(
            [Folder.objects.create(name="Synthetic other scope")]
        )
    else:
        assignment.builtin = True
        assignment.save(update_fields=["builtin"])
    before = _unrelated_iam_state()
    with pytest.raises(ValueError, match="contract mismatch"):
        seed_tprm_browser_admin_grant(
            synthetic_admin_email=admin.email, synthetic_test_database=True
        )
    assert _unrelated_iam_state() == before
    assert RoleAssignment.objects.filter(name=TPRM_FIXTURE_ADMIN_GRANT).count() == 1
