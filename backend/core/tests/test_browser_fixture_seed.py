"""Browser-only role setup never grants user access or changes default IAM."""

import pytest
from django.contrib.auth.models import Permission

from app_tests.browser_fixtures import (
    TPRM_TEMPLATE_READ_PERMISSIONS,
    TPRM_TEMPLATE_READER_ROLE,
    seed_tprm_template_reader,
)
from core.startup import startup
from iam.models import Folder, Role, RoleAssignment, UserGroup

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
