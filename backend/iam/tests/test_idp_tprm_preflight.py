import importlib

import pytest
from django.apps import apps as django_apps

from core.utils import RoleCodename, UserGroupCodename
from iam.models import Folder, IdPGroup, Role, RoleAssignment, UserGroup


@pytest.mark.django_db
def test_upgrade_preflight_reports_and_preserves_legacy_idp_enclave_mapping():
    enclave = Folder.objects.create(
        name="IdP preflight enclave",
        content_type=Folder.ContentType.ENCLAVE,
        parent_folder=Folder.get_root_folder(),
    )
    respondent_group = UserGroup.objects.create(
        name=UserGroupCodename.THIRD_PARTY_RESPONDENT.value,
        folder=enclave,
        builtin=True,
    )
    assignment = RoleAssignment.objects.create(
        user_group=respondent_group,
        role=Role.objects.get(name=RoleCodename.THIRD_PARTY_RESPONDENT.value),
        folder=enclave,
        builtin=True,
        is_recursive=True,
    )
    assignment.perimeter_folders.add(enclave)
    idp_group = IdPGroup.objects.create(name="legacy-preflight-idp")
    mapping_field = IdPGroup._meta.get_field("user_groups")
    mapping_through = mapping_field.remote_field.through
    mapping = mapping_through.objects.create(
        **{
            f"{mapping_field.m2m_field_name()}_id": idp_group.id,
            f"{mapping_field.m2m_reverse_field_name()}_id": respondent_group.id,
        }
    )

    migration = importlib.import_module(
        "iam.migrations.0029_preflight_idp_tprm_enclave_inheritance"
    )
    with pytest.raises(RuntimeError, match="migration made no changes") as exc_info:
        migration.reject_idp_tprm_enclave_inheritance(django_apps, None)

    assert "reviewed IAM remediation" in str(exc_info.value)
    assert IdPGroup.objects.filter(id=idp_group.id).exists()
    assert UserGroup.objects.filter(id=respondent_group.id).exists()
    assert RoleAssignment.objects.filter(id=assignment.id).exists()
    assert mapping_through.objects.filter(pk=mapping.pk).exists()


@pytest.mark.django_db
def test_upgrade_preflight_allows_unprivileged_idp_mapping():
    ordinary_group = UserGroup.objects.create(
        name="ordinary-idp-target",
        folder=Folder.get_root_folder(),
    )
    idp_group = IdPGroup.objects.create(name="ordinary-preflight-idp")
    idp_group.user_groups.add(ordinary_group)
    migration = importlib.import_module(
        "iam.migrations.0029_preflight_idp_tprm_enclave_inheritance"
    )

    migration.reject_idp_tprm_enclave_inheritance(django_apps, None)

    assert idp_group.user_groups.filter(id=ordinary_group.id).exists()
