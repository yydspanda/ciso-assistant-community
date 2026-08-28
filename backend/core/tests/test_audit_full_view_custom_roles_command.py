"""Tests for the read-only custom-role full-view permission audit."""

import json
from io import StringIO

import pytest
from django.contrib.auth.models import Permission
from django.contrib.contenttypes.models import ContentType
from django.core.management import call_command
from django.core.management.base import CommandError

from iam.models import Role


@pytest.fixture
def full_view_permission(db):
    return Permission.objects.get(
        content_type__app_label="core",
        content_type__model="complianceassessment",
        codename="view_compliance_assessment_full",
    )


def _run(*args):
    stdout = StringIO()
    call_command("audit_full_view_custom_roles", *args, stdout=stdout)
    return stdout.getvalue()


@pytest.mark.django_db
def test_human_report_lists_only_non_builtin_exact_permission_holders(
    full_view_permission,
):
    included = Role.objects.create(name="Legacy full-view role", builtin=False)
    included.permissions.add(full_view_permission)
    builtin = Role.objects.create(name="BI-RL-TEST-FULL", builtin=True)
    builtin.permissions.add(full_view_permission)

    other_content_type = ContentType.objects.create(
        app_label="audit_test", model="complianceassessment"
    )
    same_codename_elsewhere = Permission.objects.create(
        name="Test-only same codename",
        codename="view_compliance_assessment_full",
        content_type=other_content_type,
    )
    wrong_permission = Role.objects.create(name="Wrong permission role", builtin=False)
    wrong_permission.permissions.add(same_codename_elsewhere)

    output = _run()

    assert "1 non-builtin custom role(s)" in output
    assert included.name in output
    assert str(included.id) in output
    assert builtin.name not in output
    assert wrong_permission.name not in output
    assert "no permissions were changed" in output


@pytest.mark.django_db
def test_json_report_is_deterministic_and_machine_readable(full_view_permission):
    role_z = Role.objects.create(name="Zeta", builtin=False)
    role_a = Role.objects.create(name="Alpha", builtin=False)
    role_z.permissions.add(full_view_permission)
    role_a.permissions.add(full_view_permission)

    payload = json.loads(_run("--json"))

    assert payload == {
        "custom_role_count": 2,
        "custom_roles": [
            {"id": str(role_a.id), "name": "Alpha"},
            {"id": str(role_z.id), "name": "Zeta"},
        ],
        "permission": {
            "app_label": "core",
            "codename": "view_compliance_assessment_full",
            "model": "complianceassessment",
        },
        "read_only": True,
    }


@pytest.mark.django_db
def test_empty_audit_passes_fail_if_present(full_view_permission):
    output = _run("--fail-if-present")

    assert "No non-builtin custom roles" in output


@pytest.mark.django_db
def test_fail_if_present_reports_then_exits_nonzero_without_mutating(
    full_view_permission,
):
    role = Role.objects.create(name="Review me", builtin=False)
    role.permissions.add(full_view_permission)
    stdout = StringIO()

    with pytest.raises(CommandError, match="1 non-builtin custom role"):
        call_command(
            "audit_full_view_custom_roles",
            "--fail-if-present",
            stdout=stdout,
        )

    assert role.name in stdout.getvalue()
    assert role.permissions.filter(id=full_view_permission.id).exists()


@pytest.mark.django_db
def test_missing_exact_permission_fails_closed(full_view_permission):
    full_view_permission.delete()

    with pytest.raises(CommandError, match="database migrations are current"):
        _run("--json")
