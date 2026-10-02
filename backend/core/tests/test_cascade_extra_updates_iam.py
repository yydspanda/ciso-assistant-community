"""Extra aggregate deletion previews retain SET_NULL effects and native read IAM."""

import uuid

import pytest
from django.contrib.auth.models import Permission
from iam.models import Folder, Role, RoleAssignment, User
from rest_framework.test import APIClient
from tprm.models import Entity, EntityAssessment

from core.models import (
    AppliedControl,
    Asset,
    ComplianceAssessment,
    FindingsAssessment,
    Framework,
    Policy,
)
from core.startup import startup

pytestmark = pytest.mark.django_db


def _client(user):
    client = APIClient()
    client.force_authenticate(user)
    return client


def _scoped_user(folder, *permissions):
    user = User.objects.create_user(f"cascade-{uuid.uuid4().hex}@tests.invalid")
    role = Role.objects.create(name=f"Cascade reader {uuid.uuid4().hex}", folder=folder)
    resolved = Permission.objects.filter(codename__in=permissions)
    assert resolved.count() == len(permissions)
    role.permissions.set(resolved)
    assignment = RoleAssignment.objects.create(
        user=user, role=role, folder=folder, is_recursive=True
    )
    assignment.perimeter_folders.add(folder)
    return user


@pytest.fixture
def cascade_domain():
    startup(sender=None, **{})
    return Folder.objects.create(
        name="Synthetic cascade domain",
        parent_folder=Folder.get_root_folder(),
        content_type=Folder.ContentType.DOMAIN,
    )


def _audit_subject(domain, *, shared_enclave):
    enclave = Folder.objects.create(
        name="Synthetic vendor workspace",
        parent_folder=domain,
        content_type=Folder.ContentType.ENCLAVE,
    )
    framework = Framework.objects.create(name="Synthetic framework", folder=domain)
    audit = ComplianceAssessment.objects.create(
        name="Owned questionnaire", folder=enclave, framework=framework
    )
    if shared_enclave:
        ComplianceAssessment.objects.create(
            name="Sibling questionnaire", folder=enclave, framework=framework
        )
    entity = Entity.objects.create(name="Synthetic vendor", folder=domain)
    subject = EntityAssessment.objects.create(
        name="Synthetic vendor assessment",
        folder=domain,
        entity=entity,
        compliance_assessment=audit,
    )
    binder = FindingsAssessment.objects.create(
        name="Synthetic independent findings binder",
        folder=domain,
        compliance_assessment=audit,
    )
    return subject, audit, binder


def _ids(bucket):
    return {row["id"] for row in bucket["related_objects"]}


@pytest.mark.parametrize("shared_enclave", [False, True])
def test_extra_audit_delete_previews_set_null_without_deleting_binder(
    cascade_domain, shared_enclave
):
    subject, audit, binder = _audit_subject(
        cascade_domain, shared_enclave=shared_enclave
    )
    user = _scoped_user(
        cascade_domain,
        "view_entityassessment",
        "delete_entityassessment",
        "view_folder",
        "view_complianceassessment",
        "view_findingsassessment",
    )
    client = _client(user)
    preview = client.get(f"/api/entity-assessments/{subject.id}/cascade-info/")
    assert preview.status_code == 200, preview.content
    body = preview.json()
    assert str(binder.id) in _ids(body["affected"])
    assert str(binder.id) not in _ids(body["deleted"])
    assert str(audit.id) in _ids(body["deleted"])
    assert all(str(subject.id) not in _ids(body[bucket]) for bucket in body)
    # Preview is read-only; the independent binder survives the real aggregate
    # delete but loses exactly the SET_NULL link announced by the preview.
    binder.refresh_from_db()
    assert binder.compliance_assessment_id == audit.id
    removed = client.delete(f"/api/entity-assessments/{subject.id}/")
    assert removed.status_code == 204, removed.content
    binder.refresh_from_db()
    assert binder.compliance_assessment_id is None


@pytest.mark.parametrize("shared_enclave", [False, True])
def test_folder_visibility_does_not_reveal_extra_updated_object(
    cascade_domain, shared_enclave
):
    subject, _audit, binder = _audit_subject(
        cascade_domain, shared_enclave=shared_enclave
    )
    user = _scoped_user(
        cascade_domain,
        "view_entityassessment",
        "delete_entityassessment",
        "view_folder",
        "view_complianceassessment",
    )
    preview = _client(user).get(f"/api/entity-assessments/{subject.id}/cascade-info/")
    assert preview.status_code == 200, preview.content
    assert str(binder.id) not in preview.content.decode()
    assert binder.name not in preview.content.decode()
    binder.refresh_from_db()
    assert binder.compliance_assessment_id is not None


def test_folder_delete_authority_does_not_substitute_for_child_read(cascade_domain):
    asset = Asset.objects.create(name="Synthetic hidden asset", folder=cascade_domain)
    user = _scoped_user(cascade_domain, "view_folder", "delete_folder")
    preview = _client(user).get(f"/api/folders/{cascade_domain.id}/cascade-info/")
    assert preview.status_code == 200, preview.content
    assert str(asset.id) not in preview.content.decode()
    assert asset.name not in preview.content.decode()
    assert Asset.objects.filter(id=asset.id).exists()


def test_policy_proxy_retains_its_independent_read_permission(cascade_domain):
    visible_control = AppliedControl.objects.create(
        name="Synthetic visible technical control",
        folder=cascade_domain,
        category="technical",
    )
    hidden_policy = Policy.objects.create(
        name="Synthetic hidden policy", folder=cascade_domain
    )
    user = _scoped_user(
        cascade_domain, "view_folder", "delete_folder", "view_appliedcontrol"
    )
    preview = _client(user).get(f"/api/folders/{cascade_domain.id}/cascade-info/")
    assert preview.status_code == 200, preview.content
    assert str(visible_control.id) in _ids(preview.json()["deleted"])
    assert str(hidden_policy.id) not in preview.content.decode()
    assert hidden_policy.name not in preview.content.decode()
