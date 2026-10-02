from __future__ import annotations

import uuid

import pytest
from auditlog.models import LogEntry
from django.contrib.auth.models import Permission
from django.contrib.contenttypes.models import ContentType
from rest_framework.test import APIClient

from core.models import (
    ComplianceAssessment,
    FlowEvent,
    Framework,
    Perimeter,
    ValidationFlow,
)
from iam.models import Folder, Role, RoleAssignment, User
from tprm.models import Entity, EntityAssessment
from tprm.services import create_enclave_audit


pytestmark = pytest.mark.django_db


def _permission(codename: str, model) -> Permission:
    return Permission.objects.get(
        codename=codename,
        content_type__app_label=model._meta.app_label,
        content_type__model=model._meta.model_name,
    )


@pytest.fixture
def owned_audit_world():
    Folder._init_root_folder()
    root = Folder.get_root_folder()
    suffix = uuid.uuid4().hex
    domain = Folder.objects.create(
        name=f"owned-audit-domain-{suffix}",
        parent_folder=root,
        content_type=Folder.ContentType.DOMAIN,
    )
    framework = Framework.objects.create(
        name=f"Owned audit framework {suffix}",
        urn=f"urn:test:framework:owned-audit:{suffix}",
        ref_id=f"owned-audit-{suffix}",
        folder=root,
    )
    perimeter = Perimeter.objects.create(
        name=f"Owned audit perimeter {suffix}", folder=domain
    )
    entity = Entity.objects.create(name=f"Owned audit vendor {suffix}", folder=domain)
    return {
        "root": root,
        "domain": domain,
        "framework": framework,
        "perimeter": perimeter,
        "entity": entity,
        "suffix": suffix,
    }


def _round(world, *, label: str, enclave: Folder | None = None):
    assessment = EntityAssessment.objects.create(
        name=f"Round {label} {world['suffix']}",
        version=label,
        folder=world["domain"],
        perimeter=world["perimeter"],
        entity=world["entity"],
    )
    audit = create_enclave_audit(
        assessment,
        world["framework"],
        enclave=enclave,
    )
    assessment.refresh_from_db()
    return assessment, audit


def _scoped_client(world, *, can_delete: bool = True):
    suffix = uuid.uuid4().hex
    user = User.objects.create_user(f"owned-audit-{suffix}@example.test")
    user.folder = world["root"]
    user.save(update_fields=["folder"])
    role = Role.objects.create(name=f"Owned audit role {suffix}", folder=world["root"])
    permissions = [
        _permission("view_entityassessment", EntityAssessment),
        _permission("view_entity", Entity),
        _permission("view_folder", Folder),
    ]
    if can_delete:
        permissions.append(_permission("delete_entityassessment", EntityAssessment))
    role.permissions.set(permissions)
    assignment = RoleAssignment.objects.create(
        user=user,
        role=role,
        folder=world["root"],
        is_recursive=True,
    )
    assignment.perimeter_folders.add(world["domain"])
    client = APIClient()
    client.force_authenticate(user=user)
    return client, role


def _delete(client, assessment, *, batch: bool):
    if not batch:
        return client.delete(f"/api/entity-assessments/{assessment.id}/")
    return client.post(
        "/api/entity-assessments/batch-action/",
        {"action": "delete", "ids": [str(assessment.id)]},
        format="json",
    )


@pytest.mark.parametrize("batch", [False, True], ids=["single", "batch"])
def test_last_round_deletes_owned_audit_and_enclave_without_child_delete_grants(
    owned_audit_world, batch
):
    assessment, audit = _round(owned_audit_world, label=f"last-{batch}")
    audit_id = audit.id
    enclave_id = audit.folder_id
    client, role = _scoped_client(owned_audit_world)

    assert not role.permissions.filter(
        codename__in=("delete_complianceassessment", "delete_folder")
    ).exists()
    response = _delete(client, assessment, batch=batch)

    assert response.status_code == (200 if batch else 204), response.content
    if batch:
        assert response.json()["failed"] == []
        assert response.json()["succeeded"] == [
            {"id": str(assessment.id), "name": assessment.name}
        ]
    assert not EntityAssessment.objects.filter(pk=assessment.id).exists()
    assert not ComplianceAssessment.objects.filter(pk=audit_id).exists()
    assert not Folder.objects.filter(pk=enclave_id).exists()


def test_shared_enclave_deletes_only_rounds_own_audit(owned_audit_world):
    assessment, audit = _round(owned_audit_world, label="shared-source")
    sibling, sibling_audit = _round(
        owned_audit_world,
        label="shared-sibling",
        enclave=audit.folder,
    )
    enclave_id = audit.folder_id
    client, _ = _scoped_client(owned_audit_world)

    response = client.delete(f"/api/entity-assessments/{assessment.id}/")

    assert response.status_code == 204, response.content
    assert not EntityAssessment.objects.filter(pk=assessment.id).exists()
    assert not ComplianceAssessment.objects.filter(pk=audit.id).exists()
    assert EntityAssessment.objects.filter(pk=sibling.id).exists()
    assert ComplianceAssessment.objects.filter(pk=sibling_audit.id).exists()
    assert Folder.objects.filter(pk=enclave_id).exists()


def test_non_enclave_audit_is_not_aggregate_deleted(owned_audit_world):
    audit = ComplianceAssessment.objects.create(
        name=f"Non-enclave audit {owned_audit_world['suffix']}",
        folder=owned_audit_world["domain"],
        perimeter=owned_audit_world["perimeter"],
        framework=owned_audit_world["framework"],
    )
    assessment = EntityAssessment.objects.create(
        name=f"Non-enclave round {owned_audit_world['suffix']}",
        folder=owned_audit_world["domain"],
        perimeter=owned_audit_world["perimeter"],
        entity=owned_audit_world["entity"],
        compliance_assessment=audit,
    )
    client, _ = _scoped_client(owned_audit_world)

    response = client.delete(f"/api/entity-assessments/{assessment.id}/")

    assert response.status_code == 204, response.content
    assert not EntityAssessment.objects.filter(pk=assessment.id).exists()
    assert ComplianceAssessment.objects.filter(pk=audit.id).exists()
    assert Folder.objects.filter(pk=owned_audit_world["domain"].id).exists()


def test_parent_delete_permission_is_required_for_single_and_batch(
    owned_audit_world,
):
    assessment, audit = _round(owned_audit_world, label="denied")
    enclave_id = audit.folder_id
    client, role = _scoped_client(owned_audit_world, can_delete=False)

    assert not role.permissions.filter(codename="delete_entityassessment").exists()
    single = client.delete(f"/api/entity-assessments/{assessment.id}/")
    batch = client.post(
        "/api/entity-assessments/batch-action/",
        {"action": "delete", "ids": [str(assessment.id)]},
        format="json",
    )

    assert single.status_code == 403, single.content
    assert batch.status_code == 200, batch.content
    assert batch.json()["succeeded"] == []
    assert batch.json()["failed"] == [
        {
            "id": str(assessment.id),
            "name": assessment.name,
            "error": "Permission denied",
        }
    ]
    assert EntityAssessment.objects.filter(pk=assessment.id).exists()
    assert ComplianceAssessment.objects.filter(pk=audit.id).exists()
    assert Folder.objects.filter(pk=enclave_id).exists()


def test_batch_delete_does_not_disclose_or_delete_hidden_round(owned_audit_world):
    visible, visible_audit = _round(owned_audit_world, label="visible")
    root = owned_audit_world["root"]
    suffix = uuid.uuid4().hex
    hidden_domain = Folder.objects.create(
        name=f"hidden-owned-audit-{suffix}",
        parent_folder=root,
        content_type=Folder.ContentType.DOMAIN,
    )
    hidden_world = {
        "root": root,
        "domain": hidden_domain,
        "framework": owned_audit_world["framework"],
        "perimeter": Perimeter.objects.create(
            name=f"Hidden perimeter {suffix}", folder=hidden_domain
        ),
        "entity": Entity.objects.create(
            name=f"Hidden vendor {suffix}", folder=hidden_domain
        ),
        "suffix": suffix,
    }
    hidden, hidden_audit = _round(hidden_world, label="hidden")
    hidden_name = hidden.name
    hidden_enclave_id = hidden_audit.folder_id
    client, _ = _scoped_client(owned_audit_world)

    response = client.post(
        "/api/entity-assessments/batch-action/",
        {"action": "delete", "ids": [str(visible.id), str(hidden.id)]},
        format="json",
    )

    assert response.status_code == 200, response.content
    assert response.json()["succeeded"] == [
        {"id": str(visible.id), "name": visible.name}
    ]
    assert response.json()["failed"] == [
        {"id": str(hidden.id), "error": "Object not found or access denied"}
    ]
    assert hidden_name not in response.content.decode()
    assert not EntityAssessment.objects.filter(pk=visible.id).exists()
    assert not ComplianceAssessment.objects.filter(pk=visible_audit.id).exists()
    assert EntityAssessment.objects.filter(pk=hidden.id).exists()
    assert ComplianceAssessment.objects.filter(pk=hidden_audit.id).exists()
    assert Folder.objects.filter(pk=hidden_enclave_id).exists()


def test_legacy_shared_audit_deletes_only_requested_entity_assessment(
    owned_audit_world,
):
    assessment, audit = _round(owned_audit_world, label="legacy-source")
    other = EntityAssessment.objects.create(
        name=f"Legacy sibling {owned_audit_world['suffix']}",
        version="legacy-sibling",
        folder=owned_audit_world["domain"],
        perimeter=owned_audit_world["perimeter"],
        entity=owned_audit_world["entity"],
        compliance_assessment=audit,
    )
    audit_id = audit.id
    enclave_id = audit.folder_id
    client, role = _scoped_client(owned_audit_world)

    assert not role.permissions.filter(
        codename__in=("delete_complianceassessment", "delete_folder")
    ).exists()
    response = client.delete(f"/api/entity-assessments/{assessment.id}/")

    assert response.status_code == 204, response.content
    assert not EntityAssessment.objects.filter(pk=assessment.id).exists()
    other.refresh_from_db()
    assert other.compliance_assessment_id == audit_id
    assert ComplianceAssessment.objects.filter(pk=audit_id).exists()
    assert Folder.objects.filter(pk=enclave_id).exists()


def test_accepted_flow_and_delete_audit_entries_survive_aggregate_delete(
    owned_audit_world,
):
    assessment, audit = _round(owned_audit_world, label="accepted")
    assessment_id = assessment.id
    audit_id = audit.id
    assessment_folder_id = assessment.folder_id
    audit_folder_id = audit.folder_id
    flow = ValidationFlow.objects.create(
        folder=owned_audit_world["domain"],
        status=ValidationFlow.Status.ACCEPTED,
    )
    flow.entity_assessments.add(assessment)
    flow.compliance_assessments.add(audit)
    event = FlowEvent.objects.create(
        folder=owned_audit_world["domain"],
        validation_flow=flow,
        event_type="accepted",
        event_actor=None,
    )
    client, _ = _scoped_client(owned_audit_world)

    response = client.delete(f"/api/entity-assessments/{assessment.id}/")

    assert response.status_code == 204, response.content
    flow.refresh_from_db()
    assert flow.status == ValidationFlow.Status.ACCEPTED
    assert not flow.entity_assessments.exists()
    assert not flow.compliance_assessments.exists()
    assert FlowEvent.objects.filter(pk=event.id, validation_flow=flow).exists()

    assessment_delete = LogEntry.objects.get(
        content_type=ContentType.objects.get_for_model(EntityAssessment),
        object_pk=str(assessment_id),
        action=LogEntry.Action.DELETE,
    )
    audit_delete = LogEntry.objects.get(
        content_type=ContentType.objects.get_for_model(ComplianceAssessment),
        object_pk=str(audit_id),
        action=LogEntry.Action.DELETE,
    )
    assert assessment_delete.additional_data["folder_id"] == str(assessment_folder_id)
    assert audit_delete.additional_data["folder_id"] == str(audit_folder_id)
