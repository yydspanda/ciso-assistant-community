from __future__ import annotations

import uuid

import pytest
from django.contrib.auth.models import Permission
from iam.models import Folder, Role, RoleAssignment, User
from rest_framework.exceptions import PermissionDenied
from rest_framework.test import APIClient

from core.models import ComplianceAssessment, Framework, RequirementNode
from core.serializers import (
    ComplianceAssessmentWriteSerializer,
    RequirementNodeWriteSerializer,
)


pytestmark = pytest.mark.django_db


@pytest.fixture
def framework_parent_world():
    root = Folder.get_root_folder()
    folder = Folder.objects.create(
        name=f"Framework parent immutability {uuid.uuid4().hex}",
        parent_folder=root,
    )
    frameworks = [
        Framework.objects.create(
            name=f"Framework {index}",
            urn=f"urn:test:framework-parent-immutability:{uuid.uuid4().hex}",
            ref_id=f"FW-{index}",
            folder=folder,
        )
        for index in range(2)
    ]
    user = User.objects.create_user(
        email=f"framework-parent-{uuid.uuid4().hex}@example.com",
        password="test-password",
    )
    role = Role.objects.create(
        name=f"Framework parent writer {uuid.uuid4().hex}",
        folder=root,
    )
    role.permissions.set(
        Permission.objects.filter(
            codename__in={
                "view_complianceassessment",
                "change_complianceassessment",
                "view_requirementnode",
                "change_requirementnode",
                "view_framework",
                "view_compliance_assessment_full",
            }
        )
    )
    assignment = RoleAssignment.objects.create(
        user=user,
        role=role,
        folder=root,
        is_recursive=True,
    )
    assignment.perimeter_folders.add(folder)
    return {
        "folder": folder,
        "frameworks": frameworks,
        "user": user,
    }


@pytest.mark.parametrize(
    ("serializer_class", "create_data", "model"),
    (
        (
            ComplianceAssessmentWriteSerializer,
            {"name": "Created assessment"},
            ComplianceAssessment,
        ),
        (
            RequirementNodeWriteSerializer,
            {
                "name": "Created requirement",
                "urn": "urn:test:framework-parent-immutability:created-requirement",
                "ref_id": "REQ-CREATED",
                "assessable": True,
                "order_id": 1,
                "implementation_groups": ["IG1"],
            },
            RequirementNode,
        ),
    ),
)
def test_framework_parent_create_and_same_value_update_remain_supported(
    framework_parent_world,
    serializer_class,
    create_data,
    model,
):
    world = framework_parent_world
    framework = world["frameworks"][0]
    payload = {
        **create_data,
        "folder": str(world["folder"].id),
        "framework": str(framework.id),
    }
    serializer = serializer_class(data=payload)
    serializer.is_valid(raise_exception=True)
    instance = serializer.save()

    assert isinstance(instance, model)
    assert instance.framework_id == framework.id

    update = serializer_class(
        instance,
        data={"framework": str(framework.id), "name": "Updated name"},
        partial=True,
    )
    update.is_valid(raise_exception=True)
    assert update.validated_data["framework"].id == framework.id
    updated = update.save()
    updated.refresh_from_db()
    assert updated.framework_id == framework.id
    assert updated.name == "Updated name"


@pytest.mark.parametrize(
    ("endpoint", "model", "object_data"),
    (
        (
            "compliance-assessments",
            ComplianceAssessment,
            {"name": "Existing assessment"},
        ),
        (
            "requirement-nodes",
            RequirementNode,
            {
                "name": "Existing requirement",
                "urn": "urn:test:framework-parent-immutability:existing-requirement",
                "ref_id": "REQ-EXISTING",
                "assessable": True,
                "order_id": 1,
                "implementation_groups": ["IG1"],
            },
        ),
    ),
)
def test_framework_parent_update_rejects_existing_and_missing_targets_identically(
    framework_parent_world,
    endpoint,
    model,
    object_data,
):
    world = framework_parent_world
    current_framework, other_framework = world["frameworks"]
    instance = model.objects.create(
        **object_data,
        folder=world["folder"],
        framework=current_framework,
    )
    client = APIClient()
    client.force_authenticate(world["user"])

    existing = client.patch(
        f"/api/{endpoint}/{instance.id}/",
        {"framework": str(other_framework.id)},
        format="json",
    )
    missing = client.patch(
        f"/api/{endpoint}/{instance.id}/",
        {"framework": str(uuid.uuid4())},
        format="json",
    )

    assert existing.status_code == missing.status_code == 403
    assert existing.json() == missing.json() == {"framework": "This field is immutable"}
    instance.refresh_from_db()
    assert instance.framework_id == current_framework.id


@pytest.mark.parametrize(
    ("serializer_class", "model", "object_data"),
    (
        (
            ComplianceAssessmentWriteSerializer,
            ComplianceAssessment,
            {"name": "Assessment serializer rejection"},
        ),
        (
            RequirementNodeWriteSerializer,
            RequirementNode,
            {
                "name": "Requirement serializer rejection",
                "urn": "urn:test:framework-parent-immutability:serializer-rejection",
                "ref_id": "REQ-REJECT",
                "assessable": True,
                "order_id": 1,
                "implementation_groups": ["IG1"],
            },
        ),
    ),
)
def test_framework_parent_serializer_rejects_cross_framework_after_uuid_parsing(
    framework_parent_world,
    serializer_class,
    model,
    object_data,
):
    world = framework_parent_world
    current_framework, other_framework = world["frameworks"]
    instance = model.objects.create(
        **object_data,
        folder=world["folder"],
        framework=current_framework,
    )
    serializer = serializer_class(
        instance,
        data={"framework": other_framework.id},
        partial=True,
    )

    with pytest.raises(PermissionDenied):
        serializer.is_valid(raise_exception=True)
    instance.refresh_from_db()
    assert instance.framework_id == current_framework.id
