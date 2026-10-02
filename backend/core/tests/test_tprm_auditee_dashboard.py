"""The TPRM create endpoint must wire a respondent-visible dashboard card."""

import pytest
from django.contrib.auth.models import Permission
from iam.models import Folder, Role, RoleAssignment, User, UserGroup
from rest_framework.test import APIClient
from tprm.models import Entity, EntityAssessment, Representative

from core.models import (
    Actor,
    ComplianceAssessment,
    Framework,
    RequirementAssignment,
    RequirementNode,
)
from core.startup import startup
from core.utils import RoleCodename, UserGroupCodename

pytestmark = pytest.mark.django_db


@pytest.fixture
def tprm_dashboard_world():
    startup(sender=None, **{})
    root = Folder.get_root_folder()
    domain = Folder.objects.create(
        name="TPRM dashboard domain",
        content_type=Folder.ContentType.DOMAIN,
        parent_folder=root,
    )
    entity = Entity.objects.create(name="Dashboard vendor", folder=domain)
    respondent = User.objects.create_user(
        "dashboard-vendor@tests.invalid", is_third_party=True
    )
    Representative.objects.create(
        entity=entity,
        email=respondent.email,
        user=respondent,
    )
    framework = Framework.objects.create(
        name="TPRM dashboard framework",
        folder=root,
        min_score=0,
        max_score=4,
    )
    RequirementNode.objects.create(
        name="TPRM dashboard requirement",
        urn="urn:test:tprm-dashboard:requirement",
        ref_id="TPRM-DASH-1",
        framework=framework,
        folder=root,
        assessable=True,
    )
    admin = User.objects.create_superuser("tprm-dashboard-admin@tests.invalid")
    return {
        "admin": admin,
        "domain": domain,
        "entity": entity,
        "framework": framework,
        "respondent": respondent,
    }


def _create_tprm_audit(world):
    admin_client = APIClient()
    admin_client.force_authenticate(world["admin"])
    created = admin_client.post(
        "/api/entity-assessments/",
        {
            "name": "Vendor questionnaire",
            "entity": str(world["entity"].id),
            "folder": str(world["domain"].id),
            "representatives": [str(world["respondent"].id)],
            "create_audit": True,
            "framework": str(world["framework"].id),
        },
        format="json",
    )
    assert created.status_code == 201, created.content
    entity_assessment = EntityAssessment.objects.get(name="Vendor questionnaire")
    audit = ComplianceAssessment.objects.get(
        id=entity_assessment.compliance_assessment_id
    )
    assignment = RequirementAssignment.objects.get(compliance_assessment=audit)
    return audit, assignment


def _grant_template_visibility(world):
    role = Role.objects.create(
        name="Synthetic TPRM template reader",
        folder=Folder.get_root_folder(),
    )
    permissions = Permission.objects.filter(
        content_type__app_label="core",
        codename__in=(
            "view_framework",
            "view_requirementnode",
            "view_question",
            "view_questionchoice",
        ),
    )
    assert permissions.count() == 4
    role.permissions.set(permissions)
    grant = RoleAssignment.objects.create(
        user=world["respondent"],
        role=role,
        folder=Folder.get_root_folder(),
    )
    grant.perimeter_folders.add(Folder.get_root_folder())


def test_entity_assessment_endpoint_wires_third_party_dashboard_card(
    tprm_dashboard_world,
):
    world = tprm_dashboard_world
    audit, assignment = _create_tprm_audit(world)
    enclave = audit.folder

    respondent_group = UserGroup.objects.get(
        name=UserGroupCodename.THIRD_PARTY_RESPONDENT,
        folder=enclave,
    )
    access = RoleAssignment.objects.get(
        user_group=respondent_group,
        role__name=RoleCodename.THIRD_PARTY_RESPONDENT,
        folder=enclave,
        is_recursive=True,
    )
    assert world["respondent"].user_groups.filter(id=respondent_group.id).exists()
    assert access.perimeter_folders.filter(id=enclave.id).exists()
    assert assignment.actor.filter(
        id__in=[actor.id for actor in Actor.get_all_for_user(world["respondent"])]
    ).exists()
    assert audit.id in set(
        RoleAssignment.get_viewable_object_ids(
            world["respondent"], ComplianceAssessment
        )
    )
    assert assignment.id in set(
        RoleAssignment.get_viewable_object_ids(
            world["respondent"], RequirementAssignment
        )
    )

    respondent_client = APIClient()
    respondent_client.force_authenticate(world["respondent"])
    dashboard = respondent_client.get("/api/compliance-assessments/auditee-dashboard/")

    assert dashboard.status_code == 200, dashboard.content
    cards = dashboard.json()
    assert [card["assignment_id"] for card in cards] == [str(assignment.id)]
    assert cards[0]["name"] == audit.name
    assert (
        respondent_client.get(
            f"/api/requirement-assignments/{assignment.id}/"
        ).status_code
        == 200
    )
    assert (
        respondent_client.get(f"/api/compliance-assessments/{audit.id}/").status_code
        == 200
    )
    # The endpoint creates the audit enclave grant, not an independent read
    # grant over the root-owned template catalog.  Keep that boundary explicit:
    # the dashboard card is valid, while its template payload remains forbidden.
    template_payload = respondent_client.get(
        f"/api/requirement-assignments/{assignment.id}/requirements_list/"
    )
    assert template_payload.status_code == 403


def test_tprm_requirements_need_an_explicit_template_catalog_grant(
    tprm_dashboard_world,
):
    world = tprm_dashboard_world
    _audit, assignment = _create_tprm_audit(world)
    _grant_template_visibility(world)
    respondent_client = APIClient()
    respondent_client.force_authenticate(world["respondent"])

    template_payload = respondent_client.get(
        f"/api/requirement-assignments/{assignment.id}/requirements_list/"
    )

    assert template_payload.status_code == 200, template_payload.content
    assert len(template_payload.json()["requirement_assessments"]) == 1
