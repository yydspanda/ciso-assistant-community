"""Adversarial IAM tests for compliance dashboard aggregates.

These helpers do not serialize model instances, so every consumed scalar and
relationship must cross its own authorization boundary.  In particular, a
generic-visible subset of RequirementAssessment rows is not a valid basis for
an audit-wide count or progress percentage.
"""

from __future__ import annotations

import uuid

import pytest
from django.contrib.auth.models import Permission
from rest_framework.exceptions import PermissionDenied

from core.helpers import (
    assessment_per_status,
    build_audits_stats,
    combined_assessments_per_status,
    get_audits_metrics,
    get_compliance_analytics,
    get_metrics,
)
from core.models import (
    ComplianceAssessment,
    Framework,
    Perimeter,
    RequirementAssessment,
    RequirementNode,
)
from iam.models import Folder, Role, RoleAssignment, User


pytestmark = pytest.mark.django_db


def _domain(name: str, *, parent: Folder) -> Folder:
    return Folder.objects.create(
        name=name,
        content_type=Folder.ContentType.DOMAIN,
        parent_folder=parent,
    )


def _permission(codename: str, model) -> Permission:
    return Permission.objects.get(
        codename=codename,
        content_type__app_label=model._meta.app_label,
        content_type__model=model._meta.model_name,
    )


def _grant_full_aggregate_reader(user: User, folder: Folder) -> Role:
    role = Role.objects.create(
        name=f"Compliance aggregate reader {uuid.uuid4().hex}",
        folder=Folder.get_root_folder(),
    )
    role.permissions.set(
        [
            _permission("view_complianceassessment", ComplianceAssessment),
            _permission("view_compliance_assessment_full", ComplianceAssessment),
            _permission("view_requirementassessment", RequirementAssessment),
            _permission("view_requirementnode", RequirementNode),
            _permission("view_framework", Framework),
            _permission("view_folder", Folder),
            _permission("view_perimeter", Perimeter),
        ]
    )
    assignment = RoleAssignment.objects.create(
        user=user,
        role=role,
        folder=Folder.get_root_folder(),
        is_recursive=True,
    )
    assignment.perimeter_folders.add(folder)
    return role


def _auditor_visibility(*fields: str) -> dict:
    return {field: {"auditor": "read", "respondent": "hidden"} for field in fields}


@pytest.fixture
def aggregate_iam_world():
    Folder._init_root_folder()
    root = Folder.get_root_folder()
    visible = _domain(f"aggregate-visible-{uuid.uuid4().hex[:8]}", parent=root)
    hidden = _domain(f"aggregate-hidden-{uuid.uuid4().hex[:8]}", parent=root)

    framework = Framework.objects.create(
        name="Visible aggregate framework",
        urn=f"urn:test:framework:aggregate:{uuid.uuid4().hex}",
        ref_id="AGGREGATE-IAM",
        folder=visible,
        min_score=0,
        max_score=4,
    )
    requirement = RequirementNode.objects.create(
        name="Visible aggregate requirement",
        urn=f"{framework.urn}:requirement",
        ref_id="AGGREGATE-R1",
        framework=framework,
        folder=visible,
        assessable=True,
    )
    perimeter = Perimeter.objects.create(
        name="Visible aggregate perimeter", folder=visible
    )
    visibility = _auditor_visibility(
        "folder",
        "framework",
        "name",
        "perimeter",
        "result",
        "score",
        "selected_implementation_groups",
        "status",
        "updated_at",
    )
    assessment = ComplianceAssessment.objects.create(
        name="Visible aggregate audit",
        ref_id="AGGREGATE-A1",
        framework=framework,
        folder=visible,
        perimeter=perimeter,
        min_score=0,
        max_score=4,
        status=ComplianceAssessment.Status.IN_PROGRESS,
        field_visibility=visibility,
    )
    requirement_assessment = RequirementAssessment(
        compliance_assessment=assessment,
        requirement=requirement,
        folder=visible,
        status=RequirementAssessment.Status.DONE,
        result=RequirementAssessment.Result.NON_COMPLIANT,
        score=2,
        is_scored=True,
    )
    # Avoid unrelated metrics/outcome hooks; this fixture owns only aggregate
    # read behavior and the row is fully initialized before insertion.
    RequirementAssessment.objects.bulk_create([requirement_assessment])

    user = User.objects.create_user(f"aggregate-reader-{uuid.uuid4().hex}@example.test")
    role = _grant_full_aggregate_reader(user, visible)

    return {
        "assessment": assessment,
        "framework": framework,
        "hidden_folder": hidden,
        "perimeter": perimeter,
        "requirement": requirement,
        "requirement_assessment": requirement_assessment,
        "role": role,
        "user": user,
        "visible_folder": visible,
        "visibility": visibility,
    }


def _hide_assessment_field(world: dict, field: str) -> None:
    visibility = {name: dict(access) for name, access in world["visibility"].items()}
    visibility[field]["auditor"] = "hidden"
    ComplianceAssessment.objects.filter(pk=world["assessment"].pk).update(
        field_visibility=visibility
    )


def test_fully_authorized_reader_keeps_existing_aggregate_shapes(
    aggregate_iam_world,
):
    world = aggregate_iam_world
    user = world["user"]

    stats = build_audits_stats(user)
    result_index = list(RequirementAssessment.Result).index(
        RequirementAssessment.Result.NON_COMPLIANT
    )
    assert stats["names"] == [world["assessment"].name]
    assert stats["uuids"] == [world["assessment"].id]
    assert stats["data"][0][result_index] == 1

    audit_metrics = get_audits_metrics(user)
    assert audit_metrics["progress_avg"] == 100
    assert audit_metrics["audits_stats"] == stats

    metrics = get_metrics(user, folder_id=None)
    assert metrics["compliance"] == {
        "used_frameworks": 1,
        "audits": 1,
        "active_audits": 1,
        "evidences": 0,
        "expired_evidences": 0,
        "non_compliant_items": 1,
    }

    analytics = get_compliance_analytics(user)
    framework_data = analytics[world["framework"].name]
    assert framework_data["framework_id"] == str(world["framework"].id)
    assert framework_data["framework_average"] == 100
    assert framework_data["domains"][0]["domain"] == world["visible_folder"].name
    assert framework_data["domains"][0]["assessments"] == [
        {
            "assessment_id": str(world["assessment"].id),
            "assessment_name": world["assessment"].name,
            "progress": 100,
            "perimeter": world["perimeter"].name,
            "perimeter_id": str(world["perimeter"].id),
            "status": ComplianceAssessment.Status.IN_PROGRESS,
        }
    ]


@pytest.mark.parametrize(
    "helper",
    [
        build_audits_stats,
        get_audits_metrics,
        get_compliance_analytics,
        lambda user: get_metrics(user, folder_id=None),
    ],
    ids=("audit-stats", "audit-metrics", "analytics", "dashboard-metrics"),
)
def test_hidden_result_fails_every_result_consuming_aggregate_closed(
    aggregate_iam_world, helper
):
    _hide_assessment_field(aggregate_iam_world, "result")

    with pytest.raises(PermissionDenied, match="complete full-view access"):
        helper(aggregate_iam_world["user"])


def test_hidden_score_blocks_progress_without_overblocking_result_counts(
    aggregate_iam_world,
):
    world = aggregate_iam_world
    _hide_assessment_field(world, "score")

    # These aggregates never inspect score and remain available.
    assert build_audits_stats(world["user"])["names"] == [world["assessment"].name]
    assert (
        get_metrics(world["user"], folder_id=None)["compliance"]["non_compliant_items"]
        == 1
    )

    # Progress treats a non-null score as an assessed signal; computing it
    # would therefore disclose a hidden field indirectly.
    with pytest.raises(PermissionDenied, match="complete full-view access"):
        get_audits_metrics(world["user"])
    with pytest.raises(PermissionDenied, match="complete full-view access"):
        get_compliance_analytics(world["user"])


@pytest.mark.parametrize(
    "helper",
    [
        build_audits_stats,
        get_audits_metrics,
        get_compliance_analytics,
        lambda user: get_metrics(user, folder_id=None),
    ],
    ids=("audit-stats", "audit-metrics", "analytics", "dashboard-metrics"),
)
def test_one_generic_hidden_requirement_row_rejects_whole_assessment(
    aggregate_iam_world, helper
):
    world = aggregate_iam_world
    RequirementAssessment.objects.filter(pk=world["requirement_assessment"].pk).update(
        folder=world["hidden_folder"]
    )

    with pytest.raises(PermissionDenied, match="complete full-view access"):
        helper(world["user"])


@pytest.mark.parametrize(
    ("codename", "model"),
    [
        ("view_framework", Framework),
        ("view_folder", Folder),
        ("view_perimeter", Perimeter),
    ],
    ids=("framework", "folder", "perimeter"),
)
def test_analytics_requires_independent_related_object_visibility(
    aggregate_iam_world, codename, model
):
    world = aggregate_iam_world
    world["role"].permissions.remove(_permission(codename, model))

    with pytest.raises(PermissionDenied, match="complete full-view access"):
        get_compliance_analytics(world["user"])


def test_dashboard_framework_count_requires_framework_visibility(
    aggregate_iam_world,
):
    world = aggregate_iam_world
    world["role"].permissions.remove(_permission("view_framework", Framework))

    with pytest.raises(PermissionDenied, match="complete full-view access"):
        get_metrics(world["user"], folder_id=None)


def test_direct_object_ids_argument_cannot_bypass_assessment_scope(
    aggregate_iam_world,
):
    world = aggregate_iam_world
    hidden_assessment = ComplianceAssessment.objects.create(
        name="Hidden aggregate audit",
        ref_id="AGGREGATE-HIDDEN",
        framework=world["framework"],
        folder=world["hidden_folder"],
        perimeter=world["perimeter"],
        min_score=0,
        max_score=4,
        status=ComplianceAssessment.Status.IN_PROGRESS,
        field_visibility=world["visibility"],
    )

    assert build_audits_stats(world["user"], object_ids=[hidden_assessment.id]) == {
        "data": [],
        "names": [],
        "uuids": [],
    }


def test_status_aggregates_keep_authorized_shape_and_honor_status_visibility(
    aggregate_iam_world,
):
    world = aggregate_iam_world

    status_data = assessment_per_status(world["user"], ComplianceAssessment)
    assert sum(item["value"] for item in status_data["values"]) == 1
    combined = combined_assessments_per_status(world["user"])
    compliance_series = next(
        item for item in combined["series"] if item["name"] == "complianceAssessments"
    )
    assert sum(compliance_series["data"]) == 1

    _hide_assessment_field(world, "status")
    with pytest.raises(PermissionDenied, match="complete full-view access"):
        assessment_per_status(world["user"], ComplianceAssessment)
    with pytest.raises(PermissionDenied, match="complete full-view access"):
        combined_assessments_per_status(world["user"])
