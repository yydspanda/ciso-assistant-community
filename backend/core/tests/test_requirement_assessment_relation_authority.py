"""Focused IAM contracts for upstream Finding and TaskTemplate RA links."""

from __future__ import annotations

import uuid

import pytest
from rest_framework.exceptions import PermissionDenied
from rest_framework.test import APIClient

from core.models import Finding, RequirementAssessment, TaskTemplate
from core.serializers import (
    FindingReadSerializer,
    FindingWriteSerializer,
    RequirementAssessmentReadSerializer,
    RequirementAssessmentWriteSerializer,
    TaskTemplateReadSerializer,
    TaskTemplateWriteSerializer,
)
from core.tests import test_inverse_requirement_assessment_relationships as inverse_ra
from iam.models import Folder

pytestmark = pytest.mark.django_db
# Re-export the established focused-world fixture into this module.  Keeping the
# world builder in one place makes these tests exercise the exact same direct
# Actor/assignment boundary as the original inverse-relationship suite.
relationship_world = inverse_ra.relationship_world


def _enable_relation_policy(world, field_name: str, access: str = "edit") -> None:
    assessment = world["assessment"]
    assessment.field_visibility = {
        **assessment.field_visibility,
        field_name: {"auditor": "edit", "respondent": access},
    }
    assessment.save(update_fields=["field_visibility"])


def _grant_relation_targets(world) -> None:
    inverse_ra._grant_permissions(
        world["respondent"],
        world["folder"],
        "add_finding",
        "change_finding",
        "add_tasktemplate",
        "change_tasktemplate",
    )


def test_task_template_delta_preserves_hidden_ra_and_projects_only_visible_ids(
    relationship_world,
    monkeypatch,
):
    world = relationship_world
    _enable_relation_policy(world, "task_templates")
    _grant_relation_targets(world)
    task = TaskTemplate.objects.create(
        name=f"governed-task-{uuid.uuid4().hex}",
        folder=world["folder"],
        is_recurrent=True,
    )
    task.requirement_assessments.add(world["assigned_a"], world["unassigned"])

    serializer = TaskTemplateWriteSerializer(
        task,
        data={"requirement_assessments": [str(world["assigned_b"].id)]},
        partial=True,
        context={"request": inverse_ra._request_for(world["respondent"])},
    )
    serializer.is_valid(raise_exception=True)
    saved = serializer.save()

    assert set(saved.requirement_assessments.values_list("id", flat=True)) == {
        world["assigned_b"].id,
        world["unassigned"].id,
    }

    original_string = RequirementAssessment.__str__

    def guarded_string(row):
        if row.id == world["unassigned"].id:
            raise AssertionError("hidden RequirementAssessment was stringified")
        return original_string(row)

    monkeypatch.setattr(RequirementAssessment, "__str__", guarded_string)
    payload = TaskTemplateReadSerializer(
        saved,
        context={"request": inverse_ra._request_for(world["respondent"])},
    ).data
    assert inverse_ra._represented_ids(payload["requirement_assessments"]) == {
        str(world["assigned_b"].id)
    }


def test_task_template_batch_read_projects_forward_ra_relationships(
    relationship_world,
    monkeypatch,
):
    world = relationship_world
    _enable_relation_policy(world, "task_templates")
    first = TaskTemplate.objects.create(
        name=f"batch-task-a-{uuid.uuid4().hex}",
        folder=world["folder"],
        is_recurrent=True,
    )
    second = TaskTemplate.objects.create(
        name=f"batch-task-b-{uuid.uuid4().hex}",
        folder=world["folder"],
        is_recurrent=True,
    )
    first.requirement_assessments.add(world["assigned_a"], world["unassigned"])
    second.requirement_assessments.add(world["assigned_b"], world["unassigned"])

    original_string = RequirementAssessment.__str__

    def guarded_string(row):
        if row.id == world["unassigned"].id:
            raise AssertionError("hidden RequirementAssessment was stringified")
        return original_string(row)

    monkeypatch.setattr(RequirementAssessment, "__str__", guarded_string)
    payload = TaskTemplateReadSerializer(
        [first, second],
        many=True,
        context={"request": inverse_ra._request_for(world["respondent"])},
    ).data

    represented_ids = {
        row["id"]: inverse_ra._represented_ids(row["requirement_assessments"])
        for row in payload
    }
    assert represented_ids == {
        str(first.id): {str(world["assigned_a"].id)},
        str(second.id): {str(world["assigned_b"].id)},
    }
    assert str(world["unassigned"].id) not in str(payload)


def test_task_template_rejects_unassigned_requirement_assessment(
    relationship_world,
):
    world = relationship_world
    _enable_relation_policy(world, "task_templates")
    _grant_relation_targets(world)
    task = TaskTemplate.objects.create(
        name=f"forged-task-{uuid.uuid4().hex}",
        folder=world["folder"],
        is_recurrent=True,
    )
    serializer = TaskTemplateWriteSerializer(
        task,
        data={"requirement_assessments": [str(world["unassigned"].id)]},
        partial=True,
        context={"request": inverse_ra._request_for(world["respondent"])},
    )

    with pytest.raises(PermissionDenied):
        serializer.is_valid(raise_exception=True)
    assert not task.requirement_assessments.exists()


def test_requirement_assessment_task_delta_preserves_hidden_task_and_read_masks_id(
    relationship_world,
):
    world = relationship_world
    _enable_relation_policy(world, "task_templates")
    _grant_relation_targets(world)
    hidden_folder = Folder.objects.create(
        name=f"hidden-task-domain-{uuid.uuid4().hex[:8]}",
        content_type=Folder.ContentType.DOMAIN,
        parent_folder=Folder.get_root_folder(),
    )
    visible_task = TaskTemplate.objects.create(
        name=f"visible-task-{uuid.uuid4().hex}",
        folder=world["folder"],
        is_recurrent=True,
    )
    hidden_task = TaskTemplate.objects.create(
        name=f"hidden-task-{uuid.uuid4().hex}",
        folder=hidden_folder,
        is_recurrent=True,
    )
    row = world["assigned_a"]
    row.task_templates.add(visible_task, hidden_task)

    serializer = RequirementAssessmentWriteSerializer(
        row,
        data={"task_templates": []},
        partial=True,
        context={"request": inverse_ra._request_for(world["respondent"])},
    )
    serializer.is_valid(raise_exception=True)
    serializer.save()

    assert set(row.task_templates.values_list("id", flat=True)) == {hidden_task.id}
    payload = RequirementAssessmentReadSerializer(
        row,
        context={"request": inverse_ra._request_for(world["respondent"])},
    ).data
    assert payload["task_templates"] == []


def test_finding_binding_reuses_ra_authority_and_derives_requirement_node(
    relationship_world,
):
    world = relationship_world
    _enable_relation_policy(world, "findings")
    _grant_relation_targets(world)
    serializer = FindingWriteSerializer(
        data={
            "name": f"governed-finding-{uuid.uuid4().hex}",
            "folder": str(world["folder"].id),
            "requirement_assessment": str(world["assigned_a"].id),
            # This redundant client value must neither win nor be needed.
            "requirement_node": str(world["unassigned"].requirement_id),
        },
        context={"request": inverse_ra._request_for(world["respondent"])},
    )
    serializer.is_valid(raise_exception=True)
    finding = serializer.save()

    assert finding.requirement_assessment_id == world["assigned_a"].id
    assert finding.requirement_node_id == world["assigned_a"].requirement_id


@pytest.mark.parametrize("denial", ("unassigned", "read_only", "terminal"))
def test_finding_binding_rejects_ra_outside_assignment_or_field_policy(
    relationship_world,
    denial,
):
    world = relationship_world
    _enable_relation_policy(
        world,
        "findings",
        access="read" if denial == "read_only" else "edit",
    )
    _grant_relation_targets(world)
    row = world["unassigned"] if denial == "unassigned" else world["assigned_a"]
    if denial == "terminal":
        world["assignment"].status = "submitted"
        world["assignment"].save(update_fields=["status"])

    serializer = FindingWriteSerializer(
        data={
            "name": f"denied-finding-{uuid.uuid4().hex}",
            "folder": str(world["folder"].id),
            "requirement_assessment": str(row.id),
        },
        context={"request": inverse_ra._request_for(world["respondent"])},
    )

    with pytest.raises(PermissionDenied):
        serializer.is_valid(raise_exception=True)
    assert not Finding.objects.filter(name=serializer.initial_data["name"]).exists()


def test_finding_unbind_checks_authority_on_existing_requirement_assessment(
    relationship_world,
):
    world = relationship_world
    _enable_relation_policy(world, "findings", access="read")
    _grant_relation_targets(world)
    finding = Finding.objects.create(
        name=f"bound-finding-{uuid.uuid4().hex}",
        folder=world["folder"],
        requirement_assessment=world["assigned_a"],
        requirement_node=world["assigned_a"].requirement,
    )
    serializer = FindingWriteSerializer(
        finding,
        data={"requirement_assessment": None},
        partial=True,
        context={"request": inverse_ra._request_for(world["respondent"])},
    )

    with pytest.raises(PermissionDenied):
        serializer.is_valid(raise_exception=True)
    finding.refresh_from_db()
    assert finding.requirement_assessment_id == world["assigned_a"].id


def test_finding_read_projects_singular_ra_without_stringifying_hidden_row(
    relationship_world,
    monkeypatch,
):
    world = relationship_world
    _enable_relation_policy(world, "findings")
    visible_finding = Finding.objects.create(
        name=f"visible-bound-finding-{uuid.uuid4().hex}",
        folder=world["folder"],
        requirement_assessment=world["assigned_a"],
        requirement_node=world["assigned_a"].requirement,
    )
    hidden_finding = Finding.objects.create(
        name=f"hidden-bound-finding-{uuid.uuid4().hex}",
        folder=world["folder"],
        requirement_assessment=world["unassigned"],
        requirement_node=world["unassigned"].requirement,
    )

    original_string = RequirementAssessment.__str__

    def guarded_string(row):
        if row.id == world["unassigned"].id:
            raise AssertionError("hidden RequirementAssessment was stringified")
        return original_string(row)

    monkeypatch.setattr(RequirementAssessment, "__str__", guarded_string)
    payload = FindingReadSerializer(
        [visible_finding, hidden_finding],
        many=True,
        context={"request": inverse_ra._request_for(world["respondent"])},
    ).data

    assert str(payload[0]["requirement_assessment"]["id"]) == str(
        world["assigned_a"].id
    )
    assert payload[1]["requirement_assessment"] is None
    assert str(world["unassigned"].id) not in str(payload[1])


def test_finding_write_response_does_not_echo_hidden_singular_ra(
    relationship_world,
):
    world = relationship_world
    _enable_relation_policy(world, "findings")
    _grant_relation_targets(world)
    finding = Finding.objects.create(
        name=f"hidden-write-response-{uuid.uuid4().hex}",
        folder=world["folder"],
        requirement_assessment=world["unassigned"],
        requirement_node=world["unassigned"].requirement,
    )
    serializer = FindingWriteSerializer(
        finding,
        data={"name": f"ordinary-edit-{uuid.uuid4().hex}"},
        partial=True,
        context={"request": inverse_ra._request_for(world["respondent"])},
    )

    serializer.is_valid(raise_exception=True)
    serializer.save()

    assert serializer.data["requirement_assessment"] is None
    assert str(world["unassigned"].id) not in str(serializer.data)


@pytest.mark.parametrize(
    ("endpoint", "model"),
    (
        ("findings", Finding),
        ("task-templates", TaskTemplate),
    ),
)
def test_relation_filter_rejects_hidden_ra_operand(
    relationship_world,
    endpoint,
    model,
):
    world = relationship_world
    policy_field = "findings" if model is Finding else "task_templates"
    _enable_relation_policy(world, policy_field)
    target = model.objects.create(
        name=f"hidden-filter-target-{uuid.uuid4().hex}",
        folder=world["folder"],
    )
    if model is Finding:
        target.requirement_assessment = world["unassigned"]
        target.requirement_node = world["unassigned"].requirement
        target.save(update_fields=["requirement_assessment", "requirement_node"])
        parameter = "requirement_assessment"
    else:
        target.requirement_assessments.add(world["unassigned"])
        parameter = "requirement_assessments"

    client = APIClient()
    client.force_authenticate(world["respondent"])
    response = client.get(
        f"/api/{endpoint}/",
        {parameter: str(world["unassigned"].id)},
    )

    assert response.status_code == 403, response.content


def test_finding_nullable_filter_sentinel_survives_authority_gate(
    relationship_world,
):
    world = relationship_world
    _enable_relation_policy(world, "findings")
    finding = Finding.objects.create(
        name=f"unbound-filter-target-{uuid.uuid4().hex}",
        folder=world["folder"],
    )
    client = APIClient()
    client.force_authenticate(world["respondent"])

    response = client.get("/api/findings/", {"requirement_assessment": "--"})

    assert response.status_code == 200, response.content
    assert str(finding.id) in {row["id"] for row in response.json()["results"]}
