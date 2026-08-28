"""Adversarial IAM tests for compliance assessment read projections."""

from __future__ import annotations

import uuid

import pytest

from core.models import (
    Answer,
    ComplianceAssessment,
    Question,
    QuestionChoice,
    RequirementAssessment,
)
from core.tests.test_compliance_assessment_tree_iam import (
    _all_nodes,
    _client,
    _grant_questionnaire_read,
    _list_results,
    audit_iam_world as _audit_iam_world_fixture,
)
from core.utils import get_authorized_compliance_progress_projections
from iam.models import Folder, RoleAssignment


pytestmark = pytest.mark.django_db
audit_iam_world = _audit_iam_world_fixture


def _target_list_item(world: dict) -> dict:
    response = _client(world["respondent"]).get(
        "/api/compliance-assessments/",
        {"folder": str(world["child_folder"].id)},
    )
    assert response.status_code == 200, response.content
    return next(
        item
        for item in _list_results(response)
        if item["id"] == str(world["target"].id)
    )


def test_list_and_detail_progress_use_respondent_axis_and_questionnaire_iam(
    audit_iam_world,
):
    world = audit_iam_world
    target = world["target"]
    _grant_questionnaire_read(world["respondent"], world["child_folder"])

    question = Question.objects.create(
        requirement_node=world["assigned_requirement"],
        urn=f"urn:test:list-progress:{uuid.uuid4().hex}:question",
        ref_id="LIST-Q",
        text="Visible choice question",
        type=Question.Type.UNIQUE_CHOICE,
        folder=world["child_folder"],
    )
    hidden_choice = QuestionChoice.objects.create(
        question=question,
        urn=f"urn:test:list-progress:{uuid.uuid4().hex}:hidden-choice",
        ref_id="LIST-QC-HIDDEN",
        value="hidden",
        folder=world["hidden_folder"],
    )
    answer = Answer.objects.create(
        requirement_assessment=world["assigned_ra"],
        question=question,
        folder=world["child_folder"],
    )
    answer.selected_choices.add(hidden_choice)

    # Status is DONE, but hidden on the respondent axis. Result/score are also
    # hidden and the only selected choice is outside QuestionChoice IAM, so a
    # caller-aware projection has no completed carrier.
    target.field_visibility = {
        **target.field_visibility,
        "status": {"auditor": "edit", "respondent": "hidden"},
        "result": {"auditor": "edit", "respondent": "hidden"},
        "score": {"auditor": "edit", "respondent": "hidden"},
        "answers": {"auditor": "edit", "respondent": "edit"},
    }
    target.computed_outcome = {"private": {"result": "compliant"}}
    target.save(update_fields=["field_visibility", "computed_outcome"])

    item = _target_list_item(world)
    assert item["progress"] is None
    assert "status" not in item
    assert "computed_outcome" not in item

    detail = _client(world["respondent"]).get(
        f"/api/compliance-assessments/{target.id}/"
    )
    assert detail.status_code == 200, detail.content
    assert detail.json()["progress"] is None
    assert detail.json()["answers_progress"] is None

    # A visible result may drive progress, but hiding answers must suppress the
    # dedicated answer percentage rather than disclosing completion indirectly.
    target.field_visibility = {
        **target.field_visibility,
        "result": {"auditor": "edit", "respondent": "read"},
        "answers": {"auditor": "edit", "respondent": "hidden"},
    }
    target.save(update_fields=["field_visibility"])
    assert _target_list_item(world)["progress"] == 100
    detail = _client(world["respondent"]).get(
        f"/api/compliance-assessments/{target.id}/"
    )
    assert detail.status_code == 200, detail.content
    assert detail.json()["progress"] == 100
    assert detail.json()["answers_progress"] is None


@pytest.mark.parametrize("action", ["tree", "combined_tree"])
def test_tree_surfaces_omit_requirement_nodes_outside_generic_iam(
    audit_iam_world, action
):
    world = audit_iam_world
    hidden_requirement = world["assigned_requirement"]
    hidden_requirement.folder = world["hidden_folder"]
    hidden_requirement.save(update_fields=["folder"])

    response = _client(world["respondent"]).get(
        f"/api/compliance-assessments/{world['target'].id}/{action}/"
    )
    assert response.status_code == 200, response.content
    tree = response.json()["tree"] if action == "combined_tree" else response.json()
    assert "R-ASSIGNED" not in {node.get("ref_id") for node in _all_nodes(tree)}


def test_direct_ra_masks_hidden_framework_and_perimeter(
    audit_iam_world,
):
    world = audit_iam_world
    target = world["target"]
    target.framework.folder = world["hidden_folder"]
    target.framework.save(update_fields=["folder"])

    response = _client(world["respondent"]).get(
        f"/api/requirement-assessments/{world['assigned_ra'].id}/"
    )
    assert response.status_code == 200, response.content
    data = response.json()
    assert data["requirement"]["id"] == str(world["assigned_requirement"].id)
    assert data["perimeter"] is None
    assert data["compliance_assessment"]["framework"] is None


def _assert_folder_is_hidden_from_respondent(world: dict) -> None:
    assert world["child_folder"].id not in set(
        RoleAssignment.get_viewable_object_ids(world["respondent"], Folder)
    )


def test_direct_ra_masks_folder_without_independent_folder_iam(audit_iam_world):
    world = audit_iam_world
    _assert_folder_is_hidden_from_respondent(world)

    response = _client(world["respondent"]).get(
        f"/api/requirement-assessments/{world['assigned_ra'].id}/"
    )

    assert response.status_code == 200, response.content
    assert response.json()["folder"] is None


def test_compliance_requirements_list_masks_folder_without_independent_folder_iam(
    audit_iam_world,
):
    world = audit_iam_world
    _assert_folder_is_hidden_from_respondent(world)

    response = _client(world["respondent"]).get(
        f"/api/compliance-assessments/{world['target'].id}/requirements_list/"
    )

    assert response.status_code == 200, response.content
    row = next(
        item
        for item in response.json()["requirement_assessments"]
        if item["id"] == str(world["assigned_ra"].id)
    )
    assert row["folder"] is None


def test_assignment_requirements_list_masks_folder_without_independent_folder_iam(
    audit_iam_world,
):
    world = audit_iam_world
    _assert_folder_is_hidden_from_respondent(world)

    response = _client(world["respondent"]).get(
        f"/api/requirement-assignments/{world['assignment'].id}/requirements_list/"
    )

    assert response.status_code == 200, response.content
    row = next(
        item
        for item in response.json()["requirement_assessments"]
        if item["id"] == str(world["assigned_ra"].id)
    )
    assert row["folder"] is None


def test_direct_ra_denies_row_when_requirement_node_is_hidden(audit_iam_world):
    world = audit_iam_world
    world["assigned_requirement"].folder = world["hidden_folder"]
    world["assigned_requirement"].save(update_fields=["folder"])

    response = _client(world["respondent"]).get(
        f"/api/requirement-assessments/{world['assigned_ra'].id}/"
    )
    assert response.status_code == 404


def test_inspect_requirement_masks_nested_hidden_framework_and_perimeter(
    audit_iam_world,
):
    world = audit_iam_world
    target = world["target"]
    target.framework.folder = world["hidden_folder"]
    target.framework.save(update_fields=["folder"])

    response = _client(world["respondent"]).get(
        f"/api/requirement-nodes/{world['assigned_requirement'].id}/inspect_requirement/"
    )
    assert response.status_code == 200, response.content
    row = next(
        item
        for item in response.json()["requirement_assessments"]
        if item["id"] == str(world["assigned_ra"].id)
    )
    assert row["perimeter"] is None
    assert row["compliance_assessment"]["framework"] is None


def test_auditee_dashboard_never_uses_hidden_answers_or_result(
    audit_iam_world,
):
    world = audit_iam_world
    target = world["target"]
    _grant_questionnaire_read(world["respondent"], world["child_folder"])
    question = Question.objects.create(
        requirement_node=world["assigned_requirement"],
        urn=f"urn:test:dashboard-progress:{uuid.uuid4().hex}",
        ref_id="DASH-Q",
        text="Answered dashboard question",
        type=Question.Type.TEXT,
        folder=world["child_folder"],
    )
    Answer.objects.create(
        requirement_assessment=world["assigned_ra"],
        question=question,
        value="private answer",
        folder=world["child_folder"],
    )
    target.field_visibility = {
        **target.field_visibility,
        "status": {"auditor": "edit", "respondent": "hidden"},
        "answers": {"auditor": "edit", "respondent": "hidden"},
        "result": {"auditor": "edit", "respondent": "hidden"},
        "respondent_alignment": {
            "auditor": "hidden",
            "respondent": "hidden",
        },
    }
    target.save(update_fields=["field_visibility"])

    dashboard = _client(world["respondent"]).get(
        "/api/compliance-assessments/auditee-dashboard/"
    )
    assert dashboard.status_code == 200, dashboard.content
    card = next(item for item in dashboard.json() if item["id"] == str(target.id))
    assert card["status"] is None
    assert card["assessed_requirements"] is None
    assert card["progress_percent"] is None

    target.field_visibility = {
        **target.field_visibility,
        "result": {"auditor": "edit", "respondent": "read"},
    }
    target.save(update_fields=["field_visibility"])
    dashboard = _client(world["respondent"]).get(
        "/api/compliance-assessments/auditee-dashboard/"
    )
    card = next(item for item in dashboard.json() if item["id"] == str(target.id))
    assert card["assessed_requirements"] == 1
    assert card["progress_percent"] == 100


def test_progress_helper_requires_generic_assessment_visibility(audit_iam_world):
    world = audit_iam_world
    target = world["target"]
    target.folder = world["hidden_folder"]
    target.save(update_fields=["folder"])

    projection = get_authorized_compliance_progress_projections(
        world["respondent"], [target]
    )

    assert projection == {target.id: None}
