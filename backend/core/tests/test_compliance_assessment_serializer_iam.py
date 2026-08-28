"""Adversarial IAM tests for the compliance-assessment detail serializer."""

from __future__ import annotations

import uuid

import pytest

from core.models import (
    Actor,
    Answer,
    Asset,
    ComplianceAssessment,
    Question,
    ReferenceControl,
    ValidationFlow,
)
from core.serializers import ComplianceAssessmentReadSerializer
from core.tests.test_compliance_assessment_tree_iam import (
    _client,
    _grant,
    _related_ids,
    audit_iam_world as _audit_iam_world_fixture,
)
from iam.models import User


pytestmark = pytest.mark.django_db
# Re-export the shared fixture into this module so pytest can resolve it without
# moving repository-wide test infrastructure into conftest.py.
audit_iam_world = _audit_iam_world_fixture


@pytest.fixture
def ca_serializer_iam_world(audit_iam_world):
    world = audit_iam_world
    respondent = world["respondent"]
    child = world["child_folder"]
    hidden = world["hidden_folder"]
    target = world["target"]

    # The shared tree fixture keeps library nodes at root because tree assembly
    # has separate coverage. This serializer test exercises generic
    # RequirementNode IAM explicitly, so place its two assessable nodes in the
    # audit domain rather than broadening the respondent to the repository root.
    for requirement in (
        world["assigned_requirement"],
        world["unassigned_requirement"],
    ):
        requirement.folder = child
        requirement.save(update_fields=["folder"])

    # The tree fixture already grants CA/RA/framework/reference-control/evidence
    # reads. These extra permissions make one object of every relationship
    # independently visible while its sibling-domain counterpart remains
    # inaccessible.
    _grant(
        respondent,
        f"CA serializer related reader {uuid.uuid4().hex}",
        {
            "view_answer",
            "view_asset",
            "view_campaign",
            "view_perimeter",
            "view_question",
            "view_questionchoice",
            "view_requirementnode",
            "view_user",
            "view_validationflow",
        },
        child,
    )

    visible_asset = Asset.objects.create(name="Visible CA asset", folder=child)
    hidden_asset = Asset.objects.create(name="Hidden CA asset", folder=hidden)
    target.assets.add(visible_asset, hidden_asset)
    target.evidences.add(world["visible_evidence"], world["hidden_evidence"])

    visible_author_user = User.objects.create_user(
        f"visible-author-{uuid.uuid4().hex}@serializer-iam.tests"
    )
    visible_author_user.folder = child
    visible_author_user.save(update_fields=["folder"])
    visible_author, _ = Actor.objects.get_or_create(user=visible_author_user)

    hidden_author_user = User.objects.create_user(
        f"hidden-author-{uuid.uuid4().hex}@serializer-iam.tests"
    )
    hidden_author_user.folder = hidden
    hidden_author_user.save(update_fields=["folder"])
    hidden_author, _ = Actor.objects.get_or_create(user=hidden_author_user)

    target.authors.add(visible_author, hidden_author)
    target.reviewers.add(visible_author, hidden_author)

    visible_flow = ValidationFlow.objects.create(
        folder=child,
        approver=hidden_author_user,
        request_notes="visible flow, hidden approver",
    )
    hidden_flow = ValidationFlow.objects.create(
        folder=hidden,
        approver=visible_author_user,
        request_notes="hidden flow",
    )
    visible_flow.compliance_assessments.add(target)
    hidden_flow.compliance_assessments.add(target)

    visible_reference = ReferenceControl.objects.create(
        name="Visible CA reference",
        ref_id="CA-REF-VISIBLE",
        urn=f"urn:test:ca-reference:{uuid.uuid4().hex}:visible",
        folder=child,
    )
    hidden_reference = ReferenceControl.objects.create(
        name="Hidden CA reference",
        ref_id="CA-REF-HIDDEN",
        urn=f"urn:test:ca-reference:{uuid.uuid4().hex}:hidden",
        folder=hidden,
    )
    world["assigned_requirement"].reference_controls.add(
        visible_reference, hidden_reference
    )

    assigned_question = Question.objects.create(
        requirement_node=world["assigned_requirement"],
        urn=f"urn:test:ca-progress:{uuid.uuid4().hex}:assigned",
        ref_id="CA-Q-ASSIGNED",
        text="Assigned and answered",
        type=Question.Type.TEXT,
        folder=child,
    )
    Answer.objects.create(
        requirement_assessment=world["assigned_ra"],
        question=assigned_question,
        value="answered",
        folder=child,
    )
    Question.objects.create(
        requirement_node=world["unassigned_requirement"],
        urn=f"urn:test:ca-progress:{uuid.uuid4().hex}:unassigned",
        ref_id="CA-Q-UNASSIGNED",
        text="Unassigned and unanswered",
        type=Question.Type.TEXT,
        folder=child,
    )

    # Result is an authorized progress carrier for this respondent. The
    # assigned RA is compliant while the hidden/unassigned RA is not assessed;
    # a whole-audit calculation would therefore return 50 instead of 100.
    visibility = dict(target.field_visibility)
    visibility["status"] = {"auditor": "edit", "respondent": "hidden"}
    visibility["result"] = {"auditor": "edit", "respondent": "edit"}
    visibility["score"] = {"auditor": "edit", "respondent": "hidden"}
    ComplianceAssessment.objects.filter(id=target.id).update(
        field_visibility=visibility
    )
    target.field_visibility = visibility

    return {
        **world,
        "visible_asset": visible_asset,
        "hidden_asset": hidden_asset,
        "visible_author": visible_author,
        "hidden_author": hidden_author,
        "visible_flow": visible_flow,
        "hidden_flow": hidden_flow,
        "visible_reference": visible_reference,
        "hidden_reference": hidden_reference,
    }


def test_detail_projects_aggregates_and_relationships_to_caller_iam(
    ca_serializer_iam_world,
):
    world = ca_serializer_iam_world
    response = _client(world["respondent"]).get(
        f"/api/compliance-assessments/{world['target'].id}/"
    )

    assert response.status_code == 200, response.content
    data = response.json()

    assert data["progress"] == 100
    assert data["answers_progress"] == 100
    assert _related_ids(data["assets"]) == {str(world["visible_asset"].id)}
    assert _related_ids(data["evidences"]) == {str(world["visible_evidence"].id)}
    assert _related_ids(data["authors"]) == {str(world["visible_author"].id)}
    assert _related_ids(data["reviewers"]) == {str(world["visible_author"].id)}
    assert _related_ids(data["validation_flows"]) == {str(world["visible_flow"].id)}
    assert data["validation_flows"][0]["approver"] is None
    assert data["folder"] is None
    assert data["path"] is None
    assert data["perimeter"]["folder"] is None
    assert _related_ids(data["framework"]["reference_controls"]) == {
        str(world["visible_reference"].id)
    }


def test_detail_omits_framework_projection_when_framework_is_not_viewable(
    ca_serializer_iam_world,
):
    world = ca_serializer_iam_world
    framework = world["target"].framework
    framework.folder = world["hidden_folder"]
    framework.field_visibility = {
        "framework_private_field": {
            "auditor": "edit",
            "respondent": "edit",
        }
    }
    framework.save(update_fields=["folder", "field_visibility"])
    ComplianceAssessment.objects.filter(id=world["target"].id).update(
        field_visibility={}
    )

    response = _client(world["respondent"]).get(
        f"/api/compliance-assessments/{world['target'].id}/"
    )

    assert response.status_code == 200, response.content
    data = response.json()
    assert data["framework"] is None
    assert "selected_implementation_groups" not in data
    assert "framework_private_field" not in data["field_visibility"]


def test_serializer_without_authenticated_request_fails_closed(
    ca_serializer_iam_world,
):
    world = ca_serializer_iam_world
    data = ComplianceAssessmentReadSerializer(world["target"]).data

    assert data["progress"] is None
    assert data["answers_progress"] is None
    assert data["assets"] == []
    assert data["evidences"] == []
    assert data["authors"] == []
    assert data["reviewers"] == []
    assert data["validation_flows"] == []
    assert data["folder"] is None
    assert data["path"] is None
    assert data["perimeter"] is None
    assert data["campaign"] is None
    assert data["framework"] is None
    assert "selected_implementation_groups" not in data
    assert data["field_visibility"] != world["target"].field_visibility


def test_detail_omits_hidden_assessment_status_result_and_scoring_configuration(
    ca_serializer_iam_world,
):
    world = ca_serializer_iam_world
    target = world["target"]
    target.computed_outcome = {"private": {"result": "non_compliant"}}
    target.field_visibility = {
        **target.field_visibility,
        "status": {"auditor": "edit", "respondent": "hidden"},
        "result": {"auditor": "edit", "respondent": "hidden"},
        "score": {"auditor": "edit", "respondent": "hidden"},
    }
    target.save(update_fields=["computed_outcome", "field_visibility"])

    response = _client(world["respondent"]).get(
        f"/api/compliance-assessments/{target.id}/"
    )

    assert response.status_code == 200, response.content
    data = response.json()
    for field_name in (
        "status",
        "computed_outcome",
        "min_score",
        "max_score",
        "scores_definition",
        "score_calculation_method",
        "target_score",
        "anchor_na_to_target",
    ):
        assert field_name not in data
    assert "min_score" not in data["framework"]
    assert "max_score" not in data["framework"]
