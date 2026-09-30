"""Upstream owner moves must retain the fork's authority boundaries."""

import pytest

from core.models import RequirementAssignment, RequirementAssignmentMailOutbox
from core.tests.test_compliance_assessment_tree_iam import (
    _client,
    audit_iam_world,
)
from core.tests.test_requirement_assignment_mail_outbox import (
    _make_author,
    _queue,
    mailing_world,
)
from core.views import ComplianceAssessmentActionPlanFilterSet

pytestmark = pytest.mark.django_db


@pytest.mark.parametrize("field", ("created_at", "updated_at"))
@pytest.mark.parametrize("lookup", ("gte", "lt"))
def test_narrow_action_plan_filter_keeps_upstream_timestamp_ranges(field, lookup):
    name = f"{field}__{lookup}"
    timestamp_filter = ComplianceAssessmentActionPlanFilterSet.base_filters[name]
    assert timestamp_filter.field_name == field
    assert timestamp_filter.lookup_expr == lookup
    valid = ComplianceAssessmentActionPlanFilterSet({name: "2026-09-30T00:00:00Z"})
    assert valid.is_valid(), valid.errors
    invalid = ComplianceAssessmentActionPlanFilterSet({name: "not-a-date"})
    assert not invalid.is_valid()


def test_mailing_recovers_missing_assignment_in_the_outbox_transaction(
    mailing_world, monkeypatch, django_capture_on_commit_callbacks
):
    world = mailing_world
    world["assignment"].delete()
    world["target"].authors.clear()
    world["target"].perimeter.default_assignee.set([world["author_actor"]])

    response, enqueued = _queue(world, monkeypatch, django_capture_on_commit_callbacks)

    assert response.status_code == 200, response.content
    assert response.json()["assignments_started"] == 1
    assignment = world["target"].requirement_assignments.get()
    assert assignment.status == RequirementAssignment.Status.IN_PROGRESS
    assert set(assignment.actor.all()) == {world["author_actor"]}
    assert (
        assignment.requirement_assessments.count()
        == world["target"].requirement_assessments.count()
    )
    outbox = RequirementAssignmentMailOutbox.objects.get()
    assert outbox.assignment_id == assignment.id
    assert enqueued == [[outbox.id]]


def test_hidden_default_assignee_rolls_back_recovered_assignment_and_authors(
    mailing_world, monkeypatch, django_capture_on_commit_callbacks
):
    world = mailing_world
    world["assignment"].delete()
    world["target"].authors.clear()
    _, hidden_actor = _make_author("hidden-default", world["hidden_folder"])
    world["target"].perimeter.default_assignee.set([hidden_actor])

    response, enqueued = _queue(world, monkeypatch, django_capture_on_commit_callbacks)

    assert response.status_code == 403, response.content
    assert not world["target"].requirement_assignments.exists()
    assert not world["target"].authors.exists()
    assert not RequirementAssignmentMailOutbox.objects.exists()
    assert enqueued == []


def test_moved_search_requires_assignment_or_exact_full_audit_authority(
    audit_iam_world,
):
    world = audit_iam_world
    world["assignment"].actor.clear()

    response = _client(world["respondent"]).get(
        "/api/search/", {"q": "Child audit", "type": "compliance-assessments"}
    )

    assert response.status_code == 200, response.content
    assert response.json()["results"] == []
    assert response.json()["total_candidates"] == 0


def test_moved_search_still_accepts_an_assigned_respondent(audit_iam_world):
    world = audit_iam_world
    response = _client(world["respondent"]).get(
        "/api/search/", {"q": "Child audit", "type": "compliance-assessments"}
    )

    assert response.status_code == 200, response.content
    assert {row["id"] for row in response.json()["results"]} == {
        str(world["target"].id)
    }


def test_posture_pdf_does_not_evaluate_full_audit_cel_for_a_respondent(
    audit_iam_world, monkeypatch
):
    world = audit_iam_world
    world["assigned_requirement"].visibility_expression = "true"
    world["assigned_requirement"].save(update_fields=["visibility_expression"])
    monkeypatch.setattr(
        "core.views.scoped_requirement_assessments",
        lambda *args, **kwargs: pytest.fail("unassigned CEL data was evaluated"),
    )
    response = _client(world["respondent"]).get(
        f"/api/compliance-assessments/{world['target'].id}/posture-pdf/"
    )
    assert response.status_code == 403, response.content
