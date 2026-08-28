"""IAM regression tests for audit trees and coverage analytics.

These endpoints hand-build response dictionaries and aggregate related objects,
so serializer filtering alone cannot protect them.  The fixtures below exercise
the real folder IAM boundary with a respondent, a full-view auditor, and an
inaccessible sibling domain.
"""

from __future__ import annotations

import uuid
from pathlib import Path

import pytest
from django.contrib.auth.models import Permission
from django.core.files.base import ContentFile
from rest_framework.test import APIClient

from core.audit_inheritance import AuditTreeAggregationStrategy
from core.helpers import annotate_tree_with_coverage
from core.models import (
    Actor,
    Answer,
    AppliedControl,
    ComplianceAssessment,
    CustomWordTemplate,
    Evidence,
    Framework,
    Perimeter,
    Question,
    QuestionChoice,
    ReferenceControl,
    RequirementAssessment,
    RequirementAssignment,
    RequirementNode,
    RiskAssessment,
    RiskMatrix,
    RiskScenario,
    SecurityException,
    Team,
    Threat,
)
from global_settings.models import GlobalSettings
from iam.models import Folder, Role, RoleAssignment, User
from tprm.models import Entity, Representative


pytestmark = pytest.mark.django_db


def _domain(name: str, *, parent: Folder) -> Folder:
    return Folder.objects.create(
        name=name,
        content_type=Folder.ContentType.DOMAIN,
        parent_folder=parent,
    )


def _grant(
    user: User,
    name: str,
    codenames: set[str],
    *folders: Folder,
    is_recursive: bool = True,
) -> None:
    role = Role.objects.create(name=name, folder=Folder.get_root_folder())
    role.permissions.set(Permission.objects.filter(codename__in=codenames))
    assignment = RoleAssignment.objects.create(
        user=user,
        role=role,
        folder=Folder.get_root_folder(),
        is_recursive=is_recursive,
    )
    assignment.perimeter_folders.add(*folders)


def _client(user: User) -> APIClient:
    client = APIClient()
    client.force_authenticate(user=user)
    return client


def _find_node(tree: dict, ref_id: str) -> dict:
    for node in tree.values():
        if node.get("ref_id") == ref_id:
            return node
        if children := node.get("children"):
            try:
                return _find_node(children, ref_id)
            except LookupError:
                pass
    raise LookupError(ref_id)


def _all_nodes(tree: dict):
    for node in tree.values():
        yield node
        yield from _all_nodes(node.get("children") or {})


def _related_ids(values) -> set[str]:
    ids = set()
    for value in values or []:
        raw_id = value.get("id") if isinstance(value, dict) else value
        if raw_id is not None:
            ids.add(str(raw_id))
    return ids


def _list_results(response) -> list[dict]:
    body = response.json()
    return body.get("results", []) if isinstance(body, dict) else body


def _grant_questionnaire_read(user: User, folder: Folder) -> None:
    _grant(
        user,
        f"Questionnaire reader {uuid.uuid4().hex}",
        {"view_question", "view_questionchoice", "view_answer"},
        folder,
    )


def _enable_audit_inheritance() -> None:
    flags, _ = GlobalSettings.objects.get_or_create(
        name=GlobalSettings.Names.FEATURE_FLAGS, defaults={"value": {}}
    )
    flags.value = {**(flags.value or {}), "audit_tree_inheritance": True}
    flags.save(update_fields=["value"])
    general, _ = GlobalSettings.objects.get_or_create(
        name=GlobalSettings.Names.GENERAL, defaults={"value": {}}
    )
    general.value = {
        **(general.value or {}),
        "audit_tree_aggregation_strategy": AuditTreeAggregationStrategy.PARENT_WINS,
    }
    general.save(update_fields=["value"])


def _grant_complete_ancestor_read(world: dict) -> None:
    _grant(
        world["auditor"],
        f"Complete ancestor reader {uuid.uuid4().hex}",
        {
            "view_complianceassessment",
            "view_compliance_assessment_full",
            "view_requirementassessment",
        },
        world["ancestor"].folder,
    )


def _all_quality_findings(payload: dict):
    for severity in ("errors", "warnings", "info"):
        yield from payload.get(severity, [])


def _build_questionnaire_iam_fixture(world: dict) -> dict:
    """Create independently hidden Question, QuestionChoice and Answer rows.

    Some deliberately-crossed folders prove that each relation is authorized
    independently: an Answer in the visible folder must still disappear when
    its Question is hidden, and a hidden Answer must not become readable merely
    because its parent Question and RequirementAssessment are visible.
    """
    suffix = uuid.uuid4().hex
    requirement = world["assigned_requirement"]
    ra = world["assigned_ra"]
    child = world["child_folder"]
    hidden = world["hidden_folder"]

    visible_choice_question = Question.objects.create(
        requirement_node=requirement,
        urn=f"urn:test:questionnaire:{suffix}:visible-choice-question",
        ref_id="Q-VISIBLE-CHOICE",
        text="Visible multiple-choice question",
        type=Question.Type.MULTIPLE_CHOICE,
        folder=child,
    )
    visible_choice = QuestionChoice.objects.create(
        question=visible_choice_question,
        urn=f"urn:test:questionnaire:{suffix}:visible-choice",
        ref_id="QC-VISIBLE",
        value="Visible choice",
        folder=child,
    )
    hidden_choice = QuestionChoice.objects.create(
        question=visible_choice_question,
        urn=f"urn:test:questionnaire:{suffix}:hidden-choice",
        ref_id="QC-HIDDEN",
        value="Hidden choice",
        folder=hidden,
    )
    visible_answer = Answer.objects.create(
        requirement_assessment=ra,
        question=visible_choice_question,
        folder=child,
    )
    visible_answer.selected_choices.add(visible_choice, hidden_choice)

    hidden_question = Question.objects.create(
        requirement_node=requirement,
        urn=f"urn:test:questionnaire:{suffix}:hidden-question",
        ref_id="Q-HIDDEN",
        text="Hidden question",
        type=Question.Type.TEXT,
        folder=hidden,
    )
    hidden_question_answer = Answer.objects.create(
        requirement_assessment=ra,
        question=hidden_question,
        value="answer behind a hidden question",
        # The Answer itself is visible. The Question IAM check must still hide it.
        folder=child,
    )

    hidden_answer_question = Question.objects.create(
        requirement_node=requirement,
        urn=f"urn:test:questionnaire:{suffix}:hidden-answer-question",
        ref_id="Q-HIDDEN-ANSWER",
        text="Visible question with a hidden answer",
        type=Question.Type.TEXT,
        folder=child,
    )
    hidden_answer = Answer.objects.create(
        requirement_assessment=ra,
        question=hidden_answer_question,
        value="hidden answer",
        folder=hidden,
    )

    unanswered_question = Question.objects.create(
        requirement_node=requirement,
        urn=f"urn:test:questionnaire:{suffix}:unanswered-question",
        ref_id="Q-UNANSWERED",
        text="Visible unanswered question",
        type=Question.Type.TEXT,
        folder=child,
    )
    hidden_choice_write_question = Question.objects.create(
        requirement_node=requirement,
        urn=f"urn:test:questionnaire:{suffix}:hidden-choice-write-question",
        ref_id="Q-HIDDEN-CHOICE-WRITE",
        text="Visible question with only a hidden choice",
        type=Question.Type.UNIQUE_CHOICE,
        folder=child,
    )
    hidden_write_choice = QuestionChoice.objects.create(
        question=hidden_choice_write_question,
        urn=f"urn:test:questionnaire:{suffix}:hidden-write-choice",
        ref_id="QC-HIDDEN-WRITE",
        value="Hidden write choice",
        folder=hidden,
    )

    return {
        "visible_choice_question": visible_choice_question,
        "visible_choice": visible_choice,
        "hidden_choice": hidden_choice,
        "visible_answer": visible_answer,
        "hidden_question": hidden_question,
        "hidden_question_answer": hidden_question_answer,
        "hidden_answer_question": hidden_answer_question,
        "hidden_answer": hidden_answer,
        "unanswered_question": unanswered_question,
        "hidden_choice_write_question": hidden_choice_write_question,
        "hidden_write_choice": hidden_write_choice,
    }


@pytest.fixture
def audit_iam_world():
    # Keep this fixture independent of the expensive post-migrate builtin
    # library bootstrap.  Full-suite runs still use normal startup; focused
    # runs may safely suppress that hook and initialise only the IAM rows this
    # boundary test actually owns.
    Folder._init_root_folder()
    root = Folder.get_root_folder()
    parent = _domain(f"tree-iam-parent-{uuid.uuid4().hex[:6]}", parent=root)
    child = _domain(f"tree-iam-child-{uuid.uuid4().hex[:6]}", parent=parent)
    hidden = _domain(f"tree-iam-hidden-{uuid.uuid4().hex[:6]}", parent=root)

    framework = Framework.objects.create(
        name="Tree IAM framework",
        urn=f"urn:test:framework:tree-iam-{uuid.uuid4().hex}",
        ref_id="TREE-IAM",
        folder=child,
        min_score=0,
        max_score=4,
    )
    section = RequirementNode.objects.create(
        name="Section",
        urn=f"{framework.urn}:section",
        ref_id="S",
        framework=framework,
        folder=root,
        assessable=False,
    )
    assigned_requirement = RequirementNode.objects.create(
        name="Assigned requirement",
        urn=f"{framework.urn}:assigned",
        parent_urn=section.urn,
        ref_id="R-ASSIGNED",
        framework=framework,
        folder=root,
        assessable=True,
    )
    unassigned_requirement = RequirementNode.objects.create(
        name="Unassigned requirement",
        urn=f"{framework.urn}:unassigned",
        parent_urn=section.urn,
        ref_id="R-UNASSIGNED",
        framework=framework,
        folder=root,
        assessable=True,
    )

    field_visibility = {
        field: {"auditor": "edit", "respondent": "hidden"}
        for field in (
            "status",
            "result",
            "score",
            "is_scored",
            "documentation_score",
            "applied_controls",
            "evidences",
        )
    }
    target = ComplianceAssessment.objects.create(
        name="Child audit",
        ref_id="CHILD-AUDIT",
        framework=framework,
        folder=child,
        perimeter=Perimeter.objects.create(name="Child perimeter", folder=child),
        min_score=0,
        max_score=4,
        status="in_progress",
        field_visibility=field_visibility,
    )
    target.create_requirement_assessments()
    target_ras = {
        ra.requirement_id: ra
        for ra in target.requirement_assessments.select_related("requirement")
    }
    assigned_ra = target_ras[assigned_requirement.id]
    assigned_ra.status = RequirementAssessment.Status.DONE
    assigned_ra.result = RequirementAssessment.Result.COMPLIANT
    assigned_ra.is_scored = True
    assigned_ra.score = 3
    assigned_ra.documentation_score = 2
    assigned_ra.save()
    unassigned_ra = target_ras[unassigned_requirement.id]

    ancestor = ComplianceAssessment.objects.create(
        name="Parent audit",
        ref_id="PARENT-AUDIT",
        framework=framework,
        folder=parent,
        perimeter=Perimeter.objects.create(name="Parent perimeter", folder=parent),
        min_score=0,
        max_score=4,
        status="in_progress",
        field_visibility=field_visibility,
    )
    ancestor.create_requirement_assessments()
    ancestor_ra = ancestor.requirement_assessments.get(requirement=assigned_requirement)
    ancestor_ra.result = RequirementAssessment.Result.NON_COMPLIANT
    ancestor_ra.is_scored = True
    ancestor_ra.score = 1
    ancestor_ra.save()

    respondent = User.objects.create_user("respondent@tree-iam.tests")
    # Give the respondent ordinary audit access on both target and parent.  The
    # combined-tree assertion therefore proves the respondent-specific deny,
    # rather than merely relying on the ancestor being invisible anyway.
    _grant(
        respondent,
        f"Tree IAM respondent {uuid.uuid4().hex}",
        {
            "view_complianceassessment",
            "view_requirementassessment",
            "change_requirementassessment",
            "view_requirementassignment",
            "view_appliedcontrol",
            "view_evidence",
            "view_framework",
            "view_referencecontrol",
            "view_threat",
        },
        parent,
        child,
    )
    # The synthetic framework nodes live directly in root.  Grant only that
    # exact folder so questionnaire IAM is exercised without opening sibling
    # domains containing deliberately hidden test objects.
    _grant(
        respondent,
        f"Tree IAM respondent framework nodes {uuid.uuid4().hex}",
        {"view_requirementnode"},
        root,
        is_recursive=False,
    )
    # User creation normally provisions its actor via ActorSyncManager.  Keep
    # this robust for both signal-enabled and stripped-down test settings.
    actor, _ = Actor.objects.get_or_create(user=respondent)
    assignment = RequirementAssignment.objects.create(
        compliance_assessment=target,
        folder=child,
        status=RequirementAssignment.Status.IN_PROGRESS,
    )
    assignment.actor.add(actor)
    assignment.requirement_assessments.add(assigned_ra)

    auditor = User.objects.create_user("auditor@tree-iam.tests")
    _grant(
        auditor,
        f"Tree IAM auditor {uuid.uuid4().hex}",
        {
            "change_complianceassessment",
            "view_complianceassessment",
            "view_compliance_assessment_full",
            "view_requirementassessment",
            "change_requirementassessment",
            "view_requirementassignment",
            "view_appliedcontrol",
            "view_evidence",
            "view_framework",
            "view_referencecontrol",
            "view_securityexception",
            "view_threat",
        },
        child,
    )
    _grant(
        auditor,
        f"Tree IAM auditor framework nodes {uuid.uuid4().hex}",
        {"view_requirementnode"},
        root,
        is_recursive=False,
    )

    visible_control = AppliedControl.objects.create(
        name="Visible control", folder=child
    )
    hidden_control = AppliedControl.objects.create(name="Hidden control", folder=hidden)
    visible_evidence = Evidence.objects.create(name="Visible evidence", folder=child)
    hidden_evidence = Evidence.objects.create(name="Hidden evidence", folder=hidden)

    return {
        "target": target,
        "ancestor": ancestor,
        "ancestor_ra": ancestor_ra,
        "assignment": assignment,
        "assigned_requirement": assigned_requirement,
        "unassigned_requirement": unassigned_requirement,
        "assigned_ra": assigned_ra,
        "unassigned_ra": unassigned_ra,
        "child_folder": child,
        "hidden_folder": hidden,
        "respondent": respondent,
        "auditor": auditor,
        "visible_control": visible_control,
        "hidden_control": hidden_control,
        "visible_evidence": visible_evidence,
        "hidden_evidence": hidden_evidence,
    }


def test_tree_limits_respondent_rows_and_strips_derived_hidden_fields(audit_iam_world):
    world = audit_iam_world
    response = _client(world["respondent"]).get(
        f"/api/compliance-assessments/{world['target'].id}/tree/"
    )

    assert response.status_code == 200, response.content
    assert response["X-Viewer-Role"] == "respondent"
    tree = response.json()
    assigned = _find_node(tree, "R-ASSIGNED")
    unassigned = _find_node(tree, "R-UNASSIGNED")

    assert assigned["ra_id"] == str(world["assigned_ra"].id)
    assert unassigned["ra_id"] is None
    assert [node["ra_id"] for node in _all_nodes(tree) if node.get("ra_id")] == [
        str(world["assigned_ra"].id)
    ]

    # Hand-built and aggregate keys must obey the same field_visibility rule as
    # serializer fields.  In particular, a hidden base field hides all aliases
    # derived from it rather than leaking the same value under another name.
    for key in (
        "status",
        "status_display",
        "status_i18n",
        "result",
        "result_i18n",
        "score",
        "aggregated_score",
        "aggregated_min_score",
        "aggregated_max_score",
        "documentation_score",
        "aggregated_documentation_score",
        "min_score",
        "max_score",
        "weight",
        "has_applied_controls",
        "has_evidence",
    ):
        assert key not in assigned


def test_tree_coverage_uses_only_visible_links_and_clears_stale_flags(
    audit_iam_world,
):
    world = audit_iam_world
    target = world["target"]
    target.field_visibility = {
        **target.field_visibility,
        "applied_controls": {"auditor": "edit", "respondent": "read"},
        "evidences": {"auditor": "edit", "respondent": "read"},
    }
    target.save(update_fields=["field_visibility"])
    ra = world["assigned_ra"]
    hidden_control = world["hidden_control"]
    visible_control = world["visible_control"]
    hidden_evidence = world["hidden_evidence"]
    visible_evidence = world["visible_evidence"]
    tree = {
        "assigned": {
            "ra_id": str(ra.id),
            "children": {},
            # Simulate a request reusing a tree annotated for a broader viewer.
            "has_applied_controls": True,
            "has_evidence": True,
        }
    }

    # A visible evidence linked through an invisible control is still hidden;
    # so is direct evidence outside the viewer's folder perimeter.
    ra.applied_controls.add(hidden_control)
    hidden_control.evidences.add(visible_evidence)
    ra.evidences.add(hidden_evidence)
    annotate_tree_with_coverage(tree, target, user=world["respondent"])
    node = tree["assigned"]
    assert "has_applied_controls" not in node
    assert "has_evidence" not in node

    # A visible control counts, but its invisible evidence does not.
    ra.applied_controls.add(visible_control)
    visible_control.evidences.add(hidden_evidence)
    annotate_tree_with_coverage(tree, target, user=world["respondent"])
    assert node["has_applied_controls"] is True
    assert "has_evidence" not in node

    # Direct visible evidence is safe to expose.
    ra.evidences.add(visible_evidence)
    annotate_tree_with_coverage(tree, target, user=world["respondent"])
    assert node["has_applied_controls"] is True
    assert node["has_evidence"] is True

    # Reusing the same dictionary after relationships narrow must clear prior
    # truthy markers.  Hidden links remain, including visible evidence through
    # the hidden control, and none of them may keep a stale flag alive.
    ra.applied_controls.remove(visible_control)
    ra.evidences.remove(visible_evidence)
    annotate_tree_with_coverage(tree, target, user=world["respondent"])
    assert "has_applied_controls" not in node
    assert "has_evidence" not in node


def test_combined_tree_suppresses_ancestors_and_overlay_for_respondent(
    audit_iam_world,
):
    world = audit_iam_world
    _enable_audit_inheritance()

    response = _client(world["respondent"]).get(
        f"/api/compliance-assessments/{world['target'].id}/combined_tree/"
    )

    assert response.status_code == 200, response.content
    assert response["X-Viewer-Role"] == "respondent"
    body = response.json()
    assert body["viewer_role"] == "respondent"
    assert body["strategy"] == AuditTreeAggregationStrategy.NONE
    assert body["ancestors"] == []
    assert all("inheritance" not in node for node in _all_nodes(body["tree"]))
    assert _find_node(body["tree"], "R-UNASSIGNED")["ra_id"] is None


def test_combined_tree_redacts_folder_metadata_without_folder_iam(
    audit_iam_world,
):
    world = audit_iam_world
    parent_folder = world["ancestor"].folder
    _grant_complete_ancestor_read(world)
    _enable_audit_inheritance()

    assert parent_folder.id not in RoleAssignment.get_viewable_object_ids(
        world["auditor"], Folder
    )
    response = _client(world["auditor"]).get(
        f"/api/compliance-assessments/{world['target'].id}/combined_tree/"
    )

    assert response.status_code == 200, response.content
    body = response.json()
    assert body["ancestors"]
    assert body["ancestors"][0]["folder_id"] is None
    assert body["ancestors"][0]["folder_name"] is None
    inherited = _find_node(body["tree"], "R-ASSIGNED")["inheritance"]
    assert inherited["source"]["folder_id"] is None
    assert inherited["source"]["folder_name"] is None
    assert all(entry["folder_name"] is None for entry in inherited["path"])


@pytest.mark.parametrize(
    "hidden_scope", ["current-ra", "ancestor-ra", "framework-node"]
)
def test_combined_tree_fails_closed_instead_of_emitting_partial_inheritance(
    audit_iam_world,
    hidden_scope,
):
    world = audit_iam_world
    _grant_complete_ancestor_read(world)
    _enable_audit_inheritance()

    if hidden_scope == "current-ra":
        row = world["assigned_ra"]
        row.folder = world["hidden_folder"]
        row.save(update_fields=["folder"])
    elif hidden_scope == "ancestor-ra":
        row = world["ancestor_ra"]
        row.folder = world["hidden_folder"]
        row.save(update_fields=["folder"])
    else:
        section = RequirementNode.objects.get(
            framework=world["target"].framework,
            ref_id="S",
        )
        section.folder = world["hidden_folder"]
        section.save(update_fields=["folder"])

    response = _client(world["auditor"]).get(
        f"/api/compliance-assessments/{world['target'].id}/combined_tree/"
    )

    assert response.status_code == 403, response.content
    assert b"Complete audit inheritance data" in response.content


def test_combined_tree_requires_independent_framework_iam(audit_iam_world):
    world = audit_iam_world
    _grant_complete_ancestor_read(world)
    _enable_audit_inheritance()
    framework = world["target"].framework
    framework.folder = world["hidden_folder"]
    framework.save(update_fields=["folder"])

    response = _client(world["auditor"]).get(
        f"/api/compliance-assessments/{world['target'].id}/combined_tree/"
    )

    assert response.status_code == 403, response.content
    assert b"Complete audit inheritance data" in response.content


def test_combined_tree_does_not_substitute_an_older_visible_ancestor(
    audit_iam_world,
    monkeypatch,
):
    import core.utils as core_utils

    world = audit_iam_world
    _grant_complete_ancestor_read(world)
    _enable_audit_inheritance()
    newest = ComplianceAssessment.objects.create(
        name="Canonical newest parent audit",
        ref_id="CANONICAL-NEWEST",
        framework=world["target"].framework,
        folder=world["ancestor"].folder,
        perimeter=Perimeter.objects.create(
            name="Canonical newest perimeter", folder=world["ancestor"].folder
        ),
        min_score=0,
        max_score=4,
        status="in_progress",
        field_visibility=world["ancestor"].field_visibility,
    )
    newest.create_requirement_assessments()
    assert newest.updated_at > world["ancestor"].updated_at

    original = core_utils.get_full_view_compliance_assessment_ids

    def hide_canonical_ancestor(user):
        return original(user).exclude(id=newest.id)

    monkeypatch.setattr(
        core_utils,
        "get_full_view_compliance_assessment_ids",
        hide_canonical_ancestor,
    )
    response = _client(world["auditor"]).get(
        f"/api/compliance-assessments/{world['target'].id}/combined_tree/"
    )

    assert response.status_code == 403, response.content
    assert b"Complete audit inheritance data" in response.content


@pytest.mark.parametrize("hidden_field", ["status", "result", "score", "is_scored"])
def test_combined_tree_requires_every_ancestor_selection_and_value_field(
    audit_iam_world,
    hidden_field,
):
    world = audit_iam_world
    _grant_complete_ancestor_read(world)
    _enable_audit_inheritance()
    ancestor = world["ancestor"]
    ancestor.field_visibility = {
        **ancestor.field_visibility,
        hidden_field: {"auditor": "hidden", "respondent": "hidden"},
    }
    ancestor.save(update_fields=["field_visibility"])

    response = _client(world["auditor"]).get(
        f"/api/compliance-assessments/{world['target'].id}/combined_tree/"
    )

    assert response.status_code == 403, response.content
    assert b"Complete audit inheritance data" in response.content


@pytest.mark.parametrize("hidden_carrier", ["question", "choice", "answer"])
def test_combined_tree_rejects_partial_questionnaire_carriers(
    audit_iam_world,
    hidden_carrier,
):
    world = audit_iam_world
    _grant_complete_ancestor_read(world)
    _grant(
        world["auditor"],
        f"Visible questionnaire reader {uuid.uuid4().hex}",
        {"view_question", "view_questionchoice", "view_answer"},
        world["child_folder"],
    )
    _enable_audit_inheritance()

    question = Question.objects.create(
        requirement_node=world["assigned_requirement"],
        urn=f"urn:test:combined-question:{uuid.uuid4().hex}",
        ref_id="COMBINED-Q",
        text="Combined tree question",
        type=Question.Type.TEXT,
        folder=(
            world["hidden_folder"]
            if hidden_carrier == "question"
            else world["child_folder"]
        ),
    )
    if hidden_carrier == "choice":
        QuestionChoice.objects.create(
            question=question,
            urn=f"urn:test:combined-choice:{uuid.uuid4().hex}",
            ref_id="COMBINED-C",
            value="Hidden combined choice",
            folder=world["hidden_folder"],
        )
    elif hidden_carrier == "answer":
        Answer.objects.create(
            requirement_assessment=world["assigned_ra"],
            question=question,
            value="Hidden combined answer",
            folder=world["hidden_folder"],
        )

    response = _client(world["auditor"]).get(
        f"/api/compliance-assessments/{world['target'].id}/combined_tree/"
    )

    assert response.status_code == 403, response.content
    assert b"Complete audit inheritance data" in response.content


def test_combined_tree_allows_complete_questionnaire_and_coverage_projection(
    audit_iam_world,
):
    world = audit_iam_world
    _grant_complete_ancestor_read(world)
    _grant(
        world["auditor"],
        f"Complete questionnaire reader {uuid.uuid4().hex}",
        {"view_question", "view_questionchoice", "view_answer"},
        world["child_folder"],
    )
    _enable_audit_inheritance()
    question = Question.objects.create(
        requirement_node=world["assigned_requirement"],
        urn=f"urn:test:combined-complete:{uuid.uuid4().hex}",
        ref_id="COMBINED-COMPLETE",
        text="Complete combined question",
        type=Question.Type.UNIQUE_CHOICE,
        folder=world["child_folder"],
    )
    choice = QuestionChoice.objects.create(
        question=question,
        urn=f"urn:test:combined-complete-choice:{uuid.uuid4().hex}",
        ref_id="COMBINED-COMPLETE-C",
        value="Complete combined choice",
        folder=world["child_folder"],
    )
    answer = Answer.objects.create(
        requirement_assessment=world["assigned_ra"],
        question=question,
        folder=world["child_folder"],
    )
    answer.selected_choices.add(choice)
    world["assigned_ra"].applied_controls.add(world["visible_control"])
    world["visible_control"].evidences.add(world["visible_evidence"])

    response = _client(world["auditor"]).get(
        f"/api/compliance-assessments/{world['target'].id}/combined_tree/"
    )

    assert response.status_code == 200, response.content
    node = _find_node(response.json()["tree"], "R-ASSIGNED")
    assert question.urn in node["questions"]
    assert question.urn in node["answers"]
    assert node["has_applied_controls"] is True
    assert node["has_evidence"] is True


@pytest.mark.parametrize(
    "hidden_link", ["applied-control", "direct-evidence", "indirect-evidence"]
)
def test_combined_tree_rejects_hidden_coverage_links(
    audit_iam_world,
    hidden_link,
):
    world = audit_iam_world
    _grant_complete_ancestor_read(world)
    _enable_audit_inheritance()
    row = world["assigned_ra"]
    if hidden_link == "applied-control":
        row.applied_controls.add(world["hidden_control"])
    elif hidden_link == "direct-evidence":
        row.evidences.add(world["hidden_evidence"])
    else:
        row.applied_controls.add(world["visible_control"])
        world["visible_control"].evidences.add(world["hidden_evidence"])

    response = _client(world["auditor"]).get(
        f"/api/compliance-assessments/{world['target'].id}/combined_tree/"
    )

    assert response.status_code == 403, response.content
    assert b"Complete audit inheritance data" in response.content


@pytest.mark.parametrize(
    "changed_projection", ["question", "coverage-link", "mapping-authorization"]
)
def test_combined_tree_terminal_reproof_binds_relational_projection(
    audit_iam_world,
    monkeypatch,
    changed_projection,
):
    world = audit_iam_world
    _grant_complete_ancestor_read(world)
    _grant(
        world["auditor"],
        f"Combined reproof questionnaire reader {uuid.uuid4().hex}",
        {"view_question", "view_questionchoice", "view_answer"},
        world["child_folder"],
    )
    _enable_audit_inheritance()

    if changed_projection == "question":
        import core.audit_inheritance as inheritance

        question = Question.objects.create(
            requirement_node=world["assigned_requirement"],
            urn=f"urn:test:combined-reproof:{uuid.uuid4().hex}",
            ref_id="COMBINED-REPROOF",
            text="Before terminal reproof",
            type=Question.Type.TEXT,
            folder=world["child_folder"],
        )
        original = inheritance.build_overlay_map

        def mutate_after_overlay(*args, **kwargs):
            result = original(*args, **kwargs)
            Question.objects.filter(id=question.id).update(
                text="Changed during response generation"
            )
            return result

        monkeypatch.setattr(inheritance, "build_overlay_map", mutate_after_overlay)
    elif changed_projection == "coverage-link":
        import core.views as core_views

        original = core_views.annotate_tree_with_coverage

        def mutate_after_coverage(*args, **kwargs):
            result = original(*args, **kwargs)
            world["assigned_ra"].applied_controls.add(world["visible_control"])
            return result

        monkeypatch.setattr(
            core_views, "annotate_tree_with_coverage", mutate_after_coverage
        )
    else:
        import core.helpers as core_helpers
        import core.utils as core_utils
        import core.views as core_views

        RequirementAssessment.objects.filter(id=world["assigned_ra"].id).update(
            mapping_inference={"synthetic": "authority-bearing"}
        )
        state = {"authority": "before"}

        def mapping_context(*args, **kwargs):
            return {"authority": state["authority"]}

        def sanitized_mapping(*args, **kwargs):
            return {"authority": state["authority"]}

        monkeypatch.setattr(
            core_utils,
            "get_mapping_inference_visibility_context",
            mapping_context,
        )
        monkeypatch.setattr(
            core_utils,
            "sanitize_mapping_inference_for_viewer",
            sanitized_mapping,
        )
        monkeypatch.setattr(
            core_helpers,
            "get_mapping_inference_visibility_context",
            mapping_context,
        )
        monkeypatch.setattr(
            core_helpers,
            "sanitize_mapping_inference_for_viewer",
            sanitized_mapping,
        )
        original = core_views.strip_tree_fields_for_viewer

        def revoke_after_serialization(*args, **kwargs):
            result = original(*args, **kwargs)
            state["authority"] = "after"
            return result

        monkeypatch.setattr(
            core_views,
            "strip_tree_fields_for_viewer",
            revoke_after_serialization,
        )

    response = _client(world["auditor"]).get(
        f"/api/compliance-assessments/{world['target'].id}/combined_tree/"
    )

    assert response.status_code == 403, response.content
    assert b"Complete audit inheritance data" in response.content


def test_my_assignments_filters_roots_and_uses_caller_visible_metrics(
    audit_iam_world,
):
    world = audit_iam_world
    actor = world["auditor"].actor
    _grant(
        world["auditor"],
        f"Assignment risk reader {uuid.uuid4().hex}",
        {"view_riskassessment", "view_riskmatrix", "view_riskscenario"},
        world["child_folder"],
    )
    world["target"].authors.add(actor)
    world["ancestor"].authors.add(actor)

    risk_matrix = RiskMatrix.objects.create(
        name="My assignments matrix",
        folder=world["child_folder"],
        json_definition={},
    )
    visible_risk_assessment = RiskAssessment.objects.create(
        name="Visible assigned risk assessment",
        folder=world["child_folder"],
        risk_matrix=risk_matrix,
    )
    visible_risk_assessment.authors.add(actor)
    hidden_risk_assessment = RiskAssessment.objects.create(
        name="Hidden assigned risk assessment",
        folder=world["hidden_folder"],
        risk_matrix=risk_matrix,
    )
    hidden_risk_assessment.authors.add(actor)
    visible_scenario = RiskScenario.objects.create(
        name="Visible owned scenario",
        risk_assessment=visible_risk_assessment,
        folder=world["child_folder"],
    )
    visible_scenario.owner.add(actor)
    hidden_scenario = RiskScenario.objects.create(
        name="Hidden owned scenario",
        risk_assessment=hidden_risk_assessment,
        folder=world["hidden_folder"],
    )
    hidden_scenario.owner.add(actor)

    visible_with_evidence = world["visible_control"]
    visible_with_evidence.status = AppliedControl.Status.ACTIVE
    visible_with_evidence.save(update_fields=["status"])
    visible_with_evidence.owner.add(actor)
    visible_with_evidence.evidences.add(
        world["visible_evidence"], world["hidden_evidence"]
    )

    visible_without_readable_evidence = AppliedControl.objects.create(
        name="Visible control with hidden evidence only",
        folder=world["child_folder"],
        status=AppliedControl.Status.TO_DO,
    )
    visible_without_readable_evidence.owner.add(actor)
    visible_without_readable_evidence.evidences.add(world["hidden_evidence"])

    world["hidden_control"].owner.add(actor)
    world["hidden_control"].evidences.add(world["visible_evidence"])

    response = _client(world["auditor"]).get("/api/folders/my_assignments/")

    assert response.status_code == 200, response.content
    payload = response.json()
    assert payload["summary_schema"] == "my-assignments/v1"
    assert {item["id"] for item in payload["audits"]} == {str(world["target"].id)}
    assert {item["id"] for item in payload["risk_assessments"]} == {
        str(visible_risk_assessment.id)
    }
    assert {item["id"] for item in payload["risk_scenarios"]} == {
        str(visible_scenario.id)
    }
    assert {item["id"] for item in payload["controls"]} == {
        str(visible_without_readable_evidence.id)
    }
    assert set(payload["audits"][0]) == {
        "id",
        "name",
        "ref_id",
        "version",
        "eta",
        "due_date",
        "progress",
        "answers_progress",
        "status",
    }
    assert set(payload["risk_assessments"][0]) == {
        "id",
        "name",
        "ref_id",
        "status",
        "version",
        "eta",
        "due_date",
    }
    assert set(payload["controls"][0]) == {
        "id",
        "name",
        "ref_id",
        "status",
        "priority",
        "eta",
    }
    assert set(payload["risk_scenarios"][0]) == {
        "id",
        "name",
        "ref_id",
        "treatment",
        "current_level",
        "residual_level",
    }
    assert payload["metrics"]["progress"] == {
        "audits": 50,
        "controls": 50,
        "evidences": None,
    }
    assert payload["metrics"]["scope"] == "authorized_visible"
    assert payload["metrics"]["complete"] == {
        "audits": True,
        "controls": True,
        "evidences": False,
    }
    assert str(world["ancestor"].id).encode() not in response.content
    assert str(world["hidden_control"].id).encode() not in response.content
    assert str(hidden_risk_assessment.id).encode() not in response.content
    assert str(hidden_scenario.id).encode() not in response.content
    assert world["hidden_evidence"].name.encode() not in response.content


def test_my_assignments_marks_incomplete_audit_progress_unavailable(
    audit_iam_world,
):
    world = audit_iam_world
    world["target"].authors.add(world["auditor"].actor)
    world["target"].field_visibility = {
        **world["target"].field_visibility,
        "status": {"auditor": "hidden", "respondent": "hidden"},
    }
    world["target"].save(update_fields=["field_visibility"])
    hidden_row = world["unassigned_ra"]
    hidden_row.folder = world["hidden_folder"]
    hidden_row.save(update_fields=["folder"])

    response = _client(world["auditor"]).get("/api/folders/my_assignments/")

    assert response.status_code == 200, response.content
    payload = response.json()
    assert payload["audits"][0]["progress"] is None
    assert "status" not in payload["audits"][0]
    assert payload["metrics"]["progress"]["audits"] is None


def test_full_coverage_requires_full_view_and_fails_closed_on_hidden_links(
    audit_iam_world, monkeypatch
):
    world = audit_iam_world
    target = world["target"]
    respondent_client = _client(world["respondent"])
    auditor_client = _client(world["auditor"])
    controls_url = f"/api/compliance-assessments/{target.id}/controls_coverage/"
    evidence_url = f"/api/compliance-assessments/{target.id}/evidence_coverage/"

    # Simulate a model that gains a published flag in a future upstream change:
    # the ordinary published-read shortcut must never bypass an action override.
    monkeypatch.setattr(ComplianceAssessment, "is_published", True, raising=False)

    # Folder access to the audit is insufficient: advanced authorized-visible
    # aggregates are guarded by the full-view permission.
    assert respondent_client.get(controls_url).status_code == 403
    assert respondent_client.get(evidence_url).status_code == 403
    controls = auditor_client.get(controls_url)
    evidence = auditor_client.get(evidence_url)
    assert controls.status_code == 200
    assert evidence.status_code == 200
    for response in (controls, evidence):
        assert response.json()["scope"] == "authorized_visible"
        assert response.json()["complete"] is False
        assert response.json()["snapshot_consistency"] == "read_committed"

    ra = world["assigned_ra"]
    ra.applied_controls.add(world["hidden_control"])
    assert auditor_client.get(controls_url).status_code == 403

    # Once all controls are visible the controls aggregate is complete again,
    # but evidence analysis must independently fail closed on a hidden direct
    # or indirect association.
    ra.applied_controls.remove(world["hidden_control"])
    ra.applied_controls.add(world["visible_control"])
    assert auditor_client.get(controls_url).status_code == 200
    world["visible_control"].evidences.add(world["hidden_evidence"])
    assert auditor_client.get(evidence_url).status_code == 403
    # The shared complete-audit prerequisite also makes other full-only
    # projections fail closed while a hidden evidence relationship exists.
    assert auditor_client.get(controls_url).status_code == 403


def test_respondent_cannot_reach_full_audit_exports_or_comparisons(
    audit_iam_world, monkeypatch
):
    world = audit_iam_world
    target = world["target"]
    ancestor = world["ancestor"]
    client = _client(world["respondent"])
    monkeypatch.setattr(ComplianceAssessment, "is_published", True, raising=False)

    requests = (
        (
            f"/api/compliance-assessments/{target.id}/compliance_assessment_csv/",
            {},
        ),
        (
            f"/api/compliance-assessments/{target.id}/compare/",
            {"compare_id": str(ancestor.id)},
        ),
        (
            f"/api/compliance-assessments/{target.id}/map_from_preview/",
            {"source_audit_id": str(ancestor.id)},
        ),
    )
    for url, params in requests:
        response = client.get(url, params)
        assert response.status_code == 403, (url, response.content)


def test_comparable_audits_omit_candidate_with_hidden_auditor_status(
    audit_iam_world,
):
    world = audit_iam_world
    _grant(
        world["auditor"],
        f"Comparable related reader {uuid.uuid4().hex}",
        {"view_folder", "view_perimeter"},
        world["child_folder"],
    )
    target = world["target"]
    visible_candidate = ComplianceAssessment.objects.create(
        name="Visible comparable audit",
        framework=target.framework,
        folder=target.folder,
        perimeter=target.perimeter,
        field_visibility=target.field_visibility,
    )
    visible_candidate.create_requirement_assessments()
    hidden_candidate = ComplianceAssessment.objects.create(
        name="Status-hidden comparable audit",
        framework=target.framework,
        folder=target.folder,
        perimeter=target.perimeter,
        field_visibility={
            **target.field_visibility,
            "status": {"auditor": "hidden", "respondent": "hidden"},
        },
    )
    hidden_candidate.create_requirement_assessments()

    response = _client(world["auditor"]).get(
        f"/api/compliance-assessments/{target.id}/comparable_audits/"
    )

    assert response.status_code == 200, response.content
    result_ids = {item["id"] for item in response.json()["results"]}
    assert str(visible_candidate.id) in result_ids
    assert str(hidden_candidate.id) not in result_ids


def test_direct_ra_api_scopes_assignments_and_filters_nested_related_data(
    audit_iam_world,
):
    world = audit_iam_world
    target = world["target"]
    requirement = world["assigned_requirement"]
    assigned_ra = world["assigned_ra"]

    # Related fields are readable for the respondent, while scoring and result
    # fields remain hidden.  This separates field policy from object IAM.
    visibility = dict(target.field_visibility)
    visibility["applied_controls"] = {"auditor": "edit", "respondent": "edit"}
    visibility["evidences"] = {"auditor": "edit", "respondent": "edit"}
    target.field_visibility = visibility
    target.scores_definition = {"scale": [{"value": 0, "name": "secret-zero"}]}
    target.save(update_fields=["field_visibility", "scores_definition"])
    requirement.min_score = 1
    requirement.max_score = 4
    requirement.weight = 7
    requirement.save(update_fields=["min_score", "max_score", "weight"])

    visible_reference = ReferenceControl.objects.create(
        name="Visible reference",
        ref_id="VISIBLE-REF",
        urn=f"urn:test:reference:{uuid.uuid4().hex}",
        folder=world["child_folder"],
    )
    hidden_reference = ReferenceControl.objects.create(
        name="Hidden reference",
        ref_id="HIDDEN-REF",
        urn=f"urn:test:reference:{uuid.uuid4().hex}",
        folder=world["hidden_folder"],
    )
    visible_threat = Threat.objects.create(
        name="Visible threat",
        ref_id="VISIBLE-THREAT",
        urn=f"urn:test:threat:{uuid.uuid4().hex}",
        folder=world["child_folder"],
    )
    hidden_threat = Threat.objects.create(
        name="Hidden threat",
        ref_id="HIDDEN-THREAT",
        urn=f"urn:test:threat:{uuid.uuid4().hex}",
        folder=world["hidden_folder"],
    )
    requirement.reference_controls.add(visible_reference, hidden_reference)
    requirement.threats.add(visible_threat, hidden_threat)
    assigned_ra.applied_controls.add(world["visible_control"], world["hidden_control"])
    assigned_ra.evidences.add(world["visible_evidence"], world["hidden_evidence"])

    client = _client(world["respondent"])
    assigned_response = client.get(f"/api/requirement-assessments/{assigned_ra.id}/")
    assert assigned_response.status_code == 200, assigned_response.content
    assert (
        client.get(
            f"/api/requirement-assessments/{world['unassigned_ra'].id}/"
        ).status_code
        == 404
    )
    listing = client.get(
        "/api/requirement-assessments/",
        {"compliance_assessment": str(target.id)},
    )
    assert listing.status_code == 200, listing.content
    assert {item["id"] for item in _list_results(listing)} == {str(assigned_ra.id)}

    data = assigned_response.json()
    for key in (
        "status",
        "result",
        "score",
        "is_scored",
        "documentation_score",
        "effective_min_score",
        "effective_max_score",
        "effective_scores_definition",
    ):
        assert key not in data
    for key in ("min_score", "max_score", "scores_definition_ref", "weight"):
        assert key not in data["requirement"]
    for key in (
        "min_score",
        "max_score",
        "scores_definition",
        "score_calculation_method",
    ):
        assert key not in data["compliance_assessment"]

    assert _related_ids(data["applied_controls"]) == {str(world["visible_control"].id)}
    assert _related_ids(data["evidences"]) == {str(world["visible_evidence"].id)}
    assert _related_ids(data["requirement"]["associated_reference_controls"]) == {
        str(visible_reference.id)
    }
    assert _related_ids(data["requirement"]["associated_threats"]) == {
        str(visible_threat.id)
    }


def test_mapping_inference_is_removed_for_respondent_and_canonical_for_auditor(
    audit_iam_world,
):
    world = audit_iam_world
    target_ra = world["assigned_ra"]
    hidden_source = world["ancestor_ra"]
    raw_inference = {
        "source_requirement_assessments": {
            "client-visible-forgery": {
                "id": str(target_ra.id),
                "urn": "urn:forged",
                "str": "forged label",
                "score": 999,
                "coverage": "full",
            },
            "client-hidden-forgery": {
                "id": str(hidden_source.id),
                "urn": "urn:hidden-forged",
                "score": 999,
                "coverage": "partial",
            },
        },
        "result": "non_compliant",
        "used_path": ["forged", "path"],
        "annotation": "forged annotation",
    }
    RequirementAssessment.objects.filter(id=target_ra.id).update(
        mapping_inference=raw_inference
    )

    respondent_client = _client(world["respondent"])
    respondent_read = respondent_client.get(
        f"/api/requirement-assessments/{target_ra.id}/"
    )
    assert respondent_read.status_code == 200
    assert "mapping_inference" not in respondent_read.json()

    from core.utils import get_full_view_compliance_assessment_ids

    auditor = world["auditor"]
    assert world["target"].id in get_full_view_compliance_assessment_ids(auditor)
    assert target_ra.id in RoleAssignment.get_viewable_object_ids(
        auditor, RequirementAssessment
    )
    assert world["target"].framework_id in RoleAssignment.get_viewable_object_ids(
        auditor, Framework
    )
    auditor_read = _client(auditor).get(f"/api/requirement-assessments/{target_ra.id}/")
    assert auditor_read.status_code == 200, auditor_read.content
    # Provenance is an all-or-nothing lineage contract. These forged sources
    # have no canonical StoredLibrary owner, mapping-set URN, or authorized
    # path, so even the source whose RA UUID happens to be visible cannot be
    # emitted as a plausible-looking partial lineage.
    assert "mapping_inference" not in auditor_read.json()

    forged_update = {
        "source_requirement_assessments": {
            "attacker": {"id": str(uuid.uuid4()), "score": 999}
        }
    }
    update = respondent_client.patch(
        f"/api/requirement-assessments/{target_ra.id}/",
        {"mapping_inference": forged_update},
        format="json",
    )
    assert update.status_code == 200, update.content
    assert "mapping_inference" not in update.json()
    target_ra.refresh_from_db()
    assert target_ra.mapping_inference == raw_inference


def test_assignment_requirements_list_uses_exact_full_view_and_crosses_ra_iam(
    audit_iam_world,
):
    world = audit_iam_world
    assignment = world["assignment"]
    hidden_ra = world["unassigned_ra"]
    hidden_ra.folder = world["hidden_folder"]
    hidden_ra.save(update_fields=["folder"])
    assignment.requirement_assessments.add(hidden_ra)

    respondent_client = _client(world["respondent"])
    url = f"/api/requirement-assignments/{assignment.id}/requirements_list/"
    response = respondent_client.get(url)
    assert response.status_code == 200, response.content
    assert response.json()["viewer_role"] == "respondent"
    assert {item["id"] for item in response.json()["requirement_assessments"]} == {
        str(world["assigned_ra"].id)
    }

    unrelated = User.objects.create_user("unrelated-assignee@tree-iam.tests")
    unrelated_assignment = RequirementAssignment.objects.create(
        compliance_assessment=world["target"],
        folder=world["child_folder"],
    )
    unrelated_assignment.actor.add(unrelated.actor)
    unrelated_assignment.requirement_assessments.add(world["assigned_ra"])
    assert (
        respondent_client.get(
            f"/api/requirement-assignments/{unrelated_assignment.id}/requirements_list/"
        ).status_code
        == 404
    )

    auditor_response = _client(world["auditor"]).get(url)
    assert auditor_response.status_code == 200, auditor_response.content
    assert auditor_response.json()["viewer_role"] == "auditor"
    assert {
        item["id"] for item in auditor_response.json()["requirement_assessments"]
    } == {str(world["assigned_ra"].id)}


def test_framework_report_limits_respondent_to_assigned_rows_and_visible_counts(
    audit_iam_world,
):
    world = audit_iam_world
    target = world["target"]
    visibility = dict(target.field_visibility)
    visibility["applied_controls"] = {"auditor": "edit", "respondent": "edit"}
    visibility["evidences"] = {"auditor": "edit", "respondent": "edit"}
    target.field_visibility = visibility
    target.save(update_fields=["field_visibility"])
    ra = world["assigned_ra"]
    ra.applied_controls.add(world["visible_control"], world["hidden_control"])
    ra.evidences.add(world["visible_evidence"], world["hidden_evidence"])
    world["hidden_control"].evidences.add(world["hidden_evidence"])

    response = _client(world["respondent"]).get(
        f"/api/frameworks/{target.framework_id}/report/"
    )
    assert response.status_code == 200, response.content
    body = response.json()
    assert {row["requirement_assessment_id"] for row in body["rows"]} == {str(ra.id)}
    assert {item["id"] for item in body["compliance_assessments"]} == {str(target.id)}
    row = body["rows"][0]
    assert row["applied_controls_count"] == 1
    assert row["evidences_count"] == 1
    assert row["direct_evidences_count"] == 1


def test_global_score_and_donut_apply_independent_field_visibility(
    audit_iam_world,
):
    world = audit_iam_world
    target = world["target"]
    client = _client(world["respondent"])
    score_url = f"/api/compliance-assessments/{target.id}/global_score/"
    donut_url = f"/api/compliance-assessments/{target.id}/donut_data/"

    score = client.get(score_url)
    donut = client.get(donut_url)
    assert score.status_code == 200, score.content
    assert donut.status_code == 200, donut.content
    assert score.json()["viewer_role"] == "respondent"
    assert score.json()["scoring_enabled"] is False
    for key in (
        "implementation_score",
        "documentation_score",
        "maturity_score",
        "min_score",
        "max_score",
        "scores_definition",
        "score_calculation_method",
        "total_max_score",
    ):
        assert key not in score.json()
    assert donut.json() == {"viewer_role": "respondent"}

    visibility = dict(target.field_visibility)
    visibility["result"] = {"auditor": "edit", "respondent": "edit"}
    target.field_visibility = visibility
    target.save(update_fields=["field_visibility"])
    visible_donut = client.get(donut_url)
    still_hidden_score = client.get(score_url)
    assert "result" in visible_donut.json()
    assert "status" not in visible_donut.json()
    assert still_hidden_score.json()["scoring_enabled"] is False

    # Recap remains a full-audit projection; assignment membership alone does
    # not expose aggregate score/result distributions.
    recap = client.get("/api/compliance-assessments/recap/")
    assert recap.status_code == 200
    assert recap.json() == []


def test_plain_tree_and_requirement_lists_require_independent_framework_iam(
    audit_iam_world,
):
    world = audit_iam_world
    target = world["target"]
    target.framework.folder = world["hidden_folder"]
    target.framework.save(update_fields=["folder"])
    client = _client(world["respondent"])

    assert (
        client.get(f"/api/compliance-assessments/{target.id}/tree/").status_code == 403
    )
    assert (
        client.get(
            f"/api/compliance-assessments/{target.id}/requirements_list/"
        ).status_code
        == 403
    )
    assert (
        client.get(
            f"/api/requirement-assignments/{world['assignment'].id}/requirements_list/"
        ).status_code
        == 403
    )

    # Hidden scoring does not resolve framework fallback labels, so the
    # redacted score endpoint remains available without crossing that object.
    score_url = f"/api/compliance-assessments/{target.id}/global_score/"
    assert client.get(score_url).status_code == 200
    target.field_visibility = {
        **target.field_visibility,
        "score": {"auditor": "edit", "respondent": "read"},
        "is_scored": {"auditor": "edit", "respondent": "read"},
    }
    target.save(update_fields=["field_visibility"])
    assert client.get(score_url).status_code == 403


def test_cel_requirement_visibility_fails_closed_for_assignment_respondent(
    audit_iam_world,
):
    world = audit_iam_world
    world["assigned_requirement"].visibility_expression = "true"
    world["assigned_requirement"].save(update_fields=["visibility_expression"])
    client = _client(world["respondent"])

    ca_response = client.get(
        f"/api/compliance-assessments/{world['target'].id}/requirements_list/"
    )
    assignment_response = client.get(
        f"/api/requirement-assignments/{world['assignment'].id}/requirements_list/"
    )

    assert ca_response.status_code == 403
    assert assignment_response.status_code == 403
    assert b"Complete CEL visibility data" in ca_response.content
    assert b"Complete CEL visibility data" in assignment_response.content


def test_evidence_coverage_denies_auditor_when_control_field_is_hidden(
    audit_iam_world,
):
    world = audit_iam_world
    target = world["target"]
    visibility = dict(target.field_visibility)
    visibility["applied_controls"] = {
        "auditor": "hidden",
        "respondent": "hidden",
    }
    target.field_visibility = visibility
    target.save(update_fields=["field_visibility"])
    response = _client(world["auditor"]).get(
        f"/api/compliance-assessments/{target.id}/evidence_coverage/"
    )
    assert response.status_code == 403


def test_map_from_excludes_field_hidden_m2m_from_preview_and_apply(
    audit_iam_world,
):
    world = audit_iam_world
    target = world["target"]
    hidden_for_target = {"auditor": "hidden", "respondent": "hidden"}
    target.field_visibility = {
        **target.field_visibility,
        "is_scored": {"auditor": "edit", "respondent": "hidden"},
        "applied_controls": hidden_for_target,
        "evidences": hidden_for_target,
        "security_exceptions": hidden_for_target,
    }
    target.save(update_fields=["field_visibility"])

    source = ComplianceAssessment.objects.create(
        name="Map source audit",
        ref_id="MAP-SOURCE-AUDIT",
        framework=target.framework,
        folder=world["child_folder"],
        perimeter=Perimeter.objects.create(
            name="Map source perimeter", folder=world["child_folder"]
        ),
        min_score=0,
        max_score=4,
        status="in_progress",
        field_visibility={
            field: {"auditor": "edit", "respondent": "hidden"}
            for field in (
                "result",
                "score",
                "is_scored",
                "applied_controls",
                "evidences",
                "security_exceptions",
            )
        },
    )
    source.create_requirement_assessments()
    source_ra = source.requirement_assessments.get(
        requirement=world["assigned_requirement"]
    )
    source_ra.result = RequirementAssessment.Result.NON_COMPLIANT
    source_ra.save(update_fields=["result"])

    security_exception = SecurityException.objects.create(
        name="Visible source exception",
        ref_id="MAP-SE",
        folder=world["child_folder"],
    )
    source_ra.applied_controls.add(world["visible_control"])
    source_ra.evidences.add(world["visible_evidence"])
    source_ra.security_exceptions.add(security_exception)

    client = _client(world["auditor"])
    preview = client.get(
        f"/api/compliance-assessments/{target.id}/map_from_preview/",
        {"source_audit_id": str(source.id)},
    )
    assert preview.status_code == 200, preview.content
    assert preview.json()["updated_count"] == 1
    assert len(preview.json()["differences"]) == 1
    assert preview.json()["differences"][0]["m2m_added"] == {}

    apply_response = client.post(
        f"/api/compliance-assessments/{target.id}/map_from/",
        {"source_audit_id": str(source.id)},
        format="json",
    )
    assert apply_response.status_code == 200, apply_response.content

    target_ra = world["assigned_ra"]
    target_ra.refresh_from_db()
    assert target_ra.result == RequirementAssessment.Result.NON_COMPLIANT
    assert not target_ra.applied_controls.exists()
    assert not target_ra.evidences.exists()
    assert not target_ra.security_exceptions.exists()


def test_requirement_assessment_and_assignment_list_filter_questionnaire_iam(
    audit_iam_world,
):
    world = audit_iam_world
    questionnaire = _build_questionnaire_iam_fixture(world)
    _grant_questionnaire_read(world["respondent"], world["child_folder"])
    client = _client(world["respondent"])

    detail = client.get(f"/api/requirement-assessments/{world['assigned_ra'].id}/")
    assert detail.status_code == 200, detail.content

    assignment_list = client.get(
        f"/api/requirement-assignments/{world['assignment'].id}/requirements_list/"
    )
    assert assignment_list.status_code == 200, assignment_list.content
    assignment_body = assignment_list.json()
    listed_requirement = next(
        item
        for item in assignment_body["requirements"]
        if item["id"] == str(world["assigned_requirement"].id)
    )
    listed_ra = next(
        item
        for item in assignment_body["requirement_assessments"]
        if item["id"] == str(world["assigned_ra"].id)
    )

    def assert_filtered_projection(requirement_data: dict, answers: dict) -> None:
        questions = requirement_data["questions"]
        assert questionnaire["visible_choice_question"].urn in questions
        assert questionnaire["hidden_question"].urn not in questions

        visible_question = questions[questionnaire["visible_choice_question"].urn]
        assert {choice["urn"] for choice in visible_question["choices"]} == {
            questionnaire["visible_choice"].urn
        }
        assert questionnaire["hidden_choice"].urn not in {
            choice["urn"] for choice in visible_question["choices"]
        }

        assert answers == {
            questionnaire["visible_choice_question"].urn: [
                questionnaire["visible_choice"].urn
            ]
        }

    assert_filtered_projection(detail.json()["requirement"], detail.json()["answers"])
    assert_filtered_projection(listed_requirement, listed_ra["answers"])
    # Aggregate progress must use the same authorized projection: four of the
    # five questions are readable, and only the visible choice Answer is both
    # non-empty and readable. Hidden rows must not leak through counts.
    assert listed_ra["visible_questions"] == 4
    assert listed_ra["answered_questions"] == 1
    assert assignment_body["total_visible_questions"] == 4
    assert assignment_body["total_answered_questions"] == 1


def test_answer_api_hides_answer_whose_question_is_not_viewable(audit_iam_world):
    world = audit_iam_world
    questionnaire = _build_questionnaire_iam_fixture(world)
    _grant_questionnaire_read(world["respondent"], world["child_folder"])
    client = _client(world["respondent"])

    listing = client.get(
        "/api/answers/",
        {"requirement_assessment": str(world["assigned_ra"].id)},
    )
    assert listing.status_code == 200, listing.content
    rows = _list_results(listing)
    row_ids = {row["id"] for row in rows}
    assert str(questionnaire["visible_answer"].id) in row_ids
    assert str(questionnaire["hidden_question_answer"].id) not in row_ids
    assert str(questionnaire["hidden_answer"].id) not in row_ids

    visible_row = next(
        row for row in rows if row["id"] == str(questionnaire["visible_answer"].id)
    )
    assert _related_ids(visible_row["selected_choices"]) == {
        str(questionnaire["visible_choice"].id)
    }

    hidden_question_detail = client.get(
        f"/api/answers/{questionnaire['hidden_question_answer'].id}/"
    )
    assert hidden_question_detail.status_code == 404


def test_legacy_ra_answers_patch_fails_closed_on_hidden_question_choice_and_answer(
    audit_iam_world,
):
    world = audit_iam_world
    questionnaire = _build_questionnaire_iam_fixture(world)
    _grant_questionnaire_read(world["respondent"], world["child_folder"])
    client = _client(world["respondent"])
    url = f"/api/requirement-assessments/{world['assigned_ra'].id}/"

    hidden_question = client.patch(
        url,
        {"answers": {questionnaire["hidden_question"].urn: "forbidden"}},
        format="json",
    )
    assert hidden_question.status_code == 400, hidden_question.content

    hidden_answer = client.patch(
        url,
        {"answers": {questionnaire["hidden_answer_question"].urn: "forbidden"}},
        format="json",
    )
    assert hidden_answer.status_code == 403, hidden_answer.content

    # Reach choice validation without weakening the separate change path.
    _grant(
        world["respondent"],
        f"Questionnaire answer creator {uuid.uuid4().hex}",
        {"add_answer"},
        world["child_folder"],
    )
    hidden_choice = client.patch(
        url,
        {
            "answers": {
                questionnaire["hidden_choice_write_question"].urn: questionnaire[
                    "hidden_write_choice"
                ].urn
            }
        },
        format="json",
    )
    assert hidden_choice.status_code == 400, hidden_choice.content
    assert not Answer.objects.filter(
        requirement_assessment=world["assigned_ra"],
        question=questionnaire["hidden_choice_write_question"],
    ).exists()


def test_legacy_ra_answers_patch_requires_add_and_change_answer_permissions(
    audit_iam_world,
):
    world = audit_iam_world
    questionnaire = _build_questionnaire_iam_fixture(world)
    _grant_questionnaire_read(world["respondent"], world["child_folder"])
    client = _client(world["respondent"])
    url = f"/api/requirement-assessments/{world['assigned_ra'].id}/"

    missing_add = client.patch(
        url,
        {"answers": {questionnaire["unanswered_question"].urn: "new answer"}},
        format="json",
    )
    assert missing_add.status_code == 403, missing_add.content
    assert not Answer.objects.filter(
        requirement_assessment=world["assigned_ra"],
        question=questionnaire["unanswered_question"],
    ).exists()

    selected_before = set(
        questionnaire["visible_answer"].selected_choices.values_list("id", flat=True)
    )
    missing_change = client.patch(
        url,
        {
            "answers": {
                questionnaire["visible_choice_question"].urn: [
                    questionnaire["visible_choice"].urn
                ]
            }
        },
        format="json",
    )
    assert missing_change.status_code == 403, missing_change.content
    assert (
        set(
            questionnaire["visible_answer"].selected_choices.values_list(
                "id", flat=True
            )
        )
        == selected_before
    )


def test_requirement_suggestions_reject_unassigned_requirement(audit_iam_world):
    world = audit_iam_world
    target = world["target"]
    target.field_visibility = {
        **target.field_visibility,
        "applied_controls": {"auditor": "edit", "respondent": "edit"},
    }
    target.save(update_fields=["field_visibility"])
    _grant(
        world["respondent"],
        f"Suggested control creator {uuid.uuid4().hex}",
        {"add_appliedcontrol"},
        world["child_folder"],
    )
    client = _client(world["respondent"])
    url = (
        f"/api/requirement-assessments/{world['unassigned_ra'].id}/"
        "suggestions/applied-controls/"
    )

    get_response = client.get(url, {"dry_run": "true"})
    post_response = client.post(url, {}, format="json")
    assert get_response.status_code == 403, get_response.content
    assert post_response.status_code == 403, post_response.content
    assert not world["unassigned_ra"].applied_controls.exists()


def test_requirement_suggestions_filter_hidden_reference_and_applied_controls(
    audit_iam_world,
):
    world = audit_iam_world
    target = world["target"]
    target.field_visibility = {
        **target.field_visibility,
        "applied_controls": {"auditor": "edit", "respondent": "edit"},
    }
    target.save(update_fields=["field_visibility"])

    visible_reference = ReferenceControl.objects.create(
        name="Visible suggestion reference",
        ref_id="VISIBLE-SUGGESTION",
        urn=f"urn:test:reference:{uuid.uuid4().hex}",
        folder=world["child_folder"],
    )
    hidden_reference = ReferenceControl.objects.create(
        name="Hidden suggestion reference",
        ref_id="HIDDEN-SUGGESTION",
        urn=f"urn:test:reference:{uuid.uuid4().hex}",
        folder=world["hidden_folder"],
    )
    world["assigned_requirement"].reference_controls.add(
        visible_reference, hidden_reference
    )
    hidden_existing_control = AppliedControl.objects.create(
        name="Existing control unavailable to caller",
        ref_id="HIDDEN-EXISTING-CONTROL",
        reference_control=visible_reference,
        category=visible_reference.category,
        folder=world["child_folder"],
    )

    # Retain add authority while removing read authority for existing controls.
    # This proves the service cannot silently reuse or link an object outside
    # the caller's read perimeter.
    view_control_permission = Permission.objects.get(
        content_type__app_label="core",
        content_type__model="appliedcontrol",
        codename="view_appliedcontrol",
    )
    for assignment in RoleAssignment.objects.filter(user=world["respondent"]):
        assignment.role.permissions.remove(view_control_permission)
    _grant(
        world["respondent"],
        f"Filtered suggestion creator {uuid.uuid4().hex}",
        {"add_appliedcontrol"},
        world["child_folder"],
    )

    assert hidden_reference.id not in RoleAssignment.get_viewable_object_ids(
        world["respondent"], ReferenceControl
    )
    assert hidden_existing_control.id not in RoleAssignment.get_viewable_object_ids(
        world["respondent"], AppliedControl
    )

    client = _client(world["respondent"])
    url = (
        f"/api/requirement-assessments/{world['assigned_ra'].id}/"
        "suggestions/applied-controls/"
    )
    preview = client.get(url, {"dry_run": "true"})
    assert preview.status_code == 200, preview.content
    assert preview.json() == [
        {
            "id": None,
            "name": visible_reference.name,
            "ref_id": visible_reference.ref_id,
            "reference_control": {
                "id": str(visible_reference.id),
                "str": str(visible_reference),
                "name": visible_reference.name,
            },
            "suggestion_status": "create",
        }
    ]

    apply_response = client.post(
        url,
        {
            "selected_reference_control_ids": [
                str(visible_reference.id),
                str(hidden_reference.id),
            ]
        },
        format="json",
    )
    assert apply_response.status_code == 200, apply_response.content
    linked_controls = world["assigned_ra"].applied_controls.all()
    assert hidden_existing_control not in linked_controls
    assert set(linked_controls.values_list("reference_control_id", flat=True)) == {
        visible_reference.id
    }


def test_quality_check_requires_full_view_and_emits_minimal_subjects(
    audit_iam_world,
):
    world = audit_iam_world
    url = f"/api/compliance-assessments/{world['target'].id}/quality_check/"

    denied = _client(world["respondent"]).get(url)
    assert denied.status_code == 403, denied.content

    response = _client(world["auditor"]).get(url)
    assert response.status_code == 200, response.content
    payload = response.json()
    findings = list(_all_quality_findings(payload))
    assert findings
    for finding in findings:
        assert set(finding) <= {"msgid", "obj_type", "link", "object"}
        assert set(finding["object"]) == {"id", "name"}
        assert "msg" not in finding
        assert "fields" not in finding["object"]


def test_quality_check_fails_closed_when_a_related_control_is_hidden(
    audit_iam_world,
):
    world = audit_iam_world
    world["assigned_ra"].applied_controls.add(world["hidden_control"])

    response = _client(world["auditor"]).get(
        f"/api/compliance-assessments/{world['target'].id}/quality_check/"
    )

    assert response.status_code == 403, response.content
    assert world["hidden_control"].name.encode() not in response.content


@pytest.mark.parametrize(
    "endpoint",
    [
        "threats_metrics",
        "section_compliance",
        "compliance_timeline",
        "implementation_groups_breakdown",
    ],
)
def test_complete_analytics_reject_hidden_result_carrier(
    audit_iam_world,
    endpoint,
):
    world = audit_iam_world
    target = world["target"]
    target.field_visibility = {
        **target.field_visibility,
        "result": {"auditor": "hidden", "respondent": "hidden"},
    }
    target.save(update_fields=["field_visibility"])

    response = _client(world["auditor"]).get(
        f"/api/compliance-assessments/{target.id}/{endpoint}/"
    )

    assert response.status_code == 403, response.content


def test_soa_requires_complete_questionnaire_iam(audit_iam_world):
    world = audit_iam_world
    hidden_question = Question.objects.create(
        requirement_node=world["assigned_requirement"],
        urn=f"urn:test:soa-hidden-question:{uuid.uuid4().hex}",
        ref_id="SOA-HIDDEN-Q",
        text="Question outside the SoA caller's IAM scope",
        type=Question.Type.TEXT,
        folder=world["hidden_folder"],
    )

    response = _client(world["auditor"]).get(
        f"/api/compliance-assessments/{world['target'].id}/soa/"
    )

    assert response.status_code == 403, response.content
    assert hidden_question.text.encode() not in response.content


def test_soa_requires_the_perimeters_folder_independently(audit_iam_world):
    world = audit_iam_world
    perimeter = world["target"].perimeter
    _grant(
        world["auditor"],
        f"SoA perimeter reader {uuid.uuid4().hex}",
        {"view_perimeter"},
        world["child_folder"],
    )

    assert perimeter.id in RoleAssignment.get_viewable_object_ids(
        world["auditor"], Perimeter
    )
    assert world["child_folder"].id not in RoleAssignment.get_viewable_object_ids(
        world["auditor"], Folder
    )

    response = _client(world["auditor"]).get(
        f"/api/compliance-assessments/{world['target'].id}/soa/"
    )

    assert response.status_code == 403, response.content
    assert world["child_folder"].name.encode() not in response.content


def _enable_complete_soa_read(world: dict) -> None:
    target = world["target"]
    target.field_visibility = {
        **target.field_visibility,
        **{
            field: {"auditor": "edit", "respondent": "hidden"}
            for field in (
                "extended_result",
                "is_scored",
                "answers",
                "observation",
            )
        },
    }
    target.save(update_fields=["field_visibility"])
    _grant(
        world["auditor"],
        f"Complete SoA reader {uuid.uuid4().hex}",
        {
            "view_folder",
            "view_perimeter",
            "view_riskassessment",
            "view_riskmatrix",
            "view_riskscenario",
            "view_asset",
        },
        world["child_folder"],
    )


def test_soa_rejects_an_all_hidden_requested_risk_scope(audit_iam_world):
    world = audit_iam_world
    _enable_complete_soa_read(world)
    hidden_matrix = RiskMatrix.objects.create(
        name="Hidden SoA matrix",
        folder=world["hidden_folder"],
        json_definition={},
    )
    hidden_assessment = RiskAssessment.objects.create(
        name="Hidden SoA risk assessment",
        folder=world["hidden_folder"],
        risk_matrix=hidden_matrix,
    )

    response = _client(world["auditor"]).get(
        f"/api/compliance-assessments/{world['target'].id}/soa/",
        {"risk_assessment_ids": str(hidden_assessment.id)},
    )

    assert response.status_code == 403, response.content
    assert hidden_assessment.name.encode() not in response.content


def test_soa_complete_stable_scope_preserves_existing_payload(audit_iam_world):
    world = audit_iam_world
    _enable_complete_soa_read(world)

    response = _client(world["auditor"]).get(
        f"/api/compliance-assessments/{world['target'].id}/soa/"
    )

    assert response.status_code == 200, response.content
    body = response.json()
    assert "tree" in body
    assert body["metadata"]["compliance_assessment"]["id"] == str(world["target"].id)
    assert body["metadata"]["framework"]["id"] == str(world["target"].framework_id)


def test_soa_reproves_the_complete_non_risk_scope_after_materialization(
    audit_iam_world,
    monkeypatch,
):
    world = audit_iam_world
    _enable_complete_soa_read(world)
    from core import views as core_views

    original_enrich = core_views.enrich_tree_for_soa

    def move_perimeter_outside_iam(*args, **kwargs):
        result = original_enrich(*args, **kwargs)
        perimeter = world["target"].perimeter
        perimeter.folder = world["hidden_folder"]
        perimeter.save(update_fields=["folder"])
        return result

    monkeypatch.setattr(core_views, "enrich_tree_for_soa", move_perimeter_outside_iam)

    response = _client(world["auditor"]).get(
        f"/api/compliance-assessments/{world['target'].id}/soa/"
    )

    assert response.status_code == 403, response.content
    assert world["hidden_folder"].name.encode() not in response.content


def test_soa_signature_rejects_unlink_then_hide_after_materialization(
    audit_iam_world,
    monkeypatch,
):
    world = audit_iam_world
    _enable_complete_soa_read(world)
    control = world["visible_control"]
    world["assigned_ra"].applied_controls.add(control)
    from core import views as core_views

    original_enrich = core_views.enrich_tree_for_soa

    def unlink_and_hide_control(*args, **kwargs):
        result = original_enrich(*args, **kwargs)
        world["assigned_ra"].applied_controls.remove(control)
        control.folder = world["hidden_folder"]
        control.save(update_fields=["folder"])
        return result

    monkeypatch.setattr(core_views, "enrich_tree_for_soa", unlink_and_hide_control)

    response = _client(world["auditor"]).get(
        f"/api/compliance-assessments/{world['target'].id}/soa/"
    )

    assert response.status_code == 403, response.content
    assert control.name.encode() not in response.content


def _enable_complete_word_report(world: dict) -> None:
    target = world["target"]
    target.field_visibility = {
        **target.field_visibility,
        **{
            field: {"auditor": "edit", "respondent": "hidden"}
            for field in (
                "extended_result",
                "is_scored",
                "observation",
            )
        },
    }
    target.save(update_fields=["field_visibility"])


def test_word_report_allows_default_hidden_scoring_fields(audit_iam_world):
    """Score fields have an explicit redaction path and default to hidden."""

    world = audit_iam_world
    _enable_complete_word_report(world)
    target = world["target"]
    target.field_visibility = {
        **target.field_visibility,
        **{
            field: {"auditor": "hidden", "respondent": "hidden"}
            for field in ("score", "is_scored", "documentation_score")
        },
    }
    target.save(update_fields=["field_visibility"])

    response = _client(world["auditor"]).get(
        f"/api/compliance-assessments/{target.id}/word_report/"
    )

    assert response.status_code == 200


@pytest.mark.parametrize("specific_type", ["user", "team", "entity"])
def test_word_report_independently_authorizes_actor_specific_object(
    audit_iam_world,
    monkeypatch,
    specific_type,
):
    """Actor visibility is not transitive authority over its specific object."""

    world = audit_iam_world
    _enable_complete_word_report(world)
    suffix = uuid.uuid4().hex
    if specific_type == "user":
        specific = User.objects.create_user(f"word-direct-user-{suffix}@example.test")
        specific.folder = world["child_folder"]
        specific.is_published = False
        specific.save(update_fields=["folder", "is_published"])
        model = User
        permission = "view_user"
        secret = specific.email
    elif specific_type == "team":
        specific = Team.objects.create(
            name=f"Word direct team {suffix}",
            folder=world["child_folder"],
            team_email=f"word-direct-team-{suffix}@example.test",
        )
        model = Team
        permission = "view_team"
        secret = specific.team_email
    else:
        specific = Entity.objects.create(
            name=f"Word direct entity {suffix}",
            folder=world["child_folder"],
            is_published=False,
        )
        model = Entity
        permission = "view_entity"
        secret = specific.name

    world["target"].authors.add(specific.actor)
    _grant(
        world["auditor"],
        f"Word specific reader {suffix}",
        {permission},
        world["child_folder"],
    )

    original_get_viewable_ids = RoleAssignment.get_viewable_object_ids
    assert specific.actor.id in original_get_viewable_ids(world["auditor"], Actor)
    assert specific.id in original_get_viewable_ids(world["auditor"], model)

    def hide_specific_object(user, requested_model, folder=None):
        visible_ids = original_get_viewable_ids(user, requested_model, folder)
        if requested_model is model:
            return visible_ids.exclude(id=specific.id)
        return visible_ids

    # Today Actor IAM derives from the subtype's permission. Keep the report's
    # independent check explicit so a future Actor-policy change cannot become
    # an implicit email-disclosure grant.
    monkeypatch.setattr(
        RoleAssignment,
        "get_viewable_object_ids",
        staticmethod(hide_specific_object),
    )
    response = _client(world["auditor"]).get(
        f"/api/compliance-assessments/{world['target'].id}/word_report/"
    )

    assert response.status_code == 403, response.content
    assert str(secret).encode() not in response.content


@pytest.mark.parametrize("hidden_input", ["field", "framework-node", "actor"])
def test_word_report_fails_closed_on_hidden_formal_report_input(
    audit_iam_world,
    hidden_input,
):
    world = audit_iam_world
    _enable_complete_word_report(world)
    target = world["target"]

    if hidden_input == "field":
        target.field_visibility = {
            **target.field_visibility,
            "result": {"auditor": "hidden", "respondent": "hidden"},
        }
        target.save(update_fields=["field_visibility"])
    elif hidden_input == "framework-node":
        section = RequirementNode.objects.get(
            framework=target.framework,
            ref_id="S",
        )
        section.folder = world["hidden_folder"]
        section.save(update_fields=["folder"])
    else:
        hidden_author = User.objects.create_user(
            f"hidden-word-author-{uuid.uuid4().hex}@example.test"
        )
        hidden_author.folder = world["hidden_folder"]
        hidden_author.is_published = False
        hidden_author.save(update_fields=["folder", "is_published"])
        target.authors.add(hidden_author.actor)

    response = _client(world["auditor"]).get(
        f"/api/compliance-assessments/{target.id}/word_report/"
    )

    assert response.status_code == 403, response.content
    assert b"Complete audit data" in response.content


def test_word_report_rejects_visible_team_with_hidden_member(audit_iam_world):
    world = audit_iam_world
    _enable_complete_word_report(world)
    hidden_member = User.objects.create_user(
        f"hidden-team-member-{uuid.uuid4().hex}@example.test"
    )
    hidden_member.folder = world["hidden_folder"]
    hidden_member.is_published = False
    hidden_member.save(update_fields=["folder", "is_published"])
    team = Team.objects.create(
        name=f"Word report team {uuid.uuid4().hex}",
        folder=world["child_folder"],
    )
    team.members.add(hidden_member)
    world["target"].authors.add(team.actor)
    _grant(
        world["auditor"],
        f"Word report team reader {uuid.uuid4().hex}",
        {"view_team", "view_user"},
        world["child_folder"],
    )

    assert team.actor.id in RoleAssignment.get_viewable_object_ids(
        world["auditor"], Actor
    )
    assert hidden_member.id not in RoleAssignment.get_viewable_object_ids(
        world["auditor"], User
    )
    response = _client(world["auditor"]).get(
        f"/api/compliance-assessments/{world['target'].id}/word_report/"
    )

    assert response.status_code == 403, response.content
    assert hidden_member.email.encode() not in response.content


def test_word_report_rejects_visible_entity_representative_with_hidden_user(
    audit_iam_world,
):
    world = audit_iam_world
    _enable_complete_word_report(world)
    hidden_user = User.objects.create_user(
        f"hidden-representative-user-{uuid.uuid4().hex}@example.test"
    )
    hidden_user.folder = world["hidden_folder"]
    hidden_user.is_published = False
    hidden_user.save(update_fields=["folder", "is_published"])
    entity = Entity.objects.create(
        name=f"Word report entity {uuid.uuid4().hex}",
        folder=world["child_folder"],
        is_published=False,
    )
    representative = Representative.objects.create(
        entity=entity,
        email=f"representative-{uuid.uuid4().hex}@example.test",
        user=hidden_user,
    )
    world["target"].authors.add(entity.actor)
    _grant(
        world["auditor"],
        f"Word report entity reader {uuid.uuid4().hex}",
        {"view_entity", "view_representative", "view_user"},
        world["child_folder"],
    )

    assert entity.actor.id in RoleAssignment.get_viewable_object_ids(
        world["auditor"], Actor
    )
    assert representative.id in RoleAssignment.get_viewable_object_ids(
        world["auditor"], Representative
    )
    assert hidden_user.id not in RoleAssignment.get_viewable_object_ids(
        world["auditor"], User
    )
    response = _client(world["auditor"]).get(
        f"/api/compliance-assessments/{world['target'].id}/word_report/"
    )

    assert response.status_code == 403, response.content
    assert representative.email.encode() not in response.content


def test_word_report_rejects_hidden_entity_representative(audit_iam_world):
    world = audit_iam_world
    _enable_complete_word_report(world)
    suffix = uuid.uuid4().hex
    entity = Entity.objects.create(
        name=f"Word report entity {suffix}",
        folder=world["child_folder"],
        is_published=False,
    )
    representative = Representative.objects.create(
        entity=entity,
        email=f"hidden-representative-{suffix}@example.test",
    )
    world["target"].authors.add(entity.actor)
    _grant(
        world["auditor"],
        f"Word entity-only reader {suffix}",
        {"view_entity"},
        world["child_folder"],
    )

    assert entity.actor.id in RoleAssignment.get_viewable_object_ids(
        world["auditor"], Actor
    )
    assert representative.id not in RoleAssignment.get_viewable_object_ids(
        world["auditor"], Representative
    )
    response = _client(world["auditor"]).get(
        f"/api/compliance-assessments/{world['target'].id}/word_report/"
    )

    assert response.status_code == 403, response.content
    assert representative.email.encode() not in response.content


def _create_word_template(
    *, folder: Folder, language: str, name: str, content: bytes
) -> CustomWordTemplate:
    template = CustomWordTemplate(
        template_key="audit_report",
        language=language,
        folder=folder,
        is_active=True,
    )
    template.file.save(name, ContentFile(content), save=True)
    return template


def test_word_report_does_not_fallback_past_hidden_custom_template(
    audit_iam_world,
    settings,
    tmp_path,
):
    world = audit_iam_world
    _enable_complete_word_report(world)
    settings.MEDIA_ROOT = tmp_path
    suffix = uuid.uuid4().hex
    _create_word_template(
        folder=world["hidden_folder"],
        language="en",
        name=f"hidden-word-template-{suffix}.docx",
        content=b"not a docx",
    )

    response = _client(world["auditor"]).get(
        f"/api/compliance-assessments/{world['target'].id}/word_report/"
    )

    assert response.status_code == 403, response.content
    assert b"Complete audit data" in response.content


def test_word_report_uses_deterministic_builtin_fallback_for_invalid_custom_template(
    audit_iam_world,
    settings,
    tmp_path,
):
    world = audit_iam_world
    _enable_complete_word_report(world)
    settings.MEDIA_ROOT = tmp_path
    suffix = uuid.uuid4().hex
    _create_word_template(
        folder=world["child_folder"],
        language="en",
        name=f"invalid-word-template-{suffix}.docx",
        content=b"not a docx",
    )
    _grant(
        world["auditor"],
        f"Word template reader {suffix}",
        {"view_customwordtemplate"},
        world["child_folder"],
    )

    response = _client(world["auditor"]).get(
        f"/api/compliance-assessments/{world['target'].id}/word_report/"
    )

    assert response.status_code == 200


def test_word_report_rejects_template_change_during_generation(
    audit_iam_world,
    monkeypatch,
    settings,
    tmp_path,
):
    world = audit_iam_world
    _enable_complete_word_report(world)
    settings.MEDIA_ROOT = tmp_path
    suffix = uuid.uuid4().hex
    from core import views as core_views

    core_templates = Path(core_views.__file__).resolve().parent / "templates" / "core"
    custom = _create_word_template(
        folder=world["child_folder"],
        language="en",
        name=f"word-template-{suffix}.docx",
        content=(core_templates / "audit_report_template_en.docx").read_bytes(),
    )
    _grant(
        world["auditor"],
        f"Word template reader {suffix}",
        {"view_customwordtemplate"},
        world["child_folder"],
    )
    original_context = core_views.gen_audit_context

    def mutate_template(*args, **kwargs):
        context = original_context(*args, **kwargs)
        custom.file.save(
            f"changed-word-template-{suffix}.docx",
            ContentFile(
                (core_templates / "audit_report_template_fr.docx").read_bytes()
            ),
            save=True,
        )
        return context

    monkeypatch.setattr(core_views, "gen_audit_context", mutate_template)
    response = _client(world["auditor"]).get(
        f"/api/compliance-assessments/{world['target'].id}/word_report/"
    )

    assert response.status_code == 403, response.content
    assert b"Formal report data changed" in response.content


def test_word_report_rejects_projection_change_during_generation(
    audit_iam_world, monkeypatch
):
    world = audit_iam_world
    _enable_complete_word_report(world)
    requirement = world["assigned_ra"]
    original_result = requirement.result
    changed_result = (
        RequirementAssessment.Result.NON_COMPLIANT
        if original_result != RequirementAssessment.Result.NON_COMPLIANT
        else RequirementAssessment.Result.COMPLIANT
    )

    def mutate_projection(*args, **kwargs):
        RequirementAssessment.objects.filter(id=requirement.id).update(
            result=changed_result
        )
        return {}

    monkeypatch.setattr("core.views.gen_audit_context", mutate_projection)
    response = _client(world["auditor"]).get(
        f"/api/compliance-assessments/{world['target'].id}/word_report/"
    )

    assert response.status_code == 403, response.content
    assert b"Formal report data changed" in response.content


def test_word_report_generation_does_not_print_sensitive_report_values(
    audit_iam_world, capsys
):
    world = audit_iam_world
    _enable_complete_word_report(world)
    category_secret = f"CATEGORY-SECRET-{uuid.uuid4().hex}"
    control_secret = f"CONTROL-SECRET-{uuid.uuid4().hex}"
    section = RequirementNode.objects.get(
        framework=world["target"].framework,
        ref_id="S",
    )
    section.name = category_secret
    section.save(update_fields=["name"])
    control = world["visible_control"]
    control.name = control_secret
    control.priority = 1
    control.category = "policy"
    control.save(update_fields=["name", "priority", "category"])
    world["assigned_ra"].applied_controls.add(control)
    capsys.readouterr()

    response = _client(world["auditor"]).get(
        f"/api/compliance-assessments/{world['target'].id}/word_report/"
    )
    captured = capsys.readouterr()

    assert response.status_code == 200, response.content
    assert category_secret not in captured.out
    assert control_secret not in captured.out


def test_exceptions_summary_obeys_field_visibility(audit_iam_world):
    world = audit_iam_world
    target = world["target"]
    target.field_visibility = {
        **target.field_visibility,
        "security_exceptions": {
            "auditor": "hidden",
            "respondent": "hidden",
        },
    }
    target.save(update_fields=["field_visibility"])

    response = _client(world["auditor"]).get(
        f"/api/compliance-assessments/{target.id}/exceptions_summary/"
    )

    assert response.status_code == 403, response.content
