"""Authority and concurrency regressions for same-framework baseline clones."""

from __future__ import annotations

import uuid

import pytest
from auditlog.models import LogEntry
from django.contrib.auth.models import Permission
from django.contrib.contenttypes.models import ContentType
from django.core.exceptions import ValidationError as DjangoValidationError
from django.db import IntegrityError, transaction
from django.db.models import QuerySet
from iam.models import Folder, Role, RoleAssignment, User
from rest_framework.test import APIClient

from core.models import (
    Answer,
    AppliedControl,
    ComplianceAssessment,
    Evidence,
    Framework,
    HistoricalMetric,
    Perimeter,
    Question,
    QuestionChoice,
    RequirementAssessment,
    RequirementNode,
)

pytestmark = pytest.mark.django_db


COPY_FIELDS = (
    "result",
    "status",
    "score",
    "is_scored",
    "is_score_overridden",
    "documentation_score",
    "observation",
    "answers",
    "applied_controls",
    "evidences",
)
COPY_POLICY = {
    field: {"auditor": "edit", "respondent": "hidden"} for field in COPY_FIELDS
}


def _grant_clone_access(user: User, folder: Folder) -> None:
    role = Role.objects.create(
        name=f"Baseline clone {uuid.uuid4().hex}",
        folder=Folder.get_root_folder(),
    )
    role.permissions.set(
        Permission.objects.filter(
            codename__in={
                "add_complianceassessment",
                "change_complianceassessment",
                "view_complianceassessment",
                "view_compliance_assessment_full",
                "view_requirementassessment",
                "view_framework",
                "view_requirementnode",
                "view_question",
                "view_questionchoice",
                "view_answer",
                "view_perimeter",
                "view_evidence",
                "view_appliedcontrol",
                "view_folder",
                "add_requirementassessment",
                "add_answer",
                "change_requirementassessment",
                "change_answer",
                "add_appliedcontrol",
            }
        )
    )
    assignment = RoleAssignment.objects.create(
        user=user,
        role=role,
        folder=Folder.get_root_folder(),
        is_recursive=False,
    )
    assignment.perimeter_folders.add(folder)


@pytest.fixture
def baseline_world():
    Folder._init_root_folder()
    root = Folder.get_root_folder()
    folder = Folder.objects.create(
        name=f"baseline-copy-{uuid.uuid4().hex[:8]}",
        content_type=Folder.ContentType.DOMAIN,
        parent_folder=root,
    )
    framework = Framework.objects.create(
        name="Baseline copy framework",
        urn=f"urn:test:risk:framework:baseline-copy-{uuid.uuid4().hex}",
        ref_id="BASELINE-COPY",
        folder=folder,
        min_score=0,
        max_score=5,
        field_visibility=COPY_POLICY,
    )
    requirement = RequirementNode.objects.create(
        name="Baseline requirement",
        urn=f"{framework.urn}:req:one",
        ref_id="REQ-1",
        framework=framework,
        folder=folder,
        assessable=True,
    )
    question = Question.objects.create(
        requirement_node=requirement,
        urn=f"{requirement.urn}:question:one",
        ref_id="Q-1",
        text="Pick one",
        type=Question.Type.UNIQUE_CHOICE,
        folder=folder,
    )
    choice = QuestionChoice.objects.create(
        question=question,
        urn=f"{question.urn}:choice:one",
        ref_id="C-1",
        value="One",
        folder=folder,
    )
    baseline = ComplianceAssessment.objects.create(
        name="Source baseline",
        framework=framework,
        folder=folder,
        perimeter=Perimeter.objects.create(name="Source perimeter", folder=folder),
        min_score=0,
        max_score=5,
        field_visibility=COPY_POLICY,
    )
    baseline.create_requirement_assessments()
    source_ra = baseline.requirement_assessments.get(requirement=requirement)
    source_ra.result = RequirementAssessment.Result.COMPLIANT
    source_ra.status = RequirementAssessment.Status.DONE
    source_ra.score = 4
    source_ra.documentation_score = 3
    source_ra.is_scored = True
    source_ra.is_score_overridden = True
    source_ra.observation = "authority-proved source"
    source_ra.save()
    evidence = Evidence.objects.create(name="Baseline evidence", folder=folder)
    control = AppliedControl.objects.create(name="Baseline control", folder=folder)
    source_ra.evidences.add(evidence)
    source_ra.applied_controls.add(control)
    source_answer = Answer.objects.get(
        requirement_assessment=source_ra,
        question=question,
    )
    source_answer.selected_choices.add(choice)

    user = User.objects.create_user(f"baseline-{uuid.uuid4().hex}@example.test")
    _grant_clone_access(user, folder)
    client = APIClient()
    client.force_authenticate(user=user)
    return {
        "folder": folder,
        "framework": framework,
        "requirement": requirement,
        "question": question,
        "choice": choice,
        "baseline": baseline,
        "source_ra": source_ra,
        "source_answer": source_answer,
        "evidence": evidence,
        "control": control,
        "user": user,
        "client": client,
    }


def _clone(
    world,
    name="Target clone",
    *,
    field_visibility=COPY_POLICY,
    **extra,
):
    perimeter = Perimeter.objects.create(
        name=f"Target perimeter {uuid.uuid4().hex}",
        folder=world["folder"],
    )
    return world["client"].post(
        "/api/compliance-assessments/",
        {
            "name": name,
            "version": "1.0",
            "folder": str(world["folder"].id),
            "perimeter": str(perimeter.id),
            "framework": str(world["framework"].id),
            "baseline": str(world["baseline"].id),
            "field_visibility": field_visibility,
            **extra,
        },
        format="json",
    )


def test_same_framework_clone_uses_authority_proved_locked_snapshot(baseline_world):
    response = _clone(baseline_world)

    assert response.status_code == 201, response.content
    clone = ComplianceAssessment.objects.get(id=response.json()["id"])
    cloned_ra = clone.requirement_assessments.get(
        requirement=baseline_world["requirement"]
    )
    assert cloned_ra.result == RequirementAssessment.Result.COMPLIANT
    assert cloned_ra.status == RequirementAssessment.Status.DONE
    assert cloned_ra.score == 4
    assert cloned_ra.documentation_score == 3
    assert cloned_ra.is_score_overridden is True
    assert cloned_ra.observation == "authority-proved source"
    assert set(cloned_ra.evidences.values_list("id", flat=True)) == {
        baseline_world["evidence"].id
    }
    assert set(cloned_ra.applied_controls.values_list("id", flat=True)) == {
        baseline_world["control"].id
    }
    cloned_answer = cloned_ra.answers.get(question=baseline_world["question"])
    assert set(cloned_answer.selected_choices.values_list("id", flat=True)) == {
        baseline_world["choice"].id
    }
    assert clone.baseline_source_assessment_id_snapshot == baseline_world["baseline"].id
    assert len(clone.baseline_snapshot_sha256) == 64
    assert clone.baseline_copied_by_id_snapshot == baseline_world["user"].id
    assert clone.baseline_copied_at is not None
    creation_log = LogEntry.objects.get(
        content_type=ContentType.objects.get_for_model(ComplianceAssessment),
        object_pk=str(clone.id),
        action=LogEntry.Action.CREATE,
    )
    for provenance_field in (
        "baseline_source_assessment_id_snapshot",
        "baseline_snapshot_sha256",
        "baseline_copied_by_id_snapshot",
        "baseline_copied_at",
    ):
        assert provenance_field in creation_log.changes_dict
    final_metric = HistoricalMetric.objects.get(
        model="ComplianceAssessment",
        object_id=clone.id,
    )
    assert final_metric.data["reqs"]["total"] == 1


def test_same_framework_clone_rejects_hidden_source_answer_before_target_create(
    baseline_world, monkeypatch
):
    original = RoleAssignment.get_viewable_object_ids
    hidden_answer_id = baseline_world["source_answer"].id

    def hide_source_answer(user, model, folder=None):
        visible = original(user, model, folder)
        if model is Answer:
            return visible.exclude(id=hidden_answer_id)
        return visible

    monkeypatch.setattr(
        RoleAssignment,
        "get_viewable_object_ids",
        staticmethod(hide_source_answer),
    )

    response = _clone(baseline_world, name="Rejected hidden answer clone")

    assert response.status_code == 403, response.content
    assert not ComplianceAssessment.objects.filter(
        name="Rejected hidden answer clone"
    ).exists()


def test_same_framework_clone_rejects_hidden_target_answer_policy(baseline_world):
    hidden_target_policy = {
        **COPY_POLICY,
        "answers": {"auditor": "hidden", "respondent": "hidden"},
    }

    response = _clone(
        baseline_world,
        name="Rejected target policy clone",
        field_visibility=hidden_target_policy,
    )

    assert response.status_code == 403, response.content
    assert not ComplianceAssessment.objects.filter(
        name="Rejected target policy clone"
    ).exists()


def test_same_framework_clone_rejects_read_only_target_field(baseline_world):
    read_only_target_policy = {
        **COPY_POLICY,
        "answers": {"auditor": "read", "respondent": "hidden"},
    }

    response = _clone(
        baseline_world,
        name="Rejected read-only target clone",
        field_visibility=read_only_target_policy,
    )

    assert response.status_code == 403, response.content
    assert not ComplianceAssessment.objects.filter(
        name="Rejected read-only target clone"
    ).exists()


@pytest.mark.parametrize(
    "codename",
    (
        "add_requirementassessment",
        "change_requirementassessment",
        "add_answer",
        "change_answer",
    ),
)
def test_same_framework_clone_requires_child_write_permissions(
    baseline_world,
    codename,
):
    assignment = baseline_world["user"].roleassignment_set.get()
    assignment.role.permissions.remove(Permission.objects.get(codename=codename))

    rejected_name = f"Rejected child permission clone {codename}"
    response = _clone(baseline_world, name=rejected_name)

    assert response.status_code == 403, response.content
    assert not ComplianceAssessment.objects.filter(name=rejected_name).exists()


def test_same_framework_clone_rechecks_field_policy_after_graph_lock(
    baseline_world, monkeypatch
):
    from core import views

    original = views._lock_baseline_copy_graph

    def hide_answers_after_lock(**kwargs):
        baseline, snapshot = original(**kwargs)
        baseline.field_visibility = {
            **baseline.field_visibility,
            "answers": {"auditor": "hidden", "respondent": "hidden"},
        }
        ComplianceAssessment.objects.filter(id=baseline.id).update(
            field_visibility=baseline.field_visibility
        )
        return baseline, snapshot

    monkeypatch.setattr(views, "_lock_baseline_copy_graph", hide_answers_after_lock)

    response = _clone(baseline_world, name="Rejected policy race clone")

    assert response.status_code == 403, response.content
    assert not ComplianceAssessment.objects.filter(
        name="Rejected policy race clone"
    ).exists()


def test_same_framework_clone_rejects_relation_change_between_snapshot_and_lock(
    baseline_world, monkeypatch
):
    from core import views

    raced_evidence = Evidence.objects.create(
        name="Raced evidence",
        folder=baseline_world["folder"],
    )
    original = views.lock_rows_in_global_model_order
    injected = False

    def mutate_relation_before_target_lock(target_ids_by_model):
        nonlocal injected
        if not injected and set(target_ids_by_model) == {AppliedControl, Evidence}:
            injected = True
            baseline_world["source_ra"].evidences.add(raced_evidence)
        return original(target_ids_by_model)

    monkeypatch.setattr(
        views,
        "lock_rows_in_global_model_order",
        mutate_relation_before_target_lock,
    )

    response = _clone(baseline_world, name="Rejected relation race clone")

    assert injected is True
    assert response.status_code == 403, response.content
    assert not ComplianceAssessment.objects.filter(
        name="Rejected relation race clone"
    ).exists()
    assert (
        not baseline_world["source_ra"].evidences.filter(id=raced_evidence.id).exists()
    )


def test_same_framework_clone_rejects_missing_source_answer(baseline_world):
    Answer.objects.filter(id=baseline_world["source_answer"].id).delete()

    response = _clone(baseline_world, name="Rejected missing answer clone")

    assert response.status_code == 403, response.content
    assert not ComplianceAssessment.objects.filter(
        name="Rejected missing answer clone"
    ).exists()


def test_same_framework_clone_rejects_missing_requirement_assessment(baseline_world):
    baseline_world["source_ra"].delete()

    response = _clone(baseline_world, name="Rejected missing assessment row clone")

    assert response.status_code == 403, response.content
    assert not ComplianceAssessment.objects.filter(
        name="Rejected missing assessment row clone"
    ).exists()


def test_same_framework_clone_rejects_invalid_choice_and_scalar_carrier(
    baseline_world,
):
    Answer.objects.filter(id=baseline_world["source_answer"].id).update(
        value="forged-choice-scalar"
    )

    response = _clone(baseline_world, name="Rejected malformed answer clone")

    assert response.status_code == 403, response.content
    assert not ComplianceAssessment.objects.filter(
        name="Rejected malformed answer clone"
    ).exists()


def test_same_framework_clone_rejects_invalid_scalar_value(baseline_world):
    baseline_world["source_answer"].selected_choices.clear()
    baseline_world["question"].type = Question.Type.NUMBER
    baseline_world["question"].save(update_fields=["type"])
    Answer.objects.filter(id=baseline_world["source_answer"].id).update(value=True)

    response = _clone(baseline_world, name="Rejected malformed scalar clone")

    assert response.status_code == 403, response.content
    assert not ComplianceAssessment.objects.filter(
        name="Rejected malformed scalar clone"
    ).exists()


def test_same_framework_clone_rejects_score_outside_target_contract(baseline_world):
    response = _clone(
        baseline_world,
        name="Rejected target scoring clone",
        min_score=0,
        max_score=3,
    )

    assert response.status_code == 400, response.content
    assert not ComplianceAssessment.objects.filter(
        name="Rejected target scoring clone"
    ).exists()


def test_same_framework_clone_rejects_stale_question_owned_score(baseline_world):
    baseline_world["choice"].add_score = 2
    baseline_world["choice"].save(update_fields=["add_score"])
    source_ra = baseline_world["source_ra"]
    source_ra.is_score_overridden = False
    source_ra.score = 4
    source_ra.is_scored = True
    source_ra.save(update_fields=["is_score_overridden", "score", "is_scored"])

    response = _clone(baseline_world, name="Rejected stale score clone")

    assert response.status_code == 400, response.content
    assert not ComplianceAssessment.objects.filter(
        name="Rejected stale score clone"
    ).exists()


def test_computed_outcome_is_derived_and_client_input_is_ignored(baseline_world):
    framework = baseline_world["framework"]
    framework.outcomes_definition = [
        {
            "ref_id": "deterministic",
            "expression": "true",
            "result": "review",
            "label": "Deterministic",
        }
    ]
    framework.save(update_fields=["outcomes_definition"])

    response = _clone(
        baseline_world,
        name="Derived outcome clone",
        computed_outcome={"forged": {"result": "approved"}},
    )

    assert response.status_code == 201, response.content
    clone = ComplianceAssessment.objects.get(id=response.json()["id"])
    assert clone.computed_outcome == {
        "deterministic": {"result": "review", "label": "Deterministic"}
    }


def test_dynamic_groups_are_recomputed_before_suggested_controls(
    baseline_world,
    monkeypatch,
):
    requirement = baseline_world["requirement"]
    requirement.implementation_groups = ["dynamic-a"]
    requirement.save(update_fields=["implementation_groups"])
    choice = baseline_world["choice"]
    choice.select_implementation_groups = ["dynamic-a"]
    choice.save(update_fields=["select_implementation_groups"])
    observed_groups = []

    def observe_groups(self, **_kwargs):
        self.compliance_assessment.refresh_from_db(
            fields=["selected_implementation_groups"]
        )
        observed_groups.append(
            tuple(self.compliance_assessment.selected_implementation_groups or [])
        )
        return []

    monkeypatch.setattr(
        RequirementAssessment,
        "create_applied_controls_from_suggestions",
        observe_groups,
    )

    response = _clone(
        baseline_world,
        name="Dynamic group clone",
        create_applied_controls_from_suggestions=True,
    )

    assert response.status_code == 201, response.content
    assert observed_groups == [("dynamic-a",)]


def test_clone_provenance_is_write_once(baseline_world):
    response = _clone(baseline_world, name="Immutable provenance clone")
    assert response.status_code == 201, response.content
    clone = ComplianceAssessment.objects.get(id=response.json()["id"])

    clone.baseline_snapshot_sha256 = "0" * 64
    with pytest.raises(DjangoValidationError, match="immutable"):
        clone.save(update_fields=["baseline_snapshot_sha256"])


def test_requirement_assessment_owner_pair_is_database_unique(baseline_world):
    with pytest.raises(IntegrityError):
        with transaction.atomic():
            RequirementAssessment.objects.create(
                compliance_assessment=baseline_world["baseline"],
                requirement=baseline_world["requirement"],
                folder=baseline_world["folder"],
            )


def test_answer_owner_pair_is_database_unique(baseline_world):
    with pytest.raises(IntegrityError):
        with transaction.atomic():
            Answer.objects.create(
                requirement_assessment=baseline_world["source_ra"],
                question=baseline_world["question"],
                folder=baseline_world["folder"],
            )


def test_audit_update_uses_framework_before_assessment_lock_order(
    baseline_world,
    monkeypatch,
):
    lock_order = []
    original = QuerySet.select_for_update

    def observe_lock(queryset, *args, **kwargs):
        if queryset.model in {Framework, ComplianceAssessment}:
            lock_order.append(queryset.model)
        return original(queryset, *args, **kwargs)

    monkeypatch.setattr(QuerySet, "select_for_update", observe_lock)

    response = baseline_world["client"].patch(
        f"/api/compliance-assessments/{baseline_world['baseline'].id}/",
        {"name": "Updated without inverse lock order"},
        format="json",
    )

    assert response.status_code == 200, response.content
    assert lock_order[:2] == [Framework, ComplianceAssessment]
