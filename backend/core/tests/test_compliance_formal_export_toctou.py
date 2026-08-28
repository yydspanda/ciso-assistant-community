"""Terminal authorization proofs for complete compliance exports and compare."""

from __future__ import annotations

import uuid

import pytest

from core.models import ComplianceAssessment, Framework, RequirementAssessment
from core.tests.test_compliance_assessment_tree_iam import (
    _client,
    _grant,
    _grant_complete_ancestor_read,
    audit_iam_world as _audit_iam_world_fixture,
)


pytestmark = pytest.mark.django_db
audit_iam_world = _audit_iam_world_fixture

CYFUN_FRAMEWORK_URN = "urn:intuitem:risk:framework:ccb-cyfun2025"


@pytest.fixture
def formal_export_world(audit_iam_world):
    world = audit_iam_world
    _grant_complete_ancestor_read(world)
    _grant(
        world["auditor"],
        f"Formal export related reader {uuid.uuid4().hex}",
        {
            "view_actor",
            "view_answer",
            "view_evidencerevision",
            "view_folder",
            "view_perimeter",
            "view_question",
            "view_questionchoice",
        },
        world["child_folder"],
        world["ancestor"].folder,
    )
    return world


def _prepare_cyfun_profile(world: dict) -> None:
    # A full test database may already contain the built-in CyFun framework.
    # Move only that unique URN for this transaction, then give the compact
    # synthetic framework the endpoint discriminator. Pytest rolls both writes
    # back with the fixture transaction.
    Framework.objects.filter(urn=CYFUN_FRAMEWORK_URN).exclude(
        id=world["target"].framework_id
    ).update(urn=f"{CYFUN_FRAMEWORK_URN}:displaced:{uuid.uuid4().hex}")
    Framework.objects.filter(id=world["target"].framework_id).update(
        urn=CYFUN_FRAMEWORK_URN
    )
    world["assigned_requirement"].ref_id = "GV.OC-01.1"
    world["assigned_requirement"].save(update_fields=["ref_id"])
    world["target"].refresh_from_db()


@pytest.mark.parametrize(
    ("action", "content_type"),
    [
        ("compliance_assessment_csv", "text/csv"),
        ("xlsx", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"),
        (
            "cyfun_xlsx",
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        ),
        ("export", "application/zip"),
        ("compare", "application/json"),
    ],
)
def test_formal_exports_keep_stable_authorized_wire(
    formal_export_world,
    action,
    content_type,
):
    world = formal_export_world
    if action == "cyfun_xlsx":
        _prepare_cyfun_profile(world)
    params = {"compare_id": str(world["ancestor"].id)} if action == "compare" else {}

    response = _client(world["auditor"]).get(
        f"/api/compliance-assessments/{world['target'].id}/{action}/",
        params,
    )

    assert response.status_code == 200, response.content
    assert response["Content-Type"].startswith(content_type)


def test_html_zip_rejects_unlink_then_hide_during_generation(
    formal_export_world,
    monkeypatch,
):
    from core import views as core_views

    world = formal_export_world
    assessment = world["target"]
    requirement_assessment = world["assigned_ra"]
    evidence = world["visible_evidence"]
    requirement_assessment.evidences.add(evidence)

    def unlink_then_hide(*args, **kwargs):
        requirement_assessment.evidences.remove(evidence)
        evidence.folder = world["hidden_folder"]
        evidence.is_published = False
        evidence.save(update_fields=["folder", "is_published"])
        return "<html>authorized-but-stale</html>", [evidence]

    monkeypatch.setattr(core_views, "generate_html", unlink_then_hide)

    response = _client(world["auditor"]).get(
        f"/api/compliance-assessments/{assessment.id}/export/"
    )

    assert response.status_code == 403, response.content
    assert b"Audit export data changed" in response.content


def test_xlsx_rejects_field_policy_change_after_payload_materialization(
    formal_export_world,
    monkeypatch,
):
    from core import views as core_views

    world = formal_export_world
    assessment = world["target"]
    original_to_excel = core_views.pd.DataFrame.to_excel
    changed = False

    def mutate_policy(dataframe, *args, **kwargs):
        nonlocal changed
        result = original_to_excel(dataframe, *args, **kwargs)
        if not changed:
            changed = True
            field_visibility = dict(assessment.field_visibility)
            field_visibility["result"] = {
                "auditor": "hidden",
                "respondent": "hidden",
            }
            ComplianceAssessment.objects.filter(id=assessment.id).update(
                field_visibility=field_visibility
            )
        return result

    monkeypatch.setattr(core_views.pd.DataFrame, "to_excel", mutate_policy)

    response = _client(world["auditor"]).get(
        f"/api/compliance-assessments/{assessment.id}/xlsx/"
    )

    assert response.status_code == 403, response.content
    assert b"Audit export data changed" in response.content


def test_compare_rejects_field_policy_change_after_payload_materialization(
    formal_export_world,
    monkeypatch,
):
    world = formal_export_world
    assessment = world["target"]
    original_get_donut_data = ComplianceAssessment.get_donut_data
    changed = False

    def mutate_policy(instance, *args, **kwargs):
        nonlocal changed
        result = original_get_donut_data(instance, *args, **kwargs)
        if instance.id == assessment.id and not changed:
            changed = True
            field_visibility = dict(assessment.field_visibility)
            field_visibility["score"] = {
                "auditor": "hidden",
                "respondent": "hidden",
            }
            ComplianceAssessment.objects.filter(id=assessment.id).update(
                field_visibility=field_visibility
            )
        return result

    monkeypatch.setattr(ComplianceAssessment, "get_donut_data", mutate_policy)

    response = _client(world["auditor"]).get(
        f"/api/compliance-assessments/{assessment.id}/compare/",
        {"compare_id": str(world["ancestor"].id)},
    )

    assert response.status_code == 403, response.content
    assert b"Audit comparison data changed" in response.content


def test_cyfun_xlsx_rejects_value_change_after_workbook_save(
    formal_export_world,
    monkeypatch,
):
    from core import views as core_views

    world = formal_export_world
    _prepare_cyfun_profile(world)
    requirement_assessment = world["assigned_ra"]
    changed_score = 1 if requirement_assessment.score != 1 else 2
    original_load_workbook = core_views.load_workbook

    def load_mutating_workbook(*args, **kwargs):
        workbook = original_load_workbook(*args, **kwargs)
        original_save = workbook.save

        def save_then_mutate(*save_args, **save_kwargs):
            result = original_save(*save_args, **save_kwargs)
            RequirementAssessment.objects.filter(id=requirement_assessment.id).update(
                score=changed_score
            )
            return result

        workbook.save = save_then_mutate
        return workbook

    monkeypatch.setattr(core_views, "load_workbook", load_mutating_workbook)

    response = _client(world["auditor"]).get(
        f"/api/compliance-assessments/{world['target'].id}/cyfun_xlsx/"
    )

    assert response.status_code == 403, response.content
    assert b"Audit export data changed" in response.content
