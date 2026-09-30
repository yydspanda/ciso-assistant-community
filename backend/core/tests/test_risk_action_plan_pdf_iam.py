"""IAM regressions for the risk action-plan PDF projection."""

from __future__ import annotations

import uuid

import pytest
from django.contrib.auth.models import Permission
from rest_framework.test import APIClient

from core.models import (
    AppliedControl,
    Perimeter,
    Policy,
    RiskAssessment,
    RiskMatrix,
    RiskScenario,
)
from iam.models import Folder, Role, RoleAssignment, User


pytestmark = pytest.mark.django_db


PDF_PERMISSIONS = {
    "view_appliedcontrol",
    "view_folder",
    "view_perimeter",
    "view_riskassessment",
    "view_riskscenario",
}


def _domain(label: str) -> Folder:
    return Folder.objects.create(
        name=f"risk-pdf-{label}-{uuid.uuid4().hex[:8]}",
        content_type=Folder.ContentType.DOMAIN,
        parent_folder=Folder.get_root_folder(),
    )


def _user(folder: Folder) -> User:
    user = User.objects.create_user(email=f"risk-pdf-{uuid.uuid4().hex}@iam.tests")
    user.folder = folder
    user.save(update_fields=["folder"])
    return user


def _grant(user: User, folder: Folder, *codenames: str) -> None:
    role = Role.objects.create(
        name=f"Risk PDF reader {uuid.uuid4().hex}",
        folder=Folder.get_root_folder(),
    )
    role.permissions.set(Permission.objects.filter(codename__in=codenames))
    assignment = RoleAssignment.objects.create(
        user=user,
        role=role,
        folder=Folder.get_root_folder(),
        is_recursive=False,
    )
    assignment.perimeter_folders.add(folder)


def _client(user: User) -> APIClient:
    client = APIClient()
    client.force_authenticate(user)
    return client


def _matrix(folder: Folder) -> RiskMatrix:
    return RiskMatrix.objects.create(
        name=f"Risk PDF matrix {uuid.uuid4().hex}",
        urn=f"urn:test:risk-pdf-matrix:{uuid.uuid4().hex}",
        folder=folder,
        json_definition={
            "probability": [{"name": "Possible"}],
            "impact": [{"name": "Limited"}],
            "risk": [{"name": "Low", "hexcolor": "#65a30d"}],
            "grid": [[0]],
        },
    )


def _control(
    model,
    folder: Folder,
    label: str,
    *,
    status: str = AppliedControl.Status.ACTIVE,
):
    control = model(
        name=f"{label}-{uuid.uuid4().hex}",
        folder=folder,
        category="technical",
        status=status,
    )
    control.save(skip_sync=True)
    return control


@pytest.fixture
def risk_pdf_world(monkeypatch):
    Folder._init_root_folder()
    visible = _domain("visible")
    hidden = _domain("hidden")
    monkeypatch.setattr(RiskAssessment, "upsert_daily_metrics", lambda self: None)

    matrix = _matrix(visible)
    perimeter = Perimeter.objects.create(
        name=f"Visible PDF perimeter {uuid.uuid4().hex}", folder=visible
    )
    assessment = RiskAssessment.objects.create(
        name=f"Visible PDF assessment {uuid.uuid4().hex}",
        folder=visible,
        perimeter=perimeter,
        risk_matrix=matrix,
    )
    visible_scenario = RiskScenario.objects.create(
        name=f"Visible PDF scenario {uuid.uuid4().hex}",
        ref_id="PDF-VISIBLE",
        folder=visible,
        risk_assessment=assessment,
    )

    hidden_assessment = RiskAssessment.objects.create(
        name=f"Hidden PDF assessment {uuid.uuid4().hex}",
        folder=hidden,
        risk_matrix=matrix,
    )
    hidden_scenario = RiskScenario.objects.create(
        name=f"Hidden PDF scenario {uuid.uuid4().hex}",
        ref_id="PDF-HIDDEN",
        folder=hidden,
        risk_assessment=hidden_assessment,
    )

    ordinary = _control(AppliedControl, visible, "Visible ordinary control")
    degraded_existing = _control(
        AppliedControl,
        visible,
        "Visible degraded existing control",
        status=AppliedControl.Status.DEGRADED,
    )
    policy = _control(Policy, visible, "Visible policy")
    hidden_control = _control(AppliedControl, hidden, "Hidden control")
    visible_scenario.applied_controls.add(ordinary, policy, hidden_control)
    visible_scenario.existing_applied_controls.add(degraded_existing)
    hidden_scenario.applied_controls.add(ordinary)

    return {
        "visible": visible,
        "hidden": hidden,
        "assessment": assessment,
        "visible_scenario": visible_scenario,
        "hidden_scenario": hidden_scenario,
        "ordinary": ordinary,
        "degraded_existing": degraded_existing,
        "policy": policy,
        "hidden_control": hidden_control,
    }


def _pdf_url(assessment: RiskAssessment) -> str:
    return f"/api/risk-assessments/{assessment.id}/action_plan_pdf/"


def _capture_pdf_context(monkeypatch):
    from core import views as core_views

    captured = {}
    original_render = core_views.render_to_string

    def fake_render(template_name, data):
        captured["template"] = template_name
        captured["data"] = data
        return original_render(template_name, data)

    class FakeHTML:
        def __init__(self, *, string):
            captured["html"] = string

        def write_pdf(self):
            return b"%PDF-risk-action-plan-iam"

    monkeypatch.setattr(core_views, "render_to_string", fake_render)
    monkeypatch.setattr(core_views, "HTML", FakeHTML)
    return captured


def _projected_controls(captured) -> list[AppliedControl]:
    context = captured["data"]["context"]
    return [control for controls in context.values() for control in controls]


def test_pdf_projects_only_visible_scenarios_and_exact_control_authority(
    risk_pdf_world,
    monkeypatch,
):
    world = risk_pdf_world
    user = _user(world["visible"])
    _grant(user, world["visible"], *PDF_PERMISSIONS)
    captured = _capture_pdf_context(monkeypatch)

    response = _client(user).get(_pdf_url(world["assessment"]))

    assert response.status_code == 200, response.content
    assert response.content == b"%PDF-risk-action-plan-iam"
    controls = _projected_controls(captured)
    assert {control.id for control in controls} == {
        world["ordinary"].id,
        world["degraded_existing"].id,
    }
    for control in controls:
        assert {scenario.id for scenario in control.authorized_risk_scenarios} == {
            world["visible_scenario"].id
        }
    assert world["ordinary"].name in captured["html"]
    assert world["visible_scenario"].name in captured["html"]
    assert world["hidden_scenario"].name not in captured["html"]
    assert world["hidden_control"].name not in captured["html"]
    assert world["policy"].name not in captured["html"]


def test_pdf_includes_policy_only_after_view_policy_is_granted(
    risk_pdf_world,
    monkeypatch,
):
    world = risk_pdf_world
    user = _user(world["visible"])
    _grant(user, world["visible"], *PDF_PERMISSIONS)
    captured = _capture_pdf_context(monkeypatch)
    client = _client(user)

    without_policy = client.get(_pdf_url(world["assessment"]))
    assert without_policy.status_code == 200, without_policy.content
    assert {control.id for control in _projected_controls(captured)} == {
        world["ordinary"].id,
        world["degraded_existing"].id,
    }
    assert world["policy"].name not in captured["html"]

    _grant(user, world["visible"], "view_policy")
    with_policy = client.get(_pdf_url(world["assessment"]))

    assert with_policy.status_code == 200, with_policy.content
    assert {control.id for control in _projected_controls(captured)} == {
        world["ordinary"].id,
        world["degraded_existing"].id,
        world["policy"].id,
    }
    assert world["policy"].name in captured["html"]


def test_pdf_reproves_exact_relationship_projection_after_render(
    risk_pdf_world,
    monkeypatch,
):
    world = risk_pdf_world
    user = _user(world["visible"])
    _grant(user, world["visible"], *PDF_PERMISSIONS)

    def mutate_relationship_during_render(template_name, data):
        world["visible_scenario"].applied_controls.remove(world["ordinary"])
        return "<html>stale projection</html>"

    class UnexpectedHTML:
        def __init__(self, *, string):  # pragma: no cover - must fail earlier
            raise AssertionError("stale report reached PDF generation")

    monkeypatch.setattr(
        "core.views.render_to_string", mutate_relationship_during_render
    )
    monkeypatch.setattr("core.views.HTML", UnexpectedHTML)

    response = _client(user).get(_pdf_url(world["assessment"]))

    assert response.status_code == 403, response.content


def test_pdf_binds_every_rendered_scalar_to_the_terminal_snapshot(
    risk_pdf_world,
    monkeypatch,
):
    from core import views as core_views

    world = risk_pdf_world
    user = _user(world["visible"])
    _grant(user, world["visible"], *PDF_PERMISSIONS)
    original_render = core_views.render_to_string
    calls = 0

    def mutate_control_after_first_render(template_name, data):
        nonlocal calls
        calls += 1
        html = original_render(template_name, data)
        if calls == 1:
            AppliedControl.objects.filter(id=world["ordinary"].id).update(
                name=f"Changed during render {uuid.uuid4().hex}"
            )
        return html

    class UnexpectedHTML:
        def __init__(self, *, string):  # pragma: no cover - must fail earlier
            raise AssertionError("mixed-version report reached PDF generation")

    monkeypatch.setattr(
        core_views,
        "render_to_string",
        mutate_control_after_first_render,
    )
    monkeypatch.setattr(core_views, "HTML", UnexpectedHTML)

    response = _client(user).get(_pdf_url(world["assessment"]))

    assert response.status_code == 403, response.content
    assert calls == 2


@pytest.mark.parametrize("missing_permission", ("view_folder", "view_perimeter"))
def test_pdf_requires_parent_folder_and_perimeter_read_authority(
    risk_pdf_world,
    monkeypatch,
    missing_permission,
):
    world = risk_pdf_world
    user = _user(world["visible"])
    permissions = PDF_PERMISSIONS - {missing_permission}
    _grant(user, world["visible"], *permissions)
    _capture_pdf_context(monkeypatch)

    response = _client(user).get(_pdf_url(world["assessment"]))

    assert response.status_code == 403, response.content
