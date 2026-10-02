"""IAM regressions for the risk action-plan PDF projection."""

from __future__ import annotations

from copy import deepcopy
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

    captured = {"payloads": []}

    def fake_render(template_name, data, images=None, pdf_standards=None):
        captured["template"] = template_name
        captured["payloads"].append(deepcopy(data))
        return b"%PDF-risk-action-plan-iam"

    monkeypatch.setattr(core_views, "render_pdf", fake_render)
    return captured


def _projected_controls(captured) -> list[dict]:
    payload = captured["payloads"][-1]
    return [control for group in payload["groups"] for control in group["controls"]]


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
    assert {control["name"] for control in controls} == {
        world["ordinary"].name,
        world["degraded_existing"].name,
    }
    for control in controls:
        assert control["linked"] == [str(world["visible_scenario"])]
    rendered = repr(captured["payloads"][-1])
    assert world["ordinary"].name in rendered
    assert world["visible_scenario"].name in rendered
    assert world["hidden_scenario"].name not in rendered
    assert world["hidden_control"].name not in rendered
    assert world["policy"].name not in rendered


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
    assert {control["name"] for control in _projected_controls(captured)} == {
        world["ordinary"].name,
        world["degraded_existing"].name,
    }
    assert world["policy"].name not in repr(captured["payloads"][-1])

    _grant(user, world["visible"], "view_policy")
    with_policy = client.get(_pdf_url(world["assessment"]))

    assert with_policy.status_code == 200, with_policy.content
    assert {control["name"] for control in _projected_controls(captured)} == {
        world["ordinary"].name,
        world["degraded_existing"].name,
        world["policy"].name,
    }
    assert world["policy"].name in repr(captured["payloads"][-1])


def test_pdf_reproves_exact_relationship_projection_after_render(
    risk_pdf_world,
    monkeypatch,
):
    world = risk_pdf_world
    user = _user(world["visible"])
    _grant(user, world["visible"], *PDF_PERMISSIONS)

    def mutate_relationship_during_render(
        template_name, data, images=None, pdf_standards=None
    ):
        world["visible_scenario"].applied_controls.remove(world["ordinary"])
        return b"%PDF-stale-projection"

    monkeypatch.setattr("core.views.render_pdf", mutate_relationship_during_render)

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
    calls = 0

    def mutate_control_after_first_render(
        template_name, data, images=None, pdf_standards=None
    ):
        nonlocal calls
        calls += 1
        AppliedControl.objects.filter(id=world["ordinary"].id).update(
            name=f"Changed during render {uuid.uuid4().hex}"
        )
        return b"%PDF-mixed-version"

    monkeypatch.setattr(
        core_views,
        "render_pdf",
        mutate_control_after_first_render,
    )

    response = _client(user).get(_pdf_url(world["assessment"]))

    assert response.status_code == 403, response.content
    assert calls == 1


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
