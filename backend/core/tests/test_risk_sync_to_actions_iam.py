"""Exact read/write IAM regressions for risk ``sync-to-actions``."""

from __future__ import annotations

import uuid

import pytest
from django.contrib.auth.models import Permission
from django.db.models.signals import m2m_changed
from rest_framework.test import APIClient

from core.models import (
    AppliedControl,
    Policy,
    RiskAssessment,
    RiskMatrix,
    RiskScenario,
)
from iam.models import Folder, Role, RoleAssignment, User


pytestmark = pytest.mark.django_db


SCENARIO_SYNC_PERMISSIONS = {
    "change_appliedcontrol",
    "change_policy",
    "change_riskscenario",
    "view_appliedcontrol",
    "view_policy",
    "view_riskassessment",
    "view_riskscenario",
}
ASSESSMENT_SYNC_PERMISSIONS = SCENARIO_SYNC_PERMISSIONS | {"change_riskassessment"}


def _domain(label: str) -> Folder:
    return Folder.objects.create(
        name=f"risk-sync-{label}-{uuid.uuid4().hex[:8]}",
        content_type=Folder.ContentType.DOMAIN,
        parent_folder=Folder.get_root_folder(),
    )


def _user(folder: Folder) -> User:
    user = User.objects.create_user(email=f"risk-sync-{uuid.uuid4().hex}@iam.tests")
    user.folder = folder
    user.save(update_fields=["folder"])
    return user


def _grant(user: User, folder: Folder, *codenames: str) -> None:
    role = Role.objects.create(
        name=f"Risk sync role {uuid.uuid4().hex}",
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
        name=f"Risk sync matrix {uuid.uuid4().hex}",
        urn=f"urn:test:risk-sync-matrix:{uuid.uuid4().hex}",
        folder=folder,
        json_definition={
            "probability": [{"name": "Low"}, {"name": "High"}],
            "impact": [{"name": "Low"}, {"name": "High"}],
            "risk": [
                {"name": "Low", "hexcolor": "#65a30d"},
                {"name": "Moderate", "hexcolor": "#eab308"},
                {"name": "High", "hexcolor": "#f97316"},
                {"name": "Critical", "hexcolor": "#dc2626"},
            ],
            "grid": [[0, 1], [2, 3]],
        },
    )


def _control(model, folder: Folder, label: str, *, status: str):
    control = model(
        name=f"{label}-{uuid.uuid4().hex}",
        folder=folder,
        category="technical",
        status=status,
    )
    control.save(skip_sync=True)
    return control


def _scenario(
    assessment: RiskAssessment,
    label: str,
    *,
    current: tuple[int, int],
    residual: tuple[int, int],
) -> RiskScenario:
    return RiskScenario.objects.create(
        name=f"{label}-{uuid.uuid4().hex}",
        ref_id=f"SYNC-{uuid.uuid4().hex[:8]}",
        folder=assessment.folder,
        risk_assessment=assessment,
        current_proba=current[0],
        current_impact=current[1],
        residual_proba=residual[0],
        residual_impact=residual[1],
    )


@pytest.fixture
def sync_world(monkeypatch):
    Folder._init_root_folder()
    visible = _domain("visible")
    hidden = _domain("hidden")
    monkeypatch.setattr(RiskAssessment, "upsert_daily_metrics", lambda self: None)

    assessment = RiskAssessment.objects.create(
        name=f"Risk sync assessment {uuid.uuid4().hex}",
        folder=visible,
        risk_matrix=_matrix(visible),
    )
    primary = _scenario(
        assessment,
        "Primary affected scenario",
        current=(0, 0),
        residual=(1, 1),
    )
    secondary = _scenario(
        assessment,
        "Secondary affected scenario",
        current=(1, 0),
        residual=(0, 1),
    )
    unaffected = _scenario(
        assessment,
        "Unaffected scenario",
        current=(0, 1),
        residual=(1, 0),
    )

    ordinary = _control(
        AppliedControl,
        visible,
        "Active ordinary control",
        status=AppliedControl.Status.ACTIVE,
    )
    policy = _control(
        Policy,
        visible,
        "Active policy",
        status=AppliedControl.Status.ACTIVE,
    )
    inaccessible_inactive = _control(
        AppliedControl,
        hidden,
        "Inaccessible inactive control",
        status=AppliedControl.Status.TO_DO,
    )
    primary.applied_controls.add(ordinary, policy)
    secondary.applied_controls.add(ordinary, policy)
    unaffected.applied_controls.add(inaccessible_inactive)

    return {
        "visible": visible,
        "hidden": hidden,
        "assessment": assessment,
        "primary": primary,
        "secondary": secondary,
        "unaffected": unaffected,
        "ordinary": ordinary,
        "policy": policy,
        "inaccessible_inactive": inaccessible_inactive,
    }


def _url(world: dict, endpoint: str) -> str:
    if endpoint == "scenario":
        return f"/api/risk-scenarios/{world['primary'].id}/sync-to-actions/"
    if endpoint == "assessment":
        return f"/api/risk-assessments/{world['assessment'].id}/sync-to-actions/"
    raise AssertionError(endpoint)


def _scenario_state(scenario: RiskScenario) -> dict:
    scenario.refresh_from_db()
    return {
        "applied": frozenset(scenario.applied_controls.values_list("id", flat=True)),
        "existing": frozenset(
            scenario.existing_applied_controls.values_list("id", flat=True)
        ),
        "current": (scenario.current_proba, scenario.current_impact),
        "residual": (scenario.residual_proba, scenario.residual_impact),
    }


def _world_state(world: dict) -> dict:
    return {
        key: _scenario_state(world[key])
        for key in ("primary", "secondary", "unaffected")
    }


@pytest.mark.parametrize("endpoint", ("scenario", "assessment"))
def test_sync_dry_run_and_write_succeed_with_complete_exact_authority(
    sync_world,
    endpoint,
):
    world = sync_world
    user = _user(world["visible"])
    permissions = (
        SCENARIO_SYNC_PERMISSIONS
        if endpoint == "scenario"
        else ASSESSMENT_SYNC_PERMISSIONS
    )
    _grant(user, world["visible"], *permissions)
    client = _client(user)
    before = _world_state(world)

    dry_run = client.post(
        f"{_url(world, endpoint)}?dry_run=true",
        {"reset_residual": True},
        format="json",
    )

    assert dry_run.status_code == 200, dry_run.content
    expected_change_ids = (
        {str(world["ordinary"].id), str(world["policy"].id)}
        if endpoint == "scenario"
        else {str(world["primary"].id), str(world["secondary"].id)}
    )
    assert {item["id"] for item in dry_run.json()["changes"]} == expected_change_ids
    assert _world_state(world) == before

    write = client.post(
        f"{_url(world, endpoint)}?dry_run=false",
        {"reset_residual": True},
        format="json",
    )

    assert write.status_code == 200, write.content
    assert {item["id"] for item in write.json()["changes"]} == expected_change_ids
    affected_keys = ("primary",) if endpoint == "scenario" else ("primary", "secondary")
    expected_control_ids = {world["ordinary"].id, world["policy"].id}
    for key in affected_keys:
        after = _scenario_state(world[key])
        assert after["applied"] == frozenset()
        assert after["existing"] == expected_control_ids
        assert after["current"] == before[key]["residual"]
        assert after["residual"] == (-1, -1)

    untouched_keys = {"primary", "secondary", "unaffected"} - set(affected_keys)
    for key in untouched_keys:
        assert _scenario_state(world[key]) == before[key]


@pytest.mark.parametrize(
    "endpoint,missing_permission",
    (
        ("scenario", "view_riskassessment"),
        ("scenario", "view_riskscenario"),
        ("scenario", "change_riskscenario"),
        ("scenario", "view_appliedcontrol"),
        ("scenario", "change_appliedcontrol"),
        ("scenario", "view_policy"),
        ("scenario", "change_policy"),
        ("assessment", "view_riskassessment"),
        ("assessment", "change_riskassessment"),
        ("assessment", "view_riskscenario"),
        ("assessment", "change_riskscenario"),
        ("assessment", "view_appliedcontrol"),
        ("assessment", "change_appliedcontrol"),
        ("assessment", "view_policy"),
        ("assessment", "change_policy"),
    ),
)
def test_sync_rejects_missing_read_or_write_authority_without_mutating_state(
    sync_world,
    endpoint,
    missing_permission,
):
    world = sync_world
    user = _user(world["visible"])
    full_permissions = (
        SCENARIO_SYNC_PERMISSIONS
        if endpoint == "scenario"
        else ASSESSMENT_SYNC_PERMISSIONS
    )
    _grant(user, world["visible"], *(full_permissions - {missing_permission}))
    client = _client(user)
    before = _world_state(world)

    for dry_run in ("true", "false"):
        response = client.post(
            f"{_url(world, endpoint)}?dry_run={dry_run}",
            {"reset_residual": True},
            format="json",
        )

        assert response.status_code == 403, (
            endpoint,
            missing_permission,
            dry_run,
            response.content,
        )
        assert _world_state(world) == before


def test_scenario_sync_does_not_require_control_authority_for_a_true_noop(
    sync_world,
):
    world = sync_world
    user = _user(world["visible"])
    _grant(
        user,
        world["visible"],
        "view_riskassessment",
        "view_riskscenario",
        "change_riskscenario",
    )
    client = _client(user)
    scenario = world["unaffected"]
    url = f"/api/risk-scenarios/{scenario.id}/sync-to-actions/"
    before = _world_state(world)

    for dry_run in ("true", "false"):
        response = client.post(
            f"{url}?dry_run={dry_run}",
            {"reset_residual": True},
            format="json",
        )
        assert response.status_code == 200, response.content
        assert response.json() == {"changes": []}
        assert _world_state(world) == before


@pytest.mark.parametrize("endpoint", ("scenario", "assessment"))
def test_sync_rejects_locked_parent_without_mutating_state(sync_world, endpoint):
    world = sync_world
    user = _user(world["visible"])
    permissions = (
        SCENARIO_SYNC_PERMISSIONS
        if endpoint == "scenario"
        else ASSESSMENT_SYNC_PERMISSIONS
    )
    _grant(user, world["visible"], *permissions)
    RiskAssessment.objects.filter(id=world["assessment"].id).update(is_locked=True)
    client = _client(user)
    before = _world_state(world)

    for dry_run in ("true", "false"):
        response = client.post(
            f"{_url(world, endpoint)}?dry_run={dry_run}",
            {"reset_residual": True},
            format="json",
        )
        assert response.status_code == 403, response.content
        assert _world_state(world) == before


def test_scenario_sync_mutates_only_the_authorized_frozen_source_snapshot(
    sync_world,
):
    """A relation added after authorization is neither moved nor cleared."""

    world = sync_world
    user = _user(world["visible"])
    _grant(user, world["visible"], *SCENARIO_SYNC_PERMISSIONS)
    late_control = _control(
        AppliedControl,
        world["hidden"],
        "Late inaccessible active control",
        status=AppliedControl.Status.ACTIVE,
    )
    source_through = RiskScenario.applied_controls.through
    destination_through = RiskScenario.existing_applied_controls.through

    def inject_late_source_link(sender, instance, action, **kwargs):
        if action == "pre_add" and instance.id == world["primary"].id:
            source_through.objects.get_or_create(
                riskscenario_id=instance.id,
                appliedcontrol_id=late_control.id,
            )

    dispatch_uid = f"risk-sync-frozen-{uuid.uuid4()}"
    m2m_changed.connect(
        inject_late_source_link,
        sender=destination_through,
        dispatch_uid=dispatch_uid,
    )
    try:
        response = _client(user).post(
            f"{_url(world, 'scenario')}?dry_run=false",
            {"reset_residual": True},
            format="json",
        )
    finally:
        m2m_changed.disconnect(
            sender=destination_through,
            dispatch_uid=dispatch_uid,
        )

    assert response.status_code == 200, response.content
    assert {item["id"] for item in response.json()["changes"]} == {
        str(world["ordinary"].id),
        str(world["policy"].id),
    }
    after = _scenario_state(world["primary"])
    assert after["applied"] == frozenset({late_control.id})
    assert after["existing"] == {
        world["ordinary"].id,
        world["policy"].id,
    }


@pytest.mark.parametrize("endpoint", ("scenario", "assessment"))
def test_sync_parses_string_false_without_resetting_residual(sync_world, endpoint):
    world = sync_world
    user = _user(world["visible"])
    permissions = (
        SCENARIO_SYNC_PERMISSIONS
        if endpoint == "scenario"
        else ASSESSMENT_SYNC_PERMISSIONS
    )
    _grant(user, world["visible"], *permissions)
    before = _world_state(world)

    response = _client(user).post(
        f"{_url(world, endpoint)}?dry_run=false",
        {"reset_residual": "false"},
        format="json",
    )

    assert response.status_code == 200, response.content
    affected_keys = ("primary",) if endpoint == "scenario" else ("primary", "secondary")
    for key in affected_keys:
        after = _scenario_state(world[key])
        assert after["current"] == before[key]["residual"]
        assert after["residual"] == before[key]["residual"]


@pytest.mark.parametrize("endpoint", ("scenario", "assessment"))
@pytest.mark.parametrize(
    "url_suffix,payload",
    (
        ("?dry_run=not-a-boolean", {}),
        ("?dry_run=false", {"reset_residual": "not-a-boolean"}),
    ),
)
def test_sync_rejects_invalid_boolean_input_without_mutation(
    sync_world,
    endpoint,
    url_suffix,
    payload,
):
    world = sync_world
    user = _user(world["visible"])
    permissions = (
        SCENARIO_SYNC_PERMISSIONS
        if endpoint == "scenario"
        else ASSESSMENT_SYNC_PERMISSIONS
    )
    _grant(user, world["visible"], *permissions)
    before = _world_state(world)

    response = _client(user).post(
        f"{_url(world, endpoint)}{url_suffix}", payload, format="json"
    )

    assert response.status_code == 400, response.content
    assert _world_state(world) == before


@pytest.mark.parametrize("endpoint", ("scenario", "assessment"))
def test_sync_missing_target_returns_404(endpoint, sync_world):
    user = _user(sync_world["visible"])
    client = _client(user)
    missing_id = uuid.uuid4()

    response = client.post(
        f"/api/{'risk-scenarios' if endpoint == 'scenario' else 'risk-assessments'}/"
        f"{missing_id}/sync-to-actions/",
        {},
        format="json",
    )

    assert response.status_code == 404, response.content


def test_assessment_sync_response_is_minimal_and_hides_existing_policy(sync_world):
    world = sync_world
    world["primary"].applied_controls.remove(world["policy"])
    world["secondary"].applied_controls.remove(world["policy"])
    world["primary"].existing_applied_controls.add(world["policy"])
    user = _user(world["visible"])
    _grant(
        user,
        world["visible"],
        *(ASSESSMENT_SYNC_PERMISSIONS - {"view_policy", "change_policy"}),
    )

    response = _client(user).post(_url(world, "assessment"), {}, format="json")

    assert response.status_code == 200, response.content
    assert response.json()["changes"]
    assert all(
        set(row) == {"id", "ref_id", "name", "current_level", "residual_level"}
        for row in response.json()["changes"]
    )
    rendered = response.content.decode()
    assert str(world["policy"].id) not in rendered
    assert world["policy"].name not in rendered


def test_scenario_sync_response_is_minimal(sync_world):
    world = sync_world
    user = _user(world["visible"])
    _grant(user, world["visible"], *SCENARIO_SYNC_PERMISSIONS)

    response = _client(user).post(_url(world, "scenario"), {}, format="json")

    assert response.status_code == 200, response.content
    assert response.json()["changes"]
    assert all(set(row) == {"id", "name"} for row in response.json()["changes"])
    assert "sync_mappings" not in response.content.decode()
