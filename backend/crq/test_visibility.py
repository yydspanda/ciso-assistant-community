"""Adversarial IAM coverage for CRQ parent-chain projections."""

from __future__ import annotations

import uuid

import pytest
from core.models import AppliedControl
from django.contrib.auth.models import Permission
from iam.models import Folder, Role, RoleAssignment, User
from rest_framework.test import APIClient

from crq.models import (
    QuantitativeRiskHypothesis,
    QuantitativeRiskScenario,
    QuantitativeRiskStudy,
)
from crq.visibility import visible_quantitative_risk_chain

pytestmark = pytest.mark.django_db


STUDY_PERMISSION = "view_quantitativeriskstudy"
SCENARIO_PERMISSION = "view_quantitativeriskscenario"
HYPOTHESIS_PERMISSION = "view_quantitativeriskhypothesis"
CONTROL_PERMISSION = "view_appliedcontrol"
CHAIN_PERMISSIONS = {
    STUDY_PERMISSION,
    SCENARIO_PERMISSION,
    HYPOTHESIS_PERMISSION,
    CONTROL_PERMISSION,
    "view_folder",
}
CRQ_LINKS = (
    "quantitative_risk_hypotheses_existing",
    "quantitative_risk_hypotheses_added",
    "quantitative_risk_hypotheses_removed",
)


def _grant(
    *,
    user: User,
    folders: tuple[Folder, ...],
    excluded_permissions: frozenset[str] = frozenset(),
) -> None:
    codenames = CHAIN_PERMISSIONS - excluded_permissions
    permissions = Permission.objects.filter(codename__in=codenames)
    assert set(permissions.values_list("codename", flat=True)) == codenames
    role = Role.objects.create(
        name=f"CRQ visibility {uuid.uuid4().hex}",
        folder=Folder.get_root_folder(),
    )
    role.permissions.set(permissions)
    assignment = RoleAssignment.objects.create(
        user=user,
        role=role,
        folder=Folder.get_root_folder(),
        is_recursive=True,
    )
    assignment.perimeter_folders.add(*folders)


def _user(
    world,
    *,
    excluded_permissions: frozenset[str] = frozenset(),
    include_alternate_folder: bool = False,
) -> User:
    user = User.objects.create_user(
        email=f"crq-visibility-{uuid.uuid4().hex}@tests.invalid"
    )
    folders = (world["folder"],)
    if include_alternate_folder:
        folders += (world["alternate_folder"],)
    _grant(
        user=user,
        folders=folders,
        excluded_permissions=excluded_permissions,
    )
    return user


def _control(folder: Folder, name: str) -> AppliedControl:
    return AppliedControl.objects.create(name=name, folder=folder)


def _scenario(
    *, study: QuantitativeRiskStudy, folder: Folder, name: str
) -> QuantitativeRiskScenario:
    return QuantitativeRiskScenario.objects.create(
        quantitative_risk_study=study,
        folder=folder,
        name=name,
        ref_id=f"QR-{uuid.uuid4().hex[:8]}",
    )


def _hypothesis(
    *,
    scenario: QuantitativeRiskScenario,
    folder: Folder,
    control: AppliedControl,
    name: str,
) -> QuantitativeRiskHypothesis:
    hypothesis = QuantitativeRiskHypothesis.objects.create(
        quantitative_risk_scenario=scenario,
        folder=folder,
        name=name,
        ref_id=f"H-{uuid.uuid4().hex[:8]}",
        risk_stage="residual",
        is_selected=True,
    )
    hypothesis.existing_applied_controls.add(control)
    hypothesis.added_applied_controls.add(control)
    hypothesis.removed_applied_controls.add(control)
    return hypothesis


@pytest.fixture
def crq_visibility_world():
    Folder._init_root_folder()
    root = Folder.get_root_folder()
    folder = Folder.objects.create(
        name=f"crq-visible-{uuid.uuid4().hex[:8]}",
        content_type=Folder.ContentType.DOMAIN,
        parent_folder=root,
    )
    alternate_folder = Folder.objects.create(
        name=f"crq-alternate-{uuid.uuid4().hex[:8]}",
        content_type=Folder.ContentType.DOMAIN,
        parent_folder=root,
    )

    study = QuantitativeRiskStudy.objects.create(
        name=f"Visible CRQ study {uuid.uuid4().hex}",
        ref_id=f"QRS-{uuid.uuid4().hex[:8]}",
        folder=folder,
    )

    valid_control = _control(folder, f"Valid CRQ control {uuid.uuid4().hex}")
    valid_scenario = _scenario(
        study=study,
        folder=folder,
        name=f"Visible CRQ scenario {uuid.uuid4().hex}",
    )
    valid_hypothesis = _hypothesis(
        scenario=valid_scenario,
        folder=folder,
        control=valid_control,
        name=f"Visible CRQ hypothesis {uuid.uuid4().hex}",
    )

    scenario_mismatch_control = _control(
        folder, f"Scenario-folder mismatch control {uuid.uuid4().hex}"
    )
    scenario_mismatch = _scenario(
        study=study,
        folder=alternate_folder,
        name=f"Scenario-folder mismatch {uuid.uuid4().hex}",
    )
    scenario_mismatch_hypothesis = _hypothesis(
        scenario=scenario_mismatch,
        folder=alternate_folder,
        control=scenario_mismatch_control,
        name=f"Scenario-folder mismatch hypothesis {uuid.uuid4().hex}",
    )

    hypothesis_mismatch_control = _control(
        folder, f"Hypothesis-folder mismatch control {uuid.uuid4().hex}"
    )
    hypothesis_mismatch_scenario = _scenario(
        study=study,
        folder=folder,
        name=f"Hypothesis-folder mismatch scenario {uuid.uuid4().hex}",
    )
    hypothesis_mismatch = _hypothesis(
        scenario=hypothesis_mismatch_scenario,
        folder=alternate_folder,
        control=hypothesis_mismatch_control,
        name=f"Hypothesis-folder mismatch {uuid.uuid4().hex}",
    )

    permission_chain_study = QuantitativeRiskStudy.objects.create(
        name=f"Permission-chain study {uuid.uuid4().hex}",
        ref_id=f"QRS-{uuid.uuid4().hex[:8]}",
        folder=folder,
    )
    permission_chain_control = _control(
        folder, f"Permission-chain control {uuid.uuid4().hex}"
    )
    permission_chain_scenario = _scenario(
        study=permission_chain_study,
        folder=folder,
        name=f"Permission-chain scenario {uuid.uuid4().hex}",
    )
    permission_chain_hypothesis = _hypothesis(
        scenario=permission_chain_scenario,
        folder=folder,
        control=permission_chain_control,
        name=f"Permission-chain hypothesis {uuid.uuid4().hex}",
    )

    return {
        "folder": folder,
        "alternate_folder": alternate_folder,
        "study": study,
        "valid_control": valid_control,
        "valid_scenario": valid_scenario,
        "valid_hypothesis": valid_hypothesis,
        "scenario_mismatch_control": scenario_mismatch_control,
        "scenario_mismatch": scenario_mismatch,
        "scenario_mismatch_hypothesis": scenario_mismatch_hypothesis,
        "hypothesis_mismatch_control": hypothesis_mismatch_control,
        "hypothesis_mismatch_scenario": hypothesis_mismatch_scenario,
        "hypothesis_mismatch": hypothesis_mismatch,
        "permission_chain_study": permission_chain_study,
        "permission_chain_control": permission_chain_control,
        "permission_chain_scenario": permission_chain_scenario,
        "permission_chain_hypothesis": permission_chain_hypothesis,
    }


def _client(user: User) -> APIClient:
    client = APIClient()
    client.force_authenticate(user)
    return client


def _action_plan_url(study: QuantitativeRiskStudy) -> str:
    return f"/api/crq/quantitative-risk-studies/{study.id}/action-plan/"


def _response_rows(response) -> list[dict]:
    body = response.json()
    return body.get("results", body)


@pytest.mark.parametrize(
    (
        "missing_permission",
        "expected_study",
        "expected_scenario",
        "expected_hypothesis",
    ),
    (
        (STUDY_PERMISSION, False, False, False),
        (SCENARIO_PERMISSION, True, False, False),
        (HYPOTHESIS_PERMISSION, True, True, False),
    ),
)
def test_visible_quantitative_risk_chain_requires_every_parent_permission(
    crq_visibility_world,
    missing_permission,
    expected_study,
    expected_scenario,
    expected_hypothesis,
):
    world = crq_visibility_world
    user = _user(world, excluded_permissions=frozenset({missing_permission}))

    chain = visible_quantitative_risk_chain(user=user)

    assert (
        chain.studies.filter(id=world["permission_chain_study"].id).exists()
        is expected_study
    )
    assert (
        chain.scenarios.filter(id=world["permission_chain_scenario"].id).exists()
        is expected_scenario
    )
    assert (
        chain.hypotheses.filter(id=world["permission_chain_hypothesis"].id).exists()
        is expected_hypothesis
    )


def test_visible_quantitative_risk_chain_rejects_cross_folder_children(
    crq_visibility_world,
):
    world = crq_visibility_world
    user = _user(world, include_alternate_folder=True)

    chain = visible_quantitative_risk_chain(user=user)

    assert chain.studies.filter(id=world["study"].id).exists()
    assert chain.scenarios.filter(id=world["valid_scenario"].id).exists()
    assert chain.hypotheses.filter(id=world["valid_hypothesis"].id).exists()
    assert not chain.scenarios.filter(id=world["scenario_mismatch"].id).exists()
    assert not chain.hypotheses.filter(
        id=world["scenario_mismatch_hypothesis"].id
    ).exists()
    assert chain.scenarios.filter(id=world["hypothesis_mismatch_scenario"].id).exists()
    assert not chain.hypotheses.filter(id=world["hypothesis_mismatch"].id).exists()


def test_crq_action_plan_returns_only_controls_from_a_coherent_visible_chain(
    crq_visibility_world,
):
    world = crq_visibility_world
    client = _client(_user(world, include_alternate_folder=True))

    response = client.get(_action_plan_url(world["study"]))

    assert response.status_code == 200, response.content
    rows = _response_rows(response)
    rows_by_id = {row["id"]: row for row in rows}
    assert set(rows_by_id) == {str(world["valid_control"].id)}
    assert rows_by_id[str(world["valid_control"].id)][
        "quantitative_risk_scenarios"
    ] == [
        {
            "str": (
                f"{world['valid_scenario'].ref_id} - {world['valid_scenario'].name}"
            ),
            "id": str(world["valid_scenario"].id),
        }
    ]
    rendered = response.content.decode()
    for hidden_value in (
        world["scenario_mismatch"].name,
        world["scenario_mismatch"].ref_id,
        world["hypothesis_mismatch_scenario"].name,
        world["hypothesis_mismatch_scenario"].ref_id,
    ):
        assert hidden_value not in rendered


@pytest.mark.parametrize(
    ("missing_permission", "expected_action_plan_status"),
    (
        (STUDY_PERMISSION, 403),
        (SCENARIO_PERMISSION, 200),
        (HYPOTHESIS_PERMISSION, 200),
    ),
)
def test_crq_action_plan_and_link_projection_fail_closed_when_chain_layer_hidden(
    crq_visibility_world,
    missing_permission,
    expected_action_plan_status,
):
    world = crq_visibility_world
    user = _user(world, excluded_permissions=frozenset({missing_permission}))
    client = _client(user)

    action_plan_response = client.get(_action_plan_url(world["permission_chain_study"]))
    control_response = client.get(
        f"/api/applied-controls/{world['permission_chain_control'].id}/"
    )

    assert action_plan_response.status_code == expected_action_plan_status
    rendered_action_plan = action_plan_response.content.decode()
    assert world["permission_chain_scenario"].name not in rendered_action_plan
    assert world["permission_chain_scenario"].ref_id not in rendered_action_plan
    if expected_action_plan_status == 200:
        assert _response_rows(action_plan_response) == []
    assert control_response.status_code == 200, control_response.content
    assert not set(CRQ_LINKS) & set(control_response.json()["linked_models"])


def test_applied_control_link_projection_rejects_cross_folder_crq_chains(
    crq_visibility_world,
):
    world = crq_visibility_world
    client = _client(_user(world, include_alternate_folder=True))

    controls = (
        world["valid_control"],
        world["scenario_mismatch_control"],
        world["hypothesis_mismatch_control"],
    )
    payloads = {}
    for control in controls:
        response = client.get(f"/api/applied-controls/{control.id}/")
        assert response.status_code == 200, response.content
        payloads[control.id] = response.json()

    assert set(CRQ_LINKS) <= set(payloads[world["valid_control"].id]["linked_models"])
    assert not set(CRQ_LINKS) & set(
        payloads[world["scenario_mismatch_control"].id]["linked_models"]
    )
    assert not set(CRQ_LINKS) & set(
        payloads[world["hypothesis_mismatch_control"].id]["linked_models"]
    )


def test_applied_control_link_filters_reject_cross_folder_crq_chains(
    crq_visibility_world,
):
    world = crq_visibility_world
    client = _client(_user(world, include_alternate_folder=True))
    valid_id = str(world["valid_control"].id)
    invalid_ids = {
        str(world["scenario_mismatch_control"].id),
        str(world["hypothesis_mismatch_control"].id),
    }

    for relation_name in CRQ_LINKS:
        response = client.get(
            "/api/applied-controls/", {"linked_models": relation_name}
        )
        assert response.status_code == 200, response.content
        returned_ids = {row["id"] for row in _response_rows(response)}
        assert valid_id in returned_ids
        assert not invalid_ids & returned_ids

    orphan_response = client.get("/api/applied-controls/", {"linked_models": "--"})
    assert orphan_response.status_code == 200, orphan_response.content
    orphan_ids = {row["id"] for row in _response_rows(orphan_response)}
    assert invalid_ids <= orphan_ids
    assert valid_id not in orphan_ids
