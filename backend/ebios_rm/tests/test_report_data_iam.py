"""Fail-closed IAM regressions for the EBIOS RM report projection."""

from __future__ import annotations

import json
import threading
import time
import uuid

import pytest
from core.models import (
    AppliedControl,
    ComplianceAssessment,
    Evidence,
    Framework,
    Policy,
    RequirementAssessment,
    RequirementNode,
    RiskAssessment,
    RiskMatrix,
    RiskScenario,
    Terminology,
    Threat,
    ValidationFlow,
)
from django.contrib.auth.models import Permission
from django.db import OperationalError, close_old_connections
from ebios_rm import report_authority, report_projection
from ebios_rm.models import (
    AttackPath,
    EbiosRMStudy,
    FearedEvent,
    OperationalScenario,
    RoTo,
    Stakeholder,
    StrategicScenario,
)
from global_settings.models import GlobalSettings
from iam.models import Folder, Role, RoleAssignment, User
from rest_framework.test import APIClient
from tprm.models import Entity

pytestmark = pytest.mark.django_db


REPORT_PERMISSIONS = {
    "view_appliedcontrol",
    "view_attackpath",
    "view_ebiosrmstudy",
    "view_entity",
    "view_fearedevent",
    "view_folder",
    "view_operationalscenario",
    "view_riskassessment",
    "view_riskmatrix",
    "view_riskscenario",
    "view_roto",
    "view_strategicscenario",
    "view_terminology",
}


def _domain(label: str) -> Folder:
    return Folder.objects.create(
        name=f"report-data-{label}-{uuid.uuid4().hex[:8]}",
        content_type=Folder.ContentType.DOMAIN,
        parent_folder=Folder.get_root_folder(),
    )


def _grant(user: User, folder: Folder, *codenames: str) -> None:
    role = Role.objects.create(
        name=f"EBIOS report reader {uuid.uuid4().hex}",
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
        name=f"Report matrix {uuid.uuid4().hex}",
        urn=f"urn:test:ebios-report-matrix:{uuid.uuid4().hex}",
        folder=folder,
        json_definition={
            "probability": [{"name": "Possible"}],
            "impact": [{"name": "Limited"}],
            "risk": [{"name": "Low", "hexcolor": "#65a30d"}],
            "grid": [[0]],
        },
    )


def _control(folder: Folder) -> AppliedControl:
    control = AppliedControl(
        name=f"Report control {uuid.uuid4().hex}",
        folder=folder,
        category="technical",
        status=AppliedControl.Status.ACTIVE,
    )
    control.save(skip_sync=True)
    return control


def _study(folder: Folder) -> EbiosRMStudy:
    return EbiosRMStudy.objects.create(
        name=f"EBIOS report study {uuid.uuid4().hex}",
        folder=folder,
        risk_matrix=_matrix(folder),
        reference_entity=Entity.objects.create(
            name=f"EBIOS report entity {uuid.uuid4().hex}",
            folder=folder,
        ),
    )


def _ebios_chain(study: EbiosRMStudy, label: str):
    origin = Terminology.objects.create(
        name=f"{label} origin {uuid.uuid4().hex}",
        folder=study.folder,
        field_path=Terminology.FieldPath.ROTO_RISK_ORIGIN,
        is_visible=True,
    )
    feared_event = FearedEvent.objects.create(
        name=f"{label} feared event {uuid.uuid4().hex}",
        ebios_rm_study=study,
        is_selected=True,
        gravity=0,
    )
    ro_to = RoTo.objects.create(
        ebios_rm_study=study,
        risk_origin=origin,
        target_objective=f"{label} target {uuid.uuid4().hex}",
        is_selected=True,
    )
    ro_to.feared_events.add(feared_event)
    strategic = StrategicScenario.objects.create(
        name=f"{label} strategic {uuid.uuid4().hex}",
        ebios_rm_study=study,
        ro_to_couple=ro_to,
    )
    attack_path = AttackPath.objects.create(
        name=f"{label} attack path {uuid.uuid4().hex}",
        ebios_rm_study=study,
        strategic_scenario=strategic,
        is_selected=True,
    )
    operational = OperationalScenario.objects.create(
        ebios_rm_study=study,
        attack_path=attack_path,
        likelihood=0,
        is_selected=True,
    )
    return {
        "origin": origin,
        "feared_event": feared_event,
        "ro_to": ro_to,
        "strategic": strategic,
        "attack_path": attack_path,
        "operational": operational,
    }


def _attach_compliance_graph(world):
    folder = world["visible"]
    framework = Framework.objects.create(
        name=f"Report framework {uuid.uuid4().hex}",
        urn=f"urn:test:ebios-report-framework:{uuid.uuid4().hex}",
        ref_id="REPORT-FRAMEWORK",
        folder=folder,
        min_score=0,
        max_score=4,
    )
    requirement = RequirementNode.objects.create(
        name=f"Report requirement {uuid.uuid4().hex}",
        urn=f"{framework.urn}:requirement",
        ref_id="REPORT-REQ",
        framework=framework,
        folder=folder,
        assessable=True,
    )
    assessment = ComplianceAssessment.objects.create(
        name=f"Report compliance assessment {uuid.uuid4().hex}",
        framework=framework,
        folder=folder,
        min_score=0,
        max_score=4,
        status="in_progress",
        field_visibility={
            field: {"auditor": "edit", "respondent": "hidden"}
            for field in ("status", "result", "applied_controls")
        }
        | {
            field: {"auditor": "hidden", "respondent": "hidden"}
            for field in ("extended_result", "evidences")
        },
    )
    requirement_assessment = RequirementAssessment.objects.create(
        compliance_assessment=assessment,
        requirement=requirement,
        folder=folder,
        status=RequirementAssessment.Status.DONE,
        result=RequirementAssessment.Result.COMPLIANT,
    )
    world["study"].compliance_assessments.add(assessment)
    _grant(
        world["user"],
        folder,
        "view_complianceassessment",
        "view_compliance_assessment_full",
        "view_framework",
        "view_requirementassessment",
        "view_requirementnode",
    )
    return assessment, requirement, requirement_assessment


@pytest.fixture
def report_world(monkeypatch):
    Folder._init_root_folder()
    visible = _domain("visible")
    hidden = _domain("hidden")
    user = User.objects.create_user(email=f"ebios-report-{uuid.uuid4().hex}@iam.tests")
    user.folder = visible
    user.save(update_fields=["folder"])
    _grant(user, visible, *REPORT_PERMISSIONS)

    # Metrics are orthogonal to this read-boundary regression and make the
    # fixture depend on unrelated metrology bootstrap state.
    monkeypatch.setattr(RiskAssessment, "upsert_daily_metrics", lambda self: None)

    matrix = _matrix(visible)
    entity = Entity.objects.create(
        name=f"Report entity {uuid.uuid4().hex}", folder=visible
    )
    study = EbiosRMStudy.objects.create(
        name=f"Visible EBIOS study {uuid.uuid4().hex}",
        folder=visible,
        risk_matrix=matrix,
        reference_entity=entity,
    )
    assessment = RiskAssessment.objects.create(
        name=f"Visible report assessment {uuid.uuid4().hex}",
        folder=visible,
        risk_matrix=matrix,
        ebios_rm_study=study,
    )
    scenario = RiskScenario.objects.create(
        name=f"Visible report scenario {uuid.uuid4().hex}",
        ref_id="REPORT-1",
        folder=visible,
        risk_assessment=assessment,
        current_proba=0,
        current_impact=0,
        residual_proba=0,
        residual_impact=0,
    )
    control = _control(visible)
    scenario.applied_controls.add(control)

    return {
        "client": _client(user),
        "user": user,
        "visible": visible,
        "hidden": hidden,
        "study": study,
        "assessment": assessment,
        "scenario": scenario,
        "control": control,
    }


def _report_url(study: EbiosRMStudy) -> str:
    return f"/api/ebios-rm/studies/{study.id}/report-data/"


def test_report_data_succeeds_for_complete_same_domain_authority(report_world):
    world = report_world

    response = world["client"].get(_report_url(world["study"]))

    assert response.status_code == 200, response.content
    payload = response.json()
    assert payload["risk_matrix_data"]["risk_assessment"]["id"] == str(
        world["assessment"].id
    )
    assert {row["id"] for row in payload["risk_matrix_data"]["risk_scenarios"]} == {
        str(world["scenario"].id)
    }
    assert set(payload["study"]) == {
        "id",
        "name",
        "description",
        "version",
        "status",
        "observation",
        "quotation_method",
        "assets",
    }
    assert set(payload["risk_matrix_data"]["risk_scenarios"][0]) == {
        "id",
        "ref_id",
        "name",
        "treatment",
        "inherent_proba",
        "inherent_impact",
        "inherent_level",
        "current_proba",
        "current_impact",
        "current_level",
        "residual_proba",
        "residual_impact",
        "residual_level",
        "strength_of_knowledge",
    }
    assert {row["id"] for row in payload["risk_action_plan"]["applied_controls"]} == {
        str(world["control"].id)
    }
    assert set(payload["risk_action_plan"]["applied_controls"][0]) == {
        "id",
        "name",
        "str",
        "category",
        "priority",
        "status",
        "owner",
        "eta",
    }


def test_report_projection_omits_edit_only_risk_and_study_relations(report_world):
    payload = report_world["client"].get(_report_url(report_world["study"])).json()

    assert "authors" not in payload["study"]
    assert "reviewers" not in payload["study"]
    assert "validation_flows" not in payload["study"]
    scenario = payload["risk_matrix_data"]["risk_scenarios"][0]
    assert "threats" not in scenario
    assert "assets" not in scenario
    assert "applied_controls" not in scenario


def test_report_data_succeeds_for_a_populated_same_study_ebios_graph(report_world):
    world = report_world
    chain = _ebios_chain(world["study"], "visible")
    RiskScenario.objects.filter(id=world["scenario"].id).update(
        operational_scenario=chain["operational"]
    )

    response = world["client"].get(_report_url(world["study"]))

    assert response.status_code == 200, response.content
    payload = response.json()
    assert {row["id"] for row in payload["feared_events"]} == {
        str(chain["feared_event"].id)
    }
    assert {row["id"] for row in payload["strategic_scenarios"]} == {
        str(chain["strategic"].id)
    }
    assert {row["id"] for row in payload["operational_scenarios"]} == {
        str(chain["operational"].id)
    }


@pytest.mark.django_db(transaction=True)
def test_report_data_blocks_cross_study_m2m_aba_during_serialization(
    report_world,
    monkeypatch,
):
    world = report_world
    visible_chain = _ebios_chain(world["study"], "aba-visible")
    hidden_chain = _ebios_chain(_study(world["hidden"]), "aba-hidden")
    hidden_committed = threading.Event()
    serialization_finished = threading.Event()
    worker_errors = []
    worker_box = {}

    def retry_locked(operation):
        deadline = time.monotonic() + 10
        while True:
            try:
                operation()
                return
            except OperationalError:
                close_old_connections()
                if time.monotonic() >= deadline:
                    raise
                time.sleep(0.05)

    def aba_writer():
        close_old_connections()
        try:
            retry_locked(
                lambda: RoTo.objects.get(
                    id=visible_chain["ro_to"].id
                ).feared_events.add(hidden_chain["feared_event"])
            )
            hidden_committed.set()
            if not serialization_finished.wait(timeout=10):
                raise AssertionError("report serialization did not finish")
            retry_locked(
                lambda: RoTo.objects.get(
                    id=visible_chain["ro_to"].id
                ).feared_events.remove(hidden_chain["feared_event"])
            )
        except Exception as exc:  # noqa: BLE001 - propagated below
            worker_errors.append(exc)
        finally:
            close_old_connections()

    original_serialize = report_projection.strategic_scenarios

    def serialize_while_writer_attempts_aba(rows):
        if "thread" not in worker_box:
            worker_box["thread"] = threading.Thread(target=aba_writer, daemon=True)
            worker_box["thread"].start()
            # With correct row locking the writer cannot commit this hidden
            # cross-study edge until the frozen report transaction exits.
            hidden_committed.wait(timeout=0.25)
        data = original_serialize(rows)
        serialization_finished.set()
        return data

    original_digest = report_projection.canonical_report_digest

    def wait_for_aba_then_digest(payload):
        if "thread" in worker_box:
            worker_box["thread"].join(timeout=12)
            assert not worker_box["thread"].is_alive()
            assert not worker_errors
        return original_digest(payload)

    monkeypatch.setattr(
        report_projection,
        "strategic_scenarios",
        serialize_while_writer_attempts_aba,
    )
    monkeypatch.setattr(
        report_projection,
        "canonical_report_digest",
        wait_for_aba_then_digest,
    )

    response = world["client"].get(_report_url(world["study"]))

    assert response.status_code == 200, response.content
    rendered = response.content.decode()
    assert str(hidden_chain["feared_event"].id) not in rendered
    assert hidden_chain["feared_event"].name not in rendered


@pytest.mark.parametrize(
    "hidden_relation",
    ("risk_assessment", "risk_scenario", "applied_control"),
)
def test_report_data_fails_closed_when_risk_graph_crosses_an_unreadable_domain(
    report_world,
    hidden_relation,
):
    world = report_world
    hidden = world["hidden"]

    if hidden_relation == "risk_assessment":
        RiskAssessment.objects.filter(id=world["assessment"].id).update(folder=hidden)
    elif hidden_relation == "risk_scenario":
        # RiskScenario.save() normally realigns this field with its parent.
        # A direct update models legacy/corrupt cross-domain data and proves the
        # comprehensive report does not silently emit a partial graph.
        RiskScenario.objects.filter(id=world["scenario"].id).update(folder=hidden)
    elif hidden_relation == "applied_control":
        AppliedControl.objects.filter(id=world["control"].id).update(folder=hidden)
    else:  # pragma: no cover - parametrization contract
        raise AssertionError(hidden_relation)

    target_model, target = {
        "risk_assessment": (RiskAssessment, world["assessment"]),
        "risk_scenario": (RiskScenario, world["scenario"]),
        "applied_control": (AppliedControl, world["control"]),
    }[hidden_relation]
    assert world["study"].id in RoleAssignment.get_viewable_object_ids(
        world["user"], EbiosRMStudy
    )
    assert target.id not in RoleAssignment.get_viewable_object_ids(
        world["user"], target_model
    )

    response = world["client"].get(_report_url(world["study"]))

    assert response.status_code == 403, response.content
    assert response.json() == {
        "detail": "Complete EBIOS RM report data is unavailable for this caller."
    }
    rendered = response.content.decode()
    for protected in (
        world["assessment"],
        world["scenario"],
        world["control"],
    ):
        assert str(protected.id) not in rendered
        assert protected.name not in rendered


def test_report_data_rejects_a_cross_study_strategic_projection(report_world):
    world = report_world
    hidden_chain = _ebios_chain(_study(world["hidden"]), "hidden-strategic")
    strategic = StrategicScenario.objects.create(
        name=f"Visible shell {uuid.uuid4().hex}",
        ebios_rm_study=world["study"],
        ro_to_couple=hidden_chain["ro_to"],
    )

    response = world["client"].get(_report_url(world["study"]))

    assert response.status_code == 403, response.content
    rendered = response.content.decode()
    for protected in (
        hidden_chain["ro_to"],
        hidden_chain["feared_event"],
    ):
        assert str(protected.id) not in rendered
        assert str(protected) not in rendered
    assert str(strategic.id) not in rendered


def test_report_data_rejects_a_cross_study_operational_projection(report_world):
    world = report_world
    hidden_chain = _ebios_chain(_study(world["hidden"]), "hidden-operational")
    hidden_chain["operational"].delete()
    operational = OperationalScenario.objects.create(
        ebios_rm_study=world["study"],
        attack_path=hidden_chain["attack_path"],
        likelihood=0,
        is_selected=True,
    )

    response = world["client"].get(_report_url(world["study"]))

    assert response.status_code == 403, response.content
    rendered = response.content.decode()
    for protected in (
        hidden_chain["attack_path"],
        hidden_chain["strategic"],
    ):
        assert str(protected.id) not in rendered
        assert str(protected) not in rendered
    assert str(operational.id) not in rendered


def test_report_data_does_not_expand_authority_to_unrendered_risk_relations(
    report_world,
):
    world = report_world
    _grant(world["user"], world["visible"], "view_threat")
    threat = Threat.objects.create(
        name=f"Hidden report threat {uuid.uuid4().hex}",
        folder=world["hidden"],
        is_published=False,
    )
    world["scenario"].threats.add(threat)

    response = world["client"].get(_report_url(world["study"]))

    assert response.status_code == 200, response.content
    rendered = response.content.decode()
    assert str(threat.id) not in rendered
    assert threat.name not in rendered


def test_report_data_does_not_treat_existing_controls_as_action_items(report_world):
    world = report_world
    existing = _control(world["hidden"])
    world["scenario"].existing_applied_controls.add(existing)

    response = world["client"].get(_report_url(world["study"]))

    assert response.status_code == 200, response.content
    assert {
        row["id"] for row in response.json()["risk_action_plan"]["applied_controls"]
    } == {str(world["control"].id)}
    rendered = response.content.decode()
    assert str(existing.id) not in rendered
    assert existing.name not in rendered


def test_report_data_requires_policy_proxy_authority(report_world):
    world = report_world
    policy = Policy(
        name=f"Report policy {uuid.uuid4().hex}",
        folder=world["visible"],
        status=AppliedControl.Status.ACTIVE,
    )
    policy.save(skip_sync=True)
    world["scenario"].applied_controls.add(policy)
    assert policy.id in RoleAssignment.get_viewable_object_ids(
        world["user"], AppliedControl
    )
    assert policy.id not in RoleAssignment.get_viewable_object_ids(
        world["user"], Policy
    )

    rejected = world["client"].get(_report_url(world["study"]))

    assert rejected.status_code == 403, rejected.content
    assert str(policy.id) not in rejected.content.decode()
    assert policy.name not in rejected.content.decode()

    _grant(world["user"], world["visible"], "view_policy")
    accepted = world["client"].get(_report_url(world["study"]))

    assert accepted.status_code == 200, accepted.content
    assert {
        row["id"] for row in accepted.json()["risk_action_plan"]["applied_controls"]
    } == {str(world["control"].id), str(policy.id)}


def test_report_data_projects_a_policy_with_policy_only_authority(report_world):
    world = report_world
    world["scenario"].applied_controls.remove(world["control"])
    for role in Role.objects.filter(
        id__in=RoleAssignment.objects.filter(user=world["user"]).values("role_id")
    ):
        role.permissions.remove(Permission.objects.get(codename="view_appliedcontrol"))
    _grant(world["user"], world["visible"], "view_policy")
    policy = Policy(
        name=f"Policy-only report row {uuid.uuid4().hex}",
        folder=world["visible"],
        status=AppliedControl.Status.ACTIVE,
    )
    policy.save(skip_sync=True)
    world["scenario"].applied_controls.add(policy)

    response = world["client"].get(_report_url(world["study"]))

    assert response.status_code == 200, response.content
    payload = response.json()
    scenario_row = payload["risk_matrix_data"]["risk_scenarios"][0]
    assert "applied_controls" not in scenario_row
    action_rows = payload["risk_action_plan"]["applied_controls"]
    assert {row["id"] for row in action_rows} == {str(policy.id)}
    assert action_rows[0]["category"] == "policy"


def test_report_data_ignores_unrendered_validation_approver(report_world):
    world = report_world
    _grant(
        world["user"],
        world["visible"],
        "view_validationflow",
        "view_user",
    )
    hidden_approver = User.objects.create_user(
        email=f"hidden-approver-{uuid.uuid4().hex}@iam.tests"
    )
    hidden_approver.folder = world["hidden"]
    hidden_approver.first_name = f"Hidden-{uuid.uuid4().hex}"
    hidden_approver.save(update_fields=["folder", "first_name"])
    flow = ValidationFlow.objects.create(
        ref_id=f"REPORT-FLOW-{uuid.uuid4().hex}",
        folder=world["visible"],
        approver=hidden_approver,
    )
    flow.ebios_studies.add(world["study"])

    response = world["client"].get(_report_url(world["study"]))

    assert response.status_code == 200, response.content
    rendered = response.content.decode()
    assert str(hidden_approver.id) not in rendered
    assert hidden_approver.email not in rendered
    assert hidden_approver.first_name not in rendered


def test_report_data_reproves_root_study_permission(report_world, monkeypatch):
    world = report_world
    original = report_projection.study

    def revoke_after_serialization(instance):
        data = original(instance)
        permission = Permission.objects.get(codename="view_ebiosrmstudy")
        for role in Role.objects.filter(
            id__in=RoleAssignment.objects.filter(user=world["user"]).values("role_id")
        ):
            role.permissions.remove(permission)
        return data

    monkeypatch.setattr(
        report_projection,
        "study",
        revoke_after_serialization,
    )

    response = world["client"].get(_report_url(world["study"]))

    assert response.status_code == 403, response.content


def test_report_data_binds_rendered_actor_display_values(report_world, monkeypatch):
    world = report_world
    _grant(world["user"], world["visible"], "view_user")
    owner = User.objects.create_user(
        email=f"visible-owner-{uuid.uuid4().hex}@iam.tests"
    )
    owner.folder = world["visible"]
    owner.save(update_fields=["folder"])
    world["control"].owner.add(owner.actor)
    original = report_projection.study

    def mutate_owner_after_payload(instance):
        data = original(instance)
        User.objects.filter(id=owner.id).update(
            email=f"changed-owner-{uuid.uuid4().hex}@iam.tests"
        )
        return data

    monkeypatch.setattr(
        report_projection,
        "study",
        mutate_owner_after_payload,
    )

    response = world["client"].get(_report_url(world["study"]))

    assert response.status_code == 403, response.content


def test_report_data_locks_stakeholder_and_owner_entities_in_one_batch(
    report_world,
    monkeypatch,
):
    world = report_world
    _grant(world["user"], world["visible"], "view_stakeholder")
    category = Terminology.objects.create(
        name=f"Entity lock category {uuid.uuid4().hex}",
        folder=world["visible"],
        field_path=Terminology.FieldPath.ENTITY_RELATIONSHIP,
        is_visible=True,
    )
    stakeholder_entity = Entity.objects.create(
        name=f"Stakeholder entity {uuid.uuid4().hex}",
        folder=world["visible"],
    )
    owner_entity = Entity.objects.create(
        name=f"Owner entity {uuid.uuid4().hex}",
        folder=world["visible"],
    )
    Stakeholder.objects.create(
        ebios_rm_study=world["study"],
        entity=stakeholder_entity,
        category=category,
        is_selected=True,
    )
    world["control"].owner.add(owner_entity.actor)

    entity_lock_batches = []
    original_lock = report_authority._lock

    def capture_entity_lock(queryset):
        if queryset.model is Entity:
            entity_lock_batches.append(set(queryset.values_list("id", flat=True)))
        return original_lock(queryset)

    monkeypatch.setattr(report_authority, "_lock", capture_entity_lock)

    response = world["client"].get(_report_url(world["study"]))

    assert response.status_code == 200, response.content
    expected_batch = {stakeholder_entity.id, owner_entity.id}
    assert entity_lock_batches == [expected_batch, expected_batch]


def test_report_data_succeeds_for_a_complete_compliance_projection(report_world):
    world = report_world
    assessment, _, _ = _attach_compliance_graph(world)

    response = world["client"].get(_report_url(world["study"]))

    assert response.status_code == 200, response.content
    assessment_rows = response.json()["compliance_assessments"]
    assert {row["id"] for row in assessment_rows} == {str(assessment.id)}
    assert assessment_rows[0]["progress"] == 100


def test_report_data_does_not_require_unrendered_compliance_evidence(report_world):
    world = report_world
    _, _, requirement_assessment = _attach_compliance_graph(world)
    hidden_evidence = Evidence.objects.create(
        name=f"Unrendered evidence {uuid.uuid4().hex}",
        folder=world["hidden"],
    )
    requirement_assessment.evidences.add(hidden_evidence)

    response = world["client"].get(_report_url(world["study"]))

    assert response.status_code == 200, response.content
    rendered = response.content.decode()
    assert str(hidden_evidence.id) not in rendered
    assert hidden_evidence.name not in rendered


def test_report_data_uses_the_risk_assessment_matrix_for_scenarios(report_world):
    world = report_world
    assessment_matrix = _matrix(world["visible"])
    assessment_matrix.json_definition = {
        "probability": [{"name": "Assessment probability"}],
        "impact": [{"name": "Assessment impact"}],
        "risk": [{"name": "Assessment risk", "hexcolor": "#123456"}],
        "grid": [[0]],
    }
    assessment_matrix.save(update_fields=["json_definition"])
    RiskAssessment.objects.filter(id=world["assessment"].id).update(
        risk_matrix=assessment_matrix
    )

    response = world["client"].get(_report_url(world["study"]))

    assert response.status_code == 200, response.content
    payload = response.json()["risk_matrix_data"]
    matrix_definition = payload["risk_matrix"]["json_definition"]
    if isinstance(matrix_definition, str):
        matrix_definition = json.loads(matrix_definition)
    assert matrix_definition["risk"][0]["name"] == "Assessment risk"
    assert payload["risk_scenarios"][0]["current_level"]["name"] == ("Assessment risk")


def test_report_data_binds_the_frozen_radar_setting(report_world, monkeypatch):
    world = report_world
    _grant(world["user"], world["visible"], "view_stakeholder")
    category = Terminology.objects.create(
        name=f"Radar category {uuid.uuid4().hex}",
        folder=world["visible"],
        field_path=Terminology.FieldPath.ENTITY_RELATIONSHIP,
        is_visible=True,
    )
    entity = Entity.objects.create(
        name=f"Radar entity {uuid.uuid4().hex}",
        folder=world["visible"],
    )
    Stakeholder.objects.create(
        ebios_rm_study=world["study"],
        entity=entity,
        category=category,
        is_selected=True,
        current_dependency=1,
        current_penetration=1,
        current_maturity=1,
        current_trust=1,
        residual_dependency=1,
        residual_penetration=1,
        residual_maturity=1,
        residual_trust=1,
    )
    general = GlobalSettings.objects.get(name="general")
    first_value = dict(general.value)
    first_value["ebios_radar_max"] = 6
    GlobalSettings.objects.filter(id=general.id).update(value=first_value)

    original = report_projection.study
    mutated = False

    def mutate_setting_after_payload(instance):
        nonlocal mutated
        data = original(instance)
        if not mutated:
            mutated = True
            changed_value = dict(first_value)
            changed_value["ebios_radar_max"] = 9
            GlobalSettings.objects.filter(id=general.id).update(value=changed_value)
        return data

    monkeypatch.setattr(report_projection, "study", mutate_setting_after_payload)

    response = world["client"].get(_report_url(world["study"]))

    assert response.status_code == 403, response.content
    assert response.json() == {
        "detail": "Complete EBIOS RM report data changed during rendering."
    }


def test_report_data_binds_requirement_node_aggregate_inputs(
    report_world,
    monkeypatch,
):
    world = report_world
    assessment, requirement, _ = _attach_compliance_graph(world)
    original = report_projection.study

    def mutate_requirement_after_payload(instance):
        data = original(instance)
        RequirementNode.objects.filter(id=requirement.id).update(assessable=False)
        return data

    monkeypatch.setattr(
        report_projection,
        "study",
        mutate_requirement_after_payload,
    )

    response = world["client"].get(_report_url(world["study"]))

    assert response.status_code == 403, response.content
    assert str(assessment.id) not in response.content.decode()


def test_report_data_turns_a_concurrent_compliance_delete_into_403(
    report_world,
    monkeypatch,
):
    world = report_world
    assessment, _, _ = _attach_compliance_graph(world)
    original = report_projection.study
    deleted = False

    def delete_assessment_after_payload(instance):
        nonlocal deleted
        data = original(instance)
        if not deleted:
            deleted = True
            ComplianceAssessment.objects.filter(id=assessment.id).delete()
        return data

    monkeypatch.setattr(
        report_projection,
        "study",
        delete_assessment_after_payload,
    )

    response = world["client"].get(_report_url(world["study"]))

    assert response.status_code == 403, response.content
    assert response.json() == {
        "detail": "Complete EBIOS RM report data changed during rendering."
    }


def test_report_data_reproves_the_graph_after_payload_materialization(
    report_world,
    monkeypatch,
):
    world = report_world
    original = report_projection.study

    def mutate_after_serialization(instance):
        data = original(instance)
        RiskScenario.objects.filter(id=world["scenario"].id).update(
            name=f"Changed during report {uuid.uuid4().hex}"
        )
        return data

    monkeypatch.setattr(
        report_projection,
        "study",
        mutate_after_serialization,
    )

    response = world["client"].get(_report_url(world["study"]))

    assert response.status_code == 403, response.content
    assert response.json() == {
        "detail": "Complete EBIOS RM report data changed during rendering."
    }
