"""Exact IAM and consistency boundary for the printable EBIOS RM report.

Only objects and edges consumed by :mod:`ebios_rm.report_projection` are
authorized and locked.  Study-owned rows are locked before their relations;
cross-study identifiers are rejected before following them.  Shared rows are
then acquired in one stable phase, which avoids the former recursive graph's
duplicate/inverted lock order.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from core.models import (
    Actor,
    AppliedControl,
    Asset,
    ComplianceAssessment,
    Framework,
    Policy,
    RequirementAssessment,
    RequirementNode,
    RiskAssessment,
    RiskMatrix,
    RiskScenario,
    Team,
    Terminology,
    Threat,
)
from django.contrib.auth.models import Permission
from global_settings.models import GlobalSettings
from iam.models import Folder, RoleAssignment, User
from rest_framework.exceptions import PermissionDenied
from tprm.models import Entity

from .models import (
    AttackPath,
    EbiosRMStudy,
    ElementaryAction,
    FearedEvent,
    KillChain,
    OperatingMode,
    OperationalScenario,
    RoTo,
    Stakeholder,
    StrategicScenario,
)

DENIED = "Complete EBIOS RM report data is unavailable for this caller."


@dataclass(frozen=True, slots=True)
class AuthorizedEbiosReportGraph:
    study: EbiosRMStudy
    radar_max: int | float


def _deny() -> None:
    raise PermissionDenied(DENIED)


def _lock(queryset) -> tuple:
    return tuple(queryset.order_by("pk").select_for_update())


def _lock_relation(field, source_ids: Iterable) -> tuple:
    source_ids = set(source_ids)
    if not source_ids:
        return ()
    source_field = field.m2m_field_name()
    return _lock(
        field.remote_field.through._default_manager.filter(
            **{f"{source_field}_id__in": source_ids}
        )
    )


def _relation_target_ids(through_rows, target_attname: str) -> set:
    return {getattr(row, target_attname) for row in through_rows}


def _require_visible_ids(*, user, model, object_ids: Iterable) -> None:
    requested = set(object_ids)
    if not requested:
        return

    if model is AppliedControl:
        ordinary_ids = set(
            AppliedControl.objects.filter(id__in=requested)
            .exclude(category="policy")
            .values_list("id", flat=True)
        )
        policy_ids = set(
            AppliedControl.objects.filter(
                id__in=requested, category="policy"
            ).values_list("id", flat=True)
        )
        visible_ordinary = set(
            RoleAssignment.get_viewable_object_ids(user, AppliedControl).filter(
                id__in=ordinary_ids
            )
        )
        visible_policies = set(
            RoleAssignment.get_viewable_object_ids(user, Policy).filter(
                id__in=policy_ids
            )
        )
        if visible_ordinary != ordinary_ids or visible_policies != policy_ids:
            _deny()
        return

    try:
        viewable_ids = RoleAssignment.get_viewable_object_ids(user, model)
        # Actor visibility is assembled with SQL UNION and Django deliberately
        # rejects a subsequent filter().  Intersect the materialized UUID set
        # for combined queries; keep the bounded SQL path for ordinary models.
        if viewable_ids.query.combinator:
            visible = set(viewable_ids) & requested
        else:
            visible = set(viewable_ids.filter(id__in=requested))
    except (NotImplementedError, Permission.DoesNotExist) as exc:
        raise PermissionDenied(DENIED) from exc
    if visible != requested:
        _deny()


def _ids(rows: Iterable) -> set:
    return {row.id for row in rows}


def _require_rows(*, user, model, rows: Iterable) -> None:
    _require_visible_ids(user=user, model=model, object_ids=_ids(rows))


def authorize_ebios_report_graph(
    *, user, study: EbiosRMStudy
) -> AuthorizedEbiosReportGraph:
    """Lock and authorize the exact report projection inside an atomic block."""

    try:
        study = EbiosRMStudy.objects.select_for_update().get(id=study.id)
    except EbiosRMStudy.DoesNotExist as exc:
        raise PermissionDenied(DENIED) from exc
    _require_visible_ids(user=user, model=EbiosRMStudy, object_ids={study.id})

    # Lock every study-owned row whose scalar state can select or feed the
    # report.  These sets cannot overlap between valid studies.  Corrupt
    # cross-study foreign keys are rejected below before their target is read.
    feared_all = _lock(FearedEvent.objects.filter(ebios_rm_study=study))
    roto_all = _lock(RoTo.objects.filter(ebios_rm_study=study))
    stakeholder_all = _lock(Stakeholder.objects.filter(ebios_rm_study=study))
    strategic_all = _lock(StrategicScenario.objects.filter(ebios_rm_study=study))
    attack_all = _lock(AttackPath.objects.filter(ebios_rm_study=study))
    operational_all = _lock(OperationalScenario.objects.filter(ebios_rm_study=study))
    risk_assessments = _lock(RiskAssessment.objects.filter(ebios_rm_study=study))

    feared_by_id = {row.id: row for row in feared_all}
    roto_by_id = {row.id: row for row in roto_all}
    stakeholder_by_id = {row.id: row for row in stakeholder_all}
    strategic_by_id = {row.id: row for row in strategic_all}
    attack_by_id = {row.id: row for row in attack_all}
    operational_by_id = {row.id: row for row in operational_all}

    for rows in (
        feared_all,
        roto_all,
        stakeholder_all,
        strategic_all,
        attack_all,
        operational_all,
    ):
        if any(row.folder_id != study.folder_id for row in rows):
            _deny()

    required_roto_ids = {row.id for row in roto_all if row.is_selected}
    required_feared_ids = {row.id for row in feared_all if row.is_selected}
    required_stakeholder_ids = {row.id for row in stakeholder_all if row.is_selected}
    required_attack_ids = {row.id for row in attack_all if row.is_selected}

    for scenario in strategic_all:
        if scenario.ro_to_couple_id not in roto_by_id:
            _deny()
        required_roto_ids.add(scenario.ro_to_couple_id)
        if scenario.focused_feared_event_id is not None:
            if scenario.focused_feared_event_id not in feared_by_id:
                _deny()
            required_feared_ids.add(scenario.focused_feared_event_id)
    for scenario in operational_all:
        if scenario.attack_path_id not in attack_by_id:
            _deny()
        required_attack_ids.add(scenario.attack_path_id)
    for path_id in required_attack_ids:
        path = attack_by_id[path_id]
        if path.strategic_scenario_id not in strategic_by_id:
            _deny()

    # Freeze the exact report edges.  Locking the source rows above blocks new
    # FK-checking inserts; locking existing through rows blocks unlink/replace.
    study_asset_links = _lock_relation(
        EbiosRMStudy._meta.get_field("assets"), {study.id}
    )
    study_compliance_links = _lock_relation(
        EbiosRMStudy._meta.get_field("compliance_assessments"), {study.id}
    )
    roto_feared_links = _lock_relation(
        RoTo._meta.get_field("feared_events"), required_roto_ids
    )
    required_feared_ids.update(
        _relation_target_ids(roto_feared_links, "fearedevent_id")
    )
    selected_feared_ids = {row.id for row in feared_all if row.is_selected}
    feared_asset_links = _lock_relation(
        FearedEvent._meta.get_field("assets"), selected_feared_ids
    )
    feared_qualification_links = _lock_relation(
        FearedEvent._meta.get_field("qualifications"), selected_feared_ids
    )
    attack_stakeholder_links = _lock_relation(
        AttackPath._meta.get_field("stakeholders"), required_attack_ids
    )
    required_stakeholder_ids.update(
        _relation_target_ids(attack_stakeholder_links, "stakeholder_id")
    )
    operational_threat_links = _lock_relation(
        OperationalScenario._meta.get_field("threats"), operational_by_id
    )

    if required_feared_ids - feared_by_id.keys():
        _deny()
    if required_stakeholder_ids - stakeholder_by_id.keys():
        _deny()

    linked_feared_by_roto = {}
    for link in roto_feared_links:
        linked_feared_by_roto.setdefault(link.roto_id, set()).add(link.fearedevent_id)
    for scenario in strategic_all:
        if (
            scenario.focused_feared_event_id is not None
            and scenario.focused_feared_event_id
            not in linked_feared_by_roto.get(scenario.ro_to_couple_id, set())
        ):
            _deny()

    # Operating-mode and kill-chain rows are owned by already locked study
    # rows, so the same parent-first rule freezes their membership.
    operating_modes = _lock(
        OperatingMode.objects.filter(operational_scenario_id__in=operational_by_id)
    )
    if any(row.folder_id != study.folder_id for row in operating_modes):
        _deny()
    operating_by_id = {row.id: row for row in operating_modes}
    kill_chains = _lock(KillChain.objects.filter(operating_mode_id__in=operating_by_id))
    if any(row.folder_id != study.folder_id for row in kill_chains):
        _deny()
    kill_antecedent_links = _lock_relation(
        KillChain._meta.get_field("antecedents"), _ids(kill_chains)
    )
    elementary_action_ids = {
        row.elementary_action_id for row in kill_chains
    } | _relation_target_ids(kill_antecedent_links, "elementaryaction_id")

    # Compliance assessments can legitimately be shared by studies.  Every
    # report acquires them by PK before their owned RequirementAssessment rows.
    compliance_ids = _relation_target_ids(
        study_compliance_links, "complianceassessment_id"
    )
    compliance_assessments = _lock(
        ComplianceAssessment.objects.filter(id__in=compliance_ids)
    )
    if _ids(compliance_assessments) != compliance_ids:
        _deny()
    framework_ids = {row.framework_id for row in compliance_assessments}
    frameworks = _lock(Framework.objects.filter(id__in=framework_ids))
    if _ids(frameworks) != framework_ids:
        _deny()
    requirement_assessments = _lock(
        RequirementAssessment.objects.filter(
            compliance_assessment_id__in=compliance_ids
        )
    )
    requirement_nodes = _lock(
        RequirementNode.objects.filter(
            id__in={row.requirement_id for row in requirement_assessments}
        )
    )
    requirement_node_by_id = {row.id: row for row in requirement_nodes}
    compliance_by_id = {row.id: row for row in compliance_assessments}
    action_requirement_ids = set()
    for row in requirement_assessments:
        requirement = requirement_node_by_id.get(row.requirement_id)
        assessment = compliance_by_id.get(row.compliance_assessment_id)
        if requirement is None or assessment is None:
            _deny()
        if not requirement.assessable:
            continue
        selected_groups = set(assessment.selected_implementation_groups or ())
        if selected_groups and selected_groups.isdisjoint(
            set(requirement.implementation_groups or ())
        ):
            continue
        action_requirement_ids.add(row.id)
    requirement_control_links = _lock_relation(
        RequirementAssessment._meta.get_field("applied_controls"),
        action_requirement_ids,
    )

    # Lock every scenario of the selected latest assessment; this freezes both
    # ordering and all raw scores used by the risk DTO.
    latest_risk_assessment = max(
        risk_assessments,
        key=lambda row: (row.created_at, str(row.id)),
        default=None,
    )
    risk_scenarios = ()
    risk_control_links = ()
    if latest_risk_assessment is not None:
        risk_scenarios = _lock(
            RiskScenario.objects.filter(risk_assessment=latest_risk_assessment)
        )
        if any(
            row.folder_id != latest_risk_assessment.folder_id for row in risk_scenarios
        ):
            _deny()
        risk_control_links = _lock_relation(
            RiskScenario._meta.get_field("applied_controls"),
            _ids(risk_scenarios),
        )

    selected_stakeholders = {row.id for row in stakeholder_all if row.is_selected}
    stakeholder_control_links = _lock_relation(
        Stakeholder._meta.get_field("applied_controls"), selected_stakeholders
    )

    # Gather shared dependency IDs before acquiring them.  From this point all
    # report requests use the same model phase and PK order.
    asset_ids = _relation_target_ids(study_asset_links, "asset_id")
    asset_ids.update(_relation_target_ids(feared_asset_links, "asset_id"))
    terminology_ids = {
        roto_by_id[item_id].risk_origin_id for item_id in required_roto_ids
    }
    terminology_ids.update(
        stakeholder_by_id[item_id].category_id for item_id in required_stakeholder_ids
    )
    terminology_ids.update(
        _relation_target_ids(feared_qualification_links, "terminology_id")
    )
    entity_ids = {
        stakeholder_by_id[item_id].entity_id for item_id in required_stakeholder_ids
    }
    threat_ids = _relation_target_ids(operational_threat_links, "threat_id")
    control_ids = _relation_target_ids(stakeholder_control_links, "appliedcontrol_id")
    control_ids.update(
        _relation_target_ids(requirement_control_links, "appliedcontrol_id")
    )
    control_ids.update(_relation_target_ids(risk_control_links, "appliedcontrol_id"))
    matrix_ids = {study.risk_matrix_id}
    if latest_risk_assessment is not None:
        matrix_ids.add(latest_risk_assessment.risk_matrix_id)

    assets = _lock(Asset.objects.filter(id__in=asset_ids))
    elementary_actions = _lock(
        ElementaryAction.objects.filter(id__in=elementary_action_ids)
    )
    matrices = _lock(RiskMatrix.objects.filter(id__in=matrix_ids))
    terminologies = _lock(Terminology.objects.filter(id__in=terminology_ids))
    threats = _lock(Threat.objects.filter(id__in=threat_ids))

    # Controls precede their owner edges and Actor display dependencies in all
    # reports.  Each model is acquired once, ordered by PK.
    controls = _lock(AppliedControl.objects.filter(id__in=control_ids))
    control_owner_links = _lock_relation(
        AppliedControl._meta.get_field("owner"), control_ids
    )
    owner_ids = _relation_target_ids(control_owner_links, "actor_id")
    actors = _lock(Actor.objects.filter(id__in=owner_ids))
    user_ids = {row.user_id for row in actors if row.user_id is not None}
    team_ids = {row.team_id for row in actors if row.team_id is not None}
    actor_entity_ids = {row.entity_id for row in actors if row.entity_id is not None}
    _lock(User.objects.filter(id__in=user_ids))
    _lock(Team.objects.filter(id__in=team_ids))
    # A stakeholder entity in one report may be a control-owner entity in
    # another.  Lock the complete Entity projection once, in PK order, so two
    # reports cannot acquire the same pair in opposite phases.
    entity_ids.update(actor_entity_ids)
    entities = _lock(Entity.objects.filter(id__in=entity_ids))

    asset_folder_ids = {row.folder_id for row in assets if row.folder_id is not None}
    folders = _lock(Folder.objects.filter(id__in=asset_folder_ids))

    # Exact visibility checks mirror the DTO, not the generic edit serializers.
    for model, rows in (
        (Asset, assets),
        (FearedEvent, tuple(feared_by_id[item] for item in required_feared_ids)),
        (RoTo, tuple(roto_by_id[item] for item in required_roto_ids)),
        (
            Stakeholder,
            tuple(stakeholder_by_id[item] for item in required_stakeholder_ids),
        ),
        (StrategicScenario, strategic_all),
        (
            AttackPath,
            tuple(attack_by_id[item] for item in required_attack_ids),
        ),
        (OperationalScenario, operational_all),
        (OperatingMode, operating_modes),
        (KillChain, kill_chains),
        (ElementaryAction, elementary_actions),
        (Entity, entities),
        (Framework, frameworks),
        (Terminology, terminologies),
        (Threat, threats),
        (RiskMatrix, matrices),
        (ComplianceAssessment, compliance_assessments),
        (RequirementAssessment, requirement_assessments),
        (RequirementNode, requirement_nodes),
        (Actor, actors),
        (Folder, folders),
    ):
        _require_rows(user=user, model=model, rows=rows)
    if latest_risk_assessment is not None:
        _require_rows(
            user=user,
            model=RiskAssessment,
            rows=(latest_risk_assessment,),
        )
        _require_rows(user=user, model=RiskScenario, rows=risk_scenarios)
    _require_visible_ids(user=user, model=AppliedControl, object_ids=control_ids)

    if _ids(assets) != asset_ids:
        _deny()
    if _ids(elementary_actions) != elementary_action_ids:
        _deny()
    if _ids(entities) != entity_ids:
        _deny()
    if _ids(matrices) != matrix_ids:
        _deny()
    if _ids(terminologies) != terminology_ids:
        _deny()
    if _ids(threats) != threat_ids:
        _deny()
    if _ids(controls) != control_ids:
        _deny()
    if _ids(actors) != owner_ids:
        _deny()

    # Freeze just the setting consumed by the radar helper.  The larger
    # GlobalSettings JSON remains outside the report's authority surface.
    general_settings = GlobalSettings.objects.get(name="general")
    radar_max = general_settings.value.get("ebios_radar_max", 6)
    return AuthorizedEbiosReportGraph(study=study, radar_max=radar_max)
