"""Caller-scoped derived metadata for AppliedControl API responses.

The underlying model helpers intentionally describe the complete database
relationship graph.  HTTP responses must not reuse those helpers because a
visible control can be linked to findings, risks, or assessment rows that the
caller cannot see.  This module builds one bounded projection for a page of
controls and fails closed when no authenticated request authority is present.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any
from uuid import UUID

from django.contrib.auth.models import Permission
from django.db.models import Model, Q
from iam.models import RoleAssignment

from core.models import (
    Actor,
    AppliedControl,
    Comment,
    Finding,
    Incident,
    Policy,
    RequirementAssessment,
    RiskAssessment,
    RiskScenario,
    TaskTemplate,
    Vulnerability,
)
from core.requirement_assessment_relationships import (
    visible_requirement_assessment_rows,
)

LINKED_RELATION_NAMES: tuple[str, ...] = (
    "requirement_assessments",
    "risk_scenarios",
    "risk_scenarios_e",
    "findings",
    "vulnerabilities",
    "stakeholders",
    "processings",
    "data_breaches_remediated",
    "quantitative_risk_hypotheses_existing",
    "quantitative_risk_hypotheses_added",
    "quantitative_risk_hypotheses_removed",
    "assetassessment",
    "task_templates",
    "incidents",
    "comments",
)


@dataclass(frozen=True, slots=True)
class VisibleRiskScenario:
    id: UUID
    risk_assessment_id: UUID
    ref_id: str
    name: str
    current_level: int
    residual_level: int


@dataclass(frozen=True, slots=True)
class AppliedControlRequestProjection:
    ranking_score: float
    findings_count: int
    links_count: int
    is_assigned: bool
    linked_models: tuple[str, ...]
    risk_scenarios: tuple[VisibleRiskScenario, ...]


EMPTY_APPLIED_CONTROL_PROJECTION = AppliedControlRequestProjection(
    ranking_score=0,
    findings_count=0,
    links_count=0,
    is_assigned=False,
    linked_models=(),
    risk_scenarios=(),
)


def filter_caller_visible_applied_controls(queryset, user):
    """Apply the permission model that owns each concrete control row.

    Policy is a permission-bearing proxy over the AppliedControl table. Generic
    control rights and policy rights must not disclose each other's rows.
    """
    visible_control_ids = RoleAssignment.get_viewable_object_ids(user, AppliedControl)
    visible_policy_ids = RoleAssignment.get_viewable_object_ids(user, Policy)
    return queryset.filter(
        Q(category="policy", id__in=visible_policy_ids)
        | (~Q(category="policy") & Q(id__in=visible_control_ids))
    )


def _relation_specs():
    # Imported lazily so core serializers can import this module while Django
    # is still populating app models.
    from crq.models import QuantitativeRiskHypothesis
    from ebios_rm.models import Stakeholder
    from privacy.models import DataBreach, Processing
    from resilience.models import AssetAssessment

    return {
        "findings": (Finding.applied_controls.through, Finding, None),
        "vulnerabilities": (
            Vulnerability.applied_controls.through,
            Vulnerability,
            None,
        ),
        "stakeholders": (Stakeholder.applied_controls.through, Stakeholder, None),
        "processings": (Processing.associated_controls.through, Processing, None),
        "data_breaches_remediated": (
            DataBreach.remediation_measures.through,
            DataBreach,
            None,
        ),
        "quantitative_risk_hypotheses_existing": (
            QuantitativeRiskHypothesis.existing_applied_controls.through,
            QuantitativeRiskHypothesis,
            _visible_quantitative_risk_hypothesis_ids,
        ),
        "quantitative_risk_hypotheses_added": (
            QuantitativeRiskHypothesis.added_applied_controls.through,
            QuantitativeRiskHypothesis,
            _visible_quantitative_risk_hypothesis_ids,
        ),
        "quantitative_risk_hypotheses_removed": (
            QuantitativeRiskHypothesis.removed_applied_controls.through,
            QuantitativeRiskHypothesis,
            _visible_quantitative_risk_hypothesis_ids,
        ),
        "assetassessment": (
            AssetAssessment.associated_controls.through,
            AssetAssessment,
            None,
        ),
        "task_templates": (
            TaskTemplate.applied_controls.through,
            TaskTemplate,
            None,
        ),
        "incidents": (Incident.applied_controls.through, Incident, None),
    }


def _viewable_ids(user, model: type[Model]):
    try:
        return RoleAssignment.get_viewable_object_ids(user, model)
    except NotImplementedError, Permission.DoesNotExist:
        # No registered IAM owner means no response-level declassification.
        return ()


def _visible_quantitative_risk_hypothesis_ids(user):
    from crq.visibility import visible_quantitative_risk_chain

    return visible_quantitative_risk_chain(user=user).hypotheses.values("id")


def _visible_relation_ids(user, related_model, resolver, cache):
    cache_key = resolver or related_model
    if cache_key not in cache:
        cache[cache_key] = (
            resolver(user)
            if resolver is not None
            else _viewable_ids(user, related_model)
        )
    return cache[cache_key]


def _m2m_pairs(through_model, related_model, control_ids, related_ids):
    foreign_keys = [
        field
        for field in through_model._meta.fields
        if getattr(field, "remote_field", None) is not None
    ]
    control_field = next(
        field
        for field in foreign_keys
        if field.remote_field.model._meta.concrete_model is AppliedControl
    )
    related_field = next(
        field
        for field in foreign_keys
        if field.remote_field.model._meta.concrete_model
        is related_model._meta.concrete_model
    )
    return tuple(
        through_model.objects.filter(
            **{
                f"{control_field.attname}__in": control_ids,
                f"{related_field.attname}__in": related_ids,
            }
        ).values_list(control_field.attname, related_field.attname)
    )


def _ranking_score(control, scenarios: Iterable[VisibleRiskScenario]) -> float:
    value = 0
    for scenario in scenarios:
        if scenario.current_level >= 0 and scenario.residual_level >= 0:
            value += (1 + scenario.current_level - scenario.residual_level) * (
                scenario.current_level + 1
            )
    return (
        abs(round(value / AppliedControl.MAP_EFFORT[control.effort], 4))
        if control.effort
        else 0
    )


def build_applied_control_visible_link_queries(*, user, control_ids) -> dict[str, Q]:
    """Return ORM predicates for the same caller-visible links as projections.

    These predicates let list/export filters stay in SQL instead of
    materializing every candidate control in Python.  Requirement-assessment
    visibility still uses the governed assignment/field projection, while a
    risk scenario requires visibility of both the child and parent assessment.
    """

    empty = Q(pk__in=())
    if user is None or not getattr(user, "is_authenticated", False):
        return {name: empty for name in LINKED_RELATION_NAMES}

    requirement_through = RequirementAssessment.applied_controls.through
    candidate_requirement_ids = requirement_through.objects.filter(
        appliedcontrol_id__in=control_ids
    ).values_list("requirementassessment_id", flat=True)
    visible_requirement_ids = tuple(
        visible_requirement_assessment_rows(
            user=user,
            ra_ids=candidate_requirement_ids,
            policy_field="applied_controls",
        )
    )

    visible_scenario_ids = RiskScenario.objects.filter(
        id__in=_viewable_ids(user, RiskScenario),
        risk_assessment_id__in=_viewable_ids(user, RiskAssessment),
    ).values_list("id", flat=True)

    predicates = {
        "requirement_assessments": Q(
            requirement_assessments__id__in=visible_requirement_ids
        ),
        "risk_scenarios": Q(risk_scenarios__id__in=visible_scenario_ids),
        "risk_scenarios_e": Q(risk_scenarios_e__id__in=visible_scenario_ids),
        "comments": Q(comments__id__in=_viewable_ids(user, Comment)),
    }
    visible_relation_ids = {}
    for relation_name, (
        _through_model,
        related_model,
        visibility_resolver,
    ) in _relation_specs().items():
        predicates[relation_name] = Q(
            **{
                f"{relation_name}__id__in": _visible_relation_ids(
                    user,
                    related_model,
                    visibility_resolver,
                    visible_relation_ids,
                )
            }
        )
    return {name: predicates.get(name, empty) for name in LINKED_RELATION_NAMES}


def build_applied_control_request_projections(
    *, user, controls: Iterable[Any]
) -> dict[UUID, AppliedControlRequestProjection]:
    """Build constant-with-page-size caller projections for ``controls``."""

    bounded_controls = tuple(
        control
        for control in controls
        if isinstance(control, Model) and control.pk is not None
    )
    controls_by_id = {control.pk: control for control in bounded_controls}
    control_ids = tuple(controls_by_id)
    if not control_ids:
        return {}
    if user is None or not getattr(user, "is_authenticated", False):
        return {
            control_id: EMPTY_APPLIED_CONTROL_PROJECTION for control_id in control_ids
        }

    linked_by_control: dict[UUID, set[str]] = defaultdict(set)

    requirement_through = RequirementAssessment.applied_controls.through
    candidate_requirement_ids = requirement_through.objects.filter(
        appliedcontrol_id__in=control_ids
    ).values_list("requirementassessment_id", flat=True)
    visible_requirements = visible_requirement_assessment_rows(
        user=user,
        ra_ids=candidate_requirement_ids,
        policy_field="applied_controls",
    )
    requirement_pairs = _m2m_pairs(
        requirement_through,
        RequirementAssessment,
        control_ids,
        visible_requirements,
    )
    for control_id, _requirement_id in requirement_pairs:
        linked_by_control[control_id].add("requirement_assessments")

    visible_scenario_ids = _viewable_ids(user, RiskScenario)
    visible_risk_assessment_ids = _viewable_ids(user, RiskAssessment)
    scenario_rows = tuple(
        RiskScenario.objects.filter(
            id__in=visible_scenario_ids,
            risk_assessment_id__in=visible_risk_assessment_ids,
        )
        .filter(
            Q(applied_controls__id__in=control_ids)
            | Q(existing_applied_controls__id__in=control_ids)
        )
        .values(
            "id",
            "risk_assessment_id",
            "ref_id",
            "name",
            "current_level",
            "residual_level",
        )
        .distinct()
    )
    scenarios_by_id = {
        row["id"]: VisibleRiskScenario(
            id=row["id"],
            risk_assessment_id=row["risk_assessment_id"],
            ref_id=row["ref_id"] or "",
            name=row["name"] or "",
            current_level=row["current_level"],
            residual_level=row["residual_level"],
        )
        for row in scenario_rows
    }
    added_scenario_pairs = _m2m_pairs(
        RiskScenario.applied_controls.through,
        RiskScenario,
        control_ids,
        scenarios_by_id,
    )
    existing_scenario_pairs = _m2m_pairs(
        RiskScenario.existing_applied_controls.through,
        RiskScenario,
        control_ids,
        scenarios_by_id,
    )
    added_scenarios_by_control: dict[UUID, list[VisibleRiskScenario]] = defaultdict(
        list
    )
    all_scenarios_by_control: dict[UUID, dict[UUID, VisibleRiskScenario]] = defaultdict(
        dict
    )
    for control_id, scenario_id in added_scenario_pairs:
        scenario = scenarios_by_id[scenario_id]
        added_scenarios_by_control[control_id].append(scenario)
        all_scenarios_by_control[control_id][scenario_id] = scenario
        linked_by_control[control_id].add("risk_scenarios")
    for control_id, scenario_id in existing_scenario_pairs:
        scenario = scenarios_by_id[scenario_id]
        all_scenarios_by_control[control_id][scenario_id] = scenario
        linked_by_control[control_id].add("risk_scenarios_e")

    findings_count: dict[UUID, int] = defaultdict(int)
    visible_relation_ids = {}
    for relation_name, (
        through_model,
        related_model,
        visibility_resolver,
    ) in _relation_specs().items():
        pairs = _m2m_pairs(
            through_model,
            related_model,
            control_ids,
            _visible_relation_ids(
                user,
                related_model,
                visibility_resolver,
                visible_relation_ids,
            ),
        )
        related_by_control: dict[UUID, set[UUID]] = defaultdict(set)
        for control_id, related_id in pairs:
            related_by_control[control_id].add(related_id)
        for control_id, related_ids in related_by_control.items():
            if related_ids:
                linked_by_control[control_id].add(relation_name)
                if relation_name == "findings":
                    findings_count[control_id] = len(related_ids)

    visible_comment_ids = _viewable_ids(user, Comment)
    for control_id in Comment.objects.filter(
        applied_control_id__in=control_ids,
        id__in=visible_comment_ids,
    ).values_list("applied_control_id", flat=True):
        linked_by_control[control_id].add("comments")

    visible_owner_pairs = _m2m_pairs(
        AppliedControl.owner.through,
        Actor,
        control_ids,
        _viewable_ids(user, Actor),
    )
    assigned_control_ids = {control_id for control_id, _actor_id in visible_owner_pairs}

    projections = {}
    requirement_count = defaultdict(int)
    for control_id, _requirement_id in requirement_pairs:
        requirement_count[control_id] += 1
    risk_count = defaultdict(int)
    for control_id, _scenario_id in added_scenario_pairs:
        risk_count[control_id] += 1

    for control_id, control in controls_by_id.items():
        visible_scenarios = tuple(all_scenarios_by_control.get(control_id, {}).values())
        projections[control_id] = AppliedControlRequestProjection(
            ranking_score=_ranking_score(
                control, added_scenarios_by_control.get(control_id, ())
            ),
            findings_count=findings_count[control_id],
            links_count=requirement_count[control_id] + risk_count[control_id],
            is_assigned=control_id in assigned_control_ids,
            linked_models=tuple(
                name
                for name in LINKED_RELATION_NAMES
                if name in linked_by_control[control_id]
            ),
            risk_scenarios=visible_scenarios,
        )
    return projections
