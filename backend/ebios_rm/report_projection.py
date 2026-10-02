"""Narrow, deterministic DTOs for the EBIOS RM printable report.

The ordinary API serializers intentionally expose rich editing contracts.  A
formal report has a much smaller consumer contract; reusing ``fields='__all__'``
here needlessly widens both the response and its IAM/locking graph.  Keep these
functions explicit so adding a rendered field requires a reviewed dependency.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable


def canonical_report_digest(payload: dict) -> str:
    encoded = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def object_ref(obj) -> dict:
    return {"id": str(obj.id), "str": str(obj)}


def action_controls(controls: Iterable) -> list[dict]:
    rows = []
    for control in controls:
        owners = sorted(
            (object_ref(owner) for owner in control.owner.all()),
            key=lambda owner: owner["id"],
        )
        rows.append(
            {
                "id": str(control.id),
                "name": control.name,
                "str": str(control),
                "category": control.category,
                "priority": (
                    str(control.get_priority_display()) if control.priority else None
                ),
                "status": control.status,
                "owner": owners,
                "eta": control.eta,
            }
        )
    return rows


def study(study_row) -> dict:
    assets = [
        {
            "id": str(asset.id),
            "str": str(asset),
            "type": asset.type,
            "folder": object_ref(asset.folder),
        }
        for asset in study_row.assets.all()
    ]
    assets.sort(
        key=lambda asset: (0 if asset["type"] == "PR" else 1, asset["str"], asset["id"])
    )
    return {
        "id": str(study_row.id),
        "name": study_row.name,
        "description": study_row.description,
        "version": study_row.version,
        "status": study_row.status,
        "observation": study_row.observation,
        "quotation_method": study_row.quotation_method,
        "assets": assets,
    }


def feared_events(rows: Iterable) -> list[dict]:
    return [
        {
            "id": str(row.id),
            "name": row.name,
            "description": row.description,
            "gravity": row.get_gravity_display(),
            "assets": sorted(
                (object_ref(asset) for asset in row.assets.all()),
                key=lambda asset: asset["id"],
            ),
            "qualifications": sorted(
                (object_ref(item) for item in row.qualifications.all()),
                key=lambda item: item["id"],
            ),
        }
        for row in rows
    ]


def ro_to_couples(rows: Iterable) -> list[dict]:
    return [
        {
            "id": str(row.id),
            "risk_origin": row.risk_origin.get_name_translated,
            "target_objective": row.target_objective,
            "motivation": row.get_motivation_display(),
            "resources": row.get_resources_display(),
            "activity": row.get_activity_display(),
            "pertinence": row.get_pertinence_display(),
            "feared_events": [
                {"id": str(item_id)}
                for item_id in sorted(
                    row.feared_events.values_list("id", flat=True),
                    key=str,
                )
            ],
            "justification": row.justification,
        }
        for row in rows
    ]


def stakeholders(rows: Iterable, *, controls_by_stakeholder: dict) -> list[dict]:
    return [
        {
            "id": str(row.id),
            "entity": object_ref(row.entity),
            "category": row.category.get_name_translated if row.category else None,
            "current_criticality": row.get_current_criticality_display(),
            "residual_criticality": row.get_residual_criticality_display(),
            "justification": row.justification,
            "applied_controls": action_controls(
                controls_by_stakeholder.get(row.id, ())
            ),
        }
        for row in rows
    ]


def strategic_scenarios(rows: Iterable) -> list[dict]:
    result = []
    for row in rows:
        feared = sorted(
            row.ro_to_couple.feared_events.all(),
            key=lambda item: str(item.id),
        )
        result.append(
            {
                "id": str(row.id),
                "name": row.name,
                "description": row.description,
                "ref_id": row.ref_id,
                "gravity": row.get_gravity_display(),
                "focused_feared_event": (
                    {"id": str(row.focused_feared_event_id)}
                    if row.focused_feared_event_id
                    else None
                ),
                "feared_events": [{"id": str(item.id)} for item in feared],
            }
        )
    return result


def attack_paths(rows: Iterable) -> list[dict]:
    return [
        {
            "id": str(row.id),
            "name": row.name,
            "risk_origin": row.ro_to_couple.risk_origin.get_name_translated,
            "target_objective": row.ro_to_couple.target_objective,
            "stakeholders": sorted(
                (object_ref(item) for item in row.stakeholders.all()),
                key=lambda item: item["id"],
            ),
            "strategic_scenario": {
                "id": str(row.strategic_scenario_id),
            },
        }
        for row in rows
    ]


def operational_scenarios(rows: Iterable) -> list[dict]:
    result = []
    for row in rows:
        description = row.operating_modes_description
        if not description:
            description = " | ".join(
                row.operating_modes.order_by("id").values_list("name", flat=True)
            )
        result.append(
            {
                "id": str(row.id),
                "ref_id": row.ref_id,
                "attack_path": {
                    "id": str(row.attack_path_id),
                    "name": row.attack_path.name,
                },
                "operating_modes_description": description,
                "likelihood": row.get_likelihood_display(),
                "gravity": row.get_gravity_display(),
                "risk_level": row.get_risk_level_display(),
                "threats": sorted(
                    (object_ref(item) for item in row.threats.all()),
                    key=lambda item: item["id"],
                ),
                "stakeholders": sorted(
                    (object_ref(item) for item in row.stakeholders),
                    key=lambda item: item["id"],
                ),
                "justification": row.justification,
            }
        )
    return result


def kill_chain_graph(mode) -> dict | None:
    steps = list(mode.kill_chain_steps.order_by("id"))
    if not steps:
        return None

    elementary_action_ids = {step.elementary_action_id for step in steps}
    antecedents_by_step = {}
    for step in steps:
        antecedent_ids = sorted(
            step.antecedents.values_list("id", flat=True),
            key=str,
        )
        antecedents_by_step[step.id] = antecedent_ids
        elementary_action_ids.update(antecedent_ids)

    from .models import ElementaryAction

    elementary_action_rows = ElementaryAction.objects.filter(
        id__in=elementary_action_ids
    ).order_by("id")
    return {
        "kill_chain_steps": [
            {
                "elementary_action": {"id": str(step.elementary_action_id)},
                "antecedents": [
                    {"id": str(item_id)} for item_id in antecedents_by_step[step.id]
                ],
                "logic_operator": step.logic_operator,
                "position_x": step.position_x,
                "position_y": step.position_y,
            }
            for step in steps
        ],
        "elementary_actions": [
            {
                "id": str(row.id),
                "name": row.name,
                "attack_stage": row.attack_stage,
                "icon_fa_class": row.icon_fa_class,
            }
            for row in elementary_action_rows
        ],
    }


def operating_modes(rows: Iterable) -> list[dict]:
    result = []
    for row in rows:
        item = {
            "id": str(row.id),
            "name": row.name,
            "description": row.description,
            "operational_scenario": {"id": str(row.operational_scenario_id)},
            "likelihood": row.get_likelihood_display(),
            "graph_columns": row.graph_columns,
            # A linked operating mode has no separate selection state.  This
            # preserves the report page's visual marker without inventing an
            # authority-bearing model field.
            "is_selected": True,
        }
        graph = kill_chain_graph(row)
        if graph is not None:
            item["graph"] = graph
        result.append(item)
    return result


def risk_matrix(matrix) -> dict:
    return {"json_definition": matrix.get_json_translated}


def risk_scenarios(rows: Iterable) -> list[dict]:
    return [
        {
            "id": str(row.id),
            "ref_id": row.ref_id,
            "name": row.name,
            "treatment": row.treatment,
            "inherent_proba": row.get_inherent_proba(),
            "inherent_impact": row.get_inherent_impact(),
            "inherent_level": row.get_inherent_risk(),
            "current_proba": row.get_current_proba(),
            "current_impact": row.get_current_impact(),
            "current_level": row.get_current_risk(),
            "residual_proba": row.get_residual_proba(),
            "residual_impact": row.get_residual_impact(),
            "residual_level": row.get_residual_risk(),
            "strength_of_knowledge": row.get_strength_of_knowledge(),
        }
        for row in rows
    ]
