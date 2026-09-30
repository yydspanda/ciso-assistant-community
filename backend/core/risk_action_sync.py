"""Transaction boundary for moving completed risk actions into existing controls.

The HTTP actions used to authorize one relationship snapshot and then call model
helpers that queried the relationships again.  That left a time-of-check/time-of-
use gap around control status and the two risk-scenario M2M relations.  This
module owns one lock-ordered, frozen snapshot and makes both entry points consume
that exact snapshot.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass
from uuid import UUID

from django.db import transaction
from rest_framework import serializers
from rest_framework.exceptions import NotFound, PermissionDenied

from core.models import AppliedControl, Policy, RiskAssessment, RiskScenario
from iam.models import RoleAssignment


@dataclass(frozen=True, slots=True)
class LockedRiskActionSnapshot:
    """Controls authorized and frozen for one affected risk scenario."""

    scenario: RiskScenario
    controls: tuple[AppliedControl, ...]


class RiskActionSyncInputSerializer(serializers.Serializer):
    """Typed request contract shared by both custom sync actions."""

    dry_run = serializers.BooleanField(default=True)
    reset_residual = serializers.BooleanField(default=False)


@dataclass(frozen=True, slots=True)
class RiskActionSyncResult:
    """Typed mutation result that can re-prove its exact response authority."""

    parent: RiskAssessment
    integrity_scenarios: tuple[RiskScenario, ...]
    authorized_scenarios: tuple[RiskScenario, ...]
    snapshots: tuple[LockedRiskActionSnapshot, ...]
    require_parent_change: bool

    @property
    def changed_scenarios(self) -> tuple[RiskScenario, ...]:
        return tuple(snapshot.scenario for snapshot in self.snapshots)

    @property
    def changed_controls(self) -> tuple[AppliedControl, ...]:
        return tuple(
            control for snapshot in self.snapshots for control in snapshot.controls
        )

    def reprove(self, *, user) -> None:
        """Fail closed if authority or parent integrity changed before response."""

        _assert_object_access(
            user=user,
            model=RiskAssessment,
            object_ids=(self.parent.id,),
            require_change=self.require_parent_change,
        )
        _assert_object_access(
            user=user,
            model=RiskScenario,
            object_ids=(scenario.id for scenario in self.authorized_scenarios),
            require_change=True,
        )
        if any(
            scenario.folder_id != self.parent.folder_id
            for scenario in self.integrity_scenarios
        ):
            raise PermissionDenied()
        _assert_parent_unlocked(self.parent)
        _assert_control_access(user=user, controls=self.changed_controls)


def _assert_object_access(
    *,
    user,
    model,
    object_ids: Iterable[UUID],
    require_change: bool,
) -> None:
    requested_ids = set(object_ids)
    if not requested_ids:
        return
    visible_ids = set(
        RoleAssignment.get_viewable_object_ids(user, model).filter(id__in=requested_ids)
    )
    if visible_ids != requested_ids:
        raise PermissionDenied()
    if require_change:
        changeable_ids = set(
            RoleAssignment.get_changeable_object_ids(user, model).filter(
                id__in=requested_ids
            )
        )
        if changeable_ids != requested_ids:
            raise PermissionDenied()


def _assert_control_access(*, user, controls: Iterable[AppliedControl]) -> None:
    """Require exact concrete/proxy read and change authority for every row."""

    controls = tuple(controls)
    ordinary_ids = {control.id for control in controls if control.category != "policy"}
    policy_ids = {control.id for control in controls if control.category == "policy"}

    for model, requested_ids in (
        (AppliedControl, ordinary_ids),
        (Policy, policy_ids),
    ):
        if not requested_ids:
            continue
        visible_ids = set(
            RoleAssignment.get_viewable_object_ids(user, model).filter(
                id__in=requested_ids
            )
        )
        changeable_ids = set(
            RoleAssignment.get_changeable_object_ids(user, model).filter(
                id__in=requested_ids
            )
        )
        if visible_ids != requested_ids or changeable_ids != requested_ids:
            raise PermissionDenied()


def _lock_action_snapshots(
    *, scenarios: Iterable[RiskScenario]
) -> tuple[LockedRiskActionSnapshot, ...]:
    """Lock source links and controls, then build the sole mutation snapshot.

    Callers must already hold the parent and scenario row locks.  Lock ordering
    is therefore parent -> scenarios -> source-through rows -> controls.  The
    explicit through-row lock prevents a concurrent removal from changing an
    inactive set into an actionable set after authorization.  The scenario row
    lock prevents new source links from passing their foreign-key check until
    this transaction commits on PostgreSQL.
    """

    scenarios = tuple(scenarios)
    scenario_by_id = {scenario.id: scenario for scenario in scenarios}
    if not scenario_by_id:
        return ()

    source_through = RiskScenario.applied_controls.through
    source_pairs = tuple(
        source_through.objects.select_for_update()
        .filter(riskscenario_id__in=scenario_by_id)
        .order_by("riskscenario_id", "appliedcontrol_id")
        .values_list("riskscenario_id", "appliedcontrol_id")
    )
    control_ids = {control_id for _, control_id in source_pairs}
    controls_by_id = {
        control.id: control
        for control in AppliedControl.objects.select_for_update()
        .filter(id__in=control_ids)
        .order_by("id")
    }

    control_ids_by_scenario: dict[UUID, list[UUID]] = defaultdict(list)
    for scenario_id, control_id in source_pairs:
        control_ids_by_scenario[scenario_id].append(control_id)

    snapshots = []
    for scenario in scenarios:
        controls = tuple(
            controls_by_id[control_id]
            for control_id in control_ids_by_scenario.get(scenario.id, ())
        )
        if controls and all(
            control.status == AppliedControl.Status.ACTIVE for control in controls
        ):
            snapshots.append(
                LockedRiskActionSnapshot(scenario=scenario, controls=controls)
            )
    return tuple(snapshots)


def _apply_snapshot(
    snapshot: LockedRiskActionSnapshot,
    *,
    parent: RiskAssessment,
    reset_residual: bool,
) -> None:
    """Move only the frozen source IDs; never clear a freshly queried relation."""

    scenario = snapshot.scenario
    controls = snapshot.controls
    # Reuse the locked parent in RiskScenario.save() instead of fetching a
    # potentially different parent object while the mutation is in progress.
    scenario.risk_assessment = parent
    scenario.current_impact = scenario.residual_impact
    scenario.current_proba = scenario.residual_proba
    scenario.existing_applied_controls.add(*controls)
    scenario.applied_controls.remove(*controls)
    if reset_residual:
        scenario.residual_impact = -1
        scenario.residual_proba = -1
    scenario.save()


def _assert_parent_unlocked(parent: RiskAssessment) -> None:
    if parent.is_locked:
        # Match the ordinary RiskScenario write boundary: a locked assessment
        # cannot be mutated through a custom action either.
        raise PermissionDenied("The risk assessment is locked.")


def sync_risk_assessment_actions(
    *,
    user,
    risk_assessment_id: UUID,
    reset_residual: bool,
    dry_run: bool,
) -> RiskActionSyncResult:
    """Synchronize every currently actionable scenario under one assessment."""

    with transaction.atomic():
        try:
            parent = RiskAssessment.objects.select_for_update().get(
                id=risk_assessment_id
            )
        except RiskAssessment.DoesNotExist as exc:
            raise NotFound() from exc
        _assert_object_access(
            user=user,
            model=RiskAssessment,
            object_ids=(parent.id,),
            require_change=True,
        )
        _assert_parent_unlocked(parent)
        scenarios = tuple(
            RiskScenario.objects.select_for_update()
            .filter(risk_assessment_id=parent.id)
            .order_by("id")
        )
        if any(scenario.folder_id != parent.folder_id for scenario in scenarios):
            raise PermissionDenied()
        snapshots = _lock_action_snapshots(scenarios=scenarios)
        result = RiskActionSyncResult(
            parent=parent,
            integrity_scenarios=scenarios,
            authorized_scenarios=tuple(snapshot.scenario for snapshot in snapshots),
            snapshots=snapshots,
            require_parent_change=True,
        )
        result.reprove(user=user)

        if not dry_run:
            for snapshot in snapshots:
                _apply_snapshot(
                    snapshot,
                    parent=parent,
                    reset_residual=reset_residual,
                )
        result.reprove(user=user)
        return result


def sync_risk_scenario_actions(
    *,
    user,
    risk_scenario_id: UUID,
    reset_residual: bool,
    dry_run: bool,
) -> RiskActionSyncResult:
    """Synchronize one scenario with the same lock and authority contract."""

    with transaction.atomic():
        # Resolve the lock owner first, then re-prove the relationship after
        # acquiring both locks.  This preserves the global parent -> child lock
        # order without trusting an unlocked parent pointer.
        try:
            parent_id = RiskScenario.objects.values_list(
                "risk_assessment_id", flat=True
            ).get(id=risk_scenario_id)
        except RiskScenario.DoesNotExist as exc:
            raise NotFound() from exc
        try:
            parent = RiskAssessment.objects.select_for_update().get(id=parent_id)
        except RiskAssessment.DoesNotExist as exc:
            raise NotFound() from exc
        try:
            scenario = RiskScenario.objects.select_for_update().get(
                id=risk_scenario_id,
                risk_assessment_id=parent.id,
            )
        except RiskScenario.DoesNotExist as exc:
            raise PermissionDenied() from exc

        _assert_object_access(
            user=user,
            model=RiskAssessment,
            object_ids=(parent.id,),
            require_change=False,
        )
        _assert_object_access(
            user=user,
            model=RiskScenario,
            object_ids=(scenario.id,),
            require_change=True,
        )
        if scenario.folder_id != parent.folder_id:
            raise PermissionDenied()
        _assert_parent_unlocked(parent)
        snapshots = _lock_action_snapshots(scenarios=(scenario,))
        result = RiskActionSyncResult(
            parent=parent,
            integrity_scenarios=(scenario,),
            authorized_scenarios=(scenario,),
            snapshots=snapshots,
            require_parent_change=False,
        )
        result.reprove(user=user)
        if snapshots and not dry_run:
            _apply_snapshot(
                snapshots[0],
                parent=parent,
                reset_residual=reset_residual,
            )
        result.reprove(user=user)
        return result
