"""Caller-scoped visibility for the quantitative-risk parent chain.

Quantitative-risk rows carry their own folders even though their authority is
also inherited from ``Study -> Scenario -> Hypothesis``.  Treating any child as
independently visible would let a stale or malformed cross-folder row bridge a
hidden parent into an AppliedControl response.  These lazy querysets therefore
require both object IAM and a coherent, caller-visible parent chain.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any
from uuid import UUID

from django.contrib.auth.models import Permission
from django.db.models import F, QuerySet
from iam.models import RoleAssignment

from .models import (
    QuantitativeRiskHypothesis,
    QuantitativeRiskScenario,
    QuantitativeRiskStudy,
)


@dataclass(frozen=True, slots=True)
class VisibleQuantitativeRiskChain:
    """Lazy, caller-authorized querysets for one bounded CRQ chain."""

    studies: QuerySet[QuantitativeRiskStudy]
    scenarios: QuerySet[QuantitativeRiskScenario]
    hypotheses: QuerySet[QuantitativeRiskHypothesis]


def _viewable_ids(user: Any, model: type) -> Iterable[UUID]:
    if user is None or not getattr(user, "is_authenticated", False):
        return ()
    try:
        return RoleAssignment.get_viewable_object_ids(user, model)
    except NotImplementedError, Permission.DoesNotExist:
        # A missing IAM owner is never an implicit declassification path.
        return ()


def visible_quantitative_risk_chain(
    *,
    user: Any,
    study_ids: Iterable[UUID] | None = None,
    scenario_ids: Iterable[UUID] | None = None,
    hypothesis_ids: Iterable[UUID] | None = None,
) -> VisibleQuantitativeRiskChain:
    """Return the visible and folder-coherent CRQ parent chain for ``user``.

    Optional ID sets bound the corresponding level without weakening ancestor
    checks.  The function is intentionally lazy so callers can embed any level
    as a subquery rather than materializing tenant-wide UUID collections.
    """

    studies = QuantitativeRiskStudy.objects.filter(
        id__in=_viewable_ids(user, QuantitativeRiskStudy)
    ).order_by()
    if study_ids is not None:
        studies = studies.filter(id__in=study_ids)

    scenarios = QuantitativeRiskScenario.objects.filter(
        id__in=_viewable_ids(user, QuantitativeRiskScenario),
        quantitative_risk_study_id__in=studies.values("id"),
        folder_id=F("quantitative_risk_study__folder_id"),
    ).order_by()
    if scenario_ids is not None:
        scenarios = scenarios.filter(id__in=scenario_ids)

    hypotheses = QuantitativeRiskHypothesis.objects.filter(
        id__in=_viewable_ids(user, QuantitativeRiskHypothesis),
        quantitative_risk_scenario_id__in=scenarios.values("id"),
        folder_id=F("quantitative_risk_scenario__folder_id"),
    ).order_by()
    if hypothesis_ids is not None:
        hypotheses = hypotheses.filter(id__in=hypothesis_ids)

    return VisibleQuantitativeRiskChain(
        studies=studies,
        scenarios=scenarios,
        hypotheses=hypotheses,
    )
