"""Audit result inheritance across the domain (Folder) tree.

When the same framework is audited at several levels of a domain hierarchy
(e.g. org-wide domain A -> business unit B -> system C), a child audit can
inherit results and scores for requirements covered by an ancestor audit.

Inheritance is always a non-destructive *overlay*: the child's stored
``RequirementAssessment.result`` / ``score`` are never modified. The resolver
computes an "effective" result/score plus the full inheritance path so the UI
can show where each value came from, with clickable links back to the source
audit.

The combination strategy is an org-wide setting
(``GlobalSettings.general -> audit_tree_aggregation_strategy``):

- ``none``        : no inheritance (feature off, the default)
- ``parent_wins`` : nearest ancestor with a value overrides the child
- ``child_wins``  : the child's own value wins; ancestors only fill gaps
- ``best_case``   : strongest result across the chain (optimistic)
- ``worst_case``  : weakest result across the chain (prudent)

Source selection per ancestor domain: among same-framework audits in that
folder, only "live" ones (in_progress / in_review / done) are eligible, and the
most recently updated one wins. ``RequirementAssessment.save()`` bumps the
parent CA's ``updated_at`` (see ``trigger_compliance_assessment_update_hooks``),
so ``updated_at`` reliably tracks last activity on an audit.

When audits use different score scales, every score is normalized to the
top-most participating ancestor's scale ("the top level parent scale").
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
import hashlib
import json
from typing import Iterable, Optional

from django.db.models import TextChoices
from django.utils.translation import gettext_lazy as _

# Statuses considered "live" for cross-audit rollups. Mirrors the filter used by
# FrameworkViewSet.report so the two stay consistent.
LIVE_STATUSES = ("in_progress", "in_review", "done")

COMPLETE_SCOPE_ERROR = "Complete audit inheritance data is unavailable for this caller."

# These values jointly determine both the winning inheritance source and the
# score projected from it.  A strict caller must be able to read every one on
# every participating audit; substituting ``None`` for a hidden value changes
# parent/best/worst selection and produces a plausible but incomplete result.
INHERITANCE_VALUE_FIELDS = ("result", "score", "is_scored")

# An ancestor's assessment status decides whether it participates at all.  It
# is intentionally separate from ``INHERITANCE_VALUE_FIELDS`` because the
# target assessment itself is always present, and a hidden target status can be
# safely stripped from the ordinary tree without changing source selection.
ANCESTOR_SELECTION_FIELDS = ("status",)


class AuditTreeAggregationStrategy(TextChoices):
    NONE = "none", _("No inheritance")
    PARENT_WINS = "parent_wins", _("Parent always wins")
    CHILD_WINS = "child_wins", _("Child always wins")
    BEST_CASE = "best_case", _("Best case (optimistic)")
    WORST_CASE = "worst_case", _("Worst case (prudent)")


# Ordered compliance strength, used by best_case / worst_case. Results outside
# this map (not_assessed, not_applicable) carry no comparable strength and are
# handled explicitly below.
RESULT_STRENGTH = {
    "non_compliant": 0,
    "partially_compliant": 1,
    "compliant": 2,
}

NOT_ASSESSED = "not_assessed"
NOT_APPLICABLE = "not_applicable"


def get_strategy() -> str:
    """Return the org-wide aggregation strategy, defaulting to ``none``.

    Gated by the ``audit_tree_inheritance`` feature flag: when the flag is off
    (the default), this returns ``none`` regardless of the configured strategy,
    so every inheritance surface — analytics panels, report toggle — disappears
    while the backend logic stays intact behind the flag.
    """
    from global_settings.models import GlobalSettings

    try:
        flags = GlobalSettings.objects.get(
            name=GlobalSettings.Names.FEATURE_FLAGS
        ).value
    except GlobalSettings.DoesNotExist:
        flags = {}
    if not (flags or {}).get("audit_tree_inheritance", False):
        return AuditTreeAggregationStrategy.NONE

    try:
        gs = GlobalSettings.objects.get(name=GlobalSettings.Names.GENERAL)
    except GlobalSettings.DoesNotExist:
        return AuditTreeAggregationStrategy.NONE
    strategy = (gs.value or {}).get(
        "audit_tree_aggregation_strategy", AuditTreeAggregationStrategy.NONE
    )
    # Normalize: a typo or legacy value must disable inheritance, never silently
    # fall through to the pessimistic worst_case branch in _pick_result.
    if strategy not in AuditTreeAggregationStrategy.values:
        return AuditTreeAggregationStrategy.NONE
    return strategy


def _ca_scale(ca) -> tuple[Optional[int], Optional[int]]:
    """Effective score scale of a compliance assessment (CA override, else framework)."""
    mn = ca.min_score if ca.min_score is not None else ca.framework.min_score
    mx = ca.max_score if ca.max_score is not None else ca.framework.max_score
    return (mn, mx)


def normalize_score(
    score: Optional[int],
    src_scale: tuple[Optional[int], Optional[int]],
    dst_scale: tuple[Optional[int], Optional[int]],
) -> Optional[int]:
    """Linearly rebase ``score`` from ``src_scale`` onto ``dst_scale``.

    Returns the score unchanged when scales match or any bound is unknown.
    Lossy by nature (rounding); only used for display overlays.
    """
    if score is None:
        return None
    smin, smax = src_scale
    dmin, dmax = dst_scale
    if None in (smin, smax, dmin, dmax) or smax == smin:
        return score
    if (smin, smax) == (dmin, dmax):
        return score
    frac = (score - smin) / (smax - smin)
    return round(dmin + frac * (dmax - dmin))


@dataclass(frozen=True)
class ChainEntry:
    """One audit's take on a single requirement, positioned in the domain chain."""

    ca_id: str
    ca_name: str
    folder_id: Optional[str]
    folder_name: Optional[str]
    distance: int  # 0 = the target audit itself, 1 = parent, 2 = grandparent, ...
    result: Optional[str]
    score: Optional[int]
    is_scored: Optional[bool]
    scale: tuple[Optional[int], Optional[int]]

    def has_result(self) -> bool:
        """A real result verdict — `not_assessed` carries no opinion."""
        return self.result not in (None, NOT_ASSESSED)

    def has_score(self) -> bool:
        """An actual score — an unscored requirement carries no opinion."""
        return self.is_scored is True and self.score is not None


@dataclass
class AncestorAudit:
    ca: object  # ComplianceAssessment
    distance: int

    def as_meta(self) -> dict:
        folder = self.ca.folder
        return {
            "ca_id": str(self.ca.id),
            "ca_name": self.ca.name,
            "folder_id": str(folder.id) if folder else None,
            "folder_name": folder.name if folder else None,
            "distance": self.distance,
            "scale": {"min": _ca_scale(self.ca)[0], "max": _ca_scale(self.ca)[1]},
        }


def select_ancestor_audits(
    target_ca, *, viewable_ca_ids: Optional[Iterable] = None
) -> list[AncestorAudit]:
    """Nearest-first list of inheritable ancestor audits on the same framework.

    Exactly one audit per ancestor domain: live status, most recently updated.
    The Global root folder participates too — an org-wide audit placed there is a
    legitimate inheritance source (common capabilities flowing down to every
    domain).
    """
    from core.models import ComplianceAssessment

    folder = target_ca.folder
    if folder is None:
        return []

    result: list[AncestorAudit] = []
    viewable = set(viewable_ca_ids) if viewable_ca_ids is not None else None
    distance = 0
    for ancestor in folder.get_parent_folders():  # nearest-first
        distance += 1
        qs = ComplianceAssessment.objects.filter(
            folder=ancestor,
            framework_id=target_ca.framework_id,
            status__in=LIVE_STATUSES,
        ).only("id", "folder_id", "framework_id", "status", "updated_at")
        if viewable is not None:
            qs = qs.filter(id__in=viewable)
        # UUID is a stable tie-breaker for legacy/imported rows that share an
        # ``updated_at`` timestamp.  Exact scope proofs must select the same
        # canonical row on every database backend.
        ca = qs.order_by("-updated_at", "-id").first()
        if ca is not None:
            result.append(AncestorAudit(ca=ca, distance=distance))
    return result


@dataclass(frozen=True)
class CompleteAuditInheritanceScope:
    """Fresh, bounded authority/content proof for one combined-tree build."""

    target_ca: object
    strategy: str
    signature: str
    compliance_assessment_ids: frozenset
    requirement_assessment_ids: frozenset
    requirement_node_ids: frozenset
    framework_ids: frozenset
    question_ids: frozenset
    question_choice_ids: frozenset
    answer_ids: frozenset
    coverage_control_ids: frozenset
    coverage_evidence_ids: frozenset
    visible_folder_ids: frozenset


def _concrete_projection(model, object_ids: Iterable) -> list[dict]:
    """Return a deterministic projection of every concrete model field."""

    ids = set(object_ids)
    if not ids:
        return []
    fields = [field.attname for field in model._meta.concrete_fields]
    return list(model.objects.filter(id__in=ids).order_by("id").values(*fields))


def _queryset_projection(queryset) -> list[dict]:
    """Return all concrete fields for a deterministic bounded queryset."""

    model = queryset.model
    fields = [field.attname for field in model._meta.concrete_fields]
    return list(queryset.order_by("id").values(*fields))


def capture_complete_inheritance_scope(
    user, target_ca_id
) -> CompleteAuditInheritanceScope:
    """Prove and sign the complete input scope used by ``combined_tree``.

    Canonical ancestor selection deliberately happens before ancestor IAM is
    applied so a newer hidden audit cannot be replaced by an older visible
    one. Framework IAM is then proved *before* any framework scale or config
    is fetched. The returned signature binds the exact authority projection,
    folder lineage, canonical ancestors, questionnaire, coverage relationships,
    and all concrete CA/RA/node/framework fields consumed by tree and
    inheritance calculations. Callers capture it before and after building and
    fail closed when the signatures differ.
    """

    from rest_framework.exceptions import PermissionDenied

    from core.models import (
        Answer,
        AppliedControl,
        ComplianceAssessment,
        Evidence,
        Framework,
        Question,
        QuestionChoice,
        RequirementAssessment,
        RequirementNode,
    )
    from core.utils import (
        get_full_view_compliance_assessment_ids,
        get_mapping_inference_visibility_context,
        is_field_visible_to,
        sanitize_mapping_inference_for_viewer,
    )
    from iam.models import Folder, RoleAssignment

    def require_exact_visibility(model, object_ids: Iterable) -> frozenset:
        """Return the exact visible set or reject the complete projection."""

        required_ids = frozenset(object_ids)
        visible_ids = frozenset(
            model.objects.filter(id__in=required_ids)
            .filter(id__in=RoleAssignment.get_viewable_object_ids(user, model))
            .values_list("id", flat=True)
        )
        if visible_ids != required_ids:
            raise PermissionDenied(COMPLETE_SCOPE_ERROR)
        return visible_ids

    strategy = get_strategy()
    try:
        # Fetch only identities required for canonical selection.  In
        # particular, do not join or dereference Framework until its own IAM
        # boundary has been proved below.
        target_identity = ComplianceAssessment.objects.only(
            "id", "framework_id", "folder_id"
        ).get(id=target_ca_id)
    except ComplianceAssessment.DoesNotExist as error:
        raise PermissionDenied(COMPLETE_SCOPE_ERROR) from error

    ancestors = (
        select_ancestor_audits(target_identity)
        if strategy != AuditTreeAggregationStrategy.NONE
        else []
    )
    ca_ids = frozenset(
        {target_identity.id, *(ancestor.ca.id for ancestor in ancestors)}
    )

    full_view_ca_ids = frozenset(
        ComplianceAssessment.objects.filter(id__in=ca_ids)
        .filter(id__in=get_full_view_compliance_assessment_ids(user))
        .values_list("id", flat=True)
    )
    if full_view_ca_ids != ca_ids:
        raise PermissionDenied(COMPLETE_SCOPE_ERROR)

    framework_ids = frozenset(
        ComplianceAssessment.objects.filter(id__in=ca_ids).values_list(
            "framework_id", flat=True
        )
    )
    visible_framework_ids = require_exact_visibility(Framework, framework_ids)

    ra_ids = frozenset(
        RequirementAssessment.objects.filter(
            compliance_assessment_id__in=ca_ids
        ).values_list("id", flat=True)
    )
    visible_ra_ids = require_exact_visibility(RequirementAssessment, ra_ids)

    requirement_node_ids = frozenset(
        RequirementNode.objects.filter(framework_id__in=framework_ids).values_list(
            "id", flat=True
        )
    )
    visible_requirement_node_ids = require_exact_visibility(
        RequirementNode, requirement_node_ids
    )

    # The combined tree embeds an independently permissioned questionnaire.
    # Filtering hidden Questions, Choices, or Answers would turn a complete
    # auditor tree into a plausible partial one, so strict mode proves the
    # entire bounded questionnaire carrier before building the response.
    question_ids = frozenset(
        Question.objects.filter(
            requirement_node_id__in=requirement_node_ids
        ).values_list("id", flat=True)
    )
    visible_question_ids = require_exact_visibility(Question, question_ids)

    target_ra_ids = frozenset(
        RequirementAssessment.objects.filter(
            compliance_assessment_id=target_identity.id
        ).values_list("id", flat=True)
    )
    answer_ids = frozenset(
        Answer.objects.filter(
            requirement_assessment_id__in=target_ra_ids,
            question_id__in=question_ids,
        ).values_list("id", flat=True)
    )
    visible_answer_ids = require_exact_visibility(Answer, answer_ids)
    selected_choice_links = Answer.selected_choices.through.objects.filter(
        answer_id__in=answer_ids
    )
    selected_choice_ids = set(
        selected_choice_links.values_list("questionchoice_id", flat=True)
    )
    question_choice_ids = frozenset(
        set(
            QuestionChoice.objects.filter(question_id__in=question_ids).values_list(
                "id", flat=True
            )
        )
        | selected_choice_ids
    )
    visible_question_choice_ids = require_exact_visibility(
        QuestionChoice, question_choice_ids
    )

    # Framework content is safe to join only after the independent Framework
    # object boundary above.  Empty legacy CA field maps may legitimately fall
    # back to this authorized framework template.
    assessments = list(
        ComplianceAssessment.objects.filter(id__in=ca_ids)
        .select_related("folder", "framework")
        .order_by("id")
    )
    assessments_by_id = {assessment.id: assessment for assessment in assessments}
    target_assessment = assessments_by_id[target_identity.id]
    field_access = []
    if ancestors:
        for assessment in assessments:
            required_fields = list(INHERITANCE_VALUE_FIELDS)
            if assessment.id != target_identity.id:
                required_fields.extend(ANCESTOR_SELECTION_FIELDS)
            for field_name in required_fields:
                visible = is_field_visible_to(assessment, field_name, "auditor")
                field_access.append((str(assessment.id), field_name, visible))
                if not visible:
                    raise PermissionDenied(COMPLETE_SCOPE_ERROR)

    coverage_field_access = {}
    for field_name in ("applied_controls", "evidences"):
        visible = is_field_visible_to(target_assessment, field_name, "auditor")
        coverage_field_access[field_name] = visible
        field_access.append((str(target_assessment.id), field_name, visible))

    # Coverage flags are derived from three M2M edges. Bind the exact links and
    # object-authority sets that can make either flag true; otherwise a hidden
    # linked object is silently converted into a false coverage claim.
    ra_control_links = RequirementAssessment.applied_controls.through.objects.none()
    coverage_control_ids = frozenset()
    if coverage_field_access["applied_controls"]:
        ra_control_links = (
            RequirementAssessment.applied_controls.through.objects.filter(
                requirementassessment_id__in=target_ra_ids
            )
        )
        coverage_control_ids = frozenset(
            ra_control_links.values_list("appliedcontrol_id", flat=True)
        )
        require_exact_visibility(AppliedControl, coverage_control_ids)

    ra_evidence_links = RequirementAssessment.evidences.through.objects.none()
    control_evidence_links = AppliedControl.evidences.through.objects.none()
    coverage_evidence_ids: frozenset = frozenset()
    if coverage_field_access["evidences"]:
        ra_evidence_links = RequirementAssessment.evidences.through.objects.filter(
            requirementassessment_id__in=target_ra_ids
        )
        evidence_ids = set(ra_evidence_links.values_list("evidence_id", flat=True))
        if coverage_field_access["applied_controls"]:
            control_evidence_links = AppliedControl.evidences.through.objects.filter(
                appliedcontrol_id__in=coverage_control_ids
            )
            evidence_ids.update(
                control_evidence_links.values_list("evidence_id", flat=True)
            )
        coverage_evidence_ids = frozenset(evidence_ids)
        require_exact_visibility(Evidence, coverage_evidence_ids)

    # The tree sanitizer derives mapping provenance from independently
    # authorized source RAs, nodes, frameworks, and StoredLibrary edge owners.
    # Sign the final least-privilege projection, not only the raw JSON stored on
    # the target RA, so a mid-request grant/revocation or owner-content change
    # cannot escape the terminal reproof.
    mapping_projection = []
    mapping_visible = is_field_visible_to(
        target_assessment, "mapping_inference", "auditor"
    )
    field_access.append(
        (str(target_assessment.id), "mapping_inference", mapping_visible)
    )
    if mapping_visible:
        target_rows = list(
            RequirementAssessment.objects.filter(id__in=target_ra_ids).order_by("id")
        )
        mapping_rows = [
            row
            for row in target_rows
            if isinstance(row.mapping_inference, dict) and row.mapping_inference
        ]
        mapping_inferences = [row.mapping_inference for row in mapping_rows]
        mapping_visibility = (
            get_mapping_inference_visibility_context(user, mapping_inferences)
            if mapping_inferences
            else None
        )
        mapping_projection = [
            {
                "requirement_assessment_id": str(row.id),
                "value": sanitize_mapping_inference_for_viewer(
                    row.mapping_inference,
                    target_assessment,
                    viewer_role="auditor",
                    visibility_context=mapping_visibility,
                    target_result=row.result,
                ),
            }
            for row in mapping_rows
        ]

    target_folder = target_assessment.folder
    lineage = (
        target_folder.get_parent_folders(include_self=True) if target_folder else []
    )
    lineage_ids = frozenset(folder.id for folder in lineage)
    visible_folder_ids = frozenset(
        Folder.objects.filter(id__in=lineage_ids)
        .filter(id__in=RoleAssignment.get_viewable_object_ids(user, Folder))
        .values_list("id", flat=True)
    )

    # Folder identity/parent links affect ancestor selection even when folder
    # metadata is redacted.  Names are signed only for folders independently
    # visible to the caller, so hidden metadata neither leaks nor creates a
    # spurious response dependency.
    folder_projection = list(
        Folder.objects.filter(id__in=lineage_ids)
        .order_by("id")
        .values("id", "parent_folder_id")
    )
    visible_folder_names = list(
        Folder.objects.filter(id__in=visible_folder_ids)
        .order_by("id")
        .values("id", "name")
    )

    projection = {
        "strategy": strategy,
        "target_ca_id": str(target_identity.id),
        "canonical_ancestors": [
            {
                "id": str(ancestor.ca.id),
                "distance": ancestor.distance,
                "updated_at": ancestor.ca.updated_at,
            }
            for ancestor in ancestors
        ],
        "authorized": {
            "compliance_assessments": sorted(map(str, full_view_ca_ids)),
            "requirement_assessments": sorted(map(str, visible_ra_ids)),
            "requirement_nodes": sorted(map(str, visible_requirement_node_ids)),
            "frameworks": sorted(map(str, visible_framework_ids)),
            "questions": sorted(map(str, visible_question_ids)),
            "question_choices": sorted(map(str, visible_question_choice_ids)),
            "answers": sorted(map(str, visible_answer_ids)),
            "coverage_controls": sorted(map(str, coverage_control_ids)),
            "coverage_evidences": sorted(map(str, coverage_evidence_ids)),
            "folders": sorted(map(str, visible_folder_ids)),
        },
        "field_access": field_access,
        "compliance_assessments": _concrete_projection(ComplianceAssessment, ca_ids),
        "requirement_assessments": _concrete_projection(RequirementAssessment, ra_ids),
        "requirement_nodes": _concrete_projection(
            RequirementNode, requirement_node_ids
        ),
        "frameworks": _concrete_projection(Framework, framework_ids),
        "questions": _concrete_projection(Question, question_ids),
        "question_choices": _concrete_projection(QuestionChoice, question_choice_ids),
        "answers": _concrete_projection(Answer, answer_ids),
        "answer_selected_choices": _queryset_projection(selected_choice_links),
        "ra_applied_controls": _queryset_projection(ra_control_links),
        "ra_evidences": _queryset_projection(ra_evidence_links),
        "control_evidences": _queryset_projection(control_evidence_links),
        "mapping_projection": mapping_projection,
        "folder_lineage": folder_projection,
        "visible_folder_names": visible_folder_names,
    }
    encoded = json.dumps(
        projection,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    ).encode("utf-8")
    signature = hashlib.sha256(encoded).hexdigest()

    return CompleteAuditInheritanceScope(
        target_ca=target_assessment,
        strategy=strategy,
        signature=signature,
        compliance_assessment_ids=ca_ids,
        requirement_assessment_ids=ra_ids,
        requirement_node_ids=requirement_node_ids,
        framework_ids=framework_ids,
        question_ids=question_ids,
        question_choice_ids=question_choice_ids,
        answer_ids=answer_ids,
        coverage_control_ids=coverage_control_ids,
        coverage_evidence_ids=coverage_evidence_ids,
        visible_folder_ids=visible_folder_ids,
    )


def _pick_nearest(strategy: str, own, ancestors):
    """Shared nearest/parent/child selection over a pre-filtered candidate set.

    ``own`` is the target's qualifying entry (distance 0) or None; ``ancestors``
    are qualifying ancestor entries, nearest-first. Used by both result and
    score resolution after each has excluded entries lacking that dimension.
    """
    if strategy == AuditTreeAggregationStrategy.CHILD_WINS:
        return own or (ancestors[0] if ancestors else None)
    if strategy == AuditTreeAggregationStrategy.PARENT_WINS:
        return ancestors[0] if ancestors else own
    return None  # best/worst handled by the dimension-specific picker


def _pick_result(strategy: str, own: Optional[ChainEntry], chain: list[ChainEntry]):
    """Winning entry for the *result* verdict — entries without a real result
    (``not_assessed``) never count toward the decision."""
    ancestors = [e for e in chain if e.has_result()]
    own_r = own if (own is not None and own.has_result()) else None

    if strategy in (
        AuditTreeAggregationStrategy.CHILD_WINS,
        AuditTreeAggregationStrategy.PARENT_WINS,
    ):
        return _pick_nearest(strategy, own_r, ancestors)

    # best_case / worst_case: compare compliance strength across the chain.
    pool = ([own_r] if own_r else []) + ancestors
    ranked = [e for e in pool if e.result in RESULT_STRENGTH]
    if ranked:
        if strategy == AuditTreeAggregationStrategy.BEST_CASE:
            return max(ranked, key=lambda e: (RESULT_STRENGTH[e.result], -e.distance))
        return min(ranked, key=lambda e: (RESULT_STRENGTH[e.result], e.distance))
    # Only not_applicable values present: surface the nearest one.
    return pool[0] if pool else None


def resolve_requirement(
    strategy: str,
    own: Optional[ChainEntry],
    chain: list[ChainEntry],
    canonical_scale: tuple[Optional[int], Optional[int]],
) -> Optional[dict]:
    """Compute the inheritance overlay for one requirement.

    Returns None when no ancestor audit covers this requirement (nothing to
    overlay — the child's own value stands alone).

    Result and score come from the SAME winning assessment: the strategy picks
    one source by result (entries that are ``not_assessed`` never count), and the
    score is whatever that source recorded — absent when that source didn't score
    it. A score is only meaningful paired with the result it was given for, so it
    never rides along with a different audit's verdict.
    """
    if not chain:
        return None

    chosen = _pick_result(strategy, own, chain)
    inherited = bool(chosen is not None and chosen.distance > 0)

    effective_result = chosen.result if chosen else NOT_ASSESSED
    effective_score = (
        normalize_score(chosen.score, chosen.scale, canonical_scale)
        if (chosen is not None and chosen.has_score())
        else None
    )

    def entry_meta(e: ChainEntry) -> dict:
        return {
            "ca_id": e.ca_id,
            "ca_name": e.ca_name,
            "folder_id": e.folder_id,
            "folder_name": e.folder_name,
            "distance": e.distance,
            "result": e.result,
            "score": normalize_score(e.score, e.scale, canonical_scale),
            "raw_score": e.score,
            "is_scored": e.is_scored,
            "scale": {"min": e.scale[0], "max": e.scale[1]},
        }

    return {
        "strategy": strategy,
        "inherited": inherited,
        "effective_result": effective_result,
        "effective_score": effective_score,
        "scale": {"min": canonical_scale[0], "max": canonical_scale[1]},
        "own": (
            {
                "result": own.result,
                "score": own.score,
                "is_scored": own.is_scored,
                "scale": {"min": own.scale[0], "max": own.scale[1]},
            }
            if own
            else None
        ),
        "source": entry_meta(chosen) if chosen is not None else None,
        # Full chain (ancestors covering this requirement), nearest-first, so the
        # UI can render a clickable inheritance path back to each source audit.
        "path": [entry_meta(e) for e in chain],
    }


def build_overlay_map(
    target_ca,
    *,
    viewable_ca_ids: Optional[Iterable] = None,
    viewable_ra_ids: Optional[Iterable] = None,
    viewable_requirement_node_ids: Optional[Iterable] = None,
    viewable_framework_ids: Optional[Iterable] = None,
    viewable_folder_ids: Optional[Iterable] = None,
    viewer_role: Optional[str] = None,
    require_complete_scope: bool = False,
    strategy: Optional[str] = None,
) -> dict:
    """Build the full inheritance overlay for a target audit.

    Returns ``{strategy, overlay, ancestors, canonical_scale}`` where ``overlay``
    maps ``str(requirement_id) -> overlay dict`` (only requirements an ancestor
    actually covers). When the feature is off or there are no ancestor audits,
    ``overlay`` is empty.
    """
    from rest_framework.exceptions import PermissionDenied

    from core.models import RequirementAssessment, RequirementNode
    from core.utils import is_field_visible_to

    if strategy is None:
        strategy = get_strategy()

    # A complete inheritance result must select the canonical latest audit in
    # every ancestor folder first and then prove access.  Filtering candidates
    # by IAM before ordering can silently substitute an older visible audit for
    # a newer hidden one, yielding a plausible but false inheritance result.
    ancestors = (
        select_ancestor_audits(
            target_ca,
            viewable_ca_ids=None if require_complete_scope else viewable_ca_ids,
        )
        if strategy != AuditTreeAggregationStrategy.NONE
        else []
    )

    scope_ca_ids = {target_ca.id, *(ancestor.ca.id for ancestor in ancestors)}
    scope_ra_ids: set = set()
    if require_complete_scope:
        if viewable_ca_ids is None or not scope_ca_ids.issubset(set(viewable_ca_ids)):
            raise PermissionDenied(COMPLETE_SCOPE_ERROR)
        if (
            viewable_ra_ids is None
            or viewable_requirement_node_ids is None
            or viewable_framework_ids is None
        ):
            raise PermissionDenied(COMPLETE_SCOPE_ERROR)

        # Framework is an independent IAM object.  Prove it before `_ca_scale`
        # or field-visibility fallback can read framework scale/config.
        scope_framework_ids = {
            target_ca.framework_id,
            *(ancestor.ca.framework_id for ancestor in ancestors),
        }
        if not scope_framework_ids.issubset(set(viewable_framework_ids)):
            raise PermissionDenied(COMPLETE_SCOPE_ERROR)

        scope_ra_ids = set(
            RequirementAssessment.objects.filter(
                compliance_assessment_id__in=scope_ca_ids
            ).values_list("id", flat=True)
        )
        if not scope_ra_ids.issubset(set(viewable_ra_ids)):
            raise PermissionDenied(COMPLETE_SCOPE_ERROR)

        framework_requirement_ids = set(
            RequirementNode.objects.filter(
                framework_id__in=scope_framework_ids
            ).values_list("id", flat=True)
        )
        if not framework_requirement_ids.issubset(set(viewable_requirement_node_ids)):
            raise PermissionDenied(COMPLETE_SCOPE_ERROR)

        # Hidden values must never be converted to null and then allowed to
        # change source selection. Strict mode is complete-or-denied whenever
        # an inheritance overlay can actually be produced. With no ancestors,
        # the endpoint remains an ordinary field-redacted tree.
        if ancestors:
            for source_ca in (target_ca, *(a.ca for a in ancestors)):
                required_fields = list(INHERITANCE_VALUE_FIELDS)
                if source_ca.id != target_ca.id:
                    required_fields.extend(ANCESTOR_SELECTION_FIELDS)
                if any(
                    not is_field_visible_to(source_ca, field_name, "auditor")
                    for field_name in required_fields
                ):
                    raise PermissionDenied(COMPLETE_SCOPE_ERROR)

    # Scale access is intentionally below the strict Framework and value-field
    # gates.  Non-strict internal callers preserve their historical behavior.
    own_scale = _ca_scale(target_ca)
    empty = {
        "strategy": strategy,
        "overlay": {},
        "ancestors": [],
        "canonical_scale": {"min": own_scale[0], "max": own_scale[1]},
    }

    if strategy == AuditTreeAggregationStrategy.NONE or not ancestors:
        return empty

    # "Top level parent scale": the most distant score-visible ancestor sets
    # the canonical scale. A hidden source scale must not influence or leak
    # through a value the caller is allowed to see.
    score_visible_ancestors = [
        ancestor
        for ancestor in ancestors
        if viewer_role is None or is_field_visible_to(ancestor.ca, "score", viewer_role)
    ]
    canonical_scale = (
        _ca_scale(score_visible_ancestors[-1].ca)
        if score_visible_ancestors
        else own_scale
    )

    visible_folders = (
        set(viewable_folder_ids) if viewable_folder_ids is not None else None
    )

    def authorized_meta(ancestor: AncestorAudit) -> dict:
        folder_visible = (
            visible_folders is None or ancestor.ca.folder_id in visible_folders
        )
        folder = ancestor.ca.folder if folder_visible else None
        scale = _ca_scale(ancestor.ca)
        return {
            "ca_id": str(ancestor.ca.id),
            "ca_name": ancestor.ca.name,
            "folder_id": str(folder.id) if folder else None,
            "folder_name": folder.name if folder else None,
            "distance": ancestor.distance,
            "scale": {"min": scale[0], "max": scale[1]},
        }

    meta_by_ca = {str(a.ca.id): authorized_meta(a) for a in ancestors}
    ca_by_id = {str(a.ca.id): a.ca for a in ancestors}
    distance_by_ca = {str(a.ca.id): a.distance for a in ancestors}
    scale_by_ca = {str(a.ca.id): _ca_scale(a.ca) for a in ancestors}

    chain_by_req: dict[str, list[ChainEntry]] = defaultdict(list)
    ancestor_ras = RequirementAssessment.objects.filter(
        compliance_assessment_id__in=[a.ca.id for a in ancestors]
    ).only("requirement_id", "compliance_assessment_id", "result", "score", "is_scored")
    if require_complete_scope:
        ancestor_ras = ancestor_ras.filter(id__in=scope_ra_ids)
    if viewable_ra_ids is not None:
        ancestor_ras = ancestor_ras.filter(id__in=viewable_ra_ids)
    for ra in ancestor_ras:
        ca_id = str(ra.compliance_assessment_id)
        meta = meta_by_ca[ca_id]
        source_ca = ca_by_id[ca_id]
        result = ra.result
        score = ra.score
        source_is_scored: Optional[bool] = ra.is_scored
        source_scale = scale_by_ca[ca_id]
        if viewer_role is not None:
            if not is_field_visible_to(source_ca, "result", viewer_role):
                result = None
            if not is_field_visible_to(source_ca, "score", viewer_role):
                score = None
                source_scale = (None, None)
            if not is_field_visible_to(source_ca, "is_scored", viewer_role):
                source_is_scored = None
        chain_by_req[str(ra.requirement_id)].append(
            ChainEntry(
                ca_id=meta["ca_id"],
                ca_name=meta["ca_name"],
                folder_id=meta["folder_id"],
                folder_name=meta["folder_name"],
                distance=distance_by_ca[ca_id],
                result=result,
                score=score,
                is_scored=source_is_scored,
                scale=source_scale,
            )
        )
    for entries in chain_by_req.values():
        entries.sort(key=lambda e: e.distance)

    target_folder = target_ca.folder
    target_folder_visible = target_folder is not None and (
        visible_folders is None or target_folder.id in visible_folders
    )
    own_by_req: dict[str, ChainEntry] = {}
    own_ras = RequirementAssessment.objects.filter(
        compliance_assessment=target_ca
    ).only("requirement_id", "result", "score", "is_scored")
    if require_complete_scope:
        own_ras = own_ras.filter(id__in=scope_ra_ids)
    if viewable_ra_ids is not None:
        own_ras = own_ras.filter(id__in=viewable_ra_ids)
    for ra in own_ras:
        own_result = ra.result
        own_score = ra.score
        own_is_scored: Optional[bool] = ra.is_scored
        visible_own_scale = own_scale
        if viewer_role is not None:
            if not is_field_visible_to(target_ca, "result", viewer_role):
                own_result = None
            if not is_field_visible_to(target_ca, "score", viewer_role):
                own_score = None
                visible_own_scale = (None, None)
            if not is_field_visible_to(target_ca, "is_scored", viewer_role):
                own_is_scored = None
        own_by_req[str(ra.requirement_id)] = ChainEntry(
            ca_id=str(target_ca.id),
            ca_name=target_ca.name,
            folder_id=str(target_folder.id) if target_folder_visible else None,
            folder_name=target_folder.name if target_folder_visible else None,
            distance=0,
            result=own_result,
            score=own_score,
            is_scored=own_is_scored,
            scale=visible_own_scale,
        )

    overlay: dict[str, dict] = {}
    for req_id, chain in chain_by_req.items():
        ov = resolve_requirement(
            strategy, own_by_req.get(req_id), chain, canonical_scale
        )
        if ov is not None:
            overlay[req_id] = ov

    return {
        "strategy": strategy,
        "overlay": overlay,
        "ancestors": [
            {
                key: value
                for key, value in authorized_meta(a).items()
                if key != "scale"
                or viewer_role is None
                or is_field_visible_to(a.ca, "score", viewer_role)
            }
            for a in ancestors
        ],
        "canonical_scale": {"min": canonical_scale[0], "max": canonical_scale[1]},
    }
