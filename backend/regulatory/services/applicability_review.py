from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Literal
from uuid import UUID

from django.core.exceptions import ObjectDoesNotExist, ValidationError
from django.db import transaction
from django.utils import timezone

from iam.models import RoleAssignment, ServiceAccount, User
from tprm.models import Entity

from regulatory.contracts import RegulatoryApplicabilityReviewPayload
from regulatory.models import (
    APPLICABILITY_REVIEW_DISPOSITION_DIGEST_PROFILE,
    PILOT_APPLICABILITY_RULE_ID,
    RegulatoryApplicabilityDecision,
    RegulatoryApplicabilityReviewDisposition,
)
from regulatory.validators import validate_regulatory_identifier

from .applicability import (
    RegulatoryApplicabilitySelection,
    get_regulatory_applicability,
    lock_regulatory_applicability_scope,
    regulatory_chain_for_applicability_decision,
    validate_persisted_regulatory_applicability_decision,
)
from .common import (
    IdempotencyConflict,
    canonical_payload_sha256,
    require_regulatory_permission,
)
from .records import (
    RegulatoryChain,
    lock_current_regulatory_chain,
    regulatory_document_recorded_floor,
)


PersistedReviewDisposition = Literal[
    "no_correction_requested",
    "correction_requested",
    "unable_to_complete",
]
ApplicabilityReviewState = Literal[
    "not_reviewable",
    "not_reviewed",
    "no_correction_requested",
    "correction_requested",
    "unable_to_complete",
]
ApplicabilityReviewWorkflowAttention = Literal[
    "needs_review",
    "reviewed_nonbinding",
]


@dataclass(frozen=True)
class RegulatoryApplicabilityReviewResult:
    chain: RegulatoryChain
    decision: RegulatoryApplicabilityDecision
    disposition: RegulatoryApplicabilityReviewDisposition


@dataclass(frozen=True)
class RegulatoryReviewerReference:
    masked: bool
    id: str | None = None
    display_name: str | None = None


@dataclass(frozen=True)
class RegulatoryApplicabilityReviewSelection:
    applicability: RegulatoryApplicabilitySelection
    disposition: RegulatoryApplicabilityReviewDisposition | None
    review_state: ApplicabilityReviewState
    workflow_attention: ApplicabilityReviewWorkflowAttention
    reviewer: RegulatoryReviewerReference | None


class RegulatoryApplicabilityReviewStateUnavailable(ValidationError):
    """The selected review history is not a coherent immutable event stream."""


_PERSISTED_DISPOSITIONS = {
    RegulatoryApplicabilityReviewDisposition.Disposition.NO_CORRECTION_REQUESTED,
    RegulatoryApplicabilityReviewDisposition.Disposition.CORRECTION_REQUESTED,
    RegulatoryApplicabilityReviewDisposition.Disposition.UNABLE_TO_COMPLETE,
}

_ALLOWED_REASON_CODES = {
    RegulatoryApplicabilityReviewDisposition.Disposition.NO_CORRECTION_REQUESTED: {
        RegulatoryApplicabilityReviewDisposition.ReasonCode.REVIEW_COMPLETED,
    },
    RegulatoryApplicabilityReviewDisposition.Disposition.CORRECTION_REQUESTED: {
        RegulatoryApplicabilityReviewDisposition.ReasonCode.FACT_CORRECTION_REQUIRED,
        RegulatoryApplicabilityReviewDisposition.ReasonCode.EVIDENCE_CORRECTION_REQUIRED,
        RegulatoryApplicabilityReviewDisposition.ReasonCode.PROVENANCE_CORRECTION_REQUIRED,
        RegulatoryApplicabilityReviewDisposition.ReasonCode.SCOPE_OR_PARENT_CORRECTION_REQUIRED,
        RegulatoryApplicabilityReviewDisposition.ReasonCode.OTHER_CORRECTION_REQUIRED,
    },
    RegulatoryApplicabilityReviewDisposition.Disposition.UNABLE_TO_COMPLETE: {
        RegulatoryApplicabilityReviewDisposition.ReasonCode.INSUFFICIENT_EVIDENCE,
        RegulatoryApplicabilityReviewDisposition.ReasonCode.CONFLICTING_INFORMATION,
        RegulatoryApplicabilityReviewDisposition.ReasonCode.INSUFFICIENT_AUTHORITY_OR_SCOPE,
        RegulatoryApplicabilityReviewDisposition.ReasonCode.OTHER_UNRESOLVED,
    },
}


def _normalize_uuid(
    value: object,
    *,
    field: str,
    errors: dict[str, str],
) -> str | None:
    if not isinstance(value, str) or not value.strip():
        errors[field] = "A physical UUID string is required."
        return None
    try:
        return str(UUID(value))
    except (ValueError, TypeError, AttributeError):
        errors[field] = "A physical UUID string is required."
        return None


def _normalize_digest(
    value: object,
    *,
    field: str,
    errors: dict[str, str],
) -> str | None:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        errors[field] = "A lowercase SHA-256 digest is required."
        return None
    return value


def _normalize_review_payload(
    payload: RegulatoryApplicabilityReviewPayload,
) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise ValidationError(
            {"payload": "An applicability-review payload is required."}
        )

    errors: dict[str, str] = {}
    required = {
        "expected_decision",
        "expected_current_disposition",
        "to_disposition",
        "reason_code",
        "rationale",
    }
    missing = required - set(payload)
    extra = set(payload) - required
    if missing:
        errors["payload.missing"] = f"Missing fields: {', '.join(sorted(missing))}."
    if extra:
        errors["payload.extra"] = f"Unknown fields: {', '.join(sorted(extra))}."

    expected_decision_fields = {
        "physical_id",
        "record_id",
        "revision",
        "semantic_payload_sha256",
    }
    expected_decision = payload.get("expected_decision")
    if not isinstance(expected_decision, dict):
        errors["expected_decision"] = "An exact decision object is required."
        expected_decision = {}
    else:
        nested_missing = expected_decision_fields - set(expected_decision)
        nested_extra = set(expected_decision) - expected_decision_fields
        if nested_missing:
            errors["expected_decision.missing"] = (
                f"Missing fields: {', '.join(sorted(nested_missing))}."
            )
        if nested_extra:
            errors["expected_decision.extra"] = (
                f"Unknown fields: {', '.join(sorted(nested_extra))}."
            )

    normalized_decision_id = _normalize_uuid(
        expected_decision.get("physical_id"),
        field="expected_decision.physical_id",
        errors=errors,
    )
    record_id = expected_decision.get("record_id")
    try:
        validate_regulatory_identifier(record_id)
    except ValidationError:
        errors["expected_decision.record_id"] = (
            "Use a 3-160 character portable regulatory identifier."
        )
    revision = expected_decision.get("revision")
    if isinstance(revision, bool) or not isinstance(revision, int) or revision < 1:
        errors["expected_decision.revision"] = "A positive revision is required."
    normalized_decision_digest = _normalize_digest(
        expected_decision.get("semantic_payload_sha256"),
        field="expected_decision.semantic_payload_sha256",
        errors=errors,
    )

    expected_head_fields = {
        "physical_id",
        "sequence",
        "disposition",
        "event_payload_sha256",
    }
    expected_head = payload.get("expected_current_disposition")
    if not isinstance(expected_head, dict):
        errors["expected_current_disposition"] = (
            "An explicit current-disposition object is required."
        )
        expected_head = {}
    else:
        nested_missing = expected_head_fields - set(expected_head)
        nested_extra = set(expected_head) - expected_head_fields
        if nested_missing:
            errors["expected_current_disposition.missing"] = (
                f"Missing fields: {', '.join(sorted(nested_missing))}."
            )
        if nested_extra:
            errors["expected_current_disposition.extra"] = (
                f"Unknown fields: {', '.join(sorted(nested_extra))}."
            )

    expected_head_values = [expected_head.get(field) for field in expected_head_fields]
    all_head_values_are_null = all(value is None for value in expected_head_values)
    all_head_values_are_present = all(
        value is not None for value in expected_head_values
    )
    normalized_head: dict[str, Any] | None
    if not all_head_values_are_null and not all_head_values_are_present:
        errors["expected_current_disposition"] = (
            "Current-disposition fields must be all null or all populated."
        )
        normalized_head = None
    elif all_head_values_are_null:
        normalized_head = None
    else:
        normalized_head_id = _normalize_uuid(
            expected_head.get("physical_id"),
            field="expected_current_disposition.physical_id",
            errors=errors,
        )
        sequence = expected_head.get("sequence")
        if isinstance(sequence, bool) or not isinstance(sequence, int) or sequence < 1:
            errors["expected_current_disposition.sequence"] = (
                "A positive sequence is required."
            )
        disposition = expected_head.get("disposition")
        if (
            not isinstance(disposition, str)
            or disposition not in _PERSISTED_DISPOSITIONS
        ):
            errors["expected_current_disposition.disposition"] = (
                "Use a persisted applicability-review disposition."
            )
        normalized_head_digest = _normalize_digest(
            expected_head.get("event_payload_sha256"),
            field="expected_current_disposition.event_payload_sha256",
            errors=errors,
        )
        normalized_head = {
            "physical_id": normalized_head_id,
            "sequence": sequence,
            "disposition": disposition,
            "event_payload_sha256": normalized_head_digest,
        }

    target = payload.get("to_disposition")
    if not isinstance(target, str) or target not in _PERSISTED_DISPOSITIONS:
        errors["to_disposition"] = "Use a persisted applicability-review disposition."
    reason_code = payload.get("reason_code")
    allowed_reason_codes = (
        _ALLOWED_REASON_CODES.get(target, set()) if isinstance(target, str) else set()
    )
    if not isinstance(reason_code, str) or reason_code not in allowed_reason_codes:
        errors["reason_code"] = (
            "The reason code is not enabled for the target disposition."
        )
    rationale = payload.get("rationale")
    if not isinstance(rationale, str) or not rationale.strip():
        errors["rationale"] = "A non-empty human rationale is required."
        normalized_rationale = ""
    else:
        normalized_rationale = rationale.strip()
        if len(normalized_rationale) > 4000:
            errors["rationale"] = "The rationale exceeds the 4000-character limit."

    if errors:
        raise ValidationError(errors)
    return {
        "expected_decision": {
            "physical_id": normalized_decision_id,
            "record_id": record_id,
            "revision": revision,
            "semantic_payload_sha256": normalized_decision_digest,
        },
        "expected_head": normalized_head,
        "to_disposition": target,
        "reason_code": reason_code,
        "rationale": normalized_rationale,
    }


def _head_payload(
    disposition: RegulatoryApplicabilityReviewDisposition | None,
) -> dict[str, Any] | None:
    if disposition is None:
        return None
    return {
        "physical_id": str(disposition.id),
        "sequence": disposition.sequence,
        "disposition": disposition.to_disposition,
        "event_payload_sha256": disposition.event_payload_sha256,
    }


def _request_payload_from_command(
    *,
    actor: User,
    registration,
    normalized: dict[str, Any],
) -> dict[str, Any]:
    return {
        "digest_profile": APPLICABILITY_REVIEW_DISPOSITION_DIGEST_PROFILE,
        "kind": "request",
        "reviewer_id": str(actor.id),
        "scope": {
            "folder_id": str(registration.folder_id),
            "registration_id": str(registration.id),
            "entity_id": str(registration.entity_id),
            "document_id": str(registration.document_id),
        },
        "decision": normalized["expected_decision"],
        "expected_head": normalized["expected_head"],
        "target_disposition": normalized["to_disposition"],
        "reason_code": normalized["reason_code"],
        "rationale": normalized["rationale"],
    }


def regulatory_applicability_review_event_sha256(
    disposition: RegulatoryApplicabilityReviewDisposition,
) -> str:
    return canonical_payload_sha256(disposition.review_disposition_event_payload())


def _validate_persisted_disposition(
    disposition: RegulatoryApplicabilityReviewDisposition,
) -> None:
    try:
        decision = disposition.decision
        validate_persisted_regulatory_applicability_decision(decision)
        exact_decision_id = disposition.decision_id
        exact_folder_id = disposition.folder_id
        exact_decision_digest = decision.semantic_payload_sha256
        exact_decision_recorder_id = decision.recorded_by_id

        lineage: list[RegulatoryApplicabilityReviewDisposition] = []
        seen: set[object] = set()
        current: RegulatoryApplicabilityReviewDisposition | None = disposition
        while current is not None:
            if current.pk is None or current.pk in seen:
                raise ValidationError(
                    {"previous_disposition": "The review lineage contains a cycle."}
                )
            seen.add(current.pk)
            lineage.append(current)
            current = (
                current.previous_disposition
                if current.previous_disposition_id is not None
                else None
            )

        previous: RegulatoryApplicabilityReviewDisposition | None = None
        for expected_sequence, event in enumerate(reversed(lineage), start=1):
            if event.folder_id != exact_folder_id:
                raise ValidationError(
                    {"folder": "Every review event must use the exact review folder."}
                )
            if event.decision_id != exact_decision_id:
                raise ValidationError(
                    {"decision": "Every review event must bind the exact decision."}
                )
            if event.decision_semantic_payload_sha256 != exact_decision_digest:
                raise ValidationError(
                    {
                        "decision_semantic_payload_sha256": (
                            "Every review event must bind the exact decision digest."
                        )
                    }
                )
            if event.decision_recorded_by_id != exact_decision_recorder_id:
                raise ValidationError(
                    {
                        "decision_recorded_by": (
                            "Every review event must bind the exact decision recorder."
                        )
                    }
                )
            if event.sequence != expected_sequence:
                raise ValidationError(
                    {"sequence": "Review event sequences must be contiguous from one."}
                )
            if previous is None:
                if (
                    event.previous_disposition_id is not None
                    or event.from_disposition
                    != RegulatoryApplicabilityReviewDisposition.Disposition.NOT_REVIEWED
                ):
                    raise ValidationError(
                        {
                            "previous_disposition": (
                                "The review root must start from not_reviewed."
                            )
                        }
                    )
            elif (
                event.previous_disposition_id != previous.id
                or event.from_disposition != previous.to_disposition
                or event.occurred_at <= previous.occurred_at
            ):
                raise ValidationError(
                    {
                        "previous_disposition": (
                            "The review predecessor, status, sequence, and time "
                            "must be contiguous."
                        )
                    }
                )
            if event.request_sha256 != canonical_payload_sha256(
                event.review_disposition_request_payload()
            ):
                raise ValidationError(
                    {"request_sha256": "A stored review request digest is invalid."}
                )
            if (
                event.event_payload_sha256
                != regulatory_applicability_review_event_sha256(event)
            ):
                raise ValidationError(
                    {"event_payload_sha256": "A stored review event digest is invalid."}
                )
            event.full_clean()
            previous = event
    except RegulatoryApplicabilityReviewStateUnavailable:
        raise
    except (
        AttributeError,
        ObjectDoesNotExist,
        TypeError,
        ValidationError,
        ValueError,
    ) as exc:
        raise RegulatoryApplicabilityReviewStateUnavailable(
            "The persisted applicability-review disposition is inconsistent."
        ) from exc


def _reviewer_reference(
    *,
    actor: User,
    reviewer: User,
) -> RegulatoryReviewerReference:
    reviewer_is_visible = reviewer.id == actor.id or (
        RoleAssignment.get_viewable_object_ids(actor, User)
        .filter(pk=reviewer.pk)
        .exists()
    )
    if not reviewer_is_visible:
        return RegulatoryReviewerReference(masked=True)
    display_name = " ".join(
        part.strip()
        for part in (reviewer.first_name, reviewer.last_name)
        if part.strip()
    )
    return RegulatoryReviewerReference(
        masked=False,
        id=str(reviewer.id),
        display_name=display_name or None,
    )


@transaction.atomic
def record_regulatory_applicability_review_disposition(
    *,
    actor: User,
    entity: Entity,
    document_id,
    payload: RegulatoryApplicabilityReviewPayload,
    idempotency_key: str,
) -> RegulatoryApplicabilityReviewResult:
    """Append one exact, non-binding, named-human applicability review event."""

    if not isinstance(idempotency_key, str):
        raise ValidationError({"idempotency_key": "A string key is required."})
    idempotency_key = idempotency_key.strip()
    if not idempotency_key:
        raise ValidationError({"idempotency_key": "A non-empty key is required."})
    if len(idempotency_key) > 200:
        raise ValidationError(
            {"idempotency_key": "The key exceeds the 200-character limit."}
        )
    normalized = _normalize_review_payload(payload)
    actor, locked_entity, folder, registration = lock_regulatory_applicability_scope(
        actor=actor,
        entity=entity,
        document_id=document_id,
        permission_codenames=(
            "view_regulatorydocument",
            "view_regulatoryapplicabilitydecision",
            "view_regulatoryapplicabilityreviewdisposition",
            "review_regulatoryapplicability",
        ),
    )
    if ServiceAccount.objects.filter(user=actor).exists():
        raise ValidationError(
            {"actor": "A named human reviewer is required for applicability review."}
        )

    requested_sha256 = canonical_payload_sha256(
        _request_payload_from_command(
            actor=actor,
            registration=registration,
            normalized=normalized,
        )
    )
    existing = (
        RegulatoryApplicabilityReviewDisposition.objects.select_for_update()
        .filter(folder=folder, idempotency_key=idempotency_key)
        .first()
    )
    if existing is not None:
        _validate_persisted_disposition(existing)
        if existing.request_sha256 != requested_sha256:
            raise IdempotencyConflict(
                {"idempotency_key": "The key is bound to a different review request."}
            )
        return RegulatoryApplicabilityReviewResult(
            chain=regulatory_chain_for_applicability_decision(existing.decision),
            decision=existing.decision,
            disposition=existing,
        )

    if locked_entity.folder_id != folder.id:
        raise ValidationError(
            {
                "entity": (
                    "New reviews require the entity to remain in its registration "
                    "folder."
                )
            }
        )
    if not (locked_entity.ref_id or "").upper().startswith("SYNTHETIC-"):
        raise ValidationError(
            {"entity": "New pilot reviews require a SYNTHETIC-* entity."}
        )

    chain = lock_current_regulatory_chain(
        registration=registration,
        folder=folder,
    )
    current_decisions = list(
        RegulatoryApplicabilityDecision.objects.select_for_update()
        .filter(
            folder=folder,
            registration=registration,
            obligation=chain.obligation,
            rule_id=PILOT_APPLICABILITY_RULE_ID,
            recorded_to__isnull=True,
        )
        .order_by("id")[:2]
    )
    if len(current_decisions) != 1:
        raise ValidationError(
            {"expected_decision": "One current applicability decision is required."}
        )
    decision = current_decisions[0]
    validate_persisted_regulatory_applicability_decision(decision)
    expected_decision = normalized["expected_decision"]
    if (
        expected_decision["physical_id"] != str(decision.id)
        or expected_decision["record_id"] != decision.record_id
        or expected_decision["revision"] != decision.revision
        or expected_decision["semantic_payload_sha256"]
        != decision.semantic_payload_sha256
    ):
        raise ValidationError(
            {"expected_decision": "The selected applicability decision is stale."}
        )
    if actor.id == decision.recorded_by_id:
        raise ValidationError(
            {"actor": "The decision recorder cannot review that exact revision."}
        )

    latest = (
        RegulatoryApplicabilityReviewDisposition.objects.select_for_update()
        .filter(folder=folder, decision=decision)
        .order_by("-sequence")
        .first()
    )
    if latest is not None:
        _validate_persisted_disposition(latest)
    if normalized["expected_head"] != _head_payload(latest):
        raise ValidationError(
            {
                "expected_current_disposition": (
                    "The current applicability-review disposition is stale."
                )
            }
        )
    if latest is not None and (
        latest.to_disposition == normalized["to_disposition"]
        and latest.reason_code == normalized["reason_code"]
        and latest.rationale == normalized["rationale"]
    ):
        raise ValidationError(
            {
                "to_disposition": (
                    "A new idempotency key cannot create a semantic no-op review."
                )
            }
        )

    aggregate_floor = regulatory_document_recorded_floor(
        document=chain.document,
        folder=folder,
    )
    latest_known_time = max(
        value
        for value in (
            aggregate_floor,
            chain.document_version.recorded_from,
            chain.provision.recorded_from,
            chain.obligation.recorded_from,
            decision.recorded_from,
            latest.occurred_at if latest is not None else None,
        )
        if value is not None
    )
    occurred_at = max(
        timezone.now(),
        latest_known_time + timedelta(microseconds=1),
    )
    current_disposition = (
        latest.to_disposition
        if latest is not None
        else RegulatoryApplicabilityReviewDisposition.Disposition.NOT_REVIEWED
    )
    disposition = RegulatoryApplicabilityReviewDisposition(
        folder=folder,
        decision=decision,
        decision_semantic_payload_sha256=decision.semantic_payload_sha256,
        decision_recorded_by_id=decision.recorded_by_id,
        reviewer=actor,
        sequence=(latest.sequence + 1) if latest is not None else 1,
        previous_disposition=latest,
        from_disposition=current_disposition,
        to_disposition=normalized["to_disposition"],
        reason_code=normalized["reason_code"],
        rationale=normalized["rationale"],
        occurred_at=occurred_at,
        digest_profile=APPLICABILITY_REVIEW_DISPOSITION_DIGEST_PROFILE,
        event_payload_sha256="0" * 64,
        request_sha256="0" * 64,
        idempotency_key=idempotency_key,
        is_binding=False,
        is_published=False,
    )
    disposition.request_sha256 = canonical_payload_sha256(
        disposition.review_disposition_request_payload()
    )
    if disposition.request_sha256 != requested_sha256:
        raise ValidationError(
            {"request_sha256": "The server-resolved review request is inconsistent."}
        )
    disposition.event_payload_sha256 = regulatory_applicability_review_event_sha256(
        disposition
    )
    disposition.save()
    _validate_persisted_disposition(disposition)
    return RegulatoryApplicabilityReviewResult(
        chain=chain,
        decision=decision,
        disposition=disposition,
    )


@transaction.atomic
def get_regulatory_applicability_review(
    *,
    actor: User,
    entity: Entity,
    document_id,
    recorded_as_of: datetime | None = None,
) -> RegulatoryApplicabilityReviewSelection:
    """Select review state for the exact applicability decision at one cutoff."""

    applicability = get_regulatory_applicability(
        actor=actor,
        entity=entity,
        document_id=document_id,
        recorded_as_of=recorded_as_of,
    )
    actor = User.objects.get(pk=actor.pk)
    registration = applicability.chain.registration
    if registration is None:
        raise RegulatoryApplicabilityReviewStateUnavailable(
            "The applicability selection has no entity registration."
        )
    require_regulatory_permission(
        actor=actor,
        codename="view_regulatoryapplicabilityreviewdisposition",
        folder=registration.folder,
    )
    decision = applicability.decision
    if decision is None:
        return RegulatoryApplicabilityReviewSelection(
            applicability=applicability,
            disposition=None,
            review_state="not_reviewable",
            workflow_attention="needs_review",
            reviewer=None,
        )

    dispositions = list(
        RegulatoryApplicabilityReviewDisposition.objects.select_related("reviewer")
        .filter(
            folder=registration.folder,
            decision=decision,
            occurred_at__lte=applicability.recorded_as_of,
        )
        .order_by("-sequence")[:2]
    )
    disposition = dispositions[0] if dispositions else None
    if disposition is not None:
        _validate_persisted_disposition(disposition)
    review_state: ApplicabilityReviewState = (
        disposition.to_disposition if disposition is not None else "not_reviewed"
    )
    workflow_attention: ApplicabilityReviewWorkflowAttention = "needs_review"
    if (
        disposition is not None
        and disposition.to_disposition
        == RegulatoryApplicabilityReviewDisposition.Disposition.NO_CORRECTION_REQUESTED
        and decision.result != RegulatoryApplicabilityDecision.Result.NEEDS_REVIEW
    ):
        workflow_attention = "reviewed_nonbinding"
    return RegulatoryApplicabilityReviewSelection(
        applicability=applicability,
        disposition=disposition,
        review_state=review_state,
        workflow_attention=workflow_attention,
        reviewer=(
            _reviewer_reference(actor=actor, reviewer=disposition.reviewer)
            if disposition is not None
            else None
        ),
    )
