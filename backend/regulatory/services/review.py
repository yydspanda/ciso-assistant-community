from datetime import timedelta

from django.core.exceptions import ValidationError
from django.db import transaction
from django.utils import timezone

from iam.models import Folder, ServiceAccount, User
from regulatory.models import (
    RegulatoryObligation,
    RegulatoryObligationProvision,
    RegulatoryObligationReviewEvent,
)

from .common import (
    IdempotencyConflict,
    canonical_payload_sha256,
    lock_regulatory_actor,
    require_regulatory_permission,
)
from .records import regulatory_document_recorded_floor


ALLOWED_REVIEW_TRANSITIONS = {
    RegulatoryObligation.ReviewStatus.MACHINE_PROPOSED: (
        RegulatoryObligation.ReviewStatus.ANALYST_REVIEWED,
    ),
    RegulatoryObligation.ReviewStatus.ANALYST_REVIEWED: (
        RegulatoryObligation.ReviewStatus.LEGAL_REVIEWED,
    ),
}

REVIEW_TRANSITION_PERMISSIONS = {
    (
        RegulatoryObligation.ReviewStatus.MACHINE_PROPOSED,
        RegulatoryObligation.ReviewStatus.ANALYST_REVIEWED,
    ): "transition_regulatoryobligation",
    (
        RegulatoryObligation.ReviewStatus.ANALYST_REVIEWED,
        RegulatoryObligation.ReviewStatus.LEGAL_REVIEWED,
    ): "legal_review_regulatoryobligation",
}


@transaction.atomic
def transition_obligation_review(
    *,
    actor: User,
    obligation_id,
    expected_from_status: str,
    to_status: str,
    rationale: str,
    idempotency_key: str,
) -> RegulatoryObligationReviewEvent:
    """Append a non-binding human review event after locking the exact revision."""

    if not idempotency_key or not idempotency_key.strip():
        raise ValidationError({"idempotency_key": "A non-empty key is required."})
    actor = lock_regulatory_actor(actor=actor)
    folder_id = (
        RegulatoryObligation.objects.filter(pk=obligation_id)
        .values_list("folder_id", flat=True)
        .first()
    )
    if folder_id is None:
        raise RegulatoryObligation.DoesNotExist
    # Regulatory mutations share actor -> folder -> aggregate lock ordering.
    # The initial lookup is intentionally unlocked and is revalidated below.
    folder = Folder.objects.select_for_update().get(pk=folder_id)
    obligation = RegulatoryObligation.objects.select_for_update().get(
        pk=obligation_id,
        folder=folder,
    )
    requested_edge = (expected_from_status, to_status)
    required_permission = REVIEW_TRANSITION_PERMISSIONS.get(requested_edge)
    if required_permission is None:
        raise ValidationError(
            {
                "to_status": (
                    f"Invalid transition from {expected_from_status!r} "
                    f"to {to_status!r}."
                )
            }
        )
    require_regulatory_permission(
        actor=actor,
        codename=required_permission,
        folder=folder,
    )
    if ServiceAccount.objects.filter(user=actor).exists():
        raise ValidationError(
            {"actor": "Named human reviewers are required for review events."}
        )

    digest = canonical_payload_sha256(
        {
            "actor_id": str(actor.id),
            "obligation_id": str(obligation.id),
            "expected_from_status": expected_from_status,
            "to_status": to_status,
            "rationale": rationale,
        }
    )
    existing = RegulatoryObligationReviewEvent.objects.filter(
        folder=folder,
        idempotency_key=idempotency_key,
    ).first()
    if existing is not None:
        if existing.payload_sha256 != digest:
            raise IdempotencyConflict(
                {"idempotency_key": "The key is bound to a different transition."}
            )
        return existing

    if obligation.recorded_to is not None:
        raise ValidationError("Only the current recorded obligation can be reviewed.")

    latest = (
        obligation.review_events.filter(folder=folder).order_by("-sequence").first()
    )
    current_status = latest.to_status if latest else obligation.review_status
    if current_status != expected_from_status:
        raise ValidationError(
            {
                "expected_from_status": (
                    f"Stale state: expected {expected_from_status!r}, "
                    f"current state is {current_status!r}."
                )
            }
        )
    if to_status not in ALLOWED_REVIEW_TRANSITIONS.get(current_status, ()):
        raise ValidationError(
            {
                "to_status": f"Invalid transition from {current_status!r} to {to_status!r}."
            }
        )
    if latest is not None and latest.actor_id == actor.id:
        raise ValidationError(
            {"actor": "Analyst and legal review require different named actors."}
        )

    try:
        obligation_link = (
            RegulatoryObligationProvision.objects.select_related(
                "provision__document_version__document",
            )
            .filter(
                folder=folder,
                obligation=obligation,
                provision__folder=folder,
                provision__document_version__folder=folder,
                provision__document_version__document__folder=folder,
            )
            .get()
        )
    except (
        RegulatoryObligationProvision.DoesNotExist,
        RegulatoryObligationProvision.MultipleObjectsReturned,
    ) as exc:
        raise ValidationError(
            "The obligation must resolve to one regulatory document."
        ) from exc
    document = obligation_link.provision.document_version.document
    aggregate_floor = regulatory_document_recorded_floor(
        document=document,
        folder=folder,
    )
    latest_known_time = max(
        value
        for value in (
            aggregate_floor,
            obligation.recorded_from,
            latest.occurred_at if latest is not None else None,
        )
        if value is not None
    )
    occurred_at = max(
        timezone.now(),
        latest_known_time + timedelta(microseconds=1),
    )

    return RegulatoryObligationReviewEvent.objects.create(
        folder=folder,
        obligation=obligation,
        sequence=(latest.sequence + 1) if latest else 1,
        from_status=current_status,
        to_status=to_status,
        actor=actor,
        occurred_at=occurred_at,
        rationale=rationale,
        idempotency_key=idempotency_key,
        payload_sha256=digest,
    )
