from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone as datetime_timezone
from decimal import Decimal
from typing import Any

from django.core.exceptions import ValidationError
from django.db import transaction
from django.db.models import Max
from django.utils import timezone
from django.utils.dateparse import parse_date, parse_datetime

from iam.models import Folder, ServiceAccount, User
from tprm.models import Entity

from regulatory.contracts import (
    RegulatoryChainCorrectionPayload,
    RegulatoryDocumentVersionCorrectionPayload,
    RegulatoryObligationCorrectionPayload,
    RegulatoryProvisionCorrectionPayload,
    RegulatoryRevisionExpectations,
)
from regulatory.models import (
    CORRECTION_DIGEST_SCHEMA,
    EntityDocumentRegistration,
    RegulatoryChainCorrectionEvent,
    RegulatoryDocument,
    RegulatoryDocumentVersion,
    RegulatoryObligation,
    RegulatoryObligationProvision,
    RegulatoryProvision,
)

from .common import (
    IdempotencyConflict,
    canonical_payload_sha256,
    lock_regulatory_actor,
    require_regulatory_permission,
)
from .records import RegulatoryChain, _provenance_fields


@dataclass(frozen=True)
class RegulatoryCorrectionResult:
    event: RegulatoryChainCorrectionEvent
    chain: RegulatoryChain


def _iso(value) -> str | None:
    if isinstance(value, str):
        parsed_datetime = parse_datetime(value)
        if parsed_datetime is not None:
            value = parsed_datetime
        else:
            parsed_date = parse_date(value)
            return parsed_date.isoformat() if parsed_date is not None else value
    if isinstance(value, datetime):
        value = value.astimezone(datetime_timezone.utc)
    return value.isoformat() if value is not None else None


def _audit_provenance(record) -> dict[str, str | None]:
    payload = record.provenance_payload()
    payload["created_at"] = _iso(record.provenance_created_at)
    return payload


def _audit_payload(
    *,
    version: RegulatoryDocumentVersion,
    provision: RegulatoryProvision,
    obligation: RegulatoryObligation,
) -> dict[str, Any]:
    """Canonical persisted revision set used by the durable correction event."""

    return {
        "digest_schema": CORRECTION_DIGEST_SCHEMA,
        "document_version": {
            "id": version.record_id,
            "version_label": version.version_label,
            "document_no": version.document_no,
            "status": version.status,
            "status_as_of": _iso(version.status_as_of),
            "effective_basis": version.effective_basis,
            "issued_date": _iso(version.issued_date),
            "published_date": _iso(version.published_date),
            "effective_date": _iso(version.effective_date),
            "transition_end": _iso(version.transition_end),
            "repeal_date": _iso(version.repeal_date),
            "source_url": version.source_url,
            "source_hash": version.source_hash,
            "content_storage_policy": version.content_storage_policy,
            "notes": version.notes,
            "source_checked_on": _iso(version.source_checked_on),
            "metadata_confidence": version.metadata_confidence,
            "legal_review_status": version.legal_review_status,
            "legal_reviewed_at": _iso(version.legal_reviewed_at),
            "legal_reviewed_by": version.legal_reviewed_by,
            "valid_from": _iso(version.valid_from),
            "valid_to": _iso(version.valid_to),
            "provenance": _audit_provenance(version),
        },
        "provision": {
            "id": provision.record_id,
            "article": provision.article,
            "heading": provision.heading,
            "text": provision.text,
            "source_locator": {
                "kind": provision.source_locator_kind,
                "value": provision.source_locator_value,
            },
            "content_hash": provision.content_hash,
            "provenance": _audit_provenance(provision),
        },
        "obligation": {
            "id": obligation.record_id,
            "title_zh": obligation.title_zh,
            "authority_level": obligation.authority_level,
            "modality": obligation.modality,
            "subject": obligation.subject,
            "action": obligation.action,
            "object": obligation.object,
            "conditions": obligation.conditions,
            "exceptions": obligation.exceptions,
            "deadline": {
                "kind": obligation.deadline_kind,
                "value": obligation.deadline_value,
                "rule_id": obligation.deadline_rule_id,
            },
            "expected_evidence": obligation.expected_evidence,
            "penalty_or_consequence": obligation.penalty_or_consequence,
            "valid_from": _iso(obligation.valid_from),
            "valid_to": _iso(obligation.valid_to),
            "review_status": obligation.review_status,
            "confidence": format(obligation.confidence, ".4f"),
            "uncertainties": obligation.uncertainties,
            "provenance": _audit_provenance(obligation),
        },
    }


def regulatory_chain_semantic_sha256(chain: RegulatoryChain) -> str:
    """Return the versioned digest used for correction compare-and-swap."""

    return canonical_payload_sha256(
        _audit_payload(
            version=chain.document_version,
            provision=chain.provision,
            obligation=chain.obligation,
        )
    )


def _validate_payload_shape(payload: RegulatoryChainCorrectionPayload) -> None:
    errors: dict[str, str] = {}
    if not isinstance(payload, dict):
        raise ValidationError({"payload": "A correction object is required."})

    sections = {
        "expected_revisions": RegulatoryRevisionExpectations,
        "document_version": RegulatoryDocumentVersionCorrectionPayload,
        "provision": RegulatoryProvisionCorrectionPayload,
        "obligation": RegulatoryObligationCorrectionPayload,
    }
    top_allowed = set(RegulatoryChainCorrectionPayload.__required_keys__) | set(
        RegulatoryChainCorrectionPayload.__optional_keys__
    )
    top_missing = set(RegulatoryChainCorrectionPayload.__required_keys__) - set(payload)
    top_extra = set(payload) - top_allowed
    if top_missing:
        errors["payload"] = f"Missing sections: {', '.join(sorted(top_missing))}."
    if top_extra:
        errors["payload_extra"] = f"Unknown sections: {', '.join(sorted(top_extra))}."

    for name, contract in sections.items():
        section = payload.get(name)
        if not isinstance(section, dict):
            errors[name] = "An object is required."
            continue
        allowed = set(contract.__required_keys__) | set(contract.__optional_keys__)
        missing = set(contract.__required_keys__) - set(section)
        extra = set(section) - allowed
        if missing:
            errors[f"{name}.missing"] = f"Missing fields: {', '.join(sorted(missing))}."
        if extra:
            errors[f"{name}.extra"] = f"Unknown fields: {', '.join(sorted(extra))}."

    if errors:
        raise ValidationError(errors)


def _validate_correction_contract(
    *,
    document: RegulatoryDocument,
    current: RegulatoryChain,
    payload: RegulatoryChainCorrectionPayload,
    current_payload_sha256: str,
) -> None:
    _validate_payload_shape(payload)
    version = payload["document_version"]
    provision = payload["provision"]
    obligation = payload["obligation"]
    expected = payload["expected_revisions"]
    errors: dict[str, str] = {}

    for name in ("document_version", "provision", "obligation"):
        value = expected.get(name)
        if isinstance(value, bool) or not isinstance(value, int) or value < 1:
            errors[f"expected_revisions.{name}"] = (
                "An expected positive integer revision is required."
            )

    expected_digest = expected["semantic_payload_sha256"]
    if (
        not isinstance(expected_digest, str)
        or len(expected_digest) != 64
        or any(character not in "0123456789abcdef" for character in expected_digest)
    ):
        errors["expected_revisions.semantic_payload_sha256"] = (
            "A lowercase SHA-256 semantic payload digest is required."
        )
    elif expected_digest != current_payload_sha256:
        errors["expected_revisions.semantic_payload_sha256"] = (
            "Stale payload: the current semantic chain changed."
        )

    actual = {
        "document_version": current.document_version.revision,
        "provision": current.provision.revision,
        "obligation": current.obligation.revision,
    }
    for name, revision in actual.items():
        if expected.get(name) != revision:
            errors[f"expected_revisions.{name}"] = (
                f"Stale revision: expected {expected.get(name)!r}, current is {revision}."
            )

    if version["id"] != current.document_version.record_id:
        errors["document_version.id"] = "A correction must preserve the version ID."
    if version["document_id"] != document.record_id:
        errors["document_version.document_id"] = (
            "The corrected version must target the current document."
        )
    if provision["id"] != current.provision.record_id:
        errors["provision.id"] = "A correction must preserve the provision ID."
    if provision["document_id"] != document.record_id:
        errors["provision.document_id"] = (
            "The corrected provision must target the current document."
        )
    if provision["version_id"] != current.document_version.record_id:
        errors["provision.version_id"] = (
            "The corrected provision must target the current version identity."
        )
    if obligation["id"] != current.obligation.record_id:
        errors["obligation.id"] = "A correction must preserve the obligation ID."
    if obligation["provision_ids"] != [current.provision.record_id]:
        errors["obligation.provision_ids"] = (
            "The correction accepts exactly the current provision identity."
        )

    if version["supersedes_version_ids"]:
        errors["document_version.supersedes_version_ids"] = (
            "Legal/source-version supersession is outside this correction service."
        )
    if version["content_storage_policy"] != "metadata_only":
        errors["document_version.content_storage_policy"] = (
            "The public correction slice remains metadata-only."
        )
    if provision.get("text") not in (None, ""):
        errors["provision.text"] = "Source text is forbidden for metadata-only records."
    if (
        version["legal_review_status"] != "unreviewed"
        or version.get("legal_reviewed_at") is not None
        or version.get("legal_reviewed_by") is not None
    ):
        errors["document_version.legal_review_status"] = (
            "A correction cannot create a source legal-review conclusion."
        )
    if obligation["review_status"] != "machine_proposed":
        errors["obligation.review_status"] = (
            "A corrected obligation revision must restart as a machine proposal."
        )
    if obligation["authority_level"] != document.authority_level:
        errors["obligation.authority_level"] = (
            "The obligation authority must match its source document."
        )

    for name, revision_payload in (
        ("document_version", version),
        ("provision", provision),
        ("obligation", obligation),
    ):
        forbidden = {
            "recorded_from",
            "recorded_to",
            "revision",
            "previous_revision",
            "previous_revision_id",
        }.intersection(revision_payload)
        if forbidden:
            errors[name] = (
                "Recorded time and revision linkage are server-owned: "
                + ", ".join(sorted(forbidden))
            )

    if errors:
        raise ValidationError(errors)


def _chain_from_event(
    *,
    registration: EntityDocumentRegistration,
    event: RegulatoryChainCorrectionEvent,
) -> RegulatoryChain:
    return RegulatoryChain(
        registration=registration,
        document=event.document,
        document_version=event.successor_document_version,
        provision=event.successor_provision,
        obligation=event.successor_obligation,
    )


def _lock_current_chain(
    *,
    registration: EntityDocumentRegistration,
    folder: Folder,
) -> RegulatoryChain:
    document = RegulatoryDocument.objects.select_for_update().get(
        pk=registration.document_id,
        folder=folder,
    )
    version = RegulatoryDocumentVersion.objects.select_for_update().get(
        document=document,
        folder=folder,
        recorded_to__isnull=True,
    )
    provision = RegulatoryProvision.objects.select_for_update().get(
        document_version=version,
        folder=folder,
        recorded_to__isnull=True,
    )
    obligation = RegulatoryObligation.objects.select_for_update().get(
        provision_links__provision=provision,
        provision_links__folder=folder,
        folder=folder,
        recorded_to__isnull=True,
    )
    RegulatoryObligationProvision.objects.select_for_update().get(
        folder=folder,
        provision=provision,
        obligation=obligation,
    )
    return RegulatoryChain(
        registration=registration,
        document=document,
        document_version=version,
        provision=provision,
        obligation=obligation,
    )


@transaction.atomic
def correct_regulatory_chain(
    *,
    actor: User,
    entity: Entity,
    document_id,
    payload: RegulatoryChainCorrectionPayload,
    rationale: str,
    idempotency_key: str,
) -> RegulatoryCorrectionResult:
    """Close one exact current revision set and append validated successors."""

    idempotency_key = idempotency_key.strip() if idempotency_key else ""
    if not idempotency_key:
        raise ValidationError({"idempotency_key": "A non-empty key is required."})
    rationale = rationale.strip() if rationale else ""
    if not rationale:
        raise ValidationError({"rationale": "A non-empty rationale is required."})
    if entity.pk is None:
        raise ValidationError({"entity": "A persisted synthetic entity is required."})

    actor = lock_regulatory_actor(actor=actor)
    entity = Entity.objects.select_for_update().get(pk=entity.pk)
    folder = Folder.objects.select_for_update().get(pk=entity.folder_id)
    if not entity.ref_id.upper().startswith("SYNTHETIC-"):
        raise ValidationError(
            {"entity": "The public correction slice accepts only SYNTHETIC-* entities."}
        )
    require_regulatory_permission(
        actor=actor,
        codename="correct_regulatoryrecord",
        folder=folder,
    )
    if ServiceAccount.objects.filter(user=actor).exists():
        raise ValidationError(
            {"actor": "A named human is required for regulatory correction."}
        )

    registration = (
        EntityDocumentRegistration.objects.select_for_update()
        .select_related("document")
        .get(entity=entity, document_id=document_id, folder=folder)
    )
    request_digest = canonical_payload_sha256(
        {
            "digest_schema": CORRECTION_DIGEST_SCHEMA,
            "actor_id": str(actor.id),
            "entity_id": str(entity.id),
            "document_id": str(document_id),
            "payload": payload,
            "rationale": rationale,
        }
    )
    existing = (
        RegulatoryChainCorrectionEvent.objects.select_for_update()
        .select_related(
            "document",
            "successor_document_version",
            "successor_provision",
            "successor_obligation",
        )
        .filter(folder=folder, idempotency_key=idempotency_key)
        .first()
    )
    if existing is not None:
        if existing.payload_sha256 != request_digest:
            raise IdempotencyConflict(
                {"idempotency_key": "The key is bound to a different correction."}
            )
        return RegulatoryCorrectionResult(
            event=existing,
            chain=_chain_from_event(registration=registration, event=existing),
        )

    current = _lock_current_chain(registration=registration, folder=folder)
    before_payload = _audit_payload(
        version=current.document_version,
        provision=current.provision,
        obligation=current.obligation,
    )
    before_payload_sha256 = canonical_payload_sha256(before_payload)
    _validate_correction_contract(
        document=current.document,
        current=current,
        payload=payload,
        current_payload_sha256=before_payload_sha256,
    )

    latest_known_time = max(
        current.document_version.recorded_from,
        current.provision.recorded_from,
        current.obligation.recorded_from,
    )
    latest_review_at = current.obligation.review_events.filter(
        folder=folder,
    ).aggregate(value=Max("occurred_at"))["value"]
    if latest_review_at is not None:
        latest_known_time = max(latest_known_time, latest_review_at)
    cutoff = max(
        timezone.now(),
        latest_known_time + timedelta(microseconds=1),
    )

    for model, instance in (
        (RegulatoryDocumentVersion, current.document_version),
        (RegulatoryProvision, current.provision),
        (RegulatoryObligation, current.obligation),
    ):
        updated = model.objects.filter(
            pk=instance.pk,
            revision=instance.revision,
            recorded_to__isnull=True,
        ).update(recorded_to=cutoff)
        if updated != 1:
            raise ValidationError(
                {"expected_revisions": "Stale write: the current chain changed."}
            )
        instance.recorded_to = cutoff

    version_data = payload["document_version"]
    successor_version = RegulatoryDocumentVersion.objects.create(
        folder=folder,
        document=current.document,
        record_id=current.document_version.record_id,
        revision=current.document_version.revision + 1,
        previous_revision=current.document_version,
        recorded_from=cutoff,
        recorded_to=None,
        version_label=version_data["version_label"],
        document_no=version_data["document_no"],
        status=version_data["status"],
        status_as_of=version_data["status_as_of"],
        effective_basis=version_data["effective_basis"],
        issued_date=version_data["issued_date"],
        published_date=version_data["published_date"],
        effective_date=version_data["effective_date"],
        transition_end=version_data["transition_end"],
        repeal_date=version_data["repeal_date"],
        source_url=version_data["source_url"],
        source_hash=version_data["source_hash"],
        content_storage_policy=version_data["content_storage_policy"],
        notes=version_data["notes"],
        source_checked_on=version_data["source_checked_on"],
        metadata_confidence=version_data["metadata_confidence"],
        legal_review_status=version_data["legal_review_status"],
        legal_reviewed_at=version_data["legal_reviewed_at"],
        legal_reviewed_by=version_data["legal_reviewed_by"],
        valid_from=version_data["valid_from"],
        valid_to=version_data["valid_to"],
        **_provenance_fields(version_data),
    )

    provision_data = payload["provision"]
    locator = provision_data["source_locator"]
    successor_provision = RegulatoryProvision.objects.create(
        folder=folder,
        document_version=successor_version,
        record_id=current.provision.record_id,
        revision=current.provision.revision + 1,
        previous_revision=current.provision,
        recorded_from=cutoff,
        recorded_to=None,
        article=provision_data["article"],
        heading=provision_data["heading"],
        text=None,
        source_locator_kind=locator["kind"],
        source_locator_value=locator["value"],
        content_hash=provision_data["content_hash"],
        **_provenance_fields(provision_data),
    )

    obligation_data = payload["obligation"]
    deadline = obligation_data["deadline"]
    successor_obligation = RegulatoryObligation.objects.create(
        folder=folder,
        record_id=current.obligation.record_id,
        revision=current.obligation.revision + 1,
        previous_revision=current.obligation,
        recorded_from=cutoff,
        recorded_to=None,
        title_zh=obligation_data["title_zh"],
        authority_level=obligation_data["authority_level"],
        modality=obligation_data["modality"],
        subject=obligation_data["subject"],
        action=obligation_data["action"],
        object=obligation_data["object"],
        conditions=obligation_data["conditions"],
        exceptions=obligation_data["exceptions"],
        deadline_kind=deadline["kind"],
        deadline_value=deadline.get("value"),
        deadline_rule_id=deadline.get("rule_id"),
        expected_evidence=obligation_data["expected_evidence"],
        penalty_or_consequence=obligation_data["penalty_or_consequence"],
        valid_from=obligation_data["valid_from"],
        valid_to=obligation_data["valid_to"],
        review_status=obligation_data["review_status"],
        confidence=Decimal(str(obligation_data["confidence"])),
        uncertainties=obligation_data["uncertainties"],
        **_provenance_fields(obligation_data),
    )
    RegulatoryObligationProvision.objects.create(
        folder=folder,
        obligation=successor_obligation,
        provision=successor_provision,
        order=0,
    )

    after_payload = _audit_payload(
        version=successor_version,
        provision=successor_provision,
        obligation=successor_obligation,
    )
    event = RegulatoryChainCorrectionEvent.objects.create(
        folder=folder,
        document=current.document,
        previous_document_version=current.document_version,
        successor_document_version=successor_version,
        previous_provision=current.provision,
        successor_provision=successor_provision,
        previous_obligation=current.obligation,
        successor_obligation=successor_obligation,
        actor=actor,
        digest_schema=CORRECTION_DIGEST_SCHEMA,
        occurred_at=cutoff,
        rationale=rationale,
        idempotency_key=idempotency_key,
        payload_sha256=request_digest,
        before_payload_sha256=before_payload_sha256,
        after_payload_sha256=canonical_payload_sha256(after_payload),
    )
    return RegulatoryCorrectionResult(
        event=event,
        chain=RegulatoryChain(
            registration=registration,
            document=current.document,
            document_version=successor_version,
            provision=successor_provision,
            obligation=successor_obligation,
        ),
    )
