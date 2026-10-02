"""Synthetic whole-document replacement metadata; no legal approval or writes API."""

import math
from dataclasses import dataclass
from datetime import UTC, date, timedelta
from decimal import Decimal

from django.core.exceptions import (
    MultipleObjectsReturned,
    ObjectDoesNotExist,
    ValidationError,
)
from django.db import transaction
from django.utils import timezone
from django.utils.dateparse import parse_date, parse_datetime
from iam.models import Folder, ServiceAccount, User
from tprm.models import Entity

from regulatory.contracts import (
    RegulatoryDocumentVersionCorrectionPayload,
    RegulatoryObligationCorrectionPayload,
    RegulatoryProvisionCorrectionPayload,
    RegulatoryRevisionExpectations,
    RegulatoryVersionSupersessionPayload,
)
from regulatory.models import (
    SUPERSESSION_DIGEST_SCHEMA,
    EntityDocumentRegistration,
    RegulatoryDocumentVersion,
    RegulatoryObligation,
    RegulatoryObligationProvision,
    RegulatoryProvision,
    RegulatoryVersionSupersessionEvent,
)

from .common import (
    IdempotencyConflict,
    canonical_payload_sha256,
    lock_regulatory_actor,
    require_regulatory_permission,
)
from .corrections import regulatory_chain_semantic_sha256
from .records import (
    RegulatoryChain,
    _provenance_fields,
    lock_current_regulatory_chain,
    regulatory_document_recorded_floor,
)


@dataclass(frozen=True)
class RegulatorySupersessionResult:
    event: RegulatoryVersionSupersessionEvent
    predecessor: RegulatoryChain
    chain: RegulatoryChain


def _strict_object(value, contract, label: str) -> dict:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise ValidationError({label: "A string-keyed object is required."})
    required = contract.__required_keys__
    allowed = required | contract.__optional_keys__
    if not required <= value.keys() or not value.keys() <= allowed:
        raise ValidationError({label: "Missing required or unknown fields."})
    return value


def _string(value, label: str, *, nullable=False) -> None:
    if nullable and value is None:
        return
    if not isinstance(value, str):
        raise ValidationError({label: "A string is required."})


def _date(value, label: str, *, nullable=False) -> date | None:
    if nullable and value is None:
        return None
    _string(value, label)
    try:
        parsed = parse_date(value)
    except ValueError:
        parsed = None
    if parsed is None or parsed.isoformat() != value:
        raise ValidationError({label: "Use an ISO calendar date."})
    return parsed


def _validate_shape(payload: RegulatoryVersionSupersessionPayload) -> str:
    _strict_object(payload, RegulatoryVersionSupersessionPayload, "payload")
    sections = {
        "expected_revisions": RegulatoryRevisionExpectations,
        "document_version": RegulatoryDocumentVersionCorrectionPayload,
        "provision": RegulatoryProvisionCorrectionPayload,
        "obligation": RegulatoryObligationCorrectionPayload,
    }
    for name, contract in sections.items():
        _strict_object(payload[name], contract, name)
    expected = payload["expected_revisions"]
    for field in ("document_version", "provision", "obligation"):
        if type(expected[field]) is not int or expected[field] < 1:
            raise ValidationError(
                {f"expected_revisions.{field}": "A positive integer is required."}
            )
    _string(
        expected["semantic_payload_sha256"],
        "expected_revisions.semantic_payload_sha256",
    )
    for name in ("document_version", "provision", "obligation"):
        section = payload[name]
        for field, value in section.items():
            if field in {"provenance", "source_locator", "deadline", "confidence"}:
                continue
            if field in {
                "conditions",
                "exceptions",
                "expected_evidence",
                "uncertainties",
                "provision_ids",
                "supersedes_version_ids",
            }:
                if not isinstance(value, list) or not all(
                    isinstance(item, str) for item in value
                ):
                    raise ValidationError(
                        {f"{name}.{field}": "A list of strings is required."}
                    )
            else:
                nullable = field in {
                    "document_no",
                    "issued_date",
                    "published_date",
                    "effective_date",
                    "transition_end",
                    "repeal_date",
                    "source_hash",
                    "legal_reviewed_at",
                    "legal_reviewed_by",
                    "valid_from",
                    "valid_to",
                    "heading",
                    "text",
                    "object",
                    "penalty_or_consequence",
                }
                _string(value, f"{name}.{field}", nullable=nullable)
        provenance = section["provenance"]
        if (
            not isinstance(provenance, dict)
            or not {"method", "created_at", "created_by"} <= provenance.keys()
            or not provenance.keys()
            <= {
                "method",
                "created_at",
                "created_by",
                "parser_version",
                "model",
                "prompt_version",
                "retrieval_version",
            }
        ):
            raise ValidationError(
                {
                    f"{name}.provenance": "A complete bounded provenance object is required."
                }
            )
        for field, value in provenance.items():
            _string(
                value,
                f"{name}.provenance.{field}",
                nullable=field
                in {"parser_version", "model", "prompt_version", "retrieval_version"},
            )
        try:
            provenance_time = parse_datetime(provenance["created_at"])
        except ValueError:
            provenance_time = None
        if provenance_time is None or timezone.is_naive(provenance_time):
            raise ValidationError(
                {
                    f"{name}.provenance.created_at": "An aware provenance time is required."
                }
            )
    locator = payload["provision"]["source_locator"]
    if not isinstance(locator, dict) or set(locator) != {"kind", "value"}:
        raise ValidationError(
            {"provision.source_locator": "Exactly kind and value are required."}
        )
    for field, value in locator.items():
        _string(value, f"provision.source_locator.{field}")
    deadline = payload["obligation"]["deadline"]
    if not isinstance(deadline, dict) or set(deadline) != {"kind", "value", "rule_id"}:
        raise ValidationError(
            {"obligation.deadline": "Exactly kind, value and rule_id are required."}
        )
    for field, value in deadline.items():
        _string(value, f"obligation.deadline.{field}", nullable=field != "kind")
    confidence = payload["obligation"]["confidence"]
    if (
        type(confidence) not in (int, float)
        or not 0 <= confidence <= 1
        or not math.isfinite(confidence)
    ):
        raise ValidationError(
            {
                "obligation.confidence": "A finite numeric confidence from 0 to 1 is required."
            }
        )
    supersedes = payload["document_version"]["supersedes_version_ids"]
    if len(supersedes) != 1 or not supersedes[0].strip():
        raise ValidationError(
            {
                "document_version.supersedes_version_ids": "Exactly one predecessor stable version ID is required."
            }
        )
    return supersedes[0]


def _validate_replacement(*, predecessor: RegulatoryChain, payload, folder) -> date:
    expected = payload["expected_revisions"]
    for name, record in (
        ("document_version", predecessor.document_version),
        ("provision", predecessor.provision),
        ("obligation", predecessor.obligation),
    ):
        if expected[name] != record.revision or record.recorded_to is not None:
            raise ValidationError(
                {"expected_revisions": "The predecessor revision is stale."}
            )
    if expected["semantic_payload_sha256"] != regulatory_chain_semantic_sha256(
        predecessor
    ):
        raise ValidationError(
            {"expected_revisions": "The predecessor semantic digest is stale."}
        )
    version, provision, obligation = (
        payload[name] for name in ("document_version", "provision", "obligation")
    )
    old = predecessor.document_version
    if (
        old.effective_date is None
        or old.valid_from != old.effective_date
        or old.effective_basis not in ("explicit_date", "publication_clause")
        or old.status not in ("effective", "published_future_effective")
    ):
        raise ValidationError(
            {"predecessor": "A known, resolved predecessor lifecycle is required."}
        )
    if (
        old.valid_to is not None
        or old.transition_end is not None
        or old.repeal_date is not None
    ):
        raise ValidationError(
            {"predecessor": "Closed, repealed and transition versions are unsupported."}
        )
    if (
        predecessor.obligation.valid_to is not None
        or predecessor.obligation.valid_from != old.effective_date
    ):
        raise ValidationError(
            {
                "predecessor": "The predecessor obligation must remain open from its effective date."
            }
        )
    if (
        old.content_storage_policy != "metadata_only"
        or old.legal_review_status != "unreviewed"
        or old.is_published
        or predecessor.provision.text not in (None, "")
    ):
        raise ValidationError(
            {
                "predecessor": "The predecessor must remain unpublished synthetic metadata."
            }
        )
    if (
        version["document_id"] != predecessor.document.record_id
        or provision["document_id"] != predecessor.document.record_id
        or provision["version_id"] != version["id"]
        or obligation["provision_ids"] != [provision["id"]]
    ):
        raise ValidationError(
            {
                "payload": "The exact same-document one-provision citation chain is required."
            }
        )
    if (
        version["content_storage_policy"] != "metadata_only"
        or provision["text"] not in (None, "")
        or version["legal_review_status"] != "unreviewed"
        or version["legal_reviewed_at"] is not None
        or version["legal_reviewed_by"] is not None
    ):
        raise ValidationError(
            {"payload": "Source text, legal review and publication are not enabled."}
        )
    if (
        obligation["review_status"] != "machine_proposed"
        or obligation["authority_level"] != predecessor.document.authority_level
    ):
        raise ValidationError(
            {
                "obligation": "The replacement is an unreviewed proposal under the original authority."
            }
        )
    if version["status"] not in ("effective", "published_future_effective") or version[
        "effective_basis"
    ] not in ("explicit_date", "publication_clause"):
        raise ValidationError(
            {
                "document_version": "A resolved effective or future-effective lifecycle is required."
            }
        )
    effective_on = _date(version["effective_date"], "document_version.effective_date")
    if (
        _date(version["valid_from"], "document_version.valid_from") != effective_on
        or _date(obligation["valid_from"], "obligation.valid_from") != effective_on
        or effective_on <= old.effective_date
    ):
        raise ValidationError(
            {
                "effective_on": "The exact new version and obligation start must be after the predecessor effective date."
            }
        )
    if (
        any(
            version[field] is not None
            for field in ("valid_to", "transition_end", "repeal_date")
        )
        or obligation["valid_to"] is not None
    ):
        raise ValidationError(
            {
                "effective_on": "Closed, repealed or transition replacements are unsupported."
            }
        )
    for field in ("status_as_of", "source_checked_on", "issued_date", "published_date"):
        _date(
            version[field],
            f"document_version.{field}",
            nullable=field in ("issued_date", "published_date"),
        )
    if version["status"] == "effective" and effective_on > _date(
        version["status_as_of"], "document_version.status_as_of"
    ):
        raise ValidationError(
            {"document_version.status": "A future version cannot be marked effective."}
        )
    new_ids = [version["id"], provision["id"], obligation["id"]]
    if len(set(new_ids)) != 3:
        raise ValidationError(
            {"payload": "Three distinct new stable identities are required."}
        )
    for model in (RegulatoryDocumentVersion, RegulatoryProvision, RegulatoryObligation):
        if model.objects.filter(folder=folder, record_id__in=new_ids).exists():
            raise ValidationError(
                {"payload": "A replacement stable ID was already used."}
            )
    if RegulatoryVersionSupersessionEvent.objects.filter(
        folder=folder,
        document=predecessor.document,
        predecessor_version_record_id=old.record_id,
    ).exists():
        raise ValidationError(
            {
                "predecessor": "The exact predecessor must be an unsuperseded leaf; forks are forbidden."
            }
        )
    return effective_on


def _append_chain(*, registration, predecessor, payload, cutoff) -> RegulatoryChain:
    folder, document = predecessor.document.folder, predecessor.document
    version_data = dict(payload["document_version"])
    for field in ("id", "document_id", "supersedes_version_ids", "provenance"):
        version_data.pop(field)
    version = RegulatoryDocumentVersion.objects.create(
        folder=folder,
        document=document,
        record_id=payload["document_version"]["id"],
        recorded_from=cutoff,
        **version_data,
        **_provenance_fields(payload["document_version"]),
    )
    provision_data = dict(payload["provision"])
    for field in (
        "id",
        "document_id",
        "version_id",
        "provenance",
        "source_locator",
        "text",
    ):
        provision_data.pop(field)
    provision = RegulatoryProvision.objects.create(
        folder=folder,
        document_version=version,
        record_id=payload["provision"]["id"],
        recorded_from=cutoff,
        text=None,
        source_locator_kind=payload["provision"]["source_locator"]["kind"],
        source_locator_value=payload["provision"]["source_locator"]["value"],
        **provision_data,
        **_provenance_fields(payload["provision"]),
    )
    obligation_data = dict(payload["obligation"])
    for field in ("id", "provision_ids", "provenance", "deadline", "confidence"):
        obligation_data.pop(field)
    deadline = payload["obligation"]["deadline"]
    obligation = RegulatoryObligation.objects.create(
        folder=folder,
        record_id=payload["obligation"]["id"],
        recorded_from=cutoff,
        deadline_kind=deadline["kind"],
        deadline_value=deadline["value"],
        deadline_rule_id=deadline["rule_id"],
        confidence=Decimal(str(payload["obligation"]["confidence"])),
        **obligation_data,
        **_provenance_fields(payload["obligation"]),
    )
    RegulatoryObligationProvision.objects.create(
        folder=folder, obligation=obligation, provision=provision, order=0
    )
    return RegulatoryChain(
        registration=registration,
        document=document,
        document_version=version,
        provision=provision,
        obligation=obligation,
    )


def _result_from_event(event) -> RegulatorySupersessionResult:
    event.full_clean()

    def chain(prefix):
        return RegulatoryChain(
            registration=event.registration,
            document=event.document,
            document_version=getattr(event, f"{prefix}_document_version"),
            provision=getattr(event, f"{prefix}_provision"),
            obligation=getattr(event, f"{prefix}_obligation"),
        )

    return RegulatorySupersessionResult(
        event=event, predecessor=chain("predecessor"), chain=chain("successor")
    )


@transaction.atomic
def supersede_regulatory_version(
    *,
    actor: User,
    entity: Entity,
    document_id,
    payload: RegulatoryVersionSupersessionPayload,
    rationale: str,
    idempotency_key: str,
) -> RegulatorySupersessionResult:
    """Append a synthetic whole-version edge and chain without changing old rows."""
    if not isinstance(rationale, str) or not rationale.strip() or len(rationale) > 4000:
        raise ValidationError(
            {
                "rationale": "A non-empty rationale of at most 4000 characters is required."
            }
        )
    if (
        not isinstance(idempotency_key, str)
        or not idempotency_key.strip()
        or len(idempotency_key) > 200
    ):
        raise ValidationError(
            {
                "idempotency_key": "A non-empty string key of at most 200 characters is required."
            }
        )
    predecessor_id = _validate_shape(payload)
    rationale, idempotency_key = rationale.strip(), idempotency_key.strip()
    actor = lock_regulatory_actor(actor=actor)
    if ServiceAccount.objects.filter(user=actor).exists():
        raise ValidationError(
            {"actor": "A named human is required for synthetic replacement metadata."}
        )
    if not isinstance(entity, Entity) or entity.pk is None:
        raise ValidationError({"entity": "A persisted synthetic entity is required."})
    try:
        entity = Entity.objects.select_for_update().get(pk=entity.pk)
        folder = Folder.objects.select_for_update().get(pk=entity.folder_id)
        require_regulatory_permission(
            actor=actor, codename="supersede_regulatoryversion", folder=folder
        )
        registration = (
            EntityDocumentRegistration.objects.select_for_update()
            .select_related("document")
            .get(entity=entity, document_id=document_id, folder=folder)
        )
    except (ObjectDoesNotExist, MultipleObjectsReturned, ValueError) as exc:
        raise ValidationError(
            {"document": "One exact synthetic document registration is required."}
        ) from exc
    if (
        not (entity.ref_id or "").upper().startswith("SYNTHETIC-")
        or registration.registration_kind != "synthetic_pilot"
    ):
        raise ValidationError(
            {"entity": "Only SYNTHETIC-* registered pilot entities are enabled."}
        )
    request_digest = canonical_payload_sha256(
        {
            "digest_schema": SUPERSESSION_DIGEST_SCHEMA,
            "actor_id": str(actor.id),
            "entity_id": str(entity.id),
            "document_id": str(registration.document_id),
            "payload": payload,
            "rationale": rationale,
        }
    )
    existing = (
        RegulatoryVersionSupersessionEvent.objects.select_for_update()
        .filter(folder=folder, idempotency_key=idempotency_key)
        .first()
    )
    if existing is not None:
        if existing.payload_sha256 != request_digest:
            raise IdempotencyConflict(
                {
                    "idempotency_key": "The key is bound to a different replacement request."
                }
            )
        return _result_from_event(existing)
    try:
        predecessor = lock_current_regulatory_chain(
            registration=registration, folder=folder, version_record_id=predecessor_id
        )
    except (ObjectDoesNotExist, MultipleObjectsReturned) as exc:
        raise ValidationError(
            {"predecessor": "One current exact predecessor chain is required."}
        ) from exc
    effective_on = _validate_replacement(
        predecessor=predecessor, payload=payload, folder=folder
    )
    floor = regulatory_document_recorded_floor(
        document=predecessor.document, folder=folder
    )
    latest_known = max(
        value
        for value in (
            floor,
            predecessor.document_version.recorded_from,
            predecessor.provision.recorded_from,
            predecessor.obligation.recorded_from,
        )
        if value is not None
    )
    cutoff = max(timezone.now(), latest_known + timedelta(microseconds=1))
    if (
        _date(
            payload["document_version"]["source_checked_on"],
            "document_version.source_checked_on",
        )
        > cutoff.astimezone(UTC).date()
    ):
        raise ValidationError(
            {
                "document_version.source_checked_on": "Source knowledge cannot be checked after the server recorded date."
            }
        )
    before_digest = regulatory_chain_semantic_sha256(predecessor)
    successor = _append_chain(
        registration=registration,
        predecessor=predecessor,
        payload=payload,
        cutoff=cutoff,
    )
    event = RegulatoryVersionSupersessionEvent.objects.create(
        folder=folder,
        document=predecessor.document,
        registration=registration,
        predecessor_document_version=predecessor.document_version,
        successor_document_version=successor.document_version,
        predecessor_provision=predecessor.provision,
        successor_provision=successor.provision,
        predecessor_obligation=predecessor.obligation,
        successor_obligation=successor.obligation,
        predecessor_version_record_id=predecessor.document_version.record_id,
        successor_version_record_id=successor.document_version.record_id,
        effective_on=effective_on,
        occurred_at=cutoff,
        recorded_by=actor,
        rationale=rationale,
        idempotency_key=idempotency_key,
        payload_sha256=request_digest,
        before_payload_sha256=before_digest,
        after_payload_sha256=regulatory_chain_semantic_sha256(successor),
    )
    return RegulatorySupersessionResult(
        event=event, predecessor=predecessor, chain=successor
    )
