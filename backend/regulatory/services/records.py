from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal

from django.core.exceptions import (
    MultipleObjectsReturned,
    ObjectDoesNotExist,
    ValidationError,
)
from django.db import transaction
from django.db.models import Max, Q
from django.utils import timezone
from django.utils.dateparse import parse_datetime

from iam.models import Folder, User
from tprm.models import Entity

from regulatory.contracts import RegulatoryChainPayload
from regulatory.models import (
    EntityDocumentRegistration,
    RegulatoryApplicabilityDecision,
    RegulatoryApplicabilityReviewDisposition,
    RegulatoryDocument,
    RegulatoryDocumentVersion,
    RegulatoryObligation,
    RegulatoryObligationProvision,
    RegulatoryObligationReviewEvent,
    RegulatoryProvision,
)

from .common import (
    IdempotencyConflict,
    canonical_payload_sha256,
    lock_regulatory_actor,
    require_regulatory_permission,
)


@dataclass(frozen=True)
class RegulatoryChain:
    registration: EntityDocumentRegistration | None
    document: RegulatoryDocument
    document_version: RegulatoryDocumentVersion
    provision: RegulatoryProvision
    obligation: RegulatoryObligation
    recorded_as_of: datetime | None = None


class RegulatoryRecordedStateUnavailable(ValidationError):
    """A syntactically valid recorded time has no unique persisted chain."""


def _provenance_fields(payload: dict) -> dict:
    provenance = payload.get("provenance")
    if not isinstance(provenance, dict):
        raise ValidationError({"provenance": "A provenance object is required."})
    required = ("method", "created_at", "created_by")
    missing = [field for field in required if not provenance.get(field)]
    if missing:
        raise ValidationError(
            {"provenance": f"Missing provenance fields: {', '.join(missing)}"}
        )
    return {
        "provenance_method": provenance["method"],
        "provenance_created_at": provenance["created_at"],
        "provenance_created_by": provenance["created_by"],
        "parser_version": provenance.get("parser_version"),
        "model_name": provenance.get("model"),
        "prompt_version": provenance.get("prompt_version"),
        "retrieval_version": provenance.get("retrieval_version"),
    }


def _validate_first_slice_contract(payload: RegulatoryChainPayload) -> None:
    document = payload["document"]
    version = payload["document_version"]
    provision = payload["provision"]
    obligation = payload["obligation"]

    errors: dict[str, str] = {}
    if version["document_id"] != document["id"]:
        errors["document_version"] = "document_id does not match the document."
    if provision["document_id"] != document["id"]:
        errors["provision"] = "document_id does not match the document."
    if provision["version_id"] != version["id"]:
        errors["provision_version"] = "version_id does not match the version."
    if obligation["provision_ids"] != [provision["id"]]:
        errors["provision_ids"] = (
            "The first slice accepts exactly the included provision ID."
        )
    if version["supersedes_version_ids"]:
        errors["supersedes_version_ids"] = (
            "Version supersession ingestion is not enabled in the first slice."
        )
    if version["content_storage_policy"] != "metadata_only":
        errors["content_storage_policy"] = (
            "The public first slice accepts metadata-only sources."
        )
    if provision.get("text") not in (None, ""):
        errors["text"] = "Source text is forbidden for metadata-only records."
    if version["legal_review_status"] != "unreviewed":
        errors["legal_review_status"] = (
            "Binding source legal review is not enabled in the first slice."
        )
    if (
        version.get("legal_reviewed_at") is not None
        or version.get("legal_reviewed_by") is not None
    ):
        errors["legal_reviewed_by"] = (
            "Unreviewed sources cannot carry legal-review identities."
        )
    if obligation["review_status"] != "machine_proposed":
        errors["review_status"] = (
            "A first-slice obligation must enter as a machine proposal."
        )
    if obligation["authority_level"] != document["authority_level"]:
        errors["authority_level"] = (
            "The obligation authority must match its only source document."
        )
    if document.get("coverage_stage", "obligations_proposed") != (
        "obligations_proposed"
    ):
        errors["coverage_stage"] = (
            "The first slice contains a provision and proposed obligation."
        )
    for record_name, record in (
        ("document_version", version),
        ("provision", provision),
        ("obligation", obligation),
    ):
        if record["recorded_to"] is not None:
            errors[f"{record_name}.recorded_to"] = (
                "The first slice accepts only current recorded revisions."
            )
    recorded_starts = {
        record_name: parse_datetime(record["recorded_from"])
        for record_name, record in (
            ("document_version", version),
            ("provision", provision),
            ("obligation", obligation),
        )
    }
    for record_name, recorded_from in recorded_starts.items():
        if recorded_from is None or timezone.is_naive(recorded_from):
            errors[f"{record_name}.recorded_from"] = (
                "A timezone-aware RFC 3339 recorded_from is required."
            )
        elif recorded_from > timezone.now():
            errors[f"{record_name}.recorded_from"] = (
                "An initial recorded_from cannot be in the future."
            )
    aware_starts = [
        value
        for value in recorded_starts.values()
        if value is not None and timezone.is_aware(value)
    ]
    if len(aware_starts) == 3 and len(set(aware_starts)) != 1:
        errors["recorded_from"] = (
            "The initial version, provision, and obligation must start together."
        )
    if errors:
        raise ValidationError(errors)


def _existing_chain(
    registration: EntityDocumentRegistration,
    payload: RegulatoryChainPayload,
) -> RegulatoryChain:
    document = registration.document
    if document.folder_id != registration.folder_id:
        raise ValidationError("The registered document folder is inconsistent.")
    version = RegulatoryDocumentVersion.objects.get(
        document=document,
        folder=registration.folder,
        record_id=payload["document_version"]["id"],
        revision=1,
        previous_revision__isnull=True,
    )
    provision = RegulatoryProvision.objects.get(
        document_version=version,
        folder=registration.folder,
        record_id=payload["provision"]["id"],
        revision=1,
        previous_revision__isnull=True,
    )
    obligation = RegulatoryObligation.objects.get(
        provision_links__provision=provision,
        folder=registration.folder,
        record_id=payload["obligation"]["id"],
        revision=1,
        previous_revision__isnull=True,
    )
    return RegulatoryChain(
        registration=registration,
        document=document,
        document_version=version,
        provision=provision,
        obligation=obligation,
    )


@transaction.atomic
def create_regulatory_chain(
    *,
    actor: User,
    entity: Entity,
    payload: RegulatoryChainPayload,
    idempotency_key: str,
) -> RegulatoryChain:
    """Persist the one-provision synthetic pilot chain as one transaction."""

    if not idempotency_key or not idempotency_key.strip():
        raise ValidationError({"idempotency_key": "A non-empty key is required."})
    if entity.pk is None:
        raise ValidationError({"entity": "A persisted synthetic entity is required."})

    actor = lock_regulatory_actor(actor=actor)

    # Never trust caller-mutated model attributes at an authority boundary. The
    # stable entity row also serialises same-folder idempotency claims.
    entity = (
        Entity.objects.select_for_update().select_related("folder").get(pk=entity.pk)
    )
    folder = Folder.objects.select_for_update().get(pk=entity.folder_id)
    if not entity.ref_id.upper().startswith("SYNTHETIC-"):
        raise ValidationError(
            {"entity": "The public first slice accepts only SYNTHETIC-* entities."}
        )

    require_regulatory_permission(
        actor=actor,
        codename="ingest_regulatoryrecord",
        folder=folder,
    )

    digest = canonical_payload_sha256({"entity_id": str(entity.id), "payload": payload})
    existing = (
        EntityDocumentRegistration.objects.select_for_update()
        .select_related("document")
        .filter(folder=folder, idempotency_key=idempotency_key)
        .first()
    )
    if existing is not None:
        if existing.payload_sha256 != digest or existing.entity_id != entity.id:
            raise IdempotencyConflict(
                {"idempotency_key": "The key is bound to a different payload."}
            )
        return _existing_chain(existing, payload)

    # Validate wall-clock-sensitive fields only for a new command. An exact
    # retry is bound to the already committed payload digest and must remain
    # idempotent if the host clock later moves behind its recorded timestamp.
    _validate_first_slice_contract(payload)

    document_data = payload["document"]
    version_data = payload["document_version"]
    provision_data = payload["provision"]
    obligation_data = payload["obligation"]

    document = RegulatoryDocument.objects.create(
        folder=folder,
        record_id=document_data["id"],
        title_zh=document_data["title_zh"],
        title_en=document_data.get("title_en", ""),
        issuer=document_data["issuer"],
        authority_level=document_data["authority_level"],
        territories=document_data["territories"],
        regulated_entity_scopes=document_data["regulated_entity_scopes"],
        domains=document_data["domains"],
        coverage_priority=document_data.get("coverage_priority", ""),
        coverage_stage=document_data.get("coverage_stage", "obligations_proposed"),
        applicability_fact_keys=document_data.get("applicability_fact_keys", []),
        selection_rationale=document_data.get("selection_rationale", ""),
    )
    registration = EntityDocumentRegistration.objects.create(
        folder=folder,
        entity=entity,
        document=document,
        idempotency_key=idempotency_key,
        payload_sha256=digest,
        ingested_by=actor,
    )

    version = RegulatoryDocumentVersion.objects.create(
        folder=folder,
        document=document,
        record_id=version_data["id"],
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
        notes=version_data.get("notes", ""),
        source_checked_on=version_data["source_checked_on"],
        metadata_confidence=version_data["metadata_confidence"],
        legal_review_status=version_data["legal_review_status"],
        legal_reviewed_at=version_data["legal_reviewed_at"],
        legal_reviewed_by=version_data["legal_reviewed_by"],
        valid_from=version_data["valid_from"],
        valid_to=version_data["valid_to"],
        recorded_from=version_data["recorded_from"],
        recorded_to=version_data["recorded_to"],
        **_provenance_fields(version_data),
    )

    locator = provision_data["source_locator"]
    provision = RegulatoryProvision.objects.create(
        folder=folder,
        document_version=version,
        record_id=provision_data["id"],
        article=provision_data["article"],
        heading=provision_data.get("heading"),
        text=None,
        source_locator_kind=locator["kind"],
        source_locator_value=locator["value"],
        content_hash=provision_data["content_hash"],
        recorded_from=provision_data["recorded_from"],
        recorded_to=provision_data["recorded_to"],
        **_provenance_fields(provision_data),
    )

    deadline = obligation_data["deadline"]
    obligation = RegulatoryObligation.objects.create(
        folder=folder,
        record_id=obligation_data["id"],
        title_zh=obligation_data["title_zh"],
        authority_level=obligation_data["authority_level"],
        modality=obligation_data["modality"],
        subject=obligation_data["subject"],
        action=obligation_data["action"],
        object=obligation_data.get("object"),
        conditions=obligation_data["conditions"],
        exceptions=obligation_data.get("exceptions", []),
        deadline_kind=deadline["kind"],
        deadline_value=deadline.get("value"),
        deadline_rule_id=deadline.get("rule_id"),
        expected_evidence=obligation_data.get("expected_evidence", []),
        penalty_or_consequence=obligation_data.get("penalty_or_consequence"),
        valid_from=obligation_data["valid_from"],
        valid_to=obligation_data["valid_to"],
        recorded_from=obligation_data["recorded_from"],
        recorded_to=obligation_data["recorded_to"],
        review_status=obligation_data["review_status"],
        confidence=Decimal(str(obligation_data["confidence"])),
        uncertainties=obligation_data.get("uncertainties", []),
        **_provenance_fields(obligation_data),
    )
    RegulatoryObligationProvision.objects.create(
        folder=folder,
        obligation=obligation,
        provision=provision,
        order=0,
    )

    return RegulatoryChain(
        registration=registration,
        document=document,
        document_version=version,
        provision=provision,
        obligation=obligation,
    )


def _recorded_interval_query(prefix: str, recorded_as_of: datetime) -> Q:
    return Q(**{f"{prefix}recorded_from__lte": recorded_as_of}) & (
        Q(**{f"{prefix}recorded_to__isnull": True})
        | Q(**{f"{prefix}recorded_to__gt": recorded_as_of})
    )


def regulatory_document_recorded_floor(
    *,
    document: RegulatoryDocument,
    folder: Folder,
) -> datetime | None:
    """Return the latest committed recorded timestamp for a locked document."""

    version_floor = RegulatoryDocumentVersion.objects.filter(
        folder=folder,
        document=document,
    ).aggregate(value=Max("recorded_from"))["value"]
    review_floor = RegulatoryObligationReviewEvent.objects.filter(
        folder=folder,
        obligation__folder=folder,
        obligation__provision_links__folder=folder,
        obligation__provision_links__provision__folder=folder,
        obligation__provision_links__provision__document_version__folder=folder,
        obligation__provision_links__provision__document_version__document=document,
    ).aggregate(value=Max("occurred_at"))["value"]
    applicability_floor = RegulatoryApplicabilityDecision.objects.filter(
        folder=folder,
        registration__folder=folder,
        registration__document=document,
        obligation__folder=folder,
    ).aggregate(value=Max("recorded_from"))["value"]
    applicability_review_floor = (
        RegulatoryApplicabilityReviewDisposition.objects.filter(
            folder=folder,
            decision__folder=folder,
            decision__registration__folder=folder,
            decision__registration__document=document,
            decision__obligation__folder=folder,
        ).aggregate(value=Max("occurred_at"))["value"]
    )
    return max(
        (
            value
            for value in (
                version_floor,
                review_floor,
                applicability_floor,
                applicability_review_floor,
            )
            if value is not None
        ),
        default=None,
    )


def lock_current_regulatory_chain(
    *,
    registration: EntityDocumentRegistration,
    folder: Folder,
) -> RegulatoryChain:
    """Lock one current physical chain after its registration and folder are locked."""

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


def select_regulatory_chain_at(
    *,
    document: RegulatoryDocument,
    folder: Folder,
    recorded_as_of: datetime,
    registration: EntityDocumentRegistration | None = None,
) -> RegulatoryChain:
    """Select one coherent revision set while the caller holds the folder lock."""

    if timezone.is_naive(recorded_as_of):
        raise ValidationError(
            {"recorded_as_of": "A timezone-aware datetime is required."}
        )
    if document.folder_id != folder.id:
        raise ValidationError("The regulatory document folder is inconsistent.")
    if registration is not None and (
        registration.folder_id != folder.id or registration.document_id != document.id
    ):
        raise ValidationError("The regulatory registration is inconsistent.")
    try:
        link = (
            RegulatoryObligationProvision.objects.select_related(
                "obligation",
                "provision__document_version",
            )
            .filter(
                folder=folder,
                obligation__folder=folder,
                provision__folder=folder,
                provision__document_version__folder=folder,
                provision__document_version__document=document,
            )
            .filter(
                _recorded_interval_query(
                    "provision__document_version__",
                    recorded_as_of,
                )
            )
            .filter(_recorded_interval_query("provision__", recorded_as_of))
            .filter(_recorded_interval_query("obligation__", recorded_as_of))
            .get()
        )
    except (ObjectDoesNotExist, MultipleObjectsReturned) as exc:
        raise RegulatoryRecordedStateUnavailable(
            {
                "recorded_as_of": (
                    "No complete unique regulatory chain exists at this recorded time."
                )
            }
        ) from exc
    version = link.provision.document_version
    provision = link.provision
    obligation = link.obligation
    active_versions = list(
        RegulatoryDocumentVersion.objects.filter(
            folder=folder,
            document=document,
        )
        .filter(_recorded_interval_query("", recorded_as_of))
        .values_list("pk", flat=True)[:2]
    )
    active_provisions = list(
        RegulatoryProvision.objects.filter(
            folder=folder,
            document_version__folder=folder,
            document_version__document=document,
        )
        .filter(
            _recorded_interval_query("document_version__", recorded_as_of),
            _recorded_interval_query("", recorded_as_of),
        )
        .values_list("pk", flat=True)[:2]
    )
    active_obligations = list(
        RegulatoryObligation.objects.filter(
            folder=folder,
            record_id=obligation.record_id,
        )
        .filter(_recorded_interval_query("", recorded_as_of))
        .values_list("pk", flat=True)[:2]
    )
    if (
        active_versions != [version.pk]
        or active_provisions != [provision.pk]
        or active_obligations != [obligation.pk]
    ):
        raise RegulatoryRecordedStateUnavailable(
            {
                "recorded_as_of": (
                    "The regulatory chain has ambiguous recorded-time cardinality."
                )
            }
        )
    obligation.prefetched_review_events = list(
        obligation.review_events.filter(
            folder=folder,
            occurred_at__lte=recorded_as_of,
        ).order_by("sequence")
    )
    obligation.selected_source_provisions = [provision]
    provision.selected_obligations = [obligation]
    version.selected_provisions = [provision]
    document.selected_versions = [version]
    return RegulatoryChain(
        registration=registration,
        document=document,
        document_version=version,
        provision=provision,
        obligation=obligation,
        recorded_as_of=recorded_as_of,
    )


@transaction.atomic
def get_regulatory_chain(
    *,
    actor: User,
    entity: Entity,
    document_id,
    recorded_as_of: datetime | None = None,
) -> RegulatoryChain:
    """Retrieve one coherent recorded-time chain within entity folder IAM."""

    actor = lock_regulatory_actor(actor=actor)
    if entity.pk is None:
        raise ValidationError({"entity": "A persisted synthetic entity is required."})
    entity = Entity.objects.select_for_update().get(pk=entity.pk)
    folder = Folder.objects.select_for_update().get(pk=entity.folder_id)
    require_regulatory_permission(
        actor=actor,
        codename="view_regulatorydocument",
        folder=folder,
    )
    registration = EntityDocumentRegistration.objects.select_related("document").get(
        entity=entity,
        document_id=document_id,
        folder=folder,
    )
    document = registration.document
    if document.folder_id != folder.id:
        raise ValidationError("The registered document folder is inconsistent.")
    recorded_floor = regulatory_document_recorded_floor(
        document=document,
        folder=folder,
    )
    wall_time = timezone.now()
    request_time = (
        max(wall_time, recorded_floor) if recorded_floor is not None else wall_time
    )
    if recorded_as_of is not None:
        if timezone.is_naive(recorded_as_of):
            raise ValidationError(
                {"recorded_as_of": "A timezone-aware datetime is required."}
            )
        if recorded_as_of > request_time:
            raise ValidationError(
                {"recorded_as_of": "A future recorded-time query is not allowed."}
            )
    return select_regulatory_chain_at(
        document=document,
        folder=folder,
        registration=registration,
        recorded_as_of=recorded_as_of or request_time,
    )
