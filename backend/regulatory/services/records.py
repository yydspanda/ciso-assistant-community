from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal

from django.core.exceptions import ValidationError
from django.db import transaction

from iam.models import Folder, User
from tprm.models import Entity

from regulatory.contracts import RegulatoryChainPayload
from regulatory.models import (
    EntityDocumentRegistration,
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


@dataclass(frozen=True)
class RegulatoryChain:
    registration: EntityDocumentRegistration
    document: RegulatoryDocument
    document_version: RegulatoryDocumentVersion
    provision: RegulatoryProvision
    obligation: RegulatoryObligation


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
        recorded_to__isnull=True,
    )
    provision = RegulatoryProvision.objects.get(
        document_version=version,
        folder=registration.folder,
        record_id=payload["provision"]["id"],
        recorded_to__isnull=True,
    )
    obligation = RegulatoryObligation.objects.get(
        provision_links__provision=provision,
        folder=registration.folder,
        record_id=payload["obligation"]["id"],
        recorded_to__isnull=True,
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
    _validate_first_slice_contract(payload)

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


@transaction.atomic
def get_regulatory_chain(
    *,
    actor: User,
    entity: Entity,
    document_id,
) -> RegulatoryChain:
    """Retrieve the current one-document pilot chain within entity folder IAM."""

    actor = lock_regulatory_actor(actor=actor)
    if entity.pk is None:
        raise ValidationError({"entity": "A persisted synthetic entity is required."})
    entity = Entity.objects.select_related("folder").get(pk=entity.pk)
    folder = entity.folder
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
    version = document.versions.get(
        folder=folder,
        recorded_to__isnull=True,
    )
    provision = version.provisions.get(
        folder=folder,
        recorded_to__isnull=True,
    )
    obligation = provision.obligations.get(
        folder=folder,
        recorded_to__isnull=True,
    )
    return RegulatoryChain(
        registration=registration,
        document=document,
        document_version=version,
        provision=provision,
        obligation=obligation,
    )
