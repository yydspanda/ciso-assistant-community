from copy import deepcopy

import pytest
from django.core.exceptions import ValidationError
from django.db import IntegrityError, transaction
from rest_framework.exceptions import PermissionDenied

from regulatory.models import (
    EntityDocumentRegistration,
    RegulatoryDocument,
    RegulatoryDocumentVersion,
    RegulatoryObligation,
    RegulatoryProvision,
)
from regulatory.services import create_regulatory_chain, get_regulatory_chain
from regulatory.services.common import IdempotencyConflict
from tprm.models import Entity

from .factories import (
    chain_payload,
    make_folder,
    make_synthetic_entity,
    make_user_with_permissions,
)


@pytest.mark.django_db
def test_synthetic_entity_persists_and_retrieves_exact_chain(regulatory_root):
    folder = make_folder()
    entity = make_synthetic_entity(folder, "PERSIST")
    actor = make_user_with_permissions(
        folder,
        "ingest_regulatoryrecord",
        "view_regulatorydocument",
    )
    payload = chain_payload("PERSIST")

    created = create_regulatory_chain(
        actor=actor,
        entity=entity,
        payload=payload,
        idempotency_key="ingest-persist-1",
    )
    retrieved = get_regulatory_chain(
        actor=actor,
        entity=entity,
        document_id=created.document.id,
    )

    assert retrieved.document.record_id == payload["document"]["id"]
    assert retrieved.registration.ingested_by_id == actor.id
    assert retrieved.document_version.record_id == payload["document_version"]["id"]
    assert (
        retrieved.document_version.source_url
        == payload["document_version"]["source_url"]
    )
    assert retrieved.document_version.source_hash == "1" * 64
    assert retrieved.document_version.valid_from.isoformat() == "2021-11-01"
    assert retrieved.document_version.recorded_from.isoformat().startswith(
        "2026-08-20T16:00:00"
    )
    assert retrieved.provision.record_id == payload["provision"]["id"]
    assert retrieved.provision.text is None
    assert retrieved.obligation.record_id == payload["obligation"]["id"]
    assert retrieved.obligation.current_review_status == "machine_proposed"
    assert not retrieved.document.is_published
    assert not retrieved.document_version.is_published
    assert not retrieved.provision.is_published
    assert not retrieved.obligation.is_published

    entity.folder = make_folder("Spoofed read folder")
    db_anchored = get_regulatory_chain(
        actor=actor,
        entity=entity,
        document_id=created.document.id,
    )
    assert db_anchored.document.id == created.document.id

    actor.__class__.objects.filter(pk=actor.pk).update(is_active=False)
    with pytest.raises(PermissionDenied, match="active actor"):
        get_regulatory_chain(
            actor=actor,
            entity=entity,
            document_id=created.document.id,
        )


@pytest.mark.django_db
def test_chain_ingestion_is_atomic_and_idempotent(regulatory_root):
    folder = make_folder()
    entity = make_synthetic_entity(folder, "IDEMPOTENT")
    actor = make_user_with_permissions(folder, "ingest_regulatoryrecord")
    payload = chain_payload("IDEMPOTENT")

    first = create_regulatory_chain(
        actor=actor,
        entity=entity,
        payload=payload,
        idempotency_key="same-key",
    )
    second = create_regulatory_chain(
        actor=actor,
        entity=entity,
        payload=deepcopy(payload),
        idempotency_key="same-key",
    )
    assert second.document.id == first.document.id
    assert RegulatoryDocument.objects.count() == 1
    assert RegulatoryDocumentVersion.objects.count() == 1
    assert RegulatoryProvision.objects.count() == 1
    assert RegulatoryObligation.objects.count() == 1
    assert EntityDocumentRegistration.objects.count() == 1

    changed = deepcopy(payload)
    changed["obligation"]["action"] = "A different authoritative payload"
    with pytest.raises(IdempotencyConflict):
        create_regulatory_chain(
            actor=actor,
            entity=entity,
            payload=changed,
            idempotency_key="same-key",
        )
    assert RegulatoryDocument.objects.count() == 1


@pytest.mark.django_db
def test_invalid_temporal_or_source_input_rolls_back_entire_chain(regulatory_root):
    folder = make_folder()
    entity = make_synthetic_entity(folder, "ROLLBACK")
    actor = make_user_with_permissions(folder, "ingest_regulatoryrecord")
    payload = chain_payload("ROLLBACK")
    payload["document_version"]["valid_to"] = "2021-11-01"

    with pytest.raises(ValidationError):
        create_regulatory_chain(
            actor=actor,
            entity=entity,
            payload=payload,
            idempotency_key="invalid-interval",
        )
    assert RegulatoryDocument.objects.count() == 0
    assert RegulatoryDocumentVersion.objects.count() == 0

    payload = chain_payload("TEXT")
    payload["provision"]["text"] = "Unlicensed source text"
    with pytest.raises(ValidationError):
        create_regulatory_chain(
            actor=actor,
            entity=entity,
            payload=payload,
            idempotency_key="invalid-text",
        )
    assert RegulatoryDocument.objects.count() == 0

    payload = chain_payload("CLOSED")
    payload["obligation"]["recorded_to"] = "2026-08-22T00:00:00+08:00"
    with pytest.raises(ValidationError, match="current recorded revisions"):
        create_regulatory_chain(
            actor=actor,
            entity=entity,
            payload=payload,
            idempotency_key="invalid-closed-record",
        )
    assert RegulatoryDocument.objects.count() == 0

    payload = chain_payload("STAGE")
    payload["document"]["coverage_stage"] = "obligations_reviewed"
    with pytest.raises(ValidationError, match="proposed obligation"):
        create_regulatory_chain(
            actor=actor,
            entity=entity,
            payload=payload,
            idempotency_key="invalid-stage",
        )
    assert RegulatoryDocument.objects.count() == 0


@pytest.mark.django_db
def test_cross_folder_and_unauthorised_access_fail_closed(regulatory_root):
    folder_a = make_folder("Regulatory A")
    folder_b = make_folder("Regulatory B")
    entity_a = make_synthetic_entity(folder_a, "A")
    actor_a = make_user_with_permissions(
        folder_a,
        "ingest_regulatoryrecord",
        "view_regulatorydocument",
    )
    outsider = make_user_with_permissions(folder_b, "view_regulatorydocument")
    chain = create_regulatory_chain(
        actor=actor_a,
        entity=entity_a,
        payload=chain_payload("FOLDER-A"),
        idempotency_key="folder-a",
    )

    with pytest.raises(PermissionDenied):
        get_regulatory_chain(
            actor=outsider,
            entity=entity_a,
            document_id=chain.document.id,
        )

    chain.document_version.folder = folder_b
    chain.document_version._state.adding = True
    chain.document_version.pk = None
    chain.document_version.record_id = "TEST-CROSS-FOLDER-v2"
    with pytest.raises(ValidationError):
        chain.document_version.save()


@pytest.mark.django_db
def test_ingestion_reloads_entity_authority_fields_from_database(regulatory_root):
    real_folder = make_folder("Real entity folder")
    spoofed_folder = make_folder("Spoofed entity folder")
    entity = Entity.objects.create(
        name="Non-synthetic entity",
        ref_id="REAL-CN-BANK-001",
        folder=real_folder,
        country="CN",
    )
    actor = make_user_with_permissions(
        spoofed_folder,
        "ingest_regulatoryrecord",
    )

    entity.ref_id = "SYNTHETIC-CN-BANK-SPOOFED"
    entity.folder = spoofed_folder
    with pytest.raises(ValidationError, match="SYNTHETIC"):
        create_regulatory_chain(
            actor=actor,
            entity=entity,
            payload=chain_payload("ENTITY-SPOOF"),
            idempotency_key="entity-spoof",
        )
    assert RegulatoryDocument.objects.count() == 0


@pytest.mark.django_db
def test_ingestion_reloads_actor_revocation_from_database(regulatory_root):
    folder = make_folder("Revoked ingestion folder")
    entity = make_synthetic_entity(folder, "REVOKED-INGESTER")
    stale_actor = make_user_with_permissions(folder, "ingest_regulatoryrecord")
    stale_actor.__class__.objects.filter(pk=stale_actor.pk).update(is_active=False)

    with pytest.raises(PermissionDenied, match="active actor"):
        create_regulatory_chain(
            actor=stale_actor,
            entity=entity,
            payload=chain_payload("REVOKED-INGESTER"),
            idempotency_key="revoked-ingester",
        )
    assert RegulatoryDocument.objects.count() == 0


@pytest.mark.django_db
def test_regulatory_payload_rows_cannot_be_updated_or_deleted(regulatory_root):
    folder = make_folder()
    entity = make_synthetic_entity(folder, "IMMUTABLE")
    actor = make_user_with_permissions(folder, "ingest_regulatoryrecord")
    chain = create_regulatory_chain(
        actor=actor,
        entity=entity,
        payload=chain_payload("IMMUTABLE"),
        idempotency_key="immutable",
    )

    chain.document.title_zh = "Mutated title"
    with pytest.raises(ValidationError, match="append-only"):
        chain.document.save()
    with pytest.raises(ValidationError, match="cannot be deleted"):
        chain.document.delete()

    with pytest.raises(IntegrityError), transaction.atomic():
        RegulatoryDocumentVersion.objects.filter(pk=chain.document_version.pk).update(
            legal_review_status="reviewed",
            legal_reviewed_at=chain.document_version.recorded_from,
            legal_reviewed_by="bypass-attempt",
        )
    with pytest.raises(IntegrityError), transaction.atomic():
        RegulatoryObligation.objects.filter(pk=chain.obligation.pk).update(
            review_status="approved"
        )
    with pytest.raises(IntegrityError), transaction.atomic():
        RegulatoryDocumentVersion.objects.filter(pk=chain.document_version.pk).update(
            content_storage_policy="official_snapshot"
        )
    with pytest.raises(IntegrityError), transaction.atomic():
        RegulatoryProvision.objects.filter(pk=chain.provision.pk).update(
            text="Unlicensed bulk-write attempt"
        )
