from copy import deepcopy
from datetime import timedelta
from unittest.mock import patch

import pytest
from django.contrib.auth.models import Permission
from django.core.exceptions import ValidationError
from django.db import IntegrityError, transaction
from rest_framework.exceptions import PermissionDenied

from iam.service_accounts import provision_service_account
from regulatory.models import (
    RegulatoryChainCorrectionEvent,
    RegulatoryDocumentVersion,
    RegulatoryObligation,
    RegulatoryProvision,
)
from regulatory.services import (
    correct_regulatory_chain,
    create_regulatory_chain,
    get_regulatory_chain,
    regulatory_chain_semantic_sha256,
    transition_obligation_review,
)
from regulatory.services.common import IdempotencyConflict

from .factories import (
    chain_payload,
    correction_payload,
    make_folder,
    make_synthetic_entity,
    make_user_with_permissions,
)


@pytest.mark.django_db
def test_correction_appends_audited_successors_and_supports_as_of(regulatory_root):
    folder = make_folder("Correction history")
    entity = make_synthetic_entity(folder, "CORRECTION")
    analyst = make_user_with_permissions(
        folder,
        "ingest_regulatoryrecord",
        "view_regulatorydocument",
        "transition_regulatoryobligation",
        "correct_regulatoryrecord",
        email_prefix="correction-analyst",
    )
    legal_reviewer = make_user_with_permissions(
        folder,
        "legal_review_regulatoryobligation",
        email_prefix="correction-legal",
    )
    initial = create_regulatory_chain(
        actor=analyst,
        entity=entity,
        payload=chain_payload("CORRECTION"),
        idempotency_key="correction-initial",
    )
    initial.obligation.refresh_from_db()
    regressed_time = initial.obligation.recorded_from - timedelta(days=1)
    with patch("regulatory.services.review.timezone.now", return_value=regressed_time):
        analyst_review = transition_obligation_review(
            actor=analyst,
            obligation_id=initial.obligation.id,
            expected_from_status="machine_proposed",
            to_status="analyst_reviewed",
            rationale="Synthetic analyst review before correction",
            idempotency_key="correction-review-analyst",
        )
        legal_review = transition_obligation_review(
            actor=legal_reviewer,
            obligation_id=initial.obligation.id,
            expected_from_status="analyst_reviewed",
            to_status="legal_reviewed",
            rationale="Synthetic legal review before correction",
            idempotency_key="correction-review-legal",
        )
    assert analyst_review.occurred_at > initial.obligation.recorded_from
    assert legal_review.occurred_at > analyst_review.occurred_at
    initial_digest = regulatory_chain_semantic_sha256(initial)
    payload = correction_payload(
        "CORRECTION",
        expected_payload_sha256=initial_digest,
    )

    with patch(
        "regulatory.services.corrections.timezone.now",
        return_value=regressed_time,
    ):
        corrected = correct_regulatory_chain(
            actor=analyst,
            entity=entity,
            document_id=initial.document.id,
            payload=payload,
            rationale="Correct the synthetic obligation wording",
            idempotency_key="correction-1",
        )
    event = corrected.event
    initial.document_version.refresh_from_db()
    initial.provision.refresh_from_db()
    initial.obligation.refresh_from_db()

    assert event.actor_id == analyst.id
    assert event.correction_kind == "recorded_time"
    assert event.digest_schema == "regulatory-chain-correction/v1"
    assert event.occurred_at > legal_review.occurred_at
    assert event.before_payload_sha256 == initial_digest
    assert event.before_payload_sha256 != event.after_payload_sha256
    for predecessor in (
        initial.document_version,
        initial.provision,
        initial.obligation,
    ):
        assert predecessor.recorded_to == event.occurred_at
    for predecessor, successor in (
        (initial.document_version, corrected.chain.document_version),
        (initial.provision, corrected.chain.provision),
        (initial.obligation, corrected.chain.obligation),
    ):
        assert successor.record_id == predecessor.record_id
        assert successor.revision == 2
        assert successor.previous_revision_id == predecessor.id
        assert successor.recorded_from == event.occurred_at
        assert successor.recorded_to is None

    assert initial.obligation.review_events.count() == 2
    assert corrected.chain.obligation.review_events.count() == 0
    assert corrected.chain.obligation.current_review_status == "machine_proposed"
    assert corrected.chain.document_version.legal_review_status == "unreviewed"
    assert corrected.chain.provision.text is None
    assert not corrected.chain.obligation.is_published

    at_initial_recording = get_regulatory_chain(
        actor=analyst,
        entity=entity,
        document_id=initial.document.id,
        recorded_as_of=initial.document_version.recorded_from,
    )
    assert at_initial_recording.document_version.revision == 1
    assert at_initial_recording.obligation.current_review_status == "machine_proposed"
    with pytest.raises(ValidationError, match="No complete unique"):
        get_regulatory_chain(
            actor=analyst,
            entity=entity,
            document_id=initial.document.id,
            recorded_as_of=(
                initial.document_version.recorded_from - timedelta(microseconds=1)
            ),
        )

    immediately_before = get_regulatory_chain(
        actor=analyst,
        entity=entity,
        document_id=initial.document.id,
        recorded_as_of=event.occurred_at - timedelta(microseconds=1),
    )
    assert immediately_before.document_version.revision == 1
    assert immediately_before.obligation.current_review_status == "legal_reviewed"

    with patch(
        "regulatory.services.records.timezone.now",
        return_value=event.occurred_at - timedelta(seconds=1),
    ):
        after_clock_rollback = get_regulatory_chain(
            actor=analyst,
            entity=entity,
            document_id=initial.document.id,
        )
        historical_after_clock_rollback = get_regulatory_chain(
            actor=analyst,
            entity=entity,
            document_id=initial.document.id,
            recorded_as_of=event.occurred_at - timedelta(microseconds=1),
        )
    assert after_clock_rollback.document_version.revision == 2
    assert historical_after_clock_rollback.document_version.revision == 1

    at_cutoff = get_regulatory_chain(
        actor=analyst,
        entity=entity,
        document_id=initial.document.id,
        recorded_as_of=event.occurred_at,
    )
    assert at_cutoff.document_version.revision == 2
    assert at_cutoff.provision.revision == 2
    assert at_cutoff.obligation.revision == 2
    assert at_cutoff.obligation.current_review_status == "machine_proposed"

    current = get_regulatory_chain(
        actor=analyst,
        entity=entity,
        document_id=initial.document.id,
    )
    assert current.obligation.id == corrected.chain.obligation.id

    retry = correct_regulatory_chain(
        actor=analyst,
        entity=entity,
        document_id=initial.document.id,
        payload=deepcopy(payload),
        rationale="Correct the synthetic obligation wording",
        idempotency_key="correction-1",
    )
    assert retry.event.id == event.id
    assert retry.chain.obligation.id == corrected.chain.obligation.id

    conflict = deepcopy(payload)
    conflict["obligation"]["action"] = "Conflicting retry payload"
    with pytest.raises(IdempotencyConflict):
        correct_regulatory_chain(
            actor=analyst,
            entity=entity,
            document_id=initial.document.id,
            payload=conflict,
            rationale="Correct the synthetic obligation wording",
            idempotency_key="correction-1",
        )

    r2_digest = regulatory_chain_semantic_sha256(corrected.chain)
    assert event.after_payload_sha256 == r2_digest
    with pytest.raises(IntegrityError):
        with transaction.atomic():
            RegulatoryChainCorrectionEvent.objects.filter(pk=event.pk).update(
                digest_schema="unsupported-schema"
            )
    event.refresh_from_db()
    assert event.digest_schema == "regulatory-chain-correction/v1"

    second = correct_regulatory_chain(
        actor=analyst,
        entity=entity,
        document_id=initial.document.id,
        payload=correction_payload(
            "CORRECTION",
            expected_revision=2,
            expected_payload_sha256=r2_digest,
        ),
        rationale="Correct the synthetic obligation wording again",
        idempotency_key="correction-2",
    )
    assert second.chain.document_version.revision == 3
    assert second.chain.provision.revision == 3
    assert second.chain.obligation.revision == 3
    assert (
        second.event.previous_document_version_id == corrected.chain.document_version.id
    )
    assert second.event.previous_provision_id == corrected.chain.provision.id
    assert second.event.previous_obligation_id == corrected.chain.obligation.id
    event.full_clean()

    before_second_cutoff = get_regulatory_chain(
        actor=analyst,
        entity=entity,
        document_id=initial.document.id,
        recorded_as_of=second.event.occurred_at - timedelta(microseconds=1),
    )
    assert before_second_cutoff.document_version.revision == 2
    at_second_cutoff = get_regulatory_chain(
        actor=analyst,
        entity=entity,
        document_id=initial.document.id,
        recorded_as_of=second.event.occurred_at,
    )
    assert at_second_cutoff.document_version.revision == 3

    historical_retry = correct_regulatory_chain(
        actor=analyst,
        entity=entity,
        document_id=initial.document.id,
        payload=deepcopy(payload),
        rationale="Correct the synthetic obligation wording",
        idempotency_key="correction-1",
    )
    assert historical_retry.event.id == event.id
    assert historical_retry.chain.document_version.revision == 2
    assert historical_retry.chain.document_version.recorded_to == (
        second.event.occurred_at
    )

    ingestion_retry = create_regulatory_chain(
        actor=analyst,
        entity=entity,
        payload=chain_payload("CORRECTION"),
        idempotency_key="correction-initial",
    )
    assert ingestion_retry.document_version.id == initial.document_version.id
    assert ingestion_retry.provision.id == initial.provision.id
    assert ingestion_retry.obligation.id == initial.obligation.id
    assert RegulatoryChainCorrectionEvent.objects.count() == 2


@pytest.mark.django_db
def test_stale_invalid_and_noop_corrections_roll_back_atomically(regulatory_root):
    folder = make_folder("Correction rollback")
    entity = make_synthetic_entity(folder, "CORRECTION-ROLLBACK")
    actor = make_user_with_permissions(
        folder,
        "ingest_regulatoryrecord",
        "correct_regulatoryrecord",
    )
    initial_payload = chain_payload("CORRECTION-ROLLBACK")
    initial = create_regulatory_chain(
        actor=actor,
        entity=entity,
        payload=initial_payload,
        idempotency_key="correction-rollback-initial",
    )

    initial_digest = regulatory_chain_semantic_sha256(initial)
    stale = correction_payload(
        "CORRECTION-ROLLBACK",
        expected_revision=2,
        expected_payload_sha256=initial_digest,
    )
    with pytest.raises(ValidationError, match="Stale revision"):
        correct_regulatory_chain(
            actor=actor,
            entity=entity,
            document_id=initial.document.id,
            payload=stale,
            rationale="Stale synthetic correction",
            idempotency_key="correction-stale",
        )

    stale_payload = correction_payload(
        "CORRECTION-ROLLBACK",
        expected_payload_sha256="0" * 64,
    )
    with pytest.raises(ValidationError, match="Stale payload"):
        correct_regulatory_chain(
            actor=actor,
            entity=entity,
            document_id=initial.document.id,
            payload=stale_payload,
            rationale="Same revision but stale semantic payload",
            idempotency_key="correction-stale-payload",
        )

    invalid = correction_payload(
        "CORRECTION-ROLLBACK",
        expected_payload_sha256=initial_digest,
    )
    invalid["document_version"]["valid_to"] = "2021-11-01"
    with pytest.raises(ValidationError):
        correct_regulatory_chain(
            actor=actor,
            entity=entity,
            document_id=initial.document.id,
            payload=invalid,
            rationale="Invalid synthetic correction",
            idempotency_key="correction-invalid",
        )

    incomplete = correction_payload(
        "CORRECTION-ROLLBACK",
        expected_payload_sha256=initial_digest,
    )
    incomplete["document_version"].pop("notes")
    with pytest.raises(ValidationError, match="Missing fields"):
        correct_regulatory_chain(
            actor=actor,
            entity=entity,
            document_id=initial.document.id,
            payload=incomplete,
            rationale="Incomplete synthetic correction",
            idempotency_key="correction-incomplete",
        )

    noop = correction_payload(
        "CORRECTION-ROLLBACK",
        expected_payload_sha256=initial_digest,
    )
    noop["obligation"]["action"] = initial_payload["obligation"]["action"]
    noop["obligation"]["uncertainties"] = initial_payload["obligation"]["uncertainties"]
    with pytest.raises(ValidationError, match="must change the chain"):
        correct_regulatory_chain(
            actor=actor,
            entity=entity,
            document_id=initial.document.id,
            payload=noop,
            rationale="No-op synthetic correction",
            idempotency_key="correction-noop",
        )

    for model, pk in (
        (RegulatoryDocumentVersion, initial.document_version.pk),
        (RegulatoryProvision, initial.provision.pk),
        (RegulatoryObligation, initial.obligation.pk),
    ):
        row = model.objects.get(pk=pk)
        assert row.recorded_to is None
        assert model.objects.count() == 1
    assert RegulatoryChainCorrectionEvent.objects.count() == 0

    corrected = correct_regulatory_chain(
        actor=actor,
        entity=entity,
        document_id=initial.document.id,
        payload=correction_payload(
            "CORRECTION-ROLLBACK",
            expected_payload_sha256=initial_digest,
        ),
        rationale="Valid synthetic correction",
        idempotency_key="correction-valid",
    )
    with pytest.raises(ValidationError, match="Stale revision"):
        correct_regulatory_chain(
            actor=actor,
            entity=entity,
            document_id=initial.document.id,
            payload=correction_payload(
                "CORRECTION-ROLLBACK",
                expected_payload_sha256=initial_digest,
            ),
            rationale="Late stale synthetic correction",
            idempotency_key="correction-late-stale",
        )
    assert corrected.chain.obligation.revision == 2
    assert RegulatoryChainCorrectionEvent.objects.count() == 1
    assert RegulatoryObligation.objects.filter(recorded_to__isnull=True).count() == 1


@pytest.mark.django_db
def test_correction_requires_folder_authority_active_human(regulatory_root):
    folder = make_folder("Correction authority")
    sibling = make_folder("Correction sibling")
    entity = make_synthetic_entity(folder, "CORRECTION-AUTH")
    ingester = make_user_with_permissions(folder, "ingest_regulatoryrecord")
    initial = create_regulatory_chain(
        actor=ingester,
        entity=entity,
        payload=chain_payload("CORRECTION-AUTH"),
        idempotency_key="correction-authority-initial",
    )
    payload = correction_payload(
        "CORRECTION-AUTH",
        expected_payload_sha256=regulatory_chain_semantic_sha256(initial),
    )

    outsider = make_user_with_permissions(sibling, "correct_regulatoryrecord")
    with pytest.raises(PermissionDenied):
        correct_regulatory_chain(
            actor=outsider,
            entity=entity,
            document_id=initial.document.id,
            payload=payload,
            rationale="Cross-folder attempt",
            idempotency_key="correction-cross-folder",
        )

    revoked = make_user_with_permissions(folder, "correct_regulatoryrecord")
    revoked.__class__.objects.filter(pk=revoked.pk).update(is_active=False)
    with pytest.raises(PermissionDenied, match="active actor"):
        correct_regulatory_chain(
            actor=revoked,
            entity=entity,
            document_id=initial.document.id,
            payload=payload,
            rationale="Revoked actor attempt",
            idempotency_key="correction-revoked",
        )

    permission = Permission.objects.get(
        content_type__app_label="regulatory",
        codename="correct_regulatoryrecord",
    )
    service_account, _ = provision_service_account(
        name="regulatory-correction-test",
        description="Synthetic correction service account",
        permission_ids=[permission.id],
        folder_ids=[folder.id],
        is_recursive=False,
        created_by=ingester,
    )
    with pytest.raises(ValidationError, match="named human"):
        correct_regulatory_chain(
            actor=service_account.user,
            entity=entity,
            document_id=initial.document.id,
            payload=payload,
            rationale="Service identity correction attempt",
            idempotency_key="correction-service-account",
        )
    assert RegulatoryChainCorrectionEvent.objects.count() == 0
    assert RegulatoryObligation.objects.count() == 1
