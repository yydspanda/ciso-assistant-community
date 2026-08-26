from copy import deepcopy
from datetime import timedelta
from unittest.mock import patch
import uuid

import pytest
from django.contrib.auth.models import Permission
from django.core.exceptions import ValidationError
from django.db import IntegrityError, transaction
from rest_framework.exceptions import PermissionDenied

from iam.models import RoleAssignment
from iam.service_accounts import provision_service_account
from regulatory.models import (
    EntityDocumentRegistration,
    RegulatoryApplicabilityReviewDisposition,
)
from regulatory.services import (
    correct_regulatory_chain,
    create_regulatory_chain,
    get_regulatory_applicability_review,
    record_regulatory_applicability_decision,
    record_regulatory_applicability_review_disposition,
    regulatory_applicability_review_event_sha256,
    regulatory_applicability_semantic_sha256,
    regulatory_chain_semantic_sha256,
)
from regulatory.services.applicability_review import (
    RegulatoryApplicabilityReviewStateUnavailable,
    _validate_persisted_disposition,
)
from regulatory.services.common import IdempotencyConflict, canonical_payload_sha256

from .factories import (
    applicability_payload,
    applicability_review_payload,
    chain_payload,
    correction_payload,
    known_institution_type_observation,
    make_folder,
    make_synthetic_entity,
    make_user_with_permissions,
)

REVIEW_VIEW_PERMISSION = "view_regulatoryapplicabilityreviewdisposition"
REVIEW_PERMISSION = "review_regulatoryapplicability"


def _make_review_chain(suffix: str):
    folder = make_folder(f"Applicability review {suffix}")
    entity = make_synthetic_entity(folder, suffix)
    recorder = make_user_with_permissions(
        folder,
        "ingest_regulatoryrecord",
        "view_regulatorydocument",
        "view_regulatoryapplicabilitydecision",
        REVIEW_VIEW_PERMISSION,
        "record_regulatoryapplicability",
        REVIEW_PERMISSION,
        "view_entity",
        email_prefix="applicability-review-recorder",
    )
    reviewer = make_user_with_permissions(
        folder,
        "view_regulatorydocument",
        "view_regulatoryapplicabilitydecision",
        REVIEW_VIEW_PERMISSION,
        REVIEW_PERMISSION,
        "view_entity",
        email_prefix="applicability-review-checker",
    )
    chain = create_regulatory_chain(
        actor=recorder,
        entity=entity,
        payload=chain_payload(suffix),
        idempotency_key=f"applicability-review-chain-{suffix}",
    )
    decision = record_regulatory_applicability_decision(
        actor=recorder,
        entity=entity,
        document_id=chain.document.id,
        payload=applicability_payload(suffix, chain=chain),
        idempotency_key=f"applicability-review-decision-{suffix}",
    ).decision
    return folder, entity, recorder, reviewer, chain, decision


def _record_review(
    *,
    actor,
    entity,
    chain,
    decision,
    suffix: str,
    expected_disposition=None,
    to_disposition="no_correction_requested",
    reason_code=None,
    rationale=None,
    idempotency_key=None,
):
    return record_regulatory_applicability_review_disposition(
        actor=actor,
        entity=entity,
        document_id=chain.document.id,
        payload=applicability_review_payload(
            suffix,
            decision=decision,
            expected_disposition=expected_disposition,
            to_disposition=to_disposition,
            reason_code=reason_code,
            rationale=rationale,
        ),
        idempotency_key=idempotency_key or f"applicability-review-{suffix}",
    )


@pytest.mark.django_db
@pytest.mark.parametrize(
    ("to_disposition", "expected_attention"),
    (
        ("no_correction_requested", "reviewed_nonbinding"),
        ("correction_requested", "needs_review"),
        ("unable_to_complete", "needs_review"),
    ),
)
def test_root_review_dispositions_are_exact_digest_bound_and_derived(
    regulatory_root,
    to_disposition,
    expected_attention,
):
    _, entity, recorder, reviewer, chain, decision = _make_review_chain(
        to_disposition.upper()
    )

    result = _record_review(
        actor=reviewer,
        entity=entity,
        chain=chain,
        decision=decision,
        suffix=to_disposition.upper(),
        to_disposition=to_disposition,
    )
    event = result.disposition

    assert result.decision == decision
    assert event.sequence == 1
    assert event.previous_disposition is None
    assert event.from_disposition == "not_reviewed"
    assert event.to_disposition == to_disposition
    assert event.reviewer == reviewer
    assert event.decision_recorded_by == recorder
    assert event.decision_semantic_payload_sha256 == decision.semantic_payload_sha256
    assert event.is_binding is False
    assert event.is_published is False
    assert event.event_payload_sha256 == regulatory_applicability_review_event_sha256(
        event
    )
    assert event.request_sha256 == canonical_payload_sha256(
        event.review_disposition_request_payload()
    )

    selected = get_regulatory_applicability_review(
        actor=reviewer,
        entity=entity,
        document_id=chain.document.id,
    )
    assert selected.applicability.decision == decision
    assert selected.disposition == event
    assert selected.review_state == to_disposition
    assert selected.workflow_attention == expected_attention
    assert selected.reviewer.masked is False
    assert selected.reviewer.id == str(reviewer.id)


@pytest.mark.django_db
def test_review_read_fails_closed_without_decision_or_with_unknown_facts(
    regulatory_root,
):
    folder = make_folder("Applicability review not reviewable")
    entity = make_synthetic_entity(folder, "NOT-REVIEWABLE")
    actor = make_user_with_permissions(
        folder,
        "ingest_regulatoryrecord",
        "view_regulatorydocument",
        "view_regulatoryapplicabilitydecision",
        REVIEW_VIEW_PERMISSION,
        "record_regulatoryapplicability",
        REVIEW_PERMISSION,
        "view_entity",
        email_prefix="applicability-review-not-reviewable",
    )
    chain = create_regulatory_chain(
        actor=actor,
        entity=entity,
        payload=chain_payload("NOT-REVIEWABLE"),
        idempotency_key="applicability-review-chain-not-reviewable",
    )

    without_decision = get_regulatory_applicability_review(
        actor=actor,
        entity=entity,
        document_id=chain.document.id,
    )
    assert without_decision.applicability.decision is None
    assert without_decision.review_state == "not_reviewable"
    assert without_decision.workflow_attention == "needs_review"

    decision = record_regulatory_applicability_decision(
        actor=actor,
        entity=entity,
        document_id=chain.document.id,
        payload=applicability_payload(
            "NOT-REVIEWABLE",
            chain=chain,
            observations=[],
        ),
        idempotency_key="applicability-review-needs-review-decision",
    ).decision
    reviewer = make_user_with_permissions(
        folder,
        "view_regulatorydocument",
        "view_regulatoryapplicabilitydecision",
        REVIEW_VIEW_PERMISSION,
        REVIEW_PERMISSION,
        "view_entity",
        email_prefix="applicability-review-unknown-checker",
    )
    _record_review(
        actor=reviewer,
        entity=entity,
        chain=chain,
        decision=decision,
        suffix="NEEDS-REVIEW",
    )
    reviewed_unknown = get_regulatory_applicability_review(
        actor=reviewer,
        entity=entity,
        document_id=chain.document.id,
    )
    assert reviewed_unknown.applicability.decision.result == "needs_review"
    assert reviewed_unknown.review_state == "no_correction_requested"
    assert reviewed_unknown.workflow_attention == "needs_review"


@pytest.mark.django_db
def test_review_successors_require_exact_head_and_material_change(regulatory_root):
    folder, entity, _, reviewer, chain, decision = _make_review_chain("SUCCESSOR")
    first = _record_review(
        actor=reviewer,
        entity=entity,
        chain=chain,
        decision=decision,
        suffix="SUCCESSOR-1",
        to_disposition="correction_requested",
    ).disposition

    exact_retry = _record_review(
        actor=reviewer,
        entity=entity,
        chain=chain,
        decision=decision,
        suffix="SUCCESSOR-1",
        to_disposition="correction_requested",
        idempotency_key="applicability-review-SUCCESSOR-1",
    )
    assert exact_retry.disposition == first

    conflicting_retry_payload = applicability_review_payload(
        "SUCCESSOR-CONFLICT",
        decision=decision,
        to_disposition="unable_to_complete",
    )
    with pytest.raises(IdempotencyConflict):
        record_regulatory_applicability_review_disposition(
            actor=reviewer,
            entity=entity,
            document_id=chain.document.id,
            payload=conflicting_retry_payload,
            idempotency_key="applicability-review-SUCCESSOR-1",
        )

    another_reviewer = make_user_with_permissions(
        folder,
        "view_regulatorydocument",
        "view_regulatoryapplicabilitydecision",
        REVIEW_VIEW_PERMISSION,
        REVIEW_PERMISSION,
        "view_entity",
        email_prefix="applicability-review-replay-checker",
    )
    with pytest.raises(IdempotencyConflict):
        record_regulatory_applicability_review_disposition(
            actor=another_reviewer,
            entity=entity,
            document_id=chain.document.id,
            payload=applicability_review_payload(
                "SUCCESSOR-1",
                decision=decision,
                to_disposition="correction_requested",
            ),
            idempotency_key="applicability-review-SUCCESSOR-1",
        )

    stale_payload = applicability_review_payload(
        "SUCCESSOR-STALE",
        decision=decision,
        to_disposition="unable_to_complete",
    )
    with pytest.raises(ValidationError, match="stale"):
        record_regulatory_applicability_review_disposition(
            actor=reviewer,
            entity=entity,
            document_id=chain.document.id,
            payload=stale_payload,
            idempotency_key="applicability-review-successor-stale",
        )

    noop_payload = applicability_review_payload(
        "ignored",
        decision=decision,
        expected_disposition=first,
        to_disposition="correction_requested",
        rationale=first.rationale,
    )
    with pytest.raises(ValidationError, match="no-op"):
        record_regulatory_applicability_review_disposition(
            actor=reviewer,
            entity=entity,
            document_id=chain.document.id,
            payload=noop_payload,
            idempotency_key="applicability-review-successor-noop",
        )

    second = _record_review(
        actor=reviewer,
        entity=entity,
        chain=chain,
        decision=decision,
        suffix="SUCCESSOR-2",
        expected_disposition=first,
        to_disposition="correction_requested",
        rationale="Materially refined correction rationale",
    ).disposition
    third = _record_review(
        actor=reviewer,
        entity=entity,
        chain=chain,
        decision=decision,
        suffix="SUCCESSOR-3",
        expected_disposition=second,
        to_disposition="no_correction_requested",
        rationale="Withdraw the earlier correction request after checking the record",
    ).disposition

    assert second.sequence == 2
    assert second.previous_disposition == first
    assert second.from_disposition == "correction_requested"
    assert second.occurred_at > first.occurred_at
    assert third.sequence == 3
    assert third.previous_disposition == second
    assert third.from_disposition == "correction_requested"
    assert third.to_disposition == "no_correction_requested"

    retry_after_later_dispositions = _record_review(
        actor=reviewer,
        entity=entity,
        chain=chain,
        decision=decision,
        suffix="SUCCESSOR-1",
        to_disposition="correction_requested",
        idempotency_key="applicability-review-SUCCESSOR-1",
    )
    assert retry_after_later_dispositions.disposition == first


@pytest.mark.django_db
def test_review_contract_is_strict_and_atomic(regulatory_root):
    _, entity, _, reviewer, chain, decision = _make_review_chain("STRICT")
    base = applicability_review_payload("STRICT", decision=decision)
    invalid_payloads = []

    extra = deepcopy(base)
    extra["occurred_at"] = "2026-08-24T00:00:00Z"
    invalid_payloads.append(extra)
    partial_head = deepcopy(base)
    partial_head["expected_current_disposition"]["sequence"] = 1
    invalid_payloads.append(partial_head)
    wrong_reason = deepcopy(base)
    wrong_reason["reason_code"] = "insufficient_evidence"
    invalid_payloads.append(wrong_reason)
    blank_rationale = deepcopy(base)
    blank_rationale["rationale"] = "   "
    invalid_payloads.append(blank_rationale)
    caller_actor = deepcopy(base)
    caller_actor["reviewer_id"] = str(reviewer.id)
    invalid_payloads.append(caller_actor)
    too_long = deepcopy(base)
    too_long["rationale"] = "x" * 4001
    invalid_payloads.append(too_long)
    for malformed_decision in ([], {}, 7, "not-an-object"):
        decision_container = deepcopy(base)
        decision_container["expected_decision"] = malformed_decision
        invalid_payloads.append(decision_container)
    for malformed_head in ([], {}, 7, "not-an-object"):
        head_container = deepcopy(base)
        head_container["expected_current_disposition"] = malformed_head
        invalid_payloads.append(head_container)
    for malformed_rationale in ([], {}, 7, None):
        rationale_container = deepcopy(base)
        rationale_container["rationale"] = malformed_rationale
        invalid_payloads.append(rationale_container)
    for malformed_target in ([], {}, 7, None):
        target_container = deepcopy(base)
        target_container["to_disposition"] = malformed_target
        invalid_payloads.append(target_container)
    for malformed_reason in ([], {}, 7, None):
        reason_container = deepcopy(base)
        reason_container["reason_code"] = malformed_reason
        invalid_payloads.append(reason_container)
    for malformed_head_disposition in ([], {}, 7, None):
        head_disposition_container = deepcopy(base)
        head_disposition_container["expected_current_disposition"] = {
            "physical_id": str(uuid.uuid4()),
            "sequence": 1,
            "disposition": malformed_head_disposition,
            "event_payload_sha256": "a" * 64,
        }
        invalid_payloads.append(head_disposition_container)

    for index, invalid_payload in enumerate(invalid_payloads):
        with pytest.raises(ValidationError):
            record_regulatory_applicability_review_disposition(
                actor=reviewer,
                entity=entity,
                document_id=chain.document.id,
                payload=invalid_payload,
                idempotency_key=f"applicability-review-strict-{index}",
            )
        assert RegulatoryApplicabilityReviewDisposition.objects.count() == 0

    for malformed_key in ([], {}, 7, None):
        with pytest.raises(ValidationError) as exc_info:
            record_regulatory_applicability_review_disposition(
                actor=reviewer,
                entity=entity,
                document_id=chain.document.id,
                payload=base,
                idempotency_key=malformed_key,
            )
        assert "idempotency_key" in exc_info.value.message_dict

    for index, malformed_payload in enumerate(([], 7, None, "not-an-object")):
        with pytest.raises(ValidationError):
            record_regulatory_applicability_review_disposition(
                actor=reviewer,
                entity=entity,
                document_id=chain.document.id,
                payload=malformed_payload,
                idempotency_key=f"applicability-review-malformed-payload-{index}",
            )

    with patch.object(
        RegulatoryApplicabilityReviewDisposition,
        "save",
        side_effect=IntegrityError("forced late review-event write failure"),
    ):
        with pytest.raises(IntegrityError, match="forced late"):
            record_regulatory_applicability_review_disposition(
                actor=reviewer,
                entity=entity,
                document_id=chain.document.id,
                payload=base,
                idempotency_key="applicability-review-forced-late-rollback",
            )
    assert RegulatoryApplicabilityReviewDisposition.objects.count() == 0


@pytest.mark.django_db
def test_review_rejects_stale_decision_identity_and_digest(regulatory_root):
    _, entity, _, reviewer, chain, decision = _make_review_chain("DECISION-CAS")
    stale_payloads = []
    wrong_identity = applicability_review_payload("WRONG-ID", decision=decision)
    wrong_identity["expected_decision"]["physical_id"] = str(uuid.uuid4())
    stale_payloads.append(wrong_identity)
    wrong_digest = applicability_review_payload("WRONG-DIGEST", decision=decision)
    wrong_digest["expected_decision"]["semantic_payload_sha256"] = "f" * 64
    stale_payloads.append(wrong_digest)

    for index, payload in enumerate(stale_payloads):
        with pytest.raises(ValidationError, match="stale"):
            record_regulatory_applicability_review_disposition(
                actor=reviewer,
                entity=entity,
                document_id=chain.document.id,
                payload=payload,
                idempotency_key=f"applicability-review-decision-cas-{index}",
            )
    assert RegulatoryApplicabilityReviewDisposition.objects.count() == 0


@pytest.mark.django_db
def test_review_maker_checker_service_identity_and_permission_boundaries(
    regulatory_root,
):
    folder, entity, recorder, reviewer, chain, decision = _make_review_chain("IAM")
    payload = applicability_review_payload("IAM", decision=decision)

    with pytest.raises(ValidationError, match="recorder"):
        record_regulatory_applicability_review_disposition(
            actor=recorder,
            entity=entity,
            document_id=chain.document.id,
            payload=payload,
            idempotency_key="applicability-review-self",
        )

    missing_review_permission = make_user_with_permissions(
        folder,
        "view_regulatorydocument",
        "view_regulatoryapplicabilitydecision",
        REVIEW_VIEW_PERMISSION,
        "view_entity",
        email_prefix="applicability-review-no-transition",
    )
    with pytest.raises(PermissionDenied):
        record_regulatory_applicability_review_disposition(
            actor=missing_review_permission,
            entity=entity,
            document_id=chain.document.id,
            payload=payload,
            idempotency_key="applicability-review-no-permission",
        )

    permission_codenames = (
        "view_regulatorydocument",
        "view_regulatoryapplicabilitydecision",
        REVIEW_VIEW_PERMISSION,
        REVIEW_PERMISSION,
    )
    permissions = list(
        Permission.objects.filter(
            content_type__app_label="regulatory",
            codename__in=permission_codenames,
        ).values_list("id", flat=True)
    )
    permissions.append(
        Permission.objects.get(
            content_type__app_label="tprm",
            codename="view_entity",
        ).id
    )
    service_account, _ = provision_service_account(
        name="regulatory-applicability-review-test",
        description="Synthetic applicability review service account",
        permission_ids=permissions,
        folder_ids=[folder.id],
        is_recursive=False,
        created_by=reviewer,
    )
    with pytest.raises(ValidationError, match="named human"):
        record_regulatory_applicability_review_disposition(
            actor=service_account.user,
            entity=entity,
            document_id=chain.document.id,
            payload=payload,
            idempotency_key="applicability-review-service-account",
        )
    assert RegulatoryApplicabilityReviewDisposition.objects.count() == 0


@pytest.mark.django_db
def test_review_rechecks_active_role_and_immutable_folder_scope(regulatory_root):
    folder, entity, _, reviewer, chain, decision = _make_review_chain("IAM-STATE")
    payload = applicability_review_payload("IAM-STATE", decision=decision)

    reviewer.__class__.objects.filter(pk=reviewer.pk).update(is_active=False)
    with pytest.raises(PermissionDenied, match="active"):
        record_regulatory_applicability_review_disposition(
            actor=reviewer,
            entity=entity,
            document_id=chain.document.id,
            payload=payload,
            idempotency_key="applicability-review-inactive-reviewer",
        )

    revoked_reviewer = make_user_with_permissions(
        folder,
        "view_regulatorydocument",
        "view_regulatoryapplicabilitydecision",
        REVIEW_VIEW_PERMISSION,
        REVIEW_PERMISSION,
        "view_entity",
        email_prefix="applicability-review-revoked-checker",
    )
    RoleAssignment.objects.filter(user=revoked_reviewer).delete()
    with pytest.raises(PermissionDenied):
        record_regulatory_applicability_review_disposition(
            actor=revoked_reviewer,
            entity=entity,
            document_id=chain.document.id,
            payload=payload,
            idempotency_key="applicability-review-revoked-reviewer",
        )

    sibling_folder = make_folder("Applicability review sibling scope")
    sibling_reviewer = make_user_with_permissions(
        sibling_folder,
        "view_regulatorydocument",
        "view_regulatoryapplicabilitydecision",
        REVIEW_VIEW_PERMISSION,
        REVIEW_PERMISSION,
        "view_entity",
        email_prefix="applicability-review-sibling-checker",
    )
    with pytest.raises(PermissionDenied):
        record_regulatory_applicability_review_disposition(
            actor=sibling_reviewer,
            entity=entity,
            document_id=chain.document.id,
            payload=payload,
            idempotency_key="applicability-review-sibling-reviewer",
        )

    live_reviewer = make_user_with_permissions(
        folder,
        "view_regulatorydocument",
        "view_regulatoryapplicabilitydecision",
        REVIEW_VIEW_PERMISSION,
        REVIEW_PERMISSION,
        "view_entity",
        email_prefix="applicability-review-live-scope-checker",
    )
    entity.__class__.objects.filter(pk=entity.pk).update(ref_id="REAL-SCOPE-REMOVED")
    with pytest.raises(ValidationError, match="SYNTHETIC"):
        record_regulatory_applicability_review_disposition(
            actor=live_reviewer,
            entity=entity,
            document_id=chain.document.id,
            payload=payload,
            idempotency_key="applicability-review-lost-synthetic-scope",
        )
    assert RegulatoryApplicabilityReviewDisposition.objects.count() == 0


@pytest.mark.django_db
def test_review_clock_rollback_preserves_strict_event_order(regulatory_root):
    _, entity, _, reviewer, chain, decision = _make_review_chain("CLOCK")
    with patch(
        "regulatory.services.applicability_review.timezone.now",
        return_value=decision.recorded_from - timedelta(days=1),
    ):
        first = _record_review(
            actor=reviewer,
            entity=entity,
            chain=chain,
            decision=decision,
            suffix="CLOCK-1",
            to_disposition="correction_requested",
        ).disposition
    assert first.occurred_at > decision.recorded_from

    with patch(
        "regulatory.services.applicability_review.timezone.now",
        return_value=first.occurred_at - timedelta(days=1),
    ):
        second = _record_review(
            actor=reviewer,
            entity=entity,
            chain=chain,
            decision=decision,
            suffix="CLOCK-2",
            expected_disposition=first,
            to_disposition="unable_to_complete",
        ).disposition
    assert second.sequence == 2
    assert second.occurred_at > first.occurred_at


@pytest.mark.django_db
def test_review_time_floor_revision_isolation_and_historical_retry(regulatory_root):
    _, entity, recorder, reviewer, chain, first_decision = _make_review_chain("HISTORY")
    first_payload = applicability_review_payload("HISTORY", decision=first_decision)
    first_review = record_regulatory_applicability_review_disposition(
        actor=reviewer,
        entity=entity,
        document_id=chain.document.id,
        payload=first_payload,
        idempotency_key="applicability-review-history-first",
    ).disposition

    regressed_now = first_review.occurred_at - timedelta(days=1)
    with patch(
        "regulatory.services.applicability.timezone.now", return_value=regressed_now
    ):
        second_decision = record_regulatory_applicability_decision(
            actor=recorder,
            entity=entity,
            document_id=chain.document.id,
            payload=applicability_payload(
                "HISTORY",
                chain=chain,
                observations=[known_institution_type_observation("insurance")],
                expected_revision=first_decision.revision,
                expected_payload_sha256=regulatory_applicability_semantic_sha256(
                    first_decision
                ),
            ),
            idempotency_key="applicability-review-history-second-decision",
        ).decision
    assert second_decision.recorded_from > first_review.occurred_at

    historical = get_regulatory_applicability_review(
        actor=reviewer,
        entity=entity,
        document_id=chain.document.id,
        recorded_as_of=second_decision.recorded_from - timedelta(microseconds=1),
    )
    current = get_regulatory_applicability_review(
        actor=reviewer,
        entity=entity,
        document_id=chain.document.id,
    )
    assert historical.applicability.decision == first_decision
    assert historical.disposition == first_review
    assert historical.review_state == "no_correction_requested"
    assert current.applicability.decision == second_decision
    assert current.disposition is None
    assert current.review_state == "not_reviewed"
    assert current.workflow_attention == "needs_review"

    moved_folder = make_folder("Applicability review moved entity")
    entity.__class__.objects.filter(pk=entity.pk).update(
        folder=moved_folder,
        ref_id="RENAMED-AFTER-REVIEW",
    )
    retry = record_regulatory_applicability_review_disposition(
        actor=reviewer,
        entity=entity,
        document_id=chain.document.id,
        payload=deepcopy(first_payload),
        idempotency_key="applicability-review-history-first",
    )
    assert retry.disposition == first_review

    moved_historical = get_regulatory_applicability_review(
        actor=reviewer,
        entity=entity,
        document_id=chain.document.id,
        recorded_as_of=second_decision.recorded_from - timedelta(microseconds=1),
    )
    assert moved_historical.applicability.decision == first_decision
    assert moved_historical.disposition == first_review
    assert moved_historical.review_state == "no_correction_requested"

    with pytest.raises(ValidationError, match="registration folder"):
        _record_review(
            actor=reviewer,
            entity=entity,
            chain=chain,
            decision=second_decision,
            suffix="HISTORY-NEW-AFTER-MOVE",
        )
    assert RegulatoryApplicabilityReviewDisposition.objects.count() == 1


@pytest.mark.django_db
def test_two_entity_registrations_keep_review_streams_isolated(regulatory_root):
    folder, first_entity, recorder, reviewer, chain, first_decision = (
        _make_review_chain("TWO-REGISTRATIONS")
    )
    first_event = _record_review(
        actor=reviewer,
        entity=first_entity,
        chain=chain,
        decision=first_decision,
        suffix="TWO-REGISTRATIONS-FIRST",
    ).disposition

    second_entity = make_synthetic_entity(folder, "TWO-REGISTRATIONS-SECOND")
    EntityDocumentRegistration.objects.create(
        folder=folder,
        entity=second_entity,
        document=chain.document,
        registration_kind=EntityDocumentRegistration.RegistrationKind.SYNTHETIC_PILOT,
        idempotency_key="applicability-review-second-registration",
        payload_sha256="a" * 64,
        ingested_by=recorder,
        is_published=False,
    )
    second_decision = record_regulatory_applicability_decision(
        actor=recorder,
        entity=second_entity,
        document_id=chain.document.id,
        payload=applicability_payload("TWO-REGISTRATIONS-SECOND", chain=chain),
        idempotency_key="applicability-review-second-registration-decision",
    ).decision
    second_event = _record_review(
        actor=reviewer,
        entity=second_entity,
        chain=chain,
        decision=second_decision,
        suffix="TWO-REGISTRATIONS-SECOND",
        to_disposition="correction_requested",
    ).disposition

    first_selection = get_regulatory_applicability_review(
        actor=reviewer,
        entity=first_entity,
        document_id=chain.document.id,
    )
    second_selection = get_regulatory_applicability_review(
        actor=reviewer,
        entity=second_entity,
        document_id=chain.document.id,
    )
    assert first_selection.applicability.decision == first_decision
    assert first_selection.disposition == first_event
    assert first_selection.review_state == "no_correction_requested"
    assert second_selection.applicability.decision == second_decision
    assert second_selection.disposition == second_event
    assert second_selection.review_state == "correction_requested"


@pytest.mark.django_db
def test_obligation_correction_hides_r1_review_from_r2(regulatory_root):
    folder, entity, recorder, reviewer, chain, decision = _make_review_chain(
        "OBLIGATION-R1-R2"
    )
    RoleAssignment.objects.get(user=recorder).role.permissions.add(
        Permission.objects.get(
            content_type__app_label="regulatory",
            codename="correct_regulatoryrecord",
        )
    )
    event = _record_review(
        actor=reviewer,
        entity=entity,
        chain=chain,
        decision=decision,
        suffix="OBLIGATION-R1-R2",
    ).disposition

    corrected = correct_regulatory_chain(
        actor=recorder,
        entity=entity,
        document_id=chain.document.id,
        payload=correction_payload(
            "OBLIGATION-R1-R2",
            expected_payload_sha256=regulatory_chain_semantic_sha256(chain),
        ),
        rationale="Correct the synthetic obligation after its review disposition",
        idempotency_key="applicability-review-obligation-r1-r2-correction",
    )
    assert corrected.event.occurred_at > event.occurred_at

    current = get_regulatory_applicability_review(
        actor=reviewer,
        entity=entity,
        document_id=chain.document.id,
    )
    historical = get_regulatory_applicability_review(
        actor=reviewer,
        entity=entity,
        document_id=chain.document.id,
        recorded_as_of=corrected.event.occurred_at - timedelta(microseconds=1),
    )
    assert current.applicability.chain.obligation.revision == 2
    assert current.applicability.decision is None
    assert current.review_state == "not_reviewable"
    assert current.disposition is None
    assert historical.applicability.chain.obligation.revision == 1
    assert historical.applicability.decision == decision
    assert historical.disposition == event
    assert historical.review_state == "no_correction_requested"


@pytest.mark.django_db
def test_review_read_states_and_reviewer_user_iam_masking(regulatory_root):
    folder, entity, _, reviewer, chain, decision = _make_review_chain("MASK")
    no_review = get_regulatory_applicability_review(
        actor=reviewer,
        entity=entity,
        document_id=chain.document.id,
    )
    assert no_review.review_state == "not_reviewed"
    assert no_review.reviewer is None

    event = _record_review(
        actor=reviewer,
        entity=entity,
        chain=chain,
        decision=decision,
        suffix="MASK",
    ).disposition
    blind_reader = make_user_with_permissions(
        folder,
        "view_regulatorydocument",
        "view_regulatoryapplicabilitydecision",
        REVIEW_VIEW_PERMISSION,
        "view_entity",
        email_prefix="applicability-review-masked-reader",
    )
    masked = get_regulatory_applicability_review(
        actor=blind_reader,
        entity=entity,
        document_id=chain.document.id,
    )
    assert masked.disposition == event
    assert masked.reviewer.masked is True
    assert masked.reviewer.id is None
    assert masked.reviewer.display_name is None

    reviewer.__class__.objects.filter(pk=reviewer.pk).update(
        folder=folder,
        first_name="Synthetic",
        last_name="Reviewer",
    )
    visible_reader = make_user_with_permissions(
        folder,
        "view_regulatorydocument",
        "view_regulatoryapplicabilitydecision",
        REVIEW_VIEW_PERMISSION,
        "view_entity",
        "view_user",
        email_prefix="applicability-review-visible-reader",
    )
    visible = get_regulatory_applicability_review(
        actor=visible_reader,
        entity=entity,
        document_id=chain.document.id,
    )
    assert visible.reviewer.masked is False
    assert visible.reviewer.id == str(reviewer.id)
    assert visible.reviewer.display_name == "Synthetic Reviewer"
    assert not hasattr(visible.reviewer, "email")

    missing_disposition_view = make_user_with_permissions(
        folder,
        "view_regulatorydocument",
        "view_regulatoryapplicabilitydecision",
        "view_entity",
        email_prefix="applicability-review-hidden-reader",
    )
    with pytest.raises(PermissionDenied):
        get_regulatory_applicability_review(
            actor=missing_disposition_view,
            entity=entity,
            document_id=chain.document.id,
        )


@pytest.mark.django_db
@pytest.mark.parametrize(
    "tampered_digest_field",
    ("request_sha256", "event_payload_sha256"),
)
def test_review_chain_fails_closed_on_root_digest_tampering(
    regulatory_root,
    tampered_digest_field,
):
    suffix = f"TAMPER-{tampered_digest_field}"
    _, entity, _, reviewer, chain, decision = _make_review_chain(suffix)
    first = _record_review(
        actor=reviewer,
        entity=entity,
        chain=chain,
        decision=decision,
        suffix=f"{suffix}-1",
        to_disposition="correction_requested",
    ).disposition
    second = _record_review(
        actor=reviewer,
        entity=entity,
        chain=chain,
        decision=decision,
        suffix=f"{suffix}-2",
        expected_disposition=first,
        to_disposition="unable_to_complete",
    ).disposition
    third = _record_review(
        actor=reviewer,
        entity=entity,
        chain=chain,
        decision=decision,
        suffix=f"{suffix}-3",
        expected_disposition=second,
        to_disposition="no_correction_requested",
    ).disposition

    lineage_root = third.previous_disposition.previous_disposition
    lineage_root.previous_disposition = third
    with pytest.raises(RegulatoryApplicabilityReviewStateUnavailable):
        _validate_persisted_disposition(third)
    lineage_root.previous_disposition = None

    RegulatoryApplicabilityReviewDisposition.objects.filter(pk=first.pk).update(
        **{tampered_digest_field: "f" * 64}
    )

    with pytest.raises(RegulatoryApplicabilityReviewStateUnavailable):
        get_regulatory_applicability_review(
            actor=reviewer,
            entity=entity,
            document_id=chain.document.id,
        )

    with pytest.raises(RegulatoryApplicabilityReviewStateUnavailable):
        _record_review(
            actor=reviewer,
            entity=entity,
            chain=chain,
            decision=decision,
            suffix=f"{suffix}-4",
            expected_disposition=third,
            to_disposition="correction_requested",
        )
    assert RegulatoryApplicabilityReviewDisposition.objects.count() == 3


@pytest.mark.django_db
def test_review_events_are_append_only_and_database_constrained(regulatory_root):
    _, entity, recorder, reviewer, chain, decision = _make_review_chain("DB-GATES")
    event = _record_review(
        actor=reviewer,
        entity=entity,
        chain=chain,
        decision=decision,
        suffix="DB-GATES",
    ).disposition

    event.rationale = "An attempted in-place edit"
    with pytest.raises(ValidationError, match="append-only"):
        event.save()
    event.refresh_from_db()
    with pytest.raises(ValidationError, match="cannot be deleted"):
        event.delete()

    with pytest.raises(IntegrityError):
        with transaction.atomic():
            RegulatoryApplicabilityReviewDisposition.objects.filter(pk=event.pk).update(
                reviewer_id=recorder.id
            )

    with pytest.raises(IntegrityError):
        with transaction.atomic():
            RegulatoryApplicabilityReviewDisposition.objects.filter(pk=event.pk).update(
                reason_code="insufficient_evidence"
            )

    duplicate_root = RegulatoryApplicabilityReviewDisposition(
        folder=event.folder,
        decision=decision,
        decision_semantic_payload_sha256=decision.semantic_payload_sha256,
        decision_recorded_by=recorder,
        reviewer=reviewer,
        sequence=1,
        previous_disposition=None,
        from_disposition="not_reviewed",
        to_disposition="no_correction_requested",
        reason_code="review_completed",
        rationale="A raw duplicate root used to exercise database uniqueness",
        occurred_at=event.occurred_at + timedelta(microseconds=1),
        digest_profile=event.digest_profile,
        event_payload_sha256="a" * 64,
        request_sha256="b" * 64,
        idempotency_key="applicability-review-db-gates-duplicate-root",
        is_binding=False,
        is_published=False,
    )
    with pytest.raises(IntegrityError):
        with transaction.atomic():
            RegulatoryApplicabilityReviewDisposition.objects.bulk_create(
                [duplicate_root]
            )
