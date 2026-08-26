import pytest
from django.contrib.auth.models import Permission
from django.core.exceptions import ValidationError
from django.db import IntegrityError, transaction
from rest_framework.exceptions import PermissionDenied

from regulatory.models import RegulatoryObligationReviewEvent
from regulatory.services import create_regulatory_chain, transition_obligation_review
from iam.service_accounts import provision_service_account

from .factories import (
    chain_payload,
    make_folder,
    make_synthetic_entity,
    make_user_with_permissions,
)


@pytest.mark.django_db
def test_review_transitions_are_append_only_separated_and_non_binding(regulatory_root):
    folder = make_folder()
    entity = make_synthetic_entity(folder, "REVIEW")
    analyst = make_user_with_permissions(
        folder,
        "ingest_regulatoryrecord",
        "transition_regulatoryobligation",
        email_prefix="analyst",
    )
    legal_reviewer = make_user_with_permissions(
        folder,
        "legal_review_regulatoryobligation",
        email_prefix="legal",
    )
    chain = create_regulatory_chain(
        actor=analyst,
        entity=entity,
        payload=chain_payload("REVIEW"),
        idempotency_key="review-chain",
    )

    first = transition_obligation_review(
        actor=analyst,
        obligation_id=chain.obligation.id,
        expected_from_status="machine_proposed",
        to_status="analyst_reviewed",
        rationale="Analyst checked the structured proposal; no legal approval.",
        idempotency_key="review-event-1",
    )
    retry = transition_obligation_review(
        actor=analyst,
        obligation_id=chain.obligation.id,
        expected_from_status="machine_proposed",
        to_status="analyst_reviewed",
        rationale="Analyst checked the structured proposal; no legal approval.",
        idempotency_key="review-event-1",
    )
    assert retry.id == first.id

    second = transition_obligation_review(
        actor=legal_reviewer,
        obligation_id=chain.obligation.id,
        expected_from_status="analyst_reviewed",
        to_status="legal_reviewed",
        rationale="A separate named reviewer checked the proposal; it remains unpublished.",
        idempotency_key="review-event-2",
    )
    assert second.sequence == 2
    assert RegulatoryObligationReviewEvent.objects.count() == 2
    chain.obligation.refresh_from_db()
    assert chain.obligation.review_status == "machine_proposed"
    assert chain.obligation.current_review_status == "legal_reviewed"
    assert not chain.obligation.is_published


@pytest.mark.django_db
def test_review_skips_binding_states_and_self_review_fail_closed(regulatory_root):
    folder = make_folder()
    entity = make_synthetic_entity(folder, "FAIL-CLOSED")
    actor = make_user_with_permissions(
        folder,
        "ingest_regulatoryrecord",
        "transition_regulatoryobligation",
        "legal_review_regulatoryobligation",
    )
    chain = create_regulatory_chain(
        actor=actor,
        entity=entity,
        payload=chain_payload("FAIL-CLOSED"),
        idempotency_key="fail-closed-chain",
    )

    for target in ("legal_reviewed", "approved", "rejected", "superseded"):
        with pytest.raises(ValidationError):
            transition_obligation_review(
                actor=actor,
                obligation_id=chain.obligation.id,
                expected_from_status="machine_proposed",
                to_status=target,
                rationale="Attempted invalid transition",
                idempotency_key=f"invalid-{target}",
            )
    assert RegulatoryObligationReviewEvent.objects.count() == 0

    transition_obligation_review(
        actor=actor,
        obligation_id=chain.obligation.id,
        expected_from_status="machine_proposed",
        to_status="analyst_reviewed",
        rationale="First review",
        idempotency_key="valid-first",
    )
    with pytest.raises(ValidationError, match="different named actors"):
        transition_obligation_review(
            actor=actor,
            obligation_id=chain.obligation.id,
            expected_from_status="analyst_reviewed",
            to_status="legal_reviewed",
            rationale="Self review attempt",
            idempotency_key="invalid-self-review",
        )


@pytest.mark.django_db
def test_transition_requires_folder_scoped_permission(regulatory_root):
    folder = make_folder()
    other_folder = make_folder()
    entity = make_synthetic_entity(folder, "PERMISSION")
    ingester = make_user_with_permissions(folder, "ingest_regulatoryrecord")
    outsider = make_user_with_permissions(
        other_folder,
        "transition_regulatoryobligation",
    )
    chain = create_regulatory_chain(
        actor=ingester,
        entity=entity,
        payload=chain_payload("PERMISSION"),
        idempotency_key="permission-chain",
    )

    with pytest.raises(PermissionDenied):
        transition_obligation_review(
            actor=outsider,
            obligation_id=chain.obligation.id,
            expected_from_status="machine_proposed",
            to_status="analyst_reviewed",
            rationale="Out-of-scope attempt",
            idempotency_key="permission-denied",
        )
    assert RegulatoryObligationReviewEvent.objects.count() == 0


@pytest.mark.django_db
def test_analyst_permission_cannot_perform_legal_review(regulatory_root):
    folder = make_folder()
    entity = make_synthetic_entity(folder, "ROLE-SEPARATION")
    first_analyst = make_user_with_permissions(
        folder,
        "ingest_regulatoryrecord",
        "transition_regulatoryobligation",
        email_prefix="first-analyst",
    )
    second_analyst = make_user_with_permissions(
        folder,
        "transition_regulatoryobligation",
        email_prefix="second-analyst",
    )
    chain = create_regulatory_chain(
        actor=first_analyst,
        entity=entity,
        payload=chain_payload("ROLE-SEPARATION"),
        idempotency_key="role-separation-chain",
    )
    transition_obligation_review(
        actor=first_analyst,
        obligation_id=chain.obligation.id,
        expected_from_status="machine_proposed",
        to_status="analyst_reviewed",
        rationale="First analyst review",
        idempotency_key="role-separation-first",
    )

    with pytest.raises(PermissionDenied):
        transition_obligation_review(
            actor=second_analyst,
            obligation_id=chain.obligation.id,
            expected_from_status="analyst_reviewed",
            to_status="legal_reviewed",
            rationale="Second analyst attempted legal review",
            idempotency_key="role-separation-second",
        )
    assert chain.obligation.current_review_status == "analyst_reviewed"


@pytest.mark.django_db
def test_review_reloads_actor_revocation_from_database(regulatory_root):
    folder = make_folder()
    entity = make_synthetic_entity(folder, "REVOKED-REVIEWER")
    ingester = make_user_with_permissions(folder, "ingest_regulatoryrecord")
    stale_reviewer = make_user_with_permissions(
        folder,
        "transition_regulatoryobligation",
    )
    chain = create_regulatory_chain(
        actor=ingester,
        entity=entity,
        payload=chain_payload("REVOKED-REVIEWER"),
        idempotency_key="revoked-reviewer-chain",
    )
    stale_reviewer.__class__.objects.filter(pk=stale_reviewer.pk).update(
        is_active=False
    )

    with pytest.raises(PermissionDenied, match="active actor"):
        transition_obligation_review(
            actor=stale_reviewer,
            obligation_id=chain.obligation.id,
            expected_from_status="machine_proposed",
            to_status="analyst_reviewed",
            rationale="Revoked actor attempt",
            idempotency_key="revoked-reviewer-attempt",
        )
    assert RegulatoryObligationReviewEvent.objects.count() == 0


@pytest.mark.django_db
def test_database_rejects_binding_review_event_bypass(regulatory_root):
    folder = make_folder()
    entity = make_synthetic_entity(folder, "DB-GUARD")
    actor = make_user_with_permissions(
        folder,
        "ingest_regulatoryrecord",
        "transition_regulatoryobligation",
    )
    chain = create_regulatory_chain(
        actor=actor,
        entity=entity,
        payload=chain_payload("DB-GUARD"),
        idempotency_key="db-guard-chain",
    )

    event = RegulatoryObligationReviewEvent(
        folder=folder,
        obligation=chain.obligation,
        sequence=1,
        from_status="machine_proposed",
        to_status="approved",
        actor=actor,
        rationale="Attempted binding-state bypass",
        idempotency_key="db-guard-event",
        payload_sha256="f" * 64,
    )
    with pytest.raises(IntegrityError), transaction.atomic():
        RegulatoryObligationReviewEvent.objects.bulk_create([event])


@pytest.mark.django_db
def test_service_account_cannot_act_as_named_legal_reviewer(regulatory_root):
    folder = make_folder()
    entity = make_synthetic_entity(folder, "HUMAN-REVIEW")
    analyst = make_user_with_permissions(
        folder,
        "ingest_regulatoryrecord",
        "transition_regulatoryobligation",
    )
    chain = create_regulatory_chain(
        actor=analyst,
        entity=entity,
        payload=chain_payload("HUMAN-REVIEW"),
        idempotency_key="human-review-chain",
    )
    transition_obligation_review(
        actor=analyst,
        obligation_id=chain.obligation.id,
        expected_from_status="machine_proposed",
        to_status="analyst_reviewed",
        rationale="Human analyst review",
        idempotency_key="human-review-analyst",
    )
    permission = Permission.objects.get(
        content_type__app_label="regulatory",
        codename="legal_review_regulatoryobligation",
    )
    service_account, _ = provision_service_account(
        name="regulatory-legal-review-test",
        description="Synthetic test service account",
        permission_ids=[permission.id],
        folder_ids=[folder.id],
        is_recursive=False,
        created_by=analyst,
    )

    with pytest.raises(ValidationError, match="Named human reviewers"):
        transition_obligation_review(
            actor=service_account.user,
            obligation_id=chain.obligation.id,
            expected_from_status="analyst_reviewed",
            to_status="legal_reviewed",
            rationale="Machine legal review attempt",
            idempotency_key="human-review-machine-attempt",
        )
    assert chain.obligation.current_review_status == "analyst_reviewed"
