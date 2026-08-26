from copy import copy, deepcopy
from datetime import timedelta
from unittest.mock import patch
import uuid

import pytest
from django.contrib.auth.models import Permission
from django.core.exceptions import ValidationError
from django.db import IntegrityError, transaction
from django.utils import timezone
from django.utils.dateparse import parse_datetime
from rest_framework.exceptions import PermissionDenied

from iam.service_accounts import provision_service_account
from regulatory.models import RegulatoryApplicabilityDecision
from regulatory.services import (
    correct_regulatory_chain,
    create_regulatory_chain,
    get_regulatory_applicability,
    record_regulatory_applicability_decision,
    regulatory_applicability_semantic_sha256,
    regulatory_chain_semantic_sha256,
    transition_obligation_review,
)
from regulatory.services.common import IdempotencyConflict, canonical_payload_sha256

from .factories import (
    APPLICABILITY_FACT_KEY,
    applicability_payload,
    chain_payload,
    correction_payload,
    known_institution_type_observation,
    make_folder,
    make_synthetic_entity,
    make_user_with_permissions,
    unknown_institution_type_observation,
)


APPLICABILITY_PERMISSION = "record_regulatoryapplicability"


def _make_applicability_chain(suffix: str, *, folder=None, permissions=()):
    folder = folder or make_folder(f"Applicability {suffix}")
    entity = make_synthetic_entity(folder, suffix)
    actor = make_user_with_permissions(
        folder,
        "ingest_regulatoryrecord",
        "view_regulatorydocument",
        "view_regulatoryapplicabilitydecision",
        "view_entitydocumentregistration",
        APPLICABILITY_PERMISSION,
        *permissions,
        email_prefix="applicability-analyst",
    )
    chain = create_regulatory_chain(
        actor=actor,
        entity=entity,
        payload=chain_payload(suffix),
        idempotency_key=f"applicability-chain-{suffix}",
    )
    return folder, entity, actor, chain


def _record(*, actor, entity, chain, payload, idempotency_key):
    return record_regulatory_applicability_decision(
        actor=actor,
        entity=entity,
        document_id=chain.document.id,
        payload=payload,
        idempotency_key=idempotency_key,
    )


@pytest.mark.django_db
@pytest.mark.parametrize(
    ("case", "observations", "expected_result"),
    (
        ("missing", [], "needs_review"),
        ("unknown", [unknown_institution_type_observation()], "needs_review"),
        (
            "bank",
            [known_institution_type_observation("bank")],
            "applicable",
        ),
        (
            "insurance",
            [known_institution_type_observation("insurance")],
            "not_applicable",
        ),
    ),
)
def test_three_value_applicability_is_server_computed_and_nonbinding(
    regulatory_root,
    case,
    observations,
    expected_result,
):
    _, entity, actor, chain = _make_applicability_chain(case.upper())
    payload = applicability_payload(
        case.upper(),
        chain=chain,
        observations=observations,
    )

    result = _record(
        actor=actor,
        entity=entity,
        chain=chain,
        payload=payload,
        idempotency_key=f"applicability-{case}",
    )
    decision = result.decision

    assert decision.result == expected_result
    assert decision.record_id == payload["record_id"]
    assert decision.fact_snapshot_id == payload["fact_snapshot_id"]
    assert decision.registration.entity_id == entity.id
    assert decision.obligation_id == chain.obligation.id
    assert decision.revision == 1
    assert decision.previous_revision_id is None
    assert decision.recorded_to is None
    assert decision.review_status == "draft"
    assert not decision.is_published
    assert result.chain.obligation.id == chain.obligation.id
    assert decision.semantic_payload_sha256 == (
        regulatory_applicability_semantic_sha256(decision)
    )
    assert decision.fact_snapshot_sha256 == canonical_payload_sha256(
        {
            "observations": decision.fact_snapshot,
            "missing_fact_keys": decision.missing_fact_keys,
        }
    )

    if case == "missing":
        assert decision.fact_snapshot == [unknown_institution_type_observation()]
        assert decision.missing_fact_keys == [APPLICABILITY_FACT_KEY]
    elif observations[0]["known"]:
        actual_observation = decision.fact_snapshot[0]
        expected_observation = observations[0]
        for field in ("fact", "known", "value", "source_refs"):
            assert actual_observation[field] == expected_observation[field]
        assert parse_datetime(actual_observation["observed_at"]) == parse_datetime(
            expected_observation["observed_at"]
        )
        assert decision.missing_fact_keys == []
    else:
        assert decision.fact_snapshot == observations
        assert decision.missing_fact_keys == []

    selected = get_regulatory_applicability(
        actor=actor,
        entity=entity,
        document_id=chain.document.id,
    )
    assert selected.decision.id == decision.id
    assert selected.chain.obligation.id == chain.obligation.id


@pytest.mark.django_db
def test_applicability_payload_is_strict_and_fact_evidence_fails_closed(
    regulatory_root,
):
    _, entity, actor, chain = _make_applicability_chain("STRICT")
    base = applicability_payload("STRICT", chain=chain)
    invalid_payloads = []

    injected_result = deepcopy(base)
    injected_result["result"] = "not_applicable"
    invalid_payloads.append(("injected-result", injected_result))

    extra_field = deepcopy(base)
    extra_field["confirmed_by"] = "attacker@example.test"
    invalid_payloads.append(("extra-field", extra_field))

    unregistered_fact = deepcopy(base)
    unregistered_fact["observations"][0]["fact"] = "entity.attacker_controlled"
    invalid_payloads.append(("unregistered-fact", unregistered_fact))

    duplicate_fact = deepcopy(base)
    duplicate_fact["observations"].append(deepcopy(duplicate_fact["observations"][0]))
    invalid_payloads.append(("duplicate-fact", duplicate_fact))

    for label, observation in (
        (
            "missing-evidence",
            known_institution_type_observation("bank", source_refs=[]),
        ),
        (
            "whitespace-evidence",
            known_institution_type_observation("bank", source_refs=[" \t "]),
        ),
        (
            "wrong-evidence-type",
            known_institution_type_observation("bank", source_refs=[["nested"]]),
        ),
        (
            "missing-observation-time",
            known_institution_type_observation("bank", observed_at=None),
        ),
        (
            "future-observation-time",
            known_institution_type_observation(
                "bank",
                observed_at=(timezone.now() + timedelta(days=1)).isoformat(),
            ),
        ),
        (
            "too-many-evidence-references",
            known_institution_type_observation(
                "bank",
                source_refs=[f"test:evidence:{index}" for index in range(21)],
            ),
        ),
        (
            "oversized-evidence-reference",
            known_institution_type_observation(
                "bank",
                source_refs=["x" * 501],
            ),
        ),
        (
            "oversized-fact-value",
            known_institution_type_observation("x" * 101),
        ),
    ):
        payload = deepcopy(base)
        payload["observations"] = [observation]
        invalid_payloads.append((label, payload))

    for label, field, value in (
        ("unknown-value", "value", "bank"),
        ("unknown-evidence", "source_refs", ["test:forged-evidence"]),
        (
            "unknown-observation-time",
            "observed_at",
            "2026-08-21T00:00:00+08:00",
        ),
    ):
        observation = unknown_institution_type_observation()
        observation[field] = value
        payload = deepcopy(base)
        payload["observations"] = [observation]
        invalid_payloads.append((label, payload))

    invalid_interval = deepcopy(base)
    invalid_interval["valid_to"] = invalid_interval["valid_from"]
    invalid_payloads.append(("invalid-valid-interval", invalid_interval))

    for label, payload in invalid_payloads:
        with pytest.raises(ValidationError), transaction.atomic():
            _record(
                actor=actor,
                entity=entity,
                chain=chain,
                payload=payload,
                idempotency_key=f"strict-{label}",
            )
        assert RegulatoryApplicabilityDecision.objects.count() == 0


@pytest.mark.django_db
def test_applicability_revisions_are_idempotent_digest_bound_and_atomic(
    regulatory_root,
):
    _, entity, actor, chain = _make_applicability_chain("REVISION")
    first_payload = applicability_payload("REVISION", chain=chain)
    first = _record(
        actor=actor,
        entity=entity,
        chain=chain,
        payload=first_payload,
        idempotency_key="applicability-revision-1",
    )
    first_digest = regulatory_applicability_semantic_sha256(first.decision)

    retry = _record(
        actor=actor,
        entity=entity,
        chain=chain,
        payload=deepcopy(first_payload),
        idempotency_key="applicability-revision-1",
    )
    assert retry.decision.id == first.decision.id

    conflicting_retry = deepcopy(first_payload)
    conflicting_retry["observations"] = [
        known_institution_type_observation("insurance")
    ]
    with pytest.raises(IdempotencyConflict):
        _record(
            actor=actor,
            entity=entity,
            chain=chain,
            payload=conflicting_retry,
            idempotency_key="applicability-revision-1",
        )

    second_payload = applicability_payload(
        "REVISION",
        chain=chain,
        observations=[known_institution_type_observation("insurance")],
        expected_revision=1,
        expected_payload_sha256=first_digest,
    )
    second = _record(
        actor=actor,
        entity=entity,
        chain=chain,
        payload=second_payload,
        idempotency_key="applicability-revision-2",
    )
    second_digest = regulatory_applicability_semantic_sha256(second.decision)
    first.decision.refresh_from_db()

    assert second.decision.revision == 2
    assert second.decision.previous_revision_id == first.decision.id
    assert first.decision.recorded_to == second.decision.recorded_from
    assert second.decision.result == "not_applicable"
    assert first_digest != second_digest

    regressed_now = first.decision.recorded_from - timedelta(days=1)
    with patch(
        "regulatory.services.applicability.timezone.now",
        return_value=regressed_now,
    ):
        historical_retry = _record(
            actor=actor,
            entity=entity,
            chain=chain,
            payload=deepcopy(first_payload),
            idempotency_key="applicability-revision-1",
        )
    assert historical_retry.decision.id == first.decision.id
    assert historical_retry.decision.recorded_to == second.decision.recorded_from

    noop = applicability_payload(
        "REVISION",
        chain=chain,
        observations=[known_institution_type_observation("insurance")],
        expected_revision=2,
        expected_payload_sha256=second_digest,
    )
    with pytest.raises(ValidationError, match="[Nn]o-op"):
        _record(
            actor=actor,
            entity=entity,
            chain=chain,
            payload=noop,
            idempotency_key="applicability-noop",
        )

    stale = applicability_payload(
        "REVISION",
        chain=chain,
        observations=[known_institution_type_observation("bank")],
        expected_revision=1,
        expected_payload_sha256=first_digest,
    )
    with pytest.raises(ValidationError, match="[Ss]tale"):
        _record(
            actor=actor,
            entity=entity,
            chain=chain,
            payload=stale,
            idempotency_key="applicability-stale",
        )

    assert RegulatoryApplicabilityDecision.objects.count() == 2
    current = get_regulatory_applicability(
        actor=actor,
        entity=entity,
        document_id=chain.document.id,
    )
    assert current.decision.id == second.decision.id


@pytest.mark.django_db
def test_applicability_recorded_as_of_uses_half_open_intervals_and_clock_floor(
    regulatory_root,
):
    _, entity, actor, chain = _make_applicability_chain("ASOF")
    first = _record(
        actor=actor,
        entity=entity,
        chain=chain,
        payload=applicability_payload("ASOF", chain=chain, observations=[]),
        idempotency_key="applicability-asof-1",
    )
    first_digest = regulatory_applicability_semantic_sha256(first.decision)
    second = _record(
        actor=actor,
        entity=entity,
        chain=chain,
        payload=applicability_payload(
            "ASOF",
            chain=chain,
            observations=[known_institution_type_observation("bank")],
            expected_revision=1,
            expected_payload_sha256=first_digest,
        ),
        idempotency_key="applicability-asof-2",
    )
    cutoff = second.decision.recorded_from

    before_first = get_regulatory_applicability(
        actor=actor,
        entity=entity,
        document_id=chain.document.id,
        recorded_as_of=first.decision.recorded_from - timedelta(microseconds=1),
    )
    assert before_first.decision is None

    immediately_before = get_regulatory_applicability(
        actor=actor,
        entity=entity,
        document_id=chain.document.id,
        recorded_as_of=cutoff - timedelta(microseconds=1),
    )
    assert immediately_before.decision.id == first.decision.id
    assert immediately_before.decision.result == "needs_review"

    at_cutoff = get_regulatory_applicability(
        actor=actor,
        entity=entity,
        document_id=chain.document.id,
        recorded_as_of=cutoff,
    )
    assert at_cutoff.decision.id == second.decision.id
    assert at_cutoff.decision.result == "applicable"

    regressed_now = cutoff - timedelta(days=1)
    with (
        patch(
            "regulatory.services.applicability.timezone.now",
            return_value=regressed_now,
        ),
        patch(
            "regulatory.services.records.timezone.now",
            return_value=regressed_now,
        ),
    ):
        current_after_clock_rollback = get_regulatory_applicability(
            actor=actor,
            entity=entity,
            document_id=chain.document.id,
        )
    assert current_after_clock_rollback.decision.id == second.decision.id


@pytest.mark.django_db
def test_obligation_correction_does_not_inherit_or_accept_stale_applicability(
    regulatory_root,
):
    _, entity, actor, chain = _make_applicability_chain(
        "PARENT-CAS",
        permissions=("correct_regulatoryrecord",),
    )
    first_payload = applicability_payload("PARENT-CAS", chain=chain)
    first = _record(
        actor=actor,
        entity=entity,
        chain=chain,
        payload=first_payload,
        idempotency_key="applicability-parent-r1",
    )
    first_digest = regulatory_applicability_semantic_sha256(first.decision)
    stale_parent_payload = applicability_payload(
        "PARENT-CAS",
        chain=chain,
        observations=[known_institution_type_observation("insurance")],
        expected_revision=1,
        expected_payload_sha256=first_digest,
    )

    corrected = correct_regulatory_chain(
        actor=actor,
        entity=entity,
        document_id=chain.document.id,
        payload=correction_payload(
            "PARENT-CAS",
            expected_payload_sha256=regulatory_chain_semantic_sha256(chain),
        ),
        rationale="Correct the synthetic parent after its applicability snapshot",
        idempotency_key="applicability-parent-correction",
    )
    assert corrected.event.occurred_at > first.decision.recorded_from

    current = get_regulatory_applicability(
        actor=actor,
        entity=entity,
        document_id=chain.document.id,
    )
    assert current.chain.obligation.revision == 2
    assert current.decision is None

    historical = get_regulatory_applicability(
        actor=actor,
        entity=entity,
        document_id=chain.document.id,
        recorded_as_of=corrected.event.occurred_at - timedelta(microseconds=1),
    )
    assert historical.chain.obligation.revision == 1
    assert historical.decision.id == first.decision.id

    with pytest.raises(ValidationError, match="[Ss]tale"):
        _record(
            actor=actor,
            entity=entity,
            chain=corrected.chain,
            payload=stale_parent_payload,
            idempotency_key="applicability-stale-parent",
        )
    assert RegulatoryApplicabilityDecision.objects.count() == 1

    exact_historical_retry = _record(
        actor=actor,
        entity=entity,
        chain=corrected.chain,
        payload=deepcopy(first_payload),
        idempotency_key="applicability-parent-r1",
    )
    assert exact_historical_retry.decision.id == first.decision.id


@pytest.mark.django_db
def test_applicability_floor_orders_review_and_correction_during_clock_rollback(
    regulatory_root,
):
    _, entity, actor, chain = _make_applicability_chain(
        "CROSS-PATH-FLOOR",
        permissions=(
            "transition_regulatoryobligation",
            "correct_regulatoryrecord",
        ),
    )
    recorded = _record(
        actor=actor,
        entity=entity,
        chain=chain,
        payload=applicability_payload("CROSS-PATH-FLOOR", chain=chain),
        idempotency_key="applicability-cross-path-floor",
    )
    regressed_time = recorded.decision.recorded_from - timedelta(days=1)

    with patch("regulatory.services.review.timezone.now", return_value=regressed_time):
        review = transition_obligation_review(
            actor=actor,
            obligation_id=chain.obligation.id,
            expected_from_status="machine_proposed",
            to_status="analyst_reviewed",
            rationale="Synthetic review after the applicability snapshot",
            idempotency_key="applicability-cross-path-review",
        )
    assert review.occurred_at > recorded.decision.recorded_from

    with patch(
        "regulatory.services.corrections.timezone.now",
        return_value=regressed_time,
    ):
        corrected = correct_regulatory_chain(
            actor=actor,
            entity=entity,
            document_id=chain.document.id,
            payload=correction_payload(
                "CROSS-PATH-FLOOR",
                expected_payload_sha256=regulatory_chain_semantic_sha256(chain),
            ),
            rationale="Correct the chain after applicability and review history",
            idempotency_key="applicability-cross-path-correction",
        )
    assert corrected.event.occurred_at > review.occurred_at

    historical = get_regulatory_applicability(
        actor=actor,
        entity=entity,
        document_id=chain.document.id,
        recorded_as_of=corrected.event.occurred_at - timedelta(microseconds=1),
    )
    assert historical.chain.obligation.id == chain.obligation.id
    assert historical.decision.id == recorded.decision.id

    current = get_regulatory_applicability(
        actor=actor,
        entity=entity,
        document_id=chain.document.id,
    )
    assert current.chain.obligation.id == corrected.chain.obligation.id
    assert current.decision is None


@pytest.mark.django_db
def test_applicability_is_registration_and_folder_scoped_and_requires_named_human(
    regulatory_root,
):
    folder_a, entity_a, actor_a, chain_a = _make_applicability_chain("IAM-A")
    first = _record(
        actor=actor_a,
        entity=entity_a,
        chain=chain_a,
        payload=applicability_payload("IAM-A", chain=chain_a),
        idempotency_key="applicability-iam-a",
    )

    registration_blind = make_user_with_permissions(
        folder_a,
        "view_regulatorydocument",
        "view_regulatoryapplicabilitydecision",
        "view_entity",
        APPLICABILITY_PERMISSION,
    )
    with pytest.raises(PermissionDenied, match="view_entitydocumentregistration"):
        get_regulatory_applicability(
            actor=registration_blind,
            entity=entity_a,
            document_id=chain_a.document.id,
        )
    with pytest.raises(PermissionDenied, match="view_entitydocumentregistration"):
        _record(
            actor=registration_blind,
            entity=entity_a,
            chain=chain_a,
            payload=applicability_payload(
                "IAM-A",
                chain=chain_a,
                observations=[known_institution_type_observation("insurance")],
                expected_revision=1,
                expected_payload_sha256=regulatory_applicability_semantic_sha256(
                    first.decision
                ),
            ),
            idempotency_key="applicability-registration-blind",
        )

    folder_b = make_folder("Applicability IAM B")
    outsider = make_user_with_permissions(
        folder_b,
        "view_regulatorydocument",
        "view_regulatoryapplicabilitydecision",
        "view_entitydocumentregistration",
        APPLICABILITY_PERMISSION,
    )
    with pytest.raises(PermissionDenied):
        get_regulatory_applicability(
            actor=outsider,
            entity=entity_a,
            document_id=chain_a.document.id,
        )
    with pytest.raises(PermissionDenied):
        _record(
            actor=outsider,
            entity=entity_a,
            chain=chain_a,
            payload=applicability_payload(
                "IAM-A",
                chain=chain_a,
                observations=[known_institution_type_observation("insurance")],
                expected_revision=1,
                expected_payload_sha256=regulatory_applicability_semantic_sha256(
                    first.decision
                ),
            ),
            idempotency_key="applicability-cross-folder",
        )

    _, entity_two, actor_two, chain_two = _make_applicability_chain(
        "IAM-SECOND-ENTITY",
        folder=folder_a,
    )
    second_entity_result = _record(
        actor=actor_two,
        entity=entity_two,
        chain=chain_two,
        payload=applicability_payload(
            "IAM-SECOND-ENTITY",
            chain=chain_two,
            observations=[known_institution_type_observation("insurance")],
        ),
        idempotency_key="applicability-second-entity",
    )
    assert second_entity_result.decision.registration.entity_id == entity_two.id
    assert second_entity_result.decision.id != first.decision.id
    assert second_entity_result.decision.result == "not_applicable"

    permission = Permission.objects.get(
        content_type__app_label="regulatory",
        codename=APPLICABILITY_PERMISSION,
    )
    registration_view_permission = Permission.objects.get(
        content_type__app_label="regulatory",
        codename="view_entitydocumentregistration",
    )
    service_account, _ = provision_service_account(
        name="regulatory-applicability-test",
        description="Synthetic applicability service account",
        permission_ids=[permission.id, registration_view_permission.id],
        folder_ids=[folder_a.id],
        is_recursive=False,
        created_by=actor_a,
    )
    with pytest.raises(ValidationError, match="named human"):
        _record(
            actor=service_account.user,
            entity=entity_a,
            chain=chain_a,
            payload=applicability_payload(
                "IAM-A",
                chain=chain_a,
                observations=[known_institution_type_observation("insurance")],
                expected_revision=1,
                expected_payload_sha256=regulatory_applicability_semantic_sha256(
                    first.decision
                ),
            ),
            idempotency_key="applicability-service-account",
        )

    revoked = make_user_with_permissions(
        folder_a,
        APPLICABILITY_PERMISSION,
    )
    revoked.__class__.objects.filter(pk=revoked.pk).update(is_active=False)
    with pytest.raises(PermissionDenied, match="active actor"):
        _record(
            actor=revoked,
            entity=entity_a,
            chain=chain_a,
            payload=applicability_payload(
                "IAM-A",
                chain=chain_a,
                observations=[known_institution_type_observation("insurance")],
                expected_revision=1,
                expected_payload_sha256=regulatory_applicability_semantic_sha256(
                    first.decision
                ),
            ),
            idempotency_key="applicability-revoked-actor",
        )

    entity_a.__class__.objects.filter(pk=entity_a.pk).update(
        ref_id="RENAMED-AFTER-APPLICABILITY",
        folder=folder_b,
    )
    stable_read = get_regulatory_applicability(
        actor=actor_a,
        entity=entity_a,
        document_id=chain_a.document.id,
    )
    assert stable_read.decision.id == first.decision.id
    stable_retry = _record(
        actor=actor_a,
        entity=entity_a,
        chain=chain_a,
        payload=applicability_payload("IAM-A", chain=chain_a),
        idempotency_key="applicability-iam-a",
    )
    assert stable_retry.decision.id == first.decision.id
    with pytest.raises(ValidationError, match="registration folder"):
        _record(
            actor=actor_a,
            entity=entity_a,
            chain=chain_a,
            payload=applicability_payload(
                "IAM-A",
                chain=chain_a,
                observations=[known_institution_type_observation("insurance")],
                expected_revision=1,
                expected_payload_sha256=regulatory_applicability_semantic_sha256(
                    first.decision
                ),
            ),
            idempotency_key="applicability-after-entity-move",
        )
    assert RegulatoryApplicabilityDecision.objects.count() == 2


@pytest.mark.django_db
def test_applicability_decisions_are_append_only_and_database_constrained(
    regulatory_root,
):
    _, entity, actor, chain = _make_applicability_chain("IMMUTABLE")
    result = _record(
        actor=actor,
        entity=entity,
        chain=chain,
        payload=applicability_payload("IMMUTABLE", chain=chain),
        idempotency_key="applicability-immutable",
    )
    decision = result.decision

    decision.result = "not_applicable"
    with pytest.raises(ValidationError, match="append-only"):
        decision.save()
    decision.refresh_from_db()
    with pytest.raises(ValidationError, match="cannot be deleted"):
        decision.delete()

    with pytest.raises(IntegrityError), transaction.atomic():
        RegulatoryApplicabilityDecision.objects.filter(pk=decision.pk).update(
            result="approved"
        )
    with pytest.raises(IntegrityError), transaction.atomic():
        RegulatoryApplicabilityDecision.objects.filter(pk=decision.pk).update(
            digest_schema="unsupported-schema"
        )
    with pytest.raises(IntegrityError), transaction.atomic():
        RegulatoryApplicabilityDecision.objects.filter(pk=decision.pk).update(
            is_published=True
        )

    duplicate_current = copy(decision)
    duplicate_current.pk = uuid.uuid4()
    duplicate_current.id = duplicate_current.pk
    duplicate_current.revision = 2
    duplicate_current.previous_revision_id = decision.id
    duplicate_current.idempotency_key = "applicability-duplicate-current"
    duplicate_current._state.adding = True
    with pytest.raises(IntegrityError), transaction.atomic():
        RegulatoryApplicabilityDecision.objects.bulk_create([duplicate_current])

    decision.refresh_from_db()
    assert decision.result == "applicable"
    assert decision.fact_snapshot[0]["fact"] == APPLICABILITY_FACT_KEY
    assert decision.semantic_payload_sha256 == (
        regulatory_applicability_semantic_sha256(decision)
    )

    RegulatoryApplicabilityDecision.objects.filter(pk=decision.pk).update(
        fact_snapshot=[known_institution_type_observation("insurance")]
    )
    with pytest.raises(ValidationError, match="digest"):
        get_regulatory_applicability(
            actor=actor,
            entity=entity,
            document_id=chain.document.id,
        )
