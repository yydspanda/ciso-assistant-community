"""One coherent draft selection across source, applicability and review reads."""

from datetime import timedelta

import pytest
from django.core.exceptions import ValidationError
from django.utils import timezone
from rest_framework.test import APIClient

from regulatory.models import RegulatoryDocumentVersion
from regulatory.services import (
    correct_regulatory_chain,
    create_regulatory_chain,
    get_regulatory_chain,
    record_regulatory_applicability_decision,
    regulatory_chain_semantic_sha256,
    supersede_regulatory_version,
)

from .factories import (
    applicability_payload,
    chain_payload,
    correction_payload,
    make_folder,
    make_synthetic_entity,
    make_user_with_permissions,
)


def _replacement(suffix="DUAL", *, decision=False):
    folder = make_folder()
    entity = make_synthetic_entity(folder, suffix)
    actor = make_user_with_permissions(
        folder,
        "ingest_regulatoryrecord",
        "supersede_regulatoryversion",
        "correct_regulatoryrecord",
        "view_regulatorydocument",
        "view_entitydocumentregistration",
        "view_regulatoryapplicabilitydecision",
        "view_regulatoryapplicabilityreviewdisposition",
        "record_regulatoryapplicability",
    )
    old = create_regulatory_chain(
        actor=actor,
        entity=entity,
        payload=chain_payload(suffix),
        idempotency_key=f"initial-{suffix}",
    )
    if decision:
        record_regulatory_applicability_decision(
            actor=actor,
            entity=entity,
            document_id=old.document.pk,
            payload=applicability_payload(suffix, chain=old),
            idempotency_key=f"decision-{suffix}",
        )
    payload = correction_payload(
        suffix, expected_payload_sha256=regulatory_chain_semantic_sha256(old)
    )
    version, provision, obligation = (
        payload[name] for name in ("document_version", "provision", "obligation")
    )
    effective_on = timezone.now().date() + timedelta(days=30)
    version.update(
        id=f"TEST-CN-REG-{suffix}-v2",
        version_label="Synthetic future replacement",
        supersedes_version_ids=[old.document_version.record_id],
        status="published_future_effective",
        effective_date=effective_on.isoformat(),
        valid_from=effective_on.isoformat(),
        source_hash="3" * 64,
    )
    provision.update(id=f"TEST-CN-REG-{suffix}-v2-art1", version_id=version["id"])
    obligation.update(
        id=f"TEST-CN-OBL-{suffix}-v2",
        provision_ids=[provision["id"]],
        valid_from=effective_on.isoformat(),
    )
    replacement = supersede_regulatory_version(
        actor=actor,
        entity=entity,
        document_id=old.document.pk,
        payload=payload,
        rationale="Synthetic whole-version replacement only.",
        idempotency_key=f"replacement-{suffix}",
    )
    return entity, actor, old, replacement


def _read_all(client, entity, old, **selectors):
    base = f"/api/regulatory/v1/documents/{old.document.pk}/"
    responses = [client.get(base, selectors)]
    for action in ("applicability", "applicability-review"):
        responses.append(
            client.get(f"{base}{action}/", {"entity": str(entity.pk), **selectors})
        )
    return responses


@pytest.mark.django_db
def test_future_coexistence_boundary_and_three_response_anchor(regulatory_root):
    entity, actor, old, replacement = _replacement(decision=True)
    client = APIClient()
    client.force_authenticate(actor)
    cutoff = replacement.event.occurred_at
    effective_on = replacement.event.effective_on
    for valid_on, expected in (
        (effective_on - timedelta(days=1), old),
        (effective_on, replacement.chain),
        (effective_on + timedelta(days=1), replacement.chain),
    ):
        responses = _read_all(
            client,
            entity,
            old,
            recorded_as_of=cutoff.isoformat(),
            valid_on=valid_on.isoformat(),
        )
        assert [response.status_code for response in responses] == [200, 200, 200]
        bodies = [response.json() for response in responses]
        assert (
            bodies[0]["selection"] == bodies[1]["selection"] == bodies[2]["selection"]
        )
        assert bodies[0]["selection"] == {
            "version_id": expected.document_version.record_id,
            "version_revision": 1,
            "valid_on": valid_on.isoformat(),
            "recorded_at": cutoff.isoformat(),
        }
        assert len(bodies[0]["document_versions"]) == 1
        assert (
            bodies[0]["document_versions"][0]["record_id"]
            == expected.document_version.record_id
        )
        assert (
            bodies[1]["obligation_id"]
            == bodies[2]["obligation_id"]
            == expected.obligation.record_id
        )
        assert all(body["legal_conclusion"] is False for body in bodies)
        if expected is replacement.chain:
            assert bodies[1]["decision"] is None
            assert bodies[1]["non_binding_result"] == "needs_review"
            assert bodies[2]["latest_disposition"] is None
            assert bodies[0]["document_versions"][0]["supersedes_version_ids"] == [
                old.document_version.record_id
            ]

    old.document_version.refresh_from_db()
    assert old.document_version.recorded_to is None
    assert old.document_version.valid_to is None
    assert old.document_version.status == "effective"
    current = _read_all(client, entity, old)
    assert all(response.status_code == 200 for response in current)
    assert all(
        response.json()["selection"]["version_id"] == old.document_version.record_id
        for response in current
    )


@pytest.mark.django_db
def test_late_knowledge_and_explicit_future_preview_do_not_rewrite_history(
    regulatory_root,
):
    entity, actor, old, replacement = _replacement("KNOWLEDGE")
    client = APIClient()
    client.force_authenticate(actor)
    before = replacement.event.occurred_at - timedelta(microseconds=1)
    # As known before the event, even a later valid day has only the old source.
    historical = _read_all(
        client,
        entity,
        old,
        recorded_as_of=before.isoformat(),
        valid_on=replacement.event.effective_on.isoformat(),
    )
    assert all(response.status_code == 200 for response in historical)
    assert all(
        response.json()["selection"]["version_id"] == old.document_version.record_id
        for response in historical
    )
    unavailable = _read_all(
        client,
        entity,
        old,
        recorded_as_of=before.isoformat(),
        version_id=replacement.chain.document_version.record_id,
    )
    assert [response.status_code for response in unavailable] == [404, 404, 404]
    preview = _read_all(
        client,
        entity,
        old,
        version_id=replacement.chain.document_version.record_id,
        recorded_as_of=replacement.event.occurred_at.isoformat(),
    )
    assert all(response.status_code == 200 for response in preview)
    assert all(response.json()["selection"]["valid_on"] is None for response in preview)
    contradictory = _read_all(
        client,
        entity,
        old,
        version_id=old.document_version.record_id,
        valid_on=replacement.event.effective_on.isoformat(),
    )
    assert [response.status_code for response in contradictory] == [404, 404, 404]


@pytest.mark.django_db
@pytest.mark.parametrize(
    "selectors",
    [
        {"valid_on": "2026-02-30"},
        {"valid_on": "20260201"},
        {"valid_on": ""},
        {"valid_on": ["2026-01-01", "2026-01-02"]},
        {"version_id": ""},
        {"version_id": ["TEST-v1", "TEST-v2"]},
        {"version_id": " illegal version "},
    ],
)
def test_selectors_never_silently_ignored(regulatory_root, selectors):
    entity, actor, old, _ = _replacement("BAD-SELECTOR")
    client = APIClient()
    client.force_authenticate(actor)
    responses = _read_all(client, entity, old, **selectors)
    assert [response.status_code for response in responses] == [400, 400, 400]
    assert client.get("/api/regulatory/v1/documents/", selectors).status_code == 400


@pytest.mark.django_db
def test_bound_source_tamper_and_correction_fail_before_any_partial_write(
    regulatory_root,
):
    entity, actor, old, replacement = _replacement("BOUND")
    before_count = RegulatoryDocumentVersion.objects.count()
    with pytest.raises(ValidationError, match="rebind"):
        correct_regulatory_chain(
            actor=actor,
            entity=entity,
            document_id=old.document.pk,
            payload=correction_payload(
                "BOUND", expected_payload_sha256=regulatory_chain_semantic_sha256(old)
            ),
            rationale="Cannot reinterpret an existing edge.",
            idempotency_key="bound-correction",
        )
    assert RegulatoryDocumentVersion.objects.count() == before_count
    old.document_version.refresh_from_db()
    assert old.document_version.recorded_to is None

    # Privileged SQL is not the supported write path; reads still reject drift.
    RegulatoryDocumentVersion.objects.filter(pk=old.document_version.pk).update(
        version_label="Tampered after source binding"
    )
    with pytest.raises(ValidationError):
        get_regulatory_chain(actor=actor, entity=entity, document_id=old.document.pk)
    client = APIClient()
    client.force_authenticate(actor)
    assert [r.status_code for r in _read_all(client, entity, old)] == [404, 404, 404]


@pytest.mark.django_db
def test_new_decision_cannot_cross_known_replacement_boundary(regulatory_root):
    entity, actor, old, replacement = _replacement("INTERVAL")
    payload = applicability_payload("INTERVAL", chain=old)
    with pytest.raises(ValidationError, match="replacement boundary"):
        record_regulatory_applicability_decision(
            actor=actor,
            entity=entity,
            document_id=old.document.pk,
            payload=payload,
            idempotency_key="decision-boundary",
        )
    payload["valid_to"] = replacement.event.effective_on.isoformat()
    result = record_regulatory_applicability_decision(
        actor=actor,
        entity=entity,
        document_id=old.document.pk,
        payload=payload,
        idempotency_key="decision-boundary",
    )
    assert result.decision.valid_to == replacement.event.effective_on
