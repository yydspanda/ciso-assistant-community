from datetime import timedelta

import pytest
from django.utils import timezone
from rest_framework import status
from rest_framework.test import APIClient

from regulatory.models import EntityDocumentRegistration
from regulatory.services import (
    correct_regulatory_chain,
    create_regulatory_chain,
    record_regulatory_applicability_decision,
    regulatory_chain_semantic_sha256,
)

from .factories import (
    applicability_payload,
    chain_payload,
    correction_payload,
    make_folder,
    make_synthetic_entity,
    make_user_with_permissions,
)


def _make_chain(suffix: str, *, permissions: tuple[str, ...] = ()):
    folder = make_folder(f"Applicability API {suffix}")
    entity = make_synthetic_entity(folder, suffix)
    actor = make_user_with_permissions(
        folder,
        "ingest_regulatoryrecord",
        "view_regulatorydocument",
        "view_regulatoryapplicabilitydecision",
        "view_entity",
        *permissions,
        email_prefix="applicability-api",
    )
    chain = create_regulatory_chain(
        actor=actor,
        entity=entity,
        payload=chain_payload(suffix),
        idempotency_key=f"applicability-api-chain-{suffix}",
    )
    return folder, entity, actor, chain


def _url(chain) -> str:
    return f"/api/regulatory/v1/documents/{chain.document.id}/applicability/"


@pytest.mark.django_db
def test_applicability_api_requires_separate_view_permission_and_is_read_only(
    regulatory_root,
):
    folder, entity, actor, chain = _make_chain(
        "READ",
        permissions=("record_regulatoryapplicability",),
    )
    reader = make_user_with_permissions(
        folder,
        "view_regulatorydocument",
        "view_entity",
        email_prefix="applicability-reader",
    )
    client = APIClient()
    client.force_authenticate(reader)

    response = client.get(_url(chain), {"entity": str(entity.id)})

    assert response.status_code == status.HTTP_403_FORBIDDEN

    entity_blind = make_user_with_permissions(
        folder,
        "view_regulatorydocument",
        "view_regulatoryapplicabilitydecision",
        email_prefix="applicability-entity-blind",
    )
    client.force_authenticate(entity_blind)
    response = client.get(_url(chain), {"entity": str(entity.id)})
    assert response.status_code == status.HTTP_403_FORBIDDEN

    client.force_authenticate(actor)
    response = client.get(_url(chain), {"entity": str(entity.id)})
    assert response.status_code == status.HTTP_200_OK
    assert response.json()["evaluation_status"] == "not_evaluated"
    assert response.json()["non_binding_result"] == "needs_review"
    assert response.json()["reason_code"] == (
        "no_decision_for_selected_obligation_revision"
    )
    assert response.json()["decision"] is None

    result = record_regulatory_applicability_decision(
        actor=actor,
        entity=entity,
        document_id=chain.document.id,
        payload=applicability_payload("READ", chain=chain),
        idempotency_key="applicability-api-decision-read",
    )
    response = client.get(_url(chain), {"entity": str(entity.id)})

    assert response.status_code == status.HTTP_200_OK
    body = response.json()
    assert body["contract_status"] == "draft"
    assert body["legal_conclusion"] is False
    assert body["is_binding"] is False
    assert body["scope"] == {"type": "legal_entity", "id": str(entity.id)}
    assert body["obligation_id"] == chain.obligation.record_id
    assert body["obligation_revision"] == 1
    assert body["recorded_as_of"] is None
    assert body["evaluation_status"] == "evaluated"
    assert body["non_binding_result"] == "applicable"
    assert body["decision"]["id"] == str(result.decision.id)
    assert body["decision"]["legal_conclusion"] is False
    assert body["decision"]["is_binding"] is False
    assert body["decision"]["review_status"] == "draft"
    assert body["decision"]["facts"][0]["source_refs"] == [
        "test:synthetic-institution-register"
    ]
    assert body["decision"]["provenance"]["method"] == "human"
    assert "idempotency_key" not in body["decision"]
    assert "request_sha256" not in body["decision"]
    assert "recorded_by" not in body["decision"]

    for method in (client.post, client.put):
        response = method(
            _url(chain),
            {"entity": str(entity.id)},
            format="json",
        )
        assert response.status_code == status.HTTP_405_METHOD_NOT_ALLOWED


@pytest.mark.django_db
def test_applicability_api_validates_entity_and_recorded_time_strictly(
    regulatory_root,
):
    _, entity, actor, chain = _make_chain("INPUT")
    client = APIClient()
    client.force_authenticate(actor)
    url = _url(chain)

    for invalid_url in (
        url,
        f"{url}?entity=",
        f"{url}?entity={entity.id}&entity={entity.id}",
    ):
        assert client.get(invalid_url).status_code == status.HTTP_400_BAD_REQUEST

    assert (
        client.get(url, {"entity": "not-a-uuid"}).status_code
        == status.HTTP_404_NOT_FOUND
    )
    assert (
        client.get(
            url,
            {"entity": "00000000-0000-0000-0000-000000000000"},
        ).status_code
        == status.HTTP_404_NOT_FOUND
    )

    invalid_recorded_urls = (
        f"{url}?entity={entity.id}&recorded_as_of=",
        f"{url}?entity={entity.id}&recorded_as_of=2026-08-21",
        f"{url}?entity={entity.id}&recorded_as_of=2026-08-21T00:00:00",
        (
            f"{url}?entity={entity.id}"
            "&recorded_as_of=2026-08-21T00:00:00Z"
            "&recorded_as_of=2026-08-22T00:00:00Z"
        ),
    )
    for invalid_url in invalid_recorded_urls:
        assert client.get(invalid_url).status_code == status.HTTP_400_BAD_REQUEST

    future = (timezone.now() + timedelta(days=1)).isoformat()
    response = client.get(
        url,
        {"entity": str(entity.id), "recorded_as_of": future},
    )
    assert response.status_code == status.HTTP_400_BAD_REQUEST

    before_chain = chain.document_version.recorded_from - timedelta(microseconds=1)
    response = client.get(
        url,
        {
            "entity": str(entity.id),
            "recorded_as_of": before_chain.isoformat(),
        },
    )
    assert response.status_code == status.HTTP_404_NOT_FOUND


@pytest.mark.django_db
def test_applicability_api_hides_sibling_folder_document_and_entity(
    regulatory_root,
):
    _, entity_a, actor_a, chain_a = _make_chain("SCOPE-A")
    _, entity_b, _, chain_b = _make_chain("SCOPE-B")
    client = APIClient()
    client.force_authenticate(actor_a)

    response = client.get(_url(chain_b), {"entity": str(entity_b.id)})
    assert response.status_code == status.HTTP_404_NOT_FOUND

    response = client.get(_url(chain_a), {"entity": str(entity_b.id)})
    assert response.status_code == status.HTTP_404_NOT_FOUND

    response = client.get(_url(chain_a), {"entity": str(entity_a.id)})
    assert response.status_code == status.HTTP_200_OK


@pytest.mark.django_db
def test_applicability_api_isolates_two_entities_registered_to_one_document(
    regulatory_root,
):
    folder, first_entity, actor, chain = _make_chain(
        "TWO-ENTITIES",
        permissions=("record_regulatoryapplicability",),
    )
    second_entity = make_synthetic_entity(folder, "TWO-ENTITIES-SECOND")
    EntityDocumentRegistration.objects.create(
        folder=folder,
        entity=second_entity,
        document=chain.document,
        idempotency_key="applicability-api-second-registration",
        payload_sha256="f" * 64,
        ingested_by=actor,
    )
    recorded = record_regulatory_applicability_decision(
        actor=actor,
        entity=first_entity,
        document_id=chain.document.id,
        payload=applicability_payload("TWO-ENTITIES", chain=chain),
        idempotency_key="applicability-api-first-entity-decision",
    )
    client = APIClient()
    client.force_authenticate(actor)

    first = client.get(_url(chain), {"entity": str(first_entity.id)})
    second = client.get(_url(chain), {"entity": str(second_entity.id)})

    assert first.status_code == status.HTTP_200_OK
    assert first.json()["evaluation_status"] == "evaluated"
    assert first.json()["decision"]["id"] == str(recorded.decision.id)
    assert second.status_code == status.HTTP_200_OK
    assert second.json()["scope"]["id"] == str(second_entity.id)
    assert second.json()["evaluation_status"] == "not_evaluated"
    assert second.json()["non_binding_result"] == "needs_review"
    assert second.json()["decision"] is None


@pytest.mark.django_db
def test_applicability_api_does_not_inherit_decision_after_obligation_correction(
    regulatory_root,
):
    _, entity, actor, chain = _make_chain(
        "CORRECTION",
        permissions=(
            "record_regulatoryapplicability",
            "correct_regulatoryrecord",
        ),
    )
    recorded = record_regulatory_applicability_decision(
        actor=actor,
        entity=entity,
        document_id=chain.document.id,
        payload=applicability_payload("CORRECTION", chain=chain),
        idempotency_key="applicability-api-before-correction",
    )
    corrected = correct_regulatory_chain(
        actor=actor,
        entity=entity,
        document_id=chain.document.id,
        payload=correction_payload(
            "CORRECTION",
            expected_payload_sha256=regulatory_chain_semantic_sha256(chain),
        ),
        rationale="Correct the exact synthetic obligation for API isolation",
        idempotency_key="applicability-api-correction",
    )
    client = APIClient()
    client.force_authenticate(actor)

    current = client.get(_url(chain), {"entity": str(entity.id)})

    assert current.status_code == status.HTTP_200_OK
    assert current.json()["obligation_revision"] == 2
    assert current.json()["evaluation_status"] == "not_evaluated"
    assert current.json()["non_binding_result"] == "needs_review"
    assert current.json()["decision"] is None

    historical_at = corrected.event.occurred_at - timedelta(microseconds=1)
    historical = client.get(
        _url(chain),
        {
            "entity": str(entity.id),
            "recorded_as_of": historical_at.isoformat(),
        },
    )

    assert historical.status_code == status.HTTP_200_OK
    assert historical.json()["obligation_revision"] == 1
    assert historical.json()["evaluation_status"] == "evaluated"
    assert historical.json()["decision"]["id"] == str(recorded.decision.id)
    assert historical.json()["recorded_as_of"] == historical_at.isoformat()
