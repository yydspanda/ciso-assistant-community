import pytest
from copy import copy
from datetime import timedelta
import uuid
from unittest.mock import patch

from django.utils import timezone
from rest_framework import status
from rest_framework.test import APIClient

from regulatory.services import (
    correct_regulatory_chain,
    create_regulatory_chain,
    regulatory_chain_semantic_sha256,
    transition_obligation_review,
)
from regulatory.models import EntityDocumentRegistration, RegulatoryDocumentVersion

from .factories import (
    chain_payload,
    correction_payload,
    make_folder,
    make_synthetic_entity,
    make_user_with_permissions,
)


def _results(response):
    body = response.json()
    return body.get("results", body) if isinstance(body, dict) else body


@pytest.mark.django_db
def test_read_api_returns_chain_and_hides_sibling_folder(regulatory_root):
    folder_a = make_folder("API folder A")
    folder_b = make_folder("API folder B")
    entity_a = make_synthetic_entity(folder_a, "API-A")
    entity_b = make_synthetic_entity(folder_b, "API-B")
    ingester_a = make_user_with_permissions(folder_a, "ingest_regulatoryrecord")
    ingester_b = make_user_with_permissions(folder_b, "ingest_regulatoryrecord")
    chain_a = create_regulatory_chain(
        actor=ingester_a,
        entity=entity_a,
        payload=chain_payload("API-A"),
        idempotency_key="api-a",
    )
    chain_b = create_regulatory_chain(
        actor=ingester_b,
        entity=entity_b,
        payload=chain_payload("API-B"),
        idempotency_key="api-b",
    )
    second_entity_a = make_synthetic_entity(folder_a, "API-A-SECOND")
    EntityDocumentRegistration.objects.create(
        folder=folder_a,
        entity=second_entity_a,
        document=chain_a.document,
        idempotency_key="api-a-second-registration",
        payload_sha256="f" * 64,
        ingested_by=ingester_a,
    )
    reader = make_user_with_permissions(folder_a, "view_regulatorydocument")
    client = APIClient()
    client.force_authenticate(reader)

    response = client.get("/api/regulatory/v1/documents/")
    assert response.status_code == status.HTTP_200_OK
    ids = {item["id"] for item in _results(response)}
    assert str(chain_a.document.id) in ids
    assert str(chain_b.document.id) not in ids

    response = client.get(f"/api/regulatory/v1/documents/{chain_a.document.id}/")
    assert response.status_code == status.HTTP_200_OK
    body = response.json()
    assert body["folder"] == {}
    assert body["contract_status"] == "draft"
    assert body["legal_conclusion"] is False
    assert "registered_entities" not in body
    version = body["document_versions"][0]
    assert version["record_id"] == chain_a.document_version.record_id
    provision = version["provisions"][0]
    assert provision["record_id"] == chain_a.provision.record_id
    obligation = provision["obligations"][0]
    assert obligation["record_id"] == chain_a.obligation.record_id
    assert obligation["review_status"] == "machine_proposed"
    assert obligation["legal_conclusion"] is False

    response = client.get(f"/api/regulatory/v1/documents/{chain_b.document.id}/")
    assert response.status_code == status.HTTP_404_NOT_FOUND
    response = client.get(
        f"/api/regulatory/v1/documents/{chain_b.document.id}/",
        {"recorded_as_of": chain_b.document_version.recorded_from.isoformat()},
    )
    assert response.status_code == status.HTTP_404_NOT_FOUND


@pytest.mark.django_db
def test_regulatory_api_is_authenticated_and_read_only(regulatory_root):
    unauthenticated = APIClient()
    response = unauthenticated.get("/api/regulatory/v1/documents/")
    assert response.status_code == status.HTTP_401_UNAUTHORIZED

    folder = make_folder()
    reader = make_user_with_permissions(folder, "view_regulatorydocument")
    client = APIClient()
    client.force_authenticate(reader)
    for method in (client.post, client.patch, client.delete):
        response = method("/api/regulatory/v1/documents/", {}, format="json")
        assert response.status_code == status.HTTP_405_METHOD_NOT_ALLOWED

    for hidden_path in (
        "/api/regulatory/v1/documents/batch-action/",
        "/api/regulatory/v1/documents/00000000-0000-0000-0000-000000000000/object/",
        "/api/regulatory/v1/documents/00000000-0000-0000-0000-000000000000/cascade-info/",
    ):
        response = client.get(hidden_path)
        assert response.status_code == status.HTTP_404_NOT_FOUND


@pytest.mark.django_db
def test_detail_selects_one_recorded_time_chain_and_filters_review_history(
    regulatory_root,
):
    folder = make_folder("API as-of folder")
    entity = make_synthetic_entity(folder, "API-ASOF")
    actor = make_user_with_permissions(
        folder,
        "ingest_regulatoryrecord",
        "view_regulatorydocument",
        "transition_regulatoryobligation",
        "correct_regulatoryrecord",
    )
    initial = create_regulatory_chain(
        actor=actor,
        entity=entity,
        payload=chain_payload("API-ASOF"),
        idempotency_key="api-asof-initial",
    )
    before_review = timezone.now()
    review = transition_obligation_review(
        actor=actor,
        obligation_id=initial.obligation.id,
        expected_from_status="machine_proposed",
        to_status="analyst_reviewed",
        rationale="Synthetic review for historical API",
        idempotency_key="api-asof-review",
    )
    corrected = correct_regulatory_chain(
        actor=actor,
        entity=entity,
        document_id=initial.document.id,
        payload=correction_payload(
            "API-ASOF",
            expected_payload_sha256=regulatory_chain_semantic_sha256(initial),
        ),
        rationale="Synthetic correction for historical API",
        idempotency_key="api-asof-correction",
    )
    cutoff = corrected.event.occurred_at
    client = APIClient()
    client.force_authenticate(actor)
    url = f"/api/regulatory/v1/documents/{initial.document.id}/"

    response = client.get(url)
    assert response.status_code == status.HTTP_200_OK
    assert response.json()["recorded_as_of"] is None
    assert response.json()["folder"] == {}
    current_version = response.json()["document_versions"][0]
    assert current_version["revision"] == 2
    assert current_version["provisions"][0]["obligations"][0]["review_status"] == (
        "machine_proposed"
    )

    response = client.get(url, {"recorded_as_of": before_review.isoformat()})
    assert response.status_code == status.HTTP_200_OK
    historical = response.json()
    assert historical["recorded_as_of"] is not None
    assert historical["folder"] == {}
    historical_obligation = historical["document_versions"][0]["provisions"][0][
        "obligations"
    ][0]
    assert historical_obligation["revision"] == 1
    assert historical_obligation["review_status"] == "machine_proposed"

    response = client.get(
        url,
        {"recorded_as_of": review.occurred_at.isoformat()},
    )
    assert response.status_code == status.HTTP_200_OK
    reviewed = response.json()["document_versions"][0]["provisions"][0]["obligations"][
        0
    ]
    assert reviewed["revision"] == 1
    assert reviewed["review_status"] == "analyst_reviewed"

    response = client.get(
        url,
        {"recorded_as_of": (cutoff - timedelta(microseconds=1)).isoformat()},
    )
    assert response.status_code == status.HTTP_200_OK
    assert response.json()["document_versions"][0]["revision"] == 1

    response = client.get(url, {"recorded_as_of": cutoff.isoformat()})
    assert response.status_code == status.HTTP_200_OK
    assert response.json()["document_versions"][0]["revision"] == 2

    with patch(
        "regulatory.views.timezone.now",
        return_value=cutoff - timedelta(seconds=1),
    ):
        response = client.get(url)
        assert response.status_code == status.HTTP_200_OK
        assert response.json()["document_versions"][0]["revision"] == 2
        response = client.get(url, {"recorded_as_of": cutoff.isoformat()})
        assert response.status_code == status.HTTP_200_OK
        assert response.json()["document_versions"][0]["revision"] == 2

    response = client.get(
        url,
        {
            "recorded_as_of": (
                initial.document_version.recorded_from - timedelta(microseconds=1)
            ).isoformat()
        },
    )
    assert response.status_code == status.HTTP_404_NOT_FOUND


@pytest.mark.django_db
def test_recorded_as_of_parameter_fails_closed(regulatory_root):
    folder = make_folder("API as-of validation")
    entity = make_synthetic_entity(folder, "API-ASOF-VALIDATION")
    actor = make_user_with_permissions(
        folder,
        "ingest_regulatoryrecord",
        "view_regulatorydocument",
    )
    chain = create_regulatory_chain(
        actor=actor,
        entity=entity,
        payload=chain_payload("API-ASOF-VALIDATION"),
        idempotency_key="api-asof-validation",
    )
    client = APIClient()
    client.force_authenticate(actor)
    url = f"/api/regulatory/v1/documents/{chain.document.id}/"

    invalid_urls = (
        f"{url}?recorded_as_of=",
        f"{url}?recorded_as_of=2026-08-21",
        f"{url}?recorded_as_of=2026-08-21T00:00:00",
        f"{url}?recorded_as_of=2026-02-30T00:00:00Z",
        f"{url}?recorded_as_of=2026-08-21T00:00:00Z&recorded_as_of=2026-08-22T00:00:00Z",
    )
    for invalid_url in invalid_urls:
        assert client.get(invalid_url).status_code == status.HTTP_400_BAD_REQUEST

    future = (timezone.now() + timedelta(days=1)).isoformat()
    assert (
        client.get(url, {"recorded_as_of": future}).status_code
        == status.HTTP_400_BAD_REQUEST
    )
    assert (
        client.get(
            "/api/regulatory/v1/documents/",
            {"recorded_as_of": chain.document_version.recorded_from.isoformat()},
        ).status_code
        == status.HTTP_400_BAD_REQUEST
    )


@pytest.mark.django_db
def test_detail_fails_closed_if_child_folder_is_corrupted(regulatory_root):
    folder = make_folder("API aggregate folder")
    other_folder = make_folder("API corrupt child folder")
    entity = make_synthetic_entity(folder, "API-CORRUPT")
    actor = make_user_with_permissions(
        folder,
        "ingest_regulatoryrecord",
        "view_regulatorydocument",
    )
    chain = create_regulatory_chain(
        actor=actor,
        entity=entity,
        payload=chain_payload("API-CORRUPT"),
        idempotency_key="api-corrupt",
    )
    RegulatoryDocumentVersion.objects.filter(pk=chain.document_version.pk).update(
        folder=other_folder
    )

    client = APIClient()
    client.force_authenticate(actor)
    response = client.get(f"/api/regulatory/v1/documents/{chain.document.id}/")

    assert response.status_code == status.HTTP_404_NOT_FOUND


@pytest.mark.django_db
def test_detail_fails_closed_for_orphan_active_version(regulatory_root):
    folder = make_folder("API ambiguous version folder")
    entity = make_synthetic_entity(folder, "API-AMBIGUOUS")
    actor = make_user_with_permissions(
        folder,
        "ingest_regulatoryrecord",
        "view_regulatorydocument",
    )
    chain = create_regulatory_chain(
        actor=actor,
        entity=entity,
        payload=chain_payload("API-AMBIGUOUS"),
        idempotency_key="api-ambiguous",
    )
    orphan = copy(chain.document_version)
    orphan.id = uuid.uuid4()
    orphan.record_id = f"{orphan.record_id}-orphan"
    orphan.previous_revision = None
    orphan._state.adding = True
    orphan.save(force_insert=True)

    client = APIClient()
    client.force_authenticate(actor)
    response = client.get(f"/api/regulatory/v1/documents/{chain.document.id}/")

    assert response.status_code == status.HTTP_404_NOT_FOUND
