import pytest
from rest_framework import status
from rest_framework.test import APIClient

from regulatory.services import create_regulatory_chain
from regulatory.models import RegulatoryDocumentVersion

from .factories import (
    chain_payload,
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

    assert response.status_code == status.HTTP_200_OK
    assert response.json()["document_versions"] == []
