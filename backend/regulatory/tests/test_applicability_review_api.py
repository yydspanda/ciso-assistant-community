from datetime import timedelta

import pytest
from django.contrib.auth.models import Permission
from django.utils import timezone
from rest_framework import status
from rest_framework.test import APIClient

from core.startup import (
    ADMINISTRATOR_PERMISSIONS_LIST,
    ANALYST_PERMISSIONS_LIST,
    APPROVER_PERMISSIONS_LIST,
    READER_PERMISSIONS_LIST,
)
from iam.models import RoleAssignment
from regulatory.services import (
    create_regulatory_chain,
    record_regulatory_applicability_decision,
    record_regulatory_applicability_review_disposition,
)

from .factories import (
    applicability_payload,
    applicability_review_payload,
    chain_payload,
    known_institution_type_observation,
    make_folder,
    make_synthetic_entity,
    make_user_with_permissions,
    unknown_institution_type_observation,
)


READ_PERMISSIONS = (
    "view_regulatorydocument",
    "view_entitydocumentregistration",
    "view_regulatoryapplicabilitydecision",
    "view_regulatoryapplicabilityreviewdisposition",
)


def _make_scope(suffix: str, *, record_decision: bool = False, observations=None):
    folder = make_folder(f"Applicability review API {suffix}")
    entity = make_synthetic_entity(folder, suffix)
    maker = make_user_with_permissions(
        folder,
        "ingest_regulatoryrecord",
        "record_regulatoryapplicability",
        "view_regulatorydocument",
        "view_entitydocumentregistration",
        "view_regulatoryapplicabilitydecision",
        email_prefix="applicability-review-maker",
    )
    chain = create_regulatory_chain(
        actor=maker,
        entity=entity,
        payload=chain_payload(suffix),
        idempotency_key=f"applicability-review-api-chain-{suffix}",
    )
    reviewer = make_user_with_permissions(
        folder,
        *READ_PERMISSIONS,
        "review_regulatoryapplicability",
        email_prefix="applicability-review-reviewer",
    )
    reviewer.first_name = "Synthetic"
    reviewer.last_name = "Reviewer"
    reviewer.save(update_fields=["first_name", "last_name"])
    reader = make_user_with_permissions(
        folder,
        *READ_PERMISSIONS,
        email_prefix="applicability-review-reader",
    )
    scope = {
        "folder": folder,
        "entity": entity,
        "maker": maker,
        "reviewer": reviewer,
        "reader": reader,
        "chain": chain,
        "decision": None,
    }
    if record_decision:
        scope["decision"] = _record_decision(
            scope,
            suffix,
            observations=observations,
        )
    return scope


def _record_decision(scope, suffix: str, *, observations=None):
    return record_regulatory_applicability_decision(
        actor=scope["maker"],
        entity=scope["entity"],
        document_id=scope["chain"].document.id,
        payload=applicability_payload(
            suffix,
            chain=scope["chain"],
            observations=observations,
        ),
        idempotency_key=f"applicability-review-api-decision-{suffix}",
    ).decision


def _record_disposition(
    scope,
    suffix: str,
    *,
    to_disposition="no_correction_requested",
    reason_code=None,
    rationale=None,
    expected_disposition=None,
):
    return record_regulatory_applicability_review_disposition(
        actor=scope["reviewer"],
        entity=scope["entity"],
        document_id=scope["chain"].document.id,
        payload=applicability_review_payload(
            suffix,
            decision=scope["decision"],
            expected_disposition=expected_disposition,
            to_disposition=to_disposition,
            reason_code=reason_code,
            rationale=rationale,
        ),
        idempotency_key=f"applicability-review-api-event-{suffix}",
    ).disposition


def _url(scope) -> str:
    return (
        f"/api/regulatory/v1/documents/{scope['chain'].document.id}/"
        "applicability-review/"
    )


def _applicability_url(scope) -> str:
    return f"/api/regulatory/v1/documents/{scope['chain'].document.id}/applicability/"


def _get(client: APIClient, scope, **params):
    return client.get(
        _url(scope),
        {"entity": str(scope["entity"].id), **params},
    )


@pytest.mark.django_db
def test_applicability_review_api_requires_every_read_gate_and_derives_absence(
    regulatory_root,
):
    scope = _make_scope("READ-GATES")
    url = _url(scope)

    assert (
        APIClient().get(url, {"entity": str(scope["entity"].id)}).status_code
        == status.HTTP_401_UNAUTHORIZED
    )

    permission_cases = (
        (
            (
                "view_regulatoryapplicabilitydecision",
                "view_regulatoryapplicabilityreviewdisposition",
                "view_entitydocumentregistration",
            ),
            status.HTTP_404_NOT_FOUND,
        ),
        (
            (
                "view_regulatorydocument",
                "view_regulatoryapplicabilitydecision",
                "view_entitydocumentregistration",
            ),
            status.HTTP_403_FORBIDDEN,
        ),
        (
            (
                "view_regulatorydocument",
                "view_regulatoryapplicabilityreviewdisposition",
                "view_entitydocumentregistration",
            ),
            status.HTTP_403_FORBIDDEN,
        ),
        (
            (
                "view_regulatorydocument",
                "view_regulatoryapplicabilitydecision",
                "view_regulatoryapplicabilityreviewdisposition",
                "view_entity",
            ),
            status.HTTP_403_FORBIDDEN,
        ),
    )
    client = APIClient()
    for index, (permissions, expected_status) in enumerate(permission_cases):
        user = make_user_with_permissions(
            scope["folder"],
            *permissions,
            email_prefix=f"applicability-review-gate-{index}",
        )
        client.force_authenticate(user)
        assert _get(client, scope).status_code == expected_status

    client.force_authenticate(scope["reader"])
    response = _get(client, scope)
    assert response.status_code == status.HTTP_200_OK
    body = response.json()
    assert body["evaluation_status"] == "not_evaluated"
    assert body["computed_non_binding_result"] == "needs_review"
    assert body["review_state"] == "not_reviewable"
    assert body["workflow_attention"] == "needs_review"
    assert body["decision"] is None
    assert body["latest_disposition"] is None

    scope["decision"] = _record_decision(scope, "READ-GATES")
    response = _get(client, scope)
    assert response.status_code == status.HTTP_200_OK
    body = response.json()
    assert body["evaluation_status"] == "evaluated"
    assert body["decision"]["id"] == str(scope["decision"].id)
    assert body["review_state"] == "not_reviewed"
    assert body["workflow_attention"] == "needs_review"
    assert body["latest_disposition"] is None


@pytest.mark.django_db
@pytest.mark.parametrize(
    ("role_name", "role_permissions", "expected_status"),
    (
        ("reader", READER_PERMISSIONS_LIST, status.HTTP_403_FORBIDDEN),
        ("analyst", ANALYST_PERMISSIONS_LIST, status.HTTP_200_OK),
        ("approver", APPROVER_PERMISSIONS_LIST, status.HTTP_200_OK),
        ("administrator", ADMINISTRATOR_PERMISSIONS_LIST, status.HTTP_200_OK),
    ),
)
def test_builtin_role_read_matrix(
    regulatory_root,
    role_name,
    role_permissions,
    expected_status,
):
    scope = _make_scope(f"ROLE-{role_name.upper()}", record_decision=True)
    effective_read_permissions = tuple(
        permission for permission in READ_PERMISSIONS if permission in role_permissions
    )
    user = make_user_with_permissions(
        scope["folder"],
        *effective_read_permissions,
        email_prefix=f"applicability-review-{role_name}",
    )
    client = APIClient()
    client.force_authenticate(user)

    response = _get(client, scope)

    assert response.status_code == expected_status
    if expected_status == status.HTTP_200_OK:
        assert response.json()["review_state"] == "not_reviewed"


@pytest.mark.django_db
@pytest.mark.parametrize(
    ("to_disposition", "reason_code", "expected_attention"),
    (
        ("no_correction_requested", "review_completed", "reviewed_nonbinding"),
        ("correction_requested", "fact_correction_required", "needs_review"),
        ("unable_to_complete", "insufficient_evidence", "needs_review"),
    ),
)
def test_applicability_review_api_returns_each_bounded_disposition(
    regulatory_root,
    to_disposition,
    reason_code,
    expected_attention,
):
    suffix = f"STATE-{to_disposition.upper().replace('_', '-')}"
    scope = _make_scope(suffix, record_decision=True)
    rationale = f"Synthetic API rationale for {to_disposition}"
    disposition = _record_disposition(
        scope,
        suffix,
        to_disposition=to_disposition,
        reason_code=reason_code,
        rationale=rationale,
    )
    client = APIClient()
    client.force_authenticate(scope["reader"])

    response = _get(client, scope)

    assert response.status_code == status.HTTP_200_OK
    body = response.json()
    assert body["contract_status"] == "draft"
    assert body["legal_conclusion"] is False
    assert body["is_binding"] is False
    assert body["computed_non_binding_result"] == "applicable"
    assert body["review_state"] == to_disposition
    assert body["workflow_attention"] == expected_attention
    event = body["latest_disposition"]
    assert event["id"] == str(disposition.id)
    assert event["sequence"] == 1
    assert event["from_disposition"] == "not_reviewed"
    assert event["to_disposition"] == to_disposition
    assert event["reason_code"] == reason_code
    assert event["rationale"] == rationale
    assert event["digest_profile"] == ("regulatory-applicability-review-disposition/v1")
    assert (
        event["decision_semantic_payload_sha256"]
        == (body["decision"]["semantic_payload_sha256"])
    )
    assert event["event_payload_sha256"] == disposition.event_payload_sha256
    assert event["reviewer"] == {"masked": True}
    for private_field in (
        "idempotency_key",
        "request_sha256",
        "decision_recorded_by",
    ):
        assert private_field not in event


@pytest.mark.django_db
def test_no_correction_requested_never_clears_unknown_fact_attention(regulatory_root):
    scope = _make_scope(
        "UNKNOWN-FACT",
        record_decision=True,
        observations=[unknown_institution_type_observation()],
    )
    _record_disposition(scope, "UNKNOWN-FACT")
    client = APIClient()
    client.force_authenticate(scope["reader"])

    response = _get(client, scope)

    assert response.status_code == status.HTTP_200_OK
    body = response.json()
    assert body["computed_non_binding_result"] == "needs_review"
    assert body["review_state"] == "no_correction_requested"
    assert body["workflow_attention"] == "needs_review"


@pytest.mark.django_db
def test_applicability_review_api_selects_the_same_recorded_time(regulatory_root):
    scope = _make_scope("AS-OF", record_decision=True)
    disposition = _record_disposition(scope, "AS-OF")
    client = APIClient()
    client.force_authenticate(scope["reader"])
    before_event = disposition.occurred_at - timedelta(microseconds=1)

    before = _get(client, scope, recorded_as_of=before_event.isoformat())
    at_event = _get(
        client,
        scope,
        recorded_as_of=disposition.occurred_at.isoformat(),
    )

    assert before.status_code == status.HTTP_200_OK
    assert before.json()["review_state"] == "not_reviewed"
    assert before.json()["latest_disposition"] is None
    assert before.json()["recorded_as_of"] == before_event.isoformat()
    assert at_event.status_code == status.HTTP_200_OK
    assert at_event.json()["review_state"] == "no_correction_requested"
    assert at_event.json()["latest_disposition"]["id"] == str(disposition.id)

    duplicate_time_url = (
        f"{_url(scope)}?entity={scope['entity'].id}"
        f"&recorded_as_of={before_event.isoformat()}"
        f"&recorded_as_of={disposition.occurred_at.isoformat()}"
    )
    assert client.get(duplicate_time_url).status_code == status.HTTP_400_BAD_REQUEST
    assert (
        _get(client, scope, recorded_as_of="2026-08-21T00:00:00").status_code
        == status.HTTP_400_BAD_REQUEST
    )
    future = (timezone.now() + timedelta(days=1)).isoformat()
    assert (
        _get(client, scope, recorded_as_of=future).status_code
        == status.HTTP_400_BAD_REQUEST
    )


@pytest.mark.django_db
def test_applicability_review_api_masks_and_safely_unmasks_reviewer(
    regulatory_root,
):
    scope = _make_scope("REVIEWER-IAM", record_decision=True)
    _record_disposition(scope, "REVIEWER-IAM")
    client = APIClient()

    client.force_authenticate(scope["reviewer"])
    self_visible = _get(client, scope)
    assert self_visible.status_code == status.HTTP_200_OK
    assert self_visible.json()["latest_disposition"]["reviewer"] == {
        "masked": False,
        "id": str(scope["reviewer"].id),
        "display_name": "Synthetic Reviewer",
    }
    assert scope["reviewer"].email not in self_visible.content.decode()

    client.force_authenticate(scope["reader"])

    hidden = _get(client, scope)

    assert hidden.status_code == status.HTTP_200_OK
    assert hidden.json()["latest_disposition"]["reviewer"] == {"masked": True}
    assert scope["reviewer"].email not in hidden.content.decode()

    assignment = RoleAssignment.objects.get(user=scope["reader"])
    assignment.role.permissions.add(
        Permission.objects.get(
            content_type__app_label="iam",
            codename="view_user",
        )
    )
    visible = _get(client, scope)

    assert visible.status_code == status.HTTP_200_OK
    assert visible.json()["latest_disposition"]["reviewer"] == {
        "masked": False,
        "id": str(scope["reviewer"].id),
        "display_name": "Synthetic Reviewer",
    }
    assert scope["reviewer"].email not in visible.content.decode()


@pytest.mark.django_db
def test_successor_decision_starts_not_reviewed_and_keeps_d1_history(regulatory_root):
    scope = _make_scope("D1-D2", record_decision=True)
    first_decision = scope["decision"]
    first_disposition = _record_disposition(scope, "D1-D2")
    second_decision = record_regulatory_applicability_decision(
        actor=scope["maker"],
        entity=scope["entity"],
        document_id=scope["chain"].document.id,
        payload=applicability_payload(
            "D1-D2",
            chain=scope["chain"],
            observations=[known_institution_type_observation("insurance")],
            expected_revision=first_decision.revision,
            expected_payload_sha256=first_decision.semantic_payload_sha256,
        ),
        idempotency_key="applicability-review-api-decision-D1-D2-r2",
    ).decision
    scope["decision"] = second_decision
    client = APIClient()
    client.force_authenticate(scope["reader"])

    current = _get(client, scope)
    historical_at = second_decision.recorded_from - timedelta(microseconds=1)
    historical = _get(client, scope, recorded_as_of=historical_at.isoformat())

    assert current.status_code == status.HTTP_200_OK
    assert current.json()["decision"]["id"] == str(second_decision.id)
    assert current.json()["computed_non_binding_result"] == "not_applicable"
    assert current.json()["review_state"] == "not_reviewed"
    assert current.json()["latest_disposition"] is None
    assert historical.status_code == status.HTTP_200_OK
    assert historical.json()["decision"]["id"] == str(first_decision.id)
    assert historical.json()["review_state"] == "no_correction_requested"
    assert historical.json()["latest_disposition"]["id"] == str(first_disposition.id)


@pytest.mark.django_db
def test_review_state_does_not_leak_to_original_endpoint_and_writes_are_hidden(
    regulatory_root,
):
    scope = _make_scope("READ-ONLY", record_decision=True)
    rationale = "Unique disposition rationale must stay on the review endpoint"
    _record_disposition(scope, "READ-ONLY", rationale=rationale)
    client = APIClient()
    client.force_authenticate(scope["reader"])

    original = client.get(
        _applicability_url(scope),
        {"entity": str(scope["entity"].id)},
    )

    assert original.status_code == status.HTTP_200_OK
    for review_field in (
        "review_state",
        "workflow_attention",
        "latest_disposition",
        "reviewer",
    ):
        assert review_field not in original.json()
    assert rationale not in original.content.decode()
    assert scope["reviewer"].email not in original.content.decode()

    write_url = f"{_url(scope)}?entity={scope['entity'].id}"
    for method in (client.post, client.put, client.patch, client.delete):
        response = method(write_url, {}, format="json")
        assert response.status_code == status.HTTP_405_METHOD_NOT_ALLOWED
