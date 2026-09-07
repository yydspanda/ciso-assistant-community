"""Pure regression tests for durable SyncEvent origin classification."""

from types import SimpleNamespace
from uuid import uuid4

import pytest

from integrations.models import IntegrationSyncJob, SyncEvent
from integrations.tasks import _sync_event_triggered_by


def _job(*, direction="outbound", requested_by_id=None, authority=None):
    capability = {}
    if authority is not None:
        capability["reconciliation_authority"] = authority
    return SimpleNamespace(
        direction=direction,
        requested_by_id_snapshot=requested_by_id,
        origin_principal_snapshot=(
            f"user:{requested_by_id}"
            if requested_by_id is not None
            else "ciso-assistant:model-outbox"
        ),
        capability=capability,
    )


def _reconciliation_authority(checker_id):
    return {
        "schema": "integration-reconciliation-corrective-v1",
        "decision_id": str(uuid4()),
        "source_job_id": str(uuid4()),
        "source_request_digest": "a" * 64,
        "action": "keep_local",
        "checker_id": str(checker_id),
        "sequence": 1,
        "total": 2,
    }


def test_incoming_effect_is_always_attributed_to_webhook():
    checker_id = uuid4()
    job = _job(
        direction=IntegrationSyncJob.Direction.INCOMING,
        requested_by_id=checker_id,
        authority=_reconciliation_authority(checker_id),
    )

    assert _sync_event_triggered_by(job) == SyncEvent.TriggeredBy.WEBHOOK


def test_exact_corrective_effect_is_attributed_to_reconciliation():
    checker_id = uuid4()
    job = _job(
        requested_by_id=checker_id,
        authority=_reconciliation_authority(checker_id),
    )

    assert _sync_event_triggered_by(job) == SyncEvent.TriggeredBy.RECONCILIATION


def test_human_requested_outbound_effect_is_attributed_to_user():
    assert (
        _sync_event_triggered_by(_job(requested_by_id=uuid4()))
        == SyncEvent.TriggeredBy.USER
    )


def test_unrequested_model_outbox_effect_is_attributed_to_schedule():
    assert _sync_event_triggered_by(_job()) == SyncEvent.TriggeredBy.SCHEDULED


@pytest.mark.parametrize(
    "mutate",
    (
        lambda authority: authority.update(checker_id=str(uuid4())),
        lambda authority: authority.update(sequence=3, total=2),
        lambda authority: authority.update(source_request_digest="not-a-digest"),
        lambda authority: authority.update(unexpected="unsigned-shape"),
    ),
)
def test_malformed_corrective_context_is_not_attributed_to_reconciliation(mutate):
    checker_id = uuid4()
    authority = _reconciliation_authority(checker_id)
    mutate(authority)

    assert (
        _sync_event_triggered_by(_job(requested_by_id=checker_id, authority=authority))
        == SyncEvent.TriggeredBy.USER
    )
