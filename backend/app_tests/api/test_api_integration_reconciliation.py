import uuid
from datetime import datetime, timedelta

import pytest
from allauth.idp.oidc.models import Client
from core.models import AppliedControl, Asset
from django.contrib.auth.models import Permission
from django.contrib.contenttypes.models import ContentType
from django.core.exceptions import ValidationError as DjangoValidationError
from django.db import transaction
from django.utils import timezone
from iam.models import Folder, Role, RoleAssignment, ServiceAccount, User
from integrations.capabilities import (
    authority_hmac,
    canonical_sha256,
    configuration_authority_hmac,
    model_row_authority_hmac,
    persist_outbound_sync_jobs,
)
from integrations.models import (
    IntegrationConfiguration,
    IntegrationProvider,
    IntegrationReconciliationDecision,
    IntegrationSyncJob,
    SyncEvent,
    SyncMapping,
)
from knox.models import AuthToken
from rest_framework.test import APIClient

RECONCILER_PERMISSIONS = {
    "view_folder",
    "view_asset",
    "change_asset",
    "view_appliedcontrol",
    "change_appliedcontrol",
    "view_integrationprovider",
    "view_integrationconfiguration",
    "change_integrationconfiguration",
    "view_syncmapping",
    "change_syncmapping",
    "reconcile_integrationsyncjob",
}


def _client(user):
    client = APIClient()
    _, token = AuthToken.objects.create(user=user)
    client.credentials(HTTP_AUTHORIZATION=f"Token {token}")
    return client


def _user_with_permissions(folder, codenames):
    suffix = uuid.uuid4().hex[:8]
    role = Role.objects.create(name=f"sync-reconciler-{suffix}", folder=folder)
    role.permissions.set(Permission.objects.filter(codename__in=codenames))
    user = User.objects.create_user(
        f"sync-reconciler-{suffix}@tests.example", is_published=True
    )
    user.folder = folder
    user.save(update_fields=["folder"])
    assignment = RoleAssignment.objects.create(
        user=user,
        role=role,
        folder=folder,
        is_recursive=True,
    )
    assignment.perimeter_folders.add(folder)
    return user


@pytest.fixture
def reconciliation_world(app_config):
    _ = app_config  # Initializes the integration registry for real orchestrators.
    root = Folder.get_root_folder()
    folder = Folder.objects.create(
        name=f"sync-reconcile-{uuid.uuid4().hex[:8]}",
        parent_folder=root,
        content_type=Folder.ContentType.DOMAIN,
    )
    provider = IntegrationProvider.objects.create(
        name="servicenow",
        provider_type=IntegrationProvider.ProviderType.ITSM,
        folder=folder,
    )
    configuration = IntegrationConfiguration.objects.create(
        provider=provider,
        folder=folder,
        credentials={
            "instance_url": "https://example.service-now.com",
            "username": "user",
            "password": "secret",
        },
        settings={
            "enable_outgoing_sync": True,
            "enable_incoming_sync": True,
            "models": {
                "asset": {
                    "table_name": "cmdb_ci",
                    "field_map": {"name": "u_name"},
                }
            },
        },
        webhook_secret="webhook-secret",
    )
    asset = Asset.objects.create(name="Server", folder=folder, type="PR")
    baseline_version = timezone.now() - timedelta(minutes=5)
    mapping = SyncMapping.objects.create(
        configuration=configuration,
        content_type=ContentType.objects.get_for_model(Asset),
        local_object_id=asset.id,
        remote_id="sys1",
        remote_data={
            "key": "sys1",
            "updated": baseline_version.isoformat(),
            "fields": {"u_name": "Server"},
        },
        folder=folder,
        last_synced_at=baseline_version,
    )
    with transaction.atomic():
        [job_id] = persist_outbound_sync_jobs(
            content_type_id=mapping.content_type_id,
            object_id=asset.id,
            configuration_ids=[configuration.id],
            changed_fields=["name"],
        )
    job = IntegrationSyncJob.objects.get(id=job_id)
    job.status = IntegrationSyncJob.Status.UNCERTAIN
    job.failure_code = "provider_result_uncertain"
    job.attempt_id = uuid.uuid4()
    job.claimed_at = job.created_at
    job.effect_started_at = job.created_at
    job.terminal_at = job.created_at
    job.save(
        update_fields=[
            "status",
            "failure_code",
            "attempt_id",
            "claimed_at",
            "effect_started_at",
            "terminal_at",
            "updated_at",
        ]
    )
    return {
        "folder": folder,
        "provider": provider,
        "configuration": configuration,
        "asset": asset,
        "mapping": mapping,
        "job": job,
    }


def _make_manual_review_job(world):
    from integrations.capabilities import persist_webhook_sync_job
    from integrations.tasks import process_webhook_event

    world["job"].delete()
    configuration = world["configuration"]
    configuration.settings = {
        **configuration.settings,
        "conflict_resolution": "manual",
    }
    configuration.save(update_fields=["settings", "updated_at"])
    asset = world["asset"]
    asset.name = "Locally reviewed name"
    asset.save(skip_sync=True)
    payload = {
        "sys_id": world["mapping"].remote_id,
        "sys_updated_on": timezone.now().isoformat(),
        "u_name": "Remote name",
    }
    job_id = persist_webhook_sync_job(
        authenticated_configuration=configuration,
        authenticated_configuration_hmac_sha256=configuration_authority_hmac(
            configuration
        ),
        authenticated_provider_hmac_sha256=model_row_authority_hmac(
            configuration.provider
        ),
        authenticated_body_hmac_sha256=authority_hmac(
            canonical_sha256(payload),
            domain="integration-webhook-authenticated-body-v1",
        ),
        remote_id=world["mapping"].remote_id,
        event_type="sn_update",
        payload=payload,
    )
    assert job_id is not None
    assert process_webhook_event.call_local(job_id) == "review_required"
    return IntegrationSyncJob.objects.get(id=job_id)


def _make_jira_manual_review_world(world):
    from integrations.capabilities import persist_webhook_sync_job
    from integrations.tasks import process_webhook_event

    folder = world["folder"]
    provider = IntegrationProvider.objects.create(
        name="jira",
        provider_type=IntegrationProvider.ProviderType.ITSM,
        folder=folder,
    )
    configuration = IntegrationConfiguration.objects.create(
        provider=provider,
        folder=folder,
        credentials={
            "server_url": "https://jira.example.com",
            "email": "user@example.com",
            "api_token": "secret",
        },
        settings={
            "enable_outgoing_sync": True,
            "enable_incoming_sync": True,
            "conflict_resolution": "manual",
            "table_name": "PROJ:Task",
            "field_map": {"name": "summary", "status": "status"},
            "value_map": {
                "status": {
                    "to_do": "To Do",
                    "in_progress": "In Progress",
                }
            },
        },
        webhook_secret="webhook-secret",
    )
    baseline_version = timezone.now() - timedelta(minutes=5)
    control = AppliedControl.objects.create(
        name="Local control",
        status=AppliedControl.Status.IN_PROGRESS,
        folder=folder,
    )
    mapping = SyncMapping.objects.create(
        configuration=configuration,
        content_type=ContentType.objects.get_for_model(AppliedControl),
        local_object_id=control.id,
        remote_id="PROJ-1",
        remote_data={
            "key": "PROJ-1",
            "updated": baseline_version.isoformat(),
            "fields": {
                "summary": "Earlier control",
                "status": {"name": "In Progress"},
            },
        },
        folder=folder,
        last_synced_at=baseline_version,
    )
    control.name = "Locally reviewed control"
    control.save(skip_sync=True)
    payload = {
        "webhookEvent": "jira:issue_updated",
        "issue": {
            "key": "PROJ-1",
            "fields": {
                "summary": "Remote control",
                "status": {"name": "To Do"},
                "updated": timezone.now().isoformat(),
            },
        },
    }
    job_id = persist_webhook_sync_job(
        authenticated_configuration=configuration,
        authenticated_configuration_hmac_sha256=configuration_authority_hmac(
            configuration
        ),
        authenticated_provider_hmac_sha256=model_row_authority_hmac(provider),
        authenticated_body_hmac_sha256=authority_hmac(
            canonical_sha256(payload),
            domain="integration-webhook-authenticated-body-v1",
        ),
        remote_id="PROJ-1",
        event_type="jira:issue_updated",
        payload=payload,
    )
    assert job_id is not None
    assert process_webhook_event.call_local(job_id) == "review_required"
    return {
        "configuration": configuration,
        "control": control,
        "mapping": mapping,
        "review_job": IntegrationSyncJob.objects.get(id=job_id),
    }


def _receipt(job, *, outcome, remote_id, remote_data, **overrides):
    receipt = {
        "schema_version": "provider-receipt-v1",
        "provider_id": str(job.provider_id_snapshot),
        "provider_event_id": f"provider-event-{uuid.uuid4().hex}",
        "request_digest": job.request_digest,
        "remote_id": remote_id,
        "outcome": outcome,
        "observed_at": timezone.now().isoformat(),
        "evidence_reference": "provider-audit:change-0001",
        "remote_data_sha256": canonical_sha256(remote_data),
    }
    receipt.update(overrides)
    return receipt


@pytest.mark.django_db
def test_checker_can_confirm_exact_uncertain_effect(reconciliation_world):
    world = reconciliation_world
    checker = _user_with_permissions(world["folder"], RECONCILER_PERMISSIONS)

    remote_data = {
        "key": "sys1",
        "updated": timezone.now().isoformat(),
        "fields": {"u_name": "confirmed"},
    }
    response = _client(checker).post(
        f"/api/integrations/sync-jobs/{world['job'].id}/reconcile/",
        {
            "action": "confirm_applied",
            "reason": "Provider audit log confirms this exact operation.",
            "remote_data": remote_data,
            "provider_receipt": _receipt(
                world["job"],
                outcome="applied",
                remote_id="SYS1",
                remote_data=remote_data,
            ),
        },
        format="json",
    )

    assert response.status_code == 200, response.content
    world["job"].refresh_from_db()
    world["mapping"].refresh_from_db()
    assert world["job"].status == IntegrationSyncJob.Status.SUCCEEDED
    assert world["job"].payload == {}
    assert world["job"].reconciled_by_id_snapshot == checker.id
    assert world["job"].reconciliation_before_digest
    assert world["job"].reconciliation_after_digest
    assert world["job"].provider_receipt_hmac_sha256
    decision = IntegrationReconciliationDecision.objects.get(
        job_id_snapshot=world["job"].id
    )
    assert decision.actor_id_snapshot == checker.id
    assert decision.action == "confirm_applied"
    assert decision.request_digest_snapshot == world["job"].request_digest
    assert decision.provider_remote_data_sha256 == canonical_sha256(remote_data)
    assert decision.decision_hmac_sha256
    decision.reason = "An attempted rewrite"
    with pytest.raises(DjangoValidationError):
        decision.save()
    with pytest.raises(DjangoValidationError):
        decision.delete()
    with pytest.raises(DjangoValidationError):
        IntegrationReconciliationDecision.objects.filter(id=decision.id).update(
            reason="An attempted queryset rewrite"
        )
    assert world["mapping"].remote_id == "sys1"
    assert world["mapping"].version == 2
    assert SyncEvent.objects.filter(
        mapping=world["mapping"],
        triggered_by=SyncEvent.TriggeredBy.RECONCILIATION,
    ).exists()


@pytest.mark.django_db
def test_checker_cannot_confirm_a_stale_remote_snapshot(reconciliation_world):
    world = reconciliation_world
    checker = _user_with_permissions(world["folder"], RECONCILER_PERMISSIONS)
    accepted_version = world["mapping"].remote_data["updated"]
    stale_version = datetime.fromisoformat(accepted_version) - timedelta(seconds=1)
    stale_remote_data = {
        "key": "sys1",
        "updated": stale_version.isoformat(),
        "fields": {"u_name": "stale-provider-state"},
    }

    response = _client(checker).post(
        f"/api/integrations/sync-jobs/{world['job'].id}/reconcile/",
        {
            "action": "confirm_applied",
            "reason": "A stale provider snapshot must not move the watermark back.",
            "remote_data": stale_remote_data,
            "provider_receipt": _receipt(
                world["job"],
                outcome="applied",
                remote_id="sys1",
                remote_data=stale_remote_data,
            ),
        },
        format="json",
    )

    assert response.status_code == 400, response.content
    assert "older than the accepted remote state" in str(response.json())
    world["job"].refresh_from_db()
    world["mapping"].refresh_from_db()
    assert world["job"].status == IntegrationSyncJob.Status.UNCERTAIN
    assert world["mapping"].remote_data["updated"] == accepted_version
    assert not IntegrationReconciliationDecision.objects.filter(
        job_id_snapshot=world["job"].id
    ).exists()


@pytest.mark.django_db
def test_maker_cannot_reconcile_their_own_job(reconciliation_world):
    world = reconciliation_world
    maker = _user_with_permissions(world["folder"], RECONCILER_PERMISSIONS)
    world["job"].requested_by_id_snapshot = maker.id
    world["job"].save(update_fields=["requested_by_id_snapshot", "updated_at"])

    remote_data = {}
    response = _client(maker).post(
        f"/api/integrations/sync-jobs/{world['job'].id}/reconcile/",
        {
            "action": "confirm_not_applied",
            "reason": "This decision must be independently checked.",
            "remote_data": remote_data,
            "provider_receipt": _receipt(
                world["job"],
                outcome="not_applied",
                remote_id="sys1",
                remote_data=remote_data,
            ),
        },
        format="json",
    )

    assert response.status_code == 403, response.content
    world["job"].refresh_from_db()
    assert world["job"].status == IntegrationSyncJob.Status.UNCERTAIN


@pytest.mark.django_db
def test_provider_without_idempotency_proof_cannot_be_retried(reconciliation_world):
    world = reconciliation_world
    checker = _user_with_permissions(world["folder"], RECONCILER_PERMISSIONS)

    response = _client(checker).post(
        f"/api/integrations/sync-jobs/{world['job'].id}/reconcile/",
        {
            "action": "retry_same_operation",
            "reason": "Attempt a retry only if the provider proves idempotency.",
        },
        format="json",
    )

    assert response.status_code == 400, response.content
    assert "cannot prove idempotent retry" in str(response.json())
    world["job"].refresh_from_db()
    assert world["job"].status == IntegrationSyncJob.Status.UNCERTAIN
    assert world["job"].payload == {"u_name": "Server"}


@pytest.mark.django_db
def test_generic_cancel_is_rejected_without_mutating_authority(reconciliation_world):
    world = reconciliation_world
    checker = _user_with_permissions(world["folder"], RECONCILER_PERMISSIONS)
    url = f"/api/integrations/sync-jobs/{world['job'].id}/reconcile/"

    denied = _client(checker).post(
        url,
        {
            "action": "cancel",
            "reason": "The provider effect was disproven by an operator.",
        },
        format="json",
    )
    assert denied.status_code == 400, denied.content
    world["job"].refresh_from_db()
    assert world["job"].status == IntegrationSyncJob.Status.UNCERTAIN
    assert not IntegrationReconciliationDecision.objects.filter(
        job_id_snapshot=world["job"].id
    ).exists()


@pytest.mark.django_db
def test_checker_can_confirm_effect_was_not_applied(reconciliation_world):
    world = reconciliation_world
    checker = _user_with_permissions(world["folder"], RECONCILER_PERMISSIONS)
    remote_data = {}

    response = _client(checker).post(
        f"/api/integrations/sync-jobs/{world['job'].id}/reconcile/",
        {
            "action": "confirm_not_applied",
            "reason": "Provider audit evidence proves no update was applied.",
            "remote_data": remote_data,
            "provider_receipt": _receipt(
                world["job"],
                outcome="not_applied",
                remote_id="SYS1",
                remote_data=remote_data,
            ),
        },
        format="json",
    )

    assert response.status_code == 200, response.content
    world["job"].refresh_from_db()
    world["mapping"].refresh_from_db()
    assert world["job"].status == IntegrationSyncJob.Status.FAILED
    assert world["job"].failure_code == "reconciled_confirmed_not_applied"
    assert world["job"].payload == {}
    assert world["mapping"].sync_status == SyncMapping.SyncStatus.FAILED
    decision = IntegrationReconciliationDecision.objects.get(
        job_id_snapshot=world["job"].id
    )
    assert decision.action == "confirm_not_applied"
    assert decision.provider_outcome == "not_applied"
    event = SyncEvent.objects.get(
        job_id_snapshot=world["job"].id,
        triggered_by=SyncEvent.TriggeredBy.RECONCILIATION,
    )
    assert event.actor_id_snapshot == checker.id
    assert event.request_digest_snapshot == world["job"].request_digest
    assert event.success is False


@pytest.mark.django_db
def test_provider_receipt_is_exact_and_operation_bound(reconciliation_world):
    world = reconciliation_world
    checker = _user_with_permissions(world["folder"], RECONCILER_PERMISSIONS)
    client = _client(checker)
    url = f"/api/integrations/sync-jobs/{world['job'].id}/reconcile/"
    remote_data = {
        "key": "sys1",
        "updated": timezone.now().isoformat(),
        "fields": {"u_name": "Server"},
    }
    valid_receipt = _receipt(
        world["job"],
        outcome="applied",
        remote_id="sys1",
        remote_data=remote_data,
    )
    invalid_payloads = []

    extra_receipt = {**valid_receipt, "unreviewed": True}
    invalid_payloads.append(
        {"provider_receipt": extra_receipt, "remote_data": remote_data}
    )
    invalid_payloads.append(
        {
            "provider_receipt": {
                **valid_receipt,
                "request_digest": "0" * 64,
            },
            "remote_data": remote_data,
        }
    )
    invalid_payloads.append(
        {
            "provider_receipt": {**valid_receipt, "outcome": "not_applied"},
            "remote_data": remote_data,
        }
    )
    invalid_payloads.append(
        {
            "provider_receipt": {
                **valid_receipt,
                "remote_data_sha256": "0" * 64,
            },
            "remote_data": remote_data,
        }
    )
    invalid_payloads.append(
        {
            "provider_receipt": {**valid_receipt, "remote_id": "anotherid"},
            "remote_data": remote_data,
        }
    )
    invalid_payloads.append(
        {
            "provider_receipt": {
                **valid_receipt,
                "observed_at": (
                    world["job"].effect_started_at - timedelta(minutes=10)
                ).isoformat(),
            },
            "remote_data": remote_data,
        }
    )
    invalid_payloads.append(
        {
            "provider_receipt": valid_receipt,
            "remote_data": remote_data,
            "remote_id": "sys1",
        }
    )

    for partial_payload in invalid_payloads:
        response = client.post(
            url,
            {
                "action": "confirm_applied",
                "reason": "Reject evidence that is not exact and operation-bound.",
                **partial_payload,
            },
            format="json",
        )
        assert response.status_code == 400, response.content

    world["job"].refresh_from_db()
    world["mapping"].refresh_from_db()
    assert world["job"].status == IntegrationSyncJob.Status.UNCERTAIN
    assert world["mapping"].version == 1
    assert not IntegrationReconciliationDecision.objects.filter(
        job_id_snapshot=world["job"].id
    ).exists()


@pytest.mark.django_db
def test_service_account_cannot_act_as_checker(reconciliation_world):
    world = reconciliation_world
    machine_user = _user_with_permissions(world["folder"], RECONCILER_PERMISSIONS)
    assignment = RoleAssignment.objects.get(user=machine_user)
    oidc_client = Client(
        id=f"sa-{uuid.uuid4().hex}",
        name="integration-reconciler-machine",
        type=Client.Type.CONFIDENTIAL,
        grant_types=Client.GrantType.CLIENT_CREDENTIALS,
        scopes="",
        response_types="",
        owner=machine_user,
    )
    oidc_client.set_secret("machine-secret")
    oidc_client.save()
    ServiceAccount.objects.create(
        name=f"integration-reconciler-{uuid.uuid4().hex[:8]}",
        client=oidc_client,
        user=machine_user,
        role=assignment.role,
    )
    remote_data = {}

    response = _client(machine_user).post(
        f"/api/integrations/sync-jobs/{world['job'].id}/reconcile/",
        {
            "action": "confirm_not_applied",
            "reason": "A machine principal must not make this binding decision.",
            "remote_data": remote_data,
            "provider_receipt": _receipt(
                world["job"],
                outcome="not_applied",
                remote_id="sys1",
                remote_data=remote_data,
            ),
        },
        format="json",
    )

    assert response.status_code == 403, response.content
    world["job"].refresh_from_db()
    assert world["job"].status == IntegrationSyncJob.Status.UNCERTAIN


@pytest.mark.django_db
def test_checker_can_accept_typed_remote_command_from_exact_review_state(
    reconciliation_world,
):
    world = reconciliation_world
    review_job = _make_manual_review_job(world)
    checker = _user_with_permissions(world["folder"], RECONCILER_PERMISSIONS)

    response = _client(checker).post(
        f"/api/integrations/sync-jobs/{review_job.id}/reconcile/",
        {
            "action": "accept_remote",
            "reason": "Independent review accepts the validated remote proposal.",
        },
        format="json",
    )

    assert response.status_code == 200, response.content
    review_job.refresh_from_db()
    world["asset"].refresh_from_db()
    world["mapping"].refresh_from_db()
    assert review_job.status == IntegrationSyncJob.Status.SUCCEEDED
    assert review_job.payload == {}
    assert world["asset"].name == "Remote name"
    assert world["mapping"].sync_status == SyncMapping.SyncStatus.SYNCED


@pytest.mark.django_db
def test_keep_local_creates_new_exact_outbound_job_with_checker_as_maker(
    reconciliation_world,
):
    world = reconciliation_world
    review_job = _make_manual_review_job(world)
    checker = _user_with_permissions(world["folder"], RECONCILER_PERMISSIONS)

    response = _client(checker).post(
        f"/api/integrations/sync-jobs/{review_job.id}/reconcile/",
        {
            "action": "keep_local",
            "reason": "Independent review retains the approved local value.",
        },
        format="json",
    )

    assert response.status_code == 200, response.content
    review_job.refresh_from_db()
    world["mapping"].refresh_from_db()
    successor = IntegrationSyncJob.objects.exclude(id=review_job.id).get()
    assert review_job.status == IntegrationSyncJob.Status.SUPERSEDED
    assert world["mapping"].sync_status == SyncMapping.SyncStatus.PENDING
    assert successor.status == IntegrationSyncJob.Status.QUEUED
    assert successor.direction == IntegrationSyncJob.Direction.OUTBOUND
    assert successor.requested_by_id_snapshot == checker.id
    assert successor.origin_principal_snapshot == f"user:{checker.id}"
    assert successor.changed_fields == sorted(
        world["asset"].INTEGRATION_SYNCABLE_FIELDS
    )
    decision = IntegrationReconciliationDecision.objects.get(
        job_id_snapshot=review_job.id
    )
    assert decision.action == "keep_local"


@pytest.mark.django_db
def test_jira_keep_local_binds_ordered_corrective_jobs_to_one_decision(
    reconciliation_world,
):
    jira = _make_jira_manual_review_world(reconciliation_world)
    review_job = jira["review_job"]
    checker = _user_with_permissions(
        reconciliation_world["folder"], RECONCILER_PERMISSIONS
    )

    response = _client(checker).post(
        f"/api/integrations/sync-jobs/{review_job.id}/reconcile/",
        {
            "action": "keep_local",
            "reason": "Retain the reviewed local control and correct Jira in order.",
        },
        format="json",
    )

    assert response.status_code == 200, response.content
    review_job.refresh_from_db()
    corrective_jobs = list(
        IntegrationSyncJob.objects.filter(
            mapping_id_snapshot=jira["mapping"].id,
            direction=IntegrationSyncJob.Direction.OUTBOUND,
        ).order_by("created_at", "id")
    )
    decision = IntegrationReconciliationDecision.objects.get(
        job_id_snapshot=review_job.id
    )
    assert review_job.status == IntegrationSyncJob.Status.SUPERSEDED
    assert len(corrective_jobs) == 2
    assert [job.payload for job in corrective_jobs] == [
        {"summary": "Locally reviewed control"},
        {"status": "In Progress"},
    ]
    contexts = [job.capability["reconciliation_authority"] for job in corrective_jobs]
    assert [context["sequence"] for context in contexts] == [1, 2]
    assert all(
        context
        == {
            "schema": "integration-reconciliation-corrective-v1",
            "decision_id": str(decision.id),
            "source_job_id": str(review_job.id),
            "source_request_digest": review_job.request_digest,
            "action": "keep_local",
            "checker_id": str(checker.id),
            "sequence": position,
            "total": 2,
        }
        for position, context in enumerate(contexts, start=1)
    )


@pytest.mark.django_db
def test_jira_keep_local_rolls_back_every_corrective_job_on_partial_failure(
    reconciliation_world, monkeypatch
):
    from integrations import capabilities

    jira = _make_jira_manual_review_world(reconciliation_world)
    review_job = jira["review_job"]
    checker = _user_with_permissions(
        reconciliation_world["folder"], RECONCILER_PERMISSIONS
    )
    create_sync_job = capabilities._create_sync_job
    calls = 0

    def fail_second_corrective_job(**kwargs):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise RuntimeError("simulated second corrective job failure")
        return create_sync_job(**kwargs)

    monkeypatch.setattr(
        capabilities,
        "_create_sync_job",
        fail_second_corrective_job,
    )
    with pytest.raises(RuntimeError, match="second corrective job failure"):
        _client(checker).post(
            f"/api/integrations/sync-jobs/{review_job.id}/reconcile/",
            {
                "action": "keep_local",
                "reason": "The corrective group must commit atomically or not at all.",
            },
            format="json",
        )

    review_job.refresh_from_db()
    jira["mapping"].refresh_from_db()
    assert review_job.status == IntegrationSyncJob.Status.REVIEW_REQUIRED
    assert jira["mapping"].sync_status == SyncMapping.SyncStatus.CONFLICT
    assert not IntegrationSyncJob.objects.filter(
        mapping_id_snapshot=jira["mapping"].id,
        direction=IntegrationSyncJob.Direction.OUTBOUND,
    ).exists()
    assert not IntegrationReconciliationDecision.objects.filter(
        job_id_snapshot=review_job.id
    ).exists()


@pytest.mark.django_db
def test_keep_local_fails_closed_when_later_job_is_active(reconciliation_world):
    world = reconciliation_world
    review_job = _make_manual_review_job(world)
    checker = _user_with_permissions(world["folder"], RECONCILER_PERMISSIONS)
    with transaction.atomic():
        [successor_id] = persist_outbound_sync_jobs(
            content_type_id=world["mapping"].content_type_id,
            object_id=world["asset"].id,
            configuration_ids=[world["configuration"].id],
            changed_fields=["description"],
        )

    response = _client(checker).post(
        f"/api/integrations/sync-jobs/{review_job.id}/reconcile/",
        {
            "action": "keep_local",
            "reason": "Do not reorder an already queued successor operation.",
        },
        format="json",
    )

    assert response.status_code == 400, response.content
    assert "later sync job is active" in str(response.json())
    review_job.refresh_from_db()
    world["mapping"].refresh_from_db()
    assert review_job.status == IntegrationSyncJob.Status.REVIEW_REQUIRED
    assert world["mapping"].sync_status == SyncMapping.SyncStatus.CONFLICT
    assert IntegrationSyncJob.objects.get(id=successor_id).status == (
        IntegrationSyncJob.Status.QUEUED
    )
    assert not IntegrationReconciliationDecision.objects.filter(
        job_id_snapshot=review_job.id
    ).exists()


@pytest.mark.django_db
def test_each_retry_requires_a_different_human_authorizer(
    reconciliation_world, monkeypatch
):
    world = reconciliation_world
    first_checker = _user_with_permissions(world["folder"], RECONCILER_PERMISSIONS)
    second_checker = _user_with_permissions(world["folder"], RECONCILER_PERMISSIONS)
    from integrations.itsm.servicenow.integration import ServiceNowOrchestrator

    monkeypatch.setattr(ServiceNowOrchestrator, "SUPPORTS_IDEMPOTENT_OPERATIONS", True)
    url = f"/api/integrations/sync-jobs/{world['job'].id}/reconcile/"
    payload = {
        "action": "retry_same_operation",
        "reason": "Provider contract proves this operation identifier is idempotent.",
    }

    first = _client(first_checker).post(url, payload, format="json")
    assert first.status_code == 200, first.content
    world["job"].refresh_from_db()
    world["job"].status = IntegrationSyncJob.Status.UNCERTAIN
    world["job"].attempt_id = uuid.uuid4()
    world["job"].claimed_at = timezone.now()
    world["job"].effect_started_at = timezone.now()
    world["job"].terminal_at = timezone.now()
    world["job"].failure_code = "provider_result_uncertain"
    world["job"].save()

    repeated = _client(first_checker).post(url, payload, format="json")
    assert repeated.status_code == 403, repeated.content
    independent = _client(second_checker).post(url, payload, format="json")
    assert independent.status_code == 200, independent.content
    assert set(
        IntegrationReconciliationDecision.objects.filter(
            job_id_snapshot=world["job"].id
        ).values_list("actor_id_snapshot", flat=True)
    ) == {first_checker.id, second_checker.id}


@pytest.mark.django_db
def test_checker_can_requeue_exact_pre_effect_job_after_key_restore(
    reconciliation_world,
):
    world = reconciliation_world
    checker = _user_with_permissions(world["folder"], RECONCILER_PERMISSIONS)
    world["job"].status = IntegrationSyncJob.Status.REVIEW_REQUIRED
    world["job"].failure_code = "signing_key_unavailable"
    world["job"].effect_started_at = None
    world["job"].claimed_at = world["job"].created_at
    world["job"].save()

    response = _client(checker).post(
        f"/api/integrations/sync-jobs/{world['job'].id}/reconcile/",
        {
            "action": "requeue_after_key_restore",
            "reason": "The retained signing key was restored and independently checked.",
        },
        format="json",
    )

    assert response.status_code == 200, response.content
    world["job"].refresh_from_db()
    assert world["job"].status == IntegrationSyncJob.Status.QUEUED
    assert world["job"].failure_code == "reconciled_key_restored"
    assert world["job"].attempt_id is None
    assert world["job"].claimed_at is None
    decision = IntegrationReconciliationDecision.objects.get(
        job_id_snapshot=world["job"].id
    )
    assert decision.action == "requeue_after_key_restore"
    assert decision.actor_id_snapshot == checker.id


@pytest.mark.django_db
def test_key_restore_requeue_rejects_started_or_tampered_effect(
    reconciliation_world,
):
    world = reconciliation_world
    checker = _user_with_permissions(world["folder"], RECONCILER_PERMISSIONS)
    url = f"/api/integrations/sync-jobs/{world['job'].id}/reconcile/"
    payload = {
        "action": "requeue_after_key_restore",
        "reason": "Only an exact pre-effect operation may be requeued.",
    }
    world["job"].status = IntegrationSyncJob.Status.REVIEW_REQUIRED
    world["job"].failure_code = "signing_key_unavailable"
    world["job"].save()

    started = _client(checker).post(url, payload, format="json")
    assert started.status_code == 400, started.content
    world["job"].refresh_from_db()
    world["job"].effect_started_at = None
    world["job"].payload = {"u_name": "tampered"}
    world["job"].save()
    tampered = _client(checker).post(url, payload, format="json")
    assert tampered.status_code == 400, tampered.content
    world["job"].refresh_from_db()
    assert world["job"].status == IntegrationSyncJob.Status.REVIEW_REQUIRED
    assert not IntegrationReconciliationDecision.objects.filter(
        job_id_snapshot=world["job"].id
    ).exists()
