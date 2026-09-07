"""DB-backed tests for integration routing and durable sync authority."""

from datetime import timedelta
from types import SimpleNamespace
from unittest.mock import MagicMock, patch
import uuid

import pytest
from core.models import Asset
from django.contrib.contenttypes.models import ContentType
from django.db import transaction
from django.test import override_settings
from django.utils import timezone
from iam.models import Folder

from integrations.itsm.servicenow.integration import ServiceNowOrchestrator
from integrations.capabilities import (
    authority_hmac,
    canonical_sha256,
    configuration_authority_hmac,
    model_row_authority_hmac,
)
from integrations.models import (
    IntegrationConfiguration,
    IntegrationProvider,
    IntegrationSyncAttempt,
    IntegrationSyncJob,
    SyncMapping,
)


@pytest.fixture
def root_folder(db):
    folder, _ = Folder.objects.get_or_create(
        content_type=Folder.ContentType.ROOT, defaults={"name": "Global"}
    )
    return folder


@pytest.fixture
def servicenow_provider(db):
    provider, _ = IntegrationProvider.objects.get_or_create(
        name="servicenow", provider_type="itsm"
    )
    return provider


def _config(provider, models_settings):
    return IntegrationConfiguration.objects.create(
        provider=provider,
        credentials={
            "instance_url": "https://example.service-now.com",
            "username": "u",
            "password": "p",
        },
        settings={
            "enable_outgoing_sync": True,
            "enable_incoming_sync": True,
            "models": models_settings,
        },
        webhook_secret="secret",
    )


def _mock_client():
    client = MagicMock()
    client.create_remote_object.return_value = "SYS1"
    client.get_remote_object.return_value = {
        "key": "SYS1",
        "updated": timezone.now().isoformat(),
        "fields": {},
    }
    return client


def test_asset_save_accepts_skip_sync(root_folder):
    asset = Asset.objects.create(name="DB Server", folder=root_folder, type="PR")
    # The inbound pull path saves with skip_sync=True; must not raise.
    asset.name = "DB Server 2"
    asset.save(skip_sync=True)
    asset.refresh_from_db()
    assert asset.name == "DB Server 2"


def test_legacy_direct_push_fails_closed(root_folder, servicenow_provider):
    config = _config(
        servicenow_provider,
        {"asset": {"table_name": "cmdb_ci", "field_map": {"name": "u_name"}}},
    )
    asset = Asset.objects.create(name="DB Server", folder=root_folder, type="PR")
    SyncMapping.objects.create(
        configuration=config,
        content_type=ContentType.objects.get_for_model(Asset),
        local_object_id=asset.id,
        remote_id="",
        folder=root_folder,
        sync_status=SyncMapping.SyncStatus.PENDING,
    )
    client = _mock_client()

    orchestrator = ServiceNowOrchestrator(config)
    with pytest.raises(RuntimeError, match="durable sync intent"):
        orchestrator.push_changes(asset, ["name"])

    client.create_remote_object.assert_not_called()
    mapping = SyncMapping.objects.get(configuration=config)
    assert mapping.remote_id == ""
    assert mapping.content_type.model == "asset"


def test_legacy_direct_push_fails_closed_even_when_model_unconfigured(
    root_folder, servicenow_provider
):
    # Config mapped only for applied_control: an Asset push must be skipped.
    config = _config(
        servicenow_provider,
        {"applied_control": {"table_name": "incident", "field_map": {"name": "x"}}},
    )
    asset = Asset.objects.create(name="DB Server", folder=root_folder, type="PR")
    client = _mock_client()

    orchestrator = ServiceNowOrchestrator(config)
    with pytest.raises(RuntimeError, match="durable sync intent"):
        orchestrator.push_changes(asset, ["name"])
    client.create_remote_object.assert_not_called()
    assert not SyncMapping.objects.filter(configuration=config).exists()


def test_legacy_direct_pull_fails_closed(root_folder, servicenow_provider):
    config = _config(
        servicenow_provider,
        {"asset": {"table_name": "cmdb_ci", "field_map": {"name": "u_name"}}},
    )
    before = Asset.objects.count()
    client = _mock_client()

    orchestrator = ServiceNowOrchestrator(config)
    with pytest.raises(RuntimeError, match="durable sync intent"):
        orchestrator.pull_changes("UNKNOWNSYSID", {"fields": {"u_name": "X"}})
    assert Asset.objects.count() == before


def test_asset_creation_without_mapping_does_not_trigger_sync(
    root_folder, servicenow_provider, django_capture_on_commit_callbacks
):
    """A model save alone is not authority to create a remote relationship."""
    _config(
        servicenow_provider,
        {"asset": {"table_name": "cmdb_ci", "field_map": {"name": "u_name"}}},
    )
    with patch(
        "integrations.capabilities.enqueue_integration_sync_jobs"
    ) as enqueue_jobs:
        with django_capture_on_commit_callbacks(execute=True):
            Asset.objects.create(name="New server", folder=root_folder, type="PR")
    enqueue_jobs.assert_not_called()
    assert not IntegrationSyncJob.objects.exists()


def test_asset_update_with_coherent_mapping_triggers_sync(
    root_folder, servicenow_provider, django_capture_on_commit_callbacks
):
    config = _config(
        servicenow_provider,
        {"asset": {"table_name": "cmdb_ci", "field_map": {"name": "u_name"}}},
    )
    asset = Asset.objects.create(name="Old name", folder=root_folder, type="PR")
    SyncMapping.objects.create(
        configuration=config,
        content_type=ContentType.objects.get_for_model(Asset),
        local_object_id=asset.id,
        remote_id="SYS1",
        folder=root_folder,
    )

    with patch(
        "integrations.capabilities.enqueue_integration_sync_jobs"
    ) as enqueue_jobs:
        with django_capture_on_commit_callbacks(execute=True):
            asset.name = "New name"
            asset.save()

    enqueue_jobs.assert_called_once()
    job_id = enqueue_jobs.call_args.args[0][0]
    job = IntegrationSyncJob.objects.get(id=job_id)
    assert job.direction == IntegrationSyncJob.Direction.OUTBOUND
    assert job.capability["configuration_id"] == str(config.id)
    assert job.capability["mapping_version"] == 1
    assert job.changed_fields == ["name"]
    assert "password" not in str(job.capability)


def test_asset_update_with_cross_folder_mapping_does_not_trigger_sync(
    root_folder, servicenow_provider, django_capture_on_commit_callbacks
):
    child = Folder.objects.create(
        name="Child", parent_folder=root_folder, content_type=Folder.ContentType.DOMAIN
    )
    config = _config(
        servicenow_provider,
        {"asset": {"table_name": "cmdb_ci", "field_map": {"name": "u_name"}}},
    )
    asset = Asset.objects.create(name="Old name", folder=child, type="PR")
    SyncMapping.objects.create(
        configuration=config,
        content_type=ContentType.objects.get_for_model(Asset),
        local_object_id=asset.id,
        remote_id="SYS1",
        folder=root_folder,
    )

    with patch(
        "integrations.capabilities.enqueue_integration_sync_jobs"
    ) as enqueue_jobs:
        with django_capture_on_commit_callbacks(execute=True):
            asset.name = "New name"
            asset.save()

    enqueue_jobs.assert_not_called()
    assert not IntegrationSyncJob.objects.exists()


def test_applied_control_legacy_direct_push_is_disabled(
    root_folder, servicenow_provider
):
    """Legacy behavior: applied_control pushes on every active config, even one
    with no mapping keys at all (providers carry AC defaults). The
    configured-target gate only applies to new models."""
    from core.models import AppliedControl

    config = IntegrationConfiguration.objects.create(
        provider=servicenow_provider,
        credentials={
            "instance_url": "https://example.service-now.com",
            "username": "u",
            "password": "p",
        },
        settings={"enable_outgoing_sync": True},  # no mapping keys
        webhook_secret="secret",
    )
    control = AppliedControl.objects.create(name="Control", folder=root_folder)
    SyncMapping.objects.create(
        configuration=config,
        content_type=ContentType.objects.get_for_model(AppliedControl),
        local_object_id=control.id,
        remote_id="",
        folder=root_folder,
        sync_status=SyncMapping.SyncStatus.PENDING,
    )
    client = _mock_client()

    orchestrator = ServiceNowOrchestrator(config)
    with pytest.raises(RuntimeError, match="durable sync intent"):
        orchestrator.push_changes(control, ["name"])

    client.create_remote_object.assert_not_called()


def test_applied_control_legacy_direct_push_without_mapping_is_disabled(
    root_folder, servicenow_provider
):
    from core.models import AppliedControl

    config = IntegrationConfiguration.objects.create(
        provider=servicenow_provider,
        credentials={},
        settings={"enable_outgoing_sync": True},
        webhook_secret="secret",
        folder=root_folder,
    )
    control = AppliedControl.objects.create(name="Control", folder=root_folder)
    client = _mock_client()

    with pytest.raises(RuntimeError, match="durable sync intent"):
        ServiceNowOrchestrator(config).push_changes(control, ["name"])
    client.create_remote_object.assert_not_called()
    assert not SyncMapping.objects.filter(configuration=config).exists()


def test_relink_reuses_existing_sync_mapping(
    root_folder, servicenow_provider, django_capture_on_commit_callbacks
):
    """Relinking an already-linked object must upsert the mapping, not raise
    IntegrityError on the (configuration, content_type, local_object_id)
    unique constraint."""
    from core.views import IntegrationLinkViewSetMixin

    config = _config(
        servicenow_provider,
        {"asset": {"table_name": "cmdb_ci", "field_map": {"name": "u_name"}}},
    )
    asset = Asset.objects.create(name="DB Server", folder=root_folder, type="PR")

    class _Base:
        def perform_update(self, serializer):
            pass

    class _ViewSet(IntegrationLinkViewSetMixin, _Base):
        model = Asset

    class _Serializer:
        instance = asset

        def __init__(self, remote_id):
            self.validated_data = {
                "integration_config": config,
                "remote_object_id": remote_id,
            }

    from iam.models import RoleAssignment

    viewset = _ViewSet()
    viewset.request = SimpleNamespace(user=object())
    with (
        patch.object(
            RoleAssignment,
            "get_viewable_object_ids",
            side_effect=lambda _user, model: model.objects.values_list("id", flat=True),
        ),
        patch.object(RoleAssignment, "is_access_allowed", return_value=True),
        patch("core.views.persist_outbound_sync_jobs"),
        django_capture_on_commit_callbacks(execute=False),
    ):
        viewset.perform_update(_Serializer("SYS1"))
        viewset.perform_update(_Serializer("SYS2"))  # relink: must not raise

    mappings = SyncMapping.objects.filter(configuration=config)
    assert mappings.count() == 1
    assert mappings.get().remote_id == "sys2"


def test_direct_serializer_update_cannot_bypass_configuration_authority(
    root_folder, servicenow_provider
):
    from rest_framework.exceptions import PermissionDenied

    from integrations.models import IntegrationSchemaCache
    from integrations.serializers import IntegrationConfigurationSerializer

    config = _config(
        servicenow_provider,
        {"asset": {"table_name": "cmdb_ci", "field_map": {"name": "u_name"}}},
    )
    IntegrationSchemaCache.objects.create(
        configuration=config, tables=[{"name": "cmdb_ci", "label": "CI"}]
    )
    serializer = IntegrationConfigurationSerializer()

    with pytest.raises(PermissionDenied):
        serializer.update(
            config,
            {
                "credentials": {
                    "instance_url": "https://other.service-now.com",
                    "username": "u",
                    "password": "p",
                }
            },
        )

    config.refresh_from_db()
    assert config.credentials["instance_url"] == "https://example.service-now.com"
    assert IntegrationSchemaCache.objects.filter(configuration=config).exists()


def test_legacy_direct_pull_cannot_update_linked_asset(
    root_folder, servicenow_provider
):
    config = _config(
        servicenow_provider,
        {"asset": {"table_name": "cmdb_ci", "field_map": {"name": "u_name"}}},
    )
    asset = Asset.objects.create(name="Old name", folder=root_folder, type="PR")
    SyncMapping.objects.create(
        configuration=config,
        content_type=ContentType.objects.get_for_model(Asset),
        local_object_id=asset.id,
        remote_id="SYS9",
        sync_status=SyncMapping.SyncStatus.SYNCED,
    )
    client = _mock_client()

    orchestrator = ServiceNowOrchestrator(config)
    with pytest.raises(RuntimeError, match="durable sync intent"):
        orchestrator.pull_changes("SYS9", {"fields": {"u_name": "New name"}})

    asset.refresh_from_db()
    assert asset.name == "Old name"


def _persist_outbound_job(config, local_object, changed_fields=None):
    from integrations.capabilities import persist_outbound_sync_jobs

    content_type = ContentType.objects.get_for_model(local_object)
    with transaction.atomic():
        job_ids = persist_outbound_sync_jobs(
            content_type_id=content_type.id,
            object_id=local_object.id,
            configuration_ids=[config.id],
            changed_fields=changed_fields or ["name"],
        )
    assert len(job_ids) == 1
    return IntegrationSyncJob.objects.get(id=job_ids[0])


def _persist_webhook_job(config, payload, event_type="sn_update"):
    from integrations.capabilities import persist_webhook_sync_job

    payload = dict(payload)
    payload.setdefault("sys_updated_on", timezone.now().isoformat())
    job_id = persist_webhook_sync_job(
        authenticated_configuration=config,
        authenticated_configuration_hmac_sha256=configuration_authority_hmac(config),
        authenticated_provider_hmac_sha256=model_row_authority_hmac(config.provider),
        authenticated_body_hmac_sha256=authority_hmac(
            canonical_sha256(payload),
            domain="integration-webhook-authenticated-body-v1",
        ),
        remote_id=payload["sys_id"],
        event_type=event_type,
        payload=payload,
    )
    assert job_id is not None
    return IntegrationSyncJob.objects.get(id=job_id)


@pytest.mark.django_db(transaction=True)
def test_outbound_intent_requires_the_business_transaction(
    root_folder, servicenow_provider
):
    from integrations.capabilities import persist_outbound_sync_jobs

    config = _config(
        servicenow_provider,
        {"asset": {"table_name": "cmdb_ci", "field_map": {"name": "u_name"}}},
    )
    asset = Asset.objects.create(name="Server", folder=root_folder, type="PR")
    SyncMapping.objects.create(
        configuration=config,
        content_type=ContentType.objects.get_for_model(Asset),
        local_object_id=asset.id,
        remote_id="SYS1",
        folder=root_folder,
    )

    with pytest.raises(RuntimeError, match="business mutation transaction"):
        persist_outbound_sync_jobs(
            content_type_id=ContentType.objects.get_for_model(Asset).id,
            object_id=asset.id,
            configuration_ids=[config.id],
            changed_fields=["name"],
        )


def test_jira_field_write_and_status_transition_are_separate_fifo_jobs(root_folder):
    from core.models import AppliedControl
    from integrations.capabilities import persist_outbound_sync_jobs

    provider = IntegrationProvider.objects.create(
        name="jira",
        provider_type=IntegrationProvider.ProviderType.ITSM,
        folder=root_folder,
    )
    config = IntegrationConfiguration.objects.create(
        provider=provider,
        folder=root_folder,
        credentials={
            "server_url": "https://jira.example.com",
            "email": "user@example.com",
            "api_token": "secret",
        },
        settings={
            "enable_outgoing_sync": True,
            "table_name": "PROJ:Task",
            "field_map": {"name": "summary", "status": "status"},
            "value_map": {"status": {"in_progress": "In Progress"}},
        },
        webhook_secret="secret",
    )
    control = AppliedControl.objects.create(
        name="Control",
        status="in_progress",
        folder=root_folder,
    )
    SyncMapping.objects.create(
        configuration=config,
        content_type=ContentType.objects.get_for_model(AppliedControl),
        local_object_id=control.id,
        remote_id="PROJ-1",
        folder=root_folder,
    )

    with transaction.atomic():
        job_ids = persist_outbound_sync_jobs(
            content_type_id=ContentType.objects.get_for_model(AppliedControl).id,
            object_id=control.id,
            configuration_ids=[config.id],
            changed_fields=["name", "status"],
            origin_principal="user:test-maker",
        )

    jobs = list(
        IntegrationSyncJob.objects.filter(id__in=job_ids).order_by("created_at")
    )
    assert len(jobs) == 2
    assert [job.payload for job in jobs] == [
        {"summary": "Control"},
        {"status": "In Progress"},
    ]
    assert [job.changed_fields for job in jobs] == [["name"], ["status"]]
    assert all(job.capability["operation_kind"] == "update" for job in jobs)


def test_queued_job_remains_valid_while_its_retired_signing_key_is_retained(
    root_folder, servicenow_provider
):
    from integrations.tasks import sync_object_to_integrations

    config = _config(
        servicenow_provider,
        {"asset": {"table_name": "cmdb_ci", "field_map": {"name": "u_name"}}},
    )
    asset = Asset.objects.create(name="Server", folder=root_folder, type="PR")
    SyncMapping.objects.create(
        configuration=config,
        content_type=ContentType.objects.get_for_model(Asset),
        local_object_id=asset.id,
        remote_id="SYS1",
        folder=root_folder,
    )
    with override_settings(
        INTEGRATION_SIGNING_KEYS={"old-v1": "old-secret-0123456789-0123456789"},
        INTEGRATION_SIGNING_PRIMARY_KEY_ID="old-v1",
    ):
        job = _persist_outbound_job(config, asset)
    assert job.capability["signing_key_id"] == "old-v1"

    orchestrator = MagicMock()
    orchestrator.execute_outbound_payload.return_value = (
        "SYS1",
        {"key": "SYS1", "updated": timezone.now().isoformat(), "fields": {}},
    )
    with (
        override_settings(
            INTEGRATION_SIGNING_KEYS={
                "new-v2": "new-secret-0123456789-0123456789",
                "old-v1": "old-secret-0123456789-0123456789",
            },
            INTEGRATION_SIGNING_PRIMARY_KEY_ID="new-v2",
        ),
        patch(
            "integrations.tasks.IntegrationRegistry.get_orchestrator",
            return_value=orchestrator,
        ),
    ):
        assert sync_object_to_integrations.call_local(job.id) == "succeeded"


def test_missing_retired_signing_key_requires_review_without_scrubbing_payload(
    root_folder, servicenow_provider
):
    from integrations.tasks import sync_object_to_integrations

    config = _config(
        servicenow_provider,
        {"asset": {"table_name": "cmdb_ci", "field_map": {"name": "u_name"}}},
    )
    asset = Asset.objects.create(name="Server", folder=root_folder, type="PR")
    SyncMapping.objects.create(
        configuration=config,
        content_type=ContentType.objects.get_for_model(Asset),
        local_object_id=asset.id,
        remote_id="SYS1",
        folder=root_folder,
    )
    with override_settings(
        INTEGRATION_SIGNING_KEYS={"old-v1": "old-secret-0123456789-0123456789"},
        INTEGRATION_SIGNING_PRIMARY_KEY_ID="old-v1",
    ):
        job = _persist_outbound_job(config, asset)

    with override_settings(
        INTEGRATION_SIGNING_KEYS={"new-v2": "new-secret-0123456789-0123456789"},
        INTEGRATION_SIGNING_PRIMARY_KEY_ID="new-v2",
    ):
        assert sync_object_to_integrations.call_local(job.id) == "review_required"

    job.refresh_from_db()
    assert job.status == IntegrationSyncJob.Status.REVIEW_REQUIRED
    assert job.failure_code == "signing_key_unavailable"
    assert job.payload == {"u_name": "Server"}


def test_sync_worker_supersedes_inactive_configuration(
    root_folder, servicenow_provider
):
    from integrations.tasks import sync_object_to_integrations

    config = _config(
        servicenow_provider,
        {"asset": {"table_name": "cmdb_ci", "field_map": {"name": "u_name"}}},
    )
    asset = Asset.objects.create(name="Server", folder=root_folder, type="PR")
    SyncMapping.objects.create(
        configuration=config,
        content_type=ContentType.objects.get_for_model(Asset),
        local_object_id=asset.id,
        remote_id="SYS1",
        folder=root_folder,
    )
    job = _persist_outbound_job(config, asset)
    config.is_active = False
    config.save(update_fields=["is_active"])

    with patch(
        "integrations.tasks.IntegrationRegistry.get_orchestrator"
    ) as get_orchestrator:
        result = sync_object_to_integrations.call_local(job.id)

    assert result == "superseded"
    get_orchestrator.assert_not_called()
    job.refresh_from_db()
    assert job.status == IntegrationSyncJob.Status.SUPERSEDED


def test_sync_worker_executes_exact_durable_job_once(root_folder, servicenow_provider):
    from integrations.tasks import sync_object_to_integrations

    config = _config(
        servicenow_provider,
        {"asset": {"table_name": "cmdb_ci", "field_map": {"name": "u_name"}}},
    )
    asset = Asset.objects.create(name="Server", folder=root_folder, type="PR")
    mapping = SyncMapping.objects.create(
        configuration=config,
        content_type=ContentType.objects.get_for_model(Asset),
        local_object_id=asset.id,
        remote_id="SYS1",
        folder=root_folder,
    )
    job = _persist_outbound_job(config, asset)
    orchestrator = MagicMock()
    orchestrator.execute_outbound_payload.return_value = (
        "SYS1",
        {
            "key": "SYS1",
            "updated": timezone.now().isoformat(),
            "fields": {
                "u_name": "Server",
                "private_customer_data": "must-not-be-retained",
            },
        },
    )

    with patch(
        "integrations.tasks.IntegrationRegistry.get_orchestrator",
        return_value=orchestrator,
    ):
        assert sync_object_to_integrations.call_local(job.id) == "succeeded"

    orchestrator.execute_outbound_payload.assert_called_once_with(
        model_key="asset",
        operation_kind="update",
        remote_id="SYS1",
        payload={"u_name": "Server"},
        operation_id=job.request_digest,
    )
    mapping.refresh_from_db()
    job.refresh_from_db()
    assert mapping.version == 2
    assert mapping.remote_data["fields"] == {"u_name": "Server"}
    assert job.status == IntegrationSyncJob.Status.SUCCEEDED
    assert job.payload == {}
    assert job.provider_receipt_hmac_sha256
    assert job.provider_receipt_signing_key_id == job.capability["signing_key_id"]
    attempt = IntegrationSyncAttempt.objects.get(job_id_snapshot=job.id)
    assert attempt.attempt_id == job.attempt_id
    assert attempt.outcome == IntegrationSyncJob.Status.SUCCEEDED
    assert attempt.effect_started_at == job.effect_started_at
    assert attempt.result_digest == canonical_sha256(mapping.remote_data)
    assert attempt.attempt_hmac_sha256

    with patch(
        "integrations.tasks.IntegrationRegistry.get_orchestrator"
    ) as second_orchestrator:
        assert sync_object_to_integrations.call_local(job.id) == "noop"
    second_orchestrator.assert_not_called()


def test_worker_routes_mismatched_provider_readback_to_uncertain(
    root_folder, servicenow_provider
):
    from integrations.tasks import sync_object_to_integrations

    config = _config(
        servicenow_provider,
        {"asset": {"table_name": "cmdb_ci", "field_map": {"name": "u_name"}}},
    )
    asset = Asset.objects.create(name="Server", folder=root_folder, type="PR")
    mapping = SyncMapping.objects.create(
        configuration=config,
        content_type=ContentType.objects.get_for_model(Asset),
        local_object_id=asset.id,
        remote_id="SYS1",
        folder=root_folder,
    )
    job = _persist_outbound_job(config, asset)
    execution_orchestrator = MagicMock()
    execution_orchestrator.execute_outbound_payload.return_value = (
        "SYS1",
        {
            "key": "SYS2",
            "updated": timezone.now().isoformat(),
            "fields": {"u_name": "Server"},
        },
    )

    with patch(
        "integrations.tasks.IntegrationRegistry.get_orchestrator",
        return_value=execution_orchestrator,
    ):
        assert sync_object_to_integrations.call_local(job.id) == "uncertain"

    mapping.refresh_from_db()
    job.refresh_from_db()
    assert mapping.version == 1
    assert mapping.remote_id == "sys1"
    assert job.status == IntegrationSyncJob.Status.UNCERTAIN
    assert job.failure_code == "provider_result_uncertain"
    attempt = IntegrationSyncAttempt.objects.get(job_id_snapshot=job.id)
    assert attempt.outcome == IntegrationSyncJob.Status.UNCERTAIN


def test_outbound_fifo_preserves_a_to_b_to_a_updates(root_folder, servicenow_provider):
    from integrations.tasks import sync_object_to_integrations

    config = _config(
        servicenow_provider,
        {"asset": {"table_name": "cmdb_ci", "field_map": {"name": "u_name"}}},
    )
    asset = Asset.objects.create(name="A", folder=root_folder, type="PR")
    mapping = SyncMapping.objects.create(
        configuration=config,
        content_type=ContentType.objects.get_for_model(Asset),
        local_object_id=asset.id,
        remote_id="sys1",
        folder=root_folder,
    )

    asset.name = "B"
    asset.save()
    asset.name = "A"
    asset.save()
    first_job, second_job = IntegrationSyncJob.objects.order_by("created_at", "id")
    assert first_job.request_digest != second_job.request_digest
    assert (
        first_job.capability["source_state_hmac_sha256"]
        != (second_job.capability["source_state_hmac_sha256"])
    )

    orchestrator = MagicMock()
    orchestrator.execute_outbound_payload.side_effect = [
        (
            "sys1",
            {
                "key": "sys1",
                "updated": timezone.now().isoformat(),
                "fields": {"u_name": "B"},
            },
        ),
        (
            "sys1",
            {
                "key": "sys1",
                "updated": timezone.now().isoformat(),
                "fields": {"u_name": "A"},
            },
        ),
    ]
    with patch(
        "integrations.tasks.IntegrationRegistry.get_orchestrator",
        return_value=orchestrator,
    ):
        assert sync_object_to_integrations.call_local(second_job.id) == "noop"
        assert sync_object_to_integrations.call_local(first_job.id) == "succeeded"
        assert sync_object_to_integrations.call_local(second_job.id) == "succeeded"

    assert [
        call.kwargs["payload"]
        for call in orchestrator.execute_outbound_payload.call_args_list
    ] == [{"u_name": "B"}, {"u_name": "A"}]
    mapping.refresh_from_db()
    assert mapping.version == 3
    assert mapping.remote_data["fields"]["u_name"] == "A"


def test_sync_worker_uses_exact_payload_when_object_changes_after_enqueue(
    root_folder, servicenow_provider
):
    from integrations.tasks import sync_object_to_integrations

    config = _config(
        servicenow_provider,
        {"asset": {"table_name": "cmdb_ci", "field_map": {"name": "u_name"}}},
    )
    asset = Asset.objects.create(name="Server", folder=root_folder, type="PR")
    SyncMapping.objects.create(
        configuration=config,
        content_type=ContentType.objects.get_for_model(Asset),
        local_object_id=asset.id,
        remote_id="SYS1",
        folder=root_folder,
    )
    job = _persist_outbound_job(config, asset)
    asset.name = "Changed after enqueue"
    asset.save(skip_sync=True)

    orchestrator = MagicMock()
    orchestrator.execute_outbound_payload.return_value = (
        "SYS1",
        {
            "key": "SYS1",
            "updated": timezone.now().isoformat(),
            "fields": {"u_name": "Server"},
        },
    )
    with patch(
        "integrations.tasks.IntegrationRegistry.get_orchestrator",
        return_value=orchestrator,
    ):
        assert sync_object_to_integrations.call_local(job.id) == "succeeded"

    assert orchestrator.execute_outbound_payload.call_args.kwargs["payload"] == {
        "u_name": "Server"
    }
    job.refresh_from_db()
    assert job.status == IntegrationSyncJob.Status.SUCCEEDED


def test_sync_worker_rejects_legacy_payload_bearing_jobs(
    root_folder, servicenow_provider
):
    from integrations.tasks import process_webhook_event, sync_object_to_integrations

    config = _config(
        servicenow_provider,
        {"asset": {"table_name": "cmdb_ci", "field_map": {"name": "u_name"}}},
    )
    asset = Asset.objects.create(name="Server", folder=root_folder, type="PR")
    content_type = ContentType.objects.get_for_model(Asset)

    with patch(
        "integrations.tasks.IntegrationRegistry.get_orchestrator"
    ) as get_orchestrator:
        assert (
            sync_object_to_integrations.call_local(
                content_type.id, asset.id, [config.id], ["name"]
            )
            == "noop"
        )
        assert process_webhook_event.call_local({}, "updated", {"x": 1}) == "noop"

    get_orchestrator.assert_not_called()


def test_webhook_worker_executes_exact_durable_job_once(
    root_folder, servicenow_provider
):
    from integrations.tasks import process_webhook_event

    config = _config(
        servicenow_provider,
        {"asset": {"table_name": "cmdb_ci", "field_map": {"name": "u_name"}}},
    )
    asset = Asset.objects.create(name="Server", folder=root_folder, type="PR")
    mapping = SyncMapping.objects.create(
        configuration=config,
        content_type=ContentType.objects.get_for_model(Asset),
        local_object_id=asset.id,
        remote_id="SYS1",
        folder=root_folder,
    )
    payload = {
        "sys_id": "SYS1",
        "u_name": "New name",
        "unmapped_private_note": "must-not-be-retained",
    }
    job = _persist_webhook_job(config, payload, event_type="sn_update")
    assert "unmapped_private_note" not in job.payload
    orchestrator = ServiceNowOrchestrator(config)

    with patch(
        "integrations.tasks.IntegrationRegistry.get_orchestrator",
        return_value=orchestrator,
    ):
        assert process_webhook_event.call_local(job.id) == "succeeded"

    asset.refresh_from_db()
    assert asset.name == "New name"
    mapping.refresh_from_db()
    job.refresh_from_db()
    assert mapping.version == 2
    assert job.status == IntegrationSyncJob.Status.SUCCEEDED
    assert job.payload == {}

    with patch(
        "integrations.tasks.IntegrationRegistry.get_orchestrator"
    ) as duplicate_orchestrator:
        assert process_webhook_event.call_local(job.id) == "noop"
    duplicate_orchestrator.assert_not_called()


def test_webhook_worker_supersedes_tampered_payload_and_changed_config(
    root_folder, servicenow_provider
):
    from integrations.tasks import process_webhook_event

    config = _config(
        servicenow_provider,
        {"asset": {"table_name": "cmdb_ci", "field_map": {"name": "u_name"}}},
    )
    asset = Asset.objects.create(name="Server", folder=root_folder, type="PR")
    mapping = SyncMapping.objects.create(
        configuration=config,
        content_type=ContentType.objects.get_for_model(Asset),
        local_object_id=asset.id,
        remote_id="SYS1",
        folder=root_folder,
    )
    payload = {"sys_id": "SYS1", "u_name": "New name"}
    tampered_job = _persist_webhook_job(config, payload, event_type="sn_update")
    IntegrationSyncJob.objects.filter(id=tampered_job.id).update(
        payload={**payload, "unexpected": True}
    )

    with patch(
        "integrations.tasks.IntegrationRegistry.get_orchestrator"
    ) as get_orchestrator:
        assert process_webhook_event.call_local(tampered_job.id) == "superseded"
    get_orchestrator.assert_not_called()

    changed_config_job = _persist_webhook_job(
        config,
        {"sys_id": "SYS1", "u_name": "Another name"},
        event_type="sn_update",
    )
    config.is_active = False
    config.save(update_fields=["is_active"])
    with patch(
        "integrations.tasks.IntegrationRegistry.get_orchestrator"
    ) as get_orchestrator:
        assert process_webhook_event.call_local(changed_config_job.id) == "superseded"
    get_orchestrator.assert_not_called()
    mapping.refresh_from_db()
    assert mapping.version == 1


def test_webhook_worker_rejects_remote_version_column_tampering(
    root_folder, servicenow_provider
):
    from integrations.tasks import process_webhook_event

    config = _config(
        servicenow_provider,
        {"asset": {"table_name": "cmdb_ci", "field_map": {"name": "u_name"}}},
    )
    asset = Asset.objects.create(name="Server", folder=root_folder, type="PR")
    SyncMapping.objects.create(
        configuration=config,
        content_type=ContentType.objects.get_for_model(Asset),
        local_object_id=asset.id,
        remote_id="SYS1",
        folder=root_folder,
    )
    job = _persist_webhook_job(
        config,
        {"sys_id": "SYS1", "u_name": "New name"},
        event_type="sn_update",
    )
    IntegrationSyncJob.objects.filter(id=job.id).update(
        remote_version=job.remote_version - timedelta(days=1)
    )

    with patch(
        "integrations.tasks.IntegrationRegistry.get_orchestrator"
    ) as execution_orchestrator:
        assert process_webhook_event.call_local(job.id) == "superseded"

    execution_orchestrator.assert_not_called()
    job.refresh_from_db()
    assert job.status == IntegrationSyncJob.Status.SUPERSEDED
    assert job.failure_code == "authority_changed"


def test_two_authenticated_webhooks_run_in_order_without_dropping_second(
    root_folder, servicenow_provider
):
    from integrations.tasks import process_webhook_event

    config = _config(
        servicenow_provider,
        {"asset": {"table_name": "cmdb_ci", "field_map": {"name": "u_name"}}},
    )
    asset = Asset.objects.create(name="Server", folder=root_folder, type="PR")
    mapping = SyncMapping.objects.create(
        configuration=config,
        content_type=ContentType.objects.get_for_model(Asset),
        local_object_id=asset.id,
        remote_id="SYS1",
        folder=root_folder,
    )
    first_payload = {"sys_id": "SYS1", "u_name": "First name"}
    second_payload = {"sys_id": "SYS1", "u_name": "Second name"}
    first_job = _persist_webhook_job(config, first_payload, event_type="sn_update")
    second_job = _persist_webhook_job(config, second_payload, event_type="sn_update")
    orchestrator = ServiceNowOrchestrator(config)

    with patch(
        "integrations.tasks.IntegrationRegistry.get_orchestrator",
        return_value=orchestrator,
    ):
        assert process_webhook_event.call_local(second_job.id) == "noop"
        assert process_webhook_event.call_local(first_job.id) == "succeeded"
        assert process_webhook_event.call_local(second_job.id) == "succeeded"

    mapping.refresh_from_db()
    assert mapping.version == 3


def test_same_timestamp_with_different_remote_state_requires_review(
    root_folder, servicenow_provider
):
    from integrations.tasks import process_webhook_event

    config = _config(
        servicenow_provider,
        {"asset": {"table_name": "cmdb_ci", "field_map": {"name": "u_name"}}},
    )
    asset = Asset.objects.create(name="Current", folder=root_folder, type="PR")
    remote_version = timezone.now() - timedelta(seconds=1)
    mapping = SyncMapping.objects.create(
        configuration=config,
        content_type=ContentType.objects.get_for_model(Asset),
        local_object_id=asset.id,
        remote_id="SYS1",
        remote_data={
            "key": "sys1",
            "updated": remote_version.isoformat(),
            "fields": {"u_name": "Current"},
        },
        folder=root_folder,
    )
    job = _persist_webhook_job(
        config,
        {
            "sys_id": "SYS1",
            "u_name": "Same-second change",
            "sys_updated_on": remote_version.isoformat(),
        },
        event_type="sn_update",
    )
    assert job.capability["remote_version_ambiguous"] is True

    with patch(
        "integrations.tasks.IntegrationRegistry.get_orchestrator",
        return_value=ServiceNowOrchestrator(config),
    ):
        assert process_webhook_event.call_local(job.id) == "review_required"

    asset.refresh_from_db()
    mapping.refresh_from_db()
    job.refresh_from_db()
    assert asset.name == "Current"
    assert mapping.sync_status == SyncMapping.SyncStatus.CONFLICT
    assert job.status == IntegrationSyncJob.Status.REVIEW_REQUIRED
    assert job.failure_code == "ambiguous_remote_version"
    assert job.payload["u_name"] == "Same-second change"


def test_completed_delete_tombstone_rejects_delayed_pre_delete_update(
    root_folder, servicenow_provider
):
    from integrations.capabilities import persist_webhook_sync_job
    from integrations.tasks import process_webhook_event

    config = _config(
        servicenow_provider,
        {"asset": {"table_name": "cmdb_ci", "field_map": {"name": "u_name"}}},
    )
    asset = Asset.objects.create(name="Current", folder=root_folder, type="PR")
    baseline_version = timezone.now() - timedelta(minutes=3)
    delete_version = timezone.now() - timedelta(minutes=1)
    mapping = SyncMapping.objects.create(
        configuration=config,
        content_type=ContentType.objects.get_for_model(Asset),
        local_object_id=asset.id,
        remote_id="SYS1",
        remote_data={
            "key": "sys1",
            "updated": baseline_version.isoformat(),
            "fields": {"u_name": "Current"},
        },
        folder=root_folder,
        last_synced_at=baseline_version,
    )
    delete_job = _persist_webhook_job(
        config,
        {
            "sys_id": "SYS1",
            "sys_updated_on": delete_version.isoformat(),
        },
        event_type="sn_delete",
    )

    with patch(
        "integrations.tasks.IntegrationRegistry.get_orchestrator",
        return_value=ServiceNowOrchestrator(config),
    ):
        assert process_webhook_event.call_local(delete_job.id) == "succeeded"

    mapping.refresh_from_db()
    delete_job.refresh_from_db()
    assert delete_job.status == IntegrationSyncJob.Status.SUCCEEDED
    assert mapping.sync_status == SyncMapping.SyncStatus.FAILED
    assert mapping.remote_data == {
        "key": "sys1",
        "updated": delete_job.remote_version.isoformat(),
        "fields": {},
    }

    delayed_payload = {
        "sys_id": "SYS1",
        "sys_updated_on": (delete_version - timedelta(minutes=1)).isoformat(),
        "u_name": "stale-name",
    }
    delayed_job_id = persist_webhook_sync_job(
        authenticated_configuration=config,
        authenticated_configuration_hmac_sha256=configuration_authority_hmac(config),
        authenticated_provider_hmac_sha256=model_row_authority_hmac(config.provider),
        authenticated_body_hmac_sha256=authority_hmac(
            canonical_sha256(delayed_payload),
            domain="integration-webhook-authenticated-body-v1",
        ),
        remote_id="SYS1",
        event_type="sn_update",
        payload=delayed_payload,
    )

    assert delayed_job_id is None
    asset.refresh_from_db()
    assert asset.name == "Current"


def test_mixed_outbound_then_incoming_fifo_rebases_without_dropping_event(
    root_folder, servicenow_provider
):
    from integrations.tasks import process_webhook_event, sync_object_to_integrations

    config = _config(
        servicenow_provider,
        {"asset": {"table_name": "cmdb_ci", "field_map": {"name": "u_name"}}},
    )
    asset = Asset.objects.create(name="A", folder=root_folder, type="PR")
    mapping = SyncMapping.objects.create(
        configuration=config,
        content_type=ContentType.objects.get_for_model(Asset),
        local_object_id=asset.id,
        remote_id="sys1",
        folder=root_folder,
    )
    asset.name = "B"
    asset.save()
    outbound_job = IntegrationSyncJob.objects.get(
        direction=IntegrationSyncJob.Direction.OUTBOUND
    )
    incoming_version = timezone.now()
    incoming_job = _persist_webhook_job(
        config,
        {
            "sys_id": "sys1",
            "u_name": "C",
            "sys_updated_on": incoming_version.isoformat(),
        },
        event_type="sn_update",
    )

    outbound_orchestrator = MagicMock()
    outbound_orchestrator.execute_outbound_payload.return_value = (
        "sys1",
        {
            "key": "sys1",
            "updated": (incoming_version - timedelta(seconds=1)).isoformat(),
            "fields": {"u_name": "B"},
        },
    )
    with patch(
        "integrations.tasks.IntegrationRegistry.get_orchestrator",
        return_value=outbound_orchestrator,
    ):
        assert process_webhook_event.call_local(incoming_job.id) == "noop"
        assert sync_object_to_integrations.call_local(outbound_job.id) == "succeeded"

    with patch(
        "integrations.tasks.IntegrationRegistry.get_orchestrator",
        return_value=ServiceNowOrchestrator(config),
    ):
        assert process_webhook_event.call_local(incoming_job.id) == "succeeded"

    asset.refresh_from_db()
    mapping.refresh_from_db()
    assert asset.name == "C"
    assert mapping.version == 3


def test_outbound_readback_supersedes_an_older_queued_webhook(
    root_folder, servicenow_provider
):
    from integrations.tasks import process_webhook_event, sync_object_to_integrations

    config = _config(
        servicenow_provider,
        {"asset": {"table_name": "cmdb_ci", "field_map": {"name": "u_name"}}},
    )
    asset = Asset.objects.create(name="A", folder=root_folder, type="PR")
    mapping = SyncMapping.objects.create(
        configuration=config,
        content_type=ContentType.objects.get_for_model(Asset),
        local_object_id=asset.id,
        remote_id="sys1",
        folder=root_folder,
    )
    asset.name = "B"
    asset.save()
    outbound_job = IntegrationSyncJob.objects.get(
        direction=IntegrationSyncJob.Direction.OUTBOUND
    )
    readback_version = timezone.now() - timedelta(seconds=1)
    incoming_job = _persist_webhook_job(
        config,
        {
            "sys_id": "sys1",
            "u_name": "stale-name",
            "sys_updated_on": (readback_version - timedelta(seconds=1)).isoformat(),
        },
        event_type="sn_update",
    )
    outbound_orchestrator = MagicMock()
    outbound_orchestrator.execute_outbound_payload.return_value = (
        "sys1",
        {
            "key": "sys1",
            "updated": readback_version.isoformat(),
            "fields": {"u_name": "B"},
        },
    )

    with patch(
        "integrations.tasks.IntegrationRegistry.get_orchestrator",
        return_value=outbound_orchestrator,
    ):
        assert process_webhook_event.call_local(incoming_job.id) == "noop"
        assert sync_object_to_integrations.call_local(outbound_job.id) == "succeeded"
        assert process_webhook_event.call_local(incoming_job.id) == "noop"

    asset.refresh_from_db()
    mapping.refresh_from_db()
    incoming_job.refresh_from_db()
    assert asset.name == "B"
    assert mapping.version == 2
    assert incoming_job.status == IntegrationSyncJob.Status.SUPERSEDED
    assert incoming_job.failure_code == "stale_remote_version"


def test_ambiguous_provider_result_is_not_retried_automatically(
    root_folder, servicenow_provider
):
    from integrations.tasks import sync_object_to_integrations

    config = _config(
        servicenow_provider,
        {"asset": {"table_name": "cmdb_ci", "field_map": {"name": "u_name"}}},
    )
    asset = Asset.objects.create(name="Server", folder=root_folder, type="PR")
    SyncMapping.objects.create(
        configuration=config,
        content_type=ContentType.objects.get_for_model(Asset),
        local_object_id=asset.id,
        remote_id="SYS1",
        folder=root_folder,
    )
    job = _persist_outbound_job(config, asset)
    orchestrator = MagicMock()
    orchestrator.execute_outbound_payload.side_effect = TimeoutError("unknown result")

    with patch(
        "integrations.tasks.IntegrationRegistry.get_orchestrator",
        return_value=orchestrator,
    ):
        assert sync_object_to_integrations.call_local(job.id) == "uncertain"
        assert sync_object_to_integrations.call_local(job.id) == "noop"

    job.refresh_from_db()
    assert job.status == IntegrationSyncJob.Status.UNCERTAIN
    assert job.payload == {"u_name": "Server"}
    assert job.attempts == 1


def test_sweeper_requeues_transport_misses_and_marks_stale_claims_uncertain(
    root_folder, servicenow_provider
):
    from integrations.tasks import sweep_integration_sync_jobs

    config = _config(
        servicenow_provider,
        {"asset": {"table_name": "cmdb_ci", "field_map": {"name": "u_name"}}},
    )
    asset = Asset.objects.create(name="Server", folder=root_folder, type="PR")
    SyncMapping.objects.create(
        configuration=config,
        content_type=ContentType.objects.get_for_model(Asset),
        local_object_id=asset.id,
        remote_id="SYS1",
        folder=root_folder,
    )
    queued_job = _persist_outbound_job(config, asset)
    stale_job = _persist_webhook_job(
        config,
        {"sys_id": "SYS1", "sys_updated_on": "2026-09-04 11:00:00"},
    )
    stale_claimed_at = timezone.now() - timedelta(minutes=16)
    IntegrationSyncJob.objects.filter(id=stale_job.id).update(
        status=IntegrationSyncJob.Status.PROCESSING,
        attempt_id=uuid.uuid4(),
        claimed_at=stale_claimed_at,
        effect_started_at=stale_claimed_at,
    )

    with patch("integrations.tasks.enqueue_integration_sync_jobs") as enqueue_jobs:
        result = sweep_integration_sync_jobs.call_local()

    assert result["uncertain"] == 1
    assert result["enqueued"] >= 1
    assert queued_job.id in set(enqueue_jobs.call_args.args[0])
    stale_job.refresh_from_db()
    assert stale_job.status == IntegrationSyncJob.Status.UNCERTAIN
    assert stale_job.payload["sys_updated_on"] == "2026-09-04 11:00:00"
