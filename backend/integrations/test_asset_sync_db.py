"""DB-backed tests for Asset sync wiring (model routing, skip_sync, no-create)."""

from unittest.mock import MagicMock, patch

import pytest
from core.models import Asset
from django.db import transaction
from iam.models import Folder

from integrations.itsm.servicenow.integration import ServiceNowOrchestrator
from integrations.models import (
    IntegrationConfiguration,
    IntegrationProvider,
    SyncMapping,
)
from integrations.tasks import sync_object_to_integrations


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
    client.create_remote_object.return_value = "SYS-1"
    client.get_remote_object.return_value = {"key": "SYS-1", "fields": {}}
    return client


def _capture_asset_sync_args(
    *, root_folder, servicenow_provider, django_capture_on_commit_callbacks
):
    config = _config(
        servicenow_provider,
        {"asset": {"table_name": "cmdb_ci", "field_map": {"name": "u_name"}}},
    )
    with (
        patch("integrations.tasks.sync_object_to_integrations") as mock_task,
        django_capture_on_commit_callbacks(execute=True),
    ):
        asset = Asset.objects.create(
            name="Queued server",
            folder=root_folder,
            type="PR",
        )
    mock_task.schedule.assert_called_once()
    return config, asset, mock_task.schedule.call_args.kwargs["args"]


def test_asset_save_accepts_skip_sync(root_folder):
    asset = Asset.objects.create(name="DB Server", folder=root_folder, type="PR")
    # The inbound pull path saves with skip_sync=True; must not raise.
    asset.name = "DB Server 2"
    asset.save(skip_sync=True)
    asset.refresh_from_db()
    assert asset.name == "DB Server 2"


def test_push_routes_to_asset_mapper_and_table(root_folder, servicenow_provider):
    config = _config(
        servicenow_provider,
        {"asset": {"table_name": "cmdb_ci", "field_map": {"name": "u_name"}}},
    )
    asset = Asset.objects.create(name="DB Server", folder=root_folder, type="PR")
    client = _mock_client()

    with patch.object(ServiceNowOrchestrator, "_get_client", return_value=client):
        orchestrator = ServiceNowOrchestrator(config)
        result = orchestrator.push_changes(asset, ["name"])

    assert result is True
    client.create_remote_object.assert_called_once_with(asset)
    mapping = SyncMapping.objects.get(configuration=config)
    assert mapping.remote_id == "SYS-1"
    assert mapping.content_type.model == "asset"


def test_push_skips_when_model_not_configured(root_folder, servicenow_provider):
    # Config mapped only for applied_control: an Asset push must be skipped.
    config = _config(
        servicenow_provider,
        {"applied_control": {"table_name": "incident", "field_map": {"name": "x"}}},
    )
    asset = Asset.objects.create(name="DB Server", folder=root_folder, type="PR")
    client = _mock_client()

    with patch.object(ServiceNowOrchestrator, "_get_client", return_value=client):
        orchestrator = ServiceNowOrchestrator(config)
        result = orchestrator.push_changes(asset, ["name"])

    assert result is False
    client.create_remote_object.assert_not_called()
    assert not SyncMapping.objects.filter(configuration=config).exists()


def test_pull_for_unlinked_remote_creates_no_asset(root_folder, servicenow_provider):
    config = _config(
        servicenow_provider,
        {"asset": {"table_name": "cmdb_ci", "field_map": {"name": "u_name"}}},
    )
    before = Asset.objects.count()
    client = _mock_client()

    with patch.object(ServiceNowOrchestrator, "_get_client", return_value=client):
        orchestrator = ServiceNowOrchestrator(config)
        result = orchestrator.pull_changes(
            "UNKNOWN-SYS-ID", {"fields": {"u_name": "X"}}
        )

    assert result is False
    assert Asset.objects.count() == before


def test_asset_creation_triggers_sync(
    root_folder, servicenow_provider, django_capture_on_commit_callbacks
):
    """Creating an Asset with a configured integration schedules a push.

    Regression for the `is_new = self.pk is None` dead-code bug: the UUID pk is
    defaulted at instantiation, so creation-sync never fired.
    """
    _config(
        servicenow_provider,
        {"asset": {"table_name": "cmdb_ci", "field_map": {"name": "u_name"}}},
    )
    with (
        patch("integrations.tasks.sync_object_to_integrations") as mock_task,
        django_capture_on_commit_callbacks(execute=True),
    ):
        Asset.objects.create(name="New server", folder=root_folder, type="PR")
    mock_task.schedule.assert_called_once()


def test_asset_creation_does_not_enqueue_for_inactive_provider(
    root_folder,
    servicenow_provider,
    django_capture_on_commit_callbacks,
):
    _config(
        servicenow_provider,
        {"asset": {"table_name": "cmdb_ci", "field_map": {"name": "u_name"}}},
    )
    IntegrationProvider.objects.filter(id=servicenow_provider.id).update(
        is_active=False
    )

    with (
        patch("integrations.tasks.sync_object_to_integrations") as mock_task,
        django_capture_on_commit_callbacks(execute=True),
    ):
        Asset.objects.create(name="No export", folder=root_folder, type="PR")

    mock_task.schedule.assert_not_called()


@pytest.mark.parametrize(
    "boundary_change",
    (
        "provider_deactivated",
        "provider_type_changed",
        "configuration_deactivated",
        "configuration_moved",
        "configuration_repointed",
        "outgoing_disabled",
        "model_mapping_removed",
    ),
)
def test_delayed_asset_sync_fails_closed_after_connector_boundary_change(
    root_folder,
    servicenow_provider,
    django_capture_on_commit_callbacks,
    boundary_change,
):
    config, _asset, scheduled_args = _capture_asset_sync_args(
        root_folder=root_folder,
        servicenow_provider=servicenow_provider,
        django_capture_on_commit_callbacks=django_capture_on_commit_callbacks,
    )

    if boundary_change == "provider_deactivated":
        IntegrationProvider.objects.filter(id=servicenow_provider.id).update(
            is_active=False
        )
    elif boundary_change == "provider_type_changed":
        IntegrationProvider.objects.filter(id=servicenow_provider.id).update(
            provider_type="disabled"
        )
    elif boundary_change == "configuration_deactivated":
        IntegrationConfiguration.objects.filter(id=config.id).update(is_active=False)
    elif boundary_change == "configuration_moved":
        other_folder = Folder.objects.create(
            name="Other integration domain",
            content_type=Folder.ContentType.DOMAIN,
            parent_folder=root_folder,
        )
        IntegrationConfiguration.objects.filter(id=config.id).update(
            folder=other_folder
        )
    elif boundary_change == "configuration_repointed":
        IntegrationConfiguration.objects.filter(id=config.id).update(
            credentials={
                **config.credentials,
                "instance_url": "https://other.service-now.com",
            }
        )
    elif boundary_change == "outgoing_disabled":
        IntegrationConfiguration.objects.filter(id=config.id).update(
            settings={**config.settings, "enable_outgoing_sync": False}
        )
    else:
        IntegrationConfiguration.objects.filter(id=config.id).update(
            settings={
                **config.settings,
                "models": {
                    "applied_control": {
                        "table_name": "incident",
                        "field_map": {"name": "short_description"},
                    }
                },
            }
        )

    with (
        patch(
            "integrations.tasks.IntegrationRegistry.get_orchestrator"
        ) as get_orchestrator,
        patch("integrations.tasks.logger.error") as log_error,
    ):
        sync_object_to_integrations.call_local(*scheduled_args)

    get_orchestrator.assert_not_called()
    log_error.assert_not_called()


def test_delayed_asset_sync_exports_when_connector_boundary_is_unchanged(
    root_folder,
    servicenow_provider,
    django_capture_on_commit_callbacks,
):
    config, asset, scheduled_args = _capture_asset_sync_args(
        root_folder=root_folder,
        servicenow_provider=servicenow_provider,
        django_capture_on_commit_callbacks=django_capture_on_commit_callbacks,
    )
    orchestrator = MagicMock()

    with patch(
        "integrations.tasks.IntegrationRegistry.get_orchestrator",
        return_value=orchestrator,
    ) as get_orchestrator:
        sync_object_to_integrations.call_local(*scheduled_args)

    get_orchestrator.assert_called_once()
    assert get_orchestrator.call_args.args[0].id == config.id
    pushed_object, changed_fields = orchestrator.push_changes.call_args.args
    assert pushed_object.id == asset.id
    assert changed_fields == []


def test_legacy_unbound_asset_sync_job_is_deserializable_but_fails_closed(
    root_folder,
    servicenow_provider,
    django_capture_on_commit_callbacks,
):
    _config, _asset, scheduled_args = _capture_asset_sync_args(
        root_folder=root_folder,
        servicenow_provider=servicenow_provider,
        django_capture_on_commit_callbacks=django_capture_on_commit_callbacks,
    )

    with patch(
        "integrations.tasks.IntegrationRegistry.get_orchestrator"
    ) as get_orchestrator:
        sync_object_to_integrations.call_local(*scheduled_args[:4])

    get_orchestrator.assert_not_called()


def test_failed_integration_callback_does_not_block_later_webhook_callback(
    root_folder,
    servicenow_provider,
    django_capture_on_commit_callbacks,
):
    _config(
        servicenow_provider,
        {"asset": {"table_name": "cmdb_ci", "field_map": {"name": "u_name"}}},
    )
    callback_order = []

    def failed_schedule(*_args, **_kwargs):
        callback_order.append("integration")
        raise RuntimeError("scheduler unavailable")

    with (
        patch(
            "integrations.tasks.sync_object_to_integrations.schedule",
            side_effect=failed_schedule,
        ),
        django_capture_on_commit_callbacks(execute=True),
        transaction.atomic(),
    ):
        asset = Asset.objects.create(
            name="Committed despite scheduler failure",
            folder=root_folder,
            type="PR",
        )
        transaction.on_commit(
            lambda: callback_order.append("webhook"),
            robust=True,
        )

    assert Asset.objects.filter(id=asset.id).exists()
    assert callback_order == ["integration", "webhook"]


def test_applied_control_push_not_gated_by_mapping_config(
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
    client = _mock_client()

    with patch.object(ServiceNowOrchestrator, "_get_client", return_value=client):
        orchestrator = ServiceNowOrchestrator(config)
        result = orchestrator.push_changes(control, ["name"])

    assert result is True
    client.create_remote_object.assert_called_once_with(control)


def test_relink_reuses_existing_sync_mapping(root_folder, servicenow_provider):
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

    viewset = _ViewSet()
    with patch("core.views.sync_object_to_integrations"):
        viewset.perform_update(_Serializer("SYS-1"))
        viewset.perform_update(_Serializer("SYS-2"))  # relink: must not raise

    mappings = SyncMapping.objects.filter(configuration=config)
    assert mappings.count() == 1
    assert mappings.get().remote_id == "SYS-2"


def test_credential_change_invalidates_schema_cache(root_folder, servicenow_provider):
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

    # Settings-only update keeps the cache.
    serializer.update(config, {"settings": {**config.settings}})
    assert IntegrationSchemaCache.objects.filter(configuration=config).exists()

    # Credential change (repointing the instance) drops it.
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
    assert not IntegrationSchemaCache.objects.filter(configuration=config).exists()


def test_pull_updates_linked_asset(root_folder, servicenow_provider):
    from django.contrib.contenttypes.models import ContentType

    config = _config(
        servicenow_provider,
        {"asset": {"table_name": "cmdb_ci", "field_map": {"name": "u_name"}}},
    )
    asset = Asset.objects.create(name="Old name", folder=root_folder, type="PR")
    SyncMapping.objects.create(
        configuration=config,
        content_type=ContentType.objects.get_for_model(Asset),
        local_object_id=asset.id,
        remote_id="SYS-9",
        sync_status=SyncMapping.SyncStatus.SYNCED,
    )
    client = _mock_client()

    with patch.object(ServiceNowOrchestrator, "_get_client", return_value=client):
        orchestrator = ServiceNowOrchestrator(config)
        result = orchestrator.pull_changes("SYS-9", {"fields": {"u_name": "New name"}})

    assert result is True
    asset.refresh_from_db()
    assert asset.name == "New name"
