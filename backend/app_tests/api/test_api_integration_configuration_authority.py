import uuid
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from core.models import Asset
from django.contrib.auth.models import Permission
from django.contrib.contenttypes.models import ContentType
from django.utils import timezone
from iam.models import Folder, Role, RoleAssignment, User
from integrations.models import (
    IntegrationConfiguration,
    IntegrationProvider,
    IntegrationSchemaCache,
    IntegrationSyncJob,
    SyncMapping,
)
from integrations.serializers import IntegrationConfigurationSerializer
from integrations.views import IntegrationConfigurationViewSet
from knox.models import AuthToken
from rest_framework.exceptions import PermissionDenied, ValidationError
from rest_framework.test import APIClient

CONFIG_URL = "/api/integrations/configs/"


def _client(user):
    client = APIClient()
    _, token = AuthToken.objects.create(user=user)
    client.credentials(HTTP_AUTHORIZATION=f"Token {token}")
    return client


def _grant(user, folder, *codenames):
    role = Role.objects.create(
        name=f"integration-config-{uuid.uuid4().hex[:8]}",
        folder=Folder.get_root_folder(),
    )
    role.permissions.set(Permission.objects.filter(codename__in=codenames))
    assignment = RoleAssignment.objects.create(
        user=user,
        role=role,
        folder=Folder.get_root_folder(),
        is_recursive=True,
    )
    assignment.perimeter_folders.add(folder)
    return assignment


@pytest.fixture
def configuration_world(app_config):
    root = Folder.get_root_folder()
    source = Folder.objects.create(
        name=f"config-source-{uuid.uuid4().hex[:8]}",
        parent_folder=root,
        content_type=Folder.ContentType.DOMAIN,
    )
    target = Folder.objects.create(
        name=f"config-target-{uuid.uuid4().hex[:8]}",
        parent_folder=root,
        content_type=Folder.ContentType.DOMAIN,
    )
    hidden = Folder.objects.create(
        name=f"config-hidden-{uuid.uuid4().hex[:8]}",
        parent_folder=root,
        content_type=Folder.ContentType.DOMAIN,
    )
    provider, _ = IntegrationProvider.objects.get_or_create(
        name="servicenow",
        defaults={
            "provider_type": IntegrationProvider.ProviderType.ITSM,
            "folder": root,
        },
    )
    provider.folder = root
    provider.is_active = True
    provider.save(update_fields=["folder", "is_active", "updated_at"])
    configuration = IntegrationConfiguration.objects.create(
        provider=provider,
        folder=source,
        credentials={
            "instance_url": "https://source.service-now.com",
            "username": "source-user",
            "password": "locked-secret",
        },
        settings={"enable_incoming_sync": True},
        webhook_secret="webhook-secret",
    )
    user = User.objects.create_user(
        f"integration-config-{uuid.uuid4().hex[:8]}@tests.example",
        is_published=True,
    )
    user.folder = root
    user.save(update_fields=["folder"])
    source_assignment = _grant(
        user,
        source,
        "view_folder",
        "view_integrationconfiguration",
        "change_integrationconfiguration",
        "delete_integrationconfiguration",
    )
    return SimpleNamespace(
        root=root,
        source=source,
        target=target,
        hidden=hidden,
        provider=provider,
        configuration=configuration,
        user=user,
        source_assignment=source_assignment,
        client=_client(user),
    )


def _create_payload(world, *, folder=None, provider=None):
    return {
        "provider_id": str((provider or world.provider).id),
        "folder_id": str((folder or world.target).id),
        "credentials": {
            "instance_url": "https://new.service-now.com",
            "username": "new-user",
            "password": "new-secret",
        },
        "settings": {"enable_incoming_sync": True},
        "is_active": True,
        "webhook_secret": "new-webhook-secret",
    }


def _link_configuration(world):
    asset = Asset.objects.create(
        name=f"Linked asset {uuid.uuid4().hex[:8]}",
        folder=world.source,
        type="PR",
    )
    return SyncMapping.objects.create(
        configuration=world.configuration,
        content_type=ContentType.objects.get_for_model(Asset),
        local_object_id=asset.id,
        remote_id=f"REMOTE-{uuid.uuid4().hex[:8]}",
        folder=world.source,
    )


def _configuration_sync_job(world, status):
    now = timezone.now()
    shape = {}
    if status == IntegrationSyncJob.Status.PROCESSING:
        shape.update(attempt_id=uuid.uuid4(), claimed_at=now)
    elif status == IntegrationSyncJob.Status.UNCERTAIN:
        shape.update(
            attempt_id=uuid.uuid4(),
            claimed_at=now,
            effect_started_at=now,
            terminal_at=now,
        )
    elif status == IntegrationSyncJob.Status.REVIEW_REQUIRED:
        shape.update(terminal_at=now)
    return IntegrationSyncJob.objects.create(
        direction=IntegrationSyncJob.Direction.OUTBOUND,
        status=status,
        request_digest=uuid.uuid4().hex * 2,
        configuration_id_snapshot=world.configuration.id,
        provider_id_snapshot=world.provider.id,
        mapping_id_snapshot=uuid.uuid4(),
        content_type_id_snapshot=ContentType.objects.get_for_model(Asset).id,
        local_object_id_snapshot=uuid.uuid4(),
        folder_id_snapshot=world.source.id,
        origin_principal_snapshot="user:test",
        **shape,
    )


@pytest.mark.django_db
def test_create_requires_target_folder_view_and_add(configuration_world):
    world = configuration_world
    _grant(world.user, world.target, "view_folder")

    response = world.client.post(CONFIG_URL, _create_payload(world), format="json")

    assert response.status_code == 403, response.content
    assert not IntegrationConfiguration.objects.filter(folder=world.target).exists()


@pytest.mark.django_db
def test_put_move_requires_source_change_and_target_add(configuration_world):
    world = configuration_world
    _grant(world.user, world.target, "view_folder")
    payload = _create_payload(world)

    response = world.client.put(
        f"{CONFIG_URL}{world.configuration.id}/", payload, format="json"
    )

    assert response.status_code == 403, response.content
    world.configuration.refresh_from_db()
    assert world.configuration.folder_id == world.source.id
    assert world.configuration.credentials["password"] == "locked-secret"


@pytest.mark.django_db
def test_cross_domain_move_requires_change_on_source(configuration_world):
    world = configuration_world
    user = User.objects.create_user(
        f"target-only-{uuid.uuid4().hex[:8]}@tests.example",
        is_published=True,
    )
    user.folder = world.root
    user.save(update_fields=["folder"])
    _grant(
        user,
        world.source,
        "view_folder",
        "view_integrationconfiguration",
    )
    _grant(
        user,
        world.target,
        "view_folder",
        "add_integrationconfiguration",
        "change_integrationconfiguration",
    )

    response = _client(user).patch(
        f"{CONFIG_URL}{world.configuration.id}/",
        {"folder_id": str(world.target.id)},
        format="json",
    )

    assert response.status_code == 403, response.content
    world.configuration.refresh_from_db()
    assert world.configuration.folder_id == world.source.id


@pytest.mark.django_db
def test_partial_update_refetches_locked_credentials(configuration_world):
    world = configuration_world
    cache = IntegrationSchemaCache.objects.create(
        configuration=world.configuration,
        tables=[{"name": "cmdb_ci"}],
    )
    original_get_object = IntegrationConfigurationViewSet.get_object
    stale_object_returned = False

    def return_stale_then_replace_credentials(view):
        nonlocal stale_object_returned
        instance = original_get_object(view)
        if not stale_object_returned:
            stale_object_returned = True
            IntegrationConfiguration.objects.filter(id=instance.id).update(
                credentials={
                    "instance_url": "https://latest.service-now.com",
                    "username": "latest-user",
                    "password": "latest-secret",
                }
            )
        return instance

    with patch.object(
        IntegrationConfigurationViewSet,
        "get_object",
        return_stale_then_replace_credentials,
    ):
        response = world.client.patch(
            f"{CONFIG_URL}{world.configuration.id}/",
            {
                "credentials": {
                    "instance_url": "https://patched.service-now.com",
                    "username": "patched-user",
                }
            },
            format="json",
        )

    assert response.status_code == 200, response.content
    world.configuration.refresh_from_db()
    assert world.configuration.credentials == {
        "instance_url": "https://patched.service-now.com",
        "username": "patched-user",
        "password": "latest-secret",
    }
    assert not IntegrationSchemaCache.objects.filter(id=cache.id).exists()


@pytest.mark.django_db
def test_update_rechecks_source_iam_after_configuration_lock(configuration_world):
    world = configuration_world
    original_get_object = IntegrationConfigurationViewSet.get_object

    def return_then_revoke_source(view):
        instance = original_get_object(view)
        world.source_assignment.delete()
        return instance

    with patch.object(
        IntegrationConfigurationViewSet,
        "get_object",
        return_then_revoke_source,
    ):
        response = world.client.patch(
            f"{CONFIG_URL}{world.configuration.id}/",
            {"is_active": False},
            format="json",
        )

    assert response.status_code == 403, response.content
    world.configuration.refresh_from_db()
    assert world.configuration.is_active is True


@pytest.mark.django_db
def test_inactive_or_cross_domain_provider_is_rejected(configuration_world):
    world = configuration_world
    _grant(
        world.user,
        world.target,
        "view_folder",
        "add_integrationconfiguration",
    )
    world.provider.is_active = False
    world.provider.save(update_fields=["is_active", "updated_at"])

    inactive_response = world.client.patch(
        f"{CONFIG_URL}{world.configuration.id}/",
        {"is_active": False},
        format="json",
    )

    assert inactive_response.status_code == 403, inactive_response.content
    foreign_provider = IntegrationProvider.objects.create(
        name=f"servicenow-foreign-{uuid.uuid4().hex[:8]}",
        provider_type=IntegrationProvider.ProviderType.ITSM,
        folder=world.hidden,
        is_active=True,
    )
    with patch(
        "integrations.serializers.IntegrationRegistry.validate_configuration",
        return_value=(True, []),
    ):
        incoherent_response = world.client.post(
            CONFIG_URL,
            _create_payload(world, provider=foreign_provider),
            format="json",
        )

    assert incoherent_response.status_code == 403, incoherent_response.content
    assert not IntegrationConfiguration.objects.filter(folder=world.target).exists()


@pytest.mark.django_db
@pytest.mark.parametrize(
    "protected_field",
    ("provider", "folder", "credentials", "settings"),
)
def test_linked_configuration_requires_explicit_unlink_before_repointing(
    configuration_world, protected_field
):
    world = configuration_world
    mapping = _link_configuration(world)
    _grant(
        world.user,
        world.target,
        "view_folder",
        "add_integrationconfiguration",
    )
    alternate_provider = IntegrationProvider.objects.create(
        name=f"alternate-provider-{uuid.uuid4().hex[:8]}",
        provider_type=IntegrationProvider.ProviderType.ITSM,
        folder=world.root,
        is_active=True,
    )
    payload_by_field = {
        "provider": {
            "provider_id": str(alternate_provider.id),
            "credentials": {
                "instance_url": "https://alternate.service-now.com",
                "username": "alternate-user",
                "password": "alternate-secret",
            },
        },
        "folder": {"folder_id": str(world.target.id)},
        "credentials": {
            "credentials": {
                "instance_url": "https://changed.service-now.com",
                "username": "changed-user",
                "password": "changed-secret",
            }
        },
        "settings": {"settings": {"enable_incoming_sync": False}},
    }
    original = {
        "provider_id": world.configuration.provider_id,
        "folder_id": world.configuration.folder_id,
        "credentials": dict(world.configuration.credentials),
        "settings": dict(world.configuration.settings),
    }

    with patch(
        "integrations.serializers.IntegrationRegistry.validate_configuration",
        return_value=(True, []),
    ):
        response = world.client.patch(
            f"{CONFIG_URL}{world.configuration.id}/",
            payload_by_field[protected_field],
            format="json",
        )

    assert response.status_code == 400, response.content
    assert "Unlink all synchronized objects" in response.content.decode()
    world.configuration.refresh_from_db()
    mapping.refresh_from_db()
    assert world.configuration.provider_id == original["provider_id"]
    assert world.configuration.folder_id == original["folder_id"]
    assert world.configuration.credentials == original["credentials"]
    assert world.configuration.settings == original["settings"]
    assert mapping.configuration_id == world.configuration.id


@pytest.mark.django_db
def test_linked_configuration_may_be_deactivated_without_repointing(
    configuration_world,
):
    world = configuration_world
    mapping = _link_configuration(world)

    with patch(
        "integrations.serializers.IntegrationRegistry.validate_configuration",
        return_value=(True, []),
    ):
        response = world.client.patch(
            f"{CONFIG_URL}{world.configuration.id}/",
            {"is_active": False},
            format="json",
        )

    assert response.status_code == 200, response.content
    world.configuration.refresh_from_db()
    mapping.refresh_from_db()
    assert world.configuration.is_active is False
    assert mapping.configuration_id == world.configuration.id


@pytest.mark.django_db
def test_configuration_delete_requires_explicit_mapping_unlink(
    configuration_world,
):
    world = configuration_world
    mapping = _link_configuration(world)
    url = f"{CONFIG_URL}{world.configuration.id}/"

    blocked = world.client.delete(url)

    assert blocked.status_code == 400, blocked.content
    assert IntegrationConfiguration.objects.filter(id=world.configuration.id).exists()
    assert SyncMapping.objects.filter(id=mapping.id).exists()

    mapping.delete()
    deleted = world.client.delete(url)

    assert deleted.status_code == 204, deleted.content
    assert not IntegrationConfiguration.objects.filter(
        id=world.configuration.id
    ).exists()


@pytest.mark.django_db
@pytest.mark.parametrize(
    "job_status",
    (
        IntegrationSyncJob.Status.QUEUED,
        IntegrationSyncJob.Status.PROCESSING,
        IntegrationSyncJob.Status.UNCERTAIN,
        IntegrationSyncJob.Status.REVIEW_REQUIRED,
    ),
)
def test_configuration_update_rejects_unresolved_snapshot_job(
    configuration_world, job_status
):
    world = configuration_world
    job = _configuration_sync_job(world, job_status)

    with patch(
        "integrations.serializers.IntegrationRegistry.validate_configuration",
        return_value=(True, []),
    ):
        response = world.client.patch(
            f"{CONFIG_URL}{world.configuration.id}/",
            {"is_active": False},
            format="json",
        )

    assert response.status_code == 409, response.content
    assert "pending or unresolved work" in str(response.json())
    world.configuration.refresh_from_db()
    job.refresh_from_db()
    assert world.configuration.is_active is True
    assert job.status == job_status


@pytest.mark.django_db
def test_configuration_delete_rejects_unresolved_snapshot_job(
    configuration_world,
):
    world = configuration_world
    job = _configuration_sync_job(world, IntegrationSyncJob.Status.QUEUED)

    response = world.client.delete(f"{CONFIG_URL}{world.configuration.id}/")

    assert response.status_code == 409, response.content
    assert IntegrationConfiguration.objects.filter(id=world.configuration.id).exists()
    job.refresh_from_db()
    assert job.status == IntegrationSyncJob.Status.QUEUED


@pytest.mark.django_db
def test_schema_cache_delete_rolls_back_with_failed_update(configuration_world):
    world = configuration_world
    cache = IntegrationSchemaCache.objects.create(
        configuration=world.configuration,
        tables=[{"name": "cmdb_ci"}],
    )
    original_perform_update = IntegrationConfigurationViewSet.perform_update

    def save_then_fail(view, serializer):
        original_perform_update(view, serializer)
        raise ValidationError("forced failure")

    with patch.object(
        IntegrationConfigurationViewSet,
        "perform_update",
        save_then_fail,
    ):
        response = world.client.patch(
            f"{CONFIG_URL}{world.configuration.id}/",
            {
                "credentials": {
                    "instance_url": "https://rolled-back.service-now.com",
                    "username": "source-user",
                }
            },
            format="json",
        )

    assert response.status_code == 400, response.content
    world.configuration.refresh_from_db()
    assert world.configuration.credentials["instance_url"] == (
        "https://source.service-now.com"
    )
    assert IntegrationSchemaCache.objects.filter(id=cache.id).exists()


@pytest.mark.django_db
def test_serializer_save_cannot_bypass_locked_view(configuration_world):
    world = configuration_world
    serializer = IntegrationConfigurationSerializer(
        world.configuration,
        data={"is_active": False},
        partial=True,
        context={"request": SimpleNamespace(user=world.user)},
    )
    assert serializer.is_valid(), serializer.errors

    with pytest.raises(PermissionDenied):
        serializer.save()
    with pytest.raises(PermissionDenied):
        serializer.delete(world.configuration)

    world.configuration.refresh_from_db()
    assert world.configuration.is_active is True


@pytest.mark.django_db
def test_serializer_create_cannot_bypass_locked_view(configuration_world):
    world = configuration_world
    _grant(
        world.user,
        world.target,
        "view_folder",
        "add_integrationconfiguration",
    )
    serializer = IntegrationConfigurationSerializer(
        data=_create_payload(world),
        context={"request": SimpleNamespace(user=world.user)},
    )
    assert serializer.is_valid(), serializer.errors

    with pytest.raises(PermissionDenied):
        serializer.save()

    assert not IntegrationConfiguration.objects.filter(folder=world.target).exists()


@pytest.mark.django_db
def test_webhook_without_exact_mapping_is_acknowledged_but_not_queued(
    configuration_world,
):
    world = configuration_world
    orchestrator = SimpleNamespace(
        validate_webhook_request=lambda _request: True,
        extract_webhook_event_type=lambda _payload: "updated",
        extract_webhook_remote_id=lambda _payload: "REMOTE-MISSING",
    )
    with (
        patch(
            "integrations.views.IntegrationRegistry.get_orchestrator",
            return_value=orchestrator,
        ),
        patch(
            "integrations.capabilities.enqueue_integration_sync_jobs"
        ) as enqueue_jobs,
    ):
        response = APIClient().post(
            f"/api/integrations/webhook/{world.configuration.id}/",
            {"sys_id": "REMOTE-MISSING"},
            format="json",
        )

    assert response.status_code == 202, response.content
    assert not IntegrationSyncJob.objects.exists()
    enqueue_jobs.assert_not_called()


@pytest.mark.django_db
def test_webhook_persists_exact_job_before_queueing_uuid(
    configuration_world, django_capture_on_commit_callbacks
):
    world = configuration_world
    asset = Asset.objects.create(name="Webhook asset", folder=world.source, type="PR")
    mapping = SyncMapping.objects.create(
        configuration=world.configuration,
        content_type=ContentType.objects.get_for_model(Asset),
        local_object_id=asset.id,
        remote_id="REMOTE-EXACT",
        folder=world.source,
    )
    payload = {"sys_id": "REMOTE-EXACT"}
    orchestrator = SimpleNamespace(
        validate_webhook_request=lambda _request: True,
        extract_webhook_event_type=lambda _payload: "updated",
        extract_webhook_remote_id=lambda _payload: "REMOTE-EXACT",
    )
    with (
        patch(
            "integrations.views.IntegrationRegistry.get_orchestrator",
            return_value=orchestrator,
        ),
        patch(
            "integrations.capabilities.enqueue_integration_sync_jobs"
        ) as enqueue_jobs,
    ):
        with django_capture_on_commit_callbacks(execute=False) as callbacks:
            response = APIClient().post(
                f"/api/integrations/webhook/{world.configuration.id}/",
                payload,
                format="json",
            )

    assert response.status_code == 202, response.content
    job = IntegrationSyncJob.objects.get(
        mapping_id_snapshot=mapping.id,
        direction=IntegrationSyncJob.Direction.INCOMING,
    )
    assert job.status == IntegrationSyncJob.Status.QUEUED
    assert job.capability["configuration_id"] == str(world.configuration.id)
    assert job.event_type == "updated"
    assert job.payload == payload
    enqueue_jobs.assert_not_called()
    for callback in callbacks:
        callback()
    enqueue_jobs.assert_called_once_with((job.id,))
