import uuid
from unittest.mock import patch

import pytest
from core.models import Asset
from django.contrib.auth.models import Permission
from django.contrib.contenttypes.models import ContentType
from django.db import IntegrityError
from django.db.models import QuerySet
from django.utils import timezone
from iam.models import Folder, Role, RoleAssignment, User
from integrations.models import (
    IntegrationConfiguration,
    IntegrationProvider,
    IntegrationSyncJob,
    SyncEvent,
    SyncMapping,
)
from knox.models import AuthToken
from rest_framework.test import APIClient

FULL_GRAPH_PERMISSIONS = {
    "view_folder",
    "view_asset",
    "change_asset",
    "view_integrationprovider",
    "view_integrationconfiguration",
    "change_integrationconfiguration",
    "view_syncmapping",
    "add_syncmapping",
    "change_syncmapping",
    "delete_syncmapping",
}


def _client(user):
    client = APIClient()
    _, token = AuthToken.objects.create(user=user)
    client.credentials(HTTP_AUTHORIZATION=f"Token {token}")
    return client


def _user_with_permissions(folder, codenames):
    suffix = uuid.uuid4().hex[:8]
    role = Role.objects.create(name=f"sync-map-{suffix}", folder=folder)
    role.permissions.set(Permission.objects.filter(codename__in=codenames))
    user = User.objects.create_user(
        f"sync-map-{suffix}@tests.example", is_published=True
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
def sync_mapping_world(app_config):
    root = Folder.get_root_folder()
    folder = Folder.objects.create(
        name=f"sync-map-{uuid.uuid4().hex[:8]}",
        parent_folder=root,
        content_type=Folder.ContentType.DOMAIN,
    )
    other_folder = Folder.objects.create(
        name=f"sync-map-other-{uuid.uuid4().hex[:8]}",
        parent_folder=root,
        content_type=Folder.ContentType.DOMAIN,
    )
    provider = IntegrationProvider.objects.create(
        name=f"provider-{uuid.uuid4().hex[:8]}",
        provider_type=IntegrationProvider.ProviderType.ITSM,
        folder=folder,
    )
    configuration = IntegrationConfiguration.objects.create(
        provider=provider,
        folder=folder,
        credentials={},
        settings={"enable_outgoing_sync": True},
        webhook_secret="test-secret",
    )
    return {
        "root": root,
        "folder": folder,
        "other_folder": other_folder,
        "provider": provider,
        "configuration": configuration,
    }


def _mapping(world, local_object, *, remote_id="REMOTE-1", folder=None):
    return SyncMapping.objects.create(
        configuration=world["configuration"],
        content_type=ContentType.objects.get_for_model(type(local_object)),
        local_object_id=local_object.id,
        remote_id=remote_id,
        folder=folder or world["folder"],
    )


def _sync_job(world, mapping, status):
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
    elif status in {
        IntegrationSyncJob.Status.SUCCEEDED,
        IntegrationSyncJob.Status.SUPERSEDED,
        IntegrationSyncJob.Status.FAILED,
    }:
        shape.update(terminal_at=now)
    return IntegrationSyncJob.objects.create(
        direction=IntegrationSyncJob.Direction.OUTBOUND,
        status=status,
        request_digest=uuid.uuid4().hex * 2,
        configuration_id_snapshot=world["configuration"].id,
        provider_id_snapshot=world["provider"].id,
        mapping_id_snapshot=mapping.id,
        content_type_id_snapshot=mapping.content_type_id,
        local_object_id_snapshot=mapping.local_object_id,
        folder_id_snapshot=mapping.folder_id,
        origin_principal_snapshot="user:test",
        **shape,
    )


@pytest.mark.django_db
def test_explicit_link_rejects_remote_id_owned_by_another_local_object(
    sync_mapping_world,
):
    world = sync_mapping_world
    owner = Asset.objects.create(name="remote owner", folder=world["folder"])
    target = Asset.objects.create(name="unchanged", folder=world["folder"])
    existing = _mapping(world, owner, remote_id="REMOTE-EXCLUSIVE")
    user = _user_with_permissions(world["folder"], FULL_GRAPH_PERMISSIONS)

    with patch("core.views.persist_outbound_sync_jobs") as persist_jobs:
        response = _client(user).patch(
            f"/api/assets/{target.id}/",
            {
                "name": "must roll back",
                "integration_config": str(world["configuration"].id),
                "remote_object_id": "REMOTE-EXCLUSIVE",
            },
            format="json",
        )

    assert response.status_code == 409, response.content
    assert "already linked or unavailable" in str(response.json())
    target.refresh_from_db()
    existing.refresh_from_db()
    assert target.name == "unchanged"
    assert existing.local_object_id == owner.id
    assert SyncMapping.objects.filter(configuration=world["configuration"]).count() == 1
    persist_jobs.assert_not_called()


@pytest.mark.django_db
def test_explicit_link_rejects_provider_equivalent_remote_id(
    sync_mapping_world,
):
    world = sync_mapping_world
    provider = world["provider"]
    provider.name = "jira"
    provider.save(update_fields=["name"])
    owner = Asset.objects.create(name="remote owner", folder=world["folder"])
    target = Asset.objects.create(name="unchanged", folder=world["folder"])
    existing = _mapping(world, owner, remote_id="PROJ-123")
    user = _user_with_permissions(world["folder"], FULL_GRAPH_PERMISSIONS)

    with patch("core.views.persist_outbound_sync_jobs") as persist_jobs:
        response = _client(user).patch(
            f"/api/assets/{target.id}/",
            {
                "integration_config": str(world["configuration"].id),
                "remote_object_id": "proj-123",
            },
            format="json",
        )

    assert response.status_code == 409, response.content
    existing.refresh_from_db()
    assert existing.remote_id == "PROJ-123"
    assert existing.local_object_id == owner.id
    assert SyncMapping.objects.filter(configuration=world["configuration"]).count() == 1
    persist_jobs.assert_not_called()


@pytest.mark.django_db
def test_explicit_link_stores_only_provider_canonical_remote_id(
    sync_mapping_world,
):
    world = sync_mapping_world
    provider = world["provider"]
    provider.name = "jira"
    provider.save(update_fields=["name"])
    target = Asset.objects.create(name="target", folder=world["folder"])
    user = _user_with_permissions(world["folder"], FULL_GRAPH_PERMISSIONS)

    with patch("core.views.persist_outbound_sync_jobs"):
        response = _client(user).patch(
            f"/api/assets/{target.id}/",
            {
                "integration_config": str(world["configuration"].id),
                "remote_object_id": "proj-456",
            },
            format="json",
        )

    assert response.status_code == 200, response.content
    mapping = SyncMapping.objects.get(configuration=world["configuration"])
    assert mapping.remote_id == "PROJ-456"


@pytest.mark.django_db
def test_explicit_link_translates_database_uniqueness_race_to_409(
    sync_mapping_world,
):
    world = sync_mapping_world
    target = Asset.objects.create(name="unchanged", folder=world["folder"])
    user = _user_with_permissions(world["folder"], FULL_GRAPH_PERMISSIONS)

    with (
        patch(
            "core.views.SyncMapping.objects.create",
            side_effect=IntegrityError("simulated uniqueness race"),
        ),
        patch("core.views.persist_outbound_sync_jobs") as persist_jobs,
    ):
        response = _client(user).patch(
            f"/api/assets/{target.id}/",
            {
                "name": "must roll back",
                "integration_config": str(world["configuration"].id),
                "remote_object_id": "REMOTE-RACE",
            },
            format="json",
        )

    assert response.status_code == 409, response.content
    assert "already linked or unavailable" in str(response.json())
    target.refresh_from_db()
    assert target.name == "unchanged"
    assert not SyncMapping.objects.exists()
    persist_jobs.assert_not_called()


@pytest.mark.django_db
def test_explicit_link_uses_global_integration_lock_order(
    sync_mapping_world, monkeypatch
):
    world = sync_mapping_world
    target = Asset.objects.create(name="target", folder=world["folder"])
    user = _user_with_permissions(world["folder"], FULL_GRAPH_PERMISSIONS)
    lock_order = []
    original_select_for_update = QuerySet.select_for_update

    def record_select_for_update(queryset, *args, **kwargs):
        lock_order.append(queryset.model._meta.label_lower)
        return original_select_for_update(queryset, *args, **kwargs)

    monkeypatch.setattr(QuerySet, "select_for_update", record_select_for_update)
    with patch("core.views.persist_outbound_sync_jobs"):
        response = _client(user).patch(
            f"/api/assets/{target.id}/",
            {
                "integration_config": str(world["configuration"].id),
                "remote_object_id": "REMOTE-ORDER",
            },
            format="json",
        )

    assert response.status_code == 200, response.content
    configuration_position = lock_order.index("integrations.integrationconfiguration")
    provider_position = lock_order.index("integrations.integrationprovider")
    mapping_position = lock_order.index("integrations.syncmapping")
    local_position = lock_order.index("core.asset")
    assert lock_order[:configuration_position].count("iam.folder") >= 2
    assert (
        configuration_position < provider_position < mapping_position < local_position
    )


@pytest.mark.django_db
def test_explicit_relink_rejects_unresolved_job_and_rolls_back_local_change(
    sync_mapping_world,
):
    world = sync_mapping_world
    target = Asset.objects.create(name="unchanged", folder=world["folder"])
    mapping = _mapping(world, target, remote_id="REMOTE-OLD")
    job = _sync_job(world, mapping, IntegrationSyncJob.Status.QUEUED)
    user = _user_with_permissions(world["folder"], FULL_GRAPH_PERMISSIONS)

    with patch("core.views.persist_outbound_sync_jobs") as persist_jobs:
        response = _client(user).patch(
            f"/api/assets/{target.id}/",
            {
                "integration_config": str(world["configuration"].id),
                "remote_object_id": "REMOTE-NEW",
            },
            format="json",
        )

    assert response.status_code == 409, response.content
    target.refresh_from_db()
    mapping.refresh_from_db()
    job.refresh_from_db()
    assert target.name == "unchanged"
    assert mapping.remote_id == "REMOTE-OLD"
    assert mapping.version == 1
    assert job.status == IntegrationSyncJob.Status.QUEUED
    assert not SyncEvent.objects.filter(mapping_id_snapshot=mapping.id).exists()
    persist_jobs.assert_not_called()


@pytest.mark.django_db
def test_explicit_relink_versions_and_attributes_append_only_event(
    sync_mapping_world,
):
    world = sync_mapping_world
    target = Asset.objects.create(name="target", folder=world["folder"])
    mapping = _mapping(world, target, remote_id="REMOTE-OLD")
    user = _user_with_permissions(world["folder"], FULL_GRAPH_PERMISSIONS)

    with patch("core.views.persist_outbound_sync_jobs") as persist_jobs:
        response = _client(user).patch(
            f"/api/assets/{target.id}/",
            {
                "integration_config": str(world["configuration"].id),
                "remote_object_id": "REMOTE-NEW",
            },
            format="json",
        )

    assert response.status_code == 200, response.content
    mapping.refresh_from_db()
    assert mapping.remote_id == "REMOTE-NEW"
    assert mapping.sync_status == SyncMapping.SyncStatus.PENDING
    assert mapping.version == 2
    event = SyncEvent.objects.get(mapping_id_snapshot=mapping.id)
    assert event.mapping_id == mapping.id
    assert event.job_id_snapshot is None
    assert event.actor_id_snapshot == user.id
    assert event.changes == {
        "action": "relink",
        "before": {
            "local_object_id": str(target.id),
            "remote_id": "REMOTE-OLD",
            "sync_status": SyncMapping.SyncStatus.SYNCED,
        },
        "after": {
            "local_object_id": str(target.id),
            "remote_id": "REMOTE-NEW",
            "sync_status": SyncMapping.SyncStatus.PENDING,
        },
        "mapping_version": 2,
    }
    persist_jobs.assert_called_once()


@pytest.mark.django_db
def test_mapping_delete_requires_and_accepts_exact_graph_authority(
    sync_mapping_world,
):
    world = sync_mapping_world
    local_object = Asset.objects.create(name="linked", folder=world["folder"])
    mapping = _mapping(world, local_object)
    user = _user_with_permissions(world["folder"], FULL_GRAPH_PERMISSIONS)

    response = _client(user).delete(f"/api/integrations/sync-mappings/{mapping.id}/")

    assert response.status_code == 204, response.content
    assert not SyncMapping.objects.filter(id=mapping.id).exists()
    assert Asset.objects.filter(id=local_object.id).exists()
    assert IntegrationConfiguration.objects.filter(
        id=world["configuration"].id
    ).exists()
    event = SyncEvent.objects.get(mapping_id_snapshot=mapping.id)
    assert event.mapping_id is None
    assert event.actor_id_snapshot == user.id
    assert event.changes["action"] == "unlink"
    assert event.changes["mapping_version"] == 2
    assert event.remote_id_snapshot == "REMOTE-1"


@pytest.mark.django_db
def test_mapping_delete_allows_authorized_cleanup_of_old_noncanonical_id(
    sync_mapping_world,
):
    world = sync_mapping_world
    provider = world["provider"]
    provider.name = "jira"
    provider.save(update_fields=["name"])
    local_object = Asset.objects.create(name="linked", folder=world["folder"])
    mapping = _mapping(world, local_object, remote_id=" proj-1 ")
    user = _user_with_permissions(world["folder"], FULL_GRAPH_PERMISSIONS)

    response = _client(user).delete(f"/api/integrations/sync-mappings/{mapping.id}/")

    assert response.status_code == 204, response.content
    assert not SyncMapping.objects.filter(id=mapping.id).exists()


@pytest.mark.django_db
@pytest.mark.parametrize(
    "missing_permission",
    (
        "delete_syncmapping",
        "change_integrationconfiguration",
        "change_asset",
        "view_integrationconfiguration",
        "view_integrationprovider",
    ),
)
def test_mapping_delete_fails_closed_when_a_graph_authority_is_missing(
    sync_mapping_world, missing_permission
):
    world = sync_mapping_world
    local_object = Asset.objects.create(name="linked", folder=world["folder"])
    mapping = _mapping(world, local_object)
    user = _user_with_permissions(
        world["folder"], FULL_GRAPH_PERMISSIONS - {missing_permission}
    )

    response = _client(user).delete(f"/api/integrations/sync-mappings/{mapping.id}/")

    assert response.status_code == 403, response.content
    assert SyncMapping.objects.filter(id=mapping.id).exists()


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
def test_mapping_delete_rejects_pending_or_unresolved_sync_job(
    sync_mapping_world, job_status
):
    world = sync_mapping_world
    local_object = Asset.objects.create(name="linked", folder=world["folder"])
    mapping = _mapping(world, local_object)
    job = _sync_job(world, mapping, job_status)
    user = _user_with_permissions(world["folder"], FULL_GRAPH_PERMISSIONS)

    response = _client(user).delete(f"/api/integrations/sync-mappings/{mapping.id}/")

    assert response.status_code == 409, response.content
    assert "pending or unresolved work" in str(response.json())
    assert SyncMapping.objects.filter(id=mapping.id).exists()
    job.refresh_from_db()
    assert job.status == job_status


@pytest.mark.django_db
def test_mapping_delete_fails_closed_for_cross_folder_local_object(
    sync_mapping_world,
):
    world = sync_mapping_world
    local_object = Asset.objects.create(name="hidden", folder=world["other_folder"])
    mapping = _mapping(world, local_object, folder=world["folder"])
    user = _user_with_permissions(world["folder"], FULL_GRAPH_PERMISSIONS)

    response = _client(user).delete(f"/api/integrations/sync-mappings/{mapping.id}/")

    assert response.status_code == 403, response.content
    assert SyncMapping.objects.filter(id=mapping.id).exists()


@pytest.mark.django_db
def test_mapping_delete_fails_closed_for_incoherent_provider_ancestor(
    sync_mapping_world,
):
    world = sync_mapping_world
    local_object = Asset.objects.create(name="linked", folder=world["folder"])
    mapping = _mapping(world, local_object)
    provider = world["provider"]
    provider.folder = world["other_folder"]
    provider.save(update_fields=["folder"])
    # Root-scoped permissions make every graph node independently visible; the
    # denial therefore proves relationship coherence rather than hidden IAM.
    user = _user_with_permissions(world["root"], FULL_GRAPH_PERMISSIONS)

    response = _client(user).delete(f"/api/integrations/sync-mappings/{mapping.id}/")

    assert response.status_code == 403, response.content
    assert SyncMapping.objects.filter(id=mapping.id).exists()
