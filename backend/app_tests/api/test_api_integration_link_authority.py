import uuid
from unittest.mock import patch

import pytest
from core.models import AppliedControl, Asset
from core.utils import RoleCodename
from django.contrib.auth.models import Permission
from django.contrib.contenttypes.models import ContentType
from django.db import IntegrityError
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


def _client(user):
    client = APIClient()
    _, token = AuthToken.objects.create(user=user)
    client.credentials(HTTP_AUTHORIZATION=f"Token {token}")
    return client


@pytest.fixture
def integration_world(app_config):
    root = Folder.get_root_folder()
    own_folder = Folder.objects.create(
        name=f"integration-own-{uuid.uuid4().hex[:6]}",
        parent_folder=root,
        content_type=Folder.ContentType.DOMAIN,
    )
    hidden_folder = Folder.objects.create(
        name=f"integration-hidden-{uuid.uuid4().hex[:6]}",
        parent_folder=root,
        content_type=Folder.ContentType.DOMAIN,
    )
    provider = IntegrationProvider.objects.create(
        name=f"provider-{uuid.uuid4().hex[:6]}",
        provider_type=IntegrationProvider.ProviderType.ITSM,
        folder=root,
    )
    own_config = IntegrationConfiguration.objects.create(
        provider=provider,
        folder=own_folder,
        credentials={},
        settings={"enable_outgoing_sync": True},
        webhook_secret="secret",
    )
    hidden_config = IntegrationConfiguration.objects.create(
        provider=provider,
        folder=hidden_folder,
        credentials={},
        settings={"enable_outgoing_sync": True},
        webhook_secret="secret",
    )
    user = User.objects.create_user(
        f"integration-{uuid.uuid4().hex[:8]}@tests.example", is_published=True
    )
    user.folder = own_folder
    user.save(update_fields=["folder"])
    assignment = RoleAssignment.objects.create(
        user=user,
        role=Role.objects.get(name=RoleCodename.DOMAIN_MANAGER.value),
        folder=own_folder,
        is_recursive=True,
    )
    assignment.perimeter_folders.add(own_folder)
    provider_role = Role.objects.create(
        name=f"integration-provider-{uuid.uuid4().hex[:6]}", folder=root
    )
    provider_role.permissions.set(
        Permission.objects.filter(codename="view_integrationprovider")
    )
    provider_assignment = RoleAssignment.objects.create(
        user=user,
        role=provider_role,
        folder=root,
        is_recursive=True,
    )
    provider_assignment.perimeter_folders.add(root)
    return {
        "root": root,
        "own_folder": own_folder,
        "hidden_folder": hidden_folder,
        "provider": provider,
        "own_config": own_config,
        "hidden_config": hidden_config,
        "user": user,
        "client": _client(user),
    }


def _model_contract(kind, folder, *, name="original"):
    if kind == "asset":
        return Asset, "/api/assets/", {"name": name, "folder": str(folder.id)}
    return (
        AppliedControl,
        "/api/applied-controls/",
        {
            "name": name,
            "folder": str(folder.id),
        },
    )


@pytest.mark.django_db
@pytest.mark.parametrize("kind", ("asset", "applied_control"))
def test_hidden_integration_config_create_is_atomic_and_has_no_task(
    integration_world, kind
):
    world = integration_world
    model, url, payload = _model_contract(kind, world["own_folder"])
    payload.update(
        {
            "integration_config": str(world["hidden_config"].id),
            "create_remote_object": True,
        }
    )

    with patch("core.views.persist_outbound_sync_jobs") as persist_jobs:
        response = world["client"].post(url, payload, format="json")

    assert response.status_code == 403, response.content
    assert not model.objects.filter(name="original").exists()
    assert not SyncMapping.objects.exists()
    persist_jobs.assert_not_called()


@pytest.mark.django_db
@pytest.mark.parametrize("kind", ("asset", "applied_control"))
def test_hidden_integration_config_update_rolls_back_object_and_mapping(
    integration_world, kind
):
    world = integration_world
    model, url, _ = _model_contract(kind, world["own_folder"])
    instance = model.objects.create(name="original", folder=world["own_folder"])

    with patch("core.views.persist_outbound_sync_jobs") as persist_jobs:
        response = world["client"].patch(
            f"{url}{instance.id}/",
            {
                "name": "unauthorized-change",
                "integration_config": str(world["hidden_config"].id),
                "remote_object_id": "REMOTE-HIDDEN",
            },
            format="json",
        )

    assert response.status_code == 403, response.content
    instance.refresh_from_db()
    assert instance.name == "original"
    assert not SyncMapping.objects.exists()
    persist_jobs.assert_not_called()


@pytest.mark.django_db
@pytest.mark.parametrize("kind", ("asset", "applied_control"))
def test_visible_cross_folder_config_is_rejected_atomically(
    integration_world, authenticated_client, kind
):
    world = integration_world
    model, url, _ = _model_contract(kind, world["own_folder"])
    instance = model.objects.create(name="original", folder=world["own_folder"])

    with patch("core.views.persist_outbound_sync_jobs") as persist_jobs:
        response = authenticated_client.patch(
            f"{url}{instance.id}/",
            {
                "name": "must-roll-back",
                "integration_config": str(world["hidden_config"].id),
                "remote_object_id": "REMOTE-CROSS-FOLDER",
            },
            format="json",
        )

    assert response.status_code == 403, response.content
    instance.refresh_from_db()
    assert instance.name == "original"
    assert not SyncMapping.objects.exists()
    persist_jobs.assert_not_called()


@pytest.mark.django_db
@pytest.mark.parametrize("kind", ("asset", "applied_control"))
def test_inactive_provider_link_is_rejected_atomically(integration_world, kind):
    world = integration_world
    model, url, _ = _model_contract(kind, world["own_folder"])
    instance = model.objects.create(name="original", folder=world["own_folder"])
    provider = world["own_config"].provider
    provider.is_active = False
    provider.save(update_fields=["is_active"])

    with patch("core.views.persist_outbound_sync_jobs") as persist_jobs:
        response = world["client"].patch(
            f"{url}{instance.id}/",
            {
                "name": "must-roll-back",
                "integration_config": str(world["own_config"].id),
                "remote_object_id": "REMOTE-INACTIVE",
            },
            format="json",
        )

    assert response.status_code == 403, response.content
    instance.refresh_from_db()
    assert instance.name == "original"
    assert not SyncMapping.objects.exists()
    persist_jobs.assert_not_called()


@pytest.mark.django_db
@pytest.mark.parametrize("kind", ("asset", "applied_control"))
def test_mapping_write_commits_before_external_task(integration_world, kind):
    world = integration_world
    model, url, _ = _model_contract(kind, world["own_folder"])
    instance = model.objects.create(name="original", folder=world["own_folder"])

    with patch("core.views.persist_outbound_sync_jobs") as persist_jobs:
        response = world["client"].patch(
            f"{url}{instance.id}/",
            {
                "integration_config": str(world["own_config"].id),
                "remote_object_id": "REMOTE-1",
            },
            format="json",
        )
        assert response.status_code == 200, response.content
        mapping = SyncMapping.objects.get(
            configuration=world["own_config"],
            content_type=ContentType.objects.get_for_model(model),
            local_object_id=instance.id,
        )
        assert mapping.folder_id == world["own_folder"].id
        assert mapping.remote_id == "REMOTE-1"
        assert mapping.sync_status == SyncMapping.SyncStatus.PENDING
        persist_jobs.assert_called_once()


@pytest.mark.django_db
@pytest.mark.parametrize("kind", ("asset", "applied_control"))
def test_remote_create_persists_pending_mapping_before_external_task(
    integration_world, kind
):
    world = integration_world
    model, url, payload = _model_contract(kind, world["own_folder"])
    payload.update(
        {
            "integration_config": str(world["own_config"].id),
            "create_remote_object": True,
        }
    )

    with patch("core.views.persist_outbound_sync_jobs") as persist_jobs:
        response = world["client"].post(url, payload, format="json")
        assert response.status_code == 201, response.content
        instance = model.objects.get(name="original")
        mapping = SyncMapping.objects.get(
            configuration=world["own_config"],
            content_type=ContentType.objects.get_for_model(model),
            local_object_id=instance.id,
        )
        assert mapping.remote_id == ""
        assert mapping.folder_id == world["own_folder"].id
        assert mapping.sync_status == SyncMapping.SyncStatus.PENDING
        persist_jobs.assert_called_once()


@pytest.mark.django_db
def test_mapping_failure_rolls_back_applied_control_update(
    integration_world,
):
    world = integration_world
    control = AppliedControl.objects.create(name="original", folder=world["own_folder"])

    with (
        patch("core.views.SyncMapping.objects.create", side_effect=IntegrityError),
        patch("core.views.persist_outbound_sync_jobs") as persist_jobs,
        pytest.raises(IntegrityError),
    ):
        world["client"].patch(
            f"/api/applied-controls/{control.id}/",
            {
                "name": "must-roll-back",
                "integration_config": str(world["own_config"].id),
                "remote_object_id": "REMOTE-FAIL",
            },
            format="json",
        )

    control.refresh_from_db()
    assert control.name == "original"
    assert not SyncMapping.objects.exists()
    persist_jobs.assert_not_called()


@pytest.mark.django_db
@pytest.mark.parametrize("kind", ("asset", "applied_control"))
def test_detail_projects_only_exact_visible_same_folder_mapping(
    integration_world, kind
):
    world = integration_world
    model, url, _ = _model_contract(kind, world["own_folder"])
    instance = model.objects.create(name="projection", folder=world["own_folder"])
    exact_content_type = ContentType.objects.get_for_model(model)
    other_model = AppliedControl if model is Asset else Asset
    other_content_type = ContentType.objects.get_for_model(other_model)
    visible = SyncMapping.objects.create(
        configuration=world["own_config"],
        content_type=exact_content_type,
        local_object_id=instance.id,
        remote_id="VISIBLE-EXACT",
        folder=world["own_folder"],
    )
    SyncMapping.objects.create(
        configuration=world["hidden_config"],
        content_type=exact_content_type,
        local_object_id=instance.id,
        remote_id="HIDDEN-CONFIG",
        error_message="hidden-error",
        folder=world["hidden_folder"],
    )
    SyncMapping.objects.create(
        configuration=world["own_config"],
        content_type=other_content_type,
        local_object_id=instance.id,
        remote_id="OTHER-MODEL-COLLISION",
        folder=world["own_folder"],
    )

    response = world["client"].get(f"{url}{instance.id}/")

    assert response.status_code == 200, response.content
    assert response.json()["sync_mappings"] == [
        {
            "id": str(visible.id),
            "remote_id": "VISIBLE-EXACT",
            "sync_status": SyncMapping.SyncStatus.SYNCED,
            "last_synced_at": None,
            "last_sync_direction": "",
            "error_message": "",
            "provider": world["own_config"].provider.name,
        }
    ]
    assert "HIDDEN-CONFIG" not in response.content.decode()
    assert "hidden-error" not in response.content.decode()
    assert "OTHER-MODEL-COLLISION" not in response.content.decode()


@pytest.mark.django_db
@pytest.mark.parametrize("kind", ("asset", "applied_control"))
def test_linked_object_requires_explicit_unlink_before_delete(integration_world, kind):
    world = integration_world
    model, url, _ = _model_contract(kind, world["own_folder"])
    instance = model.objects.create(name="linked-delete", folder=world["own_folder"])
    mapping = SyncMapping.objects.create(
        configuration=world["own_config"],
        content_type=ContentType.objects.get_for_model(model),
        local_object_id=instance.id,
        remote_id=f"DELETE-{uuid.uuid4().hex[:8]}",
        folder=world["own_folder"],
    )

    response = world["client"].delete(f"{url}{instance.id}/")

    assert response.status_code == 409, response.content
    assert "Unlink all synchronized objects" in str(response.json())
    assert model.objects.filter(id=instance.id).exists()
    assert SyncMapping.objects.filter(id=mapping.id).exists()


@pytest.mark.django_db
@pytest.mark.parametrize("kind", ("asset", "applied_control"))
def test_linked_object_requires_explicit_unlink_before_folder_move(
    integration_world, kind
):
    world = integration_world
    destination = Folder.objects.create(
        name=f"integration-destination-{uuid.uuid4().hex[:6]}",
        parent_folder=world["own_folder"],
        content_type=Folder.ContentType.DOMAIN,
    )
    model, url, _ = _model_contract(kind, world["own_folder"])
    instance = model.objects.create(name="linked-move", folder=world["own_folder"])
    mapping = SyncMapping.objects.create(
        configuration=world["own_config"],
        content_type=ContentType.objects.get_for_model(model),
        local_object_id=instance.id,
        remote_id=f"MOVE-{uuid.uuid4().hex[:8]}",
        folder=world["own_folder"],
    )

    with patch("core.views.persist_outbound_sync_jobs") as persist_jobs:
        response = world["client"].patch(
            f"{url}{instance.id}/",
            {"folder": str(destination.id)},
            format="json",
        )

    assert response.status_code == 409, response.content
    instance.refresh_from_db()
    assert instance.folder_id == world["own_folder"].id
    assert SyncMapping.objects.filter(id=mapping.id).exists()
    persist_jobs.assert_not_called()


@pytest.mark.django_db
def test_detail_requires_independent_provider_visibility(integration_world):
    world = integration_world
    asset = Asset.objects.create(name="provider-hidden", folder=world["own_folder"])
    mapping = SyncMapping.objects.create(
        configuration=world["own_config"],
        content_type=ContentType.objects.get_for_model(Asset),
        local_object_id=asset.id,
        remote_id="PROVIDER-HIDDEN",
        folder=world["own_folder"],
    )
    role = Role.objects.create(
        name=f"projection-{uuid.uuid4().hex[:6]}", folder=world["own_folder"]
    )
    role.permissions.set(
        Permission.objects.filter(
            codename__in={
                "view_folder",
                "view_asset",
                "view_integrationconfiguration",
                "view_syncmapping",
            }
        )
    )
    user = User.objects.create_user(
        f"projection-{uuid.uuid4().hex[:8]}@tests.example", is_published=True
    )
    user.folder = world["own_folder"]
    user.save(update_fields=["folder"])
    assignment = RoleAssignment.objects.create(
        user=user,
        role=role,
        folder=world["own_folder"],
        is_recursive=True,
    )
    assignment.perimeter_folders.add(world["own_folder"])
    assert mapping.id in set(RoleAssignment.get_viewable_object_ids(user, SyncMapping))
    assert world["provider"].id not in set(
        RoleAssignment.get_viewable_object_ids(user, IntegrationProvider)
    )

    response = _client(user).get(f"/api/assets/{asset.id}/")

    assert response.status_code == 200, response.content
    assert response.json().get("sync_mappings", []) == []
    assert "PROVIDER-HIDDEN" not in response.content.decode()


@pytest.mark.django_db
def test_detail_rejects_incoherent_provider_owner(
    integration_world, authenticated_client
):
    world = integration_world
    asset = Asset.objects.create(name="provider-incoherent", folder=world["own_folder"])
    SyncMapping.objects.create(
        configuration=world["own_config"],
        content_type=ContentType.objects.get_for_model(Asset),
        local_object_id=asset.id,
        remote_id="PROVIDER-INCOHERENT",
        folder=world["own_folder"],
    )
    provider = world["provider"]
    provider.folder = world["hidden_folder"]
    provider.save(update_fields=["folder", "updated_at"])

    response = authenticated_client.get(f"/api/assets/{asset.id}/")

    assert response.status_code == 200, response.content
    assert response.json().get("sync_mappings", []) == []
    assert "PROVIDER-INCOHERENT" not in response.content.decode()


def _mapping_merge_user(world, *, can_view_configuration=False):
    role = Role.objects.create(
        name=f"mapping-merge-{uuid.uuid4().hex[:6]}", folder=world["own_folder"]
    )
    codenames = {
        "view_appliedcontrol",
        "add_appliedcontrol",
        "change_appliedcontrol",
        "delete_appliedcontrol",
        "view_syncmapping",
        "add_syncmapping",
        "change_syncmapping",
        "delete_syncmapping",
    }
    if can_view_configuration:
        codenames.add("view_integrationconfiguration")
    role.permissions.set(
        Permission.objects.filter(
            codename__in=codenames,
        )
    )
    user = User.objects.create_user(
        f"mapping-merge-{uuid.uuid4().hex[:8]}@tests.example", is_published=True
    )
    user.folder = world["own_folder"]
    user.save(update_fields=["folder"])
    assignment = RoleAssignment.objects.create(
        user=user,
        role=role,
        folder=world["own_folder"],
        is_recursive=True,
    )
    assignment.perimeter_folders.add(world["own_folder"])
    return user


@pytest.mark.django_db
def test_merge_rejects_mapping_with_independently_hidden_configuration(
    integration_world,
):
    world = integration_world
    source = AppliedControl.objects.create(name="source", folder=world["own_folder"])
    target = AppliedControl.objects.create(name="target", folder=world["own_folder"])
    mapping = SyncMapping.objects.create(
        configuration=world["own_config"],
        content_type=ContentType.objects.get_for_model(AppliedControl),
        local_object_id=source.id,
        remote_id="REMOTE-HIDDEN-CONFIG",
        folder=world["own_folder"],
    )
    client = _client(_mapping_merge_user(world))

    with patch("core.applied_controls_helper.persist_outbound_sync_jobs") as schedule:
        response = client.post(
            "/api/applied-controls/merge/",
            {
                "source_ids": [str(source.id)],
                "target": {"type": "existing", "id": str(target.id)},
            },
            format="json",
        )

    assert response.status_code == 403, response.content
    assert AppliedControl.objects.filter(id=source.id).exists()
    mapping.refresh_from_db()
    assert mapping.local_object_id == source.id
    schedule.assert_not_called()


@pytest.mark.django_db
def test_merge_does_not_require_independent_provider_view(integration_world):
    world = integration_world
    source = AppliedControl.objects.create(name="source", folder=world["own_folder"])
    target = AppliedControl.objects.create(name="target", folder=world["own_folder"])
    mapping = SyncMapping.objects.create(
        configuration=world["own_config"],
        content_type=ContentType.objects.get_for_model(AppliedControl),
        local_object_id=source.id,
        remote_id="REMOTE-PROVIDER-CARRIER",
        folder=world["own_folder"],
    )
    user = _mapping_merge_user(world, can_view_configuration=True)
    assert world["provider"].id not in set(
        RoleAssignment.get_viewable_object_ids(user, IntegrationProvider)
    )

    with patch("core.applied_controls_helper.persist_outbound_sync_jobs"):
        response = _client(user).post(
            "/api/applied-controls/merge/",
            {
                "source_ids": [str(source.id)],
                "target": {"type": "existing", "id": str(target.id)},
            },
            format="json",
        )

    assert response.status_code == 200, response.content
    mapping.refresh_from_db()
    assert mapping.local_object_id == target.id


@pytest.mark.django_db
def test_merge_rewire_versions_event_and_attributes_refresh(integration_world):
    world = integration_world
    source = AppliedControl.objects.create(name="source", folder=world["own_folder"])
    target = AppliedControl.objects.create(name="target", folder=world["own_folder"])
    mapping = SyncMapping.objects.create(
        configuration=world["own_config"],
        content_type=ContentType.objects.get_for_model(AppliedControl),
        local_object_id=source.id,
        remote_id="REMOTE-MOVE",
        folder=world["own_folder"],
    )

    with patch(
        "core.applied_controls_helper.persist_outbound_sync_jobs"
    ) as persist_jobs:
        response = world["client"].post(
            "/api/applied-controls/merge/",
            {
                "source_ids": [str(source.id)],
                "target": {"type": "existing", "id": str(target.id)},
            },
            format="json",
        )
        assert response.status_code == 200, response.content
        mapping.refresh_from_db()
        assert mapping.local_object_id == target.id
        assert mapping.sync_status == SyncMapping.SyncStatus.PENDING
        assert mapping.version == 2
        event = SyncEvent.objects.get(mapping_id_snapshot=mapping.id)
        assert event.mapping_id == mapping.id
        assert event.actor_id_snapshot == world["user"].id
        assert event.job_id_snapshot is None
        assert event.changes["action"] == "merge_relink"
        assert event.changes["mapping_version"] == 2
        persist_jobs.assert_called_once_with(
            content_type_id=ContentType.objects.get_for_model(AppliedControl).id,
            object_id=target.id,
            configuration_ids=[world["own_config"].id],
            changed_fields=[],
            origin_principal=f"user:{world['user'].id}",
            requested_by_id=world["user"].id,
        )


@pytest.mark.django_db
def test_merge_rejects_inactive_mapping_configuration(integration_world):
    world = integration_world
    source = AppliedControl.objects.create(name="source", folder=world["own_folder"])
    target = AppliedControl.objects.create(name="target", folder=world["own_folder"])
    mapping = SyncMapping.objects.create(
        configuration=world["own_config"],
        content_type=ContentType.objects.get_for_model(AppliedControl),
        local_object_id=source.id,
        remote_id="REMOTE-INACTIVE",
        folder=world["own_folder"],
    )
    world["own_config"].is_active = False
    world["own_config"].save(update_fields=["is_active"])

    with patch("core.applied_controls_helper.persist_outbound_sync_jobs") as schedule:
        response = world["client"].post(
            "/api/applied-controls/merge/",
            {
                "source_ids": [str(source.id)],
                "target": {"type": "existing", "id": str(target.id)},
            },
            format="json",
        )

    assert response.status_code == 403, response.content
    assert AppliedControl.objects.filter(id=source.id).exists()
    mapping.refresh_from_db()
    assert mapping.local_object_id == source.id
    schedule.assert_not_called()


@pytest.mark.django_db
def test_merge_rejects_unresolved_mapping_job(integration_world):
    world = integration_world
    source = AppliedControl.objects.create(name="source", folder=world["own_folder"])
    target = AppliedControl.objects.create(name="target", folder=world["own_folder"])
    mapping = SyncMapping.objects.create(
        configuration=world["own_config"],
        content_type=ContentType.objects.get_for_model(AppliedControl),
        local_object_id=source.id,
        remote_id="REMOTE-BUSY",
        folder=world["own_folder"],
    )
    job = IntegrationSyncJob.objects.create(
        direction=IntegrationSyncJob.Direction.OUTBOUND,
        status=IntegrationSyncJob.Status.QUEUED,
        request_digest=uuid.uuid4().hex * 2,
        configuration_id_snapshot=world["own_config"].id,
        provider_id_snapshot=world["provider"].id,
        mapping_id_snapshot=mapping.id,
        content_type_id_snapshot=mapping.content_type_id,
        local_object_id_snapshot=source.id,
        folder_id_snapshot=world["own_folder"].id,
        origin_principal_snapshot="user:test",
    )

    with patch(
        "core.applied_controls_helper.persist_outbound_sync_jobs"
    ) as persist_jobs:
        response = world["client"].post(
            "/api/applied-controls/merge/",
            {
                "source_ids": [str(source.id)],
                "target": {"type": "existing", "id": str(target.id)},
            },
            format="json",
        )

    assert response.status_code == 409, response.content
    assert AppliedControl.objects.filter(id=source.id).exists()
    mapping.refresh_from_db()
    job.refresh_from_db()
    assert mapping.local_object_id == source.id
    assert mapping.version == 1
    assert job.status == IntegrationSyncJob.Status.QUEUED
    assert not SyncEvent.objects.filter(mapping_id_snapshot=mapping.id).exists()
    persist_jobs.assert_not_called()


@pytest.mark.django_db
def test_merge_duplicate_unlink_event_survives_mapping_delete(integration_world):
    world = integration_world
    source = AppliedControl.objects.create(name="source", folder=world["own_folder"])
    target = AppliedControl.objects.create(name="target", folder=world["own_folder"])
    content_type = ContentType.objects.get_for_model(AppliedControl)
    source_mapping = SyncMapping.objects.create(
        configuration=world["own_config"],
        content_type=content_type,
        local_object_id=source.id,
        remote_id="REMOTE-DUPLICATE-SOURCE",
        folder=world["own_folder"],
    )
    target_mapping = SyncMapping.objects.create(
        configuration=world["own_config"],
        content_type=content_type,
        local_object_id=target.id,
        remote_id="REMOTE-DUPLICATE-TARGET",
        folder=world["own_folder"],
    )

    with patch("core.applied_controls_helper.persist_outbound_sync_jobs"):
        response = world["client"].post(
            "/api/applied-controls/merge/",
            {
                "source_ids": [str(source.id)],
                "target": {"type": "existing", "id": str(target.id)},
            },
            format="json",
        )

    assert response.status_code == 200, response.content
    assert not SyncMapping.objects.filter(id=source_mapping.id).exists()
    assert SyncMapping.objects.filter(id=target_mapping.id).exists()
    event = SyncEvent.objects.get(mapping_id_snapshot=source_mapping.id)
    assert event.mapping_id is None
    assert event.actor_id_snapshot == world["user"].id
    assert event.changes["action"] == "merge_unlink_duplicate"
    assert event.changes["mapping_version"] == 2
    assert event.changes["after"] == {"survivor_mapping_id": str(target_mapping.id)}
