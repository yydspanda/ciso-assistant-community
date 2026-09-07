import uuid
from unittest.mock import Mock, patch

import pytest
from iam.models import Folder
from rest_framework.test import APIClient

from integrations.models import IntegrationConfiguration, IntegrationProvider


@pytest.fixture
def webhook_configuration(app_config):
    root = Folder.get_root_folder()
    folder = Folder.objects.create(
        name=f"webhook-{uuid.uuid4().hex[:8]}",
        parent_folder=root,
        content_type=Folder.ContentType.DOMAIN,
    )
    provider, _ = IntegrationProvider.objects.get_or_create(
        name="jira",
        folder=root,
        defaults={"provider_type": IntegrationProvider.ProviderType.ITSM},
    )
    if not provider.is_active:
        provider.is_active = True
        provider.save(update_fields=["is_active"])
    return IntegrationConfiguration.objects.create(
        provider=provider,
        folder=folder,
        credentials={},
        settings={"enable_incoming_sync": True},
        webhook_secret="test-secret",
    )


@pytest.mark.django_db
def test_authenticated_ignored_webhook_does_not_mint_job(webhook_configuration):
    orchestrator = Mock()
    orchestrator.validate_webhook_request.return_value = True
    orchestrator.extract_webhook_event_type.return_value = "issue_created"
    orchestrator.classify_webhook_event.return_value = "ignore"

    with (
        patch(
            "integrations.views.IntegrationRegistry.get_orchestrator",
            return_value=orchestrator,
        ),
        patch("integrations.views.persist_webhook_sync_job") as persist_job,
    ):
        response = APIClient().post(
            f"/api/integrations/webhook/{webhook_configuration.id}/",
            {"issue": {"key": "PROJ-1"}},
            format="json",
        )

    assert response.status_code == 202, response.content
    orchestrator.extract_webhook_remote_id.assert_not_called()
    persist_job.assert_not_called()


@pytest.mark.django_db
def test_authenticated_update_webhook_mints_only_canonical_remote_id(
    webhook_configuration,
):
    orchestrator = Mock()
    orchestrator.validate_webhook_request.return_value = True
    orchestrator.extract_webhook_event_type.return_value = "issue_updated"
    orchestrator.classify_webhook_event.return_value = "update"
    orchestrator.extract_webhook_remote_id.return_value = " proj-1 "

    with (
        patch(
            "integrations.views.IntegrationRegistry.get_orchestrator",
            return_value=orchestrator,
        ),
        patch(
            "integrations.views.persist_webhook_sync_job", return_value=uuid.uuid4()
        ) as persist_job,
    ):
        response = APIClient().post(
            f"/api/integrations/webhook/{webhook_configuration.id}/",
            {"issue": {"key": "proj-1"}},
            format="json",
        )

    assert response.status_code == 202, response.content
    persist_job.assert_called_once()
    assert persist_job.call_args.kwargs["remote_id"] == "PROJ-1"
    assert persist_job.call_args.kwargs["event_type"] == "issue_updated"
