import uuid
from secrets import compare_digest

from django.contrib.contenttypes.models import ContentType
from huey.contrib.djhuey import HUEY, lock_task, task
from structlog import get_logger

from integrations.itsm.jira.integration import *
from integrations.itsm.servicenow.integration import *
from integrations.models import IntegrationConfiguration

from .registry import IntegrationRegistry

logger = get_logger(__name__)


@task()
def sync_object_to_integrations(
    content_type: ContentType,
    object_id: uuid.UUID,
    config_ids: list[uuid.UUID],
    changed_fields: list[str],
    config_fingerprints: dict[str, str] | None = None,
):
    """Push local changes through configurations still authorized at execution."""
    from django.apps import apps
    from iam.models import Folder

    from integrations.settings_access import (
        integration_sync_fingerprint,
        is_model_configured,
    )
    from integrations.syncable import model_key_for_content_type

    Model = apps.get_model(content_type.app_label, content_type.model)
    obj = Model.objects.get(pk=object_id)
    model_key = model_key_for_content_type(content_type)
    if model_key is None:
        logger.warning(
            "Skipping outbound integration sync for an unregistered model",
            content_type=f"{content_type.app_label}.{content_type.model}",
            object_id=str(object_id),
        )
        return

    expected_fingerprints = config_fingerprints or {}
    root_folder = Folder.get_root_folder()

    for config_id in config_ids:
        try:
            expected_fingerprint = expected_fingerprints.get(str(config_id))
            if expected_fingerprint is None:
                logger.warning(
                    "Skipping outbound integration sync without an authority fingerprint",
                    configuration_id=str(config_id),
                    model=model_key,
                    object_id=str(object_id),
                )
                continue

            config = (
                IntegrationConfiguration.objects.select_related("provider")
                .filter(
                    pk=config_id,
                    folder=root_folder,
                    is_active=True,
                    provider__is_active=True,
                    provider__provider_type="itsm",
                )
                .first()
            )
            if config is None:
                logger.info(
                    "Skipping outbound integration sync outside the active root ITSM boundary",
                    configuration_id=str(config_id),
                    model=model_key,
                    object_id=str(object_id),
                )
                continue

            # Skip if outgoing sync is disabled
            if not config.settings.get("enable_outgoing_sync", False):
                continue
            if not is_model_configured(config.settings, model_key):
                logger.info(
                    "Skipping outbound integration sync for an unconfigured model",
                    configuration_id=str(config_id),
                    model=model_key,
                    object_id=str(object_id),
                )
                continue
            current_fingerprint = integration_sync_fingerprint(config, model_key)
            if not compare_digest(expected_fingerprint, current_fingerprint):
                logger.warning(
                    "Skipping outbound integration sync after configuration changed",
                    configuration_id=str(config_id),
                    model=model_key,
                    object_id=str(object_id),
                )
                continue

            orchestrator = IntegrationRegistry.get_orchestrator(config)
            orchestrator.push_changes(obj, changed_fields)
        except Exception as e:
            logger.error(f"Sync failed for config {config_id}: {e}")
            # Don't fail the whole batch if one integration fails


@task()
@lock_task("warm-integration-schema")
def warm_integration_schema_cache():
    """Pre-fetch remote schema into the DB cache so integration settings pages
    load without live latency.

    Provider-agnostic: refresh_schema(force=False) is populate-if-empty for
    providers that cache (ServiceNow) and the base no-op for the rest (Jira),
    so a restart with a populated cache costs no live calls. The lock makes the
    once-per-worker enqueue from on_startup fail fast instead of racing
    last-write-wins on the cache row when the cache is cold. Each config is
    isolated so one failure (bad credentials, network) doesn't abort the rest.
    """
    configs = IntegrationConfiguration.objects.filter(
        is_active=True, provider__provider_type="itsm"
    )
    for config in configs:
        try:
            orchestrator = IntegrationRegistry.get_orchestrator(config)
            orchestrator.refresh_schema(force=False)
            logger.info("Warmed integration schema cache", config_id=str(config.id))
        except Exception as e:
            logger.error(
                f"Failed to warm schema cache for config {config.id}: {e}",
                exc_info=True,
            )


@HUEY.on_startup()
def _enqueue_schema_cache_warmup():
    """Warm the schema cache once the Huey consumer is up. Enqueued (not run
    inline) so worker startup isn't blocked by remote HTTP calls."""
    try:
        warm_integration_schema_cache()
    except Exception as e:
        logger.error(f"Failed to enqueue integration schema cache warmup: {e}")


@task()
def process_webhook_event(config_id: uuid.UUID, event_type: str, payload: dict):
    """Process incoming webhook from remote system"""
    try:
        config = IntegrationConfiguration.objects.get(pk=config_id)

        # Skip if incoming sync is disabled
        if not config.settings.get("enable_incoming_sync", False):
            return

        orchestrator = IntegrationRegistry.get_orchestrator(config)

        # Let the specific orchestrator handle the event
        orchestrator.handle_webhook_event(event_type, payload)

    except IntegrationConfiguration.DoesNotExist:
        logger.error(
            f"process_webhook_event failed: No IntegrationConfiguration found for ID {config_id}"
        )
    except Exception as e:
        logger.error(
            f"process_webhook_event failed for config {config_id}: {e}", exc_info=True
        )
