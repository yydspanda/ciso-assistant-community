"""Mixin that makes a Django model syncable with remote ITSM integrations.

A model opts in by inheriting ``IntegrationSyncableMixin``, declaring
``INTEGRATION_MODEL_KEY`` (a key registered in ``integrations.syncable``) and
``INTEGRATION_SYNCABLE_FIELDS`` (the fields whose change triggers a sync), and
calling the helpers from its ``save()``.

This module imports nothing from ``core`` or ``integrations.models`` at import
time (only lazily, inside methods) so it is safe to import from model modules.
"""

from __future__ import annotations

from typing import ClassVar

import structlog

logger = structlog.get_logger(__name__)


class IntegrationSyncableMixin:
    # Overridden per model.
    INTEGRATION_MODEL_KEY: str = ""
    INTEGRATION_SYNCABLE_FIELDS: ClassVar[set[str]] = set()

    def _get_changed_fields(self, old_instance) -> list[str]:
        """Names of syncable fields that differ from ``old_instance``."""
        changed = []
        for field in self.INTEGRATION_SYNCABLE_FIELDS:
            if getattr(old_instance, field) != getattr(self, field):
                changed.append(field)
        return changed

    def _capture_sync_changed_fields(self) -> list[str]:
        """Changed syncable fields vs the persisted row ([] when new).

        Uses ``_state.adding`` (not ``pk is None``: AbstractBaseModel's UUID pk
        has ``default=uuid.uuid4``, so pk is set before the first save). Skips
        the DB read entirely on creation and loads only the syncable columns on
        update, keeping bulk imports cheap.
        """
        if self._state.adding:
            return []
        old = (
            type(self)
            .objects.filter(pk=self.pk)
            .only(*self.INTEGRATION_SYNCABLE_FIELDS)
            .first()
        )
        return self._get_changed_fields(old) if old else []

    def _trigger_sync(self, is_new: bool, changed_fields: list[str]) -> None:
        """Queue an outbound sync for every active ITSM integration that has a
        mapping configured for this model. No-op when nothing relevant changed
        or no configured integration applies."""
        if not (is_new or changed_fields):
            return

        from django.contrib.contenttypes.models import ContentType
        from django.db import transaction
        from iam.models import Folder

        from integrations.models import IntegrationConfiguration
        from integrations.settings_access import (
            integration_sync_fingerprint,
            is_model_configured,
        )
        from integrations.tasks import sync_object_to_integrations

        root_folder = Folder.get_root_folder()
        configurations = IntegrationConfiguration.objects.select_related(
            "provider"
        ).filter(
            folder=root_folder,
            provider__provider_type="itsm",
            provider__is_active=True,
            is_active=True,
        )
        configured = [
            configuration
            for configuration in configurations
            if is_model_configured(configuration.settings, self.INTEGRATION_MODEL_KEY)
        ]
        config_ids = [configuration.id for configuration in configured]
        if not config_ids:
            return
        config_fingerprints = {
            str(configuration.id): integration_sync_fingerprint(
                configuration, self.INTEGRATION_MODEL_KEY
            )
            for configuration in configured
        }

        content_type = ContentType.objects.get_for_model(self)
        pk = self.pk

        def schedule_sync() -> None:
            try:
                sync_object_to_integrations.schedule(
                    args=(
                        content_type,
                        pk,
                        config_ids,
                        changed_fields,
                        config_fingerprints,
                    ),
                    delay=1,
                )
            except Exception as exc:
                # Persistence is authoritative.  A committed mutation must not
                # surface as an API failure or prevent later robust callbacks
                # (including the governed relationship webhook) from running.
                logger.exception(
                    "Failed to schedule integration sync after commit",
                    model=content_type.model,
                    object_id=str(pk),
                    configuration_count=len(config_ids),
                    error_type=type(exc).__name__,
                )

        transaction.on_commit(
            schedule_sync,
            robust=True,
        )
