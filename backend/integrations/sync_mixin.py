"""Mixin that makes a Django model syncable with remote ITSM integrations.

A model opts in by inheriting ``IntegrationSyncableMixin``, declaring
``INTEGRATION_MODEL_KEY`` (a key registered in ``integrations.syncable``) and
``INTEGRATION_SYNCABLE_FIELDS`` (the fields whose change triggers a sync), and
calling the helpers from its ``save()``.

This module imports nothing from ``core`` or ``integrations.models`` at import
time (only lazily, inside methods) so it is safe to import from model modules.
"""

from __future__ import annotations


class IntegrationSyncableMixin:
    # Overridden per model.
    INTEGRATION_MODEL_KEY: str = ""
    INTEGRATION_SYNCABLE_FIELDS: set[str] = set()

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

    def _has_existing_sync_mapping(self) -> bool:
        """Cheap preflight used only to decide whether to take the root mutex.

        Authority is re-read after the lock by ``_trigger_sync``. A concurrent
        first link cannot lose the update: the explicit link transaction takes
        the same root mutex and queues a complete initial projection.
        """

        if self._state.adding or getattr(self, "folder_id", None) is None:
            return False
        from django.contrib.contenttypes.models import ContentType

        from integrations.models import SyncMapping

        return SyncMapping.objects.filter(
            content_type=ContentType.objects.get_for_model(self),
            local_object_id=self.pk,
        ).exists()

    def _trigger_sync(self, is_new: bool, changed_fields: list[str]) -> None:
        """Queue an outbound sync for every active ITSM integration that has a
        mapping configured for this model. No-op when nothing relevant changed
        or no configured integration applies."""
        if not (is_new or changed_fields):
            return

        from django.contrib.contenttypes.models import ContentType

        from integrations.capabilities import persist_outbound_sync_jobs
        from integrations.models import SyncMapping

        content_type = ContentType.objects.get_for_model(self)
        object_folder_id = getattr(self, "folder_id", None)
        if object_folder_id is None:
            return
        # A model save is not authority to create a new remote relationship.
        # Only an existing, owner-coherent mapping may trigger an outbound sync;
        # the explicit link endpoints create that mapping under IAM + row locks.
        config_ids = list(
            SyncMapping.objects.filter(
                content_type=content_type,
                local_object_id=self.pk,
                folder_id=object_folder_id,
                configuration__folder_id=object_folder_id,
                configuration__is_active=True,
                configuration__provider__is_active=True,
                configuration__provider__provider_type="itsm",
            )
            .order_by("configuration_id")
            .values_list("configuration_id", flat=True)
        )
        if not config_ids:
            return

        pk = self.pk
        requested_by_id = getattr(
            self, "_integration_sync_requested_by_id_snapshot", None
        )
        origin_principal = (
            f"user:{requested_by_id}"
            if requested_by_id is not None
            else "ciso-assistant:model-outbox"
        )
        persist_outbound_sync_jobs(
            content_type_id=content_type.id,
            object_id=pk,
            configuration_ids=config_ids,
            changed_fields=changed_fields,
            origin_principal=origin_principal,
            requested_by_id=requested_by_id,
        )
