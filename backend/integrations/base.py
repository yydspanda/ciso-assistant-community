from abc import ABC, abstractmethod
from datetime import timedelta
import hmac
import json
from typing import Any

import structlog
from django.contrib.contenttypes.models import ContentType
from django.core.serializers.json import DjangoJSONEncoder
from django.db import models
from django.http import HttpRequest
from django.utils import timezone
from django.utils.dateparse import parse_datetime

from core.base_models import AbstractBaseModel
from integrations.models import IntegrationConfiguration, SyncMapping

logger = structlog.get_logger(__name__)


class BaseIntegrationClient(ABC):
    """Base class for all integration clients"""

    def __init__(
        self,
        configuration: IntegrationConfiguration,
        model_key: str = "applied_control",
    ):
        from integrations.settings_access import get_model_settings

        self.configuration = configuration
        self.model_key = model_key
        self.credentials = configuration.credentials
        self.settings = configuration.settings
        # Per-model mapping settings (e.g. the remote table for this model).
        self.model_settings = get_model_settings(
            configuration.settings or {}, model_key
        )

    @abstractmethod
    def test_connection(self) -> bool:
        """Test if credentials are valid"""
        pass

    @abstractmethod
    def create_remote_object(self, local_object) -> str:
        """Create object in remote system, return remote ID"""
        pass

    def create_remote_payload(self, payload: dict[str, Any]) -> str:
        """Create from an already approved immutable provider projection.

        Durable workers use this boundary so a delayed job never remaps a
        newer local object state. Providers that support creation must override
        it; the default fails closed.
        """

        raise NotImplementedError("Provider cannot create from a durable payload")

    @abstractmethod
    def update_remote_object(self, remote_id: str, changes: dict[str, Any]) -> bool:
        """Update object in remote system"""
        pass

    @abstractmethod
    def get_remote_object(self, remote_id: str) -> dict[str, Any]:
        """Fetch object from remote system"""
        pass

    @abstractmethod
    def list_remote_objects(
        self, query_params: dict[str, Any] | None = None
    ) -> list[dict[str, Any]]:
        """List objects from remote system based on query parameters"""
        pass


class BaseFieldMapper(ABC):
    """Maps fields between local and remote systems"""

    # Define field mappings as class attributes
    # Format: {'local_field': 'remote_field'}
    FIELD_MAPPINGS: dict[str, str] = {}

    def __init__(
        self,
        configuration: IntegrationConfiguration,
        model_key: str = "applied_control",
    ):
        from integrations.settings_access import get_model_settings

        self.configuration = configuration
        self.model_key = model_key
        # Per-model mapping settings (table_name/field_map/value_map/...), with
        # the legacy top-level shim applied for applied_control.
        self.model_settings = get_model_settings(
            configuration.settings or {}, model_key
        )
        # Allow per-instance custom mappings. Uses the same "field_map" key the
        # settings layer writes and is_model_configured() reads. (Providers that
        # override _get_mappings don't consult this, but keep it consistent.)
        self.custom_mappings = self.model_settings.get("field_map", {})

    # Optional per-provider, per-model operation gating for models other than
    # applied_control: {model_key: {field: {"pull": {...}, "push": {...}}}}.
    # Operations are provider-specific (e.g. Jira's name is pull-on-create only
    # while ServiceNow's is not), which is why they live on the mapper classes
    # rather than in the provider-agnostic syncable registry.
    FIELD_MAPPINGS_OPERATIONS_BY_MODEL: dict[str, dict[str, dict[str, set]]] = {}

    def _field_operations(self) -> dict[str, dict[str, set]]:
        """Per-model pull/push operation gating.

        applied_control keeps the provider's explicit FIELD_MAPPINGS_OPERATIONS
        (preserves immutability nuances like Jira name being pull-on-create).
        Other models use FIELD_MAPPINGS_OPERATIONS_BY_MODEL when the provider
        declares one, else every mappable field on create+update both ways.
        """
        ops = getattr(self, "FIELD_MAPPINGS_OPERATIONS", None)
        if self.model_key == "applied_control" and ops:
            return ops
        per_model = self.FIELD_MAPPINGS_OPERATIONS_BY_MODEL.get(self.model_key)
        if per_model:
            return per_model
        from integrations.syncable import mappable_field_keys

        return {
            key: {"pull": {"create", "update"}, "push": {"create", "update"}}
            for key in mappable_field_keys(self.model_key)
        }

    def get_allowed_fields(self, direction: str, operation: str) -> set[str]:
        from integrations.syncable import mappable_field_keys

        model_fields = mappable_field_keys(self.model_key)
        allowed = set()
        for field, ops in self._field_operations().items():
            if field in model_fields and operation in ops.get(direction, set()):
                allowed.add(field)
        return allowed

    def governed_mappings(self) -> dict[str, str]:
        """Return a fail-closed mapping restricted to the public sync schema."""

        from integrations.syncable import mappable_field_keys

        mappings = self._get_mappings()
        if not isinstance(mappings, dict):
            raise ValueError("Integration field_map must be an object")
        model_fields = mappable_field_keys(self.model_key)
        governed: dict[str, str] = {}
        remote_targets: set[str] = set()
        for local_field, remote_field in mappings.items():
            if (
                not isinstance(local_field, str)
                or local_field not in model_fields
                or not isinstance(remote_field, str)
                or not remote_field
                or remote_field != remote_field.strip()
                or remote_field in remote_targets
            ):
                raise ValueError("Integration field_map is outside the governed schema")
            governed[local_field] = remote_field
            remote_targets.add(remote_field)
        return governed

    def allowed_mappings(self, direction: str, operation: str) -> dict[str, str]:
        allowed_fields = self.get_allowed_fields(direction, operation)
        return {
            local_field: remote_field
            for local_field, remote_field in self.governed_mappings().items()
            if local_field in allowed_fields
        }

    def remote_field_names(self, direction: str, operation: str) -> set[str]:
        return set(self.allowed_mappings(direction, operation).values())

    def to_remote(self, local_object: models.Model) -> dict[str, Any]:
        """Convert local object to remote format (all fields)"""
        remote_data = {}
        for local_field, remote_field in self.allowed_mappings(
            "push", "create"
        ).items():
            value = self._get_local_value(local_object, local_field)
            if value is not None:
                transformed = self._transform_value_to_remote(local_field, value)
                if transformed is not None:
                    remote_data[remote_field] = transformed
        return remote_data

    def to_remote_partial(
        self, local_object: models.Model, changed_fields: list[str]
    ) -> dict[str, Any]:
        """Convert only specific fields to remote format"""
        remote_data = {}
        mappings = self.allowed_mappings("push", "update")

        for local_field in changed_fields:
            if local_field in mappings:
                remote_field = mappings[local_field]
                value = self._get_local_value(local_object, local_field)
                if value is not None:
                    transformed = self._transform_value_to_remote(local_field, value)
                    if transformed is not None:
                        remote_data[remote_field] = transformed

        return remote_data

    def to_local(self, remote_data: dict[str, Any]) -> dict[str, Any]:
        """Convert remote data to local format"""
        local_data = {}
        reverse_mappings = {
            remote_field: local_field
            for local_field, remote_field in self.allowed_mappings(
                "pull", "update"
            ).items()
        }

        for remote_field, local_field in reverse_mappings.items():
            # Use helper to get potentially nested value
            value = self._get_remote_value(remote_data, remote_field)
            if value is not None:
                transformed = self._transform_value_to_local(local_field, value)
                if transformed is not None:
                    local_data[local_field] = transformed

        return local_data

    def _get_mappings(self) -> dict[str, str]:
        """Combine class-level and instance-level mappings"""
        return {**self.FIELD_MAPPINGS, **self.custom_mappings}

    def _get_local_value(self, local_object: models.Model, field_name: str) -> Any:
        """Get value from local object, handling nested attributes"""
        if "." in field_name:
            # Handle nested attributes like 'owner.name'
            parts = field_name.split(".")
            value = local_object
            for part in parts:
                value = getattr(value, part, None)
                if value is None:
                    return None
            return value
        return getattr(local_object, field_name, None)

    def _get_remote_value(self, remote_data: dict[str, Any], field_name: str) -> Any:
        """Get value from remote data, handling nested attributes"""
        if "." in field_name:
            parts = field_name.split(".")
            value = remote_data
            for part in parts:
                if not isinstance(value, dict):
                    return None
                value = value.get(part)
                if value is None:
                    return None
            return value
        return remote_data.get(field_name)

    @abstractmethod
    def _transform_value_to_remote(self, field: str, value: Any) -> Any:
        """Transform specific field values for remote system

        Args:
            field: Local field name
            value: Local field value

        Returns:
            Transformed value suitable for remote system, or None to skip
        """
        pass

    @abstractmethod
    def _transform_value_to_local(self, field: str, value: Any) -> Any:
        """Transform specific field values from remote system

        Args:
            field: Local field name
            value: Remote field value

        Returns:
            Transformed value suitable for local system, or None to skip
        """
        pass

    def suggest_mapping_for_table(
        self, table_name: str, client: "BaseIntegrationClient"
    ) -> dict[str, Any]:
        """Suggest a default mapping for the given remote table.

        Returns ``{"field_map": {...}, "value_map": {...}}`` already intersected
        with what actually exists in the remote table (so a row is only filled
        in when its target field/choice exists upstream). Default
        implementation returns no suggestions; providers override.
        """
        return {"field_map": {}, "value_map": {}}


class BaseSyncOrchestrator(ABC):
    """Orchestrates sync operations between local and remote systems"""

    DEFAULT_MODEL_KEY = "applied_control"
    # A provider must explicitly opt in only after its API accepts the durable
    # request digest as an idempotency/correlation key for every side effect.
    SUPPORTS_IDEMPOTENT_OPERATIONS = False

    def __init__(self, configuration: IntegrationConfiguration):
        self.configuration = configuration
        # Clients/mappers are model-aware and built lazily per model_key. Caching
        # avoids re-connecting (e.g. the Jira client opens a session in __init__).
        self._client_cache: dict[str, BaseIntegrationClient] = {}
        self._mapper_cache: dict[str, BaseFieldMapper] = {}

    @abstractmethod
    def _get_client(self, model_key: str) -> BaseIntegrationClient:
        """Return the appropriate client for this integration + model"""
        pass

    @abstractmethod
    def _get_mapper(self, model_key: str) -> BaseFieldMapper:
        """Return the appropriate field mapper for this integration + model"""
        pass

    def client_for(self, model_key: str) -> BaseIntegrationClient:
        if model_key not in self._client_cache:
            self._client_cache[model_key] = self._get_client(model_key)
        return self._client_cache[model_key]

    def mapper_for(self, model_key: str) -> BaseFieldMapper:
        if model_key not in self._mapper_cache:
            self._mapper_cache[model_key] = self._get_mapper(model_key)
        return self._mapper_cache[model_key]

    @property
    def client(self) -> BaseIntegrationClient:
        """Back-compat default client (applied_control)."""
        return self.client_for(self.DEFAULT_MODEL_KEY)

    @property
    def mapper(self) -> BaseFieldMapper:
        """Back-compat default mapper (applied_control)."""
        return self.mapper_for(self.DEFAULT_MODEL_KEY)

    def get_interactive_actions(self) -> list[str]:
        """Return a list of supported interactive actions (RPCs)."""
        return []

    def execute_action(self, action: str, params: dict) -> Any:
        """
        Execute a dynamic action requested by the frontend.
        Raises NotImplementedError if action is unknown.
        """
        raise NotImplementedError(
            f"Action '{action}' is not supported by this integration."
        )

    def refresh_schema(self, force: bool = True) -> list:
        """Re-fetch and cache the remote schema.

        Default is a no-op so the generic 'refresh schema' button in the UI is
        harmless for providers that don't cache schema. Providers that do
        (ServiceNow) override this. ``force`` distinguishes a user-triggered
        hard refresh from populate-if-empty startup warming.
        """
        return []

    def execute_outbound_payload(
        self,
        *,
        model_key: str,
        operation_kind: str,
        remote_id: str,
        payload: dict[str, Any],
        operation_id: str,
    ) -> tuple[str, dict[str, Any]]:
        """Perform provider I/O only; never read or mutate application rows."""

        client = self.client_for(model_key)
        if operation_kind == "create":
            remote_id = client.create_remote_payload(dict(payload))
            if not remote_id:
                raise RuntimeError("Provider returned no remote object identifier")
        elif operation_kind == "update":
            if not remote_id:
                raise RuntimeError("An update requires a remote object identifier")
            if (
                payload
                and client.update_remote_object(remote_id, dict(payload)) is False
            ):
                raise RuntimeError("Provider rejected the remote update")
        elif operation_kind == "refresh_existing":
            if not remote_id or payload:
                raise RuntimeError(
                    "A refresh requires an existing identifier and an empty payload"
                )
        else:
            raise ValueError("Unsupported durable integration operation")

        remote_data = client.get_remote_object(remote_id)
        if not isinstance(remote_data, dict):
            raise RuntimeError("Provider returned an invalid remote snapshot")
        logger.info(
            "Completed durable provider operation",
            operation_id=operation_id,
            operation_kind=operation_kind,
            remote_id=remote_id,
        )
        return remote_id, self.validate_remote_snapshot(
            model_key=model_key,
            remote_id=remote_id,
            remote_data=remote_data,
        )

    def project_remote_snapshot(
        self, *, model_key: str, remote_data: dict[str, Any]
    ) -> dict[str, Any]:
        """Retain only provider identity, version, and explicitly mapped fields."""

        from integrations.remote_ids import normalize_remote_id

        if not isinstance(remote_data, dict):
            raise ValueError("Remote snapshots must be JSON objects")
        raw_fields = remote_data.get("fields", {})
        if not isinstance(raw_fields, dict):
            raise ValueError("Remote snapshot fields must be a JSON object")
        allowed_fields = set(self.mapper_for(model_key).governed_mappings().values())
        raw_key = remote_data.get("key")
        projected = {
            "key": (
                normalize_remote_id(self.configuration.provider.name, raw_key)
                if raw_key is not None
                else None
            ),
            "updated": remote_data.get("updated"),
            "fields": {
                key: raw_fields[key]
                for key in sorted(allowed_fields)
                if key in raw_fields
            },
        }
        # Normalize through Django's JSON encoder now, before the value reaches
        # a persistent audit/cache field. This rejects non-serializable SDK
        # objects and prevents a later model save from becoming the first check.
        return json.loads(json.dumps(projected, cls=DjangoJSONEncoder))

    def validate_remote_snapshot(
        self,
        *,
        model_key: str,
        remote_id: str,
        remote_data: dict[str, Any],
    ) -> dict[str, Any]:
        """Project and authenticate the identity/version of a provider readback."""

        from integrations.remote_ids import normalize_remote_id

        projected = self.project_remote_snapshot(
            model_key=model_key,
            remote_data=remote_data,
        )
        expected_id = normalize_remote_id(
            self.configuration.provider.name,
            remote_id,
        )
        observed_id = normalize_remote_id(
            self.configuration.provider.name,
            projected.get("key"),
        )
        if not hmac.compare_digest(expected_id, observed_id):
            raise ValueError("Provider readback returned a different object")
        projected["key"] = expected_id
        observed_version = self.extract_remote_snapshot_version(projected)
        if observed_version is None:
            raise ValueError("Provider readback has no valid version")
        if observed_version > timezone.now() + timedelta(minutes=5):
            raise ValueError("Provider readback version is in the future")
        return projected

    def extract_webhook_remote_version(self, payload: dict[str, Any]) -> str | None:
        remote_data = self._extract_remote_data(payload)
        if not isinstance(remote_data, dict):
            return None
        value = remote_data.get("updated")
        return value if isinstance(value, str) and value else None

    def extract_remote_snapshot_version(
        self, remote_data: dict[str, Any]
    ) -> Any | None:
        if not isinstance(remote_data, dict):
            return None
        raw_value = remote_data.get("updated")
        if not isinstance(raw_value, str) or not raw_value:
            return None
        parsed = parse_datetime(raw_value)
        if parsed is None:
            return None
        if timezone.is_naive(parsed):
            parsed = timezone.make_aware(parsed)
        return parsed

    def classify_webhook_event(self, event_type: str) -> str:
        """Map a provider event to update/delete/ignore/invalid."""

        if event_type in {"created", "updated"}:
            return "update"
        if event_type == "deleted":
            return "delete"
        return "ignore"

    def project_webhook_payload(
        self, *, event_type: str, payload: dict[str, Any], model_key: str
    ) -> dict[str, Any]:
        """Return the minimal provider-shaped payload safe to retain.

        Providers must explicitly define their webhook schema. A valid
        signature alone is never authority to persist arbitrary fields.
        """

        raise ValueError("The provider has no governed webhook payload schema")

    def prepare_incoming_event(
        self,
        *,
        event_type: str,
        payload: dict[str, Any],
        mapping: "SyncMapping",
        local_object: models.Model,
    ) -> dict[str, Any]:
        """Build a deterministic incoming plan without network or DB writes."""

        from integrations.remote_ids import (
            InvalidRemoteIdentifier,
            normalize_remote_id,
        )
        from integrations.syncable import model_key_for_content_type

        action = self.classify_webhook_event(event_type)
        raw_remote_id = self._extract_remote_id(payload)
        try:
            remote_id = (
                normalize_remote_id(self.configuration.provider.name, raw_remote_id)
                if raw_remote_id
                else ""
            )
        except InvalidRemoteIdentifier:
            return {"action": "invalid", "reason": "invalid_remote_id"}
        if action in {"update", "delete"} and not remote_id:
            return {"action": "invalid", "reason": "missing_remote_id"}
        if remote_id and remote_id != mapping.remote_id:
            return {"action": "invalid", "reason": "remote_id_changed"}
        if action in {"ignore", "invalid", "delete"}:
            return {"action": action, "remote_id": remote_id}

        remote_data = self._extract_remote_data(payload)
        if not isinstance(remote_data, dict) or not remote_data:
            return {"action": "invalid", "reason": "missing_remote_data"}
        model_key = (
            model_key_for_content_type(mapping.content_type) or self.DEFAULT_MODEL_KEY
        )
        mapper = self.mapper_for(model_key)
        try:
            remote_data = self.project_remote_snapshot(
                model_key=model_key,
                remote_data=remote_data,
            )
        except (TypeError, ValueError):
            return {"action": "invalid", "reason": "invalid_remote_snapshot"}
        if mapping.last_synced_at is None and mapping.remote_data != remote_data:
            # NULL is the conservative migration/runtime sentinel for a mapping
            # without proved successful-sync evidence.  It must not collapse to
            # remote-wins, otherwise an upgraded legacy row could silently
            # overwrite a newer local value using an untrusted auto_now marker.
            return {
                "action": "review",
                "reason": "unproved_sync_baseline",
                "remote_id": remote_id,
                "remote_data": remote_data,
                "local_data": mapper.to_local(remote_data),
            }
        has_conflict = bool(
            hasattr(local_object, "updated_at")
            and mapping.last_synced_at is not None
            and local_object.updated_at > mapping.last_synced_at
            and mapping.remote_data != remote_data
        )
        resolution = self.configuration.settings.get(
            "conflict_resolution", "remote_wins"
        )
        if has_conflict and resolution == "manual":
            return {
                "action": "review",
                "reason": "manual_conflict",
                "remote_id": remote_id,
                "remote_data": remote_data,
                "local_data": mapper.to_local(remote_data),
            }
        if has_conflict and resolution == "local_wins":
            return {
                "action": "push_local",
                "remote_id": remote_id,
                "remote_payload": mapper.to_remote(local_object),
            }
        return {
            "action": "apply_remote",
            "remote_id": remote_id,
            "remote_data": remote_data,
            "local_data": mapper.to_local(remote_data),
        }

    def push_changes(
        self, local_object: models.Model, changed_fields: list[str]
    ) -> bool:
        """Push local changes to remote system

        Args:
            local_object: The Django model instance that changed
            changed_fields: list of field names that changed

        Returns:
            True if sync succeeded, False otherwise
        """
        raise RuntimeError(
            "Direct integration writes are disabled; persist a durable sync intent."
        )

        from .models import SyncMapping  # pragma: no cover
        from integrations.settings_access import is_model_configured
        from integrations.syncable import model_key_for_content_type

        content_type = ContentType.objects.get_for_model(local_object)
        model_key = model_key_for_content_type(content_type)
        if not model_key:
            logger.info(
                "Skipping push: model is not syncable",
                model=content_type.model,
                config_id=str(self.configuration.id),
            )
            return False
        # applied_control is exempt from the configured-target gate: historic
        # behavior pushed AC changes on every active config, relying on the
        # providers' built-in defaults (Jira field map, ServiceNow 'incident'
        # table). The gate protects new models (asset, ...), which have no
        # defaults and must not sync without an explicit remote target.
        if model_key != self.DEFAULT_MODEL_KEY and not is_model_configured(
            self.configuration.settings, model_key
        ):
            logger.info(
                "Skipping push: model not configured for this integration",
                model=content_type.model,
                config_id=str(self.configuration.id),
            )
            return False

        mapping = self._get_existing_mapping(local_object)
        if mapping is None:
            return False

        mapper = self.mapper_for(model_key)
        client = self.client_for(model_key)

        try:
            if mapping.remote_id:
                # Update existing remote object
                changes = mapper.to_remote_partial(local_object, changed_fields)
                if changes:  # Only update if there are actual changes to sync
                    client.update_remote_object(mapping.remote_id, changes)
                    logger.info(
                        f"Updated remote object {mapping.remote_id} with changes: {list(changes.keys())}"
                    )
            else:
                # Create new remote object
                remote_id = client.create_remote_object(local_object)
                mapping.remote_id = remote_id
                logger.info("Created remote object", remote_id=remote_id)

            # Update mapping status
            mapping.sync_status = SyncMapping.SyncStatus.SYNCED
            mapping.last_sync_direction = SyncMapping.SyncDirection.PUSH
            mapping.version += 1
            mapping.remote_data = client.get_remote_object(mapping.remote_id)
            mapping.error_message = ""
            mapping.save()

            self._log_sync_event(
                mapping, SyncMapping.SyncDirection.PUSH, changed_fields, success=True
            )
            return True

        except Exception as e:
            logger.error(
                f"Failed to push changes for {local_object}: {e}", exc_info=True
            )
            mapping.sync_status = SyncMapping.SyncStatus.FAILED
            mapping.error_message = str(e)
            mapping.save()

            self._log_sync_event(
                mapping,
                SyncMapping.SyncDirection.PUSH,
                changed_fields,
                success=False,
                error=str(e),
            )
            return False

    def pull_changes(self, remote_id: str, remote_data: dict[str, Any]) -> bool:
        """Pull changes from remote system to local object

        Args:
            remote_id: Remote object identifier
            remote_data: Current remote object data

        Returns:
            True if sync succeeded, False otherwise
        """
        raise RuntimeError(
            "Direct integration writes are disabled; persist a durable sync intent."
        )

        from .models import SyncMapping  # pragma: no cover
        from integrations.syncable import model_key_for_content_type

        try:
            mapping = SyncMapping.objects.get(
                configuration=self.configuration, remote_id=remote_id
            )
        except SyncMapping.DoesNotExist:
            logger.warning(f"No mapping found for remote_id {remote_id}")
            return False
        except SyncMapping.MultipleObjectsReturned:
            # One remote_id linked to multiple local models under the same
            # config is unsupported in v1 (the link UI creates one per link).
            logger.error(
                "Multiple mappings for remote_id; skipping pull",
                remote_id=remote_id,
                config_id=str(self.configuration.id),
            )
            return False

        # The mapping records which local model this is; map accordingly.
        model_key = (
            model_key_for_content_type(mapping.content_type) or self.DEFAULT_MODEL_KEY
        )
        mapper = self.mapper_for(model_key)

        try:
            # Check for conflicts
            if self._has_conflict(mapping, remote_data):
                logger.warning("Conflict detected for mapping", mapping_id=mapping.id)
                mapping.sync_status = "conflict"
                mapping.save()
                # Handle conflict based on resolution strategy
                return self._resolve_conflict(mapping, remote_data, model_key)

            # Convert remote data to local format
            local_data = mapper.to_local(remote_data)
            local_object = self._get_local_object(mapping)

            # Apply changes to local object
            self._update_local_object(local_object, local_data)

            # Update mapping status
            mapping.sync_status = SyncMapping.SyncStatus.SYNCED
            mapping.last_sync_direction = SyncMapping.SyncDirection.PULL
            mapping.remote_data = remote_data
            mapping.version += 1
            mapping.error_message = ""
            mapping.save()

            self._log_sync_event(
                mapping,
                SyncMapping.SyncDirection.PULL,
                list(local_data.keys()),
                success=True,
            )
            logger.info(f"Pulled changes from remote {remote_id} to local object")
            return True

        except Exception as e:
            logger.error(f"Failed to pull changes from {remote_id}: {e}", exc_info=True)
            mapping.sync_status = SyncMapping.SyncStatus.FAILED
            mapping.error_message = str(e)
            mapping.save()

            self._log_sync_event(
                mapping, SyncMapping.SyncDirection.PULL, [], success=False, error=str(e)
            )
            return False

    def validate_webhook_request(self, request: HttpRequest) -> bool:
        """
        Validates the incoming webhook request (signatures, tokens, etc).
        Returns True if valid, raises generic exceptions or returns False if invalid.
        """
        raise NotImplementedError("validate_webhook_request must be implemented")

    def extract_webhook_event_type(self, payload: dict) -> str:
        """
        Extracts the event type string (e.g., 'issue_updated', 'sn_update') from the payload.
        """
        raise NotImplementedError("extract_webhook_event_type must be implemented")

    def extract_webhook_remote_id(self, payload: dict[str, Any]) -> str:
        """Return the provider-specific identifier used to resolve a mapping."""

        return self._extract_remote_id(payload)

    def handle_webhook_event(self, event_type: str, payload: dict[str, Any]) -> bool:
        """Handle incoming webhook event

        Args:
            event_type: Type of event (e.g., 'issue_updated', 'issue_created')
            payload: Webhook payload

        Returns:
            True if event was handled successfully
        """
        raise RuntimeError(
            "Direct webhook mutation is disabled; persist a durable sync intent."
        )

        try:  # pragma: no cover
            remote_id = self._extract_remote_id(payload)
            if not remote_id:
                logger.warning(
                    f"Could not extract remote ID from payload for event {event_type}"
                )
                return False

            if event_type in ["created", "updated"]:
                remote_data = self._extract_remote_data(payload)
                if not remote_data:
                    logger.warning(
                        f"Could not extract remote data from payload for event {event_type}"
                    )
                    return False
                return self.pull_changes(remote_id, remote_data)
            elif event_type == "deleted":
                return self._handle_remote_deletion(remote_id)
            else:
                logger.info(f"Ignoring unhandled event type: {event_type}")
                return True  # Not a failure, just not handled

        except Exception as e:
            logger.error(f"Failed to handle webhook event: {e}", exc_info=True)
            return False

    @abstractmethod
    def _extract_remote_id(self, payload: dict[str, Any]) -> str:
        """Extract remote object ID from webhook payload"""
        pass

    @abstractmethod
    def _extract_remote_data(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Extract remote object data from webhook payload"""
        pass

    def _get_existing_mapping(self, local_object: models.Model) -> SyncMapping | None:
        """Return the exact owner-coherent mapping; never create one on save."""
        from .models import SyncMapping

        content_type = ContentType.objects.get_for_model(local_object)
        object_folder_id = getattr(local_object, "folder_id", None)
        if object_folder_id is None:
            logger.warning(
                "Skipping push for object without an owner folder",
                model=content_type.model,
                object_id=str(local_object.pk),
            )
            return None

        mapping = (
            SyncMapping.objects.filter(
                configuration_id=self.configuration.pk,
                configuration__is_active=True,
                configuration__provider__is_active=True,
                configuration__folder_id=object_folder_id,
                content_type=content_type,
                local_object_id=local_object.pk,
                folder_id=object_folder_id,
            )
            .select_related("configuration")
            .first()
        )
        if mapping is None:
            logger.warning(
                "Skipping push without an active, owner-coherent mapping",
                config_id=str(self.configuration.pk),
                model=content_type.model,
                object_id=str(local_object.pk),
            )
        return mapping

    def _get_local_object(self, mapping: SyncMapping) -> AbstractBaseModel:
        """Get local Django model instance from mapping"""
        # Use the ContentType to get the correct model
        Model = mapping.content_type.model_class()
        return Model.objects.get(pk=mapping.local_object_id)

    def _update_local_object(
        self, local_object: models.Model, local_data: dict[str, Any]
    ) -> None:
        """Apply legacy pull callers through the same typed local boundary."""
        from integrations.local_commands import apply_inbound_update
        from integrations.syncable import model_key_for_content_type

        content_type = ContentType.objects.get_for_model(local_object)
        model_key = model_key_for_content_type(content_type) or self.DEFAULT_MODEL_KEY
        apply_inbound_update(
            local_object=local_object,
            local_data=local_data,
            mapper=self.mapper_for(model_key),
        )
        logger.debug(
            f"Updated local object {local_object.pk} with fields: {list(local_data.keys())}"
        )

    def _has_conflict(self, mapping: SyncMapping, remote_data: dict[str, Any]) -> bool:
        """Check if there's a conflict between local and remote changes

        A conflict exists if:
        1. Local object was modified since last sync (version mismatch)
        2. Remote data differs from cached remote_data
        """
        # Simple version-based conflict detection
        # You can override this for more sophisticated conflict detection
        local_object = self._get_local_object(mapping)

        # Check if local object was modified recently
        if hasattr(local_object, "updated_at"):
            # Compare local object's last update to the mapping's last sync
            if local_object.updated_at > mapping.last_synced_at:
                # Local changes exist, check if remote also changed
                if mapping.remote_data != remote_data:
                    return True

        return False

    def _resolve_conflict(
        self,
        mapping: SyncMapping,
        remote_data: dict[str, Any],
        model_key: str | None = None,
    ) -> bool:
        """Resolve conflict between local and remote changes

        Default strategy: Remote wins (last-write-wins from remote side)
        Override this method to implement different conflict resolution strategies
        """
        model_key = model_key or self.DEFAULT_MODEL_KEY
        mapper = self.mapper_for(model_key)
        client = self.client_for(model_key)
        conflict_resolution = self.configuration.settings.get(
            "conflict_resolution", "remote_wins"
        )

        if conflict_resolution == "remote_wins":
            logger.info(f"Resolving conflict for mapping {mapping.id}: remote wins")
            local_data = mapper.to_local(remote_data)
            local_object = self._get_local_object(mapping)
            self._update_local_object(local_object, local_data)

            mapping.sync_status = SyncMapping.SyncStatus.SYNCED
            mapping.remote_data = remote_data
            mapping.version += 1
            mapping.save()
            return True

        elif conflict_resolution == "local_wins":
            logger.info(f"Resolving conflict for mapping {mapping.id}: local wins")
            local_object = self._get_local_object(mapping)
            remote_changes = mapper.to_remote(local_object)
            client.update_remote_object(mapping.remote_id, remote_changes)

            mapping.sync_status = SyncMapping.SyncStatus.SYNCED
            mapping.remote_data = remote_data
            mapping.version += 1
            mapping.save()
            return True

        elif conflict_resolution == "manual":
            logger.info(f"Conflict for mapping {mapping.id} requires manual resolution")
            mapping.sync_status = "conflict"
            mapping.save()
            return False

        return False

    def _handle_remote_deletion(self, remote_id: str) -> bool:
        """Handle deletion of remote object

        Default behavior: Mark mapping as failed
        Override to implement custom deletion handling
        """
        from .models import SyncMapping

        try:
            mapping = SyncMapping.objects.get(
                configuration=self.configuration, remote_id=remote_id
            )

            # Option 1: Mark as failed
            mapping.sync_status = SyncMapping.SyncStatus.FAILED
            mapping.error_message = "Remote object was deleted"
            mapping.save()

            # Option 2: Delete the local object (use with caution!)
            # local_object = self._get_local_object(mapping)
            # local_object.delete() # This will delete the mapping via CASCADE

            # Option 3: Set local object to a 'deprecated' or 'archived' status
            # local_object = self._get_local_object(mapping)
            # local_object.status = "deprecated"
            # local_object.save(skip_sync=True)
            # mapping.delete() # Remove the mapping

            logger.info(
                f"Remote object {remote_id} was deleted. Marked mapping {mapping.id} as failed."
            )
            return True

        except SyncMapping.DoesNotExist:
            logger.warning(f"No mapping found for deleted remote object {remote_id}")
            return False

    def _log_sync_event(
        self,
        mapping: SyncMapping,
        direction: str,
        changed_fields: list[str],
        success: bool,
        error: str = "",
    ) -> None:
        """Create audit log entry for sync operation"""
        from .models import SyncEvent

        SyncEvent.objects.create(
            mapping=mapping,
            mapping_id_snapshot=mapping.id,
            configuration_id_snapshot=mapping.configuration_id,
            content_type_id_snapshot=mapping.content_type_id,
            local_object_id_snapshot=mapping.local_object_id,
            remote_id_snapshot=mapping.remote_id,
            direction=direction,
            changes={"fields": changed_fields},
            triggered_by=SyncEvent.TriggeredBy.WEBHOOK
            if direction == SyncMapping.SyncDirection.PULL
            else SyncEvent.TriggeredBy.USER,
            success=success,
            error_details=error,
        )


class BaseITSMOrchestrator(BaseSyncOrchestrator):
    """Base orchestrator specifically for ITSM integrations

    Provides common ITSM-specific functionality
    """

    def _extract_remote_id(self, payload: dict[str, Any]) -> str:
        """Most ITSM systems use 'key' or 'id' for issue identifier"""
        # Jira payload: { ..., "issue": { "id": "10001", "key": "PROJ-1" } }
        issue = payload.get("issue", {})
        return issue.get("key")

    def _extract_remote_data(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Most ITSM systems nest data under 'issue' or 'fields'"""
        # We pass the whole 'issue' object, as mappers may need 'id' or 'key'
        # as well as the 'fields' dictionary.
        if "issue" in payload:
            return payload["issue"]
        return payload
