from collections.abc import Mapping
from dataclasses import dataclass

import structlog
from core.serializers import BaseModelSerializer
from django.db import transaction
from django.urls import reverse
from iam.models import Folder, RoleAssignment
from rest_framework import serializers
from rest_framework.exceptions import PermissionDenied

from .models import (
    IntegrationConfiguration,
    IntegrationProvider,
    SyncMapping,
)
from .registry import IntegrationRegistry
from .syncable import SYNCABLE_MODELS, mappable_field_keys

logger = structlog.get_logger(__name__)


_LEGACY_MAPPING_KEYS = ("field_map", "value_map")


def _validate_model_mapping_settings(
    model_key: str, model_settings, *, path: str
) -> list[str]:
    """Validate one model's persisted mapping as an unambiguous contract."""

    errors: list[str] = []
    if not isinstance(model_settings, Mapping):
        return [f"{path} must be an object."]

    governed_fields = mappable_field_keys(model_key)
    if "field_map" in model_settings:
        field_map = model_settings["field_map"]
        if not isinstance(field_map, Mapping):
            errors.append(f"{path}.field_map must be an object.")
        else:
            remote_targets: set[str] = set()
            for local_field, remote_target in field_map.items():
                field_path = f"{path}.field_map.{local_field}"
                if (
                    not isinstance(local_field, str)
                    or local_field not in governed_fields
                ):
                    errors.append(
                        f"{field_path} is not a mappable field for {model_key}."
                    )
                    continue
                if not isinstance(remote_target, str):
                    errors.append(f"{field_path} must target a string field name.")
                    continue
                canonical_target = remote_target.strip()
                if not canonical_target:
                    errors.append(f"{field_path} must not have an empty remote target.")
                    continue
                if remote_target != canonical_target or any(
                    character.isspace() for character in remote_target
                ):
                    errors.append(f"{field_path} contains non-canonical whitespace.")
                if canonical_target in remote_targets:
                    errors.append(
                        f"{field_path} duplicates remote target {canonical_target!r}."
                    )
                remote_targets.add(canonical_target)

    if "value_map" in model_settings:
        value_map = model_settings["value_map"]
        if not isinstance(value_map, Mapping):
            errors.append(f"{path}.value_map must be an object.")
        else:
            for local_field, mapping in value_map.items():
                field_path = f"{path}.value_map.{local_field}"
                if (
                    not isinstance(local_field, str)
                    or local_field not in governed_fields
                ):
                    errors.append(
                        f"{field_path} is not a mappable field for {model_key}."
                    )
                    continue
                if not isinstance(mapping, Mapping):
                    errors.append(f"{field_path} must be an object.")
                    continue

                # Incoming sync reverses this mapping after coercing provider
                # values to strings.  Reject collisions that would otherwise
                # make the selected local value depend on insertion order.
                remote_values: set[str] = set()
                for remote_value in mapping.values():
                    if isinstance(remote_value, (Mapping, list, tuple, set)):
                        errors.append(
                            f"{field_path} values must be scalar JSON values."
                        )
                        continue
                    canonical_value = str(remote_value)
                    if canonical_value in remote_values:
                        errors.append(
                            f"{field_path} has an ambiguous remote value "
                            f"{canonical_value!r}."
                        )
                    remote_values.add(canonical_value)

    return errors


def _validate_governed_settings(settings) -> dict:
    """Return a plain settings object after validating all mapping carriers."""

    if not isinstance(settings, Mapping):
        raise serializers.ValidationError({"settings": ["Must be an object."]})

    normalized = dict(settings)
    errors: list[str] = []

    legacy_settings = {
        key: normalized[key] for key in _LEGACY_MAPPING_KEYS if key in normalized
    }
    if legacy_settings:
        errors.extend(
            _validate_model_mapping_settings(
                "applied_control", legacy_settings, path="settings"
            )
        )

    if "models" in normalized:
        models = normalized["models"]
        if not isinstance(models, Mapping):
            errors.append("settings.models must be an object.")
        else:
            for model_key, model_settings in models.items():
                if not isinstance(model_key, str) or model_key not in SYNCABLE_MODELS:
                    errors.append(
                        f"settings.models.{model_key} is not a syncable model."
                    )
                    continue
                errors.extend(
                    _validate_model_mapping_settings(
                        model_key,
                        model_settings,
                        path=f"settings.models.{model_key}",
                    )
                )

    if errors:
        raise serializers.ValidationError({"settings": errors})
    return normalized


class _ExactInputSerializer(serializers.Serializer):
    """DRF normally ignores unknown keys; authority input must reject them."""

    def to_internal_value(self, data):
        if not isinstance(data, Mapping):
            raise serializers.ValidationError("Expected an object.")
        unexpected = set(data) - set(self.fields)
        if unexpected:
            raise serializers.ValidationError(
                {field: "Unexpected field." for field in sorted(unexpected)}
            )
        return super().to_internal_value(data)


class IntegrationProviderReceiptSerializer(_ExactInputSerializer):
    """Normalized provider evidence bound to one exact operation and snapshot."""

    schema_version = serializers.ChoiceField(choices=("provider-receipt-v1",))
    provider_id = serializers.UUIDField()
    provider_event_id = serializers.CharField(
        min_length=1, max_length=255, trim_whitespace=True
    )
    request_digest = serializers.RegexField(r"\A[0-9a-f]{64}\Z")
    remote_id = serializers.CharField(
        allow_blank=True, max_length=255, trim_whitespace=False
    )
    outcome = serializers.ChoiceField(choices=("applied", "not_applied"))
    observed_at = serializers.DateTimeField()
    evidence_reference = serializers.CharField(
        min_length=8, max_length=2048, trim_whitespace=True
    )
    remote_data_sha256 = serializers.RegexField(r"\A[0-9a-f]{64}\Z")


class IntegrationSyncJobReconcileSerializer(_ExactInputSerializer):
    """Validate a checker decision without exposing the retained job payload."""

    action = serializers.ChoiceField(
        choices=(
            "confirm_applied",
            "confirm_not_applied",
            "retry_same_operation",
            "requeue_after_key_restore",
            "accept_remote",
            "keep_local",
        )
    )
    reason = serializers.CharField(min_length=8, max_length=2000, trim_whitespace=True)
    provider_receipt = IntegrationProviderReceiptSerializer(required=False)
    remote_data = serializers.DictField(required=False)

    def validate(self, attrs):
        action = attrs["action"]
        if action in {"confirm_applied", "confirm_not_applied"}:
            missing = {
                field
                for field in ("provider_receipt", "remote_data")
                if field not in attrs
            }
            if missing:
                raise serializers.ValidationError(
                    {field: "This field is required." for field in sorted(missing)}
                )
        else:
            unexpected = {
                field for field in ("provider_receipt", "remote_data") if field in attrs
            }
            if unexpected:
                raise serializers.ValidationError(
                    {
                        field: "This field is only accepted when confirming an effect."
                        for field in sorted(unexpected)
                    }
                )
        return attrs


_CONFIGURATION_MUTATION_AUTHORITY = object()


@dataclass(frozen=True)
class _ConfigurationMutationProof:
    authority: object
    operation: str
    serializer_marker: int
    instance_marker: int | None
    instance_id: object | None
    provider_id: object
    folder_id: object


def _bind_configuration_mutation_authority(
    serializer: "IntegrationConfigurationSerializer",
    *,
    instance: IntegrationConfiguration | None,
    provider: IntegrationProvider,
    folder: Folder,
    operation: str | None = None,
) -> None:
    """Bind a one-shot proof minted by the locked API mutation boundary.

    The serializer is also used by generic batch and internal call sites.  It
    must therefore fail closed unless the configuration, provider and folder
    have already been stabilized and authorized by the view transaction.
    """

    if not transaction.get_connection().in_atomic_block:
        raise RuntimeError("Integration configuration writes require a transaction.")
    if serializer.instance is not instance:
        raise RuntimeError("Mutation proof does not match the serializer instance.")
    operation = operation or ("create" if instance is None else "update")
    if operation not in {"create", "update", "delete"}:
        raise RuntimeError("Unknown integration configuration mutation operation.")

    # Provider-specific validation performed by ``is_valid`` happened before
    # the provider row lock.  Repeat it against the exact locked carrier.
    if operation != "delete":
        serializer._validate_registry_configuration(
            serializer.validated_data, provider=provider
        )
    serializer._configuration_mutation_proof = _ConfigurationMutationProof(
        authority=_CONFIGURATION_MUTATION_AUTHORITY,
        operation=operation,
        serializer_marker=id(serializer),
        instance_marker=id(instance) if instance is not None else None,
        instance_id=instance.id if instance is not None else None,
        provider_id=provider.id,
        folder_id=folder.id,
    )


class IntegrationProviderSerializer(serializers.ModelSerializer):
    """
    Read-only serializer for listing available integration providers.
    """

    class Meta:
        model = IntegrationProvider
        fields = ["id", "name", "provider_type", "is_active"]
        read_only_fields = fields


class ConnectionTestSerializer(serializers.Serializer):
    provider = serializers.CharField(write_only=True)
    configuration_id = serializers.PrimaryKeyRelatedField(
        queryset=IntegrationConfiguration.objects.filter(is_active=True),
        label="Configuration ID",
        required=False,
    )
    credentials = serializers.DictField()
    settings = serializers.DictField(required=False, default=dict)

    def validate_configuration_id(self, config):
        request = self.context.get("request")
        if request is None:
            raise serializers.ValidationError("Configuration not found.")
        # Viewable, not changeable: a Domain Manager may create a configuration
        # without holding change_, and must still be able to test it. What keeps
        # the stored secret safe is the same-connection pinning below, not this.
        viewable_ids = RoleAssignment.get_viewable_object_ids(
            request.user, IntegrationConfiguration
        )

        if config.id not in viewable_ids:
            raise serializers.ValidationError("Configuration not found.")
        return config

    def validate(self, data):
        provider = data.get("provider")
        config: IntegrationConfiguration | None = data.get("configuration_id")
        credentials = dict(data.get("credentials") or {})

        if config:
            if provider != config.provider.name:
                raise serializers.ValidationError(
                    {"provider": "Provider does not match configuration."}
                )
            stored = config.credentials or {}
            # a stored secret is only replayable to the connection it was stored for
            backfilled = {k for k in stored if not credentials.get(k)}
            if backfilled and any(
                v != stored.get(k)
                for k, v in credentials.items()
                if k not in backfilled
            ):
                raise serializers.ValidationError(
                    {"credentials": "reenterSecretToTestModifiedConnection"}
                )
            credentials.update({k: stored[k] for k in backfilled})

        is_valid, errors = IntegrationRegistry.validate_configuration(
            provider,
            {"credentials": credentials, "settings": data.get("settings", {})},
        )

        if not is_valid:
            raise serializers.ValidationError({"provider_specific_errors": errors})

        data["credentials"] = credentials
        return data


class IntegrationConfigurationSerializer(BaseModelSerializer):
    """
    Serializer for creating, reading, and updating IntegrationConfiguration instances.
    """

    # On read, show the provider's name for better readability
    provider = serializers.StringRelatedField(read_only=True)
    # On write, accept the provider's primary key
    provider_id = serializers.PrimaryKeyRelatedField(
        queryset=IntegrationProvider.objects.filter(is_active=True),
        source="provider",
        label="Provider ID",
    )

    # On read, show the folder's name
    folder = serializers.StringRelatedField(read_only=True)
    # On write, accept the folder's primary key
    folder_id = serializers.PrimaryKeyRelatedField(
        queryset=Folder.objects.all(),
        source="folder",
        label="Folder ID",
    )

    webhook_secret = serializers.CharField(write_only=True, required=False)

    # A generated, read-only field to show the full webhook URL
    webhook_url_full = serializers.SerializerMethodField()

    has_api_token = serializers.SerializerMethodField()
    has_webhook_secret = serializers.SerializerMethodField()

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        request = self.context.get("request")
        if request is not None and "folder_id" in self.fields:
            accessible_folders = RoleAssignment.get_viewable_object_ids(
                request.user, Folder
            )

            self.fields["folder_id"].queryset = Folder.objects.filter(
                id__in=accessible_folders
            )

    class Meta:
        model = IntegrationConfiguration
        fields = [
            "id",
            "provider",
            "provider_id",
            "folder",
            "folder_id",
            "credentials",
            "settings",
            "is_active",
            "last_sync_at",
            "webhook_url_full",
            "has_api_token",
            "has_webhook_secret",
            "webhook_secret",
        ]
        read_only_fields = ["id", "last_sync_at", "webhook_url_full"]

    def get_webhook_url_full(self, obj: IntegrationConfiguration) -> str:
        """Construct the full, absolute webhook URL"""
        if not obj.pk:
            return ""

        request = self.context.get("request")
        if not request:
            return "Webhook URL requires request context."

        # Build the path to the webhook receiver view
        path = reverse("integrations:webhook-receiver", kwargs={"config_id": obj.id})

        return path

    def get_has_api_token(self, obj: IntegrationConfiguration) -> bool:
        return bool(
            obj.credentials
            and (obj.credentials.get("api_token") or obj.credentials.get("password"))
        )

    def get_has_webhook_secret(self, obj: IntegrationConfiguration) -> bool:
        return bool(obj.webhook_secret)

    def _consume_mutation_proof(
        self, validated_data, *, instance, operation: str
    ) -> None:
        proof = getattr(self, "_configuration_mutation_proof", None)
        provider = validated_data.get(
            "provider", instance.provider if instance is not None else None
        )
        folder = validated_data.get(
            "folder", instance.folder if instance is not None else None
        )
        expected_instance_id = instance.id if instance is not None else None
        valid = (
            isinstance(proof, _ConfigurationMutationProof)
            and proof.authority is _CONFIGURATION_MUTATION_AUTHORITY
            and proof.operation == operation
            and proof.serializer_marker == id(self)
            and proof.instance_marker
            == (id(instance) if instance is not None else None)
            and proof.instance_id == expected_instance_id
            and provider is not None
            and proof.provider_id == provider.id
            and folder is not None
            and proof.folder_id == folder.id
            and transaction.get_connection().in_atomic_block
        )
        # A proof authorizes one save only.  Consume it before any mutation so
        # an exception cannot leave a reusable capability on the serializer.
        self._configuration_mutation_proof = None
        if not valid:
            raise PermissionDenied(
                "Integration configuration writes require locked API authority."
            )

    def create(self, validated_data):
        self._consume_mutation_proof(validated_data, instance=None, operation="create")
        # BaseModelSerializer logs the complete validated payload at debug
        # level.  Integration credentials must never enter application logs;
        # the view has already performed the equivalent exact add check.
        return serializers.ModelSerializer.create(self, validated_data)

    def update(self, instance, validated_data):
        """Invalidate the cached remote schema when credentials change.

        Repointing instance_url (or swapping accounts) makes the cached
        tables/columns/choices describe the wrong instance; drop the row so the
        next page load lazily re-fetches from the new target.
        """
        self._consume_mutation_proof(
            validated_data, instance=instance, operation="update"
        )
        old_credentials = dict(instance.credentials or {})
        old_provider_id = instance.provider_id
        instance = super().update(instance, validated_data)
        new_credentials = instance.credentials or {}
        invalidate_schema = (
            "credentials" in validated_data and new_credentials != old_credentials
        ) or ("provider" in validated_data and instance.provider_id != old_provider_id)
        if invalidate_schema:
            from integrations.models import IntegrationSchemaCache

            deleted, _ = IntegrationSchemaCache.objects.filter(
                configuration=instance
            ).delete()
            if deleted:
                logger.info(
                    "Invalidated schema cache after integration configuration change",
                    config_id=str(instance.id),
                )
        return instance

    def delete(self, instance) -> None:
        self._consume_mutation_proof({}, instance=instance, operation="delete")
        return super().delete(instance)

    def to_representation(self, instance):
        """
        Modify the output representation to protect sensitive credentials.
        """
        # Get the default representation
        ret = super().to_representation(instance)

        # Never expose the full credentials, especially the API token, in GET responses.
        if "credentials" in ret and isinstance(ret["credentials"], dict):
            ret["credentials"].pop("api_token", None)  # Remove api_token if it exists
            ret["credentials"].pop("password", None)  # Remove password if it exists

        return ret

    def _validate_registry_configuration(self, data, *, provider=None) -> None:
        config: IntegrationConfiguration | None = self.instance
        provider = provider or data.get(
            "provider", config.provider if config is not None else None
        )
        if provider is None:
            raise serializers.ValidationError(
                {"provider_id": "This field is required."}
            )

        credentials = (
            dict(data["credentials"] or {})
            if "credentials" in data
            else dict(config.credentials or {})
            if config is not None
            else {}
        )
        settings = (
            data["settings"]
            if "settings" in data
            else config.settings
            if config is not None
            else {}
        )
        settings = _validate_governed_settings(settings)
        if "settings" in data:
            data["settings"] = settings
        is_valid, errors = IntegrationRegistry.validate_configuration(
            provider.name,
            {"credentials": credentials, "settings": settings},
        )
        if not is_valid:
            raise serializers.ValidationError({"provider_specific_errors": errors})

    def validate(self, data):
        """Validate the complete prospective configuration.

        PATCH payloads omit stored secrets by design.  Backfill them only from
        the locked serializer instance and only while keeping the same
        provider, so a stale instance or provider swap can never replay an old
        credential into a new connection.
        """

        data = dict(data)
        config: IntegrationConfiguration | None = self.instance
        provider: IntegrationProvider | None = data.get(
            "provider", config.provider if config is not None else None
        )
        provider_changed = bool(
            config is not None
            and provider is not None
            and provider.id != config.provider_id
        )
        if provider_changed and "credentials" not in data:
            raise serializers.ValidationError(
                {"credentials": "Credentials must be re-entered for a new provider."}
            )

        if "credentials" in data:
            credentials = dict(data.get("credentials") or {})
            if config is not None and not provider_changed:
                stored_credentials = dict(config.credentials or {})
                for secret_name in ("api_token", "password"):
                    if not credentials.get(secret_name) and stored_credentials.get(
                        secret_name
                    ):
                        credentials[secret_name] = stored_credentials[secret_name]
            data["credentials"] = credentials

        self._validate_registry_configuration(data, provider=provider)
        return super().validate(data)


# Aliases expected by BaseModelViewSet's SerializerFactory
IntegrationConfigurationReadSerializer = IntegrationConfigurationSerializer
IntegrationConfigurationWriteSerializer = IntegrationConfigurationSerializer


class SyncMappingSerializer(serializers.ModelSerializer):
    """
    Serializer for the SyncMapping model, used for deletion.
    """

    class Meta:
        model = SyncMapping
        fields = ["id", "local_object_id", "remote_id", "sync_status"]
        read_only_fields = fields
