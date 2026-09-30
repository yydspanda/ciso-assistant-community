"""Per-model access to an IntegrationConfiguration's ``settings``.

Mapping config is stored nested per syncable model under
``settings["models"][model_key]``. For backward compatibility, configs created
before this change keep their mapping at the top level of ``settings``; those
legacy keys are read (never rewritten or deleted) as the ``applied_control``
entry via a non-destructive shim.
"""

from __future__ import annotations

import json

from django.core.serializers.json import DjangoJSONEncoder
from django.utils.crypto import salted_hmac

# Top-level settings keys that, on legacy configs, constitute the implicit
# "applied_control" mapping.
_LEGACY_MODEL_KEYS = (
    "table_name",
    "field_map",
    "value_map",
    "project_key",
    "issue_type",
    "base_query",
)


def get_model_settings(config_settings: dict | None, model_key: str) -> dict:
    """Return the mapping settings for ``model_key`` (table_name/field_map/...).

    Resolution order: explicit ``settings.models[model_key]``, then the legacy
    top-level shim for ``applied_control``, otherwise an empty dict.
    """
    config_settings = config_settings or {}
    models = config_settings.get("models") or {}
    if model_key in models:
        return models[model_key] or {}
    if model_key == "applied_control":
        return {
            k: config_settings[k] for k in _LEGACY_MODEL_KEYS if k in config_settings
        }
    return {}


def is_model_configured(config_settings: dict | None, model_key: str) -> bool:
    """True if the config has a usable remote target for ``model_key``.

    A model counts as configured only once it points at a remote target (a
    ServiceNow ``table_name`` or a Jira ``project_key``). A field_map without a
    target is not enough to sync, so it does not count.
    """
    ms = get_model_settings(config_settings, model_key)
    return bool(ms.get("table_name") or ms.get("project_key"))


def integration_sync_fingerprint(configuration, model_key: str) -> str:
    """Bind queued outbound work to one reviewed connector configuration state.

    Credentials and settings can repoint an integration without changing its
    primary key.  Hash their canonical representation so delayed tasks can
    fail closed on that change without putting credential values on the queue.
    Provider and folder identity are included because they are part of the
    outbound authority boundary too.
    """

    provider = configuration.provider
    payload = {
        "configuration_id": str(configuration.id),
        "configuration_active": configuration.is_active,
        "folder_id": str(configuration.folder_id),
        "provider_id": str(configuration.provider_id),
        "provider_folder_id": str(provider.folder_id),
        "provider_name": provider.name,
        "provider_type": provider.provider_type,
        "provider_active": provider.is_active,
        "model_key": model_key,
        "credentials": configuration.credentials or {},
        "settings": configuration.settings or {},
    }
    canonical = json.dumps(
        payload,
        cls=DjangoJSONEncoder,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    digest = salted_hmac(
        "integrations.sync.configuration.v1",
        canonical,
        algorithm="sha256",
    ).hexdigest()
    return f"v1:{digest}"


def configured_model_keys(config_settings: dict | None) -> list[str]:
    """All model keys this config has a mapping for (nested + legacy implicit)."""
    from integrations.syncable import SYNCABLE_MODELS

    return [key for key in SYNCABLE_MODELS if is_model_configured(config_settings, key)]
