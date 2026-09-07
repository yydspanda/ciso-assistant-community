"""Immutable, fail-closed capabilities for asynchronous integration work.

The queue is a transport, not an authority source.  Every capability binds one
configuration, provider, mapping and local-object database snapshot.  Workers
must re-lock and revalidate that exact graph before claiming the capability and
before performing any external or local side effect.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from collections.abc import Iterable, Mapping
from datetime import timedelta
from typing import Any

from django.conf import settings
from django.contrib.contenttypes.models import ContentType
from django.core.serializers.json import DjangoJSONEncoder
from django.db import models, transaction
from django.utils import timezone
from django.utils.dateparse import parse_datetime
from iam.models import Folder
from structlog import get_logger

from integrations.models import (
    IntegrationConfiguration,
    IntegrationProvider,
    IntegrationSyncJob,
    SyncMapping,
)
from integrations.remote_ids import InvalidRemoteIdentifier, normalize_remote_id
from integrations.syncable import model_key_for_content_type

CAPABILITY_VERSION = 5
logger = get_logger(__name__)


class IntegrationSigningKeyUnavailable(Exception):
    """A queued capability references a key not present in the active ring."""


def primary_signing_key_id() -> str:
    return str(settings.INTEGRATION_SIGNING_PRIMARY_KEY_ID)


def _canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    ).encode("utf-8")


def canonical_sha256(value: Any) -> str:
    """Return a stable digest without placing configuration secrets in a job."""

    return hashlib.sha256(_canonical_json_bytes(value)).hexdigest()


def authority_hmac(
    value: Any, *, domain: str, signing_key_id: str | None = None
) -> str:
    """Return a domain-separated server-keyed digest for sensitive state."""

    key_id = signing_key_id or primary_signing_key_id()
    try:
        signing_key = settings.INTEGRATION_SIGNING_KEYS[key_id]
    except (AttributeError, KeyError, TypeError) as exc:
        raise IntegrationSigningKeyUnavailable from exc

    return hmac.new(
        str(signing_key).encode("utf-8"),
        _canonical_json_bytes({"domain": domain, "value": value}),
        hashlib.sha256,
    ).hexdigest()


def model_row_authority_hmac(
    instance: models.Model, *, signing_key_id: str | None = None
) -> str:
    """Bind every concrete row field without exposing an offline oracle."""

    return authority_hmac(
        {
            field.attname: getattr(instance, field.attname)
            for field in instance._meta.concrete_fields
        },
        domain=f"integration-model-row-v1:{instance._meta.label_lower}",
        signing_key_id=signing_key_id,
    )


def configuration_authority_hmac(
    configuration: IntegrationConfiguration,
    *,
    signing_key_id: str | None = None,
) -> str:
    """Bind configuration authority without creating a secret verifier.

    Configuration rows contain provider credentials and webhook secrets. A
    plain digest stored in the outbox would let anyone who can read the job
    table test guesses for low-entropy secrets offline. A versioned,
    server-keyed HMAC still invalidates work after any row change without
    disclosing such an oracle, while retained ring keys permit safe rotation.
    """

    return model_row_authority_hmac(configuration, signing_key_id=signing_key_id)


def folder_lineage_authority_hmac(
    folder: Folder, *, signing_key_id: str | None = None
) -> str:
    """Bind the owner and its complete parent chain, not only its UUID."""

    lineage = folder.get_parent_folders(include_self=True)
    return authority_hmac(
        [
            {
                field.attname: getattr(item, field.attname)
                for field in item._meta.concrete_fields
            }
            for item in lineage
        ],
        domain="integration-folder-lineage-v1",
        signing_key_id=signing_key_id,
    )


def folder_lineage_ids(folder: Folder) -> list[str]:
    return [str(item.id) for item in folder.get_parent_folders(include_self=True)]


def mapping_payload_authority_hmac(
    mapping: SyncMapping, *, signing_key_id: str | None = None
) -> str:
    """Bind mapping state that is not changed by the worker's claim write."""

    return authority_hmac(
        {
            "configuration_id": mapping.configuration_id,
            "content_type_id": mapping.content_type_id,
            "local_object_id": mapping.local_object_id,
            "remote_id": mapping.remote_id,
            "remote_data": mapping.remote_data,
            "folder_id": mapping.folder_id,
        },
        domain="integration-mapping-payload-v1",
        signing_key_id=signing_key_id,
    )


def integration_payload_hmac(
    payload: Mapping[str, Any], *, signing_key_id: str | None = None
) -> str:
    return authority_hmac(
        payload,
        domain="integration-sync-payload-v1",
        signing_key_id=signing_key_id,
    )


def integration_review_state_hmac(
    *,
    job_id: Any,
    request_digest: str,
    mapping: SyncMapping,
    signing_key_id: str,
) -> str:
    """Bind the exact conflict state handed from the worker to a checker."""

    return authority_hmac(
        {
            "job_id": str(job_id),
            "request_digest": request_digest,
            "mapping_id": str(mapping.id),
            "mapping_version": mapping.version,
            "mapping_status": mapping.sync_status,
            "mapping_error": mapping.error_message,
            "mapping_payload_hmac_sha256": mapping_payload_authority_hmac(
                mapping, signing_key_id=signing_key_id
            ),
        },
        domain="integration-review-state-v1",
        signing_key_id=signing_key_id,
    )


def _base_capability(
    *,
    configuration: IntegrationConfiguration,
    mapping: SyncMapping,
    local_object: models.Model,
) -> dict[str, Any]:
    provider = configuration.provider
    content_type = ContentType.objects.get_for_model(local_object)
    signing_key_id = primary_signing_key_id()
    return {
        "capability_version": CAPABILITY_VERSION,
        "signing_key_id": signing_key_id,
        "configuration_id": str(configuration.id),
        "configuration_hmac_sha256": configuration_authority_hmac(
            configuration, signing_key_id=signing_key_id
        ),
        "provider_id": str(provider.id),
        "provider_hmac_sha256": model_row_authority_hmac(
            provider, signing_key_id=signing_key_id
        ),
        "mapping_id": str(mapping.id),
        "mapping_version": mapping.version,
        "mapping_payload_hmac_sha256": mapping_payload_authority_hmac(
            mapping, signing_key_id=signing_key_id
        ),
        "content_type_id": content_type.id,
        "object_id": str(local_object.pk),
        "object_hmac_sha256": model_row_authority_hmac(
            local_object, signing_key_id=signing_key_id
        ),
        # Immutable creation generation. Unlike the execution snapshots above,
        # these values are never rebased and therefore distinguish A→B→A and
        # multiple local writes queued against the same mapping version.
        "source_state_hmac_sha256": model_row_authority_hmac(
            local_object, signing_key_id=signing_key_id
        ),
        "source_mapping_version": mapping.version,
        "folder_id": str(local_object.folder_id),
        "folder_lineage_hmac_sha256": folder_lineage_authority_hmac(
            local_object.folder, signing_key_id=signing_key_id
        ),
        "folder_lineage_ids": folder_lineage_ids(local_object.folder),
    }


def _coherent_graph(
    *,
    configuration: IntegrationConfiguration,
    mapping: SyncMapping,
    local_object: models.Model,
    content_type: ContentType,
) -> bool:
    provider = configuration.provider
    object_folder_id = getattr(local_object, "folder_id", None)
    return bool(
        provider.is_active
        and provider.provider_type == IntegrationProvider.ProviderType.ITSM
        and configuration.is_active
        and object_folder_id is not None
        and configuration.folder_id == object_folder_id
        and mapping.folder_id == object_folder_id
        and mapping.configuration_id == configuration.id
        and mapping.content_type_id == content_type.id
        and mapping.local_object_id == local_object.pk
        and model_key_for_content_type(content_type) is not None
    )


def build_outbound_capabilities(
    *,
    content_type_id: int,
    object_id: Any,
    configuration_ids: Iterable[Any],
    changed_fields: Iterable[str],
) -> list[tuple[dict[str, Any], dict[str, Any], list[str]]]:
    """Build exact provider payloads for every coherent outbound mapping."""

    try:
        content_type = ContentType.objects.get_for_id(content_type_id)
    except ContentType.DoesNotExist:
        return []
    model = content_type.model_class()
    if model is None or model_key_for_content_type(content_type) is None:
        return []
    local_object = model.objects.filter(pk=object_id).first()
    if local_object is None or getattr(local_object, "folder_id", None) is None:
        return []

    requested_ids = {str(value) for value in configuration_ids}
    mappings = (
        SyncMapping.objects.filter(
            configuration_id__in=requested_ids,
            content_type=content_type,
            local_object_id=local_object.pk,
        )
        .select_related("configuration__provider")
        .order_by("configuration_id", "id")
    )
    capabilities = []
    seen_configurations = set()
    for mapping in mappings:
        configuration = mapping.configuration
        provider = configuration.provider
        if (
            str(configuration.id) not in requested_ids
            or configuration.id in seen_configurations
            or not configuration.settings.get("enable_outgoing_sync", False)
            or not _coherent_graph(
                configuration=configuration,
                mapping=mapping,
                local_object=local_object,
                content_type=content_type,
            )
        ):
            continue
        from integrations.registry import IntegrationRegistry
        from integrations.settings_access import is_model_configured

        model_key = model_key_for_content_type(content_type)
        if model_key is None or (
            model_key != "applied_control"
            and not is_model_configured(configuration.settings, model_key)
        ):
            continue
        syncable_fields = set(
            getattr(local_object, "INTEGRATION_SYNCABLE_FIELDS", set())
        )
        requested_fields = {field for field in changed_fields if isinstance(field, str)}
        effective_fields = sorted(requested_fields & syncable_fields)
        mapper = IntegrationRegistry.get_orchestrator(configuration).mapper_for(
            model_key
        )
        if not mapping.remote_id:
            operation_kind = "create"
            request_intent = "push_full"
            effective_fields = sorted(syncable_fields)
            raw_payload = mapper.to_remote(local_object)
        elif not requested_fields:
            # Linking an existing record is a governed read-back.  An empty
            # field set must never silently expand into a full remote write.
            operation_kind = "refresh_existing"
            request_intent = "refresh_existing"
            effective_fields = []
            raw_payload = {}
        else:
            request_intent = (
                "push_full"
                if set(effective_fields) == syncable_fields
                else "push_partial"
            )
            operation_kind = "update"
            raw_payload = mapper.to_remote_partial(local_object, effective_fields)
        operation_payload = json.loads(json.dumps(raw_payload, cls=DjangoJSONEncoder))
        operation_slices = [
            (operation_kind, request_intent, operation_payload, effective_fields)
        ]
        # Jira status changes are workflow transitions, not issue field writes.
        # A durable attempt may authorize only one provider mutation, so split
        # them into a FIFO successor instead of hiding two effects in one job.
        if provider.name == "jira" and "status" in operation_payload:
            status_payload = {"status": operation_payload["status"]}
            field_payload = {
                key: value
                for key, value in operation_payload.items()
                if key != "status"
            }
            field_names = [field for field in effective_fields if field != "status"]
            if operation_kind == "create" and not field_payload:
                # Jira cannot create a meaningful issue from a transition
                # alone; reject the misconfiguration before minting authority.
                continue
            operation_slices = []
            if field_payload or operation_kind == "create":
                operation_slices.append(
                    (
                        operation_kind,
                        "push_partial",
                        field_payload,
                        field_names,
                    )
                )
            operation_slices.append(
                (
                    "update" if mapping.remote_id else "create",
                    "push_partial",
                    status_payload,
                    ["status"],
                )
            )
        for (
            slice_operation_kind,
            slice_request_intent,
            slice_payload,
            slice_fields,
        ) in operation_slices:
            capability = _base_capability(
                configuration=configuration,
                mapping=mapping,
                local_object=local_object,
            )
            capability.update(
                {
                    "operation_kind": slice_operation_kind,
                    "request_intent": slice_request_intent,
                    "mapping_remote_id": mapping.remote_id,
                    "payload_hmac_sha256": integration_payload_hmac(
                        slice_payload,
                        signing_key_id=capability["signing_key_id"],
                    ),
                }
            )
            capabilities.append((capability, slice_payload, slice_fields))
        seen_configurations.add(configuration.id)
    return capabilities


def _create_sync_job(
    *,
    direction: str,
    capability: dict[str, Any],
    changed_fields: list[str] | None = None,
    event_type: str = "",
    payload: Mapping[str, Any] | None = None,
    origin_principal: str,
    requested_by_id: Any | None = None,
) -> tuple[IntegrationSyncJob, bool]:
    capability = dict(capability)
    if not isinstance(origin_principal, str) or not origin_principal.strip():
        raise ValueError("An integration job requires an origin principal.")
    requested_by_snapshot = (
        str(requested_by_id) if requested_by_id is not None else None
    )
    capability.update(
        {
            "origin_principal_snapshot": origin_principal.strip(),
            "requested_by_id_snapshot": requested_by_snapshot,
        }
    )
    changed_fields = sorted(
        {field for field in (changed_fields or []) if isinstance(field, str)}
    )
    payload = dict(payload or {})
    payload_hmac_sha256 = integration_payload_hmac(
        payload, signing_key_id=capability.get("signing_key_id")
    )
    capability["payload_hmac_sha256"] = payload_hmac_sha256
    request_digest = sync_job_request_digest(
        direction=direction,
        capability=capability,
        changed_fields=changed_fields,
        event_type=event_type,
        payload_hmac_sha256=payload_hmac_sha256,
    )
    defaults = {
        "direction": direction,
        "capability": capability,
        "changed_fields": changed_fields,
        "event_type": event_type,
        "payload": payload,
        "payload_hmac_sha256": payload_hmac_sha256,
        "configuration_id_snapshot": capability["configuration_id"],
        "provider_id_snapshot": capability["provider_id"],
        "mapping_id_snapshot": capability["mapping_id"],
        "content_type_id_snapshot": capability["content_type_id"],
        "local_object_id_snapshot": capability["object_id"],
        "folder_id_snapshot": capability["folder_id"],
        "origin_principal_snapshot": origin_principal.strip(),
        "requested_by_id_snapshot": requested_by_snapshot,
        "attempt_authorized_by_id_snapshot": requested_by_snapshot,
    }
    job, created = IntegrationSyncJob.objects.get_or_create(
        request_digest=request_digest,
        defaults=defaults,
    )
    return job, created


def sync_job_request_digest(
    *,
    direction: str,
    capability: Mapping[str, Any],
    changed_fields: Iterable[str],
    event_type: str,
    payload_hmac_sha256: str,
) -> str:
    """Authenticate every immutable request field in a durable job.

    The next queued inbound event may be rebased after its predecessor updates
    the same local row.  Only the predecessor-mutated mapping/object snapshots
    are excluded for incoming requests; identity, tenancy, provider authority,
    event type and payload remain permanently bound.
    """

    bound_capability = dict(capability)
    for key in (
        "mapping_version",
        "mapping_payload_hmac_sha256",
        "object_hmac_sha256",
    ):
        bound_capability.pop(key, None)
    if direction == IntegrationSyncJob.Direction.OUTBOUND:
        for key in ("operation_kind", "mapping_remote_id"):
            bound_capability.pop(key, None)
    signing_key_id = capability.get("signing_key_id")
    if not isinstance(signing_key_id, str) or not signing_key_id:
        raise IntegrationSigningKeyUnavailable
    return authority_hmac(
        {
            "schema": "integration-sync-job-v2",
            "direction": direction,
            "capability": bound_capability,
            "changed_fields": sorted(
                {field for field in changed_fields if isinstance(field, str)}
            ),
            "event_type": event_type,
            "payload_hmac_sha256": payload_hmac_sha256,
        },
        domain="integration-sync-request-v2",
        signing_key_id=signing_key_id,
    )


def enqueue_integration_sync_jobs(job_ids: Iterable[Any]) -> None:
    """Best-effort transport; durable queued rows are recovered by a sweeper."""

    try:
        from integrations.tasks import (
            process_webhook_event,
            sync_object_to_integrations,
        )

        jobs = list(
            IntegrationSyncJob.objects.filter(
                id__in=list(job_ids), status=IntegrationSyncJob.Status.QUEUED
            ).values_list("id", "direction")
        )
    except Exception as exc:
        logger.error(
            "integration_sync_enqueue_lookup_failed",
            error_type=type(exc).__name__,
            exc_info=True,
        )
        return
    for job_id, direction in jobs:
        task = (
            process_webhook_event
            if direction == IntegrationSyncJob.Direction.INCOMING
            else sync_object_to_integrations
        )
        try:
            task.schedule(args=(str(job_id),), delay=1)
            IntegrationSyncJob.objects.filter(
                id=job_id, status=IntegrationSyncJob.Status.QUEUED
            ).update(last_enqueued_at=timezone.now())
        except Exception as exc:
            # The durable queued row remains discoverable by the periodic
            # sweeper; transport failure must not unwind a committed mutation.
            logger.error(
                "integration_sync_enqueue_failed",
                job_id=str(job_id),
                direction=direction,
                error_type=type(exc).__name__,
                exc_info=True,
            )


def persist_outbound_sync_jobs(
    *,
    content_type_id: int,
    object_id: Any,
    configuration_ids: Iterable[Any],
    changed_fields: list[str],
    origin_principal: str = "ciso-assistant:model-outbox",
    requested_by_id: Any | None = None,
    reconciliation_authority: Mapping[str, Any] | None = None,
) -> list[Any]:
    """Persist outbound intents inside the caller's database transaction."""

    if not transaction.get_connection().in_atomic_block:
        raise RuntimeError(
            "Outbound integration intents must be persisted inside the business "
            "mutation transaction"
        )

    capabilities = build_outbound_capabilities(
        content_type_id=content_type_id,
        object_id=object_id,
        configuration_ids=configuration_ids,
        changed_fields=changed_fields,
    )
    reconciliation_context: dict[str, Any] | None = None
    if reconciliation_authority is not None:
        expected_keys = {
            "schema",
            "decision_id",
            "source_job_id",
            "source_request_digest",
            "action",
            "checker_id",
        }
        reconciliation_context = dict(reconciliation_authority)
        if (
            set(reconciliation_context) != expected_keys
            or reconciliation_context.get("schema")
            != "integration-reconciliation-corrective-v1"
            or reconciliation_context.get("action") != "keep_local"
            or any(
                not isinstance(reconciliation_context.get(key), str)
                or not reconciliation_context[key]
                for key in expected_keys - {"schema", "action"}
            )
            or len(
                {
                    capability.get("mapping_id")
                    for capability, _payload, _fields in capabilities
                }
            )
            > 1
        ):
            raise ValueError("Invalid reconciliation corrective authority.")

    job_ids = []
    capability_count = len(capabilities)
    for sequence, (capability, payload, effective_fields) in enumerate(
        capabilities, start=1
    ):
        if reconciliation_context is not None:
            # Every provider effect produced by one checker decision carries the
            # same signed group identity plus its exact FIFO position.  The
            # context is part of the request digest and cannot be transplanted
            # to another job without invalidating worker authority.
            capability["reconciliation_authority"] = {
                **reconciliation_context,
                "sequence": sequence,
                "total": capability_count,
            }
        job, created = _create_sync_job(
            direction=IntegrationSyncJob.Direction.OUTBOUND,
            capability=capability,
            changed_fields=effective_fields,
            payload=payload,
            origin_principal=origin_principal,
            requested_by_id=requested_by_id,
        )
        if created and job.status == IntegrationSyncJob.Status.QUEUED:
            job_ids.append(job.id)
    unique_ids = list(dict.fromkeys(job_ids))
    if reconciliation_context is not None and unique_ids:
        persisted_fifo = list(
            IntegrationSyncJob.objects.filter(id__in=unique_ids)
            .order_by("created_at", "id")
            .values_list("id", flat=True)
        )
        if persisted_fifo != unique_ids:
            # Corrective Jira creation must never allow its status transition to
            # overtake the preceding field/create effect.  Roll back the whole
            # surrounding reconciliation transaction if the durable ordering
            # cannot be proved.
            raise RuntimeError("Corrective integration FIFO order is ambiguous.")
    if unique_ids:
        transaction.on_commit(
            lambda ids=tuple(unique_ids): enqueue_integration_sync_jobs(ids),
            robust=True,
        )
    return unique_ids


def persist_webhook_sync_job(
    *,
    authenticated_configuration: IntegrationConfiguration,
    authenticated_configuration_hmac_sha256: str,
    authenticated_provider_hmac_sha256: str,
    authenticated_body_hmac_sha256: str,
    remote_id: str,
    event_type: str,
    payload: Mapping[str, Any],
) -> Any | None:
    """Persist one authenticated incoming intent under an exact locked graph."""

    if not all(
        isinstance(value, str) and len(value) == 64
        for value in (
            authenticated_configuration_hmac_sha256,
            authenticated_provider_hmac_sha256,
            authenticated_body_hmac_sha256,
        )
    ):
        return None
    with transaction.atomic():
        # This is a short database-only minting transaction.  The worker never
        # carries this root lock across provider or local side effects.
        Folder._lock_folder_tree()
        try:
            configuration = (
                IntegrationConfiguration.objects.select_for_update(of=("self",))
                .select_related("provider")
                .get(pk=authenticated_configuration.pk)
            )
            provider = IntegrationProvider.objects.select_for_update(of=("self",)).get(
                pk=configuration.provider_id
            )
        except (
            IntegrationConfiguration.DoesNotExist,
            IntegrationProvider.DoesNotExist,
        ):
            return None
        if (
            configuration_authority_hmac(configuration)
            != authenticated_configuration_hmac_sha256
            or model_row_authority_hmac(provider) != authenticated_provider_hmac_sha256
            or not provider.is_active
            or provider.provider_type != IntegrationProvider.ProviderType.ITSM
            or not configuration.is_active
            or not configuration.settings.get("enable_incoming_sync", False)
        ):
            return None

        from integrations.registry import IntegrationRegistry

        orchestrator = IntegrationRegistry.get_orchestrator(configuration)
        webhook_action = orchestrator.classify_webhook_event(event_type)
        if webhook_action not in {
            "update",
            "delete",
        }:
            return None
        try:
            remote_id = normalize_remote_id(provider.name, remote_id)
        except InvalidRemoteIdentifier:
            return None

        mappings = list(
            SyncMapping.objects.select_for_update(of=("self",))
            .filter(configuration=configuration, remote_id=remote_id)
            .select_related("content_type")
            .order_by("id")[:2]
        )
        if len(mappings) != 1:
            return None
        mapping = mappings[0]
        model = mapping.content_type.model_class()
        if model is None or model_key_for_content_type(mapping.content_type) is None:
            return None
        local_object = (
            model.objects.select_for_update(of=("self",))
            .filter(pk=mapping.local_object_id)
            .first()
        )
        if local_object is None or not _coherent_graph(
            configuration=configuration,
            mapping=mapping,
            local_object=local_object,
            content_type=mapping.content_type,
        ):
            return None
        model_key = model_key_for_content_type(mapping.content_type)
        if model_key is None:
            return None
        try:
            projected_payload = orchestrator.project_webhook_payload(
                event_type=event_type,
                payload=dict(payload),
                model_key=model_key,
            )
            projected_remote_id = normalize_remote_id(
                provider.name,
                orchestrator._extract_remote_id(projected_payload),
            )
        except (InvalidRemoteIdentifier, TypeError, ValueError):
            return None
        if projected_remote_id != remote_id:
            return None
        payload = projected_payload

        raw_remote_version = orchestrator.extract_webhook_remote_version(payload)
        if not isinstance(raw_remote_version, str):
            return None
        remote_version = parse_datetime(raw_remote_version)
        if remote_version is None:
            return None
        if timezone.is_naive(remote_version):
            remote_version = timezone.make_aware(remote_version)
        # A small skew allowance is operationally necessary; unbounded future
        # timestamps could otherwise suppress every later provider event.
        if remote_version > timezone.now() + timedelta(minutes=5):
            return None

        latest_versions = []
        cached_version = orchestrator.extract_remote_snapshot_version(
            mapping.remote_data
        )
        if cached_version is not None:
            latest_versions.append(cached_version)
        latest_job_version = (
            IntegrationSyncJob.objects.select_for_update(of=("self",))
            .filter(
                mapping_id_snapshot=mapping.id,
                direction=IntegrationSyncJob.Direction.INCOMING,
                status__in=(
                    IntegrationSyncJob.Status.QUEUED,
                    IntegrationSyncJob.Status.PROCESSING,
                    IntegrationSyncJob.Status.UNCERTAIN,
                    IntegrationSyncJob.Status.REVIEW_REQUIRED,
                ),
                remote_version__isnull=False,
            )
            .order_by("-remote_version", "-created_at", "-id")
            .values_list("remote_version", flat=True)
            .first()
        )
        if latest_job_version is not None:
            latest_versions.append(latest_job_version)
        latest_remote_version = max(latest_versions) if latest_versions else None
        if latest_remote_version is not None and remote_version < latest_remote_version:
            return None
        remote_version_ambiguous = bool(
            latest_remote_version is not None
            and remote_version == latest_remote_version
        )
        if remote_version_ambiguous and webhook_action == "update":
            try:
                incoming_remote_data = orchestrator.project_remote_snapshot(
                    model_key=model_key,
                    remote_data=orchestrator._extract_remote_data(payload),
                )
            except (TypeError, ValueError):
                return None
            if incoming_remote_data == mapping.remote_data:
                return None

        # Replay identity must survive rotation of the execution-signing ring.
        # The provider-authenticated, minimized payload includes its revision;
        # hashing it with stable object IDs avoids making the same delivery new
        # merely because the primary signing key changed.
        delivery_digest = canonical_sha256(
            {
                "schema": "integration-webhook-delivery-v2",
                "configuration_id": str(configuration.id),
                "provider_id": str(provider.id),
                "event_type": event_type,
                "webhook_action": webhook_action,
                "remote_id": remote_id,
                "payload": payload,
            }
        )
        if IntegrationSyncJob.objects.filter(
            webhook_delivery_digest=delivery_digest
        ).exists():
            return None

        capability = _base_capability(
            configuration=configuration,
            mapping=mapping,
            local_object=local_object,
        )
        capability.update(
            {
                "remote_id": remote_id,
                "event_type": event_type,
                "webhook_action": webhook_action,
                "remote_version": remote_version.isoformat(),
                "remote_version_ambiguous": remote_version_ambiguous,
                "authenticated_body_hmac_sha256": (authenticated_body_hmac_sha256),
                "webhook_delivery_digest": delivery_digest,
                "payload_hmac_sha256": integration_payload_hmac(
                    payload, signing_key_id=capability["signing_key_id"]
                ),
            }
        )
        job, created = _create_sync_job(
            direction=IntegrationSyncJob.Direction.INCOMING,
            capability=capability,
            event_type=event_type,
            payload=payload,
            origin_principal=f"integration-webhook:{configuration.id}",
        )
        if not created:
            return None
        job.webhook_delivery_digest = delivery_digest
        job.remote_version = remote_version
        job.save(
            update_fields=[
                "webhook_delivery_digest",
                "remote_version",
                "updated_at",
            ]
        )
        if job.status == IntegrationSyncJob.Status.QUEUED:
            transaction.on_commit(
                lambda job_id=job.id: enqueue_integration_sync_jobs((job_id,)),
                robust=True,
            )
            return job.id
        return None
