from __future__ import annotations

from datetime import timedelta
from typing import Any
from uuid import UUID, uuid4

from django.contrib.contenttypes.models import ContentType
from django.core.exceptions import ObjectDoesNotExist
from django.db import transaction
from django.db.models import Exists, F, OuterRef, Q
from django.utils import timezone
from django.utils.dateparse import parse_datetime
from huey import crontab
from huey.contrib.djhuey import HUEY, db_periodic_task, lock_task, task
from iam.models import Folder
from structlog import get_logger

from integrations.capabilities import (
    CAPABILITY_VERSION,
    IntegrationSigningKeyUnavailable,
    authority_hmac,
    canonical_sha256,
    configuration_authority_hmac,
    enqueue_integration_sync_jobs,
    folder_lineage_authority_hmac,
    integration_payload_hmac,
    integration_review_state_hmac,
    mapping_payload_authority_hmac,
    model_row_authority_hmac,
    primary_signing_key_id,
    sync_job_request_digest,
)
from integrations.itsm.jira.integration import *  # noqa: F403
from integrations.itsm.servicenow.integration import *  # noqa: F403
from integrations.local_commands import InboundCommandRejected, apply_inbound_update
from integrations.models import (
    IntegrationConfiguration,
    IntegrationProvider,
    IntegrationSyncAttempt,
    IntegrationSyncJob,
    SyncEvent,
    SyncMapping,
)
from integrations.remote_ids import InvalidRemoteIdentifier, normalize_remote_id
from integrations.syncable import model_key_for_content_type

from .registry import IntegrationRegistry

logger = get_logger(__name__)
CLAIM_TIMEOUT = timedelta(minutes=15)
BLOCKING_STATUSES = (
    IntegrationSyncJob.Status.QUEUED,
    IntegrationSyncJob.Status.PROCESSING,
    IntegrationSyncJob.Status.UNCERTAIN,
    IntegrationSyncJob.Status.REVIEW_REQUIRED,
)


class StaleIntegrationAuthority(Exception):
    pass


class DeterministicIntegrationFailure(Exception):
    pass


def _capability_signing_key_id(capability: dict[str, Any]) -> str:
    key_id = capability.get("signing_key_id")
    if not isinstance(key_id, str) or not key_id:
        raise StaleIntegrationAuthority
    return key_id


def _request_is_exact(job: IntegrationSyncJob, capability: dict[str, Any]) -> bool:
    signing_key_id = _capability_signing_key_id(capability)
    return bool(
        isinstance(job.payload, dict)
        and capability.get("origin_principal_snapshot") == job.origin_principal_snapshot
        and capability.get("requested_by_id_snapshot")
        == (
            str(job.requested_by_id_snapshot)
            if job.requested_by_id_snapshot is not None
            else None
        )
        and job.payload_hmac_sha256
        == integration_payload_hmac(job.payload, signing_key_id=signing_key_id)
        and job.payload_hmac_sha256 == capability.get("payload_hmac_sha256")
        and job.request_digest
        == sync_job_request_digest(
            direction=job.direction,
            capability=capability,
            changed_fields=job.changed_fields,
            event_type=job.event_type,
            payload_hmac_sha256=job.payload_hmac_sha256,
        )
    )


def _lock_claimed_graph(
    *,
    job_id: Any,
    attempt_id: Any,
    direction: str,
    require_current_authority: bool,
):
    """Lock one graph in the canonical short-transaction order.

    The non-locking job read only supplies identifiers. Authority is not used
    until the root mutex, owner folders, configuration, provider, mapping,
    local object and finally the job row are all locked and revalidated. No
    caller may carry these locks across provider I/O.
    """

    try:
        preliminary_job = IntegrationSyncJob.objects.get(
            id=job_id,
            direction=direction,
            status=IntegrationSyncJob.Status.PROCESSING,
            attempt_id=attempt_id,
        )
    except (ValueError, IntegrationSyncJob.DoesNotExist) as exc:
        raise StaleIntegrationAuthority from exc
    preliminary_capability = preliminary_job.capability
    if not isinstance(preliminary_capability, dict):
        raise StaleIntegrationAuthority

    try:
        content_type_id = int(preliminary_capability["content_type_id"])
        content_type = ContentType.objects.get_for_id(content_type_id)
        model = content_type.model_class()
        if model is None or model_key_for_content_type(content_type) is None:
            raise StaleIntegrationAuthority
        lineage_ids = [
            str(value) for value in preliminary_capability["folder_lineage_ids"]
        ]
        if not lineage_ids or len(lineage_ids) != len(set(lineage_ids)):
            raise StaleIntegrationAuthority

        Folder._lock_folder_tree()
        locked_folders = {
            str(folder.id): folder
            for folder in Folder.objects.select_for_update(of=("self",))
            .filter(id__in=lineage_ids)
            .order_by("id")
        }
        if set(locked_folders) != set(lineage_ids):
            raise StaleIntegrationAuthority
        folder = locked_folders[str(preliminary_capability["folder_id"])]

        configuration = IntegrationConfiguration.objects.select_for_update(
            of=("self",)
        ).get(pk=preliminary_capability["configuration_id"])
        provider = IntegrationProvider.objects.select_for_update(of=("self",)).get(
            pk=preliminary_capability["provider_id"]
        )
        mapping = SyncMapping.objects.select_for_update(of=("self",)).get(
            pk=preliminary_capability["mapping_id"]
        )
        local_object = model.objects.select_for_update(of=("self",)).get(
            pk=preliminary_capability["object_id"]
        )
        job = IntegrationSyncJob.objects.select_for_update(of=("self",)).get(
            id=job_id,
            direction=direction,
            status=IntegrationSyncJob.Status.PROCESSING,
            attempt_id=attempt_id,
        )
    except (KeyError, TypeError, ValueError, ObjectDoesNotExist) as exc:
        raise StaleIntegrationAuthority from exc

    capability = job.capability
    if (
        capability != preliminary_capability
        or not isinstance(capability, dict)
        or capability.get("capability_version") != CAPABILITY_VERSION
        or not _request_is_exact(job, capability)
    ):
        raise StaleIntegrationAuthority
    signing_key_id = _capability_signing_key_id(capability)

    actual_lineage_ids = [
        str(item.id) for item in folder.get_parent_folders(include_self=True)
    ]
    expected_folder_id = str(capability.get("folder_id", ""))
    structural_graph_is_exact = bool(
        str(job.configuration_id_snapshot) == str(capability.get("configuration_id"))
        and str(job.provider_id_snapshot) == str(capability.get("provider_id"))
        and str(job.mapping_id_snapshot) == str(capability.get("mapping_id"))
        and job.content_type_id_snapshot == content_type_id
        and str(job.local_object_id_snapshot) == str(capability.get("object_id"))
        and str(job.folder_id_snapshot) == expected_folder_id
        and job.origin_principal_snapshot == capability.get("origin_principal_snapshot")
        and (
            str(job.requested_by_id_snapshot)
            if job.requested_by_id_snapshot is not None
            else None
        )
        == capability.get("requested_by_id_snapshot")
        and configuration.provider_id == provider.id
        and configuration.folder_id == mapping.folder_id
        and mapping.folder_id == getattr(local_object, "folder_id", None)
        and str(mapping.folder_id) == expected_folder_id
        and mapping.configuration_id == configuration.id
        and mapping.content_type_id == content_type.id
        and mapping.local_object_id == local_object.pk
        and mapping.version == capability.get("mapping_version")
        and mapping_payload_authority_hmac(mapping, signing_key_id=signing_key_id)
        == capability.get("mapping_payload_hmac_sha256")
        and folder_lineage_authority_hmac(folder, signing_key_id=signing_key_id)
        == capability.get("folder_lineage_hmac_sha256")
        and actual_lineage_ids == lineage_ids
        and str(provider.folder_id) in actual_lineage_ids
        and provider.provider_type == IntegrationProvider.ProviderType.ITSM
    )
    current_authority_is_exact = bool(
        provider.is_active
        and configuration.is_active
        and configuration_authority_hmac(configuration, signing_key_id=signing_key_id)
        == capability.get("configuration_hmac_sha256")
        and model_row_authority_hmac(provider, signing_key_id=signing_key_id)
        == capability.get("provider_hmac_sha256")
    )
    if direction == IntegrationSyncJob.Direction.OUTBOUND:
        operation_kind = capability.get("operation_kind")
        request_intent = capability.get("request_intent")
        direction_is_exact = bool(
            configuration.settings.get("enable_outgoing_sync", False)
            and operation_kind in {"create", "update", "refresh_existing"}
            and request_intent in {"push_full", "push_partial", "refresh_existing"}
            and capability.get("mapping_remote_id") == mapping.remote_id
            and (operation_kind == "create") == (mapping.remote_id == "")
            and (operation_kind == "refresh_existing")
            == (request_intent == "refresh_existing")
            and (
                request_intent != "refresh_existing"
                or (not job.changed_fields and job.payload == {})
            )
        )
    elif direction == IntegrationSyncJob.Direction.INCOMING:
        registered_provider = IntegrationRegistry.get_provider(provider.name)
        if registered_provider is None:
            raise StaleIntegrationAuthority
        authority_orchestrator = registered_provider.create_orchestrator(configuration)
        capability_remote_version = parse_datetime(
            str(capability.get("remote_version", ""))
        )
        payload_remote_version_raw = (
            authority_orchestrator.extract_webhook_remote_version(job.payload)
        )
        payload_remote_version = (
            parse_datetime(payload_remote_version_raw)
            if isinstance(payload_remote_version_raw, str)
            else None
        )
        if capability_remote_version is not None and timezone.is_naive(
            capability_remote_version
        ):
            capability_remote_version = timezone.make_aware(capability_remote_version)
        if payload_remote_version is not None and timezone.is_naive(
            payload_remote_version
        ):
            payload_remote_version = timezone.make_aware(payload_remote_version)
        direction_is_exact = bool(
            configuration.settings.get("enable_incoming_sync", False)
            and mapping.remote_id
            and mapping.remote_id == capability.get("remote_id")
            and job.event_type == capability.get("event_type")
            and job.webhook_delivery_digest == capability.get("webhook_delivery_digest")
            and capability.get("webhook_action") in {"update", "delete"}
            and isinstance(capability.get("remote_version_ambiguous"), bool)
            and job.remote_version is not None
            and capability_remote_version == job.remote_version
            and payload_remote_version == job.remote_version
        )
    else:
        direction_is_exact = False
    if not structural_graph_is_exact or not direction_is_exact:
        raise StaleIntegrationAuthority
    if require_current_authority and not current_authority_is_exact:
        raise StaleIntegrationAuthority
    return job, configuration, provider, mapping, local_object, content_type


def _has_prior_blocking_job(job: IntegrationSyncJob) -> bool:
    prior = Q(created_at__lt=job.created_at) | Q(
        created_at=job.created_at, id__lt=job.id
    )
    return IntegrationSyncJob.objects.filter(
        prior,
        mapping_id_snapshot=job.mapping_id_snapshot,
        status__in=BLOCKING_STATUSES,
    ).exists()


def _claim_job(job_id: Any, *, direction: str) -> IntegrationSyncJob | None:
    try:
        candidate = IntegrationSyncJob.objects.get(
            id=job_id,
            direction=direction,
            status=IntegrationSyncJob.Status.QUEUED,
            available_at__lte=timezone.now(),
        )
    except (ValueError, IntegrationSyncJob.DoesNotExist):
        return None
    if _has_prior_blocking_job(candidate):
        return None
    claimed_at = timezone.now()
    attempt_id = uuid4()
    claimed = IntegrationSyncJob.objects.filter(
        id=candidate.id,
        status=IntegrationSyncJob.Status.QUEUED,
    ).update(
        status=IntegrationSyncJob.Status.PROCESSING,
        claimed_at=claimed_at,
        attempt_id=attempt_id,
        effect_started_at=None,
        attempts=F("attempts") + 1,
        failure_code="",
        terminal_at=None,
        updated_at=claimed_at,
    )
    if claimed != 1:
        return None
    candidate.refresh_from_db()
    return candidate


def _authorize_effect_locked(job: IntegrationSyncJob) -> None:
    """Commit the irreversible-effect linearization point under graph locks."""

    if job.effect_started_at is not None:
        raise StaleIntegrationAuthority
    job.effect_started_at = timezone.now()
    job.save(update_fields=["effect_started_at", "updated_at"])


def _append_sync_attempt(
    job: IntegrationSyncJob,
    *,
    outcome: str,
    completed_at=None,
    result_digest: str = "",
) -> IntegrationSyncAttempt | None:
    """Append one keyed outcome for the current immutable attempt ID."""

    if job.attempt_id is None or job.claimed_at is None:
        return None
    completed_at = completed_at or timezone.now()
    signing_key_id = primary_signing_key_id()
    authorized_by_id = (
        job.attempt_authorized_by_id_snapshot or job.requested_by_id_snapshot
    )
    if not result_digest:
        result_digest = authority_hmac(
            {
                "job_status": job.status,
                "failure_code": job.failure_code,
                "provider_receipt_hmac_sha256": (job.provider_receipt_hmac_sha256),
                "review_state_hmac_sha256": job.review_state_hmac_sha256,
            },
            domain="integration-sync-attempt-result-v1",
            signing_key_id=signing_key_id,
        )
    envelope = {
        "schema": "integration-sync-attempt-v1",
        "attempt_id": str(job.attempt_id),
        "job_id": str(job.id),
        "request_digest": job.request_digest,
        "authorized_by_id": (
            str(authorized_by_id) if authorized_by_id is not None else None
        ),
        "authority_principal": job.origin_principal_snapshot,
        "outcome": outcome,
        "claimed_at": job.claimed_at.isoformat(),
        "effect_started_at": (
            job.effect_started_at.isoformat() if job.effect_started_at else None
        ),
        "completed_at": completed_at.isoformat(),
        "result_digest": result_digest,
        "signing_key_id": signing_key_id,
    }
    return IntegrationSyncAttempt.objects.create(
        attempt_id=job.attempt_id,
        job_id_snapshot=job.id,
        request_digest_snapshot=job.request_digest,
        authorized_by_id_snapshot=authorized_by_id,
        authority_principal_snapshot=job.origin_principal_snapshot,
        outcome=outcome,
        claimed_at=job.claimed_at,
        effect_started_at=job.effect_started_at,
        completed_at=completed_at,
        result_digest=result_digest,
        attempt_hmac_sha256=authority_hmac(
            envelope,
            domain="integration-sync-attempt-v1",
            signing_key_id=signing_key_id,
        ),
        signing_key_id=signing_key_id,
        created_at=completed_at,
    )


def _set_terminal_locked(
    job: IntegrationSyncJob,
    *,
    status: str,
    failure_code: str = "",
    result_digest: str = "",
) -> None:
    job.status = status
    job.failure_code = failure_code
    job.terminal_at = timezone.now()
    update_fields = ["status", "failure_code", "terminal_at", "updated_at"]
    if status not in {
        IntegrationSyncJob.Status.UNCERTAIN,
        IntegrationSyncJob.Status.REVIEW_REQUIRED,
    }:
        job.payload = {}
        update_fields.append("payload")
    job.save(update_fields=update_fields)
    _append_sync_attempt(
        job,
        outcome=status,
        completed_at=job.terminal_at,
        result_digest=result_digest,
    )


def _finish_job(
    job: IntegrationSyncJob,
    *,
    status: str,
    failure_code: str,
) -> None:
    with transaction.atomic():
        locked_job = (
            IntegrationSyncJob.objects.select_for_update(of=("self",))
            .filter(
                id=job.id,
                status=IntegrationSyncJob.Status.PROCESSING,
                attempt_id=job.attempt_id,
            )
            .first()
        )
        if locked_job is None:
            return
        _set_terminal_locked(
            locked_job,
            status=status,
            failure_code=failure_code,
        )


def _record_sync_event(
    *,
    job: IntegrationSyncJob,
    mapping: SyncMapping,
    direction: str,
    changed_fields: list[str],
    triggered_by: str,
) -> None:
    SyncEvent.objects.create(
        mapping=mapping,
        mapping_id_snapshot=mapping.id,
        configuration_id_snapshot=mapping.configuration_id,
        content_type_id_snapshot=mapping.content_type_id,
        local_object_id_snapshot=mapping.local_object_id,
        remote_id_snapshot=mapping.remote_id,
        job_id_snapshot=job.id,
        request_digest_snapshot=job.request_digest,
        actor_id_snapshot=job.requested_by_id_snapshot,
        direction=direction,
        changes={"fields": changed_fields},
        triggered_by=triggered_by,
        success=True,
    )


def _has_reconciliation_event_authority(job: IntegrationSyncJob) -> bool:
    """Recognize exact corrective provenance on an already verified job.

    The only caller runs after ``_lock_claimed_graph`` has authenticated the
    complete capability and request digest.  This additional shape check keeps
    malformed or merely user-labelled outbound jobs from being attributed to a
    governed reconciliation decision.
    """

    capability = job.capability
    if not isinstance(capability, dict):
        return False
    authority = capability.get("reconciliation_authority")
    expected_keys = {
        "schema",
        "decision_id",
        "source_job_id",
        "source_request_digest",
        "action",
        "checker_id",
        "sequence",
        "total",
    }
    if not isinstance(authority, dict) or set(authority) != expected_keys:
        return False

    requested_by_id = job.requested_by_id_snapshot
    checker_id = str(requested_by_id) if requested_by_id is not None else None
    sequence = authority.get("sequence")
    total = authority.get("total")
    source_digest = authority.get("source_request_digest")
    if (
        authority.get("schema") != "integration-reconciliation-corrective-v1"
        or authority.get("action") != "keep_local"
        or authority.get("checker_id") != checker_id
        or job.origin_principal_snapshot != f"user:{checker_id}"
        or type(sequence) is not int
        or type(total) is not int
        or sequence < 1
        or total < 1
        or sequence > total
        or not isinstance(source_digest, str)
        or len(source_digest) != 64
        or any(character not in "0123456789abcdef" for character in source_digest)
    ):
        return False
    try:
        return all(
            str(UUID(str(authority[field]))) == authority[field]
            for field in ("decision_id", "source_job_id", "checker_id")
        )
    except (AttributeError, TypeError, ValueError):
        return False


def _sync_event_triggered_by(job: IntegrationSyncJob) -> str:
    """Classify one successful durable effect by its authenticated origin."""

    if job.direction == IntegrationSyncJob.Direction.INCOMING:
        return SyncEvent.TriggeredBy.WEBHOOK
    if _has_reconciliation_event_authority(job):
        return SyncEvent.TriggeredBy.RECONCILIATION
    if job.requested_by_id_snapshot is not None:
        return SyncEvent.TriggeredBy.USER
    return SyncEvent.TriggeredBy.SCHEDULED


def _rebase_next_job(
    *,
    completed_job: IntegrationSyncJob,
    configuration: IntegrationConfiguration,
    provider: IntegrationProvider,
    mapping: SyncMapping,
    local_object,
) -> Any | None:
    """Advance exactly one FIFO successor, regardless of its direction."""

    later = Q(created_at__gt=completed_job.created_at) | Q(
        created_at=completed_job.created_at, id__gt=completed_job.id
    )
    next_job = (
        IntegrationSyncJob.objects.select_for_update(of=("self",))
        .filter(
            later,
            mapping_id_snapshot=completed_job.mapping_id_snapshot,
            status=IntegrationSyncJob.Status.QUEUED,
        )
        .order_by("created_at", "id")
        .first()
    )
    if next_job is None or not isinstance(next_job.capability, dict):
        return None
    capability = dict(next_job.capability)
    try:
        signing_key_id = _capability_signing_key_id(capability)
    except StaleIntegrationAuthority:
        return None
    original_digest = sync_job_request_digest(
        direction=next_job.direction,
        capability=capability,
        changed_fields=next_job.changed_fields,
        event_type=next_job.event_type,
        payload_hmac_sha256=next_job.payload_hmac_sha256,
    )
    try:
        stable_authority = bool(
            original_digest == next_job.request_digest
            and next_job.payload_hmac_sha256
            == integration_payload_hmac(next_job.payload, signing_key_id=signing_key_id)
            and capability.get("payload_hmac_sha256") == next_job.payload_hmac_sha256
            and capability.get("configuration_id") == str(configuration.id)
            and capability.get("configuration_hmac_sha256")
            == configuration_authority_hmac(
                configuration, signing_key_id=signing_key_id
            )
            and capability.get("provider_id") == str(provider.id)
            and capability.get("provider_hmac_sha256")
            == model_row_authority_hmac(provider, signing_key_id=signing_key_id)
            and capability.get("mapping_id") == str(mapping.id)
            and capability.get("content_type_id") == mapping.content_type_id
            and capability.get("object_id") == str(local_object.pk)
            and capability.get("folder_id") == str(local_object.folder_id)
        )
    except IntegrationSigningKeyUnavailable:
        return None
    if next_job.direction == IntegrationSyncJob.Direction.INCOMING:
        registered_provider = IntegrationRegistry.get_provider(provider.name)
        if registered_provider is None:
            raise DeterministicIntegrationFailure("provider_contract_unavailable")
        orchestrator = registered_provider.create_orchestrator(configuration)
        capability_remote_version = parse_datetime(
            str(capability.get("remote_version", ""))
        )
        payload_remote_version_raw = orchestrator.extract_webhook_remote_version(
            next_job.payload
        )
        payload_remote_version = (
            parse_datetime(payload_remote_version_raw)
            if isinstance(payload_remote_version_raw, str)
            else None
        )
        if capability_remote_version is not None and timezone.is_naive(
            capability_remote_version
        ):
            capability_remote_version = timezone.make_aware(capability_remote_version)
        if payload_remote_version is not None and timezone.is_naive(
            payload_remote_version
        ):
            payload_remote_version = timezone.make_aware(payload_remote_version)
        stable_authority = stable_authority and bool(
            capability.get("remote_id") == mapping.remote_id
            and capability.get("event_type") == next_job.event_type
            and next_job.remote_version is not None
            and capability_remote_version == next_job.remote_version
            and payload_remote_version == next_job.remote_version
        )
    if not stable_authority:
        return None

    cached_remote_version = None
    if next_job.direction == IntegrationSyncJob.Direction.INCOMING:
        cached_remote_version = orchestrator.extract_remote_snapshot_version(
            mapping.remote_data
        )
    if (
        cached_remote_version is not None
        and next_job.remote_version is not None
        and next_job.remote_version < cached_remote_version
    ):
        _set_terminal_locked(
            next_job,
            status=IntegrationSyncJob.Status.SUPERSEDED,
            failure_code="stale_remote_version",
        )
        return _rebase_next_job(
            completed_job=next_job,
            configuration=configuration,
            provider=provider,
            mapping=mapping,
            local_object=local_object,
        )

    capability.update(
        {
            "mapping_version": mapping.version,
            "mapping_payload_hmac_sha256": mapping_payload_authority_hmac(
                mapping, signing_key_id=signing_key_id
            ),
            "object_hmac_sha256": model_row_authority_hmac(
                local_object, signing_key_id=signing_key_id
            ),
            "folder_lineage_hmac_sha256": folder_lineage_authority_hmac(
                local_object.folder, signing_key_id=signing_key_id
            ),
            "folder_lineage_ids": [
                str(item.id)
                for item in local_object.folder.get_parent_folders(include_self=True)
            ],
        }
    )
    if next_job.direction == IntegrationSyncJob.Direction.OUTBOUND:
        capability["operation_kind"] = (
            "refresh_existing"
            if capability.get("request_intent") == "refresh_existing"
            else ("update" if mapping.remote_id else "create")
        )
        capability["mapping_remote_id"] = mapping.remote_id
    elif (
        cached_remote_version is not None
        and next_job.remote_version == cached_remote_version
    ):
        try:
            incoming_remote_data = orchestrator.project_remote_snapshot(
                model_key=(
                    model_key_for_content_type(mapping.content_type)
                    or orchestrator.DEFAULT_MODEL_KEY
                ),
                remote_data=orchestrator._extract_remote_data(next_job.payload),
            )
        except (TypeError, ValueError):
            incoming_remote_data = None
        if incoming_remote_data == mapping.remote_data:
            _set_terminal_locked(
                next_job,
                status=IntegrationSyncJob.Status.SUPERSEDED,
                failure_code="duplicate_remote_version",
            )
            return _rebase_next_job(
                completed_job=next_job,
                configuration=configuration,
                provider=provider,
                mapping=mapping,
                local_object=local_object,
            )
        next_job.capability = capability
        next_job.save(update_fields=["capability", "updated_at"])
        mapping.sync_status = SyncMapping.SyncStatus.CONFLICT
        mapping.error_message = "Incoming change requires governed conflict review"
        mapping.version += 1
        mapping.save()
        next_job.review_state_signing_key_id = signing_key_id
        next_job.review_state_hmac_sha256 = integration_review_state_hmac(
            job_id=next_job.id,
            request_digest=next_job.request_digest,
            mapping=mapping,
            signing_key_id=signing_key_id,
        )
        next_job.save(
            update_fields=[
                "review_state_hmac_sha256",
                "review_state_signing_key_id",
                "updated_at",
            ]
        )
        _set_terminal_locked(
            next_job,
            status=IntegrationSyncJob.Status.REVIEW_REQUIRED,
            failure_code="ambiguous_remote_version",
        )
        return next_job.id
    if (
        sync_job_request_digest(
            direction=next_job.direction,
            capability=capability,
            changed_fields=next_job.changed_fields,
            event_type=next_job.event_type,
            payload_hmac_sha256=next_job.payload_hmac_sha256,
        )
        != next_job.request_digest
    ):
        return None
    next_job.capability = capability
    next_job.save(update_fields=["capability", "updated_at"])
    transaction.on_commit(
        lambda job_id=next_job.id: enqueue_integration_sync_jobs((job_id,)),
        robust=True,
    )
    return next_job.id


def _finalize_external_success(
    *,
    job: IntegrationSyncJob,
    remote_id: str,
    remote_data: dict[str, Any],
) -> str:
    with transaction.atomic():
        (
            locked_job,
            configuration,
            provider,
            mapping,
            local_object,
            content_type,
        ) = _lock_claimed_graph(
            job_id=job.id,
            attempt_id=job.attempt_id,
            direction=job.direction,
            require_current_authority=False,
        )
        try:
            canonical_remote_id = normalize_remote_id(provider.name, remote_id)
            current_remote_id = normalize_remote_id(
                provider.name, mapping.remote_id, allow_blank=True
            )
        except InvalidRemoteIdentifier as exc:
            raise DeterministicIntegrationFailure(
                "provider_returned_invalid_remote_id"
            ) from exc
        if current_remote_id and canonical_remote_id != current_remote_id:
            raise DeterministicIntegrationFailure(
                "provider_changed_remote_object_identity"
            )
        model_key = model_key_for_content_type(content_type)
        if model_key is None:
            raise DeterministicIntegrationFailure("unsupported_sync_model")
        registered_provider = IntegrationRegistry.get_provider(provider.name)
        if registered_provider is None:
            raise DeterministicIntegrationFailure("provider_contract_unavailable")
        orchestrator = registered_provider.create_orchestrator(configuration)
        try:
            remote_data = orchestrator.validate_remote_snapshot(
                model_key=model_key,
                remote_id=canonical_remote_id,
                remote_data=remote_data,
            )
        except (InvalidRemoteIdentifier, TypeError, ValueError) as exc:
            raise DeterministicIntegrationFailure(
                "provider_returned_unverified_snapshot"
            ) from exc
        previous_remote_version = orchestrator.extract_remote_snapshot_version(
            mapping.remote_data
        )
        observed_remote_version = orchestrator.extract_remote_snapshot_version(
            remote_data
        )
        if (
            previous_remote_version is not None
            and observed_remote_version is not None
            and observed_remote_version < previous_remote_version
        ):
            raise DeterministicIntegrationFailure("provider_returned_stale_snapshot")
        observed_at = timezone.now()
        mapping.remote_id = canonical_remote_id
        mapping.remote_data = remote_data
        mapping.sync_status = SyncMapping.SyncStatus.SYNCED
        mapping.last_sync_direction = SyncMapping.SyncDirection.PUSH
        mapping.last_synced_at = observed_at
        mapping.error_message = ""
        mapping.version += 1
        mapping.save()
        _record_sync_event(
            job=locked_job,
            mapping=mapping,
            direction=SyncMapping.SyncDirection.PUSH,
            changed_fields=list(locked_job.changed_fields),
            triggered_by=_sync_event_triggered_by(locked_job),
        )
        receipt_key_id = _capability_signing_key_id(locked_job.capability)
        remote_data_sha256 = canonical_sha256(remote_data)
        normalized_receipt = {
            "schema_version": "provider-receipt-v1",
            "provider_id": str(provider.id),
            "provider_event_id": f"worker-attempt:{locked_job.attempt_id}",
            "request_digest": locked_job.request_digest,
            "remote_id": canonical_remote_id,
            "outcome": "applied",
            "observed_at": observed_at.isoformat(),
            "evidence_reference": "durable-worker-provider-readback",
            "remote_data_sha256": remote_data_sha256,
        }
        locked_job.provider_receipt_hmac_sha256 = authority_hmac(
            normalized_receipt,
            domain="integration-provider-receipt-v1",
            signing_key_id=receipt_key_id,
        )
        locked_job.provider_receipt_signing_key_id = receipt_key_id
        locked_job.save(
            update_fields=[
                "provider_receipt_hmac_sha256",
                "provider_receipt_signing_key_id",
                "updated_at",
            ]
        )
        _set_terminal_locked(
            locked_job,
            status=IntegrationSyncJob.Status.SUCCEEDED,
            result_digest=remote_data_sha256,
        )
        _rebase_next_job(
            completed_job=locked_job,
            configuration=configuration,
            provider=provider,
            mapping=mapping,
            local_object=local_object,
        )
    return "succeeded"


def _run_external_plan(
    *,
    job: IntegrationSyncJob,
    orchestrator,
    model_key: str,
    operation_kind: str,
    remote_id: str,
    payload: dict[str, Any],
) -> str:
    try:
        result_remote_id, remote_data = orchestrator.execute_outbound_payload(
            model_key=model_key,
            operation_kind=operation_kind,
            remote_id=remote_id,
            payload=payload,
            operation_id=job.request_digest,
        )
        return _finalize_external_success(
            job=job,
            remote_id=result_remote_id,
            remote_data=remote_data,
        )
    except Exception as exc:
        if operation_kind == "refresh_existing":
            _finish_job(
                job,
                status=IntegrationSyncJob.Status.FAILED,
                failure_code="provider_read_failed",
            )
            logger.warning(
                "integration_sync_remote_refresh_failed",
                job_id=str(job.id),
                error_type=type(exc).__name__,
            )
            return "failed"
        _finish_job(
            job,
            status=IntegrationSyncJob.Status.UNCERTAIN,
            failure_code="provider_result_uncertain",
        )
        logger.error(
            "integration_sync_external_result_uncertain",
            job_id=str(job.id),
            direction=job.direction,
            error_type=type(exc).__name__,
            exc_info=True,
        )
        return "uncertain"


def _run_outbound_job(job_id: Any) -> str:
    job = _claim_job(job_id, direction=IntegrationSyncJob.Direction.OUTBOUND)
    if job is None:
        return "noop"
    try:
        with transaction.atomic():
            (
                locked_job,
                configuration,
                _provider,
                mapping,
                _local_object,
                content_type,
            ) = _lock_claimed_graph(
                job_id=job.id,
                attempt_id=job.attempt_id,
                direction=job.direction,
                require_current_authority=True,
            )
            model_key = model_key_for_content_type(content_type)
            if model_key is None:
                raise DeterministicIntegrationFailure
            orchestrator = IntegrationRegistry.get_orchestrator(configuration)
            operation_kind = locked_job.capability["operation_kind"]
            remote_id = mapping.remote_id
            payload = dict(locked_job.payload)
            if operation_kind != "refresh_existing":
                _authorize_effect_locked(locked_job)
    except StaleIntegrationAuthority:
        _finish_job(
            job,
            status=IntegrationSyncJob.Status.SUPERSEDED,
            failure_code="authority_changed",
        )
        return "superseded"
    except IntegrationSigningKeyUnavailable:
        _finish_job(
            job,
            status=IntegrationSyncJob.Status.REVIEW_REQUIRED,
            failure_code="signing_key_unavailable",
        )
        return "review_required"
    except Exception as exc:
        _finish_job(
            job,
            status=IntegrationSyncJob.Status.FAILED,
            failure_code="worker_setup_failed",
        )
        logger.error(
            "integration_sync_outbound_setup_failed",
            job_id=str(job.id),
            error_type=type(exc).__name__,
            exc_info=True,
        )
        return "failed"
    return _run_external_plan(
        job=job,
        orchestrator=orchestrator,
        model_key=model_key,
        operation_kind=operation_kind,
        remote_id=remote_id,
        payload=payload,
    )


def _apply_incoming_plan_locked(
    *,
    job: IntegrationSyncJob,
    configuration: IntegrationConfiguration,
    provider: IntegrationProvider,
    mapping: SyncMapping,
    local_object,
    orchestrator,
    plan: dict[str, Any],
) -> str:
    action = plan.get("action")
    if action == "invalid":
        raise DeterministicIntegrationFailure(plan.get("reason", "invalid_event"))
    if action == "review":
        mapping.sync_status = SyncMapping.SyncStatus.CONFLICT
        mapping.error_message = "Incoming change requires governed conflict review"
        mapping.version += 1
        mapping.save()
        review_key_id = _capability_signing_key_id(job.capability)
        job.review_state_hmac_sha256 = integration_review_state_hmac(
            job_id=job.id,
            request_digest=job.request_digest,
            mapping=mapping,
            signing_key_id=review_key_id,
        )
        job.review_state_signing_key_id = review_key_id
        job.save(
            update_fields=[
                "review_state_hmac_sha256",
                "review_state_signing_key_id",
                "updated_at",
            ]
        )
        _set_terminal_locked(
            job,
            status=IntegrationSyncJob.Status.REVIEW_REQUIRED,
            failure_code=str(plan.get("reason", "manual_conflict")),
        )
        return "review_required"
    if action == "ignore":
        _set_terminal_locked(job, status=IntegrationSyncJob.Status.SUCCEEDED)
        _rebase_next_job(
            completed_job=job,
            configuration=configuration,
            provider=provider,
            mapping=mapping,
            local_object=local_object,
        )
        return "succeeded"
    if action == "delete":
        if job.remote_version is None:
            raise DeterministicIntegrationFailure("missing_delete_remote_version")
        # Retain a privacy-minimal version tombstone.  A terminal delete job is
        # intentionally absent from the active-job scan used while minting a
        # later webhook, so the mapping cache must carry the accepted delete
        # watermark or a delayed pre-delete update could resurrect stale state.
        mapping.remote_data = {
            "key": mapping.remote_id,
            "updated": job.remote_version.isoformat(),
            "fields": {},
        }
        mapping.sync_status = SyncMapping.SyncStatus.FAILED
        mapping.error_message = "Remote object was deleted"
        mapping.last_sync_direction = SyncMapping.SyncDirection.PULL
        mapping.last_synced_at = timezone.now()
        mapping.version += 1
        mapping.save()
        changed_fields: list[str] = []
    elif action == "apply_remote":
        mapper = orchestrator.mapper_for(
            model_key_for_content_type(mapping.content_type)
            or orchestrator.DEFAULT_MODEL_KEY
        )
        changed_fields = apply_inbound_update(
            local_object=local_object,
            local_data=plan["local_data"],
            mapper=mapper,
        )
        mapping.sync_status = SyncMapping.SyncStatus.SYNCED
        mapping.last_sync_direction = SyncMapping.SyncDirection.PULL
        mapping.last_synced_at = timezone.now()
        mapping.remote_data = plan["remote_data"]
        mapping.error_message = ""
        mapping.version += 1
        mapping.save()
    else:
        raise DeterministicIntegrationFailure("unsupported_incoming_action")

    _record_sync_event(
        job=job,
        mapping=mapping,
        direction=SyncMapping.SyncDirection.PULL,
        changed_fields=changed_fields,
        triggered_by=SyncEvent.TriggeredBy.WEBHOOK,
    )
    _set_terminal_locked(job, status=IntegrationSyncJob.Status.SUCCEEDED)
    _rebase_next_job(
        completed_job=job,
        configuration=configuration,
        provider=provider,
        mapping=mapping,
        local_object=local_object,
    )
    return "succeeded"


def _run_incoming_job(job_id: Any) -> str:
    job = _claim_job(job_id, direction=IntegrationSyncJob.Direction.INCOMING)
    if job is None:
        return "noop"
    try:
        with transaction.atomic():
            (
                locked_job,
                configuration,
                provider,
                mapping,
                local_object,
                content_type,
            ) = _lock_claimed_graph(
                job_id=job.id,
                attempt_id=job.attempt_id,
                direction=job.direction,
                require_current_authority=True,
            )
            orchestrator = IntegrationRegistry.get_orchestrator(configuration)
            if locked_job.capability.get("remote_version_ambiguous"):
                plan = {
                    "action": "review",
                    "reason": "ambiguous_remote_version",
                }
            else:
                plan = orchestrator.prepare_incoming_event(
                    event_type=locked_job.event_type,
                    payload=dict(locked_job.payload),
                    mapping=mapping,
                    local_object=local_object,
                )
            if plan.get("action") != "push_local":
                return _apply_incoming_plan_locked(
                    job=locked_job,
                    configuration=configuration,
                    provider=provider,
                    mapping=mapping,
                    local_object=local_object,
                    orchestrator=orchestrator,
                    plan=plan,
                )
            model_key = model_key_for_content_type(content_type)
            if model_key is None:
                raise DeterministicIntegrationFailure
            remote_id = mapping.remote_id
            outbound_payload = dict(plan["remote_payload"])
            _authorize_effect_locked(locked_job)
    except StaleIntegrationAuthority:
        _finish_job(
            job,
            status=IntegrationSyncJob.Status.SUPERSEDED,
            failure_code="authority_changed",
        )
        return "superseded"
    except IntegrationSigningKeyUnavailable:
        _finish_job(
            job,
            status=IntegrationSyncJob.Status.REVIEW_REQUIRED,
            failure_code="signing_key_unavailable",
        )
        return "review_required"
    except (DeterministicIntegrationFailure, InboundCommandRejected) as exc:
        _finish_job(
            job,
            status=IntegrationSyncJob.Status.FAILED,
            failure_code="incoming_command_rejected",
        )
        logger.warning(
            "integration_sync_incoming_rejected",
            job_id=str(job.id),
            error_type=type(exc).__name__,
        )
        return "failed"
    except Exception as exc:
        _finish_job(
            job,
            status=IntegrationSyncJob.Status.FAILED,
            failure_code="worker_setup_failed",
        )
        logger.error(
            "integration_sync_incoming_setup_failed",
            job_id=str(job.id),
            error_type=type(exc).__name__,
            exc_info=True,
        )
        return "failed"

    return _run_external_plan(
        job=job,
        orchestrator=orchestrator,
        model_key=model_key,
        operation_kind="update",
        remote_id=remote_id,
        payload=outbound_payload,
    )


@task()
def sync_object_to_integrations(job_id: Any, *legacy_args):
    """Run one durable outbound job; old naked-ID jobs fail closed."""

    if legacy_args:
        logger.warning("Skipping legacy outbound integration job")
        return "noop"
    return _run_outbound_job(job_id)


@task()
@lock_task("warm-integration-schema")
def warm_integration_schema_cache():
    """Warm remote schema caches without failing the worker startup."""

    configs = IntegrationConfiguration.objects.filter(
        is_active=True, provider__provider_type="itsm"
    )
    for config in configs:
        try:
            orchestrator = IntegrationRegistry.get_orchestrator(config)
            orchestrator.refresh_schema(force=False)
            logger.info("Warmed integration schema cache", config_id=str(config.id))
        except Exception as exc:
            logger.error(
                "Failed to warm integration schema cache",
                config_id=str(config.id),
                error_type=type(exc).__name__,
                exc_info=True,
            )


@HUEY.on_startup()
def _enqueue_schema_cache_warmup():
    try:
        warm_integration_schema_cache()
    except Exception as exc:
        logger.error(
            "Failed to enqueue integration schema cache warmup",
            error_type=type(exc).__name__,
            exc_info=True,
        )


@db_periodic_task(crontab(minute="*/5"))
def sweep_integration_sync_jobs():
    """Recover safe claims and fairly redeliver only unblocked FIFO heads."""

    now = timezone.now()
    stale_before = now - CLAIM_TIMEOUT
    safely_requeued = 0
    uncertain = 0
    with transaction.atomic():
        stale_jobs = list(
            IntegrationSyncJob.objects.select_for_update(skip_locked=True)
            .filter(
                status=IntegrationSyncJob.Status.PROCESSING,
                claimed_at__lt=stale_before,
            )
            .order_by("claimed_at", "id")[:500]
        )
        for stale_job in stale_jobs:
            if stale_job.effect_started_at is None:
                _append_sync_attempt(
                    stale_job,
                    outcome="recovered_before_effect",
                    completed_at=now,
                )
                stale_job.status = IntegrationSyncJob.Status.QUEUED
                stale_job.attempt_id = None
                stale_job.claimed_at = None
                stale_job.failure_code = "claim_recovered_before_effect"
                stale_job.available_at = now
                stale_job.save(
                    update_fields=[
                        "status",
                        "attempt_id",
                        "claimed_at",
                        "failure_code",
                        "available_at",
                        "updated_at",
                    ]
                )
                safely_requeued += 1
            else:
                stale_job.status = IntegrationSyncJob.Status.UNCERTAIN
                stale_job.failure_code = "effect_completion_unknown"
                stale_job.terminal_at = now
                stale_job.save(
                    update_fields=[
                        "status",
                        "failure_code",
                        "terminal_at",
                        "updated_at",
                    ]
                )
                _append_sync_attempt(
                    stale_job,
                    outcome=IntegrationSyncJob.Status.UNCERTAIN,
                    completed_at=now,
                )
                uncertain += 1

    earlier_blocker = IntegrationSyncJob.objects.filter(
        mapping_id_snapshot=OuterRef("mapping_id_snapshot"),
        status__in=BLOCKING_STATUSES,
    ).filter(
        Q(created_at__lt=OuterRef("created_at"))
        | Q(
            created_at=OuterRef("created_at"),
            id__lt=OuterRef("id"),
        )
    )
    with transaction.atomic():
        due_ids = list(
            IntegrationSyncJob.objects.filter(
                status=IntegrationSyncJob.Status.QUEUED,
                available_at__lte=now,
            )
            .annotate(has_prior_blocker=Exists(earlier_blocker))
            .filter(has_prior_blocker=False)
            .select_for_update(skip_locked=True)
            .order_by(
                F("last_enqueued_at").asc(nulls_first=True),
                "created_at",
                "id",
            )
            .values_list("id", flat=True)[:500]
        )
    if due_ids:
        enqueue_integration_sync_jobs(due_ids)
    if uncertain:
        logger.warning("integration_sync_claims_uncertain", count=uncertain)
    return {
        "enqueued": len(due_ids),
        "safely_requeued": safely_requeued,
        "uncertain": uncertain,
    }


@task()
def process_webhook_event(job_id: Any, *legacy_args):
    """Run one durable incoming job; old payload-bearing jobs fail closed."""

    if legacy_args:
        logger.warning("Skipping legacy webhook integration job")
        return "noop"
    return _run_incoming_job(job_id)
