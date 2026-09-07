"""Governed reconciliation for ambiguous integration side effects."""

from __future__ import annotations

import hmac
from datetime import timedelta
from typing import Any
from uuid import uuid4

from django.contrib.auth.models import Permission
from django.contrib.contenttypes.models import ContentType
from django.core.exceptions import ObjectDoesNotExist
from django.db import IntegrityError, transaction
from django.db.models import Q
from django.utils import timezone
from django.utils.dateparse import parse_datetime
from iam.models import Folder, RoleAssignment, ServiceAccount
from rest_framework.exceptions import PermissionDenied, ValidationError

from integrations.capabilities import (
    CAPABILITY_VERSION,
    IntegrationSigningKeyUnavailable,
    authority_hmac,
    canonical_sha256,
    configuration_authority_hmac,
    enqueue_integration_sync_jobs,
    folder_lineage_authority_hmac,
    folder_lineage_ids,
    integration_payload_hmac,
    integration_review_state_hmac,
    mapping_payload_authority_hmac,
    model_row_authority_hmac,
    persist_outbound_sync_jobs,
    primary_signing_key_id,
    sync_job_request_digest,
)
from integrations.local_commands import InboundCommandRejected, apply_inbound_update
from integrations.models import (
    IntegrationConfiguration,
    IntegrationProvider,
    IntegrationReconciliationDecision,
    IntegrationSyncJob,
    SyncEvent,
    SyncMapping,
)
from integrations.registry import IntegrationRegistry
from integrations.remote_ids import InvalidRemoteIdentifier, normalize_remote_id
from integrations.syncable import model_key_for_content_type

RECONCILABLE_STATUSES = (
    IntegrationSyncJob.Status.UNCERTAIN,
    IntegrationSyncJob.Status.REVIEW_REQUIRED,
)

ACTIVE_SUCCESSOR_STATUSES = (
    IntegrationSyncJob.Status.QUEUED,
    IntegrationSyncJob.Status.PROCESSING,
    IntegrationSyncJob.Status.UNCERTAIN,
    IntegrationSyncJob.Status.REVIEW_REQUIRED,
)
PROVIDER_CLOCK_SKEW = timedelta(minutes=5)


def _deny() -> None:
    raise PermissionDenied("The integration sync job is unavailable.")


def _visible(user, instance) -> bool:
    try:
        ids = RoleAssignment.get_viewable_object_ids(user, type(instance))
    except (NotImplementedError, Permission.DoesNotExist):
        return False
    return type(instance)._base_manager.filter(pk=instance.pk, pk__in=ids).exists()


def _assert_action(user, instance, action: str, *, folder: Folder) -> None:
    model = type(instance)
    try:
        permission = Permission.objects.get(
            content_type=ContentType.objects.get_for_model(
                model, for_concrete_model=False
            ),
            codename=f"{action}_{model._meta.model_name}",
        )
    except Permission.DoesNotExist:
        _deny()
    if not RoleAssignment.is_access_allowed(
        user=user,
        perm=permission,
        folder=folder,
    ):
        _deny()


def _lock_reconciliation_graph(job_id: Any):
    """Lock root→folders→config→provider→mapping→local→job and re-prove it."""

    try:
        preliminary = IntegrationSyncJob.objects.get(
            id=job_id,
            status__in=RECONCILABLE_STATUSES,
        )
    except (ValueError, IntegrationSyncJob.DoesNotExist):
        _deny()

    snapshot = (
        preliminary.status,
        preliminary.configuration_id_snapshot,
        preliminary.provider_id_snapshot,
        preliminary.mapping_id_snapshot,
        preliminary.content_type_id_snapshot,
        preliminary.local_object_id_snapshot,
        preliminary.folder_id_snapshot,
    )
    capability = preliminary.capability
    if not isinstance(capability, dict):
        _deny()
    expected_owner_lineage_ids = {
        str(value) for value in capability.get("folder_lineage_ids", [])
    }
    if not expected_owner_lineage_ids:
        _deny()

    Folder._lock_folder_tree()
    try:
        # Provider ownership is read only to discover folders. No authority is
        # consumed until every discovered lineage row and then the provider are
        # locked and the relation is re-proved below.
        provider_folder_id_snapshot = (
            IntegrationProvider.objects.filter(id=preliminary.provider_id_snapshot)
            .values_list("folder_id", flat=True)
            .get()
        )
        owner_folder_snapshot = Folder.objects.get(id=preliminary.folder_id_snapshot)
        provider_folder_snapshot = Folder.objects.get(id=provider_folder_id_snapshot)
        owner_lineage_ids = {
            str(item.id)
            for item in owner_folder_snapshot.get_parent_folders(include_self=True)
        }
        provider_lineage_ids = {
            str(item.id)
            for item in provider_folder_snapshot.get_parent_folders(include_self=True)
        }
        all_folder_ids = owner_lineage_ids | provider_lineage_ids
        locked_folders = {
            str(folder.id): folder
            for folder in Folder.objects.select_for_update(of=("self",))
            .filter(id__in=all_folder_ids)
            .order_by("id")
        }
        if set(locked_folders) != all_folder_ids:
            _deny()
        owner_folder = locked_folders[str(preliminary.folder_id_snapshot)]
        provider_folder = locked_folders[str(provider_folder_id_snapshot)]
        configuration = IntegrationConfiguration.objects.select_for_update(
            of=("self",)
        ).get(id=preliminary.configuration_id_snapshot)
        provider = IntegrationProvider.objects.select_for_update(of=("self",)).get(
            id=preliminary.provider_id_snapshot
        )
        provider.folder = provider_folder
        mapping = (
            SyncMapping.objects.select_for_update(of=("self",))
            .select_related("content_type")
            .get(id=preliminary.mapping_id_snapshot)
        )
        content_type = ContentType.objects.get_for_id(
            preliminary.content_type_id_snapshot
        )
        model = content_type.model_class()
        if model is None or model_key_for_content_type(content_type) is None:
            _deny()
        local_object = model._base_manager.select_for_update(of=("self",)).get(
            pk=preliminary.local_object_id_snapshot
        )
        job = IntegrationSyncJob.objects.select_for_update(of=("self",)).get(
            id=preliminary.id,
            status__in=RECONCILABLE_STATUSES,
        )
    except (ObjectDoesNotExist, TypeError, ValueError):
        _deny()

    locked_snapshot = (
        job.status,
        job.configuration_id_snapshot,
        job.provider_id_snapshot,
        job.mapping_id_snapshot,
        job.content_type_id_snapshot,
        job.local_object_id_snapshot,
        job.folder_id_snapshot,
    )
    provider_is_available = bool(
        provider.folder_id == owner_folder.id
        or owner_folder.ancestors.filter(id=provider.folder_id).exists()
    )
    if (
        locked_snapshot != snapshot
        or owner_lineage_ids != expected_owner_lineage_ids
        or str(provider.folder_id) not in provider_lineage_ids
        or str(owner_folder.id) not in owner_lineage_ids
        or configuration.provider_id != provider.id
        or configuration.folder_id != owner_folder.id
        or mapping.configuration_id != configuration.id
        or mapping.content_type_id != content_type.id
        or mapping.local_object_id != local_object.pk
        or mapping.folder_id != owner_folder.id
        or getattr(local_object, "folder_id", None) != owner_folder.id
        or not provider_is_available
    ):
        _deny()
    return job, configuration, provider, mapping, local_object, owner_folder


def _authorize_reconciler(
    *, user, job, configuration, provider, mapping, local_object, owner_folder
) -> None:
    if not getattr(user, "is_authenticated", False):
        _deny()
    user_id = getattr(user, "id", None)
    if user_id is None or ServiceAccount.objects.filter(user_id=user_id).exists():
        raise PermissionDenied("A named human checker is required.")
    if job.requested_by_id_snapshot == user_id or job.origin_principal_snapshot == (
        f"user:{user_id}"
    ):
        raise PermissionDenied("The maker cannot reconcile their own sync job.")
    if IntegrationReconciliationDecision.objects.filter(
        job_id_snapshot=job.id,
        actor_id_snapshot=user_id,
    ).exists():
        raise PermissionDenied(
            "A previous checker cannot authorize another attempt for this sync job."
        )
    for instance in (
        owner_folder,
        provider.folder,
        configuration,
        provider,
        mapping,
        local_object,
    ):
        if not _visible(user, instance):
            _deny()

    try:
        reconcile_permission = Permission.objects.get(
            content_type=ContentType.objects.get_for_model(
                IntegrationSyncJob, for_concrete_model=False
            ),
            codename="reconcile_integrationsyncjob",
        )
    except Permission.DoesNotExist:
        _deny()
    if not RoleAssignment.is_access_allowed(
        user=user,
        perm=reconcile_permission,
        folder=owner_folder,
    ):
        _deny()
    _assert_action(user, configuration, "change", folder=owner_folder)
    _assert_action(user, mapping, "change", folder=owner_folder)
    _assert_action(user, local_object, "change", folder=owner_folder)


def _job_request_is_exact(
    *, job, configuration, provider, mapping, local_object, owner_folder
) -> bool:
    capability = job.capability
    if not isinstance(capability, dict):
        return False
    key_id = capability.get("signing_key_id")
    if not isinstance(key_id, str) or not key_id:
        return False
    return bool(
        capability.get("capability_version") == CAPABILITY_VERSION
        and capability.get("configuration_id") == str(configuration.id)
        and capability.get("provider_id") == str(provider.id)
        and capability.get("mapping_id") == str(mapping.id)
        and capability.get("content_type_id") == mapping.content_type_id
        and capability.get("object_id") == str(local_object.pk)
        and capability.get("folder_id") == str(owner_folder.id)
        and capability.get("origin_principal_snapshot") == job.origin_principal_snapshot
        and capability.get("requested_by_id_snapshot")
        == (
            str(job.requested_by_id_snapshot)
            if job.requested_by_id_snapshot is not None
            else None
        )
        and capability.get("configuration_hmac_sha256")
        == configuration_authority_hmac(configuration, signing_key_id=key_id)
        and capability.get("provider_hmac_sha256")
        == model_row_authority_hmac(provider, signing_key_id=key_id)
        and capability.get("mapping_version") == mapping.version
        and capability.get("mapping_payload_hmac_sha256")
        == mapping_payload_authority_hmac(mapping, signing_key_id=key_id)
        and capability.get("folder_lineage_ids") == folder_lineage_ids(owner_folder)
        and capability.get("folder_lineage_hmac_sha256")
        == folder_lineage_authority_hmac(owner_folder, signing_key_id=key_id)
        and job.payload_hmac_sha256
        == integration_payload_hmac(job.payload, signing_key_id=key_id)
        and capability.get("payload_hmac_sha256") == job.payload_hmac_sha256
        and _job_remote_version_is_exact(job, configuration)
        and job.request_digest
        == sync_job_request_digest(
            direction=job.direction,
            capability=capability,
            changed_fields=job.changed_fields,
            event_type=job.event_type,
            payload_hmac_sha256=job.payload_hmac_sha256,
        )
    )


def _job_remote_version_is_exact(job, configuration) -> bool:
    capability = job.capability
    if job.direction != IntegrationSyncJob.Direction.INCOMING:
        return job.remote_version is None and "remote_version" not in capability
    registered_provider = IntegrationRegistry.get_provider(configuration.provider.name)
    if registered_provider is None or job.remote_version is None:
        return False
    orchestrator = registered_provider.create_orchestrator(configuration)
    capability_version = parse_datetime(str(capability.get("remote_version", "")))
    payload_version_raw = orchestrator.extract_webhook_remote_version(job.payload)
    payload_version = (
        parse_datetime(payload_version_raw)
        if isinstance(payload_version_raw, str)
        else None
    )
    if capability_version is not None and timezone.is_naive(capability_version):
        capability_version = timezone.make_aware(capability_version)
    if payload_version is not None and timezone.is_naive(payload_version):
        payload_version = timezone.make_aware(payload_version)
    return bool(
        isinstance(capability.get("remote_version_ambiguous"), bool)
        and capability_version == job.remote_version
        and payload_version == job.remote_version
    )


def _review_state_is_exact(
    *, job, configuration, provider, mapping, local_object, owner_folder
) -> bool:
    capability = job.capability
    if not isinstance(capability, dict):
        return False
    key_id = capability.get("signing_key_id")
    source_mapping_version = capability.get("mapping_version")
    if (
        not isinstance(key_id, str)
        or not key_id
        or not isinstance(source_mapping_version, int)
    ):
        return False
    return bool(
        job.status == IntegrationSyncJob.Status.REVIEW_REQUIRED
        and job.direction == IntegrationSyncJob.Direction.INCOMING
        and capability.get("capability_version") == CAPABILITY_VERSION
        and capability.get("configuration_id") == str(configuration.id)
        and capability.get("provider_id") == str(provider.id)
        and capability.get("mapping_id") == str(mapping.id)
        and capability.get("content_type_id") == mapping.content_type_id
        and capability.get("object_id") == str(local_object.pk)
        and capability.get("folder_id") == str(owner_folder.id)
        and capability.get("origin_principal_snapshot") == job.origin_principal_snapshot
        and capability.get("requested_by_id_snapshot")
        == (
            str(job.requested_by_id_snapshot)
            if job.requested_by_id_snapshot is not None
            else None
        )
        and capability.get("configuration_hmac_sha256")
        == configuration_authority_hmac(configuration, signing_key_id=key_id)
        and capability.get("provider_hmac_sha256")
        == model_row_authority_hmac(provider, signing_key_id=key_id)
        and capability.get("folder_lineage_ids") == folder_lineage_ids(owner_folder)
        and capability.get("folder_lineage_hmac_sha256")
        == folder_lineage_authority_hmac(owner_folder, signing_key_id=key_id)
        and mapping.version == source_mapping_version + 1
        and mapping.sync_status == SyncMapping.SyncStatus.CONFLICT
        and mapping.error_message == "Incoming change requires governed conflict review"
        and job.payload_hmac_sha256
        == integration_payload_hmac(job.payload, signing_key_id=key_id)
        and capability.get("payload_hmac_sha256") == job.payload_hmac_sha256
        and _job_remote_version_is_exact(job, configuration)
        and job.request_digest
        == sync_job_request_digest(
            direction=job.direction,
            capability=capability,
            changed_fields=job.changed_fields,
            event_type=job.event_type,
            payload_hmac_sha256=job.payload_hmac_sha256,
        )
        and job.review_state_signing_key_id == key_id
        and job.review_state_hmac_sha256
        == integration_review_state_hmac(
            job_id=job.id,
            request_digest=job.request_digest,
            mapping=mapping,
            signing_key_id=key_id,
        )
    )


def _state_digest(job, mapping) -> str:
    return canonical_sha256(
        {
            "schema": "integration-reconciliation-state-v1",
            "job_id": str(job.id),
            "job_status": job.status,
            "request_digest": job.request_digest,
            "failure_code": job.failure_code,
            "attempt_id": str(job.attempt_id) if job.attempt_id else None,
            "effect_started_at": (
                job.effect_started_at.isoformat() if job.effect_started_at else None
            ),
            "mapping_id": str(mapping.id),
            "mapping_version": mapping.version,
            "mapping_remote_id": mapping.remote_id,
            "mapping_remote_data_digest": canonical_sha256(mapping.remote_data),
            "mapping_status": mapping.sync_status,
        }
    )


def _validate_provider_receipt(
    *,
    action: str,
    job: IntegrationSyncJob,
    configuration: IntegrationConfiguration,
    provider: IntegrationProvider,
    mapping: SyncMapping,
    receipt: dict[str, Any],
    remote_data: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any], str, str]:
    """Normalize and bind provider evidence to the exact uncertain effect."""

    expected_outcome = {
        "confirm_applied": "applied",
        "confirm_not_applied": "not_applied",
    }[action]
    errors: dict[str, str] = {}
    if receipt["schema_version"] != "provider-receipt-v1":
        errors["schema_version"] = "Unsupported provider receipt schema."
    if str(receipt["provider_id"]) != str(provider.id):
        errors["provider_id"] = "Receipt does not identify this provider."
    if receipt["request_digest"] != job.request_digest:
        errors["request_digest"] = "Receipt does not identify this exact operation."
    if receipt["outcome"] != expected_outcome:
        errors["outcome"] = "Receipt outcome does not match the requested action."

    if expected_outcome == "not_applied":
        if remote_data:
            errors["remote_data_sha256"] = (
                "A not-applied receipt must not supply a remote snapshot."
            )
        projected_remote_data: dict[str, Any] = {}
    else:
        model_key = model_key_for_content_type(mapping.content_type)
        if model_key is None:
            errors["remote_data_sha256"] = "The mapped model is unsupported."
            projected_remote_data = {}
            orchestrator = None
        else:
            orchestrator = IntegrationRegistry.get_orchestrator(configuration)
            try:
                projected_remote_data = orchestrator.project_remote_snapshot(
                    model_key=model_key,
                    remote_data=remote_data,
                )
            except (TypeError, ValueError):
                errors["remote_data_sha256"] = "The remote snapshot is invalid."
                projected_remote_data = {}
            if projected_remote_data != remote_data:
                errors["remote_data_sha256"] = (
                    "The remote snapshot must contain only governed projected fields."
                )

    supplied_remote_data_sha256 = receipt["remote_data_sha256"]
    actual_remote_data_sha256 = canonical_sha256(projected_remote_data)
    if not hmac.compare_digest(supplied_remote_data_sha256, actual_remote_data_sha256):
        errors["remote_data_sha256"] = (
            "Receipt does not match the supplied remote snapshot."
        )

    try:
        receipt_remote_id = normalize_remote_id(
            provider.name,
            receipt["remote_id"],
            allow_blank=True,
        )
        current_remote_id = normalize_remote_id(
            provider.name,
            mapping.remote_id,
            allow_blank=True,
        )
    except InvalidRemoteIdentifier as exc:
        raise ValidationError({"provider_receipt": {"remote_id": str(exc)}}) from exc

    operation_kind = job.capability.get("operation_kind", "update")
    if operation_kind == "update" and receipt_remote_id != current_remote_id:
        errors["remote_id"] = "Receipt does not identify the linked remote object."
    elif operation_kind == "create":
        if expected_outcome == "applied" and not receipt_remote_id:
            errors["remote_id"] = "An applied create must identify the remote object."
        elif expected_outcome == "not_applied" and receipt_remote_id:
            errors["remote_id"] = (
                "A disproven create must record that no remote object was created."
            )
    elif operation_kind not in {"create", "update"}:
        errors["request_digest"] = "The retained operation kind is unsupported."

    if expected_outcome == "applied":
        try:
            snapshot_remote_id = normalize_remote_id(
                provider.name,
                projected_remote_data.get("key"),
            )
        except (InvalidRemoteIdentifier, TypeError):
            errors["remote_data_sha256"] = (
                "The projected snapshot has no valid remote identity."
            )
        else:
            if snapshot_remote_id != receipt_remote_id:
                errors["remote_data_sha256"] = (
                    "The projected snapshot identifies a different remote object."
                )
        snapshot_version = (
            orchestrator.extract_remote_snapshot_version(projected_remote_data)
            if orchestrator is not None
            else None
        )
        if snapshot_version is None:
            errors["remote_data_sha256"] = (
                "The projected snapshot has no valid provider version."
            )
        elif orchestrator is not None:
            current_remote_version = orchestrator.extract_remote_snapshot_version(
                mapping.remote_data
            )
            if (
                current_remote_version is not None
                and snapshot_version < current_remote_version
            ):
                errors["remote_data_sha256"] = (
                    "The projected snapshot is older than the accepted remote state."
                )

    observed_at = receipt["observed_at"]
    now = timezone.now()
    effect_floor = job.effect_started_at or job.claimed_at or job.created_at
    if observed_at > now + PROVIDER_CLOCK_SKEW:
        errors["observed_at"] = "Receipt observation time is in the future."
    elif observed_at < effect_floor - PROVIDER_CLOCK_SKEW:
        errors["observed_at"] = "Receipt predates the provider effect."
    elif expected_outcome == "applied" and snapshot_version is not None:
        if snapshot_version > observed_at + PROVIDER_CLOCK_SKEW:
            errors["observed_at"] = (
                "Receipt observation predates the supplied provider version."
            )

    if errors:
        raise ValidationError({"provider_receipt": errors})

    normalized_receipt = {
        "schema_version": "provider-receipt-v1",
        "provider_id": str(provider.id),
        "provider_event_id": receipt["provider_event_id"],
        "request_digest": job.request_digest,
        "remote_id": receipt_remote_id,
        "outcome": expected_outcome,
        "observed_at": observed_at.isoformat(),
        "evidence_reference": receipt["evidence_reference"],
        "remote_data_sha256": actual_remote_data_sha256,
    }
    receipt_signing_key_id = primary_signing_key_id()
    receipt_hmac = authority_hmac(
        normalized_receipt,
        domain="integration-provider-receipt-v1",
        signing_key_id=receipt_signing_key_id,
    )
    return (
        normalized_receipt,
        projected_remote_data,
        receipt_hmac,
        receipt_signing_key_id,
    )


def _append_reconciliation_decision(
    *,
    decision_id: Any,
    job: IntegrationSyncJob,
    mapping: SyncMapping,
    actor_id: Any,
    action: str,
    reason: str,
    before_digest: str,
    after_digest: str,
    receipt: dict[str, Any] | None,
    receipt_hmac: str,
    receipt_signing_key_id: str,
) -> IntegrationReconciliationDecision:
    """Append a keyed decision record; never rewrite an earlier review."""

    decided_at = timezone.now()
    decision_signing_key_id = primary_signing_key_id()
    receipt = receipt or {}
    decision_payload = {
        "schema": "integration-reconciliation-decision-v1",
        "job_id": str(job.id),
        "mapping_id": str(mapping.id),
        "configuration_id": str(job.configuration_id_snapshot),
        "provider_id": str(job.provider_id_snapshot),
        "content_type_id": job.content_type_id_snapshot,
        "local_object_id": str(job.local_object_id_snapshot),
        "folder_id": str(job.folder_id_snapshot),
        "actor_id": str(actor_id),
        "action": action,
        "reason": reason,
        "request_digest": job.request_digest,
        "before_digest": before_digest,
        "after_digest": after_digest,
        "provider_receipt_hmac_sha256": receipt_hmac,
        "provider_receipt_signing_key_id": receipt_signing_key_id,
        "provider_outcome": receipt.get("outcome", ""),
        "provider_remote_id": receipt.get("remote_id", ""),
        "provider_remote_data_sha256": receipt.get("remote_data_sha256", ""),
        "provider_evidence_reference": receipt.get("evidence_reference", ""),
        "provider_event_id": receipt.get("provider_event_id", ""),
        "provider_observed_at": receipt.get("observed_at"),
        "decided_at": decided_at.isoformat(),
        "decision_signing_key_id": decision_signing_key_id,
    }
    return IntegrationReconciliationDecision.objects.create(
        id=decision_id,
        job_id_snapshot=job.id,
        mapping_id_snapshot=mapping.id,
        configuration_id_snapshot=job.configuration_id_snapshot,
        provider_id_snapshot=job.provider_id_snapshot,
        content_type_id_snapshot=job.content_type_id_snapshot,
        local_object_id_snapshot=job.local_object_id_snapshot,
        folder_id_snapshot=job.folder_id_snapshot,
        actor_id_snapshot=actor_id,
        action=action,
        reason=reason,
        request_digest_snapshot=job.request_digest,
        before_digest=before_digest,
        after_digest=after_digest,
        provider_outcome=receipt.get("outcome", ""),
        provider_remote_id_snapshot=receipt.get("remote_id", ""),
        provider_remote_data_sha256=receipt.get("remote_data_sha256", ""),
        provider_evidence_reference=receipt.get("evidence_reference", ""),
        provider_event_id=receipt.get("provider_event_id", ""),
        provider_observed_at=receipt.get("observed_at") or None,
        provider_receipt_hmac_sha256=receipt_hmac,
        provider_receipt_signing_key_id=receipt_signing_key_id,
        decision_hmac_sha256=authority_hmac(
            decision_payload,
            domain="integration-reconciliation-decision-v1",
            signing_key_id=decision_signing_key_id,
        ),
        decision_signing_key_id=decision_signing_key_id,
        decided_at=decided_at,
    )


def _record_reconciliation_event(
    *,
    job,
    mapping,
    actor_id,
    action: str,
    success: bool,
    changed_fields: list[str] | None = None,
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
        actor_id_snapshot=actor_id,
        direction=(
            SyncMapping.SyncDirection.PULL
            if job.direction == IntegrationSyncJob.Direction.INCOMING
            else SyncMapping.SyncDirection.PUSH
        ),
        changes={
            "reconciliation_action": action,
            "request_digest": job.request_digest,
            "fields": list(
                job.changed_fields if changed_fields is None else changed_fields
            ),
        },
        triggered_by=SyncEvent.TriggeredBy.RECONCILIATION,
        success=success,
        error_details=(
            ""
            if success
            else "Provider evidence confirms the operation was not applied"
        ),
    )


def _advance_successor(*, job, configuration, provider, mapping, local_object) -> None:
    # Reuse the worker's authenticated FIFO rebase; this function runs while
    # the same graph and job row are locked in the canonical order.
    from integrations.tasks import _rebase_next_job

    _rebase_next_job(
        completed_job=job,
        configuration=configuration,
        provider=provider,
        mapping=mapping,
        local_object=local_object,
    )


def reconcile_sync_job(*, job_id: Any, user, validated_data: dict[str, Any]) -> dict:
    """Apply one audited human decision to an ambiguous durable operation."""

    action = validated_data["action"]
    reason = validated_data["reason"].strip()
    decision_id = uuid4()
    with transaction.atomic():
        (
            job,
            configuration,
            provider,
            mapping,
            local_object,
            owner_folder,
        ) = _lock_reconciliation_graph(job_id)
        _authorize_reconciler(
            user=user,
            job=job,
            configuration=configuration,
            provider=provider,
            mapping=mapping,
            local_object=local_object,
            owner_folder=owner_folder,
        )
        before_digest = _state_digest(job, mapping)

        receipt: dict[str, Any] | None = None
        receipt_hmac = ""
        receipt_signing_key_id = ""

        if action in {
            "confirm_applied",
            "confirm_not_applied",
            "retry_same_operation",
            "requeue_after_key_restore",
        }:
            try:
                request_is_exact = _job_request_is_exact(
                    job=job,
                    configuration=configuration,
                    provider=provider,
                    mapping=mapping,
                    local_object=local_object,
                    owner_folder=owner_folder,
                )
            except IntegrationSigningKeyUnavailable as exc:
                raise ValidationError(
                    {
                        "action": (
                            "Restore the job's signing key before resolving or "
                            "requeueing the effect."
                        )
                    }
                ) from exc
            if not request_is_exact:
                raise ValidationError(
                    {"action": "The signed job authority no longer matches."}
                )
        if action in {"accept_remote", "keep_local"}:
            try:
                review_state_is_exact = _review_state_is_exact(
                    job=job,
                    configuration=configuration,
                    provider=provider,
                    mapping=mapping,
                    local_object=local_object,
                    owner_folder=owner_folder,
                )
            except IntegrationSigningKeyUnavailable as exc:
                raise ValidationError(
                    {
                        "action": (
                            "Restore the job's signing key before resolving the "
                            "review state."
                        )
                    }
                ) from exc
            if not review_state_is_exact:
                raise ValidationError(
                    {"action": "The signed review state no longer matches."}
                )

        if action in {"confirm_applied", "confirm_not_applied"}:
            if job.status != IntegrationSyncJob.Status.UNCERTAIN:
                raise ValidationError(
                    {"action": "Only an uncertain provider effect can be resolved."}
                )
            (
                receipt,
                projected_remote_data,
                receipt_hmac,
                receipt_signing_key_id,
            ) = _validate_provider_receipt(
                action=action,
                job=job,
                configuration=configuration,
                provider=provider,
                mapping=mapping,
                receipt=validated_data["provider_receipt"],
                remote_data=validated_data["remote_data"],
            )

        if action == "confirm_applied":
            confirmed_remote_id = receipt["remote_id"]

            mapping.remote_id = confirmed_remote_id
            mapping.remote_data = projected_remote_data
            mapping.sync_status = SyncMapping.SyncStatus.SYNCED
            mapping.last_sync_direction = SyncMapping.SyncDirection.PUSH
            mapping.last_synced_at = timezone.now()
            mapping.error_message = ""
            mapping.version += 1
            try:
                with transaction.atomic():
                    mapping.save()
            except IntegrityError as exc:
                raise ValidationError(
                    {"remote_id": "The confirmed remote object is already linked."}
                ) from exc
            _record_reconciliation_event(
                job=job,
                mapping=mapping,
                actor_id=user.id,
                action=action,
                success=True,
            )
            job.status = IntegrationSyncJob.Status.SUCCEEDED
            job.failure_code = ""
            job.payload = {}
            job.terminal_at = timezone.now()
            job.provider_receipt_hmac_sha256 = receipt_hmac
            job.provider_receipt_signing_key_id = receipt_signing_key_id
        elif action == "confirm_not_applied":
            mapping.sync_status = SyncMapping.SyncStatus.FAILED
            mapping.error_message = (
                "Provider evidence confirms the operation was not applied"
            )
            mapping.version += 1
            mapping.save()
            job.status = IntegrationSyncJob.Status.FAILED
            job.failure_code = "reconciled_confirmed_not_applied"
            job.payload = {}
            job.terminal_at = timezone.now()
            job.provider_receipt_hmac_sha256 = receipt_hmac
            job.provider_receipt_signing_key_id = receipt_signing_key_id
            _record_reconciliation_event(
                job=job,
                mapping=mapping,
                actor_id=user.id,
                action=action,
                success=False,
            )
        elif action == "retry_same_operation":
            if job.status != IntegrationSyncJob.Status.UNCERTAIN:
                raise ValidationError(
                    {"action": "Only an uncertain provider effect can be retried."}
                )
            orchestrator = IntegrationRegistry.get_orchestrator(configuration)
            if not getattr(orchestrator, "SUPPORTS_IDEMPOTENT_OPERATIONS", False):
                raise ValidationError(
                    {
                        "action": (
                            "This provider cannot prove idempotent retry; confirm or "
                            "disprove the operation instead."
                        )
                    }
                )
            job.status = IntegrationSyncJob.Status.QUEUED
            job.failure_code = "reconciled_retry_same_operation"
            job.attempt_id = None
            job.claimed_at = None
            job.effect_started_at = None
            job.terminal_at = None
            job.available_at = timezone.now()
            job.attempt_authorized_by_id_snapshot = user.id
        elif action == "requeue_after_key_restore":
            if (
                job.status != IntegrationSyncJob.Status.REVIEW_REQUIRED
                or job.failure_code != "signing_key_unavailable"
                or job.effect_started_at is not None
            ):
                raise ValidationError(
                    {
                        "action": (
                            "Only a pre-effect job blocked by an unavailable signing "
                            "key can be requeued after key restoration."
                        )
                    }
                )
            job.status = IntegrationSyncJob.Status.QUEUED
            job.failure_code = "reconciled_key_restored"
            job.attempt_id = None
            job.claimed_at = None
            job.terminal_at = None
            job.available_at = timezone.now()
            job.attempt_authorized_by_id_snapshot = user.id
        elif action == "accept_remote":
            orchestrator = IntegrationRegistry.get_orchestrator(configuration)
            plan = orchestrator.prepare_incoming_event(
                event_type=job.event_type,
                payload=dict(job.payload),
                mapping=mapping,
                local_object=local_object,
            )
            if (
                plan.get("action") not in {"apply_remote", "review"}
                or not isinstance(plan.get("remote_data"), dict)
                or not isinstance(plan.get("local_data"), dict)
            ):
                raise ValidationError(
                    {"action": "The retained webhook cannot produce a valid command."}
                )
            mapper = orchestrator.mapper_for(
                model_key_for_content_type(mapping.content_type)
                or orchestrator.DEFAULT_MODEL_KEY
            )
            try:
                changed_fields = apply_inbound_update(
                    local_object=local_object,
                    local_data=plan["local_data"],
                    mapper=mapper,
                )
            except InboundCommandRejected as exc:
                raise ValidationError(
                    {"action": "The retained webhook violates the local contract."}
                ) from exc
            mapping.remote_data = plan["remote_data"]
            mapping.sync_status = SyncMapping.SyncStatus.SYNCED
            mapping.last_sync_direction = SyncMapping.SyncDirection.PULL
            mapping.last_synced_at = timezone.now()
            mapping.error_message = ""
            mapping.version += 1
            mapping.save()
            job.status = IntegrationSyncJob.Status.SUCCEEDED
            job.failure_code = ""
            job.payload = {}
            job.terminal_at = timezone.now()
            _record_reconciliation_event(
                job=job,
                mapping=mapping,
                actor_id=user.id,
                action=action,
                success=True,
                changed_fields=changed_fields,
            )
        elif action == "keep_local":
            later = Q(created_at__gt=job.created_at) | Q(
                created_at=job.created_at,
                id__gt=job.id,
            )
            has_active_successor = (
                IntegrationSyncJob.objects.select_for_update(of=("self",))
                .filter(
                    later,
                    mapping_id_snapshot=job.mapping_id_snapshot,
                    status__in=ACTIVE_SUCCESSOR_STATUSES,
                )
                .exists()
            )
            if has_active_successor:
                raise ValidationError(
                    {
                        "action": (
                            "Local-wins resolution is blocked while a later sync "
                            "job is active."
                        )
                    }
                )
            full_sync_fields = sorted(
                getattr(local_object, "INTEGRATION_SYNCABLE_FIELDS", set())
            )
            if not full_sync_fields:
                raise ValidationError(
                    {
                        "action": "The local object has no governed synchronization fields."
                    }
                )
            mapping.sync_status = SyncMapping.SyncStatus.PENDING
            mapping.error_message = ""
            mapping.version += 1
            mapping.save()
            job.status = IntegrationSyncJob.Status.SUPERSEDED
            job.failure_code = "review_resolved_local_wins"
            job.payload = {}
            job.terminal_at = timezone.now()
            _record_reconciliation_event(
                job=job,
                mapping=mapping,
                actor_id=user.id,
                action=action,
                success=True,
            )
            corrective_job_ids = persist_outbound_sync_jobs(
                content_type_id=mapping.content_type_id,
                object_id=local_object.pk,
                configuration_ids=[configuration.id],
                changed_fields=full_sync_fields,
                origin_principal=f"user:{user.id}",
                requested_by_id=user.id,
                reconciliation_authority={
                    "schema": "integration-reconciliation-corrective-v1",
                    "decision_id": str(decision_id),
                    "source_job_id": str(job.id),
                    "source_request_digest": job.request_digest,
                    "action": "keep_local",
                    "checker_id": str(user.id),
                },
            )
            if not corrective_job_ids:
                raise ValidationError(
                    {
                        "action": "A corrective synchronization could not be queued."
                    }
                )
        else:
            raise ValidationError({"action": "Unsupported reconciliation action."})

        job.reconciled_by_id_snapshot = user.id
        job.reconciled_at = timezone.now()
        job.reconciliation_action = action
        job.reconciliation_reason = reason
        job.reconciliation_before_digest = before_digest
        # The after digest is deliberately computed after every mapping/job
        # state mutation, before the audit row itself is saved.
        job.reconciliation_after_digest = _state_digest(job, mapping)
        job.save()
        _append_reconciliation_decision(
            decision_id=decision_id,
            job=job,
            mapping=mapping,
            actor_id=user.id,
            action=action,
            reason=reason,
            before_digest=before_digest,
            after_digest=job.reconciliation_after_digest,
            receipt=receipt,
            receipt_hmac=receipt_hmac,
            receipt_signing_key_id=receipt_signing_key_id,
        )

        if action in {"retry_same_operation", "requeue_after_key_restore"}:
            transaction.on_commit(
                lambda job_id=job.id: enqueue_integration_sync_jobs((job_id,)),
                robust=True,
            )
        elif action != "keep_local":
            _advance_successor(
                job=job,
                configuration=configuration,
                provider=provider,
                mapping=mapping,
                local_object=local_object,
            )
        return {
            "id": str(job.id),
            "status": job.status,
            "reconciliation_action": action,
            "reconciled_at": job.reconciled_at,
        }
