import uuid

from auditlog.registry import auditlog
from django.contrib.contenttypes.models import ContentType
from django.contrib.contenttypes.fields import GenericForeignKey
from django.db import models
from django.core.exceptions import ValidationError
from django.utils import timezone

from core.base_models import AbstractBaseModel
from iam.models import FolderMixin


class IntegrationProvider(AbstractBaseModel, FolderMixin):
    """Registry of available integration types"""

    class ProviderType(models.TextChoices):
        ITSM = "itsm"

    name = models.CharField(max_length=100)  # 'jira', 'servicenow', etc.
    provider_type = models.CharField(max_length=20, choices=ProviderType.choices)
    is_active = models.BooleanField(default=True)

    class Meta:
        unique_together = ["name", "folder"]


class IntegrationConfiguration(AbstractBaseModel, FolderMixin):
    """Instance of an integration for a specific folder"""

    provider = models.ForeignKey(
        IntegrationProvider, related_name="configurations", on_delete=models.CASCADE
    )

    credentials = models.JSONField(default=dict)

    # Provider-specific settings
    settings = models.JSONField(default=dict)

    # Webhook configuration
    webhook_secret = models.CharField(max_length=255)
    webhook_url = models.URLField(
        blank=True, max_length=2048
    )  # For registering with remote system

    is_active = models.BooleanField(default=True)
    last_sync_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        unique_together = ["provider", "folder"]


class IntegrationSchemaCache(AbstractBaseModel):
    """Cached remote schema (tables, columns, choices) for an integration.

    Populated lazily on RPC cache misses, warmed on backend startup, and
    refreshed on demand via the 'refresh_schema' action. DB-backed so it is
    shared across web workers and the Huey consumer and survives restarts.
    """

    configuration = models.OneToOneField(
        IntegrationConfiguration,
        related_name="schema_cache",
        on_delete=models.CASCADE,
    )

    tables = models.JSONField(default=list)  # [{name, label}, ...]
    columns = models.JSONField(default=dict)  # {table_name: [{name, label, ...}], ...}
    choices = models.JSONField(default=dict)  # {"table:field": [{value, label}], ...}

    fetched_at = models.DateTimeField(null=True, blank=True)


class SyncMapping(AbstractBaseModel, FolderMixin):
    """Maps local objects to remote objects"""

    class SyncStatus(models.TextChoices):
        SYNCED = "synced"
        PENDING = "pending"
        FAILED = "failed"
        CONFLICT = "conflict"

    class SyncDirection(models.TextChoices):
        PUSH = "push"
        PULL = "pull"

    configuration = models.ForeignKey(
        IntegrationConfiguration, related_name="sync_mappings", on_delete=models.CASCADE
    )

    # Local object reference
    content_type = models.ForeignKey(
        ContentType, related_name="sync_mappings", on_delete=models.CASCADE
    )  # e.g. core.AppliedControl
    local_object_id = models.UUIDField()
    local_object = GenericForeignKey("content_type", "local_object_id")

    # Remote object reference
    remote_id = models.CharField(max_length=255)  # Jira issue key, etc.
    remote_data = models.JSONField(default=dict)  # Cache of remote state

    # Sync metadata
    sync_status = models.CharField(
        max_length=20, choices=SyncStatus.choices, default=SyncStatus.SYNCED
    )
    # A mapping has not been synchronized merely because it was created or
    # edited.  Authority-bearing paths set this only after a proved success.
    last_synced_at = models.DateTimeField(null=True, blank=True, editable=False)
    last_sync_direction = models.CharField(
        max_length=10, choices=SyncDirection.choices, blank=True
    )  # 'push', 'pull'
    version = models.IntegerField(default=1)  # For optimistic locking
    error_message = models.TextField(blank=True)

    class Meta:
        unique_together = ["configuration", "content_type", "local_object_id"]
        constraints = [
            models.UniqueConstraint(
                fields=["configuration", "remote_id"],
                condition=~models.Q(remote_id=""),
                name="int_syncmap_cfg_remote_uniq",
            ),
        ]
        indexes = [
            models.Index(fields=["configuration", "remote_id"]),
        ]

    def save(self, *args, **kwargs):
        from integrations.remote_ids import (
            InvalidRemoteIdentifier,
            normalize_remote_id,
        )

        try:
            self.remote_id = normalize_remote_id(
                self.configuration.provider.name,
                self.remote_id,
                allow_blank=True,
            )
        except InvalidRemoteIdentifier as exc:
            raise ValidationError({"remote_id": "Invalid remote identifier."}) from exc
        return super().save(*args, **kwargs)


class SyncEvent(models.Model):
    """Audit trail of sync operations"""

    class TriggeredBy(models.TextChoices):
        USER = "user"
        WEBHOOK = "webhook"
        SCHEDULED = "scheduled"
        RECONCILIATION = "reconciliation"

    mapping = models.ForeignKey(
        SyncMapping,
        related_name="sync_events",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
    )
    mapping_id_snapshot = models.UUIDField(editable=False)
    configuration_id_snapshot = models.UUIDField(editable=False)
    content_type_id_snapshot = models.PositiveIntegerField(editable=False)
    local_object_id_snapshot = models.UUIDField(editable=False)
    remote_id_snapshot = models.CharField(max_length=255, blank=True, editable=False)
    job_id_snapshot = models.UUIDField(null=True, blank=True, editable=False)
    request_digest_snapshot = models.CharField(
        max_length=64, blank=True, editable=False
    )
    actor_id_snapshot = models.UUIDField(null=True, blank=True, editable=False)
    direction = models.CharField(
        max_length=10, choices=SyncMapping.SyncDirection.choices
    )

    changes = models.JSONField()  # What changed
    triggered_by = models.CharField(
        max_length=50, choices=TriggeredBy.choices
    )  # 'user', 'webhook', 'scheduled'

    success = models.BooleanField(default=True)
    error_details = models.TextField(blank=True)

    created_at = models.DateTimeField(auto_now_add=True)


class IntegrationSyncJob(AbstractBaseModel):
    """Durable authority and recovery record for one integration side effect.

    Huey transports only this row's UUID.  The row contains identifiers and
    cryptographic digests rather than credentials.  Incoming payload data is
    retained only while execution/reconciliation may need it and is scrubbed
    after an unambiguous terminal result.
    """

    class Direction(models.TextChoices):
        OUTBOUND = "outbound", "Outbound"
        INCOMING = "incoming", "Incoming"

    class Status(models.TextChoices):
        QUEUED = "queued", "Queued"
        PROCESSING = "processing", "Processing"
        SUCCEEDED = "succeeded", "Succeeded"
        SUPERSEDED = "superseded", "Superseded"
        FAILED = "failed", "Failed"
        UNCERTAIN = "uncertain", "Uncertain"
        REVIEW_REQUIRED = "review_required", "Review required"

    direction = models.CharField(max_length=12, choices=Direction.choices)
    status = models.CharField(
        max_length=16,
        choices=Status.choices,
        default=Status.QUEUED,
    )
    request_digest = models.CharField(max_length=64, unique=True)
    capability = models.JSONField(default=dict)
    changed_fields = models.JSONField(default=list)
    event_type = models.CharField(max_length=100, blank=True)
    payload = models.JSONField(default=dict)
    payload_hmac_sha256 = models.CharField(max_length=64, blank=True)
    webhook_delivery_digest = models.CharField(
        max_length=64,
        null=True,
        blank=True,
        unique=True,
        editable=False,
    )
    remote_version = models.DateTimeField(null=True, blank=True, editable=False)

    configuration_id_snapshot = models.UUIDField()
    provider_id_snapshot = models.UUIDField()
    mapping_id_snapshot = models.UUIDField()
    content_type_id_snapshot = models.PositiveIntegerField()
    local_object_id_snapshot = models.UUIDField()
    folder_id_snapshot = models.UUIDField()
    origin_principal_snapshot = models.CharField(max_length=128, editable=False)
    requested_by_id_snapshot = models.UUIDField(null=True, blank=True, editable=False)
    attempt_authorized_by_id_snapshot = models.UUIDField(
        null=True, blank=True, editable=False
    )

    attempts = models.PositiveIntegerField(default=0)
    attempt_id = models.UUIDField(null=True, blank=True, editable=False)
    available_at = models.DateTimeField(default=timezone.now)
    last_enqueued_at = models.DateTimeField(null=True, blank=True, editable=False)
    claimed_at = models.DateTimeField(null=True, blank=True)
    effect_started_at = models.DateTimeField(null=True, blank=True)
    terminal_at = models.DateTimeField(null=True, blank=True)
    failure_code = models.CharField(max_length=64, blank=True)
    reconciled_by_id_snapshot = models.UUIDField(null=True, blank=True, editable=False)
    reconciled_at = models.DateTimeField(null=True, blank=True)
    reconciliation_action = models.CharField(max_length=32, blank=True)
    reconciliation_reason = models.TextField(blank=True)
    provider_receipt_hmac_sha256 = models.CharField(max_length=64, blank=True)
    provider_receipt_signing_key_id = models.CharField(
        max_length=64, blank=True, editable=False
    )
    review_state_hmac_sha256 = models.CharField(
        max_length=64, blank=True, editable=False
    )
    review_state_signing_key_id = models.CharField(
        max_length=64, blank=True, editable=False
    )
    reconciliation_before_digest = models.CharField(
        max_length=64, blank=True, editable=False
    )
    reconciliation_after_digest = models.CharField(
        max_length=64, blank=True, editable=False
    )

    class Meta:
        ordering = ["created_at", "id"]
        permissions = [
            (
                "reconcile_integrationsyncjob",
                "Can reconcile integration sync jobs",
            ),
        ]
        constraints = [
            models.CheckConstraint(
                condition=models.Q(
                    status__in=(
                        "queued",
                        "processing",
                        "succeeded",
                        "superseded",
                        "failed",
                        "uncertain",
                        "review_required",
                    )
                ),
                name="int_sync_job_status_valid",
            ),
            models.CheckConstraint(
                condition=(
                    ~models.Q(status="queued")
                    | models.Q(
                        attempt_id__isnull=True,
                        claimed_at__isnull=True,
                        effect_started_at__isnull=True,
                        terminal_at__isnull=True,
                    )
                ),
                name="int_sync_job_queued_shape",
            ),
            models.CheckConstraint(
                condition=(
                    ~models.Q(status="processing")
                    | models.Q(
                        attempt_id__isnull=False,
                        claimed_at__isnull=False,
                        terminal_at__isnull=True,
                    )
                ),
                name="int_sync_job_processing_shape",
            ),
            models.CheckConstraint(
                condition=(
                    ~models.Q(status="uncertain")
                    | models.Q(
                        attempt_id__isnull=False,
                        claimed_at__isnull=False,
                        effect_started_at__isnull=False,
                        terminal_at__isnull=False,
                    )
                ),
                name="int_sync_job_uncertain_shape",
            ),
            models.CheckConstraint(
                condition=(
                    ~models.Q(
                        status__in=(
                            "succeeded",
                            "superseded",
                            "failed",
                            "review_required",
                        )
                    )
                    | models.Q(terminal_at__isnull=False)
                ),
                name="int_sync_job_terminal_shape",
            ),
        ]
        indexes = [
            models.Index(
                fields=["status", "available_at"],
                name="int_sync_job_status_due_idx",
            ),
            models.Index(
                fields=["mapping_id_snapshot", "status", "created_at"],
                name="int_sync_job_mapping_idx",
            ),
        ]


class _AppendOnlyIntegrationQuerySet(models.QuerySet):
    """Reject application-level rewrites of authority audit records."""

    def update(self, **kwargs):
        raise ValidationError("Integration authority records cannot be updated.")

    def delete(self):
        raise ValidationError("Integration authority records cannot be deleted.")

    def bulk_update(self, objs, fields, batch_size=None):
        raise ValidationError("Integration authority records cannot be updated.")


class _AppendOnlyIntegrationRecord(models.Model):
    """Common application guard for immutable authority evidence."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    objects = models.Manager.from_queryset(_AppendOnlyIntegrationQuerySet)()

    class Meta:
        abstract = True

    def save(self, *args, **kwargs):
        if not self._state.adding:
            raise ValidationError(
                "Integration authority records are append-only; create a new record."
            )
        return super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValidationError("Integration authority records cannot be deleted.")


class IntegrationReconciliationDecision(_AppendOnlyIntegrationRecord):
    """Immutable maker/checker decision over one exact retained job state."""

    class Action(models.TextChoices):
        CONFIRM_APPLIED = "confirm_applied", "Confirm applied"
        CONFIRM_NOT_APPLIED = "confirm_not_applied", "Confirm not applied"
        RETRY_SAME_OPERATION = "retry_same_operation", "Retry same operation"
        REQUEUE_AFTER_KEY_RESTORE = (
            "requeue_after_key_restore",
            "Requeue after key restore",
        )
        ACCEPT_REMOTE = "accept_remote", "Accept remote"
        KEEP_LOCAL = "keep_local", "Keep local"

    job_id_snapshot = models.UUIDField(db_index=True, editable=False)
    mapping_id_snapshot = models.UUIDField(editable=False)
    configuration_id_snapshot = models.UUIDField(editable=False)
    provider_id_snapshot = models.UUIDField(editable=False)
    content_type_id_snapshot = models.PositiveIntegerField(editable=False)
    local_object_id_snapshot = models.UUIDField(editable=False)
    folder_id_snapshot = models.UUIDField(editable=False)
    actor_id_snapshot = models.UUIDField(db_index=True, editable=False)
    action = models.CharField(max_length=32, choices=Action.choices, editable=False)
    reason = models.TextField(editable=False)
    request_digest_snapshot = models.CharField(max_length=64, editable=False)
    before_digest = models.CharField(max_length=64, editable=False)
    after_digest = models.CharField(max_length=64, editable=False)
    provider_outcome = models.CharField(max_length=16, blank=True, editable=False)
    provider_remote_id_snapshot = models.CharField(
        max_length=255, blank=True, editable=False
    )
    provider_remote_data_sha256 = models.CharField(
        max_length=64, blank=True, editable=False
    )
    provider_evidence_reference = models.CharField(
        max_length=2048, blank=True, editable=False
    )
    provider_event_id = models.CharField(max_length=255, blank=True, editable=False)
    provider_observed_at = models.DateTimeField(null=True, blank=True, editable=False)
    provider_receipt_hmac_sha256 = models.CharField(
        max_length=64, blank=True, editable=False
    )
    provider_receipt_signing_key_id = models.CharField(
        max_length=64, blank=True, editable=False
    )
    decision_hmac_sha256 = models.CharField(max_length=64, editable=False)
    decision_signing_key_id = models.CharField(max_length=64, editable=False)
    decided_at = models.DateTimeField(default=timezone.now, editable=False)

    class Meta:
        ordering = ["decided_at", "id"]
        indexes = [
            models.Index(
                fields=["mapping_id_snapshot", "decided_at"],
                name="int_recon_mapping_time_idx",
            )
        ]


class IntegrationSyncAttempt(_AppendOnlyIntegrationRecord):
    """Immutable result record for one provider-effect attempt.

    The worker writes one row only when an attempt reaches a known or recovered
    outcome; it never mutates an earlier attempt to describe a later retry.
    """

    attempt_id = models.UUIDField(unique=True, editable=False)
    job_id_snapshot = models.UUIDField(db_index=True, editable=False)
    request_digest_snapshot = models.CharField(max_length=64, editable=False)
    authorized_by_id_snapshot = models.UUIDField(null=True, blank=True, editable=False)
    authority_principal_snapshot = models.CharField(
        max_length=128, blank=True, editable=False
    )
    outcome = models.CharField(max_length=32, editable=False)
    claimed_at = models.DateTimeField(editable=False)
    effect_started_at = models.DateTimeField(null=True, blank=True, editable=False)
    completed_at = models.DateTimeField(editable=False)
    result_digest = models.CharField(max_length=64, blank=True, editable=False)
    attempt_hmac_sha256 = models.CharField(max_length=64, editable=False)
    signing_key_id = models.CharField(max_length=64, editable=False)
    created_at = models.DateTimeField(default=timezone.now, editable=False)

    class Meta:
        ordering = ["created_at", "id"]
        indexes = [
            models.Index(
                fields=["job_id_snapshot", "created_at"],
                name="int_attempt_job_time_idx",
            )
        ]


# Sync state (SyncMapping/SyncEvent) is high-volume and intentionally untracked.
auditlog.register(
    IntegrationProvider,
    exclude_fields=["created_at", "updated_at", "is_published"],
)
auditlog.register(
    IntegrationConfiguration,
    exclude_fields=["created_at", "updated_at", "is_published", "last_sync_at"],
    mask_fields=["credentials", "webhook_secret"],
    mask_callable="global_settings.utils.redact_secret_value",
)
