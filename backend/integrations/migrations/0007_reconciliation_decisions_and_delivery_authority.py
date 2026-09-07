import uuid

import django.utils.timezone
from django.db import migrations, models


def clear_unproved_sync_watermarks(apps, _schema_editor):
    """Mark every legacy ``auto_now`` watermark as unknown.

    Migration 0006 populated the new SyncEvent snapshot columns from each
    mapping's *then-current* graph.  Those values therefore cannot prove which
    object or remote ID an older event described before a relink or merge.
    Legacy ``last_synced_at`` itself changed on every save.  There is no
    trustworthy event-time baseline in the old schema, so fail closed instead
    of manufacturing one from mutually backfilled fields.
    """

    SyncMapping = apps.get_model("integrations", "SyncMapping")
    SyncMapping.objects.update(last_synced_at=None)


def reject_unsafe_watermark_downgrade(apps, _schema_editor):
    """Block downgrade when the old non-null field would require fabrication."""

    SyncMapping = apps.get_model("integrations", "SyncMapping")
    if SyncMapping.objects.filter(last_synced_at__isnull=True).exists():
        raise RuntimeError(
            "Cannot restore legacy integration watermarks: one or more mappings "
            "have no proved successful-sync timestamp."
        )


class Migration(migrations.Migration):
    dependencies = [
        ("integrations", "0006_preserve_sync_audit_and_reconciliation"),
    ]

    operations = [
        migrations.AlterField(
            model_name="syncmapping",
            name="last_synced_at",
            field=models.DateTimeField(blank=True, editable=False, null=True),
        ),
        migrations.RunPython(
            clear_unproved_sync_watermarks,
            reverse_code=reject_unsafe_watermark_downgrade,
        ),
        migrations.AddField(
            model_name="integrationsyncjob",
            name="webhook_delivery_digest",
            field=models.CharField(
                blank=True,
                editable=False,
                max_length=64,
                null=True,
                unique=True,
            ),
        ),
        migrations.AddField(
            model_name="integrationsyncjob",
            name="remote_version",
            field=models.DateTimeField(blank=True, editable=False, null=True),
        ),
        migrations.AddField(
            model_name="integrationsyncjob",
            name="attempt_authorized_by_id_snapshot",
            field=models.UUIDField(blank=True, editable=False, null=True),
        ),
        migrations.AddField(
            model_name="syncevent",
            name="job_id_snapshot",
            field=models.UUIDField(blank=True, editable=False, null=True),
        ),
        migrations.AddField(
            model_name="syncevent",
            name="request_digest_snapshot",
            field=models.CharField(blank=True, editable=False, max_length=64),
        ),
        migrations.AddField(
            model_name="syncevent",
            name="actor_id_snapshot",
            field=models.UUIDField(blank=True, editable=False, null=True),
        ),
        migrations.CreateModel(
            name="IntegrationReconciliationDecision",
            fields=[
                (
                    "id",
                    models.UUIDField(
                        default=uuid.uuid4,
                        editable=False,
                        primary_key=True,
                        serialize=False,
                    ),
                ),
                ("job_id_snapshot", models.UUIDField(db_index=True, editable=False)),
                ("mapping_id_snapshot", models.UUIDField(editable=False)),
                ("configuration_id_snapshot", models.UUIDField(editable=False)),
                ("provider_id_snapshot", models.UUIDField(editable=False)),
                (
                    "content_type_id_snapshot",
                    models.PositiveIntegerField(editable=False),
                ),
                ("local_object_id_snapshot", models.UUIDField(editable=False)),
                ("folder_id_snapshot", models.UUIDField(editable=False)),
                ("actor_id_snapshot", models.UUIDField(db_index=True, editable=False)),
                (
                    "action",
                    models.CharField(
                        choices=[
                            ("confirm_applied", "Confirm applied"),
                            ("confirm_not_applied", "Confirm not applied"),
                            ("retry_same_operation", "Retry same operation"),
                            (
                                "requeue_after_key_restore",
                                "Requeue after key restore",
                            ),
                            ("accept_remote", "Accept remote"),
                            ("keep_local", "Keep local"),
                        ],
                        editable=False,
                        max_length=32,
                    ),
                ),
                ("reason", models.TextField(editable=False)),
                (
                    "request_digest_snapshot",
                    models.CharField(editable=False, max_length=64),
                ),
                ("before_digest", models.CharField(editable=False, max_length=64)),
                ("after_digest", models.CharField(editable=False, max_length=64)),
                (
                    "provider_outcome",
                    models.CharField(blank=True, editable=False, max_length=16),
                ),
                (
                    "provider_remote_id_snapshot",
                    models.CharField(blank=True, editable=False, max_length=255),
                ),
                (
                    "provider_remote_data_sha256",
                    models.CharField(blank=True, editable=False, max_length=64),
                ),
                (
                    "provider_evidence_reference",
                    models.CharField(blank=True, editable=False, max_length=2048),
                ),
                (
                    "provider_event_id",
                    models.CharField(blank=True, editable=False, max_length=255),
                ),
                (
                    "provider_observed_at",
                    models.DateTimeField(blank=True, editable=False, null=True),
                ),
                (
                    "provider_receipt_hmac_sha256",
                    models.CharField(blank=True, editable=False, max_length=64),
                ),
                (
                    "provider_receipt_signing_key_id",
                    models.CharField(blank=True, editable=False, max_length=64),
                ),
                (
                    "decision_hmac_sha256",
                    models.CharField(editable=False, max_length=64),
                ),
                (
                    "decision_signing_key_id",
                    models.CharField(editable=False, max_length=64),
                ),
                (
                    "decided_at",
                    models.DateTimeField(
                        default=django.utils.timezone.now, editable=False
                    ),
                ),
            ],
            options={
                "ordering": ["decided_at", "id"],
                "indexes": [
                    models.Index(
                        fields=["mapping_id_snapshot", "decided_at"],
                        name="int_recon_mapping_time_idx",
                    )
                ],
            },
        ),
        migrations.CreateModel(
            name="IntegrationSyncAttempt",
            fields=[
                (
                    "id",
                    models.UUIDField(
                        default=uuid.uuid4,
                        editable=False,
                        primary_key=True,
                        serialize=False,
                    ),
                ),
                ("attempt_id", models.UUIDField(editable=False, unique=True)),
                ("job_id_snapshot", models.UUIDField(db_index=True, editable=False)),
                (
                    "request_digest_snapshot",
                    models.CharField(editable=False, max_length=64),
                ),
                (
                    "authorized_by_id_snapshot",
                    models.UUIDField(blank=True, editable=False, null=True),
                ),
                (
                    "authority_principal_snapshot",
                    models.CharField(blank=True, editable=False, max_length=128),
                ),
                ("outcome", models.CharField(editable=False, max_length=32)),
                ("claimed_at", models.DateTimeField(editable=False)),
                (
                    "effect_started_at",
                    models.DateTimeField(blank=True, editable=False, null=True),
                ),
                ("completed_at", models.DateTimeField(editable=False)),
                (
                    "result_digest",
                    models.CharField(blank=True, editable=False, max_length=64),
                ),
                (
                    "attempt_hmac_sha256",
                    models.CharField(editable=False, max_length=64),
                ),
                ("signing_key_id", models.CharField(editable=False, max_length=64)),
                (
                    "created_at",
                    models.DateTimeField(
                        default=django.utils.timezone.now, editable=False
                    ),
                ),
            ],
            options={
                "ordering": ["created_at", "id"],
                "indexes": [
                    models.Index(
                        fields=["job_id_snapshot", "created_at"],
                        name="int_attempt_job_time_idx",
                    )
                ],
            },
        ),
        migrations.AddConstraint(
            model_name="integrationsyncjob",
            constraint=models.CheckConstraint(
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
        ),
        migrations.AddConstraint(
            model_name="integrationsyncjob",
            constraint=models.CheckConstraint(
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
        ),
        migrations.AddConstraint(
            model_name="integrationsyncjob",
            constraint=models.CheckConstraint(
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
        ),
        migrations.AddConstraint(
            model_name="integrationsyncjob",
            constraint=models.CheckConstraint(
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
        ),
    ]
