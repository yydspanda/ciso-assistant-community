import django.utils.timezone
import uuid
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("integrations", "0003_alter_integrationconfiguration_webhook_url"),
    ]

    operations = [
        migrations.CreateModel(
            name="IntegrationSyncJob",
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
                (
                    "created_at",
                    models.DateTimeField(auto_now_add=True, verbose_name="Created at"),
                ),
                (
                    "updated_at",
                    models.DateTimeField(auto_now=True, verbose_name="Updated at"),
                ),
                (
                    "is_published",
                    models.BooleanField(default=False, verbose_name="published"),
                ),
                (
                    "direction",
                    models.CharField(
                        choices=[("outbound", "Outbound"), ("incoming", "Incoming")],
                        max_length=12,
                    ),
                ),
                (
                    "status",
                    models.CharField(
                        choices=[
                            ("queued", "Queued"),
                            ("processing", "Processing"),
                            ("succeeded", "Succeeded"),
                            ("superseded", "Superseded"),
                            ("failed", "Failed"),
                            ("uncertain", "Uncertain"),
                            ("review_required", "Review required"),
                        ],
                        default="queued",
                        max_length=16,
                    ),
                ),
                ("request_digest", models.CharField(max_length=64, unique=True)),
                ("capability", models.JSONField(default=dict)),
                ("changed_fields", models.JSONField(default=list)),
                ("event_type", models.CharField(blank=True, max_length=100)),
                ("payload", models.JSONField(default=dict)),
                ("payload_hmac_sha256", models.CharField(blank=True, max_length=64)),
                ("configuration_id_snapshot", models.UUIDField()),
                ("provider_id_snapshot", models.UUIDField()),
                ("mapping_id_snapshot", models.UUIDField()),
                ("content_type_id_snapshot", models.PositiveIntegerField()),
                ("local_object_id_snapshot", models.UUIDField()),
                ("folder_id_snapshot", models.UUIDField()),
                ("attempts", models.PositiveIntegerField(default=0)),
                ("attempt_id", models.UUIDField(blank=True, editable=False, null=True)),
                (
                    "available_at",
                    models.DateTimeField(default=django.utils.timezone.now),
                ),
                (
                    "last_enqueued_at",
                    models.DateTimeField(blank=True, editable=False, null=True),
                ),
                ("claimed_at", models.DateTimeField(blank=True, null=True)),
                ("effect_started_at", models.DateTimeField(blank=True, null=True)),
                ("terminal_at", models.DateTimeField(blank=True, null=True)),
                ("failure_code", models.CharField(blank=True, max_length=64)),
                (
                    "reconciled_by_id_snapshot",
                    models.UUIDField(blank=True, editable=False, null=True),
                ),
                ("reconciled_at", models.DateTimeField(blank=True, null=True)),
                ("reconciliation_action", models.CharField(blank=True, max_length=32)),
                ("reconciliation_reason", models.TextField(blank=True)),
                (
                    "provider_receipt_hmac_sha256",
                    models.CharField(blank=True, max_length=64),
                ),
            ],
            options={
                "ordering": ["created_at", "id"],
                "indexes": [
                    models.Index(
                        fields=["status", "available_at"],
                        name="int_sync_job_status_due_idx",
                    ),
                    models.Index(
                        fields=["mapping_id_snapshot", "status", "created_at"],
                        name="int_sync_job_mapping_idx",
                    ),
                ],
                "constraints": [
                    models.CheckConstraint(
                        condition=models.Q(
                            (
                                "status__in",
                                (
                                    "queued",
                                    "processing",
                                    "succeeded",
                                    "superseded",
                                    "failed",
                                    "uncertain",
                                    "review_required",
                                ),
                            )
                        ),
                        name="int_sync_job_status_valid",
                    )
                ],
            },
        ),
    ]
