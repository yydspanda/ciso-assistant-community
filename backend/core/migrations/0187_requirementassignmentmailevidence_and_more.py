import django.utils.timezone
import hashlib
import json
import uuid

from django.db import migrations, models


def backfill_mail_delivery_evidence(apps, schema_editor):
    """Conservatively classify legacy outcomes and retain a signed snapshot.

    A legacy worker could die after SMTP acceptance while the row still said
    ``sending`` or could record the broad ``delivery_error`` code without
    proving whether the provider accepted the message.  Neither state is safe
    to treat as a retryable or deletable failure during upgrade.
    """

    Outbox = apps.get_model("core", "RequirementAssignmentMailOutbox")
    Evidence = apps.get_model("core", "RequirementAssignmentMailEvidence")
    for outbox in Outbox.objects.order_by("created_at", "id").iterator():
        prior_status = outbox.status
        update_fields = []
        if prior_status == "sending" or (
            prior_status == "failed" and outbox.failure_code == "claim_timeout"
        ):
            outbox.status = "review_required"
            outbox.failure_code = "claim_timeout"
            update_fields = ["status", "failure_code"]
        elif prior_status == "failed" and outbox.failure_code == "delivery_error":
            outbox.status = "uncertain"
            update_fields = ["status"]
        if update_fields:
            outbox.save(update_fields=update_fields)

        recorded_at = django.utils.timezone.now()
        evidence_reference = "migration:core-0187-legacy-outbox"
        payload = {
            "action": "",
            "assignment_id_snapshot": str(outbox.assignment_id),
            "attempts": outbox.attempts,
            "evidence_reference": evidence_reference,
            "failure_code": outbox.failure_code,
            "folder_id_snapshot": str(outbox.folder_id),
            "outbox_id_snapshot": str(outbox.id),
            "payload_digest": outbox.payload_digest,
            "prior_status": prior_status,
            "reason": "",
            "recipient_actor_id_snapshot": (
                str(outbox.recipient_actor_id)
                if outbox.recipient_actor_id
                else None
            ),
            "recipient_address_hash": outbox.recipient_address_hash,
            "recorded_at": recorded_at.isoformat(),
            "recorded_by_id_snapshot": None,
            "requested_by_id_snapshot": (
                str(outbox.requested_by_id) if outbox.requested_by_id else None
            ),
            "source": "system",
            "status": outbox.status,
        }
        canonical = json.dumps(
            payload,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
        Evidence.objects.create(
            outbox_id_snapshot=outbox.id,
            assignment_id_snapshot=outbox.assignment_id,
            folder_id_snapshot=outbox.folder_id,
            recipient_actor_id_snapshot=outbox.recipient_actor_id,
            requested_by_id_snapshot=outbox.requested_by_id,
            recorded_by_id_snapshot=None,
            source="system",
            prior_status=prior_status,
            status=outbox.status,
            action="",
            attempts=outbox.attempts,
            payload_digest=outbox.payload_digest,
            recipient_address_hash=outbox.recipient_address_hash,
            failure_code=outbox.failure_code,
            reason="",
            evidence_reference=evidence_reference,
            record_digest=hashlib.sha256(canonical.encode("utf-8")).hexdigest(),
            recorded_at=recorded_at,
        )


class Migration(migrations.Migration):
    dependencies = [
        ("core", "0186_baseline_clone_invariants"),
    ]

    operations = [
        migrations.CreateModel(
            name="RequirementAssignmentMailEvidence",
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
                    "outbox_id_snapshot",
                    models.UUIDField(db_index=True, editable=False),
                ),
                (
                    "assignment_id_snapshot",
                    models.UUIDField(db_index=True, editable=False),
                ),
                ("folder_id_snapshot", models.UUIDField(editable=False)),
                (
                    "recipient_actor_id_snapshot",
                    models.UUIDField(blank=True, editable=False, null=True),
                ),
                (
                    "requested_by_id_snapshot",
                    models.UUIDField(blank=True, editable=False, null=True),
                ),
                (
                    "recorded_by_id_snapshot",
                    models.UUIDField(blank=True, editable=False, null=True),
                ),
                (
                    "source",
                    models.CharField(
                        choices=[("system", "System"), ("human", "Human")],
                        editable=False,
                        max_length=8,
                    ),
                ),
                (
                    "prior_status",
                    models.CharField(blank=True, editable=False, max_length=16),
                ),
                (
                    "status",
                    models.CharField(
                        choices=[
                            ("queued", "Queued"),
                            ("sending", "Sending"),
                            ("delivered", "Delivered"),
                            ("failed", "Failed"),
                            ("uncertain", "Uncertain"),
                            ("review_required", "Review required"),
                        ],
                        editable=False,
                        max_length=16,
                    ),
                ),
                (
                    "action",
                    models.CharField(
                        blank=True,
                        choices=[
                            ("confirm_delivered", "Confirm delivered"),
                            ("confirm_not_delivered", "Confirm not delivered"),
                        ],
                        editable=False,
                        max_length=32,
                    ),
                ),
                ("attempts", models.PositiveIntegerField(editable=False)),
                (
                    "payload_digest",
                    models.CharField(editable=False, max_length=64),
                ),
                (
                    "recipient_address_hash",
                    models.CharField(editable=False, max_length=64),
                ),
                (
                    "failure_code",
                    models.CharField(blank=True, editable=False, max_length=64),
                ),
                ("reason", models.TextField(blank=True, editable=False)),
                (
                    "evidence_reference",
                    models.CharField(blank=True, editable=False, max_length=2048),
                ),
                (
                    "record_digest",
                    models.CharField(db_index=True, editable=False, max_length=64),
                ),
                (
                    "recorded_at",
                    models.DateTimeField(
                        default=django.utils.timezone.now, editable=False
                    ),
                ),
            ],
            options={
                "verbose_name": "Requirement assignment mail evidence",
                "verbose_name_plural": "Requirement assignment mail evidence",
                "ordering": ["recorded_at", "id"],
            },
        ),
        migrations.AlterModelOptions(
            name="requirementassignmentmailoutbox",
            options={
                "ordering": ["created_at"],
                "permissions": [
                    (
                        "resolve_requirementassignmentmailoutbox",
                        "Can resolve uncertain requirement assignment mail",
                    )
                ],
                "verbose_name": "Requirement assignment mail outbox entry",
                "verbose_name_plural": "Requirement assignment mail outbox entries",
            },
        ),
        migrations.RemoveConstraint(
            model_name="requirementassignmentmailoutbox",
            name="core_ra_mail_status_valid",
        ),
        migrations.AlterField(
            model_name="requirementassignmentmailoutbox",
            name="status",
            field=models.CharField(
                choices=[
                    ("queued", "Queued"),
                    ("sending", "Sending"),
                    ("delivered", "Delivered"),
                    ("failed", "Failed"),
                    ("uncertain", "Uncertain"),
                    ("review_required", "Review required"),
                ],
                default="queued",
                max_length=16,
            ),
        ),
        migrations.AddConstraint(
            model_name="requirementassignmentmailoutbox",
            constraint=models.CheckConstraint(
                condition=models.Q(
                    status__in=(
                        "queued",
                        "sending",
                        "delivered",
                        "failed",
                        "uncertain",
                        "review_required",
                    )
                ),
                name="core_ra_mail_status_valid",
            ),
        ),
        migrations.RunPython(
            backfill_mail_delivery_evidence,
            reverse_code=migrations.RunPython.noop,
        ),
        migrations.AddIndex(
            model_name="requirementassignmentmailevidence",
            index=models.Index(
                fields=["assignment_id_snapshot", "recorded_at"],
                name="core_ra_mail_ev_assignment_idx",
            ),
        ),
    ]
