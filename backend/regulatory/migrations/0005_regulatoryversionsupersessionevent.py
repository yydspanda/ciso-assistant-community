"""Add synthetic whole-version edges without changing any existing history."""

import uuid

import django.db.models.deletion
import iam.models
from django.conf import settings
from django.db import migrations, models

import regulatory.validators


def refuse_reverse_with_supersession_history(apps, schema_editor):
    event = apps.get_model("regulatory", "RegulatoryVersionSupersessionEvent")
    if event.objects.using(schema_editor.connection.alias).exists():
        raise RuntimeError(
            "Cannot remove regulatory supersession history; retain migration 0005."
        )


class Migration(migrations.Migration):
    dependencies = [
        ("regulatory", "0004_regulatoryapplicabilityreviewdisposition"),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name="RegulatoryVersionSupersessionEvent",
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
                    "predecessor_version_record_id",
                    models.CharField(
                        max_length=160,
                        validators=[
                            regulatory.validators.validate_regulatory_identifier
                        ],
                    ),
                ),
                (
                    "successor_version_record_id",
                    models.CharField(
                        max_length=160,
                        validators=[
                            regulatory.validators.validate_regulatory_identifier
                        ],
                    ),
                ),
                (
                    "replacement_kind",
                    models.CharField(
                        default="whole_document", editable=False, max_length=24
                    ),
                ),
                ("effective_on", models.DateField()),
                ("occurred_at", models.DateTimeField(editable=False)),
                ("rationale", models.TextField(max_length=4000)),
                ("idempotency_key", models.CharField(max_length=200)),
                (
                    "digest_schema",
                    models.CharField(
                        default="regulatory-version-supersession/v1",
                        editable=False,
                        max_length=64,
                    ),
                ),
                (
                    "payload_sha256",
                    models.CharField(
                        max_length=64,
                        validators=[regulatory.validators.validate_sha256],
                    ),
                ),
                (
                    "before_payload_sha256",
                    models.CharField(
                        max_length=64,
                        validators=[regulatory.validators.validate_sha256],
                    ),
                ),
                (
                    "after_payload_sha256",
                    models.CharField(
                        max_length=64,
                        validators=[regulatory.validators.validate_sha256],
                    ),
                ),
                ("is_binding", models.BooleanField(default=False, editable=False)),
                (
                    "folder",
                    models.ForeignKey(
                        default=iam.models.Folder.get_root_folder_id,
                        on_delete=django.db.models.deletion.PROTECT,
                        related_name="%(class)s_folder",
                        to="iam.folder",
                    ),
                ),
                (
                    "document",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.PROTECT,
                        related_name="supersession_events",
                        to="regulatory.regulatorydocument",
                    ),
                ),
                (
                    "registration",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.PROTECT,
                        related_name="supersession_events",
                        to="regulatory.entitydocumentregistration",
                    ),
                ),
                (
                    "recorded_by",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.PROTECT,
                        related_name="regulatory_version_supersessions",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
                (
                    "predecessor_document_version",
                    models.ForeignKey(
                        db_index=False,
                        on_delete=django.db.models.deletion.PROTECT,
                        related_name="supersession_events_as_predecessor",
                        to="regulatory.regulatorydocumentversion",
                    ),
                ),
                (
                    "successor_document_version",
                    models.ForeignKey(
                        db_index=False,
                        on_delete=django.db.models.deletion.PROTECT,
                        related_name="supersession_events_as_successor",
                        to="regulatory.regulatorydocumentversion",
                    ),
                ),
                (
                    "predecessor_provision",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.PROTECT,
                        related_name="supersession_events_as_predecessor",
                        to="regulatory.regulatoryprovision",
                    ),
                ),
                (
                    "successor_provision",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.PROTECT,
                        related_name="supersession_events_as_successor",
                        to="regulatory.regulatoryprovision",
                    ),
                ),
                (
                    "predecessor_obligation",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.PROTECT,
                        related_name="supersession_events_as_predecessor",
                        to="regulatory.regulatoryobligation",
                    ),
                ),
                (
                    "successor_obligation",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.PROTECT,
                        related_name="supersession_events_as_successor",
                        to="regulatory.regulatoryobligation",
                    ),
                ),
            ],
            options={
                "default_permissions": ("view",),
                "permissions": [
                    (
                        "supersede_regulatoryversion",
                        "Can append a synthetic whole regulatory version replacement",
                    )
                ],
                "ordering": ["occurred_at", "id"],
                "indexes": [
                    models.Index(
                        fields=["folder", "document", "occurred_at"],
                        name="reg_sup_doc_time_idx",
                    )
                ],
                "constraints": [
                    models.UniqueConstraint(
                        fields=["folder", "idempotency_key"],
                        name="reg_sup_idempotency_uniq",
                    ),
                    models.UniqueConstraint(
                        fields=["predecessor_document_version"],
                        name="reg_sup_pred_physical_uniq",
                    ),
                    models.UniqueConstraint(
                        fields=["successor_document_version"],
                        name="reg_sup_succ_physical_uniq",
                    ),
                    models.UniqueConstraint(
                        fields=["folder", "document", "predecessor_version_record_id"],
                        name="reg_sup_pred_stable_uniq",
                    ),
                    models.UniqueConstraint(
                        fields=["folder", "document", "successor_version_record_id"],
                        name="reg_sup_succ_stable_uniq",
                    ),
                    models.CheckConstraint(
                        condition=models.Q(replacement_kind="whole_document"),
                        name="reg_sup_whole_document",
                    ),
                    models.CheckConstraint(
                        condition=models.Q(
                            digest_schema="regulatory-version-supersession/v1"
                        ),
                        name="reg_sup_digest_schema",
                    ),
                    models.CheckConstraint(
                        condition=models.Q(is_binding=False), name="reg_sup_not_binding"
                    ),
                    models.CheckConstraint(
                        condition=models.Q(is_published=False),
                        name="reg_sup_not_published",
                    ),
                    models.CheckConstraint(
                        condition=~models.Q(
                            predecessor_version_record_id=models.F(
                                "successor_version_record_id"
                            )
                        ),
                        name="reg_sup_stable_changed",
                    ),
                    models.CheckConstraint(
                        condition=~models.Q(
                            predecessor_document_version=models.F(
                                "successor_document_version"
                            )
                        ),
                        name="reg_sup_physical_changed",
                    ),
                    models.CheckConstraint(
                        condition=~models.Q(
                            before_payload_sha256=models.F("after_payload_sha256")
                        ),
                        name="reg_sup_payload_changed",
                    ),
                    models.CheckConstraint(
                        condition=~models.Q(rationale=""),
                        name="reg_sup_rationale_present",
                    ),
                    models.CheckConstraint(
                        condition=~models.Q(idempotency_key=""),
                        name="reg_sup_key_present",
                    ),
                ],
            },
        ),
        migrations.RunPython(
            migrations.RunPython.noop, refuse_reverse_with_supersession_history
        ),
    ]
