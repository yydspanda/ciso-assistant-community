import django.db.models.deletion
from django.db import migrations, models


def snapshot_existing_sync_events(apps, _schema_editor):
    SyncEvent = apps.get_model("integrations", "SyncEvent")
    batch = []
    fields = (
        "mapping_id_snapshot",
        "configuration_id_snapshot",
        "content_type_id_snapshot",
        "local_object_id_snapshot",
        "remote_id_snapshot",
    )
    for event in SyncEvent.objects.select_related("mapping").iterator(chunk_size=500):
        mapping = event.mapping
        event.mapping_id_snapshot = mapping.id
        event.configuration_id_snapshot = mapping.configuration_id
        event.content_type_id_snapshot = mapping.content_type_id
        event.local_object_id_snapshot = mapping.local_object_id
        event.remote_id_snapshot = mapping.remote_id
        batch.append(event)
        if len(batch) == 500:
            SyncEvent.objects.bulk_update(batch, fields, batch_size=500)
            batch.clear()
    if batch:
        SyncEvent.objects.bulk_update(batch, fields, batch_size=500)


class Migration(migrations.Migration):
    dependencies = [
        ("integrations", "0005_syncmapping_int_syncmap_cfg_remote_uniq"),
    ]

    operations = [
        migrations.AddField(
            model_name="syncevent",
            name="mapping_id_snapshot",
            field=models.UUIDField(editable=False, null=True),
        ),
        migrations.AddField(
            model_name="syncevent",
            name="configuration_id_snapshot",
            field=models.UUIDField(editable=False, null=True),
        ),
        migrations.AddField(
            model_name="syncevent",
            name="content_type_id_snapshot",
            field=models.PositiveIntegerField(editable=False, null=True),
        ),
        migrations.AddField(
            model_name="syncevent",
            name="local_object_id_snapshot",
            field=models.UUIDField(editable=False, null=True),
        ),
        migrations.AddField(
            model_name="syncevent",
            name="remote_id_snapshot",
            field=models.CharField(
                blank=True, editable=False, max_length=255, null=True
            ),
        ),
        migrations.RunPython(
            snapshot_existing_sync_events,
            reverse_code=migrations.RunPython.noop,
        ),
        migrations.AlterField(
            model_name="syncevent",
            name="mapping_id_snapshot",
            field=models.UUIDField(editable=False),
        ),
        migrations.AlterField(
            model_name="syncevent",
            name="configuration_id_snapshot",
            field=models.UUIDField(editable=False),
        ),
        migrations.AlterField(
            model_name="syncevent",
            name="content_type_id_snapshot",
            field=models.PositiveIntegerField(editable=False),
        ),
        migrations.AlterField(
            model_name="syncevent",
            name="local_object_id_snapshot",
            field=models.UUIDField(editable=False),
        ),
        migrations.AlterField(
            model_name="syncevent",
            name="remote_id_snapshot",
            field=models.CharField(blank=True, editable=False, max_length=255),
        ),
        migrations.AlterField(
            model_name="syncevent",
            name="mapping",
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.SET_NULL,
                related_name="sync_events",
                to="integrations.syncmapping",
            ),
        ),
        migrations.AlterField(
            model_name="syncevent",
            name="triggered_by",
            field=models.CharField(
                choices=[
                    ("user", "User"),
                    ("webhook", "Webhook"),
                    ("scheduled", "Scheduled"),
                    ("reconciliation", "Reconciliation"),
                ],
                max_length=50,
            ),
        ),
        migrations.AddField(
            model_name="integrationsyncjob",
            name="origin_principal_snapshot",
            field=models.CharField(
                default="legacy:unknown", editable=False, max_length=128
            ),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name="integrationsyncjob",
            name="requested_by_id_snapshot",
            field=models.UUIDField(blank=True, editable=False, null=True),
        ),
        migrations.AddField(
            model_name="integrationsyncjob",
            name="provider_receipt_signing_key_id",
            field=models.CharField(
                blank=True, default="", editable=False, max_length=64
            ),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name="integrationsyncjob",
            name="review_state_hmac_sha256",
            field=models.CharField(
                blank=True, default="", editable=False, max_length=64
            ),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name="integrationsyncjob",
            name="review_state_signing_key_id",
            field=models.CharField(
                blank=True, default="", editable=False, max_length=64
            ),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name="integrationsyncjob",
            name="reconciliation_before_digest",
            field=models.CharField(
                blank=True, default="", editable=False, max_length=64
            ),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name="integrationsyncjob",
            name="reconciliation_after_digest",
            field=models.CharField(
                blank=True, default="", editable=False, max_length=64
            ),
            preserve_default=False,
        ),
        migrations.AlterModelOptions(
            name="integrationsyncjob",
            options={
                "ordering": ["created_at", "id"],
                "permissions": [
                    (
                        "reconcile_integrationsyncjob",
                        "Can reconcile integration sync jobs",
                    )
                ],
            },
        ),
    ]
