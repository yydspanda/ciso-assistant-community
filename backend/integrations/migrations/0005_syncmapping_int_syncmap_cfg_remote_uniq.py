import unicodedata

from django.db import migrations, models


def _canonical_remote_id(provider_name, remote_id):
    normalized = unicodedata.normalize("NFKC", remote_id).strip()
    if (
        not normalized
        or len(normalized) > 255
        or not normalized.isprintable()
        or any(character.isspace() for character in normalized)
    ):
        raise ValueError
    provider_key = unicodedata.normalize("NFKC", provider_name or "").strip().casefold()
    if provider_key == "jira":
        return normalized.upper()
    if provider_key == "servicenow":
        return normalized.lower()
    return normalized


def canonicalize_and_assert_unique_nonblank_remote_ids(apps, _schema_editor):
    SyncMapping = apps.get_model("integrations", "SyncMapping")
    rows = list(
        SyncMapping.objects.exclude(remote_id="")
        .select_related("configuration__provider")
        .order_by("configuration_id", "id")
    )
    seen = {}
    invalid_ids = []
    collision_ids = set()
    changed = []
    for mapping in rows:
        try:
            canonical = _canonical_remote_id(
                mapping.configuration.provider.name,
                mapping.remote_id,
            )
        except (TypeError, ValueError):
            invalid_ids.append(str(mapping.id))
            continue
        identity = (mapping.configuration_id, canonical)
        previous_id = seen.get(identity)
        if previous_id is not None:
            collision_ids.update((str(previous_id), str(mapping.id)))
            continue
        seen[identity] = mapping.id
        if canonical != mapping.remote_id:
            mapping.remote_id = canonical
            changed.append(mapping)

    if invalid_ids or collision_ids:
        details = []
        if invalid_ids:
            details.append(
                "invalid mapping UUIDs=" + ",".join(sorted(invalid_ids)[:20])
            )
        if collision_ids:
            details.append(
                "canonical-collision mapping UUIDs="
                + ",".join(sorted(collision_ids)[:20])
            )
        raise RuntimeError(
            "Cannot canonicalize integration remote IDs safely. Resolve the "
            "listed internal SyncMapping rows before retrying this migration; "
            + "; ".join(details)
        )
    if changed:
        SyncMapping.objects.bulk_update(changed, ["remote_id"], batch_size=500)


class Migration(migrations.Migration):
    dependencies = [
        ("contenttypes", "0002_remove_content_type_name"),
        ("iam", "0027_cleanup_stray_domain_iam_groups"),
        ("integrations", "0004_integrationsyncjob"),
    ]

    operations = [
        migrations.RunPython(
            canonicalize_and_assert_unique_nonblank_remote_ids,
            reverse_code=migrations.RunPython.noop,
        ),
        migrations.AddConstraint(
            model_name="syncmapping",
            constraint=models.UniqueConstraint(
                condition=~models.Q(remote_id=""),
                fields=("configuration", "remote_id"),
                name="int_syncmap_cfg_remote_uniq",
            ),
        ),
    ]
