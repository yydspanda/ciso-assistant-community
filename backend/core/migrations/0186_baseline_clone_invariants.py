from django.db import migrations, models


def reject_duplicate_requirement_assessments(apps, schema_editor):
    """Refuse an ambiguous ownership graph; never pick a row to keep silently."""

    RequirementAssessment = apps.get_model("core", "RequirementAssessment")
    duplicates = (
        RequirementAssessment.objects.values(
            "compliance_assessment_id",
            "requirement_id",
        )
        .annotate(row_count=models.Count("id"))
        .filter(row_count__gt=1)
    )
    duplicate_key_count = duplicates.count()
    if duplicate_key_count:
        raise RuntimeError(
            "Cannot enforce requirement-assessment ownership uniqueness: "
            f"found {duplicate_key_count} duplicate ownership key(s). "
            "Resolve each duplicate explicitly, preserving its answers, relations "
            "and audit evidence, then rerun the migration."
        )


class Migration(migrations.Migration):
    dependencies = [
        ("core", "0185_requirementassignmentmailoutbox"),
    ]

    operations = [
        # Run the lossless preflight before any DDL.  This matters on database
        # backends where schema changes cannot be rolled back atomically: an
        # ambiguous legacy graph must leave the schema untouched.
        migrations.RunPython(
            reject_duplicate_requirement_assessments,
            migrations.RunPython.noop,
        ),
        migrations.AlterField(
            model_name="complianceassessment",
            name="computed_outcome",
            field=models.JSONField(blank=True, editable=False, null=True),
        ),
        migrations.AddField(
            model_name="complianceassessment",
            name="baseline_source_assessment_id_snapshot",
            field=models.UUIDField(
                blank=True,
                db_index=True,
                editable=False,
                null=True,
            ),
        ),
        migrations.AddField(
            model_name="complianceassessment",
            name="baseline_snapshot_sha256",
            field=models.CharField(
                blank=True,
                editable=False,
                max_length=64,
                null=True,
            ),
        ),
        migrations.AddField(
            model_name="complianceassessment",
            name="baseline_copied_by_id_snapshot",
            field=models.UUIDField(blank=True, editable=False, null=True),
        ),
        migrations.AddField(
            model_name="complianceassessment",
            name="baseline_copied_at",
            field=models.DateTimeField(blank=True, editable=False, null=True),
        ),
        migrations.AddConstraint(
            model_name="requirementassessment",
            constraint=models.UniqueConstraint(
                fields=("compliance_assessment", "requirement"),
                name="uniq_ra_assessment_requirement",
            ),
        ),
    ]
