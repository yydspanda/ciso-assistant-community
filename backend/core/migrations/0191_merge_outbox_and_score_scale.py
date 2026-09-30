from django.db import migrations


class Migration(migrations.Migration):
    dependencies = [
        ("core", "0185_requirementassignmentmailoutbox"),
        ("core", "0190_compliance_assessment_score_scale"),
    ]

    operations = [
        migrations.RemoveField(
            model_name="requirementassignmentmailoutbox",
            name="is_published",
        ),
    ]
