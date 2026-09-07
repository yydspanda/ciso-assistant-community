from django.db import migrations
from django.db.models import Q


TPRM_RESPONDENT_ROLE_CODENAME = "BI-RL-TPR"
TPRM_ENCLAVE_CONTENT_TYPE = "EN"


def reject_reserved_service_account_iam(apps, schema_editor):
    """Stop upgrades that would preserve machine access to TPRM authority.

    This is intentionally a preflight, not an automatic repair: changing or
    deleting a principal's effective grants requires an explicit reviewed IAM
    decision outside the migration transaction.
    """

    ServiceAccount = apps.get_model("iam", "ServiceAccount")
    RoleAssignment = apps.get_model("iam", "RoleAssignment")

    service_account_ids = list(
        ServiceAccount.objects.filter(role__name=TPRM_RESPONDENT_ROLE_CODENAME)
        .order_by("id")
        .values_list("id", flat=True)
    )
    role_assignment_ids = list(
        RoleAssignment.objects.filter(user__service_account__isnull=False)
        .filter(
            Q(role__name=TPRM_RESPONDENT_ROLE_CODENAME)
            | Q(folder__content_type=TPRM_ENCLAVE_CONTENT_TYPE)
            | Q(user_group__folder__content_type=TPRM_ENCLAVE_CONTENT_TYPE)
            | Q(perimeter_folders__content_type=TPRM_ENCLAVE_CONTENT_TYPE)
        )
        .distinct()
        .order_by("id")
        .values_list("id", flat=True)
    )
    if not service_account_ids and not role_assignment_ids:
        return

    service_account_sample = ", ".join(str(item) for item in service_account_ids[:20])
    role_assignment_sample = ", ".join(str(item) for item in role_assignment_ids[:20])
    raise RuntimeError(
        "Reserved TPRM IAM is assigned to a service account. The migration "
        "made no changes. Revoke or replace the machine principal's "
        "BI-RL-TPR/enclave assignment through a reviewed IAM remediation, "
        "then rerun the migration. "
        f"service_accounts={len(service_account_ids)} [{service_account_sample}]; "
        f"role_assignments={len(role_assignment_ids)} "
        f"[{role_assignment_sample}]"
    )


class Migration(migrations.Migration):
    dependencies = [
        ("iam", "0027_cleanup_stray_domain_iam_groups"),
    ]

    operations = [
        migrations.RunPython(
            reject_reserved_service_account_iam,
            migrations.RunPython.noop,
        ),
    ]
