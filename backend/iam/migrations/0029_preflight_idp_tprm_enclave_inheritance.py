from django.db import migrations
from django.db.models import Q


TPRM_RESPONDENT_ROLE_CODENAME = "BI-RL-TPR"
TPRM_ENCLAVE_CONTENT_TYPE = "EN"


def reject_idp_tprm_enclave_inheritance(apps, schema_editor):
    """Refuse to preserve IdP-derived access to TPRM respondent authority.

    This migration intentionally performs no repair.  Removing an IdP mapping
    or changing a role assignment changes effective human access and therefore
    requires an explicit, reviewed IAM decision outside schema migration.
    """

    IdPGroup = apps.get_model("iam", "IdPGroup")
    RoleAssignment = apps.get_model("iam", "RoleAssignment")
    UserGroup = apps.get_model("iam", "UserGroup")

    dangerous_group_ids = set(
        UserGroup.objects.filter(
            folder__content_type=TPRM_ENCLAVE_CONTENT_TYPE
        ).values_list("id", flat=True)
    )
    dangerous_group_ids.update(
        RoleAssignment.objects.filter(user_group__isnull=False)
        .filter(
            Q(role__name=TPRM_RESPONDENT_ROLE_CODENAME)
            | Q(folder__content_type=TPRM_ENCLAVE_CONTENT_TYPE)
            | Q(user_group__folder__content_type=TPRM_ENCLAVE_CONTENT_TYPE)
            | Q(perimeter_folders__content_type=TPRM_ENCLAVE_CONTENT_TYPE)
        )
        .distinct()
        .values_list("user_group_id", flat=True)
    )
    if not dangerous_group_ids:
        return

    mapping_field = IdPGroup._meta.get_field("user_groups")
    mapping_through = mapping_field.remote_field.through
    mapping_source = mapping_field.m2m_field_name()
    mapping_target = mapping_field.m2m_reverse_field_name()
    damaged_pairs = list(
        mapping_through.objects.filter(
            **{f"{mapping_target}_id__in": dangerous_group_ids}
        )
        .order_by(f"{mapping_source}_id", f"{mapping_target}_id")
        .values_list(f"{mapping_source}_id", f"{mapping_target}_id")
    )
    if not damaged_pairs:
        return

    sample = ", ".join(
        f"{idp_group_id}:{user_group_id}"
        for idp_group_id, user_group_id in damaged_pairs[:20]
    )
    raise RuntimeError(
        "An IdP group inherits reserved TPRM respondent/enclave authority. "
        "The migration made no changes. Through a reviewed IAM remediation, "
        "remove each IdPGroup.user_groups mapping to the reserved group or "
        "replace the offending role assignment; do not use SCIM membership, "
        "TPRM respondent sync, or enclave deletion as a repair path. Then "
        "rerun the migration. "
        f"mappings={len(damaged_pairs)} [{sample}]"
    )


class Migration(migrations.Migration):
    dependencies = [
        ("iam", "0028_preflight_service_account_reserved_iam"),
    ]

    operations = [
        migrations.RunPython(
            reject_idp_tprm_enclave_inheritance,
            migrations.RunPython.noop,
        ),
    ]
