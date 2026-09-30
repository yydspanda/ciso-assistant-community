"""Explicit, synthetic-browser-test setup; never imported by application startup.

Community exposes a read-only role catalog. Browser setup therefore creates the
minimal role definition here, while the browser itself uses the normal IAM API
to assign and remove its own nonrecursive grant. This creates no assignment,
changes no builtin/default role, and is not a production provisioning interface.
The explicit opt-in prevents accidental invocation; it is not proof that a
database is synthetic. Callers must own and verify their test database.
"""

from django.contrib.auth.models import Permission
from django.db import transaction

from iam.models import Folder, Role

TPRM_TEMPLATE_READER_ROLE = "CFGRC synthetic TPRM template reader 20260930"
TPRM_TEMPLATE_READ_PERMISSIONS = (
    ("framework", "view_framework"),
    ("requirementnode", "view_requirementnode"),
    ("question", "view_question"),
    ("questionchoice", "view_questionchoice"),
)


def seed_tprm_template_reader(*, synthetic_test_database: bool = False) -> Role:
    """Create/verify exactly one unassigned, Root-only four-permission role.

    Reject a colliding or altered definition rather than repairing or broadening
    it. The Root lock serializes this test-only seed on a shared test database.
    """
    if synthetic_test_database is not True:
        raise ValueError("An explicitly verified synthetic test database is required")

    with transaction.atomic():
        root = Folder.objects.select_for_update().get(
            content_type=Folder.ContentType.ROOT, builtin=True
        )
        permissions = [
            Permission.objects.get(
                content_type__app_label="core",
                content_type__model=model,
                codename=codename,
            )
            for model, codename in TPRM_TEMPLATE_READ_PERMISSIONS
        ]
        existing = list(
            Role.objects.select_for_update().filter(name=TPRM_TEMPLATE_READER_ROLE)[:2]
        )
        if len(existing) > 1:
            raise ValueError("Duplicate synthetic template-reader role definitions")
        if existing:
            role = existing[0]
            if (
                role.builtin
                or role.folder_id != root.pk
                or set(role.permissions.values_list("pk", flat=True))
                != {permission.pk for permission in permissions}
            ):
                raise ValueError("Synthetic template-reader role contract mismatch")
            return role

        role = Role.objects.create(
            name=TPRM_TEMPLATE_READER_ROLE, folder=root, builtin=False
        )
        role.permissions.set(permissions)
        return role
