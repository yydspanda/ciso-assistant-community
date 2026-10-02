"""Explicit, synthetic-browser-test setup; never imported by application startup.

Community exposes a read-only role catalog. Browser setup therefore creates the
minimal role definition here, while the browser itself uses the normal IAM API
to assign and remove its respondent's nonrecursive grant. A separate explicit
setup function gives only the named synthetic administrator Root RA create/delete
permission. Neither function changes builtin/default roles, and neither is a
production provisioning interface.
The explicit opt-in prevents accidental invocation; it is not proof that a
database is synthetic. Callers must own and verify their test database.
"""

from django.contrib.auth.models import Permission
from django.db import transaction

from iam.models import Folder, Role, RoleAssignment, User

TPRM_TEMPLATE_READER_ROLE = "CFGRC synthetic TPRM template reader 20260930"
TPRM_TEMPLATE_READ_PERMISSIONS = (
    ("framework", "view_framework"),
    ("requirementnode", "view_requirementnode"),
    ("question", "view_question"),
    ("questionchoice", "view_questionchoice"),
)
TPRM_FIXTURE_ADMIN_ROLE = "CFGRC synthetic TPRM fixture administrator 20260930"
TPRM_FIXTURE_ADMIN_GRANT = "CFGRC synthetic TPRM fixture administrator grant 20260930"
TPRM_FIXTURE_ADMIN_PERMISSIONS = ("add_roleassignment", "delete_roleassignment")


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


def seed_tprm_browser_admin_grant(
    *, synthetic_admin_email: str, synthetic_test_database: bool = False
) -> RoleAssignment:
    """Explicitly grant only Root RA create/delete to the named test admin.

    Community's normal admin role deliberately has only RA read permission.
    This test-only setup keeps that production role unchanged and lets the
    browser exercise the normal IAM API with a separately recorded explicit
    grant. It neither grants the respondent nor changes any default role.
    """
    if synthetic_test_database is not True:
        raise ValueError("An explicitly verified synthetic test database is required")
    if synthetic_admin_email not in ("admin@tests.com", "browser-admin@example.test"):
        raise ValueError("Only a named synthetic browser administrator is supported")

    with transaction.atomic():
        root = Folder.objects.select_for_update().get(
            content_type=Folder.ContentType.ROOT, builtin=True
        )
        try:
            admin = User.objects.select_for_update().get(
                email=synthetic_admin_email, is_active=True, is_superuser=True
            )
        except User.DoesNotExist as exc:
            raise ValueError(
                "The named synthetic browser administrator is unavailable"
            ) from exc
        permission_ids = {
            Permission.objects.get(
                content_type__app_label="iam",
                content_type__model="roleassignment",
                codename=codename,
            ).pk
            for codename in TPRM_FIXTURE_ADMIN_PERMISSIONS
        }
        roles = list(Role.objects.filter(name=TPRM_FIXTURE_ADMIN_ROLE)[:2])
        if len(roles) > 1:
            raise ValueError("Duplicate synthetic fixture-administrator definitions")
        if roles:
            role = roles[0]
            if (
                role.builtin
                or role.folder_id != root.pk
                or set(role.permissions.values_list("pk", flat=True)) != permission_ids
            ):
                raise ValueError(
                    "Synthetic fixture-administrator role contract mismatch"
                )
        else:
            role = Role.objects.create(name=TPRM_FIXTURE_ADMIN_ROLE, folder=root)
            role.permissions.set(permission_ids)
        assignments = list(
            RoleAssignment.objects.filter(name=TPRM_FIXTURE_ADMIN_GRANT)[:2]
        )
        if len(assignments) > 1:
            raise ValueError("Duplicate synthetic fixture-administrator grants")
        if assignments:
            assignment = assignments[0]
            if (
                assignment.builtin
                or assignment.user_id != admin.pk
                or assignment.user_group_id is not None
                or assignment.role_id != role.pk
                or assignment.folder_id != root.pk
                or assignment.is_recursive
                or set(assignment.perimeter_folders.values_list("pk", flat=True))
                != {root.pk}
            ):
                raise ValueError(
                    "Synthetic fixture-administrator grant contract mismatch"
                )
            return assignment
        assignment = RoleAssignment.objects.create(
            name=TPRM_FIXTURE_ADMIN_GRANT,
            user=admin,
            user_group=None,
            role=role,
            folder=root,
            is_recursive=False,
            builtin=False,
        )
        assignment.perimeter_folders.set([root])
        return assignment
