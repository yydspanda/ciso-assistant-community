"""Report custom roles that hold the full compliance-assessment view permission."""

import json

from django.contrib.auth.models import Permission
from django.core.management.base import BaseCommand, CommandError

from iam.models import Role


PERMISSION_IDENTITY = {
    "app_label": "core",
    "model": "complianceassessment",
    "codename": "view_compliance_assessment_full",
}


class Command(BaseCommand):
    help = (
        "Read-only audit of non-builtin custom roles that hold the exact "
        "core ComplianceAssessment full-view permission"
    )

    def add_arguments(self, parser):
        parser.add_argument(
            "--json",
            action="store_true",
            dest="as_json",
            help="Emit a machine-readable JSON report",
        )
        parser.add_argument(
            "--fail-if-present",
            action="store_true",
            help="Exit non-zero when at least one matching custom role is present",
        )

    def handle(self, *args, **options):
        permission = (
            Permission.objects.filter(
                content_type__app_label=PERMISSION_IDENTITY["app_label"],
                content_type__model=PERMISSION_IDENTITY["model"],
                codename=PERMISSION_IDENTITY["codename"],
            )
            .only("id")
            .first()
        )
        if permission is None:
            raise CommandError(
                "The exact core.complianceassessment."
                "view_compliance_assessment_full permission does not exist; "
                "verify that database migrations are current."
            )

        roles = list(
            Role.objects.filter(builtin=False, permissions=permission)
            .order_by("name", "id")
            .values("id", "name")
        )
        report = {
            "permission": PERMISSION_IDENTITY,
            "custom_role_count": len(roles),
            "custom_roles": [
                {"id": str(role["id"]), "name": role["name"]} for role in roles
            ],
            "read_only": True,
        }

        if options["as_json"]:
            self.stdout.write(json.dumps(report, indent=2, sort_keys=True))
        else:
            self._write_human_report(report)

        if options["fail_if_present"] and roles:
            raise CommandError(
                f"{len(roles)} non-builtin custom role(s) hold the full-view "
                "permission."
            )

    def _write_human_report(self, report):
        count = report["custom_role_count"]
        if count:
            self.stdout.write(
                self.style.WARNING(
                    f"{count} non-builtin custom role(s) hold the exact "
                    "core.complianceassessment."
                    "view_compliance_assessment_full permission:"
                )
            )
            for role in report["custom_roles"]:
                self.stdout.write(f"- {role['name']} ({role['id']})")
        else:
            self.stdout.write(
                self.style.SUCCESS(
                    "No non-builtin custom roles hold the exact "
                    "core.complianceassessment."
                    "view_compliance_assessment_full permission."
                )
            )
        self.stdout.write("Audit only: no permissions were changed.")
