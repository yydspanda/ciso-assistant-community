"""Hermetic harness regressions, not a substitute for live PostgreSQL gates."""

from __future__ import annotations

import ast
import hashlib
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
POSTGRESQL_ROOT = REPOSITORY_ROOT / "tools/china_financial_grc/postgresql"
FIXTURE_PATH = POSTGRESQL_ROOT / "acceptance_fixture.py"
SCRIPT_PATH = POSTGRESQL_ROOT / "run_acceptance.sh"


def fixture_functions() -> dict:
    """Load the real helper bodies without Django setup or database access."""

    function_names = {
        "_require",
        "_jsonable",
        "_canonical_sha256",
        "_guard_acceptance_database",
        "_legacy_0004_fingerprint",
    }
    constant_names = {
        "ACCEPTANCE_DATABASES",
        "LEGACY_ROLLBACK_DATABASE",
        "LEGACY_REGULATORY_MIGRATIONS",
    }
    tree = ast.parse(FIXTURE_PATH.read_text(encoding="utf-8"))
    selected = [
        node
        for node in tree.body
        if (isinstance(node, ast.FunctionDef) and node.name in function_names)
        or (
            isinstance(node, ast.Assign)
            and any(
                isinstance(target, ast.Name) and target.id in constant_names
                for target in node.targets
            )
        )
    ]
    namespace = {
        "hashlib": hashlib,
        "json": json,
        "os": os,
        "DjangoJSONEncoder": json.JSONEncoder,
    }
    # Execute only explicit helpers from the repository-owned fixture, not inputs.
    exec(
        compile(ast.Module(body=selected, type_ignores=[]), str(FIXTURE_PATH), "exec"),
        namespace,
    )  # noqa: S102
    return namespace


def historical_model(name: str, rows: list[dict]) -> SimpleNamespace:
    manager = mock.Mock()
    manager.order_by.return_value.values.return_value = rows
    return SimpleNamespace(
        _meta=SimpleNamespace(
            label=f"regulatory.{name}",
            label_lower=f"regulatory.{name.lower()}",
            db_table=f"regulatory_{name.lower()}",
        ),
        objects=manager,
    )


class LegacyFingerprintTests(unittest.TestCase):
    def setUp(self) -> None:
        self.namespace = fixture_functions()
        self.document = historical_model("RegulatoryDocument", [{"id": "document"}])
        self.review = historical_model(
            "RegulatoryApplicabilityReviewDisposition",
            [{"id": "review", "sequence": 1, "decision_id": "decision"}],
        )
        self.connection = mock.Mock()
        self.connection.vendor = "postgresql"
        self.connection.settings_dict = {
            "NAME": self.namespace["LEGACY_ROLLBACK_DATABASE"]
        }
        self.connection.introspection.table_names.return_value = [
            self.document._meta.db_table,
            self.review._meta.db_table,
            "django_migrations",
        ]
        self.applied = [
            ("regulatory", name)
            for name in self.namespace["LEGACY_REGULATORY_MIGRATIONS"]
        ]
        self.recorder = mock.Mock()
        self.migration_query = self.recorder.Migration.objects.filter.return_value
        self.migration_query.order_by.return_value.values_list.return_value = (
            self.applied
        )
        self.historical_apps = mock.Mock()
        self.historical_apps.get_app_config.return_value.get_models.return_value = [
            self.review,
            self.document,
        ]
        self.loader = mock.Mock()
        self.loader.return_value.project_state.return_value.apps = self.historical_apps
        self.log_entry = mock.Mock()
        self.audit_query = (
            self.log_entry.objects.filter.return_value.order_by.return_value
        )
        self.audit_query.values.return_value = [{"id": 1, "changes": "synthetic"}]
        self.contract = mock.Mock(return_value={"regulatory_migrations": self.applied})
        self.namespace.update(
            connection=self.connection,
            MigrationRecorder=self.recorder,
            MigrationLoader=self.loader,
            LogEntry=self.log_entry,
            _database_contract_state=self.contract,
        )

    def fingerprint(self) -> dict:
        return self.namespace["_legacy_0004_fingerprint"]()

    def test_uses_exact_historical_state_and_hashes_rows_audit_and_contract(
        self,
    ) -> None:
        result = self.fingerprint()

        self.loader.assert_called_once_with(self.connection)
        self.loader.return_value.project_state.assert_called_once_with(
            [("regulatory", "0004_regulatoryapplicabilityreviewdisposition")]
        )
        self.assertEqual(result["regulatory_migration_leaf"], self.applied[-1][1])
        self.assertEqual(result["counts"][self.review._meta.label_lower], 1)
        self.assertEqual(
            set(result["state_component_sha256"]),
            {
                self.document._meta.label_lower,
                self.review._meta.label_lower,
                "auditlog.regulatory_entries",
                "database.contract",
            },
        )

    def test_migration_registry_matches_actual_legacy_files(self) -> None:
        actual = sorted(
            path.stem
            for path in (REPOSITORY_ROOT / "backend/regulatory/migrations").glob(
                "000[1-4]_*.py"
            )
        )
        self.assertEqual(list(self.namespace["LEGACY_REGULATORY_MIGRATIONS"]), actual)

    def test_rejects_wrong_database_before_queries(self) -> None:
        self.connection.settings_dict["NAME"] = "ciso_regulatory_acceptance"
        with self.assertRaisesRegex(RuntimeError, "restricted to the legacy"):
            self.fingerprint()
        self.recorder.Migration.objects.filter.assert_not_called()

    def test_requires_exact_four_applied_migrations(self) -> None:
        for applied in (
            self.applied[:-1],
            self.applied + [("regulatory", "0005_regulatoryversionsupersessionevent")],
            self.applied[1:],
        ):
            with self.subTest(applied=applied):
                self.migration_query.order_by.return_value.values_list.return_value = (
                    applied
                )
                with self.assertRaisesRegex(
                    RuntimeError, "exactly regulatory migrations"
                ):
                    self.fingerprint()

    def test_requires_exact_historical_tables_and_never_masks_missing_tables(
        self,
    ) -> None:
        expected = [self.document._meta.db_table, self.review._meta.db_table]
        for tables in (
            expected[:-1],
            expected[1:],
            expected + ["regulatory_regulatoryversionsupersessionevent"],
        ):
            with self.subTest(tables=tables):
                self.connection.introspection.table_names.return_value = tables
                with self.assertRaisesRegex(
                    RuntimeError, "exactly match the historical"
                ):
                    self.fingerprint()

    def test_requires_populated_review_history(self) -> None:
        self.review.objects.order_by.return_value.values.return_value = []
        with self.assertRaisesRegex(RuntimeError, "requires populated"):
            self.fingerprint()

    def test_query_errors_are_not_treated_as_an_absent_optional_table(self) -> None:
        self.review.objects.order_by.return_value.values.side_effect = RuntimeError(
            "relation does not exist"
        )
        with self.assertRaisesRegex(RuntimeError, "relation does not exist"):
            self.fingerprint()

    def test_any_row_audit_or_contract_change_changes_fingerprint(self) -> None:
        original = self.fingerprint()["state_sha256"]
        self.review.objects.order_by.return_value.values.return_value[0]["sequence"] = 2
        self.assertNotEqual(original, self.fingerprint()["state_sha256"])
        self.review.objects.order_by.return_value.values.return_value[0]["sequence"] = 1
        self.audit_query.values.return_value[0]["changes"] = "changed"
        self.assertNotEqual(original, self.fingerprint()["state_sha256"])
        self.audit_query.values.return_value[0]["changes"] = "synthetic"
        self.contract.return_value["grants"] = ["changed"]
        self.assertNotEqual(original, self.fingerprint()["state_sha256"])

    def test_database_guard_separates_legacy_inspection_from_current_commands(
        self,
    ) -> None:
        guard = self.namespace["_guard_acceptance_database"]
        with mock.patch.dict(
            os.environ, {"CHINA_GRC_POSTGRES_ACCEPTANCE": "1"}, clear=True
        ):
            guard(legacy_0004=True)
            with self.assertRaises(SystemExit):
                guard()
            for database in self.namespace["ACCEPTANCE_DATABASES"]:
                self.connection.settings_dict["NAME"] = database
                guard()
                with self.assertRaises(SystemExit):
                    guard(legacy_0004=True)
            self.connection.settings_dict["NAME"] = "production"
            with self.assertRaises(SystemExit):
                guard()
            self.connection.settings_dict["NAME"] = self.namespace[
                "LEGACY_ROLLBACK_DATABASE"
            ]
            self.connection.vendor = "sqlite"
            with self.assertRaises(SystemExit):
                guard(legacy_0004=True)
        self.connection.vendor = "postgresql"
        with mock.patch.dict(os.environ, {}, clear=True), self.assertRaises(SystemExit):
            guard(legacy_0004=True)


class LegacyShellProbeTests(unittest.TestCase):
    def run_probe(
        self, scenario: str
    ) -> tuple[subprocess.CompletedProcess[str], list[str]]:
        script = SCRIPT_PATH.read_text(encoding="utf-8")
        function = (
            "verify_legacy_review_reverse() {"
            + script.split("verify_legacy_review_reverse() {", 1)[1].split("\n}\n", 1)[
                0
            ]
            + "\n}\n"
        )
        # This invokes the actual shell probe, with database commands replaced by
        # hermetic stateful stubs. No Docker, database, credential or key is read.
        stub = r"""
set -Eeuo pipefail
evidence_dir=$1
scenario=$2
database_name=ciso_regulatory_acceptance
legacy_rollback_database=ciso_regulatory_acceptance_legacy_rollback
migrator_role=synthetic_migrator
migrator_password=synthetic_unused
legacy_leaf=0005
legacy_state=stable
source_state=stable
run_fixture() {
    printf 'fixture %s %s\n' "$1" "$2" >> "$evidence_dir/calls"
    if [[ "$1" == verify ]]; then
        [[ "$2" == "$database_name" ]]
        printf '%s\n' "$source_state" > "$3"
    else
        [[ "$1" == verify-legacy-0004 && "$2" == "$legacy_rollback_database" ]]
        [[ "$legacy_leaf" == 0004 ]]
        if [[ "$scenario" == fingerprint-fails && "$3" == *after.json ]]; then
            return 1
        fi
        printf '%s\n' "$legacy_state" > "$3"
    fi
}
create_owned_database() {
    [[ "$1" == "$legacy_rollback_database" && "$2" == "$database_name" ]]
    printf 'clone %s %s\n' "$1" "$2" >> "$evidence_dir/calls"
}
apply_grants() {
    [[ "$1" == "$legacy_rollback_database" ]]
}
run_manage() {
    printf 'migrate %s %s\n' "$1" "$6" >> "$evidence_dir/calls"
    [[ "$1" == "$legacy_rollback_database" && "$4" == migrate && "$5" == regulatory ]]
    if [[ "$6" == 0004 ]]; then
        if [[ "$scenario" == empty-reverse-fails ]]; then
            return 1
        fi
        legacy_leaf=0004
        return 0
    fi
    [[ "$6" == 0003 ]]
    if [[ "$scenario" == unexpected-success ]]; then
        return 0
    fi
    if [[ "$scenario" == wrong-reason ]]; then
        echo 'ProgrammingError: relation does not exist'
        return 1
    fi
    if [[ "$scenario" == partial-legacy-change ]]; then
        legacy_state=changed
    fi
    if [[ "$scenario" == source-changed ]]; then
        source_state=changed
    fi
    printf '%s%s\n' 'RuntimeError: Cannot remove regulatory applicability review ' \
        'history; retain migration 0004.'
    return 1
}
"""
        with tempfile.TemporaryDirectory() as temporary:
            (Path(temporary) / "seed-fingerprint.json").write_text(
                "changed\n" if scenario == "seed-changed" else "stable\n",
                encoding="utf-8",
            )
            result = subprocess.run(
                [
                    "bash",
                    "-c",
                    stub + function + "verify_legacy_review_reverse\n",
                    "probe",
                    temporary,
                    scenario,
                ],
                check=False,
                capture_output=True,
                text=True,
                env={"PATH": os.environ.get("PATH", "")},
            )
            calls_path = Path(temporary) / "calls"
            calls = (
                calls_path.read_text(encoding="utf-8").splitlines()
                if calls_path.exists()
                else []
            )
        return result, calls

    def test_exact_guard_succeeds_only_on_clone_and_source_is_verified_twice(
        self,
    ) -> None:
        result, calls = self.run_probe("success")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            calls,
            [
                "fixture verify ciso_regulatory_acceptance",
                "clone ciso_regulatory_acceptance_legacy_rollback "
                "ciso_regulatory_acceptance",
                "migrate ciso_regulatory_acceptance_legacy_rollback 0004",
                "fixture verify-legacy-0004 ciso_regulatory_acceptance_legacy_rollback",
                "migrate ciso_regulatory_acceptance_legacy_rollback 0003",
                "fixture verify-legacy-0004 ciso_regulatory_acceptance_legacy_rollback",
                "fixture verify ciso_regulatory_acceptance",
            ],
        )

    def test_wrong_guard_reason_or_unexpected_success_fails(self) -> None:
        for scenario, message in (
            ("wrong-reason", "other than the exact review-history guard"),
            ("unexpected-success", "unexpectedly succeeded"),
            ("partial-legacy-change", "changed historical rows"),
            ("source-changed", "changed the full-graph source fingerprint"),
            ("seed-changed", "differs from the seeded state"),
        ):
            with self.subTest(scenario=scenario):
                result, _ = self.run_probe(scenario)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(message, result.stderr)

    def test_empty_reverse_or_fingerprint_failures_are_not_swallowed(self) -> None:
        for scenario in ("empty-reverse-fails", "fingerprint-fails"):
            with self.subTest(scenario=scenario):
                result, calls = self.run_probe(scenario)
                self.assertNotEqual(result.returncode, 0)
                self.assertNotEqual(
                    calls[-1], "fixture verify ciso_regulatory_acceptance"
                )

    def test_key_isolation_is_pinned_before_any_django_subprocess(self) -> None:
        script = SCRIPT_PATH.read_text(encoding="utf-8")
        key_export = (
            'export IDP_OIDC_PRIVATE_KEY_FILE="$evidence_dir/idp_oidc_private_key.pem"'
        )
        self.assertIn('export IDP_OIDC_PRIVATE_KEY=""', script)
        self.assertLess(script.index(key_export), script.index("run_manage() {"))
        self.assertIn("! -name '*.pem'", script)
        workflow = (
            REPOSITORY_ROOT
            / ".github/workflows/china-financial-grc-postgresql-acceptance.yml"
        ).read_text(encoding="utf-8")
        self.assertIn("!${{ runner.temp }}/ciso-china-grc-postgresql-*/*.pem", workflow)


if __name__ == "__main__":
    unittest.main()
