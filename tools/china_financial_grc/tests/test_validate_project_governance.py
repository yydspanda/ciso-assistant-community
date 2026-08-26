import contextlib
import io
import re
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tools.china_financial_grc import validate_project_governance as validator


STAGES = "\n".join(f"| `CFGRC-P{number}` | Phase {number} |" for number in range(6))
ROADMAP = f"""# Delivery roadmap

## Stage registry

| Stage ID | Outcome |
| --- | --- |
{STAGES}

## Task registry

| Task ID | Stage | Outcome |
| --- | --- | --- |
| `CFGRC-P0-FOUNDATION` | `CFGRC-P0` | Establish the foundation. |
| `CFGRC-P1-REGISTER` | `CFGRC-P1` | Deliver the register. |
| `CFGRC-GOV-LEDGER` | `CFGRC-P1` | Govern the ledger. |
| `CFGRC-P2-POLICY` | `CFGRC-P2` | Bridge policy and controls. |
"""

PROGRESS = """# Progress

- Current Stage: `CFGRC-P1`
- In Progress Task: `CFGRC-P1-REGISTER`

## Current status

The current bounded work is registered as `CFGRC-P1-REGISTER`.

## Task board

| Task ID | State | Next evidence |
| --- | --- | --- |
| `CFGRC-P1-REGISTER` | In Progress | Named acceptance charter. |
| `CFGRC-GOV-LEDGER` | Pending | CI run. |

## Recent records

| Completed | Record ID | Task IDs | Archive |
| --- | --- | --- | --- |
| 2026-08-26 | [CFGRC-REC-20260826-01](progress-archive/2026-08.md#cfgrc-rec-20260826-01) | `CFGRC-GOV-LEDGER`, `CFGRC-P1-REGISTER` | Governance checks passed. |
| 2026-08-25 | [CFGRC-REC-20260825-01](progress-archive/2026-08.md#cfgrc-rec-20260825-01) | `CFGRC-P1-REGISTER` | Register checks passed. |
"""

ARCHIVE = """# 2026-08 completed work

Historical verification prose may exist outside canonical records.

### CFGRC-REC-20260826-01

- Completed: `2026-08-26`
- Task IDs: `CFGRC-GOV-LEDGER`, `CFGRC-P1-REGISTER`

Implemented deterministic governance checks.

#### CFGRC-EXP-202608-001

- Task ID: `CFGRC-GOV-LEDGER`
- Upstream commit: `1111111111111111111111111111111111111111`
- Model: `example/model@immutable-revision`
- Model SHA-256: `sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa`
- Config SHA-256: `sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb`
- Data SHA-256: `sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc`
- Hardware: `CPU=x86_64; RAM=16GiB; GPU=none`
- Command: `python tools/run_experiment.py --config example.json`
- Metrics: `{"accuracy":0.9,"latency_ms":12}`

### CFGRC-REC-20260825-01

- Completed: `2026-08-25`
- Task IDs: `CFGRC-P1-REGISTER`

Verified the bounded register slice.
"""


class ProjectGovernanceValidationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary_directory.name)
        self.roadmap = self.root / "delivery-roadmap.md"
        self.progress = self.root / "progress.md"
        self.archive_dir = self.root / "progress-archive"
        self.archive_dir.mkdir()
        self.august_archive = self.archive_dir / "2026-08.md"
        self.write(self.roadmap, ROADMAP)
        self.write(self.progress, PROGRESS)
        self.write(self.august_archive, ARCHIVE)

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    @staticmethod
    def write(path: Path, value: str) -> None:
        path.write_text(value.rstrip("\n") + "\n", encoding="utf-8")

    @staticmethod
    def replace(path: Path, old: str, new: str, count: int = -1) -> None:
        value = path.read_text(encoding="utf-8")
        if old not in value:
            raise AssertionError(f"mutation source not found: {old!r}")
        path.write_text(value.replace(old, new, count), encoding="utf-8")

    def validate(self) -> validator.GovernanceSummary:
        return validator.validate_project_governance(
            roadmap_path=self.roadmap,
            progress_path=self.progress,
            archive_dir=self.archive_dir,
        )

    def assert_invalid(self, pattern: str) -> None:
        with self.assertRaisesRegex(validator.GovernanceValidationError, pattern):
            self.validate()

    def test_valid_governance_contract_passes(self) -> None:
        summary = self.validate()
        self.assertEqual(summary.stages, 6)
        self.assertEqual(summary.tasks, 4)
        self.assertEqual(summary.active_task, "CFGRC-P1-REGISTER")
        self.assertEqual(summary.recent_records, 2)
        self.assertEqual(summary.archived_records, 2)
        self.assertEqual(summary.experiments, 1)

    def test_cli_reports_clear_success_and_failure(self) -> None:
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            status = validator.main(
                [
                    "--roadmap",
                    str(self.roadmap),
                    "--progress",
                    str(self.progress),
                    "--archive-dir",
                    str(self.archive_dir),
                ]
            )
        self.assertEqual(status, 0)
        self.assertIn("PASS — project governance", stdout.getvalue())

        self.replace(self.progress, "- Current Stage:", "- Broken Stage:")
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            status = validator.main(
                [
                    "--roadmap",
                    str(self.roadmap),
                    "--progress",
                    str(self.progress),
                    "--archive-dir",
                    str(self.archive_dir),
                ]
            )
        self.assertEqual(status, 1)
        self.assertIn("FAIL —", stderr.getvalue())

    def test_stage_registry_must_contain_all_six_unique_stages(self) -> None:
        self.replace(self.roadmap, "| `CFGRC-P5` | Phase 5 |\n", "")
        self.assert_invalid("stage registry must contain exactly")

    def test_stage_registry_rejects_duplicate_id(self) -> None:
        self.replace(
            self.roadmap,
            "| `CFGRC-P5` | Phase 5 |",
            "| `CFGRC-P4` | Phase 5 |",
        )
        self.assert_invalid("duplicate stage registry ID")

    def test_task_registry_rejects_duplicate_id(self) -> None:
        self.replace(
            self.roadmap,
            "| `CFGRC-P2-POLICY` | `CFGRC-P2` | Bridge policy and controls. |",
            "| `CFGRC-P1-REGISTER` | `CFGRC-P2` | Duplicate. |",
        )
        self.assert_invalid("duplicate task registry ID")

    def test_task_registry_requires_registered_stage_in_second_cell(self) -> None:
        self.replace(
            self.roadmap,
            "| `CFGRC-P2-POLICY` | `CFGRC-P2` |",
            "| `CFGRC-P2-POLICY` | `CFGRC-P9` |",
        )
        self.assert_invalid("invalid ID 'CFGRC-P9'")

    def test_current_stage_pointer_is_exactly_once(self) -> None:
        self.replace(
            self.progress,
            "- Current Stage: `CFGRC-P1`",
            "- Current Stage: `CFGRC-P1`\n- Current Stage: `CFGRC-P1`",
        )
        self.assert_invalid("exactly one 'Current Stage' pointer, found 2")

    def test_current_stage_pointer_requires_exact_format(self) -> None:
        self.replace(
            self.progress,
            "- Current Stage: `CFGRC-P1`",
            "- Current Stage: CFGRC-P1",
        )
        self.assert_invalid("malformed 'Current Stage' pointer")

    def test_pointer_allows_one_human_readable_description(self) -> None:
        self.replace(
            self.progress,
            "- Current Stage: `CFGRC-P1`",
            "- Current Stage: `CFGRC-P1` — one-entity register",
        )
        self.replace(
            self.progress,
            "- In Progress Task: `CFGRC-P1-REGISTER`",
            "- In Progress Task: `CFGRC-P1-REGISTER` — target acceptance",
        )
        self.validate()

    def test_in_progress_pointer_is_exactly_once(self) -> None:
        self.replace(
            self.progress,
            "- In Progress Task: `CFGRC-P1-REGISTER`",
            "- In Progress Task: `CFGRC-P1-REGISTER`\n"
            "- In Progress Task: `CFGRC-GOV-LEDGER`",
        )
        self.assert_invalid("exactly one 'In Progress Task' pointer, found 2")

    def test_in_progress_task_must_be_registered(self) -> None:
        self.replace(
            self.progress,
            "CFGRC-P1-REGISTER",
            "CFGRC-P1-NOT-REGISTERED",
        )
        self.assert_invalid("unregistered In Progress Task")

    def test_in_progress_task_must_belong_to_current_stage(self) -> None:
        self.replace(
            self.roadmap,
            "| `CFGRC-P1-REGISTER` | `CFGRC-P1` |",
            "| `CFGRC-P1-REGISTER` | `CFGRC-P2` |",
        )
        self.assert_invalid("belongs to CFGRC-P2, not CFGRC-P1")

    def test_task_board_requires_exactly_one_in_progress_row(self) -> None:
        self.replace(
            self.progress,
            "| `CFGRC-GOV-LEDGER` | Pending |",
            "| `CFGRC-GOV-LEDGER` | In Progress |",
        )
        self.assert_invalid("State 'In Progress', found 2")

    def test_task_board_active_row_must_match_pointer(self) -> None:
        self.replace(
            self.progress,
            "| `CFGRC-P1-REGISTER` | In Progress |",
            "| `CFGRC-P1-REGISTER` | Pending |",
        )
        self.replace(
            self.progress,
            "| `CFGRC-GOV-LEDGER` | Pending |",
            "| `CFGRC-GOV-LEDGER` | In Progress |",
        )
        self.assert_invalid(
            "pointer CFGRC-P1-REGISTER does not match Task board CFGRC-GOV-LEDGER"
        )

    def test_task_board_rejects_duplicate_task_rows(self) -> None:
        self.replace(
            self.progress,
            "| `CFGRC-GOV-LEDGER` | Pending |",
            "| `CFGRC-P1-REGISTER` | Pending |",
        )
        self.assert_invalid("duplicate Task board row")

    def test_active_task_board_rejects_terminal_states(self) -> None:
        terminal_states = (
            "Complete",
            "completed for bounded slice",
            "DONE",
            "Closed — superseded",
            "delivered pending release",
        )
        for state in terminal_states:
            with self.subTest(state=state):
                self.write(self.progress, PROGRESS)
                self.replace(
                    self.progress,
                    "| `CFGRC-GOV-LEDGER` | Pending |",
                    f"| `CFGRC-GOV-LEDGER` | {state} |",
                )
                self.assert_invalid("uses forbidden terminal State")

    def test_progress_line_limit_is_enforced(self) -> None:
        lines = self.progress.read_text(encoding="utf-8").splitlines()
        lines.extend(
            "filler" for _ in range(validator.MAX_PROGRESS_LINES + 1 - len(lines))
        )
        self.write(self.progress, "\n".join(lines))
        self.assert_invalid("exceeds the 500-line limit")

    def test_progress_rejects_legacy_activity_log(self) -> None:
        self.write(self.progress, PROGRESS + "\n## Activity log\n")
        self.assert_invalid("Activity log is forbidden")

    def test_progress_rejects_canonical_records_and_experiments(self) -> None:
        for heading, pattern in (
            ("### CFGRC-REC-20260827-01", "record headings belong"),
            ("#### CFGRC-EXP-202608-002", "experiment records belong"),
        ):
            with self.subTest(heading=heading):
                self.write(self.progress, PROGRESS + f"\n{heading}\n")
                self.assert_invalid(pattern)

    def test_progress_rejects_governance_prefixes_at_wrong_heading_levels(self) -> None:
        contracts = (
            ("CFGRC-REC-20260827-01", 3, "record headings belong"),
            ("CFGRC-EXP-202608-002", 4, "experiment records belong"),
        )
        for identifier, canonical_level, pattern in contracts:
            for level in range(1, 7):
                if level == canonical_level:
                    continue
                with self.subTest(identifier=identifier, level=level):
                    self.write(
                        self.progress,
                        PROGRESS + f"\n{'#' * level} {identifier}\n",
                    )
                    self.assert_invalid(pattern)

    def test_recent_records_limit_is_enforced(self) -> None:
        row = (
            "| 2026-08-25 | [CFGRC-REC-20260825-01]"
            "(progress-archive/2026-08.md#cfgrc-rec-20260825-01) | "
            "`CFGRC-P1-REGISTER` | Register checks passed. |"
        )
        self.replace(self.progress, row, "\n".join([row] * 10))
        self.assert_invalid("Recent records has 11 rows; maximum is 10")

    def test_recent_records_must_be_descending(self) -> None:
        self.replace(self.progress, "2026-08-26", "2026-08-24", 1)
        self.replace(self.progress, "20260826", "20260824")
        self.replace(self.august_archive, "2026-08-26", "2026-08-24", 1)
        self.replace(self.august_archive, "20260826", "20260824")
        self.assert_invalid("ordered by descending")

    def test_recent_records_cannot_omit_the_newest_archive_record(self) -> None:
        lines = self.progress.read_text(encoding="utf-8").splitlines()
        remaining = [line for line in lines if "CFGRC-REC-20260826-01" not in line]
        self.assertEqual(len(remaining), len(lines) - 1)
        self.write(self.progress, "\n".join(remaining))
        self.assert_invalid("must equal the newest 2 archive records")

    def test_recent_records_cannot_substitute_an_older_record_at_the_cap(self) -> None:
        older_record = """

### CFGRC-REC-20260824-01

- Completed: `2026-08-24`
- Task IDs: `CFGRC-P1-REGISTER`

Older completed record.
"""
        self.write(self.august_archive, ARCHIVE + older_record)
        old_row = (
            "| 2026-08-25 | [CFGRC-REC-20260825-01]"
            "(progress-archive/2026-08.md#cfgrc-rec-20260825-01) | "
            "`CFGRC-P1-REGISTER` | Register checks passed. |"
        )
        replacement = (
            "| 2026-08-24 | [CFGRC-REC-20260824-01]"
            "(progress-archive/2026-08.md#cfgrc-rec-20260824-01) | "
            "`CFGRC-P1-REGISTER` | Older record. |"
        )
        self.replace(self.progress, old_row, replacement)
        with mock.patch.object(validator, "MAX_RECENT_RECORDS", 2):
            self.assert_invalid("must equal the newest 2 archive records")

    def test_recent_records_require_descending_numeric_sequence_on_same_day(
        self,
    ) -> None:
        self.replace(self.progress, "2026-08-25", "2026-08-26", 1)
        self.replace(
            self.progress,
            "CFGRC-REC-20260825-01",
            "CFGRC-REC-20260826-02",
        )
        self.replace(
            self.progress,
            "cfgrc-rec-20260825-01",
            "cfgrc-rec-20260826-02",
        )
        self.replace(self.august_archive, "2026-08-25", "2026-08-26", 1)
        self.replace(
            self.august_archive,
            "CFGRC-REC-20260825-01",
            "CFGRC-REC-20260826-02",
        )
        self.assert_invalid("completion date and numeric sequence")

    def test_recent_record_must_exist_in_archive(self) -> None:
        self.replace(
            self.progress,
            "CFGRC-REC-20260826-01",
            "CFGRC-REC-20260827-01",
        )
        self.replace(self.progress, "2026-08-26", "2026-08-27")
        self.assert_invalid("references missing archive record")

    def test_recent_record_date_must_match_archive(self) -> None:
        self.replace(self.progress, "| 2026-08-26 |", "| 2026-08-24 |")
        self.assert_invalid("date does not match its archive record")

    def test_recent_record_tasks_must_match_archive(self) -> None:
        self.replace(
            self.progress,
            "`CFGRC-GOV-LEDGER`, `CFGRC-P1-REGISTER` | Governance",
            "`CFGRC-GOV-LEDGER` | Governance",
        )
        self.assert_invalid("task IDs do not match its archive record")

    def test_recent_record_requires_exactly_one_markdown_link(self) -> None:
        link = (
            "[CFGRC-REC-20260826-01](progress-archive/2026-08.md#cfgrc-rec-20260826-01)"
        )
        for replacement, found in (
            ("`CFGRC-REC-20260826-01`", 0),
            (link + " [extra](progress-archive/2026-08.md#extra)", 2),
        ):
            with self.subTest(found=found):
                self.write(self.progress, PROGRESS)
                self.replace(self.progress, link, replacement)
                self.assert_invalid(f"must contain exactly one relative Markdown link")

    def test_recent_record_link_must_resolve_to_its_archive(self) -> None:
        self.replace(
            self.progress,
            "progress-archive/2026-08.md#cfgrc-rec-20260826-01",
            "progress-archive/2026-09.md#cfgrc-rec-20260826-01",
        )
        self.assert_invalid("link resolves to .*2026-09.md, not .*2026-08.md")

    def test_recent_record_link_fragment_must_equal_lowercase_record_id(self) -> None:
        self.replace(
            self.progress,
            "#cfgrc-rec-20260826-01",
            "#wrong-anchor",
        )
        self.assert_invalid("link fragment must be #cfgrc-rec-20260826-01")

    def test_archive_filename_must_be_monthly(self) -> None:
        self.write(self.archive_dir / "README.md", "archive rules")
        self.assert_invalid("archive filename must be YYYY-MM.md")

    def test_record_heading_must_be_canonical(self) -> None:
        self.replace(
            self.august_archive,
            "### CFGRC-REC-20260826-01",
            "### CFGRC-REC-20260826-01 — title",
        )
        self.assert_invalid("malformed canonical heading")

    def test_archive_record_and_experiment_reject_every_wrong_heading_level(
        self,
    ) -> None:
        contracts = (
            ("### CFGRC-REC-20260826-01", "CFGRC-REC-20260826-01", 3),
            ("#### CFGRC-EXP-202608-001", "CFGRC-EXP-202608-001", 4),
        )
        for original, identifier, canonical_level in contracts:
            for level in range(1, 7):
                if level == canonical_level:
                    continue
                with self.subTest(identifier=identifier, level=level):
                    self.write(self.august_archive, ARCHIVE)
                    self.replace(
                        self.august_archive,
                        original,
                        f"{'#' * level} {identifier}",
                        1,
                    )
                    self.assert_invalid(f"must use heading level {canonical_level}")

    def test_record_requires_exactly_one_completed_field(self) -> None:
        self.replace(
            self.august_archive,
            "- Completed: `2026-08-26`",
            "- Completed: `2026-08-26`\n- Completed: `2026-08-26`",
        )
        self.assert_invalid("exactly one 'Completed' field, found 2")

    def test_record_date_must_match_record_id(self) -> None:
        self.replace(
            self.august_archive,
            "- Completed: `2026-08-26`",
            "- Completed: `2026-08-24`",
        )
        self.assert_invalid("does not match record ID date")

    def test_record_date_must_match_archive_month(self) -> None:
        september = self.archive_dir / "2026-09.md"
        self.august_archive.rename(september)
        self.august_archive = september
        self.assert_invalid("does not match archive month 2026-09")

    def test_record_ids_are_globally_unique(self) -> None:
        duplicate = """\n### CFGRC-REC-20260826-01\n\n- Completed: `2026-08-26`\n- Task IDs: `CFGRC-GOV-LEDGER`\n"""
        self.write(self.august_archive, ARCHIVE + duplicate)
        self.assert_invalid("duplicate record ID")

    def test_record_task_list_is_strict_and_unique(self) -> None:
        for replacement in (
            "CFGRC-GOV-LEDGER",
            "`CFGRC-GOV-LEDGER` and `CFGRC-P1-REGISTER`",
            "`CFGRC-GOV-LEDGER`, `CFGRC-GOV-LEDGER`",
        ):
            with self.subTest(replacement=replacement):
                self.write(self.august_archive, ARCHIVE)
                self.replace(
                    self.august_archive,
                    "`CFGRC-GOV-LEDGER`, `CFGRC-P1-REGISTER`",
                    replacement,
                    1,
                )
                self.assert_invalid("Task IDs must|duplicate task ID")

    def test_all_task_shaped_ids_must_be_registered(self) -> None:
        self.replace(
            self.august_archive,
            "Verified the bounded register slice.",
            "Verified `CFGRC-P1-UNKNOWN`.",
        )
        self.assert_invalid("is not registered in the roadmap")

    def test_malformed_task_shaped_id_is_rejected(self) -> None:
        self.replace(
            self.august_archive,
            "Verified the bounded register slice.",
            "Verified `CFGRC-P9-UNKNOWN`.",
        )
        self.assert_invalid("malformed task-shaped ID")

    def test_experiment_heading_month_must_match_archive(self) -> None:
        self.replace(
            self.august_archive,
            "CFGRC-EXP-202608-001",
            "CFGRC-EXP-202609-001",
        )
        self.assert_invalid("month does not match archive")

    def test_experiment_ids_are_globally_unique(self) -> None:
        start = ARCHIVE.index("#### CFGRC-EXP-202608-001")
        end = ARCHIVE.index("### CFGRC-REC-20260825-01")
        experiment = ARCHIVE[start:end]
        self.write(self.august_archive, ARCHIVE + "\n" + experiment)
        self.assert_invalid("duplicate experiment ID")

    def test_experiment_requires_every_reproducibility_field_exactly_once(self) -> None:
        fields = (
            "Task ID",
            "Upstream commit",
            "Model",
            "Model SHA-256",
            "Config SHA-256",
            "Data SHA-256",
            "Hardware",
            "Command",
            "Metrics",
        )
        for field in fields:
            with self.subTest(field=field):
                self.write(self.august_archive, ARCHIVE)
                lines = self.august_archive.read_text(encoding="utf-8").splitlines()
                removed = False
                kept = []
                for line in lines:
                    if not removed and line.startswith(f"- {field}:"):
                        removed = True
                        continue
                    kept.append(line)
                self.assertTrue(removed)
                self.write(self.august_archive, "\n".join(kept))
                self.assert_invalid(f"exactly one '{re.escape(field)}' field, found 0")

    def test_experiment_rejects_invalid_commit_and_hashes(self) -> None:
        mutations = (
            (
                "1111111111111111111111111111111111111111",
                "ABCDEF",
                "Upstream commit must be",
            ),
            (
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "sha256:ABCDEF",
                "Model SHA-256 must be",
            ),
            (
                "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "b" * 64,
                "Config SHA-256 must be",
            ),
            (
                "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                "sha256:1234",
                "Data SHA-256 must be",
            ),
        )
        for old, new, pattern in mutations:
            with self.subTest(field=pattern):
                self.write(self.august_archive, ARCHIVE)
                self.replace(self.august_archive, old, new, 1)
                self.assert_invalid(pattern)

    def test_experiment_rejects_empty_model_hardware_and_command(self) -> None:
        for field, value in (
            ("Model", "example/model@immutable-revision"),
            ("Hardware", "CPU=x86_64; RAM=16GiB; GPU=none"),
            ("Command", "python tools/run_experiment.py --config example.json"),
        ):
            with self.subTest(field=field):
                self.write(self.august_archive, ARCHIVE)
                self.replace(
                    self.august_archive, f"- {field}: `{value}`", f"- {field}: ``"
                )
                self.assert_invalid(f"{field} must not be empty")

    def test_experiment_metrics_must_be_strict_nonempty_finite_json(self) -> None:
        invalid_metrics = (
            "{}",
            "[]",
            "{not-json}",
            '{"score":NaN}',
            '{"score":Infinity}',
            '{"score":1e999}',
            '{"score":1,"score":2}',
        )
        for metrics in invalid_metrics:
            with self.subTest(metrics=metrics):
                self.write(self.august_archive, ARCHIVE)
                self.replace(
                    self.august_archive,
                    '{"accuracy":0.9,"latency_ms":12}',
                    metrics,
                )
                self.assert_invalid("Metrics")

    def test_experiment_task_must_be_registered(self) -> None:
        self.replace(
            self.august_archive,
            "- Task ID: `CFGRC-GOV-LEDGER`",
            "- Task ID: `CFGRC-GOV-UNKNOWN`",
        )
        self.assert_invalid(
            "is not registered in the roadmap|uses unregistered task ID"
        )

    def test_main_handles_missing_input_file(self) -> None:
        missing = self.root / "missing.md"
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            status = validator.main(
                [
                    "--roadmap",
                    str(missing),
                    "--progress",
                    str(self.progress),
                    "--archive-dir",
                    str(self.archive_dir),
                ]
            )
        self.assertEqual(status, 1)
        self.assertIn("FAIL —", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
