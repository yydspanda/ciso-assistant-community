from __future__ import annotations

import contextlib
import io
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tools.china_financial_grc import check_upstream_divergence as checker


class TemporaryGitRepository:
    def __init__(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary_directory.name) / "repository"
        self.root.mkdir()
        self.commit_number = 0
        self.git("init", "--initial-branch=main")
        self.git("config", "user.name", "Divergence Test")
        self.git("config", "user.email", "divergence-test@example.invalid")
        self.git("config", "commit.gpgsign", "false")
        self.commit("base")

    def close(self) -> None:
        self.temporary_directory.cleanup()

    def git(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["git", *arguments],
            cwd=self.root,
            check=True,
            capture_output=True,
            text=True,
        )

    def commit(self, label: str) -> str:
        self.commit_number += 1
        artifact = self.root / f"commit-{self.commit_number:02d}.txt"
        artifact.write_text(f"{label}\n", encoding="utf-8")
        self.git("add", artifact.name)
        timestamp = f"2000-01-{self.commit_number:02d}T00:00:00+0000"
        environment = os.environ.copy()
        environment.update(
            {"GIT_AUTHOR_DATE": timestamp, "GIT_COMMITTER_DATE": timestamp}
        )
        subprocess.run(
            ["git", "commit", "-m", label],
            cwd=self.root,
            check=True,
            capture_output=True,
            text=True,
            env=environment,
        )
        return self.git("rev-parse", "HEAD").stdout.strip()


class UpstreamDivergenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.repository = TemporaryGitRepository()

    def tearDown(self) -> None:
        self.repository.close()

    def measure(
        self,
        upstream_ref: str,
        head_ref: str,
        *,
        warn_threshold: int = 10,
        fail_threshold: int = 20,
    ) -> dict[str, object]:
        return checker.measure_divergence(
            self.repository.root,
            upstream_ref,
            head_ref,
            warn_threshold,
            fail_threshold,
        )

    def test_equal_histories(self) -> None:
        report = self.measure("main", "HEAD")

        self.assertEqual(report["ahead"], 0)
        self.assertEqual(report["behind"], 0)
        self.assertEqual(report["status"], "ok")
        self.assertFalse(report["warn"])
        self.assertFalse(report["fail"])
        self.assertEqual(len(str(report["upstream_oid"])), 40)
        self.assertEqual(report["upstream_oid"], report["head_oid"])
        self.assertEqual(report["merge_base"], report["head_oid"])

    def test_ahead_history_is_reported_without_failure(self) -> None:
        self.repository.git("switch", "-c", "fork")
        self.repository.commit("fork work")

        report = self.measure("main", "fork", warn_threshold=1, fail_threshold=2)

        self.assertEqual(report["ahead"], 1)
        self.assertEqual(report["behind"], 0)
        self.assertEqual(report["status"], "ok")
        self.assertFalse(report["warn"])
        self.assertFalse(report["fail"])

    def test_behind_history_is_counted_from_the_upstream_side(self) -> None:
        self.repository.git("branch", "fork")
        self.repository.commit("upstream work")

        report = self.measure("main", "fork")

        self.assertEqual(report["ahead"], 0)
        self.assertEqual(report["behind"], 1)
        self.assertEqual(report["status"], "ok")

    def test_diverged_history_reports_both_sides(self) -> None:
        self.repository.git("branch", "fork")
        self.repository.commit("upstream work")
        self.repository.git("switch", "fork")
        self.repository.commit("fork work")

        report = self.measure("main", "fork")

        self.assertEqual(report["ahead"], 1)
        self.assertEqual(report["behind"], 1)
        self.assertNotEqual(report["upstream_oid"], report["head_oid"])
        self.assertNotIn(
            report["merge_base"], {report["upstream_oid"], report["head_oid"]}
        )

    def test_warning_and_failure_thresholds_are_inclusive(self) -> None:
        self.repository.git("branch", "fork")
        self.repository.commit("upstream one")

        warning = self.measure("main", "fork", warn_threshold=1, fail_threshold=2)
        self.assertEqual(warning["status"], "warn")
        self.assertTrue(warning["warn"])
        self.assertFalse(warning["fail"])

        self.repository.commit("upstream two")
        failure = self.measure("main", "fork", warn_threshold=1, fail_threshold=2)
        self.assertEqual(failure["status"], "fail")
        self.assertTrue(failure["warn"])
        self.assertTrue(failure["fail"])

    def test_histories_without_a_merge_base_are_rejected(self) -> None:
        self.repository.git("switch", "--orphan", "unrelated")
        self.repository.commit("unrelated root")

        with self.assertRaisesRegex(checker.DivergenceCheckError, "no merge base"):
            self.measure("main", "unrelated")

    def test_shallow_repository_is_rejected(self) -> None:
        self.repository.commit("second source commit")
        shallow = Path(self.repository.temporary_directory.name) / "shallow"
        self.repository.git(
            "clone",
            "--depth=1",
            self.repository.root.as_uri(),
            str(shallow),
        )

        with self.assertRaisesRegex(checker.DivergenceCheckError, "shallow"):
            checker.measure_divergence(shallow, "HEAD", "HEAD")

    def test_cli_outputs_json_warning_and_step_summary(self) -> None:
        self.repository.git("branch", "fork")
        self.repository.commit("upstream work")
        summary = Path(self.repository.temporary_directory.name) / "summary.md"
        stdout = io.StringIO()
        stderr = io.StringIO()

        with (
            mock.patch.dict(os.environ, {"GITHUB_STEP_SUMMARY": str(summary)}),
            contextlib.redirect_stdout(stdout),
            contextlib.redirect_stderr(stderr),
        ):
            return_code = checker.main(
                [
                    "--repository",
                    str(self.repository.root),
                    "--upstream-ref",
                    "main",
                    "--head-ref",
                    "fork",
                    "--warn-behind",
                    "1",
                    "--fail-behind",
                    "2",
                ]
            )

        self.assertEqual(return_code, 0)
        self.assertEqual(json.loads(stdout.getvalue())["status"], "warn")
        self.assertIn("::warning title=Fork upstream divergence::", stderr.getvalue())
        summary_text = summary.read_text(encoding="utf-8")
        self.assertIn("| Behind | 1 |", summary_text)
        self.assertIn("| Ahead | 0 |", summary_text)

    def test_cli_fails_at_default_failure_threshold(self) -> None:
        self.repository.git("branch", "fork")
        for position in range(checker.DEFAULT_FAIL_BEHIND):
            self.repository.commit(f"upstream {position:02d}")

        with (
            mock.patch.dict(os.environ, {}, clear=True),
            contextlib.redirect_stdout(io.StringIO()),
            contextlib.redirect_stderr(io.StringIO()),
        ):
            return_code = checker.main(
                [
                    "--repository",
                    str(self.repository.root),
                    "--upstream-ref",
                    "main",
                    "--head-ref",
                    "fork",
                ]
            )

        self.assertEqual(return_code, 1)


if __name__ == "__main__":
    unittest.main()
