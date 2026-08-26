#!/usr/bin/env python3
"""Measure this fork's divergence from a freshly fetched upstream ref.

The caller owns fetching the canonical upstream.  This tool deliberately rejects
shallow repositories so that ahead/behind counts cannot silently under-report
history that was not fetched.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any


DEFAULT_UPSTREAM_REF = "refs/remotes/china-financial-grc-canonical/main"
DEFAULT_HEAD_REF = "HEAD"
DEFAULT_WARN_BEHIND = 10
DEFAULT_FAIL_BEHIND = 20
OID_PATTERN = re.compile(r"[0-9a-fA-F]{40}|[0-9a-fA-F]{64}")


class DivergenceCheckError(RuntimeError):
    """Raised when Git history cannot support an authoritative comparison."""


def _run_git(
    repository: Path, arguments: Sequence[str], *, check: bool = True
) -> subprocess.CompletedProcess[str]:
    command = ["git", "-C", str(repository), *arguments]
    completed = subprocess.run(
        command,
        check=False,
        capture_output=True,
        text=True,
    )
    if check and completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip() or "unknown error"
        raise DivergenceCheckError(
            f"{shlex.join(command)} failed with exit code "
            f"{completed.returncode}: {detail}"
        )
    return completed


def _require_full_oid(repository: Path, ref: str) -> str:
    oid = _run_git(
        repository, ["rev-parse", "--verify", f"{ref}^{{commit}}"]
    ).stdout.strip()
    if OID_PATTERN.fullmatch(oid) is None:
        raise DivergenceCheckError(
            f"Git returned a non-full object ID for {ref!r}: {oid!r}"
        )
    return oid.lower()


def _validate_repository(repository: Path) -> None:
    inside_work_tree = _run_git(
        repository, ["rev-parse", "--is-inside-work-tree"]
    ).stdout.strip()
    if inside_work_tree != "true":
        raise DivergenceCheckError(f"{repository} is not a Git work tree")

    shallow = _run_git(
        repository, ["rev-parse", "--is-shallow-repository"]
    ).stdout.strip()
    if shallow == "true":
        raise DivergenceCheckError(
            "refusing to calculate divergence in a shallow repository; fetch full "
            "history first"
        )
    if shallow != "false":
        raise DivergenceCheckError(
            f"Git returned an unexpected shallow-repository state: {shallow!r}"
        )


def measure_divergence(
    repository: Path | str,
    upstream_ref: str = DEFAULT_UPSTREAM_REF,
    head_ref: str = DEFAULT_HEAD_REF,
    warn_threshold: int = DEFAULT_WARN_BEHIND,
    fail_threshold: int = DEFAULT_FAIL_BEHIND,
) -> dict[str, Any]:
    """Return a deterministic, JSON-serializable divergence report."""

    if warn_threshold < 0:
        raise DivergenceCheckError("warn threshold must be non-negative")
    if fail_threshold <= warn_threshold:
        raise DivergenceCheckError("fail threshold must be greater than warn threshold")

    repository_path = Path(repository).resolve()
    _validate_repository(repository_path)
    upstream_oid = _require_full_oid(repository_path, upstream_ref)
    head_oid = _require_full_oid(repository_path, head_ref)

    merge_base_result = _run_git(
        repository_path,
        ["merge-base", upstream_oid, head_oid],
        check=False,
    )
    if merge_base_result.returncode == 1:
        raise DivergenceCheckError(
            f"no merge base between {upstream_ref!r} and {head_ref!r}"
        )
    if merge_base_result.returncode != 0:
        detail = (
            merge_base_result.stderr.strip()
            or merge_base_result.stdout.strip()
            or "unknown error"
        )
        raise DivergenceCheckError(f"git merge-base failed: {detail}")
    merge_base = merge_base_result.stdout.strip().lower()
    if OID_PATTERN.fullmatch(merge_base) is None:
        raise DivergenceCheckError(
            f"Git returned a non-full merge-base object ID: {merge_base!r}"
        )

    counts = _run_git(
        repository_path,
        ["rev-list", "--left-right", "--count", f"{upstream_oid}...{head_oid}"],
    ).stdout.split()
    if len(counts) != 2:
        raise DivergenceCheckError(
            f"Git returned unexpected ahead/behind counts: {' '.join(counts)!r}"
        )
    try:
        behind, ahead = (int(value) for value in counts)
    except ValueError as error:
        raise DivergenceCheckError(
            f"Git returned non-integer ahead/behind counts: {' '.join(counts)!r}"
        ) from error

    warn = behind >= warn_threshold
    fail = behind >= fail_threshold
    status = "fail" if fail else "warn" if warn else "ok"
    return {
        "ahead": ahead,
        "behind": behind,
        "fail": fail,
        "fail_threshold": fail_threshold,
        "head_oid": head_oid,
        "head_ref": head_ref,
        "merge_base": merge_base,
        "status": status,
        "upstream_oid": upstream_oid,
        "upstream_ref": upstream_ref,
        "warn": warn,
        "warn_threshold": warn_threshold,
    }


def _markdown_cell(value: object) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")


def append_step_summary(report: dict[str, Any], summary_path: Path | str) -> None:
    """Append a compact comparison table to a GitHub Actions step summary."""

    rows = (
        ("Status", report["status"]),
        ("Upstream ref", report["upstream_ref"]),
        ("Upstream commit", report["upstream_oid"]),
        ("Fork ref", report["head_ref"]),
        ("Fork commit", report["head_oid"]),
        ("Merge base", report["merge_base"]),
        ("Behind", report["behind"]),
        ("Ahead", report["ahead"]),
        (
            "Warn / fail thresholds",
            f"{report['warn_threshold']} / {report['fail_threshold']}",
        ),
    )
    lines = [
        "## China Financial GRC fork upstream divergence",
        "",
        "| Field | Value |",
        "| --- | --- |",
        *(
            f"| {_markdown_cell(label)} | {_markdown_cell(value)} |"
            for label, value in rows
        ),
        "",
    ]
    with Path(summary_path).open("a", encoding="utf-8") as stream:
        stream.write("\n".join(lines))


def _parse_arguments(argv: Sequence[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Measure fork ahead/behind counts against a fetched upstream ref."
    )
    parser.add_argument(
        "--repository",
        type=Path,
        default=Path.cwd(),
        help="Git work tree to inspect (default: current directory)",
    )
    parser.add_argument(
        "--upstream-ref",
        default=DEFAULT_UPSTREAM_REF,
        help=f"freshly fetched canonical ref (default: {DEFAULT_UPSTREAM_REF})",
    )
    parser.add_argument(
        "--head-ref",
        default=DEFAULT_HEAD_REF,
        help=f"fork ref to compare (default: {DEFAULT_HEAD_REF})",
    )
    parser.add_argument(
        "--warn-behind",
        type=int,
        default=DEFAULT_WARN_BEHIND,
        help=(
            "warn at this many missing upstream commits "
            f"(default: {DEFAULT_WARN_BEHIND})"
        ),
    )
    parser.add_argument(
        "--fail-behind",
        type=int,
        default=DEFAULT_FAIL_BEHIND,
        help=(
            "fail at this many missing upstream commits "
            f"(default: {DEFAULT_FAIL_BEHIND})"
        ),
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parse_arguments(argv)
    try:
        report = measure_divergence(
            arguments.repository,
            upstream_ref=arguments.upstream_ref,
            head_ref=arguments.head_ref,
            warn_threshold=arguments.warn_behind,
            fail_threshold=arguments.fail_behind,
        )
        summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
        if summary_path:
            append_step_summary(report, summary_path)
    except (DivergenceCheckError, OSError) as error:
        print(f"upstream divergence check error: {error}", file=sys.stderr)
        return 2

    print(json.dumps(report, ensure_ascii=True, sort_keys=True, separators=(",", ":")))
    if report["warn"]:
        print(
            "::warning title=Fork upstream divergence::"
            f"Fork is {report['behind']} commits behind canonical upstream "
            f"(warning at {report['warn_threshold']}, failure at "
            f"{report['fail_threshold']}).",
            file=sys.stderr,
        )
    return 1 if report["fail"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
