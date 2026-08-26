#!/usr/bin/env python3
"""Validate the China financial GRC roadmap and execution ledger contract.

The validator intentionally uses only the Python standard library.  It treats
the roadmap as the task/stage registry, ``progress.md`` as a compact current
pointer, and monthly files under ``progress-archive`` as canonical historical
records.  It does not interpret general prose as project state.
"""

from __future__ import annotations

import argparse
import json
import math
import re
import sys
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Any, Sequence


REPO_ROOT = Path(__file__).resolve().parents[2]
NOTES_DIR = REPO_ROOT / ".notes" / "china_financial_grc"
ROADMAP_PATH = NOTES_DIR / "delivery-roadmap.md"
PROGRESS_PATH = NOTES_DIR / "progress.md"
ARCHIVE_DIR = NOTES_DIR / "progress-archive"

MAX_PROGRESS_LINES = 500
MAX_RECENT_RECORDS = 10

STAGE_ID_TEXT = r"CFGRC-P[0-5]"
TASK_ID_TEXT = r"CFGRC-(?:P[0-5]|GOV)-[A-Z0-9](?:[A-Z0-9-]*[A-Z0-9])?"
RECORD_ID_TEXT = r"CFGRC-REC-(\d{4})(\d{2})(\d{2})-(\d{2})"
EXPERIMENT_ID_TEXT = r"CFGRC-EXP-(\d{4})(\d{2})-(\d{3})"

STAGE_ID_RE = re.compile(rf"^{STAGE_ID_TEXT}$")
TASK_ID_RE = re.compile(rf"(?<![A-Z0-9-]){TASK_ID_TEXT}(?![A-Z0-9-])")
TASK_ID_CANDIDATE_RE = re.compile(
    r"(?<![A-Z0-9-])CFGRC-(?:P\d+|GOV)-[A-Z0-9-]+(?![A-Z0-9-])"
)
EXACT_TASK_ID_RE = re.compile(rf"^{TASK_ID_TEXT}$")
RECORD_ID_RE = re.compile(rf"^{RECORD_ID_TEXT}$")
RECORD_TOKEN_RE = re.compile(rf"(?<![A-Z0-9-])CFGRC-REC-\d{{8}}-\d{{2}}(?![A-Z0-9-])")
EXPERIMENT_ID_RE = re.compile(rf"^{EXPERIMENT_ID_TEXT}$")
ARCHIVE_NAME_RE = re.compile(r"^(\d{4})-(\d{2})\.md$")
ISO_DATE_RE = re.compile(r"(?<!\d)(\d{4}-\d{2}-\d{2})(?!\d)")
SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
COMMIT_RE = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
MARKDOWN_HEADING_RE = re.compile(r"^(#{1,6})\s+")
MARKDOWN_LINK_RE = re.compile(r"(?<!!)\[[^\]\n]+\]\(([^()\s]+)\)")

EXPECTED_STAGES = {f"CFGRC-P{number}" for number in range(6)}


class GovernanceValidationError(Exception):
    """Raised when a roadmap, progress pointer, or archive is inconsistent."""


@dataclass(frozen=True)
class MarkdownTable:
    headers: tuple[str, ...]
    rows: tuple[tuple[str, ...], ...]
    start_line: int


@dataclass(frozen=True)
class ArchivedRecord:
    record_id: str
    completed: date
    sequence: int
    task_ids: frozenset[str]
    path: Path


@dataclass(frozen=True)
class GovernanceSummary:
    stages: int
    tasks: int
    active_task: str
    recent_records: int
    archived_records: int
    experiments: int
    progress_lines: int


def require(condition: bool, message: str) -> None:
    if not condition:
        raise GovernanceValidationError(message)


def read_lines(path: Path) -> list[str]:
    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError as error:
        raise GovernanceValidationError(f"{path}: expected UTF-8 text") from error
    return text.splitlines()


def strip_inline_code(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value.startswith("`") and value.endswith("`"):
        return value[1:-1].strip()
    return value


def split_table_row(line: str) -> list[str]:
    """Split a simple Markdown table row while honouring escaped pipes."""

    value = line.strip()
    if value.startswith("|"):
        value = value[1:]
    if value.endswith("|") and not value.endswith(r"\|"):
        value = value[:-1]

    cells: list[str] = []
    current: list[str] = []
    escaped = False
    for character in value:
        if escaped:
            current.append(character)
            escaped = False
        elif character == "\\":
            current.append(character)
            escaped = True
        elif character == "|":
            cells.append("".join(current).strip())
            current = []
        else:
            current.append(character)
    cells.append("".join(current).strip())
    return cells


def is_table_separator(cells: Sequence[str]) -> bool:
    return bool(cells) and all(
        re.fullmatch(r":?-{3,}:?", cell.replace(" ", "")) for cell in cells
    )


def find_exact_section(lines: Sequence[str], heading: str, path: Path) -> list[str]:
    positions = [position for position, line in enumerate(lines) if line == heading]
    require(
        len(positions) == 1,
        f"{path}: expected exactly one {heading!r} section, found {len(positions)}",
    )
    start = positions[0] + 1
    end = len(lines)
    for position in range(start, len(lines)):
        if lines[position].startswith("## "):
            end = position
            break
    return list(lines[start:end])


def parse_first_table(section: Sequence[str], path: Path, label: str) -> MarkdownTable:
    for position in range(len(section) - 1):
        header_line = section[position]
        separator_line = section[position + 1]
        if not header_line.strip().startswith("|"):
            continue
        headers = split_table_row(header_line)
        separators = split_table_row(separator_line)
        if len(headers) != len(separators) or not is_table_separator(separators):
            continue

        rows: list[tuple[str, ...]] = []
        row_position = position + 2
        while row_position < len(section) and section[row_position].strip().startswith(
            "|"
        ):
            cells = split_table_row(section[row_position])
            require(
                len(cells) == len(headers),
                f"{path}: {label} table row has {len(cells)} cells; expected {len(headers)}",
            )
            rows.append(tuple(cells))
            row_position += 1
        return MarkdownTable(tuple(headers), tuple(rows), position + 1)
    raise GovernanceValidationError(f"{path}: {label} section needs a Markdown table")


def exact_backticked_id(cell: str, pattern: re.Pattern[str], label: str) -> str:
    match = re.fullmatch(r"`([^`]+)`", cell.strip())
    require(match is not None, f"{label}: identifier must be enclosed in backticks")
    identifier = match.group(1)
    require(
        pattern.fullmatch(identifier) is not None, f"{label}: invalid ID {identifier!r}"
    )
    return identifier


def normalise_header(value: str) -> str:
    return re.sub(r"\s+", " ", strip_inline_code(value)).strip().casefold()


def header_index(table: MarkdownTable, wanted: str, path: Path, label: str) -> int:
    normalised = [normalise_header(header) for header in table.headers]
    positions = [index for index, header in enumerate(normalised) if header == wanted]
    require(
        len(positions) == 1,
        f"{path}: {label} table needs exactly one {wanted!r} column",
    )
    return positions[0]


def parse_roadmap(path: Path) -> tuple[set[str], dict[str, str]]:
    lines = read_lines(path)
    stage_section = find_exact_section(lines, "## Stage registry", path)
    stage_table = parse_first_table(stage_section, path, "Stage registry")

    stages: set[str] = set()
    for row_number, row in enumerate(stage_table.rows, start=1):
        stage = exact_backticked_id(
            row[0], STAGE_ID_RE, f"{path}: Stage registry row {row_number}"
        )
        require(stage not in stages, f"{path}: duplicate stage registry ID {stage}")
        stages.add(stage)
    require(
        stages == EXPECTED_STAGES,
        f"{path}: stage registry must contain exactly {sorted(EXPECTED_STAGES)}; got {sorted(stages)}",
    )

    task_section = find_exact_section(lines, "## Task registry", path)
    task_table = parse_first_table(task_section, path, "Task registry")
    require(task_table.rows, f"{path}: Task registry must contain at least one task")

    task_stages: dict[str, str] = {}
    for row_number, row in enumerate(task_table.rows, start=1):
        require(
            len(row) >= 2,
            f"{path}: Task registry row {row_number} needs task and stage columns",
        )
        task = exact_backticked_id(
            row[0], EXACT_TASK_ID_RE, f"{path}: Task registry row {row_number}"
        )
        stage = exact_backticked_id(
            row[1], STAGE_ID_RE, f"{path}: Task registry row {row_number} stage"
        )
        require(stage in stages, f"{path}: task {task} uses unregistered stage {stage}")
        require(task not in task_stages, f"{path}: duplicate task registry ID {task}")
        task_stages[task] = stage
    return stages, task_stages


def extract_exact_field(block: Sequence[str], field: str, context: str) -> str:
    prefix = f"- {field}:"
    matches = [line[len(prefix) :].strip() for line in block if line.startswith(prefix)]
    require(
        len(matches) == 1,
        f"{context}: expected exactly one {field!r} field, found {len(matches)}",
    )
    return matches[0]


def parse_iso_date(value: str, context: str) -> date:
    value = strip_inline_code(value)
    require(
        re.fullmatch(r"\d{4}-\d{2}-\d{2}", value) is not None,
        f"{context}: expected YYYY-MM-DD, got {value!r}",
    )
    try:
        return date.fromisoformat(value)
    except ValueError as error:
        raise GovernanceValidationError(f"{context}: invalid date {value!r}") from error


def record_identity(record_id: str, context: str) -> tuple[date, int]:
    match = RECORD_ID_RE.fullmatch(record_id)
    require(match is not None, f"{context}: invalid record ID {record_id!r}")
    year, month, day, sequence = match.groups()
    try:
        return date(int(year), int(month), int(day)), int(sequence)
    except ValueError as error:
        raise GovernanceValidationError(
            f"{context}: record ID contains an invalid calendar date"
        ) from error


def parse_task_id_list(value: str, context: str) -> frozenset[str]:
    list_pattern = re.compile(rf"`({TASK_ID_TEXT})`(?:\s*,\s*`({TASK_ID_TEXT})`)*")
    require(
        list_pattern.fullmatch(value.strip()) is not None,
        f"{context}: Task IDs must be a comma-separated list of backticked task IDs",
    )
    task_ids = TASK_ID_RE.findall(value)
    require(task_ids, f"{context}: expected at least one task ID")
    require(
        len(task_ids) == len(set(task_ids)),
        f"{context}: duplicate task ID in Task IDs field",
    )
    return frozenset(task_ids)


def heading_blocks(
    lines: Sequence[str], level: int, identifier_prefix: str
) -> list[tuple[str, list[str]]]:
    marker = "#" * level + " "
    prefix = marker + identifier_prefix
    blocks: list[tuple[str, list[str]]] = []
    starts: list[tuple[int, str]] = []
    for position, line in enumerate(lines):
        if line.startswith(prefix):
            heading_value = line[len(marker) :].strip()
            starts.append((position, heading_value))

    for position, heading_value in starts:
        end = len(lines)
        for candidate in range(position + 1, len(lines)):
            match = MARKDOWN_HEADING_RE.match(lines[candidate])
            if match is not None and len(match.group(1)) <= level:
                end = candidate
                break
        blocks.append((heading_value, list(lines[position + 1 : end])))
    return blocks


def markdown_headings(lines: Sequence[str]) -> list[tuple[int, int, str]]:
    """Return line number, level, and text for ATX and Setext headings."""

    headings: list[tuple[int, int, str]] = []
    for position, line in enumerate(lines):
        match = MARKDOWN_HEADING_RE.match(line)
        if match is not None:
            headings.append(
                (position + 1, len(match.group(1)), line[match.end() :].strip())
            )
            continue
        if position + 1 >= len(lines) or not line.strip():
            continue
        underline = lines[position + 1].strip()
        if re.fullmatch(r"=+", underline):
            headings.append((position + 1, 1, line.strip()))
        elif re.fullmatch(r"-+", underline):
            headings.append((position + 1, 2, line.strip()))
    return headings


def validate_archive_governance_headings(lines: Sequence[str], path: Path) -> None:
    contracts = (
        ("CFGRC-REC-", 3, RECORD_ID_RE, "record"),
        ("CFGRC-EXP-", 4, EXPERIMENT_ID_RE, "experiment"),
    )
    for line_number, level, heading in markdown_headings(lines):
        for prefix, expected_level, exact_pattern, label in contracts:
            if prefix not in heading:
                continue
            require(
                level == expected_level,
                f"{path}:{line_number}: canonical {label} {heading!r} must use heading level {expected_level}",
            )
            require(
                exact_pattern.fullmatch(heading) is not None,
                f"{path}:{line_number}: malformed canonical heading {heading!r}",
            )


def reject_progress_governance_headings(lines: Sequence[str], path: Path) -> None:
    for line_number, _level, heading in markdown_headings(lines):
        if "CFGRC-REC-" in heading:
            raise GovernanceValidationError(
                f"{path}:{line_number}: canonical record headings belong in monthly archives"
            )
        if "CFGRC-EXP-" in heading:
            raise GovernanceValidationError(
                f"{path}:{line_number}: experiment records belong in monthly archives"
            )


def strict_json_object(value: str, context: str) -> dict[str, Any]:
    value = strip_inline_code(value)

    def reject_constant(constant: str) -> None:
        raise ValueError(f"non-finite JSON constant {constant}")

    def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, item in pairs:
            if key in result:
                raise ValueError(f"duplicate JSON key {key!r}")
            result[key] = item
        return result

    try:
        payload = json.loads(
            value,
            parse_constant=reject_constant,
            object_pairs_hook=reject_duplicate_keys,
        )
    except (json.JSONDecodeError, ValueError) as error:
        raise GovernanceValidationError(
            f"{context}: Metrics is not strict JSON: {error}"
        ) from error
    require(
        isinstance(payload, dict) and bool(payload),
        f"{context}: Metrics must be a non-empty JSON object",
    )

    def require_finite(item: Any) -> None:
        if isinstance(item, float):
            require(
                math.isfinite(item), f"{context}: Metrics contains a non-finite number"
            )
        elif isinstance(item, dict):
            for child in item.values():
                require_finite(child)
        elif isinstance(item, list):
            for child in item:
                require_finite(child)

    require_finite(payload)
    return payload


def validate_experiment_block(
    experiment_id: str, block: Sequence[str], archive_month: str, path: Path
) -> str:
    match = EXPERIMENT_ID_RE.fullmatch(experiment_id)
    require(match is not None, f"{path}: invalid experiment ID {experiment_id!r}")
    year, month, _sequence = match.groups()
    require(
        f"{year}-{month}" == archive_month,
        f"{path}: experiment {experiment_id} month does not match archive {archive_month}",
    )
    context = f"{path}: experiment {experiment_id}"

    task_value = strip_inline_code(extract_exact_field(block, "Task ID", context))
    require(
        EXACT_TASK_ID_RE.fullmatch(task_value) is not None,
        f"{context}: invalid Task ID {task_value!r}",
    )

    upstream_commit = strip_inline_code(
        extract_exact_field(block, "Upstream commit", context)
    )
    require(
        COMMIT_RE.fullmatch(upstream_commit) is not None,
        f"{context}: Upstream commit must be a full 40- or 64-character lowercase hex OID",
    )

    model = strip_inline_code(extract_exact_field(block, "Model", context))
    require(bool(model), f"{context}: Model must not be empty")

    for field in ("Model SHA-256", "Config SHA-256", "Data SHA-256"):
        digest = strip_inline_code(extract_exact_field(block, field, context))
        require(
            SHA256_RE.fullmatch(digest) is not None,
            f"{context}: {field} must be sha256: followed by 64 lowercase hex characters",
        )

    for field in ("Hardware", "Command"):
        value = strip_inline_code(extract_exact_field(block, field, context))
        require(bool(value), f"{context}: {field} must not be empty")

    strict_json_object(extract_exact_field(block, "Metrics", context), context)
    return task_value


def parse_archives(
    archive_dir: Path,
) -> tuple[
    dict[str, ArchivedRecord], dict[str, tuple[Path, str]], list[tuple[Path, str]]
]:
    require(archive_dir.is_dir(), f"{archive_dir}: archive directory does not exist")
    records: dict[str, ArchivedRecord] = {}
    experiments: dict[str, tuple[Path, str]] = {}
    scanned_documents: list[tuple[Path, str]] = []

    archive_paths = sorted(archive_dir.glob("*.md"))
    for path in archive_paths:
        name_match = ARCHIVE_NAME_RE.fullmatch(path.name)
        require(
            name_match is not None,
            f"{path}: archive filename must be YYYY-MM.md",
        )
        archive_month = path.stem
        try:
            date.fromisoformat(f"{archive_month}-01")
        except ValueError as error:
            raise GovernanceValidationError(
                f"{path}: archive filename contains an invalid month"
            ) from error

        lines = read_lines(path)
        text = "\n".join(lines)
        scanned_documents.append((path, text))

        validate_archive_governance_headings(lines, path)
        for record_id, block in heading_blocks(lines, 3, "CFGRC-REC-"):
            context = f"{path}: record {record_id}"
            require(record_id not in records, f"{context}: duplicate record ID")
            identity_date, sequence = record_identity(record_id, context)
            completed = parse_iso_date(
                extract_exact_field(block, "Completed", context), context
            )
            require(
                completed == identity_date,
                f"{context}: Completed date {completed.isoformat()} does not match record ID date {identity_date.isoformat()}",
            )
            require(
                completed.strftime("%Y-%m") == archive_month,
                f"{context}: Completed date does not match archive month {archive_month}",
            )
            task_ids = parse_task_id_list(
                extract_exact_field(block, "Task IDs", context), context
            )
            records[record_id] = ArchivedRecord(
                record_id=record_id,
                completed=completed,
                sequence=sequence,
                task_ids=task_ids,
                path=path,
            )

        for experiment_id, block in heading_blocks(lines, 4, "CFGRC-EXP-"):
            context = f"{path}: experiment {experiment_id}"
            require(
                experiment_id not in experiments, f"{context}: duplicate experiment ID"
            )
            task_id = validate_experiment_block(
                experiment_id, block, archive_month, path
            )
            experiments[experiment_id] = (path, task_id)

    return records, experiments, scanned_documents


def parse_pointer(
    lines: Sequence[str], label: str, pattern: re.Pattern[str], path: Path
) -> str:
    prefix = f"- {label}:"
    candidates = [line for line in lines if line.startswith(prefix)]
    require(
        len(candidates) == 1,
        f"{path}: expected exactly one {label!r} pointer, found {len(candidates)}",
    )
    match = re.fullmatch(rf"- {re.escape(label)}: `([^`]+)`(?: — \S.*)?", candidates[0])
    require(match is not None, f"{path}: malformed {label!r} pointer {candidates[0]!r}")
    identifier = match.group(1)
    require(
        pattern.fullmatch(identifier) is not None,
        f"{path}: invalid {label} ID {identifier!r}",
    )
    return identifier


def parse_task_board(lines: Sequence[str], path: Path) -> tuple[str, set[str]]:
    headings = ("## Active task board", "## Task board")
    present = [heading for heading in headings if heading in lines]
    require(
        len(present) == 1,
        f"{path}: expected exactly one active task-board section, found {len(present)}",
    )
    section = find_exact_section(lines, present[0], path)
    table = parse_first_table(section, path, "Task board")
    task_column = header_index(table, "task id", path, "Task board")
    state_column = header_index(table, "state", path, "Task board")

    board_tasks: set[str] = set()
    in_progress: list[str] = []
    for row_number, row in enumerate(table.rows, start=1):
        task = exact_backticked_id(
            row[task_column],
            EXACT_TASK_ID_RE,
            f"{path}: Task board row {row_number}",
        )
        require(task not in board_tasks, f"{path}: duplicate Task board row for {task}")
        board_tasks.add(task)
        state = strip_inline_code(row[state_column])
        require(
            re.match(
                r"(?:complete(?:d)?|done|closed|delivered)\b", state, re.IGNORECASE
            )
            is None,
            f"{path}: Task board row {row_number} for {task} uses forbidden terminal State {state!r}",
        )
        if state == "In Progress":
            in_progress.append(task)
    require(
        len(in_progress) == 1,
        f"{path}: expected exactly one Task board row with State 'In Progress', found {len(in_progress)}",
    )
    return in_progress[0], board_tasks


def parse_recent_records(
    lines: Sequence[str], path: Path, archived_records: dict[str, ArchivedRecord]
) -> tuple[list[str], set[str]]:
    section = find_exact_section(lines, "## Recent records", path)
    table = parse_first_table(section, path, "Recent records")
    require(
        len(table.rows) <= MAX_RECENT_RECORDS,
        f"{path}: Recent records has {len(table.rows)} rows; maximum is {MAX_RECENT_RECORDS}",
    )

    record_ids: list[str] = []
    task_ids: set[str] = set()
    record_dates: list[date] = []
    for row_number, row in enumerate(table.rows, start=1):
        row_text = " | ".join(row)
        found_record_ids = sorted(set(RECORD_TOKEN_RE.findall(row_text)))
        require(
            len(found_record_ids) == 1,
            f"{path}: Recent records row {row_number} must contain exactly one record ID",
        )
        record_id = found_record_ids[0]
        require(
            record_id not in record_ids,
            f"{path}: Recent records contains duplicate record ID {record_id}",
        )
        require(
            record_id in archived_records,
            f"{path}: Recent records references missing archive record {record_id}",
        )

        found_dates = sorted(set(ISO_DATE_RE.findall(row_text)))
        require(
            len(found_dates) == 1,
            f"{path}: Recent records row {row_number} must contain exactly one YYYY-MM-DD date",
        )
        row_date = parse_iso_date(
            found_dates[0], f"{path}: Recent records row {row_number}"
        )
        archived = archived_records[record_id]
        require(
            row_date == archived.completed,
            f"{path}: Recent record {record_id} date does not match its archive record",
        )

        link_targets = MARKDOWN_LINK_RE.findall(row_text)
        require(
            len(link_targets) == 1,
            f"{path}: Recent records row {row_number} must contain exactly one relative Markdown link",
        )
        link_target = link_targets[0]
        require(
            "://" not in link_target
            and not link_target.startswith(("/", "//"))
            and "?" not in link_target,
            f"{path}: Recent record {record_id} archive link must be a relative path without a query",
        )
        link_path, separator, fragment = link_target.partition("#")
        require(
            separator == "#" and bool(link_path) and bool(fragment),
            f"{path}: Recent record {record_id} archive link must include a relative file and fragment",
        )
        resolved_link_path = (path.parent / link_path).resolve()
        require(
            resolved_link_path == archived.path.resolve(),
            f"{path}: Recent record {record_id} link resolves to {resolved_link_path}, not {archived.path.resolve()}",
        )
        expected_fragment = record_id.lower()
        require(
            fragment == expected_fragment,
            f"{path}: Recent record {record_id} link fragment must be #{expected_fragment}",
        )

        found_task_ids = frozenset(TASK_ID_RE.findall(row_text))
        require(
            bool(found_task_ids),
            f"{path}: Recent records row {row_number} must contain at least one task ID",
        )
        require(
            found_task_ids == archived.task_ids,
            f"{path}: Recent record {record_id} task IDs do not match its archive record",
        )
        task_ids.update(found_task_ids)
        record_ids.append(record_id)
        record_dates.append(row_date)

    require(
        record_dates == sorted(record_dates, reverse=True),
        f"{path}: Recent records must be ordered by descending YYYY-MM-DD",
    )
    expected_record_ids = [
        record.record_id
        for record in sorted(
            archived_records.values(),
            key=lambda record: (record.completed, record.sequence),
            reverse=True,
        )[:MAX_RECENT_RECORDS]
    ]
    require(
        record_ids == expected_record_ids,
        f"{path}: Recent records must equal the newest {len(expected_record_ids)} archive records by completion date and numeric sequence; expected {expected_record_ids}, got {record_ids}",
    )
    return record_ids, task_ids


def validate_task_references(
    documents: Sequence[tuple[Path, str]], registered_tasks: set[str]
) -> None:
    for path, text in documents:
        for task_id in sorted(set(TASK_ID_CANDIDATE_RE.findall(text))):
            require(
                EXACT_TASK_ID_RE.fullmatch(task_id) is not None,
                f"{path}: malformed task-shaped ID {task_id}",
            )
            require(
                task_id in registered_tasks,
                f"{path}: task ID {task_id} is not registered in the roadmap",
            )


def validate_project_governance(
    roadmap_path: Path = ROADMAP_PATH,
    progress_path: Path = PROGRESS_PATH,
    archive_dir: Path = ARCHIVE_DIR,
) -> GovernanceSummary:
    stages, task_stages = parse_roadmap(roadmap_path)
    records, experiments, archive_documents = parse_archives(archive_dir)

    progress_lines = read_lines(progress_path)
    require(
        len(progress_lines) <= MAX_PROGRESS_LINES,
        f"{progress_path}: {len(progress_lines)} lines exceeds the {MAX_PROGRESS_LINES}-line limit",
    )
    require(
        "## Activity log" not in progress_lines,
        f"{progress_path}: Activity log is forbidden; move canonical history to monthly archives",
    )
    reject_progress_governance_headings(progress_lines, progress_path)

    current_stage = parse_pointer(
        progress_lines, "Current Stage", STAGE_ID_RE, progress_path
    )
    active_task = parse_pointer(
        progress_lines, "In Progress Task", EXACT_TASK_ID_RE, progress_path
    )
    require(
        current_stage in stages,
        f"{progress_path}: unregistered Current Stage {current_stage}",
    )
    require(
        active_task in task_stages,
        f"{progress_path}: unregistered In Progress Task {active_task}",
    )
    require(
        task_stages[active_task] == current_stage,
        f"{progress_path}: In Progress Task {active_task} belongs to {task_stages[active_task]}, not {current_stage}",
    )

    board_active_task, _board_tasks = parse_task_board(progress_lines, progress_path)
    require(
        board_active_task == active_task,
        f"{progress_path}: In Progress Task pointer {active_task} does not match Task board {board_active_task}",
    )
    recent_record_ids, _recent_tasks = parse_recent_records(
        progress_lines, progress_path, records
    )

    progress_text = "\n".join(progress_lines)
    scanned_documents = [(progress_path, progress_text), *archive_documents]
    validate_task_references(scanned_documents, set(task_stages))

    for experiment_id, (path, task_id) in experiments.items():
        require(
            task_id in task_stages,
            f"{path}: experiment {experiment_id} uses unregistered task ID {task_id}",
        )

    return GovernanceSummary(
        stages=len(stages),
        tasks=len(task_stages),
        active_task=active_task,
        recent_records=len(recent_record_ids),
        archived_records=len(records),
        experiments=len(experiments),
        progress_lines=len(progress_lines),
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Validate China financial GRC project-governance Markdown."
    )
    parser.add_argument("--roadmap", type=Path, default=ROADMAP_PATH)
    parser.add_argument("--progress", type=Path, default=PROGRESS_PATH)
    parser.add_argument("--archive-dir", type=Path, default=ARCHIVE_DIR)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = build_parser().parse_args(argv)
    try:
        summary = validate_project_governance(
            roadmap_path=arguments.roadmap,
            progress_path=arguments.progress,
            archive_dir=arguments.archive_dir,
        )
    except (GovernanceValidationError, OSError) as error:
        print(f"FAIL — {error}", file=sys.stderr)
        return 1

    print(
        "PASS — project governance: "
        f"{summary.stages} stages; {summary.tasks} roadmap tasks; "
        f"active {summary.active_task}; {summary.recent_records} recent records; "
        f"{summary.archived_records} archived records; "
        f"{summary.experiments} experiments; {summary.progress_lines} progress lines"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
