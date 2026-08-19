#!/usr/bin/env python3
"""Validate the China financial GRC foundation artifacts.

This is a deliberately small repository-level linter. It validates the
regulatory interchange JSON Schema and performs cross-file checks that the
generic CISO Assistant YAML loader does not currently expose as a standalone
command. Loader-level behaviour is covered by
``backend/library/tests/test_cn_financial_libraries.py``.
"""

from __future__ import annotations

import json
import re
import sys
from collections import Counter
from collections.abc import Callable, Iterable
from datetime import date, datetime
from pathlib import Path
from typing import Any

import yaml
from jsonschema import Draft202012Validator, FormatChecker
from jsonschema.exceptions import SchemaError


REPO_ROOT = Path(__file__).resolve().parents[2]
FOUNDATION_DIR = REPO_ROOT / "documentation" / "china-financial-grc"
SCHEMA_PATH = FOUNDATION_DIR / "schemas" / "regulatory-record.schema.json"
CATALOG_PATH = FOUNDATION_DIR / "catalogs" / "regulatory-sources.json"
EXAMPLE_PATH = FOUNDATION_DIR / "examples" / "regulatory-record.example.json"
COMMON_CONTROLS_PATH = (
    REPO_ROOT
    / "backend"
    / "library"
    / "libraries"
    / "cn-financial-common-controls.yaml"
)
BASELINE_PATH = (
    REPO_ROOT / "backend" / "library" / "libraries" / "cn-financial-baseline.yaml"
)
PRODUCT_DOCS_DIR = REPO_ROOT / "product-docs" / "guides" / "china-financial-grc"
PRODUCT_DOCS_SUMMARY = REPO_ROOT / "product-docs" / "SUMMARY.md"

REQUIRED_LIBRARY_FIELDS = {
    "urn",
    "locale",
    "ref_id",
    "name",
    "description",
    "copyright",
    "version",
    "publication_date",
    "provider",
    "packager",
    "objects",
}
URN_PATTERN = re.compile(r"^urn:[a-z0-9._-]+:risk:[a-z_]+:[a-z0-9._:-]+$")
CONTROL_URN_PREFIX = (
    "urn:yydspanda:risk:reference_control:cn-financial-common-controls:"
)
ALLOWED_CONTROL_CATEGORIES = {"policy", "process", "technical", "physical", "procedure"}
ALLOWED_CSF_FUNCTIONS = {
    "govern",
    "identify",
    "protect",
    "detect",
    "respond",
    "recover",
}
MARKDOWN_LINK_PATTERN = re.compile(r"(?<!!)\[[^\]]+\]\(([^)]+)\)")


class ValidationFailure(Exception):
    """Raised when an artifact violates a foundation invariant."""


def load_json(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as stream:
        value = json.load(stream)
    if not isinstance(value, dict):
        raise ValidationFailure(f"{path}: expected a JSON object")
    return value


def load_yaml(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as stream:
        value = yaml.safe_load(stream)
    if not isinstance(value, dict):
        raise ValidationFailure(f"{path}: expected a YAML mapping")
    return value


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValidationFailure(message)


def require_unique(values: Iterable[str], label: str) -> set[str]:
    seen: set[str] = set()
    duplicates: set[str] = set()
    for value in values:
        if value in seen:
            duplicates.add(value)
        seen.add(value)
    require(not duplicates, f"{label}: duplicate identifiers: {sorted(duplicates)}")
    return seen


def index_by_id(items: list[dict[str, Any]], label: str) -> dict[str, dict[str, Any]]:
    require_unique((item["id"] for item in items), label)
    return {item["id"]: item for item in items}


def validate_half_open_interval(
    record: dict[str, Any],
    start_key: str,
    end_key: str,
    parser: Callable[[str], date | datetime],
    label: str,
) -> None:
    start = record[start_key]
    end = record[end_key]
    if start is None or end is None:
        return
    try:
        parsed_start = parser(start)
        parsed_end = parser(end)
    except ValueError as error:
        raise ValidationFailure(f"{label}: invalid interval: {error}") from error
    require(
        parsed_start < parsed_end,
        f"{label}: expected half-open interval {start_key} < {end_key}",
    )


def parse_datetime(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def validate_acyclic_supersession(
    records_by_id: dict[str, dict[str, Any]],
    edge_reader: Callable[[dict[str, Any]], Iterable[str]],
    label: str,
) -> None:
    for start_id in records_by_id:
        active: set[str] = set()
        complete: set[str] = set()

        def visit(record_id: str) -> None:
            require(
                record_id not in active, f"{label}: supersession cycle at {record_id}"
            )
            if record_id in complete:
                return
            active.add(record_id)
            for predecessor_id in edge_reader(records_by_id[record_id]):
                require(
                    predecessor_id in records_by_id,
                    f"{label}: {record_id} supersedes unknown {predecessor_id}",
                )
                require(
                    predecessor_id != record_id,
                    f"{label}: {record_id} cannot supersede itself",
                )
                visit(predecessor_id)
            active.remove(record_id)
            complete.add(record_id)

        visit(start_id)


def validate_regulatory_records(control_urns: set[str]) -> None:
    schema = load_json(SCHEMA_PATH)
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema, format_checker=FormatChecker())

    for path in (CATALOG_PATH, EXAMPLE_PATH):
        record = load_json(path)
        errors = sorted(
            validator.iter_errors(record), key=lambda error: list(error.path)
        )
        if errors:
            rendered = "\n".join(
                f"  - {'/'.join(str(part) for part in error.path) or '<root>'}: {error.message}"
                for error in errors
            )
            raise ValidationFailure(
                f"{path}: JSON Schema validation failed\n{rendered}"
            )

        documents_by_id = index_by_id(record["documents"], f"{path}: documents")
        versions_by_id = index_by_id(
            record["document_versions"], f"{path}: document versions"
        )
        provisions_by_id = index_by_id(record["provisions"], f"{path}: provisions")
        obligations_by_id = index_by_id(record["obligations"], f"{path}: obligations")
        rules_by_id = index_by_id(
            record["applicability_rules"], f"{path}: applicability rules"
        )
        applicability_decisions_by_id = index_by_id(
            record["applicability_decisions"],
            f"{path}: applicability decisions",
        )
        mappings_by_id = index_by_id(
            record["control_mappings"], f"{path}: control mappings"
        )
        decisions_by_id = index_by_id(
            record["decision_records"], f"{path}: decision records"
        )

        for version in versions_by_id.values():
            require(
                version["document_id"] in documents_by_id,
                f"{path}: document version {version['id']} references an unknown document",
            )
            for predecessor_id in version["supersedes_version_ids"]:
                if predecessor_id in versions_by_id:
                    require(
                        versions_by_id[predecessor_id]["document_id"]
                        == version["document_id"],
                        f"{path}: document version {version['id']} supersedes a version of another document",
                    )
            if version["status"] in {"effective", "published_future_effective"}:
                require(
                    version["valid_from"] is not None,
                    f"{path}: {version['status']} document version {version['id']} needs valid_from",
                )
            status_as_of = date.fromisoformat(version["status_as_of"])
            effective_date = (
                date.fromisoformat(version["effective_date"])
                if version["effective_date"] is not None
                else None
            )
            if version["status"] == "effective":
                require(
                    effective_date is not None and effective_date <= status_as_of,
                    f"{path}: effective document version {version['id']} is inconsistent with status_as_of",
                )
            if version["status"] == "published_future_effective":
                require(
                    effective_date is not None and effective_date > status_as_of,
                    f"{path}: future-effective document version {version['id']} is inconsistent with status_as_of",
                )
            if version["status"] == "active_no_explicit_commencement":
                require(
                    version["effective_date"] is None
                    and version["effective_basis"] == "no_explicit_commencement_clause",
                    f"{path}: active document version {version['id']} must preserve the absent commencement date",
                )
            if version["effective_date"] is not None:
                require(
                    version["valid_from"] == version["effective_date"],
                    f"{path}: document version {version['id']} valid_from must match effective_date",
                )
            if version["legal_review_status"] == "reviewed":
                require(
                    bool(version["legal_reviewed_at"])
                    and bool(version["legal_reviewed_by"]),
                    f"{path}: reviewed document version {version['id']} needs reviewer and time",
                )
            else:
                require(
                    version["legal_reviewed_at"] is None
                    and version["legal_reviewed_by"] is None,
                    f"{path}: unreviewed document version {version['id']} cannot name a legal review",
                )
            validate_half_open_interval(
                version,
                "valid_from",
                "valid_to",
                date.fromisoformat,
                f"{path}: {version['id']}",
            )
            validate_half_open_interval(
                version,
                "recorded_from",
                "recorded_to",
                parse_datetime,
                f"{path}: {version['id']}",
            )
        validate_acyclic_supersession(
            versions_by_id,
            lambda item: item["supersedes_version_ids"],
            f"{path}: document versions",
        )
        require(
            {version["document_id"] for version in versions_by_id.values()}
            == set(documents_by_id),
            f"{path}: every document must have at least one version",
        )

        for provision in provisions_by_id.values():
            require(
                provision["document_id"] in documents_by_id,
                f"{path}: provision {provision['id']} references an unknown document",
            )
            require(
                provision["version_id"] in versions_by_id,
                f"{path}: provision {provision['id']} references an unknown document version",
            )
            require(
                versions_by_id[provision["version_id"]]["document_id"]
                == provision["document_id"],
                f"{path}: provision {provision['id']} document/version mismatch",
            )
            validate_half_open_interval(
                provision,
                "recorded_from",
                "recorded_to",
                parse_datetime,
                f"{path}: {provision['id']}",
            )

        for obligation in obligations_by_id.values():
            unknown = set(obligation["provision_ids"]) - provisions_by_id.keys()
            require(
                not unknown,
                f"{path}: obligation {obligation['id']} references unknown provisions {sorted(unknown)}",
            )
            validate_half_open_interval(
                obligation,
                "valid_from",
                "valid_to",
                date.fromisoformat,
                f"{path}: {obligation['id']}",
            )
            validate_half_open_interval(
                obligation,
                "recorded_from",
                "recorded_to",
                parse_datetime,
                f"{path}: {obligation['id']}",
            )

        for rule in rules_by_id.values():
            require(
                rule["obligation_id"] in obligations_by_id,
                f"{path}: applicability rule {rule['id']} references an unknown obligation",
            )
            require(
                bool(rule["all"] or rule["any"]),
                f"{path}: applicability rule {rule['id']} needs at least one condition",
            )
            predecessor_id = rule["supersedes_rule_id"]
            if predecessor_id is not None and predecessor_id in rules_by_id:
                predecessor = rules_by_id[predecessor_id]
                require(
                    predecessor["obligation_id"] == rule["obligation_id"],
                    f"{path}: applicability rule {rule['id']} supersedes a rule for another obligation",
                )
                require(
                    predecessor["version"] < rule["version"],
                    f"{path}: applicability rule {rule['id']} version must increase",
                )
            validate_half_open_interval(
                rule,
                "valid_from",
                "valid_to",
                date.fromisoformat,
                f"{path}: {rule['id']}",
            )
            validate_half_open_interval(
                rule,
                "recorded_from",
                "recorded_to",
                parse_datetime,
                f"{path}: {rule['id']}",
            )
        validate_acyclic_supersession(
            rules_by_id,
            lambda item: (
                [item["supersedes_rule_id"]]
                if item["supersedes_rule_id"] is not None
                else []
            ),
            f"{path}: applicability rules",
        )

        for applicability_decision in applicability_decisions_by_id.values():
            obligation_id = applicability_decision["obligation_id"]
            require(
                obligation_id in obligations_by_id,
                f"{path}: applicability decision {applicability_decision['id']} references an unknown obligation",
            )
            rule_ref = applicability_decision["rule"]
            require(
                rule_ref["id"] in rules_by_id,
                f"{path}: applicability decision {applicability_decision['id']} references an unknown rule",
            )
            rule = rules_by_id[rule_ref["id"]]
            require(
                rule_ref["version"] == rule["version"],
                f"{path}: applicability decision {applicability_decision['id']} rule version mismatch",
            )
            require(
                rule["obligation_id"] == obligation_id,
                f"{path}: applicability decision {applicability_decision['id']} rule/obligation mismatch",
            )
            facts = {item["fact"]: item for item in applicability_decision["facts"]}
            require(
                len(facts) == len(applicability_decision["facts"]),
                f"{path}: applicability decision {applicability_decision['id']} has duplicate facts",
            )
            referenced_facts = {
                condition["fact"] for condition in [*rule["all"], *rule["any"]]
            }
            unknown_required_fact = any(
                fact_name not in facts or not facts[fact_name]["known"]
                for fact_name in referenced_facts
            )
            if unknown_required_fact:
                require(
                    applicability_decision["result"] == "needs_review",
                    f"{path}: applicability decision {applicability_decision['id']} must escalate unknown rule facts",
                )
            validate_half_open_interval(
                applicability_decision,
                "valid_from",
                "valid_to",
                date.fromisoformat,
                f"{path}: {applicability_decision['id']}",
            )
            validate_half_open_interval(
                applicability_decision,
                "recorded_from",
                "recorded_to",
                parse_datetime,
                f"{path}: {applicability_decision['id']}",
            )

        for mapping in mappings_by_id.values():
            require(
                mapping["obligation_id"] in obligations_by_id,
                f"{path}: control mapping {mapping['id']} references an unknown obligation",
            )
            require(
                mapping["control_urn"] in control_urns,
                f"{path}: control mapping {mapping['id']} references an unknown control URN",
            )
            predecessor_id = mapping["supersedes_mapping_id"]
            if predecessor_id is not None and predecessor_id in mappings_by_id:
                predecessor = mappings_by_id[predecessor_id]
                require(
                    predecessor["obligation_id"] == mapping["obligation_id"]
                    and predecessor["control_urn"] == mapping["control_urn"],
                    f"{path}: control mapping {mapping['id']} supersedes a different relationship",
                )
                require(
                    predecessor["version"] < mapping["version"],
                    f"{path}: control mapping {mapping['id']} version must increase",
                )
            validate_half_open_interval(
                mapping,
                "valid_from",
                "valid_to",
                date.fromisoformat,
                f"{path}: {mapping['id']}",
            )
            validate_half_open_interval(
                mapping,
                "recorded_from",
                "recorded_to",
                parse_datetime,
                f"{path}: {mapping['id']}",
            )
        validate_acyclic_supersession(
            mappings_by_id,
            lambda item: (
                [item["supersedes_mapping_id"]]
                if item["supersedes_mapping_id"] is not None
                else []
            ),
            f"{path}: control mappings",
        )

        subject_ids = {
            "document": set(documents_by_id),
            "document_version": set(versions_by_id),
            "provision": set(provisions_by_id),
            "obligation": set(obligations_by_id),
            "applicability_rule": set(rules_by_id),
            "applicability_decision": set(applicability_decisions_by_id),
            "control_mapping": set(mappings_by_id),
        }
        record_generated_at = parse_datetime(record["generated_at"])
        latest_decisions: dict[tuple[str, str], dict[str, Any]] = {}
        for decision in decisions_by_id.values():
            require(
                decision["subject_id"] in subject_ids[decision["subject_type"]],
                f"{path}: decision {decision['id']} references an unknown typed subject",
            )
            decided_at = parse_datetime(decision["decided_at"])
            require(
                decided_at <= record_generated_at,
                f"{path}: decision {decision['id']} occurs after the record was generated",
            )
            if decision.get("expires_at") is not None:
                require(
                    decided_at < parse_datetime(decision["expires_at"]),
                    f"{path}: decision {decision['id']} must expire after it was made",
                )
            if decision["decision"] == "approve":
                require(
                    decision["payload_sha256"] != "0" * 64,
                    f"{path}: approving decision {decision['id']} cannot use the placeholder digest",
                )
            subject_key = (decision["subject_type"], decision["subject_id"])
            ordering_key = (decided_at, decision["id"])
            previous = latest_decisions.get(subject_key)
            if previous is None or ordering_key > (
                parse_datetime(previous["decided_at"]),
                previous["id"],
            ):
                latest_decisions[subject_key] = decision

        active_approvals = {
            subject_key: decision
            for subject_key, decision in latest_decisions.items()
            if decision["decision"] == "approve"
            and (
                decision.get("expires_at") is None
                or parse_datetime(decision["expires_at"]) > record_generated_at
            )
        }
        for obligation in obligations_by_id.values():
            if obligation["review_status"] == "approved":
                subject_key = ("obligation", obligation["id"])
                require(
                    subject_key in active_approvals,
                    f"{path}: approved obligation {obligation['id']} has no approving decision record",
                )
                require(
                    parse_datetime(active_approvals[subject_key]["decided_at"])
                    >= parse_datetime(obligation["recorded_from"]),
                    f"{path}: obligation {obligation['id']} was approved before it was recorded",
                )
        for rule in rules_by_id.values():
            if rule["review_status"] == "approved":
                subject_key = ("applicability_rule", rule["id"])
                require(
                    subject_key in active_approvals,
                    f"{path}: approved rule {rule['id']} has no approving decision record",
                )
                require(
                    parse_datetime(active_approvals[subject_key]["decided_at"])
                    >= parse_datetime(rule["recorded_from"]),
                    f"{path}: applicability rule {rule['id']} was approved before it was recorded",
                )
        for applicability_decision in applicability_decisions_by_id.values():
            if applicability_decision["review_status"] == "confirmed":
                subject_key = (
                    "applicability_decision",
                    applicability_decision["id"],
                )
                require(
                    subject_key in active_approvals,
                    f"{path}: confirmed applicability decision {applicability_decision['id']} has no approving decision record",
                )
                require(
                    parse_datetime(active_approvals[subject_key]["decided_at"])
                    >= parse_datetime(applicability_decision["recorded_from"]),
                    f"{path}: applicability decision {applicability_decision['id']} was approved before it was recorded",
                )
        for mapping in mappings_by_id.values():
            if mapping["review_status"] == "approved":
                subject_key = ("control_mapping", mapping["id"])
                require(
                    subject_key in active_approvals,
                    f"{path}: approved mapping {mapping['id']} has no approving decision record",
                )
                require(
                    parse_datetime(active_approvals[subject_key]["decided_at"])
                    >= parse_datetime(mapping["recorded_from"]),
                    f"{path}: control mapping {mapping['id']} was approved before it was recorded",
                )


def validate_library_metadata(library: dict[str, Any], path: Path) -> None:
    missing = REQUIRED_LIBRARY_FIELDS - library.keys()
    require(not missing, f"{path}: missing library fields {sorted(missing)}")
    require(isinstance(library["version"], int), f"{path}: version must be an integer")
    require(library["version"] >= 1, f"{path}: version must be positive")
    require(library["locale"] == "zh", f"{path}: expected base locale zh")
    require(library["packager"] == "yydspanda", f"{path}: unexpected packager")
    require(bool(URN_PATTERN.fullmatch(library["urn"])), f"{path}: invalid library URN")
    require(isinstance(library["objects"], dict), f"{path}: objects must be a mapping")


def validate_parent_graph(nodes: list[dict[str, Any]], path: Path) -> None:
    nodes_by_urn = {node["urn"]: node for node in nodes}
    for node in nodes:
        parent = node.get("parent_urn")
        require(
            parent is None or parent in nodes_by_urn,
            f"{path}: node {node['urn']} references an unknown parent {parent}",
        )

    for start in nodes_by_urn:
        visited: set[str] = set()
        current: str | None = start
        while current is not None:
            require(
                current not in visited,
                f"{path}: requirement-node parent cycle at {current}",
            )
            visited.add(current)
            current = nodes_by_urn[current].get("parent_urn")


def validate_ciso_libraries() -> set[str]:
    common = load_yaml(COMMON_CONTROLS_PATH)
    baseline = load_yaml(BASELINE_PATH)
    validate_library_metadata(common, COMMON_CONTROLS_PATH)
    validate_library_metadata(baseline, BASELINE_PATH)

    controls = common["objects"].get("reference_controls")
    require(
        isinstance(controls, list),
        f"{COMMON_CONTROLS_PATH}: reference_controls must be a list",
    )
    require(
        len(controls) == 18, f"{COMMON_CONTROLS_PATH}: expected 18 starter controls"
    )
    control_urns = require_unique(
        (control["urn"] for control in controls), f"{COMMON_CONTROLS_PATH}: controls"
    )
    require_unique(
        (control["ref_id"] for control in controls),
        f"{COMMON_CONTROLS_PATH}: control ref_ids",
    )
    for control in controls:
        require(
            control["urn"].startswith(CONTROL_URN_PREFIX),
            f"{COMMON_CONTROLS_PATH}: control {control['ref_id']} must use the canonical modern URN",
        )
        require(
            control.get("category") in ALLOWED_CONTROL_CATEGORIES,
            f"{COMMON_CONTROLS_PATH}: invalid category on {control['ref_id']}",
        )
        require(
            control.get("csf_function") in ALLOWED_CSF_FUNCTIONS,
            f"{COMMON_CONTROLS_PATH}: invalid CSF function on {control['ref_id']}",
        )
        require(
            isinstance(control.get("typical_evidence"), list)
            and bool(control["typical_evidence"])
            and all(
                isinstance(item, str) and bool(item.strip())
                for item in control["typical_evidence"]
            ),
            f"{COMMON_CONTROLS_PATH}: {control['ref_id']} needs typical evidence",
        )

    dependencies = baseline.get("dependencies", [])
    require(
        common["urn"] in dependencies,
        f"{BASELINE_PATH}: common-control dependency is missing",
    )
    frameworks = baseline["objects"].get("frameworks")
    require(
        isinstance(frameworks, list) and len(frameworks) == 1,
        f"{BASELINE_PATH}: expected one canonical frameworks list entry",
    )
    framework = frameworks[0]
    group_definitions = framework.get("implementation_groups_definition")
    require(
        isinstance(group_definitions, list) and bool(group_definitions),
        f"{BASELINE_PATH}: implementation group definitions are missing",
    )
    group_ids = require_unique(
        (group["ref_id"] for group in group_definitions),
        f"{BASELINE_PATH}: implementation groups",
    )
    require(
        group_ids == {"COMMON", "BANK", "INSURANCE", "FINTECH"},
        f"{BASELINE_PATH}: expected COMMON/BANK/INSURANCE/FINTECH groups",
    )
    common_group = next(
        group for group in group_definitions if group["ref_id"] == "COMMON"
    )
    require(
        common_group.get("default_selected") is True,
        f"{BASELINE_PATH}: COMMON must be the safe default group",
    )
    nodes = framework.get("requirement_nodes")
    require(
        isinstance(nodes, list) and bool(nodes),
        f"{BASELINE_PATH}: no requirement nodes",
    )
    require_unique(
        (node["urn"] for node in nodes), f"{BASELINE_PATH}: requirement nodes"
    )
    require_unique((node["ref_id"] for node in nodes), f"{BASELINE_PATH}: node ref_ids")
    validate_parent_graph(nodes, BASELINE_PATH)

    assessable_nodes = [node for node in nodes if node.get("assessable") is True]
    headings = [node for node in nodes if node.get("assessable") is False]
    require(
        len(nodes) == 26 and len(assessable_nodes) == 18 and len(headings) == 8,
        f"{BASELINE_PATH}: expected 26 nodes (8 headings and 18 assessable controls)",
    )
    heading_urns = {node["urn"] for node in headings}
    for node in nodes:
        require(
            isinstance(node.get("assessable"), bool),
            f"{BASELINE_PATH}: node {node.get('urn')} must declare assessable",
        )
    for heading in headings:
        require(
            heading.get("parent_urn") is None,
            f"{BASELINE_PATH}: heading {heading['ref_id']} must be top-level",
        )
        require(
            any(node.get("parent_urn") == heading["urn"] for node in assessable_nodes),
            f"{BASELINE_PATH}: heading {heading['ref_id']} has no assessable child",
        )

    reference_counts: Counter[str] = Counter()
    group_usage_counts: Counter[str] = Counter()
    used_group_ids: set[str] = set()
    for node in assessable_nodes:
        require(
            node.get("parent_urn") in heading_urns,
            f"{BASELINE_PATH}: assessable node {node['ref_id']} needs a heading parent",
        )
        require(
            isinstance(node.get("typical_evidence"), str)
            and bool(node["typical_evidence"].strip()),
            f"{BASELINE_PATH}: assessable node {node['ref_id']} needs typical evidence",
        )
        implementation_groups = node.get("implementation_groups")
        require(
            isinstance(implementation_groups, list) and bool(implementation_groups),
            f"{BASELINE_PATH}: assessable node {node['ref_id']} needs implementation groups",
        )
        unknown_groups = set(implementation_groups) - group_ids
        require(
            len(implementation_groups) == len(set(implementation_groups)),
            f"{BASELINE_PATH}: node {node['ref_id']} has duplicate implementation groups",
        )
        require(
            not unknown_groups,
            f"{BASELINE_PATH}: node {node['ref_id']} uses unknown groups {sorted(unknown_groups)}",
        )
        used_group_ids.update(implementation_groups)
        group_usage_counts.update(implementation_groups)
        references = node.get("reference_controls")
        require(
            isinstance(references, list) and bool(references),
            f"{BASELINE_PATH}: assessable node {node['ref_id']} has no control",
        )
        unknown = set(references) - control_urns
        require(
            not unknown,
            f"{BASELINE_PATH}: node {node['ref_id']} references unknown controls {sorted(unknown)}",
        )
        reference_counts.update(references)

    require(
        used_group_ids == group_ids,
        f"{BASELINE_PATH}: every implementation group must be used",
    )
    require(
        group_usage_counts
        == Counter({"COMMON": 16, "BANK": 18, "INSURANCE": 18, "FINTECH": 18}),
        f"{BASELINE_PATH}: unexpected implementation-group coverage",
    )
    require(
        set(reference_counts) == control_urns
        and sum(reference_counts.values()) == len(control_urns)
        and all(count == 1 for count in reference_counts.values()),
        f"{BASELINE_PATH}: the 18 controls must each be referenced exactly once",
    )
    return control_urns


def validate_documentation_links() -> None:
    markdown_files = [*FOUNDATION_DIR.rglob("*.md"), *PRODUCT_DOCS_DIR.rglob("*.md")]
    require(bool(markdown_files), "No China financial GRC documentation found")

    for path in markdown_files:
        text = path.read_text(encoding="utf-8")
        for raw_target in MARKDOWN_LINK_PATTERN.findall(text):
            target = raw_target.strip().split("#", 1)[0]
            if not target or target.startswith(("https://", "http://", "mailto:")):
                continue
            resolved = (path.parent / target).resolve()
            require(
                resolved.exists(),
                f"{path}: broken relative link {raw_target}",
            )

    summary = PRODUCT_DOCS_SUMMARY.read_text(encoding="utf-8")
    for path in PRODUCT_DOCS_DIR.glob("*.md"):
        relative = path.relative_to(PRODUCT_DOCS_SUMMARY.parent).as_posix()
        require(relative in summary, f"{PRODUCT_DOCS_SUMMARY}: missing {relative}")


def main() -> int:
    try:
        control_urns = validate_ciso_libraries()
        validate_regulatory_records(control_urns)
        validate_documentation_links()
    except (
        OSError,
        ValueError,
        SchemaError,
        yaml.YAMLError,
        ValidationFailure,
    ) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1

    print("China financial GRC artifacts are valid.")
    print(f"  schema: {SCHEMA_PATH.relative_to(REPO_ROOT)}")
    print(f"  source catalog: {CATALOG_PATH.relative_to(REPO_ROOT)}")
    print(f"  example: {EXAMPLE_PATH.relative_to(REPO_ROOT)}")
    print(f"  controls: {COMMON_CONTROLS_PATH.relative_to(REPO_ROOT)}")
    print(f"  baseline: {BASELINE_PATH.relative_to(REPO_ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
