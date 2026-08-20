#!/usr/bin/env python3
"""Validate the China financial GRC foundation artifacts.

This repository-level linter validates the regulatory interchange and
applicability-fact JSON Schemas, the domain source packs, and cross-file checks
that the generic CISO Assistant YAML loader does not currently expose as a
standalone command. Loader-level behaviour is covered by
``backend/library/tests/test_cn_financial_libraries.py``.
"""

from __future__ import annotations

import json
import hashlib
import math
import re
import sys
import unicodedata
from collections import Counter
from collections.abc import Callable, Iterable
from datetime import date, datetime
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import yaml
from jsonschema import Draft202012Validator, FormatChecker
from jsonschema.exceptions import SchemaError


REPO_ROOT = Path(__file__).resolve().parents[2]
FOUNDATION_DIR = REPO_ROOT / "documentation" / "china-financial-grc"
SCHEMA_PATH = FOUNDATION_DIR / "schemas" / "regulatory-record.schema.json"
FACT_SCHEMA_PATH = FOUNDATION_DIR / "schemas" / "applicability-fact.schema.json"
PACK_INDEX_SCHEMA_PATH = (
    FOUNDATION_DIR / "schemas" / "regulatory-pack-index.schema.json"
)
CATALOGS_DIR = FOUNDATION_DIR / "catalogs"
CORE_CATALOG_PATH = CATALOGS_DIR / "regulatory-sources.json"
FACT_CATALOG_PATH = CATALOGS_DIR / "applicability-facts.json"
PACK_INDEX_PATH = CATALOGS_DIR / "regulatory-pack-index.json"
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
SOURCE_PACK_MINIMUM_DOCUMENTS = {
    "regulatory-sources.json": 26,
    "banking-regulatory-sources.json": 16,
    "insurance-regulatory-sources.json": 14,
    "fintech-data-regulatory-sources.json": 20,
}
EXPECTED_PACK_CATALOGS = {
    "common": "regulatory-sources.json",
    "banking": "banking-regulatory-sources.json",
    "insurance": "insurance-regulatory-sources.json",
    "fintech-data-ai": "fintech-data-regulatory-sources.json",
}
EXPECTED_PROFILE_PACKS = {
    "COMMON": {"common"},
    "BANK": {"common", "banking", "fintech-data-ai"},
    "INSURANCE": {"common", "banking", "insurance", "fintech-data-ai"},
    "FINTECH": {"common", "fintech-data-ai"},
    "PAYMENT": {"common", "fintech-data-ai"},
}
MINIMUM_APPLICABILITY_FACTS = 56
PAYLOAD_DIGEST_PROFILE = "cn-financial-grc-canonical-json-v1"
FACT_OPERATORS = {
    "boolean": {"eq", "ne", "exists"},
    "string": {"eq", "ne", "in", "not_in", "exists"},
    "integer": {"eq", "ne", "in", "not_in", "gt", "gte", "lt", "lte", "exists"},
    "decimal": {"eq", "ne", "in", "not_in", "gt", "gte", "lt", "lte", "exists"},
    "date": {"eq", "ne", "in", "not_in", "gt", "gte", "lt", "lte", "exists"},
    "set": {"eq", "ne", "contains", "exists"},
}
APPROVAL_DERIVED_FIELDS = {
    "document_version": {
        "legal_review_status",
        "legal_reviewed_at",
        "legal_reviewed_by",
        "recorded_to",
    },
    "provision": {"recorded_to"},
    "obligation": {"review_status", "recorded_to"},
    "applicability_rule": {"review_status", "recorded_to"},
    "applicability_decision": {
        "review_status",
        "confirmed_by",
        "confirmed_at",
        "recorded_to",
    },
    "control_mapping": {"review_status", "recorded_to"},
}

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
    def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                raise ValidationFailure(f"{path}: duplicate JSON key {key!r}")
            value[key] = item
        return value

    def reject_non_json_constant(value: str) -> None:
        raise ValidationFailure(f"{path}: non-JSON numeric constant {value!r}")

    with path.open(encoding="utf-8") as stream:
        value = json.load(
            stream,
            object_pairs_hook=reject_duplicate_keys,
            parse_constant=reject_non_json_constant,
        )
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


def validate_interval_containment(
    child: dict[str, Any],
    parent: dict[str, Any],
    start_key: str,
    end_key: str,
    parser: Callable[[str], date | datetime],
    label: str,
) -> None:
    """Require one half-open interval to be contained in another.

    A null start is unbounded toward the past and a null end is unbounded toward
    the future. Consequently, an unbounded child edge cannot fit inside a
    bounded parent edge.
    """

    child_start = child[start_key]
    child_end = child[end_key]
    parent_start = parent[start_key]
    parent_end = parent[end_key]

    if parent_start is not None:
        require(
            child_start is not None and parser(child_start) >= parser(parent_start),
            f"{label}: child interval starts outside its parent interval",
        )
    if parent_end is not None:
        require(
            child_end is not None and parser(child_end) <= parser(parent_end),
            f"{label}: child interval ends outside its parent interval",
        )


def parse_datetime(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def validate_record_times(
    record: dict[str, Any], generated_at: datetime, label: str
) -> None:
    for field in ("recorded_from", "recorded_to"):
        value = record.get(field)
        if value is not None:
            require(
                parse_datetime(value) <= generated_at,
                f"{label}: {field} occurs after the record was generated",
            )
    provenance = record.get("provenance")
    if provenance is not None:
        require(
            parse_datetime(provenance["created_at"]) <= generated_at,
            f"{label}: provenance was created after the record was generated",
        )


def normalize_identity(value: str) -> str:
    return unicodedata.normalize("NFKC", value.strip()).casefold()


def canonical_subject_digest(
    schema_version: str, subject_type: str, subject: dict[str, Any]
) -> str:
    excluded_fields = APPROVAL_DERIVED_FIELDS.get(subject_type, set())
    payload = {
        key: value for key, value in subject.items() if key not in excluded_fields
    }
    envelope = {
        "payload": payload,
        "profile": PAYLOAD_DIGEST_PROFILE,
        "schema_version": schema_version,
        "subject_id": subject["id"],
        "subject_type": subject_type,
    }
    canonical = json.dumps(
        envelope,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def canonicalize_fact_value(
    value: Any, definition: dict[str, Any], label: str
) -> bool | str | int | Decimal | date | frozenset[str]:
    value_type = definition["value_type"]
    allowed_values = definition.get("allowed_values")
    if value_type == "boolean":
        require(type(value) is bool, f"{label}: expected a boolean")
        normalized: bool | str | int | Decimal | date | frozenset[str] = value
    elif value_type == "string":
        require(
            isinstance(value, str) and bool(value.strip()),
            f"{label}: expected a non-empty string",
        )
        normalized = value
    elif value_type == "integer":
        require(
            isinstance(value, int) and not isinstance(value, bool),
            f"{label}: expected an integer",
        )
        normalized = value
    elif value_type == "decimal":
        require(
            isinstance(value, (int, float)) and not isinstance(value, bool),
            f"{label}: expected a finite JSON number",
        )
        require(
            not isinstance(value, float) or math.isfinite(value),
            f"{label}: expected a finite JSON number",
        )
        try:
            normalized = Decimal(str(value))
        except InvalidOperation as error:
            raise ValidationFailure(f"{label}: invalid decimal") from error
    elif value_type == "date":
        require(isinstance(value, str), f"{label}: expected an ISO date")
        try:
            normalized = date.fromisoformat(value)
        except ValueError as error:
            raise ValidationFailure(f"{label}: invalid ISO date") from error
    elif value_type == "set":
        require(
            isinstance(value, list)
            and all(isinstance(item, str) and bool(item.strip()) for item in value),
            f"{label}: expected an array of non-empty strings",
        )
        require(len(value) == len(set(value)), f"{label}: set values must be unique")
        normalized = frozenset(value)
    else:
        raise ValidationFailure(f"{label}: unsupported fact type {value_type!r}")

    if allowed_values is not None:
        if value_type == "set":
            disallowed = set(normalized) - set(allowed_values)
            require(
                not disallowed,
                f"{label}: values outside the controlled vocabulary {sorted(disallowed)}",
            )
        else:
            require(
                value in allowed_values,
                f"{label}: value {value!r} is outside the controlled vocabulary",
            )
    return normalized


def canonicalize_condition_operand(
    condition: dict[str, Any], definition: dict[str, Any], label: str
) -> Any:
    operator = condition["operator"]
    value_type = definition["value_type"]
    require(
        operator in FACT_OPERATORS[value_type],
        f"{label}: operator {operator!r} is not valid for {value_type}",
    )
    value = condition["value"]
    if operator == "exists":
        require(value is True, f"{label}: exists only accepts true")
        return True
    if operator in {"in", "not_in"}:
        require(
            isinstance(value, list) and bool(value),
            f"{label}: {operator} expects a non-empty array",
        )
        require(
            len(value)
            == len(
                {json.dumps(item, sort_keys=True, ensure_ascii=False) for item in value}
            ),
            f"{label}: {operator} operands must be unique",
        )
        return tuple(
            canonicalize_fact_value(item, definition, f"{label}: operand")
            for item in value
        )
    if operator == "contains":
        require(
            isinstance(value, str) and bool(value.strip()),
            f"{label}: contains expects a non-empty string",
        )
        allowed_values = definition.get("allowed_values")
        if allowed_values is not None:
            require(
                value in allowed_values,
                f"{label}: operand {value!r} is outside the controlled vocabulary",
            )
        return value
    return canonicalize_fact_value(value, definition, f"{label}: operand")


def evaluate_condition(
    condition: dict[str, Any],
    observation: dict[str, Any],
    definition: dict[str, Any],
    label: str,
) -> bool | None:
    operand = canonicalize_condition_operand(condition, definition, label)
    if not observation["known"]:
        return None
    actual = canonicalize_fact_value(observation["value"], definition, label)
    operator = condition["operator"]
    if operator == "exists":
        return True
    if operator == "eq":
        return actual == operand
    if operator == "ne":
        return actual != operand
    if operator == "in":
        return actual in operand
    if operator == "not_in":
        return actual not in operand
    if operator == "contains":
        return operand in actual
    if operator == "gt":
        return actual > operand
    if operator == "gte":
        return actual >= operand
    if operator == "lt":
        return actual < operand
    if operator == "lte":
        return actual <= operand
    raise ValidationFailure(f"{label}: unsupported operator {operator!r}")


def kleene_and(values: Iterable[bool | None]) -> bool | None:
    values = tuple(values)
    if any(value is False for value in values):
        return False
    if any(value is None for value in values):
        return None
    return True


def kleene_or(values: Iterable[bool | None]) -> bool | None:
    values = tuple(values)
    if any(value is True for value in values):
        return True
    if any(value is None for value in values):
        return None
    return False


def require_active_dependency(
    active_approvals: dict[tuple[str, str], dict[str, Any]],
    dependency_key: tuple[str, str],
    child_decision: dict[str, Any],
    label: str,
) -> None:
    require(
        dependency_key in active_approvals,
        f"{label}: missing active prerequisite approval for {dependency_key}",
    )
    require(
        parse_datetime(active_approvals[dependency_key]["decided_at"])
        <= parse_datetime(child_decision["decided_at"]),
        f"{label}: prerequisite approval occurs after the dependent approval",
    )


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


def validate_applicability_facts() -> dict[str, dict[str, Any]]:
    schema = load_json(FACT_SCHEMA_PATH)
    Draft202012Validator.check_schema(schema)
    record = load_json(FACT_CATALOG_PATH)
    errors = sorted(
        Draft202012Validator(schema, format_checker=FormatChecker()).iter_errors(
            record
        ),
        key=lambda error: list(error.path),
    )
    if errors:
        rendered = "\n".join(
            f"  - {'/'.join(str(part) for part in error.path) or '<root>'}: {error.message}"
            for error in errors
        )
        raise ValidationFailure(
            f"{FACT_CATALOG_PATH}: JSON Schema validation failed\n{rendered}"
        )

    facts_by_key = {fact["key"]: fact for fact in record["facts"]}
    require(
        len(facts_by_key) == len(record["facts"]),
        f"{FACT_CATALOG_PATH}: duplicate fact keys",
    )
    require(
        len(facts_by_key) >= MINIMUM_APPLICABILITY_FACTS,
        f"{FACT_CATALOG_PATH}: expected at least {MINIMUM_APPLICABILITY_FACTS} controlled facts",
    )
    for fact in facts_by_key.values():
        allowed_values = fact.get("allowed_values")
        require(
            allowed_values is None or fact["value_type"] in {"string", "set"},
            f"{FACT_CATALOG_PATH}: fact {fact['key']} cannot use allowed_values with {fact['value_type']}",
        )
    return facts_by_key


def validate_regulatory_pack_index() -> None:
    schema = load_json(PACK_INDEX_SCHEMA_PATH)
    Draft202012Validator.check_schema(schema)
    record = load_json(PACK_INDEX_PATH)
    errors = sorted(
        Draft202012Validator(schema, format_checker=FormatChecker()).iter_errors(
            record
        ),
        key=lambda error: list(error.path),
    )
    if errors:
        rendered = "\n".join(
            f"  - {'/'.join(str(part) for part in error.path) or '<root>'}: {error.message}"
            for error in errors
        )
        raise ValidationFailure(
            f"{PACK_INDEX_PATH}: JSON Schema validation failed\n{rendered}"
        )

    packs_by_id = index_by_id(record["packs"], f"{PACK_INDEX_PATH}: packs")
    packs_by_file = {pack["catalog_file"]: pack for pack in packs_by_id.values()}
    require(
        len(packs_by_file) == len(packs_by_id),
        f"{PACK_INDEX_PATH}: duplicate catalog files",
    )
    actual_pack_catalogs = {
        pack_id: pack["catalog_file"] for pack_id, pack in packs_by_id.items()
    }
    require(
        actual_pack_catalogs == EXPECTED_PACK_CATALOGS,
        f"{PACK_INDEX_PATH}: pack IDs are not bound to the required catalogs",
    )
    required_catalog_files = set(EXPECTED_PACK_CATALOGS.values())
    actual_catalog_files = {path.name for path in CATALOGS_DIR.glob("*-sources.json")}
    require(
        set(packs_by_file) == required_catalog_files,
        f"{PACK_INDEX_PATH}: pack inventory does not match the required catalogs",
    )
    require(
        actual_catalog_files == set(packs_by_file),
        f"{PACK_INDEX_PATH}: actual source catalogs do not exactly match the pack index",
    )
    for catalog_file, pack in packs_by_file.items():
        require(
            pack["minimum_documents"] == SOURCE_PACK_MINIMUM_DOCUMENTS[catalog_file],
            f"{PACK_INDEX_PATH}: unexpected document floor for {catalog_file}",
        )
        catalog_path = CATALOGS_DIR / catalog_file
        actual_digest = hashlib.sha256(catalog_path.read_bytes()).hexdigest()
        require(
            pack["catalog_sha256"] == actual_digest,
            f"{PACK_INDEX_PATH}: catalog digest mismatch for {catalog_file}",
        )

    profiles_by_id = index_by_id(record["profiles"], f"{PACK_INDEX_PATH}: profiles")
    require(
        set(profiles_by_id) == set(EXPECTED_PROFILE_PACKS),
        f"{PACK_INDEX_PATH}: incomplete discovery profiles",
    )
    for profile_id, expected_pack_ids in EXPECTED_PROFILE_PACKS.items():
        actual_pack_ids = set(profiles_by_id[profile_id]["pack_ids"])
        require(
            actual_pack_ids == expected_pack_ids,
            f"{PACK_INDEX_PATH}: profile {profile_id} has an unsafe pack composition",
        )
        require(
            not (actual_pack_ids - packs_by_id.keys()),
            f"{PACK_INDEX_PATH}: profile {profile_id} references an unknown pack",
        )


def validate_regulatory_records(
    control_urns: set[str], applicability_facts: dict[str, dict[str, Any]]
) -> tuple[int, int]:
    schema = load_json(SCHEMA_PATH)
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    catalog_paths = tuple(sorted(CATALOGS_DIR.glob("*-sources.json")))
    actual_catalog_files = {path.name for path in catalog_paths}
    required_catalog_files = set(EXPECTED_PACK_CATALOGS.values())
    require(
        actual_catalog_files == required_catalog_files,
        f"{CATALOGS_DIR}: actual source catalogs do not exactly match the required files",
    )
    require(
        CORE_CATALOG_PATH in catalog_paths,
        f"{CATALOGS_DIR}: the core regulatory source catalog is missing",
    )
    globally_seen_documents: dict[str, Path] = {}
    globally_seen_versions: dict[str, Path] = {}
    globally_seen_typed_ids: dict[str, dict[str, Path]] = {
        "provision": {},
        "obligation": {},
        "applicability_rule": {},
        "applicability_decision": {},
        "control_mapping": {},
        "decision_record": {},
    }

    for path in (*catalog_paths, EXAMPLE_PATH):
        is_source_catalog = path != EXAMPLE_PATH
        is_sector_catalog = is_source_catalog and path != CORE_CATALOG_PATH
        record = load_json(path)
        record_generated_at = parse_datetime(record["generated_at"])
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

        if is_source_catalog:
            typed_indexes = {
                "provision": provisions_by_id,
                "obligation": obligations_by_id,
                "applicability_rule": rules_by_id,
                "applicability_decision": applicability_decisions_by_id,
                "control_mapping": mappings_by_id,
                "decision_record": decisions_by_id,
            }
            for subject_type, typed_index in typed_indexes.items():
                for subject_id in typed_index:
                    previous_path = globally_seen_typed_ids[subject_type].get(
                        subject_id
                    )
                    require(
                        previous_path is None,
                        f"{path}: {subject_type} {subject_id} duplicates source catalog {previous_path}",
                    )
                    globally_seen_typed_ids[subject_type][subject_id] = path
            require(
                bool(documents_by_id) and bool(versions_by_id),
                f"{path}: a source catalog must contain documents and versions",
            )
            minimum_documents = SOURCE_PACK_MINIMUM_DOCUMENTS.get(path.name)
            if minimum_documents is not None:
                require(
                    len(documents_by_id) >= minimum_documents,
                    f"{path}: expected at least {minimum_documents} source documents",
                )
            for document_id in documents_by_id:
                previous_path = globally_seen_documents.get(document_id)
                require(
                    previous_path is None,
                    f"{path}: document {document_id} duplicates source catalog {previous_path}",
                )
                globally_seen_documents[document_id] = path
            for version_id in versions_by_id:
                previous_path = globally_seen_versions.get(version_id)
                require(
                    previous_path is None,
                    f"{path}: document version {version_id} duplicates source catalog {previous_path}",
                )
                globally_seen_versions[version_id] = path

        if is_sector_catalog:
            for document in documents_by_id.values():
                require(
                    document.get("coverage_priority") in {"P0", "P1", "P2"},
                    f"{path}: sector document {document['id']} needs a collection priority",
                )
                require(
                    document.get("coverage_stage")
                    in {
                        "source_metadata",
                        "provision_indexed",
                        "obligations_proposed",
                        "obligations_reviewed",
                    },
                    f"{path}: sector document {document['id']} needs a coverage stage",
                )
                require(
                    isinstance(document.get("applicability_fact_keys"), list)
                    and bool(document["applicability_fact_keys"]),
                    f"{path}: sector document {document['id']} needs applicability fact keys",
                )
                unknown_fact_keys = (
                    set(document["applicability_fact_keys"])
                    - applicability_facts.keys()
                )
                require(
                    not unknown_fact_keys,
                    f"{path}: sector document {document['id']} uses unknown applicability facts {sorted(unknown_fact_keys)}",
                )
                require(
                    bool(document.get("selection_rationale", "").strip()),
                    f"{path}: sector document {document['id']} needs a selection rationale",
                )

        for document in documents_by_id.values():
            coverage_stage = document.get("coverage_stage")
            if coverage_stage is None:
                continue
            related_provisions = [
                provision
                for provision in provisions_by_id.values()
                if provision["document_id"] == document["id"]
            ]
            related_provision_ids = {
                provision["id"] for provision in related_provisions
            }
            related_obligations = [
                obligation
                for obligation in obligations_by_id.values()
                if related_provision_ids.intersection(obligation["provision_ids"])
            ]
            if coverage_stage == "source_metadata":
                require(
                    not related_provisions and not related_obligations,
                    f"{path}: source-metadata document {document['id']} cannot contain downstream records",
                )
            elif coverage_stage == "provision_indexed":
                require(
                    bool(related_provisions) and not related_obligations,
                    f"{path}: provision-indexed document {document['id']} needs provisions but no proposed obligations",
                )
            elif coverage_stage == "obligations_proposed":
                require(
                    bool(related_provisions) and bool(related_obligations),
                    f"{path}: obligations-proposed document {document['id']} needs provisions and obligations",
                )
            elif coverage_stage == "obligations_reviewed":
                require(
                    bool(related_provisions)
                    and bool(related_obligations)
                    and all(
                        obligation["review_status"] != "machine_proposed"
                        for obligation in related_obligations
                    ),
                    f"{path}: obligations-reviewed document {document['id']} needs reviewed downstream records",
                )

        for version in versions_by_id.values():
            validate_record_times(
                version, record_generated_at, f"{path}: {version['id']}"
            )
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
            require(
                status_as_of <= record_generated_at.date(),
                f"{path}: document version {version['id']} has a future status_as_of",
            )
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
            if version["transition_end"] is not None:
                require(
                    effective_date is not None
                    and date.fromisoformat(version["transition_end"]) >= effective_date,
                    f"{path}: document version {version['id']} transition cannot end before effectiveness",
                )
            if version["status"] == "repealed":
                require(
                    version["repeal_date"] is not None
                    and version["valid_to"] == version["repeal_date"],
                    f"{path}: repealed document version {version['id']} needs matching repeal_date and valid_to",
                )
            if version["status"] == "superseded":
                require(
                    version["valid_to"] is not None,
                    f"{path}: superseded document version {version['id']} needs valid_to",
                )
            if version["status"] in {
                "effective",
                "active_no_explicit_commencement",
                "published_future_effective",
            }:
                require(
                    version["repeal_date"] is None,
                    f"{path}: active document version {version['id']} cannot have a repeal date",
                )
            if version["content_storage_policy"] != "metadata_only":
                require(
                    version["source_hash"] is not None,
                    f"{path}: stored source version {version['id']} needs a source hash",
                )
            if is_source_catalog:
                source_host = (urlparse(version["source_url"]).hostname or "").lower()
                require(
                    source_host == "gov.cn" or source_host.endswith(".gov.cn"),
                    f"{path}: document version {version['id']} must use an official government source host",
                )
                require(
                    date.fromisoformat(version["source_checked_on"])
                    <= parse_datetime(record["generated_at"]).date(),
                    f"{path}: document version {version['id']} was checked after the catalog was generated",
                )
                require(
                    status_as_of <= date.fromisoformat(version["source_checked_on"]),
                    f"{path}: document version {version['id']} status is later than its source check",
                )
            if version["legal_review_status"] == "reviewed":
                require(
                    bool(version["legal_reviewed_at"])
                    and bool(version["legal_reviewed_by"]),
                    f"{path}: reviewed document version {version['id']} needs reviewer and time",
                )
                require(
                    parse_datetime(version["legal_reviewed_at"]) <= record_generated_at,
                    f"{path}: document version {version['id']} legal review occurs after generation",
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
            validate_record_times(
                provision, record_generated_at, f"{path}: {provision['id']}"
            )
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
            source_version = versions_by_id[provision["version_id"]]
            if source_version["content_storage_policy"] == "metadata_only":
                require(
                    provision.get("text") is None,
                    f"{path}: metadata-only provision {provision['id']} cannot store source text",
                )
            validate_half_open_interval(
                provision,
                "recorded_from",
                "recorded_to",
                parse_datetime,
                f"{path}: {provision['id']}",
            )

        for obligation in obligations_by_id.values():
            validate_record_times(
                obligation, record_generated_at, f"{path}: {obligation['id']}"
            )
            unknown = set(obligation["provision_ids"]) - provisions_by_id.keys()
            require(
                not unknown,
                f"{path}: obligation {obligation['id']} references unknown provisions {sorted(unknown)}",
            )
            obligation_provisions = [
                provisions_by_id[provision_id]
                for provision_id in obligation["provision_ids"]
            ]
            source_documents = [
                documents_by_id[provision["document_id"]]
                for provision in obligation_provisions
            ]
            require(
                obligation["authority_level"]
                in {document["authority_level"] for document in source_documents},
                f"{path}: obligation {obligation['id']} authority is unsupported by its provisions",
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
            for version_id in {
                provision["version_id"] for provision in obligation_provisions
            }:
                validate_interval_containment(
                    obligation,
                    versions_by_id[version_id],
                    "valid_from",
                    "valid_to",
                    date.fromisoformat,
                    f"{path}: obligation {obligation['id']} and source version {version_id}",
                )

        for rule in rules_by_id.values():
            validate_record_times(rule, record_generated_at, f"{path}: {rule['id']}")
            require(
                rule["obligation_id"] in obligations_by_id,
                f"{path}: applicability rule {rule['id']} references an unknown obligation",
            )
            require(
                bool(rule["all"] or rule["any"]),
                f"{path}: applicability rule {rule['id']} needs at least one condition",
            )
            unknown_fact_keys = {
                condition["fact"] for condition in [*rule["all"], *rule["any"]]
            } - applicability_facts.keys()
            require(
                not unknown_fact_keys,
                f"{path}: applicability rule {rule['id']} uses unknown facts {sorted(unknown_fact_keys)}",
            )
            for position, condition in enumerate([*rule["all"], *rule["any"]]):
                canonicalize_condition_operand(
                    condition,
                    applicability_facts[condition["fact"]],
                    f"{path}: rule {rule['id']} condition {position}",
                )
            obligation = obligations_by_id[rule["obligation_id"]]
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
            validate_interval_containment(
                rule,
                obligation,
                "valid_from",
                "valid_to",
                date.fromisoformat,
                f"{path}: applicability rule {rule['id']} and obligation {obligation['id']}",
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
            validate_record_times(
                applicability_decision,
                record_generated_at,
                f"{path}: {applicability_decision['id']}",
            )
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
            require(
                set(facts) == referenced_facts,
                f"{path}: applicability decision {applicability_decision['id']} must record exactly its rule facts",
            )
            for fact_name, observation in facts.items():
                definition = applicability_facts[fact_name]
                if observation["known"]:
                    canonicalize_fact_value(
                        observation["value"],
                        definition,
                        f"{path}: applicability decision {applicability_decision['id']} fact {fact_name}",
                    )
                    require(
                        bool(observation["source_refs"])
                        and all(
                            isinstance(source_ref, str) and bool(source_ref.strip())
                            for source_ref in observation["source_refs"]
                        )
                        and observation["observed_at"] is not None,
                        f"{path}: known fact {fact_name} needs evidence and observation time",
                    )
                    observed_at = parse_datetime(observation["observed_at"])
                    require(
                        observed_at
                        <= parse_datetime(applicability_decision["recorded_from"])
                        <= record_generated_at,
                        f"{path}: fact {fact_name} was observed after the applicability decision",
                    )
                else:
                    require(
                        not observation["source_refs"]
                        and observation["observed_at"] is None,
                        f"{path}: unknown fact {fact_name} cannot carry evidence or an observation time",
                    )

            all_states = [
                evaluate_condition(
                    condition,
                    facts[condition["fact"]],
                    applicability_facts[condition["fact"]],
                    f"{path}: applicability decision {applicability_decision['id']}",
                )
                for condition in rule["all"]
            ]
            any_states = [
                evaluate_condition(
                    condition,
                    facts[condition["fact"]],
                    applicability_facts[condition["fact"]],
                    f"{path}: applicability decision {applicability_decision['id']}",
                )
                for condition in rule["any"]
            ]
            rule_parts: list[bool | None] = []
            if all_states:
                rule_parts.append(kleene_and(all_states))
            if any_states:
                rule_parts.append(kleene_or(any_states))
            computed_state = kleene_and(rule_parts)
            computed_result = {
                True: "applicable",
                False: "not_applicable",
                None: "needs_review",
            }[computed_state]
            require(
                applicability_decision["result"] == computed_result,
                f"{path}: applicability decision {applicability_decision['id']} result must be {computed_result}",
            )
            if applicability_decision["review_status"] == "confirmed":
                require(
                    applicability_decision["confirmed_at"] is not None
                    and parse_datetime(applicability_decision["confirmed_at"])
                    <= record_generated_at,
                    f"{path}: applicability decision {applicability_decision['id']} has an invalid confirmation time",
                )
            else:
                require(
                    applicability_decision["confirmed_by"] is None
                    and applicability_decision["confirmed_at"] is None,
                    f"{path}: unconfirmed applicability decision {applicability_decision['id']} cannot carry confirmation fields",
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
            obligation = obligations_by_id[obligation_id]
            validate_interval_containment(
                applicability_decision,
                rule,
                "valid_from",
                "valid_to",
                date.fromisoformat,
                f"{path}: applicability decision {applicability_decision['id']} and rule {rule['id']}",
            )
            validate_interval_containment(
                applicability_decision,
                obligation,
                "valid_from",
                "valid_to",
                date.fromisoformat,
                f"{path}: applicability decision {applicability_decision['id']} and obligation {obligation['id']}",
            )

        for mapping in mappings_by_id.values():
            validate_record_times(
                mapping, record_generated_at, f"{path}: {mapping['id']}"
            )
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
            validate_interval_containment(
                mapping,
                obligations_by_id[mapping["obligation_id"]],
                "valid_from",
                "valid_to",
                date.fromisoformat,
                f"{path}: control mapping {mapping['id']} and obligation {mapping['obligation_id']}",
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

        subjects_by_type = {
            "document": documents_by_id,
            "document_version": versions_by_id,
            "provision": provisions_by_id,
            "obligation": obligations_by_id,
            "applicability_rule": rules_by_id,
            "applicability_decision": applicability_decisions_by_id,
            "control_mapping": mappings_by_id,
        }
        latest_decisions: dict[tuple[str, str], dict[str, Any]] = {}
        subject_decision_times: set[tuple[str, str, datetime]] = set()
        for decision in decisions_by_id.values():
            require(
                decision["subject_id"] in subjects_by_type[decision["subject_type"]],
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
            subject_key = (decision["subject_type"], decision["subject_id"])
            timed_subject_key = (*subject_key, decided_at)
            require(
                timed_subject_key not in subject_decision_times,
                f"{path}: subject {subject_key} has multiple decisions at {decision['decided_at']}",
            )
            subject_decision_times.add(timed_subject_key)
            subject = subjects_by_type[decision["subject_type"]][decision["subject_id"]]
            is_zero_return = (
                decision["decision"] == "return_for_changes"
                and decision["payload_sha256"] == "0" * 64
            )
            if not is_zero_return:
                for field in ("decided_by", "role", "rationale"):
                    require(
                        isinstance(decision.get(field), str)
                        and bool(decision[field].strip()),
                        f"{path}: binding decision {decision['id']} needs a non-empty {field}",
                    )
                require(
                    decision["subject_type"] != "document",
                    f"{path}: binding decision {decision['id']} must target a versioned subject",
                )
                require(
                    decision.get("decided_by_kind") == "human",
                    f"{path}: binding decision {decision['id']} needs a human decision identity",
                )
                require(
                    decision.get("payload_digest_profile") == PAYLOAD_DIGEST_PROFILE,
                    f"{path}: binding decision {decision['id']} needs the canonical digest profile",
                )
                require(
                    decision["payload_sha256"]
                    == canonical_subject_digest(
                        record["schema_version"], decision["subject_type"], subject
                    ),
                    f"{path}: binding decision {decision['id']} payload digest mismatch",
                )
                provenance = subject.get("provenance")
                require(
                    provenance is not None,
                    f"{path}: binding decision {decision['id']} needs subject provenance",
                )
                require(
                    isinstance(provenance.get("created_by"), str)
                    and bool(provenance["created_by"].strip()),
                    f"{path}: binding decision {decision['id']} needs a non-empty maker identity",
                )
                require(
                    normalize_identity(decision["decided_by"])
                    != normalize_identity(provenance["created_by"]),
                    f"{path}: binding decision {decision['id']} violates maker-checker separation",
                )
                require(
                    decided_at >= parse_datetime(provenance["created_at"]),
                    f"{path}: binding decision {decision['id']} predates subject provenance",
                )
                if subject.get("recorded_from") is not None:
                    require(
                        decided_at >= parse_datetime(subject["recorded_from"]),
                        f"{path}: binding decision {decision['id']} predates its subject",
                    )
            ordering_key = decided_at
            previous = latest_decisions.get(subject_key)
            if previous is None or ordering_key > parse_datetime(
                previous["decided_at"]
            ):
                latest_decisions[subject_key] = decision

        for decision in decisions_by_id.values():
            if (
                decision["decision"] == "return_for_changes"
                and decision["payload_sha256"] == "0" * 64
            ):
                require(
                    not any(
                        candidate["subject_type"] == decision["subject_type"]
                        and candidate["subject_id"] == decision["subject_id"]
                        and candidate["decision"] == "approve"
                        and parse_datetime(candidate["decided_at"])
                        < parse_datetime(decision["decided_at"])
                        for candidate in decisions_by_id.values()
                    ),
                    f"{path}: zero-digest return {decision['id']} cannot follow an approval",
                )
            if decision["decision"] == "revoke":
                require(
                    any(
                        candidate["subject_type"] == decision["subject_type"]
                        and candidate["subject_id"] == decision["subject_id"]
                        and candidate["decision"] == "approve"
                        and parse_datetime(candidate["decided_at"])
                        < parse_datetime(decision["decided_at"])
                        for candidate in decisions_by_id.values()
                    ),
                    f"{path}: revocation {decision['id']} has no earlier approval",
                )

        active_approvals = {
            subject_key: decision
            for subject_key, decision in latest_decisions.items()
            if decision["decision"] == "approve"
            and (
                decision.get("expires_at") is None
                or parse_datetime(decision["expires_at"]) > record_generated_at
            )
        }

        terminal_dispositions = (
            (
                "obligation",
                obligations_by_id,
                "review_status",
                {"rejected": "reject", "superseded": "revoke"},
            ),
            (
                "applicability_rule",
                rules_by_id,
                "review_status",
                {"retired": "revoke"},
            ),
            (
                "applicability_decision",
                applicability_decisions_by_id,
                "review_status",
                {"rejected": "reject", "superseded": "revoke"},
            ),
            (
                "control_mapping",
                mappings_by_id,
                "review_status",
                {"rejected": "reject", "retired": "revoke"},
            ),
        )
        for (
            subject_type,
            subjects,
            status_field,
            disposition_by_status,
        ) in terminal_dispositions:
            for subject in subjects.values():
                expected_disposition = disposition_by_status.get(subject[status_field])
                if expected_disposition is None:
                    continue
                subject_key = (subject_type, subject["id"])
                latest = latest_decisions.get(subject_key)
                require(
                    latest is not None and latest["decision"] == expected_disposition,
                    f"{path}: {subject_type} {subject['id']} status "
                    f"{subject[status_field]} requires latest {expected_disposition} disposition",
                )

        for version in versions_by_id.values():
            subject_key = ("document_version", version["id"])
            is_reviewed = version["legal_review_status"] == "reviewed"
            require(
                is_reviewed == (subject_key in active_approvals),
                f"{path}: document version {version['id']} legal-review state and approval disagree",
            )
            if is_reviewed:
                approval = active_approvals[subject_key]
                require(
                    version["legal_reviewed_by"] == approval["decided_by"]
                    and version["legal_reviewed_at"] == approval["decided_at"],
                    f"{path}: document version {version['id']} review fields do not match its approval",
                )

        for provision in provisions_by_id.values():
            subject_key = ("provision", provision["id"])
            if subject_key in active_approvals:
                provision_approval = active_approvals[subject_key]
                require_active_dependency(
                    active_approvals,
                    ("document_version", provision["version_id"]),
                    provision_approval,
                    f"{path}: provision {provision['id']}",
                )

        for obligation in obligations_by_id.values():
            subject_key = ("obligation", obligation["id"])
            is_approved = obligation["review_status"] == "approved"
            require(
                is_approved == (subject_key in active_approvals),
                f"{path}: obligation {obligation['id']} review state and approval disagree",
            )
            if is_approved:
                approval = active_approvals[subject_key]
                for provision_id in obligation["provision_ids"]:
                    require_active_dependency(
                        active_approvals,
                        ("provision", provision_id),
                        approval,
                        f"{path}: obligation {obligation['id']}",
                    )
                    version_id = provisions_by_id[provision_id]["version_id"]
                    source_version = versions_by_id[version_id]
                    require(
                        source_version["legal_review_status"] == "reviewed",
                        f"{path}: obligation {obligation['id']} depends on an unreviewed source version",
                    )
                    require(
                        source_version["status"] not in {"draft", "unknown"},
                        f"{path}: approved obligation {obligation['id']} depends on a draft or unknown source version",
                    )
                    source_valid_from = source_version["valid_from"]
                    require(
                        source_valid_from is None
                        or date.fromisoformat(source_valid_from)
                        <= parse_datetime(approval["decided_at"]).date(),
                        f"{path}: approved obligation {obligation['id']} depends on a source version that is not yet effective",
                    )
                    require_active_dependency(
                        active_approvals,
                        ("document_version", version_id),
                        approval,
                        f"{path}: obligation {obligation['id']}",
                    )

        for rule in rules_by_id.values():
            subject_key = ("applicability_rule", rule["id"])
            is_approved = rule["review_status"] == "approved"
            require(
                is_approved == (subject_key in active_approvals),
                f"{path}: applicability rule {rule['id']} review state and approval disagree",
            )
            if is_approved:
                approval = active_approvals[subject_key]
                obligation = obligations_by_id[rule["obligation_id"]]
                require(
                    obligation["review_status"] == "approved",
                    f"{path}: applicability rule {rule['id']} depends on an unapproved obligation",
                )
                require_active_dependency(
                    active_approvals,
                    ("obligation", obligation["id"]),
                    approval,
                    f"{path}: applicability rule {rule['id']}",
                )

        for applicability_decision in applicability_decisions_by_id.values():
            subject_key = (
                "applicability_decision",
                applicability_decision["id"],
            )
            is_confirmed = applicability_decision["review_status"] == "confirmed"
            require(
                is_confirmed == (subject_key in active_approvals),
                f"{path}: applicability decision {applicability_decision['id']} review state and approval disagree",
            )
            if is_confirmed:
                approval = active_approvals[subject_key]
                rule = rules_by_id[applicability_decision["rule"]["id"]]
                obligation = obligations_by_id[applicability_decision["obligation_id"]]
                require(
                    rule["review_status"] == "approved"
                    and obligation["review_status"] == "approved",
                    f"{path}: applicability decision {applicability_decision['id']} has unapproved prerequisites",
                )
                require_active_dependency(
                    active_approvals,
                    ("applicability_rule", rule["id"]),
                    approval,
                    f"{path}: applicability decision {applicability_decision['id']}",
                )
                require(
                    applicability_decision["confirmed_by"] == approval["decided_by"]
                    and applicability_decision["confirmed_at"]
                    == approval["decided_at"],
                    f"{path}: applicability decision {applicability_decision['id']} confirmation fields do not match its approval",
                )
                observed_times = [
                    parse_datetime(fact["observed_at"])
                    for fact in applicability_decision["facts"]
                    if fact["observed_at"] is not None
                ]
                require(
                    not observed_times
                    or parse_datetime(approval["decided_at"]) >= max(observed_times),
                    f"{path}: applicability decision {applicability_decision['id']} was confirmed before its facts",
                )

        for mapping in mappings_by_id.values():
            subject_key = ("control_mapping", mapping["id"])
            is_approved = mapping["review_status"] == "approved"
            require(
                is_approved == (subject_key in active_approvals),
                f"{path}: control mapping {mapping['id']} review state and approval disagree",
            )
            if is_approved:
                approval = active_approvals[subject_key]
                obligation = obligations_by_id[mapping["obligation_id"]]
                require(
                    obligation["review_status"] == "approved",
                    f"{path}: control mapping {mapping['id']} depends on an unapproved obligation",
                )
                require_active_dependency(
                    active_approvals,
                    ("obligation", obligation["id"]),
                    approval,
                    f"{path}: control mapping {mapping['id']}",
                )

    minimum_total = sum(SOURCE_PACK_MINIMUM_DOCUMENTS.values())
    require(
        len(globally_seen_documents) >= minimum_total,
        f"{CATALOGS_DIR}: expected at least {minimum_total} source documents",
    )
    require(
        len(globally_seen_versions) >= len(globally_seen_documents),
        f"{CATALOGS_DIR}: every source document needs a version",
    )
    return len(globally_seen_documents), len(globally_seen_versions)


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
        applicability_facts = validate_applicability_facts()
        validate_regulatory_pack_index()
        source_document_count, source_version_count = validate_regulatory_records(
            control_urns, applicability_facts
        )
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
    print(f"  fact schema: {FACT_SCHEMA_PATH.relative_to(REPO_ROOT)}")
    print(f"  pack schema: {PACK_INDEX_SCHEMA_PATH.relative_to(REPO_ROOT)}")
    print(
        f"  fact catalog: {FACT_CATALOG_PATH.relative_to(REPO_ROOT)} "
        f"({len(applicability_facts)} facts)"
    )
    for catalog_path in sorted(CATALOGS_DIR.glob("*-sources.json")):
        print(f"  source catalog: {catalog_path.relative_to(REPO_ROOT)}")
    print(f"  pack index: {PACK_INDEX_PATH.relative_to(REPO_ROOT)}")
    print(
        f"  source records: {source_document_count} documents, "
        f"{source_version_count} versions"
    )
    print(f"  example: {EXAMPLE_PATH.relative_to(REPO_ROOT)}")
    print(f"  controls: {COMMON_CONTROLS_PATH.relative_to(REPO_ROOT)}")
    print(f"  baseline: {BASELINE_PATH.relative_to(REPO_ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
