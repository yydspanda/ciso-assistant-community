#!/usr/bin/env python3
"""Seed and fingerprint the synthetic PostgreSQL regulatory acceptance slice.

The script refuses non-acceptance databases and never loads real regulatory or
institution data. It intentionally uses the same domain services as the
application so that the runtime role is exercised through the authority-bearing
write path rather than through fixture SQL.
"""

from __future__ import annotations

import argparse
from datetime import timedelta
import hashlib
import json
import os
from pathlib import Path
import sys


REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
BACKEND_ROOT = REPOSITORY_ROOT / "backend"
sys.path.insert(0, str(BACKEND_ROOT))
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "ciso_assistant.settings")

import django  # noqa: E402

django.setup()

from auditlog.models import LogEntry  # noqa: E402
from django.apps import apps  # noqa: E402
from django.core.serializers.json import DjangoJSONEncoder  # noqa: E402
from django.db import connection  # noqa: E402
from django.db.migrations.recorder import MigrationRecorder  # noqa: E402

from regulatory.models import (  # noqa: E402
    RegulatoryApplicabilityDecision,
    RegulatoryApplicabilityReviewDisposition,
    RegulatoryChainCorrectionEvent,
    RegulatoryDocument,
)
from regulatory.services import (  # noqa: E402
    correct_regulatory_chain,
    create_regulatory_chain,
    get_regulatory_applicability_review,
    get_regulatory_chain,
    record_regulatory_applicability_decision,
    record_regulatory_applicability_review_disposition,
    regulatory_chain_semantic_sha256,
)
from regulatory.tests.factories import (  # noqa: E402
    applicability_payload,
    applicability_review_payload,
    chain_payload,
    correction_payload,
    make_folder,
    make_synthetic_entity,
    make_user_with_permissions,
)
from tprm.models import Entity  # noqa: E402
from iam.models import User  # noqa: E402


ACCEPTANCE_DOCUMENT_ID = "TEST-CN-REG-PG-ACCEPTANCE"
ACCEPTANCE_ENTITY_REF_ID = "SYNTHETIC-CN-BANK-PG-ACCEPTANCE"
ACCEPTANCE_DATABASES = {
    "ciso_regulatory_acceptance",
    "ciso_regulatory_acceptance_restored",
}


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def _guard_acceptance_database() -> None:
    database_name = connection.settings_dict["NAME"]
    if os.environ.get("CHINA_GRC_POSTGRES_ACCEPTANCE") != "1":
        raise SystemExit("CHINA_GRC_POSTGRES_ACCEPTANCE=1 is required")
    if connection.vendor != "postgresql":
        raise SystemExit("the acceptance fixture requires PostgreSQL")
    if str(database_name) not in ACCEPTANCE_DATABASES:
        raise SystemExit(
            "refusing to operate on a database outside the acceptance namespace"
        )


def _seed() -> None:
    if RegulatoryDocument.objects.filter(record_id=ACCEPTANCE_DOCUMENT_ID).exists():
        return

    suffix = "PG-ACCEPTANCE"
    folder = make_folder("PostgreSQL regulatory acceptance (synthetic)")
    entity = make_synthetic_entity(folder, suffix)
    maker = make_user_with_permissions(
        folder,
        "ingest_regulatoryrecord",
        "correct_regulatoryrecord",
        "view_regulatorydocument",
        "view_regulatoryapplicabilitydecision",
        "view_regulatoryapplicabilityreviewdisposition",
        "record_regulatoryapplicability",
        "view_entity",
        email_prefix="pg-acceptance-maker",
    )
    reviewer = make_user_with_permissions(
        folder,
        "view_regulatorydocument",
        "view_regulatoryapplicabilitydecision",
        "view_regulatoryapplicabilityreviewdisposition",
        "review_regulatoryapplicability",
        "view_entity",
        email_prefix="pg-acceptance-reviewer",
    )

    initial = create_regulatory_chain(
        actor=maker,
        entity=entity,
        payload=chain_payload(suffix),
        idempotency_key="pg-acceptance-chain-r1",
    )
    first_decision = record_regulatory_applicability_decision(
        actor=maker,
        entity=entity,
        document_id=initial.document.id,
        payload=applicability_payload("PG-ACCEPTANCE-R1", chain=initial),
        idempotency_key="pg-acceptance-decision-r1",
    ).decision
    record_regulatory_applicability_review_disposition(
        actor=reviewer,
        entity=entity,
        document_id=initial.document.id,
        payload=applicability_review_payload(
            "PG-ACCEPTANCE-R1",
            decision=first_decision,
        ),
        idempotency_key="pg-acceptance-review-r1",
    )

    corrected = correct_regulatory_chain(
        actor=maker,
        entity=entity,
        document_id=initial.document.id,
        payload=correction_payload(
            suffix,
            expected_payload_sha256=regulatory_chain_semantic_sha256(initial),
        ),
        rationale="Synthetic PostgreSQL backup and temporal-history acceptance",
        idempotency_key="pg-acceptance-correction-r2",
    )
    second_decision = record_regulatory_applicability_decision(
        actor=maker,
        entity=entity,
        document_id=initial.document.id,
        payload=applicability_payload(
            "PG-ACCEPTANCE-R2",
            chain=corrected.chain,
        ),
        idempotency_key="pg-acceptance-decision-r2",
    ).decision
    record_regulatory_applicability_review_disposition(
        actor=reviewer,
        entity=entity,
        document_id=initial.document.id,
        payload=applicability_review_payload(
            "PG-ACCEPTANCE-R2",
            decision=second_decision,
        ),
        idempotency_key="pg-acceptance-review-r2",
    )


def _jsonable(value):
    return json.loads(json.dumps(value, cls=DjangoJSONEncoder, ensure_ascii=False))


def _canonical_sha256(value) -> str:
    canonical = json.dumps(
        _jsonable(value),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode()
    return hashlib.sha256(canonical).hexdigest()


def _normalize_constraint_definition(definition: str) -> str:
    """Normalize PostgreSQL's equivalent varchar-array-to-text cast renderings."""

    return definition.replace(
        "::character varying::text", "::character varying"
    ).replace("]::text[]", "]")


def _database_contract_state() -> dict:
    roles = (
        "ciso_regulatory_migrator",
        "ciso_regulatory_runtime",
        "ciso_regulatory_backup",
    )
    migrations = list(
        MigrationRecorder.Migration.objects.filter(app="regulatory")
        .order_by("name")
        .values_list("app", "name")
    )
    with connection.cursor() as cursor:
        cursor.execute(
            r"""
            SELECT relation.relname,
                   constraint_record.conname,
                   constraint_record.contype,
                   constraint_record.convalidated,
                   constraint_record.condeferrable,
                   constraint_record.condeferred,
                   constraint_record.connoinherit,
                   constraint_record.confupdtype,
                   constraint_record.confdeltype,
                   constraint_record.confmatchtype,
                   pg_get_constraintdef(constraint_record.oid, true)
            FROM pg_constraint AS constraint_record
            JOIN pg_class AS relation
              ON relation.oid = constraint_record.conrelid
            JOIN pg_namespace AS namespace
              ON namespace.oid = relation.relnamespace
            WHERE namespace.nspname = 'public'
              AND relation.relname LIKE 'regulatory\_%' ESCAPE '\'
            ORDER BY relation.relname, constraint_record.conname
            """
        )
        constraints = [
            (*row[:-1], _normalize_constraint_definition(row[-1]))
            for row in cursor.fetchall()
        ]
        cursor.execute(
            r"""
            SELECT tablename, indexname, indexdef
            FROM pg_indexes
            WHERE schemaname = 'public'
              AND tablename LIKE 'regulatory\_%' ESCAPE '\'
            ORDER BY tablename, indexname
            """
        )
        indexes = cursor.fetchall()
        cursor.execute(
            r"""
            SELECT sequencename
            FROM pg_sequences
            WHERE schemaname = 'public'
              AND sequencename LIKE 'regulatory\_%' ESCAPE '\'
            ORDER BY sequencename
            """
        )
        sequence_names = [row[0] for row in cursor.fetchall()]
        sequences = []
        for sequence_name in sequence_names:
            quoted_sequence = connection.ops.quote_name(sequence_name)
            cursor.execute(
                f"SELECT last_value, is_called FROM public.{quoted_sequence}"
            )
            last_value, is_called = cursor.fetchone()
            sequences.append((sequence_name, last_value, is_called))
        cursor.execute(
            """
            SELECT grantee, table_name, privilege_type
            FROM information_schema.role_table_grants
            WHERE table_schema = 'public'
              AND grantee IN (%s, %s, %s)
            ORDER BY grantee, table_name, privilege_type
            """,
            roles,
        )
        table_grants = cursor.fetchall()
        cursor.execute(
            r"""
            SELECT grantee, table_name, column_name, privilege_type
            FROM information_schema.column_privileges
            WHERE table_schema = 'public'
              AND table_name LIKE %s ESCAPE '\'
              AND grantee IN (%s, %s, %s)
            ORDER BY grantee, table_name, column_name, privilege_type
            """,
            (r"regulatory\_%", *roles),
        )
        regulatory_column_grants = cursor.fetchall()
        cursor.execute(
            """
            SELECT role_name,
                   has_database_privilege(role_name, current_database(), 'CONNECT')
            FROM unnest(%s::text[]) AS expected(role_name)
            ORDER BY role_name
            """,
            [list(roles)],
        )
        database_connect = cursor.fetchall()

    _require(bool(migrations), "regulatory migration state is absent")
    return {
        "regulatory_migrations": migrations,
        "constraints": constraints,
        "indexes": indexes,
        "sequences": sequences,
        "table_grants": table_grants,
        "regulatory_column_grants": regulatory_column_grants,
        "database_connect": database_connect,
    }


def _fingerprint() -> dict:
    document = RegulatoryDocument.objects.get(record_id=ACCEPTANCE_DOCUMENT_ID)
    entity = Entity.objects.get(ref_id=ACCEPTANCE_ENTITY_REF_ID)
    maker = User.objects.get(email__startswith="pg-acceptance-maker-")
    reviewer = User.objects.get(email__startswith="pg-acceptance-reviewer-")
    correction = RegulatoryChainCorrectionEvent.objects.get(document=document)
    historical_at = correction.occurred_at - timedelta(microseconds=1)

    current_chain = get_regulatory_chain(
        actor=maker,
        entity=entity,
        document_id=document.id,
    )
    historical_chain = get_regulatory_chain(
        actor=maker,
        entity=entity,
        document_id=document.id,
        recorded_as_of=historical_at,
    )
    current_review = get_regulatory_applicability_review(
        actor=reviewer,
        entity=entity,
        document_id=document.id,
    )
    historical_review = get_regulatory_applicability_review(
        actor=reviewer,
        entity=entity,
        document_id=document.id,
        recorded_as_of=historical_at,
    )

    _require(
        current_chain.document_version.revision == 2,
        "current regulatory chain did not select revision 2",
    )
    _require(
        historical_chain.document_version.revision == 1,
        "historical regulatory chain did not select revision 1",
    )
    _require(
        current_review.applicability.decision is not None,
        "current applicability decision is absent",
    )
    _require(
        current_review.applicability.decision.obligation.revision == 2,
        "current applicability decision did not bind obligation revision 2",
    )
    _require(
        current_review.review_state == "no_correction_requested",
        "current review state differs from the seeded state",
    )
    _require(
        historical_review.applicability.decision is not None,
        "historical applicability decision is absent",
    )
    _require(
        historical_review.applicability.decision.obligation.revision == 1,
        "historical applicability decision did not bind obligation revision 1",
    )
    _require(
        historical_review.review_state == "no_correction_requested",
        "historical review state differs from the seeded state",
    )

    state = {}
    counts = {}
    for model in sorted(
        apps.get_app_config("regulatory").get_models(),
        key=lambda item: item._meta.label,
    ):
        rows = list(model.objects.order_by("pk").values())
        state[model._meta.label_lower] = _jsonable(rows)
        counts[model._meta.label_lower] = len(rows)

    audit_rows = list(
        LogEntry.objects.filter(content_type__app_label="regulatory")
        .order_by("pk")
        .values()
    )
    state["auditlog.regulatory_entries"] = _jsonable(audit_rows)
    counts["auditlog.regulatory_entries"] = len(audit_rows)
    database_contract = _database_contract_state()
    state["database.contract"] = _jsonable(database_contract)
    counts["database.constraints"] = len(database_contract["constraints"])
    counts["database.indexes"] = len(database_contract["indexes"])
    counts["database.sequences"] = len(database_contract["sequences"])
    state_component_sha256 = {
        key: _canonical_sha256(value) for key, value in sorted(state.items())
    }
    database_contract_component_sha256 = {
        key: _canonical_sha256(value)
        for key, value in sorted(database_contract.items())
    }

    return {
        "contract": "china-financial-grc/postgresql-acceptance/v1",
        "constraint_definition_profile": (
            "postgresql16-varchar-array-text-cast-normalization/v1"
        ),
        "synthetic_only": True,
        "state_sha256": _canonical_sha256(state),
        "state_component_sha256": state_component_sha256,
        "database_contract_component_sha256": (database_contract_component_sha256),
        "counts": counts,
        "logical_selection": {
            "current_chain_revision": current_chain.document_version.revision,
            "historical_chain_revision": historical_chain.document_version.revision,
            "current_decision_revision": current_review.applicability.decision.revision,
            "current_obligation_revision": (
                current_review.applicability.decision.obligation.revision
            ),
            "historical_decision_revision": (
                historical_review.applicability.decision.revision
            ),
            "historical_obligation_revision": (
                historical_review.applicability.decision.obligation.revision
            ),
            "current_review_state": current_review.review_state,
            "historical_review_state": historical_review.review_state,
        },
        "regulatory_migration_leaf": database_contract["regulatory_migrations"][-1][1],
    }


def _exercise_restored_runtime() -> dict:
    database_name = str(connection.settings_dict["NAME"])
    _require(
        database_name == "ciso_regulatory_acceptance_restored",
        "post-restore mutation is restricted to the restored acceptance database",
    )
    document = RegulatoryDocument.objects.get(record_id=ACCEPTANCE_DOCUMENT_ID)
    entity = Entity.objects.get(ref_id=ACCEPTANCE_ENTITY_REF_ID)
    reviewer = User.objects.get(email__startswith="pg-acceptance-reviewer-")
    decision = RegulatoryApplicabilityDecision.objects.get(
        registration__entity=entity,
        obligation__revision=2,
        recorded_to__isnull=True,
    )
    current_disposition = RegulatoryApplicabilityReviewDisposition.objects.get(
        decision=decision,
        sequence=1,
    )
    result = record_regulatory_applicability_review_disposition(
        actor=reviewer,
        entity=entity,
        document_id=document.id,
        payload=applicability_review_payload(
            "PG-ACCEPTANCE-RESTORED-SUCCESSOR",
            decision=decision,
            expected_disposition=current_disposition,
            to_disposition="correction_requested",
            reason_code="fact_correction_required",
            rationale="Synthetic restored-runtime append and sequence acceptance",
        ),
        idempotency_key="pg-acceptance-restored-review-successor",
    )
    selected = get_regulatory_applicability_review(
        actor=reviewer,
        entity=entity,
        document_id=document.id,
    )
    _require(result.disposition.sequence == 2, "restored sequence did not advance")
    _require(
        selected.review_state == "correction_requested",
        "restored successor was not selected after commit",
    )
    return {
        "contract": "china-financial-grc/postgresql-restored-runtime/v1",
        "synthetic_only": True,
        "successor_sequence": result.disposition.sequence,
        "selected_review_state": selected.review_state,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("seed", "verify", "mutate-restored"))
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    _guard_acceptance_database()
    if args.command == "seed":
        _seed()
    if args.command == "mutate-restored":
        result = _exercise_restored_runtime()
    else:
        result = _fingerprint()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(result, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
