from __future__ import annotations

from concurrent.futures import Future, ThreadPoolExecutor
from copy import deepcopy
from datetime import timedelta
import json
from queue import Queue
from threading import Barrier, Event
import time
from typing import Any, Callable

import pytest
from django.core.exceptions import ValidationError
from django.db import (
    close_old_connections,
    connection,
    connections,
    transaction,
)
from django.db.models import Q, QuerySet

from iam.models import User
from regulatory.models import (
    EntityDocumentRegistration,
    RegulatoryApplicabilityDecision,
    RegulatoryApplicabilityReviewDisposition,
    RegulatoryDocumentVersion,
)
from regulatory.services import (
    correct_regulatory_chain,
    create_regulatory_chain,
    get_regulatory_chain,
    record_regulatory_applicability_decision,
    record_regulatory_applicability_review_disposition,
    regulatory_chain_semantic_sha256,
)
from tprm.models import Entity

from .factories import (
    applicability_payload,
    applicability_review_payload,
    chain_payload,
    correction_payload,
    make_folder,
    make_synthetic_entity,
    make_user_with_permissions,
)


pytestmark = pytest.mark.django_db(transaction=True)

_THREAD_TIMEOUT_SECONDS = 15
_BLOCKING_PROBE_TIMEOUT_SECONDS = 8
_REVIEW_VIEW_PERMISSION = "view_regulatoryapplicabilityreviewdisposition"
_REVIEW_PERMISSION = "review_regulatoryapplicability"


@pytest.fixture(autouse=True)
def _postgresql_only() -> None:
    if connection.vendor != "postgresql":
        pytest.skip("PostgreSQL acceptance tests require a PostgreSQL database.")


def _configure_thread_connection(application_name: str, pid_queue: Queue[int]) -> None:
    """Open a thread-local connection with bounded lock and statement waits."""

    close_old_connections()
    database = connections["default"]
    database.close()
    with database.cursor() as cursor:
        cursor.execute(
            "SELECT set_config('application_name', %s, false)",
            [application_name],
        )
        cursor.execute("SET lock_timeout = '10s'")
        cursor.execute("SET statement_timeout = '12s'")
        cursor.execute("SELECT pg_backend_pid()")
        pid_queue.put(cursor.fetchone()[0])


def _run_on_fresh_connection(
    application_name: str,
    pid_queue: Queue[int],
    operation: Callable[[], Any],
) -> Any:
    _configure_thread_connection(application_name, pid_queue)
    try:
        return operation()
    finally:
        connections["default"].close()
        close_old_connections()


def _wait_for_database_block(
    *,
    blocked_pid: int,
    blocker_pid: int,
) -> tuple[str, str, str]:
    """Prove a real PostgreSQL wait and return its wait type, event, and SQL."""

    deadline = time.monotonic() + _BLOCKING_PROBE_TIMEOUT_SECONDS
    last_observation: tuple[Any, ...] | None = None
    while time.monotonic() < deadline:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT
                    activity.wait_event_type,
                    activity.wait_event,
                    activity.query,
                    %s = ANY(pg_blocking_pids(activity.pid)) AS expected_blocker
                FROM pg_stat_activity AS activity
                WHERE activity.pid = %s
                """,
                [blocker_pid, blocked_pid],
            )
            last_observation = cursor.fetchone()
        if last_observation is not None and last_observation[3]:
            wait_type, wait_event, query, _ = last_observation
            assert wait_type == "Lock"
            return wait_type, wait_event, query
        time.sleep(0.05)
    raise AssertionError(
        "PostgreSQL did not report the expected blocker; "
        f"last observation was {last_observation!r}."
    )


def _future_result(future: Future[Any]) -> Any:
    return future.result(timeout=_THREAD_TIMEOUT_SECONDS)


def _make_correction_scope(suffix: str):
    folder = make_folder(f"PostgreSQL lock acceptance {suffix}")
    writer_entity = make_synthetic_entity(folder, f"{suffix}-WRITER")
    writer = make_user_with_permissions(
        folder,
        "ingest_regulatoryrecord",
        "view_regulatorydocument",
        "correct_regulatoryrecord",
        email_prefix=f"pg-writer-{suffix.lower()}",
    )
    reader = make_user_with_permissions(
        folder,
        "view_regulatorydocument",
        email_prefix=f"pg-reader-{suffix.lower()}",
    )
    chain = create_regulatory_chain(
        actor=writer,
        entity=writer_entity,
        payload=chain_payload(suffix),
        idempotency_key=f"pg-chain-{suffix}",
    )
    reader_entity = make_synthetic_entity(folder, f"{suffix}-READER")
    EntityDocumentRegistration.objects.create(
        folder=folder,
        entity=reader_entity,
        document=chain.document,
        idempotency_key=f"pg-reader-registration-{suffix}",
        payload_sha256="a" * 64,
        ingested_by=writer,
    )
    payload = correction_payload(
        suffix,
        expected_payload_sha256=regulatory_chain_semantic_sha256(chain),
    )
    return writer_entity, writer, reader_entity, reader, chain, payload


def _make_applicability_review_scope(suffix: str):
    folder = make_folder(f"PostgreSQL review acceptance {suffix}")
    entity = make_synthetic_entity(folder, suffix)
    recorder = make_user_with_permissions(
        folder,
        "ingest_regulatoryrecord",
        "view_regulatorydocument",
        "view_regulatoryapplicabilitydecision",
        "record_regulatoryapplicability",
        "view_entitydocumentregistration",
        email_prefix=f"pg-recorder-{suffix.lower()}",
    )
    chain = create_regulatory_chain(
        actor=recorder,
        entity=entity,
        payload=chain_payload(suffix),
        idempotency_key=f"pg-review-chain-{suffix}",
    )
    decision = record_regulatory_applicability_decision(
        actor=recorder,
        entity=entity,
        document_id=chain.document.id,
        payload=applicability_payload(suffix, chain=chain),
        idempotency_key=f"pg-review-decision-{suffix}",
    ).decision
    return folder, entity, recorder, chain, decision


def _make_reviewer(folder, suffix: str) -> User:
    return make_user_with_permissions(
        folder,
        "view_regulatorydocument",
        "view_regulatoryapplicabilitydecision",
        _REVIEW_VIEW_PERMISSION,
        _REVIEW_PERMISSION,
        "view_entitydocumentregistration",
        email_prefix=f"pg-reviewer-{suffix.lower()}",
    )


def test_writer_first_current_read_blocks_then_observes_committed_successor(
    regulatory_root,
) -> None:
    (
        writer_entity,
        writer,
        reader_entity,
        reader,
        initial_chain,
        payload,
    ) = _make_correction_scope("WRITE-FIRST")
    writer_pid_queue: Queue[int] = Queue()
    reader_pid_queue: Queue[int] = Queue()
    correction_is_uncommitted = Event()
    allow_writer_commit = Event()

    def write_operation():
        with transaction.atomic():
            result = correct_regulatory_chain(
                actor=User.objects.get(pk=writer.pk),
                entity=Entity.objects.get(pk=writer_entity.pk),
                document_id=initial_chain.document.id,
                payload=deepcopy(payload),
                rationale="PostgreSQL writer-first lock acceptance",
                idempotency_key="pg-correction-write-first",
            )
            correction_is_uncommitted.set()
            if not allow_writer_commit.wait(_THREAD_TIMEOUT_SECONDS):
                raise AssertionError("Timed out while holding the writer transaction.")
            return result.event.occurred_at, result.chain.obligation.id

    def read_operation():
        selected = get_regulatory_chain(
            actor=User.objects.get(pk=reader.pk),
            entity=Entity.objects.get(pk=reader_entity.pk),
            document_id=initial_chain.document.id,
        )
        return selected.obligation.id, selected.obligation.revision

    with ThreadPoolExecutor(max_workers=2) as executor:
        writer_future = executor.submit(
            _run_on_fresh_connection,
            "cfgrc-pg-writer-first",
            writer_pid_queue,
            write_operation,
        )
        reader_future: Future[Any] | None = None
        try:
            writer_pid = writer_pid_queue.get(timeout=_THREAD_TIMEOUT_SECONDS)
            assert correction_is_uncommitted.wait(_THREAD_TIMEOUT_SECONDS)
            reader_future = executor.submit(
                _run_on_fresh_connection,
                "cfgrc-pg-reader-after-writer",
                reader_pid_queue,
                read_operation,
            )
            reader_pid = reader_pid_queue.get(timeout=_THREAD_TIMEOUT_SECONDS)
            _, _, blocked_query = _wait_for_database_block(
                blocked_pid=reader_pid,
                blocker_pid=writer_pid,
            )
            assert "iam_folder" in blocked_query
        finally:
            allow_writer_commit.set()

        cutoff, successor_obligation_id = _future_result(writer_future)
        assert reader_future is not None
        selected_obligation_id, selected_revision = _future_result(reader_future)

    assert selected_obligation_id == successor_obligation_id
    assert selected_revision == 2
    historical = get_regulatory_chain(
        actor=reader,
        entity=reader_entity,
        document_id=initial_chain.document.id,
        recorded_as_of=cutoff - timedelta(microseconds=1),
    )
    assert historical.obligation.id == initial_chain.obligation.id
    assert historical.obligation.revision == 1


def test_reader_first_returns_predecessor_while_writer_waits_for_folder_lock(
    regulatory_root,
) -> None:
    (
        writer_entity,
        writer,
        reader_entity,
        reader,
        initial_chain,
        payload,
    ) = _make_correction_scope("READ-FIRST")
    reader_pid_queue: Queue[int] = Queue()
    writer_pid_queue: Queue[int] = Queue()
    predecessor_selected = Event()
    allow_reader_commit = Event()

    def read_operation():
        with transaction.atomic():
            selected = get_regulatory_chain(
                actor=User.objects.get(pk=reader.pk),
                entity=Entity.objects.get(pk=reader_entity.pk),
                document_id=initial_chain.document.id,
            )
            predecessor_selected.set()
            if not allow_reader_commit.wait(_THREAD_TIMEOUT_SECONDS):
                raise AssertionError("Timed out while holding the reader transaction.")
            return selected.obligation.id, selected.obligation.revision

    def write_operation():
        result = correct_regulatory_chain(
            actor=User.objects.get(pk=writer.pk),
            entity=Entity.objects.get(pk=writer_entity.pk),
            document_id=initial_chain.document.id,
            payload=deepcopy(payload),
            rationale="PostgreSQL reader-first lock acceptance",
            idempotency_key="pg-correction-read-first",
        )
        return result.chain.obligation.id, result.chain.obligation.revision

    with ThreadPoolExecutor(max_workers=2) as executor:
        reader_future = executor.submit(
            _run_on_fresh_connection,
            "cfgrc-pg-reader-first",
            reader_pid_queue,
            read_operation,
        )
        writer_future: Future[Any] | None = None
        try:
            reader_pid = reader_pid_queue.get(timeout=_THREAD_TIMEOUT_SECONDS)
            assert predecessor_selected.wait(_THREAD_TIMEOUT_SECONDS)
            writer_future = executor.submit(
                _run_on_fresh_connection,
                "cfgrc-pg-writer-after-reader",
                writer_pid_queue,
                write_operation,
            )
            writer_pid = writer_pid_queue.get(timeout=_THREAD_TIMEOUT_SECONDS)
            _, _, blocked_query = _wait_for_database_block(
                blocked_pid=writer_pid,
                blocker_pid=reader_pid,
            )
            assert "iam_folder" in blocked_query
        finally:
            allow_reader_commit.set()

        selected_obligation_id, selected_revision = _future_result(reader_future)
        assert writer_future is not None
        successor_obligation_id, successor_revision = _future_result(writer_future)

    assert selected_obligation_id == initial_chain.obligation.id
    assert selected_revision == 1
    assert successor_obligation_id != selected_obligation_id
    assert successor_revision == 2


def test_concurrent_exact_head_review_has_one_winner_and_one_stale_writer(
    regulatory_root,
) -> None:
    folder, entity, _, chain, decision = _make_applicability_review_scope("EXACT-HEAD")
    first_reviewer = _make_reviewer(folder, "EXACT-HEAD-A")
    second_reviewer = _make_reviewer(folder, "EXACT-HEAD-B")
    start_barrier = Barrier(2)

    def review_worker(reviewer_id, suffix: str, idempotency_key: str):
        pid_queue: Queue[int] = Queue()

        def operation():
            reviewer = User.objects.get(pk=reviewer_id)
            target_entity = Entity.objects.get(pk=entity.pk)
            start_barrier.wait(timeout=_THREAD_TIMEOUT_SECONDS)
            try:
                result = record_regulatory_applicability_review_disposition(
                    actor=reviewer,
                    entity=target_entity,
                    document_id=chain.document.id,
                    payload=applicability_review_payload(
                        suffix,
                        decision=decision,
                        rationale=f"Concurrent exact-head review {suffix}",
                    ),
                    idempotency_key=idempotency_key,
                )
            except ValidationError as exc:
                return "validation_error", exc
            return "success", result.disposition.id

        return _run_on_fresh_connection(
            f"cfgrc-pg-review-{suffix.lower()}",
            pid_queue,
            operation,
        )

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = (
            executor.submit(
                review_worker,
                first_reviewer.id,
                "EXACT-HEAD-A",
                "pg-exact-head-a",
            ),
            executor.submit(
                review_worker,
                second_reviewer.id,
                "EXACT-HEAD-B",
                "pg-exact-head-b",
            ),
        )
        outcomes = [_future_result(future) for future in futures]

    successes = [value for status, value in outcomes if status == "success"]
    failures = [value for status, value in outcomes if status == "validation_error"]
    assert len(successes) == 1
    assert len(failures) == 1
    stale_error = failures[0]
    assert "expected_current_disposition" in stale_error.message_dict
    assert "stale" in str(stale_error).lower()

    persisted = list(
        RegulatoryApplicabilityReviewDisposition.objects.filter(
            decision=decision
        ).order_by("sequence")
    )
    assert len(persisted) == 1
    assert persisted[0].id == successes[0]
    assert persisted[0].sequence == 1
    assert persisted[0].previous_disposition_id is None


def _plan_index_names(plan: dict[str, Any]) -> set[str]:
    names: set[str] = set()
    index_name = plan.get("Index Name")
    if index_name:
        names.add(index_name)
    for child in plan.get("Plans", []):
        names.update(_plan_index_names(child))
    return names


def _explain_index_names(queryset: QuerySet) -> set[str]:
    explained = queryset.explain(
        analyze=True,
        buffers=True,
        format="json",
        timing=False,
    )
    payload = json.loads(explained)
    return _plan_index_names(payload[0]["Plan"])


def test_existing_temporal_selection_indexes_are_explain_usable(
    regulatory_root,
) -> None:
    folder, entity, _, chain, decision = _make_applicability_review_scope("INDEX-PLANS")
    reviewer = _make_reviewer(folder, "INDEX-PLANS")
    disposition = record_regulatory_applicability_review_disposition(
        actor=reviewer,
        entity=entity,
        document_id=chain.document.id,
        payload=applicability_review_payload(
            "INDEX-PLANS",
            decision=decision,
        ),
        idempotency_key="pg-index-plan-review",
    ).disposition
    selected_at = disposition.occurred_at

    version_query = (
        RegulatoryDocumentVersion.objects.filter(
            folder=folder,
            document=chain.document,
            recorded_from__lte=selected_at,
        )
        .filter(Q(recorded_to__isnull=True) | Q(recorded_to__gt=selected_at))
        .order_by("recorded_from")
    )
    applicability_query = (
        RegulatoryApplicabilityDecision.objects.filter(
            folder=folder,
            registration=decision.registration,
            obligation=decision.obligation,
            recorded_from__lte=selected_at,
        )
        .filter(Q(recorded_to__isnull=True) | Q(recorded_to__gt=selected_at))
        .order_by("recorded_from")
    )
    disposition_query = RegulatoryApplicabilityReviewDisposition.objects.filter(
        folder=folder,
        decision=decision,
        occurred_at__lte=selected_at,
    ).order_by("occurred_at")

    with transaction.atomic(), connection.cursor() as cursor:
        # The synthetic fixture is intentionally tiny. Disabling sequential scans
        # asks PostgreSQL whether each existing index can support its selection
        # predicate without pretending this is a production latency benchmark.
        cursor.execute("SET LOCAL enable_seqscan = off")
        plans = {
            "document_version": _explain_index_names(version_query),
            "applicability": _explain_index_names(applicability_query),
            "disposition": _explain_index_names(disposition_query),
        }

    assert "reg_ver_doc_asof_idx" in plans["document_version"], plans
    assert "reg_app_dec_asof_idx" in plans["applicability"], plans
    assert "reg_app_rev_dec_time_idx" in plans["disposition"], plans
