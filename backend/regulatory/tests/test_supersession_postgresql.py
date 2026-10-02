"""Real PostgreSQL linearisation for bounded synthetic whole-version replacement.

The IAM observation below proves retry checks, not a shared IAM epoch or a
concurrent role-revocation guarantee. These are deterministic acceptance cases,
not benchmarks, and do not establish production or legal approval.
"""

from __future__ import annotations

from concurrent.futures import Future, ThreadPoolExecutor
from contextlib import contextmanager
from copy import deepcopy
from datetime import UTC, date, timedelta
from importlib import import_module
from queue import Queue
from threading import Event, Lock
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

import pytest
from django.core.exceptions import ValidationError
from django.db import connection, transaction
from django.utils import timezone
from rest_framework.exceptions import PermissionDenied

from iam.models import User
from regulatory.models import (
    EntityDocumentRegistration,
    RegulatoryDocumentVersion,
    RegulatoryObligation,
    RegulatoryObligationProvision,
    RegulatoryProvision,
    RegulatoryVersionSupersessionEvent,
)
from regulatory.services import (
    create_regulatory_chain,
    get_regulatory_chain,
    regulatory_chain_semantic_sha256,
    supersede_regulatory_version,
)
from regulatory.services.records import RegulatoryRecordedStateUnavailable
from tprm.models import Entity

from .factories import (
    chain_payload,
    correction_payload,
    make_folder,
    make_synthetic_entity,
    make_user_with_permissions,
)
from .test_postgresql_acceptance import (
    _THREAD_TIMEOUT_SECONDS,
    _run_on_fresh_connection,
    _wait_for_database_block,
)

pytestmark = pytest.mark.django_db(transaction=True)


@pytest.fixture(autouse=True)
def _postgresql_only() -> None:
    if connection.vendor != "postgresql":
        pytest.skip("Supersession concurrency acceptance requires PostgreSQL.")


@contextmanager
def _workers(*release_events: Event):
    """Always release our gates, drain every future, and propagate worker errors."""

    executor = ThreadPoolExecutor(max_workers=2)
    futures: dict[str, Future[Any]] = {}
    outcomes: dict[str, Any] = {}
    try:
        yield executor, futures, outcomes
    finally:
        for event in release_events:
            event.set()
        errors: list[BaseException] = []
        try:
            for name, future in futures.items():
                try:
                    outcomes[name] = future.result(timeout=_THREAD_TIMEOUT_SECONDS)
                except BaseException as exc:
                    errors.append(exc)
        finally:
            executor.shutdown(wait=True, cancel_futures=True)
        if errors:
            raise BaseExceptionGroup("Supersession PostgreSQL workers failed", errors)


def _make_scope(suffix: str):
    folder = make_folder(f"PostgreSQL supersession acceptance {suffix}")
    entity_a = make_synthetic_entity(folder, f"{suffix}-A")
    actor_a = make_user_with_permissions(
        folder,
        "ingest_regulatoryrecord",
        "supersede_regulatoryversion",
        "view_regulatorydocument",
        email_prefix=f"pg-supersession-{suffix.lower()}-a",
    )
    old = create_regulatory_chain(
        actor=actor_a,
        entity=entity_a,
        payload=chain_payload(suffix),
        idempotency_key=f"pg-supersession-initial-{suffix}",
    )
    entity_b = make_synthetic_entity(folder, f"{suffix}-B")
    actor_b = make_user_with_permissions(
        folder,
        "supersede_regulatoryversion",
        "view_regulatorydocument",
        email_prefix=f"pg-supersession-{suffix.lower()}-b",
    )
    reader_entity = make_synthetic_entity(folder, f"{suffix}-READER")
    reader = make_user_with_permissions(
        folder,
        "view_regulatorydocument",
        email_prefix=f"pg-supersession-{suffix.lower()}-reader",
    )
    # Legitimate registrations share one document/folder while preserving
    # separate actor and entity locks before reaching the folder boundary.
    for entity in (entity_b, reader_entity):
        EntityDocumentRegistration.objects.create(
            folder=folder,
            entity=entity,
            document=old.document,
            idempotency_key=f"pg-supersession-registration-{entity.ref_id}",
            payload_sha256="a" * 64,
            ingested_by=actor_a,
        )
    return SimpleNamespace(
        suffix=suffix,
        folder=folder,
        entity_a=entity_a,
        actor_a=actor_a,
        entity_b=entity_b,
        actor_b=actor_b,
        reader_entity=reader_entity,
        reader=reader,
        old=old,
    )


def _payload(scope, label: str = "v2") -> dict:
    payload = correction_payload(
        scope.suffix,
        expected_payload_sha256=regulatory_chain_semantic_sha256(scope.old),
    )
    version, provision, obligation = (
        payload[name] for name in ("document_version", "provision", "obligation")
    )
    today = timezone.now().astimezone(UTC).date()
    effective_on = today + timedelta(days=30)
    version.update(
        id=f"TEST-CN-REG-{scope.suffix}-{label}",
        version_label=f"Synthetic future replacement {label}",
        supersedes_version_ids=[scope.old.document_version.record_id],
        status="published_future_effective",
        status_as_of=today.isoformat(),
        source_checked_on=today.isoformat(),
        effective_date=effective_on.isoformat(),
        valid_from=effective_on.isoformat(),
        source_hash="3" * 64,
    )
    provision.update(
        id=f"TEST-CN-REG-{scope.suffix}-{label}-art1",
        version_id=version["id"],
    )
    obligation.update(
        id=f"TEST-CN-OBL-{scope.suffix}-{label}",
        provision_ids=[provision["id"]],
        valid_from=effective_on.isoformat(),
    )
    return payload


def _write(scope, *, actor_id, entity_id, payload, key):
    return supersede_regulatory_version(
        actor=User.objects.get(pk=actor_id),
        entity=Entity.objects.get(pk=entity_id),
        document_id=scope.old.document.pk,
        payload=deepcopy(payload),
        rationale="Synthetic whole-version PostgreSQL acceptance; non-binding.",
        idempotency_key=key,
    )


def _read(scope, **selectors):
    return get_regulatory_chain(
        actor=User.objects.get(pk=scope.reader.pk),
        entity=Entity.objects.get(pk=scope.reader_entity.pk),
        document_id=scope.old.document.pk,
        **selectors,
    )


def _counts(scope) -> tuple[int, ...]:
    return tuple(
        model.objects.filter(folder=scope.folder).count()
        for model in (
            RegulatoryDocumentVersion,
            RegulatoryProvision,
            RegulatoryObligation,
            RegulatoryVersionSupersessionEvent,
            RegulatoryObligationProvision,
        )
    )


def _source_snapshots(scope) -> list[dict]:
    return [
        row.__class__.objects.filter(pk=row.pk).values().get()
        for row in (
            scope.old.document_version,
            scope.old.provision,
            scope.old.obligation,
        )
    ]


def _assert_one_append_and_unchanged_sources(scope, snapshots) -> None:
    assert _counts(scope) == (2, 2, 2, 1, 2)
    assert _source_snapshots(scope) == snapshots


def _assert_post_commit_selection(scope, replacement) -> None:
    future = _read(scope, valid_on=replacement.event.effective_on)
    assert future.document_version.pk == replacement.chain.document_version.pk
    assert future.provision.pk == replacement.chain.provision.pk
    assert future.obligation.pk == replacement.chain.obligation.pk
    assert future.recorded_as_of >= replacement.event.occurred_at
    assert future.valid_on == replacement.event.effective_on

    # Future metadata never silently becomes the default current legal date.
    current = _read(scope)
    assert current.document_version.pk == scope.old.document_version.pk
    assert current.obligation.pk == scope.old.obligation.pk
    assert current.valid_on < replacement.event.effective_on

    before = replacement.event.occurred_at - timedelta(microseconds=1)
    historical = _read(
        scope,
        recorded_as_of=before,
        valid_on=replacement.event.effective_on,
    )
    assert historical.document_version.pk == scope.old.document_version.pk
    assert historical.provision.pk == scope.old.provision.pk
    assert historical.obligation.pk == scope.old.obligation.pk
    with pytest.raises(RegulatoryRecordedStateUnavailable):
        _read(
            scope,
            recorded_as_of=before,
            version_record_id=replacement.chain.document_version.record_id,
        )


def test_supersession_writer_first_read_waits_and_selects_committed_future_version(
    regulatory_root,
) -> None:
    scope = _make_scope("SUP-WRITE-FIRST")
    payload = _payload(scope)
    snapshots = _source_snapshots(scope)
    writer_pids: Queue[int] = Queue()
    reader_pids: Queue[int] = Queue()
    uncommitted = Event()
    allow_commit = Event()

    def write_operation():
        with transaction.atomic():
            result = _write(
                scope,
                actor_id=scope.actor_a.pk,
                entity_id=scope.entity_a.pk,
                payload=payload,
                key="pg-supersession-writer-first",
            )
            uncommitted.set()
            assert allow_commit.wait(_THREAD_TIMEOUT_SECONDS)
            return result

    def read_operation():
        return _read(
            scope,
            valid_on=date.fromisoformat(payload["document_version"]["effective_date"]),
        )

    with _workers(allow_commit) as (executor, futures, outcomes):
        futures["writer"] = executor.submit(
            _run_on_fresh_connection,
            "cfgrc-pg-supersession-writer-first",
            writer_pids,
            write_operation,
        )
        writer_pid = writer_pids.get(timeout=_THREAD_TIMEOUT_SECONDS)
        assert uncommitted.wait(_THREAD_TIMEOUT_SECONDS)
        futures["reader"] = executor.submit(
            _run_on_fresh_connection,
            "cfgrc-pg-supersession-reader-after-writer",
            reader_pids,
            read_operation,
        )
        reader_pid = reader_pids.get(timeout=_THREAD_TIMEOUT_SECONDS)
        assert reader_pid != writer_pid
        _, _, blocked_query = _wait_for_database_block(
            blocked_pid=reader_pid, blocker_pid=writer_pid
        )
        assert "iam_folder" in blocked_query

    replacement, selected = outcomes["writer"], outcomes["reader"]
    assert selected.document_version.pk == replacement.chain.document_version.pk
    assert selected.provision.pk == replacement.chain.provision.pk
    assert selected.obligation.pk == replacement.chain.obligation.pk
    assert selected.document_version.revision == 1
    assert selected.recorded_as_of >= replacement.event.occurred_at
    _assert_one_append_and_unchanged_sources(scope, snapshots)
    _assert_post_commit_selection(scope, replacement)


def test_supersession_reader_first_returns_old_while_writer_waits_for_folder(
    regulatory_root,
) -> None:
    scope = _make_scope("SUP-READ-FIRST")
    payload = _payload(scope)
    snapshots = _source_snapshots(scope)
    reader_pids: Queue[int] = Queue()
    writer_pids: Queue[int] = Queue()
    selected_old = Event()
    allow_commit = Event()

    def read_operation():
        with transaction.atomic():
            selected = _read(scope)
            selected_old.set()
            assert allow_commit.wait(_THREAD_TIMEOUT_SECONDS)
            return selected

    def write_operation():
        return _write(
            scope,
            actor_id=scope.actor_a.pk,
            entity_id=scope.entity_a.pk,
            payload=payload,
            key="pg-supersession-reader-first",
        )

    with _workers(allow_commit) as (executor, futures, outcomes):
        futures["reader"] = executor.submit(
            _run_on_fresh_connection,
            "cfgrc-pg-supersession-reader-first",
            reader_pids,
            read_operation,
        )
        reader_pid = reader_pids.get(timeout=_THREAD_TIMEOUT_SECONDS)
        assert selected_old.wait(_THREAD_TIMEOUT_SECONDS)
        futures["writer"] = executor.submit(
            _run_on_fresh_connection,
            "cfgrc-pg-supersession-writer-after-reader",
            writer_pids,
            write_operation,
        )
        writer_pid = writer_pids.get(timeout=_THREAD_TIMEOUT_SECONDS)
        assert writer_pid != reader_pid
        _, _, blocked_query = _wait_for_database_block(
            blocked_pid=writer_pid, blocker_pid=reader_pid
        )
        assert "iam_folder" in blocked_query

    selected, replacement = outcomes["reader"], outcomes["writer"]
    assert selected.document_version.pk == scope.old.document_version.pk
    assert selected.provision.pk == scope.old.provision.pk
    assert selected.obligation.pk == scope.old.obligation.pk
    assert selected.recorded_as_of < replacement.event.occurred_at
    _assert_one_append_and_unchanged_sources(scope, snapshots)
    _assert_post_commit_selection(scope, replacement)


def test_supersession_same_predecessor_concurrent_writers_have_one_winner(
    regulatory_root,
) -> None:
    scope = _make_scope("SUP-ONE-WINNER")
    first_payload, second_payload = _payload(scope, "v2a"), _payload(scope, "v2b")
    assert first_payload["expected_revisions"] == second_payload["expected_revisions"]
    snapshots = _source_snapshots(scope)
    first_pids: Queue[int] = Queue()
    second_pids: Queue[int] = Queue()
    uncommitted = Event()
    allow_commit = Event()

    def first_operation():
        with transaction.atomic():
            result = _write(
                scope,
                actor_id=scope.actor_a.pk,
                entity_id=scope.entity_a.pk,
                payload=first_payload,
                key="pg-supersession-one-winner-a",
            )
            uncommitted.set()
            assert allow_commit.wait(_THREAD_TIMEOUT_SECONDS)
            return result

    def second_operation():
        with pytest.raises(ValidationError, match="unsuperseded leaf"):
            _write(
                scope,
                actor_id=scope.actor_b.pk,
                entity_id=scope.entity_b.pk,
                payload=second_payload,
                key="pg-supersession-one-winner-b",
            )

    with _workers(allow_commit) as (executor, futures, outcomes):
        futures["first"] = executor.submit(
            _run_on_fresh_connection,
            "cfgrc-pg-supersession-first-writer",
            first_pids,
            first_operation,
        )
        first_pid = first_pids.get(timeout=_THREAD_TIMEOUT_SECONDS)
        assert uncommitted.wait(_THREAD_TIMEOUT_SECONDS)
        futures["second"] = executor.submit(
            _run_on_fresh_connection,
            "cfgrc-pg-supersession-second-writer",
            second_pids,
            second_operation,
        )
        second_pid = second_pids.get(timeout=_THREAD_TIMEOUT_SECONDS)
        assert second_pid != first_pid
        _, _, blocked_query = _wait_for_database_block(
            blocked_pid=second_pid, blocker_pid=first_pid
        )
        assert "iam_folder" in blocked_query

    replacement = outcomes["first"]
    _assert_one_append_and_unchanged_sources(scope, snapshots)
    assert not RegulatoryDocumentVersion.objects.filter(
        folder=scope.folder, record_id=second_payload["document_version"]["id"]
    ).exists()
    assert not RegulatoryProvision.objects.filter(
        folder=scope.folder, record_id=second_payload["provision"]["id"]
    ).exists()
    assert not RegulatoryObligation.objects.filter(
        folder=scope.folder, record_id=second_payload["obligation"]["id"]
    ).exists()
    assert not RegulatoryVersionSupersessionEvent.objects.filter(
        folder=scope.folder, idempotency_key="pg-supersession-one-winner-b"
    ).exists()
    _assert_post_commit_selection(scope, replacement)


def test_supersession_parallel_exact_retry_reauthorizes_without_duplicate_history(
    regulatory_root,
) -> None:
    scope = _make_scope("SUP-EXACT-RETRY")
    payload = _payload(scope)
    snapshots = _source_snapshots(scope)
    first_pids: Queue[int] = Queue()
    retry_pids: Queue[int] = Queue()
    uncommitted = Event()
    allow_commit = Event()
    permission_checks: list[tuple[int, Any, str, Any]] = []
    checks_lock = Lock()
    supersession_module = import_module("regulatory.services.supersession")
    original_permission_check = supersession_module.require_regulatory_permission

    def observed_permission_check(**kwargs):
        original_permission_check(**kwargs)
        with connection.cursor() as cursor:
            cursor.execute("SELECT pg_backend_pid()")
            pid = cursor.fetchone()[0]
        with checks_lock:
            permission_checks.append(
                (pid, kwargs["actor"].pk, kwargs["codename"], kwargs["folder"].pk)
            )

    def first_operation():
        with transaction.atomic():
            result = _write(
                scope,
                actor_id=scope.actor_a.pk,
                entity_id=scope.entity_a.pk,
                payload=payload,
                key="pg-supersession-exact-retry",
            )
            uncommitted.set()
            assert allow_commit.wait(_THREAD_TIMEOUT_SECONDS)
            return result

    def retry_operation():
        return _write(
            scope,
            actor_id=scope.actor_a.pk,
            entity_id=scope.entity_a.pk,
            payload=payload,
            key="pg-supersession-exact-retry",
        )

    # The wrapper always calls the real check and is restored after both thread
    # results have been consumed, including failed probes or worker exceptions.
    with patch.object(
        supersession_module,
        "require_regulatory_permission",
        side_effect=observed_permission_check,
    ):
        with _workers(allow_commit) as (executor, futures, outcomes):
            futures["first"] = executor.submit(
                _run_on_fresh_connection,
                "cfgrc-pg-supersession-exact-first",
                first_pids,
                first_operation,
            )
            first_pid = first_pids.get(timeout=_THREAD_TIMEOUT_SECONDS)
            assert uncommitted.wait(_THREAD_TIMEOUT_SECONDS)
            futures["retry"] = executor.submit(
                _run_on_fresh_connection,
                "cfgrc-pg-supersession-exact-retry",
                retry_pids,
                retry_operation,
            )
            retry_pid = retry_pids.get(timeout=_THREAD_TIMEOUT_SECONDS)
            assert retry_pid != first_pid
            _, _, blocked_query = _wait_for_database_block(
                blocked_pid=retry_pid, blocker_pid=first_pid
            )
            assert "iam_user" in blocked_query

    first, retry = outcomes["first"], outcomes["retry"]
    assert first.event.pk == retry.event.pk
    assert first.event.payload_sha256 == retry.event.payload_sha256
    assert first.chain.document_version.pk == retry.chain.document_version.pk
    assert first.chain.provision.pk == retry.chain.provision.pk
    assert first.chain.obligation.pk == retry.chain.obligation.pk
    assert sorted(permission_checks) == sorted(
        [
            (pid, scope.actor_a.pk, "supersede_regulatoryversion", scope.folder.pk)
            for pid in (first_pid, retry_pid)
        ]
    )
    assert (
        supersession_module.require_regulatory_permission is original_permission_check
    )
    _assert_one_append_and_unchanged_sources(scope, snapshots)
    _assert_post_commit_selection(scope, first)

    # Retry does not trust the caller's stale, still-active in-memory principal.
    assert scope.actor_a.is_active is True
    User.objects.filter(pk=scope.actor_a.pk).update(is_active=False)
    with pytest.raises(PermissionDenied, match="active actor"):
        supersede_regulatory_version(
            actor=scope.actor_a,
            entity=scope.entity_a,
            document_id=scope.old.document.pk,
            payload=deepcopy(payload),
            rationale="Synthetic whole-version PostgreSQL acceptance; non-binding.",
            idempotency_key="pg-supersession-exact-retry",
        )
    _assert_one_append_and_unchanged_sources(scope, snapshots)
