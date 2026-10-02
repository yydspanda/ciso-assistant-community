from copy import deepcopy
from datetime import UTC, date, timedelta
from importlib import import_module
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from auditlog.models import LogEntry
from django.contrib.auth.models import Permission
from django.core.exceptions import ValidationError
from django.db import IntegrityError, migrations, transaction
from django.utils import timezone
from iam.models import Role, RoleAssignment
from iam.service_accounts import provision_service_account
from rest_framework.exceptions import PermissionDenied

from regulatory.models import (
    RegulatoryDocumentVersion,
    RegulatoryObligation,
    RegulatoryProvision,
    RegulatoryVersionSupersessionEvent,
)
from regulatory.services import (
    create_regulatory_chain,
    get_regulatory_chain,
    regulatory_chain_semantic_sha256,
    supersede_regulatory_version,
)
from regulatory.services.common import IdempotencyConflict
from regulatory.services.records import RegulatoryRecordedStateUnavailable

from .factories import (
    chain_payload,
    correction_payload,
    make_folder,
    make_synthetic_entity,
    make_user_with_permissions,
)


@pytest.fixture
def supersession_scope(regulatory_root):
    folder = make_folder()
    entity = make_synthetic_entity(folder, "REPLACE")
    actor = make_user_with_permissions(
        folder,
        "ingest_regulatoryrecord",
        "supersede_regulatoryversion",
        "view_regulatorydocument",
    )
    chain = create_regulatory_chain(
        actor=actor,
        entity=entity,
        payload=chain_payload("REPLACE"),
        idempotency_key="initial",
    )
    return SimpleNamespace(folder=folder, entity=entity, actor=actor, chain=chain)


def supersession_payload(chain, label="v2", effective_on="2027-01-01"):
    payload = correction_payload(
        "REPLACE",
        expected_payload_sha256=regulatory_chain_semantic_sha256(chain),
        expected_revision=chain.document_version.revision,
    )
    payload["expected_revisions"].update(
        provision=chain.provision.revision, obligation=chain.obligation.revision
    )
    version, provision, obligation = (
        payload[name] for name in ("document_version", "provision", "obligation")
    )
    version.update(
        id=f"TEST-CN-REG-REPLACE-{label}",
        version_label=f"Synthetic {label}",
        document_id=chain.document.record_id,
        supersedes_version_ids=[chain.document_version.record_id],
        status="published_future_effective",
        effective_date=effective_on,
        valid_from=effective_on,
    )
    provision.update(
        id=f"TEST-CN-REG-REPLACE-{label}-art1",
        document_id=chain.document.record_id,
        version_id=version["id"],
    )
    obligation.update(
        id=f"TEST-CN-OBL-REPLACE-{label}",
        provision_ids=[provision["id"]],
        valid_from=effective_on,
    )
    return payload


def replace(scope, payload=None, key="replace"):
    return supersede_regulatory_version(
        actor=scope.actor,
        entity=scope.entity,
        document_id=scope.chain.document.id,
        payload=payload if payload is not None else supersession_payload(scope.chain),
        rationale="Synthetic whole-document metadata only; no legal approval.",
        idempotency_key=key,
    )


def counts():
    return tuple(
        model.objects.count()
        for model in (
            RegulatoryDocumentVersion,
            RegulatoryProvision,
            RegulatoryObligation,
            RegulatoryVersionSupersessionEvent,
        )
    )


def test_future_version_coexists_without_closing_or_reviewing_old_rows(
    supersession_scope,
):
    scope = supersession_scope
    old_rows = (
        scope.chain.document_version,
        scope.chain.provision,
        scope.chain.obligation,
    )
    snapshots = [
        model.__class__.objects.filter(pk=model.pk).values().get() for model in old_rows
    ]
    digest = regulatory_chain_semantic_sha256(scope.chain)
    result = replace(scope)
    assert counts() == (2, 2, 2, 1)
    assert result.predecessor.document_version.id == scope.chain.document_version.id
    assert result.event.registration == scope.chain.registration
    assert result.event.effective_on == date(2027, 1, 1)
    assert result.event.recorded_by == scope.actor
    assert result.event.replacement_kind == "whole_document"
    assert not result.event.is_binding and not result.event.is_published
    assert result.event.before_payload_sha256 == digest
    assert result.event.after_payload_sha256 == regulatory_chain_semantic_sha256(
        result.chain
    )
    for record, snapshot in zip(old_rows, snapshots):
        assert record.__class__.objects.filter(pk=record.pk).values().get() == snapshot
    for record in (
        result.chain.document_version,
        result.chain.provision,
        result.chain.obligation,
    ):
        assert record.revision == 1 and record.previous_revision_id is None
        assert (
            record.recorded_from == result.event.occurred_at
            and record.recorded_to is None
        )
        assert not record.is_published
    assert result.chain.obligation.current_review_status == "machine_proposed"
    assert result.chain.obligation.review_events.count() == 0
    assert result.chain.document_version.legal_review_status == "unreviewed"
    assert result.chain.provision.text is None
    assert LogEntry.objects.get_for_object(result.event).count() == 1


def test_exact_retry_is_durable_but_another_request_conflicts(supersession_scope):
    payload = supersession_payload(supersession_scope.chain)
    result = replace(supersession_scope, payload)
    assert replace(supersession_scope, payload).event.id == result.event.id
    altered = deepcopy(payload)
    altered["obligation"]["action"] += " changed"
    with pytest.raises(IdempotencyConflict):
        replace(supersession_scope, altered)
    assert counts() == (2, 2, 2, 1)


def test_linear_three_version_chain_rejects_fork_and_loop(supersession_scope):
    scope = supersession_scope
    first_payload = supersession_payload(scope.chain)
    first = replace(scope, first_payload)
    with pytest.raises(ValidationError, match="leaf"):
        replace(scope, supersession_payload(scope.chain, "fork", "2029-01-01"), "fork")
    next_scope = SimpleNamespace(**{**vars(scope), "chain": first.chain})
    second = replace(
        next_scope, supersession_payload(first.chain, "v3", "2028-01-01"), "next"
    )
    assert (
        second.event.predecessor_document_version_id == first.chain.document_version.id
    )
    assert second.event.occurred_at > first.event.occurred_at
    loop = supersession_payload(second.chain, "v1", "2029-01-01")
    with pytest.raises(ValidationError, match="already used"):
        replace(SimpleNamespace(**{**vars(scope), "chain": second.chain}), loop, "loop")
    assert replace(scope, first_payload).event.id == first.event.id
    assert counts() == (3, 3, 3, 2)


@pytest.mark.parametrize(
    "path,value",
    [
        (("expected_revisions", "document_version"), 2),
        (("expected_revisions", "semantic_payload_sha256"), "0" * 64),
        (("document_version", "document_id"), "OTHER-DOCUMENT"),
        (("provision", "version_id"), "OTHER-VERSION"),
        (("obligation", "provision_ids"), ["OTHER-PROVISION"]),
        (("document_version", "supersedes_version_ids"), []),
        (("document_version", "supersedes_version_ids"), ["OLD", "SECOND"]),
        (("document_version", "effective_date"), None),
        (("document_version", "effective_basis"), "unresolved"),
        (("document_version", "effective_date"), "2021-11-01"),
        (("obligation", "valid_from"), "2027-02-01"),
        (("document_version", "valid_to"), "2028-01-01"),
        (("document_version", "transition_end"), "2028-01-01"),
        (("document_version", "repeal_date"), "2028-01-01"),
        (("obligation", "valid_to"), "2028-01-01"),
        (("document_version", "content_storage_policy"), "official_snapshot"),
        (("document_version", "legal_review_status"), "reviewed"),
        (("provision", "text"), "Forbidden source text"),
        (("obligation", "review_status"), "approved"),
        (("document_version", "status"), "effective"),
        (("document_version", "recorded_from"), "2026-10-01T00:00:00Z"),
        (("obligation", "is_published"), True),
        (("provision", "source_locator"), {"kind": "article"}),
        (("obligation", "deadline"), {"kind": "none"}),
        (("obligation", "confidence"), True),
        (("expected_revisions", "document_version"), True),
        (("document_version", "version_label"), 8),
        (("document_version", "status_as_of"), "2026-02-30"),
        (("document_version", "provenance"), []),
    ],
)
def test_invalid_replacement_is_atomic(supersession_scope, path, value):
    payload = supersession_payload(supersession_scope.chain)
    payload[path[0]][path[1]] = value
    before = counts()
    with pytest.raises(ValidationError):
        replace(supersession_scope, payload)
    assert counts() == before
    assert (
        RegulatoryDocumentVersion.objects.get(
            pk=supersession_scope.chain.document_version.pk
        ).recorded_to
        is None
    )


@pytest.mark.parametrize(
    "confidence",
    [10**1000, float("nan"), float("inf"), float("-inf"), -0.1, 1.1],
    ids=["huge-int", "nan", "infinity", "negative-infinity", "below-zero", "above-one"],
)
def test_unbounded_confidence_fails_before_writes(supersession_scope, confidence):
    payload = supersession_payload(supersession_scope.chain)
    payload["obligation"]["confidence"] = confidence
    with pytest.raises(ValidationError, match="confidence"):
        replace(supersession_scope, payload)
    assert counts() == (1, 1, 1, 0)


def test_future_source_check_rejects_before_appending_chain(supersession_scope):
    payload = supersession_payload(supersession_scope.chain)
    payload["document_version"]["source_checked_on"] = (
        (timezone.now() + timedelta(days=1)).date().isoformat()
    )
    with (
        patch("regulatory.services.supersession._append_chain") as append_chain,
        pytest.raises(ValidationError, match="server recorded date"),
    ):
        replace(supersession_scope, payload)
    append_chain.assert_not_called()
    assert counts() == (1, 1, 1, 0)


@pytest.mark.parametrize(
    "changes",
    [
        {"valid_to": date(2026, 9, 1)},
        {"valid_from": date(2021, 11, 2)},
    ],
    ids=["closed-obligation", "mismatched-obligation-start"],
)
def test_predecessor_obligation_interval_rejects_before_writes(
    supersession_scope, changes
):
    scope = supersession_scope
    RegulatoryObligation.objects.filter(pk=scope.chain.obligation.pk).update(**changes)
    scope.chain.obligation.refresh_from_db()
    payload = supersession_payload(scope.chain)
    with (
        patch("regulatory.services.supersession._append_chain") as append_chain,
        pytest.raises(ValidationError),
    ):
        replace(scope, payload)
    append_chain.assert_not_called()
    assert counts() == (1, 1, 1, 0)


@pytest.mark.parametrize("prefix", ["predecessor", "successor"])
@pytest.mark.parametrize("record_name", ["document_version", "provision", "obligation"])
def test_bound_revision_integrity_is_checked_beyond_semantic_digest(
    supersession_scope, prefix, record_name
):
    scope = supersession_scope
    result = replace(scope)
    chain = result.predecessor if prefix == "predecessor" else result.chain
    digest = regulatory_chain_semantic_sha256(chain)
    record = getattr(chain, record_name)
    record.__class__.objects.filter(pk=record.pk).update(revision=2)
    record.refresh_from_db()
    assert record.previous_revision_id is None
    assert regulatory_chain_semantic_sha256(chain) == digest
    result.event.refresh_from_db()
    with pytest.raises(ValidationError):
        result.event.full_clean()
    with pytest.raises(RegulatoryRecordedStateUnavailable, match="source binding"):
        get_regulatory_chain(
            actor=scope.actor,
            entity=scope.entity,
            document_id=scope.chain.document.pk,
            valid_on=date(2027, 1, 1),
        )


@pytest.mark.parametrize("prefix", ["predecessor", "successor"])
def test_bound_chain_recorded_epoch_must_remain_shared(supersession_scope, prefix):
    result = replace(supersession_scope)
    record = getattr(result.event, f"{prefix}_provision")
    digest = (
        result.event.before_payload_sha256
        if prefix == "predecessor"
        else result.event.after_payload_sha256
    )
    RegulatoryProvision.objects.filter(pk=record.pk).update(
        recorded_from=record.recorded_from + timedelta(microseconds=1)
    )
    record.refresh_from_db()
    chain = result.predecessor if prefix == "predecessor" else result.chain
    getattr(chain, "provision").refresh_from_db()
    assert regulatory_chain_semantic_sha256(chain) == digest
    result.event.refresh_from_db()
    with pytest.raises(ValidationError):
        result.event.full_clean()


@pytest.mark.parametrize("record_name", ["document_version", "provision", "obligation"])
def test_bound_predecessor_recorded_intervals_must_remain_open(
    supersession_scope, record_name
):
    result = replace(supersession_scope)
    record = getattr(result.predecessor, record_name)
    record.__class__.objects.filter(pk=record.pk).update(
        recorded_to=result.event.occurred_at
    )
    result.event.refresh_from_db()
    with pytest.raises(ValidationError, match="recorded interval must remain open"):
        result.event.full_clean()


@pytest.mark.parametrize(
    "invalid", [None, [], "payload", {1: "bad"}, {"replacement_kind": "partial"}]
)
def test_malformed_top_level_fails_closed(supersession_scope, invalid):
    with pytest.raises(ValidationError):
        supersede_regulatory_version(
            actor=supersession_scope.actor,
            entity=supersession_scope.entity,
            document_id=supersession_scope.chain.document.id,
            payload=invalid,
            rationale="Synthetic",
            idempotency_key="bad",
        )
    assert counts() == (1, 1, 1, 0)


@pytest.mark.parametrize(
    "field,value",
    [
        ("rationale", None),
        ("rationale", " "),
        ("rationale", "x" * 4001),
        ("idempotency_key", []),
        ("idempotency_key", " "),
        ("idempotency_key", "x" * 201),
    ],
)
def test_command_types_are_strict(supersession_scope, field, value):
    args = dict(
        actor=supersession_scope.actor,
        entity=supersession_scope.entity,
        document_id=supersession_scope.chain.document.id,
        payload=supersession_payload(supersession_scope.chain),
        rationale="Synthetic",
        idempotency_key="bad",
    )
    args[field] = value
    with pytest.raises(ValidationError):
        supersede_regulatory_version(**args)
    assert counts() == (1, 1, 1, 0)


def test_ids_must_all_be_new_and_distinct(supersession_scope):
    for section in ("document_version", "provision", "obligation"):
        payload = supersession_payload(supersession_scope.chain)
        payload[section]["id"] = getattr(supersession_scope.chain, section).record_id
        with pytest.raises(ValidationError):
            replace(supersession_scope, payload, section)
    payload = supersession_payload(supersession_scope.chain)
    payload["obligation"]["id"] = payload["provision"]["id"]
    with pytest.raises(ValidationError, match="distinct"):
        replace(supersession_scope, payload)
    assert counts() == (1, 1, 1, 0)


def test_dedicated_permission_is_opt_in_and_folder_scoped(supersession_scope):
    scope = supersession_scope
    ingester = make_user_with_permissions(scope.folder, "ingest_regulatoryrecord")
    outsider = make_user_with_permissions(make_folder(), "supersede_regulatoryversion")
    for actor in (ingester, outsider):
        with pytest.raises(PermissionDenied):
            replace(SimpleNamespace(**{**vars(scope), "actor": actor}))
    permission = Permission.objects.get(
        content_type__app_label="regulatory", codename="supersede_regulatoryversion"
    )
    assert not Role.objects.filter(builtin=True, permissions=permission).exists()
    RoleAssignment.objects.filter(user=scope.actor).delete()
    with pytest.raises(PermissionDenied):
        replace(scope)
    assert counts() == (1, 1, 1, 0)


def test_named_active_human_and_live_synthetic_scope_required(supersession_scope):
    scope = supersession_scope
    scope.actor.__class__.objects.filter(pk=scope.actor.pk).update(is_active=False)
    with pytest.raises(PermissionDenied):
        replace(scope)
    scope.actor.__class__.objects.filter(pk=scope.actor.pk).update(is_active=True)
    scope.entity.__class__.objects.filter(pk=scope.entity.pk).update(
        ref_id="REAL-INSTITUTION"
    )
    with pytest.raises(ValidationError, match="SYNTHETIC"):
        replace(scope)
    scope.entity.__class__.objects.filter(pk=scope.entity.pk).update(
        ref_id="SYNTHETIC-AGAIN", folder=make_folder()
    )
    with pytest.raises((PermissionDenied, ValidationError)):
        replace(scope)
    assert counts() == (1, 1, 1, 0)


def test_service_account_cannot_supersede(supersession_scope):
    scope = supersession_scope
    permission = Permission.objects.get(
        content_type__app_label="regulatory", codename="supersede_regulatoryversion"
    )
    service_account, _ = provision_service_account(
        name="Synthetic replacement workload",
        description="Synthetic test only",
        permission_ids=[permission.id],
        folder_ids=[scope.folder.id],
        is_recursive=False,
        created_by=scope.actor,
    )
    with pytest.raises(ValidationError, match="named human"):
        replace(SimpleNamespace(**{**vars(scope), "actor": service_account.user}))
    assert counts() == (1, 1, 1, 0)


def test_server_cutoff_follows_history_under_clock_rollback(supersession_scope):
    scope = supersession_scope
    payload = supersession_payload(scope.chain)
    known_utc_date = scope.chain.document_version.recorded_from.astimezone(UTC).date()
    payload["document_version"].update(
        source_checked_on=known_utc_date.isoformat(),
        status_as_of=known_utc_date.isoformat(),
    )
    with patch(
        "regulatory.services.supersession.timezone.now",
        return_value=scope.chain.document_version.recorded_from - timedelta(days=1),
    ):
        result = replace(scope, payload)
    assert result.event.occurred_at > scope.chain.document_version.recorded_from
    assert result.chain.document_version.source_checked_on <= (
        result.event.occurred_at.astimezone(UTC).date()
    )


def test_event_failure_rolls_back_all_new_rows(supersession_scope):
    with patch.object(
        RegulatoryVersionSupersessionEvent.objects,
        "create",
        side_effect=ValidationError("synthetic event failure"),
    ):
        with pytest.raises(ValidationError, match="event failure"):
            replace(supersession_scope)
    assert counts() == (1, 1, 1, 0)


def test_event_is_append_only_and_database_rejects_promotion(supersession_scope):
    event = replace(supersession_scope).event
    event.rationale = "changed"
    with pytest.raises(ValidationError, match="append-only"):
        event.save()
    with pytest.raises(ValidationError, match="cannot be deleted"):
        event.delete()
    for field in ("is_binding", "is_published"):
        with pytest.raises(IntegrityError), transaction.atomic():
            RegulatoryVersionSupersessionEvent.objects.filter(pk=event.pk).update(
                **{field: True}
            )
    event.refresh_from_db()
    assert not event.is_binding and not event.is_published
    original_digest = event.before_payload_sha256
    event.before_payload_sha256 = "0" * 64
    with pytest.raises(ValidationError, match="exact persisted chain"):
        event.full_clean()
    assert (
        RegulatoryVersionSupersessionEvent.objects.get(
            pk=event.pk
        ).before_payload_sha256
        == original_digest
    )


def test_reverse_migration_guard_retains_populated_history():
    module = import_module(
        "regulatory.migrations.0005_regulatoryversionsupersessionevent"
    )
    assert isinstance(module.Migration.operations[-1], migrations.RunPython)
    assert (
        module.Migration.operations[-1].reverse_code
        is module.refuse_reverse_with_supersession_history
    )

    class Manager:
        populated = True

        def using(self, alias):
            assert alias == "owned-synthetic"
            return self

        def exists(self):
            return self.populated

    manager = Manager()

    class Apps:
        def get_model(self, app_label, model_name):
            assert (app_label, model_name) == (
                "regulatory",
                "RegulatoryVersionSupersessionEvent",
            )
            return SimpleNamespace(objects=manager)

    editor = SimpleNamespace(connection=SimpleNamespace(alias="owned-synthetic"))
    with pytest.raises(RuntimeError, match="retain migration 0005"):
        module.refuse_reverse_with_supersession_history(Apps(), editor)
    manager.populated = False
    module.refuse_reverse_with_supersession_history(Apps(), editor)
