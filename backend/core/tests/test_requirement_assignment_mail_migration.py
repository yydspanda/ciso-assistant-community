"""Pure regression tests for conservative legacy mail-outbox migration."""

from importlib import import_module
from types import SimpleNamespace
from uuid import uuid4


class _Rows(list):
    def order_by(self, *fields):
        return self

    def iterator(self):
        return iter(self)


class _EvidenceManager:
    def __init__(self):
        self.rows = []

    def create(self, **values):
        self.rows.append(values)


def _outbox(status, failure_code=""):
    row = SimpleNamespace(
        id=uuid4(),
        assignment_id=uuid4(),
        folder_id=uuid4(),
        recipient_actor_id=uuid4(),
        requested_by_id=uuid4(),
        payload_digest="a" * 64,
        recipient_address_hash="b" * 64,
        status=status,
        attempts=1,
        failure_code=failure_code,
    )
    row.saved_fields = []

    def save(*, update_fields):
        row.saved_fields.append(update_fields)

    row.save = save
    return row


def test_legacy_mail_outcomes_are_migrated_without_claiming_delivery():
    migration = import_module(
        "core.migrations.0187_requirementassignmentmailevidence_and_more"
    )
    rows = _Rows(
        [
            _outbox("sending"),
            _outbox("failed", "claim_timeout"),
            _outbox("failed", "delivery_error"),
            _outbox("delivered"),
            _outbox("queued"),
        ]
    )
    outbox_model = SimpleNamespace(objects=rows)
    evidence_manager = _EvidenceManager()
    evidence_model = SimpleNamespace(objects=evidence_manager)

    class _Apps:
        @staticmethod
        def get_model(app_label, model_name):
            assert app_label == "core"
            if model_name == "RequirementAssignmentMailOutbox":
                return outbox_model
            assert model_name == "RequirementAssignmentMailEvidence"
            return evidence_model

    migration.backfill_mail_delivery_evidence(_Apps(), schema_editor=None)

    assert [row.status for row in rows] == [
        "review_required",
        "review_required",
        "uncertain",
        "delivered",
        "queued",
    ]
    assert len(evidence_manager.rows) == len(rows)
    assert [row["prior_status"] for row in evidence_manager.rows] == [
        "sending",
        "failed",
        "failed",
        "delivered",
        "queued",
    ]
    assert all(
        row["evidence_reference"] == "migration:core-0187-legacy-outbox"
        and len(row["record_digest"]) == 64
        for row in evidence_manager.rows
    )
