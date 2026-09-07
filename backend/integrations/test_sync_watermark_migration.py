"""Pure regression tests for conservative legacy sync-watermark migration."""

from datetime import UTC, datetime
from importlib import import_module
from types import SimpleNamespace
from uuid import uuid4

import pytest


class _FilteredRows(list):
    def exists(self):
        return bool(self)


class _MappingRows(list):
    def update(self, **values):
        for row in self:
            for field, value in values.items():
                setattr(row, field, value)
        return len(self)

    def filter(self, **criteria):
        assert criteria == {"last_synced_at__isnull": True}
        return _FilteredRows(row for row in self if row.last_synced_at is None)


def _mapping(watermark):
    return SimpleNamespace(id=uuid4(), last_synced_at=watermark)


def _apps(mappings):
    class _Apps:
        @staticmethod
        def get_model(app_label, model_name):
            assert (app_label, model_name) == ("integrations", "SyncMapping")
            return SimpleNamespace(objects=mappings)

    return _Apps()


def test_legacy_watermarks_are_all_marked_unknown():
    migration = import_module(
        "integrations.migrations.0007_reconciliation_decisions_and_delivery_authority"
    )
    now = datetime(2026, 9, 7, 12, 0, tzinfo=UTC)
    mappings = _MappingRows([_mapping(now), _mapping(now)])

    migration.clear_unproved_sync_watermarks(_apps(mappings), None)

    assert [row.last_synced_at for row in mappings] == [None, None]


def test_reverse_migration_refuses_to_fabricate_unknown_watermarks():
    migration = import_module(
        "integrations.migrations.0007_reconciliation_decisions_and_delivery_authority"
    )
    now = datetime(2026, 9, 7, 12, 0, tzinfo=UTC)
    mappings = _MappingRows([_mapping(now), _mapping(None)])

    with pytest.raises(RuntimeError, match="no proved successful-sync timestamp"):
        migration.reject_unsafe_watermark_downgrade(_apps(mappings), None)

    mappings[1].last_synced_at = now
    migration.reject_unsafe_watermark_downgrade(_apps(mappings), None)
