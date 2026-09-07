"""Focused serializer tests for governed integration mapping settings."""

import uuid
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from integrations.serializers import IntegrationConfigurationSerializer


def _serializer(stored_settings, *, patch_data=None):
    provider = SimpleNamespace(
        id=uuid.uuid4(),
        name="servicenow",
    )
    configuration = SimpleNamespace(
        id=uuid.uuid4(),
        provider=provider,
        provider_id=provider.id,
        folder_id=uuid.uuid4(),
        credentials={},
        settings=stored_settings,
        is_active=True,
        builtin=False,
    )
    serializer = IntegrationConfigurationSerializer(
        configuration,
        data=patch_data or {"is_active": False},
        partial=True,
    )
    # Unique-together belongs to persistence and is unrelated to this pure
    # mapping-contract test; suppress its database lookup.
    serializer.validators = []
    return serializer


def _validate(stored_settings, *, patch_data=None):
    serializer = _serializer(stored_settings, patch_data=patch_data)
    with patch(
        "integrations.serializers.IntegrationRegistry.validate_configuration",
        return_value=(True, []),
    ):
        valid = serializer.is_valid()
    return serializer, valid


@pytest.mark.parametrize(
    "settings",
    (
        {
            "field_map": {"name": "short_description", "status": "state"},
            "value_map": {"status": {"to_do": "1", "active": "2"}},
        },
        {
            "models": {
                "applied_control": {
                    "field_map": {"name": "summary"},
                    "value_map": {"status": {"to_do": "To Do"}},
                },
                "asset": {
                    "field_map": {"name": "u_asset_name", "type": "u_type"},
                    "value_map": {"type": {"PR": "primary", "SP": "support"}},
                },
            }
        },
    ),
)
def test_serializer_accepts_legacy_and_nested_governed_mappings(settings):
    serializer, valid = _validate(settings)

    assert valid, serializer.errors


@pytest.mark.parametrize(
    "settings, expected",
    (
        ({"models": []}, "settings.models must be an object"),
        (
            {"models": {"unknown_model": {}}},
            "is not a syncable model",
        ),
        (
            {"models": {"asset": []}},
            "settings.models.asset must be an object",
        ),
        (
            {"models": {"asset": {"field_map": []}}},
            "field_map must be an object",
        ),
        (
            {"models": {"asset": {"field_map": {"status": "u_status"}}}},
            "is not a mappable field for asset",
        ),
        (
            {"field_map": {"unknown": "u_unknown"}},
            "is not a mappable field for applied_control",
        ),
        (
            {"models": {"asset": {"value_map": []}}},
            "value_map must be an object",
        ),
        (
            {"models": {"asset": {"value_map": {"status": {}}}}},
            "is not a mappable field for asset",
        ),
        (
            {"models": {"asset": {"value_map": {"type": []}}}},
            "settings.models.asset.value_map.type must be an object",
        ),
    ),
)
def test_serializer_rejects_unknown_or_non_object_mapping_shapes(settings, expected):
    serializer, valid = _validate(settings)

    assert not valid
    assert expected in str(serializer.errors)


@pytest.mark.parametrize(
    "remote_target",
    ("", "   ", " leading", "trailing ", "embedded\tspace"),
)
def test_serializer_rejects_empty_or_noncanonical_remote_targets(remote_target):
    serializer, valid = _validate(
        {"models": {"asset": {"field_map": {"name": remote_target}}}}
    )

    assert not valid
    assert "remote target" in str(serializer.errors) or "whitespace" in str(
        serializer.errors
    )


def test_serializer_rejects_remote_targets_that_collide_after_trimming():
    serializer, valid = _validate(
        {
            "models": {
                "asset": {
                    "field_map": {
                        "name": "u_identity",
                        "description": " u_identity ",
                    }
                }
            }
        }
    )

    assert not valid
    assert "duplicates remote target" in str(serializer.errors)


def test_serializer_rejects_ambiguous_value_map_reverse_values():
    serializer, valid = _validate(
        {
            "models": {
                "asset": {
                    "value_map": {"type": {"PR": 1, "SP": "1"}},
                }
            }
        }
    )

    assert not valid
    assert "ambiguous remote value" in str(serializer.errors)


def test_patch_validates_complete_stored_settings_when_settings_are_omitted():
    serializer, valid = _validate(
        {"models": {"asset": {"field_map": {"not_governed": "u_secret"}}}},
        patch_data={"is_active": False},
    )

    assert not valid
    assert "not a mappable field for asset" in str(serializer.errors)


def test_patch_validates_the_replacement_as_the_complete_prospective_settings():
    serializer, valid = _validate(
        {"models": {"unknown_model": {}}},
        patch_data={
            "settings": {
                "models": {
                    "asset": {"field_map": {"name": "u_asset_name"}},
                }
            }
        },
    )

    assert valid, serializer.errors
    assert serializer.validated_data["settings"] == {
        "models": {"asset": {"field_map": {"name": "u_asset_name"}}}
    }
