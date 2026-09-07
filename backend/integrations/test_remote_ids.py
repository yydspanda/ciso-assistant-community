import pytest

from integrations.remote_ids import InvalidRemoteIdentifier, normalize_remote_id


@pytest.mark.parametrize(
    ("provider_name", "remote_id", "expected"),
    (
        ("jira", " proj-123 ", "PROJ-123"),
        ("JIRA", "ｐｒｏｊ-123", "PROJ-123"),
        ("servicenow", " A0B1C2 ", "a0b1c2"),
        ("custom", " Case-Sensitive ", "Case-Sensitive"),
    ),
)
def test_normalize_remote_id_has_one_provider_specific_representation(
    provider_name, remote_id, expected
):
    assert normalize_remote_id(provider_name, remote_id) == expected


@pytest.mark.parametrize("remote_id", ("", "   ", "REMOTE ID", "REMOTE\nID", 123))
def test_normalize_remote_id_rejects_ambiguous_or_non_string_values(remote_id):
    with pytest.raises(InvalidRemoteIdentifier):
        normalize_remote_id("custom", remote_id)


def test_normalize_remote_id_allows_only_explicit_pending_blank():
    assert normalize_remote_id("jira", "  ", allow_blank=True) == ""
