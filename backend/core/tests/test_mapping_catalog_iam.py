"""Mapping catalog projections retain the exact owner and endpoint authority."""

import pytest

from core.models import StoredLibrary
from core.tests.test_mapping_graph_iam import (
    _client,
    _domain,
    _framework,
    _grant,
    _mapping_owner,
    _results,
)
from iam.models import Folder, User


pytestmark = pytest.mark.django_db


@pytest.mark.parametrize("shape", ["plural", "legacy-singular"])
@pytest.mark.parametrize("endpoint", ["", "provider/"])
def test_mapping_catalog_preserves_join_and_excludes_hidden_owner_or_endpoint(
    shape,
    endpoint,
):
    Folder._init_root_folder()
    visible_folder = _domain("catalog-visible")
    hidden_folder = _domain("catalog-hidden")
    source, (source_node,) = _framework("CATALOG-SOURCE", visible_folder)
    target, (target_node,) = _framework("CATALOG-TARGET", visible_folder)
    hidden, (hidden_node,) = _framework("CATALOG-HIDDEN", hidden_folder)
    cases = [
        ("VISIBLE", visible_folder, source, target, source_node, target_node),
        ("HIDDEN-OWNER", hidden_folder, source, target, source_node, target_node),
        ("HIDDEN-SOURCE", visible_folder, hidden, target, hidden_node, target_node),
        ("HIDDEN-TARGET", visible_folder, source, hidden, source_node, hidden_node),
    ]
    owners = []
    for label, folder, source_fw, target_fw, source_ra, target_ra in cases:
        owner = _mapping_owner(
            label,
            folder,
            source_fw,
            target_fw,
            [(source_ra, target_ra)],
        )
        content = owner.content
        if shape == "legacy-singular":
            content = {
                "requirement_mapping_set": content["requirement_mapping_sets"][0]
            }
        StoredLibrary.objects.filter(id=owner.id).update(
            provider=f"synthetic-{label}", content=content
        )
        owners.append(owner)

    user = User.objects.create_user("catalog-reader@mapping-iam.test")
    _grant(user, "Visible mapping catalog", [visible_folder])
    client = _client(user)

    response = client.get(f"/api/requirement-mapping-sets/{endpoint}")

    assert response.status_code == 200, response.content
    if endpoint:
        assert response.json() == {"synthetic-VISIBLE": "synthetic-VISIBLE"}
    else:
        rows = _results(response)
        assert {row["id"] for row in rows} == {str(owners[0].id)}
        assert rows[0]["source_framework"]["urn"] == source.urn
        assert rows[0]["target_framework"]["urn"] == target.urn
    for hidden_owner in owners[1:]:
        denied = client.get(f"/api/requirement-mapping-sets/{hidden_owner.id}/")
        assert denied.status_code == 404, denied.content
