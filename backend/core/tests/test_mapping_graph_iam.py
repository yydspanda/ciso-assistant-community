"""Adversarial IAM tests for StoredLibrary-backed mapping paths/provenance."""

from __future__ import annotations

from copy import deepcopy
import uuid

import pytest
from django.contrib.auth.models import Permission
from rest_framework.test import APIClient

from core.mappings.engine import engine
from core.models import (
    ComplianceAssessment,
    Framework,
    Perimeter,
    RequirementAssessment,
    RequirementMappingSet,
    RequirementNode,
    StoredLibrary,
)
from iam.models import Folder, Role, RoleAssignment, User


pytestmark = pytest.mark.django_db


AUDIT_FIELDS = {
    field: {"auditor": "edit", "respondent": "hidden"}
    for field in (
        "result",
        "status",
        "score",
        "is_scored",
        "documentation_score",
        "observation",
        "applied_controls",
        "evidences",
        "security_exceptions",
    )
}

MAPPING_PERMISSIONS = {
    "add_complianceassessment",
    "view_complianceassessment",
    "view_compliance_assessment_full",
    "view_requirementassessment",
    "change_requirementassessment",
    "view_framework",
    "view_requirementnode",
    "view_storedlibrary",
    "view_perimeter",
}


def _domain(name: str) -> Folder:
    return Folder.objects.create(
        name=name,
        content_type=Folder.ContentType.DOMAIN,
        parent_folder=Folder.get_root_folder(),
    )


def _grant(user: User, name: str, folders: list[Folder]) -> None:
    role = Role.objects.create(name=name, folder=Folder.get_root_folder())
    role.permissions.set(Permission.objects.filter(codename__in=MAPPING_PERMISSIONS))
    assignment = RoleAssignment.objects.create(
        user=user,
        role=role,
        folder=Folder.get_root_folder(),
        is_recursive=False,
    )
    assignment.perimeter_folders.add(*folders)


def _client(user: User) -> APIClient:
    client = APIClient()
    client.force_authenticate(user=user)
    return client


def _framework(label: str, folder: Folder, *, node_count: int = 1):
    suffix = uuid.uuid4().hex
    framework = Framework.objects.create(
        name=f"Framework {label}",
        urn=f"urn:test:risk:framework:mapping-{label.lower()}-{suffix}",
        ref_id=f"FW-{label}",
        folder=folder,
        min_score=0,
        max_score=100,
    )
    nodes = []
    for index in range(node_count):
        nodes.append(
            RequirementNode.objects.create(
                name=f"Requirement {label}-{index + 1}",
                urn=f"urn:test:risk:req_node:mapping-{label.lower()}-{suffix}:{index + 1}",
                ref_id=f"{label}-{index + 1}",
                framework=framework,
                folder=folder,
                assessable=True,
            )
        )
    return framework, nodes


def _mapping_owner(
    label: str,
    folder: Folder,
    source_framework: Framework,
    target_framework: Framework,
    mappings: list[tuple[RequirementNode, RequirementNode]],
) -> StoredLibrary:
    suffix = uuid.uuid4().hex
    mapping_set = {
        "urn": f"urn:test:risk:req_mapping_set:{label.lower()}-{suffix}",
        "ref_id": f"MAP-{label}",
        "name": f"Mapping {label}",
        "source_framework_urn": source_framework.urn,
        "target_framework_urn": target_framework.urn,
        "requirement_mappings": [
            {
                "source_requirement_urn": source.urn,
                "target_requirement_urn": target.urn,
                "relationship": "equal",
            }
            for source, target in mappings
        ],
    }
    return StoredLibrary.objects.create(
        name=f"Mapping owner {label}",
        urn=f"urn:test:risk:library:mapping-{label.lower()}-{suffix}",
        ref_id=f"LIB-MAP-{label}",
        version=1,
        locale="en",
        default_locale=True,
        hash_checksum=(suffix * 2)[:64],
        content={"requirement_mapping_sets": [mapping_set]},
        objects_meta={"requirement_mapping_sets": 1},
        is_loaded=True,
        folder=folder,
    )


def _assessment(label: str, framework: Framework, folder: Folder):
    assessment = ComplianceAssessment.objects.create(
        name=f"Audit {label}",
        ref_id=f"AUD-{label}",
        framework=framework,
        perimeter=Perimeter.objects.create(name=f"Perimeter {label}", folder=folder),
        folder=folder,
        min_score=0,
        max_score=100,
        field_visibility=AUDIT_FIELDS,
    )
    assessment.create_requirement_assessments()
    return assessment


def _results(response) -> list[dict]:
    body = response.json()
    return body.get("results", []) if isinstance(body, dict) else body


@pytest.fixture(autouse=True)
def _restore_mapping_engine_cache():
    saved = (
        engine._all_rms,
        engine._framework_mappings,
        engine._frameworks,
        engine._direct_mappings,
    )
    yield
    (
        engine._all_rms,
        engine._framework_mappings,
        engine._frameworks,
        engine._direct_mappings,
    ) = saved


def test_hidden_intermediate_framework_cannot_bridge_any_mapping_endpoint():
    Folder._init_root_folder()
    source_folder = _domain("mapping-source")
    hidden_middle_folder = _domain("mapping-hidden-middle")
    target_folder = _domain("mapping-target")
    source_framework, (source_node,) = _framework("A", source_folder)
    middle_framework, (middle_node,) = _framework("B", hidden_middle_folder)
    target_framework, (target_node,) = _framework("C", target_folder)
    _mapping_owner(
        "A-B",
        source_folder,
        source_framework,
        middle_framework,
        [(source_node, middle_node)],
    )
    _mapping_owner(
        "B-C",
        target_folder,
        middle_framework,
        target_framework,
        [(middle_node, target_node)],
    )
    source_audit = _assessment("A", source_framework, source_folder)
    target_audit = _assessment("C", target_framework, target_folder)
    source_ra = source_audit.requirement_assessments.get(requirement=source_node)
    source_ra.result = RequirementAssessment.Result.COMPLIANT
    source_ra.score = 80
    source_ra.is_scored = True
    source_ra.save()
    target_ra = target_audit.requirement_assessments.get(requirement=target_node)
    original_result = target_ra.result
    engine.reload_cache()

    restricted = User.objects.create_user("hidden-middle@mapping-iam.test")
    _grant(restricted, "Mapping without middle", [source_folder, target_folder])
    client = _client(restricted)

    options = client.get(f"/api/compliance-assessments/{source_audit.id}/frameworks/")
    assert options.status_code == 200, options.content
    assert str(target_framework.id) not in {
        str(option["id"]) for option in options.json()
    }
    assert str(middle_framework.id) not in {
        str(option["id"]) for option in options.json()
    }

    listing = client.get(
        "/api/compliance-assessments/",
        {"has_mapping_path_to": str(target_audit.id)},
    )
    assert listing.status_code == 200, listing.content
    assert str(source_audit.id) not in {item["id"] for item in _results(listing)}

    preview = client.get(
        f"/api/compliance-assessments/{target_audit.id}/map_from_preview/",
        {"source_audit_id": str(source_audit.id)},
    )
    assert preview.status_code == 400, preview.content
    apply = client.post(
        f"/api/compliance-assessments/{target_audit.id}/map_from/",
        {"source_audit_id": str(source_audit.id)},
        format="json",
    )
    assert apply.status_code == 400, apply.content
    target_ra.refresh_from_db()
    assert target_ra.result == original_result

    graph = client.get("/api/requirement-mapping-sets/graph-data/")
    assert graph.status_code == 200, graph.content
    graph_urns = {node["urn"] for node in graph.json()["nodes"]}
    assert not graph_urns & {
        source_framework.urn,
        middle_framework.urn,
        target_framework.urn,
    }

    fully_authorized = User.objects.create_user("full-path@mapping-iam.test")
    _grant(
        fully_authorized,
        "Complete mapping path",
        [source_folder, hidden_middle_folder, target_folder],
    )
    full_client = _client(fully_authorized)
    full_options = full_client.get(
        f"/api/compliance-assessments/{source_audit.id}/frameworks/"
    )
    assert full_options.status_code == 200, full_options.content
    assert str(target_framework.id) in {
        str(option["id"]) for option in full_options.json()
    }
    full_preview = full_client.get(
        f"/api/compliance-assessments/{target_audit.id}/map_from_preview/",
        {"source_audit_id": str(source_audit.id)},
    )
    assert full_preview.status_code == 200, full_preview.content
    full_apply = full_client.post(
        f"/api/compliance-assessments/{target_audit.id}/map_from/",
        {"source_audit_id": str(source_audit.id)},
        format="json",
    )
    assert full_apply.status_code == 200, full_apply.content
    mapped_read = full_client.get(f"/api/requirement-assessments/{target_ra.id}/")
    assert mapped_read.status_code == 200, mapped_read.content
    provenance = mapped_read.json()["mapping_inference"]
    assert provenance["used_path"] == [
        source_framework.urn,
        middle_framework.urn,
        target_framework.urn,
    ]
    assert set(provenance["source_requirement_assessments"]) == {
        source_node.urn,
        middle_node.urn,
    }


def test_hidden_stored_library_owner_removes_direct_mapping_path():
    Folder._init_root_folder()
    source_folder = _domain("mapping-owner-source")
    target_folder = _domain("mapping-owner-target")
    hidden_owner_folder = _domain("mapping-hidden-owner")
    source_framework, (source_node,) = _framework("OWNER-A", source_folder)
    target_framework, (target_node,) = _framework("OWNER-C", target_folder)
    owner = _mapping_owner(
        "HIDDEN-OWNER",
        hidden_owner_folder,
        source_framework,
        target_framework,
        [(source_node, target_node)],
    )
    source_audit = _assessment("OWNER-A", source_framework, source_folder)
    target_audit = _assessment("OWNER-C", target_framework, target_folder)
    engine.reload_cache()

    user = User.objects.create_user("hidden-owner@mapping-iam.test")
    _grant(user, "Mapping without owner", [source_folder, target_folder])
    client = _client(user)

    assert (
        client.get(
            f"/api/compliance-assessments/{target_audit.id}/map_from_preview/",
            {"source_audit_id": str(source_audit.id)},
        ).status_code
        == 400
    )
    assert client.get(f"/api/requirement-mapping-sets/{owner.id}/").status_code == 404
    graph = client.get("/api/requirement-mapping-sets/graph-data/")
    assert graph.status_code == 200, graph.content
    assert graph.json()["links"] == []


def test_map_apply_rolls_back_when_locked_source_projection_changes(monkeypatch):
    Folder._init_root_folder()
    source_folder = _domain("mapping-reproof-source")
    target_folder = _domain("mapping-reproof-target")
    source_framework, (source_node,) = _framework("REPROOF-A", source_folder)
    target_framework, (target_node,) = _framework("REPROOF-C", target_folder)
    _mapping_owner(
        "REPROOF",
        source_folder,
        source_framework,
        target_framework,
        [(source_node, target_node)],
    )
    source_audit = _assessment("REPROOF-A", source_framework, source_folder)
    target_audit = _assessment("REPROOF-C", target_framework, target_folder)
    source_ra = source_audit.requirement_assessments.get(requirement=source_node)
    source_ra.result = RequirementAssessment.Result.COMPLIANT
    source_ra.score = 90
    source_ra.is_scored = True
    source_ra.save()
    target_ra = target_audit.requirement_assessments.get(requirement=target_node)
    original_result = target_ra.result
    engine.reload_cache()

    user = User.objects.create_user("mapping-reproof@mapping-iam.test")
    _grant(user, "Mapping reproof", [source_folder, target_folder])

    import core.views as views

    original_compute = views.compute_map_from_merge
    calls = 0

    def changing_compute(*args, **kwargs):
        nonlocal calls
        calls += 1
        result = original_compute(*args, **kwargs)
        if calls == 3:
            changed_results = deepcopy(result[0])
            changed_results["requirement_assessments"][target_node.urn]["result"] = (
                RequirementAssessment.Result.NON_COMPLIANT
            )
            return changed_results, result[1], result[2], result[3]
        return result

    monkeypatch.setattr(views, "compute_map_from_merge", changing_compute)
    response = _client(user).post(
        f"/api/compliance-assessments/{target_audit.id}/map_from/",
        {"source_audit_id": str(source_audit.id)},
        format="json",
    )

    assert calls == 3
    assert response.status_code == 403, response.content
    target_ra.refresh_from_db()
    assert target_ra.result == original_result


def test_map_preview_rejects_field_policy_change_seen_by_fresh_terminal_reproof(
    monkeypatch,
):
    Folder._init_root_folder()
    folder = _domain("mapping-preview-reproof")
    framework, (node,) = _framework("PREVIEW-REPROOF", folder)
    source_audit = _assessment("PREVIEW-SOURCE", framework, folder)
    target_audit = _assessment("PREVIEW-TARGET", framework, folder)
    source_ra = source_audit.requirement_assessments.get(requirement=node)
    source_ra.result = RequirementAssessment.Result.COMPLIANT
    source_ra.save(update_fields=["result"])

    user = User.objects.create_user("preview-reproof@mapping-iam.test")
    _grant(user, "Preview reproof", [folder])

    import core.views as views

    original_compute = views.compute_map_from_merge
    calls = 0

    def changing_policy_compute(*args, **kwargs):
        nonlocal calls
        calls += 1
        result = original_compute(*args, **kwargs)
        if calls == 1:
            changed_visibility = deepcopy(target_audit.field_visibility)
            changed_visibility["result"] = {
                "auditor": "hidden",
                "respondent": "hidden",
            }
            ComplianceAssessment.objects.filter(id=target_audit.id).update(
                field_visibility=changed_visibility
            )
        return result

    monkeypatch.setattr(views, "compute_map_from_merge", changing_policy_compute)
    response = _client(user).get(
        f"/api/compliance-assessments/{target_audit.id}/map_from_preview/",
        {"source_audit_id": str(source_audit.id)},
    )

    assert calls == 2
    assert response.status_code == 403, response.content


def test_cross_framework_baseline_create_uses_locked_authorized_mapping_snapshot():
    Folder._init_root_folder()
    source_folder = _domain("mapping-baseline-source")
    target_folder = _domain("mapping-baseline-target")
    source_framework, (source_node,) = _framework("BASELINE-A", source_folder)
    target_framework, (target_node,) = _framework("BASELINE-C", target_folder)
    _mapping_owner(
        "BASELINE",
        source_folder,
        source_framework,
        target_framework,
        [(source_node, target_node)],
    )
    source_audit = _assessment("BASELINE-A", source_framework, source_folder)
    source_ra = source_audit.requirement_assessments.get(requirement=source_node)
    source_ra.result = RequirementAssessment.Result.COMPLIANT
    source_ra.save(update_fields=["result"])
    target_perimeter = Perimeter.objects.create(
        name="Baseline target perimeter", folder=target_folder
    )
    engine.reload_cache()

    user = User.objects.create_user("mapping-baseline@mapping-iam.test")
    _grant(user, "Mapping baseline create", [source_folder, target_folder])
    response = _client(user).post(
        "/api/compliance-assessments/",
        {
            "name": "Mapped baseline target",
            "ref_id": "AUD-BASELINE-TARGET",
            "version": "1.0",
            "folder": str(target_folder.id),
            "perimeter": str(target_perimeter.id),
            "framework": str(target_framework.id),
            "baseline": str(source_audit.id),
        },
        format="json",
    )

    assert response.status_code == 201, response.content
    created = ComplianceAssessment.objects.get(id=response.json()["id"])
    mapped_ra = created.requirement_assessments.get(requirement=target_node)
    assert mapped_ra.result == RequirementAssessment.Result.COMPLIANT
    assert mapped_ra.mapping_inference["used_path"] == [
        source_framework.urn,
        target_framework.urn,
    ]


def test_provenance_uses_stored_library_owner_not_colliding_mapping_set_uuid():
    Folder._init_root_folder()
    source_folder = _domain("mapping-provenance-source")
    target_folder = _domain("mapping-provenance-target")
    hidden_decoy_folder = _domain("mapping-provenance-decoy")
    source_framework, (source_node,) = _framework("PROV-A", source_folder)
    target_framework, (target_node,) = _framework("PROV-C", target_folder)
    owner = _mapping_owner(
        "PROVENANCE",
        source_folder,
        source_framework,
        target_framework,
        [(source_node, target_node)],
    )
    mapping_set_data = owner.content["requirement_mapping_sets"][0]
    RequirementMappingSet.objects.create(
        id=owner.id,
        name="Hidden decoy live mapping row",
        urn=mapping_set_data["urn"],
        ref_id="DECOY",
        source_framework=source_framework,
        target_framework=target_framework,
        folder=hidden_decoy_folder,
    )
    source_audit = _assessment("PROV-A", source_framework, source_folder)
    target_audit = _assessment("PROV-C", target_framework, target_folder)
    source_ra = source_audit.requirement_assessments.get(requirement=source_node)
    source_ra.result = RequirementAssessment.Result.COMPLIANT
    source_ra.score = 90
    source_ra.is_scored = True
    source_ra.save()
    target_ra = target_audit.requirement_assessments.get(requirement=target_node)
    engine.reload_cache()

    user = User.objects.create_user("provenance-owner@mapping-iam.test")
    _grant(user, "Mapping provenance reader", [source_folder, target_folder])
    from core.utils import get_mapping_authorization

    authorization = get_mapping_authorization(user)
    mapped, path = engine.best_mapping_inferences(
        engine.load_audit_fields(source_audit, user=user),
        source_framework.urn,
        target_framework.urn,
        authorization=authorization,
    )
    assert path == [source_framework.urn, target_framework.urn]
    inference = mapped["requirement_assessments"][target_node.urn]["mapping_inference"]
    target_ra.mapping_inference = inference
    target_ra.save(update_fields=["mapping_inference"])

    client = _client(user)
    response = client.get(f"/api/requirement-assessments/{target_ra.id}/")
    assert response.status_code == 200, response.content
    provenance = response.json()["mapping_inference"]
    source = provenance["source_requirement_assessments"][source_node.urn]
    assert source["used_mapping_set"] == {
        "id": str(owner.id),
        "name": mapping_set_data["name"],
        "ref_id": mapping_set_data["ref_id"],
        "urn": mapping_set_data["urn"],
    }
    assert source["used_mapping_set"]["name"] != "Hidden decoy live mapping row"

    wrong_id = deepcopy(inference)
    wrong_id["source_requirement_assessments"][source_node.urn]["used_mapping_set"][
        "id"
    ] = str(uuid.uuid4())
    RequirementAssessment.objects.filter(id=target_ra.id).update(
        mapping_inference=wrong_id
    )
    wrong_response = client.get(f"/api/requirement-assessments/{target_ra.id}/")
    assert wrong_response.status_code == 200, wrong_response.content
    assert "mapping_inference" not in wrong_response.json()


def test_one_hidden_source_node_removes_entire_provenance_not_a_subset():
    Folder._init_root_folder()
    source_folder = _domain("mapping-lineage-source")
    hidden_node_folder = _domain("mapping-lineage-hidden-node")
    target_folder = _domain("mapping-lineage-target")
    source_framework, source_nodes = _framework(
        "LINEAGE-A", source_folder, node_count=2
    )
    source_node, hidden_source_node = source_nodes
    hidden_source_node.folder = hidden_node_folder
    hidden_source_node.save(update_fields=["folder"])
    target_framework, (target_node,) = _framework("LINEAGE-C", target_folder)
    owner = _mapping_owner(
        "PARTIAL-LINEAGE",
        source_folder,
        source_framework,
        target_framework,
        [(source_node, target_node), (hidden_source_node, target_node)],
    )
    source_audit = _assessment("LINEAGE-A", source_framework, source_folder)
    target_audit = _assessment("LINEAGE-C", target_framework, target_folder)
    source_ras = {
        ra.requirement_id: ra
        for ra in source_audit.requirement_assessments.select_related("requirement")
    }
    target_ra = target_audit.requirement_assessments.get(requirement=target_node)
    mapping_set = owner.content["requirement_mapping_sets"][0]
    raw = {
        "source_requirement_assessments": {
            source_node.urn: {
                "id": str(source_ras[source_node.id].id),
                "urn": source_node.urn,
                "str": "visible source",
                "coverage": "full",
                "source_framework": {
                    "id": str(source_framework.id),
                    "name": source_framework.name,
                },
                "used_mapping_set": {
                    "id": str(owner.id),
                    "urn": mapping_set["urn"],
                    "library_urn": owner.urn,
                },
            },
            hidden_source_node.urn: {
                "id": str(source_ras[hidden_source_node.id].id),
                "urn": hidden_source_node.urn,
                "str": "hidden source",
                "coverage": "full",
                "source_framework": {
                    "id": str(source_framework.id),
                    "name": source_framework.name,
                },
                "used_mapping_set": {
                    "id": str(owner.id),
                    "urn": mapping_set["urn"],
                    "library_urn": owner.urn,
                },
            },
        },
        "used_path": [source_framework.urn, target_framework.urn],
        "result": "compliant",
    }
    target_ra.mapping_inference = raw
    target_ra.save(update_fields=["mapping_inference"])
    engine.reload_cache()

    user = User.objects.create_user("partial-lineage@mapping-iam.test")
    _grant(user, "Partial lineage reader", [source_folder, target_folder])
    response = _client(user).get(f"/api/requirement-assessments/{target_ra.id}/")
    assert response.status_code == 200, response.content
    assert "mapping_inference" not in response.json()
