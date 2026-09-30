import copy
import hashlib
import json
from pathlib import Path

import pytest
import yaml

from core.mappings.engine import MappingEngine
from core.models import (
    ComplianceAssessment,
    Framework,
    LoadedLibrary,
    Perimeter,
    RequirementAssessment,
    RequirementMappingSet,
    RequirementNode,
    StoredLibrary,
)
from iam.models import Folder


LIBRARIES = Path(__file__).resolve().parents[1] / "libraries"
LEGACY_PATH = LIBRARIES / "essential-eight.yaml"
CURRENT_PATH = LIBRARIES / "essential-eight-2023.yaml"
MAPPING_PATH = LIBRARIES / "mapping-essential-eight-and-essential-eight-2023.yaml"

LEGACY_LIBRARY_URN = "urn:intuitem:risk:library:essential-eight"
CURRENT_LIBRARY_URN = "urn:intuitem:risk:library:essential-eight-2023"
LEGACY_FRAMEWORK_URN = "urn:intuitem:risk:framework:essential-eight"
CURRENT_FRAMEWORK_URN = "urn:intuitem:risk:framework:essential-eight-2023"
LEGACY_NODE_FINGERPRINT = (
    "8f7194c2dd55b22c633ebcc936c0739fbdce73bfff87e15c71e8c36cd571128e"
)

CC_BY_4_URL = "https://creativecommons.org/licenses/by/4.0/"
OFFICIAL_SOURCE_URLS = {
    "https://www.cyber.gov.au/sites/default/files/2025-03/"
    "Essential%20Eight%20maturity%20model%20(November%202023).pdf",
    "https://www.cyber.gov.au/business-government/asds-cyber-security-frameworks/"
    "essential-eight/essential-eight-assessment-process-guide",
    "https://www.cyber.gov.au/business-government/asds-cyber-security-frameworks/"
    "essential-eight/essential-eight-maturity-model-and-ism-mapping",
}


def _read(path: Path) -> dict:
    return yaml.safe_load(path.read_bytes())


def _nodes(document: dict) -> list[dict]:
    return document["objects"]["framework"]["requirement_nodes"]


def _mapping_set(document: dict) -> dict:
    value = document["objects"].get("requirement_mapping_set")
    if value is not None:
        return value
    values = document["objects"]["requirement_mapping_sets"]
    assert len(values) == 1
    return values[0]


def _canonical_fingerprint(value) -> str:
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode()
    return hashlib.sha256(encoded).hexdigest()


def _renamespace(value, namespace: str):
    """Clone a shipped document without colliding with post-migrate seed rows."""

    if isinstance(value, str):
        return value.replace("urn:intuitem:risk:", f"urn:{namespace}:risk:")
    if isinstance(value, list):
        return [_renamespace(item, namespace) for item in value]
    if isinstance(value, dict):
        return {key: _renamespace(item, namespace) for key, item in value.items()}
    return value


def _store(document: dict) -> StoredLibrary:
    content = yaml.safe_dump(document, sort_keys=False, allow_unicode=True).encode()
    stored, error = StoredLibrary.store_library_content(content, builtin=True)
    assert error is None, error
    assert stored is not None
    return stored


def test_essential_eight_artifacts_have_stable_identity_complete_mapping_and_rights():
    legacy = _read(LEGACY_PATH)
    current = _read(CURRENT_PATH)
    mapping = _read(MAPPING_PATH)

    assert (legacy["urn"], legacy["version"]) == (LEGACY_LIBRARY_URN, 3)
    assert legacy["name"].endswith(" - legacy")
    assert legacy["objects"]["framework"]["urn"] == LEGACY_FRAMEWORK_URN
    assert current["urn"] == CURRENT_LIBRARY_URN
    assert current["objects"]["framework"]["urn"] == CURRENT_FRAMEWORK_URN

    legacy_nodes = _nodes(legacy)
    current_nodes = _nodes(current)
    assert _canonical_fingerprint(legacy_nodes) == LEGACY_NODE_FINGERPRINT
    assert (len(legacy_nodes), len(current_nodes)) == (157, 160)

    for document in (legacy, current):
        framework = document["objects"]["framework"]
        definitions = {
            item["ref_id"] for item in framework["implementation_groups_definition"]
        }
        assert definitions == {"1", "2", "3"}

        nodes = _nodes(document)
        by_urn = {node["urn"].casefold(): node for node in nodes}
        assert len(by_urn) == len(nodes)
        for node in nodes:
            groups = set(node.get("implementation_groups") or [])
            assert groups <= definitions
            if node["assessable"]:
                assert groups
            if parent_urn := node.get("parent_urn"):
                parent = by_urn[parent_urn.casefold()]
                assert node["depth"] == parent["depth"] + 1

    mapping_set = _mapping_set(mapping)
    mappings = mapping_set["requirement_mappings"]
    pairs = {
        (item["source_requirement_urn"], item["target_requirement_urn"])
        for item in mappings
    }
    legacy_assessable = {node["urn"] for node in legacy_nodes if node["assessable"]}
    current_assessable = {node["urn"] for node in current_nodes if node["assessable"]}

    assert mapping["dependencies"] == [LEGACY_LIBRARY_URN, CURRENT_LIBRARY_URN]
    assert mapping_set["source_framework_urn"] == LEGACY_FRAMEWORK_URN
    assert mapping_set["target_framework_urn"] == CURRENT_FRAMEWORK_URN
    assert len(mappings) == len(pairs) == 152
    assert {source for source, _ in pairs} == legacy_assessable
    assert {target for _, target in pairs} == current_assessable
    assert {item["relationship"] for item in mappings} <= {
        "equal",
        "subset",
        "superset",
    }
    assert {item["rationale"] for item in mappings} <= {"syntactic", "semantic"}

    notice = current["copyright"]
    assert "© Commonwealth of Australia 2023" in notice
    assert "© Commonwealth of Australia 2024" in notice
    assert CC_BY_4_URL in notice
    assert all(url in notice for url in OFFICIAL_SOURCE_URLS)
    assert "adapted and restructured" in notice
    assert "not endorsed by ASD or the Commonwealth of Australia" in notice
    assert "No Coat of Arms, ASD logo, or third-party material is included" in notice


@pytest.mark.django_db
def test_legacy_metadata_update_preserves_assessment_rows_and_results():
    namespace = "essential-eight-update-test"
    version_3 = _renamespace(_read(LEGACY_PATH), namespace)
    version_2 = copy.deepcopy(version_3)
    version_2["version"] = 2
    version_2["name"] = version_2["name"].removesuffix(" - legacy")
    version_2["description"] = "Pre-deprecation metadata"
    version_2["publication_date"] = "2024-03-17"
    version_2["objects"]["framework"]["name"] = version_2["objects"]["framework"][
        "name"
    ].removesuffix(" - legacy")
    version_2["objects"]["framework"]["description"] = "Pre-deprecation metadata"

    stored_v2 = _store(version_2)
    assert stored_v2.load() is None
    loaded = LoadedLibrary.objects.get(urn=version_2["urn"])
    framework = Framework.objects.get(urn=version_2["objects"]["framework"]["urn"])
    requirement = RequirementNode.objects.filter(
        framework=framework, assessable=True
    ).first()
    assert requirement is not None

    root = Folder.get_root_folder()
    perimeter = Perimeter.objects.create(name="Essential Eight update", folder=root)
    assessment = ComplianceAssessment.objects.create(
        name="Existing Essential Eight audit",
        framework=framework,
        perimeter=perimeter,
        folder=root,
    )
    assessment.create_requirement_assessments()
    row = RequirementAssessment.objects.get(
        compliance_assessment=assessment, requirement=requirement
    )
    row.status = RequirementAssessment.Status.DONE
    row.result = RequirementAssessment.Result.COMPLIANT
    row.observation = "Reviewed before the library metadata update"
    row.score = 87
    row.is_scored = True
    row.save()

    preserved = {
        "loaded": loaded.pk,
        "framework": framework.pk,
        "requirement": requirement.pk,
        "assessment": assessment.pk,
        "row": row.pk,
        "row_created_at": row.created_at,
        "assessment_created_at": assessment.created_at,
        "row_count": assessment.requirement_assessments.count(),
    }

    _store(version_3)
    assert loaded.update() is None

    loaded.refresh_from_db()
    framework.refresh_from_db()
    requirement.refresh_from_db()
    assessment.refresh_from_db()
    row.refresh_from_db()
    assert loaded.pk == preserved["loaded"]
    assert loaded.version == 3
    assert loaded.name.endswith(" - legacy")
    assert framework.pk == preserved["framework"]
    assert framework.name.endswith(" - legacy")
    assert requirement.pk == preserved["requirement"]
    assert assessment.pk == preserved["assessment"]
    assert assessment.framework_id == framework.pk
    assert assessment.created_at == preserved["assessment_created_at"]
    assert assessment.requirement_assessments.count() == preserved["row_count"]
    assert row.pk == preserved["row"]
    assert row.requirement_id == requirement.pk
    assert row.created_at == preserved["row_created_at"]
    assert row.status == RequirementAssessment.Status.DONE
    assert row.result == RequirementAssessment.Result.COMPLIANT
    assert row.observation == "Reviewed before the library metadata update"
    assert (row.score, row.is_scored) == (87, True)


@pytest.mark.django_db
def test_shipped_frameworks_and_mapping_load_into_the_runtime_engine():
    namespace = "essential-eight-loader-test"
    legacy = _renamespace(_read(LEGACY_PATH), namespace)
    current = _renamespace(_read(CURRENT_PATH), namespace)
    mapping = _renamespace(_read(MAPPING_PATH), namespace)

    legacy_stored = _store(legacy)
    current_stored = _store(current)
    mapping_stored = _store(mapping)
    assert mapping_stored.autoload is True
    assert legacy_stored.load() is None
    assert current_stored.load() is None
    assert mapping_stored.load() is None

    source_urn = legacy["objects"]["framework"]["urn"]
    target_urn = current["objects"]["framework"]["urn"]
    assert RequirementNode.objects.filter(framework__urn=source_urn).count() == 157
    assert RequirementNode.objects.filter(framework__urn=target_urn).count() == 160
    assert not RequirementMappingSet.objects.filter(
        urn=_mapping_set(mapping)["urn"]
    ).exists()

    engine = MappingEngine()
    assert (source_urn, target_urn) in engine.direct_mappings
    runtime_mapping = engine.get_rms((source_urn, target_urn))
    assert runtime_mapping is not None
    assert runtime_mapping["library_urn"] == mapping["urn"]
    assert runtime_mapping["urn"] == _mapping_set(mapping)["urn"]
    assert len(runtime_mapping["requirement_mappings"]) == 152
