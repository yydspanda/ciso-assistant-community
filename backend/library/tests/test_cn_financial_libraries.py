from collections import Counter
from pathlib import Path

import pytest

from core.models import (
    Framework,
    LoadedLibrary,
    ReferenceControl,
    RequirementNode,
    StoredLibrary,
)


LIBRARIES_DIR = Path(__file__).resolve().parents[1] / "libraries"
COMMON_CONTROLS_URN = "urn:yydspanda:risk:library:cn-financial-common-controls"
BASELINE_URN = "urn:yydspanda:risk:library:cn-financial-baseline"
FRAMEWORK_URN = "urn:yydspanda:risk:framework:cn-financial-baseline"


def _get_or_store_builtin(filename: str, urn: str) -> StoredLibrary:
    """Reuse libraries populated by the test startup hook, or store explicitly."""

    if stored := StoredLibrary.objects.filter(urn=urn).first():
        return stored

    stored, error = StoredLibrary.store_library_file(
        LIBRARIES_DIR / filename, builtin=True
    )
    assert error is None
    assert stored is not None
    return stored


@pytest.mark.django_db
def test_cn_financial_baseline_loads_dependency_and_control_references():
    common_controls = _get_or_store_builtin(
        "cn-financial-common-controls.yaml", COMMON_CONTROLS_URN
    )
    baseline = _get_or_store_builtin("cn-financial-baseline.yaml", BASELINE_URN)

    assert common_controls.builtin is True
    assert baseline.builtin is True

    # Loading only the baseline must resolve and load the common-control library.
    assert baseline.load() is None

    loaded_common = LoadedLibrary.objects.get(urn=COMMON_CONTROLS_URN)
    loaded_baseline = LoadedLibrary.objects.get(urn=BASELINE_URN)
    assert loaded_baseline.dependencies.filter(pk=loaded_common.pk).exists()

    controls = list(
        ReferenceControl.objects.filter(library__urn=COMMON_CONTROLS_URN).order_by(
            "urn"
        )
    )
    assert len(controls) == 18
    assert all(
        isinstance(control.typical_evidence, list)
        and control.typical_evidence
        and all(
            isinstance(evidence, str) and evidence.strip()
            for evidence in control.typical_evidence
        )
        for control in controls
    )

    framework = Framework.objects.get(urn=FRAMEWORK_URN)
    nodes = list(
        RequirementNode.objects.filter(framework=framework)
        .prefetch_related("reference_controls")
        .order_by("urn")
    )
    assessable_nodes = [node for node in nodes if node.assessable]
    headings = [node for node in nodes if not node.assessable]

    assert len(nodes) == 26
    assert len(assessable_nodes) == 18
    assert len(headings) == 8

    group_definitions = framework.implementation_groups_definition
    assert isinstance(group_definitions, list)
    group_ids = {group["ref_id"] for group in group_definitions}
    assert group_ids == {"COMMON", "BANK", "INSURANCE", "FINTECH"}
    assert (
        next(group for group in group_definitions if group["ref_id"] == "COMMON")[
            "default_selected"
        ]
        is True
    )

    heading_urns = {heading.urn for heading in headings}
    assert all(heading.parent_urn is None for heading in headings)
    assert all(
        any(node.parent_urn == heading.urn for node in assessable_nodes)
        for heading in headings
    )
    assert all(node.parent_urn in heading_urns for node in assessable_nodes)
    assert all(
        isinstance(node.typical_evidence, str) and node.typical_evidence.strip()
        for node in assessable_nodes
    )
    assert all(
        isinstance(node.implementation_groups, list)
        and node.implementation_groups
        and set(node.implementation_groups) <= group_ids
        for node in assessable_nodes
    )
    assert Counter(
        group for node in assessable_nodes for group in node.implementation_groups
    ) == Counter({"COMMON": 16, "BANK": 18, "INSURANCE": 18, "FINTECH": 18})

    referenced_control_urns = [
        control.urn
        for node in assessable_nodes
        for control in node.reference_controls.all()
    ]
    control_urns = {control.urn for control in controls}
    assert Counter(referenced_control_urns) == Counter(
        {control_urn: 1 for control_urn in control_urns}
    )
    assert all(
        control.library.urn == COMMON_CONTROLS_URN
        for node in assessable_nodes
        for control in node.reference_controls.all()
    )
