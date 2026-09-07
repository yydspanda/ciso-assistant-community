"""End-to-end tests for the AppliedControl /merge/ action: direct M2M union,
reverse-M2M rewire, FK rewire, permission gating, dry-run preview,
ManagedDocument conflict detection + resolution, source-count cap, and
registry-drift guards."""

import pytest

from core.models import (
    Actor,
    AppliedControl,
    Asset,
    Comment,
    Evidence,
    Framework,
    Incident,
    RequirementAssessment,
    RequirementNode,
    RiskAssessment,
    RiskMatrix,
    RiskScenario,
)
from iam.models import Folder, RoleAssignment

MERGE_URL = "/api/applied-controls/merge/"


# --- helpers -----------------------------------------------------------------


def _make_control(folder, name, **kwargs):
    return AppliedControl.objects.create(name=name, folder=folder, **kwargs)


def _make_compliance_assessment(folder):
    """Create a minimal ComplianceAssessment + RequirementAssessment for rewire tests."""
    from core.models import ComplianceAssessment

    framework = Framework.objects.create(
        urn="urn:test:framework:merge", folder=folder, name="merge-test"
    )
    req = RequirementNode.objects.create(
        urn="urn:test:framework:merge:r1",
        folder=folder,
        framework=framework,
        assessable=True,
    )
    audit = ComplianceAssessment.objects.create(
        name="audit", folder=folder, framework=framework
    )
    ra = RequirementAssessment.objects.create(
        compliance_assessment=audit, requirement=req, folder=folder
    )
    return ra


def _make_risk_scenario(folder):
    matrix_lib_urn = "urn:intuitem:risk:library:critical_risk_matrix_3x3"
    matrix = RiskMatrix.objects.filter(
        urn__icontains="critical_risk_matrix_3x3"
    ).first() or RiskMatrix.objects.create(
        urn=matrix_lib_urn,
        folder=folder,
        name="3x3",
        json_definition={
            "type": "risk_matrix",
            "name": "3x3",
            "description": "",
            "probability": [
                {"abbreviation": "L", "name": "Low", "description": ""},
                {"abbreviation": "M", "name": "Medium", "description": ""},
                {"abbreviation": "H", "name": "High", "description": ""},
            ],
            "impact": [
                {"abbreviation": "L", "name": "Low", "description": ""},
                {"abbreviation": "M", "name": "Medium", "description": ""},
                {"abbreviation": "H", "name": "High", "description": ""},
            ],
            "risk": [
                {
                    "abbreviation": "VL",
                    "name": "Very Low",
                    "description": "",
                    "hexcolor": "#fff",
                },
                {
                    "abbreviation": "L",
                    "name": "Low",
                    "description": "",
                    "hexcolor": "#fff",
                },
                {
                    "abbreviation": "H",
                    "name": "High",
                    "description": "",
                    "hexcolor": "#fff",
                },
            ],
            "grid": [[0, 1, 2], [0, 1, 2], [0, 1, 2]],
        },
    )
    risk_assessment = RiskAssessment.objects.create(
        name="ra", folder=folder, risk_matrix=matrix
    )
    return RiskScenario.objects.create(
        name="scn", folder=folder, risk_assessment=risk_assessment
    )


@pytest.fixture
def folder(db):
    return Folder.objects.create(name="merge-test-folder")


@pytest.fixture
def other_folder(db):
    return Folder.objects.create(name="merge-test-folder-2")


# --- core rewire contract ---------------------------------------------------


@pytest.mark.django_db
def test_merge_target_new_unions_m2ms_and_rewires_reverse_relations(
    authenticated_client, folder
):
    """target=new: direct M2Ms unioned, reverse M2M (RA) rewired, sources deleted."""
    asset_a = Asset.objects.create(name="asset-a", folder=folder)
    asset_b = Asset.objects.create(name="asset-b", folder=folder)
    evidence = Evidence.objects.create(name="ev", folder=folder)

    src1 = _make_control(folder, "src-1")
    src1.assets.add(asset_a)
    src1.evidences.add(evidence)
    src2 = _make_control(folder, "src-2")
    src2.assets.add(asset_b)

    ra = _make_compliance_assessment(folder)
    ra.applied_controls.add(src1)

    payload = {
        "source_ids": [str(src1.id), str(src2.id)],
        "target": {
            "type": "new",
            "fields": {"name": "merged", "folder": str(folder.id)},
        },
    }
    resp = authenticated_client.post(MERGE_URL, payload, format="json")

    assert resp.status_code == 200, resp.json()
    body = resp.json()
    target = AppliedControl.objects.get(id=body["target_id"])
    assert target.name == "merged"
    assert set(target.assets.values_list("id", flat=True)) == {asset_a.id, asset_b.id}
    assert set(target.evidences.values_list("id", flat=True)) == {evidence.id}
    assert ra.applied_controls.filter(id=target.id).exists()
    assert not AppliedControl.objects.filter(id__in=[src1.id, src2.id]).exists()
    assert body["rewired"]["RequirementAssessment"] == 1
    assert body["target_is_new"] is True


@pytest.mark.django_db
def test_merge_target_existing_survivor(authenticated_client, folder):
    """target=existing where target is one of the originally-selected rows."""
    survivor = _make_control(folder, "keep-me")
    src = _make_control(folder, "absorb-me")
    asset = Asset.objects.create(name="x", folder=folder)
    src.assets.add(asset)

    payload = {
        # serializer strips the target id from source_ids → survivor merge
        "source_ids": [str(survivor.id), str(src.id)],
        "target": {"type": "existing", "id": str(survivor.id)},
    }
    resp = authenticated_client.post(MERGE_URL, payload, format="json")

    assert resp.status_code == 200, resp.json()
    survivor.refresh_from_db()
    assert survivor.name == "keep-me"  # scalars untouched on existing target
    assert set(survivor.assets.values_list("id", flat=True)) == {asset.id}
    assert not AppliedControl.objects.filter(id=src.id).exists()


@pytest.mark.django_db
def test_replace_a_with_b_single_source(authenticated_client, folder):
    """Replace flow: one source, target = unrelated existing control."""
    src = _make_control(folder, "old")
    target = _make_control(folder, "new")
    Comment.objects.create(applied_control=src, body="hi", author_id=None)

    payload = {
        "source_ids": [str(src.id)],
        "target": {"type": "existing", "id": str(target.id)},
    }
    resp = authenticated_client.post(MERGE_URL, payload, format="json")

    assert resp.status_code == 200, resp.json()
    assert not AppliedControl.objects.filter(id=src.id).exists()
    assert Comment.objects.filter(applied_control=target).count() == 1


@pytest.mark.django_db
def test_through_table_dedup(authenticated_client, folder):
    """When the same RA already references both source and target, no duplicate after merge."""
    src = _make_control(folder, "src")
    target = _make_control(folder, "tgt")
    ra = _make_compliance_assessment(folder)
    ra.applied_controls.add(src, target)
    assert ra.applied_controls.count() == 2

    payload = {
        "source_ids": [str(src.id)],
        "target": {"type": "existing", "id": str(target.id)},
    }
    resp = authenticated_client.post(MERGE_URL, payload, format="json")
    assert resp.status_code == 200, resp.json()
    assert ra.applied_controls.count() == 1
    assert ra.applied_controls.first().id == target.id


@pytest.mark.django_db
def test_risk_scenario_existing_vs_added_are_independent(authenticated_client, folder):
    """RiskScenario has TWO M2Ms to AppliedControl (applied_controls + existing_applied_controls).
    Both should be rewired but kept separate."""
    scn = _make_risk_scenario(folder)
    src = _make_control(folder, "src")
    target = _make_control(folder, "tgt")
    scn.applied_controls.add(src)
    scn.existing_applied_controls.add(src)

    payload = {
        "source_ids": [str(src.id)],
        "target": {"type": "existing", "id": str(target.id)},
    }
    resp = authenticated_client.post(MERGE_URL, payload, format="json")
    assert resp.status_code == 200, resp.json()
    assert scn.applied_controls.filter(id=target.id).exists()
    assert scn.existing_applied_controls.filter(id=target.id).exists()


# --- guards -----------------------------------------------------------------


@pytest.mark.django_db
def test_too_many_sources_rejected(authenticated_client, folder):
    target = _make_control(folder, "tgt")
    sources = [_make_control(folder, f"s{i}") for i in range(21)]
    payload = {
        "source_ids": [str(s.id) for s in sources],
        "target": {"type": "existing", "id": str(target.id)},
    }
    resp = authenticated_client.post(MERGE_URL, payload, format="json")
    assert resp.status_code == 400
    # All 21 sources still present
    assert AppliedControl.objects.filter(id__in=[s.id for s in sources]).count() == 21


@pytest.mark.django_db
def test_dry_run_does_not_modify_state(authenticated_client, folder):
    src = _make_control(folder, "src")
    target = _make_control(folder, "tgt")
    asset = Asset.objects.create(name="a", folder=folder)
    src.assets.add(asset)

    payload = {
        "source_ids": [str(src.id)],
        "target": {"type": "existing", "id": str(target.id)},
        "dry_run": True,
    }
    resp = authenticated_client.post(MERGE_URL, payload, format="json")
    assert resp.status_code == 200, resp.json()
    body = resp.json()
    assert "rewired_preview" in body
    assert "unioned_m2m_preview" in body
    # State unchanged
    assert AppliedControl.objects.filter(id=src.id).exists()
    assert not target.assets.filter(id=asset.id).exists()


@pytest.mark.django_db
def test_folder_mismatch_flag(authenticated_client, folder, other_folder):
    src = _make_control(folder, "src")
    target = _make_control(other_folder, "tgt")
    payload = {
        "source_ids": [str(src.id)],
        "target": {"type": "existing", "id": str(target.id)},
        "dry_run": True,
    }
    resp = authenticated_client.post(MERGE_URL, payload, format="json")
    assert resp.status_code == 200, resp.json()
    assert resp.json()["folder_mismatch"] is True


@pytest.mark.django_db
@pytest.mark.parametrize(
    ("merge_url", "policy_source"),
    ((MERGE_URL, False), ("/api/policies/merge/", True)),
)
@pytest.mark.parametrize("dry_run", (False, True))
def test_merge_never_rewires_audit_rows_without_full_audit_scope(
    authenticated_client,
    folder,
    monkeypatch,
    merge_url,
    policy_source,
    dry_run,
):
    source = (
        _make_policy(folder, "scoped-source")
        if policy_source
        else _make_control(folder, "scoped-source")
    )
    target = (
        _make_policy(folder, "scoped-target")
        if policy_source
        else _make_control(folder, "scoped-target")
    )
    ra = _make_compliance_assessment(folder)
    ra.applied_controls.add(source)
    monkeypatch.setattr(
        "core.assignment_access.has_full_view_compliance_assessment",
        lambda _user, _assessment: False,
    )

    response = authenticated_client.post(
        merge_url,
        {
            "source_ids": [str(source.id)],
            "target": {"type": "existing", "id": str(target.id)},
            "dry_run": dry_run,
        },
        format="json",
    )

    assert response.status_code == 403, response.content
    assert AppliedControl.objects.filter(id=source.id).exists()
    assert set(ra.applied_controls.values_list("id", flat=True)) == {source.id}


@pytest.mark.django_db
def test_merge_guards_existing_target_and_new_target_audit_links(
    authenticated_client, folder, monkeypatch
):
    source = _make_control(folder, "unlinked-source")
    target = _make_control(folder, "linked-target")
    ra = _make_compliance_assessment(folder)
    ra.applied_controls.add(target)
    monkeypatch.setattr(
        "core.assignment_access.has_full_view_compliance_assessment",
        lambda _user, _assessment: False,
    )

    existing_response = authenticated_client.post(
        MERGE_URL,
        {
            "source_ids": [str(source.id)],
            "target": {"type": "existing", "id": str(target.id)},
        },
        format="json",
    )
    new_response = authenticated_client.post(
        MERGE_URL,
        {
            "source_ids": [str(source.id)],
            "target": {
                "type": "new",
                "fields": {
                    "name": "forbidden-new-target",
                    "folder": str(folder.id),
                    "requirement_assessments": [str(ra.id)],
                },
            },
        },
        format="json",
    )

    assert existing_response.status_code == 403, existing_response.content
    assert new_response.status_code == 403, new_response.content
    assert AppliedControl.objects.filter(id=source.id).exists()
    assert set(ra.applied_controls.values_list("id", flat=True)) == {target.id}


@pytest.mark.django_db
def test_merge_rejects_links_owned_by_a_locked_audit(authenticated_client, folder):
    source = _make_control(folder, "locked-source")
    target = _make_control(folder, "locked-target")
    ra = _make_compliance_assessment(folder)
    ra.applied_controls.add(source)
    ra.compliance_assessment.is_locked = True
    ra.compliance_assessment.save(update_fields=["is_locked"])

    response = authenticated_client.post(
        MERGE_URL,
        {
            "source_ids": [str(source.id)],
            "target": {"type": "existing", "id": str(target.id)},
        },
        format="json",
    )

    assert response.status_code == 403, response.content
    assert AppliedControl.objects.filter(id=source.id).exists()
    assert set(ra.applied_controls.values_list("id", flat=True)) == {source.id}


@pytest.mark.django_db
@pytest.mark.parametrize("dry_run", (False, True))
def test_merge_rejects_hidden_direct_relations_without_preview_counts(
    authenticated_client, folder, monkeypatch, dry_run
):
    source = _make_control(folder, "hidden-evidence-source")
    target = _make_control(folder, "hidden-evidence-target")
    evidence = Evidence.objects.create(name="hidden-evidence", folder=folder)
    source.evidences.add(evidence)
    original = RoleAssignment.get_viewable_object_ids

    def hide_evidence(user, model, folder=None):
        if model is Evidence:
            return Evidence.objects.none().values_list("id", flat=True)
        return original(user, model, folder)

    monkeypatch.setattr(
        RoleAssignment,
        "get_viewable_object_ids",
        staticmethod(hide_evidence),
    )

    response = authenticated_client.post(
        MERGE_URL,
        {
            "source_ids": [str(source.id)],
            "target": {"type": "existing", "id": str(target.id)},
            "dry_run": dry_run,
        },
        format="json",
    )

    assert response.status_code == 403, response.content
    assert b"unioned_m2m_preview" not in response.content
    assert AppliedControl.objects.filter(id=source.id).exists()
    assert set(source.evidences.values_list("id", flat=True)) == {evidence.id}
    assert not target.evidences.exists()


@pytest.mark.django_db
def test_merge_keeps_independently_visible_owner_identity_across_home_folder(
    authenticated_client, folder
):
    from iam.models import User

    user = User.objects.get(email="admin@tests.com")
    actor, _ = Actor.objects.get_or_create(user=user)
    assert actor.specific.folder_id != folder.id
    source = _make_control(folder, "visible-owner-source")
    target = _make_control(folder, "visible-owner-target")
    source.owner.add(actor)

    response = authenticated_client.post(
        MERGE_URL,
        {
            "source_ids": [str(source.id)],
            "target": {"type": "existing", "id": str(target.id)},
        },
        format="json",
    )

    assert response.status_code == 200, response.content
    assert set(target.owner.values_list("id", flat=True)) == {actor.id}


@pytest.mark.django_db
@pytest.mark.parametrize("dry_run", (False, True))
def test_merge_rejects_hidden_reverse_parent_without_preview_counts(
    authenticated_client, folder, monkeypatch, dry_run
):
    scenario = _make_risk_scenario(folder)
    source = _make_control(folder, "hidden-parent-source")
    target = _make_control(folder, "hidden-parent-target")
    scenario.applied_controls.add(source)
    original = RoleAssignment.get_viewable_object_ids

    def hide_scenario(user, model, folder=None):
        if model is RiskScenario:
            return RiskScenario.objects.none().values_list("id", flat=True)
        return original(user, model, folder)

    monkeypatch.setattr(
        RoleAssignment,
        "get_viewable_object_ids",
        staticmethod(hide_scenario),
    )

    response = authenticated_client.post(
        MERGE_URL,
        {
            "source_ids": [str(source.id)],
            "target": {"type": "existing", "id": str(target.id)},
            "dry_run": dry_run,
        },
        format="json",
    )

    assert response.status_code == 403, response.content
    assert b"rewired_preview" not in response.content
    assert AppliedControl.objects.filter(id=source.id).exists()
    assert set(scenario.applied_controls.values_list("id", flat=True)) == {source.id}


@pytest.mark.django_db
def test_merge_requires_change_authority_on_reverse_parent(
    authenticated_client, folder, monkeypatch
):
    scenario = _make_risk_scenario(folder)
    source = _make_control(folder, "no-parent-change-source")
    target = _make_control(folder, "no-parent-change-target")
    scenario.applied_controls.add(source)
    _patch_perm_denial(monkeypatch, "change_riskscenario")

    response = authenticated_client.post(
        MERGE_URL,
        {
            "source_ids": [str(source.id)],
            "target": {"type": "existing", "id": str(target.id)},
        },
        format="json",
    )

    assert response.status_code == 403, response.content
    assert AppliedControl.objects.filter(id=source.id).exists()
    assert set(scenario.applied_controls.values_list("id", flat=True)) == {source.id}


@pytest.mark.django_db
def test_merge_rejects_locked_reverse_parent_owner(authenticated_client, folder):
    scenario = _make_risk_scenario(folder)
    scenario.risk_assessment.is_locked = True
    scenario.risk_assessment.save(update_fields=["is_locked"])
    source = _make_control(folder, "locked-parent-source")
    target = _make_control(folder, "locked-parent-target")
    scenario.existing_applied_controls.add(source)

    response = authenticated_client.post(
        MERGE_URL,
        {
            "source_ids": [str(source.id)],
            "target": {"type": "existing", "id": str(target.id)},
        },
        format="json",
    )

    assert response.status_code == 403, response.content
    assert AppliedControl.objects.filter(id=source.id).exists()
    assert set(scenario.existing_applied_controls.values_list("id", flat=True)) == {
        source.id
    }


@pytest.mark.django_db
def test_merge_rejects_cross_folder_document_parent(
    authenticated_client, folder, other_folder
):
    from doc_management.models import DocumentContainer

    source = _make_control(folder, "document-drift-source")
    target = _make_control(folder, "document-drift-target")
    document = DocumentContainer.objects.create(
        name="wrong-owner-document", folder=other_folder
    )
    document.applied_controls.add(source)

    response = authenticated_client.post(
        MERGE_URL,
        {
            "source_ids": [str(source.id)],
            "target": {"type": "existing", "id": str(target.id)},
        },
        format="json",
    )

    assert response.status_code == 403, response.content
    assert AppliedControl.objects.filter(id=source.id).exists()
    assert set(document.applied_controls.values_list("id", flat=True)) == {source.id}


@pytest.mark.django_db
def test_merge_rejects_relation_added_during_lock_acquisition(
    authenticated_client, folder, monkeypatch
):
    from core import applied_controls_helper

    source = _make_control(folder, "late-relation-source")
    target = _make_control(folder, "late-relation-target")
    evidence = Evidence.objects.create(name="late-evidence", folder=folder)
    original = applied_controls_helper.lock_rows_in_global_model_order
    injected = False

    def inject_after_candidate_locks(target_ids_by_model):
        nonlocal injected
        locked = original(target_ids_by_model)
        if not injected:
            injected = True
            source.evidences.add(evidence)
        return locked

    monkeypatch.setattr(
        applied_controls_helper,
        "lock_rows_in_global_model_order",
        inject_after_candidate_locks,
    )

    response = authenticated_client.post(
        MERGE_URL,
        {
            "source_ids": [str(source.id)],
            "target": {"type": "existing", "id": str(target.id)},
        },
        format="json",
    )

    assert response.status_code == 403, response.content
    assert AppliedControl.objects.filter(id=source.id).exists()
    # The injected relation belongs to the request transaction and rolls back.
    assert not source.evidences.exists()
    assert not target.evidences.exists()


@pytest.mark.django_db
def test_merge_rejects_requirement_link_reparented_with_same_ra_id(
    authenticated_client, folder, monkeypatch
):
    from core import applied_controls_helper

    source = _make_control(folder, "ra-race-source")
    target = _make_control(folder, "ra-race-target")
    requirement_assessment = _make_compliance_assessment(folder)
    requirement_assessment.applied_controls.add(source)
    original = applied_controls_helper.lock_rows_in_global_model_order
    moved = False

    def move_same_ra_after_candidate_locks(target_ids_by_model):
        nonlocal moved
        locked = original(target_ids_by_model)
        if not moved:
            moved = True
            requirement_assessment.applied_controls.remove(source)
            requirement_assessment.applied_controls.add(target)
        return locked

    monkeypatch.setattr(
        applied_controls_helper,
        "lock_rows_in_global_model_order",
        move_same_ra_after_candidate_locks,
    )

    response = authenticated_client.post(
        MERGE_URL,
        {
            "source_ids": [str(source.id)],
            "target": {"type": "existing", "id": str(target.id)},
        },
        format="json",
    )

    assert response.status_code == 403, response.content
    assert AppliedControl.objects.filter(id=source.id).exists()
    assert set(
        requirement_assessment.applied_controls.values_list("id", flat=True)
    ) == {source.id}


@pytest.mark.django_db
def test_merge_reproves_source_visibility_after_control_lock(
    authenticated_client, folder, monkeypatch
):
    from core import applied_controls_helper
    from core.views import AppliedControlViewSet

    source = _make_control(folder, "visibility-race-source")
    target = _make_control(folder, "visibility-race-target")
    original_get_queryset = AppliedControlViewSet.get_queryset
    original_lock = applied_controls_helper.lock_rows_in_global_model_order
    changed = False

    def published_queryset(view):
        return original_get_queryset(view).filter(is_published=True)

    def hide_after_candidate_locks(target_ids_by_model):
        nonlocal changed
        locked = original_lock(target_ids_by_model)
        if not changed:
            changed = True
            AppliedControl.objects.filter(id=source.id).update(is_published=False)
        return locked

    monkeypatch.setattr(AppliedControlViewSet, "get_queryset", published_queryset)
    monkeypatch.setattr(
        applied_controls_helper,
        "lock_rows_in_global_model_order",
        hide_after_candidate_locks,
    )

    response = authenticated_client.post(
        MERGE_URL,
        {
            "source_ids": [str(source.id)],
            "target": {"type": "existing", "id": str(target.id)},
        },
        format="json",
    )

    assert response.status_code == 403, response.content
    source.refresh_from_db()
    assert source.is_published is True
    assert AppliedControl.objects.filter(id=target.id).exists()


@pytest.mark.django_db
def test_merge_cannot_rewrite_submitted_validation_payload(
    authenticated_client, folder
):
    from core.models import ValidationFlow
    from iam.models import User

    requester = User.objects.get(email="admin@tests.com")
    source = _make_policy(folder, "submitted-policy-source")
    target = _make_policy(folder, "submitted-policy-target")
    flow = ValidationFlow.objects.create(
        folder=folder,
        requester=requester,
        status=ValidationFlow.Status.SUBMITTED,
    )
    flow.policies.add(source)

    response = authenticated_client.post(
        POLICY_MERGE_URL,
        {
            "source_ids": [str(source.id)],
            "target": {"type": "existing", "id": str(target.id)},
        },
        format="json",
    )

    assert response.status_code == 403, response.content
    assert AppliedControl.objects.filter(id=source.id).exists()
    assert set(flow.policies.values_list("id", flat=True)) == {source.id}


@pytest.mark.django_db
def test_merge_new_target_authorizes_requested_reverse_parents_before_create(
    authenticated_client, folder, monkeypatch
):
    source = _make_control(folder, "requested-parent-source")
    incident = Incident.objects.create(name="requested-incident", folder=folder)
    before = AppliedControl.objects.count()
    _patch_perm_denial(monkeypatch, "change_incident")

    response = authenticated_client.post(
        MERGE_URL,
        {
            "source_ids": [str(source.id)],
            "target": {
                "type": "new",
                "fields": {
                    "name": "forbidden-created-target",
                    "folder": str(folder.id),
                    "incidents": [str(incident.id)],
                },
            },
        },
        format="json",
    )

    assert response.status_code == 403, response.content
    assert AppliedControl.objects.count() == before
    assert AppliedControl.objects.filter(id=source.id).exists()
    assert not incident.applied_controls.exists()


@pytest.mark.django_db
def test_merge_rejects_mapping_whose_provider_is_inactive(authenticated_client, folder):
    from django.contrib.contenttypes.models import ContentType

    from integrations.models import (
        IntegrationConfiguration,
        IntegrationProvider,
        SyncMapping,
    )

    source = _make_control(folder, "inactive-provider-source")
    target = _make_control(folder, "inactive-provider-target")
    provider = IntegrationProvider.objects.create(
        name="inactive-provider",
        provider_type=IntegrationProvider.ProviderType.ITSM,
        is_active=False,
        folder=Folder.get_root_folder(),
    )
    configuration = IntegrationConfiguration.objects.create(
        provider=provider,
        folder=folder,
        webhook_secret="not-a-real-secret",
        webhook_url="",
        is_active=True,
    )
    mapping = SyncMapping.objects.create(
        configuration=configuration,
        content_type=ContentType.objects.get_for_model(AppliedControl),
        local_object_id=source.id,
        remote_id="INACTIVE-PROVIDER",
        folder=folder,
    )

    response = authenticated_client.post(
        MERGE_URL,
        {
            "source_ids": [str(source.id)],
            "target": {"type": "existing", "id": str(target.id)},
        },
        format="json",
    )

    assert response.status_code == 403, response.content
    assert AppliedControl.objects.filter(id=source.id).exists()
    mapping.refresh_from_db()
    assert mapping.local_object_id == source.id


# --- managed-document conflict ----------------------------------------------


def _make_policy(folder, name):
    from core.models import Policy

    return Policy.objects.create(name=name, folder=folder)


def _make_container(folder, name, *policies):
    """A document container linked (policies M2M) to the given policies."""
    from doc_management.models import DocumentContainer

    c = DocumentContainer.objects.create(name=name, folder=folder)
    for p in policies:
        c.policies.add(p)
    return c


@pytest.mark.django_db
def test_policy_documents_union_onto_target(authenticated_client, folder):
    """Document links are associative: merging two policies that each have a
    document container leaves the target linked to BOTH (union, no conflict)."""
    src1 = _make_policy(folder, "p1")
    src2 = _make_policy(folder, "p2")
    target = _make_policy(folder, "tgt")
    c1 = _make_container(folder, "doc1", src1)
    c2 = _make_container(folder, "doc2", src2)

    payload = {
        "source_ids": [str(src1.id), str(src2.id)],
        "target": {"type": "existing", "id": str(target.id)},
    }
    resp = authenticated_client.post(MERGE_URL, payload, format="json")
    assert resp.status_code == 200, resp.json()
    assert target.id in set(c1.policies.values_list("id", flat=True))
    assert target.id in set(c2.policies.values_list("id", flat=True))
    assert not AppliedControl.objects.filter(id__in=[src1.id, src2.id]).exists()


@pytest.mark.django_db
def test_single_policy_document_repoints_onto_target(authenticated_client, folder):
    src = _make_policy(folder, "src")
    target = _make_policy(folder, "tgt")
    c = _make_container(folder, "d", src)

    payload = {
        "source_ids": [str(src.id)],
        "target": {"type": "existing", "id": str(target.id)},
    }
    resp = authenticated_client.post(MERGE_URL, payload, format="json")
    assert resp.status_code == 200, resp.json()
    policy_ids = set(c.policies.values_list("id", flat=True))
    assert target.id in policy_ids
    assert src.id not in policy_ids


# --- policy proxy path ------------------------------------------------------


POLICY_MERGE_URL = "/api/policies/merge/"


@pytest.mark.django_db
def test_policy_merge_target_new_keeps_category_policy(authenticated_client, folder):
    """Merging policies via /policies/merge/ with target=new must produce a row
    classified as a policy so it still appears in the Policies list view."""
    from core.models import Policy

    src1 = Policy.objects.create(name="pol-1", folder=folder)
    src2 = Policy.objects.create(name="pol-2", folder=folder)

    payload = {
        "source_ids": [str(src1.id), str(src2.id)],
        "target": {
            "type": "new",
            "fields": {"name": "merged-policy", "folder": str(folder.id)},
        },
    }
    resp = authenticated_client.post(POLICY_MERGE_URL, payload, format="json")

    assert resp.status_code == 200, resp.json()
    target_id = resp.json()["target_id"]
    # The merged row must be visible through the Policy proxy (category='policy').
    assert Policy.objects.filter(id=target_id).exists()
    assert AppliedControl.objects.get(id=target_id).category == "policy"
    assert not AppliedControl.objects.filter(id__in=[src1.id, src2.id]).exists()


@pytest.mark.django_db
def test_policy_merge_target_new_overrides_caller_category(
    authenticated_client, folder
):
    """Even if the caller passes a non-policy category on /policies/merge/,
    the endpoint must force category='policy' so the result stays visible in
    the Policies list."""
    from core.models import Policy

    src = Policy.objects.create(name="pol-a", folder=folder)

    payload = {
        "source_ids": [str(src.id)],
        "target": {
            "type": "new",
            "fields": {
                "name": "still-policy",
                "folder": str(folder.id),
                # Caller tries to sneak in a different category.
                "category": "technical",
            },
        },
    }
    resp = authenticated_client.post(POLICY_MERGE_URL, payload, format="json")
    assert resp.status_code == 200, resp.json()
    target_id = resp.json()["target_id"]
    assert Policy.objects.filter(id=target_id).exists()
    assert AppliedControl.objects.get(id=target_id).category == "policy"


# --- permission denial paths ------------------------------------------------


def _patch_perm_denial(monkeypatch, denied_codename: str):
    """Make RoleAssignment.is_access_allowed return False for the given
    permission codename, True otherwise. Used to simulate a user who can see
    the rows but lacks specific change/delete/add rights."""
    from iam.models import RoleAssignment

    def fake(user, perm, folder, **kwargs):
        return perm.codename != denied_codename

    monkeypatch.setattr(RoleAssignment, "is_access_allowed", staticmethod(fake))


@pytest.mark.django_db
def test_merge_denied_when_user_lacks_change_on_source_folder(
    authenticated_client, folder, monkeypatch
):
    src = _make_control(folder, "src")
    target = _make_control(folder, "tgt")
    _patch_perm_denial(monkeypatch, "change_appliedcontrol")

    payload = {
        "source_ids": [str(src.id)],
        "target": {"type": "existing", "id": str(target.id)},
    }
    resp = authenticated_client.post(MERGE_URL, payload, format="json")
    assert resp.status_code == 403, resp.content
    # No mutation — both controls still present
    assert AppliedControl.objects.filter(id__in=[src.id, target.id]).count() == 2


@pytest.mark.django_db
def test_merge_denied_when_user_lacks_delete_on_source_folder(
    authenticated_client, folder, monkeypatch
):
    src = _make_control(folder, "src")
    target = _make_control(folder, "tgt")
    _patch_perm_denial(monkeypatch, "delete_appliedcontrol")

    payload = {
        "source_ids": [str(src.id)],
        "target": {"type": "existing", "id": str(target.id)},
    }
    resp = authenticated_client.post(MERGE_URL, payload, format="json")
    assert resp.status_code == 403, resp.content
    assert AppliedControl.objects.filter(id__in=[src.id, target.id]).count() == 2


@pytest.mark.django_db
def test_merge_new_target_denied_when_user_lacks_add_on_target_folder(
    authenticated_client, folder, monkeypatch
):
    """target=new must refuse if the user can't create AppliedControls in the
    target folder, and the new row must not be persisted."""
    src = _make_control(folder, "src")
    before_count = AppliedControl.objects.count()
    _patch_perm_denial(monkeypatch, "add_appliedcontrol")

    payload = {
        "source_ids": [str(src.id)],
        "target": {
            "type": "new",
            "fields": {"name": "would-be-target", "folder": str(folder.id)},
        },
    }
    resp = authenticated_client.post(MERGE_URL, payload, format="json")
    assert resp.status_code == 403, resp.content
    # Source untouched, no orphan target created (the security-refactor guarantee).
    assert AppliedControl.objects.filter(id=src.id).exists()
    assert AppliedControl.objects.count() == before_count


# --- rewire-registry drift guards -------------------------------------------


@pytest.mark.django_db
def test_reverse_m2m_registry_covers_all_introspected_relations():
    """Every reverse M2M on AppliedControl must be registered in
    _reverse_m2m_through_tables(), else it will silently orphan through-rows."""
    from core.applied_controls_helper import (
        _expected_reverse_m2m_throughs,
        _registered_reverse_m2m_throughs,
    )

    missing = _expected_reverse_m2m_throughs() - _registered_reverse_m2m_throughs()
    assert not missing, (
        f"Reverse M2M(s) on AppliedControl not registered for merge rewire: "
        f"{[m.__name__ for m in missing]}"
    )


@pytest.mark.django_db
def test_direct_m2m_fields_covers_all_declared_fields():
    """Every M2M declared on AppliedControl must be listed in DIRECT_M2M_FIELDS
    so the target inherits those relations during merge."""
    from core.applied_controls_helper import (
        DIRECT_M2M_FIELDS,
        _expected_direct_m2m_fields,
    )

    missing = _expected_direct_m2m_fields() - set(DIRECT_M2M_FIELDS)
    assert not missing, (
        f"Direct M2M field(s) on AppliedControl not in DIRECT_M2M_FIELDS: {missing}"
    )
