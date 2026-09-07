import uuid
from unittest.mock import patch

import pytest
from rest_framework import status

from core.compliance_deletion import (
    assert_compliance_assessment_deletion_manifest,
)
from core.deletion_authority import GOVERNED_FOLDER_DELETION_ROOTS
from core.models import (
    Asset,
    Campaign,
    ComplianceAssessment,
    Framework,
    Perimeter,
    RequirementAssignment,
    RequirementAssignmentMailEvidence,
    RequirementAssignmentMailOutbox,
    TaskTemplate,
    Terminology,
    ValidationFlow,
)
from iam.models import Folder
from pmbok.models import Accreditation, GenericCollection
from portals.models import FrameworkSnapshot
from tprm.models import Entity, EntityAssessment


def _folder(name: str, parent: Folder, *, content_type=Folder.ContentType.DOMAIN):
    return Folder.objects.create(
        name=f"{name}-{uuid.uuid4().hex[:8]}",
        parent_folder=parent,
        content_type=content_type,
    )


def _audit(folder: Folder) -> ComplianceAssessment:
    framework = Framework.objects.create(
        name=f"governed-delete-framework-{uuid.uuid4().hex[:8]}",
        folder=folder,
        min_score=0,
        max_score=100,
    )
    return ComplianceAssessment.objects.create(
        name=f"governed-delete-audit-{uuid.uuid4().hex[:8]}",
        folder=folder,
        framework=framework,
    )


@pytest.mark.django_db
def test_generic_folder_detail_move_rejects_enclave_and_containing_ancestor(
    authenticated_client,
):
    root = Folder.get_root_folder()
    destination = _folder("destination", root)
    ancestor = _folder("audit-owner", root)
    enclave = _folder(
        "tprm-enclave",
        ancestor,
        content_type=Folder.ContentType.ENCLAVE,
    )

    for target in (enclave, ancestor):
        response = authenticated_client.patch(
            f"/api/folders/{target.id}/",
            {"parent_folder": str(destination.id)},
            format="json",
        )
        assert response.status_code == status.HTTP_403_FORBIDDEN, response.content

    enclave.refresh_from_db()
    ancestor.refresh_from_db()
    assert enclave.parent_folder_id == ancestor.id
    assert ancestor.parent_folder_id == root.id


@pytest.mark.django_db
def test_generic_folder_detail_and_batch_delete_reject_reserved_subtrees(
    authenticated_client,
):
    root = Folder.get_root_folder()
    ancestor = _folder("audit-owner", root)
    enclave = _folder(
        "tprm-enclave",
        ancestor,
        content_type=Folder.ContentType.ENCLAVE,
    )

    detail_response = authenticated_client.delete(f"/api/folders/{enclave.id}/")
    assert detail_response.status_code == status.HTTP_403_FORBIDDEN

    batch_response = authenticated_client.post(
        "/api/folders/batch-action/",
        {"action": "delete", "ids": [str(ancestor.id)]},
        format="json",
    )
    assert batch_response.status_code == status.HTTP_200_OK, batch_response.content
    assert batch_response.json()["succeeded"] == []
    assert [row["id"] for row in batch_response.json()["failed"]] == [str(ancestor.id)]
    assert Folder.objects.filter(id=ancestor.id).exists()
    assert Folder.objects.filter(id=enclave.id).exists()


@pytest.mark.django_db
def test_generic_folder_batch_move_rejects_ancestor_but_allows_plain_folder(
    authenticated_client,
):
    root = Folder.get_root_folder()
    destination = _folder("destination", root)
    ancestor = _folder("audit-owner", root)
    enclave = _folder(
        "tprm-enclave",
        ancestor,
        content_type=Folder.ContentType.ENCLAVE,
    )
    plain = _folder("plain", root)

    blocked = authenticated_client.post(
        "/api/folders/batch-action/",
        {
            "action": "change_field",
            "ids": [str(ancestor.id)],
            "field": "parent_folder",
            "value": str(destination.id),
        },
        format="json",
    )
    assert blocked.status_code == status.HTTP_200_OK, blocked.content
    assert blocked.json()["succeeded"] == []
    assert len(blocked.json()["failed"]) == 1

    allowed = authenticated_client.patch(
        f"/api/folders/{plain.id}/",
        {"parent_folder": str(destination.id)},
        format="json",
    )
    assert allowed.status_code == status.HTTP_200_OK, allowed.content
    plain.refresh_from_db()
    ancestor.refresh_from_db()
    assert plain.parent_folder_id == destination.id
    assert ancestor.parent_folder_id == root.id
    assert Folder.objects.filter(id=enclave.id).exists()


@pytest.mark.django_db
@pytest.mark.parametrize("corruption_kind", ("missing", "surplus"))
def test_generic_folder_delete_fails_closed_when_fk_tree_and_closure_disagree(
    authenticated_client,
    corruption_kind,
):
    root = Folder.get_root_folder()
    ancestor = _folder("closure-owner", root)
    enclave = _folder(
        "closure-enclave",
        ancestor,
        content_type=Folder.ContentType.ENCLAVE,
    )
    closure_field = Folder._meta.get_field("descendants")
    through = closure_field.remote_field.through
    source_field = through._meta.get_field(closure_field.m2m_field_name())
    target_field = through._meta.get_field(closure_field.m2m_reverse_field_name())

    if corruption_kind == "missing":
        through._base_manager.filter(
            **{
                source_field.attname: ancestor.id,
                target_field.attname: enclave.id,
            }
        ).delete()
    else:
        unrelated_enclave = _folder(
            "unrelated-enclave",
            root,
            content_type=Folder.ContentType.ENCLAVE,
        )
        through._base_manager.create(
            **{
                source_field.attname: ancestor.id,
                target_field.attname: unrelated_enclave.id,
            }
        )

    response = authenticated_client.delete(f"/api/folders/{ancestor.id}/")

    assert response.status_code == status.HTTP_403_FORBIDDEN, response.content
    assert Folder.objects.filter(id=ancestor.id).exists()
    assert Folder.objects.filter(id=enclave.id).exists()


@pytest.mark.django_db
@pytest.mark.parametrize(
    ("folder_case", "use_batch"),
    (
        ("plain_audit", False),
        ("active_mail", True),
        ("reverse_owner", False),
        ("missing_child_delete", True),
    ),
)
def test_generic_folder_delete_never_cascades_governed_audit_graph(
    authenticated_client,
    folder_case,
    use_batch,
):
    root = Folder.get_root_folder()
    domain = _folder(f"folder-cascade-{folder_case}", root)
    audit = _audit(domain)
    assignment = None
    outbox = None
    collection = None
    if folder_case in {"active_mail", "missing_child_delete"}:
        assignment = RequirementAssignment.objects.create(
            compliance_assessment=audit,
            folder=domain,
            status=RequirementAssignment.Status.IN_PROGRESS,
        )
    if folder_case == "active_mail":
        outbox = RequirementAssignmentMailOutbox.objects.create(
            assignment=assignment,
            folder=domain,
            payload_digest="1" * 64,
            recipient_address_hash="2" * 64,
            status=RequirementAssignmentMailOutbox.Status.SENDING,
        )
    if folder_case == "reverse_owner":
        collection = GenericCollection.objects.create(
            name="Folder cascade reverse owner",
            folder=root,
        )
        collection.compliance_assessments.add(audit)

    def allow_except_child_delete(*args, **kwargs):
        perm = kwargs.get("perm") or args[1]
        return not (
            folder_case == "missing_child_delete"
            and perm.codename == "delete_requirementassignment"
        )

    with patch(
        "iam.models.RoleAssignment.is_access_allowed",
        side_effect=allow_except_child_delete,
    ):
        if use_batch:
            response = authenticated_client.post(
                "/api/folders/batch-action/",
                {"action": "delete", "ids": [str(domain.id)]},
                format="json",
            )
            assert response.status_code == status.HTTP_200_OK, response.content
            assert response.json()["succeeded"] == []
            assert [row["id"] for row in response.json()["failed"]] == [
                str(domain.id)
            ]
        else:
            response = authenticated_client.delete(f"/api/folders/{domain.id}/")
            assert response.status_code == status.HTTP_403_FORBIDDEN, response.content

    assert Folder.objects.filter(id=domain.id).exists()
    assert ComplianceAssessment.objects.filter(id=audit.id).exists()
    if assignment is not None:
        assert RequirementAssignment.objects.filter(id=assignment.id).exists()
    if outbox is not None:
        assert RequirementAssignmentMailOutbox.objects.filter(id=outbox.id).exists()
    if collection is not None:
        assert collection.compliance_assessments.filter(id=audit.id).exists()


@pytest.mark.django_db
def test_generic_folder_delete_preserves_upstream_cascade_for_non_assessment_content(
    authenticated_client,
):
    root = Folder.get_root_folder()
    domain = _folder("ordinary-folder-content", root)
    asset = Asset.objects.create(name="Ordinary cascaded asset", folder=domain)

    response = authenticated_client.delete(f"/api/folders/{domain.id}/")

    assert response.status_code == status.HTTP_204_NO_CONTENT, response.content
    assert not Folder.objects.filter(id=domain.id).exists()
    assert not Asset.objects.filter(id=asset.id).exists()


@pytest.mark.django_db
def test_generic_audit_delete_rejects_entity_assessment_owned_audit(
    authenticated_client,
):
    root = Folder.get_root_folder()
    domain = _folder("audit-domain", root)
    audit = _audit(domain)
    entity = Entity.objects.create(
        name=f"delete-owner-{uuid.uuid4().hex[:8]}", folder=domain
    )
    assessment = EntityAssessment.objects.create(
        name=f"delete-owner-assessment-{uuid.uuid4().hex[:8]}",
        folder=domain,
        entity=entity,
        compliance_assessment=audit,
    )

    response = authenticated_client.delete(f"/api/compliance-assessments/{audit.id}/")

    assert response.status_code == status.HTTP_403_FORBIDDEN, response.content
    assessment.refresh_from_db()
    assert assessment.compliance_assessment_id == audit.id
    assert ComplianceAssessment.objects.filter(id=audit.id).exists()


@pytest.mark.django_db
@pytest.mark.parametrize("owner_kind", ("accreditation", "framework_snapshot"))
def test_generic_audit_delete_rejects_surviving_reverse_owner(
    authenticated_client,
    owner_kind,
):
    root = Folder.get_root_folder()
    domain = _folder("audit-domain", root)
    audit = _audit(domain)

    if owner_kind == "accreditation":
        category = Terminology.objects.filter(
            field_path=Terminology.FieldPath.ACCREDITATION_CATEGORY
        ).first()
        accreditation_status = Terminology.objects.filter(
            field_path=Terminology.FieldPath.ACCREDITATION_STATUS
        ).first()
        assert category is not None
        assert accreditation_status is not None
        owner = Accreditation.objects.create(
            name=f"accreditation-{uuid.uuid4().hex[:8]}",
            folder=domain,
            category=category,
            status=accreditation_status,
            checklist=audit,
        )
        owner_field = "checklist_id"
    else:
        owner = FrameworkSnapshot.objects.create(
            name=f"snapshot-{uuid.uuid4().hex[:8]}",
            folder=domain,
            source_audit=audit,
        )
        owner_field = "source_audit_id"

    response = authenticated_client.delete(f"/api/compliance-assessments/{audit.id}/")

    assert response.status_code == status.HTTP_403_FORBIDDEN, response.content
    owner.refresh_from_db()
    assert getattr(owner, owner_field) == audit.id
    assert ComplianceAssessment.objects.filter(id=audit.id).exists()


@pytest.mark.django_db
@pytest.mark.parametrize(
    ("owner_model", "relation_name"),
    (
        (GenericCollection, "compliance_assessments"),
        (TaskTemplate, "compliance_assessments"),
        (ValidationFlow, "compliance_assessments"),
    ),
)
def test_generic_audit_delete_rejects_surviving_many_to_many_owner(
    authenticated_client,
    owner_model,
    relation_name,
):
    root = Folder.get_root_folder()
    domain = _folder("audit-domain", root)
    audit = _audit(domain)
    owner_fields = {"folder": domain}
    if owner_model is not ValidationFlow:
        owner_fields["name"] = f"m2m-owner-{uuid.uuid4().hex[:8]}"
    owner = owner_model.objects.create(**owner_fields)
    getattr(owner, relation_name).add(audit)

    response = authenticated_client.delete(f"/api/compliance-assessments/{audit.id}/")

    assert response.status_code == status.HTTP_403_FORBIDDEN, response.content
    assert getattr(owner, relation_name).filter(id=audit.id).exists()
    assert ComplianceAssessment.objects.filter(id=audit.id).exists()


@pytest.mark.django_db
def test_generic_audit_without_reverse_owner_remains_deletable(authenticated_client):
    root = Folder.get_root_folder()
    domain = _folder("audit-domain", root)
    audit = _audit(domain)

    response = authenticated_client.delete(f"/api/compliance-assessments/{audit.id}/")

    assert response.status_code == status.HTTP_204_NO_CONTENT, response.content
    assert not ComplianceAssessment.objects.filter(id=audit.id).exists()


@pytest.mark.django_db
@pytest.mark.parametrize("owner_field", ("perimeter", "campaign"))
def test_generic_audit_delete_requires_current_owner_visibility(
    authenticated_client,
    owner_field,
):
    root = Folder.get_root_folder()
    domain = _folder("audit-domain", root)
    owner_domain = _folder("audit-owner-domain", root)
    audit = _audit(domain)
    if owner_field == "perimeter":
        owner = Perimeter.objects.create(name="Hidden perimeter", folder=owner_domain)
    else:
        owner = Campaign.objects.create(name="Hidden campaign", folder=owner_domain)
    setattr(audit, owner_field, owner)
    audit.save(update_fields=[owner_field])
    hidden_model = type(owner)

    def hide_owner(_user, model):
        queryset = model.objects.all()
        if model is hidden_model:
            queryset = queryset.exclude(id=owner.id)
        return queryset.values_list("id", flat=True)

    with (
        patch(
            "iam.models.RoleAssignment.get_viewable_object_ids",
            side_effect=hide_owner,
        ),
        patch("iam.models.RoleAssignment.is_access_allowed", return_value=True),
    ):
        response = authenticated_client.delete(
            f"/api/compliance-assessments/{audit.id}/"
        )

    assert response.status_code == status.HTTP_403_FORBIDDEN, response.content
    assert ComplianceAssessment.objects.filter(id=audit.id).exists()
    assert hidden_model.objects.filter(id=owner.id).exists()


@pytest.mark.django_db
@pytest.mark.parametrize(
    ("is_locked", "audit_status"),
    (
        (True, ComplianceAssessment.Status.PLANNED),
        (False, ComplianceAssessment.Status.IN_REVIEW),
    ),
)
def test_generic_audit_delete_rejects_non_mutable_state(
    authenticated_client,
    is_locked,
    audit_status,
):
    root = Folder.get_root_folder()
    domain = _folder("audit-domain", root)
    audit = _audit(domain)
    audit.is_locked = is_locked
    audit.status = audit_status
    audit.save(update_fields=["is_locked", "status"])

    response = authenticated_client.delete(f"/api/compliance-assessments/{audit.id}/")

    assert response.status_code == status.HTTP_403_FORBIDDEN, response.content
    assert ComplianceAssessment.objects.filter(id=audit.id).exists()


def test_compliance_assessment_deletion_manifest_matches_model_metadata():
    assert_compliance_assessment_deletion_manifest()


def test_generic_folder_delete_guard_is_bounded_to_ca_and_ea_roots():
    assert {
        (spec.app_label, spec.model_name, spec.folder_field_name)
        for spec in GOVERNED_FOLDER_DELETION_ROOTS
    } == {
        ("core", "ComplianceAssessment", "folder"),
        ("tprm", "EntityAssessment", "folder"),
    }


@pytest.mark.django_db
@pytest.mark.parametrize(
    "mail_status",
    (
        RequirementAssignmentMailOutbox.Status.QUEUED,
        RequirementAssignmentMailOutbox.Status.SENDING,
        RequirementAssignmentMailOutbox.Status.UNCERTAIN,
        RequirementAssignmentMailOutbox.Status.REVIEW_REQUIRED,
    ),
)
def test_generic_audit_delete_rejects_active_or_ambiguous_assignment_mail(
    authenticated_client,
    mail_status,
):
    root = Folder.get_root_folder()
    domain = _folder("audit-domain", root)
    audit = _audit(domain)
    assignment = RequirementAssignment.objects.create(
        compliance_assessment=audit,
        folder=domain,
        status=RequirementAssignment.Status.IN_PROGRESS,
    )
    outbox = RequirementAssignmentMailOutbox.objects.create(
        assignment=assignment,
        folder=domain,
        payload_digest=uuid.uuid4().hex * 2,
        recipient_address_hash="a" * 64,
        status=mail_status,
    )

    response = authenticated_client.delete(f"/api/compliance-assessments/{audit.id}/")

    assert response.status_code == status.HTTP_403_FORBIDDEN, response.content
    assert ComplianceAssessment.objects.filter(id=audit.id).exists()
    assert RequirementAssignment.objects.filter(id=assignment.id).exists()
    assert RequirementAssignmentMailOutbox.objects.filter(id=outbox.id).exists()


@pytest.mark.django_db
@pytest.mark.parametrize(
    "evidence_case",
    ("missing", "status", "payload_digest", "recipient_address_hash"),
)
def test_generic_audit_delete_requires_matching_terminal_mail_evidence(
    authenticated_client,
    evidence_case,
):
    root = Folder.get_root_folder()
    domain = _folder("audit-domain", root)
    audit = _audit(domain)
    assignment = RequirementAssignment.objects.create(
        compliance_assessment=audit,
        folder=domain,
        status=RequirementAssignment.Status.IN_PROGRESS,
    )
    outbox = RequirementAssignmentMailOutbox.objects.create(
        assignment=assignment,
        folder=domain,
        payload_digest="3" * 64,
        recipient_address_hash="4" * 64,
        status=RequirementAssignmentMailOutbox.Status.DELIVERED,
    )
    if evidence_case != "missing":
        evidence_values = {
            "status": outbox.status,
            "payload_digest": outbox.payload_digest,
            "recipient_address_hash": outbox.recipient_address_hash,
        }
        evidence_values[evidence_case] = {
            "status": RequirementAssignmentMailOutbox.Status.FAILED,
            "payload_digest": "5" * 64,
            "recipient_address_hash": "6" * 64,
        }[evidence_case]
        RequirementAssignmentMailEvidence.objects.create(
            outbox_id_snapshot=outbox.id,
            assignment_id_snapshot=assignment.id,
            folder_id_snapshot=domain.id,
            source=RequirementAssignmentMailEvidence.Source.SYSTEM,
            prior_status=RequirementAssignmentMailOutbox.Status.SENDING,
            attempts=outbox.attempts,
            record_digest="7" * 64,
            **evidence_values,
        )

    def all_ids(_user, model):
        return model.objects.values_list("id", flat=True)

    with (
        patch(
            "iam.models.RoleAssignment.get_viewable_object_ids",
            side_effect=all_ids,
        ),
        patch("iam.models.RoleAssignment.is_access_allowed", return_value=True),
    ):
        response = authenticated_client.delete(
            f"/api/compliance-assessments/{audit.id}/"
        )

    assert response.status_code == status.HTTP_403_FORBIDDEN, response.content
    assert ComplianceAssessment.objects.filter(id=audit.id).exists()
    assert RequirementAssignmentMailOutbox.objects.filter(id=outbox.id).exists()


@pytest.mark.django_db
@pytest.mark.parametrize(
    "mail_status",
    (
        RequirementAssignmentMailOutbox.Status.DELIVERED,
        RequirementAssignmentMailOutbox.Status.FAILED,
    ),
)
def test_generic_audit_delete_removes_terminal_mail_but_retains_append_only_evidence(
    authenticated_client,
    mail_status,
):
    root = Folder.get_root_folder()
    domain = _folder("audit-domain", root)
    audit = _audit(domain)
    assignment = RequirementAssignment.objects.create(
        compliance_assessment=audit,
        folder=domain,
        status=RequirementAssignment.Status.IN_PROGRESS,
    )
    outbox = RequirementAssignmentMailOutbox.objects.create(
        assignment=assignment,
        folder=domain,
        payload_digest=uuid.uuid4().hex * 2,
        recipient_address_hash="b" * 64,
        status=mail_status,
        attempts=1,
    )
    evidence = RequirementAssignmentMailEvidence.objects.create(
        outbox_id_snapshot=outbox.id,
        assignment_id_snapshot=assignment.id,
        folder_id_snapshot=domain.id,
        source=RequirementAssignmentMailEvidence.Source.SYSTEM,
        prior_status=RequirementAssignmentMailOutbox.Status.SENDING,
        status=mail_status,
        attempts=1,
        payload_digest=outbox.payload_digest,
        recipient_address_hash=outbox.recipient_address_hash,
        record_digest="c" * 64,
    )

    def all_ids(_user, model):
        return model.objects.values_list("id", flat=True)

    with (
        patch(
            "iam.models.RoleAssignment.get_viewable_object_ids",
            side_effect=all_ids,
        ),
        patch("iam.models.RoleAssignment.is_access_allowed", return_value=True),
    ):
        response = authenticated_client.delete(
            f"/api/compliance-assessments/{audit.id}/"
        )

    assert response.status_code == status.HTTP_204_NO_CONTENT, response.content
    assert not ComplianceAssessment.objects.filter(id=audit.id).exists()
    assert not RequirementAssignment.objects.filter(id=assignment.id).exists()
    assert not RequirementAssignmentMailOutbox.objects.filter(id=outbox.id).exists()
    assert RequirementAssignmentMailEvidence.objects.filter(id=evidence.id).exists()


@pytest.mark.django_db
@pytest.mark.parametrize("use_batch", (False, True))
def test_framework_delete_rejects_dependent_audits(authenticated_client, use_batch):
    root = Folder.get_root_folder()
    domain = _folder("framework-owner", root)
    audit = _audit(domain)
    framework = audit.framework

    if use_batch:
        response = authenticated_client.post(
            "/api/frameworks/batch-action/",
            {"action": "delete", "ids": [str(framework.id)]},
            format="json",
        )
        assert response.status_code == status.HTTP_200_OK, response.content
        assert response.json()["succeeded"] == []
        assert [row["id"] for row in response.json()["failed"]] == [
            str(framework.id)
        ]
    else:
        response = authenticated_client.delete(f"/api/frameworks/{framework.id}/")
        assert response.status_code == status.HTTP_403_FORBIDDEN, response.content

    assert Framework.objects.filter(id=framework.id).exists()
    assert ComplianceAssessment.objects.filter(id=audit.id).exists()


@pytest.mark.django_db
@pytest.mark.parametrize("use_batch", (False, True))
def test_entity_delete_rejects_dependent_assessments(authenticated_client, use_batch):
    root = Folder.get_root_folder()
    domain = _folder("entity-owner", root)
    enclave = _folder(
        "entity-audit-enclave",
        domain,
        content_type=Folder.ContentType.ENCLAVE,
    )
    audit = _audit(enclave)
    entity = Entity.objects.create(name="Dependent entity", folder=domain)
    assessment = EntityAssessment.objects.create(
        name="Dependent entity assessment",
        folder=domain,
        entity=entity,
        compliance_assessment=audit,
    )

    if use_batch:
        response = authenticated_client.post(
            "/api/entities/batch-action/",
            {"action": "delete", "ids": [str(entity.id)]},
            format="json",
        )
        assert response.status_code == status.HTTP_200_OK, response.content
        assert response.json()["succeeded"] == []
        assert [row["id"] for row in response.json()["failed"]] == [str(entity.id)]
    else:
        response = authenticated_client.delete(f"/api/entities/{entity.id}/")
        assert response.status_code == status.HTTP_403_FORBIDDEN, response.content

    assert Entity.objects.filter(id=entity.id).exists()
    assert EntityAssessment.objects.filter(id=assessment.id).exists()
    assert ComplianceAssessment.objects.filter(id=audit.id).exists()
    assert Folder.objects.filter(id=enclave.id).exists()
