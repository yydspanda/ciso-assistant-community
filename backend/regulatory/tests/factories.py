from copy import deepcopy
import uuid

from django.contrib.auth.models import Permission

from iam.models import Folder, Role, RoleAssignment, User
from tprm.models import Entity


def make_folder(name: str | None = None) -> Folder:
    return Folder.objects.create(
        name=name or f"Regulatory test {uuid.uuid4().hex[:8]}",
        parent_folder=Folder.get_root_folder(),
        content_type=Folder.ContentType.DOMAIN,
    )


def make_synthetic_entity(folder: Folder, suffix: str | None = None) -> Entity:
    suffix = suffix or uuid.uuid4().hex[:8]
    return Entity.objects.create(
        name=f"Synthetic bank {suffix} (non-authoritative)",
        ref_id=f"SYNTHETIC-CN-BANK-{suffix}",
        folder=folder,
        country="CN",
    )


def make_user_with_permissions(
    folder: Folder,
    *codenames: str,
    email_prefix: str = "reg-user",
) -> User:
    user = User.objects.create_user(
        email=f"{email_prefix}-{uuid.uuid4().hex[:8]}@example.test",
        is_published=True,
    )
    role = Role.objects.create(
        name=f"reg-role-{uuid.uuid4().hex[:8]}",
        folder=Folder.get_root_folder(),
    )
    role.permissions.set(
        Permission.objects.filter(
            content_type__app_label="regulatory",
            codename__in=codenames,
        )
    )
    assignment = RoleAssignment.objects.create(
        user=user,
        role=role,
        folder=Folder.get_root_folder(),
        is_recursive=True,
    )
    assignment.perimeter_folders.add(folder)
    return user


def chain_payload(suffix: str = "001") -> dict:
    document_id = f"TEST-CN-REG-{suffix}"
    version_id = f"TEST-CN-REG-{suffix}-v1"
    provision_id = f"TEST-CN-REG-{suffix}-v1-art1"
    obligation_id = f"TEST-CN-OBL-{suffix}"
    recorded_at = "2026-08-21T00:00:00+08:00"
    provenance = {
        "method": "model_proposal",
        "created_at": recorded_at,
        "created_by": "test:synthetic-model-run",
        "parser_version": None,
        "model": "test-model",
        "prompt_version": "test-prompt-v1",
        "retrieval_version": "test-source-register-v1",
    }
    return {
        "document": {
            "id": document_id,
            "title_zh": f"合成监管测试文件 {suffix}",
            "title_en": "Synthetic regulatory test instrument",
            "issuer": "合成测试监管机构",
            "authority_level": "law",
            "territories": ["CN"],
            "regulated_entity_scopes": ["banking"],
            "domains": ["banking", "compliance"],
            "coverage_priority": "P0",
            "coverage_stage": "obligations_proposed",
            "applicability_fact_keys": ["entity.licence_type"],
            "selection_rationale": "Synthetic test data only; not legal advice.",
        },
        "document_version": {
            "id": version_id,
            "document_id": document_id,
            "version_label": "Synthetic version 1",
            "document_no": None,
            "status": "effective",
            "status_as_of": "2026-08-21",
            "effective_basis": "explicit_date",
            "issued_date": "2021-08-20",
            "published_date": "2021-08-20",
            "effective_date": "2021-11-01",
            "transition_end": None,
            "repeal_date": None,
            "supersedes_version_ids": [],
            "source_url": f"https://example.test/regulatory/{suffix}",
            "source_hash": "1" * 64,
            "content_storage_policy": "metadata_only",
            "notes": "Synthetic metadata; no source text is stored.",
            "source_checked_on": "2026-08-21",
            "metadata_confidence": "confirmed",
            "legal_review_status": "unreviewed",
            "legal_reviewed_at": None,
            "legal_reviewed_by": None,
            "valid_from": "2021-11-01",
            "valid_to": None,
            "recorded_from": recorded_at,
            "recorded_to": None,
            "provenance": deepcopy(provenance),
        },
        "provision": {
            "id": provision_id,
            "document_id": document_id,
            "version_id": version_id,
            "article": "第一条",
            "heading": "合成条款",
            "text": None,
            "source_locator": {"kind": "article", "value": "第一条"},
            "content_hash": "2" * 64,
            "recorded_from": recorded_at,
            "recorded_to": None,
            "provenance": deepcopy(provenance),
        },
        "obligation": {
            "id": obligation_id,
            "title_zh": "合成待复核义务",
            "provision_ids": [provision_id],
            "authority_level": "law",
            "modality": "must",
            "subject": "合成银行主体",
            "action": "建立并保留可复核的合成测试记录",
            "object": "合成测试流程",
            "conditions": ["仅用于自动化测试"],
            "exceptions": [],
            "deadline": {"kind": "none", "value": None, "rule_id": None},
            "expected_evidence": ["合成测试证据"],
            "penalty_or_consequence": None,
            "valid_from": "2021-11-01",
            "valid_to": None,
            "recorded_from": recorded_at,
            "recorded_to": None,
            "review_status": "machine_proposed",
            "confidence": 0.65,
            "uncertainties": ["Requires named human review"],
            "provenance": deepcopy(provenance),
        },
    }
