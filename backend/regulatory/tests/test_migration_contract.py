import pytest
from django.contrib.auth.models import Permission
from django.db import connection

from core.startup import (
    ADMINISTRATOR_PERMISSIONS_LIST,
    ANALYST_PERMISSIONS_LIST,
    APPROVER_PERMISSIONS_LIST,
    DOMAIN_MANAGER_PERMISSIONS_LIST,
    READER_PERMISSIONS_LIST,
)
from iam.models import ALLOWED_PERMISSION_APPS


@pytest.mark.django_db
def test_initial_migration_tables_constraints_and_permissions_exist(regulatory_root):
    tables = set(connection.introspection.table_names())
    expected_tables = {
        "regulatory_regulatorydocument",
        "regulatory_entitydocumentregistration",
        "regulatory_regulatorydocumentversion",
        "regulatory_regulatoryprovision",
        "regulatory_regulatoryobligation",
        "regulatory_regulatoryobligationprovision",
        "regulatory_regulatoryobligationreviewevent",
        "regulatory_regulatorychaincorrectionevent",
        "regulatory_regulatoryapplicabilitydecision",
    }
    assert expected_tables <= tables

    with connection.cursor() as cursor:
        constraints = connection.introspection.get_constraints(
            cursor,
            "regulatory_regulatorydocumentversion",
        )
    for name in (
        "reg_ver_doc_asof_idx",
        "reg_ver_folder_record_rev_uniq",
        "reg_ver_one_current",
        "reg_ver_recorded_interval",
        "reg_ver_valid_interval",
        "reg_ver_phase1_metadata_only",
        "reg_ver_not_published",
    ):
        assert name in constraints

    codenames = set(
        Permission.objects.filter(content_type__app_label="regulatory").values_list(
            "codename",
            flat=True,
        )
    )
    assert "view_regulatorydocument" in codenames
    assert "ingest_regulatoryrecord" in codenames
    assert "transition_regulatoryobligation" in codenames
    assert "legal_review_regulatoryobligation" in codenames
    assert "correct_regulatoryrecord" in codenames
    correction_permission = Permission.objects.get(
        content_type__app_label="regulatory",
        codename="correct_regulatoryrecord",
    )
    assert correction_permission.content_type.model == "regulatorydocument"
    assert "regulatory" in ALLOWED_PERMISSION_APPS

    with connection.cursor() as cursor:
        correction_constraints = connection.introspection.get_constraints(
            cursor,
            "regulatory_regulatorychaincorrectionevent",
        )
    for name in (
        "reg_correction_doc_time_idx",
        "reg_correction_idempotency_uniq",
        "reg_correction_previous_ver_uniq",
        "reg_correction_successor_ver_uniq",
        "reg_correction_previous_prov_uniq",
        "reg_correction_successor_prov_uniq",
        "reg_correction_previous_obl_uniq",
        "reg_correction_successor_obl_uniq",
        "reg_correction_recorded_time",
        "reg_correction_digest_schema",
        "reg_correction_payload_changed",
        "reg_correction_version_changed",
        "reg_correction_provision_changed",
        "reg_correction_obligation_changed",
        "reg_correction_rationale_present",
        "reg_correction_not_published",
    ):
        assert name in correction_constraints

    with connection.cursor() as cursor:
        applicability_constraints = connection.introspection.get_constraints(
            cursor,
            "regulatory_regulatoryapplicabilitydecision",
        )
    for name in (
        "reg_app_dec_asof_idx",
        "reg_app_dec_record_rev_uniq",
        "reg_app_fact_record_rev_uniq",
        "reg_app_dec_one_current",
        "reg_app_dec_previous_uniq",
        "reg_app_dec_idem_uniq",
        "reg_app_dec_revision_pos",
        "reg_app_dec_recorded_int",
        "reg_app_dec_valid_int",
        "reg_app_dec_scope_legal",
        "reg_app_dec_rule_id",
        "reg_app_dec_rule_version",
        "reg_app_dec_draft",
        "reg_app_dec_nonbinding",
        "reg_app_dec_digest_schema",
        "reg_app_dec_eval_profile",
        "reg_app_dec_rationale",
        "reg_app_dec_result_reason",
        "reg_app_dec_not_published",
    ):
        assert name in applicability_constraints

    applicability_view_permission = Permission.objects.get(
        content_type__app_label="regulatory",
        codename="view_regulatoryapplicabilitydecision",
    )
    assert applicability_view_permission.content_type.model == (
        "regulatoryapplicabilitydecision"
    )
    applicability_record_permission = Permission.objects.get(
        content_type__app_label="regulatory",
        codename="record_regulatoryapplicability",
    )
    assert applicability_record_permission.content_type.model == (
        "regulatoryapplicabilitydecision"
    )


def test_builtin_roles_keep_regulatory_write_authority_bounded():
    assert "view_regulatorydocument" in READER_PERMISSIONS_LIST
    assert "view_regulatoryapplicabilitydecision" not in READER_PERMISSIONS_LIST
    assert "record_regulatoryapplicability" not in READER_PERMISSIONS_LIST
    assert "view_regulatorydocument" in APPROVER_PERMISSIONS_LIST
    assert "view_regulatoryapplicabilitydecision" in APPROVER_PERMISSIONS_LIST
    assert "view_entity" in APPROVER_PERMISSIONS_LIST
    assert "record_regulatoryapplicability" not in APPROVER_PERMISSIONS_LIST
    for permissions in (
        ANALYST_PERMISSIONS_LIST,
        DOMAIN_MANAGER_PERMISSIONS_LIST,
    ):
        assert "view_regulatorydocument" in permissions
        assert "view_regulatoryapplicabilitydecision" in permissions
        assert "record_regulatoryapplicability" in permissions
        assert "ingest_regulatoryrecord" in permissions
        assert "correct_regulatoryrecord" in permissions
        assert "transition_regulatoryobligation" in permissions
        assert "legal_review_regulatoryobligation" not in permissions
    assert "view_regulatorydocument" in ADMINISTRATOR_PERMISSIONS_LIST
    assert "view_regulatoryapplicabilitydecision" in ADMINISTRATOR_PERMISSIONS_LIST
    assert "record_regulatoryapplicability" in ADMINISTRATOR_PERMISSIONS_LIST
    assert "ingest_regulatoryrecord" in ADMINISTRATOR_PERMISSIONS_LIST
    assert "correct_regulatoryrecord" in ADMINISTRATOR_PERMISSIONS_LIST
    assert "transition_regulatoryobligation" in ADMINISTRATOR_PERMISSIONS_LIST
    assert "legal_review_regulatoryobligation" in ADMINISTRATOR_PERMISSIONS_LIST
    assert "legal_review_regulatoryobligation" in APPROVER_PERMISSIONS_LIST
    assert "ingest_regulatoryrecord" not in READER_PERMISSIONS_LIST
    assert "correct_regulatoryrecord" not in READER_PERMISSIONS_LIST
    assert "correct_regulatoryrecord" not in APPROVER_PERMISSIONS_LIST
    assert "transition_regulatoryobligation" not in APPROVER_PERMISSIONS_LIST
