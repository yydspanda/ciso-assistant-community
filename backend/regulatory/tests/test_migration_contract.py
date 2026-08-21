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
    }
    assert expected_tables <= tables

    with connection.cursor() as cursor:
        constraints = connection.introspection.get_constraints(
            cursor,
            "regulatory_regulatorydocumentversion",
        )
    for name in (
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
    assert "regulatory" in ALLOWED_PERMISSION_APPS


def test_builtin_roles_keep_regulatory_write_authority_bounded():
    assert "view_regulatorydocument" in READER_PERMISSIONS_LIST
    assert "view_regulatorydocument" in APPROVER_PERMISSIONS_LIST
    for permissions in (
        ANALYST_PERMISSIONS_LIST,
        DOMAIN_MANAGER_PERMISSIONS_LIST,
    ):
        assert "view_regulatorydocument" in permissions
        assert "ingest_regulatoryrecord" in permissions
        assert "transition_regulatoryobligation" in permissions
        assert "legal_review_regulatoryobligation" not in permissions
    assert "view_regulatorydocument" in ADMINISTRATOR_PERMISSIONS_LIST
    assert "ingest_regulatoryrecord" in ADMINISTRATOR_PERMISSIONS_LIST
    assert "transition_regulatoryobligation" in ADMINISTRATOR_PERMISSIONS_LIST
    assert "legal_review_regulatoryobligation" in ADMINISTRATOR_PERMISSIONS_LIST
    assert "legal_review_regulatoryobligation" in APPROVER_PERMISSIONS_LIST
    assert "ingest_regulatoryrecord" not in READER_PERMISSIONS_LIST
    assert "transition_regulatoryobligation" not in APPROVER_PERMISSIONS_LIST
