"""PostgreSQL-safe row locking for single-control reference synchronization."""

import pytest
from django.db.models import QuerySet
from iam.models import Folder, User
from rest_framework.test import APIClient

from core.models import AppliedControl, Policy, ReferenceControl

pytestmark = pytest.mark.django_db


@pytest.mark.parametrize(
    "target_model,endpoint",
    ((AppliedControl, "applied-controls"), (Policy, "policies")),
)
def test_sync_to_reference_control_locks_only_the_target_row(
    monkeypatch,
    target_model,
    endpoint,
):
    root = Folder.get_root_folder()
    folder = Folder.objects.create(
        name=f"{endpoint} sync lock domain",
        content_type=Folder.ContentType.DOMAIN,
        parent_folder=root,
    )
    reference = ReferenceControl.objects.create(
        name=f"{endpoint} lock reference",
        urn=f"urn:test:{endpoint}:lock-reference",
        folder=folder,
        category="technical",
        csf_function="identify",
    )
    target = target_model.objects.create(
        name=f"{endpoint} lock target",
        folder=folder,
        reference_control=reference,
        csf_function="protect",
        **({"category": "process"} if target_model is AppliedControl else {}),
    )
    admin = User.objects.create_superuser(f"{endpoint}-lock-admin@tests.invalid")
    client = APIClient()
    client.force_authenticate(admin)

    lock_calls: list[tuple[type, tuple[str, ...] | None]] = []
    original_select_for_update = QuerySet.select_for_update

    def tracked_select_for_update(queryset, *args, **kwargs):
        if queryset.model is target_model:
            lock_calls.append((queryset.model, kwargs.get("of")))
        return original_select_for_update(queryset, *args, **kwargs)

    monkeypatch.setattr(QuerySet, "select_for_update", tracked_select_for_update)
    response = client.post(
        f"/api/{endpoint}/{target.id}/sync-to-reference-control/?dry_run=false",
        {},
        format="json",
    )

    assert response.status_code == 200, response.content
    assert (target_model, ("self",)) in lock_calls
    target.refresh_from_db()
    assert target.csf_function == reference.csf_function
    assert target.category == (
        "policy" if target_model is Policy else reference.category
    )
