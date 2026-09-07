from types import SimpleNamespace

import pytest
from rest_framework.exceptions import PermissionDenied

from core.models import ValidationFlow
from core.serializers import ValidationFlowWriteSerializer
from iam.models import Folder, RoleAssignment, User
from pmbok.models import GenericCollection
from pmbok.serializers import GenericCollectionWriteSerializer


@pytest.mark.django_db
@pytest.mark.parametrize(
    ("model", "serializer_class", "permission_codename"),
    (
        (
            GenericCollection,
            GenericCollectionWriteSerializer,
            "add_genericcollection",
        ),
        (ValidationFlow, ValidationFlowWriteSerializer, "add_validationflow"),
    ),
)
def test_owner_move_rechecks_destination_authority_after_root_lock(
    monkeypatch,
    model,
    serializer_class,
    permission_codename,
):
    root = Folder.get_root_folder()
    source = Folder.objects.create(name="relation-owner-source", parent_folder=root)
    destination = Folder.objects.create(
        name="relation-owner-destination",
        parent_folder=root,
    )
    user = User.objects.create_user(email=f"{model._meta.model_name}@example.com")
    create_fields = {"folder": source}
    if model is GenericCollection:
        create_fields["name"] = "governed collection"
    instance = model.objects.create(**create_fields)

    destination_add_checks = 0

    def revoke_after_initial_validation(*, user, perm, folder):
        nonlocal destination_add_checks
        del user
        if perm.codename == permission_codename and folder.pk == destination.pk:
            destination_add_checks += 1
            return destination_add_checks == 1
        return True

    monkeypatch.setattr(
        RoleAssignment,
        "is_access_allowed",
        revoke_after_initial_validation,
    )
    serializer = serializer_class(
        instance,
        data={"folder": str(destination.pk)},
        partial=True,
        context={"request": SimpleNamespace(user=user)},
    )
    assert serializer.is_valid(), serializer.errors

    with pytest.raises(PermissionDenied):
        serializer.save()

    instance.refresh_from_db()
    assert destination_add_checks == 2
    assert instance.folder_id == source.pk
