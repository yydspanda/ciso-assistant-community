"""Provisioning and update helpers for OAuth2 service accounts (see ServiceAccount model)."""

from django.contrib.auth.models import Permission
from django.core.exceptions import ValidationError
from django.db import transaction

from allauth.idp.oidc.adapter import get_adapter as get_oidc_adapter
from allauth.idp.oidc.models import Client

from core.reserved_iam import (
    MANAGED_TPRM_RESPONDENT_IAM_ERROR,
    ManagedTprmRespondentIamError,
    TPRM_RESPONDENT_ROLE_CODENAME,
    assert_tprm_role_assignment_write_allowed,
)
from iam.models import (
    ALLOWED_PERMISSION_APPS,
    IGNORED_PERMISSION_MODELS,
    Folder,
    Role,
    RoleAssignment,
    ServiceAccount,
    User,
)

SERVICE_ACCOUNT_EMAIL_DOMAIN = "service-accounts.local"
INVALID_SERVICE_ACCOUNT_IAM_BUNDLE_ERROR = "invalidServiceAccountIamBundle"

# Marks "field omitted" so it's distinguishable from "field sent as null".
UNSET = object()


def get_selectable_permissions():
    """Permissions a service account may be granted — same catalog RBAC uses."""
    return (
        Permission.objects.filter(content_type__app_label__in=ALLOWED_PERMISSION_APPS)
        .exclude(content_type__model__in=IGNORED_PERMISSION_MODELS)
        .select_related("content_type")
        .order_by("content_type__app_label", "content_type__model", "codename")
    )


def _validated_permissions(permission_ids, *, for_update: bool = False):
    queryset = get_selectable_permissions().filter(id__in=permission_ids)
    if for_update:
        queryset = queryset.select_for_update(of=("self",))
    permissions = list(queryset)
    if len(permissions) != len(set(permission_ids)):
        raise ValidationError("Invalid permission selection.")
    return permissions


def get_selectable_builtin_role(role_id) -> Role:
    role = (
        Role.objects.filter(id=role_id, builtin=True)
        .exclude(name=TPRM_RESPONDENT_ROLE_CODENAME)
        .first()
    )
    if role is None:
        raise ValidationError("Invalid role selection.")
    return role


def _objects_by_string_pk(objects):
    return {str(obj.pk): obj for obj in objects}


def lock_user_service_account_rows(
    user_ids,
) -> tuple[dict[str, User], dict[str, ServiceAccount]]:
    """Lock Users before their reverse ServiceAccounts under the root mutex.

    SCIM and every ServiceAccount lifecycle writer share this order.  Keeping
    the root mutex acquisition inside the protocol prevents a machine-account
    writer from holding a ServiceAccount row while waiting on a User row that
    a SCIM writer already owns.
    """

    if not transaction.get_connection().in_atomic_block:
        raise RuntimeError("User/service-account locking requires a transaction.")
    Folder._lock_folder_tree()
    requested_ids = {user_id for user_id in user_ids if user_id is not None}
    locked_users = list(
        User.objects.select_for_update(of=("self",))
        .filter(id__in=requested_ids)
        .order_by("id")
    )
    locked_service_accounts = list(
        ServiceAccount.objects.select_for_update(of=("self",))
        .select_related("client", "role")
        .filter(user_id__in=requested_ids)
        .order_by("id")
    )
    return _objects_by_string_pk(locked_users), {
        str(item.user_id): item for item in locked_service_accounts
    }


def _lock_service_account_identity(
    service_account_id,
) -> tuple[ServiceAccount, User]:
    """Lock one lifecycle target as root -> User -> ServiceAccount."""

    Folder._lock_folder_tree()
    snapshot = (
        ServiceAccount.objects.filter(id=service_account_id)
        .values("user_id")
        .first()
    )
    if snapshot is None:
        raise ServiceAccount.DoesNotExist
    users, accounts_by_user = lock_user_service_account_rows((snapshot["user_id"],))
    user = users.get(str(snapshot["user_id"]))
    service_account = accounts_by_user.get(str(snapshot["user_id"]))
    if (
        user is None
        or service_account is None
        or service_account.id != service_account_id
    ):
        raise ValidationError(INVALID_SERVICE_ACCOUNT_IAM_BUNDLE_ERROR)
    return service_account, user


def set_service_account_active(
    service_account: ServiceAccount, *, is_active: bool
) -> ServiceAccount:
    """Apply activation state with the canonical identity lock protocol."""

    with transaction.atomic():
        locked_service_account, locked_user = _lock_service_account_identity(
            service_account.id
        )
        if is_active and not locked_service_account.is_active:
            locked_service_account._activate_locked(locked_user)
        elif not is_active and locked_service_account.is_active:
            locked_service_account._deactivate_locked(locked_user)
    return locked_service_account


def deactivate_service_account_if_expired(service_account_id, as_of) -> bool:
    """Deactivate only if the freshly locked row is still expired and active."""

    with transaction.atomic():
        try:
            locked_service_account, locked_user = _lock_service_account_identity(
                service_account_id
            )
        except ServiceAccount.DoesNotExist:
            return False
        if (
            not locked_service_account.is_active
            or locked_service_account.expiry_date is None
            or locked_service_account.expiry_date >= as_of
        ):
            return False
        locked_service_account._deactivate_locked(locked_user)
    return True


def rotate_service_account_secret(
    service_account: ServiceAccount, *, grace_period=None
) -> str:
    """Rotate a secret after locking root -> User -> ServiceAccount."""

    with transaction.atomic():
        locked_service_account, _locked_user = _lock_service_account_identity(
            service_account.id
        )
        plain_secret = locked_service_account._rotate_secret_locked(grace_period)
        # Preserve the public model method's prior in-memory contract even
        # though the mutation is deliberately performed on a fresh locked row.
        for field_name in (
            "previous_secret_hash",
            "previous_secret_expires_at",
            "secret_preview",
            "updated_at",
        ):
            setattr(
                service_account,
                field_name,
                getattr(locked_service_account, field_name),
            )
        if "client" in service_account._state.fields_cache:
            service_account.client.secret = locked_service_account.client.secret
        return plain_secret


def delete_service_account(service_account: ServiceAccount, *args, **kwargs):
    """Delete a machine-principal bundle after root -> User -> SA locking."""

    with transaction.atomic():
        locked_service_account, locked_user = _lock_service_account_identity(
            service_account.id
        )
        return locked_service_account._delete_locked(
            locked_user, *args, **kwargs
        )


def _lock_roles(role_ids) -> dict[str, Role]:
    role_ids = {str(role_id) for role_id in role_ids if role_id is not None}
    roles = list(
        Role.objects.select_for_update(of=("self",))
        .filter(id__in=role_ids)
        .order_by("id")
    )
    if len(roles) != len(role_ids):
        raise ValidationError("Invalid role selection.")
    return _objects_by_string_pk(roles)


def _lock_folders(folder_ids) -> dict[str, Folder]:
    folder_ids = {str(folder_id) for folder_id in folder_ids if folder_id is not None}
    folders = list(
        Folder.objects.select_for_update(of=("self",))
        .filter(id__in=folder_ids)
        .order_by("id")
    )
    if len(folders) != len(folder_ids):
        raise ValidationError("Invalid domain selection.")
    return _objects_by_string_pk(folders)


def _assert_assignment_allowed(*, folder, role, user_group, perimeter_folders):
    try:
        assert_tprm_role_assignment_write_allowed(
            folder=folder,
            role=role,
            user_group=user_group,
            perimeter_folders=perimeter_folders,
        )
    except ManagedTprmRespondentIamError as exc:
        raise ValidationError(MANAGED_TPRM_RESPONDENT_IAM_ERROR) from exc


def _assert_service_account_bundle(
    *,
    service_account: ServiceAccount,
    role_assignment: RoleAssignment,
    root_folder: Folder,
    current_role: Role,
    perimeter_folders: list[Folder],
) -> None:
    """Fail closed when historical/direct writes broke the one-account bundle."""

    _assert_assignment_allowed(
        folder=role_assignment.folder,
        role=current_role,
        user_group=role_assignment.user_group,
        perimeter_folders=perimeter_folders,
    )

    if (
        role_assignment.user_id != service_account.user_id
        or role_assignment.user_group_id is not None
        or role_assignment.role_id != service_account.role_id
        or service_account.role_id != current_role.id
        or role_assignment.folder_id != root_folder.id
        or not perimeter_folders
    ):
        raise ValidationError(INVALID_SERVICE_ACCOUNT_IAM_BUNDLE_ERROR)

    # A non-builtin role is mutable by this service and must therefore remain
    # dedicated to exactly this service-account bundle.
    if not current_role.builtin and (
        ServiceAccount.objects.exclude(id=service_account.id)
        .filter(role_id=current_role.id)
        .exists()
        or RoleAssignment.objects.exclude(id=role_assignment.id)
        .filter(role_id=current_role.id)
        .exists()
    ):
        raise ValidationError(INVALID_SERVICE_ACCOUNT_IAM_BUNDLE_ERROR)


def provision_service_account(
    *,
    name: str,
    description: str | None,
    permission_ids: list[int] | None,
    role_id=None,
    folder_ids: list,
    is_recursive: bool,
    created_by: User | None,
    expiry_date=None,
) -> tuple[ServiceAccount, str]:
    """Returns (sa, plaintext_secret); exactly one of permission_ids/role_id is expected."""
    if role_id is None and not permission_ids:
        raise ValidationError("Provide either a role or permissions.")
    if role_id is not None and permission_ids:
        raise ValidationError("Provide either a role or permissions, not both.")
    if not folder_ids:
        raise ValidationError("Invalid domain selection.")

    adapter = get_oidc_adapter()
    client_id = adapter.generate_client_id()
    plain_secret = ServiceAccount.generate_secret()

    with transaction.atomic():
        # This root-row mutex is the common first lock for folder-scoped IAM
        # writers. Role/folder rows are then locked before the account bundle.
        Folder._lock_folder_tree()
        root_folder_id = Folder.get_root_folder_id()
        if root_folder_id is None:
            raise ValidationError(INVALID_SERVICE_ACCOUNT_IAM_BUNDLE_ERROR)

        locked_roles = _lock_roles([role_id] if role_id is not None else [])
        role = locked_roles.get(str(role_id)) if role_id is not None else None
        if role is not None and not role.builtin:
            raise ValidationError("Invalid role selection.")

        locked_folders = _lock_folders(
            [
                root_folder_id,
                *folder_ids,
                *([role.folder_id] if role is not None else []),
            ]
        )
        root_folder = locked_folders[str(root_folder_id)]
        if root_folder.content_type != Folder.ContentType.ROOT:
            raise ValidationError(INVALID_SERVICE_ACCOUNT_IAM_BUNDLE_ERROR)
        folders = [
            locked_folders[str(folder_id)] for folder_id in dict.fromkeys(folder_ids)
        ]

        _assert_assignment_allowed(
            folder=root_folder,
            role=role,
            user_group=None,
            perimeter_folders=folders,
        )
        permissions = (
            _validated_permissions(permission_ids, for_update=True)
            if role is None
            else None
        )

        user = User.objects._create_user(
            email=f"sa-{client_id}@{SERVICE_ACCOUNT_EMAIL_DOMAIN}",
            password=None,
            mailing=False,
            initial_group=None,
            first_name=name,
        )
        client = Client(
            id=client_id,
            name=name,
            type=Client.Type.CONFIDENTIAL,
            grant_types=Client.GrantType.CLIENT_CREDENTIALS,
            scopes="",
            response_types="",
            owner=user,
        )
        client.set_secret(plain_secret)
        client.save()
        if role is None:
            role = Role.objects.create(name=f"SA-{client_id}", folder=root_folder)
            role.permissions.set(permissions)
        role_assignment = RoleAssignment.objects.create(
            user=user,
            role=role,
            is_recursive=is_recursive,
            folder=root_folder,
        )
        role_assignment.perimeter_folders.set(folders)
        service_account = ServiceAccount.objects.create(
            name=name,
            description=description,
            client=client,
            user=user,
            role=role,
            created_by=created_by,
            expiry_date=expiry_date,
            secret_preview=ServiceAccount.secret_preview_for(plain_secret),
        )
    return service_account, plain_secret


def _switch_role(
    service_account: ServiceAccount,
    role_assignment: RoleAssignment,
    new_role: Role,
) -> None:
    old_role = service_account.role
    service_account.role = new_role
    service_account.save(update_fields=["role", "updated_at"])
    role_assignment.role = new_role
    role_assignment.save(update_fields=["role", "updated_at"])
    if not old_role.builtin:
        old_role.delete()


def _detach_to_dedicated_role(
    service_account: ServiceAccount,
    role_assignment: RoleAssignment,
    permissions: list[Permission],
    root_folder: Folder,
) -> None:
    new_role = Role.objects.create(
        name=f"SA-{service_account.client_id}", folder=root_folder
    )
    new_role.permissions.set(permissions)
    _switch_role(service_account, role_assignment, new_role)


def update_service_account(
    service_account: ServiceAccount,
    *,
    name: str | None = None,
    description=UNSET,
    permission_ids: list[int] | None = None,
    role_id=None,
    folder_ids: list | None = None,
    is_recursive: bool | None = None,
    expiry_date=UNSET,
    is_active=UNSET,
) -> ServiceAccount:
    with transaction.atomic():
        Folder._lock_folder_tree()
        root_folder_id = Folder.get_root_folder_id()
        if root_folder_id is None:
            raise ValidationError(INVALID_SERVICE_ACCOUNT_IAM_BUNDLE_ERROR)

        # Discover the graph only after taking the folder-tree mutex. Every
        # governed writer uses that mutex, so these identifiers stay stable
        # while we acquire the rows in the shared lock order.
        snapshot = (
            ServiceAccount.objects.filter(id=service_account.id)
            .values("user_id", "role_id")
            .first()
        )
        if snapshot is None:
            raise ValidationError(INVALID_SERVICE_ACCOUNT_IAM_BUNDLE_ERROR)
        locked_users, locked_accounts_by_user = lock_user_service_account_rows(
            (snapshot["user_id"],)
        )
        locked_user = locked_users.get(str(snapshot["user_id"]))
        locked_service_account = locked_accounts_by_user.get(str(snapshot["user_id"]))
        if (
            locked_user is None
            or locked_service_account is None
            or locked_service_account.id != service_account.id
            or locked_service_account.role_id != snapshot["role_id"]
        ):
            raise ValidationError(INVALID_SERVICE_ACCOUNT_IAM_BUNDLE_ERROR)
        assignment_snapshots = list(
            RoleAssignment.objects.filter(user_id=snapshot["user_id"])
            .values("id", "role_id", "folder_id")
            .order_by("id")
        )
        assignment_ids = [row["id"] for row in assignment_snapshots]

        perimeter_field = RoleAssignment._meta.get_field("perimeter_folders")
        perimeter_through = perimeter_field.remote_field.through
        perimeter_source = perimeter_field.m2m_field_name()
        perimeter_target = perimeter_field.m2m_reverse_field_name()
        perimeter_pairs = list(
            perimeter_through.objects.filter(
                **{f"{perimeter_source}_id__in": assignment_ids}
            )
            .values_list(
                f"{perimeter_source}_id",
                f"{perimeter_target}_id",
            )
            .order_by(f"{perimeter_source}_id", f"{perimeter_target}_id")
        )

        role_ids = {
            snapshot["role_id"],
            *(row["role_id"] for row in assignment_snapshots),
        }
        if role_id is not None:
            role_ids.add(role_id)
        locked_roles = _lock_roles(role_ids)

        folders_to_lock = {
            root_folder_id,
            *(row["folder_id"] for row in assignment_snapshots),
            *(folder_id for _, folder_id in perimeter_pairs),
            *(role.folder_id for role in locked_roles.values()),
        }
        if folder_ids is not None:
            if not folder_ids:
                raise ValidationError("Invalid domain selection.")
            folders_to_lock.update(folder_ids)
        locked_folders = _lock_folders(folders_to_lock)

        # User and ServiceAccount were locked in the shared identity order;
        # assignments and their through rows follow the account identity.
        locked_assignments = list(
            RoleAssignment.objects.select_for_update(of=("self",))
            .filter(user_id=locked_service_account.user_id)
            .select_related("folder", "role", "user_group", "user_group__folder")
            .order_by("id")
        )
        if [item.id for item in locked_assignments] != assignment_ids:
            raise ValidationError(INVALID_SERVICE_ACCOUNT_IAM_BUNDLE_ERROR)
        locked_perimeter_rows = list(
            perimeter_through.objects.select_for_update()
            .filter(**{f"{perimeter_source}_id__in": assignment_ids})
            .order_by("pk")
        )
        actual_perimeter_pairs = [
            (
                getattr(row, f"{perimeter_source}_id"),
                getattr(row, f"{perimeter_target}_id"),
            )
            for row in locked_perimeter_rows
        ]
        if set(actual_perimeter_pairs) != set(perimeter_pairs):
            raise ValidationError(INVALID_SERVICE_ACCOUNT_IAM_BUNDLE_ERROR)

        root_folder = locked_folders[str(root_folder_id)]
        current_role = locked_roles[str(locked_service_account.role_id)]
        # Invoke the reserved-IAM guard even when another bundle invariant is
        # also damaged, so a reserved role never becomes a repair mechanism.
        _assert_assignment_allowed(
            folder=root_folder,
            role=current_role,
            user_group=None,
            perimeter_folders=(),
        )
        perimeters_by_assignment: dict[str, list[Folder]] = {
            str(item.id): [] for item in locked_assignments
        }
        for assignment_id, perimeter_id in actual_perimeter_pairs:
            try:
                perimeter = locked_folders[str(perimeter_id)]
            except KeyError as exc:
                raise ValidationError(INVALID_SERVICE_ACCOUNT_IAM_BUNDLE_ERROR) from exc
            perimeters_by_assignment[str(assignment_id)].append(perimeter)
        for assignment in locked_assignments:
            _assert_assignment_allowed(
                folder=assignment.folder,
                role=locked_roles[str(assignment.role_id)],
                user_group=assignment.user_group,
                perimeter_folders=perimeters_by_assignment[str(assignment.id)],
            )

        if len(locked_assignments) != 1:
            raise ValidationError(INVALID_SERVICE_ACCOUNT_IAM_BUNDLE_ERROR)
        role_assignment = locked_assignments[0]
        current_perimeters = perimeters_by_assignment[str(role_assignment.id)]
        _assert_service_account_bundle(
            service_account=locked_service_account,
            role_assignment=role_assignment,
            root_folder=root_folder,
            current_role=current_role,
            perimeter_folders=current_perimeters,
        )

        target_role = current_role
        if role_id is not None:
            target_role = locked_roles[str(role_id)]
            if not target_role.builtin:
                raise ValidationError("Invalid role selection.")
        target_perimeters = current_perimeters
        if folder_ids is not None:
            target_perimeters = [
                locked_folders[str(folder_id)]
                for folder_id in dict.fromkeys(folder_ids)
            ]
        _assert_assignment_allowed(
            folder=root_folder,
            role=target_role,
            user_group=None,
            perimeter_folders=target_perimeters,
        )

        if role_id is not None and permission_ids:
            raise ValidationError("Provide either a role or permissions, not both.")
        permissions_match_current_builtin_role = (
            role_id is None
            and permission_ids is not None
            and current_role.builtin
            and set(permission_ids)
            == set(current_role.permissions.values_list("id", flat=True))
        )
        permissions = None
        if permission_ids is not None and not permissions_match_current_builtin_role:
            permissions = _validated_permissions(permission_ids, for_update=True)

        if name is not None:
            locked_service_account.name = name
            locked_service_account.client.name = name
            locked_service_account.client.save(update_fields=["name"])
        if description is not UNSET:
            locked_service_account.description = description
        if expiry_date is not UNSET:
            locked_service_account.expiry_date = expiry_date
        locked_service_account.save()
        if role_id is not None:
            if target_role.id != locked_service_account.role_id:
                _switch_role(locked_service_account, role_assignment, target_role)
        elif permission_ids is not None:
            if current_role.builtin:
                if not permissions_match_current_builtin_role:
                    _detach_to_dedicated_role(
                        locked_service_account,
                        role_assignment,
                        permissions,
                        root_folder,
                    )
            else:
                locked_service_account.role.permissions.set(permissions)
        if folder_ids is not None:
            role_assignment.perimeter_folders.set(target_perimeters)
        if is_recursive is not None:
            role_assignment.is_recursive = is_recursive
        role_assignment.save()
        if is_active is not UNSET:
            if is_active and not locked_service_account.is_active:
                locked_service_account._activate_locked(locked_user)
            elif not is_active and locked_service_account.is_active:
                locked_service_account._deactivate_locked(locked_user)
    return locked_service_account
