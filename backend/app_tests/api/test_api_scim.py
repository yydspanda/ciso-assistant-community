"""Security regression tests for SCIM 2.0 provisioning and IdP-group inheritance.

These pin the invariants added to harden the feature for release:
  * SCIM only reads/mutates the accounts it provisioned (is_scim_managed),
    and never adopts or rewrites an administrator / local-login account.
  * Only SCIM-managed users can be pulled into an IdP group, so a locally
    managed admin can never inherit admin via a SCIM membership push.
  * Legacy IdP inheritance into a TPRM audit enclave is frozen rather than
    letting SCIM mutate respondent authority or silently repair the mapping.
  * SCIM cannot deactivate the last active administrator.
  * IdP-group role inheritance is gated behind the idp_groups feature flag.
"""

import importlib
import json
from uuid import uuid4

import pytest
from allauth.idp.oidc.models import Client
from django.apps import apps as django_apps
from django.urls import reverse
from knox.models import AuthToken
from rest_framework.test import APIClient

from global_settings import utils as ff_utils
from global_settings.models import GlobalSettings
from global_settings.utils import clear_feature_flags_cache

from core.reserved_iam import MANAGED_TPRM_RESPONDENT_IAM_ERROR
from core.utils import RoleCodename, UserGroupCodename
from iam.models import (
    Folder,
    IdPGroup,
    Role,
    RoleAssignment,
    SCIMToken,
    ServiceAccount,
    User,
    UserGroup,
)

USERS_URL = "/api/scim/v2/Users"
GROUPS_URL = "/api/scim/v2/Groups"


@pytest.fixture(autouse=True)
def _enterprise_flags(monkeypatch):
    """idp_groups is enterprise-only (declared on the EE FeatureFlagsSerializer,
    hence unsupported on CE); these tests exercise the EE-gated behavior from
    the CE test bed."""
    supported = ff_utils.get_supported_feature_flags() | {"idp_groups"}
    monkeypatch.setattr(ff_utils, "get_supported_feature_flags", lambda: supported)


def _set_idp_groups_flag(enabled: bool):
    ff, _ = GlobalSettings.objects.get_or_create(
        name=GlobalSettings.Names.FEATURE_FLAGS
    )
    ff.value = {**(ff.value or {}), "idp_groups": enabled}
    ff.save()
    # Direct ORM write: bypasses the serializer, the single invalidation point.
    clear_feature_flags_cache()


@pytest.fixture
def enable_idp_groups(app_config):
    _set_idp_groups_flag(True)


def _scim_client():
    """A client authenticated with a genuine SCIM bearer token (Knox token
    wrapped in a SCIMToken). The owner is a non-admin so it does not affect
    admin-count assertions."""
    owner = User.objects.create_user("scim-bot@tests.com", is_published=True)
    instance, token = AuthToken.objects.create(user=owner)
    SCIMToken.objects.create(auth_token=instance, name="test")
    client = APIClient()
    client.credentials(HTTP_AUTHORIZATION=f"Bearer {token}")
    return client


def _scim_user(email, external_id):
    # create_user only persists a whitelist of fields, so set the SCIM markers
    # explicitly. is_scim_managed is what marks the account as SCIM-owned;
    # external_id is optional (RFC 7643) and kept here for realism.
    user = User.objects.create_user(email, is_published=True)
    user.scim_external_id = external_id
    user.is_scim_managed = True
    user.save(update_fields=["scim_external_id", "is_scim_managed"])
    return user


def _admin_group():
    return UserGroup.objects.get(name="BI-UG-ADM")


def _attach_service_account(user):
    """Create only the reverse machine-principal identity needed by the guard."""

    identifier = f"scim-guard-{uuid4().hex}"
    client = Client(
        id=identifier,
        name=identifier,
        type=Client.Type.CONFIDENTIAL,
        grant_types=Client.GrantType.CLIENT_CREDENTIALS,
        scopes="",
        response_types="",
        owner=user,
    )
    client.set_secret("test-only-service-account-secret")
    client.save()
    return ServiceAccount.objects.create(
        name=identifier,
        client=client,
        user=user,
        role=Role.objects.get(name=RoleCodename.READER.value),
    )


def _legacy_tprm_idp_mapping(*, member=None):
    """Create pre-guard damage without using a current application writer."""

    enclave = Folder.objects.create(
        name="Legacy SCIM respondent enclave",
        content_type=Folder.ContentType.ENCLAVE,
        parent_folder=Folder.get_root_folder(),
    )
    respondent_group = UserGroup.objects.create(
        name=UserGroupCodename.THIRD_PARTY_RESPONDENT.value,
        folder=enclave,
        builtin=True,
    )
    assignment = RoleAssignment.objects.create(
        user_group=respondent_group,
        role=Role.objects.get(name=RoleCodename.THIRD_PARTY_RESPONDENT.value),
        folder=enclave,
        builtin=True,
        is_recursive=True,
    )
    assignment.perimeter_folders.add(enclave)
    idp_group = IdPGroup.objects.create(name="legacy-tprm-idp")
    # Direct through-table setup models an installation that predates the
    # serializer guard.  No supported current writer can create this mapping.
    mapping_field = IdPGroup._meta.get_field("user_groups")
    mapping_through = mapping_field.remote_field.through
    mapping_through.objects.create(
        **{
            f"{mapping_field.m2m_field_name()}_id": idp_group.id,
            f"{mapping_field.m2m_reverse_field_name()}_id": respondent_group.id,
        }
    )
    if member is not None:
        idp_group.users.add(member)
    return idp_group, respondent_group, assignment


@pytest.mark.django_db
class TestSCIMAuthentication:
    def test_unauthenticated_is_rejected(self, enable_idp_groups):
        assert APIClient().get(USERS_URL).status_code == 401

    def test_non_scim_token_is_rejected(self, enable_idp_groups):
        # A valid Knox token that is NOT a SCIM token must not reach SCIM.
        user = User.objects.create_user("plain@tests.com", is_published=True)
        _, token = AuthToken.objects.create(user=user)
        client = APIClient()
        client.credentials(HTTP_AUTHORIZATION=f"Bearer {token}")
        assert client.get(USERS_URL).status_code == 403

    def test_flag_off_is_forbidden(self, app_config):
        _set_idp_groups_flag(False)
        assert _scim_client().get(USERS_URL).status_code == 403


@pytest.mark.django_db
class TestSCIMOwnershipInvariant:
    def test_list_returns_only_scim_managed_users(self, enable_idp_groups):
        _scim_user("provisioned@tests.com", "ext-1")
        User.objects.create_user("local@tests.com", is_published=True)  # not SCIM
        resp = _scim_client().get(USERS_URL)
        assert resp.status_code == 200
        emails = {r["userName"] for r in json.loads(resp.content)["Resources"]}
        assert emails == {"provisioned@tests.com"}

    def test_provisioning_without_external_id_stays_manageable(self, enable_idp_groups):
        # externalId is optional (RFC 7643 §3.1). A user provisioned without one
        # must still be SCIM-managed: listed, retrievable and PATCH/DELETE-able.
        client = _scim_client()
        created = client.post(
            USERS_URL,
            data={"userName": "noext@tests.com", "active": True},
            format="json",
        )
        assert created.status_code == 201
        uid = json.loads(created.content)["id"]

        user = User.objects.get(email="noext@tests.com")
        assert user.scim_external_id is None
        assert user.is_scim_managed is True

        # listed
        listed = json.loads(client.get(USERS_URL).content)["Resources"]
        assert "noext@tests.com" in {r["userName"] for r in listed}

        # retrievable + PATCH-addressable (not a 404)
        assert client.get(f"{USERS_URL}/{uid}").status_code == 200
        patched = client.patch(
            f"{USERS_URL}/{uid}",
            data={"Operations": [{"op": "replace", "path": "active", "value": False}]},
            format="json",
        )
        assert patched.status_code == 200
        user.refresh_from_db()
        assert user.is_active is False

        # DELETE-addressable
        assert client.delete(f"{USERS_URL}/{uid}").status_code == 204

    def test_create_refuses_to_adopt_an_admin(self, enable_idp_groups):
        admin = User.objects.create_user("boss@tests.com", is_published=True)
        _admin_group().user_set.add(admin)
        resp = _scim_client().post(
            USERS_URL,
            data={"userName": "boss@tests.com", "active": False},
            format="json",
        )
        assert resp.status_code == 409
        admin.refresh_from_db()
        assert admin.is_active is True
        assert admin.scim_external_id is None

    def test_create_refuses_to_adopt_a_local_login_account(self, enable_idp_groups):
        User.objects.create_user(
            "keeplocal@tests.com", is_published=True, keep_local_login=True
        )
        resp = _scim_client().post(
            USERS_URL, data={"userName": "keeplocal@tests.com"}, format="json"
        )
        assert resp.status_code == 409

    def test_external_id_cannot_adopt_or_mutate_a_superuser(
        self, enable_idp_groups
    ):
        protected = User.objects.create_superuser(
            "protected-root@tests.com", is_published=True
        )
        protected.scim_external_id = "external-protected-root"
        protected.save(update_fields=["scim_external_id"])
        client = _scim_client()

        adopted = client.post(
            USERS_URL,
            data={
                "externalId": "external-protected-root",
                "userName": "renamed-root@tests.com",
                "active": False,
            },
            format="json",
        )

        assert adopted.status_code == 409
        protected.refresh_from_db()
        assert protected.email == "protected-root@tests.com"
        assert protected.is_active is True
        assert protected.is_scim_managed is False

        # Model legacy corruption explicitly: even if the ownership marker was
        # set by an old/direct writer, SCIM must fail closed rather than repair
        # or mutate a superuser.
        User.objects.filter(id=protected.id).update(is_scim_managed=True)
        patched = client.patch(
            f"{USERS_URL}/{protected.id}",
            data={"Operations": [{"op": "replace", "path": "active", "value": False}]},
            format="json",
        )
        deleted = client.delete(f"{USERS_URL}/{protected.id}")
        assert patched.status_code == 409
        assert deleted.status_code == 409
        protected.refresh_from_db()
        assert protected.is_active is True

    def test_external_id_cannot_adopt_or_mutate_a_service_account(
        self, enable_idp_groups
    ):
        protected = User.objects.create_user(
            "protected-machine@tests.com", is_published=True
        )
        protected.scim_external_id = "external-protected-machine"
        protected.save(update_fields=["scim_external_id"])
        service_account = _attach_service_account(protected)
        client = _scim_client()

        adopted = client.post(
            USERS_URL,
            data={
                "externalId": "external-protected-machine",
                "userName": "renamed-machine@tests.com",
                "active": False,
            },
            format="json",
        )

        assert adopted.status_code == 409
        protected.refresh_from_db()
        assert protected.email == "protected-machine@tests.com"
        assert protected.is_active is True
        assert protected.is_scim_managed is False

        User.objects.filter(id=protected.id).update(is_scim_managed=True)
        patched = client.patch(
            f"{USERS_URL}/{protected.id}",
            data={"Operations": [{"op": "replace", "path": "active", "value": False}]},
            format="json",
        )
        deleted = client.delete(f"{USERS_URL}/{protected.id}")
        assert patched.status_code == 409
        assert deleted.status_code == 409
        protected.refresh_from_db()
        assert protected.is_active is True
        assert ServiceAccount.objects.filter(id=service_account.id).exists()

    def test_create_adopts_a_plain_local_account(self, enable_idp_groups):
        User.objects.create_user("joiner@tests.com", is_published=True)
        resp = _scim_client().post(
            USERS_URL,
            data={"userName": "joiner@tests.com", "externalId": "ext-99"},
            format="json",
        )
        assert resp.status_code == 200
        adopted = User.objects.get(email="joiner@tests.com")
        assert adopted.is_scim_managed is True
        assert adopted.scim_external_id == "ext-99"

    def test_adopted_account_can_have_its_email_changed_by_scim(
        self, enable_idp_groups
    ):
        """SCIM may freely redirect an adopted account's email — on the same
        request or a later one — because is_local closes the actual
        exploitation surface (local login / password-reset) regardless."""
        User.objects.create_user("joiner2@tests.com", is_published=True)
        client = _scim_client()
        first = client.post(
            USERS_URL,
            data={
                "userName": "joiner2@tests.com",
                "emails": [{"value": "new-address@tests.com", "primary": True}],
            },
            format="json",
        )
        assert first.status_code == 200
        user = User.objects.get(id=json.loads(first.content)["id"])
        assert user.email == "new-address@tests.com"

    def test_adopted_account_loses_local_login_regardless_of_email_changes(
        self, enable_idp_groups
    ):
        """The real security boundary: once is_scim_managed, is_local is
        False (unless keep_local_login), so no email SCIM puts on the
        account ever re-opens local password login or password-reset."""
        User.objects.create_user("joiner3@tests.com", is_published=True)
        resp = _scim_client().post(
            USERS_URL,
            data={
                "userName": "joiner3@tests.com",
                "emails": [{"value": "attacker@evil.test", "primary": True}],
            },
            format="json",
        )
        assert resp.status_code == 200
        user = User.objects.get(id=json.loads(resp.content)["id"])
        assert user.email == "attacker@evil.test"
        assert user.is_local is False

    def test_cannot_patch_a_non_scim_user(self, enable_idp_groups):
        local = User.objects.create_user("local@tests.com", is_published=True)
        resp = _scim_client().patch(
            f"{USERS_URL}/{local.id}",
            data={"Operations": [{"op": "replace", "path": "active", "value": False}]},
            format="json",
        )
        assert resp.status_code == 404
        local.refresh_from_db()
        assert local.is_active is True


@pytest.mark.django_db
class TestSCIMGroupMembershipEscalation:
    def test_non_scim_user_cannot_be_added_to_a_group(self, enable_idp_groups):
        local_admin = User.objects.create_user("victim@tests.com", is_published=True)
        resp = _scim_client().post(
            GROUPS_URL,
            data={
                "displayName": "engineers",
                "members": [{"value": str(local_admin.id)}],
            },
            format="json",
        )
        assert resp.status_code == 201
        idp_group = IdPGroup.objects.get(name="engineers")
        # The locally-managed user is dropped: it never becomes a member.
        assert idp_group.users.count() == 0

    def test_scim_user_inherits_admin_via_mapped_group(self, enable_idp_groups):
        member = _scim_user("eng@tests.com", "ext-eng")
        idp_group = IdPGroup.objects.create(name="admins-idp")
        idp_group.user_groups.add(_admin_group())  # admin maps the group
        resp = _scim_client().patch(
            f"{GROUPS_URL}/{idp_group.id}",
            data={
                "Operations": [
                    {
                        "op": "add",
                        "path": "members",
                        "value": [{"value": str(member.id)}],
                    }
                ]
            },
            format="json",
        )
        assert resp.status_code == 200
        assert idp_group.users.filter(pk=member.pk).exists()
        assert member.is_admin() is True

    @pytest.mark.parametrize(
        "operation",
        [
            {
                "op": "add",
                "path": "members",
                "value": [{"value": "{candidate}"}],
            },
            {
                "op": "remove",
                "path": "members",
                "value": [{"value": "{existing}"}],
            },
            {
                "op": "replace",
                "path": "members",
                "value": [{"value": "{candidate}"}],
            },
            {"op": "remove", "path": "members"},
        ],
        ids=("add", "remove", "set", "clear"),
    )
    def test_legacy_tprm_mapping_rejects_every_patch_membership_mutation(
        self, enable_idp_groups, operation
    ):
        existing = _scim_user("legacy-member@tests.com", "ext-legacy")
        candidate = _scim_user("candidate-member@tests.com", "ext-candidate")
        idp_group, _respondent_group, _assignment = _legacy_tprm_idp_mapping(
            member=existing
        )
        operation = json.loads(
            json.dumps(operation)
            .replace("{existing}", str(existing.id))
            .replace("{candidate}", str(candidate.id))
        )

        response = _scim_client().patch(
            f"{GROUPS_URL}/{idp_group.id}",
            data={"Operations": [operation]},
            format="json",
        )

        assert response.status_code == 409
        assert response.json()["detail"] == MANAGED_TPRM_RESPONDENT_IAM_ERROR
        assert response.json()["scimType"] == "mutability"
        assert set(idp_group.users.values_list("id", flat=True)) == {existing.id}

    def test_legacy_tprm_mapping_rejects_put_and_group_delete(
        self, enable_idp_groups
    ):
        existing = _scim_user("legacy-put-member@tests.com", "ext-legacy-put")
        idp_group, respondent_group, assignment = _legacy_tprm_idp_mapping(
            member=existing
        )
        client = _scim_client()

        replaced = client.put(
            f"{GROUPS_URL}/{idp_group.id}",
            data={"displayName": idp_group.name, "members": []},
            format="json",
        )
        deleted = client.delete(f"{GROUPS_URL}/{idp_group.id}")

        assert replaced.status_code == 409
        assert deleted.status_code == 409
        assert IdPGroup.objects.filter(id=idp_group.id).exists()
        assert UserGroup.objects.filter(id=respondent_group.id).exists()
        assert RoleAssignment.objects.filter(id=assignment.id).exists()
        assert set(idp_group.users.values_list("id", flat=True)) == {existing.id}

    def test_existing_legacy_tprm_group_cannot_be_reused_by_scim_post(
        self, enable_idp_groups
    ):
        candidate = _scim_user("legacy-post-member@tests.com", "ext-legacy-post")
        idp_group, _respondent_group, _assignment = _legacy_tprm_idp_mapping()

        response = _scim_client().post(
            GROUPS_URL,
            data={
                "displayName": idp_group.name,
                "members": [{"value": str(candidate.id)}],
            },
            format="json",
        )

        assert response.status_code == 409
        assert not idp_group.users.filter(id=candidate.id).exists()

    def test_legacy_external_group_perimeter_into_enclave_is_also_frozen(
        self, enable_idp_groups
    ):
        enclave = Folder.objects.create(
            name="Legacy external perimeter enclave",
            content_type=Folder.ContentType.ENCLAVE,
            parent_folder=Folder.get_root_folder(),
        )
        external_group = UserGroup.objects.create(
            name="legacy-external-idp-target",
            folder=Folder.get_root_folder(),
        )
        assignment = RoleAssignment.objects.create(
            user_group=external_group,
            role=Role.objects.get(name=RoleCodename.READER.value),
            folder=Folder.get_root_folder(),
        )
        assignment.perimeter_folders.add(enclave)
        idp_group = IdPGroup.objects.create(name="legacy-external-perimeter-idp")
        idp_group.user_groups.add(external_group)
        candidate = _scim_user(
            "legacy-external-candidate@tests.com", "ext-external-candidate"
        )

        response = _scim_client().patch(
            f"{GROUPS_URL}/{idp_group.id}",
            data={
                "Operations": [
                    {
                        "op": "add",
                        "path": "members",
                        "value": [{"value": str(candidate.id)}],
                    }
                ]
            },
            format="json",
        )

        assert response.status_code == 409
        assert response.json()["detail"] == MANAGED_TPRM_RESPONDENT_IAM_ERROR
        assert not idp_group.users.filter(id=candidate.id).exists()


@pytest.mark.django_db
class TestSCIMProtectedGroupPrincipals:
    @staticmethod
    def _machine_user(email="group-machine@tests.com", external_id="group-machine"):
        user = _scim_user(email, external_id)
        _attach_service_account(user)
        return user

    def test_create_with_managed_superuser_is_rejected_without_prefix_group(
        self, enable_idp_groups
    ):
        protected = User.objects.create_superuser(
            "group-root@tests.com", is_published=True
        )
        User.objects.filter(id=protected.id).update(
            is_scim_managed=True,
            scim_external_id="group-root",
        )

        response = _scim_client().post(
            GROUPS_URL,
            data={
                "displayName": "must-not-survive-protected-create",
                "members": [{"value": str(protected.id)}],
            },
            format="json",
        )

        assert response.status_code == 409
        assert response.json()["scimType"] == "mutability"
        assert not IdPGroup.objects.filter(
            name="must-not-survive-protected-create"
        ).exists()

    def test_add_service_account_rejects_entire_patch_before_rename(
        self, enable_idp_groups
    ):
        protected = self._machine_user()
        idp_group = IdPGroup.objects.create(name="protected-add-original")

        response = _scim_client().patch(
            f"{GROUPS_URL}/{idp_group.id}",
            data={
                "Operations": [
                    {
                        "op": "replace",
                        "path": "displayName",
                        "value": "protected-add-renamed",
                    },
                    {
                        "op": "add",
                        "path": "members",
                        "value": [{"value": str(protected.id)}],
                    },
                ]
            },
            format="json",
        )

        assert response.status_code == 409
        idp_group.refresh_from_db()
        assert idp_group.name == "protected-add-original"
        assert not idp_group.users.exists()

    @pytest.mark.parametrize("operation", ["remove", "clear"])
    def test_current_service_account_blocks_remove_and_clear(
        self, enable_idp_groups, operation
    ):
        protected = self._machine_user(
            email=f"group-machine-{operation}@tests.com",
            external_id=f"group-machine-{operation}",
        )
        idp_group = IdPGroup.objects.create(name=f"protected-{operation}")
        idp_group.users.add(protected)
        patch_operation = {
            "op": "remove",
            "path": "members",
        }
        if operation == "remove":
            patch_operation["value"] = [{"value": str(protected.id)}]

        response = _scim_client().patch(
            f"{GROUPS_URL}/{idp_group.id}",
            data={"Operations": [patch_operation]},
            format="json",
        )

        assert response.status_code == 409
        assert idp_group.users.filter(id=protected.id).exists()

    def test_put_with_service_account_rejects_rename_and_replace(
        self, enable_idp_groups
    ):
        existing = _scim_user("protected-put-existing@tests.com", "protected-put")
        protected = self._machine_user(
            "protected-put-machine@tests.com", "protected-put-machine"
        )
        idp_group = IdPGroup.objects.create(name="protected-put-original")
        idp_group.users.add(existing)

        response = _scim_client().put(
            f"{GROUPS_URL}/{idp_group.id}",
            data={
                "displayName": "protected-put-renamed",
                "members": [{"value": str(protected.id)}],
            },
            format="json",
        )

        assert response.status_code == 409
        idp_group.refresh_from_db()
        assert idp_group.name == "protected-put-original"
        assert set(idp_group.users.values_list("id", flat=True)) == {existing.id}

    def test_delete_with_current_service_account_is_rejected(
        self, enable_idp_groups
    ):
        protected = self._machine_user(
            "protected-delete-machine@tests.com", "protected-delete-machine"
        )
        idp_group = IdPGroup.objects.create(name="protected-delete")
        idp_group.users.add(protected)

        response = _scim_client().delete(f"{GROUPS_URL}/{idp_group.id}")

        assert response.status_code == 409
        assert IdPGroup.objects.filter(id=idp_group.id).exists()
        assert idp_group.users.filter(id=protected.id).exists()


@pytest.mark.django_db
class TestIdPGroupMappingReservedTprmAuthority:
    @staticmethod
    def _legacy_external_group_with_enclave_perimeter():
        root = Folder.get_root_folder()
        enclave = Folder.objects.create(
            name="Legacy proposed-mapping enclave",
            content_type=Folder.ContentType.ENCLAVE,
            parent_folder=root,
        )
        group = UserGroup.objects.create(
            name="legacy-proposed-mapping-target",
            folder=root,
        )
        assignment = RoleAssignment.objects.create(
            user_group=group,
            role=Role.objects.get(name=RoleCodename.READER.value),
            folder=root,
            is_recursive=False,
        )
        assignment.perimeter_folders.add(enclave)
        return enclave, group, assignment

    def test_preflight_then_update_cannot_activate_unmapped_legacy_assignment(
        self, enable_idp_groups, authenticated_client
    ):
        _enclave, group, assignment = (
            self._legacy_external_group_with_enclave_perimeter()
        )
        migration = importlib.import_module(
            "iam.migrations.0029_preflight_idp_tprm_enclave_inheritance"
        )
        # The preflight correctly passes before any IdP mapping exists.  The
        # runtime proposed-mapping guard must close the later activation path.
        migration.reject_idp_tprm_enclave_inheritance(django_apps, None)
        member = _scim_user("proposed-map-member@tests.com", "ext-proposed-map")
        idp_group = IdPGroup.objects.create(name="preflight-passed-idp")
        idp_group.users.add(member)

        response = authenticated_client.patch(
            reverse("idp-groups-detail", args=[idp_group.id]),
            {"user_groups": [str(group.id)]},
            format="json",
        )

        assert response.status_code == 403
        assert response.json()["error"] == MANAGED_TPRM_RESPONDENT_IAM_ERROR
        assert not idp_group.user_groups.exists()
        assert idp_group.users.filter(id=member.id).exists()
        assert assignment.perimeter_folders.exists()

    def test_create_cannot_map_a_legacy_group_into_reserved_authority(
        self, enable_idp_groups, authenticated_client
    ):
        _enclave, group, _assignment = (
            self._legacy_external_group_with_enclave_perimeter()
        )

        response = authenticated_client.post(
            reverse("idp-groups-list"),
            {
                "name": "rejected-dangerous-idp-create",
                "folder": str(Folder.get_root_folder_id()),
                "user_groups": [str(group.id)],
            },
            format="json",
        )

        assert response.status_code == 403
        assert response.json()["error"] == MANAGED_TPRM_RESPONDENT_IAM_ERROR
        assert not IdPGroup.objects.filter(
            name="rejected-dangerous-idp-create"
        ).exists()

    def test_update_cannot_activate_respondent_role_on_ordinary_group(
        self, enable_idp_groups, authenticated_client
    ):
        root = Folder.get_root_folder()
        group = UserGroup.objects.create(
            name="legacy-respondent-role-target",
            folder=root,
        )
        assignment = RoleAssignment.objects.create(
            user_group=group,
            role=Role.objects.get(name=RoleCodename.THIRD_PARTY_RESPONDENT.value),
            folder=root,
            is_recursive=True,
        )
        assignment.perimeter_folders.add(root)
        idp_group = IdPGroup.objects.create(name="respondent-role-proposed-idp")

        response = authenticated_client.patch(
            reverse("idp-groups-detail", args=[idp_group.id]),
            {"user_groups": [str(group.id)]},
            format="json",
        )

        assert response.status_code == 403
        assert response.json()["error"] == MANAGED_TPRM_RESPONDENT_IAM_ERROR
        assert not idp_group.user_groups.exists()

    def test_parent_domain_recursive_assignment_remains_mappable(
        self, enable_idp_groups, authenticated_client
    ):
        root = Folder.get_root_folder()
        parent = Folder.objects.create(
            name="Ordinary IdP parent domain",
            content_type=Folder.ContentType.DOMAIN,
            parent_folder=root,
        )
        Folder.objects.create(
            name="Descendant audit enclave outside the assignment perimeter",
            content_type=Folder.ContentType.ENCLAVE,
            parent_folder=parent,
        )
        group = UserGroup.objects.create(name="ordinary-parent-group", folder=parent)
        assignment = RoleAssignment.objects.create(
            user_group=group,
            role=Role.objects.get(name=RoleCodename.READER.value),
            folder=parent,
            is_recursive=True,
        )
        assignment.perimeter_folders.add(parent)

        response = authenticated_client.post(
            reverse("idp-groups-list"),
            {
                "name": "allowed-parent-recursive-idp",
                "folder": str(root.id),
                "user_groups": [str(group.id)],
            },
            format="json",
        )

        assert response.status_code == 201, response.content
        created = IdPGroup.objects.get(name="allowed-parent-recursive-idp")
        assert set(created.user_groups.values_list("id", flat=True)) == {group.id}

    def test_generic_delete_freezes_an_existing_damaged_mapping(
        self, enable_idp_groups, authenticated_client
    ):
        _enclave, group, _assignment = (
            self._legacy_external_group_with_enclave_perimeter()
        )
        idp_group = IdPGroup.objects.create(name="damaged-generic-delete-idp")
        idp_group.user_groups.add(group)

        response = authenticated_client.delete(
            reverse("idp-groups-detail", args=[idp_group.id])
        )

        assert response.status_code == 403
        assert response.json()["error"] == MANAGED_TPRM_RESPONDENT_IAM_ERROR
        assert IdPGroup.objects.filter(id=idp_group.id).exists()
        assert idp_group.user_groups.filter(id=group.id).exists()

    def test_user_delete_cannot_cascade_repair_a_damaged_idp_mapping(
        self, enable_idp_groups, authenticated_client
    ):
        _enclave, group, assignment = (
            self._legacy_external_group_with_enclave_perimeter()
        )
        member = User.objects.create_user(
            "damaged-idp-member@tests.com", is_published=True
        )
        idp_group = IdPGroup.objects.create(name="damaged-user-delete-idp")
        idp_group.user_groups.add(group)
        idp_group.users.add(member)

        response = authenticated_client.delete(
            reverse("users-detail", args=[member.id])
        )

        assert response.status_code == 403
        assert response.json()["error"] == MANAGED_TPRM_RESPONDENT_IAM_ERROR
        assert User.objects.filter(id=member.id).exists()
        assert idp_group.users.filter(id=member.id).exists()
        assert idp_group.user_groups.filter(id=group.id).exists()
        assert assignment.perimeter_folders.exists()

    def test_user_group_delete_cannot_cascade_repair_reserved_assignment(
        self, enable_idp_groups, authenticated_client
    ):
        _enclave, group, assignment = (
            self._legacy_external_group_with_enclave_perimeter()
        )
        idp_group = IdPGroup.objects.create(name="damaged-group-delete-idp")
        idp_group.user_groups.add(group)

        response = authenticated_client.delete(
            reverse("user-groups-detail", args=[group.id])
        )

        assert response.status_code == 403
        assert response.json()["error"] == MANAGED_TPRM_RESPONDENT_IAM_ERROR
        assert UserGroup.objects.filter(id=group.id).exists()
        assert RoleAssignment.objects.filter(id=assignment.id).exists()
        assert assignment.perimeter_folders.exists()
        assert idp_group.user_groups.filter(id=group.id).exists()


@pytest.mark.django_db
class TestSCIMLastAdminGuard:
    def test_cannot_deactivate_the_last_admin(self, enable_idp_groups):
        admin = _scim_user("solo-admin@tests.com", "ext-solo")
        _admin_group().user_set.add(admin)
        resp = _scim_client().delete(f"{USERS_URL}/{admin.id}")
        assert resp.status_code == 409
        admin.refresh_from_db()
        assert admin.is_active is True

    def test_can_deactivate_a_non_last_admin(self, enable_idp_groups):
        a = _scim_user("admin-a@tests.com", "ext-a")
        b = _scim_user("admin-b@tests.com", "ext-b")
        _admin_group().user_set.add(a, b)
        resp = _scim_client().delete(f"{USERS_URL}/{a.id}")
        assert resp.status_code == 204
        a.refresh_from_db()
        assert a.is_active is False

    def test_patch_cannot_deactivate_last_admin(self, enable_idp_groups):
        admin = _scim_user("solo-admin@tests.com", "ext-solo")
        _admin_group().user_set.add(admin)
        resp = _scim_client().patch(
            f"{USERS_URL}/{admin.id}",
            data={"Operations": [{"op": "replace", "path": "active", "value": False}]},
            format="json",
        )
        assert resp.status_code == 409
        admin.refresh_from_db()
        assert admin.is_active is True

    def test_put_cannot_deactivate_last_admin(self, enable_idp_groups):
        admin = _scim_user("solo-admin@tests.com", "ext-solo")
        _admin_group().user_set.add(admin)
        resp = _scim_client().put(
            f"{USERS_URL}/{admin.id}",
            data={"userName": "solo-admin@tests.com", "active": False},
            format="json",
        )
        assert resp.status_code == 409
        admin.refresh_from_db()
        assert admin.is_active is True


@pytest.mark.django_db
class TestSCIMDisplayNameValidation:
    """Unit-level tests for _display_name_error, which guards all group
    endpoints against names that won't fit IdPGroup.name."""

    def test_rejects_too_long_name(self, enable_idp_groups):
        from iam.scim.views import _display_name_error

        max_len = IdPGroup._meta.get_field("name").max_length
        assert _display_name_error("x" * max_len) is None
        resp = _display_name_error("x" * (max_len + 1))
        assert resp is not None
        assert resp.status_code == 400

    def test_rejects_non_string(self, enable_idp_groups):
        from iam.scim.views import _display_name_error

        resp = _display_name_error(12345)
        assert resp is not None
        assert resp.status_code == 400

    def test_accepts_none(self, enable_idp_groups):
        from iam.scim.views import _display_name_error

        assert _display_name_error(None) is None


@pytest.mark.django_db
class TestIdPGroupsFlagGating:
    def test_flag_toggle_revokes_inherited_admin(self, app_config):
        _set_idp_groups_flag(True)
        member = _scim_user("inherits@tests.com", "ext-i")
        idp_group = IdPGroup.objects.create(name="admins-idp")
        idp_group.user_groups.add(_admin_group())
        idp_group.users.add(member)
        assert member.is_admin() is True
        assert member in User.get_admin_users()

        _set_idp_groups_flag(False)
        assert member.is_admin() is False
        assert member not in User.get_admin_users()
