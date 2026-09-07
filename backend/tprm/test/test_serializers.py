from unittest.mock import patch, MagicMock, PropertyMock

from django.test import TestCase
from django.contrib.auth import get_user_model
from django.db import transaction
from rest_framework.exceptions import PermissionDenied, ValidationError

from core.models import (
    ComplianceAssessment,
    Evidence,
    Framework,
    Perimeter,
    RequirementAssignment,
    ValidationFlow,
)
from core.relation_locking import lock_rows_in_global_model_order
from core.utils import RoleCodename, UserGroupCodename
from iam.models import Folder, IdPGroup, Role, RoleAssignment, UserGroup
from pmbok.models import GenericCollection
from tprm.models import Entity, EntityAssessment, Representative, Solution
from tprm.serializers import (
    EntityReadSerializer,
    EntityWriteSerializer,
    EntityImportExportSerializer,
    EntityAssessmentReadSerializer,
    EntityAssessmentWriteSerializer,
    RepresentativeReadSerializer,
    RepresentativeWriteSerializer,
    SolutionReadSerializer,
    SolutionWriteSerializer,
)

User = get_user_model()


class EntitySerializersTestCase(TestCase):
    """Tests for Entity-related serializers"""

    def setUp(self):
        self.folder = Folder.objects.create(name="Test Folder")
        self.entity_data = {
            "name": "Test Entity",
            "description": "Entity description",
            "mission": "Entity mission",
            "reference_link": "https://example.com",
            "folder": self.folder,
        }
        self.entity = Entity.objects.create(**self.entity_data)
        self.owned_folder = Folder.objects.create(name="Owned Folder")
        self.entity.owned_folders.add(self.owned_folder)

    def test_entity_read_serializer(self):
        """Test that EntityReadSerializer correctly serializes an Entity"""
        serializer = EntityReadSerializer(self.entity)
        data = serializer.data

        self.assertEqual(data["name"], self.entity_data["name"])
        self.assertEqual(data["description"], self.entity_data["description"])
        self.assertEqual(data["mission"], self.entity_data["mission"])
        self.assertEqual(data["reference_link"], self.entity_data["reference_link"])
        self.assertIn("folder", data)
        self.assertIn("owned_folders", data)

    def test_entity_write_serializer(self):
        """Test that EntityWriteSerializer correctly creates an Entity"""
        new_entity_data = {
            "name": "New Entity",
            "description": "New description",
            "mission": "New mission",
            "reference_link": "https://newexample.com",
            "folder": self.folder.id,
        }

        mock_request = MagicMock()
        mock_user = MagicMock()
        mock_request.user = mock_user

        with patch("iam.models.RoleAssignment.is_access_allowed", return_value=True):
            serializer = EntityWriteSerializer(
                data=new_entity_data, context={"request": mock_request}
            )
            self.assertTrue(serializer.is_valid())
            entity = serializer.save()

        self.assertEqual(entity.name, new_entity_data["name"])
        self.assertEqual(entity.description, new_entity_data["description"])
        self.assertEqual(entity.mission, new_entity_data["mission"])
        self.assertEqual(entity.reference_link, new_entity_data["reference_link"])
        self.assertEqual(entity.folder, self.folder)

    def test_entity_import_export_serializer(self):
        """Test that EntityImportExportSerializer correctly serializes an Entity for import/export"""
        serializer = EntityImportExportSerializer(self.entity)
        data = serializer.data

        self.assertEqual(data["name"], self.entity_data["name"])
        self.assertEqual(data["description"], self.entity_data["description"])
        self.assertEqual(data["mission"], self.entity_data["mission"])
        self.assertEqual(data["reference_link"], self.entity_data["reference_link"])
        self.assertIn("folder", data)
        self.assertIn("owned_folders", data)
        self.assertIn("created_at", data)
        self.assertIn("updated_at", data)


class EntityAssessmentSerializersTestCase(TestCase):
    """Tests for EntityAssessment-related serializers"""

    def setUp(self):
        self.folder = Folder.objects.create(name="Test Folder")
        self.perimeter_folder = Folder.objects.create(name="Perimeter Folder")
        self.perimeter = Perimeter.objects.create(
            name="Test Perimeter", folder=self.perimeter_folder
        )
        self.entity = Entity.objects.create(name="Test Entity", folder=self.folder)

        self.framework = Framework.objects.create(
            name="Test Framework", min_score=0, max_score=100
        )

        self.assessment = EntityAssessment.objects.create(
            name="Test Assessment",
            entity=self.entity,
            folder=self.folder,
            perimeter=self.perimeter,
        )

        self.user = User.objects.create_user(
            email="test@example.com", password="password"
        )
        self.assessment.authors.add(self.user.actor)
        self.assessment.reviewers.add(self.user.actor)

        self.solution = Solution.objects.create(
            name="Test Solution", provider_entity=self.entity
        )
        self.assessment.solutions.add(self.solution)

        self.representative = User.objects.create_user(
            email="rep@example.com", password="password", is_third_party=True
        )
        Representative.objects.create(
            email=self.representative.email,
            entity=self.entity,
            user=self.representative,
        )
        self.assessment.representatives.add(self.representative)

    def _make_representative_user(self, email, *, entity=None):
        user = User.objects.create_user(
            email=email,
            password="password",
            is_third_party=True,
        )
        Representative.objects.create(
            email=email,
            entity=entity or self.entity,
            user=user,
        )
        return user

    def test_entity_assessment_read_serializer(self):
        """Test that EntityAssessmentReadSerializer correctly serializes an EntityAssessment"""
        serializer = EntityAssessmentReadSerializer(self.assessment)
        data = serializer.data

        self.assertEqual(data["name"], "Test Assessment")
        self.assertIn("entity", data)
        self.assertIn("folder", data)
        self.assertIn("perimeter", data)
        self.assertIn("solutions", data)
        self.assertIn("representatives", data)
        self.assertIn("authors", data)
        self.assertIn("reviewers", data)

    # The use of Audit for testing this methode create a mess bc of the databases, become a test with too many patch and mock
    @patch("core.models.ComplianceAssessment.objects.create")
    @patch("iam.models.Folder.objects.create")
    @patch.object(EntityAssessment, "compliance_assessment", new_callable=PropertyMock)
    @patch(
        "tprm.serializers.EntityAssessmentWriteSerializer._assign_third_party_respondents"
    )
    @patch(
        "tprm.serializers.EntityAssessmentWriteSerializer._create_requirement_assignment"
    )
    def test_entity_assessment_write_serializer_with_audit(
        self,
        mock_create_requirement_assignment,
        mock_assign_third_party,
        mock_compliance_assessment,
        mock_folder_create,
        mock_audit_create,
    ):
        """Test that EntityAssessmentWriteSerializer correctly creates an EntityAssessment with audit"""
        mock_enclave_folder = MagicMock()
        mock_folder_create.return_value = mock_enclave_folder

        mock_audit = MagicMock(spec=ComplianceAssessment)
        mock_audit._state = MagicMock()
        mock_audit.folder = mock_enclave_folder
        mock_audit_create.return_value = mock_audit

        mock_compliance_assessment.return_value = mock_audit

        data = {
            "name": "New Assessment",
            "entity": self.entity.id,
            "folder": self.perimeter_folder.id,
            "perimeter": self.perimeter.id,
            "create_audit": True,
            "framework": self.framework.id,
            "selected_implementation_groups": ["group1", "group2"],
        }
        with (
            patch("iam.models.RoleAssignment.is_access_allowed", return_value=True),
            patch(
                "tprm.serializers.RoleAssignment.get_viewable_object_ids",
                side_effect=self._all_model_ids,
            ),
            patch.object(
                EntityAssessmentWriteSerializer,
                "_assert_audit_owner_coherence",
            ),
        ):
            serializer = EntityAssessmentWriteSerializer(
                data=data, context={"request": MagicMock()}
            )
            self.assertTrue(serializer.is_valid())
            serializer.save()

        mock_audit_create.assert_called_once()
        self.assertEqual(mock_audit_create.call_args[1]["name"], data["name"])
        self.assertEqual(
            mock_audit_create.call_args[1]["framework"].id, self.framework.id
        )
        # Enclave audits carry no perimeter, even when the entity assessment has one.
        self.assertNotIn("perimeter", mock_audit_create.call_args[1])
        self.assertEqual(
            mock_audit_create.call_args[1]["selected_implementation_groups"],
            data["selected_implementation_groups"],
        )

    def test_link_audit_checks_change_complianceassessment_on_audit_folder(self):
        """Linking an existing audit relocates it, so the gate must be
        change_complianceassessment in the audit's own folder — not this
        serializer's change_entityassessment."""
        audit_folder = Folder.objects.create(name="Audit Folder")
        audit = ComplianceAssessment.objects.create(
            name="Linkable Audit", framework=self.framework, folder=audit_folder
        )
        assignment = RequirementAssignment.objects.create(
            compliance_assessment=audit,
            folder=audit_folder,
        )
        assessment = EntityAssessment.objects.create(
            name="Link Target", entity=self.entity, folder=self.folder
        )
        request = MagicMock()
        request.user = self.user

        checked = []

        def record_access(user, perm, folder):
            checked.append((perm.codename, folder))
            return True

        with (
            patch(
                "iam.models.RoleAssignment.is_access_allowed",
                side_effect=record_access,
            ),
            patch(
                "tprm.serializers.has_full_view_compliance_assessment",
                return_value=True,
            ),
            patch(
                "core.views.ComplianceAssessmentViewSet._assert_complete_assessment_read_access"
            ),
            patch(
                "tprm.serializers.RoleAssignment.get_viewable_object_ids",
                side_effect=self._all_model_ids,
            ),
        ):
            serializer = EntityAssessmentWriteSerializer(
                instance=assessment,
                data={"link_audit": audit.id},
                partial=True,
                context={"request": request},
            )
            self.assertTrue(serializer.is_valid(), serializer.errors)
            serializer.save()

        self.assertIn(("change_complianceassessment", audit_folder), checked)
        self.assertNotIn(("change_entityassessment", audit_folder), checked)
        assessment.refresh_from_db()
        audit.refresh_from_db()
        self.assertEqual(assessment.compliance_assessment_id, audit.id)
        self.assertEqual(audit.folder.content_type, Folder.ContentType.ENCLAVE)
        self.assertIsNone(audit.perimeter)
        assignment.refresh_from_db()
        self.assertEqual(assignment.folder_id, audit.folder_id)

    def test_link_audit_collection_owner_requires_independent_change_authority(self):
        audit_folder = Folder.objects.create(name="Collection audit folder")
        audit = ComplianceAssessment.objects.create(
            name="Collection-owned audit",
            framework=self.framework,
            folder=audit_folder,
        )
        collection = GenericCollection.objects.create(
            name="Audit collection",
            folder=self.folder,
        )
        collection.compliance_assessments.add(audit)
        serializer = EntityAssessmentWriteSerializer(
            self.assessment,
            context={"request": MagicMock(user=self.user)},
        )

        def deny_collection_change(*, perm, **_kwargs):
            return perm.codename != "change_genericcollection"

        with (
            transaction.atomic(),
            patch(
                "tprm.serializers.RoleAssignment.get_viewable_object_ids",
                side_effect=self._all_model_ids,
            ),
            patch(
                "iam.models.RoleAssignment.is_access_allowed",
                side_effect=deny_collection_change,
            ),
        ):
            Folder._lock_folder_tree()
            with self.assertRaises(PermissionDenied):
                serializer._lock_existing_audit_relation_owners(audit)

        self.assertTrue(collection.compliance_assessments.filter(id=audit.id).exists())

    def test_link_audit_validation_flow_owner_fails_closed(self):
        audit_folder = Folder.objects.create(name="Workflow audit folder")
        audit = ComplianceAssessment.objects.create(
            name="Workflow-owned audit",
            framework=self.framework,
            folder=audit_folder,
        )
        flow = ValidationFlow.objects.create(folder=self.folder)
        flow.compliance_assessments.add(audit)
        serializer = EntityAssessmentWriteSerializer(
            self.assessment,
            context={"request": MagicMock(user=self.user)},
        )

        with transaction.atomic():
            Folder._lock_folder_tree()
            with self.assertRaises(PermissionDenied):
                serializer._lock_existing_audit_relation_owners(audit)

        self.assertTrue(flow.compliance_assessments.filter(id=audit.id).exists())

    @patch("iam.models.RoleAssignment.is_access_allowed", return_value=True)
    def test_entity_assessment_write_serializer_without_framework(
        self, mock_is_access_allowed
    ):
        """Test that EntityAssessmentWriteSerializer raises ValidationError if framework is not provided"""
        data = {
            "name": "New Assessment",
            "entity": self.entity.id,
            "folder": self.perimeter_folder.id,
            "perimeter": self.perimeter.id,
            "create_audit": True,
        }

        serializer = EntityAssessmentWriteSerializer(
            data=data, context={"request": MagicMock()}
        )
        self.assertTrue(serializer.is_valid())

        with patch(
            "tprm.serializers.RoleAssignment.get_viewable_object_ids",
            side_effect=self._all_model_ids,
        ):
            with self.assertRaises(ValidationError) as context:
                serializer.save()

        self.assertIn("framework", context.exception.detail)

    @patch("iam.models.RoleAssignment.is_access_allowed", return_value=True)
    @patch(
        "tprm.serializers.EntityAssessmentWriteSerializer._assign_third_party_respondents"
    )
    def test_entity_assessment_write_update(self, mock_assign, mock_is_access_allowed):
        """Test that EntityAssessmentWriteSerializer correctly updates an EntityAssessment"""
        new_rep = self._make_representative_user("newrep@example.com")

        data = {"name": "Updated Assessment", "representatives": [new_rep.id]}

        request = MagicMock()
        request.user.is_authenticated = True

        with (
            patch(
                "iam.models.RoleAssignment._get_accessible_ids",
                return_value=([new_rep.id]),
            ),
            patch(
                "tprm.serializers.RoleAssignment.get_viewable_object_ids",
                side_effect=self._all_model_ids,
            ),
        ):
            serializer = EntityAssessmentWriteSerializer(
                self.assessment, data=data, partial=True, context={"request": request}
            )
            self.assertTrue(serializer.is_valid())
            updated_assessment = serializer.save()

        self.assertEqual(updated_assessment.name, "Updated Assessment")
        self.assertIn(new_rep, updated_assessment.representatives.all())

        self.assertEqual(updated_assessment.representatives.count(), 1)
        self.assertNotIn(self.representative, updated_assessment.representatives.all())

        mock_assign.assert_called_once()

    def _bind_audit(self):
        enclave = Folder.objects.create(
            name="Bound audit enclave",
            content_type=Folder.ContentType.ENCLAVE,
            parent_folder=self.assessment.folder,
        )
        audit = ComplianceAssessment.objects.create(
            name="Bound audit",
            framework=self.framework,
            folder=enclave,
        )
        audit.authors.add(self.representative.actor)
        audit.reviewers.add(self.user.actor)
        assignment = RequirementAssignment.objects.create(
            compliance_assessment=audit,
            folder=enclave,
        )
        assignment.actor.add(self.representative.actor)
        self.assessment.compliance_assessment = audit
        self.assessment.save(update_fields=["compliance_assessment"])
        return audit, assignment

    def _sync_respondent_scaffold(self, *, allow_create, visible_ids=None):
        serializer = EntityAssessmentWriteSerializer(
            self.assessment,
            context={"request": MagicMock(user=self.user)},
        )

        def visibility(_user, model):
            queryset = model.objects.all()
            if visible_ids is not None and model is User:
                queryset = queryset.filter(id__in=visible_ids)
            return queryset.values_list("id", flat=True)

        with (
            transaction.atomic(),
            patch(
                "tprm.serializers.RoleAssignment.get_viewable_object_ids",
                side_effect=visibility,
            ),
        ):
            Folder._lock_folder_tree()
            serializer._assign_third_party_respondents(
                self.assessment,
                set(self.assessment.representatives.all()),
                allow_create=allow_create,
            )

    def _respondent_scaffold(self, audit):
        group = UserGroup.objects.get(
            folder=audit.folder,
            name=str(UserGroupCodename.THIRD_PARTY_RESPONDENT),
        )
        assignment = RoleAssignment.objects.get(user_group=group)
        return group, assignment

    def test_respondent_sync_create_provisions_exact_scaffold(self):
        audit, _assignment = self._bind_audit()

        self._sync_respondent_scaffold(allow_create=True)

        group, assignment = self._respondent_scaffold(audit)
        self.assertTrue(group.builtin)
        self.assertSetEqual(
            set(group.user_set.values_list("id", flat=True)),
            {self.representative.id},
        )
        self.assertEqual(assignment.folder_id, audit.folder_id)
        self.assertIsNone(assignment.user_id)
        self.assertEqual(
            assignment.role.name,
            str(RoleCodename.THIRD_PARTY_RESPONDENT),
        )
        self.assertTrue(assignment.builtin)
        self.assertTrue(assignment.is_recursive)
        self.assertSetEqual(
            set(assignment.perimeter_folders.values_list("id", flat=True)),
            {audit.folder_id},
        )

    def test_respondent_sync_update_replaces_visible_stale_membership(self):
        audit, _assignment = self._bind_audit()
        self._sync_respondent_scaffold(allow_create=True)
        group, _role_assignment = self._respondent_scaffold(audit)
        stale_member = User.objects.create_user(
            email="stale-respondent@example.com",
            password="password",
            is_third_party=True,
        )
        group.user_set.add(stale_member)

        self._sync_respondent_scaffold(allow_create=False)

        self.assertSetEqual(
            set(group.user_set.values_list("id", flat=True)),
            {self.representative.id},
        )

    def test_respondent_sync_rejects_legacy_idp_inheritance_atomically(self):
        audit, _assignment = self._bind_audit()
        self._sync_respondent_scaffold(allow_create=True)
        group, role_assignment = self._respondent_scaffold(audit)
        idp_group = IdPGroup.objects.create(name="legacy-tprm-sync-idp")
        idp_group.user_groups.add(group)
        idp_group.users.add(self.representative)

        with self.assertRaises(PermissionDenied) as exc_info:
            self._sync_respondent_scaffold(allow_create=False)

        self.assertIn("managedTprmRespondentMembership", str(exc_info.exception))
        self.assertTrue(idp_group.user_groups.filter(id=group.id).exists())
        self.assertSetEqual(
            set(idp_group.users.values_list("id", flat=True)),
            {self.representative.id},
        )
        self.assertSetEqual(
            set(role_assignment.perimeter_folders.values_list("id", flat=True)),
            {audit.folder_id},
        )

    def test_respondent_sync_rejects_hidden_residual_member_atomically(self):
        audit, _assignment = self._bind_audit()
        self._sync_respondent_scaffold(allow_create=True)
        group, role_assignment = self._respondent_scaffold(audit)
        hidden_member = User.objects.create_user(
            email="hidden-stale-respondent@example.com",
            password="password",
            is_third_party=True,
        )
        group.user_set.add(hidden_member)
        expected_members = {self.representative.id, hidden_member.id}

        with self.assertRaises(PermissionDenied):
            self._sync_respondent_scaffold(
                allow_create=False,
                visible_ids={self.representative.id},
            )

        self.assertSetEqual(
            set(group.user_set.values_list("id", flat=True)),
            expected_members,
        )
        self.assertSetEqual(
            set(role_assignment.perimeter_folders.values_list("id", flat=True)),
            {audit.folder_id},
        )

    def test_respondent_sync_update_does_not_create_missing_scaffold(self):
        audit, assignment = self._bind_audit()
        new_representative = self._make_representative_user(
            "missing-scaffold-new-representative@example.com"
        )
        expected_representatives = {self.representative.id}
        expected_authors = {self.representative.actor.id}
        expected_assignment_actors = {self.representative.actor.id}

        with (
            patch("iam.models.RoleAssignment.is_access_allowed", return_value=True),
            patch(
                "tprm.serializers.RoleAssignment.get_viewable_object_ids",
                side_effect=self._all_model_ids,
            ),
            patch(
                "tprm.serializers.has_full_view_compliance_assessment",
                return_value=True,
            ),
            patch(
                "core.views.ComplianceAssessmentViewSet._assert_complete_assessment_read_access"
            ),
        ):
            serializer = EntityAssessmentWriteSerializer(
                self.assessment,
                data={"representatives": [new_representative.id]},
                partial=True,
                context={"request": MagicMock(user=self.user)},
            )
            self.assertTrue(serializer.is_valid(), serializer.errors)
            with self.assertRaises(PermissionDenied):
                serializer.save()

        self.assertFalse(UserGroup.objects.filter(folder=audit.folder).exists())
        self.assertFalse(RoleAssignment.objects.filter(folder=audit.folder).exists())
        self.assertSetEqual(
            set(self.assessment.representatives.values_list("id", flat=True)),
            expected_representatives,
        )
        self.assertSetEqual(
            set(audit.authors.values_list("id", flat=True)),
            expected_authors,
        )
        self.assertSetEqual(
            set(assignment.actor.values_list("id", flat=True)),
            expected_assignment_actors,
        )

    def test_respondent_sync_update_rejects_malformed_reserved_group(self):
        audit, _assignment = self._bind_audit()
        malformed = UserGroup.objects.create(
            folder=audit.folder,
            name=str(UserGroupCodename.THIRD_PARTY_RESPONDENT),
            builtin=False,
        )

        with self.assertRaises(PermissionDenied):
            self._sync_respondent_scaffold(allow_create=False)

        malformed.refresh_from_db()
        self.assertFalse(malformed.builtin)
        self.assertEqual(
            UserGroup.objects.filter(folder=audit.folder).count(),
            1,
        )
        self.assertFalse(RoleAssignment.objects.filter(folder=audit.folder).exists())

    def test_respondent_sync_update_rejects_non_exact_role_perimeter(self):
        audit, _assignment = self._bind_audit()
        self._sync_respondent_scaffold(allow_create=True)
        group, role_assignment = self._respondent_scaffold(audit)
        unrelated_folder = Folder.objects.create(name="Unrelated perimeter")
        role_assignment.perimeter_folders.add(unrelated_folder)
        expected_perimeters = {audit.folder_id, unrelated_folder.id}

        with self.assertRaises(PermissionDenied):
            self._sync_respondent_scaffold(allow_create=False)

        self.assertSetEqual(
            set(role_assignment.perimeter_folders.values_list("id", flat=True)),
            expected_perimeters,
        )
        self.assertSetEqual(
            set(group.user_set.values_list("id", flat=True)),
            {self.representative.id},
        )

    @staticmethod
    def _all_model_ids(_user, model):
        return model.objects.values_list("id", flat=True)

    @patch("iam.models.RoleAssignment.is_access_allowed", return_value=True)
    def test_direct_compliance_assessment_fk_is_not_a_write_surface(
        self, _mock_is_access_allowed
    ):
        hidden_folder = Folder.objects.create(
            name="Hidden enclave", content_type=Folder.ContentType.ENCLAVE
        )
        hidden_audit = ComplianceAssessment.objects.create(
            name="Hidden audit",
            framework=self.framework,
            folder=hidden_folder,
        )
        request = MagicMock(user=self.user)
        data = {
            "name": "Bypass attempt",
            "entity": self.entity.id,
            "folder": self.folder.id,
            "representatives": [self.representative.id],
            "compliance_assessment": hidden_audit.id,
        }

        with patch(
            "tprm.serializers.RoleAssignment.get_viewable_object_ids",
            side_effect=self._all_model_ids,
        ):
            serializer = EntityAssessmentWriteSerializer(
                data=data,
                context={"request": request},
            )
            self.assertTrue(serializer.is_valid(), serializer.errors)
            created = serializer.save()

        self.assertIsNone(created.compliance_assessment_id)
        self.assertFalse(self.user.user_groups.filter(folder=hidden_folder).exists())

    @patch("iam.models.RoleAssignment.is_access_allowed", return_value=True)
    @patch(
        "tprm.serializers.EntityAssessmentWriteSerializer._assign_third_party_respondents"
    )
    def test_name_only_update_preserves_linked_audit_identities(
        self, mock_assign_respondents, _mock_is_access_allowed
    ):
        audit, assignment = self._bind_audit()
        expected_authors = set(audit.authors.values_list("id", flat=True))
        expected_reviewers = set(audit.reviewers.values_list("id", flat=True))
        expected_actors = set(assignment.actor.values_list("id", flat=True))
        request = MagicMock(user=self.user)

        serializer = EntityAssessmentWriteSerializer(
            self.assessment,
            data={"name": "Only the EA name changed"},
            partial=True,
            context={"request": request},
        )
        self.assertTrue(serializer.is_valid(), serializer.errors)
        serializer.save()

        self.assertSetEqual(
            set(audit.authors.values_list("id", flat=True)), expected_authors
        )
        self.assertSetEqual(
            set(audit.reviewers.values_list("id", flat=True)), expected_reviewers
        )
        self.assertSetEqual(
            set(assignment.actor.values_list("id", flat=True)), expected_actors
        )
        mock_assign_respondents.assert_not_called()

    def test_locked_or_in_review_audit_rejects_identity_sync_atomically(self):
        audit, assignment = self._bind_audit()
        new_representative = self._make_representative_user(
            "locked-new-rep@example.com"
        )
        request = MagicMock(user=self.user)
        expected_representatives = set(
            self.assessment.representatives.values_list("id", flat=True)
        )
        expected_authors = set(audit.authors.values_list("id", flat=True))
        expected_actors = set(assignment.actor.values_list("id", flat=True))

        for is_locked, status in (
            (True, ComplianceAssessment.Status.PLANNED),
            (False, ComplianceAssessment.Status.IN_REVIEW),
        ):
            with self.subTest(is_locked=is_locked, status=status):
                audit.is_locked = is_locked
                audit.status = status
                audit.save(update_fields=["is_locked", "status"])
                with (
                    patch(
                        "iam.models.RoleAssignment.is_access_allowed",
                        return_value=True,
                    ),
                    patch(
                        "tprm.serializers.RoleAssignment.get_viewable_object_ids",
                        side_effect=self._all_model_ids,
                    ),
                    patch(
                        "tprm.serializers.has_full_view_compliance_assessment",
                        return_value=True,
                    ),
                    patch(
                        "tprm.serializers.EntityAssessmentWriteSerializer._assign_third_party_respondents"
                    ) as mock_assign_respondents,
                ):
                    serializer = EntityAssessmentWriteSerializer(
                        self.assessment,
                        data={"representatives": [new_representative.id]},
                        partial=True,
                        context={"request": request},
                    )
                    self.assertTrue(serializer.is_valid(), serializer.errors)
                    with self.assertRaises(PermissionDenied):
                        serializer.save()
                    mock_assign_respondents.assert_not_called()

                self.assertSetEqual(
                    set(self.assessment.representatives.values_list("id", flat=True)),
                    expected_representatives,
                )
                self.assertSetEqual(
                    set(audit.authors.values_list("id", flat=True)),
                    expected_authors,
                )
                self.assertSetEqual(
                    set(assignment.actor.values_list("id", flat=True)),
                    expected_actors,
                )

    def test_hidden_existing_audit_identity_rejects_partial_rewrite(self):
        audit, assignment = self._bind_audit()
        hidden_user = User.objects.create_user(
            email="hidden-audit-actor@example.com", password="password"
        )
        audit.authors.add(hidden_user.actor)
        assignment.actor.add(hidden_user.actor)
        new_representative = self._make_representative_user(
            "visible-new-rep@example.com"
        )
        request = MagicMock(user=self.user)
        expected_representatives = set(
            self.assessment.representatives.values_list("id", flat=True)
        )
        expected_authors = set(audit.authors.values_list("id", flat=True))
        expected_actors = set(assignment.actor.values_list("id", flat=True))

        def visible_except_hidden(_user, model):
            queryset = model.objects.all()
            if model is type(hidden_user.actor):
                queryset = queryset.exclude(id=hidden_user.actor.id)
            return queryset.values_list("id", flat=True)

        with (
            patch("iam.models.RoleAssignment.is_access_allowed", return_value=True),
            patch(
                "tprm.serializers.RoleAssignment.get_viewable_object_ids",
                side_effect=visible_except_hidden,
            ),
            patch(
                "tprm.serializers.has_full_view_compliance_assessment",
                return_value=True,
            ),
            patch(
                "core.views.ComplianceAssessmentViewSet._assert_complete_assessment_read_access"
            ),
            patch(
                "tprm.serializers.EntityAssessmentWriteSerializer._assign_third_party_respondents"
            ) as mock_assign_respondents,
        ):
            serializer = EntityAssessmentWriteSerializer(
                self.assessment,
                data={"representatives": [new_representative.id]},
                partial=True,
                context={"request": request},
            )
            self.assertTrue(serializer.is_valid(), serializer.errors)
            with self.assertRaises(PermissionDenied):
                serializer.save()
            mock_assign_respondents.assert_not_called()

        self.assertSetEqual(
            set(self.assessment.representatives.values_list("id", flat=True)),
            expected_representatives,
        )
        self.assertSetEqual(
            set(audit.authors.values_list("id", flat=True)), expected_authors
        )
        self.assertSetEqual(
            set(assignment.actor.values_list("id", flat=True)), expected_actors
        )

    def test_identity_sync_requires_full_view_and_change_audit_authority(self):
        audit, assignment = self._bind_audit()
        new_representative = self._make_representative_user(
            "authority-new-rep@example.com"
        )
        request = MagicMock(user=self.user)
        expected_representatives = set(
            self.assessment.representatives.values_list("id", flat=True)
        )
        expected_authors = set(audit.authors.values_list("id", flat=True))
        expected_actors = set(assignment.actor.values_list("id", flat=True))

        def deny_audit_change(user, perm, folder):
            return perm.codename != "change_complianceassessment"

        for has_full_view, access_decision in (
            (False, lambda user, perm, folder: True),
            (True, deny_audit_change),
        ):
            with self.subTest(has_full_view=has_full_view):
                with (
                    patch(
                        "iam.models.RoleAssignment.is_access_allowed",
                        side_effect=access_decision,
                    ),
                    patch(
                        "tprm.serializers.RoleAssignment.get_viewable_object_ids",
                        side_effect=self._all_model_ids,
                    ),
                    patch(
                        "tprm.serializers.has_full_view_compliance_assessment",
                        return_value=has_full_view,
                    ),
                    patch(
                        "core.views.ComplianceAssessmentViewSet._assert_complete_assessment_read_access"
                    ),
                    patch(
                        "tprm.serializers.EntityAssessmentWriteSerializer._assign_third_party_respondents"
                    ) as mock_assign_respondents,
                ):
                    serializer = EntityAssessmentWriteSerializer(
                        self.assessment,
                        data={"representatives": [new_representative.id]},
                        partial=True,
                        context={"request": request},
                    )
                    self.assertTrue(serializer.is_valid(), serializer.errors)
                    with self.assertRaises(PermissionDenied):
                        serializer.save()
                    mock_assign_respondents.assert_not_called()

                self.assertSetEqual(
                    set(self.assessment.representatives.values_list("id", flat=True)),
                    expected_representatives,
                )
                self.assertSetEqual(
                    set(audit.authors.values_list("id", flat=True)),
                    expected_authors,
                )
                self.assertSetEqual(
                    set(assignment.actor.values_list("id", flat=True)),
                    expected_actors,
                )

    def test_authorized_identity_update_syncs_only_requested_governance_fields(self):
        audit, assignment = self._bind_audit()
        new_representative = self._make_representative_user(
            "authorized-new-rep@example.com"
        )
        new_reviewer = User.objects.create_user(
            email="authorized-new-reviewer@example.com", password="password"
        )
        request = MagicMock(user=self.user)

        with (
            patch("iam.models.RoleAssignment.is_access_allowed", return_value=True),
            patch(
                "tprm.serializers.RoleAssignment.get_viewable_object_ids",
                side_effect=self._all_model_ids,
            ),
            patch(
                "tprm.serializers.has_full_view_compliance_assessment",
                return_value=True,
            ),
            patch(
                "core.views.ComplianceAssessmentViewSet._assert_complete_assessment_read_access"
            ),
            patch(
                "tprm.serializers.EntityAssessmentWriteSerializer._assign_third_party_respondents"
            ) as mock_assign_respondents,
        ):
            serializer = EntityAssessmentWriteSerializer(
                self.assessment,
                data={
                    "representatives": [new_representative.id],
                    "reviewers": [new_reviewer.actor.id],
                },
                partial=True,
                context={"request": request},
            )
            self.assertTrue(serializer.is_valid(), serializer.errors)
            serializer.save()

        self.assertSetEqual(
            set(audit.authors.values_list("id", flat=True)),
            {new_representative.actor.id},
        )
        self.assertSetEqual(
            set(audit.reviewers.values_list("id", flat=True)),
            {new_reviewer.actor.id},
        )
        self.assertSetEqual(
            set(assignment.actor.values_list("id", flat=True)),
            {new_representative.actor.id},
        )
        mock_assign_respondents.assert_called_once()

    def test_representatives_must_be_active_bound_third_party_contacts(self):
        other_entity = Entity.objects.create(name="Other entity", folder=self.folder)
        internal = User.objects.create_user(
            email="internal-not-representative@example.com", password="password"
        )
        cross_entity = self._make_representative_user(
            "cross-entity-representative@example.com", entity=other_entity
        )
        inactive = self._make_representative_user("inactive-representative@example.com")
        inactive.is_active = False
        inactive.save(update_fields=["is_active"])
        expected_ids = set(self.assessment.representatives.values_list("id", flat=True))

        for candidate in (internal, cross_entity, inactive):
            with self.subTest(candidate=candidate.email):
                with (
                    patch(
                        "iam.models.RoleAssignment.is_access_allowed",
                        return_value=True,
                    ),
                    patch(
                        "tprm.serializers.RoleAssignment.get_viewable_object_ids",
                        side_effect=self._all_model_ids,
                    ),
                ):
                    serializer = EntityAssessmentWriteSerializer(
                        self.assessment,
                        data={"representatives": [candidate.id]},
                        partial=True,
                        context={"request": MagicMock(user=self.user)},
                    )
                    self.assertTrue(serializer.is_valid(), serializer.errors)
                    with self.assertRaises(PermissionDenied):
                        serializer.save()
            self.assertSetEqual(
                set(self.assessment.representatives.values_list("id", flat=True)),
                expected_ids,
            )

    def test_solution_must_belong_to_assessed_entity(self):
        other_entity = Entity.objects.create(name="Other provider", folder=self.folder)
        wrong_solution = Solution.objects.create(
            name="Wrong provider solution", provider_entity=other_entity
        )
        expected_ids = set(self.assessment.solutions.values_list("id", flat=True))
        with (
            patch("iam.models.RoleAssignment.is_access_allowed", return_value=True),
            patch(
                "tprm.serializers.RoleAssignment.get_viewable_object_ids",
                side_effect=self._all_model_ids,
            ),
        ):
            serializer = EntityAssessmentWriteSerializer(
                self.assessment,
                data={"solutions": [wrong_solution.id]},
                partial=True,
                context={"request": MagicMock(user=self.user)},
            )
            self.assertTrue(serializer.is_valid(), serializer.errors)
            with self.assertRaises(PermissionDenied):
                serializer.save()
        self.assertSetEqual(
            set(self.assessment.solutions.values_list("id", flat=True)),
            expected_ids,
        )

    def test_closed_assignment_rejects_representative_rewrite(self):
        audit, assignment = self._bind_audit()
        new_representative = self._make_representative_user(
            "closed-assignment-representative@example.com"
        )
        expected_ids = set(self.assessment.representatives.values_list("id", flat=True))

        for assignment_status in (
            RequirementAssignment.Status.SUBMITTED,
            RequirementAssignment.Status.CLOSED,
            RequirementAssignment.Status.CHANGES_REQUESTED,
        ):
            with self.subTest(status=assignment_status):
                assignment.status = assignment_status
                assignment.save(update_fields=["status"])
                with (
                    patch(
                        "iam.models.RoleAssignment.is_access_allowed",
                        return_value=True,
                    ),
                    patch(
                        "tprm.serializers.RoleAssignment.get_viewable_object_ids",
                        side_effect=self._all_model_ids,
                    ),
                    patch(
                        "tprm.serializers.has_full_view_compliance_assessment",
                        return_value=True,
                    ),
                    patch(
                        "core.views.ComplianceAssessmentViewSet._assert_complete_assessment_read_access"
                    ),
                ):
                    serializer = EntityAssessmentWriteSerializer(
                        self.assessment,
                        data={"representatives": [new_representative.id]},
                        partial=True,
                        context={"request": MagicMock(user=self.user)},
                    )
                    self.assertTrue(serializer.is_valid(), serializer.errors)
                    with self.assertRaises(PermissionDenied):
                        serializer.save()
                self.assertSetEqual(
                    set(self.assessment.representatives.values_list("id", flat=True)),
                    expected_ids,
                )
                self.assertEqual(audit.authors.count(), 1)

    def test_legacy_non_enclave_audit_owner_rejects_all_updates(self):
        audit = ComplianceAssessment.objects.create(
            name="Legacy domain audit", framework=self.framework, folder=self.folder
        )
        self.assessment.compliance_assessment = audit
        self.assessment.save(update_fields=["compliance_assessment"])
        with patch("iam.models.RoleAssignment.is_access_allowed", return_value=True):
            serializer = EntityAssessmentWriteSerializer(
                self.assessment,
                data={"name": "Must not change"},
                partial=True,
                context={"request": MagicMock(user=self.user)},
            )
            self.assertTrue(serializer.is_valid(), serializer.errors)
            with self.assertRaises(PermissionDenied):
                serializer.save()
        self.assessment.refresh_from_db()
        self.assertEqual(self.assessment.name, "Test Assessment")

    def test_linked_assessment_owner_cannot_move(self):
        self._bind_audit()
        target_folder = Folder.objects.create(name="Other perimeter folder")
        target_perimeter = Perimeter.objects.create(
            name="Other perimeter", folder=target_folder
        )
        with (
            patch("iam.models.RoleAssignment.is_access_allowed", return_value=True),
            patch(
                "tprm.serializers.RoleAssignment.get_viewable_object_ids",
                side_effect=self._all_model_ids,
            ),
        ):
            serializer = EntityAssessmentWriteSerializer(
                self.assessment,
                data={"perimeter": target_perimeter.id},
                partial=True,
                context={"request": MagicMock(user=self.user)},
            )
            self.assertTrue(serializer.is_valid(), serializer.errors)
            with self.assertRaises(PermissionDenied):
                serializer.save()
        self.assessment.refresh_from_db()
        self.assertEqual(self.assessment.folder_id, self.folder.id)
        self.assertEqual(self.assessment.perimeter_id, self.perimeter.id)

    def test_entity_assessment_reverse_collection_is_read_only(self):
        collection = GenericCollection.objects.create(
            name="Hidden collection", folder=self.folder
        )
        collection.entity_assessments.add(self.assessment)

        with (
            patch("iam.models.RoleAssignment.is_access_allowed", return_value=True),
        ):
            serializer = EntityAssessmentWriteSerializer(
                self.assessment,
                data={"genericcollection": []},
                partial=True,
                context={"request": MagicMock(user=self.user)},
            )
            self.assertTrue(serializer.is_valid(), serializer.errors)
            self.assertTrue(serializer.fields["genericcollection"].read_only)
            serializer.save()
        self.assertTrue(collection.entity_assessments.filter(id=self.assessment.id))

        with patch(
            "tprm.serializers.RoleAssignment.get_viewable_object_ids",
            side_effect=self._all_model_ids,
        ):
            data = EntityAssessmentReadSerializer(
                self.assessment,
                context={"request": MagicMock(user=self.user)},
            ).data
        self.assertEqual(data["genericcollection"], [collection.id])

    def test_representative_lock_scope_excludes_another_entity_binding(self):
        other_entity = Entity.objects.create(
            name="Another representative owner",
            folder=self.folder,
        )
        unrelated_binding = Representative.objects.create(
            email="same-user-other-entity@example.com",
            entity=other_entity,
            user=self.representative,
        )
        captured_targets = []

        def capture_locks(target_ids_by_model):
            captured_targets.append(
                {
                    model: set(target_ids)
                    for model, target_ids in target_ids_by_model.items()
                }
            )
            return lock_rows_in_global_model_order(target_ids_by_model)

        serializer = EntityAssessmentWriteSerializer(
            self.assessment,
            context={"request": MagicMock(user=self.user)},
        )
        with (
            transaction.atomic(),
            patch(
                "tprm.serializers.RoleAssignment.get_viewable_object_ids",
                side_effect=self._all_model_ids,
            ),
            patch(
                "tprm.serializers.lock_rows_in_global_model_order",
                side_effect=capture_locks,
            ),
        ):
            serializer._lock_and_validate_entity_relations(
                instance=self.assessment,
                validated_data={
                    "representatives": list(self.assessment.representatives.all())
                },
                validate_representatives=True,
            )

        locked_representative_ids = captured_targets[0][Representative]
        self.assertNotIn(unrelated_binding.id, locked_representative_ids)
        self.assertSetEqual(
            locked_representative_ids,
            set(
                Representative.objects.filter(
                    entity=self.entity,
                    user=self.representative,
                ).values_list("id", flat=True)
            ),
        )

    def test_entity_assessment_cannot_create_reverse_collection_link(self):
        collection = GenericCollection.objects.create(
            name="Visible governed collection", folder=self.folder
        )

        with (
            patch("iam.models.RoleAssignment.is_access_allowed", return_value=True),
        ):
            serializer = EntityAssessmentWriteSerializer(
                self.assessment,
                data={"genericcollection": [collection.id]},
                partial=True,
                context={"request": MagicMock(user=self.user)},
            )
            self.assertTrue(serializer.is_valid(), serializer.errors)
            serializer.save()

        self.assertFalse(collection.entity_assessments.filter(id=self.assessment.id))

    def test_hidden_evidence_cannot_be_linked(self):
        evidence = Evidence.objects.create(name="Hidden evidence", folder=self.folder)

        def hide_evidence(_user, model):
            queryset = model.objects.all()
            if model is Evidence:
                queryset = queryset.exclude(id=evidence.id)
            return queryset.values_list("id", flat=True)

        with (
            patch("iam.models.RoleAssignment.is_access_allowed", return_value=True),
            patch(
                "tprm.serializers.RoleAssignment.get_viewable_object_ids",
                side_effect=hide_evidence,
            ),
        ):
            serializer = EntityAssessmentWriteSerializer(
                self.assessment,
                data={"evidence": evidence.id},
                partial=True,
                context={"request": MagicMock(user=self.user)},
            )
            self.assertTrue(serializer.is_valid(), serializer.errors)
            with self.assertRaises(PermissionDenied):
                serializer.save()
        self.assessment.refresh_from_db()
        self.assertIsNone(self.assessment.evidence_id)

    def test_create_rejects_folder_perimeter_owner_mismatch(self):
        before = EntityAssessment.objects.count()
        with (
            patch("iam.models.RoleAssignment.is_access_allowed", return_value=True),
            patch(
                "tprm.serializers.RoleAssignment.get_viewable_object_ids",
                side_effect=self._all_model_ids,
            ),
        ):
            serializer = EntityAssessmentWriteSerializer(
                data={
                    "name": "Wrong owner",
                    "entity": self.entity.id,
                    "folder": self.folder.id,
                    "perimeter": self.perimeter.id,
                },
                context={"request": MagicMock(user=self.user)},
            )
            self.assertTrue(serializer.is_valid(), serializer.errors)
            with self.assertRaises(ValidationError):
                serializer.save()
        self.assertEqual(EntityAssessment.objects.count(), before)

    def test_create_requires_add_permission_on_perimeter_owner(self):
        before = EntityAssessment.objects.count()

        def deny_target_folder(user, perm, folder):
            del user
            return not (
                perm.codename == "add_entityassessment"
                and folder.id == self.perimeter_folder.id
            )

        with (
            patch(
                "iam.models.RoleAssignment.is_access_allowed",
                side_effect=deny_target_folder,
            ),
            patch(
                "tprm.serializers.RoleAssignment.get_viewable_object_ids",
                side_effect=self._all_model_ids,
            ),
        ):
            serializer = EntityAssessmentWriteSerializer(
                data={
                    "name": "Unauthorized target owner",
                    "entity": self.entity.id,
                    "folder": self.perimeter_folder.id,
                    "perimeter": self.perimeter.id,
                },
                context={"request": MagicMock(user=self.user)},
            )
            self.assertTrue(serializer.is_valid(), serializer.errors)
            with self.assertRaises(PermissionDenied):
                serializer.save()
        self.assertEqual(EntityAssessment.objects.count(), before)

    def test_create_audit_rejects_hidden_existing_reviewer_before_mutation(self):
        folder_count = Folder.objects.count()

        def hide_current_reviewer(_user, model):
            queryset = model.objects.all()
            if model is type(self.user.actor):
                queryset = queryset.exclude(id=self.user.actor.id)
            return queryset.values_list("id", flat=True)

        with (
            patch("iam.models.RoleAssignment.is_access_allowed", return_value=True),
            patch(
                "tprm.serializers.RoleAssignment.get_viewable_object_ids",
                side_effect=hide_current_reviewer,
            ),
        ):
            serializer = EntityAssessmentWriteSerializer(
                self.assessment,
                data={
                    "create_audit": True,
                    "framework": self.framework.id,
                    "selected_implementation_groups": [],
                },
                partial=True,
                context={"request": MagicMock(user=self.user)},
            )
            self.assertTrue(serializer.is_valid(), serializer.errors)
            with self.assertRaises(PermissionDenied):
                serializer.save()
        self.assessment.refresh_from_db()
        self.assertIsNone(self.assessment.compliance_assessment_id)
        self.assertEqual(Folder.objects.count(), folder_count)

    def test_read_validation_flow_hides_unviewable_approver_pii(self):
        flow = ValidationFlow.objects.create(
            folder=self.folder,
            approver=self.representative,
        )
        flow.entity_assessments.add(self.assessment)

        def hide_approver(_user, model):
            queryset = model.objects.all()
            if model is User:
                queryset = queryset.exclude(id=self.representative.id)
            return queryset.values_list("id", flat=True)

        with patch(
            "tprm.serializers.RoleAssignment.get_viewable_object_ids",
            side_effect=hide_approver,
        ):
            data = EntityAssessmentReadSerializer(
                self.assessment,
                context={"request": MagicMock(user=self.user)},
            ).data

        self.assertEqual(len(data["validation_flows"]), 1)
        self.assertIsNone(data["validation_flows"][0]["approver"])

        flow_without_approver = ValidationFlow.objects.create(folder=self.folder)
        flow_without_approver.entity_assessments.add(self.assessment)
        with patch(
            "tprm.serializers.RoleAssignment.get_viewable_object_ids",
            side_effect=hide_approver,
        ):
            rows = EntityAssessmentReadSerializer(
                self.assessment,
                context={"request": MagicMock(user=self.user)},
            ).data["validation_flows"]
        self.assertEqual(
            {row["approver"] for row in rows},
            {None},
        )

    def test_write_response_omits_independently_hidden_relationships(self):
        audit, _assignment = self._bind_audit()
        request = MagicMock(user=self.user)

        def hide_identity_and_audit(_user, model):
            if model in {User, type(self.user.actor), ComplianceAssessment}:
                return model.objects.none().values_list("id", flat=True)
            return model.objects.values_list("id", flat=True)

        with patch(
            "tprm.serializers.RoleAssignment.get_viewable_object_ids",
            side_effect=hide_identity_and_audit,
        ):
            data = EntityAssessmentWriteSerializer(
                self.assessment,
                context={"request": request},
            ).data

        self.assertNotIn("compliance_assessment", data)
        self.assertNotIn("reviewers", data)
        self.assertNotIn("representatives", data)
        self.assertEqual(self.assessment.compliance_assessment_id, audit.id)


class RepresentativeSerializersTestCase(TestCase):
    """Tests for Representative-related serializers"""

    def setUp(self):
        self.folder = Folder.objects.create(name="Test Folder")
        self.entity = Entity.objects.create(name="Test Entity", folder=self.folder)
        self.user = User.objects.create_user(
            email="existing@example.com", password="password"
        )

        self.representative_data = {
            "email": "rep@example.com",
            "first_name": "Test",
            "last_name": "Representative",
            "phone": "123456789",
            "role": "Manager",
            "description": "Test description",
            "entity": self.entity,
        }
        self.representative = Representative.objects.create(**self.representative_data)

    def test_representative_read_serializer(self):
        """Test that RepresentativeReadSerializer correctly serializes a Representative"""
        serializer = RepresentativeReadSerializer(self.representative)
        data = serializer.data

        self.assertEqual(data["email"], self.representative_data["email"])
        self.assertEqual(data["first_name"], self.representative_data["first_name"])
        self.assertEqual(data["last_name"], self.representative_data["last_name"])
        self.assertEqual(data["phone"], self.representative_data["phone"])
        self.assertEqual(data["role"], self.representative_data["role"])
        self.assertEqual(data["description"], self.representative_data["description"])
        self.assertIn("entity", data)
        self.assertIn("user", data)

    @patch("tprm.serializers.RepresentativeWriteSerializer._create_or_update_user")
    def test_representative_write_serializer_create_user(self, mock_create_or_update):
        """Test that RepresentativeWriteSerializer correctly creates a Representative and user"""
        data = {
            "email": "newrep@example.com",
            "first_name": "New",
            "last_name": "Representative",
            "entity": self.entity.id,
            "create_user": True,
        }

        with patch("iam.models.RoleAssignment.is_access_allowed", return_value=True):
            serializer = RepresentativeWriteSerializer(
                data=data, context={"request": MagicMock()}
            )
            self.assertTrue(serializer.is_valid())
            serializer.save()

        mock_create_or_update.assert_called_once()

        call_args = mock_create_or_update.call_args[0]
        self.assertIsInstance(call_args[0], Representative)

        self.assertEqual(call_args[0].email, data["email"])
        self.assertEqual(call_args[0].first_name, data["first_name"])
        self.assertEqual(call_args[0].last_name, data["last_name"])

        self.assertEqual(call_args[1], data["create_user"])

    @patch("iam.models.RoleAssignment.is_access_allowed", return_value=True)
    @patch("iam.models.User.objects.filter")
    def test_representative_write_serializer_existing_third_party_user(
        self, mock_filter, mock_is_access_allowed
    ):
        """Test that RepresentativeWriteSerializer correctly associates an existing third-party user with a Representative"""
        self.user.is_third_party = True

        mock_filter_result = MagicMock()
        mock_filter_result.first.return_value = self.user
        mock_filter.return_value = mock_filter_result

        data = {
            "email": "existing@example.com",
            "first_name": "Updated",
            "last_name": "User",
            "entity": self.entity.id,
            "create_user": True,
        }

        serializer = RepresentativeWriteSerializer(
            data=data, context={"request": MagicMock()}
        )
        self.assertTrue(serializer.is_valid())
        representative = serializer.save()

        self.assertEqual(representative.user, self.user)

    @patch("iam.models.RoleAssignment.is_access_allowed", return_value=True)
    @patch("iam.models.User.objects.filter")
    def test_representative_write_serializer_rejects_internal_user(
        self, mock_filter, mock_is_access_allowed
    ):
        """Test that RepresentativeWriteSerializer refuses to convert an internal user to third-party"""
        mock_filter_result = MagicMock()
        mock_filter_result.first.return_value = self.user
        mock_filter.return_value = mock_filter_result

        data = {
            "email": "existing@example.com",
            "first_name": "Updated",
            "last_name": "User",
            "entity": self.entity.id,
            "create_user": True,
        }

        serializer = RepresentativeWriteSerializer(
            data=data, context={"request": MagicMock()}
        )
        self.assertTrue(serializer.is_valid())

        with self.assertRaises(ValidationError):
            serializer.save()

    @patch("iam.models.RoleAssignment.is_access_allowed", return_value=True)
    @patch("iam.models.User.objects.create_user")
    @patch("iam.models.User.objects.filter")
    def test_representative_write_serializer_error_handling(
        self, mock_filter, mock_create_user, mock_is_access_allowed
    ):
        """Test that RepresentativeWriteSerializer handles errors when creating a user"""
        mock_filter_result = MagicMock()
        mock_filter_result.first.return_value = None
        mock_filter.return_value = mock_filter_result

        mock_create_user.side_effect = Exception("Error creating user")

        data = {
            "email": "error@example.com",
            "first_name": "Error",
            "last_name": "Test",
            "entity": self.entity.id,
            "create_user": True,
        }

        serializer = RepresentativeWriteSerializer(
            data=data, context={"request": MagicMock()}
        )
        self.assertTrue(serializer.is_valid())

        with self.assertRaises(ValidationError):
            serializer.save()


class SolutionSerializersTestCase(TestCase):
    """Tests for Solution-related serializers"""

    def setUp(self):
        self.folder = Folder.objects.create(name="Test Folder")
        self.provider_entity = Entity.objects.create(
            name="Provider Entity", folder=self.folder
        )
        self.recipient_entity = Entity.objects.create(
            name="Recipient Entity", folder=self.folder
        )

        self.solution = Solution.objects.create(
            name="Test Solution",
            description="Solution description",
            provider_entity=self.provider_entity,
            recipient_entity=self.recipient_entity,
            ref_id="SOL-001",
            criticality=3,
        )

    def test_solution_read_serializer(self):
        """Test that SolutionReadSerializer correctly serializes a Solution"""
        serializer = SolutionReadSerializer(self.solution)
        data = serializer.data

        self.assertEqual(data["name"], "Test Solution")
        self.assertEqual(data["description"], "Solution description")
        self.assertEqual(data["ref_id"], "SOL-001")
        self.assertEqual(data["criticality"], 3)
        self.assertIn("provider_entity", data)
        self.assertIn("recipient_entity", data)
        self.assertIn("assets", data)

    def test_solution_read_serializer_dora_ict_service_type_is_raw_code(self):
        """The frontend maps dora_ict_service_type to a translation from the EBA
        code, so the read serializer must expose the raw value, not the display
        label. Sibling DORA choice fields keep the display label on purpose:
        their labels are what the frontend translates from."""
        self.solution.dora_ict_service_type = "eba_TA:S02"
        self.solution.dora_reliance_level = "eba_ZZ:x795"
        self.solution.save()

        data = SolutionReadSerializer(self.solution).data

        self.assertEqual(data["dora_ict_service_type"], "eba_TA:S02")
        self.assertEqual(data["dora_reliance_level"], "Low reliance")

    @patch("iam.models.RoleAssignment.is_access_allowed", return_value=True)
    def test_solution_write_serializer(self, mock_is_access_allowed):
        """Test that SolutionWriteSerializer correctly creates a Solution"""
        new_solution_data = {
            "name": "New Solution",
            "description": "New description",
            "provider_entity": self.provider_entity.id,
            "ref_id": "SOL-002",
            "criticality": 2,
        }

        serializer = SolutionWriteSerializer(
            data=new_solution_data, context={"request": MagicMock()}
        )
        self.assertTrue(serializer.is_valid())
        solution = serializer.save()

        self.assertEqual(solution.name, new_solution_data["name"])
        self.assertEqual(solution.description, new_solution_data["description"])
        self.assertEqual(solution.provider_entity, self.provider_entity)
        self.assertEqual(solution.ref_id, new_solution_data["ref_id"])
        self.assertEqual(solution.criticality, new_solution_data["criticality"])
        self.assertIsNone(solution.recipient_entity)


# ===========================================================================
# SolutionSubcontractor serialization + chain semantics
# ===========================================================================


class SolutionSubcontractingChainTestCase(TestCase):
    """
    Tests for the nested `subcontracting_chain` field on Solution serializers
    (DORA Art. 28(2) data model). Covers:
      - Read serialization exposes the chain (id, subcontractor, recipient).
      - Write: create/update replacing the chain via bulk delete+insert.
      - PATCH empty array → clears; PATCH omitting → leaves untouched.
      - Recipient-based tree structure and fan-out.
    """

    def setUp(self):
        from tprm.models import SolutionSubcontractor

        self.folder = Folder.objects.create(name="Chain Test Folder")
        self.direct = Entity.objects.create(
            name="Direct", folder=self.folder, legal_identifiers={"LEI": "DIRE1"}
        )
        self.sub_a = Entity.objects.create(
            name="Sub A", folder=self.folder, legal_identifiers={"LEI": "SUBA1"}
        )
        self.sub_b = Entity.objects.create(
            name="Sub B", folder=self.folder, legal_identifiers={"LEI": "SUBB1"}
        )
        self.sub_c = Entity.objects.create(
            name="Sub C", folder=self.folder, legal_identifiers={"LEI": "SUBC1"}
        )
        self.solution = Solution.objects.create(
            name="Chain Sol", provider_entity=self.direct
        )
        self.SolutionSubcontractor = SolutionSubcontractor

    def _seed_chain(self):
        """Seed a 2-entry chain for tests that care about existing state."""
        self.SolutionSubcontractor.objects.create(
            solution=self.solution, subcontractor=self.sub_a
        )
        self.SolutionSubcontractor.objects.create(
            solution=self.solution, subcontractor=self.sub_b
        )

    # --- Read path --------------------------------------------------------

    def test_read_serializer_exposes_chain(self):
        self._seed_chain()
        data = SolutionReadSerializer(self.solution).data
        chain = data["subcontracting_chain"]
        self.assertEqual(len(chain), 2)
        # Each row exposes id, subcontractor, recipient — no rank.
        self.assertIn("id", chain[0])
        self.assertIn("subcontractor", chain[0])
        self.assertIn("recipient", chain[0])
        self.assertNotIn("rank", chain[0])
        # Ordered by created_at: sub_a first, sub_b second.
        self.assertEqual(str(chain[0]["subcontractor"]["id"]), str(self.sub_a.id))
        self.assertEqual(str(chain[1]["subcontractor"]["id"]), str(self.sub_b.id))

    def test_read_serializer_empty_chain_renders_empty_list(self):
        data = SolutionReadSerializer(self.solution).data
        self.assertEqual(data["subcontracting_chain"], [])

    # --- Write path: create ----------------------------------------------

    @patch("iam.models.RoleAssignment.is_access_allowed", return_value=True)
    def test_create_with_chain_persists_rows(self, _):
        payload = {
            "name": "Fresh Sol",
            "provider_entity": self.direct.id,
            "subcontracting_chain": [
                {"subcontractor": self.sub_a.id},
                {"subcontractor": self.sub_b.id},
            ],
        }
        serializer = SolutionWriteSerializer(
            data=payload, context={"request": MagicMock()}
        )
        self.assertTrue(serializer.is_valid(), serializer.errors)
        solution = serializer.save()
        chain = list(solution.subcontracting_chain.all())
        self.assertEqual(len(chain), 2)
        self.assertEqual(
            [r.subcontractor_id for r in chain], [self.sub_a.id, self.sub_b.id]
        )

    @patch("iam.models.RoleAssignment.is_access_allowed", return_value=True)
    def test_create_without_chain_leaves_chain_empty(self, _):
        payload = {"name": "No-Chain Sol", "provider_entity": self.direct.id}
        serializer = SolutionWriteSerializer(
            data=payload, context={"request": MagicMock()}
        )
        self.assertTrue(serializer.is_valid(), serializer.errors)
        solution = serializer.save()
        self.assertEqual(solution.subcontracting_chain.count(), 0)

    # --- Write path: validation ------------------------------------------

    @patch("iam.models.RoleAssignment.is_access_allowed", return_value=True)
    def test_chain_rejects_direct_provider(self, _):
        payload = {
            "name": "Loop Sol",
            "provider_entity": self.direct.id,
            "subcontracting_chain": [
                {"subcontractor": self.direct.id},
            ],
        }
        serializer = SolutionWriteSerializer(
            data=payload, context={"request": MagicMock()}
        )
        # validation itself passes (direct check happens in _replace_chain
        # because it needs the bound Solution); .save() raises.
        self.assertTrue(serializer.is_valid(), serializer.errors)
        with self.assertRaises(ValidationError) as cm:
            serializer.save()
        self.assertIn("subcontracting_chain", cm.exception.detail)

    @patch("iam.models.RoleAssignment.is_access_allowed", return_value=True)
    def test_chain_rejects_duplicate_subcontractor(self, _):
        payload = {
            "name": "Dup Sol",
            "provider_entity": self.direct.id,
            "subcontracting_chain": [
                {"subcontractor": self.sub_a.id},
                {"subcontractor": self.sub_a.id},
            ],
        }
        serializer = SolutionWriteSerializer(
            data=payload, context={"request": MagicMock()}
        )
        self.assertFalse(serializer.is_valid())
        self.assertIn("subcontracting_chain", serializer.errors)

    # --- Write path: update (PATCH) --------------------------------------

    @patch("iam.models.RoleAssignment.is_access_allowed", return_value=True)
    def test_patch_with_empty_array_clears_chain(self, _):
        self._seed_chain()
        self.assertEqual(self.solution.subcontracting_chain.count(), 2)
        serializer = SolutionWriteSerializer(
            instance=self.solution,
            data={"subcontracting_chain": []},
            partial=True,
            context={"request": MagicMock()},
        )
        self.assertTrue(serializer.is_valid(), serializer.errors)
        serializer.save()
        self.solution.refresh_from_db()
        self.assertEqual(self.solution.subcontracting_chain.count(), 0)

    @patch("iam.models.RoleAssignment.is_access_allowed", return_value=True)
    def test_patch_omitting_chain_leaves_unchanged(self, _):
        self._seed_chain()
        serializer = SolutionWriteSerializer(
            instance=self.solution,
            data={"name": "Renamed Only"},
            partial=True,
            context={"request": MagicMock()},
        )
        self.assertTrue(serializer.is_valid(), serializer.errors)
        serializer.save()
        self.solution.refresh_from_db()
        self.assertEqual(self.solution.name, "Renamed Only")
        # Chain untouched.
        self.assertEqual(self.solution.subcontracting_chain.count(), 2)

    @patch("iam.models.RoleAssignment.is_access_allowed", return_value=True)
    def test_patch_replaces_chain_completely(self, _):
        """Write is replace-semantics, not merge — old rows go, new rows come."""
        self._seed_chain()
        serializer = SolutionWriteSerializer(
            instance=self.solution,
            data={
                "subcontracting_chain": [
                    {"subcontractor": self.sub_c.id},
                ]
            },
            partial=True,
            context={"request": MagicMock()},
        )
        self.assertTrue(serializer.is_valid(), serializer.errors)
        serializer.save()
        self.solution.refresh_from_db()
        chain = list(self.solution.subcontracting_chain.all())
        self.assertEqual(len(chain), 1)
        self.assertEqual(chain[0].subcontractor_id, self.sub_c.id)

    @patch("iam.models.RoleAssignment.is_access_allowed", return_value=True)
    def test_patch_updates_recipient_tree_structure(self, _):
        """Updating recipient on existing rows changes the tree topology."""
        self._seed_chain()  # A (null recipient), B (null recipient)
        # Re-patch: B now subcontracts under A.
        serializer = SolutionWriteSerializer(
            instance=self.solution,
            data={
                "subcontracting_chain": [
                    {"subcontractor": self.sub_a.id, "recipient": None},
                    {
                        "subcontractor": self.sub_b.id,
                        "recipient": self.sub_a.id,
                    },
                ]
            },
            partial=True,
            context={"request": MagicMock()},
        )
        self.assertTrue(serializer.is_valid(), serializer.errors)
        serializer.save()
        chain = list(self.solution.subcontracting_chain.all())
        self.assertEqual(len(chain), 2)
        row_a = next(r for r in chain if r.subcontractor_id == self.sub_a.id)
        row_b = next(r for r in chain if r.subcontractor_id == self.sub_b.id)
        self.assertIsNone(row_a.recipient_id)
        self.assertEqual(row_b.recipient_id, self.sub_a.id)

    @patch("iam.models.RoleAssignment.is_access_allowed", return_value=True)
    def test_fan_out_persists_via_shared_null_recipient(self, _):
        """Two subcontractors both with recipient=null (both children of direct provider)."""
        payload = {
            "name": "FanOut Sol",
            "provider_entity": self.direct.id,
            "subcontracting_chain": [
                {"subcontractor": self.sub_a.id, "recipient": None},
                {"subcontractor": self.sub_b.id, "recipient": None},
            ],
        }
        serializer = SolutionWriteSerializer(
            data=payload, context={"request": MagicMock()}
        )
        self.assertTrue(serializer.is_valid(), serializer.errors)
        solution = serializer.save()
        chain = list(solution.subcontracting_chain.all())
        self.assertEqual(len(chain), 2)
        self.assertTrue(all(r.recipient_id is None for r in chain))
        sub_ids = {r.subcontractor_id for r in chain}
        self.assertEqual(sub_ids, {self.sub_a.id, self.sub_b.id})
        # Verify read serializer also returns both.
        read_data = SolutionReadSerializer(solution).data
        self.assertEqual(len(read_data["subcontracting_chain"]), 2)


# ===========================================================================
# EntityReadSerializer subcontracts usage fields
# ===========================================================================


class EntitySubcontractsUsageTestCase(TestCase):
    def setUp(self):
        from tprm.models import SolutionSubcontractor

        self.folder = Folder.objects.create(name="Folder")
        self.direct = Entity.objects.create(
            name="Direct", folder=self.folder, legal_identifiers={"LEI": "DIRE1"}
        )
        self.aws = Entity.objects.create(
            name="AWS", folder=self.folder, legal_identifiers={"LEI": "AWSX1"}
        )
        # Two solutions both subcontract to AWS.
        self.sol_a = Solution.objects.create(
            name="Service A", provider_entity=self.direct
        )
        self.sol_b = Solution.objects.create(
            name="Service B", provider_entity=self.direct
        )
        SolutionSubcontractor.objects.create(
            solution=self.sol_a, subcontractor=self.aws
        )
        SolutionSubcontractor.objects.create(
            solution=self.sol_b, subcontractor=self.aws
        )

    def test_subcontracts_count_reflects_usage(self):
        data = EntityReadSerializer(self.aws).data
        self.assertEqual(data["subcontracts_count"], 2)

    def test_subcontracts_usage_lists_blocking_solutions(self):
        data = EntityReadSerializer(self.aws).data
        usage = data["subcontracts_usage"]
        self.assertEqual(len(usage), 2)
        solution_names = sorted(u["solution_name"] for u in usage)
        self.assertEqual(solution_names, ["Service A", "Service B"])
        # No rank field in usage rows.
        for u in usage:
            self.assertNotIn("rank", u)
            self.assertIn("solution_id", u)
            self.assertIn("solution_name", u)

    def test_non_subcontractor_has_zero_count(self):
        other = Entity.objects.create(name="Other", folder=self.folder)
        data = EntityReadSerializer(other).data
        self.assertEqual(data["subcontracts_count"], 0)
        self.assertEqual(data["subcontracts_usage"], [])
