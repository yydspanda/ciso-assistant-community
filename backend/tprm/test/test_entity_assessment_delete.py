from contextlib import contextmanager
from unittest.mock import MagicMock, patch

from django.contrib.auth import get_user_model
from django.db import transaction
from django.db.models.query import QuerySet
from django.test import TestCase
from rest_framework.exceptions import PermissionDenied

from core.models import (
    Actor,
    Answer,
    Comment,
    ComplianceAssessment,
    Evidence,
    Framework,
    Perimeter,
    Question,
    QuestionChoice,
    RequirementAssessment,
    RequirementAssignment,
    RequirementAssignmentEvent,
    RequirementAssignmentMailEvidence,
    RequirementAssignmentMailOutbox,
    RequirementNode,
    ValidationFlow,
)
from core.utils import RoleCodename, UserGroupCodename
from iam.models import Folder, IdPGroup, Role, RoleAssignment, UserGroup
from pmbok.models import GenericCollection
from tprm.deletion_authority import assert_entity_assessment_deletion_manifest
from tprm.models import Entity, EntityAssessment, Representative, Solution
from tprm.views import EntityAssessmentViewSet

User = get_user_model()


@contextmanager
def _patched_deletion_graphs():
    with (
        patch(
            "tprm.views.EntityAssessmentViewSet._lock_linked_audit_deletion_graph"
        ) as audit_graph,
        patch("tprm.deletion_authority.lock_entity_assessment_deletion_graph"),
    ):
        yield audit_graph


class EntityAssessmentDeleteTests(TestCase):
    def setUp(self):
        self.domain = Folder.objects.create(name="TPRM delete domain")
        self.enclave = Folder.objects.create(
            name="TPRM audit enclave",
            content_type=Folder.ContentType.ENCLAVE,
            parent_folder=self.domain,
        )
        self.framework = Framework.objects.create(
            name="TPRM delete framework",
            min_score=0,
            max_score=100,
            folder=self.domain,
        )
        self.audit = ComplianceAssessment.objects.create(
            name="TPRM delete audit",
            framework=self.framework,
            folder=self.enclave,
        )
        self.entity = Entity.objects.create(
            name="TPRM delete entity",
            folder=self.domain,
        )
        self.assessment = EntityAssessment.objects.create(
            name="TPRM delete assessment",
            entity=self.entity,
            folder=self.domain,
            compliance_assessment=self.audit,
        )
        self.user = User.objects.create_user(
            email="tprm-delete@example.com",
            password="password",
        )
        self.view = EntityAssessmentViewSet()
        self.view.request = MagicMock(user=self.user)
        self.view.action = "destroy"
        self.view.format_kwarg = None
        self.view.kwargs = {"pk": str(self.assessment.id)}

    @staticmethod
    def _governed_delete_patches(*, full_view=True):
        return (
            patch(
                "core.utils.has_full_view_compliance_assessment",
                return_value=full_view,
            ),
            patch("core.views._assert_object_action_permission"),
            _patched_deletion_graphs(),
        )

    def test_missing_full_audit_view_preserves_entire_tree(self):
        full_view, object_permission, complete_access = self._governed_delete_patches(
            full_view=False
        )
        with full_view, object_permission, complete_access:
            with self.assertRaises(PermissionDenied):
                self.view.perform_destroy(self.assessment)

        self.assertTrue(EntityAssessment.objects.filter(id=self.assessment.id).exists())
        self.assertTrue(ComplianceAssessment.objects.filter(id=self.audit.id).exists())
        self.assertTrue(Folder.objects.filter(id=self.enclave.id).exists())

    def test_locked_or_in_review_audit_preserves_entire_tree(self):
        for is_locked, status in (
            (True, ComplianceAssessment.Status.PLANNED),
            (False, ComplianceAssessment.Status.IN_REVIEW),
        ):
            with self.subTest(is_locked=is_locked, status=status):
                self.audit.is_locked = is_locked
                self.audit.status = status
                self.audit.save(update_fields=["is_locked", "status"])
                full_view, object_permission, complete_access = (
                    self._governed_delete_patches()
                )
                with full_view, object_permission, complete_access:
                    with self.assertRaises(PermissionDenied):
                        self.view.perform_destroy(self.assessment)

                self.assertTrue(
                    EntityAssessment.objects.filter(id=self.assessment.id).exists()
                )
                self.assertTrue(
                    ComplianceAssessment.objects.filter(id=self.audit.id).exists()
                )
                self.assertTrue(Folder.objects.filter(id=self.enclave.id).exists())

    def test_locked_or_in_review_entity_assessment_preserves_linked_tree(self):
        for is_locked, status in (
            (True, EntityAssessment.Status.PLANNED),
            (False, EntityAssessment.Status.IN_REVIEW),
        ):
            with self.subTest(is_locked=is_locked, status=status):
                self.assessment.is_locked = is_locked
                self.assessment.status = status
                self.assessment.save(update_fields=["is_locked", "status"])
                full_view, object_permission, deletion_graphs = (
                    self._governed_delete_patches()
                )
                with full_view, object_permission, deletion_graphs:
                    with self.assertRaises(PermissionDenied):
                        self.view.perform_destroy(self.assessment)

                self.assertTrue(
                    EntityAssessment.objects.filter(id=self.assessment.id).exists()
                )
                self.assertTrue(
                    ComplianceAssessment.objects.filter(id=self.audit.id).exists()
                )
                self.assertTrue(Folder.objects.filter(id=self.enclave.id).exists())

    def test_locked_or_in_review_standalone_entity_assessment_is_preserved(self):
        self.assessment.compliance_assessment = None
        self.assessment.save(update_fields=["compliance_assessment"])

        for is_locked, status in (
            (True, EntityAssessment.Status.PLANNED),
            (False, EntityAssessment.Status.IN_REVIEW),
        ):
            with self.subTest(is_locked=is_locked, status=status):
                self.assessment.is_locked = is_locked
                self.assessment.status = status
                self.assessment.save(update_fields=["is_locked", "status"])
                full_view, object_permission, deletion_graphs = (
                    self._governed_delete_patches()
                )
                with full_view, object_permission, deletion_graphs:
                    with self.assertRaises(PermissionDenied):
                        self.view.perform_destroy(self.assessment)

                self.assertTrue(
                    EntityAssessment.objects.filter(id=self.assessment.id).exists()
                )
                self.assertTrue(Folder.objects.filter(id=self.domain.id).exists())

    def test_authorized_delete_checks_ea_audit_and_enclave_then_deletes(self):
        full_view, object_permission, complete_access = self._governed_delete_patches()
        with (
            full_view,
            object_permission as check_permission,
            complete_access,
            patch("iam.models.RoleAssignment.is_access_allowed", return_value=True),
            patch("core.views.dispatch_webhook_event"),
        ):
            self.view.perform_destroy(self.assessment)

        checked_models = [
            type(call.kwargs["instance"]) for call in check_permission.call_args_list
        ]
        self.assertEqual(
            checked_models,
            [EntityAssessment, ComplianceAssessment, Folder],
        )
        self.assertFalse(
            EntityAssessment.objects.filter(id=self.assessment.id).exists()
        )
        self.assertFalse(ComplianceAssessment.objects.filter(id=self.audit.id).exists())
        self.assertFalse(Folder.objects.filter(id=self.enclave.id).exists())

    def test_standalone_delete_uses_complete_entity_assessment_relation_graph(self):
        representative = User.objects.create_user(
            email="standalone-representative@example.com",
            password="password",
            is_third_party=True,
        )
        representative_actor, _created = Actor.objects.get_or_create(
            user=representative
        )
        representative_row = Representative.objects.create(
            entity=self.entity,
            user=representative,
            email=representative.email,
        )
        perimeter = Perimeter.objects.create(
            name="Standalone EA perimeter",
            folder=self.domain,
        )
        evidence = Evidence.objects.create(
            name="Standalone EA evidence",
            folder=self.domain,
        )
        solution = Solution.objects.create(
            name="Standalone EA solution",
            provider_entity=self.entity,
        )
        self.assessment.compliance_assessment = None
        self.assessment.perimeter = perimeter
        self.assessment.evidence = evidence
        self.assessment.save(
            update_fields=["compliance_assessment", "perimeter", "evidence"]
        )
        self.assessment.authors.add(representative_actor)
        self.assessment.representatives.add(representative)
        self.assessment.solutions.add(solution)

        hidden_rows = (
            (Folder, self.domain.id),
            (Entity, self.entity.id),
            (Perimeter, perimeter.id),
            (Evidence, evidence.id),
            (Actor, representative_actor.id),
            (User, representative.id),
            (Representative, representative_row.id),
            (Solution, solution.id),
        )
        for hidden_model, hidden_id in hidden_rows:
            with self.subTest(hidden_model=hidden_model._meta.label_lower):

                def hide_one(
                    _user,
                    model,
                    hidden_model=hidden_model,
                    hidden_id=hidden_id,
                ):
                    queryset = model.objects.all()
                    if model is hidden_model:
                        queryset = queryset.exclude(id=hidden_id)
                    return queryset.values_list("id", flat=True)

                with (
                    patch(
                        "tprm.deletion_authority.RoleAssignment.get_viewable_object_ids",
                        side_effect=hide_one,
                    ),
                    patch("iam.models.RoleAssignment.is_access_allowed", return_value=True),
                    patch("core.views._assert_object_action_permission"),
                    self.assertRaises(PermissionDenied),
                ):
                    self.view.perform_destroy(self.assessment)

        self.assertTrue(EntityAssessment.objects.filter(id=self.assessment.id).exists())
        self.assertTrue(Entity.objects.filter(id=self.entity.id).exists())
        self.assertTrue(Evidence.objects.filter(id=evidence.id).exists())

    def test_standalone_assessment_with_complete_graph_remains_deletable(self):
        self.assessment.compliance_assessment = None
        self.assessment.save(update_fields=["compliance_assessment"])

        def all_ids(_user, model):
            return model.objects.values_list("id", flat=True)

        with (
            patch(
                "tprm.deletion_authority.RoleAssignment.get_viewable_object_ids",
                side_effect=all_ids,
            ),
            patch("iam.models.RoleAssignment.is_access_allowed", return_value=True),
            patch("core.views._assert_object_action_permission"),
            patch("core.views.dispatch_webhook_event"),
        ):
            self.view.perform_destroy(self.assessment)

        self.assertFalse(EntityAssessment.objects.filter(id=self.assessment.id).exists())
        self.assertTrue(Entity.objects.filter(id=self.entity.id).exists())

    def test_entity_assessment_deletion_manifest_matches_model_metadata(self):
        assert_entity_assessment_deletion_manifest()

    def test_late_delete_failure_rolls_back_enclave_cascade(self):
        full_view, object_permission, complete_access = self._governed_delete_patches()
        with (
            full_view,
            object_permission,
            complete_access,
            patch(
                "tprm.views.EntityAssessmentViewSet._assert_enclave_contains_only_iam_scaffolding",
                side_effect=PermissionDenied("late denial"),
            ),
        ):
            with self.assertRaises(PermissionDenied):
                self.view.perform_destroy(self.assessment)

        self.assertTrue(EntityAssessment.objects.filter(id=self.assessment.id).exists())
        self.assertTrue(ComplianceAssessment.objects.filter(id=self.audit.id).exists())
        self.assertTrue(Folder.objects.filter(id=self.enclave.id).exists())

    def test_second_audit_in_enclave_blocks_entire_delete(self):
        second_audit = ComplianceAssessment.objects.create(
            name="Unrelated hidden audit",
            framework=self.framework,
            folder=self.enclave,
        )
        full_view, object_permission, complete_access = self._governed_delete_patches()
        with full_view, object_permission, complete_access:
            with self.assertRaises(PermissionDenied):
                self.view.perform_destroy(self.assessment)

        self.assertTrue(EntityAssessment.objects.filter(id=self.assessment.id).exists())
        self.assertTrue(ComplianceAssessment.objects.filter(id=self.audit.id).exists())
        self.assertTrue(
            ComplianceAssessment.objects.filter(id=second_audit.id).exists()
        )
        self.assertTrue(Folder.objects.filter(id=self.enclave.id).exists())

    def test_external_role_assignment_perimeter_link_blocks_enclave_delete(self):
        external_assignment = RoleAssignment.objects.create(
            user=self.user,
            role=Role.objects.get(name=RoleCodename.READER),
            folder=self.domain,
            is_recursive=False,
        )
        external_assignment.perimeter_folders.add(self.enclave)
        full_view, object_permission, complete_access = self._governed_delete_patches()
        with full_view, object_permission, complete_access:
            with self.assertRaises(PermissionDenied):
                self.view.perform_destroy(self.assessment)

        self.assertTrue(EntityAssessment.objects.filter(id=self.assessment.id).exists())
        self.assertTrue(ComplianceAssessment.objects.filter(id=self.audit.id).exists())
        self.assertTrue(Folder.objects.filter(id=self.enclave.id).exists())
        self.assertTrue(
            external_assignment.perimeter_folders.filter(id=self.enclave.id).exists()
        )

    def test_external_assignment_to_enclave_group_blocks_delete(self):
        group = UserGroup.objects.create(
            name=UserGroupCodename.THIRD_PARTY_RESPONDENT.value,
            folder=self.enclave,
            builtin=True,
        )
        canonical_assignment = RoleAssignment.objects.create(
            user_group=group,
            role=Role.objects.get(name=RoleCodename.THIRD_PARTY_RESPONDENT.value),
            builtin=True,
            folder=self.enclave,
            is_recursive=True,
        )
        canonical_assignment.perimeter_folders.add(self.enclave)
        external_assignment = RoleAssignment.objects.create(
            user_group=group,
            role=Role.objects.get(name=RoleCodename.READER.value),
            folder=self.domain,
        )
        external_assignment.perimeter_folders.add(self.domain)
        full_view, object_permission, complete_access = self._governed_delete_patches()
        with full_view, object_permission, complete_access:
            with self.assertRaises(PermissionDenied):
                self.view.perform_destroy(self.assessment)

        self.assertTrue(EntityAssessment.objects.filter(id=self.assessment.id).exists())
        self.assertTrue(
            RoleAssignment.objects.filter(id=external_assignment.id).exists()
        )
        self.assertTrue(UserGroup.objects.filter(id=group.id).exists())

    def test_canonical_respondent_assignment_must_be_owned_by_enclave(self):
        group = UserGroup.objects.create(
            name=UserGroupCodename.THIRD_PARTY_RESPONDENT.value,
            folder=self.enclave,
            builtin=True,
        )
        assignment = RoleAssignment.objects.create(
            user_group=group,
            role=Role.objects.get(name=RoleCodename.THIRD_PARTY_RESPONDENT.value),
            builtin=True,
            # A matching group/perimeter is insufficient: this direct owner
            # controls which folder deletion may cascade the assignment.
            folder=self.domain,
            is_recursive=True,
        )
        assignment.perimeter_folders.add(self.enclave)
        full_view, object_permission, complete_access = self._governed_delete_patches()

        with (
            full_view,
            object_permission,
            complete_access,
            patch("iam.models.RoleAssignment.is_access_allowed", return_value=True),
        ):
            with self.assertRaises(PermissionDenied):
                self.view.perform_destroy(self.assessment)

        self.assertTrue(EntityAssessment.objects.filter(id=self.assessment.id).exists())
        self.assertTrue(ComplianceAssessment.objects.filter(id=self.audit.id).exists())
        self.assertTrue(Folder.objects.filter(id=self.enclave.id).exists())
        assignment.refresh_from_db()
        self.assertEqual(assignment.folder_id, self.domain.id)

    def test_hidden_extra_respondent_membership_blocks_enclave_delete(self):
        representative = User.objects.create_user(
            email="expected-respondent@example.com",
            password="password",
            is_third_party=True,
        )
        hidden_member = User.objects.create_user(
            email="stale-hidden-respondent@example.com",
            password="password",
            is_third_party=True,
        )
        self.assessment.representatives.add(representative)
        group = UserGroup.objects.create(
            name=UserGroupCodename.THIRD_PARTY_RESPONDENT,
            folder=self.enclave,
            builtin=True,
        )
        group.user_set.add(representative, hidden_member)
        assignment = RoleAssignment.objects.create(
            user_group=group,
            role=Role.objects.get(name=RoleCodename.THIRD_PARTY_RESPONDENT),
            builtin=True,
            folder=self.enclave,
            is_recursive=True,
        )
        assignment.perimeter_folders.add(self.enclave)
        full_view, object_permission, complete_access = self._governed_delete_patches()
        with (
            full_view,
            object_permission,
            complete_access,
            patch(
                "tprm.views.RoleAssignment.get_viewable_object_ids",
                side_effect=lambda _user, model: model.objects.values_list(
                    "id", flat=True
                ),
            ),
        ):
            with self.assertRaises(PermissionDenied):
                self.view.perform_destroy(self.assessment)

        self.assertTrue(EntityAssessment.objects.filter(id=self.assessment.id).exists())
        self.assertTrue(ComplianceAssessment.objects.filter(id=self.audit.id).exists())
        self.assertTrue(Folder.objects.filter(id=self.enclave.id).exists())
        self.assertSetEqual(
            set(group.user_set.values_list("id", flat=True)),
            {representative.id, hidden_member.id},
        )

    def test_legacy_idp_inheritance_blocks_enclave_delete_atomically(self):
        representative = User.objects.create_user(
            email="legacy-idp-delete-respondent@example.com",
            password="password",
            is_third_party=True,
        )
        self.assessment.representatives.add(representative)
        group = UserGroup.objects.create(
            name=UserGroupCodename.THIRD_PARTY_RESPONDENT.value,
            folder=self.enclave,
            builtin=True,
        )
        group.user_set.add(representative)
        assignment = RoleAssignment.objects.create(
            user_group=group,
            role=Role.objects.get(name=RoleCodename.THIRD_PARTY_RESPONDENT.value),
            builtin=True,
            folder=self.enclave,
            is_recursive=True,
        )
        assignment.perimeter_folders.add(self.enclave)
        idp_group = IdPGroup.objects.create(name="legacy-tprm-delete-idp")
        idp_group.user_groups.add(group)
        idp_group.users.add(representative)

        full_view, object_permission, complete_access = self._governed_delete_patches()
        with (
            full_view,
            object_permission,
            complete_access,
            patch(
                "tprm.views.RoleAssignment.get_viewable_object_ids",
                side_effect=lambda _user, model: model.objects.values_list(
                    "id", flat=True
                ),
            ),
            patch("iam.models.RoleAssignment.is_access_allowed", return_value=True),
        ):
            with self.assertRaises(PermissionDenied) as exc_info:
                self.view.perform_destroy(self.assessment)

        self.assertIn("managedTprmRespondentMembership", str(exc_info.exception))
        self.assertTrue(EntityAssessment.objects.filter(id=self.assessment.id).exists())
        self.assertTrue(ComplianceAssessment.objects.filter(id=self.audit.id).exists())
        self.assertTrue(Folder.objects.filter(id=self.enclave.id).exists())
        self.assertTrue(IdPGroup.objects.filter(id=idp_group.id).exists())
        self.assertTrue(idp_group.user_groups.filter(id=group.id).exists())
        self.assertSetEqual(
            set(idp_group.users.values_list("id", flat=True)),
            {representative.id},
        )

    def test_unrelated_reverse_m2m_link_blocks_enclave_delete(self):
        self.entity.owned_folders.add(self.enclave)
        full_view, object_permission, complete_access = self._governed_delete_patches()
        with full_view, object_permission, complete_access:
            with self.assertRaises(PermissionDenied):
                self.view.perform_destroy(self.assessment)

        self.assertTrue(EntityAssessment.objects.filter(id=self.assessment.id).exists())
        self.assertTrue(Folder.objects.filter(id=self.enclave.id).exists())
        self.assertTrue(self.entity.owned_folders.filter(id=self.enclave.id).exists())

    def test_collection_link_requires_independent_change_authority(self):
        collection = GenericCollection.objects.create(
            name="Governed assessment collection", folder=self.domain
        )
        collection.entity_assessments.add(self.assessment)
        collection.compliance_assessments.add(self.audit)
        full_view, _object_permission, complete_access = self._governed_delete_patches()

        def deny_collection_change(*, instance, action, **_kwargs):
            if isinstance(instance, GenericCollection) and action == "change":
                raise PermissionDenied("no collection change")

        with (
            full_view,
            patch(
                "core.views._assert_object_action_permission",
                side_effect=deny_collection_change,
            ),
            complete_access,
            patch(
                "tprm.views.RoleAssignment.get_viewable_object_ids",
                side_effect=lambda _user, model: model.objects.values_list(
                    "id", flat=True
                ),
            ),
        ):
            with self.assertRaises(PermissionDenied):
                self.view.perform_destroy(self.assessment)

        self.assertTrue(EntityAssessment.objects.filter(id=self.assessment.id).exists())
        self.assertTrue(ComplianceAssessment.objects.filter(id=self.audit.id).exists())
        self.assertTrue(
            collection.entity_assessments.filter(id=self.assessment.id).exists()
        )
        self.assertTrue(
            collection.compliance_assessments.filter(id=self.audit.id).exists()
        )

    def test_validation_flow_link_must_be_unlinked_by_its_workflow(self):
        flow = ValidationFlow.objects.create(
            folder=self.domain,
            requester=self.user,
            approver=self.user,
            status=ValidationFlow.Status.ACCEPTED,
        )
        flow.entity_assessments.add(self.assessment)
        flow.compliance_assessments.add(self.audit)
        full_view, object_permission, complete_access = self._governed_delete_patches()
        with full_view, object_permission, complete_access:
            with self.assertRaises(PermissionDenied):
                self.view.perform_destroy(self.assessment)

        self.assertTrue(EntityAssessment.objects.filter(id=self.assessment.id).exists())
        self.assertTrue(ComplianceAssessment.objects.filter(id=self.audit.id).exists())
        self.assertTrue(ValidationFlow.objects.filter(id=flow.id).exists())
        self.assertTrue(flow.entity_assessments.filter(id=self.assessment.id).exists())
        self.assertTrue(flow.compliance_assessments.filter(id=self.audit.id).exists())

    def test_additive_or_subtractive_batch_m2m_is_rejected(self):
        for action in ("add_m2m", "remove_m2m"):
            with self.subTest(action=action):
                response = self.view.batch_action(
                    MagicMock(
                        data={
                            "action": action,
                            "ids": [str(self.assessment.id)],
                            "field": "representatives",
                            "value": [],
                        }
                    )
                )
                self.assertEqual(response.status_code, 400)
                self.assertIn("change_m2m", response.data["error"])

    def test_metrics_omits_row_when_audit_or_entity_is_independently_hidden(self):
        def visible_ids(_user, model):
            if model is EntityAssessment:
                return [self.assessment.id]
            if model is Folder:
                return [self.domain.id, self.enclave.id]
            return []

        with patch(
            "tprm.views.RoleAssignment.get_viewable_object_ids",
            side_effect=visible_ids,
        ):
            response = self.view.metrics(MagicMock(user=self.user))

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data, [])

    def test_metrics_omits_entire_row_when_complete_audit_gate_fails(self):
        def visible_ids(_user, model):
            return model.objects.values_list("id", flat=True)

        with (
            patch(
                "tprm.views.RoleAssignment.get_viewable_object_ids",
                side_effect=visible_ids,
            ),
            patch(
                "tprm.views.EntityAssessmentViewSet._assert_complete_linked_audit_read_access",
                side_effect=PermissionDenied("hidden questionnaire"),
            ),
        ):
            response = self.view.metrics(MagicMock(user=self.user))

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data, [])

    def _questionnaire_graph(self):
        node = RequirementNode.objects.create(
            framework=self.framework,
            folder=self.framework.folder,
            urn=f"urn:tprm:delete:{self.framework.id}",
            name="Questionnaire requirement",
            assessable=True,
        )
        question = Question.objects.create(
            requirement_node=node,
            folder=self.framework.folder,
            urn=f"{node.urn}:question",
            type=Question.Type.UNIQUE_CHOICE,
        )
        choice = QuestionChoice.objects.create(
            question=question,
            folder=self.framework.folder,
            urn=f"{question.urn}:choice",
        )
        requirement_assessment = RequirementAssessment.objects.create(
            compliance_assessment=self.audit,
            requirement=node,
            folder=self.enclave,
        )
        answer = Answer.objects.create(
            requirement_assessment=requirement_assessment,
            question=question,
            folder=self.enclave,
        )
        answer.selected_choices.add(choice)
        return requirement_assessment, answer, question, choice

    def test_delete_graph_requires_independent_questionnaire_visibility(self):
        _ra, answer, question, choice = self._questionnaire_graph()

        for hidden_model, hidden_id in (
            (Framework, self.framework.id),
            (RequirementNode, question.requirement_node_id),
            (Question, question.id),
            (QuestionChoice, choice.id),
            (Answer, answer.id),
        ):
            with self.subTest(hidden_model=hidden_model._meta.label_lower):

                def hide_one(
                    _user,
                    model,
                    hidden_model=hidden_model,
                    hidden_id=hidden_id,
                ):
                    queryset = model.objects.all()
                    if model is hidden_model:
                        queryset = queryset.exclude(id=hidden_id)
                    return queryset.values_list("id", flat=True)

                with (
                    patch(
                        "core.utils.has_full_view_compliance_assessment",
                        return_value=True,
                    ),
                    patch(
                        "tprm.views.RoleAssignment.get_viewable_object_ids",
                        side_effect=hide_one,
                    ),
                    patch(
                        "core.views.RoleAssignment.get_viewable_object_ids",
                        side_effect=hide_one,
                    ),
                    patch(
                        "iam.models.RoleAssignment.is_access_allowed",
                        return_value=True,
                    ),
                    patch("core.views._assert_object_action_permission"),
                ):
                    with self.assertRaises(PermissionDenied):
                        self.view.perform_destroy(self.assessment)

        self.assertTrue(EntityAssessment.objects.filter(id=self.assessment.id).exists())
        self.assertTrue(Answer.objects.filter(id=answer.id).exists())

    def test_delete_graph_requires_auditor_field_visibility(self):
        _ra, answer, _question, _choice = self._questionnaire_graph()
        self.audit.field_visibility = {
            "status": {"auditor": "hidden", "auditee": "hidden"},
        }
        self.audit.save(update_fields=["field_visibility"])

        def all_ids(_user, model):
            return model.objects.values_list("id", flat=True)

        with (
            patch("core.utils.has_full_view_compliance_assessment", return_value=True),
            patch(
                "tprm.views.RoleAssignment.get_viewable_object_ids",
                side_effect=all_ids,
            ),
            patch(
                "core.views.RoleAssignment.get_viewable_object_ids",
                side_effect=all_ids,
            ),
            patch("iam.models.RoleAssignment.is_access_allowed", return_value=True),
            patch("core.views._assert_object_action_permission"),
        ):
            with self.assertRaises(PermissionDenied):
                self.view.perform_destroy(self.assessment)

        self.assertTrue(EntityAssessment.objects.filter(id=self.assessment.id).exists())
        self.assertTrue(Answer.objects.filter(id=answer.id).exists())

    def test_delete_graph_requires_assignment_actor_and_carrier_visibility(self):
        actor, _created = Actor.objects.get_or_create(user=self.user)
        assignment = RequirementAssignment.objects.create(
            compliance_assessment=self.audit,
            folder=self.enclave,
        )
        assignment.actor.add(actor)

        def hide_assignment_actor(_user, model):
            queryset = model.objects.all()
            if model is Actor:
                queryset = queryset.exclude(id=actor.id)
            return queryset.values_list("id", flat=True)

        with (
            patch("core.utils.has_full_view_compliance_assessment", return_value=True),
            patch(
                "tprm.views.RoleAssignment.get_viewable_object_ids",
                side_effect=hide_assignment_actor,
            ),
            patch(
                "core.views.RoleAssignment.get_viewable_object_ids",
                side_effect=hide_assignment_actor,
            ),
            patch("iam.models.RoleAssignment.is_access_allowed", return_value=True),
            patch("core.views._assert_object_action_permission"),
        ):
            with self.assertRaises(PermissionDenied):
                self.view.perform_destroy(self.assessment)

        self.assertTrue(EntityAssessment.objects.filter(id=self.assessment.id).exists())
        self.assertTrue(RequirementAssignment.objects.filter(id=assignment.id).exists())
        self.assertTrue(Actor.objects.filter(id=actor.id).exists())

    def test_delete_graph_requires_child_delete_permission(self):
        _ra, answer, _question, _choice = self._questionnaire_graph()

        def all_ids(_user, model):
            return model.objects.values_list("id", flat=True)

        def deny_answer_delete(*, perm, **_kwargs):
            return perm.codename != "delete_answer"

        with (
            patch("core.utils.has_full_view_compliance_assessment", return_value=True),
            patch(
                "tprm.views.RoleAssignment.get_viewable_object_ids",
                side_effect=all_ids,
            ),
            patch(
                "core.views.RoleAssignment.get_viewable_object_ids",
                side_effect=all_ids,
            ),
            patch(
                "iam.models.RoleAssignment.is_access_allowed",
                side_effect=deny_answer_delete,
            ),
            patch("core.views._assert_object_action_permission"),
        ):
            with self.assertRaises(PermissionDenied):
                self.view.perform_destroy(self.assessment)

        self.assertTrue(EntityAssessment.objects.filter(id=self.assessment.id).exists())
        self.assertTrue(Answer.objects.filter(id=answer.id).exists())

    def test_delete_graph_requires_event_and_outbox_delete_permissions(self):
        assignment = RequirementAssignment.objects.create(
            compliance_assessment=self.audit,
            folder=self.enclave,
            status=RequirementAssignment.Status.IN_PROGRESS,
        )
        event = RequirementAssignmentEvent.objects.create(
            assignment=assignment,
            event_type=RequirementAssignment.Status.IN_PROGRESS,
            folder=self.enclave,
        )
        outbox = RequirementAssignmentMailOutbox.objects.create(
            assignment=assignment,
            folder=self.enclave,
            payload_digest="7" * 64,
            recipient_address_hash="8" * 64,
            status=RequirementAssignmentMailOutbox.Status.DELIVERED,
        )
        RequirementAssignmentMailEvidence.objects.create(
            outbox_id_snapshot=outbox.id,
            assignment_id_snapshot=assignment.id,
            folder_id_snapshot=self.enclave.id,
            source=RequirementAssignmentMailEvidence.Source.SYSTEM,
            prior_status=RequirementAssignmentMailOutbox.Status.SENDING,
            status=outbox.status,
            attempts=outbox.attempts,
            payload_digest=outbox.payload_digest,
            recipient_address_hash=outbox.recipient_address_hash,
            record_digest="9" * 64,
        )

        def all_ids(_user, model):
            return model.objects.values_list("id", flat=True)

        for denied_codename in (
            "delete_requirementassignmentevent",
            "delete_requirementassignmentmailoutbox",
        ):
            with self.subTest(denied_codename=denied_codename):

                def deny_one(*, perm, denied_codename=denied_codename, **_kwargs):
                    return perm.codename != denied_codename

                with (
                    patch(
                        "core.utils.has_full_view_compliance_assessment",
                        return_value=True,
                    ),
                    patch(
                        "tprm.views.RoleAssignment.get_viewable_object_ids",
                        side_effect=all_ids,
                    ),
                    patch(
                        "core.views.RoleAssignment.get_viewable_object_ids",
                        side_effect=all_ids,
                    ),
                    patch(
                        "iam.models.RoleAssignment.is_access_allowed",
                        side_effect=deny_one,
                    ),
                    patch("core.views._assert_object_action_permission"),
                ):
                    with self.assertRaises(PermissionDenied):
                        self.view.perform_destroy(self.assessment)

                self.assertTrue(
                    EntityAssessment.objects.filter(id=self.assessment.id).exists()
                )
                self.assertTrue(
                    RequirementAssignmentEvent.objects.filter(id=event.id).exists()
                )
                self.assertTrue(
                    RequirementAssignmentMailOutbox.objects.filter(id=outbox.id).exists()
                )

    def test_delete_graph_rejects_choice_from_another_question(self):
        _ra, answer, _question, _choice = self._questionnaire_graph()
        other_question = Question.objects.create(
            requirement_node=answer.requirement_assessment.requirement,
            folder=self.framework.folder,
            urn=f"urn:tprm:delete:{self.framework.id}:other-question",
            type=Question.Type.UNIQUE_CHOICE,
        )
        foreign_choice = QuestionChoice.objects.create(
            question=other_question,
            folder=self.framework.folder,
            urn=f"{other_question.urn}:choice",
        )
        answer.selected_choices.set([foreign_choice])

        def all_ids(_user, model):
            return model.objects.values_list("id", flat=True)

        with (
            patch("core.utils.has_full_view_compliance_assessment", return_value=True),
            patch(
                "tprm.views.RoleAssignment.get_viewable_object_ids",
                side_effect=all_ids,
            ),
            patch(
                "core.views.RoleAssignment.get_viewable_object_ids",
                side_effect=all_ids,
            ),
            patch("iam.models.RoleAssignment.is_access_allowed", return_value=True),
            patch("core.views._assert_object_action_permission"),
        ):
            with self.assertRaises(PermissionDenied):
                self.view.perform_destroy(self.assessment)

        self.assertTrue(Answer.objects.filter(id=answer.id).exists())
        self.assertTrue(answer.selected_choices.filter(id=foreign_choice.id).exists())

    def test_delete_graph_fails_closed_for_active_assignment_mail(self):
        for index, status in enumerate(
            (
                RequirementAssignmentMailOutbox.Status.QUEUED,
                RequirementAssignmentMailOutbox.Status.SENDING,
                RequirementAssignmentMailOutbox.Status.UNCERTAIN,
                RequirementAssignmentMailOutbox.Status.REVIEW_REQUIRED,
            ),
            start=1,
        ):
            with self.subTest(status=status):
                assignment = RequirementAssignment.objects.create(
                    compliance_assessment=self.audit,
                    folder=self.enclave,
                    status=RequirementAssignment.Status.IN_PROGRESS,
                )
                event = RequirementAssignmentEvent.objects.create(
                    assignment=assignment,
                    event_type=RequirementAssignment.Status.IN_PROGRESS,
                    folder=self.enclave,
                )
                outbox = RequirementAssignmentMailOutbox.objects.create(
                    assignment=assignment,
                    folder=self.enclave,
                    payload_digest=str(index) * 64,
                    recipient_address_hash="a" * 64,
                    status=status,
                )

                with (
                    patch(
                        "core.utils.has_full_view_compliance_assessment",
                        return_value=True,
                    ),
                    patch("core.views._assert_object_action_permission"),
                    patch(
                        "tprm.views.EntityAssessmentViewSet._assert_complete_linked_audit_read_access"
                    ),
                    patch(
                        "tprm.deletion_authority.lock_entity_assessment_deletion_graph"
                    ),
                    self.assertRaisesRegex(PermissionDenied, "queued or sending"),
                ):
                    self.view.perform_destroy(self.assessment)

                self.assertTrue(
                    EntityAssessment.objects.filter(id=self.assessment.id).exists()
                )
                self.assertTrue(
                    ComplianceAssessment.objects.filter(id=self.audit.id).exists()
                )
                self.assertTrue(
                    RequirementAssignment.objects.filter(id=assignment.id).exists()
                )
                self.assertTrue(
                    RequirementAssignmentEvent.objects.filter(id=event.id).exists()
                )
                self.assertTrue(
                    RequirementAssignmentMailOutbox.objects.filter(
                        id=outbox.id
                    ).exists()
                )

                assignment.delete()

    def test_delete_graph_accepts_only_terminal_assignment_mail(self):
        owned_ids = []
        evidence_ids = []
        for index, status in enumerate(
            (
                RequirementAssignmentMailOutbox.Status.DELIVERED,
                RequirementAssignmentMailOutbox.Status.FAILED,
            ),
            start=3,
        ):
            assignment = RequirementAssignment.objects.create(
                compliance_assessment=self.audit,
                folder=self.enclave,
                status=RequirementAssignment.Status.IN_PROGRESS,
            )
            event = RequirementAssignmentEvent.objects.create(
                assignment=assignment,
                event_type=RequirementAssignment.Status.IN_PROGRESS,
                folder=self.enclave,
            )
            outbox = RequirementAssignmentMailOutbox.objects.create(
                assignment=assignment,
                folder=self.enclave,
                payload_digest=str(index) * 64,
                recipient_address_hash="b" * 64,
                status=status,
                attempts=1,
            )
            evidence = RequirementAssignmentMailEvidence.objects.create(
                outbox_id_snapshot=outbox.id,
                assignment_id_snapshot=assignment.id,
                folder_id_snapshot=self.enclave.id,
                source=RequirementAssignmentMailEvidence.Source.SYSTEM,
                prior_status=RequirementAssignmentMailOutbox.Status.SENDING,
                status=status,
                attempts=1,
                payload_digest=outbox.payload_digest,
                recipient_address_hash=outbox.recipient_address_hash,
                record_digest=str(index) * 64,
            )
            owned_ids.append((assignment.id, event.id, outbox.id))
            evidence_ids.append(evidence.id)

        with (
            patch("core.utils.has_full_view_compliance_assessment", return_value=True),
            patch("core.views._assert_object_action_permission"),
            patch(
                "tprm.views.EntityAssessmentViewSet._assert_complete_linked_audit_read_access"
            ),
            patch("tprm.deletion_authority.lock_entity_assessment_deletion_graph"),
            patch("iam.models.RoleAssignment.is_access_allowed", return_value=True),
            patch("core.views.dispatch_webhook_event"),
        ):
            self.view.perform_destroy(self.assessment)

        self.assertFalse(
            EntityAssessment.objects.filter(id=self.assessment.id).exists()
        )
        self.assertFalse(ComplianceAssessment.objects.filter(id=self.audit.id).exists())
        for assignment_id, event_id, outbox_id in owned_ids:
            self.assertFalse(
                RequirementAssignment.objects.filter(id=assignment_id).exists()
            )
            self.assertFalse(
                RequirementAssignmentEvent.objects.filter(id=event_id).exists()
            )
            self.assertFalse(
                RequirementAssignmentMailOutbox.objects.filter(id=outbox_id).exists()
            )
        self.assertSetEqual(
            set(
                RequirementAssignmentMailEvidence.objects.filter(
                    id__in=evidence_ids
                ).values_list("id", flat=True)
            ),
            set(evidence_ids),
        )

    def test_delete_graph_requires_exact_terminal_mail_evidence_snapshot(self):
        recipient_user = User.objects.create_user(
            email="terminal-recipient@example.com",
            password="password",
        )
        recipient_actor, _created = Actor.objects.get_or_create(user=recipient_user)
        other_user = User.objects.create_user(
            email="terminal-other@example.com",
            password="password",
        )
        other_actor, _created = Actor.objects.get_or_create(user=other_user)

        mismatches = (
            ("recipient_actor_id_snapshot", other_actor.id),
            ("requested_by_id_snapshot", other_user.id),
            ("attempts", 3),
            ("failure_code", "different-terminal-outcome"),
        )
        for index, (field_name, mismatched_value) in enumerate(mismatches, start=20):
            with self.subTest(field_name=field_name):
                assignment = RequirementAssignment.objects.create(
                    compliance_assessment=self.audit,
                    folder=self.enclave,
                    status=RequirementAssignment.Status.IN_PROGRESS,
                )
                outbox = RequirementAssignmentMailOutbox.objects.create(
                    assignment=assignment,
                    folder=self.enclave,
                    recipient_actor=recipient_actor,
                    requested_by=self.user,
                    payload_digest=f"{index:064x}",
                    recipient_address_hash="c" * 64,
                    status=RequirementAssignmentMailOutbox.Status.FAILED,
                    attempts=2,
                    failure_code="terminal-failure",
                )
                evidence_values = {
                    "outbox_id_snapshot": outbox.id,
                    "assignment_id_snapshot": assignment.id,
                    "folder_id_snapshot": self.enclave.id,
                    "recipient_actor_id_snapshot": recipient_actor.id,
                    "requested_by_id_snapshot": self.user.id,
                    "source": RequirementAssignmentMailEvidence.Source.SYSTEM,
                    "prior_status": RequirementAssignmentMailOutbox.Status.SENDING,
                    "status": outbox.status,
                    "attempts": outbox.attempts,
                    "payload_digest": outbox.payload_digest,
                    "recipient_address_hash": outbox.recipient_address_hash,
                    "failure_code": outbox.failure_code,
                    "record_digest": f"{index + 100:064x}",
                }
                evidence_values[field_name] = mismatched_value
                RequirementAssignmentMailEvidence.objects.create(**evidence_values)

                with (
                    patch(
                        "core.utils.has_full_view_compliance_assessment",
                        return_value=True,
                    ),
                    patch("core.views._assert_object_action_permission"),
                    patch(
                        "tprm.views.EntityAssessmentViewSet._assert_complete_linked_audit_read_access"
                    ),
                    patch(
                        "tprm.deletion_authority.lock_entity_assessment_deletion_graph"
                    ),
                    patch(
                        "iam.models.RoleAssignment.is_access_allowed",
                        return_value=True,
                    ),
                    self.assertRaisesRegex(
                        PermissionDenied,
                        "no matching immutable evidence",
                    ),
                ):
                    self.view.perform_destroy(self.assessment)

                self.assertTrue(
                    EntityAssessment.objects.filter(id=self.assessment.id).exists()
                )
                self.assertTrue(
                    RequirementAssignment.objects.filter(id=assignment.id).exists()
                )
                self.assertTrue(
                    RequirementAssignmentMailOutbox.objects.filter(
                        id=outbox.id
                    ).exists()
                )
                assignment.delete()

    def test_delete_graph_uses_worker_compatible_mail_lock_order(self):
        requirement_assessment, _answer, _question, _choice = (
            self._questionnaire_graph()
        )
        author_actor, _created = Actor.objects.get_or_create(user=self.user)
        self.audit.authors.add(author_actor)
        author_through = ComplianceAssessment._meta.get_field(
            "authors"
        ).remote_field.through
        Comment.objects.create(
            requirement_assessment=requirement_assessment,
            author=self.user,
            body="Deletion lock-order witness",
        )
        assignment = RequirementAssignment.objects.create(
            compliance_assessment=self.audit,
            folder=self.enclave,
            status=RequirementAssignment.Status.IN_PROGRESS,
        )
        assignment.requirement_assessments.add(requirement_assessment)
        RequirementAssignmentEvent.objects.create(
            assignment=assignment,
            event_type=RequirementAssignment.Status.IN_PROGRESS,
            folder=self.enclave,
        )
        outbox = RequirementAssignmentMailOutbox.objects.create(
            assignment=assignment,
            folder=self.enclave,
            payload_digest="f" * 64,
            recipient_address_hash="e" * 64,
            status=RequirementAssignmentMailOutbox.Status.DELIVERED,
        )
        RequirementAssignmentMailEvidence.objects.create(
            outbox_id_snapshot=outbox.id,
            assignment_id_snapshot=assignment.id,
            folder_id_snapshot=self.enclave.id,
            source=RequirementAssignmentMailEvidence.Source.SYSTEM,
            prior_status=RequirementAssignmentMailOutbox.Status.SENDING,
            status=outbox.status,
            attempts=outbox.attempts,
            payload_digest=outbox.payload_digest,
            recipient_address_hash=outbox.recipient_address_hash,
            record_digest="d" * 64,
        )

        relevant_models = {
            RequirementAssignmentMailOutbox,
            RequirementAssignment,
            RequirementAssignmentEvent,
            RequirementAssessment,
            Answer,
            Comment,
            Actor,
            author_through,
        }
        locked_models = []
        original_fetch_all = QuerySet._fetch_all

        def record_locked_model(queryset):
            if queryset.query.select_for_update and queryset.model in relevant_models:
                locked_models.append(queryset.model)
            return original_fetch_all(queryset)

        def all_ids(_user, model):
            return model.objects.values_list("id", flat=True)

        with (
            transaction.atomic(),
            patch.object(QuerySet, "_fetch_all", record_locked_model),
            patch(
                "tprm.views.RoleAssignment.get_viewable_object_ids",
                side_effect=all_ids,
            ),
            patch("iam.models.RoleAssignment.is_access_allowed", return_value=True),
            patch(
                "tprm.views.EntityAssessmentViewSet._assert_complete_linked_audit_read_access"
            ),
        ):
            self.view._lock_linked_audit_deletion_graph(
                user=self.user,
                audit=self.audit,
                entity_assessment=self.assessment,
            )

        first_lock_by_model = list(dict.fromkeys(locked_models))
        self.assertEqual(
            [model for model in first_lock_by_model if model not in {Actor, author_through}],
            [
                RequirementAssignmentMailOutbox,
                RequirementAssignment,
                RequirementAssignmentEvent,
                RequirementAssessment,
                Answer,
                Comment,
            ],
        )
        self.assertLess(
            first_lock_by_model.index(Actor),
            first_lock_by_model.index(author_through),
        )
