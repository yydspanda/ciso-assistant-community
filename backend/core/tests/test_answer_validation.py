import pytest
from rest_framework.exceptions import PermissionDenied, ValidationError
from core.models import (
    Answer,
    ComplianceAssessment,
    Framework,
    Question,
    QuestionChoice,
    RequirementAssessment,
    RequirementAssignment,
    RequirementAssignmentEvent,
    RequirementAssignmentMailOutbox,
    RequirementNode,
    Assessment,
)
from core.serializers import (
    AnswerWriteSerializer,
    ComplianceAssessmentWriteSerializer,
    RequirementAssessmentWriteSerializer,
)
from iam.models import Folder


@pytest.fixture
def validation_setup(db):
    folder = Folder.get_root_folder()
    fw = Framework.objects.create(
        name="Validation FW",
        folder=folder,
        is_published=True,
    )
    rn1 = RequirementNode.objects.create(
        framework=fw,
        urn="urn:test:val:req:1",
        ref_id="REQ1",
        assessable=True,
        folder=folder,
        is_published=True,
    )
    rn2 = RequirementNode.objects.create(
        framework=fw,
        urn="urn:test:val:req:2",
        ref_id="REQ2",
        assessable=True,
        folder=folder,
        is_published=True,
    )
    q1 = Question.objects.create(
        requirement_node=rn1,
        urn="urn:test:q1",
        ref_id="Q1",
        type=Question.Type.TEXT,
        folder=folder,
        is_published=True,
    )
    q2 = Question.objects.create(
        requirement_node=rn2,
        urn="urn:test:q2",
        ref_id="Q2",
        type=Question.Type.TEXT,
        folder=folder,
        is_published=True,
    )
    ca = ComplianceAssessment.objects.create(
        name="Validation CA",
        framework=fw,
        folder=folder,
        status=Assessment.Status.IN_PROGRESS,
    )
    ra1 = RequirementAssessment.objects.create(
        compliance_assessment=ca,
        requirement=rn1,
        folder=folder,
    )
    return {
        "ca": ca,
        "ra1": ra1,
        "q1": q1,
        "q2": q2,
        "folder": folder,
    }


@pytest.mark.django_db
class TestAnswerValidation:
    def test_compliance_assessment_folder_move_relocates_complete_owned_tree(
        self, validation_setup
    ):
        data = validation_setup
        target_folder = Folder.objects.create(
            name="Relocated audit enclave",
            content_type=Folder.ContentType.ENCLAVE,
            parent_folder=data["folder"],
        )
        assignment = RequirementAssignment.objects.create(
            compliance_assessment=data["ca"],
            folder=data["folder"],
        )
        event = RequirementAssignmentEvent.objects.create(
            assignment=assignment,
            event_type=RequirementAssignment.Status.DRAFT,
            folder=data["folder"],
        )
        outbox = RequirementAssignmentMailOutbox.objects.create(
            assignment=assignment,
            folder=data["folder"],
            payload_digest="a" * 64,
            recipient_address_hash="b" * 64,
            status=RequirementAssignmentMailOutbox.Status.DELIVERED,
        )
        answer = Answer.objects.create(
            requirement_assessment=data["ra1"],
            question=data["q1"],
            folder=data["folder"],
        )

        serializer = ComplianceAssessmentWriteSerializer(
            data["ca"],
            data={"folder": target_folder.id},
            partial=True,
        )
        serializer.is_valid(raise_exception=True)
        serializer.save()

        for instance in (
            data["ca"],
            assignment,
            event,
            outbox,
            data["ra1"],
            answer,
        ):
            instance.refresh_from_db()
            assert instance.folder_id == target_folder.id
        outbox.refresh_from_db()
        assert outbox.payload_digest == "a" * 64

    def test_compliance_assessment_folder_move_rejects_active_mail_intent(
        self, validation_setup
    ):
        data = validation_setup
        target_folder = Folder.objects.create(
            name="Blocked relocation enclave",
            content_type=Folder.ContentType.ENCLAVE,
            parent_folder=data["folder"],
        )
        assignment = RequirementAssignment.objects.create(
            compliance_assessment=data["ca"],
            folder=data["folder"],
        )
        RequirementAssignmentMailOutbox.objects.create(
            assignment=assignment,
            folder=data["folder"],
            payload_digest="c" * 64,
            recipient_address_hash="d" * 64,
            status=RequirementAssignmentMailOutbox.Status.QUEUED,
        )
        serializer = ComplianceAssessmentWriteSerializer(
            data["ca"],
            data={"folder": target_folder.id},
            partial=True,
        )
        serializer.is_valid(raise_exception=True)

        with pytest.raises(ValidationError) as excinfo:
            serializer.save()
        assert "queued or sending" in str(excinfo.value.detail["folder"])
        data["ca"].refresh_from_db()
        assignment.refresh_from_db()
        assert data["ca"].folder_id == data["folder"].id
        assert assignment.folder_id == data["folder"].id

    def test_compliance_assessment_folder_move_fails_closed_on_tainted_child(
        self, validation_setup
    ):
        data = validation_setup
        target_folder = Folder.objects.create(
            name="Tainted relocation target",
            content_type=Folder.ContentType.ENCLAVE,
            parent_folder=data["folder"],
        )
        tainted_folder = Folder.objects.create(
            name="Tainted legacy child folder",
            content_type=Folder.ContentType.ENCLAVE,
            parent_folder=data["folder"],
        )
        data["ra1"].folder = tainted_folder
        data["ra1"].save(update_fields=["folder"])
        serializer = ComplianceAssessmentWriteSerializer(
            data["ca"],
            data={"folder": target_folder.id},
            partial=True,
        )
        serializer.is_valid(raise_exception=True)

        with pytest.raises(ValidationError) as excinfo:
            serializer.save()
        assert "inconsistent folder" in str(excinfo.value.detail["folder"])
        data["ca"].refresh_from_db()
        data["ra1"].refresh_from_db()
        assert data["ca"].folder_id == data["folder"].id
        assert data["ra1"].folder_id == tainted_folder.id

    def test_requirement_assessment_audit_owner_is_immutable(self, validation_setup):
        data = validation_setup
        other_assessment = ComplianceAssessment.objects.create(
            name="Other validation CA",
            framework=data["ca"].framework,
            folder=data["folder"],
            status=Assessment.Status.IN_PROGRESS,
        )
        serializer = RequirementAssessmentWriteSerializer(
            data["ra1"],
            data={"compliance_assessment": other_assessment.id},
            partial=True,
        )

        with pytest.raises(PermissionDenied) as excinfo:
            serializer.is_valid(raise_exception=True)
        assert "immutable" in str(excinfo.value.detail["compliance_assessment"])
        data["ra1"].refresh_from_db()
        assert data["ra1"].compliance_assessment_id == data["ca"].id

    def test_requirement_assessment_folder_is_immutable(self, validation_setup):
        data = validation_setup
        other_folder = Folder.objects.create(
            name="Other requirement assessment folder",
            content_type=Folder.ContentType.ENCLAVE,
            parent_folder=data["folder"],
        )
        serializer = RequirementAssessmentWriteSerializer(
            data["ra1"],
            data={"folder": other_folder.id},
            partial=True,
        )

        with pytest.raises(PermissionDenied) as excinfo:
            serializer.is_valid(raise_exception=True)
        assert "immutable" in str(excinfo.value.detail["folder"])
        data["ra1"].refresh_from_db()
        assert data["ra1"].folder_id == data["ca"].folder_id

    def test_requirement_assessment_create_binds_to_its_audit_folder(
        self, validation_setup
    ):
        data = validation_setup
        other_folder = Folder.objects.create(
            name="Cross-audit requirement assessment folder",
            content_type=Folder.ContentType.ENCLAVE,
            parent_folder=data["folder"],
        )
        mismatched = RequirementAssessmentWriteSerializer(
            data={
                "compliance_assessment": data["ca"].id,
                "folder": other_folder.id,
            }
        )
        with pytest.raises(ValidationError) as excinfo:
            mismatched.is_valid(raise_exception=True)
        assert "compliance assessment folder" in str(excinfo.value.detail["folder"])

        inherited = RequirementAssessmentWriteSerializer(
            data={"compliance_assessment": data["ca"].id}
        )
        inherited.is_valid(raise_exception=True)
        assert inherited.validated_data["folder"].id == data["ca"].folder_id

    def test_rejects_boolean_for_number_question(self, validation_setup):
        data = validation_setup
        data["q1"].type = Question.Type.NUMBER
        data["q1"].save(update_fields=["type"])

        serializer = AnswerWriteSerializer(
            data={
                "requirement_assessment": data["ra1"].id,
                "question": data["q1"].id,
                "value": True,
                "folder": data["folder"].id,
            }
        )

        with pytest.raises(ValidationError) as excinfo:
            serializer.is_valid(raise_exception=True)
        assert "finite numeric value" in str(excinfo.value.detail["value"])

    def test_date_question_requires_exact_iso_calendar_date(self, validation_setup):
        data = validation_setup
        data["q1"].type = Question.Type.DATE
        data["q1"].save(update_fields=["type"])

        invalid = AnswerWriteSerializer(
            data={
                "requirement_assessment": data["ra1"].id,
                "question": data["q1"].id,
                "value": "2026-8-01",
                "folder": data["folder"].id,
            }
        )
        with pytest.raises(ValidationError) as excinfo:
            invalid.is_valid(raise_exception=True)
        assert "YYYY-MM-DD" in str(excinfo.value.detail["value"])

        valid = AnswerWriteSerializer(
            data={
                "requirement_assessment": data["ra1"].id,
                "question": data["q1"].id,
                "value": "2026-08-01",
                "folder": data["folder"].id,
            }
        )
        assert valid.is_valid(), valid.errors
        assert valid.validated_data["value"] == "2026-08-01"

    def test_selected_choice_requires_stable_urn(self, validation_setup):
        data = validation_setup
        data["q1"].type = Question.Type.UNIQUE_CHOICE
        data["q1"].save(update_fields=["type"])
        choice = QuestionChoice.objects.create(
            question=data["q1"],
            urn=None,
            ref_id="NO-URN",
            folder=data["folder"],
            is_published=True,
        )

        serializer = AnswerWriteSerializer(
            data={
                "requirement_assessment": data["ra1"].id,
                "question": data["q1"].id,
                "selected_choices": [choice.id],
                "folder": data["folder"].id,
            }
        )

        with pytest.raises(ValidationError) as excinfo:
            serializer.is_valid(raise_exception=True)
        assert "stable non-empty URN" in str(excinfo.value.detail["value"])

    def test_selected_choice_identity_cannot_be_substituted_by_matching_urn(
        self, validation_setup
    ):
        data = validation_setup
        shared_urn = "urn:test:choice:shared-wire-identity"
        for question in (data["q1"], data["q2"]):
            question.type = Question.Type.UNIQUE_CHOICE
            question.save(update_fields=["type"])
        QuestionChoice.objects.create(
            question=data["q1"],
            urn=shared_urn,
            ref_id="TARGET-CHOICE",
            folder=data["folder"],
        )
        wrong_question_choice = QuestionChoice.objects.create(
            question=data["q2"],
            urn=shared_urn,
            ref_id="OTHER-QUESTION-CHOICE",
            folder=data["folder"],
        )

        serializer = AnswerWriteSerializer(
            data={
                "requirement_assessment": data["ra1"].id,
                "question": data["q1"].id,
                "selected_choices": [wrong_question_choice.id],
                "folder": data["folder"].id,
            }
        )

        with pytest.raises(ValidationError) as excinfo:
            serializer.is_valid(raise_exception=True)
        assert "target question" in str(excinfo.value.detail["value"])

    def test_existing_answer_ownership_carriers_are_immutable(self, validation_setup):
        data = validation_setup
        replacement_question = Question.objects.create(
            requirement_node=data["q1"].requirement_node,
            urn="urn:test:q1-replacement",
            ref_id="Q1-REPLACEMENT",
            type=Question.Type.TEXT,
            folder=data["folder"],
            is_published=True,
        )
        answer = Answer.objects.create(
            requirement_assessment=data["ra1"],
            question=data["q1"],
            value="original",
            folder=data["folder"],
        )

        serializer = AnswerWriteSerializer(
            answer,
            data={"question": replacement_question.id},
            partial=True,
        )

        with pytest.raises(ValidationError) as excinfo:
            serializer.is_valid(raise_exception=True)
        assert "ownership field is immutable" in str(excinfo.value.detail["question"])
        answer.refresh_from_db()
        assert answer.question_id == data["q1"].id
        assert answer.value == "original"

    def test_non_choice_value_update_clears_legacy_selected_choices(
        self, validation_setup
    ):
        data = validation_setup
        data["q1"].type = Question.Type.UNIQUE_CHOICE
        data["q1"].save(update_fields=["type"])
        choice = QuestionChoice.objects.create(
            question=data["q1"],
            urn="urn:test:q1:legacy-choice",
            ref_id="LEGACY-CHOICE",
            folder=data["folder"],
        )
        answer = Answer.objects.create(
            requirement_assessment=data["ra1"],
            question=data["q1"],
            folder=data["folder"],
        )
        answer.selected_choices.add(choice)

        data["q1"].type = Question.Type.TEXT
        data["q1"].save(update_fields=["type"])
        serializer = AnswerWriteSerializer(
            answer,
            data={"value": "normalized text"},
            partial=True,
        )
        serializer.is_valid(raise_exception=True)
        serializer.save()

        answer.refresh_from_db()
        assert answer.value == "normalized text"
        assert not answer.selected_choices.exists()

    def test_answer_create_must_use_requirement_assessment_folder(
        self, validation_setup
    ):
        data = validation_setup
        other_folder = Folder.objects.create(
            name=f"Other answer folder {data['q1'].id}",
            content_type=Folder.ContentType.ENCLAVE,
            parent_folder=data["folder"],
        )
        serializer = AnswerWriteSerializer(
            data={
                "requirement_assessment": data["ra1"].id,
                "question": data["q1"].id,
                "value": "cross-folder",
                "folder": other_folder.id,
            }
        )

        with pytest.raises(ValidationError) as excinfo:
            serializer.is_valid(raise_exception=True)
        assert "requirement assessment folder" in str(excinfo.value.detail["folder"])

    def test_answer_create_without_folder_inherits_requirement_assessment_folder(
        self, validation_setup
    ):
        data = validation_setup
        assessment_folder = Folder.objects.create(
            name=f"Assessment answer folder {data['q1'].id}",
            content_type=Folder.ContentType.ENCLAVE,
            parent_folder=data["folder"],
        )
        data["ca"].folder = assessment_folder
        data["ca"].save(update_fields=["folder"])
        data["ra1"].folder = assessment_folder
        data["ra1"].save(update_fields=["folder"])

        serializer = AnswerWriteSerializer(
            data={
                "requirement_assessment": data["ra1"].id,
                "question": data["q1"].id,
                "value": "same-folder default",
            }
        )
        serializer.is_valid(raise_exception=True)
        answer = serializer.save()

        assert answer.folder_id == assessment_folder.id

    def test_validate_parent_child_consistency(self, validation_setup):
        """Verify that a question must belong to the requirement assessment's node."""
        data = validation_setup
        serializer = AnswerWriteSerializer(
            data={
                "requirement_assessment": data["ra1"].id,
                "question": data["q2"].id,  # q2 belongs to rn2, ra1 belongs to rn1
                "value": "some text",
                "folder": data["folder"].id,
            }
        )
        with pytest.raises(ValidationError) as excinfo:
            serializer.is_valid(raise_exception=True)
        assert "question" in excinfo.value.detail
        assert "does not belong to requirement assessment" in str(
            excinfo.value.detail["question"][0]
        )

    def test_validate_locked_ca(self, validation_setup):
        """Verify that answers cannot be modified if the compliance assessment is locked."""
        data = validation_setup
        data["ca"].is_locked = True
        data["ca"].save()

        serializer = AnswerWriteSerializer(
            data={
                "requirement_assessment": data["ra1"].id,
                "question": data["q1"].id,
                "value": "some text",
                "folder": data["folder"].id,
            }
        )
        with pytest.raises(ValidationError) as excinfo:
            serializer.is_valid(raise_exception=True)
        assert "audit is locked" in str(excinfo.value.detail["non_field_errors"][0])

    def test_validate_in_review_ca(self, validation_setup):
        """Verify that answers cannot be modified if the compliance assessment is in review."""
        data = validation_setup
        data["ca"].status = Assessment.Status.IN_REVIEW
        data["ca"].save()

        serializer = AnswerWriteSerializer(
            data={
                "requirement_assessment": data["ra1"].id,
                "question": data["q1"].id,
                "value": "some text",
                "folder": data["folder"].id,
            }
        )
        with pytest.raises(ValidationError) as excinfo:
            serializer.is_valid(raise_exception=True)
        assert "audit is in review" in str(excinfo.value.detail["non_field_errors"][0])
