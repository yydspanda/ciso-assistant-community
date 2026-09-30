"""Upstream quick-form answers retain their own parent and mutation boundary."""

import uuid
from types import SimpleNamespace

import pytest
from django.contrib.auth.models import Permission
from iam.models import Folder, Role, RoleAssignment, User
from rest_framework.exceptions import PermissionDenied, ValidationError
from rest_framework.test import APIClient

from core.models import (
    Answer,
    Question,
    QuestionChoice,
    QuickForm,
    QuickFormPage,
    QuickFormResponse,
)
from core.serializers import AnswerWriteSerializer
from core.startup import startup

pytestmark = pytest.mark.django_db


def _grant(user, folder, *permissions):
    role = Role.objects.create(
        name=f"Quick-form answer {uuid.uuid4().hex}", folder=folder
    )
    role.permissions.set(
        Permission.objects.filter(
            content_type__app_label="core", codename__in=permissions
        )
    )
    grant = RoleAssignment.objects.create(user=user, role=role, folder=folder)
    grant.perimeter_folders.add(folder)


def _client(user):
    client = APIClient()
    client.force_authenticate(user)
    return client


def _new_question(world, suffix):
    return Question.objects.create(
        page=world["page"],
        folder=world["root"],
        urn=f"urn:test:quick-form-answer:{suffix}",
        text=f"Synthetic {suffix}",
        type=Question.Type.NUMBER,
    )


@pytest.fixture
def quick_form_answer_world():
    startup(sender=None, **{})
    root = Folder.get_root_folder()
    folder = Folder.objects.create(name="Quick-form answer domain", parent_folder=root)
    hidden_folder = Folder.objects.create(
        name="Hidden response domain", parent_folder=root
    )
    form = QuickForm.objects.create(name="Synthetic form", folder=root)
    page = QuickFormPage.objects.create(
        name="Synthetic page", quick_form=form, folder=root
    )
    question = Question.objects.create(
        page=page,
        folder=root,
        urn="urn:test:quick-form-answer:number",
        text="Synthetic number",
        type=Question.Type.NUMBER,
    )
    requester = User.objects.create_user("qf-answer-requester@tests.invalid")
    _grant(requester, folder, "view_answer", "change_answer", "view_quickformresponse")
    response = QuickFormResponse.objects.create(
        name="Synthetic response",
        quick_form=form,
        folder=folder,
        submitted_by=requester,
    )
    answer = Answer.objects.create(
        response=response, question=question, folder=folder, value=42
    )
    return {
        "root": root,
        "folder": folder,
        "hidden_folder": hidden_folder,
        "form": form,
        "page": page,
        "question": question,
        "requester": requester,
        "response": response,
        "answer": answer,
    }


def test_requester_can_read_and_update_answer_through_response_owner(
    quick_form_answer_world,
):
    world = quick_form_answer_world
    client = _client(world["requester"])
    url = f"/api/answers/{world['answer'].id}/"
    detail = client.get(url)
    assert detail.status_code == 200, detail.content
    assert detail.json()["value"] == 42
    listed = client.get("/api/answers/", {"response": str(world["response"].id)})
    assert listed.status_code == 200, listed.content
    body = listed.json()
    rows = body["results"] if isinstance(body, dict) else body
    assert [row["id"] for row in rows] == [str(world["answer"].id)]
    updated = client.patch(url, {"value": 43}, format="json")
    assert updated.status_code == 200, updated.content
    world["answer"].refresh_from_db()
    assert world["answer"].value == 43


@pytest.mark.parametrize(
    "missing_permission", ["view_answer", "view_quickformresponse"]
)
def test_neither_parent_nor_answer_read_grant_substitutes_for_the_other(
    quick_form_answer_world, missing_permission
):
    world = quick_form_answer_world
    reader = User.objects.create_user(
        f"qf-answer-missing-{missing_permission}@tests.invalid"
    )
    _grant(
        reader,
        world["folder"],
        *(
            permission
            for permission in ("view_answer", "view_quickformresponse")
            if permission != missing_permission
        ),
    )
    # Notification/asking-side membership does not create a folder IAM grant.
    world["response"].respondents.add(reader.actor)
    response = _client(reader).get(f"/api/answers/{world['answer'].id}/")
    assert response.status_code == 404


def test_hidden_response_parent_is_indistinguishable_from_missing_answer(
    quick_form_answer_world,
):
    world = quick_form_answer_world
    world["response"].folder = world["hidden_folder"]
    world["response"].save(update_fields=["folder"])
    client = _client(world["requester"])
    hidden = client.get(f"/api/answers/{world['answer'].id}/")
    missing = client.get(f"/api/answers/{uuid.uuid4()}/")
    assert hidden.status_code == missing.status_code == 404
    assert hidden.json() == missing.json()


def test_parent_and_child_folder_mismatch_is_hidden_with_both_read_scopes(
    quick_form_answer_world,
):
    world = quick_form_answer_world
    _grant(
        world["requester"],
        world["hidden_folder"],
        "view_quickformresponse",
    )
    QuickFormResponse.objects.filter(id=world["response"].id).update(
        folder=world["hidden_folder"]
    )

    client = _client(world["requester"])
    hidden = client.get(f"/api/answers/{world['answer'].id}/")
    missing = client.get(f"/api/answers/{uuid.uuid4()}/")

    assert hidden.status_code == missing.status_code == 404
    assert hidden.json() == missing.json()


def test_other_forms_question_cannot_be_read_through_a_visible_response(
    quick_form_answer_world,
):
    world = quick_form_answer_world
    other_form = QuickForm.objects.create(name="Other form", folder=world["root"])
    other_page = QuickFormPage.objects.create(
        name="Other page", quick_form=other_form, folder=world["root"]
    )
    other_question = Question.objects.create(
        page=other_page,
        folder=world["root"],
        text="Wrong owner",
        type=Question.Type.NUMBER,
    )
    # Direct ORM insertion represents a historical/corrupt parent binding.
    Answer.objects.filter(id=world["answer"].id).update(question=other_question)
    response = _client(world["requester"]).get(f"/api/answers/{world['answer'].id}/")
    assert response.status_code == 404


def test_response_read_authority_does_not_bypass_requester_or_draft_checks(
    quick_form_answer_world,
):
    world = quick_form_answer_world
    reviewer = User.objects.create_user("qf-answer-reviewer@tests.invalid")
    _grant(
        reviewer,
        world["folder"],
        "view_answer",
        "change_answer",
        "view_quickformresponse",
    )
    url = f"/api/answers/{world['answer'].id}/"
    reviewer_client = _client(reviewer)
    assert reviewer_client.get(url).status_code == 200
    denied = reviewer_client.patch(url, {"value": 99}, format="json")
    assert denied.status_code == 400, denied.content
    assert "Only the requester" in str(denied.json())
    world["response"].status = QuickFormResponse.Status.SUBMITTED
    world["response"].save(update_fields=["status"])
    submitted = _client(world["requester"]).patch(url, {"value": 99}, format="json")
    assert submitted.status_code == 400, submitted.content
    world["answer"].refresh_from_db()
    assert world["answer"].value == 42


@pytest.mark.parametrize("replacement", ["owned", "hidden", "missing", "null"])
def test_reparenting_cannot_bypass_the_persisted_requester_rule(
    quick_form_answer_world, replacement
):
    world = quick_form_answer_world
    other_user = User.objects.create_user(f"qf-reparent-{replacement}@tests.invalid")
    _grant(
        other_user,
        world["folder"],
        "view_answer",
        "change_answer",
        "view_quickformresponse",
    )
    if replacement in ("owned", "hidden"):
        other_response = QuickFormResponse.objects.create(
            name="Replacement response",
            quick_form=world["form"],
            submitted_by=other_user,
            folder=world["folder"]
            if replacement == "owned"
            else world["hidden_folder"],
        )
        response_id = str(other_response.id)
    else:
        response_id = str(uuid.uuid4()) if replacement == "missing" else None
    response = _client(other_user).patch(
        f"/api/answers/{world['answer'].id}/",
        {"response": response_id, "value": 99},
        format="json",
    )
    assert response.status_code == 403, response.content
    assert response.json()["detail"] == "The requested relationship is unavailable."
    world["answer"].refresh_from_db()
    assert world["answer"].response_id == world["response"].id
    assert world["answer"].value == 42


def test_choices_are_bound_to_the_exact_answer_question(quick_form_answer_world):
    world = quick_form_answer_world
    question = world["question"]
    question.type = Question.Type.MULTIPLE_CHOICE
    question.save(update_fields=["type"])
    own_choice = QuestionChoice.objects.create(
        question=question,
        folder=world["root"],
        urn="urn:test:qf-answer:own",
        value="Own",
    )
    other_question = Question.objects.create(
        page=world["page"],
        folder=world["root"],
        text="Other question",
        type=Question.Type.MULTIPLE_CHOICE,
    )
    wrong_choice = QuestionChoice.objects.create(
        question=other_question,
        folder=world["root"],
        urn="urn:test:qf-answer:wrong",
        value="Wrong",
    )
    world["answer"].selected_choices.add(own_choice, wrong_choice)
    response = _client(world["requester"]).get(f"/api/answers/{world['answer'].id}/")
    assert response.status_code == 200, response.content
    assert response.json()["value"] is None
    assert {row["id"] for row in response.json()["selected_choices"]} == {
        str(own_choice.id)
    }
    assert str(wrong_choice.id) not in str(response.json())


@pytest.mark.parametrize(
    "caller,state,expected_status",
    [
        ("reviewer", QuickFormResponse.Status.DRAFT, 400),
        ("requester", QuickFormResponse.Status.SUBMITTED, 400),
        ("requester", QuickFormResponse.Status.DRAFT, 204),
    ],
)
def test_delete_keeps_the_same_requester_and_draft_boundary_as_updates(
    quick_form_answer_world, caller, state, expected_status
):
    world = quick_form_answer_world
    user = (
        world["requester"]
        if caller == "requester"
        else User.objects.create_user("qf-answer-delete-reviewer@tests.invalid")
    )
    _grant(
        user, world["folder"], "view_answer", "delete_answer", "view_quickformresponse"
    )
    world["response"].status = state
    world["response"].save(update_fields=["status"])
    response = _client(user).delete(f"/api/answers/{world['answer'].id}/")
    assert response.status_code == expected_status, response.content
    assert Answer.objects.filter(id=world["answer"].id).exists() is (
        expected_status != 204
    )


def test_unchanged_response_identity_is_allowed_on_a_requester_update(
    quick_form_answer_world,
):
    world = quick_form_answer_world
    response = _client(world["requester"]).patch(
        f"/api/answers/{world['answer'].id}/",
        {"response": str(world["response"].id), "value": 44},
        format="json",
    )
    assert response.status_code == 200, response.content
    world["answer"].refresh_from_db()
    assert world["answer"].value == 44
    assert world["answer"].response_id == world["response"].id


def test_authorized_choice_update_uses_the_visible_parent_definition(
    quick_form_answer_world,
):
    world = quick_form_answer_world
    world["question"].type = Question.Type.MULTIPLE_CHOICE
    world["question"].save(update_fields=["type"])
    choice = QuestionChoice.objects.create(
        question=world["question"],
        folder=world["root"],
        urn="urn:test:qf-answer:authorized-choice",
        value="Authorized choice",
    )

    response = _client(world["requester"]).patch(
        f"/api/answers/{world['answer'].id}/",
        {"selected_choices": [str(choice.id)]},
        format="json",
    )

    assert response.status_code == 200, response.content
    world["answer"].refresh_from_db()
    assert set(world["answer"].selected_choices.all()) == {choice}
    assert world["answer"].value is None


@pytest.mark.parametrize("parent_case", ["hidden", "missing", "malformed", "no_add"])
def test_create_unavailable_parent_cases_have_one_signature_and_write_nothing(
    quick_form_answer_world, parent_case
):
    world = quick_form_answer_world
    caller = User.objects.create_user(f"qf-create-{parent_case}@tests.invalid")
    question = _new_question(world, f"create-{parent_case}")

    if parent_case == "hidden":
        # Deliberately grant Answer creation without granting response visibility.
        # Definition rows must not be consulted through this hidden parent.
        _grant(caller, world["hidden_folder"], "add_answer")
        hidden_response = QuickFormResponse.objects.create(
            name="Hidden create parent",
            quick_form=world["form"],
            folder=world["hidden_folder"],
            submitted_by=caller,
        )
        response_id = str(hidden_response.id)
    elif parent_case == "no_add":
        _grant(caller, world["folder"], "view_quickformresponse")
        visible_response = QuickFormResponse.objects.create(
            name="Visible parent without Answer grant",
            quick_form=world["form"],
            folder=world["folder"],
            submitted_by=caller,
        )
        response_id = str(visible_response.id)
    else:
        _grant(
            caller,
            world["folder"],
            "view_quickformresponse",
            "add_answer",
        )
        response_id = str(uuid.uuid4()) if parent_case == "missing" else "not-a-uuid"

    answer_count = Answer.objects.count()
    choice_link_count = Answer.selected_choices.through.objects.count()
    response = _client(caller).post(
        "/api/answers/",
        {
            "response": response_id,
            "question": str(question.id),
            "value": 7,
        },
        format="json",
    )

    assert response.status_code == 403, response.content
    assert response.json() == {
        "detail": "One or more answer relationships are unavailable."
    }
    assert Answer.objects.count() == answer_count
    assert Answer.selected_choices.through.objects.count() == choice_link_count


def test_create_uses_an_explicit_parent_folder_add_grant(quick_form_answer_world):
    world = quick_form_answer_world
    creator = User.objects.create_user("qf-create-authorized@tests.invalid")
    _grant(
        creator,
        world["folder"],
        "view_quickformresponse",
        "add_answer",
    )
    response_parent = QuickFormResponse.objects.create(
        name="Authorized create parent",
        quick_form=world["form"],
        folder=world["folder"],
        submitted_by=creator,
    )
    question = _new_question(world, "authorized-create")

    response = _client(creator).post(
        "/api/answers/",
        {
            "response": str(response_parent.id),
            "question": str(question.id),
            "value": 8,
        },
        format="json",
    )

    assert response.status_code == 201, response.content
    answer = Answer.objects.get(id=response.json()["id"])
    assert answer.folder_id == response_parent.folder_id
    assert answer.response_id == response_parent.id


@pytest.mark.parametrize(
    ("business_case", "expected_message"),
    [
        (
            "submitted",
            "Answers can only be modified while the response is in progress.",
        ),
        ("not_requester", "Only the requester can change the answers."),
    ],
)
def test_authorized_create_keeps_existing_business_validation_errors(
    quick_form_answer_world, business_case, expected_message
):
    world = quick_form_answer_world
    caller = User.objects.create_user(
        f"qf-create-business-{business_case}@tests.invalid"
    )
    _grant(
        caller,
        world["folder"],
        "view_quickformresponse",
        "add_answer",
    )
    response_parent = QuickFormResponse.objects.create(
        name=f"Business rule parent {business_case}",
        quick_form=world["form"],
        folder=world["folder"],
        submitted_by=(caller if business_case == "submitted" else world["requester"]),
        status=(
            QuickFormResponse.Status.SUBMITTED
            if business_case == "submitted"
            else QuickFormResponse.Status.DRAFT
        ),
    )
    question = _new_question(world, f"business-{business_case}")

    response = _client(caller).post(
        "/api/answers/",
        {
            "response": str(response_parent.id),
            "question": str(question.id),
            "value": 9,
        },
        format="json",
    )

    assert response.status_code == 400, response.content
    assert expected_message in str(response.json())
    assert not Answer.objects.filter(
        response=response_parent, question=question
    ).exists()


@pytest.mark.parametrize(
    ("method", "action_permission"),
    [("patch", "change_answer"), ("delete", "delete_answer")],
)
def test_mutation_requires_the_answer_action_on_the_parent_folder(
    quick_form_answer_world, method, action_permission
):
    world = quick_form_answer_world
    caller = User.objects.create_user(
        f"qf-parent-action-{action_permission}@tests.invalid"
    )
    _grant(caller, world["folder"], "view_answer", "view_quickformresponse")
    world["response"].submitted_by = caller
    world["response"].save(update_fields=["submitted_by"])

    client = _client(caller)
    url = f"/api/answers/{world['answer'].id}/"
    response = (
        client.patch(url, {"value": 91}, format="json")
        if method == "patch"
        else client.delete(url)
    )

    assert response.status_code == 403, response.content
    # The view permission class may reject the action before serializer
    # dispatch; either way the serializer's parent-folder authority must not
    # become a weaker alternate path.
    world["answer"].refresh_from_db()
    assert world["answer"].value == 42
    assert Answer.objects.filter(id=world["answer"].id).exists()


def test_parent_move_without_new_parent_visibility_hides_the_answer(
    quick_form_answer_world,
):
    world = quick_form_answer_world
    QuickFormResponse.objects.filter(id=world["response"].id).update(
        folder=world["hidden_folder"]
    )

    response = _client(world["requester"]).patch(
        f"/api/answers/{world['answer'].id}/", {"value": 92}, format="json"
    )

    assert response.status_code == 404, response.content
    world["answer"].refresh_from_db()
    assert world["answer"].value == 42


@pytest.mark.parametrize(
    ("method", "action_permission"),
    [("patch", "change_answer"), ("delete", "delete_answer")],
)
def test_parent_move_with_both_scopes_hides_a_stale_child_folder(
    quick_form_answer_world, method, action_permission
):
    world = quick_form_answer_world
    if action_permission == "delete_answer":
        _grant(world["requester"], world["folder"], "delete_answer")
    _grant(
        world["requester"],
        world["hidden_folder"],
        "view_quickformresponse",
        action_permission,
    )
    QuickFormResponse.objects.filter(id=world["response"].id).update(
        folder=world["hidden_folder"]
    )

    client = _client(world["requester"])
    url = f"/api/answers/{world['answer'].id}/"
    response = (
        client.patch(url, {"value": 93}, format="json")
        if method == "patch"
        else client.delete(url)
    )
    missing_url = f"/api/answers/{uuid.uuid4()}/"
    missing = (
        client.patch(missing_url, {"value": 93}, format="json")
        if method == "patch"
        else client.delete(missing_url)
    )

    assert response.status_code == missing.status_code == 404
    assert response.json() == missing.json()
    world["answer"].refresh_from_db()
    assert world["answer"].folder_id == world["folder"].id
    assert world["answer"].value == 42
    assert Answer.objects.filter(id=world["answer"].id).exists()


@pytest.mark.parametrize(
    ("changed_state", "exception_type", "expected_message"),
    [
        (
            "submitted",
            ValidationError,
            "Answers can only be modified while the response is in progress.",
        ),
        ("requester", ValidationError, "Only the requester can change the answers."),
        (
            "folder",
            PermissionDenied,
            "One or more answer relationships are unavailable.",
        ),
        (
            "action",
            PermissionDenied,
            "One or more answer relationships are unavailable.",
        ),
    ],
)
def test_save_rechecks_locked_parent_state_requester_and_folder_authority(
    quick_form_answer_world, changed_state, exception_type, expected_message
):
    world = quick_form_answer_world
    if changed_state == "folder":
        _grant(
            world["requester"],
            world["hidden_folder"],
            "view_quickformresponse",
            "change_answer",
        )
    serializer = AnswerWriteSerializer(
        instance=Answer.objects.select_related("response", "question").get(
            id=world["answer"].id
        ),
        data={"value": 94},
        partial=True,
        context={"request": SimpleNamespace(user=world["requester"])},
    )
    assert serializer.is_valid(), serializer.errors

    if changed_state == "submitted":
        QuickFormResponse.objects.filter(id=world["response"].id).update(
            status=QuickFormResponse.Status.SUBMITTED
        )
    elif changed_state == "requester":
        replacement = User.objects.create_user("qf-late-requester@tests.invalid")
        QuickFormResponse.objects.filter(id=world["response"].id).update(
            submitted_by=replacement
        )
    elif changed_state == "folder":
        QuickFormResponse.objects.filter(id=world["response"].id).update(
            folder=world["hidden_folder"]
        )
    else:
        change_answer = Permission.objects.get(
            content_type__app_label="core",
            content_type__model="answer",
            codename="change_answer",
        )
        for assignment in RoleAssignment.objects.filter(
            user=world["requester"], role__builtin=False
        ).select_related("role"):
            assignment.role.permissions.remove(change_answer)

    with pytest.raises(exception_type) as exc_info:
        serializer.save()
    assert expected_message in str(exc_info.value.detail)
    world["answer"].refresh_from_db()
    assert world["answer"].value == 42


@pytest.mark.parametrize("submitted_response", ["existing", "missing", "malformed"])
def test_compliance_answer_response_payload_has_one_immutable_signature(
    quick_form_answer_world, submitted_response
):
    world = quick_form_answer_world
    if submitted_response == "existing":
        response_id = str(world["response"].id)
    elif submitted_response == "missing":
        response_id = str(uuid.uuid4())
    else:
        response_id = "not-a-uuid"
    # The early immutable check does not need to traverse the CA aggregate.
    compliance_answer = Answer(
        id=uuid.uuid4(),
        requirement_assessment_id=uuid.uuid4(),
        question=world["question"],
        folder=world["folder"],
    )
    serializer = AnswerWriteSerializer(
        instance=compliance_answer,
        data={"response": response_id},
        partial=True,
        context={"request": SimpleNamespace(user=world["requester"])},
    )

    with pytest.raises(PermissionDenied) as exc_info:
        serializer.is_valid(raise_exception=True)
    assert str(exc_info.value.detail) == "The requested relationship is unavailable."


def test_compliance_answer_keeps_an_explicit_unchanged_null_response(
    quick_form_answer_world,
):
    world = quick_form_answer_world
    compliance_answer = Answer(
        id=uuid.uuid4(),
        requirement_assessment_id=uuid.uuid4(),
        question=world["question"],
        folder=world["folder"],
    )
    serializer = AnswerWriteSerializer(
        instance=compliance_answer,
        data={"response": None},
        partial=True,
        context={"request": SimpleNamespace(user=world["requester"])},
    )

    assert serializer.to_internal_value({"response": None})["response"] is None
