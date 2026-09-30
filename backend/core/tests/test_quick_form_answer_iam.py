"""Upstream quick-form answers retain their own parent and mutation boundary."""

import uuid

import pytest
from django.contrib.auth.models import Permission
from iam.models import Folder, Role, RoleAssignment, User
from rest_framework.test import APIClient

from core.models import (
    Answer,
    Question,
    QuestionChoice,
    QuickForm,
    QuickFormPage,
    QuickFormResponse,
)
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
