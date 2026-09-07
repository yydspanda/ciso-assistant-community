"""Security boundary tests for the RequirementAssignment questionnaire capability.

The built-in third-party respondent role deliberately has no generic access to
the root library corpus.  A RequirementAssignment delegates only its exact
assessment slice, and must not turn that delegation into ambient Framework,
RequirementNode, Question, QuestionChoice, or RequirementAssessment access.
"""

from __future__ import annotations

import time
import uuid
from collections.abc import Callable
from concurrent.futures import Future, ThreadPoolExecutor
from pathlib import Path
from queue import Queue
from threading import Barrier, Event
from typing import Any

import pytest
from django.contrib.auth.models import Permission
from django.db import close_old_connections, connection, connections, transaction
from iam.models import Folder, Role, RoleAssignment, User, UserGroup
from rest_framework.test import APIClient

from core.models import (
    Actor,
    Answer,
    AppliedControl,
    Campaign,
    Comment,
    ComplianceAssessment,
    Evidence,
    Framework,
    Perimeter,
    Policy,
    Question,
    QuestionChoice,
    ReferenceControl,
    RequirementAssessment,
    RequirementAssignment,
    RequirementAssignmentEvent,
    RequirementNode,
    RiskMatrix,
    SecurityException,
    StoredLibrary,
    Team,
    Threat,
)
from core.startup import startup
from ebios_rm.models import EbiosRMStudy
from pmbok.models import GenericCollection

pytestmark = pytest.mark.django_db

LIBRARY_FIXTURE = Path(__file__).parent / "fixtures" / "test-splash-assessable.yaml"
_PG_THREAD_TIMEOUT_SECONDS = 15
_PG_BLOCKING_PROBE_TIMEOUT_SECONDS = 8


def _run_on_fresh_pg_connection(
    application_name: str,
    pid_queue: Queue[int],
    operation: Callable[[], Any],
) -> Any:
    """Run one bounded operation on an independent PostgreSQL connection."""

    close_old_connections()
    database = connections["default"]
    database.close()
    try:
        with database.cursor() as cursor:
            cursor.execute(
                "SELECT set_config('application_name', %s, false)",
                [application_name],
            )
            cursor.execute("SET lock_timeout = '10s'")
            cursor.execute("SET statement_timeout = '12s'")
            cursor.execute("SELECT pg_backend_pid()")
            pid_queue.put(cursor.fetchone()[0])
        return operation()
    finally:
        database.close()
        close_old_connections()


def _wait_for_pg_block(*, blocked_pid: int, blocker_pid: int) -> str:
    """Prove that one PostgreSQL backend is waiting for the expected writer."""

    deadline = time.monotonic() + _PG_BLOCKING_PROBE_TIMEOUT_SECONDS
    last_observation: tuple[Any, ...] | None = None
    while time.monotonic() < deadline:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT
                    activity.wait_event_type,
                    activity.wait_event,
                    activity.query,
                    %s = ANY(pg_blocking_pids(activity.pid)) AS expected_blocker
                FROM pg_stat_activity AS activity
                WHERE activity.pid = %s
                """,
                [blocker_pid, blocked_pid],
            )
            last_observation = cursor.fetchone()
        if last_observation is not None and last_observation[3]:
            assert last_observation[0] == "Lock"
            return last_observation[2]
        time.sleep(0.05)
    raise AssertionError(
        "PostgreSQL did not report the expected CEL-node blocker; "
        f"last observation was {last_observation!r}."
    )


def _client(user: User) -> APIClient:
    client = APIClient()
    client.force_authenticate(user=user)
    return client


def _grant_core_permissions(user: User, codenames: set[str], folder: Folder) -> None:
    """Grant an exact set of core permissions on one test folder."""

    role = Role.objects.create(
        name=f"Capability permissions {uuid.uuid4().hex}",
        folder=Folder.get_root_folder(),
    )
    permissions = Permission.objects.filter(
        content_type__app_label="core", codename__in=codenames
    )
    assert set(permissions.values_list("codename", flat=True)) == codenames
    role.permissions.set(permissions)
    role_assignment = RoleAssignment.objects.create(
        user=user,
        role=role,
        folder=Folder.get_root_folder(),
        is_recursive=True,
    )
    role_assignment.perimeter_folders.add(folder)


def _grant_iam_permissions(user: User, codenames: set[str], folder: Folder) -> None:
    """Grant an exact set of IAM permissions on one test folder."""

    role = Role.objects.create(
        name=f"Capability IAM permissions {uuid.uuid4().hex}",
        folder=Folder.get_root_folder(),
    )
    permissions = Permission.objects.filter(
        content_type__app_label="iam", codename__in=codenames
    )
    assert set(permissions.values_list("codename", flat=True)) == codenames
    role.permissions.set(permissions)
    role_assignment = RoleAssignment.objects.create(
        user=user,
        role=role,
        folder=Folder.get_root_folder(),
        is_recursive=True,
    )
    role_assignment.perimeter_folders.add(folder)


def _grant_view_only(user: User, model_name: str, folder: Folder) -> None:
    """Grant one exact read permission without a corresponding change grant."""

    _grant_core_permissions(user, {f"view_{model_name}"}, folder)


def _assignment_update_url(world: dict, ra: RequirementAssessment) -> str:
    return (
        f"/api/requirement-assignments/{world['assignment'].id}/"
        f"requirement-assessments/{ra.id}/"
    )


@pytest.fixture
def requirement_assignment_world(builtin_tpr_role):
    # Give the library a unique URN/hash on every fixture invocation because
    # StoredLibrary maintains an in-process checksum cache across rollbacks.
    suffix = uuid.uuid4().hex
    library_urn = f"urn:intuitem:test:library:assignment-capability-{suffix}"
    framework_urn = f"urn:intuitem:test:framework:assignment-capability-{suffix}"
    node_prefix = f"urn:intuitem:test:req_node:assignment-capability-{suffix}:"
    content = LIBRARY_FIXTURE.read_text()
    content = content.replace(
        "urn:intuitem:test:library:splash-assessable", library_urn
    )
    content = content.replace(
        "urn:intuitem:test:framework:splash-assessable", framework_urn
    )
    content = content.replace("urn:intuitem:test:req_node:splash:", node_prefix)

    stored, error = StoredLibrary.store_library_content(content.encode())
    assert error is None
    assert stored is not None
    assert stored.load() is None

    root = Folder.get_root_folder()
    framework = Framework.objects.get(urn=framework_urn)
    assert stored.folder_id == root.id
    assert framework.folder_id == root.id

    leaf = framework.requirement_nodes.get(ref_id="S.1.1")
    # A non-empty CA implementation-group selection is an allowlist.  Keep the
    # loaded tree in the selected group and add one explicitly excluded row.
    framework.requirement_nodes.update(implementation_groups=["selected"])
    leaf.refresh_from_db()
    ig_denied_requirement = RequirementNode.objects.create(
        name="Requirement outside selected implementation group",
        urn=f"{node_prefix}ig-denied",
        parent_urn=leaf.parent_urn,
        ref_id="IG-DENIED",
        framework=framework,
        folder=root,
        assessable=True,
        implementation_groups=["not-selected"],
    )
    non_assessable_requirement = RequirementNode.objects.create(
        name="Structural non-assessable requirement",
        urn=f"{node_prefix}non-assessable",
        parent_urn=leaf.parent_urn,
        ref_id="NON-ASSESSABLE",
        framework=framework,
        folder=root,
        assessable=False,
        implementation_groups=["selected"],
    )

    # Questions intentionally predate create_requirement_assessments().  This
    # exercises the production seed path, including empty Answer rows owned by
    # the enclave rather than relying on post-hoc test-only answer creation.
    driver = Question.objects.create(
        requirement_node=leaf,
        urn=f"{leaf.urn}:driver",
        ref_id="CAP-Q-DRIVER",
        text="Enable the conditional question",
        type=Question.Type.BOOLEAN,
        folder=root,
        order=1,
    )
    conditional = Question.objects.create(
        requirement_node=leaf,
        urn=f"{leaf.urn}:conditional",
        ref_id="CAP-Q-CONDITIONAL",
        text="Conditionally visible number",
        type=Question.Type.NUMBER,
        depends_on={
            "question": driver.urn,
            "condition": "any",
            "answers": [True],
        },
        folder=root,
        order=2,
    )
    number = Question.objects.create(
        requirement_node=leaf,
        urn=f"{leaf.urn}:number",
        ref_id="CAP-Q-NUMBER",
        text="A strict numeric answer",
        type=Question.Type.NUMBER,
        folder=root,
        order=3,
    )
    cycle_a = Question.objects.create(
        requirement_node=leaf,
        urn=f"{leaf.urn}:cycle-a",
        ref_id="CAP-Q-CYCLE-A",
        text="Cycle A",
        type=Question.Type.TEXT,
        folder=root,
        order=4,
    )
    cycle_b = Question.objects.create(
        requirement_node=leaf,
        urn=f"{leaf.urn}:cycle-b",
        ref_id="CAP-Q-CYCLE-B",
        text="Cycle B",
        type=Question.Type.TEXT,
        folder=root,
        order=5,
    )
    cycle_a.depends_on = {
        "question": cycle_b.urn,
        "condition": "any",
        "answers": ["go"],
    }
    cycle_a.save(update_fields=["depends_on"])
    cycle_b.depends_on = {
        "question": cycle_a.urn,
        "condition": "any",
        "answers": ["go"],
    }
    cycle_b.save(update_fields=["depends_on"])
    choice_question = Question.objects.create(
        requirement_node=leaf,
        urn=f"{leaf.urn}:choice",
        ref_id="CAP-Q-CHOICE",
        text="A delegated choice",
        type=Question.Type.UNIQUE_CHOICE,
        folder=root,
        order=6,
    )
    choice = QuestionChoice.objects.create(
        question=choice_question,
        urn=f"{choice_question.urn}:yes",
        ref_id="CAP-Q-CHOICE-YES",
        value="Yes",
        add_score=1,
        compute_result=RequirementAssessment.Result.COMPLIANT,
        folder=root,
    )
    malformed_dependency_questions = (
        Question.objects.create(
            requirement_node=leaf,
            urn=f"{leaf.urn}:dependency-not-an-object",
            ref_id="CAP-Q-DEP-NOT-OBJECT",
            text="Malformed dependency object",
            type=Question.Type.TEXT,
            depends_on=[driver.urn],
            folder=root,
            order=7,
        ),
        Question.objects.create(
            requirement_node=leaf,
            urn=f"{leaf.urn}:dependency-missing-parent",
            ref_id="CAP-Q-DEP-MISSING-PARENT",
            text="Dependency without a parent identifier",
            type=Question.Type.TEXT,
            depends_on={"condition": "any", "answers": [True]},
            folder=root,
            order=8,
        ),
        Question.objects.create(
            requirement_node=leaf,
            urn=f"{leaf.urn}:dependency-empty-answers",
            ref_id="CAP-Q-DEP-EMPTY-ANSWERS",
            text="Dependency without expected answers",
            type=Question.Type.TEXT,
            depends_on={
                "question": driver.urn,
                "condition": "any",
                "answers": [],
            },
            folder=root,
            order=9,
        ),
        Question.objects.create(
            requirement_node=leaf,
            urn=f"{leaf.urn}:dependency-unknown-parent",
            ref_id="CAP-Q-DEP-UNKNOWN-PARENT",
            text="Dependency whose parent is outside the questionnaire",
            type=Question.Type.TEXT,
            depends_on={
                "question": f"{leaf.urn}:question-that-does-not-exist",
                "condition": "any",
                "answers": [True],
            },
            folder=root,
            order=10,
        ),
        Question.objects.create(
            requirement_node=leaf,
            urn=f"{leaf.urn}:dependency-wrong-parent-type",
            ref_id="CAP-Q-DEP-WRONG-TYPE",
            text="Boolean literal must not match a numeric parent",
            type=Question.Type.TEXT,
            depends_on={
                "question": number.urn,
                "condition": "any",
                "answers": [True],
            },
            folder=root,
            order=11,
        ),
    )

    domain = Folder.objects.create(
        name=f"Capability domain {suffix}",
        content_type=Folder.ContentType.DOMAIN,
        parent_folder=root,
    )
    enclave = Folder.objects.create(
        name=f"Capability respondent enclave {suffix}",
        content_type=Folder.ContentType.ENCLAVE,
        parent_folder=domain,
    )
    hidden_enclave = Folder.objects.create(
        name=f"Capability hidden enclave {suffix}",
        content_type=Folder.ContentType.ENCLAVE,
        parent_folder=domain,
    )
    cross_enclave = Folder.objects.create(
        name=f"Capability visible cross enclave {suffix}",
        content_type=Folder.ContentType.ENCLAVE,
        parent_folder=domain,
    )
    compliance_assessment = ComplianceAssessment.objects.create(
        name="Third-party capability audit",
        framework=framework,
        perimeter=Perimeter.objects.create(
            name="Third-party capability perimeter", folder=enclave
        ),
        folder=enclave,
        status=ComplianceAssessment.Status.IN_PROGRESS,
        selected_implementation_groups=["selected"],
        field_visibility={
            "answers": {"auditor": "edit", "respondent": "edit"},
            "evidences": {"auditor": "edit", "respondent": "edit"},
            "result": {"auditor": "edit", "respondent": "edit"},
        },
    )
    compliance_assessment.create_requirement_assessments()
    requirement_assessments = {
        row.requirement_id: row
        for row in compliance_assessment.requirement_assessments.select_related(
            "requirement"
        )
    }
    leaf_ra = requirement_assessments[leaf.id]
    ig_denied_ra = requirement_assessments[ig_denied_requirement.id]
    non_assessable_ra = requirement_assessments[non_assessable_requirement.id]

    respondent = User.objects.create_user(
        f"third-party-capability-{suffix}@tests.local",
        is_third_party=True,
    )
    actor, _ = Actor.objects.get_or_create(user=respondent)
    assignment = RequirementAssignment.objects.create(
        compliance_assessment=compliance_assessment,
        folder=enclave,
        status=RequirementAssignment.Status.IN_PROGRESS,
    )
    assignment.actor.add(actor)
    assignment.requirement_assessments.set(
        compliance_assessment.requirement_assessments.all()
    )
    assert assignment.requirement_assessments.count() == len(requirement_assessments)

    respondent_group = UserGroup.objects.create(
        name="BI-UG-TPR", folder=enclave, builtin=True
    )
    respondent_group.user_set.add(respondent)
    respondent_role_assignment = RoleAssignment.objects.create(
        user_group=respondent_group,
        role=Role.objects.get(name="BI-RL-TPR"),
        folder=enclave,
        is_recursive=True,
        builtin=True,
    )
    respondent_role_assignment.perimeter_folders.add(enclave)

    # Every relational question must have been seeded into the enclave before
    # the capability is captured.
    assert set(
        Answer.objects.filter(requirement_assessment=leaf_ra).values_list(
            "question_id", flat=True
        )
    ) == {
        driver.id,
        conditional.id,
        number.id,
        cycle_a.id,
        cycle_b.id,
        choice_question.id,
        *(question.id for question in malformed_dependency_questions),
    }

    return {
        "assignment": assignment,
        "ca": compliance_assessment,
        "framework": framework,
        "leaf": leaf,
        "leaf_ra": leaf_ra,
        "ig_denied_requirement": ig_denied_requirement,
        "ig_denied_ra": ig_denied_ra,
        "non_assessable_requirement": non_assessable_requirement,
        "non_assessable_ra": non_assessable_ra,
        "driver": driver,
        "conditional": conditional,
        "number": number,
        "cycle_a": cycle_a,
        "cycle_b": cycle_b,
        "choice_question": choice_question,
        "choice": choice,
        "malformed_dependency_questions": malformed_dependency_questions,
        "respondent": respondent,
        "root": root,
        "enclave": enclave,
        "hidden_enclave": hidden_enclave,
        "cross_enclave": cross_enclave,
    }


@pytest.fixture(scope="module")
def builtin_tpr_role(django_db_setup, django_db_blocker):
    """Initialise the production BI-RL-TPR role once for this test module."""

    with django_db_blocker.unblock():
        startup(sender=None)
        role = Role.objects.get(name="BI-RL-TPR")
        permission_names = set(role.permissions.values_list("codename", flat=True))
    assert {
        "view_complianceassessment",
        "view_requirementassessment",
        "change_requirementassessment",
        "view_requirementassignment",
        "view_question",
        "view_questionchoice",
        "view_answer",
        "add_answer",
        "change_answer",
        "view_evidence",
    } <= permission_names
    return role


def test_exact_capability_keeps_generic_apis_closed_and_filters_ig_and_mutation(
    requirement_assignment_world,
):
    world = requirement_assignment_world
    client = _client(world["respondent"])
    framework = world["framework"]
    leaf = world["leaf"]
    leaf_ra = world["leaf_ra"]
    choice_question = world["choice_question"]
    choice = world["choice"]

    # The root library remains sealed from the enclave on every generic API.
    generic_urls = (
        f"/api/frameworks/{framework.id}/",
        f"/api/requirement-nodes/{leaf.id}/",
        f"/api/requirement-assessments/{leaf_ra.id}/",
        f"/api/questions/{choice_question.id}/",
        f"/api/question-choices/{choice.id}/",
    )
    for url in generic_urls:
        response = client.get(url)
        assert response.status_code == 404, (url, response.content)

    response = client.get(
        f"/api/requirement-assignments/{world['assignment'].id}/requirements_list/"
    )
    assert response.status_code == 200, response.content
    body = response.json()
    assert body["viewer_role"] == "respondent"
    row_ids = {row["id"] for row in body["requirement_assessments"]}
    assert str(leaf_ra.id) in row_ids
    assert str(world["non_assessable_ra"].id) not in row_ids
    assert str(world["ig_denied_ra"].id) not in row_ids

    leaf_row = next(
        row for row in body["requirement_assessments"] if row["id"] == str(leaf_ra.id)
    )
    delegated_questions = leaf_row["requirement"]["questions"]
    assert world["choice_question"].urn in delegated_questions
    assert [
        item["urn"]
        for item in delegated_questions[world["choice_question"].urn]["choices"]
    ] == [world["choice"].urn]

    # Assignment membership alone cannot bypass IG selection or convert a
    # structural/non-assessable row into a mutable requirement.
    ig_denied = client.patch(
        _assignment_update_url(world, world["ig_denied_ra"]),
        {"result": RequirementAssessment.Result.COMPLIANT},
        format="json",
    )
    non_assessable = client.patch(
        _assignment_update_url(world, world["non_assessable_ra"]),
        {"result": RequirementAssessment.Result.COMPLIANT},
        format="json",
    )
    assert ig_denied.status_code == 404, ig_denied.content
    assert non_assessable.status_code == 404, non_assessable.content


def test_cross_folder_question_does_not_delegate_its_hidden_colocated_choice(
    requirement_assignment_world,
):
    world = requirement_assignment_world
    suffix = uuid.uuid4().hex
    question = Question.objects.create(
        requirement_node=world["leaf"],
        urn=f"{world['leaf'].urn}:cross-folder-{suffix}",
        ref_id="CAP-Q-CROSS-FOLDER",
        text="Independently visible cross-folder question",
        type=Question.Type.UNIQUE_CHOICE,
        folder=world["hidden_enclave"],
    )
    hidden_choice = QuestionChoice.objects.create(
        question=question,
        urn=f"{question.urn}:hidden",
        ref_id="CAP-Q-CROSS-FOLDER-HIDDEN",
        value="Must remain hidden",
        add_score=100,
        folder=world["hidden_enclave"],
    )
    _grant_view_only(world["respondent"], "question", world["hidden_enclave"])
    assert hidden_choice.id not in set(
        RoleAssignment.get_viewable_object_ids(world["respondent"], QuestionChoice)
    )

    client = _client(world["respondent"])
    response = client.get(
        f"/api/requirement-assignments/{world['assignment'].id}/requirements_list/"
    )
    assert response.status_code == 200, response.content
    leaf_row = next(
        row
        for row in response.json()["requirement_assessments"]
        if row["id"] == str(world["leaf_ra"].id)
    )
    projected = leaf_row["requirement"]["questions"][question.urn]
    assert hidden_choice.urn not in {
        choice["urn"] for choice in projected.get("choices", [])
    }

    update = client.patch(
        _assignment_update_url(world, world["leaf_ra"]),
        {"answers": {question.urn: hidden_choice.urn}},
        format="json",
    )
    assert update.status_code == 400, update.content
    assert b"selected choice is unavailable" in update.content.lower()
    assert not Answer.objects.filter(
        requirement_assessment=world["leaf_ra"], question=question
    ).exists()


def test_question_api_filters_nested_choices_by_choice_iam_and_legacy_folder(
    requirement_assignment_world,
):
    world = requirement_assignment_world
    suffix = uuid.uuid4().hex
    node = RequirementNode.objects.create(
        name="Visible question API owner",
        urn=f"{world['leaf'].urn}:question-api-owner-{suffix}",
        ref_id=f"CAP-Q-API-{suffix}",
        framework=world["framework"],
        folder=world["cross_enclave"],
        assessable=True,
    )
    question = Question.objects.create(
        requirement_node=node,
        urn=f"{node.urn}:choice",
        ref_id=f"CAP-Q-API-CHOICE-{suffix}",
        text="Question whose nested choices require independent IAM",
        type=Question.Type.UNIQUE_CHOICE,
        folder=world["cross_enclave"],
    )
    visible_choice = QuestionChoice.objects.create(
        question=question,
        urn=f"{question.urn}:visible",
        ref_id=f"CAP-Q-API-VISIBLE-{suffix}",
        value="Visible only with choice authority",
        folder=world["cross_enclave"],
    )
    drifted_hidden_choice = QuestionChoice.objects.create(
        question=question,
        urn=f"{question.urn}:legacy-hidden",
        ref_id=f"CAP-Q-API-HIDDEN-{suffix}",
        value="Legacy choice with a drifted hidden folder",
        folder=world["hidden_enclave"],
    )
    viewer = User.objects.create_user(f"question-api-projection-{suffix}@tests.local")
    _grant_core_permissions(
        viewer,
        {"view_requirementnode", "view_question"},
        world["cross_enclave"],
    )

    assert node.id in set(
        RoleAssignment.get_viewable_object_ids(viewer, RequirementNode)
    )
    assert question.id in set(RoleAssignment.get_viewable_object_ids(viewer, Question))
    assert {
        visible_choice.id,
        drifted_hidden_choice.id,
    }.isdisjoint(RoleAssignment.get_viewable_object_ids(viewer, QuestionChoice))

    client = _client(viewer)

    def get_list_and_detail_rows() -> tuple[dict, dict]:
        listing = client.get(f"/api/questions/?requirement_node={node.id}")
        detail = client.get(f"/api/questions/{question.id}/")
        assert listing.status_code == 200, listing.content
        assert detail.status_code == 200, detail.content
        list_row = next(
            row for row in listing.json()["results"] if row["id"] == str(question.id)
        )
        return list_row, detail.json()

    # Visibility of the Question and its parent does not imply visibility of
    # its nested choices on either generic read route.
    for row in get_list_and_detail_rows():
        assert row["choices"] == []
        assert visible_choice.urn not in str(row)
        assert drifted_hidden_choice.urn not in str(row)

    # Once exact choice read authority is granted, only the colocated choice is
    # projected.  A legacy choice whose folder drifted to a hidden sibling must
    # remain absent even though it still belongs to the visible Question.
    _grant_view_only(viewer, "questionchoice", world["cross_enclave"])
    visible_choice_ids = set(
        RoleAssignment.get_viewable_object_ids(viewer, QuestionChoice)
    )
    assert visible_choice.id in visible_choice_ids
    assert drifted_hidden_choice.id not in visible_choice_ids
    for row in get_list_and_detail_rows():
        assert {choice["urn"] for choice in row["choices"]} == {visible_choice.urn}
        assert drifted_hidden_choice.urn not in str(row)


def test_tainted_stored_answers_cannot_authorize_conditional_writes(
    requirement_assignment_world,
):
    world = requirement_assignment_world
    hidden_choice = QuestionChoice.objects.create(
        question=world["choice_question"],
        urn=f"{world['choice_question'].urn}:hidden-{uuid.uuid4().hex}",
        ref_id="CAP-Q-HIDDEN-CROSS-ANSWER",
        value="Hidden cross-answer selection",
        folder=world["hidden_enclave"],
    )
    driver_answer = Answer.objects.get(
        requirement_assessment=world["leaf_ra"], question=world["driver"]
    )
    driver_answer.value = True
    driver_answer.save(update_fields=["value"])
    driver_answer.selected_choices.add(hidden_choice)
    legacy_choice_answer = Answer.objects.get(
        requirement_assessment=world["leaf_ra"],
        question=world["choice_question"],
    )
    legacy_choice_answer.value = world["choice"].urn
    legacy_choice_answer.save(update_fields=["value"])

    client = _client(world["respondent"])
    listing = client.get(
        f"/api/requirement-assignments/{world['assignment'].id}/requirements_list/"
    )
    assert listing.status_code == 200, listing.content
    body = listing.json()
    leaf_row = next(
        row
        for row in body["requirement_assessments"]
        if row["id"] == str(world["leaf_ra"].id)
    )
    assert world["driver"].urn not in leaf_row["answers"]
    assert world["choice_question"].urn not in leaf_row["answers"]
    assert world["conditional"].urn not in leaf_row["answers"]
    assert leaf_row["visible_questions"] == 3
    assert leaf_row["answered_questions"] == 0

    update = client.patch(
        _assignment_update_url(world, world["leaf_ra"]),
        {"answers": {world["conditional"].urn: 7}},
        format="json",
    )
    assert update.status_code == 400, update.content
    assert (
        Answer.objects.get(
            requirement_assessment=world["leaf_ra"],
            question=world["conditional"],
        ).value
        is None
    )


def test_respondent_generic_ra_and_answer_mutations_cannot_bypass_exact_action(
    requirement_assignment_world,
):
    world = requirement_assignment_world
    respondent = world["respondent"]
    _grant_view_only(respondent, "requirementnode", world["root"])
    _grant_view_only(respondent, "question", world["root"])
    _grant_core_permissions(
        respondent,
        {
            "change_requirementassignment",
            "delete_requirementassignment",
            "delete_requirementassessment",
            "delete_answer",
        },
        world["enclave"],
    )
    world["assignment"].status = RequirementAssignment.Status.DRAFT
    world["assignment"].save(update_fields=["status"])
    client = _client(respondent)

    generic_ra = client.patch(
        f"/api/requirement-assessments/{world['leaf_ra'].id}/",
        {"result": RequirementAssessment.Result.COMPLIANT},
        format="json",
    )
    assert generic_ra.status_code == 403, generic_ra.content
    assert b"exact requirement-assignment endpoint" in generic_ra.content

    driver_answer = Answer.objects.get(
        requirement_assessment=world["leaf_ra"], question=world["driver"]
    )
    generic_answer = client.patch(
        f"/api/answers/{driver_answer.id}/",
        {"value": True},
        format="json",
    )
    assert generic_answer.status_code == 403, generic_answer.content
    assert b"exact requirement-assignment endpoint" in generic_answer.content

    batch_update = client.post(
        "/api/requirement-assessments/batch-action/",
        {
            "action": "change_field",
            "ids": [str(world["leaf_ra"].id)],
            "field": "result",
            "value": RequirementAssessment.Result.COMPLIANT,
        },
        format="json",
    )
    assert batch_update.status_code == 200, batch_update.content
    assert batch_update.json()["succeeded"] == []
    assert "exact requirement-assignment endpoint" in str(batch_update.json()["failed"])

    batch_delete_answer = client.post(
        "/api/answers/batch-action/",
        {"action": "delete", "ids": [str(driver_answer.id)]},
        format="json",
    )
    assert batch_delete_answer.status_code == 200, batch_delete_answer.content
    assert batch_delete_answer.json()["succeeded"] == []
    assert "exact requirement-assignment endpoint" in str(
        batch_delete_answer.json()["failed"]
    )
    assert Answer.objects.filter(id=driver_answer.id).exists()

    batch_assignment_status = client.post(
        "/api/requirement-assignments/batch-action/",
        {
            "action": "change_field",
            "ids": [str(world["assignment"].id)],
            "field": "status",
            "value": RequirementAssignment.Status.SUBMITTED,
        },
        format="json",
    )
    assert batch_assignment_status.status_code == 400
    assert batch_assignment_status.json()["error"] == "field not editable: status"
    world["assignment"].refresh_from_db()
    assert world["assignment"].status == RequirementAssignment.Status.DRAFT

    exact = client.patch(
        _assignment_update_url(world, world["leaf_ra"]),
        {"answers": {world["driver"].urn: True}},
        format="json",
    )
    assert exact.status_code == 403, exact.content
    world["leaf_ra"].refresh_from_db()
    driver_answer.refresh_from_db()
    assert world["leaf_ra"].result == RequirementAssessment.Result.NOT_ASSESSED
    assert driver_answer.value is None

    world["assignment"].status = RequirementAssignment.Status.SUBMITTED
    world["assignment"].save(update_fields=["status"])
    batch_delete_assignment = client.post(
        "/api/requirement-assignments/batch-action/",
        {"action": "delete", "ids": [str(world["assignment"].id)]},
        format="json",
    )
    assert batch_delete_assignment.status_code == 200
    assert batch_delete_assignment.json()["succeeded"] == []
    assert "Only a full-audit reviewer may change an assignment's scope" in str(
        batch_delete_assignment.json()["failed"]
    )
    assert RequirementAssignment.objects.filter(id=world["assignment"].id).exists()


def _hidden_compliance_assessment(world: dict) -> ComplianceAssessment:
    return ComplianceAssessment.objects.create(
        name=f"Hidden assignment target {uuid.uuid4().hex}",
        framework=world["framework"],
        perimeter=Perimeter.objects.create(
            name=f"Hidden assignment perimeter {uuid.uuid4().hex}",
            folder=world["hidden_enclave"],
        ),
        folder=world["hidden_enclave"],
        status=ComplianceAssessment.Status.IN_PROGRESS,
    )


def test_assignment_update_cannot_change_its_audit_with_or_without_m2m(
    requirement_assignment_world,
):
    world = requirement_assignment_world
    auditor = User.objects.create_user(
        f"assignment-source-auditor-{uuid.uuid4().hex}@tests.local"
    )
    _grant_core_permissions(
        auditor,
        {
            "view_complianceassessment",
            "view_compliance_assessment_full",
            "view_requirementassignment",
            "change_requirementassignment",
        },
        world["enclave"],
    )
    hidden_assessment = _hidden_compliance_assessment(world)
    assignment = world["assignment"]
    original_requirement_assessment_ids = set(
        assignment.requirement_assessments.values_list("id", flat=True)
    )
    url = f"/api/requirement-assignments/{assignment.id}/"

    for payload in (
        {"compliance_assessment": str(hidden_assessment.id)},
        {
            "compliance_assessment": str(hidden_assessment.id),
            "requirement_assessments": [],
        },
    ):
        response = _client(auditor).patch(url, payload, format="json")
        assert response.status_code == 403, response.content

        assignment.refresh_from_db()
        assert assignment.compliance_assessment_id == world["ca"].id
        assert (
            set(assignment.requirement_assessments.values_list("id", flat=True))
            == original_requirement_assessment_ids
        )


def test_assignment_create_requires_target_scope_and_uses_the_audit_folder(
    requirement_assignment_world,
):
    world = requirement_assignment_world
    auditor = User.objects.create_user(
        f"assignment-create-auditor-{uuid.uuid4().hex}@tests.local"
    )
    _grant_core_permissions(
        auditor,
        {
            "view_complianceassessment",
            "view_compliance_assessment_full",
        },
        world["enclave"],
    )
    _grant_core_permissions(auditor, {"view_team"}, world["enclave"])
    hidden_assessment = _hidden_compliance_assessment(world)
    endpoint = "/api/requirement-assignments/"
    initial_count = RequirementAssignment.objects.count()
    team = Team.objects.create(
        name=f"Assignment target team {uuid.uuid4().hex}",
        folder=world["enclave"],
    )
    actor_id = Actor.objects.get(team=team).id

    hidden_response = _client(auditor).post(
        endpoint,
        {
            "compliance_assessment": str(hidden_assessment.id),
            "folder": str(world["hidden_enclave"].id),
            "actor": [str(actor_id)],
            "requirement_assessments": [],
        },
        format="json",
    )
    assert hidden_response.status_code == 403, hidden_response.content
    assert RequirementAssignment.objects.count() == initial_count

    mismatched_folder = _client(auditor).post(
        endpoint,
        {
            "compliance_assessment": str(world["ca"].id),
            "folder": str(world["hidden_enclave"].id),
            "actor": [str(actor_id)],
            "requirement_assessments": [],
        },
        format="json",
    )
    assert mismatched_folder.status_code == 400, mismatched_folder.content
    assert RequirementAssignment.objects.count() == initial_count

    missing_add = _client(auditor).post(
        endpoint,
        {
            "compliance_assessment": str(world["ca"].id),
            "actor": [str(actor_id)],
            "requirement_assessments": [],
        },
        format="json",
    )
    assert missing_add.status_code == 403, missing_add.content
    assert RequirementAssignment.objects.count() == initial_count

    _grant_core_permissions(
        auditor,
        {"add_requirementassignment"},
        world["enclave"],
    )

    created = _client(auditor).post(
        endpoint,
        {
            "compliance_assessment": str(world["ca"].id),
            "actor": [str(actor_id)],
            "requirement_assessments": [],
        },
        format="json",
    )
    assert created.status_code == 201, created.content
    new_assignment = RequirementAssignment.objects.get(id=created.json()["id"])
    assert new_assignment.compliance_assessment_id == world["ca"].id
    assert new_assignment.folder_id == world["ca"].folder_id


def test_assignment_full_form_round_trip_preserves_hidden_actor_and_requirement(
    requirement_assignment_world,
    monkeypatch,
):
    world = requirement_assignment_world
    auditor = User.objects.create_user(
        f"assignment-hidden-relation-auditor-{uuid.uuid4().hex}@tests.local"
    )
    _grant_core_permissions(
        auditor,
        {
            "view_complianceassessment",
            "view_compliance_assessment_full",
            "view_requirementassignment",
            "change_requirementassignment",
            "view_requirementassessment",
            "view_team",
        },
        world["enclave"],
    )
    visible_team = Team.objects.create(
        name=f"Visible assignment actor {uuid.uuid4().hex}",
        folder=world["enclave"],
    )
    hidden_team = Team.objects.create(
        name=f"Hidden assignment actor {uuid.uuid4().hex}",
        folder=world["enclave"],
    )
    visible_actor = Actor.objects.get(team=visible_team)
    hidden_actor = Actor.objects.get(team=hidden_team)
    assignment = world["assignment"]
    assignment.actor.set([visible_actor, hidden_actor])
    expected_actor_ids = {visible_actor.id, hidden_actor.id}
    expected_requirement_ids = set(
        assignment.requirement_assessments.values_list("id", flat=True)
    )
    hidden_requirement_id = world["ig_denied_ra"].id

    original_get_viewable_ids = RoleAssignment.get_viewable_object_ids

    def mask_one_current_relation(user, model, folder=None):
        ids = original_get_viewable_ids(user, model, folder)
        if user.id != auditor.id:
            return ids
        if model is Actor:
            return [visible_actor.id]
        if model is RequirementAssessment:
            return [item for item in ids if item != hidden_requirement_id]
        return ids

    monkeypatch.setattr(
        RoleAssignment,
        "get_viewable_object_ids",
        staticmethod(mask_one_current_relation),
    )
    client = _client(auditor)
    url = f"/api/requirement-assignments/{assignment.id}/"
    detail = client.get(url)

    assert detail.status_code == 200, detail.content
    body = detail.json()
    visible_actor_ids = {item["id"] for item in body["actor"]}
    visible_requirement_ids = {item["id"] for item in body["requirement_assessments"]}
    assert visible_actor_ids == {str(visible_actor.id)}
    assert str(hidden_actor.id) not in visible_actor_ids
    assert str(hidden_requirement_id) not in visible_requirement_ids

    round_trip = client.patch(
        url,
        {
            "compliance_assessment": str(world["ca"].id),
            "folder": str(world["enclave"].id),
            "actor": sorted(visible_actor_ids),
            "requirement_assessments": sorted(visible_requirement_ids),
        },
        format="json",
    )

    assert round_trip.status_code == 200, round_trip.content
    assert set(assignment.actor.values_list("id", flat=True)) == expected_actor_ids
    assert (
        set(assignment.requirement_assessments.values_list("id", flat=True))
        == expected_requirement_ids
    )


def test_ambient_assignment_change_and_delete_do_not_grant_scope_management(
    requirement_assignment_world,
):
    world = requirement_assignment_world
    respondent = world["respondent"]
    _grant_core_permissions(
        respondent,
        {"change_requirementassignment", "delete_requirementassignment"},
        world["enclave"],
    )
    assignment = world["assignment"]
    assignment.status = RequirementAssignment.Status.DRAFT
    assignment.save(update_fields=["status"])
    expected_actor_ids = set(assignment.actor.values_list("id", flat=True))
    expected_requirement_ids = set(
        assignment.requirement_assessments.values_list("id", flat=True)
    )
    client = _client(respondent)
    url = f"/api/requirement-assignments/{assignment.id}/"

    scope_update = client.patch(
        url,
        {"requirement_assessments": [str(world["leaf_ra"].id)]},
        format="json",
    )
    deletion = client.delete(url)

    assert scope_update.status_code == 403, scope_update.content
    assert deletion.status_code == 403, deletion.content
    assert RequirementAssignment.objects.filter(id=assignment.id).exists()
    assert set(assignment.actor.values_list("id", flat=True)) == expected_actor_ids
    assert (
        set(assignment.requirement_assessments.values_list("id", flat=True))
        == expected_requirement_ids
    )


@pytest.mark.parametrize("assessment_state", ["locked", "in_review"])
def test_frozen_audit_rejects_every_assignment_mutation_surface(
    requirement_assignment_world,
    assessment_state,
):
    world = requirement_assignment_world
    auditor = User.objects.create_user(
        f"frozen-assignment-auditor-{assessment_state}-{uuid.uuid4().hex}@tests.local"
    )
    _grant_core_permissions(
        auditor,
        {
            "view_complianceassessment",
            "view_compliance_assessment_full",
            "view_requirementassignment",
            "add_requirementassignment",
            "change_requirementassignment",
            "delete_requirementassignment",
            "transition_requirementassignment",
            "view_requirementassessment",
            "view_team",
        },
        world["enclave"],
    )
    team = Team.objects.create(
        name=f"Frozen audit actor {uuid.uuid4().hex}",
        folder=world["enclave"],
    )
    actor = Actor.objects.get(team=team)
    assignment = world["assignment"]
    assignment.status = RequirementAssignment.Status.DRAFT
    assignment.save(update_fields=["status"])
    original_actor_ids = set(assignment.actor.values_list("id", flat=True))
    original_assignment_count = RequirementAssignment.objects.count()
    if assessment_state == "locked":
        world["ca"].is_locked = True
        world["ca"].save(update_fields=["is_locked"])
    else:
        world["ca"].status = ComplianceAssessment.Status.IN_REVIEW
        world["ca"].save(update_fields=["status"])
    client = _client(auditor)
    url = f"/api/requirement-assignments/{assignment.id}/"

    create_response = client.post(
        "/api/requirement-assignments/",
        {
            "compliance_assessment": str(world["ca"].id),
            "actor": [str(actor.id)],
            "requirement_assessments": [],
        },
        format="json",
    )
    update_response = client.patch(
        url,
        {"actor": [str(actor.id)]},
        format="json",
    )
    status_response = client.post(
        f"{url}set_status/",
        {"status": RequirementAssignment.Status.IN_PROGRESS},
        format="json",
    )
    delete_response = client.delete(url)

    for response in (
        create_response,
        update_response,
        status_response,
        delete_response,
    ):
        assert response.status_code == 403, response.content
    assignment.refresh_from_db()
    assert assignment.status == RequirementAssignment.Status.DRAFT
    assert set(assignment.actor.values_list("id", flat=True)) == original_actor_ids
    assert RequirementAssignment.objects.count() == original_assignment_count


def test_assignment_create_and_update_reject_requirement_folder_drift(
    requirement_assignment_world,
):
    world = requirement_assignment_world
    auditor = User.objects.create_user(
        f"assignment-ra-drift-auditor-{uuid.uuid4().hex}@tests.local"
    )
    _grant_core_permissions(
        auditor,
        {
            "view_complianceassessment",
            "view_compliance_assessment_full",
            "view_requirementassignment",
            "add_requirementassignment",
            "change_requirementassignment",
            "view_requirementassessment",
            "view_team",
        },
        world["enclave"],
    )
    _grant_view_only(auditor, "requirementassessment", world["hidden_enclave"])
    team = Team.objects.create(
        name=f"Assignment drift actor {uuid.uuid4().hex}",
        folder=world["enclave"],
    )
    actor = Actor.objects.get(team=team)
    assignment = world["assignment"]
    drifted_ra = world["ig_denied_ra"]
    assignment.requirement_assessments.remove(drifted_ra)
    expected_requirement_ids = set(
        assignment.requirement_assessments.values_list("id", flat=True)
    )
    drifted_ra.folder = world["hidden_enclave"]
    drifted_ra.save(update_fields=["folder"])
    initial_count = RequirementAssignment.objects.count()
    client = _client(auditor)

    create_response = client.post(
        "/api/requirement-assignments/",
        {
            "compliance_assessment": str(world["ca"].id),
            "actor": [str(actor.id)],
            "requirement_assessments": [str(drifted_ra.id)],
        },
        format="json",
    )
    update_response = client.patch(
        f"/api/requirement-assignments/{assignment.id}/",
        {"requirement_assessments": [str(drifted_ra.id)]},
        format="json",
    )

    assert create_response.status_code == 400, create_response.content
    assert update_response.status_code == 400, update_response.content
    assert RequirementAssignment.objects.count() == initial_count
    assert (
        set(assignment.requirement_assessments.values_list("id", flat=True))
        == expected_requirement_ids
    )


def test_assignment_questionnaire_scope_rejects_legacy_folder_drift(
    requirement_assignment_world,
):
    world = requirement_assignment_world
    world["leaf_ra"].folder = world["hidden_enclave"]
    world["leaf_ra"].save(update_fields=["folder"])

    response = _client(world["respondent"]).get(
        f"/api/requirement-assignments/{world['assignment'].id}/requirements_list/"
    )

    assert response.status_code == 403, response.content
    assert b"inconsistent requirement assessment" in response.content


def test_assignment_transition_rejects_legacy_assignment_folder_drift(
    requirement_assignment_world,
):
    world = requirement_assignment_world
    auditor = User.objects.create_user(
        f"assignment-folder-drift-auditor-{uuid.uuid4().hex}@tests.local"
    )
    _grant_core_permissions(
        auditor,
        {"view_complianceassessment", "view_compliance_assessment_full"},
        world["enclave"],
    )
    _grant_core_permissions(
        auditor,
        {"view_requirementassignment", "transition_requirementassignment"},
        world["hidden_enclave"],
    )
    world["assignment"].folder = world["hidden_enclave"]
    world["assignment"].status = RequirementAssignment.Status.DRAFT
    world["assignment"].save(update_fields=["folder", "status"])

    response = _client(auditor).post(
        f"/api/requirement-assignments/{world['assignment'].id}/set_status/",
        {"status": RequirementAssignment.Status.IN_PROGRESS},
        format="json",
    )
    read_response = _client(auditor).get(
        f"/api/requirement-assignments/{world['assignment'].id}/"
    )

    assert response.status_code == 404, response.content
    assert read_response.status_code == 404, read_response.content
    world["assignment"].refresh_from_db()
    assert world["assignment"].status == RequirementAssignment.Status.DRAFT


def test_assignment_read_rejects_workflow_event_folder_drift(
    requirement_assignment_world,
):
    world = requirement_assignment_world
    RequirementAssignmentEvent.objects.create(
        assignment=world["assignment"],
        event_type=RequirementAssignment.Status.IN_PROGRESS,
        event_actor=world["respondent"],
        event_notes="must remain inside the assignment enclave",
        folder=world["hidden_enclave"],
    )

    response = _client(world["respondent"]).get(
        f"/api/requirement-assignments/{world['assignment'].id}/"
    )

    assert response.status_code == 403, response.content
    assert b"inconsistent workflow event" in response.content


@pytest.mark.parametrize("carrier", ["leader", "deputies", "members"])
def test_team_actor_authority_is_revoked_for_every_membership_carrier(
    requirement_assignment_world,
    carrier,
):
    world = requirement_assignment_world
    team = Team.objects.create(
        name=f"Assignment authority team {carrier} {uuid.uuid4().hex}",
        folder=world["enclave"],
    )
    if carrier == "leader":
        team.leader = world["respondent"]
        team.save(update_fields=["leader"])
    else:
        getattr(team, carrier).add(world["respondent"])
    world["assignment"].actor.set([Actor.objects.get(team=team)])
    original_result = world["leaf_ra"].result

    if carrier == "leader":
        team.leader = None
        team.save(update_fields=["leader"])
    else:
        getattr(team, carrier).remove(world["respondent"])
    response = _client(world["respondent"]).patch(
        _assignment_update_url(world, world["leaf_ra"]),
        {"result": RequirementAssessment.Result.COMPLIANT},
        format="json",
    )

    assert response.status_code in {403, 404}, response.content
    world["leaf_ra"].refresh_from_db()
    assert world["leaf_ra"].result == original_result


def test_assignment_transition_event_failure_rolls_back_status_and_notification(
    requirement_assignment_world,
    monkeypatch,
):
    world = requirement_assignment_world
    _grant_core_permissions(
        world["respondent"],
        {"transition_requirementassignment"},
        world["enclave"],
    )
    event_count = RequirementAssignmentEvent.objects.filter(
        assignment=world["assignment"]
    ).count()

    def fail_event_create(**_kwargs):
        raise RuntimeError("synthetic assignment event failure")

    monkeypatch.setattr(
        RequirementAssignmentEvent.objects,
        "create",
        fail_event_create,
    )
    monkeypatch.setattr(
        "core.views.RequirementAssignmentViewSet._send_transition_notification",
        lambda *_args: pytest.fail("a rolled-back transition emitted notification"),
    )

    with pytest.raises(RuntimeError, match="synthetic assignment event failure"):
        _client(world["respondent"]).post(
            f"/api/requirement-assignments/{world['assignment'].id}/set_status/",
            {"status": RequirementAssignment.Status.SUBMITTED},
            format="json",
        )

    world["assignment"].refresh_from_db()
    assert world["assignment"].status == RequirementAssignment.Status.IN_PROGRESS
    assert (
        RequirementAssignmentEvent.objects.filter(
            assignment=world["assignment"]
        ).count()
        == event_count
    )


def test_assignment_transition_notification_runs_only_after_commit(
    requirement_assignment_world,
    monkeypatch,
    django_capture_on_commit_callbacks,
):
    world = requirement_assignment_world
    _grant_core_permissions(
        world["respondent"],
        {"transition_requirementassignment"},
        world["enclave"],
    )
    notifications = []
    monkeypatch.setattr(
        "core.views.RequirementAssignmentViewSet._send_transition_notification",
        staticmethod(
            lambda assignment, transition, observation: notifications.append(
                (assignment.id, transition, observation)
            )
        ),
    )

    with django_capture_on_commit_callbacks(execute=False) as callbacks:
        response = _client(world["respondent"]).post(
            f"/api/requirement-assignments/{world['assignment'].id}/set_status/",
            {"status": RequirementAssignment.Status.SUBMITTED},
            format="json",
        )
        assert response.status_code == 200, response.content
        assert notifications == []

    assert len(callbacks) == 1
    callbacks[0]()
    assert notifications == [
        (
            world["assignment"].id,
            (
                RequirementAssignment.Status.IN_PROGRESS,
                RequirementAssignment.Status.SUBMITTED,
            ),
            "",
        )
    ]
    world["assignment"].refresh_from_db()
    assert world["assignment"].status == RequirementAssignment.Status.SUBMITTED
    assert RequirementAssignmentEvent.objects.filter(
        assignment=world["assignment"],
        event_type=RequirementAssignment.Status.SUBMITTED,
    ).exists()


def test_assignment_recompute_rejects_any_unscoped_score_carrier(
    requirement_assignment_world,
):
    world = requirement_assignment_world
    hidden_question = Question.objects.create(
        requirement_node=world["leaf"],
        urn=f"{world['leaf'].urn}:hidden-score-{uuid.uuid4().hex}",
        ref_id="CAP-Q-HIDDEN-SCORE",
        text="Hidden scoring carrier",
        type=Question.Type.UNIQUE_CHOICE,
        folder=world["hidden_enclave"],
    )
    QuestionChoice.objects.create(
        question=hidden_question,
        urn=f"{hidden_question.urn}:yes",
        ref_id="CAP-Q-HIDDEN-SCORE-YES",
        value="Hidden score",
        add_score=100,
        compute_result=RequirementAssessment.Result.COMPLIANT,
        folder=world["hidden_enclave"],
    )
    original_score = world["leaf_ra"].score
    original_result = world["leaf_ra"].result

    response = _client(world["respondent"]).patch(
        _assignment_update_url(world, world["leaf_ra"]),
        {"answers": {world["driver"].urn: True}},
        format="json",
    )

    assert response.status_code == 403, response.content
    assert b"complete assignment carrier access" in response.content
    world["leaf_ra"].refresh_from_db()
    driver_answer = Answer.objects.get(
        requirement_assessment=world["leaf_ra"], question=world["driver"]
    )
    assert driver_answer.value is None
    assert world["leaf_ra"].score == original_score
    assert world["leaf_ra"].result == original_result


def test_dashboard_uses_the_same_scope_progress_and_masks_root_library_metadata(
    requirement_assignment_world,
):
    world = requirement_assignment_world
    respondent = world["respondent"]
    client = _client(respondent)

    requirements_response = client.get(
        f"/api/requirement-assignments/{world['assignment'].id}/requirements_list/"
    )
    dashboard_response = client.get("/api/compliance-assessments/auditee-dashboard/")

    assert requirements_response.status_code == 200, requirements_response.content
    assert dashboard_response.status_code == 200, dashboard_response.content
    requirements = requirements_response.json()
    cards = dashboard_response.json()
    assert len(cards) == 1
    card = cards[0]
    assert card["assignment_id"] == str(world["assignment"].id)

    mutable_rows = [
        row
        for row in requirements["requirement_assessments"]
        if row["requirement"]["id"] == str(world["leaf"].id)
    ]
    assert len(mutable_rows) == 1
    leaf_row = mutable_rows[0]
    assert card["total_requirements"] == len(mutable_rows)
    assert requirements["total_visible_questions"] == leaf_row["visible_questions"]
    assert requirements["total_answered_questions"] == leaf_row["answered_questions"]
    assert card["assessed_requirements"] == (
        1
        if leaf_row["visible_questions"] > 0
        and leaf_row["answered_questions"] >= leaf_row["visible_questions"]
        else 0
    )
    assert card["progress_percent"] == int(
        requirements["total_answered_questions"]
        / requirements["total_visible_questions"]
        * 100
    )

    # The dashboard may name the respondent's own enclave, but the root
    # library's Framework and Folder remain independently masked on every
    # delegated projection.
    assert world["root"].id not in set(
        RoleAssignment.get_viewable_object_ids(respondent, Folder)
    )
    assert world["framework"].id not in set(
        RoleAssignment.get_viewable_object_ids(respondent, Framework)
    )
    assert card["folder"] == world["enclave"].name
    assert card["framework"] is None
    assert all(node["folder"] is None for node in requirements["requirements"])
    assert all(node["framework"] is None for node in requirements["requirements"])
    assert leaf_row["compliance_assessment"]["framework"] is None


def test_minimal_assignment_reader_cannot_bypass_related_object_iam(
    requirement_assignment_world,
):
    world = requirement_assignment_world
    reader = User.objects.create_user(
        f"minimal-assignment-reader-{uuid.uuid4().hex}@tests.local",
        is_third_party=True,
    )
    reader_actor, _ = Actor.objects.get_or_create(user=reader)
    world["assignment"].actor.add(reader_actor)
    world["ca"].authors.add(reader_actor)
    _grant_core_permissions(
        reader,
        {"view_complianceassessment", "view_requirementassignment"},
        world["enclave"],
    )
    client = _client(reader)

    assignment_response = client.get(
        f"/api/requirement-assignments/{world['assignment'].id}/"
    )
    assessment_response = client.get("/api/compliance-assessments/")

    assert assignment_response.status_code == 200, assignment_response.content
    assignment_body = assignment_response.json()
    assert assignment_body["folder"] is None
    assert assignment_body["actor"] == []
    assert assignment_body["requirement_assessments"] == []
    assert assignment_body["compliance_assessment"]["id"] == str(world["ca"].id)

    assert assessment_response.status_code == 200, assessment_response.content
    assessment_payload = assessment_response.json()
    rows = assessment_payload.get("results", assessment_payload)
    row = next(item for item in rows if item["id"] == str(world["ca"].id))
    assert row["folder"] is None
    assert row["path"] is None
    assert row["framework"] is None
    assert row["perimeter"] is None
    assert row["authors"] == []


def test_generic_ra_update_preserves_hidden_existing_relations(
    requirement_assignment_world,
):
    world = requirement_assignment_world
    auditor = User.objects.create_user(
        f"hidden-ra-link-auditor-{uuid.uuid4().hex}@tests.local"
    )
    _grant_core_permissions(
        auditor,
        {
            "view_complianceassessment",
            "view_compliance_assessment_full",
            "view_requirementassessment",
            "change_requirementassessment",
        },
        world["enclave"],
    )
    _grant_core_permissions(
        auditor,
        {"view_requirementnode", "view_framework"},
        world["root"],
    )
    _grant_view_only(auditor, "evidence", world["enclave"])
    visible = Evidence.objects.create(
        name="Visible generic RA evidence", folder=world["enclave"]
    )
    hidden = Evidence.objects.create(
        name="Hidden generic RA evidence", folder=world["hidden_enclave"]
    )
    world["leaf_ra"].evidences.add(visible, hidden)

    response = _client(auditor).patch(
        f"/api/requirement-assessments/{world['leaf_ra'].id}/",
        {"evidences": [str(visible.id)]},
        format="json",
    )

    assert response.status_code == 200, response.content
    assert set(world["leaf_ra"].evidences.values_list("id", flat=True)) == {
        visible.id,
        hidden.id,
    }


def test_reverse_ra_genericcollection_full_form_round_trip_preserves_hidden_link(
    requirement_assignment_world,
    monkeypatch,
):
    """Cover DRF's reverse ``genericcollection_set`` source-name mapping."""

    world = requirement_assignment_world
    auditor = User.objects.create_user(
        f"hidden-generic-collection-auditor-{uuid.uuid4().hex}@tests.local"
    )
    _grant_core_permissions(
        auditor,
        {
            "view_complianceassessment",
            "view_compliance_assessment_full",
            "view_requirementassessment",
            "change_requirementassessment",
            "view_securityexception",
            "change_securityexception",
        },
        world["enclave"],
    )
    security_exception = SecurityException.objects.create(
        name="Exception with reverse collection links",
        folder=world["enclave"],
    )
    security_exception.requirement_assessments.add(world["leaf_ra"])
    visible_collection = GenericCollection.objects.create(
        name="Visible reverse collection",
        folder=world["enclave"],
    )
    hidden_collection = GenericCollection.objects.create(
        name="Hidden reverse collection",
        folder=world["hidden_enclave"],
    )
    security_exception.genericcollection_set.set(
        [visible_collection, hidden_collection]
    )

    original_get_viewable_ids = RoleAssignment.get_viewable_object_ids

    def hide_one_collection(user, model, folder=None):
        if user.id == auditor.id and model is GenericCollection:
            return [visible_collection.id]
        return original_get_viewable_ids(user, model, folder)

    monkeypatch.setattr(
        RoleAssignment,
        "get_viewable_object_ids",
        staticmethod(hide_one_collection),
    )
    response = _client(auditor).patch(
        f"/api/security-exceptions/{security_exception.id}/",
        {
            "name": security_exception.name,
            "folder": str(world["enclave"].id),
            "requirement_assessments": [str(world["leaf_ra"].id)],
            "genericcollection": [str(visible_collection.id)],
        },
        format="json",
    )

    assert response.status_code == 200, response.content
    assert set(
        security_exception.genericcollection_set.values_list("id", flat=True)
    ) == {visible_collection.id, hidden_collection.id}


@pytest.mark.parametrize("method", ["patch", "put"])
def test_security_exception_edit_and_write_responses_hide_inaccessible_relations(
    requirement_assignment_world,
    monkeypatch,
    method,
):
    world = requirement_assignment_world
    editor = User.objects.create_user(
        f"hidden-exception-relation-editor-{method}-{uuid.uuid4().hex}@tests.local"
    )
    hidden_approver = User.objects.create_user(
        f"hidden-exception-approver-{method}-{uuid.uuid4().hex}@tests.local"
    )
    _grant_core_permissions(
        editor,
        {"view_securityexception", "change_securityexception"},
        world["enclave"],
    )
    visible_evidence = Evidence.objects.create(
        name=f"Visible exception evidence {method}",
        folder=world["enclave"],
    )
    hidden_evidence = Evidence.objects.create(
        name=f"Hidden exception evidence {method}",
        folder=world["hidden_enclave"],
    )
    security_exception = SecurityException.objects.create(
        name=f"Exception response projection {method}",
        folder=world["enclave"],
        approver=hidden_approver,
    )
    security_exception.evidences.set([visible_evidence, hidden_evidence])

    original_get_viewable_ids = RoleAssignment.get_viewable_object_ids

    def hide_sensitive_relations(user, model, folder=None):
        if user.id == editor.id and model is User:
            return []
        if user.id == editor.id and model is Evidence:
            return [visible_evidence.id]
        return original_get_viewable_ids(user, model, folder)

    monkeypatch.setattr(
        RoleAssignment,
        "get_viewable_object_ids",
        staticmethod(hide_sensitive_relations),
    )
    client = _client(editor)
    object_response = client.get(
        f"/api/security-exceptions/{security_exception.id}/object/"
    )

    assert object_response.status_code == 200, object_response.content
    object_body = object_response.json()
    assert "approver" not in object_body
    assert "evidences" not in object_body
    assert str(hidden_approver.id) not in str(object_body)
    assert str(hidden_evidence.id) not in str(object_body)

    write_response = getattr(client, method)(
        f"/api/security-exceptions/{security_exception.id}/",
        {
            "name": security_exception.name,
            "folder": str(world["enclave"].id),
        },
        format="json",
    )

    assert write_response.status_code == 200, write_response.content
    write_body = write_response.json()
    assert "approver" not in write_body
    assert "evidences" not in write_body
    assert str(hidden_approver.id) not in str(write_body)
    assert str(hidden_evidence.id) not in str(write_body)
    security_exception.refresh_from_db()
    assert security_exception.approver_id == hidden_approver.id
    assert set(security_exception.evidences.values_list("id", flat=True)) == {
        visible_evidence.id,
        hidden_evidence.id,
    }


def test_generic_answer_and_ra_round_trips_preserve_hidden_selected_choice(
    requirement_assignment_world,
    monkeypatch,
):
    world = requirement_assignment_world
    auditor = User.objects.create_user(
        f"hidden-choice-round-trip-auditor-{uuid.uuid4().hex}@tests.local"
    )
    _grant_core_permissions(
        auditor,
        {
            "view_complianceassessment",
            "view_compliance_assessment_full",
            "view_requirementassessment",
            "change_requirementassessment",
            "view_answer",
            "add_answer",
            "change_answer",
        },
        world["enclave"],
    )
    _grant_core_permissions(
        auditor,
        {"view_requirementnode", "view_question", "view_questionchoice"},
        world["root"],
    )
    question = world["choice_question"]
    question.type = Question.Type.MULTIPLE_CHOICE
    question.save(update_fields=["type"])
    hidden_choice = QuestionChoice.objects.create(
        question=question,
        urn=f"{question.urn}:hidden-round-trip-{uuid.uuid4().hex}",
        ref_id="CAP-Q-CHOICE-HIDDEN-ROUND-TRIP",
        value="Hidden selection",
        folder=world["root"],
    )
    answer = Answer.objects.get(
        requirement_assessment=world["leaf_ra"],
        question=question,
    )
    answer.selected_choices.set([world["choice"], hidden_choice])
    expected_choice_ids = {world["choice"].id, hidden_choice.id}

    original_get_viewable_ids = RoleAssignment.get_viewable_object_ids

    def hide_one_choice(user, model, folder=None):
        ids = original_get_viewable_ids(user, model, folder)
        if user.id == auditor.id and model is QuestionChoice:
            return [item for item in ids if item != hidden_choice.id]
        return ids

    monkeypatch.setattr(
        RoleAssignment,
        "get_viewable_object_ids",
        staticmethod(hide_one_choice),
    )
    client = _client(auditor)
    answer_url = f"/api/answers/{answer.id}/"
    detail = client.get(answer_url)

    assert detail.status_code == 200, detail.content
    body = detail.json()
    assert {item["id"] for item in body["selected_choices"]} == {
        str(world["choice"].id)
    }
    assert str(hidden_choice.id) not in str(body)

    # Echo every writable scalar/owner field from the detail projection and
    # the visible choice set.  `value` is deliberately omitted because the
    # public wire contract treats it as mutually exclusive with choices.
    answer_round_trip = client.patch(
        answer_url,
        {
            "folder": str(world["enclave"].id),
            "requirement_assessment": str(world["leaf_ra"].id),
            "question": str(question.id),
            "selected_choices": [str(world["choice"].id)],
            "is_published": body["is_published"],
        },
        format="json",
    )

    assert answer_round_trip.status_code == 200, answer_round_trip.content
    assert set(answer.selected_choices.values_list("id", flat=True)) == (
        expected_choice_ids
    )

    ra_round_trip = client.patch(
        f"/api/requirement-assessments/{world['leaf_ra'].id}/",
        {"answers": {question.urn: [world["choice"].urn]}},
        format="json",
    )

    assert ra_round_trip.status_code == 200, ra_round_trip.content
    assert set(answer.selected_choices.values_list("id", flat=True)) == (
        expected_choice_ids
    )


def test_compliance_assessment_update_preserves_hidden_existing_relations(
    requirement_assignment_world,
):
    world = requirement_assignment_world
    auditor = User.objects.create_user(
        f"hidden-ca-link-auditor-{uuid.uuid4().hex}@tests.local"
    )
    _grant_core_permissions(
        auditor,
        {
            "view_complianceassessment",
            "view_compliance_assessment_full",
            "change_complianceassessment",
            "view_evidence",
        },
        world["enclave"],
    )
    visible = Evidence.objects.create(
        name="Visible compliance assessment evidence", folder=world["enclave"]
    )
    hidden = Evidence.objects.create(
        name="Hidden compliance assessment evidence", folder=world["hidden_enclave"]
    )
    world["ca"].evidences.add(visible, hidden)

    response = _client(auditor).patch(
        f"/api/compliance-assessments/{world['ca'].id}/",
        {"evidences": [str(visible.id)]},
        format="json",
    )

    assert response.status_code == 200, response.content
    assert set(world["ca"].evidences.values_list("id", flat=True)) == {
        visible.id,
        hidden.id,
    }


def test_compliance_assessment_update_preserves_hidden_reverse_relations(
    requirement_assignment_world,
    monkeypatch,
):
    world = requirement_assignment_world
    auditor = User.objects.create_user(
        f"hidden-ca-reverse-link-auditor-{uuid.uuid4().hex}@tests.local"
    )
    _grant_core_permissions(
        auditor,
        {
            "view_complianceassessment",
            "view_compliance_assessment_full",
            "change_complianceassessment",
        },
        world["enclave"],
    )
    hidden_collection = GenericCollection.objects.create(
        name=f"Hidden compliance collection {uuid.uuid4().hex}",
        folder=world["hidden_enclave"],
    )
    hidden_collection.compliance_assessments.add(world["ca"])
    risk_matrix = RiskMatrix.objects.create(
        name=f"Hidden EBIOS matrix {uuid.uuid4().hex}",
        urn=f"urn:test:risk-matrix:hidden-ebios:{uuid.uuid4().hex}",
        folder=world["hidden_enclave"],
        json_definition={
            "probability": [{"name": "P1"}],
            "impact": [{"name": "I1"}],
            "risk": [{"name": "R1"}],
            "grid": [[0]],
        },
    )
    hidden_study = EbiosRMStudy.objects.create(
        name=f"Hidden compliance EBIOS study {uuid.uuid4().hex}",
        folder=world["hidden_enclave"],
        risk_matrix=risk_matrix,
    )
    hidden_study.compliance_assessments.add(world["ca"])

    original_get_viewable_ids = RoleAssignment.get_viewable_object_ids

    def hide_reverse_relations(user, model, folder=None):
        if user.id == auditor.id and model in {GenericCollection, EbiosRMStudy}:
            return []
        return original_get_viewable_ids(user, model, folder)

    monkeypatch.setattr(
        RoleAssignment,
        "get_viewable_object_ids",
        staticmethod(hide_reverse_relations),
    )
    response = _client(auditor).patch(
        f"/api/compliance-assessments/{world['ca'].id}/",
        {
            "genericcollection": [],
            "ebios_rm_studies": [],
        },
        format="json",
    )

    assert response.status_code == 200, response.content
    assert set(world["ca"].genericcollection_set.values_list("id", flat=True)) == {
        hidden_collection.id
    }
    assert set(world["ca"].ebios_rm_studies.values_list("id", flat=True)) == {
        hidden_study.id
    }


def test_compliance_assessment_full_form_nulls_preserve_hidden_owner_links(
    requirement_assignment_world,
    monkeypatch,
):
    world = requirement_assignment_world
    auditor = User.objects.create_user(
        f"hidden-ca-owner-auditor-{uuid.uuid4().hex}@tests.local"
    )
    _grant_core_permissions(
        auditor,
        {
            "view_complianceassessment",
            "view_compliance_assessment_full",
            "change_complianceassessment",
        },
        world["enclave"],
    )
    campaign = Campaign.objects.create(
        name="Hidden assessment campaign",
        folder=world["enclave"],
    )
    campaign.frameworks.add(world["framework"])
    campaign.perimeters.add(world["ca"].perimeter)
    world["ca"].campaign = campaign
    world["ca"].save(update_fields=["campaign"])
    expected_ids = {
        "framework": world["ca"].framework_id,
        "folder": world["ca"].folder_id,
        "perimeter": world["ca"].perimeter_id,
        "campaign": world["ca"].campaign_id,
    }

    original_get_viewable_ids = RoleAssignment.get_viewable_object_ids
    hidden_models = {Framework, Folder, Perimeter, Campaign}

    def hide_assessment_owners(user, model, folder=None):
        if user.id == auditor.id and model in hidden_models:
            return []
        return original_get_viewable_ids(user, model, folder)

    monkeypatch.setattr(
        RoleAssignment,
        "get_viewable_object_ids",
        staticmethod(hide_assessment_owners),
    )
    response = _client(auditor).patch(
        f"/api/compliance-assessments/{world['ca'].id}/",
        {
            "framework": None,
            "folder": None,
            "perimeter": None,
            "campaign": None,
        },
        format="json",
    )

    assert response.status_code == 200, response.content
    world["ca"].refresh_from_db()
    assert {
        "framework": world["ca"].framework_id,
        "folder": world["ca"].folder_id,
        "perimeter": world["ca"].perimeter_id,
        "campaign": world["ca"].campaign_id,
    } == expected_ids


def test_compliance_assessment_create_rejects_independently_hidden_owner_fks(
    requirement_assignment_world,
    monkeypatch,
):
    world = requirement_assignment_world
    creator = User.objects.create_user(
        f"hidden-ca-create-owner-{uuid.uuid4().hex}@tests.local"
    )
    for folder in (world["enclave"], world["hidden_enclave"]):
        _grant_core_permissions(
            creator,
            {"add_complianceassessment", "view_complianceassessment"},
            folder,
        )
    _grant_view_only(creator, "framework", world["root"])
    _grant_view_only(creator, "perimeter", world["enclave"])
    _grant_view_only(creator, "campaign", world["enclave"])

    hidden_perimeter = Perimeter.objects.create(
        name=f"Known hidden create perimeter {uuid.uuid4().hex}",
        folder=world["hidden_enclave"],
    )
    visible_campaign = Campaign.objects.create(
        name=f"Visible create campaign {uuid.uuid4().hex}",
        folder=world["enclave"],
    )
    hidden_campaign = Campaign.objects.create(
        name=f"Known hidden create campaign {uuid.uuid4().hex}",
        folder=world["hidden_enclave"],
    )

    original_get_viewable_ids = RoleAssignment.get_viewable_object_ids

    def hide_create_owners(user, model, folder=None):
        if user.id == creator.id and model is Perimeter:
            return [world["ca"].perimeter_id]
        if user.id == creator.id and model is Campaign:
            return [visible_campaign.id]
        return original_get_viewable_ids(user, model, folder)

    monkeypatch.setattr(
        RoleAssignment,
        "get_viewable_object_ids",
        staticmethod(hide_create_owners),
    )
    client = _client(creator)
    endpoint = "/api/compliance-assessments/"
    initial_ids = set(ComplianceAssessment.objects.values_list("id", flat=True))

    attempts = (
        {
            "name": f"Must reject hidden perimeter {uuid.uuid4().hex}",
            "framework": str(world["framework"].id),
            "perimeter": str(hidden_perimeter.id),
            "folder": str(world["hidden_enclave"].id),
            "campaign": str(visible_campaign.id),
        },
        {
            "name": f"Must reject hidden campaign {uuid.uuid4().hex}",
            "framework": str(world["framework"].id),
            "perimeter": str(world["ca"].perimeter_id),
            "folder": str(world["enclave"].id),
            "campaign": str(hidden_campaign.id),
        },
    )
    for payload in attempts:
        response = client.post(endpoint, payload, format="json")
        assert response.status_code == 403, response.content
        assert (
            set(ComplianceAssessment.objects.values_list("id", flat=True))
            == initial_ids
        )


def test_compliance_assessment_create_rejects_independently_hidden_actors(
    requirement_assignment_world,
    monkeypatch,
):
    world = requirement_assignment_world
    creator = User.objects.create_user(
        f"hidden-ca-create-actor-{uuid.uuid4().hex}@tests.local"
    )
    _grant_core_permissions(
        creator,
        {
            "add_complianceassessment",
            "view_complianceassessment",
            "view_actor",
        },
        world["enclave"],
    )
    _grant_view_only(creator, "framework", world["root"])
    _grant_view_only(creator, "perimeter", world["enclave"])
    hidden_user = User.objects.create_user(
        f"known-hidden-ca-actor-{uuid.uuid4().hex}@tests.local"
    )
    hidden_user.folder = world["hidden_enclave"]
    hidden_user.save(update_fields=["folder"])
    hidden_actor = Actor.objects.get(user=hidden_user)

    original_get_viewable_ids = RoleAssignment.get_viewable_object_ids

    def hide_create_actor(user, model, folder=None):
        if user.id == creator.id and model is Actor:
            return []
        return original_get_viewable_ids(user, model, folder)

    monkeypatch.setattr(
        RoleAssignment,
        "get_viewable_object_ids",
        staticmethod(hide_create_actor),
    )
    client = _client(creator)
    endpoint = "/api/compliance-assessments/"
    initial_ids = set(ComplianceAssessment.objects.values_list("id", flat=True))
    base_payload = {
        "framework": str(world["framework"].id),
        "perimeter": str(world["ca"].perimeter_id),
        "folder": str(world["enclave"].id),
    }

    for field_name in ("authors", "reviewers"):
        response = client.post(
            endpoint,
            {
                **base_payload,
                "name": f"Must reject hidden {field_name} {uuid.uuid4().hex}",
                field_name: [str(hidden_actor.id)],
            },
            format="json",
        )
        assert response.status_code == 403, response.content
        assert (
            set(ComplianceAssessment.objects.values_list("id", flat=True))
            == initial_ids
        )


def test_compliance_assessment_create_binds_folder_to_visible_perimeter(
    requirement_assignment_world,
):
    world = requirement_assignment_world
    creator = User.objects.create_user(
        f"ca-create-folder-owner-{uuid.uuid4().hex}@tests.local"
    )
    for folder in (world["enclave"], world["cross_enclave"]):
        _grant_core_permissions(
            creator,
            {"add_complianceassessment", "view_complianceassessment"},
            folder,
        )
    _grant_view_only(creator, "framework", world["root"])
    _grant_view_only(creator, "perimeter", world["enclave"])
    client = _client(creator)
    endpoint = "/api/compliance-assessments/"
    initial_ids = set(ComplianceAssessment.objects.values_list("id", flat=True))
    base_payload = {
        "framework": str(world["framework"].id),
        "perimeter": str(world["ca"].perimeter_id),
    }

    mismatch = client.post(
        endpoint,
        {
            **base_payload,
            "name": f"Mismatched perimeter folder {uuid.uuid4().hex}",
            "folder": str(world["cross_enclave"].id),
        },
        format="json",
    )
    assert mismatch.status_code == 400, mismatch.content
    assert set(ComplianceAssessment.objects.values_list("id", flat=True)) == initial_ids

    created = client.post(
        endpoint,
        {
            **base_payload,
            "name": f"Perimeter-owned folder {uuid.uuid4().hex}",
        },
        format="json",
    )
    assert created.status_code == 201, created.content
    assessment = ComplianceAssessment.objects.get(id=created.json()["id"])
    assert assessment.perimeter_id == world["ca"].perimeter_id
    assert assessment.folder_id == world["ca"].perimeter.folder_id


@pytest.mark.parametrize(
    ("model", "endpoint", "permission_model_name"),
    (
        (AppliedControl, "/api/applied-controls/", "appliedcontrol"),
        (Policy, "/api/policies/", "policy"),
    ),
    ids=("applied-control", "policy"),
)
def test_control_reference_owner_fails_closed_without_leaking_hidden_fk(
    requirement_assignment_world,
    monkeypatch,
    model,
    endpoint,
    permission_model_name,
):
    world = requirement_assignment_world
    editor = User.objects.create_user(
        f"hidden-{permission_model_name}-reference-{uuid.uuid4().hex}@tests.local"
    )
    _grant_core_permissions(
        editor,
        {
            f"view_{permission_model_name}",
            f"add_{permission_model_name}",
            f"change_{permission_model_name}",
        },
        world["enclave"],
    )
    _grant_view_only(editor, "referencecontrol", world["enclave"])
    visible_reference = ReferenceControl.objects.create(
        name=f"Visible {permission_model_name} reference",
        ref_id=f"VISIBLE-{permission_model_name.upper()}",
        urn=f"urn:test:reference:{permission_model_name}:visible:{uuid.uuid4().hex}",
        folder=world["enclave"],
    )
    visible_replacement = ReferenceControl.objects.create(
        name=f"Visible replacement {permission_model_name} reference",
        ref_id=f"VISIBLE-REPLACEMENT-{permission_model_name.upper()}",
        urn=(
            f"urn:test:reference:{permission_model_name}:replacement:{uuid.uuid4().hex}"
        ),
        folder=world["enclave"],
    )
    hidden_reference = ReferenceControl.objects.create(
        name=f"Hidden {permission_model_name} reference",
        ref_id=f"HIDDEN-{permission_model_name.upper()}",
        urn=f"urn:test:reference:{permission_model_name}:hidden:{uuid.uuid4().hex}",
        folder=world["hidden_enclave"],
    )

    original_get_viewable_ids = RoleAssignment.get_viewable_object_ids

    def hide_reference_control(user, related_model, folder=None):
        if user.id == editor.id and related_model is ReferenceControl:
            return [visible_reference.id, visible_replacement.id]
        return original_get_viewable_ids(user, related_model, folder)

    monkeypatch.setattr(
        RoleAssignment,
        "get_viewable_object_ids",
        staticmethod(hide_reference_control),
    )
    client = _client(editor)
    forbidden_name = f"Forbidden hidden reference {uuid.uuid4().hex}"
    forbidden_create = client.post(
        endpoint,
        {
            "name": forbidden_name,
            "folder": str(world["enclave"].id),
            "reference_control": str(hidden_reference.id),
        },
        format="json",
    )
    assert forbidden_create.status_code == 403, forbidden_create.content
    assert not model.objects.filter(name=forbidden_name).exists()

    instance = model.objects.create(
        name=f"Existing hidden reference {uuid.uuid4().hex}",
        folder=world["enclave"],
        reference_control=hidden_reference,
    )
    detail_endpoint = f"{endpoint}{instance.id}/"
    object_response = client.get(f"{detail_endpoint}object/")
    assert object_response.status_code == 200, object_response.content
    assert "reference_control" not in object_response.json()
    assert str(hidden_reference.id) not in str(object_response.json())

    for round_trip_value in (None, str(hidden_reference.id)):
        round_trip = client.patch(
            detail_endpoint,
            {"reference_control": round_trip_value},
            format="json",
        )
        assert round_trip.status_code == 200, round_trip.content
        assert "reference_control" not in round_trip.json()
        assert str(hidden_reference.id) not in str(round_trip.json())
        instance.refresh_from_db()
        assert instance.reference_control_id == hidden_reference.id

    replacement = client.patch(
        detail_endpoint,
        {"reference_control": str(visible_replacement.id)},
        format="json",
    )
    assert replacement.status_code == 403, replacement.content
    instance.refresh_from_db()
    assert instance.reference_control_id == hidden_reference.id


def test_requirement_node_round_trip_preserves_hidden_governance_links(
    requirement_assignment_world,
):
    world = requirement_assignment_world
    editor = User.objects.create_user(
        f"hidden-node-governance-editor-{uuid.uuid4().hex}@tests.local"
    )
    _grant_core_permissions(
        editor,
        {"view_framework", "view_requirementnode", "change_requirementnode"},
        world["root"],
    )
    _grant_core_permissions(
        editor,
        {"view_referencecontrol", "view_threat"},
        world["enclave"],
    )
    visible_reference = ReferenceControl.objects.create(
        name="Visible node reference",
        ref_id="VISIBLE-NODE-REF",
        urn=f"urn:test:reference:{uuid.uuid4().hex}",
        folder=world["enclave"],
    )
    hidden_reference = ReferenceControl.objects.create(
        name="Hidden node reference",
        ref_id="HIDDEN-NODE-REF",
        urn=f"urn:test:reference:{uuid.uuid4().hex}",
        folder=world["hidden_enclave"],
    )
    visible_threat = Threat.objects.create(
        name="Visible node threat",
        ref_id="VISIBLE-NODE-THREAT",
        urn=f"urn:test:threat:{uuid.uuid4().hex}",
        folder=world["enclave"],
    )
    hidden_threat = Threat.objects.create(
        name="Hidden node threat",
        ref_id="HIDDEN-NODE-THREAT",
        urn=f"urn:test:threat:{uuid.uuid4().hex}",
        folder=world["hidden_enclave"],
    )
    world["leaf"].reference_controls.set([visible_reference, hidden_reference])
    world["leaf"].threats.set([visible_threat, hidden_threat])

    response = _client(editor).patch(
        f"/api/requirement-nodes/{world['leaf'].id}/",
        {
            "reference_controls": [str(visible_reference.id)],
            "threats": [str(visible_threat.id)],
        },
        format="json",
    )

    assert response.status_code == 200, response.content
    assert set(world["leaf"].reference_controls.values_list("id", flat=True)) == {
        visible_reference.id,
        hidden_reference.id,
    }
    assert set(world["leaf"].threats.values_list("id", flat=True)) == {
        visible_threat.id,
        hidden_threat.id,
    }


def test_used_question_and_choice_cannot_change_parent_or_leave_parent_folder(
    requirement_assignment_world,
):
    world = requirement_assignment_world
    auditor = User.objects.create_user(
        f"question-binding-auditor-{uuid.uuid4().hex}@tests.local"
    )
    _grant_core_permissions(
        auditor,
        {
            "view_question",
            "change_question",
            "view_questionchoice",
            "change_questionchoice",
            "view_framework",
            "view_requirementnode",
        },
        world["root"],
    )
    _grant_core_permissions(
        auditor,
        {"add_question"},
        world["enclave"],
    )
    client = _client(auditor)

    question_reparent = client.patch(
        f"/api/questions/{world['driver'].id}/",
        {"requirement_node": str(world["ig_denied_requirement"].id)},
        format="json",
    )
    choice_reparent = client.patch(
        f"/api/question-choices/{world['choice'].id}/",
        {"question": str(world["number"].id)},
        format="json",
    )
    folder_move = client.patch(
        f"/api/questions/{world['driver'].id}/",
        {"folder": str(world["enclave"].id)},
        format="json",
    )
    choice_folder_move = client.patch(
        f"/api/question-choices/{world['choice'].id}/",
        {"folder": str(world["enclave"].id)},
        format="json",
    )

    assert question_reparent.status_code == 400, question_reparent.content
    assert choice_reparent.status_code == 400, choice_reparent.content
    assert folder_move.status_code == 200, folder_move.content
    assert choice_folder_move.status_code == 200, choice_folder_move.content
    world["driver"].refresh_from_db()
    world["choice"].refresh_from_db()
    assert world["driver"].requirement_node_id == world["leaf"].id
    assert world["driver"].folder_id == world["leaf"].folder_id
    assert world["choice"].question_id == world["choice_question"].id
    assert world["choice"].folder_id == world["choice_question"].folder_id


def test_unused_question_and_choice_reparent_requires_target_add_authority(
    requirement_assignment_world,
):
    world = requirement_assignment_world
    user = User.objects.create_user(
        f"cross-domain-question-mover-{uuid.uuid4().hex}@tests.local"
    )
    _grant_core_permissions(
        user,
        {
            "view_question",
            "change_question",
            "view_questionchoice",
            "change_questionchoice",
            "view_requirementnode",
        },
        world["root"],
    )
    _grant_core_permissions(
        user,
        {"view_question", "view_requirementnode"},
        world["cross_enclave"],
    )
    target_node = RequirementNode.objects.create(
        name="Cross-domain target requirement",
        urn=f"{world['leaf'].urn}:cross-domain-target-{uuid.uuid4().hex}",
        ref_id="CROSS-TARGET",
        framework=world["framework"],
        folder=world["cross_enclave"],
        assessable=True,
    )
    source_question = Question.objects.create(
        requirement_node=world["leaf"],
        urn=f"{world['leaf'].urn}:unused-source-{uuid.uuid4().hex}",
        ref_id="UNUSED-SOURCE",
        text="Unused source question",
        type=Question.Type.TEXT,
        folder=world["root"],
    )
    target_question = Question.objects.create(
        requirement_node=target_node,
        urn=f"{target_node.urn}:target-question",
        ref_id="TARGET-QUESTION",
        text="Target question",
        type=Question.Type.UNIQUE_CHOICE,
        folder=world["cross_enclave"],
    )
    source_choice_question = Question.objects.create(
        requirement_node=world["leaf"],
        urn=f"{world['leaf'].urn}:unused-choice-owner-{uuid.uuid4().hex}",
        ref_id="UNUSED-CHOICE-OWNER",
        text="Unused choice owner",
        type=Question.Type.UNIQUE_CHOICE,
        folder=world["root"],
    )
    source_choice = QuestionChoice.objects.create(
        question=source_choice_question,
        urn=f"{source_choice_question.urn}:unused-choice",
        ref_id="UNUSED-CHOICE",
        value="Unused choice",
        folder=world["root"],
    )
    client = _client(user)

    question_response = client.patch(
        f"/api/questions/{source_question.id}/",
        {"requirement_node": str(target_node.id)},
        format="json",
    )
    choice_response = client.patch(
        f"/api/question-choices/{source_choice.id}/",
        {"question": str(target_question.id)},
        format="json",
    )

    assert question_response.status_code == 403, question_response.content
    assert choice_response.status_code == 403, choice_response.content
    source_question.refresh_from_db()
    source_choice.refresh_from_db()
    assert source_question.requirement_node_id == world["leaf"].id
    assert source_choice.question_id != target_question.id


def test_reverse_requirement_links_and_comments_cannot_bypass_assignment_scope(
    requirement_assignment_world,
):
    world = requirement_assignment_world
    respondent = world["respondent"]
    respondent_client = _client(respondent)
    _grant_core_permissions(
        respondent,
        {
            "view_appliedcontrol",
            "add_appliedcontrol",
            "change_appliedcontrol",
            "delete_appliedcontrol",
            "view_securityexception",
            "add_securityexception",
            "change_securityexception",
            "delete_securityexception",
        },
        world["enclave"],
    )

    evidence_response = respondent_client.post(
        "/api/evidences/",
        {
            "name": "Assignment-scoped evidence",
            "folder": str(world["enclave"].id),
            "requirement_assessments": [str(world["leaf_ra"].id)],
        },
        format="json",
    )
    assert evidence_response.status_code == 201, evidence_response.content
    evidence = Evidence.objects.get(id=evidence_response.json()["id"])
    assert list(evidence.requirement_assessments.all()) == [world["leaf_ra"]]

    control_response = respondent_client.post(
        "/api/applied-controls/",
        {
            "name": "Forbidden respondent control",
            "folder": str(world["enclave"].id),
            "requirement_assessments": [str(world["leaf_ra"].id)],
        },
        format="json",
    )
    assert control_response.status_code == 403, control_response.content
    assert not AppliedControl.objects.filter(
        name="Forbidden respondent control"
    ).exists()

    security_exception = SecurityException.objects.create(
        name="Linked exception",
        folder=world["enclave"],
    )
    security_exception.requirement_assessments.add(world["leaf_ra"])
    exception_response = respondent_client.patch(
        f"/api/security-exceptions/{security_exception.id}/",
        {"requirement_assessments": []},
        format="json",
    )
    assert exception_response.status_code == 403, exception_response.content

    world["assignment"].requirement_assessments.remove(world["ig_denied_ra"])
    unassigned_evidence = respondent_client.post(
        "/api/evidences/",
        {
            "name": "Unassigned evidence",
            "folder": str(world["enclave"].id),
            "requirement_assessments": [str(world["ig_denied_ra"].id)],
        },
        format="json",
    )
    unassigned_comment = respondent_client.post(
        "/api/comments/",
        {
            "body": "Must not attach outside the exact assignment",
            "requirement_assessment": str(world["ig_denied_ra"].id),
        },
        format="json",
    )
    assigned_comment = respondent_client.post(
        "/api/comments/",
        {
            "body": "Bound to the exact assignment",
            "requirement_assessment": str(world["leaf_ra"].id),
        },
        format="json",
    )
    assert unassigned_evidence.status_code == 403, unassigned_evidence.content
    assert unassigned_comment.status_code == 403, unassigned_comment.content
    assert assigned_comment.status_code == 201, assigned_comment.content
    assert (
        Comment.objects.get(id=assigned_comment.json()["id"]).folder_id
        == world["enclave"].id
    )

    _grant_core_permissions(
        respondent,
        {"view_evidence", "add_evidence", "change_evidence"},
        world["cross_enclave"],
    )
    world["assignment"].status = RequirementAssignment.Status.SUBMITTED
    world["assignment"].save(update_fields=["status"])
    round_trip_update = respondent_client.patch(
        f"/api/evidences/{evidence.id}/",
        {
            "name": "Evidence metadata after submission",
            "requirement_assessments": [str(world["leaf_ra"].id)],
        },
        format="json",
    )
    frozen_move = respondent_client.patch(
        f"/api/evidences/{evidence.id}/",
        {"folder": str(world["cross_enclave"].id)},
        format="json",
    )
    frozen_delete = respondent_client.delete(f"/api/evidences/{evidence.id}/")
    submitted_comment = respondent_client.post(
        "/api/comments/",
        {
            "body": "Review discussion remains available after submission",
            "requirement_assessment": str(world["leaf_ra"].id),
        },
        format="json",
    )
    assert round_trip_update.status_code == 200, round_trip_update.content
    assert frozen_move.status_code == 403, frozen_move.content
    assert frozen_delete.status_code == 403, frozen_delete.content
    assert submitted_comment.status_code == 201, submitted_comment.content
    evidence.refresh_from_db()
    assert evidence.folder_id == world["enclave"].id
    assert evidence.name == "Evidence metadata after submission"

    auditor = User.objects.create_user(
        f"reverse-link-auditor-{uuid.uuid4().hex}@tests.local"
    )
    _grant_core_permissions(
        auditor,
        {
            "view_complianceassessment",
            "view_compliance_assessment_full",
            "view_requirementassessment",
            "change_requirementassessment",
            "view_evidence",
            "add_evidence",
            "change_evidence",
            "view_comment",
            "add_comment",
        },
        world["enclave"],
    )
    world["assignment"].status = RequirementAssignment.Status.IN_PROGRESS
    world["assignment"].save(update_fields=["status"])
    auditor_response = _client(auditor).post(
        "/api/evidences/",
        {
            "name": "Auditor-linked evidence",
            "folder": str(world["enclave"].id),
            "requirement_assessments": [str(world["leaf_ra"].id)],
        },
        format="json",
    )
    assert auditor_response.status_code == 201, auditor_response.content

    world["ca"].field_visibility["evidences"]["auditor"] = "read"
    world["ca"].save(update_fields=["field_visibility"])
    auditor_evidence = Evidence.objects.get(id=auditor_response.json()["id"])
    auditor_round_trip = _client(auditor).patch(
        f"/api/evidences/{auditor_evidence.id}/",
        {
            "name": "Auditor metadata with read-only audit relation",
            "requirement_assessments": [str(world["leaf_ra"].id)],
        },
        format="json",
    )
    read_only_response = _client(auditor).post(
        "/api/evidences/",
        {
            "name": "Read-only auditor evidence",
            "folder": str(world["enclave"].id),
            "requirement_assessments": [str(world["leaf_ra"].id)],
        },
        format="json",
    )
    world["ca"].status = ComplianceAssessment.Status.IN_REVIEW
    world["ca"].save(update_fields=["status"])
    in_review_comment = _client(auditor).post(
        "/api/comments/",
        {
            "body": "Auditor discussion remains available in review",
            "requirement_assessment": str(world["leaf_ra"].id),
        },
        format="json",
    )
    assert auditor_round_trip.status_code == 200, auditor_round_trip.content
    assert read_only_response.status_code == 403, read_only_response.content
    assert in_review_comment.status_code == 201, in_review_comment.content


@pytest.mark.parametrize("revocation", ["requirement", "actor"])
def test_requirement_comments_disappear_after_exact_assignment_authority_is_revoked(
    requirement_assignment_world,
    revocation,
):
    world = requirement_assignment_world
    respondent = world["respondent"]
    _grant_core_permissions(
        respondent,
        {"view_comment", "add_comment", "change_comment", "delete_comment"},
        world["enclave"],
    )
    client = _client(respondent)
    comments_url = "/api/comments/"

    deletable = client.post(
        comments_url,
        {
            "body": "Authorized assignment discussion to delete",
            "requirement_assessment": str(world["leaf_ra"].id),
        },
        format="json",
    )
    assert deletable.status_code == 201, deletable.content
    deletable_url = f"{comments_url}{deletable.json()['id']}/"
    assert client.get(deletable_url).status_code == 200
    assert client.delete(deletable_url).status_code == 204

    created = client.post(
        comments_url,
        {
            "body": "Authorized assignment discussion",
            "requirement_assessment": str(world["leaf_ra"].id),
        },
        format="json",
    )
    assert created.status_code == 201, created.content
    comment_id = created.json()["id"]
    detail_url = f"{comments_url}{comment_id}/"
    authorized_list = client.get(
        comments_url,
        {"requirement_assessment": str(world["leaf_ra"].id)},
    )
    assert authorized_list.status_code == 200, authorized_list.content
    authorized_payload = authorized_list.json()
    authorized_rows = authorized_payload.get("results", authorized_payload)
    assert comment_id in {row["id"] for row in authorized_rows}
    assert client.get(detail_url).status_code == 200
    authorized_update = client.patch(
        detail_url,
        {"body": "Authorized actor updated this discussion"},
        format="json",
    )
    assert authorized_update.status_code == 200, authorized_update.content

    if revocation == "requirement":
        world["assignment"].requirement_assessments.remove(world["leaf_ra"])
    else:
        world["assignment"].actor.remove(Actor.objects.get(user=world["respondent"]))

    revoked_list = client.get(
        comments_url,
        {"requirement_assessment": str(world["leaf_ra"].id)},
    )
    revoked_detail = client.get(detail_url)
    revoked_update = client.patch(
        detail_url,
        {"body": "Revoked actor must not update this discussion"},
        format="json",
    )
    revoked_delete = client.delete(detail_url)

    assert revoked_list.status_code == 200, revoked_list.content
    revoked_payload = revoked_list.json()
    revoked_rows = revoked_payload.get("results", revoked_payload)
    assert comment_id not in {row["id"] for row in revoked_rows}
    assert revoked_detail.status_code == 404, revoked_detail.content
    assert revoked_update.status_code == 404, revoked_update.content
    assert revoked_delete.status_code == 404, revoked_delete.content
    comment = Comment.objects.get(id=comment_id)
    assert comment.body == "Authorized actor updated this discussion"


def test_hidden_answers_and_score_metadata_fail_closed_across_assignment_surfaces(
    requirement_assignment_world,
    monkeypatch,
):
    world = requirement_assignment_world
    leaf_ra = world["leaf_ra"]
    client = _client(world["respondent"])

    # Seed enough hidden answer data for an answer-driven dashboard to report
    # 100%. The visible result carrier remains NOT_ASSESSED, so the safe
    # fallback must instead report zero progress.
    Answer.objects.filter(
        requirement_assessment=leaf_ra, question=world["driver"]
    ).update(value=True)
    Answer.objects.filter(
        requirement_assessment=leaf_ra, question=world["conditional"]
    ).update(value=7)
    Answer.objects.filter(
        requirement_assessment=leaf_ra, question=world["number"]
    ).update(value=2)
    choice_answer = Answer.objects.get(
        requirement_assessment=leaf_ra,
        question=world["choice_question"],
    )
    choice_answer.selected_choices.add(world["choice"])
    leaf_ra.refresh_from_db()
    assert leaf_ra.result == RequirementAssessment.Result.NOT_ASSESSED

    world["ca"].field_visibility = {
        **world["ca"].field_visibility,
        "answers": {"auditor": "edit", "respondent": "hidden"},
    }
    world["ca"].save(update_fields=["field_visibility"])

    list_response = client.get(
        f"/api/requirement-assignments/{world['assignment'].id}/requirements_list/"
    )
    assert list_response.status_code == 200, list_response.content
    body = list_response.json()
    leaf_row = next(
        row for row in body["requirement_assessments"] if row["id"] == str(leaf_ra.id)
    )
    leaf_node = next(
        node for node in body["requirements"] if node["id"] == str(world["leaf"].id)
    )

    assert "answers" not in leaf_row
    assert leaf_row["visible_questions"] is None
    assert leaf_row["answered_questions"] is None
    assert body["total_visible_questions"] is None
    assert body["total_answered_questions"] is None

    score_fields = {
        "min_score",
        "max_score",
        "scores_definition_ref",
        "target_score",
        "weight",
    }
    assert score_fields.isdisjoint(leaf_node)
    assert score_fields.isdisjoint(leaf_row["requirement"])
    for row in (leaf_node, leaf_row["requirement"]):
        scoring_choice = row["questions"][world["choice_question"].urn]["choices"][0]
        assert "add_score" not in scoring_choice
        assert "compute_result" not in scoring_choice
    for field_name in (
        "score",
        "is_scored",
        "documentation_score",
        "effective_min_score",
        "effective_max_score",
        "effective_scores_definition",
        "target_score",
    ):
        assert field_name not in leaf_row
    for field_name in (
        "min_score",
        "max_score",
        "scores_definition",
        "score_calculation_method",
    ):
        assert field_name not in leaf_row["compliance_assessment"]

    def unexpected_answer_progress(**_kwargs):
        raise AssertionError("hidden answers must not drive dashboard progress")

    monkeypatch.setattr(
        "core.views.get_assignment_visible_question_counts",
        unexpected_answer_progress,
    )
    dashboard_response = client.get("/api/compliance-assessments/auditee-dashboard/")
    assert dashboard_response.status_code == 200, dashboard_response.content
    cards = dashboard_response.json()
    assert len(cards) == 1
    assert cards[0]["total_requirements"] == 1
    assert cards[0]["assessed_requirements"] == 0
    assert cards[0]["progress_percent"] == 0

    denied = client.patch(
        _assignment_update_url(world, leaf_ra),
        {"answers": {world["driver"].urn: False}},
        format="json",
    )
    assert denied.status_code == 400, denied.content
    assert (
        Answer.objects.get(
            requirement_assessment=leaf_ra,
            question=world["driver"],
        ).value
        is True
    )


def test_assignment_capability_fails_closed_when_any_cel_visibility_is_present(
    requirement_assignment_world,
):
    world = requirement_assignment_world
    client = _client(world["respondent"])
    leaf_ra = world["leaf_ra"]
    original_result = leaf_ra.result
    world["leaf"].visibility_expression = "true"
    world["leaf"].save(update_fields=["visibility_expression"])

    listing = client.get(
        f"/api/requirement-assignments/{world['assignment'].id}/requirements_list/"
    )
    update = client.patch(
        _assignment_update_url(world, leaf_ra),
        {"result": RequirementAssessment.Result.COMPLIANT},
        format="json",
    )

    assert listing.status_code == 403, listing.content
    assert update.status_code == 403, update.content
    leaf_ra.refresh_from_db()
    assert leaf_ra.result == original_result


def test_assignment_scoped_cel_mutation_is_also_closed_for_auditor(
    requirement_assignment_world,
):
    world = requirement_assignment_world
    auditor = User.objects.create_user(
        f"capability-auditor-{uuid.uuid4().hex}@tests.local"
    )
    _grant_core_permissions(
        auditor,
        {
            "view_complianceassessment",
            "view_compliance_assessment_full",
            "view_framework",
            "view_requirementassignment",
            "view_requirementassessment",
            "change_requirementassessment",
        },
        world["root"],
    )
    world["leaf"].visibility_expression = "true"
    world["leaf"].save(update_fields=["visibility_expression"])
    original_result = world["leaf_ra"].result

    response = _client(auditor).patch(
        _assignment_update_url(world, world["leaf_ra"]),
        {"result": RequirementAssessment.Result.COMPLIANT},
        format="json",
    )

    assert response.status_code == 403, response.content
    assert b"Assignment-scoped mutation" in response.content
    world["leaf_ra"].refresh_from_db()
    assert world["leaf_ra"].result == original_result


@pytest.mark.parametrize("sqlstate", ("40P01", "55P03"))
def test_retryable_database_conflict_response_is_fixed_and_redacted(sqlstate):
    from rest_framework.exceptions import ValidationError

    from core.views import BaseModelViewSet

    class RetryableDatabaseCause(Exception):
        pass

    database_cause = RetryableDatabaseCause("sensitive lock detail, backend pid 12345")
    database_cause.sqlstate = sqlstate
    wrapped_error = ValidationError("wrapped database detail")
    wrapped_error.__cause__ = database_cause

    response = BaseModelViewSet().handle_exception(wrapped_error)

    assert response.status_code == 409
    assert response["Retry-After"] == "1"
    assert response.data == {
        "detail": "A concurrent update conflicted; retry the request."
    }
    assert "12345" not in str(response.data)


@pytest.mark.skipif(
    connection.vendor != "postgresql",
    reason="Actor carrier recheck requires PostgreSQL row locking.",
)
@pytest.mark.django_db(transaction=True)
def test_ca_create_waits_for_writer_first_author_user_folder_move(
    requirement_assignment_world,
):
    world = requirement_assignment_world
    creator = User.objects.create_user(
        f"ca-author-folder-race-{uuid.uuid4().hex}@tests.local"
    )
    _grant_core_permissions(
        creator,
        {"add_complianceassessment", "view_complianceassessment"},
        world["enclave"],
    )
    _grant_view_only(creator, "framework", world["root"])
    _grant_view_only(creator, "perimeter", world["enclave"])
    _grant_iam_permissions(creator, {"view_user"}, world["enclave"])
    author_user = User.objects.create_user(
        f"ca-author-folder-target-{uuid.uuid4().hex}@tests.local"
    )
    author_user.folder = world["enclave"]
    author_user.save(update_fields=["folder"])
    author = Actor.objects.get(user=author_user)
    assert author.id in set(RoleAssignment.get_viewable_object_ids(creator, Actor))

    creator_id = creator.id
    author_user_id = author_user.id
    author_id = author.id
    create_name = f"Writer-first hidden CA author {uuid.uuid4().hex}"
    writer_pid_queue: Queue[int] = Queue()
    create_pid_queue: Queue[int] = Queue()
    folder_move_is_uncommitted = Event()
    allow_writer_commit = Event()

    def author_folder_writer() -> None:
        with transaction.atomic():
            User.objects.select_for_update(of=("self",)).get(pk=author_user_id)
            User.objects.filter(pk=author_user_id).update(
                folder_id=world["hidden_enclave"].id
            )
            folder_move_is_uncommitted.set()
            if not allow_writer_commit.wait(_PG_THREAD_TIMEOUT_SECONDS):
                raise AssertionError(
                    "Timed out while holding the writer-first User folder change."
                )

    def create_assessment() -> tuple[int, bytes]:
        response = _client(User.objects.get(pk=creator_id)).post(
            "/api/compliance-assessments/",
            {
                "name": create_name,
                "framework": str(world["framework"].id),
                "perimeter": str(world["ca"].perimeter_id),
                "folder": str(world["enclave"].id),
                "authors": [str(author_id)],
            },
            format="json",
        )
        return response.status_code, bytes(response.content)

    with ThreadPoolExecutor(max_workers=2) as executor:
        writer_future: Future[None] = executor.submit(
            _run_on_fresh_pg_connection,
            "cfgrc-ca-author-folder-writer",
            writer_pid_queue,
            author_folder_writer,
        )
        create_future: Future[tuple[int, bytes]] | None = None
        try:
            writer_pid = writer_pid_queue.get(timeout=_PG_THREAD_TIMEOUT_SECONDS)
            assert folder_move_is_uncommitted.wait(_PG_THREAD_TIMEOUT_SECONDS)
            create_future = executor.submit(
                _run_on_fresh_pg_connection,
                "cfgrc-ca-author-folder-create",
                create_pid_queue,
                create_assessment,
            )
            create_pid = create_pid_queue.get(timeout=_PG_THREAD_TIMEOUT_SECONDS)
            blocked_query = _wait_for_pg_block(
                blocked_pid=create_pid,
                blocker_pid=writer_pid,
            )
            normalized_query = " ".join(blocked_query.lower().split())
            assert '"iam_user"' in normalized_query
            assert "for update" in normalized_query
        finally:
            allow_writer_commit.set()

        writer_future.result(timeout=_PG_THREAD_TIMEOUT_SECONDS)
        assert create_future is not None
        status_code, response_content = create_future.result(
            timeout=_PG_THREAD_TIMEOUT_SECONDS
        )

    assert status_code == 403, response_content
    assert not ComplianceAssessment.objects.filter(name=create_name).exists()
    assert (
        User.objects.values_list("folder_id", flat=True).get(pk=author_user_id)
        == world["hidden_enclave"].id
    )
    assert author_id not in set(RoleAssignment.get_viewable_object_ids(creator, Actor))


@pytest.mark.skipif(
    connection.vendor != "postgresql",
    reason="Folder-tree IAM recheck requires PostgreSQL row locking.",
)
@pytest.mark.django_db(transaction=True)
def test_evidence_update_waits_for_writer_first_folder_reparent(
    requirement_assignment_world,
):
    world = requirement_assignment_world
    root = world["root"]
    visible_domain = Folder.objects.create(
        name=f"Visible writer-first domain {uuid.uuid4().hex}",
        content_type=Folder.ContentType.DOMAIN,
        parent_folder=root,
    )
    hidden_domain = Folder.objects.create(
        name=f"Hidden writer-first domain {uuid.uuid4().hex}",
        content_type=Folder.ContentType.DOMAIN,
        parent_folder=root,
    )
    moving_enclave = Folder.objects.create(
        name=f"Writer-first moving enclave {uuid.uuid4().hex}",
        content_type=Folder.ContentType.ENCLAVE,
        parent_folder=visible_domain,
    )
    editor = User.objects.create_user(
        f"evidence-folder-race-{uuid.uuid4().hex}@tests.local"
    )
    _grant_core_permissions(
        editor,
        {"view_evidence", "change_evidence"},
        visible_domain,
    )
    evidence = Evidence.objects.create(
        name=f"Writer-first evidence {uuid.uuid4().hex}",
        folder=moving_enclave,
    )
    assert evidence.id in set(RoleAssignment.get_viewable_object_ids(editor, Evidence))

    editor_id = editor.id
    evidence_id = evidence.id
    moving_enclave_id = moving_enclave.id
    original_name = evidence.name
    writer_pid_queue: Queue[int] = Queue()
    patch_pid_queue: Queue[int] = Queue()
    reparent_is_uncommitted = Event()
    allow_writer_commit = Event()

    def folder_reparent_writer() -> None:
        with transaction.atomic():
            folder = Folder.objects.get(pk=moving_enclave_id)
            folder.parent_folder_id = hidden_domain.id
            folder.save(update_fields=["parent_folder"])
            reparent_is_uncommitted.set()
            if not allow_writer_commit.wait(_PG_THREAD_TIMEOUT_SECONDS):
                raise AssertionError(
                    "Timed out while holding the writer-first folder reparent."
                )

    def patch_evidence() -> tuple[int, bytes]:
        response = _client(User.objects.get(pk=editor_id)).patch(
            f"/api/evidences/{evidence_id}/",
            {"name": "Must not survive folder reparent"},
            format="json",
        )
        return response.status_code, bytes(response.content)

    with ThreadPoolExecutor(max_workers=2) as executor:
        writer_future: Future[None] = executor.submit(
            _run_on_fresh_pg_connection,
            "cfgrc-folder-reparent-writer",
            writer_pid_queue,
            folder_reparent_writer,
        )
        patch_future: Future[tuple[int, bytes]] | None = None
        try:
            writer_pid = writer_pid_queue.get(timeout=_PG_THREAD_TIMEOUT_SECONDS)
            assert reparent_is_uncommitted.wait(_PG_THREAD_TIMEOUT_SECONDS)
            patch_future = executor.submit(
                _run_on_fresh_pg_connection,
                "cfgrc-folder-reparent-evidence-patch",
                patch_pid_queue,
                patch_evidence,
            )
            patch_pid = patch_pid_queue.get(timeout=_PG_THREAD_TIMEOUT_SECONDS)
            blocked_query = _wait_for_pg_block(
                blocked_pid=patch_pid,
                blocker_pid=writer_pid,
            )
            normalized_query = " ".join(blocked_query.lower().split())
            assert '"iam_folder"' in normalized_query
            assert "for update" in normalized_query
        finally:
            allow_writer_commit.set()

        writer_future.result(timeout=_PG_THREAD_TIMEOUT_SECONDS)
        assert patch_future is not None
        status_code, response_content = patch_future.result(
            timeout=_PG_THREAD_TIMEOUT_SECONDS
        )

    assert status_code == 403, response_content
    evidence.refresh_from_db()
    moving_enclave.refresh_from_db()
    assert evidence.name == original_name
    assert moving_enclave.parent_folder_id == hidden_domain.id
    assert evidence_id not in set(
        RoleAssignment.get_viewable_object_ids(editor, Evidence)
    )


@pytest.mark.skipif(
    connection.vendor != "postgresql",
    reason="Cross-model generic relation locking requires PostgreSQL.",
)
@pytest.mark.django_db(transaction=True)
def test_policy_and_evidence_updates_share_concrete_global_lock_order(
    requirement_assignment_world,
    monkeypatch,
):
    """Policy proxies and AppliedControl relations must share one lock slot."""

    from core.views import RequirementAssessmentRelationGuardMixin

    world = requirement_assignment_world
    editor = User.objects.create_user(
        f"policy-evidence-lock-order-{uuid.uuid4().hex}@tests.local"
    )
    _grant_core_permissions(
        editor,
        {
            "view_policy",
            "change_policy",
            "view_appliedcontrol",
            "change_appliedcontrol",
            "view_evidence",
            "change_evidence",
        },
        world["enclave"],
    )
    policy = Policy.objects.create(
        name="Concurrent policy relation owner",
        folder=world["enclave"],
    )
    evidence = Evidence.objects.create(
        name="Concurrent evidence relation owner",
        folder=world["enclave"],
    )
    editor_id = editor.id
    policy_id = policy.id
    evidence_id = evidence.id
    start_barrier = Barrier(2)
    observed_orders: Queue[tuple[str, ...]] = Queue()
    winner_pid_queue: Queue[int] = Queue()
    winner_has_all_target_locks = Event()
    allow_winner_to_continue = Event()
    original_lock = (
        RequirementAssessmentRelationGuardMixin._lock_rows_in_global_model_order
    )

    def synchronized_lock(target_ids_by_model):
        observed_orders.put(
            tuple(
                sorted(
                    {
                        model._meta.concrete_model._meta.label_lower
                        for model in target_ids_by_model
                    }
                )
            )
        )
        start_barrier.wait(timeout=_PG_THREAD_TIMEOUT_SECONDS)
        locked_rows = original_lock(target_ids_by_model)
        with connections["default"].cursor() as cursor:
            cursor.execute("SELECT pg_backend_pid()")
            winner_pid_queue.put(cursor.fetchone()[0])
        winner_has_all_target_locks.set()
        if not allow_winner_to_continue.wait(_PG_THREAD_TIMEOUT_SECONDS):
            raise AssertionError("Timed out while holding generic relation locks.")
        return locked_rows

    monkeypatch.setattr(
        RequirementAssessmentRelationGuardMixin,
        "_lock_rows_in_global_model_order",
        staticmethod(synchronized_lock),
    )

    def policy_patch() -> tuple[int, bytes]:
        response = _client(User.objects.get(pk=editor_id)).patch(
            f"/api/policies/{policy_id}/",
            {"evidences": [str(evidence_id)]},
            format="json",
        )
        return response.status_code, bytes(response.content)

    def evidence_patch() -> tuple[int, bytes]:
        response = _client(User.objects.get(pk=editor_id)).patch(
            f"/api/evidences/{evidence_id}/",
            {"applied_controls": [str(policy_id)]},
            format="json",
        )
        return response.status_code, bytes(response.content)

    policy_pid_queue: Queue[int] = Queue()
    evidence_pid_queue: Queue[int] = Queue()
    with ThreadPoolExecutor(max_workers=2) as executor:
        policy_future = executor.submit(
            _run_on_fresh_pg_connection,
            "cfgrc-policy-evidence-policy-side",
            policy_pid_queue,
            policy_patch,
        )
        evidence_future = executor.submit(
            _run_on_fresh_pg_connection,
            "cfgrc-policy-evidence-evidence-side",
            evidence_pid_queue,
            evidence_patch,
        )
        policy_pid = policy_pid_queue.get(timeout=_PG_THREAD_TIMEOUT_SECONDS)
        evidence_pid = evidence_pid_queue.get(timeout=_PG_THREAD_TIMEOUT_SECONDS)
        try:
            assert winner_has_all_target_locks.wait(_PG_THREAD_TIMEOUT_SECONDS)
            winner_pid = winner_pid_queue.get(timeout=_PG_THREAD_TIMEOUT_SECONDS)
            assert winner_pid in {policy_pid, evidence_pid}
            blocked_pid = evidence_pid if winner_pid == policy_pid else policy_pid
            blocked_query = _wait_for_pg_block(
                blocked_pid=blocked_pid,
                blocker_pid=winner_pid,
            )
            normalized_blocked_query = " ".join(blocked_query.lower().split())
            assert "core_appliedcontrol" in normalized_blocked_query
            assert "for update" in normalized_blocked_query
        finally:
            allow_winner_to_continue.set()
        responses = [
            policy_future.result(timeout=_PG_THREAD_TIMEOUT_SECONDS),
            evidence_future.result(timeout=_PG_THREAD_TIMEOUT_SECONDS),
        ]

    expected_order = ("core.appliedcontrol", "core.evidence")
    assert observed_orders.get_nowait() == expected_order
    assert observed_orders.get_nowait() == expected_order
    assert sorted(status for status, _body in responses) == [200, 403]
    assert (
        Evidence.objects.get(pk=evidence_id)
        .applied_controls.filter(pk=policy_id)
        .exists()
    )


@pytest.mark.skipif(
    connection.vendor != "postgresql",
    reason="CEL node-lock acceptance requires PostgreSQL row locking.",
)
@pytest.mark.django_db(transaction=True)
def test_assignment_patch_waits_for_writer_first_cel_node_change_and_fails_closed(
    requirement_assignment_world,
):
    world = requirement_assignment_world
    target_ra_id = world["leaf_ra"].id
    respondent_id = world["respondent"].id
    cel_node_id = world["non_assessable_requirement"].id
    update_url = _assignment_update_url(world, world["leaf_ra"])
    original_result = RequirementAssessment.objects.values_list(
        "result", flat=True
    ).get(pk=target_ra_id)
    assert original_result != RequirementAssessment.Result.COMPLIANT
    assert not RequirementNode.objects.values_list(
        "visibility_expression", flat=True
    ).get(pk=cel_node_id)

    writer_pid_queue: Queue[int] = Queue()
    patch_pid_queue: Queue[int] = Queue()
    cel_change_is_uncommitted = Event()
    allow_writer_commit = Event()

    def writer_operation() -> None:
        with transaction.atomic():
            cel_node = RequirementNode.objects.select_for_update(of=("self",)).get(
                pk=cel_node_id
            )
            cel_node.visibility_expression = "true"
            cel_node.save(update_fields=["visibility_expression"])
            cel_change_is_uncommitted.set()
            if not allow_writer_commit.wait(_PG_THREAD_TIMEOUT_SECONDS):
                raise AssertionError(
                    "Timed out while holding the writer-first CEL node lock."
                )

    def patch_operation() -> tuple[int, bytes]:
        respondent = User.objects.get(pk=respondent_id)
        response = _client(respondent).patch(
            update_url,
            {"result": RequirementAssessment.Result.COMPLIANT},
            format="json",
        )
        return response.status_code, bytes(response.content)

    with ThreadPoolExecutor(max_workers=2) as executor:
        writer_future: Future[None] = executor.submit(
            _run_on_fresh_pg_connection,
            "cfgrc-assignment-cel-writer",
            writer_pid_queue,
            writer_operation,
        )
        patch_future: Future[tuple[int, bytes]] | None = None
        try:
            writer_pid = writer_pid_queue.get(timeout=_PG_THREAD_TIMEOUT_SECONDS)
            assert cel_change_is_uncommitted.wait(_PG_THREAD_TIMEOUT_SECONDS)
            patch_future = executor.submit(
                _run_on_fresh_pg_connection,
                "cfgrc-assignment-cel-patch",
                patch_pid_queue,
                patch_operation,
            )
            patch_pid = patch_pid_queue.get(timeout=_PG_THREAD_TIMEOUT_SECONDS)
            blocked_query = _wait_for_pg_block(
                blocked_pid=patch_pid,
                blocker_pid=writer_pid,
            )
            assert "core_requirementnode" in blocked_query.lower()
            assert "for update" in blocked_query.lower()
        finally:
            allow_writer_commit.set()

        writer_future.result(timeout=_PG_THREAD_TIMEOUT_SECONDS)
        assert patch_future is not None
        status_code, response_content = patch_future.result(
            timeout=_PG_THREAD_TIMEOUT_SECONDS
        )

    assert status_code == 403, response_content
    assert b"CEL visibility is configured" in response_content
    world["non_assessable_requirement"].refresh_from_db()
    world["leaf_ra"].refresh_from_db()
    assert world["non_assessable_requirement"].visibility_expression == "true"
    assert world["leaf_ra"].result == original_result


@pytest.mark.skipif(
    connection.vendor != "postgresql",
    reason="Generic RA lock-order acceptance requires PostgreSQL row locking.",
)
@pytest.mark.django_db(transaction=True)
def test_generic_auditor_patch_locks_ca_before_ra_and_rechecks_locked_state(
    requirement_assignment_world,
):
    world = requirement_assignment_world
    auditor = User.objects.create_user(
        f"capability-pg-auditor-{uuid.uuid4().hex}@tests.local"
    )
    _grant_core_permissions(
        auditor,
        {
            "view_complianceassessment",
            "view_compliance_assessment_full",
            "view_framework",
            "view_requirementnode",
            "view_requirementassessment",
            "change_requirementassessment",
        },
        world["root"],
    )

    auditor_id = auditor.id
    compliance_assessment_id = world["ca"].id
    target_ra_id = world["leaf_ra"].id
    update_url = f"/api/requirement-assessments/{target_ra_id}/"
    original_result = RequirementAssessment.objects.values_list(
        "result", flat=True
    ).get(pk=target_ra_id)
    assert original_result != RequirementAssessment.Result.COMPLIANT

    holder_pid_queue: Queue[int] = Queue()
    patch_pid_queue: Queue[int] = Queue()
    ca_is_locked = Event()
    allow_holder_to_lock_ra = Event()

    def ca_then_ra_holder() -> None:
        with transaction.atomic():
            ComplianceAssessment.objects.select_for_update(of=("self",)).get(
                pk=compliance_assessment_id
            )
            ComplianceAssessment.objects.filter(pk=compliance_assessment_id).update(
                is_locked=True
            )
            ca_is_locked.set()
            if not allow_holder_to_lock_ra.wait(_PG_THREAD_TIMEOUT_SECONDS):
                raise AssertionError(
                    "Timed out while holding the compliance-assessment lock."
                )
            RequirementAssessment.objects.select_for_update(of=("self",)).get(
                pk=target_ra_id,
                compliance_assessment_id=compliance_assessment_id,
            )

    def generic_patch() -> tuple[int, bytes]:
        response = _client(User.objects.get(pk=auditor_id)).patch(
            update_url,
            {"result": RequirementAssessment.Result.COMPLIANT},
            format="json",
        )
        return response.status_code, bytes(response.content)

    with ThreadPoolExecutor(max_workers=2) as executor:
        holder_future: Future[None] = executor.submit(
            _run_on_fresh_pg_connection,
            "cfgrc-ra-ca-first-holder",
            holder_pid_queue,
            ca_then_ra_holder,
        )
        patch_future: Future[tuple[int, bytes]] | None = None
        try:
            holder_pid = holder_pid_queue.get(timeout=_PG_THREAD_TIMEOUT_SECONDS)
            assert ca_is_locked.wait(_PG_THREAD_TIMEOUT_SECONDS)
            patch_future = executor.submit(
                _run_on_fresh_pg_connection,
                "cfgrc-generic-ra-patch",
                patch_pid_queue,
                generic_patch,
            )
            patch_pid = patch_pid_queue.get(timeout=_PG_THREAD_TIMEOUT_SECONDS)

            blocked_query = _wait_for_pg_block(
                blocked_pid=patch_pid,
                blocker_pid=holder_pid,
            )
            normalized_query = " ".join(blocked_query.lower().split())
            assert normalized_query.startswith("select")
            # pg_stat_activity truncates long statements at
            # track_activity_query_size.  The CA table must be present in the
            # retained prefix while an RA table must not be touched yet.  The
            # proven row-lock blocker establishes the truncated FOR UPDATE
            # suffix.
            assert '"core_complianceassessment"' in normalized_query
            assert "core_requirementassessment" not in normalized_query

            # A CA-first PATCH must not hold the child RA while waiting.
            with transaction.atomic():
                locked_ra = (
                    RequirementAssessment.objects.select_for_update(
                        nowait=True,
                        of=("self",),
                    )
                    .only("id")
                    .get(pk=target_ra_id)
                )
                assert locked_ra.id == target_ra_id
        finally:
            allow_holder_to_lock_ra.set()

        holder_future.result(timeout=_PG_THREAD_TIMEOUT_SECONDS)
        assert patch_future is not None
        status_code, response_content = patch_future.result(
            timeout=_PG_THREAD_TIMEOUT_SECONDS
        )

    assert status_code == 403, response_content
    assert b"audit is locked" in response_content
    world["leaf_ra"].refresh_from_db()
    assert world["leaf_ra"].result == original_result


@pytest.mark.skipif(
    connection.vendor != "postgresql",
    reason="Assignment membership recheck requires PostgreSQL row locking.",
)
@pytest.mark.django_db(transaction=True)
def test_assignment_batch_delete_rechecks_actor_scope_after_writer_commit(
    requirement_assignment_world,
):
    world = requirement_assignment_world
    respondent = world["respondent"]
    assignment = world["assignment"]
    _grant_core_permissions(
        respondent,
        {"delete_requirementassignment"},
        world["enclave"],
    )

    respondent_id = respondent.id
    assignment_id = assignment.id
    writer_pid_queue: Queue[int] = Queue()
    delete_pid_queue: Queue[int] = Queue()
    actor_removal_is_uncommitted = Event()
    allow_writer_commit = Event()

    def actor_removal_writer() -> None:
        with transaction.atomic():
            locked_assignment = RequirementAssignment.objects.select_for_update(
                of=("self",)
            ).get(pk=assignment_id)
            locked_assignment.actor.clear()
            actor_removal_is_uncommitted.set()
            if not allow_writer_commit.wait(_PG_THREAD_TIMEOUT_SECONDS):
                raise AssertionError(
                    "Timed out while holding the assignment membership change."
                )

    def batch_delete() -> tuple[int, dict]:
        response = _client(User.objects.get(pk=respondent_id)).post(
            "/api/requirement-assignments/batch-action/",
            {"action": "delete", "ids": [str(assignment_id)]},
            format="json",
        )
        return response.status_code, response.json()

    with ThreadPoolExecutor(max_workers=2) as executor:
        writer_future: Future[None] = executor.submit(
            _run_on_fresh_pg_connection,
            "cfgrc-assignment-actor-removal",
            writer_pid_queue,
            actor_removal_writer,
        )
        delete_future: Future[tuple[int, dict]] | None = None
        try:
            writer_pid = writer_pid_queue.get(timeout=_PG_THREAD_TIMEOUT_SECONDS)
            assert actor_removal_is_uncommitted.wait(_PG_THREAD_TIMEOUT_SECONDS)
            delete_future = executor.submit(
                _run_on_fresh_pg_connection,
                "cfgrc-assignment-batch-delete",
                delete_pid_queue,
                batch_delete,
            )
            delete_pid = delete_pid_queue.get(timeout=_PG_THREAD_TIMEOUT_SECONDS)
            blocked_query = _wait_for_pg_block(
                blocked_pid=delete_pid,
                blocker_pid=writer_pid,
            )
            normalized_query = " ".join(blocked_query.lower().split())
            # The retained pg_stat_activity prefix identifies the assignment
            # SELECT.  Its proven writer blocker establishes the truncated
            # FOR UPDATE suffix.
            assert '"core_requirementassignment"' in normalized_query
        finally:
            allow_writer_commit.set()

        writer_future.result(timeout=_PG_THREAD_TIMEOUT_SECONDS)
        assert delete_future is not None
        status_code, body = delete_future.result(timeout=_PG_THREAD_TIMEOUT_SECONDS)

    assert status_code == 200, body
    assert body["succeeded"] == []
    assert "requirement assignment is unavailable" in str(body["failed"]).lower()
    assert RequirementAssignment.objects.filter(pk=assignment_id).exists()
    assert not RequirementAssignment.objects.get(pk=assignment_id).actor.exists()


@pytest.mark.skipif(
    connection.vendor != "postgresql",
    reason="Team actor revocation proof requires PostgreSQL row locking.",
)
@pytest.mark.django_db(transaction=True)
def test_assignment_patch_waits_for_writer_first_team_member_revocation(
    requirement_assignment_world,
):
    world = requirement_assignment_world
    respondent = world["respondent"]
    assignment = world["assignment"]
    team = Team.objects.create(
        name=f"Writer-first assignment team {uuid.uuid4().hex}",
        folder=world["enclave"],
    )
    team.members.add(respondent)
    assignment.actor.set([Actor.objects.get(team=team)])

    respondent_id = respondent.id
    assignment_id = assignment.id
    team_id = team.id
    target_ra_id = world["leaf_ra"].id
    update_url = _assignment_update_url(world, world["leaf_ra"])
    original_result = RequirementAssessment.objects.values_list(
        "result", flat=True
    ).get(pk=target_ra_id)
    writer_pid_queue: Queue[int] = Queue()
    patch_pid_queue: Queue[int] = Queue()
    removal_is_uncommitted = Event()
    allow_writer_commit = Event()

    def membership_removal_writer() -> None:
        with transaction.atomic():
            Team.members.through.objects.filter(
                team_id=team_id,
                user_id=respondent_id,
            ).delete()
            removal_is_uncommitted.set()
            if not allow_writer_commit.wait(_PG_THREAD_TIMEOUT_SECONDS):
                raise AssertionError(
                    "Timed out while holding the Team membership revocation."
                )

    def assignment_patch() -> tuple[int, bytes]:
        response = _client(User.objects.get(pk=respondent_id)).patch(
            update_url,
            {"result": RequirementAssessment.Result.COMPLIANT},
            format="json",
        )
        return response.status_code, bytes(response.content)

    with ThreadPoolExecutor(max_workers=2) as executor:
        writer_future: Future[None] = executor.submit(
            _run_on_fresh_pg_connection,
            "cfgrc-team-member-revocation",
            writer_pid_queue,
            membership_removal_writer,
        )
        patch_future: Future[tuple[int, bytes]] | None = None
        try:
            writer_pid = writer_pid_queue.get(timeout=_PG_THREAD_TIMEOUT_SECONDS)
            assert removal_is_uncommitted.wait(_PG_THREAD_TIMEOUT_SECONDS)
            patch_future = executor.submit(
                _run_on_fresh_pg_connection,
                "cfgrc-team-member-assignment-patch",
                patch_pid_queue,
                assignment_patch,
            )
            patch_pid = patch_pid_queue.get(timeout=_PG_THREAD_TIMEOUT_SECONDS)
            blocked_query = _wait_for_pg_block(
                blocked_pid=patch_pid,
                blocker_pid=writer_pid,
            )
            assert "core_team_members" in blocked_query.lower()
        finally:
            allow_writer_commit.set()

        writer_future.result(timeout=_PG_THREAD_TIMEOUT_SECONDS)
        assert patch_future is not None
        status_code, response_content = patch_future.result(
            timeout=_PG_THREAD_TIMEOUT_SECONDS
        )

    assert status_code in {403, 404}, response_content
    world["leaf_ra"].refresh_from_db()
    assert world["leaf_ra"].result == original_result
    assert not Team.members.through.objects.filter(
        team_id=team_id,
        user_id=respondent_id,
    ).exists()


@pytest.mark.skipif(
    connection.vendor != "postgresql",
    reason="Generic Answer binding recheck requires PostgreSQL row locking.",
)
@pytest.mark.django_db(transaction=True)
def test_generic_answer_create_waits_for_writer_first_question_reparent(
    requirement_assignment_world,
):
    world = requirement_assignment_world
    race_question = Question.objects.create(
        requirement_node=world["leaf"],
        urn=f"{world['leaf'].urn}:answer-race-{uuid.uuid4().hex}",
        ref_id="ANSWER-RACE",
        text="Writer-first generic Answer race",
        type=Question.Type.TEXT,
        folder=world["root"],
    )
    auditor = User.objects.create_user(
        f"generic-answer-race-auditor-{uuid.uuid4().hex}@tests.local"
    )
    _grant_core_permissions(
        auditor,
        {
            "view_complianceassessment",
            "view_compliance_assessment_full",
            "view_requirementassessment",
            "view_answer",
            "add_answer",
            "change_answer",
        },
        world["enclave"],
    )
    _grant_core_permissions(
        auditor,
        {"view_requirementnode", "view_question", "view_questionchoice"},
        world["root"],
    )
    auditor_id = auditor.id
    question_id = race_question.id
    target_node_id = world["ig_denied_requirement"].id
    target_ra_id = world["leaf_ra"].id
    writer_pid_queue: Queue[int] = Queue()
    create_pid_queue: Queue[int] = Queue()
    reparent_is_uncommitted = Event()
    allow_writer_commit = Event()

    def question_reparent_writer() -> None:
        with transaction.atomic():
            question = Question.objects.select_for_update(of=("self",)).get(
                id=question_id
            )
            question.requirement_node_id = target_node_id
            question.save(update_fields=["requirement_node"])
            reparent_is_uncommitted.set()
            if not allow_writer_commit.wait(_PG_THREAD_TIMEOUT_SECONDS):
                raise AssertionError("Timed out while holding the Question reparent.")

    def answer_create() -> tuple[int, bytes]:
        response = _client(User.objects.get(id=auditor_id)).post(
            "/api/answers/",
            {
                "requirement_assessment": str(target_ra_id),
                "question": str(question_id),
                "value": "must not persist",
            },
            format="json",
        )
        return response.status_code, bytes(response.content)

    with ThreadPoolExecutor(max_workers=2) as executor:
        writer_future: Future[None] = executor.submit(
            _run_on_fresh_pg_connection,
            "cfgrc-question-reparent-writer",
            writer_pid_queue,
            question_reparent_writer,
        )
        create_future: Future[tuple[int, bytes]] | None = None
        try:
            writer_pid = writer_pid_queue.get(timeout=_PG_THREAD_TIMEOUT_SECONDS)
            assert reparent_is_uncommitted.wait(_PG_THREAD_TIMEOUT_SECONDS)
            create_future = executor.submit(
                _run_on_fresh_pg_connection,
                "cfgrc-generic-answer-create",
                create_pid_queue,
                answer_create,
            )
            create_pid = create_pid_queue.get(timeout=_PG_THREAD_TIMEOUT_SECONDS)
            blocked_query = _wait_for_pg_block(
                blocked_pid=create_pid,
                blocker_pid=writer_pid,
            )
            assert "core_question" in blocked_query.lower()
        finally:
            allow_writer_commit.set()

        writer_future.result(timeout=_PG_THREAD_TIMEOUT_SECONDS)
        assert create_future is not None
        status_code, response_content = create_future.result(
            timeout=_PG_THREAD_TIMEOUT_SECONDS
        )

    assert status_code in {400, 403, 404}, response_content
    race_question.refresh_from_db()
    assert race_question.requirement_node_id == target_node_id
    assert not Answer.objects.filter(
        requirement_assessment_id=target_ra_id,
        question_id=question_id,
    ).exists()


@pytest.mark.skipif(
    connection.vendor != "postgresql",
    reason="Generic RA choice recheck requires PostgreSQL row locking.",
)
@pytest.mark.django_db(transaction=True)
def test_generic_ra_answers_wait_for_writer_first_choice_reparent(
    requirement_assignment_world,
):
    world = requirement_assignment_world
    source_question = Question.objects.create(
        requirement_node=world["leaf"],
        urn=f"{world['leaf'].urn}:ra-choice-race-{uuid.uuid4().hex}",
        ref_id="RA-CHOICE-RACE",
        type=Question.Type.UNIQUE_CHOICE,
        folder=world["root"],
    )
    target_question = Question.objects.create(
        requirement_node=world["leaf"],
        urn=f"{world['leaf'].urn}:ra-choice-target-{uuid.uuid4().hex}",
        ref_id="RA-CHOICE-TARGET",
        type=Question.Type.UNIQUE_CHOICE,
        folder=world["root"],
    )
    choice = QuestionChoice.objects.create(
        question=source_question,
        urn=f"{source_question.urn}:yes",
        ref_id="RA-CHOICE-RACE-YES",
        value="Yes",
        folder=world["root"],
    )
    auditor = User.objects.create_user(
        f"generic-ra-race-auditor-{uuid.uuid4().hex}@tests.local"
    )
    _grant_core_permissions(
        auditor,
        {
            "view_complianceassessment",
            "view_compliance_assessment_full",
            "view_requirementassessment",
            "change_requirementassessment",
            "view_answer",
            "add_answer",
            "change_answer",
        },
        world["enclave"],
    )
    _grant_core_permissions(
        auditor,
        {"view_requirementnode", "view_question", "view_questionchoice"},
        world["root"],
    )
    auditor_id = auditor.id
    choice_id = choice.id
    target_question_id = target_question.id
    target_ra_id = world["leaf_ra"].id
    writer_pid_queue: Queue[int] = Queue()
    patch_pid_queue: Queue[int] = Queue()
    reparent_is_uncommitted = Event()
    allow_writer_commit = Event()

    def choice_reparent_writer() -> None:
        with transaction.atomic():
            locked_choice = QuestionChoice.objects.select_for_update(of=("self",)).get(
                id=choice_id
            )
            locked_choice.question_id = target_question_id
            locked_choice.save(update_fields=["question"])
            reparent_is_uncommitted.set()
            if not allow_writer_commit.wait(_PG_THREAD_TIMEOUT_SECONDS):
                raise AssertionError("Timed out while holding the Choice reparent.")

    def ra_patch() -> tuple[int, bytes]:
        response = _client(User.objects.get(id=auditor_id)).patch(
            f"/api/requirement-assessments/{target_ra_id}/",
            {"answers": {source_question.urn: choice.urn}},
            format="json",
        )
        return response.status_code, bytes(response.content)

    with ThreadPoolExecutor(max_workers=2) as executor:
        writer_future: Future[None] = executor.submit(
            _run_on_fresh_pg_connection,
            "cfgrc-choice-reparent-writer",
            writer_pid_queue,
            choice_reparent_writer,
        )
        patch_future: Future[tuple[int, bytes]] | None = None
        try:
            writer_pid = writer_pid_queue.get(timeout=_PG_THREAD_TIMEOUT_SECONDS)
            assert reparent_is_uncommitted.wait(_PG_THREAD_TIMEOUT_SECONDS)
            patch_future = executor.submit(
                _run_on_fresh_pg_connection,
                "cfgrc-generic-ra-answer-patch",
                patch_pid_queue,
                ra_patch,
            )
            patch_pid = patch_pid_queue.get(timeout=_PG_THREAD_TIMEOUT_SECONDS)
            blocked_query = _wait_for_pg_block(
                blocked_pid=patch_pid,
                blocker_pid=writer_pid,
            )
            assert "core_questionchoice" in blocked_query.lower()
        finally:
            allow_writer_commit.set()

        writer_future.result(timeout=_PG_THREAD_TIMEOUT_SECONDS)
        assert patch_future is not None
        status_code, response_content = patch_future.result(
            timeout=_PG_THREAD_TIMEOUT_SECONDS
        )

    assert status_code in {400, 403, 404}, response_content
    choice.refresh_from_db()
    assert choice.question_id == target_question_id
    assert not Answer.objects.filter(
        requirement_assessment_id=target_ra_id,
        question_id=source_question.id,
    ).exists()


def test_parent_projection_does_not_follow_a_tampered_urn_outside_the_scope(
    requirement_assignment_world,
):
    world = requirement_assignment_world
    suffix = uuid.uuid4().hex
    outside_framework = Framework.objects.create(
        name="Outside assignment framework",
        urn=f"urn:intuitem:test:framework:outside-assignment-{suffix}",
        ref_id=f"OUTSIDE-{suffix[:8]}",
        folder=world["root"],
    )
    outside_parent = RequirementNode.objects.create(
        name="Outside assignment parent",
        urn=f"{outside_framework.urn}:parent",
        ref_id="OUTSIDE-PARENT",
        framework=outside_framework,
        folder=world["root"],
        assessable=False,
    )
    world["leaf"].parent_urn = outside_parent.urn
    world["leaf"].save(update_fields=["parent_urn"])

    response = _client(world["respondent"]).get(
        f"/api/requirement-assignments/{world['assignment'].id}/requirements_list/"
    )

    assert response.status_code == 200, response.content
    body = response.json()
    assert str(outside_parent.id) not in {node["id"] for node in body["requirements"]}
    leaf_node = next(
        node for node in body["requirements"] if node["id"] == str(world["leaf"].id)
    )
    leaf_row = next(
        row
        for row in body["requirement_assessments"]
        if row["id"] == str(world["leaf_ra"].id)
    )
    assert "parent_requirement" not in leaf_node
    assert leaf_row["requirement"]["parent_requirement"] is None


def test_assignment_answers_use_prospective_visibility_deny_cycles_and_reject_bool_as_number(
    requirement_assignment_world,
):
    world = requirement_assignment_world
    client = _client(world["respondent"])
    url = _assignment_update_url(world, world["leaf_ra"])

    hidden = client.patch(
        url,
        {"answers": {world["conditional"].urn: 7}},
        format="json",
    )
    assert hidden.status_code == 400, hidden.content

    bool_as_number = client.patch(
        url,
        {"answers": {world["number"].urn: True}},
        format="json",
    )
    assert bool_as_number.status_code == 400, bool_as_number.content

    cycle = client.patch(
        url,
        {
            "answers": {
                world["cycle_a"].urn: "go",
                world["cycle_b"].urn: "go",
            }
        },
        format="json",
    )
    assert cycle.status_code == 400, cycle.content

    allowed = client.patch(
        url,
        {
            "answers": {
                world["driver"].urn: True,
                world["conditional"].urn: 7,
            }
        },
        format="json",
    )
    assert allowed.status_code == 200, allowed.content

    answers = {
        answer.question_id: answer.value
        for answer in Answer.objects.filter(requirement_assessment=world["leaf_ra"])
    }
    assert answers[world["driver"].id] is True
    assert answers[world["conditional"].id] == 7
    assert answers[world["number"].id] is None
    assert answers[world["cycle_a"].id] is None
    assert answers[world["cycle_b"].id] is None


def test_malformed_dependencies_fail_closed_for_read_count_and_write(
    requirement_assignment_world,
):
    world = requirement_assignment_world
    client = _client(world["respondent"])
    list_response = client.get(
        f"/api/requirement-assignments/{world['assignment'].id}/requirements_list/"
    )
    assert list_response.status_code == 200, list_response.content
    body = list_response.json()
    leaf_row = next(
        row
        for row in body["requirement_assessments"]
        if row["id"] == str(world["leaf_ra"].id)
    )
    leaf_node = next(
        node for node in body["requirements"] if node["id"] == str(world["leaf"].id)
    )
    malformed_urns = {
        question.urn for question in world["malformed_dependency_questions"]
    }

    assert malformed_urns.isdisjoint(leaf_row["requirement"]["questions"])
    assert malformed_urns.isdisjoint(leaf_node["questions"])
    assert malformed_urns.isdisjoint(leaf_row["answers"])
    # Driver, strict number, and choice are the only initially visible
    # questions. The valid conditional, cycle, and five malformed dependency
    # declarations must not inflate either the row or assignment totals.
    assert leaf_row["visible_questions"] == 3
    assert leaf_row["answered_questions"] == 0
    assert body["total_visible_questions"] == 3
    assert body["total_answered_questions"] == 0

    update_url = _assignment_update_url(world, world["leaf_ra"])
    for question in world["malformed_dependency_questions"]:
        response = client.patch(
            update_url,
            {"answers": {question.urn: "must not be stored"}},
            format="json",
        )
        assert response.status_code == 400, (question.ref_id, response.content)

    assert not (
        Answer.objects.filter(
            requirement_assessment=world["leaf_ra"],
            question__in=world["malformed_dependency_questions"],
        )
        .exclude(value__isnull=True)
        .exists()
    )


def test_existing_answer_uses_its_own_folder_change_permission(
    requirement_assignment_world,
):
    world = requirement_assignment_world
    answer = Answer.objects.get(
        requirement_assessment=world["leaf_ra"], question=world["driver"]
    )
    answer.folder = world["hidden_enclave"]
    answer.save(update_fields=["folder"])
    _grant_view_only(world["respondent"], "answer", world["hidden_enclave"])

    response = _client(world["respondent"]).patch(
        _assignment_update_url(world, world["leaf_ra"]),
        {"answers": {world["driver"].urn: True}},
        format="json",
    )

    assert response.status_code == 403, response.content
    answer.refresh_from_db()
    assert answer.value is None


def test_evidence_links_preserve_hidden_existing_reject_visible_cross_enclave_and_lock_after_submit(
    requirement_assignment_world,
):
    world = requirement_assignment_world
    respondent = world["respondent"]
    leaf_ra = world["leaf_ra"]
    client = _client(respondent)
    url = _assignment_update_url(world, leaf_ra)

    hidden = Evidence.objects.create(
        name="Existing hidden assignment evidence", folder=world["hidden_enclave"]
    )
    evidence_a = Evidence.objects.create(
        name="Editable assignment evidence A", folder=world["enclave"]
    )
    evidence_b = Evidence.objects.create(
        name="Editable assignment evidence B", folder=world["enclave"]
    )
    leaf_ra.evidences.add(hidden, evidence_a, evidence_b)
    assert hidden.id not in set(
        RoleAssignment.get_viewable_object_ids(respondent, Evidence)
    )
    assert {evidence_a.id, evidence_b.id} <= set(
        RoleAssignment.get_viewable_object_ids(respondent, Evidence)
    )

    keep_visible_subset = client.patch(
        url,
        {"evidences": [str(evidence_a.id)]},
        format="json",
    )
    assert keep_visible_subset.status_code == 200, keep_visible_subset.content
    assert set(leaf_ra.evidences.values_list("id", flat=True)) == {
        hidden.id,
        evidence_a.id,
    }

    clear_visible_subset = client.patch(url, {"evidences": []}, format="json")
    assert clear_visible_subset.status_code == 200, clear_visible_subset.content
    assert set(leaf_ra.evidences.values_list("id", flat=True)) == {hidden.id}

    cross_enclave = Evidence.objects.create(
        name="Visible but out-of-enclave evidence", folder=world["cross_enclave"]
    )
    _grant_view_only(respondent, "evidence", world["cross_enclave"])
    assert cross_enclave.id in set(
        RoleAssignment.get_viewable_object_ids(respondent, Evidence)
    )

    cross_link = client.patch(
        url, {"evidences": [str(cross_enclave.id)]}, format="json"
    )
    assert cross_link.status_code == 403, cross_link.content
    assert set(leaf_ra.evidences.values_list("id", flat=True)) == {hidden.id}

    # A pre-existing, independently visible cross-enclave relation is
    # immutable through this capability: round-tripping it is accepted, while
    # omitting it cannot remove it.
    leaf_ra.evidences.add(cross_enclave)
    round_trip_cross = client.patch(
        url, {"evidences": [str(cross_enclave.id)]}, format="json"
    )
    assert round_trip_cross.status_code == 200, round_trip_cross.content
    assert set(leaf_ra.evidences.values_list("id", flat=True)) == {
        hidden.id,
        cross_enclave.id,
    }
    omit_cross = client.patch(url, {"evidences": []}, format="json")
    assert omit_cross.status_code == 200, omit_cross.content
    assert set(leaf_ra.evidences.values_list("id", flat=True)) == {
        hidden.id,
        cross_enclave.id,
    }

    world["assignment"].status = RequirementAssignment.Status.SUBMITTED
    world["assignment"].save(update_fields=["status"])
    submitted = client.patch(url, {"evidences": []}, format="json")
    assert submitted.status_code == 403, submitted.content
    assert set(leaf_ra.evidences.values_list("id", flat=True)) == {
        hidden.id,
        cross_enclave.id,
    }


def _prepare_control_sync_auditor(world: dict) -> tuple[User, APIClient]:
    """Grant only the authority used by control suggestions and result sync."""

    auditor = User.objects.create_user(
        f"control-sync-auditor-{uuid.uuid4().hex}@tests.local"
    )
    _grant_core_permissions(
        auditor,
        {
            "view_complianceassessment",
            "view_compliance_assessment_full",
            "view_framework",
            "view_requirementnode",
            "view_requirementassessment",
            "change_requirementassessment",
            "view_referencecontrol",
            "view_appliedcontrol",
            "add_appliedcontrol",
        },
        world["root"],
    )
    visibility = dict(world["ca"].field_visibility or {})
    for field_name in ("applied_controls", "result", "extended_result"):
        visibility[field_name] = {"auditor": "edit", "respondent": "hidden"}
    world["ca"].field_visibility = visibility
    world["ca"].save(update_fields=["field_visibility"])
    return auditor, _client(auditor)


def _control_suggestion_reference(world: dict, label: str) -> ReferenceControl:
    suffix = uuid.uuid4().hex
    reference = ReferenceControl.objects.create(
        name=f"{label} control suggestion",
        ref_id=f"{label.upper()}-{suffix[:8]}",
        urn=f"urn:test:control-suggestion:{label}:{suffix}",
        category="technical",
        folder=world["root"],
    )
    world["leaf"].reference_controls.add(reference)
    return reference


def _control_mutation_urls(world: dict) -> tuple[str, str, str]:
    return (
        f"/api/compliance-assessments/{world['ca'].id}/syncToActions/?dry_run=false",
        f"/api/compliance-assessments/{world['ca'].id}/suggestions/applied-controls/?dry_run=false",
        f"/api/requirement-assessments/{world['leaf_ra'].id}/suggestions/applied-controls/?dry_run=false",
    )


def test_sync_to_actions_get_is_always_read_only_even_when_query_requests_write(
    requirement_assignment_world,
):
    world = requirement_assignment_world
    _auditor, client = _prepare_control_sync_auditor(world)
    control = AppliedControl.objects.create(
        name="Active control for read-only sync preview",
        status=AppliedControl.Status.ACTIVE,
        folder=world["enclave"],
    )
    world["leaf_ra"].applied_controls.add(control)
    world["leaf_ra"].result = RequirementAssessment.Result.NON_COMPLIANT
    world["leaf_ra"].save(update_fields=["result"])
    world["ca"].refresh_from_db()
    original_updated_at = world["ca"].updated_at

    response = client.get(
        f"/api/compliance-assessments/{world['ca'].id}/syncToActions/?dry_run=false"
    )

    assert response.status_code == 200, response.content
    assert response.json()["changes"][str(world["leaf_ra"].id)]["changes"] == [
        {
            "current": RequirementAssessment.Result.NON_COMPLIANT,
            "new": RequirementAssessment.Result.COMPLIANT,
        }
    ]
    world["leaf_ra"].refresh_from_db()
    world["ca"].refresh_from_db()
    assert world["leaf_ra"].result == RequirementAssessment.Result.NON_COMPLIANT
    assert world["ca"].updated_at == original_updated_at
    assert set(world["leaf_ra"].applied_controls.values_list("id", flat=True)) == {
        control.id
    }


@pytest.mark.parametrize("assessment_state", ["locked", "in_review"])
def test_control_sync_and_both_suggestion_writes_atomically_reject_frozen_audit(
    requirement_assignment_world,
    assessment_state,
):
    world = requirement_assignment_world
    _auditor, client = _prepare_control_sync_auditor(world)
    reference = _control_suggestion_reference(world, assessment_state)
    existing_control = AppliedControl.objects.create(
        name=f"Frozen {assessment_state} sync control",
        status=AppliedControl.Status.ACTIVE,
        folder=world["enclave"],
    )
    world["leaf_ra"].applied_controls.add(existing_control)
    world["leaf_ra"].result = RequirementAssessment.Result.NON_COMPLIANT
    world["leaf_ra"].save(update_fields=["result"])
    if assessment_state == "locked":
        world["ca"].is_locked = True
        world["ca"].save(update_fields=["is_locked"])
    else:
        world["ca"].status = ComplianceAssessment.Status.IN_REVIEW
        world["ca"].save(update_fields=["status"])
    initial_control_ids = set(AppliedControl.objects.values_list("id", flat=True))
    initial_link_ids = set(
        world["leaf_ra"].applied_controls.values_list("id", flat=True)
    )

    sync_url, assessment_suggestions_url, requirement_suggestions_url = (
        _control_mutation_urls(world)
    )
    for url in (
        sync_url,
        assessment_suggestions_url,
        requirement_suggestions_url,
    ):
        response = client.post(
            url,
            {"selected_reference_control_ids": [str(reference.id)]},
            format="json",
        )
        assert response.status_code == 403, (url, response.content)

    world["leaf_ra"].refresh_from_db()
    assert world["leaf_ra"].result == RequirementAssessment.Result.NON_COMPLIANT
    assert set(AppliedControl.objects.values_list("id", flat=True)) == (
        initial_control_ids
    )
    assert set(world["leaf_ra"].applied_controls.values_list("id", flat=True)) == (
        initial_link_ids
    )


def test_control_sync_and_both_suggestion_writes_atomically_reject_folder_drift(
    requirement_assignment_world,
):
    world = requirement_assignment_world
    _auditor, client = _prepare_control_sync_auditor(world)
    reference = _control_suggestion_reference(world, "folder-drift")
    existing_control = AppliedControl.objects.create(
        name="Folder-drift sync control",
        status=AppliedControl.Status.ACTIVE,
        folder=world["enclave"],
    )
    world["leaf_ra"].applied_controls.add(existing_control)
    world["leaf_ra"].result = RequirementAssessment.Result.NON_COMPLIANT
    world["leaf_ra"].folder = world["hidden_enclave"]
    world["leaf_ra"].save(update_fields=["folder", "result"])
    initial_control_ids = set(AppliedControl.objects.values_list("id", flat=True))
    initial_link_ids = set(
        world["leaf_ra"].applied_controls.values_list("id", flat=True)
    )

    sync_url, assessment_suggestions_url, requirement_suggestions_url = (
        _control_mutation_urls(world)
    )
    for url in (
        sync_url,
        assessment_suggestions_url,
        requirement_suggestions_url,
    ):
        response = client.post(
            url,
            {"selected_reference_control_ids": [str(reference.id)]},
            format="json",
        )
        assert response.status_code == 403, (url, response.content)

    world["leaf_ra"].refresh_from_db()
    assert world["leaf_ra"].result == RequirementAssessment.Result.NON_COMPLIANT
    assert world["leaf_ra"].folder_id == world["hidden_enclave"].id
    assert set(AppliedControl.objects.values_list("id", flat=True)) == (
        initial_control_ids
    )
    assert set(world["leaf_ra"].applied_controls.values_list("id", flat=True)) == (
        initial_link_ids
    )


def test_control_suggestions_and_sync_succeed_with_exact_auditor_authority(
    requirement_assignment_world,
    monkeypatch,
):
    from core import views as core_views

    world = requirement_assignment_world
    _auditor, client = _prepare_control_sync_auditor(world)
    assessment_reference = _control_suggestion_reference(world, "assessment")
    requirement_reference = _control_suggestion_reference(world, "requirement")
    sync_url, assessment_suggestions_url, requirement_suggestions_url = (
        _control_mutation_urls(world)
    )
    expected_requirement_assessment_ids = set(
        world["ca"].requirement_assessments.values_list("id", flat=True)
    )
    folder_lock_calls = 0
    relation_lock_calls: list[dict] = []
    original_folder_lock = Folder._lock_folder_tree
    original_relation_lock = core_views.lock_requirement_assessment_relation_scope

    def observe_folder_lock() -> None:
        nonlocal folder_lock_calls
        folder_lock_calls += 1
        original_folder_lock()

    def observe_relation_lock(**kwargs):
        relation_lock_calls.append(kwargs.copy())
        return original_relation_lock(**kwargs)

    monkeypatch.setattr(Folder, "_lock_folder_tree", staticmethod(observe_folder_lock))
    monkeypatch.setattr(
        core_views,
        "lock_requirement_assessment_relation_scope",
        observe_relation_lock,
    )

    assessment_response = client.post(
        assessment_suggestions_url,
        {"selected_reference_control_ids": [str(assessment_reference.id)]},
        format="json",
    )
    requirement_response = client.post(
        requirement_suggestions_url,
        {"selected_reference_control_ids": [str(requirement_reference.id)]},
        format="json",
    )

    assert assessment_response.status_code == 200, assessment_response.content
    assert requirement_response.status_code == 200, requirement_response.content
    linked_controls = list(
        world["leaf_ra"].applied_controls.select_related("reference_control")
    )
    assert {control.reference_control_id for control in linked_controls} == {
        assessment_reference.id,
        requirement_reference.id,
    }
    AppliedControl.objects.filter(
        id__in=[control.id for control in linked_controls]
    ).update(status=AppliedControl.Status.ACTIVE)

    sync_response = client.post(sync_url, {}, format="json")

    assert sync_response.status_code == 200, sync_response.content
    assert set(sync_response.json()["changes"]) == {str(world["leaf_ra"].id)}
    world["leaf_ra"].refresh_from_db()
    assert world["leaf_ra"].result == RequirementAssessment.Result.COMPLIANT
    assert folder_lock_calls == 3
    assert [call["relation_field"] for call in relation_lock_calls] == [
        "applied_controls",
        None,
    ]
    for call in relation_lock_calls:
        assert set(call["requirement_assessment_ids"]) == (
            expected_requirement_assessment_ids
        )
        assert call["object_folder_id"] == world["ca"].folder_id
        assert call["allow_respondent"] is False
        assert call.get("enforce_assessment_editable", True) is True
