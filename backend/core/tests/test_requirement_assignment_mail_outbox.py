"""Adversarial tests for the requirement-assignment mail outbox."""

from __future__ import annotations

from datetime import timedelta
import hashlib
import json
import uuid

import pytest
from django.contrib.auth.models import Permission
from django.contrib.contenttypes.models import ContentType
from django.db import connection
from django.utils import timezone
from structlog.testing import capture_logs

from core.assignment_mailing import build_assignment_mail_payload_digest
from core.models import (
    Actor,
    RequirementAssignment,
    RequirementAssignmentEvent,
    RequirementAssignmentMailOutbox,
    Team,
)
from core.tasks import (
    deliver_requirement_assignment_mail,
    sweep_requirement_assignment_mail_outbox,
)
from core.tests.test_compliance_assessment_tree_iam import (
    _client,
    _grant,
    audit_iam_world as _audit_iam_world_fixture,
)
from iam.models import Folder, Role, RoleAssignment, User


pytestmark = pytest.mark.django_db
audit_iam_world = _audit_iam_world_fixture


def _make_author(prefix: str, folder: Folder) -> tuple[User, Actor]:
    user = User.objects.create_user(f"{prefix}-{uuid.uuid4().hex}@mail-outbox.tests")
    user.folder = folder
    user.save(update_fields=["folder"])
    actor, _ = Actor.objects.get_or_create(user=user)
    return user, actor


@pytest.fixture
def mailing_world(audit_iam_world, settings):
    world = audit_iam_world
    settings.EMAIL_HOST = "smtp.mail-outbox.tests"
    settings.EMAIL_HOST_RESCUE = None

    author, author_actor = _make_author("author", world["child_folder"])
    world["target"].authors.set([author_actor])
    world["assignment"].actor.set([author_actor])
    world["assignment"].status = RequirementAssignment.Status.DRAFT
    world["assignment"].save(update_fields=["status"])

    _grant(
        world["auditor"],
        f"Mail outbox authority {uuid.uuid4().hex}",
        {"transition_requirementassignment", "view_user"},
        world["child_folder"],
    )
    return {
        **world,
        "author": author,
        "author_actor": author_actor,
    }


def _mail_url(world: dict) -> str:
    return f"/api/compliance-assessments/{world['target'].id}/mailing/"


def _queue(world, monkeypatch, django_capture_on_commit_callbacks):
    enqueued: list[list[uuid.UUID]] = []
    monkeypatch.setattr(
        "core.assignment_mailing.enqueue_requirement_assignment_mail_jobs",
        lambda ids: enqueued.append(list(ids)),
    )
    with django_capture_on_commit_callbacks(execute=True):
        response = _client(world["auditor"]).post(_mail_url(world), {}, format="json")
    return response, enqueued


def test_post_commits_transition_and_outbox_but_never_sends_smtp_in_request(
    mailing_world, monkeypatch, django_capture_on_commit_callbacks
):
    monkeypatch.setattr(
        User,
        "mailing",
        lambda *args, **kwargs: pytest.fail("SMTP ran inside the request"),
    )

    response, enqueued = _queue(
        mailing_world, monkeypatch, django_capture_on_commit_callbacks
    )

    assert response.status_code == 200, response.content
    assert response.json() == {
        "results": "queued",
        "queued": 1,
        "assignments_started": 1,
    }
    mailing_world["assignment"].refresh_from_db()
    assert (
        mailing_world["assignment"].status == RequirementAssignment.Status.IN_PROGRESS
    )
    event = RequirementAssignmentEvent.objects.get(
        assignment=mailing_world["assignment"]
    )
    assert event.event_type == RequirementAssignment.Status.IN_PROGRESS
    assert event.event_actor == mailing_world["auditor"]
    outbox = RequirementAssignmentMailOutbox.objects.get()
    assert outbox.status == RequirementAssignmentMailOutbox.Status.QUEUED
    assert outbox.payload_digest and len(outbox.payload_digest) == 64
    assert outbox.recipient_address_hash and len(outbox.recipient_address_hash) == 64
    assert mailing_world["author"].email not in outbox.recipient_address_hash
    assert enqueued == [[outbox.id]]


def test_repeat_post_does_not_queue_or_transition_twice(
    mailing_world, monkeypatch, django_capture_on_commit_callbacks
):
    first, enqueued = _queue(
        mailing_world, monkeypatch, django_capture_on_commit_callbacks
    )
    assert first.status_code == 200, first.content

    second, second_enqueued = _queue(
        mailing_world, monkeypatch, django_capture_on_commit_callbacks
    )

    assert second.status_code == 200, second.content
    assert second.json() == {
        "results": "queued",
        "queued": 0,
        "assignments_started": 0,
    }
    assert RequirementAssignmentMailOutbox.objects.count() == 1
    assert (
        RequirementAssignmentEvent.objects.filter(
            assignment=mailing_world["assignment"],
            event_type=RequirementAssignment.Status.IN_PROGRESS,
        ).count()
        == 1
    )
    assert len(enqueued[0]) == 1
    assert second_enqueued == []


def test_two_author_delivery_failures_are_independent_of_committed_transition(
    mailing_world, monkeypatch, django_capture_on_commit_callbacks
):
    second_author, second_actor = _make_author(
        "second-author", mailing_world["child_folder"]
    )
    mailing_world["target"].authors.add(second_actor)
    mailing_world["assignment"].actor.add(second_actor)
    response, _ = _queue(mailing_world, monkeypatch, django_capture_on_commit_callbacks)
    assert response.status_code == 200, response.content
    assert response.json()["queued"] == 2

    calls = []

    def deliver(self, *args, **kwargs):
        calls.append(self.id)
        if self.id == mailing_world["author"].id:
            raise RuntimeError("synthetic SMTP failure containing private details")
        return True

    monkeypatch.setattr(User, "mailing", deliver)
    outboxes = list(
        RequirementAssignmentMailOutbox.objects.order_by("recipient_actor_id")
    )
    results = [
        deliver_requirement_assignment_mail.call_local(str(outbox.id))
        for outbox in outboxes
    ]

    assert sorted(results) == ["delivered", "failed"]
    mailing_world["assignment"].refresh_from_db()
    assert (
        mailing_world["assignment"].status == RequirementAssignment.Status.IN_PROGRESS
    )
    assert (
        RequirementAssignmentEvent.objects.filter(
            assignment=mailing_world["assignment"],
            event_type=RequirementAssignment.Status.IN_PROGRESS,
        ).count()
        == 1
    )
    statuses = set(
        RequirementAssignmentMailOutbox.objects.values_list("status", flat=True)
    )
    assert statuses == {
        RequirementAssignmentMailOutbox.Status.DELIVERED,
        RequirementAssignmentMailOutbox.Status.FAILED,
    }
    failed = RequirementAssignmentMailOutbox.objects.get(
        status=RequirementAssignmentMailOutbox.Status.FAILED
    )
    assert failed.failure_code == "delivery_error"
    assert calls == [outbox.recipient_actor.user_id for outbox in outboxes]
    assert second_author.id in calls


def test_duplicate_worker_delivery_is_noop(
    mailing_world, monkeypatch, django_capture_on_commit_callbacks
):
    response, _ = _queue(mailing_world, monkeypatch, django_capture_on_commit_callbacks)
    assert response.status_code == 200, response.content
    outbox = RequirementAssignmentMailOutbox.objects.get()
    calls = []
    monkeypatch.setattr(
        User,
        "mailing",
        lambda self, *args, **kwargs: calls.append(self.id) or True,
    )

    assert deliver_requirement_assignment_mail.call_local(str(outbox.id)) == "delivered"
    assert deliver_requirement_assignment_mail.call_local(str(outbox.id)) == "noop"
    outbox.refresh_from_db()
    assert outbox.status == RequirementAssignmentMailOutbox.Status.DELIVERED
    assert outbox.attempts == 1
    assert calls == [mailing_world["author"].id]


def test_smtp_boundary_runs_inside_the_exact_recipient_lock_transaction(
    mailing_world, monkeypatch, django_capture_on_commit_callbacks
):
    response, _ = _queue(mailing_world, monkeypatch, django_capture_on_commit_callbacks)
    assert response.status_code == 200, response.content
    outbox = RequirementAssignmentMailOutbox.objects.get()
    baseline_atomic_depth = len(connection.atomic_blocks)
    observed = []

    def deliver(self, *args, **kwargs):
        observed.append((len(connection.atomic_blocks), self.id, self.email))
        return True

    monkeypatch.setattr(User, "mailing", deliver)

    assert deliver_requirement_assignment_mail.call_local(str(outbox.id)) == "delivered"
    assert observed == [
        (
            baseline_atomic_depth + 1,
            mailing_world["author"].id,
            mailing_world["author"].email.strip().casefold(),
        )
    ]


@pytest.mark.parametrize(
    ("concurrent_change", "expected_failure"),
    [
        ("assignment_status", "assignment_not_active"),
        ("assessment_author", "recipient_not_authorized"),
        ("assignment_actor", "recipient_not_authorized"),
        ("actor_subtype", "recipient_changed"),
        ("user_email", "recipient_changed"),
    ],
)
def test_worker_reproves_recipient_graph_immediately_before_smtp(
    mailing_world,
    monkeypatch,
    django_capture_on_commit_callbacks,
    concurrent_change,
    expected_failure,
):
    response, _ = _queue(mailing_world, monkeypatch, django_capture_on_commit_callbacks)
    assert response.status_code == 200, response.content
    outbox = RequirementAssignmentMailOutbox.objects.get()

    replacement_team = None
    if concurrent_change == "actor_subtype":
        replacement_team = Team.objects.create(
            name=f"Replacement team {uuid.uuid4().hex}",
            folder=mailing_world["child_folder"],
        )
        replacement_team.actor.delete()

    from core import assignment_mailing

    original_normalize = assignment_mailing._normalize_recipient
    mutation_ran = False

    def normalize_then_change_authority(actor):
        nonlocal mutation_ran
        recipient = original_normalize(actor)
        if mutation_ran:
            return recipient
        mutation_ran = True
        if concurrent_change == "assignment_status":
            RequirementAssignment.objects.filter(
                id=mailing_world["assignment"].id
            ).update(status=RequirementAssignment.Status.CLOSED)
        elif concurrent_change == "assessment_author":
            mailing_world["target"].authors.through.objects.filter(
                complianceassessment_id=mailing_world["target"].id,
                actor_id=mailing_world["author_actor"].id,
            ).delete()
        elif concurrent_change == "assignment_actor":
            mailing_world["assignment"].actor.through.objects.filter(
                requirementassignment_id=mailing_world["assignment"].id,
                actor_id=mailing_world["author_actor"].id,
            ).delete()
        elif concurrent_change == "actor_subtype":
            Actor.objects.filter(id=mailing_world["author_actor"].id).update(
                user_id=None,
                team_id=replacement_team.id,
            )
        else:
            User.objects.filter(id=mailing_world["author"].id).update(
                email=f"changed-{uuid.uuid4().hex}@mail-outbox.tests"
            )
        return recipient

    smtp_calls = []
    monkeypatch.setattr(
        assignment_mailing,
        "_normalize_recipient",
        normalize_then_change_authority,
    )
    monkeypatch.setattr(
        User,
        "mailing",
        lambda self, *args, **kwargs: smtp_calls.append(self.email) or True,
    )

    assert deliver_requirement_assignment_mail.call_local(str(outbox.id)) == "failed"
    outbox.refresh_from_db()
    assert mutation_ran is True
    assert smtp_calls == []
    assert outbox.status == RequirementAssignmentMailOutbox.Status.FAILED
    assert outbox.failure_code == expected_failure


def test_ambiguous_smtp_failure_is_terminal_and_never_swept_for_retry(
    mailing_world, monkeypatch, django_capture_on_commit_callbacks
):
    response, _ = _queue(mailing_world, monkeypatch, django_capture_on_commit_callbacks)
    assert response.status_code == 200, response.content
    outbox = RequirementAssignmentMailOutbox.objects.get()
    smtp_calls = []

    def ambiguous_failure(self, *args, **kwargs):
        smtp_calls.append(self.id)
        raise RuntimeError("SMTP acceptance outcome is unknown")

    monkeypatch.setattr(User, "mailing", ambiguous_failure)
    assert deliver_requirement_assignment_mail.call_local(str(outbox.id)) == "failed"
    assert deliver_requirement_assignment_mail.call_local(str(outbox.id)) == "noop"

    swept = []
    monkeypatch.setattr(
        "core.tasks.deliver_requirement_assignment_mail",
        lambda outbox_id: swept.append(outbox_id),
    )
    assert sweep_requirement_assignment_mail_outbox.call_local() == 0
    outbox.refresh_from_db()
    assert smtp_calls == [mailing_world["author"].id]
    assert swept == []
    assert outbox.status == RequirementAssignmentMailOutbox.Status.FAILED
    assert outbox.failure_code == "delivery_error"


@pytest.mark.parametrize("primary_outcome", ["exception", "rejected"])
def test_worker_never_falls_back_to_rescue_after_primary_smtp_failure(
    mailing_world,
    monkeypatch,
    django_capture_on_commit_callbacks,
    settings,
    primary_outcome,
):
    response, _ = _queue(mailing_world, monkeypatch, django_capture_on_commit_callbacks)
    assert response.status_code == 200, response.content
    outbox = RequirementAssignmentMailOutbox.objects.get()
    settings.EMAIL_HOST_RESCUE = "rescue.mail-outbox.tests"
    connection_attempts = []

    class PrimaryConnection:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc_value, traceback):
            return False

        def send_messages(self, messages):
            assert len(messages) == 1
            if primary_outcome == "exception":
                raise RuntimeError("SMTP acceptance outcome is unknown")
            return 0

    def get_connection_once(**kwargs):
        connection_attempts.append(kwargs)
        return PrimaryConnection()

    monkeypatch.setattr(
        "core.email_utils.render_email_template",
        lambda *args, **kwargs: {
            "subject": "Assignment",
            "body": "Assignment body",
            "html_body": "<p>Assignment body</p>",
        },
    )
    monkeypatch.setattr("iam.models.get_connection", get_connection_once)

    assert deliver_requirement_assignment_mail.call_local(str(outbox.id)) == "failed"
    outbox.refresh_from_db()
    assert len(connection_attempts) == 1
    assert "host" not in connection_attempts[0]
    assert outbox.status == RequirementAssignmentMailOutbox.Status.FAILED
    assert outbox.failure_code == "delivery_error"


def test_worker_redacts_recipient_and_transport_details_from_logs(
    mailing_world,
    monkeypatch,
    django_capture_on_commit_callbacks,
    settings,
):
    response, _ = _queue(mailing_world, monkeypatch, django_capture_on_commit_callbacks)
    assert response.status_code == 200, response.content
    outbox = RequirementAssignmentMailOutbox.objects.get()

    private_subject = "Private customer assignment subject"
    private_error = "SMTP failure containing private customer details"
    private_host = "private-smtp.mail-outbox.tests"
    private_user = "private-smtp-user"
    settings.EMAIL_HOST = private_host
    settings.EMAIL_HOST_USER = private_user

    class RejectingConnection:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc_value, traceback):
            return False

        def send_messages(self, messages):
            raise RuntimeError(private_error)

    monkeypatch.setattr(
        "core.email_utils.is_email_template_enabled", lambda template_key: True
    )
    monkeypatch.setattr(
        "core.email_utils.render_email_template",
        lambda *args, **kwargs: {
            "subject": private_subject,
            "body": "Private assignment body",
            "html_body": None,
        },
    )
    monkeypatch.setattr(
        "iam.models.get_connection", lambda **kwargs: RejectingConnection()
    )

    with capture_logs() as logs:
        result = deliver_requirement_assignment_mail.call_local(str(outbox.id))

    assert result == "failed"
    serialized_logs = json.dumps(logs, default=str)
    for private_value in (
        mailing_world["author"].email,
        private_subject,
        private_error,
        private_host,
        private_user,
    ):
        assert private_value not in serialized_logs

    primary_failure = next(
        item for item in logs if item.get("event") == "Primary mail server failure"
    )
    assert primary_failure["template_key"] == "questionnaire_assignment"
    assert primary_failure["backend_stage"] == "primary"
    assert primary_failure["error_type"] == "RuntimeError"
    assert (
        not {
            "recipient",
            "subject",
            "error",
            "email_host_user",
        }
        & primary_failure.keys()
    )

    outbox_failure = next(
        item
        for item in logs
        if item.get("event") == "requirement_assignment_mail_delivery_failed"
    )
    assert outbox_failure["failure_code"] == "delivery_error"
    assert outbox_failure["error_type"] == "RuntimeError"


def test_yaml_render_failure_still_uses_legacy_template_once(
    mailing_world, monkeypatch
):
    sent_messages = []

    def fail_render(*args, **kwargs):
        raise RuntimeError("synthetic render failure")

    class AcceptingConnection:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc_value, traceback):
            return False

        def send_messages(self, messages):
            sent_messages.extend(messages)
            return len(messages)

    monkeypatch.setattr(
        "core.email_utils.render_email_template",
        fail_render,
    )
    monkeypatch.setattr(
        "iam.models.render_to_string",
        lambda *args, **kwargs: "Legacy assignment body",
    )
    monkeypatch.setattr(
        "iam.models.get_connection", lambda **kwargs: AcceptingConnection()
    )

    delivered = mailing_world["author"].mailing(
        "tprm/third_party_email.html",
        "Assignment",
        allow_rescue=False,
    )

    assert delivered is True
    assert len(sent_messages) == 1
    assert sent_messages[0].to == [mailing_world["author"].email]
    assert sent_messages[0].body == "Legacy assignment body"


def test_user_mailing_keeps_rescue_fallback_enabled_by_default(
    mailing_world, monkeypatch, settings
):
    settings.EMAIL_HOST_RESCUE = "rescue.mail-outbox.tests"
    smtp_attempts = []

    class Connection:
        def __init__(self, transport):
            self.transport = transport

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc_value, traceback):
            return False

        def send_messages(self, messages):
            smtp_attempts.append(self.transport)
            if self.transport == "primary":
                raise RuntimeError("primary unavailable")
            return len(messages)

    def connection_factory(**kwargs):
        transport = (
            "rescue" if kwargs.get("host") == settings.EMAIL_HOST_RESCUE else "primary"
        )
        return Connection(transport)

    monkeypatch.setattr(
        "core.email_utils.render_email_template",
        lambda *args, **kwargs: {
            "subject": "Assignment",
            "body": "Assignment body",
            "html_body": None,
        },
    )
    monkeypatch.setattr("iam.models.get_connection", connection_factory)

    assert (
        mailing_world["author"].mailing(
            "tprm/third_party_email.html",
            "Assignment",
        )
        is True
    )
    assert smtp_attempts == ["primary", "rescue"]


def test_disabled_template_is_recorded_as_failed_not_delivered(
    mailing_world, monkeypatch, django_capture_on_commit_callbacks
):
    response, _ = _queue(mailing_world, monkeypatch, django_capture_on_commit_callbacks)
    assert response.status_code == 200, response.content
    outbox = RequirementAssignmentMailOutbox.objects.get()
    monkeypatch.setattr(User, "mailing", lambda *args, **kwargs: False)

    assert deliver_requirement_assignment_mail.call_local(str(outbox.id)) == "failed"
    outbox.refresh_from_db()
    assert outbox.status == RequirementAssignmentMailOutbox.Status.FAILED
    assert outbox.delivered_at is None
    assert outbox.failure_code == "delivery_not_confirmed"


def test_worker_rejects_a_delivery_intent_after_assignment_is_closed(
    mailing_world, monkeypatch, django_capture_on_commit_callbacks
):
    response, _ = _queue(mailing_world, monkeypatch, django_capture_on_commit_callbacks)
    assert response.status_code == 200, response.content
    outbox = RequirementAssignmentMailOutbox.objects.get()
    mailing_world["assignment"].status = RequirementAssignment.Status.CLOSED
    mailing_world["assignment"].save(update_fields=["status"])
    monkeypatch.setattr(
        User,
        "mailing",
        lambda *args, **kwargs: pytest.fail("closed assignment was delivered"),
    )

    assert deliver_requirement_assignment_mail.call_local(str(outbox.id)) == "failed"
    outbox.refresh_from_db()
    assert outbox.status == RequirementAssignmentMailOutbox.Status.FAILED
    assert outbox.failure_code == "assignment_not_active"


def test_missing_exact_transition_permission_fails_closed_even_with_duplicate_codename(
    mailing_world, monkeypatch
):
    exact = Permission.objects.get(
        content_type__app_label="core",
        content_type__model="requirementassignment",
        codename="transition_requirementassignment",
    )
    for role_assignment in RoleAssignment.objects.filter(user=mailing_world["auditor"]):
        role_assignment.role.permissions.remove(exact)

    content_type = ContentType.objects.create(
        app_label="mail_outbox_test", model="requirementassignment"
    )
    duplicate = Permission.objects.create(
        content_type=content_type,
        codename="transition_requirementassignment",
        name="Test-only duplicate transition permission",
    )
    role = Role.objects.create(
        name=f"Duplicate transition {uuid.uuid4().hex}",
        folder=Folder.get_root_folder(),
    )
    role.permissions.add(duplicate)
    role_assignment = RoleAssignment.objects.create(
        user=mailing_world["auditor"],
        role=role,
        folder=Folder.get_root_folder(),
        is_recursive=True,
    )
    role_assignment.perimeter_folders.add(mailing_world["child_folder"])
    monkeypatch.setattr(
        "core.assignment_mailing.enqueue_requirement_assignment_mail_jobs",
        lambda ids: pytest.fail("unauthorized row was enqueued"),
    )

    response = _client(mailing_world["auditor"]).post(
        _mail_url(mailing_world), {}, format="json"
    )

    assert response.status_code == 403, response.content
    mailing_world["assignment"].refresh_from_db()
    assert mailing_world["assignment"].status == RequirementAssignment.Status.DRAFT
    assert not RequirementAssignmentMailOutbox.objects.exists()
    assert not RequirementAssignmentEvent.objects.filter(
        assignment=mailing_world["assignment"]
    ).exists()


def test_locked_path_reproves_full_view_before_any_write(mailing_world, monkeypatch):
    monkeypatch.setattr(
        "core.assignment_mailing.has_full_view_compliance_assessment",
        lambda user, assessment: False,
    )

    response = _client(mailing_world["auditor"]).post(
        _mail_url(mailing_world), {}, format="json"
    )

    assert response.status_code == 403, response.content
    mailing_world["assignment"].refresh_from_db()
    assert mailing_world["assignment"].status == RequirementAssignment.Status.DRAFT
    assert not RequirementAssignmentMailOutbox.objects.exists()
    assert not RequirementAssignmentEvent.objects.filter(
        assignment=mailing_world["assignment"]
    ).exists()


def test_periodic_sweeper_only_requeues_due_queued_rows(
    mailing_world, monkeypatch, django_capture_on_commit_callbacks
):
    response, _ = _queue(mailing_world, monkeypatch, django_capture_on_commit_callbacks)
    assert response.status_code == 200, response.content
    queued = RequirementAssignmentMailOutbox.objects.get()

    other_assignment = RequirementAssignment.objects.create(
        compliance_assessment=mailing_world["target"],
        folder=mailing_world["child_folder"],
        status=RequirementAssignment.Status.IN_PROGRESS,
    )
    other_assignment.actor.add(mailing_world["author_actor"])
    delivered = RequirementAssignmentMailOutbox.objects.create(
        assignment=other_assignment,
        recipient_actor=mailing_world["author_actor"],
        requested_by=mailing_world["auditor"],
        folder=mailing_world["child_folder"],
        payload_digest="f" * 64,
        recipient_address_hash="e" * 64,
        status=RequirementAssignmentMailOutbox.Status.DELIVERED,
    )
    enqueued = []
    monkeypatch.setattr(
        "core.tasks.deliver_requirement_assignment_mail",
        lambda outbox_id: enqueued.append(outbox_id),
    )

    assert sweep_requirement_assignment_mail_outbox.call_local() == 1
    assert enqueued == [str(queued.id)]
    assert str(delivered.id) not in enqueued


def test_periodic_sweeper_fails_stale_claim_without_automatic_redelivery(
    mailing_world, monkeypatch, django_capture_on_commit_callbacks
):
    response, _ = _queue(mailing_world, monkeypatch, django_capture_on_commit_callbacks)
    assert response.status_code == 200, response.content
    outbox = RequirementAssignmentMailOutbox.objects.get()
    RequirementAssignmentMailOutbox.objects.filter(id=outbox.id).update(
        status=RequirementAssignmentMailOutbox.Status.SENDING,
        claimed_at=timezone.now() - timedelta(minutes=16),
        attempts=1,
    )
    enqueued = []
    monkeypatch.setattr(
        "core.tasks.deliver_requirement_assignment_mail",
        lambda outbox_id: enqueued.append(outbox_id),
    )

    assert sweep_requirement_assignment_mail_outbox.call_local() == 0
    outbox.refresh_from_db()
    assert outbox.status == RequirementAssignmentMailOutbox.Status.FAILED
    assert outbox.failure_code == "claim_timeout"
    assert outbox.failed_at is not None
    assert enqueued == []


def test_any_draft_without_deliverable_author_fails_the_whole_request(
    mailing_world, monkeypatch
):
    undeliverable = RequirementAssignment.objects.create(
        compliance_assessment=mailing_world["target"],
        folder=mailing_world["child_folder"],
        status=RequirementAssignment.Status.DRAFT,
    )
    monkeypatch.setattr(
        "core.assignment_mailing.enqueue_requirement_assignment_mail_jobs",
        lambda ids: pytest.fail("partial request was enqueued"),
    )

    response = _client(mailing_world["auditor"]).post(
        _mail_url(mailing_world), {}, format="json"
    )

    assert response.status_code == 400, response.content
    mailing_world["assignment"].refresh_from_db()
    undeliverable.refresh_from_db()
    assert mailing_world["assignment"].status == RequirementAssignment.Status.DRAFT
    assert undeliverable.status == RequirementAssignment.Status.DRAFT
    assert not RequirementAssignmentMailOutbox.objects.exists()
    assert not RequirementAssignmentEvent.objects.filter(
        assignment__in=[mailing_world["assignment"], undeliverable]
    ).exists()


def test_changed_recipient_rejects_stale_unique_intent_instead_of_silent_noop(
    mailing_world, monkeypatch
):
    old_address = mailing_world["author"].email.strip().casefold()
    old_address_hash = hashlib.sha256(old_address.encode("utf-8")).hexdigest()
    old_digest = build_assignment_mail_payload_digest(
        compliance_assessment_id=mailing_world["target"].id,
        assignment_id=mailing_world["assignment"].id,
        recipient_actor_id=mailing_world["author_actor"].id,
        recipient_address_hash=old_address_hash,
    )
    stale = RequirementAssignmentMailOutbox.objects.create(
        assignment=mailing_world["assignment"],
        recipient_actor=mailing_world["author_actor"],
        requested_by=mailing_world["auditor"],
        folder=mailing_world["child_folder"],
        payload_digest=old_digest,
        recipient_address_hash=old_address_hash,
    )
    mailing_world["author"].email = f"changed-{uuid.uuid4().hex}@mail-outbox.tests"
    mailing_world["author"].save(update_fields=["email"])
    monkeypatch.setattr(
        "core.assignment_mailing.enqueue_requirement_assignment_mail_jobs",
        lambda ids: pytest.fail("stale intent was enqueued"),
    )

    response = _client(mailing_world["auditor"]).post(
        _mail_url(mailing_world), {}, format="json"
    )

    assert response.status_code == 400, response.content
    mailing_world["assignment"].refresh_from_db()
    stale.refresh_from_db()
    assert mailing_world["assignment"].status == RequirementAssignment.Status.DRAFT
    assert stale.status == RequirementAssignmentMailOutbox.Status.QUEUED
    assert RequirementAssignmentMailOutbox.objects.count() == 1
    assert not RequirementAssignmentEvent.objects.filter(
        assignment=mailing_world["assignment"]
    ).exists()


def test_user_mailing_returns_false_for_an_intentionally_disabled_template(
    mailing_world, monkeypatch
):
    monkeypatch.setattr(
        "core.email_utils.is_email_template_enabled", lambda template_key: False
    )
    monkeypatch.setattr(
        User,
        "_send_email",
        lambda *args, **kwargs: pytest.fail("disabled template was sent"),
    )

    assert (
        mailing_world["author"].mailing("tprm/third_party_email.html", "Assignment")
        is False
    )
