"""
Tests for TaskNode reliability: read-only calendar projection, explicit
materialization, conservative GC, rescheduling preservation, and pruning.
"""

from datetime import timedelta
from io import BytesIO

import pytest
from django.contrib.auth.models import Permission
from django.utils import timezone
from knox.models import AuthToken
from openpyxl import load_workbook
from rest_framework.test import APIClient

from core.models import Evidence, EvidenceRevision, TaskNode, TaskTemplate
from iam.models import Folder, Role, RoleAssignment, User

# ── Constants ──────────────────────────────────────────────────────────────

TASK_TEMPLATE_NAME = "Test Task Template"
TASK_TEMPLATE_DESCRIPTION = "Test Description"

WEEKLY_SCHEDULE = {
    "frequency": "WEEKLY",
    "interval": 1,
    "days_of_week": [0],  # Persisted schedule convention: Sunday=0
}


def _next_monday():
    """Return the next Monday on or after today."""
    today = timezone.localdate()
    days_ahead = (0 - today.weekday()) % 7  # 0 = Monday
    if days_ahead == 0:
        days_ahead = 7  # always pick a future Monday
    return today + timedelta(days=days_ahead)


def _make_weekly_template(folder, start_date, end_date=None, name=None):
    """Helper: create a recurrent weekly task template."""
    schedule = {**WEEKLY_SCHEDULE}
    if end_date:
        schedule["end_date"] = str(end_date)
    return TaskTemplate.objects.create(
        name=name or TASK_TEMPLATE_NAME,
        description=TASK_TEMPLATE_DESCRIPTION,
        folder=folder,
        is_recurrent=True,
        task_date=start_date,
        schedule=schedule,
    )


def _calendar_url(start, end):
    return f"/api/task-templates/calendar/{start}/{end}/"


def _sync_url(template):
    return f"/api/task-templates/{template.id}/sync-task-nodes/"


def _sync_template(client, template):
    response = client.post(_sync_url(template), {}, format="json")
    assert response.status_code == 200, response.content
    return response


def _scoped_client(folder, *, suffix, permission_codenames):
    user = User.objects.create_user(
        email=f"task-{suffix}@tests.example",
        is_published=True,
    )
    user.folder = Folder.get_root_folder()
    user.save(update_fields=["folder"])
    role = Role.objects.create(name=f"Task role {suffix}")
    role.permissions.set(
        Permission.objects.filter(
            content_type__app_label="core",
            codename__in=permission_codenames,
        )
    )
    assignment = RoleAssignment.objects.create(
        user=user,
        role=role,
        folder=folder,
        is_recursive=True,
    )
    assignment.perimeter_folders.add(folder)
    client = APIClient()
    _, token = AuthToken.objects.create(user=user)
    client.credentials(HTTP_AUTHORIZATION=f"Token {token}")
    return client


# ── Calendar projection and explicit materialization ─────────────────────


@pytest.mark.django_db
class TestTaskCalendarMaterialization:
    """Verify that GET is pure and POST owns materialization."""

    def test_calendar_get_does_not_materialize_nodes(self, authenticated_client):
        folder = Folder.get_root_folder()
        start = _next_monday()
        template = _make_weekly_template(folder, start)

        end = start + timedelta(weeks=4)
        response = authenticated_client.get(_calendar_url(start, end))

        assert response.status_code == 200
        tasks = response.json()
        assert len(tasks) >= 4
        assert all(task["virtual"] for task in tasks)
        assert not TaskNode.objects.filter(task_template=template).exists()

    def test_explicit_sync_materializes_once(self, authenticated_client):
        folder = Folder.get_root_folder()
        start = _next_monday()
        template = _make_weekly_template(folder, start)
        end = start + timedelta(weeks=4)

        first = _sync_template(authenticated_client, template)
        count_after_first = TaskNode.objects.filter(task_template=template).count()
        second = _sync_template(authenticated_client, template)
        count_after_second = TaskNode.objects.filter(task_template=template).count()

        assert first.json()["created"] > 0
        assert second.json() == {"created": 0, "updated": 0, "deleted": 0}
        assert count_after_first == count_after_second
        response = authenticated_client.get(_calendar_url(start, end))
        assert response.status_code == 200
        assert all(not task.get("virtual", False) for task in response.json())


@pytest.mark.django_db
class TestTaskNodeSynchronizationAuthority:
    def _folder(self, suffix):
        return Folder.objects.create(
            name=f"Task sync {suffix}",
            parent_folder=Folder.get_root_folder(),
            content_type=Folder.ContentType.DOMAIN,
        )

    def test_view_only_gets_do_not_write(self):
        folder = self._folder("read only")
        start = _next_monday()
        end = start + timedelta(weeks=4)
        template = _make_weekly_template(folder, start)
        node = TaskNode.objects.create(
            task_template=template,
            folder=folder,
            due_date=start,
            scheduled_date=start,
            to_delete=True,
        )
        client = _scoped_client(
            folder,
            suffix="view-only",
            permission_codenames=("view_tasktemplate", "view_tasknode"),
        )

        calendar_response = client.get(_calendar_url(start, end))
        object_response = client.get(f"/api/task-templates/{template.id}/object/")
        sync_response = client.post(_sync_url(template), {}, format="json")

        assert calendar_response.status_code == 200
        assert object_response.status_code == 200
        assert sync_response.status_code == 403
        node.refresh_from_db()
        assert node.to_delete is True
        assert TaskNode.objects.filter(task_template=template).count() == 1

    def test_hidden_task_node_data_is_not_disclosed(self):
        folder = self._folder("hidden node")
        start = _next_monday()
        end = start + timedelta(weeks=4)
        template = TaskTemplate.objects.create(
            name="Hidden-node template",
            folder=folder,
            is_recurrent=False,
            task_date=start,
        )
        node = TaskNode.objects.create(
            task_template=template,
            folder=folder,
            due_date=start,
            scheduled_date=start,
            status="completed",
            observation="TASK-NODE-SECRET",
        )
        client = _scoped_client(
            folder,
            suffix="template-only",
            permission_codenames=("view_tasktemplate",),
        )

        calendar_response = client.get(_calendar_url(start, end))
        object_response = client.get(f"/api/task-templates/{template.id}/object/")
        retrieve_response = client.get(f"/api/task-templates/{template.id}/")
        list_response = client.get("/api/task-templates/?limit=0")

        assert calendar_response.status_code == 200
        assert object_response.status_code == 200
        assert retrieve_response.status_code == 200
        assert list_response.status_code == 200
        assert str(node.id) not in calendar_response.content.decode()
        for response in (
            calendar_response,
            object_response,
            retrieve_response,
            list_response,
        ):
            assert "TASK-NODE-SECRET" not in response.content.decode()
        assert object_response.json()["observation"] == ""
        assert object_response.json()["status"] is None
        assert retrieve_response.json()["observation"] == ""
        assert retrieve_response.json()["status"] is None
        assert retrieve_response.json()["next_occurrence"] is None
        assert retrieve_response.json()["next_occurrence_status"] is None

    def test_hidden_node_does_not_drive_filter_order_or_yearly_review(self):
        folder = self._folder("hidden aggregate")
        start = _next_monday()
        template = _make_weekly_template(folder, start)
        node = TaskNode.objects.create(
            task_template=template,
            folder=folder,
            due_date=start,
            scheduled_date=start,
            status="completed",
        )
        past_node = TaskNode.objects.create(
            task_template=template,
            folder=folder,
            due_date=timezone.localdate() - timedelta(days=1),
            scheduled_date=timezone.localdate() - timedelta(days=1),
            status="completed",
        )
        client = _scoped_client(
            folder,
            suffix="template-aggregate-only",
            permission_codenames=("view_tasktemplate",),
        )

        filtered_response = client.get(
            "/api/task-templates/?next_occurrence_status=completed&limit=0"
        )
        ordered_response = client.get(
            "/api/task-templates/?ordering=next_occurrence&limit=0"
        )
        yearly_response = client.get(
            "/api/task-templates/yearly_review/",
            {
                "start_month": start.month,
                "start_year": start.year,
                "end_month": start.month,
                "end_year": start.year,
            },
        )
        export_response = client.get("/api/task-templates/export_xlsx/")

        assert filtered_response.status_code == 200
        assert ordered_response.status_code == 200
        assert yearly_response.status_code == 200
        assert export_response.status_code == 200
        assert str(template.id) not in filtered_response.content.decode()
        assert str(node.id) not in yearly_response.content.decode()
        assert str(past_node.id) not in yearly_response.content.decode()
        workbook = load_workbook(BytesIO(export_response.content), read_only=True)
        assert workbook.sheetnames == ["Summary"]
        workbook.close()
        ordered_payload = ordered_response.json()
        ordered_results = ordered_payload.get("results", ordered_payload)
        serialized_template = next(
            item for item in ordered_results if item["id"] == str(template.id)
        )
        assert serialized_template["next_occurrence"] is None
        assert serialized_template["next_occurrence_status"] is None

    def test_nonrecurrent_create_missing_node_add_permission_is_atomic(self):
        folder = self._folder("create denied")
        client = _scoped_client(
            folder,
            suffix="create-no-node-add",
            permission_codenames=(
                "add_tasktemplate",
                "view_tasktemplate",
                "view_tasknode",
            ),
        )

        response = client.post(
            "/api/task-templates/",
            {
                "name": "Must roll back",
                "folder": str(folder.id),
                "is_recurrent": False,
                "task_date": str(_next_monday()),
                "status": "pending",
            },
            format="json",
        )

        assert response.status_code == 403
        assert not TaskTemplate.objects.filter(name="Must roll back").exists()

    def test_nonrecurrent_update_missing_node_change_permission_is_atomic(self):
        folder = self._folder("update denied")
        template = TaskTemplate.objects.create(
            name="Original template name",
            folder=folder,
            is_recurrent=False,
            task_date=_next_monday(),
        )
        node = TaskNode.objects.create(
            task_template=template,
            folder=folder,
            due_date=template.task_date,
            scheduled_date=template.task_date,
        )
        client = _scoped_client(
            folder,
            suffix="update-no-node-change",
            permission_codenames=(
                "view_tasktemplate",
                "change_tasktemplate",
                "view_tasknode",
            ),
        )

        response = client.patch(
            f"/api/task-templates/{template.id}/",
            {"name": "Must not persist", "status": "completed"},
            format="json",
        )

        assert response.status_code == 403
        template.refresh_from_db()
        node.refresh_from_db()
        assert template.name == "Original template name"
        assert node.status == "pending"

    def test_authorized_nonrecurrent_create_and_update_keep_response_contract(self):
        folder = self._folder("write authorized")
        client = _scoped_client(
            folder,
            suffix="nonrecurrent-writer",
            permission_codenames=(
                "add_tasktemplate",
                "view_tasktemplate",
                "change_tasktemplate",
                "view_tasknode",
                "add_tasknode",
                "change_tasknode",
            ),
        )

        create_response = client.post(
            "/api/task-templates/",
            {
                "name": "Authorized template",
                "folder": str(folder.id),
                "is_recurrent": False,
                "task_date": str(_next_monday()),
                "status": "in_progress",
                "observation": "Authorized observation",
            },
            format="json",
        )

        assert create_response.status_code == 201, create_response.content
        template = TaskTemplate.objects.get(id=create_response.json()["id"])
        node = TaskNode.objects.get(task_template=template)
        assert create_response.json()["status"] == "in_progress"
        assert create_response.json()["observation"] == "Authorized observation"
        assert node.status == "in_progress"

        update_response = client.patch(
            f"/api/task-templates/{template.id}/",
            {"status": "completed", "observation": "Done"},
            format="json",
        )

        assert update_response.status_code == 200, update_response.content
        node.refresh_from_db()
        assert update_response.json()["status"] == "completed"
        assert update_response.json()["observation"] == "Done"
        assert node.status == "completed"
        assert node.observation == "Done"

    def test_sync_missing_node_delete_permission_is_atomic(self):
        folder = self._folder("denied")
        start = _next_monday()
        template = _make_weekly_template(folder, start)
        stale_date = start + timedelta(days=2)
        stale_node = TaskNode.objects.create(
            task_template=template,
            folder=folder,
            due_date=stale_date,
            scheduled_date=stale_date,
        )
        client = _scoped_client(
            folder,
            suffix="no-delete",
            permission_codenames=(
                "view_tasktemplate",
                "change_tasktemplate",
                "view_tasknode",
                "add_tasknode",
                "change_tasknode",
            ),
        )

        response = client.post(_sync_url(template), {}, format="json")

        assert response.status_code == 403
        assert list(
            TaskNode.objects.filter(task_template=template).values_list(
                "id", "due_date", "scheduled_date", "to_delete"
            )
        ) == [(stale_node.id, stale_date, stale_date, False)]

    def test_sync_missing_node_add_permission_is_atomic(self):
        folder = self._folder("no add")
        start = _next_monday()
        template = _make_weekly_template(folder, start)
        client = _scoped_client(
            folder,
            suffix="no-add",
            permission_codenames=(
                "view_tasktemplate",
                "change_tasktemplate",
                "view_tasknode",
                "change_tasknode",
                "delete_tasknode",
            ),
        )

        response = client.post(_sync_url(template), {}, format="json")

        assert response.status_code == 403
        assert not TaskNode.objects.filter(task_template=template).exists()

    def test_sync_missing_node_change_permission_is_atomic(self):
        folder = self._folder("no change")
        start = _next_monday()
        template = _make_weekly_template(folder, start)
        template.schedule["occurrences"] = 1
        template.save(update_fields=["schedule"])
        occurrence_date = start + timedelta(days=6)
        node = TaskNode.objects.create(
            task_template=template,
            folder=folder,
            due_date=occurrence_date,
            scheduled_date=occurrence_date,
            to_delete=True,
        )
        client = _scoped_client(
            folder,
            suffix="no-change",
            permission_codenames=(
                "view_tasktemplate",
                "change_tasktemplate",
                "view_tasknode",
                "add_tasknode",
                "delete_tasknode",
            ),
        )

        response = client.post(_sync_url(template), {}, format="json")

        assert response.status_code == 403
        node.refresh_from_db()
        assert node.to_delete is True
        assert TaskNode.objects.filter(task_template=template).count() == 1

    def test_authorized_sync_applies_exact_diff(self):
        folder = self._folder("authorized")
        start = _next_monday()
        template = _make_weekly_template(folder, start)
        stale_date = start + timedelta(days=2)
        stale_node = TaskNode.objects.create(
            task_template=template,
            folder=folder,
            due_date=stale_date,
            scheduled_date=stale_date,
        )
        client = _scoped_client(
            folder,
            suffix="writer",
            permission_codenames=(
                "view_tasktemplate",
                "change_tasktemplate",
                "view_tasknode",
                "add_tasknode",
                "change_tasknode",
                "delete_tasknode",
            ),
        )

        response = client.post(_sync_url(template), {}, format="json")

        assert response.status_code == 200
        assert response.json()["created"] > 0
        assert response.json()["deleted"] == 1
        assert not TaskNode.objects.filter(id=stale_node.id).exists()
        assert TaskNode.objects.filter(task_template=template).exists()
        assert (
            not TaskNode.objects.filter(task_template=template)
            .exclude(folder=folder)
            .exists()
        )


# ── Conservative GC ───────────────────────────────────────────────────────


@pytest.mark.django_db
class TestConservativeGarbageCollection:
    """GC should only delete truly untouched pending nodes."""

    def test_gc_preserves_in_progress_node(self, authenticated_client):
        """A node marked in_progress must survive GC."""
        folder = Folder.get_root_folder()
        start = _next_monday()
        template = _make_weekly_template(folder, start)

        # Materialize nodes through the explicit mutation endpoint.
        _sync_template(authenticated_client, template)

        # Mark one as in_progress
        node = TaskNode.objects.filter(task_template=template).first()
        node.status = "in_progress"
        node.save(update_fields=["status"])
        node_id = node.id

        # Saving the schedule is template-only; explicit sync owns node GC.
        response = authenticated_client.patch(
            f"/api/task-templates/{template.id}/",
            {"schedule": {**WEEKLY_SCHEDULE, "days_of_week": [1]}},  # Tuesday
            format="json",
        )
        assert response.status_code == 200, response.content
        _sync_template(authenticated_client, template)

        assert TaskNode.objects.filter(id=node_id).exists(), (
            "In-progress node was deleted by GC"
        )

    def test_gc_preserves_node_with_observation(self, authenticated_client):
        """A node with an observation must survive GC."""
        folder = Folder.get_root_folder()
        start = _next_monday()
        template = _make_weekly_template(folder, start)

        _sync_template(authenticated_client, template)

        node = TaskNode.objects.filter(task_template=template).first()
        node.observation = "Some important note"
        node.save(update_fields=["observation"])
        node_id = node.id

        response = authenticated_client.patch(
            f"/api/task-templates/{template.id}/",
            {"schedule": {**WEEKLY_SCHEDULE, "days_of_week": [1]}},
            format="json",
        )
        assert response.status_code == 200, response.content
        _sync_template(authenticated_client, template)

        assert TaskNode.objects.filter(id=node_id).exists(), (
            "Node with observation was deleted by GC"
        )

    def test_gc_preserves_node_with_evidence(self, authenticated_client):
        """A node with attached evidence must survive GC."""
        folder = Folder.get_root_folder()
        start = _next_monday()
        template = _make_weekly_template(folder, start)

        _sync_template(authenticated_client, template)

        node = TaskNode.objects.filter(task_template=template).first()
        evidence = Evidence.objects.create(name="test evidence", folder=folder)
        node.evidences.add(evidence)
        node_id = node.id

        response = authenticated_client.patch(
            f"/api/task-templates/{template.id}/",
            {"schedule": {**WEEKLY_SCHEDULE, "days_of_week": [1]}},
            format="json",
        )
        assert response.status_code == 200, response.content
        _sync_template(authenticated_client, template)

        assert TaskNode.objects.filter(id=node_id).exists(), (
            "Node with evidence was deleted by GC"
        )

    def test_gc_preserves_node_with_evidence_revision(self, authenticated_client):
        """A node with an evidence revision must survive GC."""
        folder = Folder.get_root_folder()
        start = _next_monday()
        template = _make_weekly_template(folder, start)

        _sync_template(authenticated_client, template)

        node = TaskNode.objects.filter(task_template=template).first()
        evidence = Evidence.objects.create(name="test evidence", folder=folder)
        EvidenceRevision.objects.create(
            evidence=evidence, task_node=node, folder=folder
        )
        node_id = node.id

        response = authenticated_client.patch(
            f"/api/task-templates/{template.id}/",
            {"schedule": {**WEEKLY_SCHEDULE, "days_of_week": [1]}},
            format="json",
        )
        assert response.status_code == 200, response.content
        _sync_template(authenticated_client, template)

        assert TaskNode.objects.filter(id=node_id).exists(), (
            "Node with evidence revision was deleted by GC"
        )

    def test_gc_deletes_untouched_pending_node(self, authenticated_client):
        """A pristine pending node whose slot is removed should be deleted."""
        folder = Folder.get_root_folder()
        start = _next_monday()
        template = _make_weekly_template(folder, start)

        _sync_template(authenticated_client, template)
        initial_count = TaskNode.objects.filter(task_template=template).count()
        assert initial_count >= 4

        # Change schedule — old Monday slots are no longer generated
        response = authenticated_client.patch(
            f"/api/task-templates/{template.id}/",
            {"schedule": {**WEEKLY_SCHEDULE, "days_of_week": [1]}},
            format="json",
        )
        assert response.status_code == 200, response.content
        _sync_template(authenticated_client, template)

        # New Tuesday slots may have been created, but old Monday pristine
        # nodes should have been cleaned up
        monday_nodes = TaskNode.objects.filter(
            task_template=template,
            scheduled_date__week_day=2,  # Django: Sunday=1, Monday=2
        ).count()
        assert monday_nodes == 0, "Untouched Monday nodes were not GC'd"


# ── Rescheduling preservation ─────────────────────────────────────────────


@pytest.mark.django_db
class TestReschedulingPreservation:
    """Nodes rescheduled by the user (due_date != scheduled_date) must survive."""

    def test_rescheduled_node_survives_sync(self, authenticated_client):
        """A user-rescheduled node must not be deleted on schedule sync."""
        folder = Folder.get_root_folder()
        start = _next_monday()
        template = _make_weekly_template(folder, start)

        _sync_template(authenticated_client, template)

        # Reschedule a node
        node = TaskNode.objects.filter(task_template=template).first()
        original_scheduled = node.scheduled_date
        new_due = original_scheduled + timedelta(days=2)
        node.due_date = new_due
        node.save(update_fields=["due_date"])
        node_id = node.id

        # Template update is read/write isolated from occurrence materialization.
        response = authenticated_client.patch(
            f"/api/task-templates/{template.id}/",
            {"name": "Updated Name"},
            format="json",
        )
        assert response.status_code == 200, response.content
        _sync_template(authenticated_client, template)

        node = TaskNode.objects.get(id=node_id)
        assert node.due_date == new_due, "Rescheduled due_date was overwritten"
        assert node.scheduled_date == original_scheduled

    def test_rescheduled_node_appears_in_calendar(self, authenticated_client):
        """A rescheduled node should appear in the calendar at its new due_date."""
        folder = Folder.get_root_folder()
        start = _next_monday()
        end = start + timedelta(weeks=4)
        template = _make_weekly_template(folder, start)

        _sync_template(authenticated_client, template)

        node = TaskNode.objects.filter(task_template=template).earliest(
            "scheduled_date"
        )
        new_due = node.scheduled_date + timedelta(days=3)
        node.due_date = new_due
        node.save(update_fields=["due_date"])
        node_id = str(node.id)

        response = authenticated_client.get(_calendar_url(start, end))
        tasks = response.json()

        task_ids = [str(t.get("id")) for t in tasks]
        assert node_id in task_ids, "Rescheduled node not found in calendar response"


# ── TaskTemplate.save() pruning ───────────────────────────────────────────


@pytest.mark.django_db
class TestTaskTemplateSavePruning:
    """Model saves are pure; authorized explicit sync owns conservative pruning."""

    def test_prune_respects_end_date(self, authenticated_client):
        """Save keeps nodes; explicit sync prunes untouched rows beyond end_date."""
        folder = Folder.get_root_folder()
        start = _next_monday()
        far_end = start + timedelta(weeks=12)
        template = _make_weekly_template(folder, start, end_date=far_end)

        # Materialize nodes through the explicit mutation endpoint.
        _sync_template(authenticated_client, template)
        total_before = TaskNode.objects.filter(task_template=template).count()
        assert total_before > 0

        # Shorten the schedule end_date
        new_end = start + timedelta(weeks=4)
        template.schedule["end_date"] = str(new_end)
        template.save()

        beyond_end_query = TaskNode.objects.filter(
            task_template=template,
            scheduled_date__gt=new_end,
            status="pending",
        )
        assert beyond_end_query.exists(), "TaskTemplate.save() mutated TaskNode rows"

        _sync_template(authenticated_client, template)

        assert not beyond_end_query.exists(), (
            "Authorized sync did not prune untouched nodes beyond end_date"
        )

    def test_prune_preserves_completed_node_beyond_end(self, authenticated_client):
        """Completed nodes beyond the end_date must NOT be pruned."""
        folder = Folder.get_root_folder()
        start = _next_monday()
        far_end = start + timedelta(weeks=12)
        template = _make_weekly_template(folder, start, end_date=far_end)

        _sync_template(authenticated_client, template)

        # Mark a future node as completed
        future_node = TaskNode.objects.filter(
            task_template=template,
            scheduled_date__gt=start + timedelta(weeks=6),
        ).first()
        assert future_node is not None
        future_node.status = "completed"
        future_node.save(update_fields=["status"])
        node_id = future_node.id

        # Shorten the schedule
        new_end = start + timedelta(weeks=4)
        template.schedule["end_date"] = str(new_end)
        template.save()

        assert TaskNode.objects.filter(id=node_id).exists(), (
            "TaskTemplate.save() mutated a completed node"
        )

        _sync_template(authenticated_client, template)

        assert TaskNode.objects.filter(id=node_id).exists(), (
            "Authorized sync incorrectly pruned a completed node beyond end_date"
        )
