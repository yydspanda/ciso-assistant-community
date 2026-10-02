"""Transactional outbox for requirement-assignment activation mail.

The request path proves authority and commits the workflow transition.  SMTP is
performed only by the Huey worker after commit.  The outbox is deliberately
small: it stores identifiers, a canonical payload digest, delivery state, and a
bounded failure code, but no password token, rendered body, or SMTP secret.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Final
from uuid import UUID

import structlog
from django.contrib.auth.models import Permission
from django.db import transaction
from django.db.models import F, Q
from django.utils import timezone
from iam.models import Folder, RoleAssignment, User
from rest_framework.exceptions import PermissionDenied, ValidationError

from core.models import (
    Actor,
    ComplianceAssessment,
    RequirementAssignment,
    RequirementAssignmentEvent,
    RequirementAssignmentMailOutbox,
)
from core.utils import has_full_view_compliance_assessment

MAIL_TEMPLATE: Final = "tprm/third_party_email.html"
MAIL_TEMPLATE_KEY: Final = "questionnaire_assignment"
MAIL_SUBJECT: Final = "CISO Assistant: A questionnaire has been assigned to you"
MAIL_OBJECT: Final = "auditee-assessments"
PAYLOAD_SCHEMA: Final = "requirement-assignment-mail-v1"
CLAIM_TIMEOUT: Final = timedelta(minutes=15)
logger = structlog.get_logger(__name__)


@dataclass(frozen=True, slots=True)
class _DeliveryLocator:
    """Untrusted, read-only coordinates used to enter the lock hierarchy."""

    compliance_assessment_id: UUID
    assignment_id: UUID
    outbox_id: UUID


@dataclass(slots=True)
class _LockedDeliveryGraph:
    """The exact recipient authority graph held by one database transaction."""

    assessment: ComplianceAssessment
    assignment: RequirementAssignment
    outbox: RequirementAssignmentMailOutbox
    author_link_ids: tuple[int, ...]
    assignment_actor_link_ids: tuple[int, ...]
    actor: Actor | None
    recipient_user: User | None


class _DeliveryLocatorChanged(Exception):
    """The unlocked locator changed before all parent rows were locked."""


def _exact_permission(app_label: str, model: str, codename: str) -> Permission:
    """Resolve one permission without codename-only ambiguity."""

    try:
        return Permission.objects.get(
            content_type__app_label=app_label,
            content_type__model=model,
            codename=codename,
        )
    except Permission.DoesNotExist as exc:
        raise PermissionDenied("Required mailing authority is unavailable.") from exc


def _require_folder_permission(user: User, permission: Permission, folder: Folder):
    if not RoleAssignment.is_access_allowed(user, permission, folder):
        raise PermissionDenied("Required mailing authority is unavailable.")


def _require_actor_view(user: User, actor: Actor) -> None:
    """Apply the exact permission for the Actor's authoritative subtype."""

    specific = actor.specific
    model = type(specific)
    permission = _exact_permission(
        model._meta.app_label,
        model._meta.model_name,
        f"view_{model._meta.model_name}",
    )
    folder_id = RoleAssignment.get_iam_folder_id(specific)
    folder = Folder.objects.get(id=folder_id)
    _require_folder_permission(user, permission, folder)


def _normalize_recipient(actor: Actor) -> str | None:
    specific = actor.specific
    if not hasattr(specific, "mailing"):
        return None
    addresses = {
        address.strip()
        for address in actor.get_emails()
        if isinstance(address, str) and address.strip()
    }
    if len(addresses) != 1:
        return None
    return addresses.pop()


def _address_hash(address: str) -> str:
    return hashlib.sha256(address.encode("utf-8")).hexdigest()


def build_assignment_mail_payload_digest(
    *,
    compliance_assessment_id: UUID,
    assignment_id: UUID,
    recipient_actor_id: UUID,
    recipient_address_hash: str,
) -> str:
    payload = {
        "assignment_id": str(assignment_id),
        "compliance_assessment_id": str(compliance_assessment_id),
        "object": MAIL_OBJECT,
        "object_id": str(assignment_id),
        "recipient_actor_id": str(recipient_actor_id),
        "recipient_address_hash": recipient_address_hash,
        "schema": PAYLOAD_SCHEMA,
        "subject": MAIL_SUBJECT,
        "template": MAIL_TEMPLATE,
        "template_key": MAIL_TEMPLATE_KEY,
    }
    canonical = json.dumps(
        payload,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _read_delivery_locator(outbox_id: UUID | str) -> _DeliveryLocator | None:
    """Read only enough identity to acquire parent locks in canonical order."""

    identity = (
        RequirementAssignmentMailOutbox.objects.filter(id=outbox_id)
        .values_list(
            "assignment__compliance_assessment_id",
            "assignment_id",
            "id",
        )
        .first()
    )
    if identity is None:
        return None
    return _DeliveryLocator(*identity)


def _lock_parent_and_outbox(
    locator: _DeliveryLocator,
) -> tuple[
    ComplianceAssessment,
    RequirementAssignment,
    RequirementAssignmentMailOutbox,
]:
    """Lock CA -> assignment -> outbox and reject a stale unlocked locator."""

    assessment = ComplianceAssessment.objects.select_for_update().get(
        id=locator.compliance_assessment_id
    )
    assignment = RequirementAssignment.objects.select_for_update().get(
        id=locator.assignment_id
    )
    outbox = RequirementAssignmentMailOutbox.objects.select_for_update().get(
        id=locator.outbox_id
    )
    if (
        assignment.compliance_assessment_id != assessment.id
        or outbox.assignment_id != assignment.id
    ):
        raise _DeliveryLocatorChanged
    return assessment, assignment, outbox


def _lock_delivery_graph(locator: _DeliveryLocator) -> _LockedDeliveryGraph:
    """Lock the complete delivery graph in one deterministic hierarchy.

    Both many-to-many tables are locked in a fixed table order and every set of
    rows is sorted by primary key.  Callers must already be inside ``atomic``.
    """

    assessment, assignment, outbox = _lock_parent_and_outbox(locator)
    actor_id = outbox.recipient_actor_id

    author_link_ids = tuple(
        ComplianceAssessment.authors.through.objects.select_for_update()
        .filter(
            complianceassessment_id=assessment.id,
            actor_id=actor_id,
        )
        .order_by("id")
        .values_list("id", flat=True)
    )
    assignment_actor_link_ids = tuple(
        RequirementAssignment.actor.through.objects.select_for_update()
        .filter(
            requirementassignment_id=assignment.id,
            actor_id=actor_id,
        )
        .order_by("id")
        .values_list("id", flat=True)
    )

    actor = None
    if actor_id is not None:
        actor = (
            Actor.objects.select_for_update().filter(id=actor_id).order_by("id").first()
        )

    recipient_user = None
    if actor is not None and actor.user_id is not None:
        recipient_user = (
            User.objects.select_for_update()
            .filter(id=actor.user_id)
            .order_by("id")
            .first()
        )
        if recipient_user is not None:
            actor.user = recipient_user

    return _LockedDeliveryGraph(
        assessment=assessment,
        assignment=assignment,
        outbox=outbox,
        author_link_ids=author_link_ids,
        assignment_actor_link_ids=assignment_actor_link_ids,
        actor=actor,
        recipient_user=recipient_user,
    )


def _validate_locked_delivery_graph(
    graph: _LockedDeliveryGraph,
    *,
    claimed_at: datetime,
) -> tuple[str | None, str | None]:
    """Validate status, identity, authority anchors, address, and payload."""

    outbox = graph.outbox
    assignment = graph.assignment
    actor = graph.actor
    recipient_user = graph.recipient_user

    if (
        outbox.status != RequirementAssignmentMailOutbox.Status.SENDING
        or outbox.claimed_at != claimed_at
    ):
        return "claim_changed", None
    if (
        assignment.compliance_assessment_id != graph.assessment.id
        or outbox.assignment_id != assignment.id
        or outbox.folder_id != assignment.folder_id
    ):
        return "payload_mismatch", None
    if assignment.status != RequirementAssignment.Status.IN_PROGRESS:
        return "assignment_not_active", None
    if outbox.recipient_actor_id is None:
        return "recipient_missing", None
    if actor is None or actor.id != outbox.recipient_actor_id:
        return "recipient_changed", None
    if not graph.author_link_ids or not graph.assignment_actor_link_ids:
        return "recipient_not_authorized", None
    if (
        actor.user_id is None
        or recipient_user is None
        or actor.user_id != recipient_user.id
    ):
        return "recipient_changed", None

    recipient = _normalize_recipient(actor)
    if recipient is None or _address_hash(recipient) != outbox.recipient_address_hash:
        return "recipient_changed", None
    digest = build_assignment_mail_payload_digest(
        compliance_assessment_id=graph.assessment.id,
        assignment_id=assignment.id,
        recipient_actor_id=actor.id,
        recipient_address_hash=outbox.recipient_address_hash,
    )
    if digest != outbox.payload_digest:
        return "payload_mismatch", None
    return None, recipient


def _terminal_reproof(
    graph: _LockedDeliveryGraph,
    *,
    claimed_at: datetime,
    expected_recipient: str,
) -> str | None:
    """Re-read the held graph immediately before the external SMTP call."""

    graph.outbox.refresh_from_db()
    graph.assignment.refresh_from_db()
    if graph.actor is not None:
        graph.actor.refresh_from_db()
    if graph.recipient_user is not None:
        graph.recipient_user.refresh_from_db()
    if (
        graph.actor is not None
        and graph.recipient_user is not None
        and graph.actor.user_id == graph.recipient_user.id
    ):
        graph.actor.user = graph.recipient_user

    failure_code, current_recipient = _validate_locked_delivery_graph(
        graph,
        claimed_at=claimed_at,
    )
    if failure_code is not None:
        return failure_code
    actor = graph.actor
    if actor is None:
        return "recipient_changed"
    if not (
        ComplianceAssessment.authors.through.objects.filter(
            id__in=graph.author_link_ids,
            complianceassessment_id=graph.assessment.id,
            actor_id=actor.id,
        ).exists()
        and RequirementAssignment.actor.through.objects.filter(
            id__in=graph.assignment_actor_link_ids,
            requirementassignment_id=graph.assignment.id,
            actor_id=actor.id,
        ).exists()
    ):
        return "recipient_not_authorized"
    if current_recipient != expected_recipient:
        return "recipient_changed"
    return None


def _set_outbox_failed(
    outbox: RequirementAssignmentMailOutbox,
    failure_code: str,
) -> None:
    outbox.status = RequirementAssignmentMailOutbox.Status.FAILED
    outbox.failed_at = timezone.now()
    outbox.failure_code = failure_code
    outbox.save(update_fields=["status", "failed_at", "failure_code"])


def _fail_claim(
    outbox_id: UUID | str,
    *,
    claimed_at: datetime,
    failure_code: str,
) -> bool:
    """Terminalise one exact claim using the canonical parent-first order."""

    for _ in range(3):
        locator = _read_delivery_locator(outbox_id)
        if locator is None:
            return False
        try:
            with transaction.atomic():
                _, _, outbox = _lock_parent_and_outbox(locator)
                if (
                    outbox.status != RequirementAssignmentMailOutbox.Status.SENDING
                    or outbox.claimed_at != claimed_at
                ):
                    return False
                _set_outbox_failed(outbox, failure_code)
                return True
        except (
            _DeliveryLocatorChanged,
            ComplianceAssessment.DoesNotExist,
            RequirementAssignment.DoesNotExist,
            RequirementAssignmentMailOutbox.DoesNotExist,
        ):
            continue
    return False


def enqueue_requirement_assignment_mail_jobs(outbox_ids: Iterable[UUID]) -> None:
    """Best-effort Huey enqueue; queued rows remain recoverable by the sweeper."""

    from core.tasks import deliver_requirement_assignment_mail

    for outbox_id in outbox_ids:
        try:
            deliver_requirement_assignment_mail(str(outbox_id))
        except Exception as exc:  # noqa: BLE001 - queue outage cannot undo state
            logger.error(
                "requirement_assignment_mail_enqueue_failed",
                outbox_id=str(outbox_id),
                error_type=type(exc).__name__,
            )


def queue_requirement_assignment_mails(
    *,
    requester: User,
    compliance_assessment_id: UUID,
    assert_complete_access: Callable[[User, ComplianceAssessment], None],
) -> tuple[list[UUID], int]:
    """Lock, re-authorize, transition, and persist delivery intents atomically."""

    with transaction.atomic():
        assessment = (
            ComplianceAssessment.objects.select_for_update(of=("self",))
            .select_related("folder")
            .get(id=compliance_assessment_id)
        )

        change_assessment = _exact_permission(
            "core",
            "complianceassessment",
            "change_complianceassessment",
        )
        _require_folder_permission(requester, change_assessment, assessment.folder)
        if not has_full_view_compliance_assessment(requester, assessment):
            raise PermissionDenied(
                "Complete audit data is unavailable for this caller."
            )
        assert_complete_access(requester, assessment)

        # Upstream can fill a missing assignment after a default assignee or
        # representative is added. Keep that recovery in the same authorized,
        # parent-locked transaction as durable delivery intents.
        from core.utils import ensure_audit_assignment

        ensure_audit_assignment(assessment)

        assignments = list(
            RequirementAssignment.objects.select_for_update(of=("self",))
            .filter(compliance_assessment=assessment)
            .select_related("folder")
            .order_by("id")
        )
        assignment_ids = [assignment.id for assignment in assignments]

        # Existing outbox rows are children of the locked assignments and must
        # be acquired before either relationship table.  A missing row is safe
        # to insert later because its assignment lock serialises every compliant
        # creator of that uniqueness key.
        locked_outboxes = {
            (outbox.assignment_id, outbox.recipient_actor_id): outbox
            for outbox in RequirementAssignmentMailOutbox.objects.select_for_update()
            .filter(assignment_id__in=assignment_ids)
            .order_by("id")
        }

        # Lock the relationship rows that define the exact author/recipient set.
        author_links = list(
            ComplianceAssessment.authors.through.objects.select_for_update()
            .filter(complianceassessment_id=assessment.id)
            .order_by("id")
            .values_list("actor_id", flat=True)
        )
        assignment_actor_links = list(
            RequirementAssignment.actor.through.objects.select_for_update()
            .filter(requirementassignment_id__in=assignment_ids)
            .order_by("id")
            .values_list("requirementassignment_id", "actor_id")
        )
        actor_ids = set(author_links)
        actor_ids.update(actor_id for _, actor_id in assignment_actor_links)
        actors = {
            actor.id: actor
            for actor in Actor.objects.select_for_update()
            .filter(id__in=actor_ids)
            .order_by("id")
        }
        # The requester is also referenced by both outbox.requested_by and
        # event.event_actor.  Include it in the same sorted User lock set as the
        # recipients so those later FK checks do not introduce a User-to-User
        # inversion between concurrent queue requests.
        user_ids = {requester.id}
        user_ids.update(
            actor.user_id for actor in actors.values() if actor.user_id is not None
        )
        if user_ids:
            # Stabilise the mail-capable subtype and its address while hashing.
            users = {
                user.id: user
                for user in User.objects.select_for_update()
                .filter(id__in=user_ids)
                .order_by("id")
            }
            if requester.id not in users:
                raise PermissionDenied("Required mailing authority is unavailable.")
            for actor in actors.values():
                if actor.user_id in users:
                    actor.user = users[actor.user_id]

        view_assignment = _exact_permission(
            "core", "requirementassignment", "view_requirementassignment"
        )
        transition_assignment = _exact_permission(
            "core",
            "requirementassignment",
            "transition_requirementassignment",
        )
        for assignment in assignments:
            _require_folder_permission(requester, view_assignment, assignment.folder)
            if assignment.status == RequirementAssignment.Status.DRAFT:
                _require_folder_permission(
                    requester, transition_assignment, assignment.folder
                )

        for actor in actors.values():
            _require_actor_view(requester, actor)

        author_ids = set(author_links)
        actors_by_assignment: dict[UUID, list[Actor]] = {
            assignment.id: [] for assignment in assignments
        }
        for assignment_id, actor_id in assignment_actor_links:
            if actor_id in author_ids and actor_id in actors:
                actors_by_assignment[assignment_id].append(actors[actor_id])

        recipients_by_assignment: dict[UUID, list[tuple[Actor, str]]] = {}
        for assignment in assignments:
            if assignment.status != RequirementAssignment.Status.DRAFT:
                continue
            recipients = []
            for actor in sorted(
                actors_by_assignment[assignment.id], key=lambda item: str(item.id)
            ):
                recipient = _normalize_recipient(actor)
                if recipient is not None:
                    recipients.append((actor, recipient))
            if not recipients:
                # A mixed request must never transition only the conveniently
                # deliverable subset and silently leave other drafts behind.
                raise ValidationError(
                    {"error": ["A draft assignment has no deliverable author."]}
                )
            recipients_by_assignment[assignment.id] = recipients

        outbox_ids: list[UUID] = []
        transitioned = 0
        for assignment in assignments:
            if assignment.status != RequirementAssignment.Status.DRAFT:
                continue

            for actor, recipient in recipients_by_assignment[assignment.id]:
                recipient_hash = _address_hash(recipient)
                digest = build_assignment_mail_payload_digest(
                    compliance_assessment_id=assessment.id,
                    assignment_id=assignment.id,
                    recipient_actor_id=actor.id,
                    recipient_address_hash=recipient_hash,
                )
                outbox = locked_outboxes.get((assignment.id, actor.id))
                if outbox is None:
                    outbox = RequirementAssignmentMailOutbox.objects.create(
                        assignment=assignment,
                        recipient_actor=actor,
                        folder=assignment.folder,
                        requested_by=requester,
                        payload_digest=digest,
                        recipient_address_hash=recipient_hash,
                    )
                    locked_outboxes[(assignment.id, actor.id)] = outbox
                if (
                    outbox.payload_digest != digest
                    or outbox.recipient_address_hash != recipient_hash
                    or outbox.status != RequirementAssignmentMailOutbox.Status.QUEUED
                ):
                    # An address/payload change or an already-consumed intent
                    # requires an explicit operator decision.  Never report a
                    # misleading queued=0 success for this inconsistent state.
                    raise ValidationError(
                        {"error": ["An assignment mail intent requires review."]}
                    )
                outbox_ids.append(outbox.id)

            assignment.status = RequirementAssignment.Status.IN_PROGRESS
            assignment.save(update_fields=["status"])
            RequirementAssignmentEvent.objects.create(
                assignment=assignment,
                event_type=RequirementAssignment.Status.IN_PROGRESS,
                event_actor=requester,
                folder=assignment.folder,
            )
            transitioned += 1

        unique_outbox_ids = list(dict.fromkeys(outbox_ids))
        if unique_outbox_ids:
            transaction.on_commit(
                lambda ids=tuple(unique_outbox_ids): (
                    enqueue_requirement_assignment_mail_jobs(ids)
                )
            )

    return unique_outbox_ids, transitioned


def deliver_requirement_assignment_mail_outbox(outbox_id: UUID | str) -> str:
    """CAS-claim and deliver one outbox row; duplicate delivery is a no-op.

    The claim and delivery transactions both enter through CA -> assignment ->
    outbox.  The delivery transaction then locks the two relationship tables,
    Actor, and User in that order before it re-proves the complete recipient
    graph.  The claim is committed before SMTP, so an external result is never
    presented as though a database rollback could undo it.  A process death
    after SMTP acceptance leaves ``sending`` for the terminal claim-timeout
    path; it is deliberately never re-queued automatically.  Immediate
    rescue-host fallback is also disabled because a primary SMTP exception can
    be ambiguous and must not trigger a duplicate.
    """

    claimed_at: datetime | None = None
    failure_code = "delivery_error"
    failure_error: Exception | None = None

    # The first read is deliberately unlocked.  It supplies only coordinates
    # for entering the hierarchy; every identity is checked again while held.
    claimed = False
    for _ in range(3):
        locator = _read_delivery_locator(outbox_id)
        if locator is None:
            return "noop"
        try:
            with transaction.atomic():
                assessment, _, outbox = _lock_parent_and_outbox(locator)
                # Claims for one assessment are deliberately serial.  The
                # remaining queued rows stay eligible for the periodic sweeper
                # after the active claim reaches a terminal state.
                another_claim_is_active = (
                    RequirementAssignmentMailOutbox.objects.filter(
                        assignment__compliance_assessment_id=assessment.id,
                        status=RequirementAssignmentMailOutbox.Status.SENDING,
                    )
                    .exclude(id=outbox.id)
                    .exists()
                )
                if another_claim_is_active:
                    return "noop"

                # Generate the lease timestamp only after all claim-owner rows
                # are held.  Time spent waiting for those locks must not age the
                # newly persisted claim.
                claimed_at = timezone.now()
                claimed_rows = RequirementAssignmentMailOutbox.objects.filter(
                    id=outbox.id,
                    assignment_id=locator.assignment_id,
                    status=RequirementAssignmentMailOutbox.Status.QUEUED,
                    available_at__lte=claimed_at,
                ).update(
                    status=RequirementAssignmentMailOutbox.Status.SENDING,
                    claimed_at=claimed_at,
                    failed_at=None,
                    failure_code="",
                    attempts=F("attempts") + 1,
                )
                if claimed_rows != 1:
                    return "noop"
            claimed = True
            break
        except (
            _DeliveryLocatorChanged,
            ComplianceAssessment.DoesNotExist,
            RequirementAssignment.DoesNotExist,
            RequirementAssignmentMailOutbox.DoesNotExist,
        ):
            continue

    if not claimed:
        return "noop"
    if claimed_at is None:  # defensive type narrowing; a claim always sets it
        return "noop"

    try:
        for _ in range(3):
            locator = _read_delivery_locator(outbox_id)
            if locator is None:
                return "noop"
            try:
                with transaction.atomic():
                    graph = _lock_delivery_graph(locator)
                    if (
                        graph.outbox.status
                        != RequirementAssignmentMailOutbox.Status.SENDING
                        or graph.outbox.claimed_at != claimed_at
                    ):
                        return "noop"

                    failure_code, recipient = _validate_locked_delivery_graph(
                        graph,
                        claimed_at=claimed_at,
                    )
                    if failure_code is None and recipient is not None:
                        failure_code = _terminal_reproof(
                            graph,
                            claimed_at=claimed_at,
                            expected_recipient=recipient,
                        )

                    if failure_code is None:
                        recipient_user = graph.recipient_user
                        if recipient_user is None or recipient is None:
                            failure_code = "recipient_changed"
                        else:
                            # The digest and the SMTP envelope use this exact
                            # stripped address.  Do not case-fold the local part.
                            recipient_user.email = recipient
                            if graph.actor is not None:
                                graph.actor.user = recipient_user
                            try:
                                delivered = recipient_user.mailing(
                                    email_template_name=MAIL_TEMPLATE,
                                    subject=MAIL_SUBJECT,
                                    object=MAIL_OBJECT,
                                    object_id=graph.assignment.id,
                                    allow_rescue=False,
                                    redact_logs=True,
                                )
                            except Exception as exc:  # noqa: BLE001 - SMTP boundary
                                failure_code = "delivery_error"
                                failure_error = exc
                            else:
                                if delivered is not True:
                                    failure_code = "delivery_not_confirmed"
                                    failure_error = ValueError(failure_code)

                    if failure_code is not None:
                        if failure_error is None:
                            failure_error = ValueError(failure_code)
                        _set_outbox_failed(graph.outbox, failure_code)
                    else:
                        graph.outbox.status = (
                            RequirementAssignmentMailOutbox.Status.DELIVERED
                        )
                        graph.outbox.delivered_at = timezone.now()
                        graph.outbox.failed_at = None
                        graph.outbox.failure_code = ""
                        graph.outbox.save(
                            update_fields=[
                                "status",
                                "delivered_at",
                                "failed_at",
                                "failure_code",
                            ]
                        )
                if failure_code is None:
                    return "delivered"
                break
            except (
                _DeliveryLocatorChanged,
                ComplianceAssessment.DoesNotExist,
                RequirementAssignment.DoesNotExist,
                RequirementAssignmentMailOutbox.DoesNotExist,
            ):
                continue
        else:
            failure_code = "delivery_error"
            failure_error = RuntimeError("delivery identity did not stabilise")
    except Exception as exc:  # noqa: BLE001 - terminalise ambiguous claims
        failure_error = exc
        if failure_code is None:
            failure_code = "delivery_error"

    # A database error after SMTP acceptance may have rolled back only the
    # delivery transaction.  The separately committed claim is terminalised in
    # a new parent-first transaction and is never re-queued automatically.
    terminalized = False
    try:
        terminalized = _fail_claim(
            outbox_id,
            claimed_at=claimed_at,
            failure_code=failure_code,
        )
    except Exception as exc:  # noqa: BLE001 - preserve safe non-retry semantics
        logger.error(
            "requirement_assignment_mail_terminalization_failed",
            outbox_id=str(outbox_id),
            failure_code=failure_code,
            error_type=type(exc).__name__,
        )
    if not terminalized:
        # A normal failure may already have committed FAILED inside the delivery
        # transaction.  Only report a terminalization failure when this exact
        # claim is still live after the fallback attempt.
        try:
            claim_is_still_live = RequirementAssignmentMailOutbox.objects.filter(
                id=outbox_id,
                status=RequirementAssignmentMailOutbox.Status.SENDING,
                claimed_at=claimed_at,
            ).exists()
        except Exception as exc:  # noqa: BLE001 - observability must not retry SMTP
            logger.error(
                "requirement_assignment_mail_terminalization_state_unknown",
                outbox_id=str(outbox_id),
                failure_code=failure_code,
                error_type=type(exc).__name__,
            )
        else:
            if claim_is_still_live:
                logger.error(
                    "requirement_assignment_mail_terminalization_failed",
                    outbox_id=str(outbox_id),
                    failure_code=failure_code,
                    error_type="claim_still_sending",
                )
    logger.error(
        "requirement_assignment_mail_delivery_failed",
        outbox_id=str(outbox_id),
        failure_code=failure_code,
        error_type=type(failure_error).__name__,
    )
    return "failed"


def get_due_requirement_assignment_mail_ids(*, limit: int = 100) -> list[UUID]:
    now = timezone.now()
    return list(
        RequirementAssignmentMailOutbox.objects.filter(
            status=RequirementAssignmentMailOutbox.Status.QUEUED,
            available_at__lte=now,
        )
        .order_by("available_at", "created_at", "id")
        .values_list("id", flat=True)[:limit]
    )


def fail_stale_requirement_assignment_mail_claims(*, limit: int = 100) -> int:
    """Close abandoned claims without retrying a possibly delivered email.

    A process can die after SMTP acceptance but before persisting ``delivered``.
    Automatically re-queueing that row would risk duplicate mail, so the
    sweeper records a bounded terminal failure for explicit operator review.
    """

    bounded_limit = max(0, min(limit, 100))
    if bounded_limit == 0:
        return 0

    now = timezone.now()
    cutoff = now - CLAIM_TIMEOUT
    candidates = list(
        RequirementAssignmentMailOutbox.objects.filter(
            status=RequirementAssignmentMailOutbox.Status.SENDING
        )
        .filter(Q(claimed_at__lte=cutoff) | Q(claimed_at__isnull=True))
        .order_by(
            "assignment__compliance_assessment_id",
            "assignment_id",
            "id",
        )
        .values_list(
            "assignment__compliance_assessment_id",
            "assignment_id",
            "id",
        )[:bounded_limit]
    )
    failed = 0
    for candidate in candidates:
        locator = _DeliveryLocator(*candidate)
        try:
            with transaction.atomic():
                _, _, outbox = _lock_parent_and_outbox(locator)
                changed = (
                    RequirementAssignmentMailOutbox.objects.filter(
                        id=outbox.id,
                        status=RequirementAssignmentMailOutbox.Status.SENDING,
                    )
                    .filter(Q(claimed_at__lte=cutoff) | Q(claimed_at__isnull=True))
                    .update(
                        status=RequirementAssignmentMailOutbox.Status.FAILED,
                        failed_at=now,
                        failure_code="claim_timeout",
                    )
                )
                failed += changed
        except (
            _DeliveryLocatorChanged,
            ComplianceAssessment.DoesNotExist,
            RequirementAssignment.DoesNotExist,
            RequirementAssignmentMailOutbox.DoesNotExist,
        ):
            # A concurrent identity/delete transition is either already
            # terminal or will be reconsidered from fresh coordinates later.
            continue
    return failed
