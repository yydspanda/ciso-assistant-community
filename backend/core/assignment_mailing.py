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
from datetime import timedelta
from typing import Final
from uuid import UUID

import structlog
from django.contrib.auth.models import Permission
from django.db import transaction
from django.db.models import F, Q
from django.utils import timezone
from rest_framework.exceptions import PermissionDenied, ValidationError

from core.assignment_access import assert_assignment_folder_owner
from core.relation_locking import lock_rows_in_global_model_order
from core.models import (
    Actor,
    ComplianceAssessment,
    RequirementAssignment,
    RequirementAssignmentEvent,
    RequirementAssignmentMailEvidence,
    RequirementAssignmentMailOutbox,
)
from core.utils import has_full_view_compliance_assessment
from iam.models import Folder, RoleAssignment, User


MAIL_TEMPLATE: Final = "tprm/third_party_email.html"
MAIL_TEMPLATE_KEY: Final = "questionnaire_assignment"
MAIL_SUBJECT: Final = "CISO Assistant: A questionnaire has been assigned to you"
MAIL_OBJECT: Final = "auditee-assessments"
PAYLOAD_SCHEMA: Final = "requirement-assignment-mail-v1"
CLAIM_TIMEOUT: Final = timedelta(minutes=15)
logger = structlog.get_logger(__name__)


def _record_assignment_mail_evidence(
    outbox: RequirementAssignmentMailOutbox,
    *,
    prior_status: str,
    source: str = RequirementAssignmentMailEvidence.Source.SYSTEM,
    recorded_by_id: UUID | None = None,
    action: str = "",
    reason: str = "",
    evidence_reference: str = "",
) -> RequirementAssignmentMailEvidence:
    """Persist one immutable, privacy-minimized delivery-state snapshot."""

    recorded_at = timezone.now()
    payload = {
        "action": action,
        "assignment_id_snapshot": str(outbox.assignment_id),
        "attempts": outbox.attempts,
        "evidence_reference": evidence_reference,
        "failure_code": outbox.failure_code,
        "folder_id_snapshot": str(outbox.folder_id),
        "outbox_id_snapshot": str(outbox.id),
        "payload_digest": outbox.payload_digest,
        "prior_status": prior_status,
        "reason": reason,
        "recipient_actor_id_snapshot": (
            str(outbox.recipient_actor_id) if outbox.recipient_actor_id else None
        ),
        "recipient_address_hash": outbox.recipient_address_hash,
        "recorded_at": recorded_at.isoformat(),
        "recorded_by_id_snapshot": (
            str(recorded_by_id) if recorded_by_id is not None else None
        ),
        "requested_by_id_snapshot": (
            str(outbox.requested_by_id) if outbox.requested_by_id else None
        ),
        "source": source,
        "status": outbox.status,
    }
    canonical = json.dumps(
        payload,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    )
    return RequirementAssignmentMailEvidence.objects.create(
        outbox_id_snapshot=outbox.id,
        assignment_id_snapshot=outbox.assignment_id,
        folder_id_snapshot=outbox.folder_id,
        recipient_actor_id_snapshot=outbox.recipient_actor_id,
        requested_by_id_snapshot=outbox.requested_by_id,
        recorded_by_id_snapshot=recorded_by_id,
        source=source,
        prior_status=prior_status,
        status=outbox.status,
        action=action,
        attempts=outbox.attempts,
        payload_digest=outbox.payload_digest,
        recipient_address_hash=outbox.recipient_address_hash,
        failure_code=outbox.failure_code,
        reason=reason,
        evidence_reference=evidence_reference,
        record_digest=hashlib.sha256(canonical.encode("utf-8")).hexdigest(),
        recorded_at=recorded_at,
    )


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
        address.strip().casefold()
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


def enqueue_requirement_assignment_mail_jobs(outbox_ids: Iterable[UUID]) -> None:
    """Best-effort Huey enqueue; queued rows remain recoverable by the sweeper."""

    from core.tasks import deliver_requirement_assignment_mail

    for outbox_id in outbox_ids:
        try:
            deliver_requirement_assignment_mail(str(outbox_id))
        except Exception as exc:  # queue outage must not undo the committed state
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
        Folder._lock_folder_tree()
        assessment = (
            ComplianceAssessment.objects.select_for_update()
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

        assignments = list(
            RequirementAssignment.objects.select_for_update()
            .filter(compliance_assessment=assessment)
            .select_related("folder")
            .order_by("created_at", "id")
        )
        assignment_ids = [assignment.id for assignment in assignments]
        for assignment in assignments:
            assignment.compliance_assessment = assessment
            assert_assignment_folder_owner(assignment)

        # Lock the relationship rows that define the exact author/recipient set.
        author_links = list(
            ComplianceAssessment.authors.through.objects.select_for_update()
            .filter(complianceassessment_id=assessment.id)
            .values_list("actor_id", flat=True)
        )
        assignment_actor_links = list(
            RequirementAssignment.actor.through.objects.select_for_update()
            .filter(requirementassignment_id__in=assignment_ids)
            .values_list("requirementassignment_id", "actor_id")
        )
        actor_ids = set(author_links)
        actor_ids.update(actor_id for _, actor_id in assignment_actor_links)
        actors = lock_rows_in_global_model_order({Actor: actor_ids})[Actor]

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
                outbox, created = RequirementAssignmentMailOutbox.objects.get_or_create(
                    assignment=assignment,
                    recipient_actor=actor,
                    defaults={
                        "folder": assignment.folder,
                        "requested_by": requester,
                        "payload_digest": digest,
                        "recipient_address_hash": recipient_hash,
                    },
                )
                if (
                    outbox.folder_id != assignment.folder_id
                    or outbox.payload_digest != digest
                    or outbox.recipient_address_hash != recipient_hash
                    or outbox.status != RequirementAssignmentMailOutbox.Status.QUEUED
                ):
                    # An address/payload change or an already-consumed intent
                    # requires an explicit operator decision.  Never report a
                    # misleading queued=0 success for this inconsistent state.
                    raise ValidationError(
                        {"error": ["An assignment mail intent requires review."]}
                    )
                if created:
                    _record_assignment_mail_evidence(
                        outbox,
                        prior_status="",
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

    The CAS protects delivery ownership, while the inner transaction binds the
    external SMTP call to the exact active assignment, author link, assignment
    actor link, Actor subtype, and User address that were re-proved.  A process
    death after SMTP acceptance still leaves ``sending`` for the terminal
    claim-timeout path; it is deliberately never re-queued automatically.
    Immediate rescue-host fallback is also disabled on this durable path because
    a primary SMTP exception can be ambiguous and must not trigger a duplicate.
    """

    claimed_at = timezone.now()
    with transaction.atomic():
        claimed = RequirementAssignmentMailOutbox.objects.filter(
            id=outbox_id,
            status=RequirementAssignmentMailOutbox.Status.QUEUED,
            available_at__lte=claimed_at,
        ).update(
            status=RequirementAssignmentMailOutbox.Status.SENDING,
            claimed_at=claimed_at,
            failed_at=None,
            failure_code="",
            attempts=F("attempts") + 1,
        )
        if claimed != 1:
            return "noop"
        claimed_outbox = (
            RequirementAssignmentMailOutbox.objects.select_for_update().get(
                id=outbox_id,
                status=RequirementAssignmentMailOutbox.Status.SENDING,
            )
        )
        _record_assignment_mail_evidence(
            claimed_outbox,
            prior_status=RequirementAssignmentMailOutbox.Status.QUEUED,
        )

    failure_code = "delivery_error"
    smtp_outcome_unknown = False
    try:
        with transaction.atomic():
            try:
                outbox = (
                    RequirementAssignmentMailOutbox.objects.select_for_update().get(
                        id=outbox_id,
                        status=RequirementAssignmentMailOutbox.Status.SENDING,
                    )
                )
            except RequirementAssignmentMailOutbox.DoesNotExist:
                return "noop"

            assignment = RequirementAssignment.objects.select_for_update().get(
                id=outbox.assignment_id
            )
            assignment.compliance_assessment = ComplianceAssessment.objects.get(
                id=assignment.compliance_assessment_id
            )
            assert_assignment_folder_owner(assignment)
            if outbox.folder_id != assignment.folder_id:
                failure_code = "outbox_folder_mismatch"
                raise ValueError(failure_code)
            actor_id = outbox.recipient_actor_id
            if actor_id is None:
                failure_code = "recipient_missing"
                raise ValueError(failure_code)
            actor = lock_rows_in_global_model_order({Actor: {actor_id}})[Actor][
                actor_id
            ]

            # Only the direct User subtype owns this mail API. Locking Actor and
            # User prevents subtype/address changes after the exact recipient
            # is resolved but before the SMTP backend receives it.
            if actor.user_id is None:
                failure_code = "recipient_changed"
                raise ValueError(failure_code)
            # The shared Actor lock plan already holds this User before Actor.
            recipient_user = User.objects.get(id=actor.user_id)
            actor.user = recipient_user

            assignment_actor_links = list(
                RequirementAssignment.actor.through.objects.select_for_update()
                .filter(
                    requirementassignment_id=assignment.id,
                    actor_id=actor.id,
                )
                .values_list("id", flat=True)
            )
            author_links = list(
                ComplianceAssessment.authors.through.objects.select_for_update()
                .filter(
                    complianceassessment_id=assignment.compliance_assessment_id,
                    actor_id=actor.id,
                )
                .values_list("id", flat=True)
            )

            if assignment.status != RequirementAssignment.Status.IN_PROGRESS:
                failure_code = "assignment_not_active"
                raise ValueError(failure_code)
            if not assignment_actor_links or not author_links:
                failure_code = "recipient_not_authorized"
                raise ValueError(failure_code)

            recipient = _normalize_recipient(actor)
            if (
                recipient is None
                or _address_hash(recipient) != outbox.recipient_address_hash
            ):
                failure_code = "recipient_changed"
                raise ValueError(failure_code)
            digest = build_assignment_mail_payload_digest(
                compliance_assessment_id=assignment.compliance_assessment_id,
                assignment_id=assignment.id,
                recipient_actor_id=actor.id,
                recipient_address_hash=outbox.recipient_address_hash,
            )
            if digest != outbox.payload_digest:
                failure_code = "payload_mismatch"
                raise ValueError(failure_code)

            # Fresh terminal reproof catches same-transaction mutations in
            # tests and protects future refactors. On PostgreSQL the row locks
            # above additionally prevent a concurrent transaction from
            # crossing this boundary until delivery state is committed.
            assignment = RequirementAssignment.objects.select_for_update().get(
                id=assignment.id
            )
            actor = Actor.objects.select_for_update().get(id=actor.id)
            if assignment.status != RequirementAssignment.Status.IN_PROGRESS:
                failure_code = "assignment_not_active"
                raise ValueError(failure_code)
            if actor.user_id != recipient_user.id:
                failure_code = "recipient_changed"
                raise ValueError(failure_code)
            if not (
                RequirementAssignment.actor.through.objects.filter(
                    id__in=assignment_actor_links,
                    requirementassignment_id=assignment.id,
                    actor_id=actor.id,
                ).exists()
                and ComplianceAssessment.authors.through.objects.filter(
                    id__in=author_links,
                    complianceassessment_id=assignment.compliance_assessment_id,
                    actor_id=actor.id,
                ).exists()
            ):
                failure_code = "recipient_not_authorized"
                raise ValueError(failure_code)

            recipient_user = User.objects.select_for_update().get(id=actor.user_id)
            actor.user = recipient_user
            current_recipient = _normalize_recipient(actor)
            if (
                current_recipient != recipient
                or current_recipient is None
                or _address_hash(current_recipient) != outbox.recipient_address_hash
            ):
                failure_code = "recipient_changed"
                raise ValueError(failure_code)

            # Once control enters the mail backend, an exception or process
            # death cannot prove whether SMTP accepted the message.  Keep this
            # marker true until both the external result and our durable state
            # commit are complete.
            smtp_outcome_unknown = True
            delivered = recipient_user.mailing(
                email_template_name=MAIL_TEMPLATE,
                subject=MAIL_SUBJECT,
                object=MAIL_OBJECT,
                object_id=assignment.id,
                allow_rescue=False,
                redact_logs=True,
            )
            if delivered is not True:
                smtp_outcome_unknown = False
                failure_code = "delivery_not_confirmed"
                raise ValueError(failure_code)

            prior_status = outbox.status
            outbox.status = RequirementAssignmentMailOutbox.Status.DELIVERED
            outbox.delivered_at = timezone.now()
            outbox.failed_at = None
            outbox.failure_code = ""
            outbox.save(
                update_fields=[
                    "status",
                    "delivered_at",
                    "failed_at",
                    "failure_code",
                ]
            )
            _record_assignment_mail_evidence(
                outbox,
                prior_status=prior_status,
            )
        smtp_outcome_unknown = False
        return "delivered"
    except Exception as exc:
        final_status = (
            RequirementAssignmentMailOutbox.Status.UNCERTAIN
            if smtp_outcome_unknown
            else RequirementAssignmentMailOutbox.Status.FAILED
        )
        if smtp_outcome_unknown:
            failure_code = "smtp_outcome_unknown"
        with transaction.atomic():
            failed_outbox = (
                RequirementAssignmentMailOutbox.objects.select_for_update()
                .filter(
                    id=outbox_id,
                    status=RequirementAssignmentMailOutbox.Status.SENDING,
                )
                .first()
            )
            if failed_outbox is not None:
                prior_status = failed_outbox.status
                failed_outbox.status = final_status
                failed_outbox.failed_at = timezone.now()
                failed_outbox.failure_code = failure_code
                failed_outbox.save(
                    update_fields=["status", "failed_at", "failure_code"]
                )
                _record_assignment_mail_evidence(
                    failed_outbox,
                    prior_status=prior_status,
                )
        logger.error(
            "requirement_assignment_mail_delivery_failed",
            outbox_id=str(outbox_id),
            failure_code=failure_code,
            error_type=type(exc).__name__,
        )
        return final_status


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


def fail_stale_requirement_assignment_mail_claims() -> int:
    """Escalate abandoned claims without retrying a possibly delivered email.

    A process can die after SMTP acceptance but before persisting ``delivered``.
    Automatically re-queueing that row would risk duplicate mail, so the
    sweeper records a review-required state and immutable evidence for a named
    human decision.
    """

    now = timezone.now()
    cutoff = now - CLAIM_TIMEOUT
    with transaction.atomic():
        stale_outboxes = list(
            RequirementAssignmentMailOutbox.objects.select_for_update()
            .filter(status=RequirementAssignmentMailOutbox.Status.SENDING)
            .filter(Q(claimed_at__lte=cutoff) | Q(claimed_at__isnull=True))
            .order_by("id")
        )
        for outbox in stale_outboxes:
            prior_status = outbox.status
            outbox.status = RequirementAssignmentMailOutbox.Status.REVIEW_REQUIRED
            outbox.failed_at = now
            outbox.failure_code = "claim_timeout"
            outbox.save(update_fields=["status", "failed_at", "failure_code"])
            _record_assignment_mail_evidence(outbox, prior_status=prior_status)
    return len(stale_outboxes)


def resolve_requirement_assignment_mail_outbox(
    *,
    outbox_id: UUID | str,
    checker: User,
    action: str,
    reason: str,
    evidence_reference: str,
) -> str:
    """Resolve an ambiguous SMTP outcome through a named maker/checker gate.

    This is an internal service boundary, not an unauthenticated worker hook.
    A future UI/API may call it only after normal CISO Assistant IAM.  The
    decision binds the exact retained outbox payload and stores no mail body or
    recipient address.
    """

    allowed_actions = {
        RequirementAssignmentMailEvidence.Action.CONFIRM_DELIVERED,
        RequirementAssignmentMailEvidence.Action.CONFIRM_NOT_DELIVERED,
    }
    if action not in allowed_actions:
        raise ValidationError({"action": ["Unsupported mail resolution action."]})
    reason = reason.strip() if isinstance(reason, str) else ""
    evidence_reference = (
        evidence_reference.strip() if isinstance(evidence_reference, str) else ""
    )
    if not reason or len(reason) > 2000:
        raise ValidationError({"reason": ["A bounded decision reason is required."]})
    if not evidence_reference or len(evidence_reference) > 2048:
        raise ValidationError(
            {"evidence_reference": ["A bounded evidence reference is required."]}
        )
    if not getattr(checker, "is_authenticated", False) or not checker.id:
        raise PermissionDenied("A named human checker is required.")

    with transaction.atomic():
        Folder._lock_folder_tree()
        try:
            checker = User.objects.select_for_update().get(id=checker.id)
        except User.DoesNotExist as exc:
            raise PermissionDenied("A named human checker is required.") from exc
        if (
            not checker.is_active
            or User.objects.filter(
                id=checker.id,
                service_account__isnull=False,
            ).exists()
        ):
            raise PermissionDenied("A named human checker is required.")

        try:
            outbox = RequirementAssignmentMailOutbox.objects.select_for_update().get(
                id=outbox_id
            )
            assignment = RequirementAssignment.objects.select_for_update().get(
                id=outbox.assignment_id
            )
            folder = Folder.objects.get(id=outbox.folder_id)
        except (
            RequirementAssignmentMailOutbox.DoesNotExist,
            RequirementAssignment.DoesNotExist,
            Folder.DoesNotExist,
        ) as exc:
            raise PermissionDenied("The mail intent is unavailable.") from exc

        assignment.compliance_assessment = ComplianceAssessment.objects.get(
            id=assignment.compliance_assessment_id
        )
        assert_assignment_folder_owner(assignment)
        if outbox.folder_id != assignment.folder_id:
            raise PermissionDenied("The mail intent owner is inconsistent.")
        if outbox.requested_by_id == checker.id:
            raise PermissionDenied(
                "The mail requester cannot resolve their own intent."
            )
        if outbox.status not in {
            RequirementAssignmentMailOutbox.Status.UNCERTAIN,
            RequirementAssignmentMailOutbox.Status.REVIEW_REQUIRED,
        }:
            raise ValidationError(
                {"action": ["Only an ambiguous mail intent can be resolved."]}
            )

        reconcile_permission = _exact_permission(
            "core",
            "requirementassignmentmailoutbox",
            "resolve_requirementassignmentmailoutbox",
        )
        view_assignment = _exact_permission(
            "core",
            "requirementassignment",
            "view_requirementassignment",
        )
        _require_folder_permission(checker, reconcile_permission, folder)
        _require_folder_permission(checker, view_assignment, folder)

        prior_status = outbox.status
        now = timezone.now()
        if action == RequirementAssignmentMailEvidence.Action.CONFIRM_DELIVERED:
            outbox.status = RequirementAssignmentMailOutbox.Status.DELIVERED
            outbox.delivered_at = now
            outbox.failed_at = None
            outbox.failure_code = "human_confirmed_delivered"
        else:
            outbox.status = RequirementAssignmentMailOutbox.Status.FAILED
            outbox.delivered_at = None
            outbox.failed_at = now
            outbox.failure_code = "human_confirmed_not_delivered"
        outbox.save(
            update_fields=[
                "status",
                "delivered_at",
                "failed_at",
                "failure_code",
            ]
        )
        _record_assignment_mail_evidence(
            outbox,
            prior_status=prior_status,
            source=RequirementAssignmentMailEvidence.Source.HUMAN,
            recorded_by_id=checker.id,
            action=action,
            reason=reason,
            evidence_reference=evidence_reference,
        )
    return outbox.status
