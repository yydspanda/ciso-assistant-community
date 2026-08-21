import hashlib
import json
from typing import Any

from django.contrib.auth.models import Permission
from django.core.exceptions import ValidationError
from rest_framework.exceptions import PermissionDenied

from iam.models import Folder, RoleAssignment, User


class IdempotencyConflict(ValidationError):
    """An idempotency key was reused for a different authoritative payload."""


def lock_regulatory_actor(*, actor: User) -> User:
    """Reload and lock the principal so stale in-memory authority cannot act."""

    if not isinstance(actor, User) or actor.pk is None:
        raise PermissionDenied("A persisted actor is required.")
    current_actor = User.objects.select_for_update().filter(pk=actor.pk).first()
    if current_actor is None:
        raise PermissionDenied("The actor is unavailable.")
    if not current_actor.is_active:
        raise PermissionDenied("An active actor is required.")
    return current_actor


def canonical_payload_sha256(payload: Any) -> str:
    try:
        encoded = json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ValidationError(f"Payload is not canonical JSON: {exc}") from exc
    return hashlib.sha256(encoded).hexdigest()


def require_regulatory_permission(
    *,
    actor: User,
    codename: str,
    folder: Folder,
) -> None:
    if not getattr(actor, "is_authenticated", False):
        raise PermissionDenied("An authenticated actor is required.")
    if not getattr(actor, "is_active", False):
        raise PermissionDenied("An active actor is required.")
    try:
        permission = Permission.objects.get(
            content_type__app_label="regulatory",
            codename=codename,
        )
    except Permission.DoesNotExist as exc:
        raise PermissionDenied(
            f"Regulatory permission {codename!r} is unavailable."
        ) from exc
    if not RoleAssignment.is_access_allowed(
        user=actor,
        perm=permission,
        folder=folder,
    ):
        raise PermissionDenied(f"The actor cannot use {codename!r} in this folder.")
