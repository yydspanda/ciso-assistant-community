"""Deterministic local command boundary for authenticated integration input."""

from __future__ import annotations

from typing import Any

from django.contrib.contenttypes.models import ContentType
from django.core.exceptions import FieldDoesNotExist
from django.core.exceptions import ValidationError as DjangoValidationError

from integrations.syncable import model_key_for_content_type


class InboundCommandRejected(Exception):
    """The provider proposal cannot cross the local model boundary."""


def apply_inbound_update(
    *,
    local_object,
    local_data: dict[str, Any],
    mapper,
) -> list[str]:
    """Validate and apply one provider proposal without bypassing model rules.

    The remote system proposes values; the local model remains authoritative.
    Only explicitly syncable, provider-approved update fields may cross this
    boundary. Django field validators, choices and model ``clean`` hooks run
    before one ``skip_sync`` save prevents an outbound echo.
    """

    if not isinstance(local_data, dict):
        raise InboundCommandRejected("Incoming integration data is not an object")
    model_meta = local_object._meta
    model_key = getattr(local_object, "INTEGRATION_MODEL_KEY", None)
    if not model_key:
        raise InboundCommandRejected("The local object is not integration-syncable")
    declared_model_key = model_key_for_content_type(
        ContentType.objects.get_for_model(local_object)
    )
    if declared_model_key != model_key:
        raise InboundCommandRejected("The local integration contract is inconsistent")

    syncable = set(getattr(local_object, "INTEGRATION_SYNCABLE_FIELDS", set()))
    provider_allowed = set(mapper.get_allowed_fields("pull", "update"))
    allowed = syncable & provider_allowed
    submitted = set(local_data)
    if submitted - allowed:
        raise InboundCommandRejected("Incoming integration fields are not allowed")
    if not submitted:
        return []

    for field_name, value in local_data.items():
        try:
            field = model_meta.get_field(field_name)
        except FieldDoesNotExist as exc:
            raise InboundCommandRejected(
                "An incoming integration field does not exist"
            ) from exc
        if (
            field.primary_key
            or not field.editable
            or field.many_to_many
            or field.one_to_many
        ):
            raise InboundCommandRejected("An incoming integration field is immutable")
        try:
            cleaned = field.clean(value, local_object)
        except DjangoValidationError as exc:
            raise InboundCommandRejected(
                "An incoming integration value failed deterministic validation"
            ) from exc
        setattr(local_object, field_name, cleaned)

    try:
        local_object.full_clean()
    except DjangoValidationError as exc:
        raise InboundCommandRejected(
            "The incoming command violates local model constraints"
        ) from exc
    local_object.save(skip_sync=True)
    return sorted(submitted)
