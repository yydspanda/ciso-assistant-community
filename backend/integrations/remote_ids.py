"""Deterministic provider-specific canonicalization for remote object IDs."""

from __future__ import annotations

import re
import unicodedata


class InvalidRemoteIdentifier(ValueError):
    """Raised when untrusted input cannot be represented as a safe remote ID."""


def normalize_remote_id(
    provider_name: str, remote_id: str, *, allow_blank: bool = False
) -> str:
    """Return the one stored/lookup representation for a provider remote ID.

    Jira issue keys are case-insensitive and conventionally uppercase, while
    ServiceNow ``sys_id`` values are conventionally lowercase. Unknown
    providers keep case because changing it could alter their identity contract.
    """

    if not isinstance(remote_id, str):
        raise InvalidRemoteIdentifier("Remote identifiers must be strings.")

    normalized = unicodedata.normalize("NFKC", remote_id).strip()
    if not normalized:
        if allow_blank:
            return ""
        raise InvalidRemoteIdentifier("A remote identifier is required.")
    if len(normalized) > 255:
        raise InvalidRemoteIdentifier("The remote identifier is too long.")
    if not normalized.isprintable() or any(char.isspace() for char in normalized):
        raise InvalidRemoteIdentifier(
            "The remote identifier contains invalid characters."
        )

    provider_key = unicodedata.normalize("NFKC", provider_name or "").strip().casefold()
    if provider_key == "jira":
        normalized = normalized.upper()
        if re.fullmatch(r"[A-Z][A-Z0-9_]*-[1-9][0-9]*", normalized) is None:
            raise InvalidRemoteIdentifier("The Jira issue key is invalid.")
        return normalized
    if provider_key == "servicenow":
        normalized = normalized.lower()
        # ServiceNow table clients interpolate sys_id into a URL path. Match
        # their provider grammar exactly so separators and traversal tokens can
        # never become part of the path.
        if re.fullmatch(r"[0-9a-z]{1,64}", normalized) is None:
            raise InvalidRemoteIdentifier("The ServiceNow sys_id is invalid.")
        return normalized
    return normalized
