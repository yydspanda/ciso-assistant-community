from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone as datetime_timezone
from typing import Any

from django.contrib.auth.models import Permission
from django.core.exceptions import (
    MultipleObjectsReturned,
    ObjectDoesNotExist,
    ValidationError,
)
from django.db import transaction
from django.db.models import Q
from django.utils import timezone
from django.utils.dateparse import parse_date, parse_datetime
from rest_framework.exceptions import PermissionDenied

from iam.models import Folder, RoleAssignment, ServiceAccount, User
from tprm.models import Entity

from regulatory.contracts import RegulatoryApplicabilityPayload
from regulatory.models import (
    APPLICABILITY_DIGEST_SCHEMA,
    APPLICABILITY_EVALUATOR_PROFILE,
    PILOT_APPLICABILITY_FACT_KEY,
    PILOT_APPLICABILITY_RATIONALE_MATCH,
    PILOT_APPLICABILITY_RATIONALE_MISSING,
    PILOT_APPLICABILITY_RATIONALE_NO_MATCH,
    PILOT_APPLICABILITY_RATIONALE_UNKNOWN,
    PILOT_APPLICABILITY_RULE_ID,
    PILOT_APPLICABILITY_RULE_VERSION,
    PILOT_APPLICABILITY_SOURCE_REF_MAX_COUNT,
    PILOT_APPLICABILITY_SOURCE_REF_MAX_LENGTH,
    PILOT_APPLICABILITY_VALUE_MAX_LENGTH,
    EntityDocumentRegistration,
    RegulatoryApplicabilityDecision,
    RegulatoryObligationProvision,
)

from .common import (
    IdempotencyConflict,
    canonical_payload_sha256,
    lock_regulatory_actor,
    require_regulatory_permission,
)
from .corrections import regulatory_chain_semantic_sha256
from .records import (
    RegulatoryChain,
    _provenance_fields,
    regulatory_document_recorded_floor,
    select_regulatory_chain_at,
)


@dataclass(frozen=True)
class RegulatoryApplicabilityResult:
    chain: RegulatoryChain
    decision: RegulatoryApplicabilityDecision


@dataclass(frozen=True)
class RegulatoryApplicabilitySelection:
    chain: RegulatoryChain
    decision: RegulatoryApplicabilityDecision | None
    recorded_as_of: datetime


def _pilot_rule_snapshot() -> dict[str, Any]:
    return RegulatoryApplicabilityDecision.pilot_rule_snapshot()


def _iso(value: date | datetime | str | None) -> str | None:
    if isinstance(value, str):
        parsed_datetime = parse_datetime(value)
        if parsed_datetime is not None:
            value = parsed_datetime
        else:
            parsed_date = parse_date(value)
            return parsed_date.isoformat() if parsed_date is not None else value
    if isinstance(value, datetime):
        if timezone.is_naive(value):
            return value.isoformat()
        value = value.astimezone(datetime_timezone.utc)
    return value.isoformat() if value is not None else None


def _aware_datetime(value: object) -> datetime | None:
    parsed = parse_datetime(value) if isinstance(value, str) else None
    if parsed is None or timezone.is_naive(parsed):
        return None
    return parsed


def _validate_digest(value: object, label: str, errors: dict[str, str]) -> None:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        errors[label] = "A lowercase SHA-256 digest is required."


def _validate_payload_shape(payload: RegulatoryApplicabilityPayload) -> None:
    if not isinstance(payload, dict):
        raise ValidationError({"payload": "An applicability payload is required."})

    errors: dict[str, str] = {}
    required = {
        "record_id",
        "fact_snapshot_id",
        "expected_obligation",
        "expected_current",
        "observations",
        "valid_from",
        "valid_to",
        "provenance",
    }
    missing = required - set(payload)
    extra = set(payload) - required
    if missing:
        errors["payload.missing"] = f"Missing fields: {', '.join(sorted(missing))}."
    if extra:
        errors["payload.extra"] = f"Unknown fields: {', '.join(sorted(extra))}."

    nested_contracts = {
        "expected_obligation": {
            "physical_id",
            "record_id",
            "revision",
            "chain_semantic_payload_sha256",
        },
        "expected_current": {"decision_revision", "semantic_payload_sha256"},
        "provenance": {
            "method",
            "created_at",
            "created_by",
            "parser_version",
            "model",
            "prompt_version",
            "retrieval_version",
        },
    }
    for name, fields in nested_contracts.items():
        section = payload.get(name)
        if not isinstance(section, dict):
            errors[name] = "An object is required."
            continue
        nested_missing = fields - set(section)
        nested_extra = set(section) - fields
        if nested_missing:
            errors[f"{name}.missing"] = (
                f"Missing fields: {', '.join(sorted(nested_missing))}."
            )
        if nested_extra:
            errors[f"{name}.extra"] = (
                f"Unknown fields: {', '.join(sorted(nested_extra))}."
            )

    observations = payload.get("observations")
    if not isinstance(observations, list):
        errors["observations"] = "An observations array is required."
    elif len(observations) > 1:
        errors["observations"] = (
            "The single-condition pilot accepts at most one observation."
        )
    if errors:
        raise ValidationError(errors)


def _normalize_provenance(payload: dict[str, Any]) -> dict[str, Any]:
    errors: dict[str, str] = {}
    method = payload.get("method")
    if method not in {"human", "parser", "model_proposal", "import"}:
        errors["provenance.method"] = "Use a supported provenance method."
    created_by = payload.get("created_by")
    if not isinstance(created_by, str) or not created_by.strip():
        errors["provenance.created_by"] = "A non-empty creator is required."
    elif len(created_by) > 300:
        errors["provenance.created_by"] = "The creator exceeds the length limit."
    created_at = _aware_datetime(payload.get("created_at"))
    if created_at is None:
        errors["provenance.created_at"] = (
            "A timezone-aware RFC 3339 date-time is required."
        )
    optional_strings = {}
    for field in ("parser_version", "model", "prompt_version", "retrieval_version"):
        value = payload.get(field)
        if value is not None and (not isinstance(value, str) or not value.strip()):
            errors[f"provenance.{field}"] = "Use a non-empty string or null."
        elif isinstance(value, str) and len(value) > 300:
            errors[f"provenance.{field}"] = "The value exceeds the length limit."
        optional_strings[field] = value
    if errors:
        raise ValidationError(errors)
    return {
        "method": method,
        "created_at": _iso(created_at),
        "created_by": created_by,
        **optional_strings,
    }


def _normalize_observations(
    observations: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[str]]:
    errors: dict[str, str] = {}
    normalized_by_key: dict[str, dict[str, Any]] = {}
    allowed_fields = {"fact", "known", "value", "source_refs", "observed_at"}

    for index, observation in enumerate(observations):
        label = f"observations.{index}"
        if not isinstance(observation, dict):
            errors[label] = "An observation object is required."
            continue
        extra = set(observation) - allowed_fields
        required = {"fact", "known", "source_refs", "observed_at"} - set(observation)
        if extra:
            errors[f"{label}.extra"] = f"Unknown fields: {', '.join(sorted(extra))}."
        if required:
            errors[f"{label}.missing"] = (
                f"Missing fields: {', '.join(sorted(required))}."
            )
            continue

        fact = observation.get("fact")
        if fact != PILOT_APPLICABILITY_FACT_KEY:
            errors[f"{label}.fact"] = "The fact is not registered for this pilot."
            continue
        if fact in normalized_by_key:
            errors[f"{label}.fact"] = "Duplicate fact observations are forbidden."
            continue
        known = observation.get("known")
        if not isinstance(known, bool):
            errors[f"{label}.known"] = "known must be a boolean."
            continue

        source_refs = observation.get("source_refs")
        if not isinstance(source_refs, list):
            errors[f"{label}.source_refs"] = "source_refs must be an array."
            continue
        source_refs_are_valid_strings = all(
            isinstance(item, str) and bool(item.strip()) for item in source_refs
        )
        if not source_refs_are_valid_strings:
            errors[f"{label}.source_refs"] = (
                "Every source reference must be a non-empty string."
            )
        elif len(source_refs) != len(set(source_refs)):
            errors[f"{label}.source_refs"] = (
                "Duplicate source references are forbidden."
            )

        if known:
            value = observation.get("value")
            if (
                "value" not in observation
                or not isinstance(value, str)
                or not value.strip()
            ):
                errors[f"{label}.value"] = (
                    "A known institution type must be a non-empty string."
                )
            elif len(value) > PILOT_APPLICABILITY_VALUE_MAX_LENGTH:
                errors[f"{label}.value"] = (
                    "The institution type exceeds the pilot length limit."
                )
            if not source_refs:
                errors[f"{label}.source_refs"] = (
                    "A known fact requires at least one evidence reference."
                )
            elif len(source_refs) > PILOT_APPLICABILITY_SOURCE_REF_MAX_COUNT:
                errors[f"{label}.source_refs"] = (
                    "Too many evidence references were supplied."
                )
            elif source_refs_are_valid_strings and any(
                len(source_ref) > PILOT_APPLICABILITY_SOURCE_REF_MAX_LENGTH
                for source_ref in source_refs
            ):
                errors[f"{label}.source_refs"] = (
                    "An evidence reference exceeds the pilot length limit."
                )
            observed_at = _aware_datetime(observation.get("observed_at"))
            if observed_at is None:
                errors[f"{label}.observed_at"] = (
                    "A known fact requires a timezone-aware observation time."
                )
            normalized_by_key[fact] = {
                "fact": fact,
                "known": True,
                "value": value,
                "source_refs": (
                    sorted(source_refs) if source_refs_are_valid_strings else []
                ),
                "observed_at": _iso(observed_at) if observed_at is not None else None,
            }
        else:
            if "value" in observation:
                errors[f"{label}.value"] = "An unknown fact cannot carry a value."
            if source_refs:
                errors[f"{label}.source_refs"] = (
                    "An unknown fact cannot carry evidence references."
                )
            if observation.get("observed_at") is not None:
                errors[f"{label}.observed_at"] = (
                    "An unknown fact cannot carry an observation time."
                )
            normalized_by_key[fact] = {
                "fact": fact,
                "known": False,
                "source_refs": [],
                "observed_at": None,
            }

    if errors:
        raise ValidationError(errors)

    missing = []
    if PILOT_APPLICABILITY_FACT_KEY not in normalized_by_key:
        missing.append(PILOT_APPLICABILITY_FACT_KEY)
        normalized_by_key[PILOT_APPLICABILITY_FACT_KEY] = {
            "fact": PILOT_APPLICABILITY_FACT_KEY,
            "known": False,
            "source_refs": [],
            "observed_at": None,
        }
    return [normalized_by_key[key] for key in sorted(normalized_by_key)], missing


def _normalize_payload(payload: RegulatoryApplicabilityPayload) -> dict[str, Any]:
    _validate_payload_shape(payload)
    observations, missing = _normalize_observations(payload["observations"])
    provenance = _normalize_provenance(payload["provenance"])
    errors: dict[str, str] = {}

    for field in ("record_id", "fact_snapshot_id"):
        value = payload.get(field)
        if not isinstance(value, str) or not value.strip():
            errors[field] = "A non-empty portable identifier is required."

    expected_obligation = payload["expected_obligation"]
    if not isinstance(expected_obligation.get("physical_id"), str):
        errors["expected_obligation.physical_id"] = (
            "A physical UUID string is required."
        )
    if not isinstance(expected_obligation.get("record_id"), str):
        errors["expected_obligation.record_id"] = "A record ID is required."
    revision = expected_obligation.get("revision")
    if isinstance(revision, bool) or not isinstance(revision, int) or revision < 1:
        errors["expected_obligation.revision"] = "A positive revision is required."
    _validate_digest(
        expected_obligation.get("chain_semantic_payload_sha256"),
        "expected_obligation.chain_semantic_payload_sha256",
        errors,
    )

    expected_current = payload["expected_current"]
    expected_revision = expected_current.get("decision_revision")
    expected_digest = expected_current.get("semantic_payload_sha256")
    if (expected_revision is None) != (expected_digest is None):
        errors["expected_current"] = (
            "Revision and semantic digest must both be null or both be present."
        )
    if expected_revision is not None and (
        isinstance(expected_revision, bool)
        or not isinstance(expected_revision, int)
        or expected_revision < 1
    ):
        errors["expected_current.decision_revision"] = (
            "A positive decision revision is required."
        )
    if expected_digest is not None:
        _validate_digest(
            expected_digest,
            "expected_current.semantic_payload_sha256",
            errors,
        )

    normalized_dates: dict[str, str | None] = {}
    for field in ("valid_from", "valid_to"):
        value = payload.get(field)
        parsed = parse_date(value) if isinstance(value, str) else None
        if value is not None and parsed is None:
            errors[field] = "Use an ISO 8601 date or null."
        normalized_dates[field] = parsed.isoformat() if parsed is not None else None
    if (
        normalized_dates["valid_from"] is not None
        and normalized_dates["valid_to"] is not None
        and normalized_dates["valid_to"] <= normalized_dates["valid_from"]
    ):
        errors["valid_to"] = "valid_to must be later than valid_from."
    if errors:
        raise ValidationError(errors)

    return {
        "record_id": payload["record_id"],
        "fact_snapshot_id": payload["fact_snapshot_id"],
        "expected_obligation": dict(expected_obligation),
        "expected_current": dict(expected_current),
        "observations": observations,
        "missing_fact_keys": missing,
        **normalized_dates,
        "provenance": provenance,
    }


def _computed_outcome(
    fact_snapshot: list[dict[str, Any]],
    missing_fact_keys: list[str],
) -> tuple[str, str, str]:
    observation = fact_snapshot[0]
    if missing_fact_keys:
        return (
            RegulatoryApplicabilityDecision.Result.NEEDS_REVIEW,
            RegulatoryApplicabilityDecision.RationaleCode.MISSING_OR_UNKNOWN_FACT,
            PILOT_APPLICABILITY_RATIONALE_MISSING,
        )
    if not observation["known"]:
        return (
            RegulatoryApplicabilityDecision.Result.NEEDS_REVIEW,
            RegulatoryApplicabilityDecision.RationaleCode.MISSING_OR_UNKNOWN_FACT,
            PILOT_APPLICABILITY_RATIONALE_UNKNOWN,
        )
    if observation["value"] == "bank":
        return (
            RegulatoryApplicabilityDecision.Result.APPLICABLE,
            RegulatoryApplicabilityDecision.RationaleCode.RULE_SATISFIED,
            PILOT_APPLICABILITY_RATIONALE_MATCH,
        )
    return (
        RegulatoryApplicabilityDecision.Result.NOT_APPLICABLE,
        RegulatoryApplicabilityDecision.RationaleCode.RULE_NOT_SATISFIED,
        PILOT_APPLICABILITY_RATIONALE_NO_MATCH,
    )


def _semantic_payload(
    *,
    decision: RegulatoryApplicabilityDecision | None = None,
    registration: EntityDocumentRegistration | None = None,
    obligation=None,
    recorded_by: User | None = None,
    record_id: str | None = None,
    fact_snapshot_id: str | None = None,
    fact_snapshot: list[dict[str, Any]] | None = None,
    missing_fact_keys: list[str] | None = None,
    result: str | None = None,
    rationale_code: str | None = None,
    rationale: str | None = None,
    valid_from: date | str | None = None,
    valid_to: date | str | None = None,
    provenance: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if decision is not None:
        return decision.applicability_semantic_payload()
    assert registration is not None
    assert obligation is not None
    assert recorded_by is not None
    return {
        "digest_schema": APPLICABILITY_DIGEST_SCHEMA,
        "evaluator_profile": APPLICABILITY_EVALUATOR_PROFILE,
        "record_id": record_id,
        "fact_snapshot_id": fact_snapshot_id,
        "scope": {
            "type": "legal_entity",
            "registration_id": str(registration.id),
            "entity_id": str(registration.entity_id),
            "document_id": str(registration.document_id),
        },
        "obligation": {
            "physical_id": str(obligation.id),
            "record_id": obligation.record_id,
            "revision": obligation.revision,
        },
        "rule": _pilot_rule_snapshot(),
        "fact_snapshot": fact_snapshot,
        "missing_fact_keys": missing_fact_keys,
        "result": result,
        "rationale_code": rationale_code,
        "rationale": rationale,
        "valid_from": _iso(valid_from),
        "valid_to": _iso(valid_to),
        "review_status": "draft",
        "is_binding": False,
        "recorded_by_id": str(recorded_by.id),
        "provenance": provenance,
    }


def regulatory_applicability_semantic_sha256(
    decision: RegulatoryApplicabilityDecision,
) -> str:
    return canonical_payload_sha256(_semantic_payload(decision=decision))


def _validate_persisted_decision(decision: RegulatoryApplicabilityDecision) -> None:
    errors: dict[str, str] = {}
    if decision.rule_snapshot != _pilot_rule_snapshot():
        errors["rule_snapshot"] = "The persisted pilot rule snapshot is invalid."
    if (
        canonical_payload_sha256(decision.rule_snapshot)
        != decision.rule_snapshot_sha256
    ):
        errors["rule_snapshot_sha256"] = "The persisted rule digest is invalid."
    fact_digest_payload = {
        "observations": decision.fact_snapshot,
        "missing_fact_keys": decision.missing_fact_keys,
    }
    if canonical_payload_sha256(fact_digest_payload) != decision.fact_snapshot_sha256:
        errors["fact_snapshot_sha256"] = "The persisted fact digest is invalid."
    try:
        normalized_facts, _ = _normalize_observations(decision.fact_snapshot)
    except ValidationError:
        normalized_facts = []
        errors["fact_snapshot"] = "The persisted fact snapshot is invalid."
    if normalized_facts != decision.fact_snapshot:
        errors["fact_snapshot"] = "The persisted fact snapshot is not canonical."
    if decision.missing_fact_keys not in ([], [PILOT_APPLICABILITY_FACT_KEY]):
        errors["missing_fact_keys"] = "The persisted missing-fact marker is invalid."
    if "fact_snapshot" not in errors:
        computed_result, computed_code, computed_rationale = _computed_outcome(
            decision.fact_snapshot,
            decision.missing_fact_keys,
        )
        if (
            decision.result != computed_result
            or decision.rationale_code != computed_code
            or decision.rationale != computed_rationale
        ):
            errors["result"] = "The persisted applicability outcome is inconsistent."
    if regulatory_applicability_semantic_sha256(decision) != (
        decision.semantic_payload_sha256
    ):
        errors["semantic_payload_sha256"] = (
            "The persisted applicability semantic digest is invalid."
        )
    if errors:
        raise ValidationError(errors)


def _locked_scope(
    *,
    actor: User,
    entity: Entity,
    document_id,
    permission_codenames: tuple[str, ...],
) -> tuple[User, Entity, Folder, EntityDocumentRegistration]:
    actor = lock_regulatory_actor(actor=actor)
    if entity.pk is None:
        raise ValidationError({"entity": "A persisted synthetic entity is required."})
    entity = Entity.objects.select_for_update().get(pk=entity.pk)
    registration_folder_id = (
        EntityDocumentRegistration.objects.filter(
            entity=entity,
            document_id=document_id,
        )
        .values_list("folder_id", flat=True)
        .first()
    )
    if registration_folder_id is None:
        raise EntityDocumentRegistration.DoesNotExist
    # Registration folder is the immutable historical IAM boundary. Entity.folder
    # may move later; reads and exact retries must remain auditable in the folder
    # that owns the protected registration and decision history.
    folder = Folder.objects.select_for_update().get(pk=registration_folder_id)
    for codename in permission_codenames:
        require_regulatory_permission(actor=actor, codename=codename, folder=folder)
    try:
        entity_view_permission = Permission.objects.get(
            content_type__app_label="tprm",
            codename="view_entity",
        )
    except Permission.DoesNotExist as exc:
        raise PermissionDenied("Entity view permission is unavailable.") from exc
    if not RoleAssignment.is_access_allowed(
        user=actor,
        perm=entity_view_permission,
        folder=folder,
    ):
        raise PermissionDenied("The actor cannot view the applicability entity.")
    registration = (
        EntityDocumentRegistration.objects.select_for_update(of=("self",))
        .select_related("document", "entity")
        .get(
            folder=folder,
            entity=entity,
            document_id=document_id,
        )
    )
    if (
        registration.document.folder_id != folder.id
        or registration.registration_kind
        != EntityDocumentRegistration.RegistrationKind.SYNTHETIC_PILOT
    ):
        raise ValidationError("The applicability registration is inconsistent.")
    return actor, entity, folder, registration


def _chain_for_decision(decision: RegulatoryApplicabilityDecision) -> RegulatoryChain:
    try:
        link = (
            RegulatoryObligationProvision.objects.select_related(
                "provision__document_version",
            )
            .filter(
                folder=decision.folder,
                obligation=decision.obligation,
                obligation__folder=decision.folder,
                provision__folder=decision.folder,
                provision__document_version__folder=decision.folder,
                provision__document_version__document=decision.registration.document,
            )
            .get()
        )
    except (ObjectDoesNotExist, MultipleObjectsReturned) as exc:
        raise ValidationError(
            "The persisted applicability chain is inconsistent."
        ) from exc
    return RegulatoryChain(
        registration=decision.registration,
        document=decision.registration.document,
        document_version=link.provision.document_version,
        provision=link.provision,
        obligation=decision.obligation,
        recorded_as_of=decision.recorded_from,
    )


def _selection_time(
    *,
    document,
    folder: Folder,
    recorded_as_of: datetime | None,
) -> datetime:
    floor = regulatory_document_recorded_floor(document=document, folder=folder)
    wall_time = timezone.now()
    current_time = max(wall_time, floor) if floor is not None else wall_time
    if recorded_as_of is not None:
        if timezone.is_naive(recorded_as_of):
            raise ValidationError(
                {"recorded_as_of": "A timezone-aware datetime is required."}
            )
        if recorded_as_of > current_time:
            raise ValidationError(
                {"recorded_as_of": "A future recorded-time query is not allowed."}
            )
        return recorded_as_of
    return current_time


@transaction.atomic
def record_regulatory_applicability_decision(
    *,
    actor: User,
    entity: Entity,
    document_id,
    payload: RegulatoryApplicabilityPayload,
    idempotency_key: str,
) -> RegulatoryApplicabilityResult:
    """Record one deterministic, non-binding synthetic applicability revision."""

    if not idempotency_key or not idempotency_key.strip():
        raise ValidationError({"idempotency_key": "A non-empty key is required."})
    normalized = _normalize_payload(payload)
    actor, locked_entity, folder, registration = _locked_scope(
        actor=actor,
        entity=entity,
        document_id=document_id,
        permission_codenames=("record_regulatoryapplicability",),
    )
    if ServiceAccount.objects.filter(user=actor).exists():
        raise ValidationError("A named human must initiate applicability evaluation.")
    request_sha256 = canonical_payload_sha256(
        {
            "actor_id": str(actor.id),
            "entity_id": str(registration.entity_id),
            "document_id": str(registration.document_id),
            "payload": normalized,
        }
    )
    existing = (
        RegulatoryApplicabilityDecision.objects.select_for_update(of=("self",))
        .select_related(
            "folder",
            "registration__document",
            "registration__entity",
            "obligation",
            "recorded_by",
        )
        .filter(folder=folder, idempotency_key=idempotency_key)
        .first()
    )
    if existing is not None:
        if existing.request_sha256 != request_sha256:
            raise IdempotencyConflict(
                {"idempotency_key": "The key is bound to a different request."}
            )
        _validate_persisted_decision(existing)
        return RegulatoryApplicabilityResult(
            chain=_chain_for_decision(existing),
            decision=existing,
        )
    if locked_entity.folder_id != folder.id:
        raise ValidationError(
            {
                "entity": (
                    "New decisions require the entity to remain in its "
                    "registration folder."
                )
            }
        )
    if not (locked_entity.ref_id or "").upper().startswith("SYNTHETIC-"):
        raise ValidationError(
            {"entity": "New pilot decisions require a SYNTHETIC-* entity."}
        )

    document = registration.document
    selection_time = _selection_time(
        document=document,
        folder=folder,
        recorded_as_of=None,
    )
    chain = select_regulatory_chain_at(
        document=document,
        folder=folder,
        registration=registration,
        recorded_as_of=selection_time,
    )
    expected_obligation = normalized["expected_obligation"]
    current_chain_sha256 = regulatory_chain_semantic_sha256(chain)
    obligation_mismatch = (
        expected_obligation["physical_id"] != str(chain.obligation.id)
        or expected_obligation["record_id"] != chain.obligation.record_id
        or expected_obligation["revision"] != chain.obligation.revision
        or expected_obligation["chain_semantic_payload_sha256"] != current_chain_sha256
    )
    if obligation_mismatch:
        raise ValidationError(
            {"expected_obligation": "The selected obligation revision is stale."}
        )

    current_rows = list(
        RegulatoryApplicabilityDecision.objects.select_for_update(of=("self",))
        .select_related(
            "registration__document",
            "registration__entity",
            "obligation",
            "recorded_by",
        )
        .filter(
            folder=folder,
            registration=registration,
            obligation=chain.obligation,
            rule_id=PILOT_APPLICABILITY_RULE_ID,
            recorded_to__isnull=True,
        )[:2]
    )
    if len(current_rows) > 1:
        raise ValidationError("The current applicability decision is ambiguous.")
    current = current_rows[0] if current_rows else None
    expected_current = normalized["expected_current"]
    if current is None:
        if expected_current["decision_revision"] is not None:
            raise ValidationError({"expected_current": "No current decision exists."})
        revision = 1
    else:
        _validate_persisted_decision(current)
        if (
            expected_current["decision_revision"] != current.revision
            or expected_current["semantic_payload_sha256"]
            != current.semantic_payload_sha256
        ):
            raise ValidationError(
                {"expected_current": "The current decision is stale."}
            )
        if normalized["record_id"] != current.record_id:
            raise ValidationError(
                {"record_id": "A revision must preserve its record ID."}
            )
        if normalized["fact_snapshot_id"] != current.fact_snapshot_id:
            raise ValidationError(
                {"fact_snapshot_id": "A revision must preserve its snapshot ID."}
            )
        revision = current.revision + 1

    floor = regulatory_document_recorded_floor(document=document, folder=folder)
    latest = max(
        value
        for value in (
            floor,
            chain.document_version.recorded_from,
            chain.provision.recorded_from,
            chain.obligation.recorded_from,
            current.recorded_from if current is not None else None,
        )
        if value is not None
    )
    cutoff = max(timezone.now(), latest + timedelta(microseconds=1))

    for observation in normalized["observations"]:
        if observation["known"]:
            observed_at = _aware_datetime(observation["observed_at"])
            if observed_at is None or observed_at > cutoff:
                raise ValidationError(
                    {"observations": "A fact cannot be observed after the decision."}
                )
    provenance_created_at = _aware_datetime(normalized["provenance"]["created_at"])
    if provenance_created_at is None or provenance_created_at > cutoff:
        raise ValidationError(
            {"provenance.created_at": "Provenance cannot postdate the decision."}
        )

    valid_from = (
        parse_date(normalized["valid_from"])
        if normalized["valid_from"] is not None
        else None
    )
    valid_to = (
        parse_date(normalized["valid_to"])
        if normalized["valid_to"] is not None
        else None
    )
    if chain.obligation.valid_from is not None and (
        valid_from is None or valid_from < chain.obligation.valid_from
    ):
        raise ValidationError(
            {"valid_from": "The decision starts outside the obligation interval."}
        )
    if chain.obligation.valid_to is not None and (
        valid_to is None or valid_to > chain.obligation.valid_to
    ):
        raise ValidationError(
            {"valid_to": "The decision ends outside the obligation interval."}
        )

    result, rationale_code, rationale = _computed_outcome(
        normalized["observations"],
        normalized["missing_fact_keys"],
    )
    rule_snapshot = _pilot_rule_snapshot()
    rule_sha256 = canonical_payload_sha256(rule_snapshot)
    fact_sha256 = canonical_payload_sha256(
        {
            "observations": normalized["observations"],
            "missing_fact_keys": normalized["missing_fact_keys"],
        }
    )
    semantic_payload = _semantic_payload(
        registration=registration,
        obligation=chain.obligation,
        recorded_by=actor,
        record_id=normalized["record_id"],
        fact_snapshot_id=normalized["fact_snapshot_id"],
        fact_snapshot=normalized["observations"],
        missing_fact_keys=normalized["missing_fact_keys"],
        result=result,
        rationale_code=rationale_code,
        rationale=rationale,
        valid_from=valid_from,
        valid_to=valid_to,
        provenance=normalized["provenance"],
    )
    semantic_sha256 = canonical_payload_sha256(semantic_payload)
    if current is not None and current.semantic_payload_sha256 == semantic_sha256:
        raise ValidationError("A new idempotency key cannot create a no-op revision.")

    if current is not None:
        updated = RegulatoryApplicabilityDecision.objects.filter(
            pk=current.pk,
            recorded_to__isnull=True,
        ).update(recorded_to=cutoff)
        if updated != 1:
            raise ValidationError("The current applicability decision changed.")
        current.recorded_to = cutoff

    decision = RegulatoryApplicabilityDecision.objects.create(
        folder=folder,
        registration=registration,
        obligation=chain.obligation,
        recorded_by=actor,
        record_id=normalized["record_id"],
        revision=revision,
        previous_revision=current,
        recorded_from=cutoff,
        recorded_to=None,
        scope_type="legal_entity",
        rule_id=PILOT_APPLICABILITY_RULE_ID,
        rule_version=PILOT_APPLICABILITY_RULE_VERSION,
        rule_snapshot=rule_snapshot,
        fact_snapshot_id=normalized["fact_snapshot_id"],
        fact_snapshot=normalized["observations"],
        missing_fact_keys=normalized["missing_fact_keys"],
        result=result,
        rationale_code=rationale_code,
        rationale=rationale,
        valid_from=valid_from,
        valid_to=valid_to,
        review_status="draft",
        is_binding=False,
        digest_schema=APPLICABILITY_DIGEST_SCHEMA,
        evaluator_profile=APPLICABILITY_EVALUATOR_PROFILE,
        rule_snapshot_sha256=rule_sha256,
        fact_snapshot_sha256=fact_sha256,
        semantic_payload_sha256=semantic_sha256,
        request_sha256=request_sha256,
        idempotency_key=idempotency_key,
        **_provenance_fields(normalized),
    )
    _validate_persisted_decision(decision)
    return RegulatoryApplicabilityResult(chain=chain, decision=decision)


@transaction.atomic
def get_regulatory_applicability(
    *,
    actor: User,
    entity: Entity,
    document_id,
    recorded_as_of: datetime | None = None,
) -> RegulatoryApplicabilitySelection:
    """Select one entity-scoped decision at the same time as its exact chain."""

    _, _, folder, registration = _locked_scope(
        actor=actor,
        entity=entity,
        document_id=document_id,
        permission_codenames=(
            "view_regulatorydocument",
            "view_regulatoryapplicabilitydecision",
        ),
    )
    selected_at = _selection_time(
        document=registration.document,
        folder=folder,
        recorded_as_of=recorded_as_of,
    )
    chain = select_regulatory_chain_at(
        document=registration.document,
        folder=folder,
        registration=registration,
        recorded_as_of=selected_at,
    )
    decisions = list(
        RegulatoryApplicabilityDecision.objects.select_related(
            "registration__document",
            "registration__entity",
            "obligation",
            "recorded_by",
        )
        .filter(
            folder=folder,
            registration=registration,
            obligation=chain.obligation,
            rule_id=PILOT_APPLICABILITY_RULE_ID,
            recorded_from__lte=selected_at,
        )
        .filter(Q(recorded_to__isnull=True) | Q(recorded_to__gt=selected_at))[:2]
    )
    if len(decisions) > 1:
        raise ValidationError("The selected applicability decision is ambiguous.")
    decision = decisions[0] if decisions else None
    if decision is not None:
        _validate_persisted_decision(decision)
    return RegulatoryApplicabilitySelection(
        chain=chain,
        decision=decision,
        recorded_as_of=selected_at,
    )


# Package-internal shared contracts for the independent review-disposition
# service. Keeping one scope, digest, and historical-chain implementation avoids
# a second authority path while leaving the public service exports bounded.
lock_regulatory_applicability_scope = _locked_scope
validate_persisted_regulatory_applicability_decision = _validate_persisted_decision
regulatory_chain_for_applicability_decision = _chain_for_decision
