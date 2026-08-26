import re
from collections.abc import Iterable

from django.core.exceptions import ValidationError


IDENTIFIER_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{2,159}$")
SHA256_PATTERN = re.compile(r"^[a-f0-9]{64}$")

REGULATORY_DOMAINS = frozenset(
    {
        "governance",
        "compliance",
        "banking",
        "insurance",
        "fintech",
        "licensing",
        "prudential_capital",
        "liquidity_risk",
        "credit_risk",
        "market_risk",
        "insurance_solvency",
        "actuarial_reserving",
        "insurance_funds",
        "payment_services",
        "regulatory_reporting",
        "aml_kyc",
        "consumer_protection",
        "data_security",
        "privacy",
        "cross_border_data",
        "cybersecurity",
        "mlps",
        "critical_infrastructure",
        "cryptography",
        "ai_model_governance",
        "outsourcing",
        "operational_resilience",
        "internal_control",
        "audit",
        "cost_control",
    }
)


def validate_regulatory_identifier(value: str) -> None:
    if not isinstance(value, str) or not IDENTIFIER_PATTERN.fullmatch(value):
        raise ValidationError(
            "Use a 3-160 character portable regulatory identifier.",
            code="invalid_regulatory_identifier",
        )


def validate_sha256(value: str | None) -> None:
    if value in (None, ""):
        return
    if not isinstance(value, str) or not SHA256_PATTERN.fullmatch(value):
        raise ValidationError(
            "Use a lowercase 64-character SHA-256 digest.",
            code="invalid_sha256",
        )


def _validate_string_list(
    value: object,
    *,
    require_items: bool,
    allowed: Iterable[str] | None = None,
) -> None:
    if not isinstance(value, list):
        raise ValidationError("Expected a JSON array of strings.")
    if require_items and not value:
        raise ValidationError("At least one value is required.")
    if any(not isinstance(item, str) or not item.strip() for item in value):
        raise ValidationError("Every value must be a non-empty string.")
    if len(value) != len(set(value)):
        raise ValidationError("Duplicate values are not allowed.")
    if allowed is not None:
        unknown = sorted(set(value) - set(allowed))
        if unknown:
            raise ValidationError(f"Unsupported values: {', '.join(unknown)}")


def validate_non_empty_string_list(value: object) -> None:
    _validate_string_list(value, require_items=True)


def validate_string_list(value: object) -> None:
    _validate_string_list(value, require_items=False)


def validate_regulatory_domains(value: object) -> None:
    _validate_string_list(
        value,
        require_items=True,
        allowed=REGULATORY_DOMAINS,
    )
