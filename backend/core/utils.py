import hashlib
from decimal import Decimal
from enum import Enum

import json
from re import sub
from typing import Literal
from datetime import datetime, timedelta, date

from django.utils.translation import gettext_lazy as _
from django.conf import settings

from rest_framework.exceptions import ValidationError
import structlog
import calendar
from dateutil import relativedelta as rd
from uuid import UUID

# Re-export so callers can import from a single utils module.
from .friendly_names import generate_friendly_name  # noqa: F401

logger = structlog.get_logger(__name__)


def extract_node_id(urn: str | None) -> str | None:
    """Extract the node_id (mobile part) from a URN.

    URN format: urn:{org}:risk:{type}:{slug}:{node_id}
    The node_id is everything after the 5th colon and may contain colons.
    """
    if not urn:
        return None
    parts = urn.split(":")
    if len(parts) <= 5:
        return None
    node_id = ":".join(parts[5:]).strip()
    return node_id if node_id else None


def resolve_compute_result(compute_result: str | None) -> str | None:
    """Map a QuestionChoice.compute_result string to a Result value."""
    if compute_result is None:
        return None
    value = compute_result.strip().lower()
    if value == "":
        return None
    if value in ("true", "1", "compliant"):
        return "compliant"
    if value in ("false", "0", "non_compliant"):
        return "non_compliant"
    if value == "partially_compliant":
        return "partially_compliant"
    if value == "not_applicable":
        return "not_applicable"
    logger.warning(
        "Unknown compute_result value ignored", compute_result=compute_result
    )
    return None


def aggregate_compute_results(resolved_results: list[str | None]) -> str | None:
    """Aggregate resolved compute_result values: not_applicable is neutral, else worst-wins."""
    contributing = [r for r in resolved_results if r is not None]
    if not contributing:
        return None

    non_na = [r for r in contributing if r != "not_applicable"]
    if not non_na:
        return "not_applicable"

    has_compliant = any(r == "compliant" for r in non_na)
    has_non_compliant = any(r == "non_compliant" for r in non_na)
    has_partial = any(r == "partially_compliant" for r in non_na)

    if has_partial or (has_compliant and has_non_compliant):
        return "partially_compliant"
    if has_non_compliant:
        return "non_compliant"
    return "compliant"


# Currency formatting conventions: (position, space)
# position: "before" or "after" the amount
# space: whether to include a space between symbol and amount
_CURRENCY_FORMAT = {
    # Symbol before, no space: $100
    "$": ("before", False),
    "£": ("before", False),
    "¥": ("before", False),
    "CN¥": ("before", False),
    "₹": ("before", False),
    "₩": ("before", False),
    "A$": ("before", False),
    "NZ$": ("before", False),
    "S$": ("before", False),
    "₺": ("before", False),
    "NT$": ("before", False),
    "฿": ("before", False),
    "MYR": ("before", False),
    # Symbol before, with space: CHF 100
    "C$": ("before", True),
    "CHF": ("before", True),
    "HK$": ("before", True),
    "R$": ("before", True),
    "MX$": ("before", True),
    "ZAR": ("before", True),
    # Symbol after, with space: 100 €
    "€": ("after", True),
    "SEK": ("after", True),
    "NOK": ("after", True),
    "DKK": ("after", True),
    "PLN": ("after", True),
    "XPF": ("after", True),
}


def get_global_currency() -> str:
    """Get the currency from global settings, defaulting to €."""
    from global_settings.models import GlobalSettings

    general_settings = GlobalSettings.objects.filter(name="general").first()
    return general_settings.value.get("currency", "€") if general_settings else "€"


def format_currency(value, currency: str) -> str:
    """Format a numeric value with its currency symbol in the correct position.

    Respects per-currency conventions for symbol position (before/after)
    and spacing. For large values, uses abbreviated forms (K, M, B).
    """
    if not currency:
        return f"{value} *"

    if isinstance(value, (int, float, Decimal)):
        if value >= 1_000_000_000:
            formatted = f"{value / 1_000_000_000:.1f}B"
        elif value >= 1_000_000:
            formatted = f"{value / 1_000_000:.1f}M"
        elif value >= 1_000:
            formatted = f"{value / 1_000:.0f}K"
        else:
            formatted = f"{value:,.0f}"
    else:
        formatted = str(value)

    position, space = _CURRENCY_FORMAT.get(currency, ("before", True))
    sep = " " if space else ""

    if position == "after":
        return f"{formatted}{sep}{currency}"
    return f"{currency}{sep}{formatted}"


def sizeof_json(obj) -> int:
    """
    Returns the size of a JSON-encoded object in bytes.
    If obj is already bytes (compressed), return its length directly.
    """
    if isinstance(obj, (bytes, bytearray, memoryview)):
        return len(obj)
    return len(json.dumps(obj).encode("utf-8"))


def camel_case(s):
    if not s:
        return ""
    s = sub(r"(_|-)+", " ", s).title().replace(" ", "")

    return "".join([s[0].lower(), s[1:]])


def sha256(string: bytes) -> str:
    """Return the SHA256-hashed hexadecimal representation of the bytes object given as argument."""
    h = hashlib.new("SHA256")
    h.update(string)
    return h.hexdigest()


class RoleCodename(Enum):
    ADMINISTRATOR = "BI-RL-ADM"
    DOMAIN_MANAGER = "BI-RL-DMA"
    ANALYST = "BI-RL-ANA"
    APPROVER = "BI-RL-APP"
    READER = "BI-RL-AUD"
    THIRD_PARTY_RESPONDENT = "BI-RL-TPR"
    AUDITEE = "BI-RL-ADE"
    TECHNICAL_TESTER = "BI-RL-TST"

    def __str__(self) -> str:
        return self.value


class UserGroupCodename(Enum):
    ADMINISTRATOR = "BI-UG-ADM"
    GLOBAL_READER = "BI-UG-GAD"
    GLOBAL_APPROVER = "BI-UG-GAP"
    GLOBAL_AUDITEE = "BI-UG-GAE"
    DOMAIN_MANAGER = "BI-UG-DMA"
    ANALYST = "BI-UG-ANA"
    APPROVER = "BI-UG-APP"
    READER = "BI-UG-AUD"
    THIRD_PARTY_RESPONDENT = "BI-UG-TPR"
    AUDITEE = "BI-UG-ADE"
    TECHNICAL_TESTER = "BI-UG-TST"

    def __str__(self) -> str:
        return self.value


# Translations for builtin role names, following the library localization pattern.
# Structure: {role_codename: {locale: {"name": translated_name}}}
# The English name serves as the base; other locales provide translations.
BUILTIN_ROLE_TRANSLATIONS = {
    "BI-RL-ADM": {
        "en": {"name": "Administrator"},
        "ar": {"name": "المسؤول"},
        "cs": {"name": "Administrátor"},
        "da": {"name": "Administrator"},
        "de": {"name": "Administrator"},
        "el": {"name": "Διαχειριστής"},
        "es": {"name": "Administrador"},
        "et": {"name": "Administraator"},
        "fr": {"name": "Administrateur"},
        "hi": {"name": "प्रशासक"},
        "hr": {"name": "Administrator"},
        "hu": {"name": "Adminisztrátor"},
        "id": {"name": "Administrator"},
        "it": {"name": "Amministratore"},
        "ko": {"name": "관리자"},
        "lt": {"name": "Administratorius"},
        "nl": {"name": "Beheerder"},
        "pl": {"name": "Administrator"},
        "pt": {"name": "Administrador"},
        "ro": {"name": "Administrator"},
        "sv": {"name": "Administratör"},
        "tr": {"name": "Yönetici"},
        "uk": {"name": "Адміністратор"},
        "ur": {"name": "ایڈمنسٹریٹر"},
        "zh": {"name": "管理员"},
    },
    "BI-RL-DMA": {
        "en": {"name": "Domain manager"},
        "ar": {"name": "مدير النطاق"},
        "cs": {"name": "Správce domény"},
        "da": {"name": "Domæneansvarlig"},
        "de": {"name": "Bereichsverantwortlicher"},
        "el": {"name": "Υπεύθυνος τομέα"},
        "es": {"name": "Gerente de dominio"},
        "et": {"name": "Valdkonnahaldur"},
        "fr": {"name": "Gestionnaire de domaine"},
        "hi": {"name": "डोमेन प्रबंधक"},
        "hr": {"name": "Upravitelj domene"},
        "hu": {"name": "Tartománykezelő"},
        "id": {"name": "Manajer domain"},
        "it": {"name": "Gestore del dominio"},
        "ko": {"name": "도메인 관리자"},
        "lt": {"name": "Srities vadovas"},
        "nl": {"name": "Domeinbeheerder"},
        "pl": {"name": "Menadżer domeny"},
        "pt": {"name": "Gerente de domínio"},
        "ro": {"name": "Manager de domeniu"},
        "sv": {"name": "Domänansvarig"},
        "tr": {"name": "Etki alanı yöneticisi"},
        "uk": {"name": "Менеджер домену"},
        "ur": {"name": "ڈومین مینیجر"},
        "zh": {"name": "域管理员"},
    },
    "BI-RL-ANA": {
        "en": {"name": "Analyst"},
        "ar": {"name": "المحلل"},
        "cs": {"name": "Analytik"},
        "da": {"name": "Analytiker"},
        "de": {"name": "Analyst"},
        "el": {"name": "Αναλυτής"},
        "es": {"name": "Analista"},
        "et": {"name": "Analüütik"},
        "fr": {"name": "Analyste"},
        "hi": {"name": "विश्लेषक"},
        "hr": {"name": "Analitičar"},
        "hu": {"name": "Elemző"},
        "id": {"name": "Analis"},
        "it": {"name": "Analista"},
        "ko": {"name": "분석가"},
        "lt": {"name": "Analitikas"},
        "nl": {"name": "Analist"},
        "pl": {"name": "Analityk"},
        "pt": {"name": "Analista"},
        "ro": {"name": "Analist"},
        "sv": {"name": "Analytiker"},
        "tr": {"name": "Analist"},
        "uk": {"name": "Аналітик"},
        "ur": {"name": "تجزیہ کار"},
        "zh": {"name": "分析师"},
    },
    "BI-RL-APP": {
        "en": {"name": "Approver"},
        "ar": {"name": "الموافق"},
        "cs": {"name": "Schvalovatel"},
        "da": {"name": "Godkender"},
        "de": {"name": "Genehmiger"},
        "el": {"name": "Εγκρίνων"},
        "es": {"name": "Aprobador"},
        "et": {"name": "Kinnitaja"},
        "fr": {"name": "Approbateur"},
        "hi": {"name": "स्वीकर्ता"},
        "hr": {"name": "Odobravatelj"},
        "hu": {"name": "Jóváhagyó"},
        "id": {"name": "Penyetuju"},
        "it": {"name": "Approvatore"},
        "ko": {"name": "승인자"},
        "lt": {"name": "Tvirtintojas"},
        "nl": {"name": "Goedkeurder"},
        "pl": {"name": "Akceptujący"},
        "pt": {"name": "Aprovador"},
        "ro": {"name": "Aprobator"},
        "sv": {"name": "Godkännare"},
        "tr": {"name": "Onaylayan"},
        "uk": {"name": "Затверджувач"},
        "ur": {"name": "منظور کنندہ"},
        "zh": {"name": "审批者"},
    },
    "BI-RL-AUD": {
        "en": {"name": "Reader"},
        "ar": {"name": "القارئ"},
        "cs": {"name": "Čtečka"},
        "da": {"name": "Læser"},
        "de": {"name": "Leser"},
        "el": {"name": "Αναγνώστης"},
        "es": {"name": "Lector"},
        "et": {"name": "Lugeja"},
        "fr": {"name": "Lecteur"},
        "hi": {"name": "रीडर"},
        "hr": {"name": "Čitatelj"},
        "hu": {"name": "Olvasó"},
        "id": {"name": "Pembaca"},
        "it": {"name": "Lettore"},
        "ko": {"name": "열람자"},
        "lt": {"name": "Skaitytojas"},
        "nl": {"name": "Lezer"},
        "pl": {"name": "Czytelnik"},
        "pt": {"name": "Leitor"},
        "ro": {"name": "Cititor"},
        "sv": {"name": "Läsare"},
        "tr": {"name": "Okuyucu"},
        "uk": {"name": "Читач"},
        "ur": {"name": "ریڈر"},
        "zh": {"name": "阅读者"},
    },
    "BI-RL-TPR": {
        "en": {"name": "Third-party respondent"},
        "ar": {"name": "المجيب من طرف ثالث"},
        "cs": {"name": "Respondent třetí strany"},
        "da": {"name": "Tredjepartsrespondent"},
        "de": {"name": "Drittanbieter-Befragter"},
        "el": {"name": "Ερωτώμενος τρίτου μέρους"},
        "es": {"name": "Encuestado de terceros"},
        "et": {"name": "Kolmanda osapoole vastaja"},
        "fr": {"name": "Répondant tiers"},
        "hi": {"name": "तृतीय-पक्ष प्रतिवादी"},
        "hr": {"name": "Ispitanik treće strane"},
        "hu": {"name": "Harmadik fél válaszadója"},
        "id": {"name": "Responden pihak ketiga"},
        "it": {"name": "Rispondente di terze parti"},
        "ko": {"name": "제3자 응답자"},
        "lt": {"name": "Trečiosios šalies respondentas"},
        "nl": {"name": "Externe respondent"},
        "pl": {"name": "Respondent strony trzeciej"},
        "pt": {"name": "Respondente terceiro"},
        "ro": {"name": "Respondent terță parte"},
        "sv": {"name": "Tredjepartsrespondent"},
        "tr": {"name": "Üçüncü taraf yanıtlayıcı"},
        "uk": {"name": "Респондент третьої сторони"},
        "ur": {"name": "فریق ثالث جواب دہندہ"},
        "zh": {"name": "第三方受访者"},
    },
    "BI-RL-ADE": {
        "en": {"name": "Respondent"},
        "ar": {"name": "المجيب"},
        "cs": {"name": "Respondent"},
        "da": {"name": "Respondent"},
        "de": {"name": "Befragter"},
        "el": {"name": "Ερωτώμενος"},
        "es": {"name": "Encuestado"},
        "et": {"name": "Vastaja"},
        "fr": {"name": "Répondant"},
        "hi": {"name": "प्रतिवादी"},
        "hr": {"name": "Ispitanik"},
        "hu": {"name": "Válaszadó"},
        "id": {"name": "Responden"},
        "it": {"name": "Rispondente"},
        "ko": {"name": "응답자"},
        "lt": {"name": "Respondentas"},
        "nl": {"name": "Respondent"},
        "pl": {"name": "Respondent"},
        "pt": {"name": "Respondente"},
        "ro": {"name": "Respondent"},
        "sv": {"name": "Respondent"},
        "tr": {"name": "Yanıtlayıcı"},
        "uk": {"name": "Респондент"},
        "ur": {"name": "جواب دہندہ"},
        "zh": {"name": "受访者"},
    },
    "BI-RL-TST": {
        "en": {"name": "Technical tester"},
        "ar": {"name": "مختبِر تقني"},
        "cs": {"name": "Technický tester"},
        "da": {"name": "Teknisk tester"},
        "de": {"name": "Technischer Tester"},
        "el": {"name": "Τεχνικός δοκιμαστής"},
        "es": {"name": "Probador técnico"},
        "et": {"name": "Tehniline testija"},
        "fr": {"name": "Testeur technique"},
        "hi": {"name": "तकनीकी परीक्षक"},
        "hr": {"name": "Tehnički tester"},
        "hu": {"name": "Műszaki tesztelő"},
        "id": {"name": "Penguji teknis"},
        "it": {"name": "Tester tecnico"},
        "ko": {"name": "기술 테스터"},
        "lt": {"name": "Techninis testuotojas"},
        "nl": {"name": "Technisch tester"},
        "pl": {"name": "Tester techniczny"},
        "pt": {"name": "Testador técnico"},
        "ro": {"name": "Tester tehnic"},
        "sv": {"name": "Teknisk testare"},
        "tr": {"name": "Teknik test uzmanı"},
        "uk": {"name": "Технічний тестувальник"},
        "ur": {"name": "تکنیکی ٹیسٹر"},
        "zh": {"name": "技术测试员"},
    },
}


def get_translated_builtin_role_name(role_codename: str) -> str:
    """Return the translated display name for a builtin role codename.

    Uses the same locale-resolution pattern as library objects:
    check BUILTIN_ROLE_TRANSLATIONS for the current Django language,
    fall back to English, then to the raw codename.
    """
    from django.utils.translation import get_language

    translations = BUILTIN_ROLE_TRANSLATIONS.get(role_codename, {})
    lang = get_language() or "en"
    # Try exact locale, then base language (e.g. "fr-FR" → "fr")
    locale_trans = translations.get(lang) or translations.get(lang.split("-")[0], {})
    return locale_trans.get("name") or translations.get("en", {}).get(
        "name", role_codename
    )


BUILTIN_USERGROUP_CODENAMES = {
    str(UserGroupCodename.ADMINISTRATOR): str(RoleCodename.ADMINISTRATOR),
    str(UserGroupCodename.GLOBAL_READER): str(RoleCodename.READER),
    str(UserGroupCodename.GLOBAL_APPROVER): str(RoleCodename.APPROVER),
    str(UserGroupCodename.GLOBAL_AUDITEE): str(RoleCodename.AUDITEE),
    str(UserGroupCodename.DOMAIN_MANAGER): str(RoleCodename.DOMAIN_MANAGER),
    str(UserGroupCodename.ANALYST): str(RoleCodename.ANALYST),
    str(UserGroupCodename.APPROVER): str(RoleCodename.APPROVER),
    str(UserGroupCodename.READER): str(RoleCodename.READER),
    str(UserGroupCodename.THIRD_PARTY_RESPONDENT): str(
        RoleCodename.THIRD_PARTY_RESPONDENT
    ),
    str(UserGroupCodename.AUDITEE): str(RoleCodename.AUDITEE),
    str(UserGroupCodename.TECHNICAL_TESTER): str(RoleCodename.TECHNICAL_TESTER),
}

# NOTE: This is set to "Main" now, but will be changed to a unique identifier
# for internationalization.
MAIN_ENTITY_DEFAULT_NAME = "Main"

COUNTRY_FLAGS = {
    "fr": "🇫🇷",
    "en": "🇬🇧",
}

LANGUAGES = {
    "fr": _("French"),
    "en": _("English"),
}


class VersionFormatError(Exception):
    """Raised when a version string is not properly formatted."""

    pass


def parse_version(version: str) -> list[int]:
    """
    Parses a version string that starts with 'v' and contains dot-separated numbers.
    Accepts strings like 'v1', 'v1.2', or 'v1.2.3'.
    """
    if not version.startswith("v"):
        raise VersionFormatError(f"Version must start with 'v': {version}")
    # Remove leading 'v' and split on dots
    parts = version.lstrip("v").split(".")
    try:
        return [int(part) for part in parts]
    except ValueError as e:
        raise VersionFormatError(f"Non-numeric version component in {version}") from e


def compare_versions(
    version_a: str, version_b: str, level: Literal["major", "minor", "patch"] = "patch"
) -> int:
    """
    Compares two version strings at the specified level of granularity.

    Parameters:
        version_a (str): A version string (e.g., 'v1.2.3' or 'v1.2').
        version_b (str): Another version string.
        level (str): Granularity to compare: 'major' (only the first component),
                     'minor' (first two components), or 'patch' (all three components).
                     For example, comparing 'v1.2' with 'v1.2.0' at level='minor' will be equal.

    Returns:
        int: -1 if version_a is lower than version_b;
             0 if they are equal (up to the specified level);
             1 if version_a is greater than version_b.

    Raises:
        VersionFormatError: if either version string is not formatted correctly.
        ValueError: if an invalid level is specified.

    Example:
        >>> compare_versions("v1.2", "v1.2.0", level="minor")
        0
        >>> compare_versions("v1.2.1", "v1.2.0", level="patch")
        1
        >>> compare_versions("v2", "v1.9.9", level="major")
        1
    """
    level_to_parts = {"major": 1, "minor": 2, "patch": 3}
    if level not in level_to_parts:
        raise ValueError(
            "Invalid level specified; choose 'major', 'minor', or 'patch'."
        )
    parts_to_check = level_to_parts[level]

    va = parse_version(version_a)
    vb = parse_version(version_b)

    # Pad with zeros if necessary
    while len(va) < parts_to_check:
        va.append(0)
    while len(vb) < parts_to_check:
        vb.append(0)

    # Compare component-wise using tuple comparison
    if tuple(va[:parts_to_check]) < tuple(vb[:parts_to_check]):
        return -1
    elif tuple(va[:parts_to_check]) > tuple(vb[:parts_to_check]):
        return 1
    return 0


def compare_schema_versions(
    schema_ver_a: int | None,
    version_a: str | None,
    version_b: str = settings.VERSION.split("-")[0],
    schema_ver_b: int = settings.SCHEMA_VERSION,
    level: Literal["major", "minor", "patch"] = "patch",
):
    """
    Compares the schema version in a backup with the current schema version,
    falling back to a semantic version comparison if no schema version is provided.

    Parameters:
        schema_ver_a (int): The schema version stored in the backup.
        version_a (str): The application version stored in the backup (e.g., '1.2.3').
        version_b (str, optional): The current application version. Defaults to
                                   `settings.VERSION.split("-")[0]`.
        schema_ver_b (int, optional): The current schema version. Defaults to
                                      `settings.SCHEMA_VERSION`.
        level (str, optional): Granularity to compare for the semantic version check:
                               'major' (first component), 'minor' (first two components),
                               or 'patch' (all three components). Defaults to 'patch'.

    Raises:
        ValidationError: If the backup's schema version is greater than the current schema version,
                        or if the backup's version is not compatible with the current version.

    Logs:
        - Logs an info message if a schema version is found in the backup.
        - Logs an error and raises a `ValidationError` if the backup's schema version
          is greater than the current schema version.
        - Logs an info message if no schema version is found and falls back to a
          semantic version comparison.
        - Logs an error and raises a `ValidationError` if the backup version is
          greater than or incompatible with the current version.

    Example:
        >>> compare_schema_versions(3, "1.2.0", "1.3.0", schema_ver_b=3, level="minor")
        # No error raised, schema versions match, versions are not checked.

        >>> compare_schema_versions(4, schema_ver_b=3, level="minor")
        ValidationError: {'error': 'backupGreaterVersionError'}

        >>> compare_schema_versions(None, "1.4.0", "1.3.0", level="minor")
        ValidationError: {'error': 'backupGreaterVersionError'}
    """
    if schema_ver_a is not None:
        logger.info(
            "Schema version found in backup",
            backup_schema_version=schema_ver_a,
        )
        if schema_ver_a > schema_ver_b:
            logger.error(
                "Backup schema version greater than current schema version",
                backup_schema_version=schema_ver_a,
                ciso_assistant_schema_version=schema_ver_b,
            )
            raise ValidationError({"error": "backupGreaterVersionError"})
        elif schema_ver_a < schema_ver_b:
            logger.info(
                "Backup schema version less than current schema version",
                backup_schema_version=schema_ver_a,
                ciso_assistant_schema_version=schema_ver_b,
            )
            raise ValidationError({"error": "backupLowerVersionError"})
        logger.info("Schema version in backup matches current schema version")
    else:
        logger.info(
            "Schema version not found in backup, using version instead",
            import_version=version_a,
        )
        current_version = version_b

        # Compare backup and current versions at the 'minor' level
        cmp_minor = compare_versions(version_a, current_version, level="minor")
        if cmp_minor == 1:
            logger.error(
                "Backup version greater than current version",
                version=version_a,
            )
            raise ValidationError({"error": "backupGreaterVersionError"})
        elif cmp_minor != 0:
            logger.error(
                f"Import version {version_a} not compatible with current version {current_version}"
            )
            raise ValidationError(
                {"error": "importVersionNotCompatibleWithCurrentVersion"}
            )


def time_state(date_str: str) -> dict:
    """
    Determine the state based on the provided date string.

    Args:
        date_str (str): Date string in ISO 8601 format.

    Returns:
        dict: A dictionary with 'name' and 'hexcolor' keys indicating the state.
              - 'incoming' if the date is in the future.
              - 'outdated' if the date is in the past.
              - 'today' if the date exactly matches the current time.
    """
    # Parse the date string
    eta = datetime.fromisoformat(date_str)
    # Get the current date and time. If eta contains timezone info, use it.
    now = datetime.now(eta.tzinfo) if eta.tzinfo else datetime.now()

    if eta > now:
        return {"name": "incoming", "hexcolor": "#93c5fd"}
    elif eta < now:
        return {"name": "outdated", "hexcolor": "#f87171"}
    else:
        return {"name": "today", "hexcolor": "#fbbf24"}


def _convert_to_python_weekday(day):
    """Converts from 0=Sunday to 0=Monday weekday format"""
    return (day - 1) % 7


def _get_month_range(year, month):
    """Returns first and last day of given month"""
    first_day = date(year, month, 1)
    last_day = date(year, month, calendar.monthrange(year, month)[1])
    return first_day, last_day


def _get_nth_weekday_of_month(year, month, weekday, n):
    """Gets the nth occurrence of a specific weekday in a month"""
    first_day, last_day = _get_month_range(year, month)

    if n < 0:  # Handle negative indexing (from end of month)
        current_date = last_day
        count = 0
        while current_date >= first_day:
            if current_date.weekday() == weekday:
                count -= 1
                if count == n:
                    return current_date
            current_date -= timedelta(days=1)
        return None
    else:  # Handle positive indexing (from start of month)
        current_date = first_day
        days_to_add = (weekday - current_date.weekday()) % 7
        first_occurrence = current_date + timedelta(days=days_to_add)
        target_date = first_occurrence + timedelta(days=(n - 1) * 7)

        # Check if still in same month
        return target_date if target_date.month == month else None


def _date_matches_schedule(task, date_to_check):
    """Checks if a given date matches the schedule pattern"""
    schedule = task.schedule
    frequency = schedule.get("frequency")

    if frequency == "DAILY":
        return True

    # Python's weekday() returns 0 for Monday, 6 for Sunday
    # Convert to 0=Sunday, 6=Saturday for our system
    weekday = date_to_check.weekday()
    adjusted_weekday = (weekday + 1) % 7

    if frequency == "WEEKLY":
        days_of_week = schedule.get("days_of_week", [])
        return not days_of_week or adjusted_weekday in days_of_week

    elif frequency == "MONTHLY":
        days_of_week = schedule.get("days_of_week", [])
        weeks_of_month = schedule.get("weeks_of_month", [])

        # If both are empty, any day matches
        if not days_of_week and not weeks_of_month:
            return True

        # Check days of week if specified
        if days_of_week and adjusted_weekday not in days_of_week:
            return False

        # Check weeks of month if specified
        if weeks_of_month:
            # Calculate which occurrence of the weekday it is in the month
            first_day = date(date_to_check.year, date_to_check.month, 1)
            first_matching_day = first_day

            while first_matching_day.weekday() != weekday:
                first_matching_day += timedelta(days=1)

            occurrence = ((date_to_check.day - first_matching_day.day) // 7) + 1

            # Check if it's the last occurrence (-1)
            if -1 in weeks_of_month:
                next_month = date(
                    date_to_check.year + (1 if date_to_check.month == 12 else 0),
                    1 if date_to_check.month == 12 else date_to_check.month + 1,
                    1,
                )
                last_day = next_month - timedelta(days=1)
                last_matching_day = last_day

                while last_matching_day.weekday() != weekday:
                    last_matching_day -= timedelta(days=1)

                if date_to_check == last_matching_day:
                    return True

            return occurrence in weeks_of_month

        return True

    elif frequency == "YEARLY":
        months_of_year = schedule.get("months_of_year", [])
        days_of_week = schedule.get("days_of_week", [])
        weeks_of_month = schedule.get("weeks_of_month", [])

        # Check month
        if months_of_year and date_to_check.month not in months_of_year:
            return False

        # If no further restrictions, any day in valid months matches
        if not days_of_week and not weeks_of_month:
            return True

        # Check day of week
        if days_of_week and adjusted_weekday not in days_of_week:
            return False

        # Check week of month
        if weeks_of_month:
            first_day = date(date_to_check.year, date_to_check.month, 1)
            first_matching_day = first_day
            while first_matching_day.weekday() != weekday:
                first_matching_day += timedelta(days=1)
            occurrence = ((date_to_check.day - first_matching_day.day) // 7) + 1

            # Check for last week special case (-1)
            if -1 in weeks_of_month:
                last_day_num = calendar.monthrange(
                    date_to_check.year, date_to_check.month
                )[1]
                last_date = date(date_to_check.year, date_to_check.month, last_day_num)
                last_matching_day = last_date
                while last_matching_day.weekday() != weekday:
                    last_matching_day -= timedelta(days=1)
                if date_to_check == last_matching_day:
                    return True

            return occurrence in weeks_of_month

        return True

    return False


def _calculate_next_occurrence(task, base_date):
    """Calculates the next occurrence date based on the schedule"""
    if not task.schedule:
        return None

    schedule = task.schedule
    frequency = schedule.get("frequency")
    interval = schedule.get("interval", 1)

    if frequency == "DAILY":
        return base_date + timedelta(days=interval)

    elif frequency == "WEEKLY":
        days_of_week = schedule.get("days_of_week", [])

        if not days_of_week:
            return base_date + timedelta(weeks=interval)

        current_weekday = base_date.weekday()
        current_dow_adjusted = (current_weekday + 1) % 7
        sorted_days = sorted(days_of_week)

        # Find next day in the same week
        next_day = next(
            (day for day in sorted_days if day > current_dow_adjusted), None
        )

        if next_day is not None:
            # Calculate days to add
            python_weekday = _convert_to_python_weekday(next_day)
            days_to_add = (python_weekday - current_weekday) % 7
            if days_to_add == 0:  # Same day next week
                days_to_add = 7
            return base_date + timedelta(days=days_to_add)
        else:
            # Move to first day of next week
            first_day_next_week = sorted_days[0]
            python_weekday = _convert_to_python_weekday(first_day_next_week)
            days_to_add = (python_weekday - current_weekday) % 7
            if days_to_add == 0:  # Same day next week
                days_to_add = 7
            days_to_add += 7 * (interval - 1)  # Add interval weeks
            return base_date + timedelta(days=days_to_add)

    elif frequency == "MONTHLY":
        days_of_week = schedule.get("days_of_week", [])
        weeks_of_month = schedule.get("weeks_of_month", [])

        if not days_of_week and not weeks_of_month:
            return base_date + rd.relativedelta(months=interval)

        # Check remaining days in current month first
        next_date = base_date + timedelta(days=1)
        while next_date.month == base_date.month:
            if _date_matches_schedule(task, next_date):
                return next_date
            next_date += timedelta(days=1)

        # Calculate for next month(s)
        target_month = base_date.month + interval
        target_year = base_date.year

        # Adjust year if needed
        while target_month > 12:
            target_month -= 12
            target_year += 1

        possible_dates = []

        if weeks_of_month and days_of_week:
            for week in sorted(weeks_of_month):
                for day in sorted(days_of_week):
                    python_weekday = _convert_to_python_weekday(day)

                    if week < 0:  # Last occurrence of weekday
                        last_day = calendar.monthrange(target_year, target_month)[1]
                        last_date = date(target_year, target_month, last_day)

                        # Find last occurrence of this weekday
                        days_diff = (last_date.weekday() - python_weekday) % 7
                        if days_diff > 0:
                            target_date = last_date - timedelta(days=days_diff)
                        else:
                            target_date = last_date - timedelta(days=7 - days_diff)

                        if target_date.month == target_month:
                            possible_dates.append(target_date)
                    else:
                        target_date = _get_nth_weekday_of_month(
                            target_year, target_month, python_weekday, week
                        )
                        if target_date:
                            possible_dates.append(target_date)
        else:
            # Use same day in next month(s)
            day = min(base_date.day, calendar.monthrange(target_year, target_month)[1])
            possible_dates.append(date(target_year, target_month, day))

        # Return earliest date after base_date
        valid_dates = [d for d in possible_dates if d > base_date]
        if valid_dates:
            return min(valid_dates)

        # Try next interval if no valid dates found
        return _calculate_next_occurrence(
            task, base_date + rd.relativedelta(months=interval)
        )

    elif frequency == "YEARLY":
        months_of_year = schedule.get("months_of_year", [])
        days_of_week = schedule.get("days_of_week", [])
        weeks_of_month = schedule.get("weeks_of_month", [])

        if not months_of_year and not days_of_week and not weeks_of_month:
            return base_date + rd.relativedelta(years=interval)

        target_year = base_date.year

        # If we're past all months in current year, move to next year
        if months_of_year and base_date.month > max(months_of_year):
            target_year += interval
        elif base_date.month == 12:  # End of year case
            target_year += interval

        sorted_months = sorted(months_of_year) if months_of_year else [base_date.month]
        possible_dates = []

        for month in sorted_months:
            if not days_of_week and not weeks_of_month:
                # Same day each year
                last_day_of_month = calendar.monthrange(target_year, month)[1]
                day = min(base_date.day, last_day_of_month)
                possible_dates.append(date(target_year, month, day))
            elif weeks_of_month and days_of_week:
                # Specific week/day combinations
                for week in sorted(weeks_of_month):
                    for day in sorted(days_of_week):
                        python_weekday = _convert_to_python_weekday(day)

                        if week < 0:  # From end of month
                            target_date = _get_nth_weekday_of_month(
                                target_year, month, python_weekday, week
                            )
                            if target_date:
                                possible_dates.append(target_date)
                        else:
                            target_date = _get_nth_weekday_of_month(
                                target_year, month, python_weekday, week
                            )
                            if target_date:
                                possible_dates.append(target_date)
            elif days_of_week:
                # All occurrences of specified weekdays in month
                for day in range(1, calendar.monthrange(target_year, month)[1] + 1):
                    check_date = date(target_year, month, day)
                    adjusted_weekday = (check_date.weekday() + 1) % 7
                    if adjusted_weekday in days_of_week:
                        possible_dates.append(check_date)
            else:
                # Just specified weeks of month
                day = min(base_date.day, calendar.monthrange(target_year, month)[1])
                possible_dates.append(date(target_year, month, day))

        # Return earliest date after base_date
        valid_dates = [d for d in possible_dates if d > base_date]
        if valid_dates:
            return min(valid_dates)

        # If no valid dates, try next interval
        return date(target_year + interval, sorted_months[0], 1)

    return None


def _create_task_dict(task, task_date):
    """Creates a dictionary representing a future task based on the template."""

    # Create task dictionary with all necessary properties
    task_dict = {
        "id": task.id,
        "virtual": True,
        "name": task.name,
        "description": task.description,
        "due_date": task_date,
        "status": "pending",
        "task_template": task.id,
    }

    return task_dict


def _generate_occurrences(template, start_date, end_date):
    """Generates future occurrences for a task template."""
    occurrences = []

    if not template.schedule:
        return occurrences

    # Determine start date
    base_date = template.task_date or datetime.now().date()

    # Get recurrence settings
    end_recurrence_date = None
    end_recurrence_date_str = template.schedule.get("end_date")
    if end_recurrence_date_str:
        end_recurrence_date = datetime.strptime(
            end_recurrence_date_str, "%Y-%m-%d"
        ).date()
        if end_recurrence_date < start_date:
            return occurrences  # Recurrence ended before our range

    max_occurrences = template.schedule.get("occurrences")

    # Find first occurrence on or after start_date
    current_date = base_date
    while current_date < start_date:
        next_date = _calculate_next_occurrence(template, current_date)
        if not next_date or (end_recurrence_date and next_date > end_recurrence_date):
            return occurrences  # No occurrences in our range
        current_date = next_date

    occurrence_count = 0

    # Generate occurrences in the date range
    while current_date and current_date <= end_date:
        # Check if recurrence has ended
        if (end_recurrence_date and current_date > end_recurrence_date) or (
            max_occurrences and occurrence_count >= max_occurrences
        ):
            break

        # Generate task if date matches schedule pattern
        if _date_matches_schedule(template, current_date):
            occurrences.append(_create_task_dict(template, current_date))
            occurrence_count += 1

        # Calculate next date
        current_date = _calculate_next_occurrence(template, current_date)

    return occurrences


def _is_question_visible(question, answers_by_urn, questions_by_urn=None, visited=None):
    """Check if a question is visible based on depends_on logic.

    Works with Question model objects (new relational models).
    - question: a Question model instance
    - answers_by_urn: dict of {question.urn: answer_value}
    - questions_by_urn: dict of {question.urn: Question} (optional, for lookups)
    - visited: set of urns already visited (cycle protection)
    """
    depends_on = (
        question.depends_on
        if hasattr(question, "depends_on")
        else question.get("depends_on")
        if isinstance(question, dict)
        else None
    )
    if not depends_on:
        return True

    dep_ref = depends_on.get("question") if isinstance(depends_on, dict) else None
    if not dep_ref:
        return True

    # Cycle protection
    if visited is None:
        visited = set()
    q_urn = getattr(question, "urn", None) or (
        question.get("urn") if isinstance(question, dict) else None
    )
    if q_urn:
        if q_urn in visited:
            return True
        visited = visited | {q_urn}

    # Check parent question visibility first (recursive chain)
    if questions_by_urn:
        parent_question = questions_by_urn.get(dep_ref)
        if parent_question and not _is_question_visible(
            parent_question, answers_by_urn, questions_by_urn, visited
        ):
            return False

    target_answer = answers_by_urn.get(dep_ref)
    # Use explicit None/empty-list check to avoid hiding on falsy values like 0 or False
    if target_answer is None or (isinstance(target_answer, list) and not target_answer):
        return False

    condition = depends_on.get("condition", "any")
    dep_answers = depends_on.get("answers", [])

    if condition == "any":
        if isinstance(target_answer, list):
            return any(a in dep_answers for a in target_answer)
        return target_answer in dep_answers

    if condition == "all":
        if isinstance(target_answer, list):
            return all(a in target_answer for a in dep_answers)
        # Single-value answer can only satisfy "all" if there's exactly one expected answer
        return len(dep_answers) == 1 and target_answer == dep_answers[0]

    return False


def build_answers_dict(answers_qs):
    """Build {question.urn: answer_value} dict from Answer queryset for backward compat.

    For choice-type questions, returns ref_id strings (single choice) or lists
    of ref_id strings (multiple choice). For other types, returns the raw value.
    """
    from core.models import Question

    result = {}
    for a in answers_qs:
        if a.question.type == Question.Type.UNIQUE_CHOICE:
            refs = [c.urn for c in a.selected_choices.all()]
            result[a.question.urn] = refs[0] if refs else None
        elif a.question.type == Question.Type.MULTIPLE_CHOICE:
            result[a.question.urn] = [c.urn for c in a.selected_choices.all()]
        else:
            result[a.question.urn] = a.value
    return result


def _build_answer_context(questions_qs, answers_qs):
    """Build lookup dicts used for question visibility and score computation.

    Returns (selected_choice_pks_by_qid, answers_by_urn, questions_by_urn, has_answer_by_qid).
    """
    from core.models import Question

    selected_choice_pks_by_qid = {}
    answers_by_urn = {}
    questions_by_urn = {}
    has_answer_by_qid = {}

    for a in answers_qs:
        q_type = a.question.type
        if q_type in (
            Question.Type.UNIQUE_CHOICE,
            Question.Type.MULTIPLE_CHOICE,
        ):
            pks = {c.id for c in a.selected_choices.all()}
            selected_choice_pks_by_qid[a.question_id] = pks
            has_answer_by_qid[a.question_id] = len(pks) > 0
        else:
            has_answer_by_qid[a.question_id] = a.value is not None and a.value != ""

        if a.question.urn:
            answers_by_urn[a.question.urn] = a.get_choice_urns() or a.value

    for q in questions_qs:
        questions_by_urn[q.urn] = q

    return (
        selected_choice_pks_by_qid,
        answers_by_urn,
        questions_by_urn,
        has_answer_by_qid,
    )


def update_selected_implementation_groups(compliance_assessment):
    """Recalculate dynamic IGs from visible answers, preserving manually-picked ones.

    An IG is "dynamic" iff at least one QuestionChoice in the framework lists it in
    select_implementation_groups. Those get fully recomputed here. Any other IG already
    on the assessment is treated as a manual pick and left untouched.
    """
    from core.models import Answer, Question, QuestionChoice

    dynamic_eligible_igs: set[str] = set()
    for select_list in QuestionChoice.objects.filter(
        question__requirement_node__framework=compliance_assessment.framework,
        select_implementation_groups__isnull=False,
    ).values_list("select_implementation_groups", flat=True):
        if select_list:
            dynamic_eligible_igs.update(select_list)

    igs_to_select: set[str] = set()

    requirement_assessments = (
        compliance_assessment.requirement_assessments.select_related(
            "requirement", "requirement__framework"
        )
        .prefetch_related(
            "answers",
            "answers__question",
            "answers__selected_choices",
            "requirement__questions",
            "requirement__questions__choices",
        )
        .all()
    )

    for ra in requirement_assessments:
        questions_qs = ra.requirement.questions.all()
        if not questions_qs:
            continue

        answers_qs = ra.answers.all()
        (
            selected_choice_pks_by_qid,
            answers_by_urn,
            questions_by_urn,
            has_answer_by_qid,
        ) = _build_answer_context(questions_qs, answers_qs)

        for question in questions_qs:
            if not _is_question_visible(question, answers_by_urn, questions_by_urn):
                continue

            if not has_answer_by_qid.get(question.id):
                continue

            selected_pks = selected_choice_pks_by_qid.get(question.id, set())
            for choice in question.choices.all():
                if choice.id in selected_pks:
                    igs_to_select.update(choice.select_implementation_groups or [])

        if ra.requirement.framework.implementation_groups_definition:
            for ig in ra.requirement.framework.implementation_groups_definition:
                if ig.get("default_selected"):
                    igs_to_select.add(ig["ref_id"])

    current = set(compliance_assessment.selected_implementation_groups or [])
    manual_only = current - dynamic_eligible_igs

    compliance_assessment.selected_implementation_groups = list(
        manual_only | igs_to_select
    )
    compliance_assessment.save(update_fields=["selected_implementation_groups"])


def build_questions_dict(node):
    """Reconstruct the JSON-format questions dict from relational Question/QuestionChoice models.

    Returns a dict like {urn: {type, text, choices, ...}} or None for unsaved objects
    or nodes with no questions.
    """
    if node.pk is None:
        return None

    from core.models import Question

    questions_qs = node.questions.all()

    if not questions_qs:
        return None

    result = {}
    for question in questions_qs:
        choices = []
        for choice in question.choices.all():
            choice_data = {
                "urn": choice.urn,
                "value": choice.value or "",
            }
            if choice.add_score is not None:
                choice_data["add_score"] = choice.add_score
            if choice.compute_result is not None:
                resolved = resolve_compute_result(choice.compute_result)
                if resolved is not None:
                    choice_data["compute_result"] = resolved
            if choice.description:
                choice_data["description"] = choice.description
            if choice.color:
                choice_data["color"] = choice.color
            if choice.select_implementation_groups:
                choice_data["select_implementation_groups"] = (
                    choice.select_implementation_groups
                )
            if choice.annotation:
                choice_data["annotation"] = choice.annotation
            choices.append(choice_data)

        q_data = {
            "type": question.type,
            "text": question.text or "",
            "weight": question.weight,
        }
        if question.annotation:
            q_data["annotation"] = question.annotation
        if choices:
            q_data["choices"] = choices
        if question.depends_on:
            q_data["depends_on"] = question.depends_on
        result[question.urn] = q_data

    return result if result else None


AUDITOR_VIEW_PERM = "view_compliance_assessment_full"
AUDIT_ACCESS_PERM = "view_complianceassessment"


def get_full_view_compliance_assessment_ids(user):
    """Return lazy IDs readable both generically and with full auditor scope."""
    from django.contrib.auth.models import Permission

    from core.models import ComplianceAssessment
    from iam.models import RoleAssignment

    generic_ids = RoleAssignment.get_viewable_object_ids(user, ComplianceAssessment)
    full_permission = Permission.objects.get(
        codename=AUDITOR_VIEW_PERM,
        content_type__app_label="core",
        content_type__model="complianceassessment",
    )
    full_folder_ids = RoleAssignment.get_allowed_folder_ids(user, full_permission)
    return ComplianceAssessment.objects.filter(
        id__in=generic_ids,
        folder_id__in=full_folder_ids,
    ).values_list("id", flat=True)


def has_full_view_compliance_assessment(user, compliance_assessment) -> bool:
    """Return whether *user* may consume the assessment's complete data set.

    Callers normally already proved generic access to ``compliance_assessment``.
    Keeping this as an explicit second gate makes published/future read paths
    default to the respondent boundary unless the dedicated full-view
    permission is also present.
    """
    from core.models import ComplianceAssessment

    return ComplianceAssessment.objects.filter(
        id=compliance_assessment.id,
        id__in=get_full_view_compliance_assessment_ids(user),
    ).exists()


def get_respondent_scoped_folder_ids(user) -> set[UUID]:
    """Return folder IDs where *user* sees audits as a **respondent** — i.e. the
    scoped, field-stripped view applies.

    A user is a respondent on a folder when they can access compliance
    assessments there (``view_complianceassessment``) but have NOT been granted
    the full auditor view (``view_compliance_assessment_full``). This is permission-based and
    **default-deny**: any role not explicitly granted ``view_compliance_assessment_full`` is
    treated as a respondent. Auditor-side roles (reader, approver, analyst,
    domain-manager, administrator) hold ``view_compliance_assessment_full`` and are therefore
    excluded; auditee and third-party respondent do not and are included.

    Uses the IAM snapshot caches exclusively (no extra DB queries).
    """
    from iam.models import RoleAssignment

    perms_per_folder = RoleAssignment.get_permissions_per_folder(
        user, is_recursive=True
    )
    return {
        UUID(folder_id)
        for folder_id, codenames in perms_per_folder.items()
        if AUDIT_ACCESS_PERM in codenames and AUDITOR_VIEW_PERM not in codenames
    }


def get_authorized_requirement_assessment_ids(
    user,
    compliance_assessment,
    *,
    respondent_scope: bool | None = None,
):
    """Return a lazy queryset of requirement-assessment IDs *user* may consume.

    Generic folder IAM is always enforced.  A respondent is additionally
    restricted to requirement assignments naming one of their actors.  The
    queryset is deliberately suitable for use as an ORM subquery so callers
    can constrain relationship queries without materialising broad ID lists.
    """
    from core.models import (
        Actor,
        ComplianceAssessment,
        RequirementAssessment,
        RequirementAssignment,
    )
    from iam.models import RoleAssignment

    if respondent_scope is None:
        respondent_scope = not has_full_view_compliance_assessment(
            user, compliance_assessment
        )

    authorized = RequirementAssessment.objects.filter(
        compliance_assessment=compliance_assessment,
        compliance_assessment_id__in=RoleAssignment.get_viewable_object_ids(
            user, ComplianceAssessment
        ),
        id__in=RoleAssignment.get_viewable_object_ids(user, RequirementAssessment),
    )
    if respondent_scope:
        user_actors = Actor.get_all_for_user(user)
        assigned_ids = RequirementAssignment.objects.filter(
            compliance_assessment=compliance_assessment,
            actor__in=user_actors,
        ).values_list("requirement_assessments__id", flat=True)
        authorized = authorized.filter(id__in=assigned_ids)
    else:
        # Re-prove the authority-bearing full-view grant in the same lazy SQL
        # that returns rows.  A grant revoked after the role classification
        # above therefore fails closed instead of widening to the full audit.
        authorized = authorized.filter(
            compliance_assessment_id__in=get_full_view_compliance_assessment_ids(user)
        )

    return authorized.values_list("id", flat=True)


def scope_requirement_assessments_for_user(
    user, compliance_assessment, requirement_assessments
) -> tuple[list, bool]:
    """Preserve audit order while applying the respondent assignment boundary.

    Returns ``(scoped_rows, is_respondent)`` so response builders can also
    suppress auditor-only overlays without recomputing the classification.
    Every caller crosses generic ``view_requirementassessment`` IAM; respondents
    additionally cross the actor-assignment boundary.
    """
    is_respondent = not has_full_view_compliance_assessment(user, compliance_assessment)
    authorized_ids = get_authorized_requirement_assessment_ids(
        user,
        compliance_assessment,
        respondent_scope=is_respondent,
    )
    if hasattr(requirement_assessments, "filter"):
        return (
            list(requirement_assessments.filter(id__in=authorized_ids)),
            is_respondent,
        )

    authorized_id_set = set(authorized_ids)
    return [
        row for row in requirement_assessments if row.id in authorized_id_set
    ], is_respondent


# --- Field Visibility ---
#
# The compliance assessment's `field_visibility` is the single source of truth
# at runtime. It is populated at CA creation from DEFAULT_VISIBILITY merged with
# the framework's `field_visibility`, and can be edited per-CA from then on.
#
# Storage shape: {field_name: {role: 'edit'|'read'|'hidden'}}
# Roles known today: 'auditor', 'respondent'. Future roles slot in alongside.
# A missing field key, or a missing role within a field's pair, resolves to 'edit'
# (matching the "no restriction" default).

EVERYONE_EDIT = {"auditor": "edit", "respondent": "edit"}
AUDITOR_ONLY = {"auditor": "edit", "respondent": "hidden"}
AUDITOR_READ_ONLY = {"auditor": "read", "respondent": "hidden"}
HIDDEN = {"auditor": "hidden", "respondent": "hidden"}

DEFAULT_VISIBILITY = {
    "score": HIDDEN,
    "is_scored": HIDDEN,
    "documentation_score": HIDDEN,
    "status": AUDITOR_ONLY,
    "extended_result": AUDITOR_ONLY,
    # respondent_alignment is only ever populated by the respondent answering
    # the auto-question. AUDITOR_ONLY would prevent that, so the auditor's
    # badge would never render — functionally equivalent to HIDDEN. Default
    # off; auditors who want it explicitly flip to "Auditor + Respondent".
    "respondent_alignment": HIDDEN,
}


def resolve_visibility_from_overrides(overrides, field_name):
    """Resolve a field's visibility pair from a raw `field_visibility` dict.

    Shape: {role: 'edit'|'read'|'hidden'}.

    Lookup order:
      1. Explicit override in `overrides`.
      2. DEFAULT_VISIBILITY (backstop in case a new field was added in code
         without a migration to backfill existing CAs).
      3. EVERYONE_EDIT (truly unknown field).

    Use this when you have a raw dict (e.g. from a queryset `.values()` call).
    For a model instance, prefer `resolve_field_visibility(ca, field)`.
    """
    # is_score_overridden inherits score's visibility.
    if field_name == "is_score_overridden":
        field_name = "score"
    pair = (overrides or {}).get(field_name)
    if isinstance(pair, dict):
        return pair
    fallback = DEFAULT_VISIBILITY.get(field_name)
    if isinstance(fallback, dict):
        return dict(fallback)
    return dict(EVERYONE_EDIT)


def resolve_field_visibility(compliance_assessment, field_name):
    """Return the per-role visibility pair for a field on a CA instance."""
    overrides = getattr(compliance_assessment, "field_visibility", None) or {}
    # Legacy assessments may have an entirely empty snapshot.  Their detail
    # serializer and progress calculation already fall back to the framework
    # template; authority-bearing runtime checks must resolve the same policy.
    # A non-empty assessment snapshot remains authoritative even when one key
    # is absent, preserving the normal DEFAULT_VISIBILITY fallback semantics.
    if not overrides:
        framework = getattr(compliance_assessment, "framework", None)
        overrides = getattr(framework, "field_visibility", None) or {}
    return resolve_visibility_from_overrides(overrides, field_name)


def _role_access(compliance_assessment, field_name, role):
    pair = resolve_field_visibility(compliance_assessment, field_name)
    return pair.get(role, "edit")


def is_field_visible_to(compliance_assessment, field_name, role):
    """Whether a field is readable by the given role."""
    return _role_access(compliance_assessment, field_name, role) != "hidden"


def get_authorized_compliance_progress_projections(user, assessments):
    """Return caller-scoped progress projections for a bounded CA collection.

    ``ComplianceAssessment.progress`` is intentionally the complete-audit
    metric.  API list/detail callers can instead be assignment-scoped and can
    have independent IAM on requirement nodes, questions, choices, and answers.
    Computing a percentage before crossing those boundaries discloses hidden
    work through the numerator or denominator.  This projector applies the
    exact full-view/assignment axis, generic IAM for every carrier, and the
    caller's field-visibility axis before deriving either percentage.

    The caller is expected to pass the current page (or one detail object), so
    the hydrated row set remains bounded by an API response rather than the
    complete assessment table.
    """
    from collections import defaultdict

    from django.db.models import Prefetch, Q

    from core.models import (
        Actor,
        Answer,
        ComplianceAssessment,
        Question,
        QuestionChoice,
        RequirementAssessment,
        RequirementAssignment,
        RequirementNode,
    )
    from iam.models import RoleAssignment

    assessment_list = list(assessments)
    if not assessment_list:
        return {}
    if user is None or not getattr(user, "is_authenticated", False):
        return {assessment.id: None for assessment in assessment_list}

    assessment_ids = [assessment.id for assessment in assessment_list]
    visible_assessment_ids = set(
        ComplianceAssessment.objects.filter(id__in=assessment_ids)
        .filter(
            id__in=RoleAssignment.get_viewable_object_ids(user, ComplianceAssessment)
        )
        .values_list("id", flat=True)
    )
    full_view_ids = set(
        ComplianceAssessment.objects.filter(id__in=visible_assessment_ids)
        .filter(id__in=get_full_view_compliance_assessment_ids(user))
        .values_list("id", flat=True)
    )
    respondent_ids = visible_assessment_ids - full_view_ids
    assigned_ra_ids = RequirementAssignment.objects.filter(
        compliance_assessment_id__in=respondent_ids,
        actor__in=Actor.get_all_for_user(user),
    ).values_list("requirement_assessments__id", flat=True)

    visible_ra_ids = set(
        RoleAssignment.get_viewable_object_ids(user, RequirementAssessment)
    )
    visible_requirement_ids = set(
        RoleAssignment.get_viewable_object_ids(user, RequirementNode)
    )
    visible_question_ids = set(RoleAssignment.get_viewable_object_ids(user, Question))
    visible_choice_ids = set(
        RoleAssignment.get_viewable_object_ids(user, QuestionChoice)
    )
    visible_answer_ids = set(RoleAssignment.get_viewable_object_ids(user, Answer))

    # Start from the rows belonging to the exact authority axis before applying
    # related-object IAM.  The difference between this set and the hydrated
    # visible set is a completeness signal, not a row that may be silently
    # treated as absent/unfinished in a plausible percentage.
    candidate_rows = list(
        RequirementAssessment.objects.filter(
            compliance_assessment_id__in=visible_assessment_ids,
            requirement__assessable=True,
        )
        .filter(
            Q(compliance_assessment_id__in=full_view_ids) | Q(id__in=assigned_ra_ids)
        )
        .select_related("requirement")
    )

    rows = (
        RequirementAssessment.objects.filter(
            compliance_assessment_id__in=assessment_ids,
            requirement__assessable=True,
            id__in=visible_ra_ids,
            requirement_id__in=visible_requirement_ids,
        )
        .filter(
            compliance_assessment_id__in=RoleAssignment.get_viewable_object_ids(
                user, ComplianceAssessment
            )
        )
        .filter(
            Q(compliance_assessment_id__in=full_view_ids) | Q(id__in=assigned_ra_ids)
        )
        .select_related("requirement")
        .prefetch_related(
            Prefetch(
                "requirement__questions",
                queryset=Question.objects.filter(id__in=visible_question_ids),
            ),
            Prefetch(
                "answers",
                queryset=(
                    Answer.objects.filter(
                        id__in=visible_answer_ids,
                        question_id__in=visible_question_ids,
                    )
                    .select_related("question")
                    .prefetch_related(
                        Prefetch(
                            "selected_choices",
                            queryset=QuestionChoice.objects.filter(
                                id__in=visible_choice_ids
                            ),
                        )
                    )
                ),
            ),
        )
    )
    rows_by_assessment = defaultdict(list)
    for row in rows:
        rows_by_assessment[row.compliance_assessment_id].append(row)

    candidate_rows_by_assessment = defaultdict(list)
    relevant_requirement_ids = set()
    relevant_ra_ids = set()
    for assessment in assessment_list:
        candidates = [
            row
            for row in candidate_rows
            if row.compliance_assessment_id == assessment.id
            and assessment.requirement_matches_selected_groups(row.requirement)
        ]
        candidate_rows_by_assessment[assessment.id] = candidates
        relevant_requirement_ids.update(row.requirement_id for row in candidates)
        relevant_ra_ids.update(row.id for row in candidates)

    all_question_ids_by_requirement = defaultdict(set)
    for requirement_id, question_id in Question.objects.filter(
        requirement_node_id__in=relevant_requirement_ids
    ).values_list("requirement_node_id", "id"):
        all_question_ids_by_requirement[requirement_id].add(question_id)

    relevant_question_ids = (
        set().union(*all_question_ids_by_requirement.values())
        if all_question_ids_by_requirement
        else set()
    )
    all_choice_ids_by_question = defaultdict(set)
    for question_id, choice_id in QuestionChoice.objects.filter(
        question_id__in=relevant_question_ids
    ).values_list("question_id", "id"):
        all_choice_ids_by_question[question_id].add(choice_id)

    all_answer_ids_by_ra = defaultdict(set)
    for ra_id, answer_id in Answer.objects.filter(
        requirement_assessment_id__in=relevant_ra_ids
    ).values_list("requirement_assessment_id", "id"):
        all_answer_ids_by_ra[ra_id].add(answer_id)

    projections = {}
    for assessment in assessment_list:
        if assessment.id not in visible_assessment_ids:
            projections[assessment.id] = None
            continue
        viewer_role = "auditor" if assessment.id in full_view_ids else "respondent"
        scoped_rows = [
            row
            for row in rows_by_assessment[assessment.id]
            if assessment.requirement_matches_selected_groups(row.requirement)
        ]
        question_counts = {
            row.id: row.get_visible_questions_counts() for row in scoped_rows
        }

        answers_visible = is_field_visible_to(assessment, "answers", viewer_role)
        status_visible = is_field_visible_to(assessment, "status", viewer_role)
        result_visible = is_field_visible_to(assessment, "result", viewer_role)
        score_visible = is_field_visible_to(assessment, "score", viewer_role)
        min_score_fallback = (
            assessment.min_score if assessment.min_score is not None else 0
        )
        candidates = candidate_rows_by_assessment[assessment.id]
        base_complete = all(
            row.id in visible_ra_ids and row.requirement_id in visible_requirement_ids
            for row in candidates
        )
        questions_complete = all(
            all_question_ids_by_requirement[row.requirement_id] <= visible_question_ids
            for row in candidates
        )
        choices_complete = all(
            all_choice_ids_by_question[question_id] <= visible_choice_ids
            for row in candidates
            for question_id in all_question_ids_by_requirement[row.requirement_id]
        )
        answers_complete = all(
            all_answer_ids_by_ra[row.id] <= visible_answer_ids for row in candidates
        )
        progress_complete = base_complete and (
            status_visible
            or (
                questions_complete
                and (not answers_visible or (choices_complete and answers_complete))
            )
        )
        answer_projection_complete = (
            base_complete
            and questions_complete
            and choices_complete
            and answers_complete
        )

        assessed_count = 0
        for row in scoped_rows:
            total_questions, answered_questions = question_counts[row.id]
            if status_visible:
                assessed = row.status == RequirementAssessment.Status.DONE
            else:
                result_assessed = (
                    result_visible
                    and row.result != RequirementAssessment.Result.NOT_ASSESSED
                )
                if total_questions:
                    assessed = (
                        result_assessed
                        or (score_visible and row.score is not None)
                        or (answers_visible and answered_questions == total_questions)
                    )
                elif result_visible:
                    assessed = result_assessed
                elif score_visible:
                    resolved_min = (
                        row.requirement.min_score
                        if row.requirement.min_score is not None
                        else min_score_fallback
                    )
                    assessed = row.score is not None and row.score > resolved_min
                else:
                    assessed = False
            if assessed:
                assessed_count += 1

        visible_question_count = sum(total for total, _ in question_counts.values())
        answered_question_count = sum(
            answered for _, answered in question_counts.values()
        )
        projections[assessment.id] = {
            "viewer_role": viewer_role,
            "complete": progress_complete,
            "answers_complete": answer_projection_complete,
            "total_requirements": len(scoped_rows) if progress_complete else None,
            "assessed_requirements": assessed_count if progress_complete else None,
            "progress": (
                int(assessed_count / len(scoped_rows) * 100) if scoped_rows else 0
            )
            if progress_complete
            else None,
            "answers_progress": (
                int(answered_question_count / visible_question_count * 100)
                if answers_visible
                and answer_projection_complete
                and visible_question_count
                else None
            ),
        }

    return projections


def _stored_library_mapping_sets(stored_library):
    """Yield mapping-set dictionaries owned by one StoredLibrary artifact."""

    content = stored_library.content
    if not isinstance(content, dict):
        return
    single = content.get("requirement_mapping_set")
    if isinstance(single, dict):
        yield single
    multiple = content.get("requirement_mapping_sets")
    if isinstance(multiple, list):
        yield from (item for item in multiple if isinstance(item, dict))


def get_mapping_authorization(user):
    """Build an exact generic-IAM snapshot for StoredLibrary-backed mappings.

    ``RequirementMappingSet`` is deliberately absent here. The runtime engine
    consumes mapping entries directly from ``StoredLibrary.content`` and the
    API resource at ``/requirement-mapping-sets/`` is likewise backed by
    ``StoredLibrary``. An edge is admitted only if its owner, both Frameworks,
    and every source/target RequirementNode in the mapping set are readable.
    """

    from core.mappings.engine import (
        MappingAuthorization,
        canonical_mapping_edge_identity,
        mapping_set_with_owner,
    )
    from core.models import Framework, RequirementNode, StoredLibrary
    from django.db.models import Q
    from iam.models import RoleAssignment

    visible_framework_ids = RoleAssignment.get_viewable_object_ids(user, Framework)
    framework_urns = frozenset(
        str(urn).lower()
        for urn in Framework.objects.filter(id__in=visible_framework_ids)
        .exclude(urn__isnull=True)
        .values_list("urn", flat=True)
    )
    visible_node_ids = RoleAssignment.get_viewable_object_ids(user, RequirementNode)
    node_frameworks = {
        str(urn).lower(): str(framework_urn).lower()
        for urn, framework_urn in RequirementNode.objects.filter(
            id__in=visible_node_ids,
            urn__isnull=False,
            framework__urn__isnull=False,
        ).values_list("urn", "framework__urn")
    }
    visible_stored_library_ids = RoleAssignment.get_viewable_object_ids(
        user, StoredLibrary
    )
    edge_identities = set()
    for stored_library in StoredLibrary.objects.filter(
        id__in=visible_stored_library_ids,
        is_loaded=True,
    ).filter(
        Q(content__requirement_mapping_set__isnull=False)
        | Q(content__requirement_mapping_sets__isnull=False)
    ):
        for raw_mapping_set in _stored_library_mapping_sets(stored_library):
            mapping_set = mapping_set_with_owner(raw_mapping_set, stored_library)
            source_urn = mapping_set.get("source_framework_urn")
            target_urn = mapping_set.get("target_framework_urn")
            if not isinstance(source_urn, str) or not isinstance(target_urn, str):
                continue
            source_urn = source_urn.lower()
            target_urn = target_urn.lower()
            if source_urn not in framework_urns or target_urn not in framework_urns:
                continue
            mappings = mapping_set.get("requirement_mappings")
            if not isinstance(mappings, list) or not mappings:
                continue
            complete = True
            for mapping in mappings:
                if not isinstance(mapping, dict):
                    complete = False
                    break
                source_node_urn = mapping.get("source_requirement_urn")
                target_node_urn = mapping.get("target_requirement_urn")
                if not isinstance(source_node_urn, str) or not isinstance(
                    target_node_urn, str
                ):
                    complete = False
                    break
                if (
                    node_frameworks.get(source_node_urn.lower()) != source_urn
                    or node_frameworks.get(target_node_urn.lower()) != target_urn
                ):
                    complete = False
                    break
            identity = canonical_mapping_edge_identity(mapping_set)
            if complete and identity is not None:
                edge_identities.add(identity)

    return MappingAuthorization(
        framework_urns=framework_urns,
        requirement_node_urns=frozenset(node_frameworks),
        edge_identities=frozenset(edge_identities),
    )


def get_mapping_inference_visibility_context(user, mapping_inferences) -> dict:
    """Resolve a complete, canonical mapping-provenance authorization view."""
    from core.mappings.engine import (
        canonical_mapping_edge_identity,
        mapping_set_with_owner,
    )
    from core.models import (
        Framework,
        RequirementAssessment,
        RequirementNode,
        StoredLibrary,
    )
    from iam.models import RoleAssignment

    source_ids: set[UUID] = set()
    source_urns: set[str] = set()
    framework_urns: set[str] = set()
    stored_library_ids: set[UUID] = set()
    for inference in mapping_inferences:
        if not isinstance(inference, dict):
            continue
        used_path = inference.get("used_path")
        if isinstance(used_path, list):
            framework_urns.update(
                item.lower() for item in used_path if isinstance(item, str)
            )
        sources = inference.get("source_requirement_assessments") or {}
        if not isinstance(sources, dict):
            continue
        for source in sources.values():
            if not isinstance(source, dict):
                continue
            try:
                source_ids.add(UUID(str(source.get("id"))))
            except TypeError, ValueError:
                pass
            source_urn = source.get("urn")
            if isinstance(source_urn, str):
                source_urns.add(source_urn.lower())
            source_framework = source.get("source_framework")
            if isinstance(source_framework, dict):
                framework_urn = source_framework.get("urn")
                if isinstance(framework_urn, str):
                    framework_urns.add(framework_urn.lower())
            mapping_set = source.get("used_mapping_set")
            if isinstance(mapping_set, dict):
                try:
                    stored_library_ids.add(UUID(str(mapping_set.get("id"))))
                except TypeError, ValueError:
                    pass

    authorization = get_mapping_authorization(user)
    visible_ra_ids = RoleAssignment.get_viewable_object_ids(user, RequirementAssessment)
    full_ca_ids = get_full_view_compliance_assessment_ids(user)
    visible_node_ids = RoleAssignment.get_viewable_object_ids(user, RequirementNode)
    source_assessments = {
        ra.id: ra
        for ra in RequirementAssessment.objects.filter(
            id__in=source_ids,
            compliance_assessment_id__in=full_ca_ids,
            requirement_id__in=visible_node_ids,
        )
        .filter(id__in=visible_ra_ids)
        .select_related(
            "requirement",
            "compliance_assessment",
            "compliance_assessment__framework",
        )
    }
    requirement_nodes = {
        node.urn.lower(): node
        for node in RequirementNode.objects.filter(
            urn__in=source_urns,
            id__in=visible_node_ids,
        ).select_related("framework")
    }
    visible_framework_ids = RoleAssignment.get_viewable_object_ids(user, Framework)
    frameworks = {
        framework.urn.lower(): framework
        for framework in Framework.objects.filter(
            urn__in=framework_urns,
            id__in=visible_framework_ids,
        )
    }

    visible_stored_library_ids = RoleAssignment.get_viewable_object_ids(
        user, StoredLibrary
    )
    mapping_edges = {}
    duplicate_edges = set()
    for stored_library in StoredLibrary.objects.filter(
        id__in=stored_library_ids,
        is_loaded=True,
    ).filter(id__in=visible_stored_library_ids):
        for raw_mapping_set in _stored_library_mapping_sets(stored_library):
            mapping_set = mapping_set_with_owner(raw_mapping_set, stored_library)
            identity = canonical_mapping_edge_identity(mapping_set)
            mapping_urn = mapping_set.get("urn")
            if identity not in authorization.edge_identities or not isinstance(
                mapping_urn, str
            ):
                continue
            key = (stored_library.id, mapping_urn.lower())
            if key in mapping_edges:
                duplicate_edges.add(key)
            else:
                mapping_edges[key] = mapping_set
    for key in duplicate_edges:
        mapping_edges.pop(key, None)

    return {
        "authorization": authorization,
        "source_assessments": source_assessments,
        "requirement_nodes": requirement_nodes,
        "frameworks": frameworks,
        "mapping_edges": mapping_edges,
    }


def sanitize_mapping_inference_for_viewer(
    mapping_inference,
    compliance_assessment,
    *,
    viewer_role: str,
    visibility_context: dict | None,
    target_result=None,
):
    """Return least-privilege mapping provenance, or ``None`` if unprovable."""
    if viewer_role != "auditor" or not isinstance(mapping_inference, dict):
        return None
    if not isinstance(visibility_context, dict):
        return None

    authorization = visibility_context.get("authorization")
    source_assessments = visibility_context.get("source_assessments") or {}
    requirement_nodes = visibility_context.get("requirement_nodes") or {}
    frameworks = visibility_context.get("frameworks") or {}
    mapping_edges = visibility_context.get("mapping_edges") or {}
    raw_sources = mapping_inference.get("source_requirement_assessments") or {}
    if not isinstance(raw_sources, dict) or not raw_sources:
        return None

    used_path = mapping_inference.get("used_path")
    if (
        authorization is None
        or not isinstance(used_path, list)
        or len(used_path) < 2
        or not all(isinstance(item, str) and item for item in used_path)
    ):
        return None
    canonical_path = [item.lower() for item in used_path]
    if len(canonical_path) != len(set(canonical_path)):
        return None
    target_framework_urn = getattr(compliance_assessment.framework, "urn", None)
    if (
        not isinstance(target_framework_urn, str)
        or canonical_path[-1] != target_framework_urn.lower()
        or any(
            urn not in frameworks or not authorization.allows_framework(urn)
            for urn in canonical_path
        )
    ):
        return None

    sanitized_sources = {}
    used_edge_identities = set()
    for source_key, source in raw_sources.items():
        if not isinstance(source_key, str) or not isinstance(source, dict):
            return None
        source_urn = source.get("urn")
        if not isinstance(source_urn, str) or source_key.lower() != source_urn.lower():
            return None
        source_urn = source_urn.lower()
        source_node = requirement_nodes.get(source_urn)
        if source_node is None or not authorization.allows_requirement_node(source_urn):
            return None

        node_framework_urn = getattr(source_node.framework, "urn", None)
        if not isinstance(node_framework_urn, str):
            return None
        node_framework_urn = node_framework_urn.lower()
        if node_framework_urn not in canonical_path:
            return None
        path_index = canonical_path.index(node_framework_urn)
        if path_index >= len(canonical_path) - 1:
            return None

        raw_framework = source.get("source_framework")
        if not isinstance(raw_framework, dict):
            return None
        try:
            raw_framework_id = UUID(str(raw_framework.get("id")))
        except TypeError, ValueError:
            return None
        if raw_framework_id != source_node.framework_id:
            return None

        raw_mapping_set = source.get("used_mapping_set")
        if not isinstance(raw_mapping_set, dict):
            return None
        try:
            owner_id = UUID(str(raw_mapping_set.get("id")))
        except TypeError, ValueError:
            return None
        mapping_urn = raw_mapping_set.get("urn")
        if not isinstance(mapping_urn, str):
            return None
        mapping_set = mapping_edges.get((owner_id, mapping_urn.lower()))
        if mapping_set is None:
            return None
        from core.mappings.engine import canonical_mapping_edge_identity

        identity = canonical_mapping_edge_identity(mapping_set)
        if identity is None or identity not in authorization.edge_identities:
            return None
        _, owner_urn, _, edge_source, edge_target, _ = identity
        if (
            edge_source != node_framework_urn
            or edge_target != canonical_path[path_index + 1]
        ):
            return None
        raw_owner_urn = raw_mapping_set.get("library_urn")
        if raw_owner_urn is not None and (
            not isinstance(raw_owner_urn, str) or raw_owner_urn.lower() != owner_urn
        ):
            return None
        used_edge_identities.add(identity)

        source_copy = {
            "urn": source_node.urn,
            "str": str(source_node.safe_display_str),
            "source_framework": {
                "id": str(source_node.framework_id),
                "name": source_node.framework.get_name_translated
                or source_node.framework.name,
            },
            "used_mapping_set": {
                "id": str(owner_id),
                "name": mapping_set.get("name"),
                "ref_id": mapping_set.get("ref_id"),
                "urn": mapping_set.get("urn"),
            },
        }
        if source.get("coverage") in {"full", "partial"}:
            source_copy["coverage"] = source["coverage"]

        raw_source_id = source.get("id")
        if raw_source_id is not None:
            try:
                source_id = UUID(str(raw_source_id))
            except TypeError, ValueError:
                return None
            source_assessment = source_assessments.get(source_id)
            if (
                source_assessment is None
                or source_assessment.requirement_id != source_node.id
                or source_assessment.compliance_assessment.framework_id
                != source_node.framework_id
            ):
                return None
            source_ca = source_assessment.compliance_assessment
            source_copy["id"] = str(source_assessment.id)
            source_copy["str"] = str(source_assessment)
            if is_field_visible_to(source_ca, "score", "auditor"):
                source_copy["score"] = source_assessment.score
            if is_field_visible_to(source_ca, "is_scored", "auditor"):
                source_copy["is_scored"] = source_assessment.is_scored
        elif path_index == 0:
            # The first hop must be anchored to an actual authorized source RA.
            return None

        sanitized_sources[source_node.urn] = source_copy

    path_edges = {
        (canonical_path[index], canonical_path[index + 1])
        for index in range(len(canonical_path) - 1)
    }
    represented_edges = {
        (identity[3], identity[4]) for identity in used_edge_identities
    }
    if represented_edges != path_edges or len(sanitized_sources) != len(raw_sources):
        return None
    sanitized = {"source_requirement_assessments": sanitized_sources}
    if is_field_visible_to(compliance_assessment, "result", viewer_role):
        sanitized["result"] = target_result
    sanitized["used_path"] = canonical_path
    annotation = mapping_inference.get("annotation")
    if isinstance(annotation, str):
        sanitized["annotation"] = annotation
    return sanitized


def is_field_editable_by(compliance_assessment, field_name, role):
    """Whether a field is writable by the given role."""
    return _role_access(compliance_assessment, field_name, role) == "edit"


def build_initial_field_visibility(framework):
    """Build the initial `field_visibility` map for a new CA.

    Layered per-role: code defaults are seeded for every known field, then the
    framework's overrides are merged on top — but per-role, so a framework that
    only specifies a single role (e.g. {"score": {"auditor": "edit"}}) does not
    erase the default value for the other roles.
    """
    fw_overrides = getattr(framework, "field_visibility", None) or {}
    merged = {key: dict(pair) for key, pair in DEFAULT_VISIBILITY.items()}
    for key, pair in fw_overrides.items():
        if not isinstance(pair, dict):
            continue
        # Ensure the field has a starting pair (DEFAULT_VISIBILITY may not
        # cover every key the framework configures).
        merged.setdefault(key, dict(EVERYONE_EDIT))
        merged[key].update(pair)
    return merged


def bulk_update_with_log(model, rows, fields, batch_size=500):
    """``bulk_update`` that still leaves a trail: it skips ``post_save``, so
    auditlog logs nothing and workflow events never fire. Writes the entries a
    per-object ``save()`` would. Returns the number of rows that changed."""
    from auditlog.diff import model_instance_diff
    from auditlog.models import LogEntry
    from django.db import transaction

    rows = [row for row in rows if row.pk is not None]
    fields = list(fields)
    if not rows or not fields:
        return 0

    use_json = getattr(settings, "AUDITLOG_STORE_JSON_CHANGES", False)
    logged = 0
    # One transaction: a half-written trail is worse than a failed call.
    with transaction.atomic():
        # Stored values first: after bulk_update there is nothing left to diff.
        # Locked, because at READ COMMITTED two concurrent writers would both
        # read the pre-change value and log the same "from".
        stored = model.objects.select_for_update().in_bulk([row.pk for row in rows])
        model.objects.bulk_update(rows, fields, batch_size=batch_size)
        for row in rows:
            old = stored.get(row.pk)
            if old is None:
                continue
            changes = model_instance_diff(
                old, row, fields_to_check=fields, use_json_for_changes=use_json
            )
            if not changes:
                continue
            # log_create fills content_type, cid and additional_data (folder_id,
            # which the dispatcher scopes on); the middleware fills the actor.
            LogEntry.objects.log_create(
                row, action=LogEntry.Action.UPDATE, changes=changes
            )
            logged += 1
    return logged
