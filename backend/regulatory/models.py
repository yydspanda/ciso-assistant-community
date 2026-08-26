from __future__ import annotations

from copy import deepcopy
from datetime import date, datetime, timezone as datetime_timezone
import hashlib
import json

from django.conf import settings
from django.core.exceptions import ValidationError
from django.core.validators import MaxValueValidator, MinValueValidator
from django.db import models
from django.db.models import F, Q
from django.utils import timezone
from django.utils.dateparse import parse_datetime
from django.utils.translation import gettext_lazy as _

from auditlog.registry import auditlog

from core.base_models import AbstractBaseModel
from iam.models import Folder

from .validators import (
    validate_non_empty_string_list,
    validate_regulatory_domains,
    validate_regulatory_identifier,
    validate_sha256,
    validate_string_list,
)

CORRECTION_DIGEST_SCHEMA = "regulatory-chain-correction/v1"
APPLICABILITY_DIGEST_SCHEMA = "regulatory-applicability-evaluation/v1"
APPLICABILITY_EVALUATOR_PROFILE = "synthetic-single-condition/v1"
APPLICABILITY_REVIEW_DISPOSITION_DIGEST_PROFILE = (
    "regulatory-applicability-review-disposition/v1"
)
APPLICABILITY_REVIEW_PERSISTED_DISPOSITIONS = (
    "no_correction_requested",
    "correction_requested",
    "unable_to_complete",
)
PILOT_APPLICABILITY_SCOPE_TYPE = "legal_entity"
PILOT_APPLICABILITY_FACT_KEY = "entity.institution_type"
PILOT_APPLICABILITY_EXPECTED_VALUE = "bank"
PILOT_APPLICABILITY_RULE_ID = "SYNTHETIC-ENTITY-INSTITUTION-TYPE-BANK-001"
PILOT_APPLICABILITY_RULE_VERSION = 1
PILOT_APPLICABILITY_VALUE_MAX_LENGTH = 100
PILOT_APPLICABILITY_SOURCE_REF_MAX_COUNT = 20
PILOT_APPLICABILITY_SOURCE_REF_MAX_LENGTH = 500
PILOT_APPLICABILITY_RATIONALE_MATCH = (
    "The known institution type matches the fixed synthetic bank rule."
)
PILOT_APPLICABILITY_RATIONALE_NO_MATCH = (
    "The known institution type does not match the fixed synthetic bank rule."
)
PILOT_APPLICABILITY_RATIONALE_MISSING = (
    "The required institution-type fact was missing and was recorded as unknown."
)
PILOT_APPLICABILITY_RATIONALE_UNKNOWN = (
    "The required institution-type fact is explicitly unknown."
)
PILOT_APPLICABILITY_RULE_SNAPSHOT = {
    "id": PILOT_APPLICABILITY_RULE_ID,
    "version": PILOT_APPLICABILITY_RULE_VERSION,
    "all": [
        {
            "fact": PILOT_APPLICABILITY_FACT_KEY,
            "operator": "eq",
            "value": PILOT_APPLICABILITY_EXPECTED_VALUE,
        }
    ],
    "any": [],
    "unknown_result": "needs_review",
}


def _canonical_json_sha256(payload) -> str:
    encoded = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _canonical_temporal_value(value: date | datetime | str | None) -> str | None:
    if isinstance(value, datetime):
        if timezone.is_aware(value):
            value = value.astimezone(datetime_timezone.utc)
        return value.isoformat()
    if isinstance(value, date):
        return value.isoformat()
    return value


class AuthorityLevel(models.TextChoices):
    LAW = "law", _("Law")
    ADMINISTRATIVE_REGULATION = (
        "administrative_regulation",
        _("Administrative regulation"),
    )
    DEPARTMENTAL_RULE = "departmental_rule", _("Departmental rule")
    REGULATORY_NORMATIVE_DOCUMENT = (
        "regulatory_normative_document",
        _("Regulatory normative document"),
    )
    MANDATORY_STANDARD = "mandatory_standard", _("Mandatory standard")
    RECOMMENDED_STANDARD = "recommended_standard", _("Recommended standard")
    INTERNAL_POLICY = "internal_policy", _("Internal policy")
    INTERPRETIVE_MATERIAL = "interpretive_material", _("Interpretive material")
    ENFORCEMENT_MATERIAL = "enforcement_material", _("Enforcement material")


class RegulatoryFolderModel(AbstractBaseModel):
    """IAM-compatible base that protects regulatory history from folder deletion."""

    folder = models.ForeignKey(
        Folder,
        on_delete=models.PROTECT,
        related_name="%(class)s_folder",
        default=Folder.get_root_folder_id,
    )

    class Meta:
        abstract = True

    def clean(self) -> None:
        if self.is_published:
            raise ValidationError(
                {"is_published": "Regulatory records cannot be published in Phase 1."}
            )
        super().clean()

    def save(self, *args, **kwargs) -> None:
        if not self._state.adding:
            raise ValidationError(
                "Regulatory records are append-only; create a successor record instead."
            )
        self.full_clean()
        super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        raise ValidationError("Regulatory records cannot be deleted.")


class TemporalRevisionMixin(models.Model):
    """Portable logical identity plus append-mostly recorded-time revision data."""

    record_id = models.CharField(
        max_length=160,
        validators=[validate_regulatory_identifier],
    )
    revision = models.PositiveIntegerField(default=1)
    previous_revision = models.ForeignKey(
        "self",
        null=True,
        blank=True,
        on_delete=models.PROTECT,
        related_name="+",
    )
    recorded_from = models.DateTimeField(default=timezone.now)
    recorded_to = models.DateTimeField(null=True, blank=True)

    provenance_method = models.CharField(
        max_length=20,
        choices=(
            ("human", _("Human")),
            ("parser", _("Parser")),
            ("model_proposal", _("Model proposal")),
            ("import", _("Import")),
        ),
    )
    provenance_created_at = models.DateTimeField(default=timezone.now)
    provenance_created_by = models.CharField(max_length=300)
    parser_version = models.CharField(max_length=300, null=True, blank=True)
    model_name = models.CharField(max_length=300, null=True, blank=True)
    prompt_version = models.CharField(max_length=300, null=True, blank=True)
    retrieval_version = models.CharField(max_length=300, null=True, blank=True)

    class Meta:
        abstract = True

    def clean(self) -> None:
        errors: dict[str, str] = {}
        if self.recorded_to is not None and self.recorded_to <= self.recorded_from:
            errors["recorded_to"] = "recorded_to must be later than recorded_from."

        previous = self.previous_revision
        if previous is None:
            if self.revision != 1:
                errors["revision"] = "The first recorded revision must be revision 1."
        else:
            if previous.pk == self.pk:
                errors["previous_revision"] = "A revision cannot precede itself."
            if previous.record_id != self.record_id:
                errors["record_id"] = "A predecessor must have the same record_id."
            if previous.folder_id != self.folder_id:
                errors["folder"] = "A predecessor must be in the same folder."
            if self.revision != previous.revision + 1:
                errors["revision"] = "Revision must increment its predecessor by one."
            if previous.recorded_to != self.recorded_from:
                errors["recorded_from"] = (
                    "A successor must begin when its predecessor recorded interval closes."
                )

        if errors:
            raise ValidationError(errors)
        super().clean()

    def provenance_payload(self) -> dict[str, str | None]:
        return {
            "method": self.provenance_method,
            "created_at": self.provenance_created_at.isoformat(),
            "created_by": self.provenance_created_by,
            "parser_version": self.parser_version,
            "model": self.model_name,
            "prompt_version": self.prompt_version,
            "retrieval_version": self.retrieval_version,
        }


class RegulatoryDocument(RegulatoryFolderModel):
    class CoveragePriority(models.TextChoices):
        P0 = "P0", "P0"
        P1 = "P1", "P1"
        P2 = "P2", "P2"

    class CoverageStage(models.TextChoices):
        SOURCE_METADATA = "source_metadata", _("Source metadata")
        PROVISION_INDEXED = "provision_indexed", _("Provision indexed")
        OBLIGATIONS_PROPOSED = "obligations_proposed", _("Obligations proposed")
        OBLIGATIONS_REVIEWED = "obligations_reviewed", _("Obligations reviewed")

    record_id = models.CharField(
        max_length=160,
        validators=[validate_regulatory_identifier],
    )
    title_zh = models.CharField(max_length=1000)
    title_en = models.CharField(max_length=1000, blank=True)
    issuer = models.CharField(max_length=500)
    authority_level = models.CharField(max_length=40, choices=AuthorityLevel.choices)
    territories = models.JSONField(
        default=list,
        validators=[validate_non_empty_string_list],
    )
    regulated_entity_scopes = models.JSONField(
        default=list,
        validators=[validate_non_empty_string_list],
    )
    domains = models.JSONField(default=list, validators=[validate_regulatory_domains])
    coverage_priority = models.CharField(
        max_length=2,
        choices=CoveragePriority.choices,
        blank=True,
    )
    coverage_stage = models.CharField(
        max_length=32,
        choices=CoverageStage.choices,
        default=CoverageStage.OBLIGATIONS_PROPOSED,
    )
    applicability_fact_keys = models.JSONField(
        default=list,
        blank=True,
        validators=[validate_string_list],
    )
    selection_rationale = models.TextField(blank=True, max_length=2000)

    class Meta:
        ordering = ["record_id"]
        constraints = [
            models.UniqueConstraint(
                fields=["folder", "record_id"],
                name="reg_doc_folder_record_uniq",
            ),
            models.CheckConstraint(
                condition=Q(is_published=False),
                name="reg_doc_not_published",
            ),
            models.CheckConstraint(
                condition=Q(coverage_stage="obligations_proposed"),
                name="reg_doc_phase1_proposed",
            ),
        ]
        permissions = [
            (
                "ingest_regulatoryrecord",
                "Can atomically ingest a regulatory record chain",
            ),
            (
                "correct_regulatoryrecord",
                "Can atomically correct a current regulatory record chain",
            ),
        ]

    def __str__(self) -> str:
        return self.title_zh

    def clean(self) -> None:
        if self.coverage_stage != self.CoverageStage.OBLIGATIONS_PROPOSED:
            raise ValidationError(
                {
                    "coverage_stage": (
                        "The first vertical slice persists proposed obligations."
                    )
                }
            )
        super().clean()


class EntityDocumentRegistration(RegulatoryFolderModel):
    """Synthetic pilot register membership; never an applicability conclusion."""

    class RegistrationKind(models.TextChoices):
        SYNTHETIC_PILOT = "synthetic_pilot", _("Synthetic pilot")

    entity = models.ForeignKey(
        "tprm.Entity",
        on_delete=models.PROTECT,
        related_name="regulatory_document_registrations",
    )
    document = models.ForeignKey(
        RegulatoryDocument,
        on_delete=models.PROTECT,
        related_name="entity_registrations",
    )
    registration_kind = models.CharField(
        max_length=32,
        choices=RegistrationKind.choices,
        default=RegistrationKind.SYNTHETIC_PILOT,
    )
    idempotency_key = models.CharField(max_length=200)
    payload_sha256 = models.CharField(max_length=64, validators=[validate_sha256])
    ingested_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.PROTECT,
        related_name="regulatory_chain_ingestions",
    )

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["entity", "document"],
                name="reg_entity_document_uniq",
            ),
            models.UniqueConstraint(
                fields=["folder", "idempotency_key"],
                name="reg_ingest_idempotency_uniq",
            ),
            models.CheckConstraint(
                condition=Q(is_published=False),
                name="reg_entity_doc_not_published",
            ),
        ]

    def clean(self) -> None:
        errors = {}
        if self.entity_id and self.entity.folder_id != self.folder_id:
            errors["entity"] = "The entity must be in the registration folder."
        if self.document_id and self.document.folder_id != self.folder_id:
            errors["document"] = "The document must be in the registration folder."
        if errors:
            raise ValidationError(errors)
        super().clean()


class RegulatoryDocumentVersion(TemporalRevisionMixin, RegulatoryFolderModel):
    class Status(models.TextChoices):
        DRAFT = "draft", _("Draft")
        PUBLISHED_FUTURE_EFFECTIVE = (
            "published_future_effective",
            _("Published, future effective"),
        )
        EFFECTIVE = "effective", _("Effective")
        ACTIVE_NO_EXPLICIT_COMMENCEMENT = (
            "active_no_explicit_commencement",
            _("Active without explicit commencement"),
        )
        SUPERSEDED = "superseded", _("Superseded")
        REPEALED = "repealed", _("Repealed")
        UNKNOWN = "unknown", _("Unknown")

    class EffectiveBasis(models.TextChoices):
        EXPLICIT_DATE = "explicit_date", _("Explicit date")
        PUBLICATION_CLAUSE = "publication_clause", _("Publication clause")
        NO_EXPLICIT_COMMENCEMENT = (
            "no_explicit_commencement_clause",
            _("No explicit commencement clause"),
        )
        UNRESOLVED = "unresolved", _("Unresolved")

    class StoragePolicy(models.TextChoices):
        METADATA_ONLY = "metadata_only", _("Metadata only")
        OFFICIAL_SNAPSHOT = "official_snapshot", _("Official snapshot")
        LICENSED_COPY = "licensed_copy", _("Licensed copy")

    class MetadataConfidence(models.TextChoices):
        CONFIRMED = "confirmed", _("Confirmed")
        PARTIAL = "partial", _("Partial")
        UNRESOLVED = "unresolved", _("Unresolved")

    class LegalReviewStatus(models.TextChoices):
        UNREVIEWED = "unreviewed", _("Unreviewed")
        REVIEWED = "reviewed", _("Reviewed")

    document = models.ForeignKey(
        RegulatoryDocument,
        on_delete=models.PROTECT,
        related_name="versions",
    )
    version_label = models.CharField(max_length=300)
    document_no = models.CharField(max_length=300, null=True, blank=True)
    status = models.CharField(max_length=48, choices=Status.choices)
    status_as_of = models.DateField()
    effective_basis = models.CharField(max_length=48, choices=EffectiveBasis.choices)
    issued_date = models.DateField(null=True, blank=True)
    published_date = models.DateField(null=True, blank=True)
    effective_date = models.DateField(null=True, blank=True)
    transition_end = models.DateField(null=True, blank=True)
    repeal_date = models.DateField(null=True, blank=True)
    source_url = models.URLField(max_length=2048)
    source_hash = models.CharField(
        max_length=64,
        null=True,
        blank=True,
        validators=[validate_sha256],
    )
    content_storage_policy = models.CharField(
        max_length=32,
        choices=StoragePolicy.choices,
    )
    notes = models.TextField(blank=True, max_length=4000)
    source_checked_on = models.DateField()
    metadata_confidence = models.CharField(
        max_length=16,
        choices=MetadataConfidence.choices,
    )
    legal_review_status = models.CharField(
        max_length=16,
        choices=LegalReviewStatus.choices,
        default=LegalReviewStatus.UNREVIEWED,
    )
    legal_reviewed_at = models.DateTimeField(null=True, blank=True)
    legal_reviewed_by = models.CharField(max_length=300, null=True, blank=True)
    valid_from = models.DateField(null=True, blank=True)
    valid_to = models.DateField(null=True, blank=True)

    class Meta:
        ordering = ["record_id", "revision"]
        indexes = [
            models.Index(
                fields=["folder", "document", "recorded_from"],
                name="reg_ver_doc_asof_idx",
            )
        ]
        constraints = [
            models.UniqueConstraint(
                fields=["folder", "record_id", "revision"],
                name="reg_ver_folder_record_rev_uniq",
            ),
            models.UniqueConstraint(
                fields=["folder", "record_id"],
                condition=Q(recorded_to__isnull=True),
                name="reg_ver_one_current",
            ),
            models.CheckConstraint(
                condition=Q(revision__gte=1),
                name="reg_ver_revision_positive",
            ),
            models.CheckConstraint(
                condition=Q(recorded_to__isnull=True)
                | Q(recorded_to__gt=F("recorded_from")),
                name="reg_ver_recorded_interval",
            ),
            models.CheckConstraint(
                condition=Q(valid_to__isnull=True)
                | Q(valid_from__isnull=True)
                | Q(valid_to__gt=F("valid_from")),
                name="reg_ver_valid_interval",
            ),
            models.CheckConstraint(
                condition=(
                    ~Q(status__in=["effective", "published_future_effective"])
                    | Q(valid_from__isnull=False)
                ),
                name="reg_ver_active_valid_from",
            ),
            models.CheckConstraint(
                condition=Q(effective_date__isnull=True)
                | Q(valid_from=F("effective_date")),
                name="reg_ver_effective_valid_from",
            ),
            models.CheckConstraint(
                condition=Q(status_as_of__lte=F("source_checked_on")),
                name="reg_ver_status_source_check",
            ),
            models.CheckConstraint(
                condition=Q(transition_end__isnull=True)
                | (
                    Q(effective_date__isnull=False)
                    & Q(transition_end__gte=F("effective_date"))
                ),
                name="reg_ver_transition_window",
            ),
            models.CheckConstraint(
                condition=(
                    ~Q(status="repealed")
                    | (Q(repeal_date__isnull=False) & Q(valid_to=F("repeal_date")))
                ),
                name="reg_ver_repeal_interval",
            ),
            models.CheckConstraint(
                condition=~Q(status="superseded") | Q(valid_to__isnull=False),
                name="reg_ver_superseded_end",
            ),
            models.CheckConstraint(
                condition=(
                    ~Q(
                        status__in=[
                            "effective",
                            "active_no_explicit_commencement",
                            "published_future_effective",
                        ]
                    )
                    | Q(repeal_date__isnull=True)
                ),
                name="reg_ver_active_not_repealed",
            ),
            models.CheckConstraint(
                condition=Q(content_storage_policy="metadata_only")
                | (Q(source_hash__isnull=False) & ~Q(source_hash="")),
                name="reg_ver_stored_hash",
            ),
            models.CheckConstraint(
                condition=Q(content_storage_policy="metadata_only"),
                name="reg_ver_phase1_metadata_only",
            ),
            models.CheckConstraint(
                condition=(
                    Q(
                        legal_review_status="unreviewed",
                        legal_reviewed_at__isnull=True,
                        legal_reviewed_by__isnull=True,
                    )
                    | (
                        Q(
                            legal_review_status="reviewed",
                            legal_reviewed_at__isnull=False,
                            legal_reviewed_by__isnull=False,
                        )
                        & ~Q(legal_reviewed_by="")
                    )
                ),
                name="reg_ver_legal_review_pair",
            ),
            models.CheckConstraint(
                condition=Q(
                    legal_review_status="unreviewed",
                    legal_reviewed_at__isnull=True,
                    legal_reviewed_by__isnull=True,
                ),
                name="reg_ver_phase1_unreviewed",
            ),
            models.CheckConstraint(
                condition=Q(is_published=False),
                name="reg_ver_not_published",
            ),
        ]

    def clean(self) -> None:
        errors = {}
        if self.document_id and self.document.folder_id != self.folder_id:
            errors["document"] = "The document version must use its document folder."
        if not self.source_url.lower().startswith("https://"):
            errors["source_url"] = "Only HTTPS official-source URLs are accepted."
        if (
            self.content_storage_policy != self.StoragePolicy.METADATA_ONLY
            and not self.source_hash
        ):
            errors["source_hash"] = "Stored source content requires a SHA-256 hash."
        if self.content_storage_policy != self.StoragePolicy.METADATA_ONLY:
            errors["content_storage_policy"] = (
                "Only metadata-only sources are enabled in Phase 1."
            )
        if (
            self.legal_review_status != self.LegalReviewStatus.UNREVIEWED
            or self.legal_reviewed_at is not None
            or self.legal_reviewed_by is not None
        ):
            errors["legal_review_status"] = (
                "Source legal review is not enabled in Phase 1."
            )
        if self.status == self.Status.PUBLISHED_FUTURE_EFFECTIVE and (
            self.effective_date is None or self.effective_date <= self.status_as_of
        ):
            errors["effective_date"] = (
                "A future-effective version needs an effective date after status_as_of."
            )
        if self.status == self.Status.EFFECTIVE and (
            self.effective_date is None or self.effective_date > self.status_as_of
        ):
            errors["effective_date"] = (
                "An effective version needs an effective date on or before status_as_of."
            )
        if (
            self.status
            in (self.Status.EFFECTIVE, self.Status.PUBLISHED_FUTURE_EFFECTIVE)
            and self.valid_from is None
        ):
            errors["valid_from"] = "An effective lifecycle needs valid_from."
        if self.status == self.Status.ACTIVE_NO_EXPLICIT_COMMENCEMENT and (
            self.effective_date is not None
            or self.effective_basis != self.EffectiveBasis.NO_EXPLICIT_COMMENCEMENT
        ):
            errors["effective_basis"] = (
                "This status requires no explicit commencement date or clause."
            )
        if self.status == self.Status.REPEALED and self.repeal_date is None:
            errors["repeal_date"] = "A repealed version requires a repeal date."
        if self.effective_date is not None and self.valid_from != self.effective_date:
            errors["valid_from"] = "valid_from must match effective_date."
        if self.status_as_of > self.source_checked_on:
            errors["status_as_of"] = "Status cannot postdate the source check."
        if self.transition_end is not None and (
            self.effective_date is None or self.transition_end < self.effective_date
        ):
            errors["transition_end"] = "A transition cannot end before effectiveness."
        if self.status == self.Status.REPEALED and (
            self.repeal_date is None or self.valid_to != self.repeal_date
        ):
            errors["valid_to"] = (
                "A repealed version needs matching repeal_date and valid_to."
            )
        if self.status == self.Status.SUPERSEDED and self.valid_to is None:
            errors["valid_to"] = "A superseded version needs valid_to."
        if (
            self.status
            in (
                self.Status.EFFECTIVE,
                self.Status.ACTIVE_NO_EXPLICIT_COMMENCEMENT,
                self.Status.PUBLISHED_FUTURE_EFFECTIVE,
            )
            and self.repeal_date is not None
        ):
            errors["repeal_date"] = "An active version cannot have a repeal date."
        if self.valid_to is not None and self.valid_from is not None:
            if self.valid_to <= self.valid_from:
                errors["valid_to"] = "valid_to must be later than valid_from."
        if errors:
            raise ValidationError(errors)
        super().clean()

    def __str__(self) -> str:
        return f"{self.record_id} r{self.revision}"


class RegulatoryProvision(TemporalRevisionMixin, RegulatoryFolderModel):
    class LocatorKind(models.TextChoices):
        ARTICLE = "article", _("Article")
        PAGE = "page", _("Page")
        PAGE_BBOX = "page_bbox", _("Page bounding box")
        DOM_SELECTOR = "dom_selector", _("DOM selector")
        ANNEX = "annex", _("Annex")
        TABLE_CELL = "table_cell", _("Table cell")
        OTHER = "other", _("Other")

    document_version = models.ForeignKey(
        RegulatoryDocumentVersion,
        on_delete=models.PROTECT,
        related_name="provisions",
    )
    article = models.CharField(max_length=300)
    heading = models.CharField(max_length=1000, null=True, blank=True)
    text = models.TextField(null=True, blank=True)
    source_locator_kind = models.CharField(max_length=20, choices=LocatorKind.choices)
    source_locator_value = models.CharField(max_length=1000)
    content_hash = models.CharField(max_length=64, validators=[validate_sha256])

    class Meta:
        ordering = ["record_id", "revision"]
        constraints = [
            models.UniqueConstraint(
                fields=["folder", "record_id", "revision"],
                name="reg_prov_folder_record_rev_uniq",
            ),
            models.UniqueConstraint(
                fields=["folder", "record_id"],
                condition=Q(recorded_to__isnull=True),
                name="reg_prov_one_current",
            ),
            models.CheckConstraint(
                condition=Q(revision__gte=1),
                name="reg_prov_revision_positive",
            ),
            models.CheckConstraint(
                condition=Q(recorded_to__isnull=True)
                | Q(recorded_to__gt=F("recorded_from")),
                name="reg_prov_recorded_interval",
            ),
            models.CheckConstraint(
                condition=Q(is_published=False),
                name="reg_prov_not_published",
            ),
            models.CheckConstraint(
                condition=Q(text__isnull=True) | Q(text=""),
                name="reg_prov_phase1_no_text",
            ),
        ]

    def clean(self) -> None:
        errors = {}
        if (
            self.document_version_id
            and self.document_version.folder_id != self.folder_id
        ):
            errors["document_version"] = (
                "The provision must use its document version folder."
            )
        if (
            self.document_version_id
            and self.document_version.content_storage_policy
            == RegulatoryDocumentVersion.StoragePolicy.METADATA_ONLY
            and self.text not in (None, "")
        ):
            errors["text"] = "Provision text is forbidden for metadata-only sources."
        if errors:
            raise ValidationError(errors)
        super().clean()

    def __str__(self) -> str:
        return f"{self.record_id} r{self.revision}"


class RegulatoryObligation(TemporalRevisionMixin, RegulatoryFolderModel):
    class Modality(models.TextChoices):
        MUST = "must", _("Must")
        MUST_NOT = "must_not", _("Must not")
        SHOULD = "should", _("Should")
        MAY = "may", _("May")
        ORGANISATION_DEFINED = "organisation_defined", _("Organisation defined")

    class DeadlineKind(models.TextChoices):
        NONE = "none", _("None")
        FIXED_DATE = "fixed_date", _("Fixed date")
        DURATION_AFTER_TRIGGER = (
            "duration_after_trigger",
            _("Duration after trigger"),
        )
        PERIODIC = "periodic", _("Periodic")
        WITHOUT_UNDUE_DELAY = "without_undue_delay", _("Without undue delay")
        NEEDS_REVIEW = "needs_review", _("Needs review")

    class ReviewStatus(models.TextChoices):
        MACHINE_PROPOSED = "machine_proposed", _("Machine proposed")
        ANALYST_REVIEWED = "analyst_reviewed", _("Analyst reviewed")
        LEGAL_REVIEWED = "legal_reviewed", _("Legal reviewed")
        APPROVED = "approved", _("Approved")
        REJECTED = "rejected", _("Rejected")
        SUPERSEDED = "superseded", _("Superseded")

    title_zh = models.CharField(max_length=1000)
    authority_level = models.CharField(max_length=40, choices=AuthorityLevel.choices)
    modality = models.CharField(max_length=32, choices=Modality.choices)
    subject = models.CharField(max_length=1000)
    action = models.TextField(max_length=4000)
    object = models.TextField(max_length=2000, null=True, blank=True)
    conditions = models.JSONField(
        default=list,
        blank=True,
        validators=[validate_string_list],
    )
    exceptions = models.JSONField(
        default=list,
        blank=True,
        validators=[validate_string_list],
    )
    deadline_kind = models.CharField(max_length=32, choices=DeadlineKind.choices)
    deadline_value = models.CharField(max_length=500, null=True, blank=True)
    deadline_rule_id = models.CharField(max_length=300, null=True, blank=True)
    expected_evidence = models.JSONField(
        default=list,
        blank=True,
        validators=[validate_string_list],
    )
    penalty_or_consequence = models.TextField(
        max_length=4000,
        null=True,
        blank=True,
    )
    valid_from = models.DateField(null=True, blank=True)
    valid_to = models.DateField(null=True, blank=True)
    review_status = models.CharField(
        max_length=24,
        choices=ReviewStatus.choices,
        default=ReviewStatus.MACHINE_PROPOSED,
    )
    confidence = models.DecimalField(
        max_digits=5,
        decimal_places=4,
        validators=[MinValueValidator(0), MaxValueValidator(1)],
    )
    uncertainties = models.JSONField(
        default=list,
        blank=True,
        validators=[validate_string_list],
    )
    provisions = models.ManyToManyField(
        RegulatoryProvision,
        through="RegulatoryObligationProvision",
        related_name="obligations",
    )

    class Meta:
        ordering = ["record_id", "revision"]
        constraints = [
            models.UniqueConstraint(
                fields=["folder", "record_id", "revision"],
                name="reg_obl_folder_record_rev_uniq",
            ),
            models.UniqueConstraint(
                fields=["folder", "record_id"],
                condition=Q(recorded_to__isnull=True),
                name="reg_obl_one_current",
            ),
            models.CheckConstraint(
                condition=Q(revision__gte=1),
                name="reg_obl_revision_positive",
            ),
            models.CheckConstraint(
                condition=Q(recorded_to__isnull=True)
                | Q(recorded_to__gt=F("recorded_from")),
                name="reg_obl_recorded_interval",
            ),
            models.CheckConstraint(
                condition=Q(valid_to__isnull=True)
                | Q(valid_from__isnull=True)
                | Q(valid_to__gt=F("valid_from")),
                name="reg_obl_valid_interval",
            ),
            models.CheckConstraint(
                condition=Q(confidence__gte=0) & Q(confidence__lte=1),
                name="reg_obl_confidence_range",
            ),
            models.CheckConstraint(
                condition=Q(review_status="machine_proposed"),
                name="reg_obl_phase1_initial",
            ),
            models.CheckConstraint(
                condition=Q(is_published=False),
                name="reg_obl_not_published",
            ),
        ]
        permissions = [
            (
                "transition_regulatoryobligation",
                "Can transition a regulatory obligation review",
            ),
            (
                "legal_review_regulatoryobligation",
                "Can perform the separate legal review of a regulatory obligation",
            ),
        ]

    def clean(self) -> None:
        errors = {}
        if self.valid_to is not None and self.valid_from is not None:
            if self.valid_to <= self.valid_from:
                errors["valid_to"] = "valid_to must be later than valid_from."
        if self.review_status != self.ReviewStatus.MACHINE_PROPOSED:
            errors["review_status"] = (
                "Obligations must enter as machine proposals in Phase 1."
            )
        if errors:
            raise ValidationError(errors)
        super().clean()

    @property
    def current_review_status(self) -> str:
        events = getattr(self, "prefetched_review_events", None)
        if events is not None:
            events = [event for event in events if event.folder_id == self.folder_id]
            latest = max(events, key=lambda event: event.sequence, default=None)
        else:
            latest = (
                self.review_events.filter(folder_id=self.folder_id)
                .order_by("-sequence")
                .first()
            )
        return latest.to_status if latest else self.review_status

    def __str__(self) -> str:
        return f"{self.record_id} r{self.revision}"


class RegulatoryObligationProvision(RegulatoryFolderModel):
    obligation = models.ForeignKey(
        RegulatoryObligation,
        on_delete=models.PROTECT,
        related_name="provision_links",
    )
    provision = models.ForeignKey(
        RegulatoryProvision,
        on_delete=models.PROTECT,
        related_name="obligation_links",
    )
    order = models.PositiveIntegerField(default=0)

    class Meta:
        ordering = ["order", "id"]
        constraints = [
            models.UniqueConstraint(
                fields=["obligation", "provision"],
                name="reg_obl_provision_uniq",
            ),
            models.CheckConstraint(
                condition=Q(is_published=False),
                name="reg_obl_prov_not_published",
            ),
        ]

    def clean(self) -> None:
        errors = {}
        if self.obligation_id and self.obligation.folder_id != self.folder_id:
            errors["obligation"] = "The obligation must be in the link folder."
        if self.provision_id and self.provision.folder_id != self.folder_id:
            errors["provision"] = "The provision must be in the link folder."

        if self.obligation_id and self.provision_id:
            version = self.provision.document_version
            if version.valid_from is not None and (
                self.obligation.valid_from is None
                or self.obligation.valid_from < version.valid_from
            ):
                errors["obligation"] = (
                    "The obligation valid interval starts outside its source version."
                )
            if version.valid_to is not None and (
                self.obligation.valid_to is None
                or self.obligation.valid_to > version.valid_to
            ):
                errors["obligation"] = (
                    "The obligation valid interval ends outside its source version."
                )

        if errors:
            raise ValidationError(errors)
        super().clean()


class RegulatoryObligationReviewEvent(RegulatoryFolderModel):
    obligation = models.ForeignKey(
        RegulatoryObligation,
        on_delete=models.PROTECT,
        related_name="review_events",
    )
    sequence = models.PositiveIntegerField()
    from_status = models.CharField(
        max_length=24,
        choices=RegulatoryObligation.ReviewStatus.choices,
    )
    to_status = models.CharField(
        max_length=24,
        choices=RegulatoryObligation.ReviewStatus.choices,
    )
    actor = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.PROTECT,
        related_name="regulatory_obligation_review_events",
    )
    occurred_at = models.DateTimeField(default=timezone.now)
    rationale = models.TextField(max_length=4000)
    idempotency_key = models.CharField(max_length=200)
    payload_sha256 = models.CharField(max_length=64, validators=[validate_sha256])

    class Meta:
        ordering = ["sequence"]
        constraints = [
            models.UniqueConstraint(
                fields=["obligation", "sequence"],
                name="reg_obl_review_sequence_uniq",
            ),
            models.UniqueConstraint(
                fields=["folder", "idempotency_key"],
                name="reg_review_idempotency_uniq",
            ),
            models.CheckConstraint(
                condition=Q(sequence__gte=1),
                name="reg_obl_review_sequence_positive",
            ),
            models.CheckConstraint(
                condition=(
                    Q(
                        sequence=1,
                        from_status="machine_proposed",
                        to_status="analyst_reviewed",
                    )
                    | Q(
                        sequence=2,
                        from_status="analyst_reviewed",
                        to_status="legal_reviewed",
                    )
                ),
                name="reg_obl_review_phase1_edge",
            ),
            models.CheckConstraint(
                condition=Q(is_published=False),
                name="reg_obl_review_not_published",
            ),
        ]

    def clean(self) -> None:
        errors = {}
        if self.obligation_id and self.obligation.folder_id != self.folder_id:
            errors["obligation"] = "The event must use its obligation folder."
        if not (self.rationale or "").strip():
            errors["rationale"] = "A review rationale is required."
        expected_edge = {
            1: (
                RegulatoryObligation.ReviewStatus.MACHINE_PROPOSED,
                RegulatoryObligation.ReviewStatus.ANALYST_REVIEWED,
            ),
            2: (
                RegulatoryObligation.ReviewStatus.ANALYST_REVIEWED,
                RegulatoryObligation.ReviewStatus.LEGAL_REVIEWED,
            ),
        }.get(self.sequence)
        if expected_edge != (self.from_status, self.to_status):
            errors["to_status"] = "This review edge is not enabled in Phase 1."
        if self.obligation_id and self.sequence == 2:
            previous = self.obligation.review_events.filter(sequence=1).first()
            if previous is None or previous.to_status != self.from_status:
                errors["sequence"] = "The analyst review event must exist first."
            elif previous.actor_id == self.actor_id:
                errors["actor"] = (
                    "Analyst and legal review require different named actors."
                )
        if errors:
            raise ValidationError(errors)
        super().clean()


class RegulatoryApplicabilityDecision(TemporalRevisionMixin, RegulatoryFolderModel):
    """Versioned synthetic fact snapshot plus deterministic non-binding result."""

    class ScopeType(models.TextChoices):
        LEGAL_ENTITY = PILOT_APPLICABILITY_SCOPE_TYPE, _("Legal entity")

    class Result(models.TextChoices):
        APPLICABLE = "applicable", _("Applicable")
        NOT_APPLICABLE = "not_applicable", _("Not applicable")
        NEEDS_REVIEW = "needs_review", _("Needs review")

    class RationaleCode(models.TextChoices):
        RULE_SATISFIED = "rule_satisfied", _("Rule satisfied")
        RULE_NOT_SATISFIED = "rule_not_satisfied", _("Rule not satisfied")
        MISSING_OR_UNKNOWN_FACT = (
            "missing_or_unknown_fact",
            _("Missing or unknown fact"),
        )

    class ReviewStatus(models.TextChoices):
        DRAFT = "draft", _("Draft")

    previous_revision = models.ForeignKey(
        "self",
        null=True,
        blank=True,
        on_delete=models.PROTECT,
        related_name="+",
        db_index=False,
    )
    registration = models.ForeignKey(
        EntityDocumentRegistration,
        on_delete=models.PROTECT,
        related_name="applicability_decisions",
    )
    obligation = models.ForeignKey(
        RegulatoryObligation,
        on_delete=models.PROTECT,
        related_name="applicability_decisions",
    )
    recorded_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.PROTECT,
        related_name="regulatory_applicability_decisions",
    )
    scope_type = models.CharField(
        max_length=24,
        choices=ScopeType.choices,
        default=ScopeType.LEGAL_ENTITY,
        editable=False,
    )
    rule_id = models.CharField(
        max_length=160,
        default=PILOT_APPLICABILITY_RULE_ID,
        validators=[validate_regulatory_identifier],
    )
    rule_version = models.PositiveIntegerField(
        default=PILOT_APPLICABILITY_RULE_VERSION,
    )
    rule_snapshot = models.JSONField()
    fact_snapshot_id = models.CharField(
        max_length=160,
        validators=[validate_regulatory_identifier],
    )
    fact_snapshot = models.JSONField()
    missing_fact_keys = models.JSONField(
        default=list,
        blank=True,
        validators=[validate_string_list],
    )
    result = models.CharField(max_length=24, choices=Result.choices)
    rationale_code = models.CharField(
        max_length=32,
        choices=RationaleCode.choices,
    )
    rationale = models.TextField(max_length=4000)
    valid_from = models.DateField(null=True, blank=True)
    valid_to = models.DateField(null=True, blank=True)
    review_status = models.CharField(
        max_length=16,
        choices=ReviewStatus.choices,
        default=ReviewStatus.DRAFT,
        editable=False,
    )
    is_binding = models.BooleanField(default=False, editable=False)
    digest_schema = models.CharField(
        max_length=64,
        default=APPLICABILITY_DIGEST_SCHEMA,
        editable=False,
    )
    evaluator_profile = models.CharField(
        max_length=64,
        default=APPLICABILITY_EVALUATOR_PROFILE,
        editable=False,
    )
    rule_snapshot_sha256 = models.CharField(
        max_length=64,
        validators=[validate_sha256],
    )
    fact_snapshot_sha256 = models.CharField(
        max_length=64,
        validators=[validate_sha256],
    )
    semantic_payload_sha256 = models.CharField(
        max_length=64,
        validators=[validate_sha256],
    )
    request_sha256 = models.CharField(
        max_length=64,
        validators=[validate_sha256],
    )
    idempotency_key = models.CharField(max_length=200)

    class Meta:
        ordering = ["record_id", "revision"]
        indexes = [
            models.Index(
                fields=[
                    "folder",
                    "registration",
                    "obligation",
                    "recorded_from",
                ],
                name="reg_app_dec_asof_idx",
            )
        ]
        constraints = [
            models.UniqueConstraint(
                fields=["folder", "record_id", "revision"],
                name="reg_app_dec_record_rev_uniq",
            ),
            models.UniqueConstraint(
                fields=["folder", "fact_snapshot_id", "revision"],
                name="reg_app_fact_record_rev_uniq",
            ),
            models.UniqueConstraint(
                fields=["folder", "registration", "obligation", "rule_id"],
                condition=Q(recorded_to__isnull=True),
                name="reg_app_dec_one_current",
            ),
            models.UniqueConstraint(
                fields=["previous_revision"],
                name="reg_app_dec_previous_uniq",
            ),
            models.UniqueConstraint(
                fields=["folder", "idempotency_key"],
                name="reg_app_dec_idem_uniq",
            ),
            models.CheckConstraint(
                condition=Q(revision__gte=1),
                name="reg_app_dec_revision_pos",
            ),
            models.CheckConstraint(
                condition=Q(recorded_to__isnull=True)
                | Q(recorded_to__gt=F("recorded_from")),
                name="reg_app_dec_recorded_int",
            ),
            models.CheckConstraint(
                condition=Q(valid_to__isnull=True)
                | Q(valid_from__isnull=True)
                | Q(valid_to__gt=F("valid_from")),
                name="reg_app_dec_valid_int",
            ),
            models.CheckConstraint(
                condition=Q(scope_type=PILOT_APPLICABILITY_SCOPE_TYPE),
                name="reg_app_dec_scope_legal",
            ),
            models.CheckConstraint(
                condition=Q(rule_id=PILOT_APPLICABILITY_RULE_ID),
                name="reg_app_dec_rule_id",
            ),
            models.CheckConstraint(
                condition=Q(rule_version=PILOT_APPLICABILITY_RULE_VERSION),
                name="reg_app_dec_rule_version",
            ),
            models.CheckConstraint(
                condition=Q(review_status="draft"),
                name="reg_app_dec_draft",
            ),
            models.CheckConstraint(
                condition=Q(is_binding=False),
                name="reg_app_dec_nonbinding",
            ),
            models.CheckConstraint(
                condition=Q(digest_schema=APPLICABILITY_DIGEST_SCHEMA),
                name="reg_app_dec_digest_schema",
            ),
            models.CheckConstraint(
                condition=Q(evaluator_profile=APPLICABILITY_EVALUATOR_PROFILE),
                name="reg_app_dec_eval_profile",
            ),
            models.CheckConstraint(
                condition=~Q(rationale=""),
                name="reg_app_dec_rationale",
            ),
            models.CheckConstraint(
                condition=(
                    Q(
                        result="applicable",
                        rationale_code="rule_satisfied",
                    )
                    | Q(
                        result="not_applicable",
                        rationale_code="rule_not_satisfied",
                    )
                    | Q(
                        result="needs_review",
                        rationale_code="missing_or_unknown_fact",
                    )
                ),
                name="reg_app_dec_result_reason",
            ),
            models.CheckConstraint(
                condition=Q(is_published=False),
                name="reg_app_dec_not_published",
            ),
        ]
        permissions = [
            (
                "record_regulatoryapplicability",
                "Can record a deterministic regulatory applicability evaluation",
            )
        ]

    @staticmethod
    def pilot_rule_snapshot() -> dict:
        return deepcopy(PILOT_APPLICABILITY_RULE_SNAPSHOT)

    def applicability_semantic_payload(self) -> dict:
        return {
            "digest_schema": APPLICABILITY_DIGEST_SCHEMA,
            "evaluator_profile": APPLICABILITY_EVALUATOR_PROFILE,
            "record_id": self.record_id,
            "fact_snapshot_id": self.fact_snapshot_id,
            "scope": {
                "type": PILOT_APPLICABILITY_SCOPE_TYPE,
                "registration_id": str(self.registration_id),
                "entity_id": str(self.registration.entity_id),
                "document_id": str(self.registration.document_id),
            },
            "obligation": {
                "physical_id": str(self.obligation_id),
                "record_id": self.obligation.record_id,
                "revision": self.obligation.revision,
            },
            "rule": self.pilot_rule_snapshot(),
            "fact_snapshot": self.fact_snapshot,
            "missing_fact_keys": self.missing_fact_keys,
            "result": self.result,
            "rationale_code": self.rationale_code,
            "rationale": self.rationale,
            "valid_from": _canonical_temporal_value(self.valid_from),
            "valid_to": _canonical_temporal_value(self.valid_to),
            "review_status": self.ReviewStatus.DRAFT,
            "is_binding": False,
            "recorded_by_id": str(self.recorded_by_id),
            "provenance": {
                "method": self.provenance_method,
                "created_at": _canonical_temporal_value(self.provenance_created_at),
                "created_by": self.provenance_created_by,
                "parser_version": self.parser_version,
                "model": self.model_name,
                "prompt_version": self.prompt_version,
                "retrieval_version": self.retrieval_version,
            },
        }

    def _validate_fact_snapshot(self) -> dict[str, str]:
        errors: dict[str, str] = {}
        if not isinstance(self.fact_snapshot, list) or len(self.fact_snapshot) != 1:
            return {
                "fact_snapshot": (
                    "The pilot snapshot must contain exactly one normalized fact."
                )
            }
        observation = self.fact_snapshot[0]
        if not isinstance(observation, dict):
            return {"fact_snapshot": "A normalized fact object is required."}
        if observation.get("fact") != PILOT_APPLICABILITY_FACT_KEY:
            errors["fact_snapshot"] = "The pilot fact key is fixed."
            return errors
        known = observation.get("known")
        if type(known) is not bool:
            errors["fact_snapshot"] = "The fact known flag must be boolean."
            return errors

        source_refs = observation.get("source_refs")
        observed_at = observation.get("observed_at")
        if known:
            if set(observation) != {
                "fact",
                "known",
                "value",
                "source_refs",
                "observed_at",
            }:
                errors["fact_snapshot"] = "The known fact shape is invalid."
                return errors
            value = observation.get("value")
            if not isinstance(value, str) or not value.strip():
                errors["fact_snapshot"] = (
                    "A known institution type must be a non-empty string."
                )
            elif len(value) > PILOT_APPLICABILITY_VALUE_MAX_LENGTH:
                errors["fact_snapshot"] = (
                    "The institution type exceeds the pilot length limit."
                )
            try:
                validate_non_empty_string_list(source_refs)
            except ValidationError:
                errors["fact_snapshot"] = (
                    "A known fact needs non-empty unique evidence references."
                )
            else:
                if len(source_refs) > PILOT_APPLICABILITY_SOURCE_REF_MAX_COUNT:
                    errors["fact_snapshot"] = (
                        "The known fact has too many evidence references."
                    )
                elif any(
                    len(source_ref) > PILOT_APPLICABILITY_SOURCE_REF_MAX_LENGTH
                    for source_ref in source_refs
                ):
                    errors["fact_snapshot"] = (
                        "An evidence reference exceeds the pilot length limit."
                    )
            parsed_observed_at = (
                parse_datetime(observed_at) if isinstance(observed_at, str) else None
            )
            if parsed_observed_at is None or timezone.is_naive(parsed_observed_at):
                errors["fact_snapshot"] = (
                    "A known fact needs an aware RFC 3339 observation time."
                )
            elif parsed_observed_at > self.recorded_from:
                errors["fact_snapshot"] = (
                    "A fact cannot be observed after the decision was recorded."
                )
            if self.missing_fact_keys:
                errors["missing_fact_keys"] = (
                    "A known fact cannot also be marked missing."
                )
        else:
            if set(observation) != {
                "fact",
                "known",
                "source_refs",
                "observed_at",
            }:
                errors["fact_snapshot"] = "The unknown fact shape is invalid."
            elif source_refs != [] or observed_at is not None:
                errors["fact_snapshot"] = (
                    "An unknown fact cannot carry evidence or observation time."
                )
        return errors

    def clean(self) -> None:
        errors: dict[str, str] = {}
        if self.registration_id:
            if self.registration.folder_id != self.folder_id:
                errors["registration"] = (
                    "The registration must be in the decision folder."
                )
            if self.registration.registration_kind != (
                EntityDocumentRegistration.RegistrationKind.SYNTHETIC_PILOT
            ):
                errors["registration"] = (
                    "The decision requires a synthetic-pilot registration."
                )
        if self.obligation_id:
            if self.obligation.folder_id != self.folder_id:
                errors["obligation"] = "The obligation must be in the decision folder."
            elif (
                self.registration_id
                and not self.obligation.provision_links.filter(
                    folder_id=self.folder_id,
                    provision__folder_id=self.folder_id,
                    provision__document_version__folder_id=self.folder_id,
                    provision__document_version__document_id=self.registration.document_id,
                ).exists()
            ):
                errors["obligation"] = (
                    "The obligation must cite the registered document."
                )
        if self.rule_snapshot != self.pilot_rule_snapshot():
            errors["rule_snapshot"] = "The synthetic pilot rule snapshot is fixed."
        elif self.rule_snapshot_sha256 != _canonical_json_sha256(self.rule_snapshot):
            errors["rule_snapshot_sha256"] = (
                "The rule snapshot digest must match the fixed snapshot."
            )
        if self.rule_id != PILOT_APPLICABILITY_RULE_ID:
            errors["rule_id"] = "The synthetic pilot rule ID is fixed."
        if self.rule_version != PILOT_APPLICABILITY_RULE_VERSION:
            errors["rule_version"] = "The synthetic pilot rule version is fixed."
        if self.scope_type != PILOT_APPLICABILITY_SCOPE_TYPE:
            errors["scope_type"] = "The synthetic pilot scope is a legal entity."
        if set(self.missing_fact_keys or []) - {PILOT_APPLICABILITY_FACT_KEY}:
            errors["missing_fact_keys"] = "The snapshot uses an unsupported fact key."
        errors.update(self._validate_fact_snapshot())
        fact_digest_payload = {
            "observations": self.fact_snapshot,
            "missing_fact_keys": self.missing_fact_keys,
        }
        try:
            expected_fact_digest = _canonical_json_sha256(fact_digest_payload)
        except TypeError, ValueError:
            expected_fact_digest = None
        if self.fact_snapshot_sha256 != expected_fact_digest:
            errors["fact_snapshot_sha256"] = (
                "The fact snapshot digest must match the normalized fact state."
            )
        if "fact_snapshot" not in errors:
            observation = self.fact_snapshot[0]
            expected_result = (
                self.Result.NEEDS_REVIEW
                if not observation["known"]
                else (
                    self.Result.APPLICABLE
                    if observation["value"] == PILOT_APPLICABILITY_EXPECTED_VALUE
                    else self.Result.NOT_APPLICABLE
                )
            )
            if self.result != expected_result:
                errors["result"] = (
                    "The result must match deterministic evaluation of the snapshot."
                )
        if self.valid_to is not None and self.valid_from is not None:
            if self.valid_to <= self.valid_from:
                errors["valid_to"] = "valid_to must be later than valid_from."
        if self.obligation_id:
            if self.obligation.valid_from is not None and (
                self.valid_from is None or self.valid_from < self.obligation.valid_from
            ):
                errors["valid_from"] = (
                    "The decision valid interval starts outside its obligation."
                )
            if self.obligation.valid_to is not None and (
                self.valid_to is None or self.valid_to > self.obligation.valid_to
            ):
                errors["valid_to"] = (
                    "The decision valid interval ends outside its obligation."
                )
        expected_reason = {
            self.Result.APPLICABLE: self.RationaleCode.RULE_SATISFIED,
            self.Result.NOT_APPLICABLE: self.RationaleCode.RULE_NOT_SATISFIED,
            self.Result.NEEDS_REVIEW: self.RationaleCode.MISSING_OR_UNKNOWN_FACT,
        }.get(self.result)
        if expected_reason != self.rationale_code:
            errors["rationale_code"] = "The rationale code must match the result."
        expected_rationale = {
            self.Result.APPLICABLE: PILOT_APPLICABILITY_RATIONALE_MATCH,
            self.Result.NOT_APPLICABLE: PILOT_APPLICABILITY_RATIONALE_NO_MATCH,
            self.Result.NEEDS_REVIEW: (
                PILOT_APPLICABILITY_RATIONALE_MISSING
                if self.missing_fact_keys
                else PILOT_APPLICABILITY_RATIONALE_UNKNOWN
            ),
        }.get(self.result)
        if self.rationale != expected_rationale:
            errors["rationale"] = "The rationale must match deterministic evaluation."
        if not (self.idempotency_key or "").strip():
            errors["idempotency_key"] = "A non-empty idempotency key is required."
        if self.previous_revision_id:
            previous = self.previous_revision
            stable_fields = (
                "registration_id",
                "obligation_id",
                "scope_type",
                "rule_id",
                "rule_version",
                "rule_snapshot_sha256",
                "fact_snapshot_id",
            )
            if any(
                getattr(previous, field) != getattr(self, field)
                for field in stable_fields
            ):
                errors["previous_revision"] = (
                    "A successor must preserve its scope, obligation, rule, and "
                    "fact snapshot identity."
                )
            elif previous.semantic_payload_sha256 == self.semantic_payload_sha256:
                errors["semantic_payload_sha256"] = (
                    "A successor must change the semantic payload."
                )
        if self.registration_id and self.obligation_id and self.recorded_by_id:
            try:
                expected_semantic_digest = _canonical_json_sha256(
                    self.applicability_semantic_payload()
                )
            except TypeError, ValueError:
                expected_semantic_digest = None
            if self.semantic_payload_sha256 != expected_semantic_digest:
                errors["semantic_payload_sha256"] = (
                    "The semantic digest must match the deterministic evaluation."
                )
        if errors:
            raise ValidationError(errors)
        super().clean()

    def __str__(self) -> str:
        return f"{self.record_id} r{self.revision}: {self.result}"

    @property
    def entity_id(self):
        return self.registration.entity_id

    @property
    def entity(self):
        return self.registration.entity

    @property
    def observations(self) -> list[dict]:
        """Artifact-compatible read alias for the embedded fact snapshot."""

        return self.fact_snapshot


class RegulatoryApplicabilityReviewDisposition(RegulatoryFolderModel):
    """Append-only named-human review of one exact applicability revision."""

    class Disposition(models.TextChoices):
        NOT_REVIEWED = "not_reviewed", _("Not reviewed")
        NO_CORRECTION_REQUESTED = (
            "no_correction_requested",
            _("No correction requested"),
        )
        CORRECTION_REQUESTED = "correction_requested", _("Correction requested")
        UNABLE_TO_COMPLETE = "unable_to_complete", _("Unable to complete")

    class ReasonCode(models.TextChoices):
        REVIEW_COMPLETED = "review_completed", _("Review completed")
        FACT_CORRECTION_REQUIRED = (
            "fact_correction_required",
            _("Fact correction required"),
        )
        EVIDENCE_CORRECTION_REQUIRED = (
            "evidence_correction_required",
            _("Evidence correction required"),
        )
        PROVENANCE_CORRECTION_REQUIRED = (
            "provenance_correction_required",
            _("Provenance correction required"),
        )
        SCOPE_OR_PARENT_CORRECTION_REQUIRED = (
            "scope_or_parent_correction_required",
            _("Scope or parent correction required"),
        )
        OTHER_CORRECTION_REQUIRED = (
            "other_correction_required",
            _("Other correction required"),
        )
        INSUFFICIENT_EVIDENCE = "insufficient_evidence", _("Insufficient evidence")
        CONFLICTING_INFORMATION = (
            "conflicting_information",
            _("Conflicting information"),
        )
        INSUFFICIENT_AUTHORITY_OR_SCOPE = (
            "insufficient_authority_or_scope",
            _("Insufficient authority or scope"),
        )
        OTHER_UNRESOLVED = "other_unresolved", _("Other unresolved")

    decision = models.ForeignKey(
        RegulatoryApplicabilityDecision,
        on_delete=models.PROTECT,
        related_name="review_dispositions",
    )
    decision_semantic_payload_sha256 = models.CharField(
        max_length=64,
        validators=[validate_sha256],
    )
    decision_recorded_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.PROTECT,
        related_name="regulatory_applicability_reviews_as_decision_recorder",
    )
    reviewer = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.PROTECT,
        related_name="regulatory_applicability_reviews_as_reviewer",
    )
    sequence = models.PositiveIntegerField()
    previous_disposition = models.ForeignKey(
        "self",
        null=True,
        blank=True,
        db_index=False,
        on_delete=models.PROTECT,
        related_name="successor_dispositions",
    )
    from_disposition = models.CharField(
        max_length=32,
        choices=Disposition.choices,
    )
    to_disposition = models.CharField(
        max_length=32,
        choices=Disposition.choices,
    )
    reason_code = models.CharField(max_length=48, choices=ReasonCode.choices)
    rationale = models.TextField(max_length=4000)
    occurred_at = models.DateTimeField(editable=False)
    digest_profile = models.CharField(
        max_length=64,
        default=APPLICABILITY_REVIEW_DISPOSITION_DIGEST_PROFILE,
        editable=False,
    )
    event_payload_sha256 = models.CharField(
        max_length=64,
        validators=[validate_sha256],
    )
    request_sha256 = models.CharField(
        max_length=64,
        validators=[validate_sha256],
    )
    idempotency_key = models.CharField(max_length=200)
    is_binding = models.BooleanField(default=False, editable=False)

    class Meta:
        default_permissions = ("view",)
        permissions = [
            (
                "review_regulatoryapplicability",
                "Can review an exact regulatory applicability evaluation",
            )
        ]
        ordering = ["decision_id", "sequence"]
        indexes = [
            models.Index(
                fields=["folder", "decision", "occurred_at"],
                name="reg_app_rev_dec_time_idx",
            )
        ]
        constraints = [
            models.UniqueConstraint(
                fields=["decision", "sequence"],
                name="reg_app_rev_dec_seq_uniq",
            ),
            models.UniqueConstraint(
                fields=["decision"],
                condition=Q(previous_disposition__isnull=True),
                name="reg_app_rev_one_root",
            ),
            models.UniqueConstraint(
                fields=["previous_disposition"],
                name="reg_app_rev_prev_uniq",
            ),
            models.UniqueConstraint(
                fields=["folder", "idempotency_key"],
                name="reg_app_rev_idem_uniq",
            ),
            models.CheckConstraint(
                condition=Q(sequence__gte=1),
                name="reg_app_rev_seq_pos",
            ),
            models.CheckConstraint(
                condition=(
                    Q(
                        sequence=1,
                        previous_disposition__isnull=True,
                        from_disposition="not_reviewed",
                    )
                    | (
                        Q(sequence__gte=2, previous_disposition__isnull=False)
                        & Q(
                            from_disposition__in=(
                                APPLICABILITY_REVIEW_PERSISTED_DISPOSITIONS
                            )
                        )
                    )
                ),
                name="reg_app_rev_root_succ",
            ),
            models.CheckConstraint(
                condition=(
                    Q(
                        to_disposition="no_correction_requested",
                        reason_code="review_completed",
                    )
                    | Q(
                        to_disposition="correction_requested",
                        reason_code__in=(
                            "fact_correction_required",
                            "evidence_correction_required",
                            "provenance_correction_required",
                            "scope_or_parent_correction_required",
                            "other_correction_required",
                        ),
                    )
                    | Q(
                        to_disposition="unable_to_complete",
                        reason_code__in=(
                            "insufficient_evidence",
                            "conflicting_information",
                            "insufficient_authority_or_scope",
                            "other_unresolved",
                        ),
                    )
                ),
                name="reg_app_rev_reason_target",
            ),
            models.CheckConstraint(
                condition=~Q(rationale=""),
                name="reg_app_rev_rationale",
            ),
            models.CheckConstraint(
                condition=~Q(idempotency_key=""),
                name="reg_app_rev_idem_present",
            ),
            models.CheckConstraint(
                condition=Q(
                    digest_profile=APPLICABILITY_REVIEW_DISPOSITION_DIGEST_PROFILE
                ),
                name="reg_app_rev_digest_profile",
            ),
            models.CheckConstraint(
                condition=Q(is_binding=False),
                name="reg_app_rev_nonbinding",
            ),
            models.CheckConstraint(
                condition=Q(is_published=False),
                name="reg_app_rev_not_published",
            ),
            models.CheckConstraint(
                condition=~Q(reviewer=F("decision_recorded_by")),
                name="reg_app_rev_actor_separate",
            ),
            models.CheckConstraint(
                condition=~Q(previous_disposition=F("id")),
                name="reg_app_rev_prev_not_self",
            ),
        ]

    def review_disposition_event_payload(self) -> dict:
        registration = self.decision.registration
        previous = self.previous_disposition
        return {
            "digest_profile": APPLICABILITY_REVIEW_DISPOSITION_DIGEST_PROFILE,
            "scope": {
                "folder_id": str(self.folder_id),
                "registration_id": str(self.decision.registration_id),
                "entity_id": str(registration.entity_id),
                "document_id": str(registration.document_id),
            },
            "reviewer_id": str(self.reviewer_id),
            "decision_recorded_by_id": str(self.decision_recorded_by_id),
            "decision": {
                "physical_id": str(self.decision_id),
                "record_id": self.decision.record_id,
                "revision": self.decision.revision,
                "semantic_payload_sha256": (self.decision_semantic_payload_sha256),
            },
            "sequence": self.sequence,
            "previous_disposition": (
                {
                    "physical_id": str(previous.id),
                    "event_payload_sha256": previous.event_payload_sha256,
                }
                if previous is not None
                else None
            ),
            "from_disposition": self.from_disposition,
            "to_disposition": self.to_disposition,
            "reason_code": self.reason_code,
            "rationale": self.rationale,
            "occurred_at": _canonical_temporal_value(self.occurred_at),
            "is_binding": False,
            "is_published": False,
        }

    def review_disposition_request_payload(self) -> dict:
        """Canonical reviewer-bound command reconstructed from the stored event."""

        registration = self.decision.registration
        previous = self.previous_disposition
        return {
            "digest_profile": APPLICABILITY_REVIEW_DISPOSITION_DIGEST_PROFILE,
            "kind": "request",
            "reviewer_id": str(self.reviewer_id),
            "scope": {
                "folder_id": str(self.folder_id),
                "registration_id": str(self.decision.registration_id),
                "entity_id": str(registration.entity_id),
                "document_id": str(registration.document_id),
            },
            "decision": {
                "physical_id": str(self.decision_id),
                "record_id": self.decision.record_id,
                "revision": self.decision.revision,
                "semantic_payload_sha256": (self.decision_semantic_payload_sha256),
            },
            "expected_head": (
                {
                    "physical_id": str(previous.id),
                    "sequence": previous.sequence,
                    "disposition": previous.to_disposition,
                    "event_payload_sha256": previous.event_payload_sha256,
                }
                if previous is not None
                else None
            ),
            "target_disposition": self.to_disposition,
            "reason_code": self.reason_code,
            "rationale": self.rationale,
        }

    def clean(self) -> None:
        errors: dict[str, str] = {}
        decision = self.decision if self.decision_id else None
        previous = self.previous_disposition if self.previous_disposition_id else None
        occurred_at_is_aware = self.occurred_at is not None and timezone.is_aware(
            self.occurred_at
        )

        if self.occurred_at is not None and not occurred_at_is_aware:
            errors["occurred_at"] = "A timezone-aware event time is required."

        if decision is not None:
            if decision.folder_id != self.folder_id:
                errors["decision"] = "The decision must be in the review folder."
            elif decision.registration.folder_id != self.folder_id:
                errors["decision"] = (
                    "The decision registration must be in the review folder."
                )
            try:
                expected_decision_digest = _canonical_json_sha256(
                    decision.applicability_semantic_payload()
                )
            except TypeError, ValueError:
                expected_decision_digest = None
            if decision.semantic_payload_sha256 != expected_decision_digest:
                errors["decision"] = (
                    "The exact decision semantic digest is inconsistent."
                )
            if self.decision_semantic_payload_sha256 != (
                decision.semantic_payload_sha256
            ):
                errors["decision_semantic_payload_sha256"] = (
                    "The copied semantic digest must match the exact decision."
                )
            if self.decision_recorded_by_id != decision.recorded_by_id:
                errors["decision_recorded_by"] = (
                    "The copied decision recorder must match the exact decision."
                )
            if occurred_at_is_aware and self.occurred_at <= decision.recorded_from:
                errors["occurred_at"] = (
                    "The review event must occur strictly after its decision."
                )
            elif (
                occurred_at_is_aware
                and decision.recorded_to is not None
                and self.occurred_at >= decision.recorded_to
            ):
                errors["occurred_at"] = (
                    "The review event must precede the decision's recorded close."
                )

        if (
            self.reviewer_id
            and self.decision_recorded_by_id
            and self.reviewer_id == self.decision_recorded_by_id
        ):
            errors["reviewer"] = "The decision recorder cannot review that revision."

        if previous is None:
            if (
                self.sequence != 1
                or self.from_disposition != self.Disposition.NOT_REVIEWED
            ):
                errors["previous_disposition"] = (
                    "The first event must start at not_reviewed with sequence 1."
                )
        else:
            if previous.pk == self.pk:
                errors["previous_disposition"] = "An event cannot precede itself."
            elif previous.folder_id != self.folder_id:
                errors["previous_disposition"] = (
                    "The predecessor must be in the review folder."
                )
            elif previous.decision_id != self.decision_id:
                errors["previous_disposition"] = (
                    "The predecessor must review the same decision."
                )
            elif decision is not None and (
                previous.decision_recorded_by_id != decision.recorded_by_id
                or previous.decision_semantic_payload_sha256
                != decision.semantic_payload_sha256
            ):
                errors["previous_disposition"] = (
                    "The predecessor must bind the same decision maker and digest."
                )
            elif self.sequence != previous.sequence + 1:
                errors["sequence"] = "Sequence must increment its predecessor by one."
            elif self.from_disposition != previous.to_disposition:
                errors["from_disposition"] = (
                    "The event must start at its predecessor disposition."
                )
            elif occurred_at_is_aware and previous.occurred_at >= self.occurred_at:
                errors["occurred_at"] = (
                    "The event must occur strictly after its predecessor."
                )
            elif previous.event_payload_sha256 != _canonical_json_sha256(
                previous.review_disposition_event_payload()
            ):
                errors["previous_disposition"] = (
                    "The predecessor event digest is inconsistent."
                )
            elif (
                self.to_disposition == previous.to_disposition
                and self.reason_code == previous.reason_code
                and (self.rationale or "").strip() == (previous.rationale or "").strip()
            ):
                errors["to_disposition"] = (
                    "A same-disposition successor must materially change its reason "
                    "or rationale."
                )

        allowed_reason_codes = {
            self.Disposition.NO_CORRECTION_REQUESTED: {
                self.ReasonCode.REVIEW_COMPLETED,
            },
            self.Disposition.CORRECTION_REQUESTED: {
                self.ReasonCode.FACT_CORRECTION_REQUIRED,
                self.ReasonCode.EVIDENCE_CORRECTION_REQUIRED,
                self.ReasonCode.PROVENANCE_CORRECTION_REQUIRED,
                self.ReasonCode.SCOPE_OR_PARENT_CORRECTION_REQUIRED,
                self.ReasonCode.OTHER_CORRECTION_REQUIRED,
            },
            self.Disposition.UNABLE_TO_COMPLETE: {
                self.ReasonCode.INSUFFICIENT_EVIDENCE,
                self.ReasonCode.CONFLICTING_INFORMATION,
                self.ReasonCode.INSUFFICIENT_AUTHORITY_OR_SCOPE,
                self.ReasonCode.OTHER_UNRESOLVED,
            },
        }
        if self.reason_code not in allowed_reason_codes.get(self.to_disposition, set()):
            errors["reason_code"] = (
                "The reason code is not enabled for the target disposition."
            )
        normalized_rationale = (self.rationale or "").strip()
        if not normalized_rationale:
            errors["rationale"] = "A non-empty human rationale is required."
        elif self.rationale != normalized_rationale:
            errors["rationale"] = "The human rationale must be whitespace-normalized."
        normalized_idempotency_key = (self.idempotency_key or "").strip()
        if not normalized_idempotency_key:
            errors["idempotency_key"] = "A non-empty idempotency key is required."
        elif self.idempotency_key != normalized_idempotency_key:
            errors["idempotency_key"] = (
                "The idempotency key must be whitespace-normalized."
            )
        if self.digest_profile != APPLICABILITY_REVIEW_DISPOSITION_DIGEST_PROFILE:
            errors["digest_profile"] = "The review digest profile is fixed."
        if self.is_binding:
            errors["is_binding"] = "Applicability review is non-binding."

        if decision is not None and self.reviewer_id and self.occurred_at is not None:
            try:
                expected_event_digest = _canonical_json_sha256(
                    self.review_disposition_event_payload()
                )
            except TypeError, ValueError:
                expected_event_digest = None
            if self.event_payload_sha256 != expected_event_digest:
                errors["event_payload_sha256"] = (
                    "The event digest must match the exact review payload."
                )
            try:
                expected_request_digest = _canonical_json_sha256(
                    self.review_disposition_request_payload()
                )
            except TypeError, ValueError:
                expected_request_digest = None
            if self.request_sha256 != expected_request_digest:
                errors["request_sha256"] = (
                    "The request digest must match the reviewer-bound command."
                )

        if errors:
            raise ValidationError(errors)
        super().clean()

    def __str__(self) -> str:
        return f"{self.decision_id} review {self.sequence}: {self.to_disposition}"


class RegulatoryChainCorrectionEvent(RegulatoryFolderModel):
    """Auditable boundary for one atomic recorded-time chain correction."""

    class CorrectionKind(models.TextChoices):
        RECORDED_TIME = "recorded_time", _("Recorded-time correction")

    document = models.ForeignKey(
        RegulatoryDocument,
        on_delete=models.PROTECT,
        related_name="correction_events",
    )
    previous_document_version = models.ForeignKey(
        RegulatoryDocumentVersion,
        on_delete=models.PROTECT,
        related_name="correction_events_as_previous",
        db_index=False,
    )
    successor_document_version = models.ForeignKey(
        RegulatoryDocumentVersion,
        on_delete=models.PROTECT,
        related_name="correction_events_as_successor",
        db_index=False,
    )
    previous_provision = models.ForeignKey(
        RegulatoryProvision,
        on_delete=models.PROTECT,
        related_name="correction_events_as_previous",
        db_index=False,
    )
    successor_provision = models.ForeignKey(
        RegulatoryProvision,
        on_delete=models.PROTECT,
        related_name="correction_events_as_successor",
        db_index=False,
    )
    previous_obligation = models.ForeignKey(
        RegulatoryObligation,
        on_delete=models.PROTECT,
        related_name="correction_events_as_previous",
        db_index=False,
    )
    successor_obligation = models.ForeignKey(
        RegulatoryObligation,
        on_delete=models.PROTECT,
        related_name="correction_events_as_successor",
        db_index=False,
    )
    actor = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.PROTECT,
        related_name="regulatory_chain_corrections",
    )
    correction_kind = models.CharField(
        max_length=24,
        choices=CorrectionKind.choices,
        default=CorrectionKind.RECORDED_TIME,
    )
    digest_schema = models.CharField(
        max_length=64,
        default=CORRECTION_DIGEST_SCHEMA,
        editable=False,
    )
    occurred_at = models.DateTimeField()
    rationale = models.TextField(max_length=4000)
    idempotency_key = models.CharField(max_length=200)
    payload_sha256 = models.CharField(max_length=64, validators=[validate_sha256])
    before_payload_sha256 = models.CharField(
        max_length=64,
        validators=[validate_sha256],
    )
    after_payload_sha256 = models.CharField(
        max_length=64,
        validators=[validate_sha256],
    )

    class Meta:
        ordering = ["occurred_at", "id"]
        indexes = [
            models.Index(
                fields=["folder", "document", "occurred_at"],
                name="reg_correction_doc_time_idx",
            )
        ]
        constraints = [
            models.UniqueConstraint(
                fields=["folder", "idempotency_key"],
                name="reg_correction_idempotency_uniq",
            ),
            models.UniqueConstraint(
                fields=["previous_document_version"],
                name="reg_correction_previous_ver_uniq",
            ),
            models.UniqueConstraint(
                fields=["successor_document_version"],
                name="reg_correction_successor_ver_uniq",
            ),
            models.UniqueConstraint(
                fields=["previous_provision"],
                name="reg_correction_previous_prov_uniq",
            ),
            models.UniqueConstraint(
                fields=["successor_provision"],
                name="reg_correction_successor_prov_uniq",
            ),
            models.UniqueConstraint(
                fields=["previous_obligation"],
                name="reg_correction_previous_obl_uniq",
            ),
            models.UniqueConstraint(
                fields=["successor_obligation"],
                name="reg_correction_successor_obl_uniq",
            ),
            models.CheckConstraint(
                condition=Q(correction_kind="recorded_time"),
                name="reg_correction_recorded_time",
            ),
            models.CheckConstraint(
                condition=Q(digest_schema=CORRECTION_DIGEST_SCHEMA),
                name="reg_correction_digest_schema",
            ),
            models.CheckConstraint(
                condition=~Q(before_payload_sha256=F("after_payload_sha256")),
                name="reg_correction_payload_changed",
            ),
            models.CheckConstraint(
                condition=~Q(previous_document_version=F("successor_document_version")),
                name="reg_correction_version_changed",
            ),
            models.CheckConstraint(
                condition=~Q(previous_provision=F("successor_provision")),
                name="reg_correction_provision_changed",
            ),
            models.CheckConstraint(
                condition=~Q(previous_obligation=F("successor_obligation")),
                name="reg_correction_obligation_changed",
            ),
            models.CheckConstraint(
                condition=~Q(rationale=""),
                name="reg_correction_rationale_present",
            ),
            models.CheckConstraint(
                condition=Q(is_published=False),
                name="reg_correction_not_published",
            ),
        ]

    def _validate_successor_pair(self, previous, successor, field: str) -> dict:
        errors = {}
        if (
            previous.folder_id != self.folder_id
            or successor.folder_id != self.folder_id
        ):
            errors[field] = "Correction revisions must remain in the event folder."
        elif successor.previous_revision_id != previous.id:
            errors[field] = "The successor must link to the recorded predecessor."
        elif successor.record_id != previous.record_id:
            errors[field] = "The successor must preserve the portable record ID."
        elif successor.revision != previous.revision + 1:
            errors[field] = "The successor revision must increment by one."
        elif previous.recorded_to != self.occurred_at:
            errors[field] = "The predecessor must close at the correction time."
        elif successor.recorded_from != self.occurred_at:
            errors[field] = "The successor must start at the correction time."
        return errors

    def clean(self) -> None:
        errors = {}
        if self.document_id and self.document.folder_id != self.folder_id:
            errors["document"] = "The document must be in the correction folder."
        if not (self.rationale or "").strip():
            errors["rationale"] = "A correction rationale is required."
        if self.before_payload_sha256 == self.after_payload_sha256:
            errors["after_payload_sha256"] = "A correction must change the chain."

        pairs = (
            (
                "previous_document_version_id",
                "successor_document_version_id",
                "previous_document_version",
                "successor_document_version",
                "successor_document_version",
            ),
            (
                "previous_provision_id",
                "successor_provision_id",
                "previous_provision",
                "successor_provision",
                "successor_provision",
            ),
            (
                "previous_obligation_id",
                "successor_obligation_id",
                "previous_obligation",
                "successor_obligation",
                "successor_obligation",
            ),
        )
        for previous_id, successor_id, previous_attr, successor_attr, field in pairs:
            if getattr(self, previous_id) and getattr(self, successor_id):
                errors.update(
                    self._validate_successor_pair(
                        getattr(self, previous_attr),
                        getattr(self, successor_attr),
                        field,
                    )
                )

        if (
            self.previous_document_version_id
            and self.document_id
            and self.previous_document_version.document_id != self.document_id
        ):
            errors["previous_document_version"] = (
                "The predecessor version must belong to the corrected document."
            )
        if (
            self.successor_document_version_id
            and self.document_id
            and self.successor_document_version.document_id != self.document_id
        ):
            errors["successor_document_version"] = (
                "The successor version must belong to the corrected document."
            )
        if (
            self.previous_provision_id
            and self.previous_document_version_id
            and self.previous_provision.document_version_id
            != self.previous_document_version_id
        ):
            errors["previous_provision"] = (
                "The predecessor provision must belong to the predecessor version."
            )
        if (
            self.successor_provision_id
            and self.successor_document_version_id
            and self.successor_provision.document_version_id
            != self.successor_document_version_id
        ):
            errors["successor_provision"] = (
                "The successor provision must belong to the successor version."
            )
        if (
            self.previous_obligation_id
            and self.previous_provision_id
            and not self.previous_obligation.provision_links.filter(
                folder_id=self.folder_id,
                provision_id=self.previous_provision_id,
            ).exists()
        ):
            errors["previous_obligation"] = (
                "The predecessor obligation must cite the predecessor provision."
            )
        if (
            self.successor_obligation_id
            and self.successor_provision_id
            and not self.successor_obligation.provision_links.filter(
                folder_id=self.folder_id,
                provision_id=self.successor_provision_id,
            ).exists()
        ):
            errors["successor_obligation"] = (
                "The successor obligation must cite the successor provision."
            )
        if errors:
            raise ValidationError(errors)
        super().clean()


common_exclude = ["created_at", "updated_at"]
auditlog.register(RegulatoryDocument, exclude_fields=common_exclude)
auditlog.register(EntityDocumentRegistration, exclude_fields=common_exclude)
auditlog.register(RegulatoryDocumentVersion, exclude_fields=common_exclude)
auditlog.register(RegulatoryProvision, exclude_fields=common_exclude)
auditlog.register(RegulatoryObligation, exclude_fields=common_exclude)
auditlog.register(RegulatoryObligationProvision, exclude_fields=common_exclude)
auditlog.register(RegulatoryObligationReviewEvent, exclude_fields=common_exclude)
auditlog.register(RegulatoryApplicabilityDecision, exclude_fields=common_exclude)
auditlog.register(
    RegulatoryApplicabilityReviewDisposition,
    exclude_fields=common_exclude,
)
auditlog.register(RegulatoryChainCorrectionEvent, exclude_fields=common_exclude)
