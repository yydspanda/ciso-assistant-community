from rest_framework import serializers

from core.serializer_fields import FieldsRelatedField
from core.serializers import BaseModelSerializer

from .models import (
    RegulatoryApplicabilityDecision,
    RegulatoryApplicabilityReviewDisposition,
    RegulatoryDocument,
    RegulatoryDocumentVersion,
    RegulatoryObligation,
    RegulatoryProvision,
)


class RegulatoryApplicabilityDecisionReadSerializer(serializers.ModelSerializer):
    scope = serializers.SerializerMethodField()
    rule = serializers.SerializerMethodField()
    facts = serializers.SerializerMethodField()
    provenance = serializers.SerializerMethodField()
    legal_conclusion = serializers.SerializerMethodField()

    class Meta:
        model = RegulatoryApplicabilityDecision
        fields = [
            "id",
            "record_id",
            "revision",
            "fact_snapshot_id",
            "scope",
            "rule",
            "facts",
            "missing_fact_keys",
            "result",
            "rationale_code",
            "rationale",
            "valid_from",
            "valid_to",
            "recorded_from",
            "recorded_to",
            "review_status",
            "is_binding",
            "digest_schema",
            "evaluator_profile",
            "rule_snapshot_sha256",
            "fact_snapshot_sha256",
            "semantic_payload_sha256",
            "provenance",
            "legal_conclusion",
        ]

    def get_scope(self, obj: RegulatoryApplicabilityDecision) -> dict:
        return {
            "type": obj.scope_type,
            "id": str(obj.registration.entity_id),
        }

    def get_rule(self, obj: RegulatoryApplicabilityDecision) -> dict:
        return obj.rule_snapshot

    def get_facts(self, obj: RegulatoryApplicabilityDecision) -> list[dict]:
        return obj.fact_snapshot

    def get_provenance(self, obj: RegulatoryApplicabilityDecision) -> dict:
        return obj.provenance_payload()

    def get_legal_conclusion(self, obj: RegulatoryApplicabilityDecision) -> bool:
        return False


class RegulatoryApplicabilityReviewDispositionReadSerializer(
    serializers.ModelSerializer
):
    """Read one review event without serializing its related User directly."""

    reviewer = serializers.SerializerMethodField()

    class Meta:
        model = RegulatoryApplicabilityReviewDisposition
        fields = [
            "id",
            "sequence",
            "from_disposition",
            "to_disposition",
            "reason_code",
            "rationale",
            "occurred_at",
            "digest_profile",
            "decision_semantic_payload_sha256",
            "event_payload_sha256",
            "reviewer",
        ]

    def get_reviewer(
        self,
        obj: RegulatoryApplicabilityReviewDisposition,
    ) -> dict:
        """Return the service-authorized minimal reviewer reference.

        The service performs related-User object IAM. This serializer deliberately
        does not use ``FieldsRelatedField`` because its implicit ``str(User)`` can
        fall back to an email address when a user has no display name.
        """

        reference = self.context.get("reviewer_reference")
        if reference is None or reference.masked or reference.id is None:
            return {"masked": True}

        display_name = reference.display_name
        if isinstance(display_name, str):
            display_name = display_name.strip() or None
            # Fail closed if an upstream display fallback ever supplies an email.
            if display_name is not None and "@" in display_name:
                display_name = None
        else:
            display_name = None
        return {
            "masked": False,
            "id": str(reference.id),
            "display_name": display_name,
        }


class RegulatoryObligationReadSerializer(serializers.ModelSerializer):
    review_status = serializers.SerializerMethodField()
    deadline = serializers.SerializerMethodField()
    provenance = serializers.SerializerMethodField()
    provision_ids = serializers.SerializerMethodField()
    legal_conclusion = serializers.SerializerMethodField()

    class Meta:
        model = RegulatoryObligation
        fields = [
            "id",
            "record_id",
            "revision",
            "title_zh",
            "authority_level",
            "modality",
            "subject",
            "action",
            "object",
            "conditions",
            "exceptions",
            "deadline",
            "expected_evidence",
            "penalty_or_consequence",
            "valid_from",
            "valid_to",
            "recorded_from",
            "recorded_to",
            "review_status",
            "confidence",
            "uncertainties",
            "provenance",
            "provision_ids",
            "legal_conclusion",
        ]

    def get_review_status(self, obj: RegulatoryObligation) -> str:
        events = getattr(obj, "prefetched_review_events", [])
        latest = max(events, key=lambda event: event.sequence, default=None)
        return latest.to_status if latest else obj.review_status

    def get_deadline(self, obj: RegulatoryObligation) -> dict:
        return {
            "kind": obj.deadline_kind,
            "value": obj.deadline_value,
            "rule_id": obj.deadline_rule_id,
        }

    def get_provenance(self, obj: RegulatoryObligation) -> dict:
        return obj.provenance_payload()

    def get_provision_ids(self, obj: RegulatoryObligation) -> list[str]:
        provisions = getattr(obj, "selected_source_provisions", [])
        return [
            provision.record_id
            for provision in provisions
            if provision.folder_id == obj.folder_id
        ]

    def get_legal_conclusion(self, obj: RegulatoryObligation) -> bool:
        return False


class RegulatoryProvisionReadSerializer(serializers.ModelSerializer):
    source_locator = serializers.SerializerMethodField()
    provenance = serializers.SerializerMethodField()
    obligations = serializers.SerializerMethodField()

    class Meta:
        model = RegulatoryProvision
        fields = [
            "id",
            "record_id",
            "revision",
            "article",
            "heading",
            "text",
            "source_locator",
            "content_hash",
            "recorded_from",
            "recorded_to",
            "provenance",
            "obligations",
        ]

    def get_source_locator(self, obj: RegulatoryProvision) -> dict:
        return {
            "kind": obj.source_locator_kind,
            "value": obj.source_locator_value,
        }

    def get_provenance(self, obj: RegulatoryProvision) -> dict:
        return obj.provenance_payload()

    def get_obligations(self, obj: RegulatoryProvision) -> list[dict]:
        obligations = getattr(obj, "selected_obligations", [])
        obligations = [
            obligation
            for obligation in obligations
            if obligation.folder_id == obj.folder_id
        ]
        return RegulatoryObligationReadSerializer(
            obligations,
            many=True,
            context=self.context,
        ).data


class RegulatoryDocumentVersionReadSerializer(serializers.ModelSerializer):
    provenance = serializers.SerializerMethodField()
    supersedes_version_ids = serializers.SerializerMethodField()
    provisions = serializers.SerializerMethodField()

    class Meta:
        model = RegulatoryDocumentVersion
        fields = [
            "id",
            "record_id",
            "revision",
            "version_label",
            "document_no",
            "status",
            "status_as_of",
            "effective_basis",
            "issued_date",
            "published_date",
            "effective_date",
            "transition_end",
            "repeal_date",
            "supersedes_version_ids",
            "source_url",
            "source_hash",
            "content_storage_policy",
            "notes",
            "source_checked_on",
            "metadata_confidence",
            "legal_review_status",
            "legal_reviewed_at",
            "legal_reviewed_by",
            "valid_from",
            "valid_to",
            "recorded_from",
            "recorded_to",
            "provenance",
            "provisions",
        ]

    def get_provenance(self, obj: RegulatoryDocumentVersion) -> dict:
        return obj.provenance_payload()

    def get_supersedes_version_ids(self, obj: RegulatoryDocumentVersion) -> list[str]:
        return []

    def get_provisions(self, obj: RegulatoryDocumentVersion) -> list[dict]:
        provisions = getattr(obj, "selected_provisions", [])
        provisions = [
            provision
            for provision in provisions
            if provision.folder_id == obj.folder_id
        ]
        return RegulatoryProvisionReadSerializer(
            provisions,
            many=True,
            context=self.context,
        ).data


class RegulatoryDocumentReadSerializer(BaseModelSerializer):
    folder = FieldsRelatedField()

    class Meta:
        model = RegulatoryDocument
        fields = [
            "id",
            "record_id",
            "title_zh",
            "title_en",
            "issuer",
            "authority_level",
            "territories",
            "regulated_entity_scopes",
            "domains",
            "coverage_priority",
            "coverage_stage",
            "applicability_fact_keys",
            "selection_rationale",
            "folder",
        ]


class RegulatoryDocumentDetailSerializer(RegulatoryDocumentReadSerializer):
    document_versions = serializers.SerializerMethodField()
    contract_status = serializers.SerializerMethodField()
    legal_conclusion = serializers.SerializerMethodField()
    recorded_as_of = serializers.SerializerMethodField()

    class Meta(RegulatoryDocumentReadSerializer.Meta):
        fields = RegulatoryDocumentReadSerializer.Meta.fields + [
            "contract_status",
            "legal_conclusion",
            "recorded_as_of",
            "document_versions",
        ]

    def get_document_versions(self, obj: RegulatoryDocument) -> list[dict]:
        versions = getattr(obj, "selected_versions", [])
        versions = [
            version for version in versions if version.folder_id == obj.folder_id
        ]
        return RegulatoryDocumentVersionReadSerializer(
            versions,
            many=True,
            context=self.context,
        ).data

    def get_contract_status(self, obj: RegulatoryDocument) -> str:
        return "draft"

    def get_legal_conclusion(self, obj: RegulatoryDocument) -> bool:
        return False

    def get_recorded_as_of(self, obj: RegulatoryDocument) -> str | None:
        recorded_as_of = self.context.get("requested_recorded_as_of")
        return recorded_as_of.isoformat() if recorded_as_of is not None else None
