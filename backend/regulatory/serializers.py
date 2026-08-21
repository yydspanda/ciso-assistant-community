from rest_framework import serializers

from core.serializer_fields import FieldsRelatedField
from core.serializers import BaseModelSerializer

from .models import (
    RegulatoryDocument,
    RegulatoryDocumentVersion,
    RegulatoryObligation,
    RegulatoryProvision,
)


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
        return obj.current_review_status

    def get_deadline(self, obj: RegulatoryObligation) -> dict:
        return {
            "kind": obj.deadline_kind,
            "value": obj.deadline_value,
            "rule_id": obj.deadline_rule_id,
        }

    def get_provenance(self, obj: RegulatoryObligation) -> dict:
        return obj.provenance_payload()

    def get_provision_ids(self, obj: RegulatoryObligation) -> list[str]:
        provisions = getattr(obj, "current_source_provisions", None)
        if provisions is None:
            provisions = obj.provisions.filter(
                recorded_to__isnull=True,
                folder_id=obj.folder_id,
            )
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
        obligations = getattr(obj, "current_obligations", None)
        if obligations is None:
            obligations = obj.obligations.filter(
                recorded_to__isnull=True,
                folder_id=obj.folder_id,
            )
        obligations = [
            obligation
            for obligation in obligations
            if obligation.folder_id == obj.folder_id
        ]
        return RegulatoryObligationReadSerializer(obligations, many=True).data


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
        provisions = getattr(obj, "current_provisions", None)
        if provisions is None:
            provisions = obj.provisions.filter(
                recorded_to__isnull=True,
                folder_id=obj.folder_id,
            )
        provisions = [
            provision
            for provision in provisions
            if provision.folder_id == obj.folder_id
        ]
        return RegulatoryProvisionReadSerializer(provisions, many=True).data


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

    class Meta(RegulatoryDocumentReadSerializer.Meta):
        fields = RegulatoryDocumentReadSerializer.Meta.fields + [
            "contract_status",
            "legal_conclusion",
            "document_versions",
        ]

    def get_document_versions(self, obj: RegulatoryDocument) -> list[dict]:
        versions = getattr(obj, "current_versions", None)
        if versions is None:
            versions = obj.versions.filter(
                recorded_to__isnull=True,
                folder_id=obj.folder_id,
            )
        versions = [
            version for version in versions if version.folder_id == obj.folder_id
        ]
        return RegulatoryDocumentVersionReadSerializer(versions, many=True).data

    def get_contract_status(self, obj: RegulatoryDocument) -> str:
        return "draft"

    def get_legal_conclusion(self, obj: RegulatoryDocument) -> bool:
        return False
