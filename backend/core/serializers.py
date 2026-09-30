import copy
import importlib
from typing import Any
from uuid import UUID

import structlog
from django.db import models, transaction
from datetime import datetime

from django.db.models import F, Q
from django.utils import timezone

from django.conf import settings
from core.models import *
from core.questionnaire_visibility import (
    DirectQuestionVisibilityContext,
    QuestionnaireVisibilityContext,
    project_questionnaire_payload,
)
from core.requirement_assessment_relationships import (
    GovernedRequirementAssessmentPrimaryKeyRelatedField,
    RequirementAssessmentRelationshipAuthorityMixin,
    RequirementAssessmentRelationshipProjectionListSerializer,
    RequirementAssessmentRelationshipProjectionMixin,
    assert_requirement_assessment_rows_editable,
    visible_requirement_assessment_rows,
)
from core.serializer_fields import (
    FieldsRelatedField,
    HashSlugRelatedField,
    PathField,
)
from core.constants import LEGACY_TTP_LIBRARIES
from core.utils import time_state
from ebios_rm.models import EbiosRMStudy, Stakeholder
from tprm.models import Contract, Solution
from threat_modeling.models import ThreatModel
from pmbok.models import GenericCollection
from doc_management.models import DocumentContainer
from global_settings.utils import ff_is_enabled

from core.commitment import COMMITMENT_LIST_FIELDS, CommitmentSerializerMixin
from iam.models import *
from django.contrib.auth.models import Permission

from rest_framework import serializers
from rest_framework.exceptions import APIException, PermissionDenied
from django.core.exceptions import (
    FieldDoesNotExist,
    ValidationError as DjangoValidationError,
)

from integrations.models import IntegrationConfiguration, SyncMapping

logger = structlog.get_logger(__name__)


class SerializerFactory:
    """Factory to get a serializer class from a list of modules.

    Attributes:
    modules (list): List of module names to search for the serializer.
    """

    def __init__(self, *modules: str):
        # Reverse to prioritize later modules
        self.modules = list(reversed(modules))

    def get_serializer(self, base_name: str, action: str):
        if action in ["list", "retrieve"]:
            serializer_name = f"{base_name}ReadSerializer"
        elif action in [
            "create",
            "update",
            "partial_update",
            "destroy",
            # OPTIONS: DRF describes the shape a client may send, so the
            # write serializer is the one to answer with.
            "metadata",
        ]:
            serializer_name = f"{base_name}WriteSerializer"
        else:
            return None

        return self._get_serializer_class(serializer_name)

    def _get_serializer_class(self, serializer_name: str):
        for module_name in self.modules:
            try:
                serializer_module = importlib.import_module(module_name)
                serializer_class = getattr(serializer_module, serializer_name)
                return serializer_class
            except ModuleNotFoundError, AttributeError:
                continue

        raise ValueError(
            f"Serializer {serializer_name} not found in any provided modules"
        )


class BaseModelSerializer(serializers.ModelSerializer):
    FLAGGED_FIELDS: dict[str, str] = {}

    # Fields a third-party *respondent* must never write on this model. They are
    # stripped centrally (see `_strip_respondent_protected_fields`) for any user
    # whose access to the target object's folder is respondent-scoped.
    # The per-audit-configurable equivalent for RequirementAssessment
    # fields lives in the compliance assessment's `field_visibility`.
    RESPONDENT_PROTECTED_FIELDS: set[str] = set()

    # Built-in objects are immutable by default. A model may keep specific fields
    # editable on built-in rows by listing them here, or set "__all__" for
    # built-in rows that are user-owned and fully editable (e.g. the default org
    # entity). Deletion of built-in objects is blocked at the permission layer.
    BUILTIN_EDITABLE_FIELDS: "set[str] | str" = set()

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        for field_name, flag_name in self.FLAGGED_FIELDS.items():
            if not ff_is_enabled(flag_name):
                self.fields.pop(field_name)

        # `builtin` flag must never be writable through the API.
        if "builtin" in self.fields:
            self.fields["builtin"].read_only = True

        # Enforce built-in immutability field-by-field: on a built-in instance,
        # every field outside BUILTIN_EDITABLE_FIELDS becomes read-only.
        if self.BUILTIN_EDITABLE_FIELDS != "__all__" and getattr(
            self.instance, "builtin", False
        ):
            for field_name, field in self.fields.items():
                if field_name not in self.BUILTIN_EDITABLE_FIELDS:
                    field.read_only = True

    def _strip_respondent_protected_fields(self, attrs: dict) -> dict:
        """Drop `RESPONDENT_PROTECTED_FIELDS` from *attrs* when the requesting
        user is a respondent on the target object's folder.

        Stripping is silent: full PUT bodies carry every field, so raising would
        turn unrelated respondent edits into 400s. Resolves the folder from the
        existing instance on update, or the incoming payload on create.
        """
        if not self.RESPONDENT_PROTECTED_FIELDS:
            return attrs
        request = self.context.get("request")
        if request is None or not getattr(request.user, "is_authenticated", False):
            return attrs
        folder = (
            Folder.get_folder(self.instance)
            if self.instance is not None
            else attrs.get("folder")
        )
        if folder is None:
            return attrs
        from core.utils import (
            get_respondent_scoped_folder_ids,
            has_full_view_compliance_assessment,
        )

        compliance_assessment = getattr(self.instance, "compliance_assessment", None)
        if compliance_assessment is not None:
            if has_full_view_compliance_assessment(request.user, compliance_assessment):
                return attrs
        elif folder.id not in get_respondent_scoped_folder_ids(request.user):
            return attrs
        for field_name in self.RESPONDENT_PROTECTED_FIELDS:
            attrs.pop(field_name, None)
        return attrs

    def _check_object_perm(
        self,
        instance_or_data,
        action: str,
        *,
        folder: Folder | None = None,
        model: type[models.Model] | None = None,
    ) -> None:
        """Check that the requesting user has *action* permission on the resolved folder.

        `model` overrides the permission codename's model when the checked
        object is not an instance of the serializer's own model.
        """
        if folder is None:
            folder = Folder.get_folder(instance_or_data)
        if folder is None:
            return
        request = self.context.get("request")
        if request is None:
            return
        model = model or self.Meta.model
        if not RoleAssignment.is_access_allowed(
            user=request.user,
            perm=Permission.objects.get(
                codename=f"{action}_{model._meta.model_name}",
            ),
            folder=folder,
        ):
            raise PermissionDenied(
                {
                    "folder": f"You do not have permission to {action} objects in this folder"
                }
            )

    def _ensure_immutable(self, field_name: str, value) -> None:
        """Raise PermissionDenied if a field differs from the persisted value.

        This treats null transitions as changes: None -> value, value -> None,
        and value -> different value are all blocked on update.
        """
        if self.instance is None:
            return
        current_id = getattr(self.instance, f"{field_name}_id", None)
        new_id = getattr(value, "id", None)
        if str(new_id) != str(current_id):
            raise PermissionDenied({field_name: "This field is immutable"})

    def validate_folder(self, folder: Folder) -> Folder:
        """Enforce permission when an object is moved to a different folder."""
        if (
            self.instance is not None
            and hasattr(self.instance, "folder_id")
            and str(folder.id) != str(self.instance.folder_id)
        ):
            if getattr(self.instance, "builtin", False):
                raise PermissionDenied(
                    {"folder": "Builtin objects cannot change folder"}
                )
            self._check_object_perm(self.instance, "add", folder=folder)
        return folder

    def update(self, instance: models.Model, validated_data: Any) -> models.Model:
        if self.context.get("commitment_transition"):
            # Taking a commitment step is its own right; see CommitmentActionsMixin.
            self._check_object_perm(instance, "transition", model=Commitment)
        else:
            self._check_object_perm(instance, "change")
        if hasattr(instance, "urn") and getattr(instance, "urn"):
            raise PermissionDenied({"urn": "Imported objects cannot be modified"})
        try:
            object_updated = super().update(instance, validated_data)
            return object_updated
        except Exception as e:
            logger.error(e)
            raise serializers.ValidationError(e.args[0])

    def _check_m2m_visibility(self, validated_data: dict) -> None:
        """Verify that all M2M linked objects are visible to the requesting user."""
        request = self.context.get("request")
        if not request or not request.user.is_authenticated:
            return
        user = request.user
        accessible_cache: dict = {}
        for field_name, value in validated_data.items():
            if not isinstance(value, list) or not value:
                continue
            if not all(isinstance(item, models.Model) for item in value):
                continue
            related_model = type(value[0])
            if related_model not in accessible_cache:
                try:
                    ids = RoleAssignment.get_viewable_object_ids(user, related_model)
                    accessible_cache[related_model] = {str(i) for i in ids}
                except NotImplementedError, Permission.DoesNotExist:
                    accessible_cache[related_model] = None
            accessible_ids = accessible_cache[related_model]
            if accessible_ids is None:
                continue
            # keeping an already-linked object is not linking a new one
            current_ids: set = set()
            if self.instance is not None and not isinstance(self.instance, list):
                manager = getattr(self.instance, field_name, None)
                if manager is not None and hasattr(manager, "values_list"):
                    current_ids = {
                        str(pk) for pk in manager.values_list("pk", flat=True)
                    }
            for item in value:
                if (
                    str(item.id) not in accessible_ids
                    and str(item.id) not in current_ids
                ):
                    raise PermissionDenied(
                        {
                            field_name: f"You do not have permission to link to this {related_model._meta.model_name}"
                        }
                    )

    def validate(self, data):
        data = super().validate(data)
        self._check_m2m_visibility(data)
        data = self._strip_respondent_protected_fields(data)
        return data

    def delete(self, instance: models.Model) -> None:
        """Enforce delete permission before removing *instance*."""
        self._check_object_perm(instance, "delete")
        instance.delete()

    def create(self, validated_data: Any):
        logger.debug("validated data", **validated_data)
        folder = Folder.get_folder(validated_data)
        folder = folder if folder else Folder.get_root_folder()
        self._check_object_perm(validated_data, "add", folder=folder)
        try:
            object_created = super().create(validated_data)
            return object_created
        except ValidationError as e:
            logger.error(e)
            raise serializers.ValidationError(e.args[0])

    def get_path(self, obj):
        """
        Gets the pre-calculated folder path for list views, with a fallback.
        """
        optimized_data = self.context.get("optimized_data")
        if optimized_data:
            # Use the pre-calculated path data if available
            return optimized_data.get("paths", {}).get(obj.id, [])

        # Fallback for single object serialization (e.g., retrieve endpoint)
        # We manually serialize the folder objects to match the new optimized output
        folders = obj.get_folder_full_path()
        return [{"id": f.id, "name": f.name} for f in folders]

    class Meta:
        model: models.Model


# Imported after BaseModelSerializer to avoid a circular import:
# custom_fields.serializers imports BaseModelSerializer from this module.
from custom_fields.serializers import CustomFieldsSerializerMixin  # noqa: E402


class ReferentialSerializer(BaseModelSerializer):
    name = serializers.CharField(source="get_name_translated")
    description = serializers.CharField(
        source="get_description_translated", allow_blank=True, allow_null=True
    )
    annotation = serializers.CharField(
        source="get_annotation_translated", allow_blank=True, allow_null=True
    )

    class Meta:
        model: ReferentialObjectMixin
        exclude = ["translations"]


class AssessmentReadSerializer(BaseModelSerializer):
    path = PathField(read_only=True)
    perimeter = FieldsRelatedField(["id", "folder"])
    authors = FieldsRelatedField(many=True)
    reviewers = FieldsRelatedField(many=True)
    folder = FieldsRelatedField()


# Risk Assessment


class RiskMatrixReadSerializer(ReferentialSerializer):
    folder = FieldsRelatedField()
    json_definition = serializers.JSONField(source="get_json_translated")
    library = FieldsRelatedField(["name", "id"])
    editing_languages = serializers.SerializerMethodField()

    def get_editing_languages(self, obj):
        """Return list of language codes available in the published translations."""
        langs = set()
        if obj.locale:
            langs.add(obj.locale)
        if obj.translations and isinstance(obj.translations, dict):
            langs.update(obj.translations.keys())
        return sorted(langs) if langs else [obj.locale or "en"]

    class Meta:
        model = RiskMatrix
        exclude = ["translations"]


class RiskMatrixWriteSerializer(RiskMatrixReadSerializer):
    pass


class RiskMatrixImportExportSerializer(BaseModelSerializer):
    library = serializers.SlugRelatedField(slug_field="urn", read_only=True)

    class Meta:
        model = RiskMatrix
        fields = [
            "created_at",
            "updated_at",
            "urn",
            "name",
            "description",
            "ref_id",
            "annotation",
            "translations",
            "locale",
            "default_locale",
            "library",
            "is_enabled",
            "provider",
            "json_definition",
        ]


class VulnerabilityReadSerializer(BaseModelSerializer):
    path = PathField(read_only=True)
    folder = FieldsRelatedField()
    applied_controls = FieldsRelatedField(many=True)
    assets = FieldsRelatedField(many=True)
    filtering_labels = FieldsRelatedField(["id", "folder"], many=True)
    security_exceptions = FieldsRelatedField(many=True)
    security_advisories = FieldsRelatedField(many=True)
    cwes = FieldsRelatedField(many=True)
    severity = serializers.CharField(source="get_severity_display")
    state = serializers.SerializerMethodField()

    RESOLVED_STATUSES = {"mitigated", "fixed", "not_exploitable", "unaffected"}

    def _get_sla_policy(self):
        """Per-instance cache — one DB query per serializer instantiation."""
        if not hasattr(self, "_sla_policy"):
            from global_settings.models import GlobalSettings

            try:
                sla_settings = GlobalSettings.objects.get(name="vulnerability-sla")
                self._sla_policy = (
                    sla_settings.value if isinstance(sla_settings.value, dict) else {}
                )
            except GlobalSettings.DoesNotExist:
                self._sla_policy = {}
        return self._sla_policy

    def get_state(self, obj):
        from datetime import date

        if obj.status in self.RESOLVED_STATUSES:
            return {"name": "resolved", "hexcolor": "#86efac"}

        if not obj.due_date:
            return None

        today = date.today()

        if obj.due_date < today:
            return {"name": "overdue", "hexcolor": "#f87171"}
        if obj.due_date == today:
            return {"name": "today", "hexcolor": "#f97316"}

        # Check if we're in the caution zone (past 50% of the SLA window)
        sla_policy = self._get_sla_policy()
        severity_label = obj.get_severity_display()
        try:
            sla_days = int(sla_policy.get(severity_label, 0)) or None
        except TypeError, ValueError:
            sla_days = None
        if sla_days is not None:
            remaining = (obj.due_date - today).days
            if remaining < sla_days * 0.5:
                return {"name": "caution", "hexcolor": "#fbbf24"}

        return {"name": "on track", "hexcolor": "#93c5fd"}

    class Meta:
        model = Vulnerability
        fields = "__all__"


class VulnerabilityWriteSerializer(BaseModelSerializer):
    findings = serializers.PrimaryKeyRelatedField(
        many=True, required=False, queryset=Finding.objects.all()
    )

    class Meta:
        model = Vulnerability
        exclude = ["created_at", "updated_at"]


class VulnerabilityImportExportSerializer(BaseModelSerializer):
    folder = HashSlugRelatedField(slug_field="pk", read_only=True)
    applied_controls = HashSlugRelatedField(slug_field="pk", read_only=True, many=True)

    class Meta:
        model = Vulnerability
        fields = [
            "ref_id",
            "name",
            "description",
            "folder",
            "status",
            "severity",
            "applied_controls",
            "created_at",
            "updated_at",
        ]


class RiskAcceptanceWriteSerializer(BaseModelSerializer):
    # Write-only flag so a new acceptance can be submitted for approval directly
    # from the creation form, instead of creating a draft then submitting it.
    submit = serializers.BooleanField(write_only=True, required=False, default=False)

    class Meta:
        model = RiskAcceptance
        exclude = ["accepted_at", "rejected_at", "revoked_at", "state"]

    def validate(self, data):
        # `submit` is only honoured on create; don't reject updates that carry it.
        if not self.instance and data.get("submit") and not data.get("approver"):
            raise serializers.ValidationError(
                {"approver": "An approver is required to submit for approval."}
            )
        return super().validate(data)

    def create(self, validated_data):
        submit = validated_data.pop("submit", False)
        instance = super().create(validated_data)
        if submit:
            instance.set_state("submitted")
        return instance

    def update(self, instance, validated_data):
        validated_data.pop("submit", False)
        return super().update(instance, validated_data)


class RiskAcceptanceReadSerializer(BaseModelSerializer):
    path = PathField(read_only=True)
    folder = FieldsRelatedField()
    risk_scenarios = FieldsRelatedField(many=True)
    approver = FieldsRelatedField(["id", "first_name", "last_name"])
    state = serializers.CharField(source="get_state_display")

    class Meta:
        model = RiskAcceptance
        fields = "__all__"


class PerimeterWriteSerializer(BaseModelSerializer):
    def validate_name(self, value):
        """
        Check that the folder perimeter name does not contain the character "/"
        """
        if "/" in value:
            raise serializers.ValidationError(
                "The name cannot contain '/' for a Perimeter."
            )
        return value

    def update(self, instance, validated_data):
        new_folder = validated_data.get("folder", None)
        if new_folder is not None:
            new_folder_id = (
                new_folder.id if isinstance(new_folder, models.Model) else new_folder
            )
            if new_folder_id and str(new_folder_id) != str(instance.folder_id):
                raise PermissionDenied({"folder": "Perimeter domain cannot be changed"})
        return super().update(instance, validated_data)

    class Meta:
        model = Perimeter
        exclude = ["created_at"]


class PerimeterReadSerializer(BaseModelSerializer):
    path = PathField(read_only=True)
    folder = FieldsRelatedField()
    lc_status = serializers.CharField(source="get_lc_status_display")
    default_assignee = FieldsRelatedField(many=True)

    class Meta:
        model = Perimeter
        fields = "__all__"


class PerimeterImportExportSerializer(BaseModelSerializer):
    folder = HashSlugRelatedField(slug_field="pk", read_only=True)

    class Meta:
        model = Perimeter
        fields = [
            "ref_id",
            "name",
            "description",
            "folder",
            "lc_status",
            "created_at",
            "updated_at",
        ]


class RiskAssessmentWriteSerializer(BaseModelSerializer):
    genericcollection = serializers.PrimaryKeyRelatedField(
        source="genericcollection_set",
        many=True,
        required=False,
        queryset=GenericCollection.objects.all(),
    )

    def validate(self, attrs):
        if hasattr(self, "instance") and self.instance and self.instance.is_locked:
            # If we're unlocking (setting is_locked to False), allow the operation
            if "is_locked" in attrs and attrs["is_locked"] is False:
                return super().validate(attrs)

            # Otherwise, only allow modifying the is_locked field
            locked_fields = [field for field in attrs.keys() if field != "is_locked"]
            if locked_fields:
                raise serializers.ValidationError(
                    f"⚠️ Cannot modify the risk assessment attributes when it is locked. Only the 'Locked' field can be modified."
                )
        return super().validate(attrs)

    def update(self, instance, validated_data):
        # Check if status is changing to deprecated
        old_status = instance.status
        new_status = validated_data.get("status", old_status)

        # Auto-lock when status changes to deprecated
        if old_status != "deprecated" and new_status == "deprecated":
            validated_data["is_locked"] = True

        # If perimeter is being changed, update folder to match the new perimeter's folder
        if "perimeter" in validated_data:
            new_perimeter = validated_data["perimeter"]
            if new_perimeter and new_perimeter.folder:
                validated_data["folder"] = new_perimeter.folder

        # Check if folder is being changed (either directly or via perimeter)
        new_folder = validated_data.get("folder")
        if new_folder and new_folder != instance.folder:
            # Cascade folder change to all child RiskScenarios
            instance.risk_scenarios.update(folder=new_folder)

        return super().update(instance, validated_data)

    class Meta:
        model = RiskAssessment
        exclude = ["created_at", "updated_at"]


class RiskAssessmentDuplicateSerializer(BaseModelSerializer):
    class Meta:
        model = RiskAssessment
        fields = ["name", "version", "perimeter", "description", "folder"]


class RiskAssessmentReadSerializer(AssessmentReadSerializer):
    path = PathField(read_only=True)
    str = serializers.CharField(source="__str__")
    perimeter = FieldsRelatedField(["id", "folder"])
    folder = FieldsRelatedField()
    risk_scenarios = FieldsRelatedField(many=True, fields=["id", "name", "ref_id"])
    risk_scenarios_count = serializers.IntegerField(source="risk_scenarios.count")
    risk_matrix = FieldsRelatedField()
    ebios_rm_study = FieldsRelatedField(["id", "name"])
    validation_flows = FieldsRelatedField(
        many=True,
        fields=[
            "id",
            "ref_id",
            "status",
            "request_notes",
            "last_event_notes",
            {"approver": ["id", "email", "first_name", "last_name"]},
        ],
        source="validationflow_set",
    )

    class Meta:
        model = RiskAssessment
        exclude = []


class RiskAssessmentImportExportSerializer(BaseModelSerializer):
    risk_matrix = serializers.SlugRelatedField(slug_field="urn", read_only=True)

    folder = HashSlugRelatedField(slug_field="pk", read_only=True)
    perimeter = HashSlugRelatedField(slug_field="pk", read_only=True)
    ebios_rm_study = HashSlugRelatedField(slug_field="pk", read_only=True)

    class Meta:
        model = RiskAssessment
        fields = [
            "ref_id",
            "name",
            "version",
            "description",
            "folder",
            "perimeter",
            "eta",
            "due_date",
            "status",
            "observation",
            "risk_matrix",
            "ebios_rm_study",
            "created_at",
            "updated_at",
        ]


class AssetCapabilityReadSerializer(ReferentialSerializer):
    class Meta:
        model = AssetCapability
        exclude = ["translations"]


class AssetCapabilityWriteSerializer(AssetCapabilityReadSerializer):
    pass


class IntegrationLinkSerializerMixin(serializers.Serializer):
    """Adds remote-object linking to a model serializer.

    Declares the write-only ``integration_config`` / ``remote_object_id`` /
    ``create_remote_object`` fields (stripped before the model is written) and
    exposes existing ``sync_mappings`` on read, scoped by content type. The
    actual SyncMapping creation / sync scheduling is done by
    ``IntegrationLinkViewSetMixin`` on the viewset.
    """

    integration_config = serializers.PrimaryKeyRelatedField(
        required=False,
        allow_null=True,
        queryset=IntegrationConfiguration.objects.all(),
        write_only=True,
    )
    remote_object_id = serializers.CharField(
        required=False, allow_blank=True, allow_null=True, write_only=True
    )
    create_remote_object = serializers.BooleanField(
        required=False, default=False, write_only=True
    )

    _INTEGRATION_LINK_FIELDS = (
        "integration_config",
        "remote_object_id",
        "create_remote_object",
    )

    def _strip_integration_link_fields(self, validated_data):
        for field in self._INTEGRATION_LINK_FIELDS:
            validated_data.pop(field, None)

    def create(self, validated_data):
        self._strip_integration_link_fields(validated_data)
        return super().create(validated_data)

    def update(self, instance, validated_data):
        self._strip_integration_link_fields(validated_data)
        return super().update(instance, validated_data)

    def to_representation(self, instance):
        ret = super().to_representation(instance)
        # Only run the sync-mapping lookup on detail reads. Skipping it for
        # list/create/update avoids a per-object SELECT that almost always
        # returns nothing (mirrors AppliedControlReadSerializer).
        if self.context.get("action") != "retrieve":
            return ret
        from django.contrib.contenttypes.models import ContentType

        content_type = ContentType.objects.get_for_model(instance.__class__)
        sync_mappings = [
            {
                "id": mapping.id,
                "remote_id": mapping.remote_id,
                "sync_status": mapping.sync_status,
                "last_synced_at": mapping.last_synced_at,
                "last_sync_direction": mapping.last_sync_direction,
                "error_message": mapping.error_message,
                "provider": mapping.configuration.provider.name,
            }
            for mapping in SyncMapping.objects.filter(
                content_type=content_type, local_object_id=instance.id
            )
            .select_related("configuration__provider")
            .only(
                "id",
                "remote_id",
                "sync_status",
                "last_synced_at",
                "last_sync_direction",
                "error_message",
                "configuration__provider__name",
            )
        ]
        if sync_mappings:
            ret["sync_mappings"] = sync_mappings
        return ret


class AssetWriteSerializer(
    IntegrationLinkSerializerMixin, CustomFieldsSerializerMixin, BaseModelSerializer
):
    ebios_rm_studies = serializers.PrimaryKeyRelatedField(
        many=True,
        queryset=EbiosRMStudy.objects.all(),
        required=False,
        allow_null=True,
        write_only=True,
    )
    parent_assets = serializers.PrimaryKeyRelatedField(
        many=True,
        queryset=Asset.objects.all(),
        required=False,
    )
    support_assets = serializers.PrimaryKeyRelatedField(
        source="child_assets",
        many=True,
        queryset=Asset.objects.all(),
        required=False,
    )
    solutions = serializers.PrimaryKeyRelatedField(
        many=True,
        queryset=Solution.objects.all(),
        required=False,
    )
    security_exceptions = serializers.PrimaryKeyRelatedField(
        many=True,
        queryset=SecurityException.objects.all(),
        required=False,
    )
    documents = serializers.PrimaryKeyRelatedField(
        many=True,
        queryset=DocumentContainer.objects.all(),
        required=False,
    )
    applied_controls = serializers.PrimaryKeyRelatedField(
        many=True,
        queryset=AppliedControl.objects.all(),
        required=False,
    )
    vulnerabilities = serializers.PrimaryKeyRelatedField(
        many=True,
        queryset=Vulnerability.objects.all(),
        required=False,
    )
    incidents = serializers.PrimaryKeyRelatedField(
        many=True,
        queryset=Incident.objects.all(),
        required=False,
    )
    organisation_objectives = serializers.PrimaryKeyRelatedField(
        queryset=OrganisationObjective.objects.all(),
        many=True,
        required=False,
    )

    class Meta:
        model = Asset
        exclude = ["business_value"]

    def validate(self, data):
        self._check_linked_assets_changeable(data)
        parent_assets = data.get("parent_assets", [])
        support_assets = data.get("child_assets", [])
        """
        Check that the assets graph will not contain cycles
        """
        myset = set()
        if self.instance:
            myset = set([self.instance])
        if parent_assets:
            myset = myset | set(support_assets)

            for asset in parent_assets:
                if myset & set(asset.ancestors_plus_self()):
                    raise serializers.ValidationError(
                        "errorAssetGraphMustNotContainCycles"
                    )
        return super().validate(data)

    def _check_linked_assets_changeable(self, data):
        request = self.context.get("request")
        if request is None:
            return
        perm = Permission.objects.get(codename="change_asset")
        for field, error_key in (
            ("parent_assets", "parent_assets"),
            ("child_assets", "support_assets"),
        ):
            if field not in data:
                continue
            proposed = {a.id: a for a in data[field] or []}
            current = (
                {a.id: a for a in getattr(self.instance, field).all()}
                if self.instance is not None
                else {}
            )
            removed = [current[i] for i in current.keys() - proposed.keys()]
            unseen = [
                a
                for a in removed
                if not RoleAssignment.is_object_readable(request.user, Asset, a.id)
            ]
            if unseen:
                data[field] = [*proposed.values(), *unseen]
            touched = [proposed[i] for i in proposed.keys() - current.keys()] + [
                a for a in removed if a not in unseen
            ]
            for asset in touched:
                if not RoleAssignment.is_access_allowed(
                    user=request.user, perm=perm, folder=asset.folder
                ):
                    raise PermissionDenied(
                        {
                            error_key: "You do not have permission to change the linked asset"
                        }
                    )

    def create(self, validated_data):
        parent_assets = validated_data.pop("parent_assets", None)
        child_assets = validated_data.pop("child_assets", None)
        applied_controls = validated_data.pop("applied_controls", None)
        vulnerabilities = validated_data.pop("vulnerabilities", None)
        incidents = validated_data.pop("incidents", None)
        asset = super().create(validated_data)

        if parent_assets is not None:
            asset.parent_assets.set(parent_assets)
        if child_assets is not None:
            asset.child_assets.set(child_assets)
        if applied_controls is not None:
            asset.applied_controls.set(applied_controls)
        if vulnerabilities is not None:
            asset.vulnerabilities.set(vulnerabilities)
        if incidents is not None:
            asset.incidents.set(incidents)

        return asset

    def update(self, instance, validated_data):
        parent_assets = validated_data.pop("parent_assets", None)
        child_assets = validated_data.pop("child_assets", None)
        applied_controls = validated_data.pop("applied_controls", None)
        vulnerabilities = validated_data.pop("vulnerabilities", None)
        incidents = validated_data.pop("incidents", None)

        instance = super().update(instance, validated_data)

        # Set parent_assets and support_assets (child_assets) if provided
        if parent_assets is not None:
            instance.parent_assets.set(parent_assets)
        if child_assets is not None:
            instance.child_assets.set(child_assets)
        if applied_controls is not None:
            instance.applied_controls.set(applied_controls)
        if vulnerabilities is not None:
            instance.vulnerabilities.set(vulnerabilities)
        if incidents is not None:
            instance.incidents.set(incidents)

        return instance


class AssetReadSerializer(AssetWriteSerializer):
    path = PathField(read_only=True)
    folder = FieldsRelatedField()
    parent_assets = FieldsRelatedField(many=True)
    support_assets = FieldsRelatedField(source="child_assets", many=True)
    owner = FieldsRelatedField(many=True)
    filtering_labels = FieldsRelatedField(["id", "folder"], many=True)
    type = serializers.CharField(source="get_type_display")
    security_exceptions = FieldsRelatedField(many=True)
    personal_data = FieldsRelatedField(many=True)
    asset_class = FieldsRelatedField(["id", "name"])
    overridden_children_capabilities = FieldsRelatedField(["id", "name"], many=True)
    solutions = FieldsRelatedField(many=True)
    applied_controls = FieldsRelatedField(many=True)
    documents = FieldsRelatedField(many=True)

    children_assets = serializers.SerializerMethodField()
    security_objectives = serializers.SerializerMethodField()
    disaster_recovery_objectives = serializers.SerializerMethodField()
    security_capabilities = serializers.SerializerMethodField()
    recovery_capabilities = serializers.SerializerMethodField()
    security_objectives_comparison = serializers.SerializerMethodField()
    recovery_objectives_comparison = serializers.SerializerMethodField()

    def get_children_assets(self, obj):
        """
        Gets pre-calculated descendant IDs for list views, with a fallback for detail views.
        """
        optimized_data = self.context.get("optimized_data")
        if optimized_data:
            # Use pre-calculated data if available
            return optimized_data.get("descendants", {}).get(obj.id, [])

        # Fallback for single object serialization
        return obj.children_assets.annotate(str=F("name")).values("id", "str")

    def get_security_objectives(self, obj):
        """
        Gets pre-calculated security objectives for list views, with a fallback.
        """
        optimized_data = self.context.get("optimized_data")
        if optimized_data:
            return optimized_data.get("security_objectives", {}).get(obj.id, [])

        # Fallback for single object serialization
        return obj.get_security_objectives_display()

    def get_disaster_recovery_objectives(self, obj):
        """
        Gets pre-calculated disaster recovery objectives for list views, with a fallback.
        """
        optimized_data = self.context.get("optimized_data")
        if optimized_data:
            return optimized_data.get("disaster_recovery_objectives", {}).get(
                obj.id, []
            )

        # Fallback for single object serialization
        return obj.get_disaster_recovery_objectives_display()

    def get_security_capabilities(self, obj):
        """
        Gets pre-calculated security capabilities for list views, with a fallback.
        """
        optimized_data = self.context.get("optimized_data")
        if optimized_data:
            return optimized_data.get("security_capabilities", {}).get(obj.id, [])

        # Fallback for single object serialization
        return obj.get_security_capabilities_display()

    def get_recovery_capabilities(self, obj):
        """
        Gets pre-calculated recovery capabilities for list views, with a fallback.
        """
        optimized_data = self.context.get("optimized_data")
        if optimized_data:
            return optimized_data.get("recovery_capabilities", {}).get(obj.id, [])

        # Fallback for single object serialization
        return obj.get_recovery_capabilities_display()

    def get_security_objectives_comparison(self, obj):
        """
        Gets comparison of security objectives vs capabilities with verdict.
        """
        optimized_data = self.context.get("optimized_data")
        if optimized_data and "security_objectives_comparison" in optimized_data:
            return optimized_data["security_objectives_comparison"].get(obj.id, [])
        return obj.get_security_objectives_comparison()

    def get_recovery_objectives_comparison(self, obj):
        """
        Gets comparison of recovery objectives vs capabilities with verdict.
        """
        optimized_data = self.context.get("optimized_data")
        if optimized_data and "recovery_objectives_comparison" in optimized_data:
            return optimized_data["recovery_objectives_comparison"].get(obj.id, [])
        return obj.get_recovery_objectives_comparison()


class AssetListSerializer(CustomFieldsSerializerMixin, BaseModelSerializer):
    """
    Lightweight serializer for the assets list view.

    Only includes fields rendered in the assets table (see frontend `table.ts`),
    plus the aggregated objectives that the list also displays. Capability
    aggregates and the `*_comparison` fields are skipped here to avoid the
    per-row graph traversals they trigger — those remain on `AssetReadSerializer`
    for the detail view.
    """

    folder = FieldsRelatedField()
    asset_class = FieldsRelatedField(["id", "name"])
    owner = FieldsRelatedField(many=True)
    filtering_labels = FieldsRelatedField(["id", "folder"], many=True)
    parent_assets = FieldsRelatedField(many=True)
    type = serializers.CharField(source="get_type_display")
    security_objectives = serializers.SerializerMethodField()
    disaster_recovery_objectives = serializers.SerializerMethodField()

    class Meta:
        model = Asset
        fields = [
            "id",
            "ref_id",
            "name",
            "description",
            "type",
            "is_primary",
            "is_business_function",
            "folder",
            "asset_class",
            "owner",
            "filtering_labels",
            "parent_assets",
            "security_objectives",
            "disaster_recovery_objectives",
            "custom_fields",
            "created_at",
            "updated_at",
        ]

    def get_security_objectives(self, obj):
        optimized_data = self.context.get("optimized_data")
        if optimized_data:
            return optimized_data.get("security_objectives", {}).get(obj.id, [])
        return obj.get_security_objectives_display()

    def get_disaster_recovery_objectives(self, obj):
        optimized_data = self.context.get("optimized_data")
        if optimized_data:
            return optimized_data.get("disaster_recovery_objectives", {}).get(
                obj.id, []
            )
        return obj.get_disaster_recovery_objectives_display()


class AssetAutocompleteSerializer(BaseModelSerializer):
    folder = FieldsRelatedField()
    type = serializers.CharField(source="get_type_display")

    class Meta:
        model = Asset
        fields = ["id", "name", "ref_id", "type", "folder"]

    def to_representation(self, instance):
        data = super().to_representation(instance)
        data["str"] = str(instance)
        return data


class AppliedControlAutocompleteSerializer(BaseModelSerializer):
    folder = FieldsRelatedField()
    category = serializers.CharField(source="get_category_display")

    class Meta:
        model = AppliedControl
        fields = ["id", "name", "ref_id", "folder", "category"]

    def to_representation(self, instance):
        data = super().to_representation(instance)
        data["str"] = str(instance)
        return data


class VulnerabilityAutocompleteSerializer(BaseModelSerializer):
    folder = FieldsRelatedField()

    class Meta:
        model = Vulnerability
        fields = ["id", "name", "ref_id", "folder"]

    def to_representation(self, instance):
        data = super().to_representation(instance)
        data["str"] = str(instance)
        return data


class RiskScenarioAutocompleteSerializer(BaseModelSerializer):
    folder = FieldsRelatedField()
    risk_assessment = FieldsRelatedField()

    class Meta:
        model = RiskScenario
        fields = ["id", "name", "ref_id", "folder", "risk_assessment"]

    def to_representation(self, instance):
        data = super().to_representation(instance)
        data["str"] = str(instance)
        return data


class AssetImportExportSerializer(BaseModelSerializer):
    folder = HashSlugRelatedField(slug_field="pk", read_only=True)
    parent_assets = HashSlugRelatedField(slug_field="pk", read_only=True, many=True)
    # Canonical path, not a pk: asset classes are root-folder referentials and
    # never travel in the dump, so a pk would dangle on the target instance.
    asset_class = serializers.SerializerMethodField()

    def get_asset_class(self, obj) -> str | None:
        return obj.asset_class.full_path if obj.asset_class else None

    class Meta:
        model = Asset
        fields = [
            "type",
            "name",
            "description",
            "reference_link",
            "security_objectives",
            "disaster_recovery_objectives",
            "parent_assets",
            "asset_class",
            "folder",
            "created_at",
            "updated_at",
        ]


class AssetClassReadSerializer(BaseModelSerializer):
    path = PathField(read_only=True)
    parent = FieldsRelatedField()
    # Needed by the frontend to resolve the folder governing this object.
    folder = FieldsRelatedField()
    full_path = serializers.CharField()
    # `name`/`description` stay canonical: the edit form round-trips them.
    translated_name = serializers.CharField(source="get_name_translated")
    translated_description = serializers.CharField(
        source="get_description_translated", allow_blank=True, allow_null=True
    )

    class Meta:
        model = AssetClass
        exclude = ["created_at", "updated_at"]


class AssetClassWriteSerializer(BaseModelSerializer):
    # Built-ins are re-seeded at every startup: they are hidable, not editable.
    BUILTIN_EDITABLE_FIELDS = {"is_visible"}

    class Meta:
        model = AssetClass
        exclude = ["created_at", "updated_at", "folder"]

    def validate_name(self, value):
        if "/" in value:
            raise serializers.ValidationError(
                "The name cannot contain '/' for an Asset class."
            )
        return value

    def validate_parent(self, parent):
        """Check that the asset class tree will not contain cycles."""
        if parent is not None and self.instance in parent.ancestors_plus_self():
            raise serializers.ValidationError(
                "errorAssetClassGraphMustNotContainCycles"
            )
        return parent


class ReferenceControlWriteSerializer(BaseModelSerializer):
    findings = serializers.PrimaryKeyRelatedField(
        many=True, required=False, queryset=Finding.objects.all()
    )

    class Meta:
        model = ReferenceControl
        exclude = ["translations"]


class ReferenceControlReadSerializer(ReferentialSerializer):
    path = PathField(read_only=True)
    folder = FieldsRelatedField()
    library = FieldsRelatedField(["name", "id"])
    filtering_labels = FieldsRelatedField(["id", "folder"], many=True)

    class Meta:
        model = ReferenceControl
        exclude = ["translations"]


class ReferenceControlImportExportSerializer(BaseModelSerializer):
    library = serializers.SlugRelatedField(slug_field="urn", read_only=True)

    folder = HashSlugRelatedField(slug_field="pk", read_only=True)

    class Meta:
        model = ReferenceControl
        fields = [
            "ref_id",
            "name",
            "description",
            "urn",
            "provider",
            "category",
            "csf_function",
            "typical_evidence",
            "annotation",
            "translations",
            "locale",
            "default_locale",
            "folder",
            "library",
            "created_at",
            "updated_at",
        ]


"""class LibraryReadSerializer(BaseModelSerializer):
    class Meta:
        model = LoadedLibrary
        fields = "__all__"


class LibraryWriteSerializer(BaseModelSerializer):
    class Meta:
        model = LoadedLibrary
        fields = "__all__"
"""


class ThreatWriteSerializer(BaseModelSerializer):
    findings = serializers.PrimaryKeyRelatedField(
        many=True, required=False, queryset=Finding.objects.all()
    )

    class Meta:
        model = Threat
        exclude = ["translations"]


class ThreatReadSerializer(ReferentialSerializer):
    path = PathField(read_only=True)
    folder = FieldsRelatedField()
    library = FieldsRelatedField(["name", "id"])
    filtering_labels = FieldsRelatedField(["id", "folder"], many=True)
    is_legacy_ttp = serializers.SerializerMethodField()

    def get_is_legacy_ttp(self, obj) -> bool:
        return bool(obj.library and obj.library.urn in LEGACY_TTP_LIBRARIES)

    class Meta:
        model = Threat
        exclude = ["translations"]


class ThreatImportExportSerializer(BaseModelSerializer):
    library = serializers.SlugRelatedField(slug_field="urn", read_only=True)

    folder = HashSlugRelatedField(slug_field="pk", read_only=True)

    class Meta:
        model = Threat
        fields = [
            "created_at",
            "updated_at",
            "folder",
            "urn",
            "ref_id",
            "provider",
            "name",
            "description",
            "annotation",
            "translations",
            "locale",
            "default_locale",
            "library",
        ]


REFERENTIAL_IMPORT_EXPORT_FIELDS = [
    "created_at",
    "updated_at",
    "folder",
    "urn",
    "ref_id",
    "provider",
    "name",
    "description",
    "annotation",
    "translations",
    "locale",
    "default_locale",
    "library",
]


class RiskScenarioWriteSerializer(BaseModelSerializer):
    # Note: Inherent risk fields are always accepted for writing,
    # but only displayed when inherent_risk feature flag is enabled
    FLAGGED_FIELDS = {"threat_models": "threat_modeling"}

    risk_matrix = serializers.PrimaryKeyRelatedField(
        read_only=True, source="risk_assessment.risk_matrix"
    )
    threat_models = serializers.PrimaryKeyRelatedField(
        many=True, required=False, queryset=ThreatModel.objects.all()
    )

    def validate_risk_assessment(self, value):
        self._ensure_immutable("risk_assessment", value)
        return value

    def validate(self, attrs):
        if (
            hasattr(self, "instance")
            and self.instance
            and self.instance.risk_assessment.is_locked
        ):
            raise serializers.ValidationError(
                "⚠️ Cannot modify the risk scenario when the risk assessment is locked."
            )

        antecedent_scenarios = attrs.get("antecedent_scenarios", [])
        consequent_scenarios = attrs.get("consequent_scenarios", [])

        # Check that the scenario graph will not contain cycles
        myset = set()
        if self.instance:
            myset = set([self.instance])

        if antecedent_scenarios:
            # Add all consequent scenarios to the set
            if self.instance:
                myset = myset | set(self.instance.consequent_scenarios.all())

            for scenario in antecedent_scenarios:
                if myset & set(scenario.ancestors_plus_self()):
                    raise serializers.ValidationError(
                        {
                            "antecedent_scenarios": "errorRiskScenarioGraphMustNotContainCycles"
                        }
                    )

        return super().validate(attrs)

    def create(self, validated_data):
        # Set folder from risk_assessment before the permission check in parent class
        if "risk_assessment" in validated_data and validated_data["risk_assessment"]:
            validated_data["folder"] = validated_data["risk_assessment"].folder

        owner_data = validated_data.get("owner", [])
        risk_scenario = super().create(validated_data)

        # Send notification to newly assigned owners
        if owner_data:
            self._send_assignment_notifications(
                risk_scenario, [actor.id for actor in owner_data]
            )

        return risk_scenario

    def update(self, instance, validated_data):
        # Track old owners before update
        old_owner_ids = set(instance.owner.values_list("id", flat=True))

        updated_instance = super().update(instance, validated_data)

        # Get new owners after update
        new_owner_ids = set(updated_instance.owner.values_list("id", flat=True))

        # Send notifications only to newly assigned owners
        newly_assigned_ids = new_owner_ids - old_owner_ids
        if newly_assigned_ids:
            self._send_assignment_notifications(
                updated_instance, list(newly_assigned_ids)
            )

        return updated_instance

    def _send_assignment_notifications(self, risk_scenario, owner_ids):
        """Send assignment notifications to the specified owners"""
        if not owner_ids:
            return

        try:
            from core.models import Actor
            from .tasks import send_risk_scenario_assignment_notification

            assigned_actors = Actor.objects.filter(id__in=owner_ids)
            assigned_emails = []
            for actor in assigned_actors:
                assigned_emails.extend(actor.get_emails())

            if assigned_emails:
                # Queue the task for async execution
                send_risk_scenario_assignment_notification(
                    risk_scenario.id, assigned_emails
                )
        except Exception as e:
            logger.error(
                f"Failed to send RiskScenario assignment notification: {str(e)}"
            )

    class Meta:
        model = RiskScenario
        exclude = ["folder"]


class RiskScenarioReadSerializer(RiskScenarioWriteSerializer):
    str = serializers.CharField(source="__str__", read_only=True)
    risk_assessment = FieldsRelatedField(["id", "name", "is_locked"])
    risk_matrix = FieldsRelatedField(source="risk_assessment.risk_matrix")
    folder = FieldsRelatedField()
    version = serializers.StringRelatedField(source="risk_assessment.version")
    operational_scenario = FieldsRelatedField(["id", "name", "ebios_rm_study"])
    threats = FieldsRelatedField(many=True)
    threat_models = FieldsRelatedField(many=True)
    assets = FieldsRelatedField(many=True)
    qualifications = FieldsRelatedField(many=True)
    risk_origin = FieldsRelatedField(["id", "name", "description"])
    antecedent_scenarios = FieldsRelatedField(
        many=True, fields=["id", "ref_id", "name"]
    )

    treatment = serializers.CharField()

    inherent_proba = serializers.JSONField(source="get_inherent_proba")
    inherent_impact = serializers.JSONField(source="get_inherent_impact")
    inherent_level = serializers.JSONField(source="get_inherent_risk")
    current_proba = serializers.JSONField(source="get_current_proba")
    current_impact = serializers.JSONField(source="get_current_impact")
    current_level = serializers.JSONField(source="get_current_risk")
    residual_proba = serializers.JSONField(source="get_residual_proba")
    residual_impact = serializers.JSONField(source="get_residual_impact")
    residual_level = serializers.JSONField(source="get_residual_risk")

    strength_of_knowledge = serializers.JSONField(source="get_strength_of_knowledge")

    applied_controls = FieldsRelatedField(many=True)
    existing_applied_controls = FieldsRelatedField(many=True)
    incidents = FieldsRelatedField(many=True)

    owner = FieldsRelatedField(many=True)
    security_exceptions = FieldsRelatedField(many=True)
    filtering_labels = FieldsRelatedField(many=True)

    within_tolerance = serializers.CharField()

    class Meta:
        model = RiskScenario
        fields = "__all__"


class RiskScenarioImportExportSerializer(BaseModelSerializer):
    threats = HashSlugRelatedField(slug_field="pk", many=True, read_only=True)
    risk_assessment = HashSlugRelatedField(slug_field="pk", read_only=True)
    vulnerabilities = HashSlugRelatedField(slug_field="pk", read_only=True, many=True)
    assets = HashSlugRelatedField(slug_field="pk", read_only=True, many=True)
    existing_applied_controls = HashSlugRelatedField(
        slug_field="pk", read_only=True, many=True
    )
    applied_controls = HashSlugRelatedField(slug_field="pk", read_only=True, many=True)
    qualifications = serializers.SlugRelatedField(
        slug_field="name", read_only=True, many=True
    )
    risk_origin = serializers.SlugRelatedField(
        slug_field="name", read_only=True, many=False
    )

    class Meta:
        model = RiskScenario
        fields = [
            "ref_id",
            "name",
            "description",
            "risk_assessment",
            "treatment",
            "threats",
            "vulnerabilities",
            "assets",
            "existing_applied_controls",
            "applied_controls",
            "current_proba",
            "current_impact",
            "residual_proba",
            "residual_impact",
            "strength_of_knowledge",
            "justification",
            "created_at",
            "updated_at",
            "qualifications",
            "risk_origin",
        ]


class AppliedControlWriteSerializer(
    RequirementAssessmentRelationshipAuthorityMixin,
    CommitmentSerializerMixin,
    CustomFieldsSerializerMixin,
    BaseModelSerializer,
):
    findings = serializers.PrimaryKeyRelatedField(
        many=True, required=False, queryset=Finding.objects.all()
    )
    requirement_assessments = GovernedRequirementAssessmentPrimaryKeyRelatedField(
        many=True, queryset=RequirementAssessment.objects.all(), required=False
    )
    stakeholders = serializers.PrimaryKeyRelatedField(
        many=True, required=False, queryset=Stakeholder.objects.all()
    )
    task_templates = serializers.PrimaryKeyRelatedField(
        many=True, required=False, queryset=TaskTemplate.objects.all()
    )
    incidents = serializers.PrimaryKeyRelatedField(
        many=True, required=False, queryset=Incident.objects.all()
    )
    control_documents = serializers.PrimaryKeyRelatedField(
        many=True, required=False, queryset=DocumentContainer.objects.all()
    )
    cost = serializers.JSONField(required=False, allow_null=True)
    integration_config = serializers.PrimaryKeyRelatedField(
        required=False,
        allow_null=True,
        queryset=IntegrationConfiguration.objects.all(),
        write_only=True,
    )
    remote_object_id = serializers.CharField(
        required=False, allow_blank=True, allow_null=True, write_only=True
    )
    create_remote_object = serializers.BooleanField(
        required=False, default=False, write_only=True
    )

    def validate_category(self, value):
        if value == "policy" and self.Meta.model is not Policy:
            raise serializers.ValidationError(
                "Policies must be created and changed through the policy API."
            )
        return value

    def validate(self, attrs):
        attrs = super().validate(attrs)
        attrs = self.validate_commitment(attrs)

        # AppliedControl.save() derives a missing category from its reference
        # control. Validate that effective value here as well; otherwise a
        # caller can omit (or clear) ``category`` and create a Policy row while
        # using only the generic AppliedControl API and permissions.
        effective_category = attrs.get(
            "category",
            getattr(self.instance, "category", None),
        )
        reference_control = attrs.get(
            "reference_control",
            getattr(self.instance, "reference_control", None),
        )
        if effective_category is None and reference_control is not None:
            effective_category = reference_control.category
        if effective_category == "policy" and self.Meta.model is not Policy:
            raise serializers.ValidationError(
                {
                    "category": (
                        "Policies must be created and changed through the policy API."
                    )
                }
            )
        return attrs

    def create(self, validated_data: Any):
        with transaction.atomic():
            commitment_data = dict(validated_data)
            self.pop_commitment(validated_data)
            validated_data.pop("create_remote_object", None)
            validated_data.pop("remote_object_id", None)
            validated_data.pop("integration_config", None)

            owner_data = validated_data.get("owner", [])
            findings = validated_data.pop("findings", [])
            task_templates = validated_data.pop("task_templates", [])
            incidents = validated_data.pop("incidents", [])
            applied_control = super().create(validated_data)
            if findings:
                applied_control.findings.set(findings)
            if task_templates:
                applied_control.task_templates.set(task_templates)
            if incidents:
                applied_control.incidents.set(incidents)

            # Send notification to newly assigned owners
            if owner_data:
                self._send_assignment_notifications(
                    applied_control, [user.id for user in owner_data]
                )

            # `validate_commitment` accepts an opening move on create, so
            # persist the host and its promise in the same transaction.
            self.apply_commitment(applied_control, commitment_data)

            return applied_control

    def update(self, instance, validated_data):
        with transaction.atomic():
            governed_relationship = "requirement_assessments" in validated_data
            old_owner_ids = (
                None
                if governed_relationship
                else set(instance.owner.values_list("id", flat=True))
            )
            old_folder_id = None if governed_relationship else instance.folder_id

            commitment_data = dict(validated_data)
            self.pop_commitment(validated_data)

            findings = validated_data.pop("findings", None)
            task_templates = validated_data.pop("task_templates", None)
            incidents = validated_data.pop("incidents", None)

            updated_instance = super().update(instance, validated_data)

            if governed_relationship:
                old_folder_id = self._governed_locked_scalar_snapshot["folder_id"]

            if findings is not None:
                updated_instance.findings.set(findings)
            if task_templates is not None:
                updated_instance.task_templates.set(task_templates)
            if incidents is not None:
                updated_instance.incidents.set(incidents)

            if old_folder_id != updated_instance.folder_id:
                # A commitment is only ever as visible as the object it is about.
                updated_instance.commitments.update(folder=updated_instance.folder)

            self.apply_commitment(updated_instance, commitment_data)

            # A governed request cannot include owner, so no owner snapshot is
            # needed outside the target lock acquired by the authority mixin.
            if old_owner_ids is not None:
                new_owner_ids = set(updated_instance.owner.values_list("id", flat=True))
                newly_assigned_ids = new_owner_ids - old_owner_ids
                if newly_assigned_ids:
                    self._send_assignment_notifications(
                        updated_instance, list(newly_assigned_ids)
                    )

            return updated_instance

    def to_representation(self, instance):
        ret = super().to_representation(instance)
        sync_mappings = [
            {
                "id": mapping.id,
                "remote_id": mapping.remote_id,
                "sync_status": mapping.sync_status,
                "last_synced_at": mapping.last_synced_at,
                "last_sync_direction": mapping.last_sync_direction,
                "error_message": mapping.error_message,
                "provider": mapping.configuration.provider.name,
            }
            for mapping in SyncMapping.objects.filter(local_object_id=instance.id).only(
                "id",
                "remote_id",
                "sync_status",
                "last_synced_at",
                "last_sync_direction",
                "error_message",
                "configuration__provider__name",
            )
        ]
        if sync_mappings:
            ret["sync_mappings"] = sync_mappings
        return ret

    def _send_assignment_notifications(self, applied_control, owner_ids):
        """Send assignment notifications to the specified owners"""
        if not owner_ids:
            return

        try:
            from core.models import Actor
            from .tasks import send_applied_control_assignment_notification

            assigned_actors = Actor.objects.filter(id__in=owner_ids)
            assigned_emails = []
            for actor in assigned_actors:
                assigned_emails.extend(actor.get_emails())

            unique_emails = tuple(dict.fromkeys(filter(None, assigned_emails)))
            if unique_emails:
                control_id = applied_control.id

                def enqueue_notification():
                    try:
                        send_applied_control_assignment_notification(
                            control_id, list(unique_emails)
                        )
                    except Exception as exc:
                        logger.error(
                            "Failed to queue AppliedControl assignment notification",
                            error_type=type(exc).__name__,
                        )

                transaction.on_commit(enqueue_notification)
        except Exception as e:
            logger.error(
                f"Failed to send AppliedControl assignment notification: {str(e)}"
            )

    class Meta:
        model = AppliedControl
        fields = "__all__"
        list_serializer_class = (
            RequirementAssessmentRelationshipProjectionListSerializer
        )


class AppliedControlRequestProjectionMixin:
    """Expose only caller-visible AppliedControl-derived metadata."""

    def _related_model_for_applied_control_field(self, name, field):
        related_field = getattr(field, "child_relation", field)
        if not isinstance(
            related_field,
            (FieldsRelatedField, serializers.PrimaryKeyRelatedField),
        ):
            return None
        source = field.source if field.source not in (None, "*") else name
        model = self.Meta.model
        for part in source.split("."):
            try:
                model_field = model._meta.get_field(part)
            except FieldDoesNotExist:
                model_field = next(
                    (
                        candidate
                        for candidate in model._meta.get_fields()
                        if getattr(candidate, "get_accessor_name", lambda: None)()
                        == part
                    ),
                    None,
                )
                if model_field is None:
                    return None
            model = getattr(model_field, "related_model", None)
            if model is None:
                return None
        return model

    @staticmethod
    def _is_applied_control_pk_related_field(field) -> bool:
        return isinstance(
            getattr(field, "child_relation", field),
            serializers.PrimaryKeyRelatedField,
        )

    def _visible_applied_control_related_ids(self, model):
        request = self.context.get("request")
        user = getattr(request, "user", None) if request is not None else None
        cache = self.context.setdefault("_applied_control_related_iam_ids", {})
        cache_key = (getattr(user, "pk", None), model._meta.label_lower)
        if cache_key in cache:
            return cache[cache_key]
        if user is None or not getattr(user, "is_authenticated", False):
            allowed = set()
        else:
            try:
                allowed = {
                    str(item_id)
                    for item_id in RoleAssignment.get_viewable_object_ids(user, model)
                }
            except NotImplementedError, Permission.DoesNotExist:
                # Models without IAM ownership retain their ordinary rendering.
                allowed = None
        cache[cache_key] = allowed
        return allowed

    @staticmethod
    def _applied_control_related_item_id(item):
        value = item.get("id") if isinstance(item, dict) else item
        return None if value is None else str(value)

    def _mask_applied_control_related_fields(self, data):
        if not isinstance(data, dict):
            return data
        for name, field in self.fields.items():
            related_model = self._related_model_for_applied_control_field(name, field)
            if related_model is None or name not in data:
                continue
            allowed = self._visible_applied_control_related_ids(related_model)
            if allowed is None:
                continue
            value = data[name]
            if isinstance(value, list):
                if self._is_applied_control_pk_related_field(field):
                    data[name] = [
                        item
                        for item in value
                        if self._applied_control_related_item_id(item) in allowed
                    ]
                else:
                    data[name] = [
                        item
                        if self._applied_control_related_item_id(item) in allowed
                        else ({} if isinstance(item, dict) else "")
                        for item in value
                    ]
            elif isinstance(value, dict):
                item_id = self._applied_control_related_item_id(value)
                if item_id is not None and item_id not in allowed:
                    data[name] = {}
        return data

    def to_representation(self, instance):
        return self._mask_applied_control_related_fields(
            super().to_representation(instance)
        )

    def _applied_control_projection_cache_key(self, instance):
        request = self.context.get("request")
        user = getattr(request, "user", None) if request is not None else None
        return (getattr(user, "pk", None), getattr(instance, "pk", None))

    def _prime_applied_control_request_projections(self, instances) -> None:
        from core.applied_control_visibility import (
            build_applied_control_request_projections,
        )

        bounded = tuple(
            instance
            for instance in instances
            if isinstance(instance, models.Model) and instance.pk is not None
        )
        if not bounded:
            return
        cache = self.context.setdefault("_applied_control_request_projections", {})
        missing = tuple(
            instance
            for instance in bounded
            if self._applied_control_projection_cache_key(instance) not in cache
        )
        if not missing:
            return
        request = self.context.get("request")
        user = getattr(request, "user", None) if request is not None else None
        projections = build_applied_control_request_projections(
            user=user,
            controls=missing,
        )
        for instance in missing:
            cache[self._applied_control_projection_cache_key(instance)] = projections[
                instance.pk
            ]

    def _applied_control_request_projection(self, instance):
        from core.applied_control_visibility import (
            EMPTY_APPLIED_CONTROL_PROJECTION,
        )

        cache = self.context.setdefault("_applied_control_request_projections", {})
        cache_key = self._applied_control_projection_cache_key(instance)
        if cache_key not in cache:
            self._prime_applied_control_request_projections((instance,))
        return cache.get(cache_key, EMPTY_APPLIED_CONTROL_PROJECTION)

    def get_ranking_score(self, obj):
        return self._applied_control_request_projection(obj).ranking_score

    def get_findings_count(self, obj):
        return self._applied_control_request_projection(obj).findings_count

    def get_is_assigned(self, obj):
        return self._applied_control_request_projection(obj).is_assigned


class AppliedControlRequestProjectionListSerializer(serializers.ListSerializer):
    """Prime derived IAM projections once for an action-plan page."""

    def to_representation(self, data):
        iterable = data.all() if isinstance(data, models.Manager) else data
        instances = list(iterable)
        self.child._prime_applied_control_request_projections(instances)
        return super().to_representation(instances)


class AppliedControlReadSerializer(
    AppliedControlRequestProjectionMixin, AppliedControlWriteSerializer
):
    path = PathField(read_only=True)
    folder = FieldsRelatedField()
    incidents = FieldsRelatedField(many=True)
    reference_control = FieldsRelatedField()
    priority = serializers.CharField(source="get_priority_display")
    category = serializers.CharField(
        source="get_category_display"
    )  # type : get_type_display
    csf_function = serializers.CharField(
        source="get_csf_function_display"
    )  # type : get_type_display
    evidences = FieldsRelatedField(many=True)
    objectives = FieldsRelatedField(many=True)
    effort = serializers.CharField(source="get_effort_display")
    control_impact = serializers.CharField(source="get_control_impact_display")
    cost = serializers.JSONField()
    annual_cost = serializers.DecimalField(
        max_digits=12, decimal_places=2, read_only=True
    )
    currency = serializers.SerializerMethodField()
    annual_cost_display = serializers.SerializerMethodField()
    filtering_labels = FieldsRelatedField(["id", "folder"], many=True)
    assets = FieldsRelatedField(many=True)

    ranking_score = serializers.SerializerMethodField()
    owner = FieldsRelatedField(many=True)
    security_exceptions = FieldsRelatedField(many=True)
    state = serializers.SerializerMethodField()
    findings_count = serializers.SerializerMethodField()
    is_assigned = serializers.SerializerMethodField()
    linked_models = serializers.SerializerMethodField()

    def get_linked_models(self, obj):
        return list(self._applied_control_request_projection(obj).linked_models)

    def get_state(self, obj):
        if not obj.eta:
            return None
        return time_state(obj.eta.isoformat())

    def get_currency(self, obj):
        if not obj.cost:
            return "€"  # Default currency
        return obj.cost.get("currency", "€")

    def get_annual_cost_display(self, obj):
        annual_cost = obj.annual_cost
        if annual_cost == 0:
            return ""
        currency = self.get_currency(obj)
        return AppliedControl._stringify_cost(f"{annual_cost:,.2f}", currency)

    def to_representation(self, instance):
        ret = super().to_representation(instance)
        if self.context.get("action") == "retrieve":
            sync_mappings = [
                {
                    "id": mapping.id,
                    "remote_id": mapping.remote_id,
                    "sync_status": mapping.sync_status,
                    "last_synced_at": mapping.last_synced_at,
                    "last_sync_direction": mapping.last_sync_direction,
                    "error_message": mapping.error_message,
                    "provider": mapping.configuration.provider.name,
                }
                for mapping in SyncMapping.objects.filter(local_object_id=instance.id)
                .select_related("configuration__provider")
                .only(
                    "id",
                    "remote_id",
                    "sync_status",
                    "last_synced_at",
                    "last_sync_direction",
                    "error_message",
                    "configuration__provider__name",
                )
            ]
            if sync_mappings:
                ret["sync_mappings"] = sync_mappings
        return ret


class AppliedControlBulkReadSerializer(AppliedControlReadSerializer):
    """Like AppliedControlReadSerializer but reads daily_rate from context to
    avoid a per-row GlobalSettings query, and drops sync_mappings (internal
    integration state, irrelevant to a bulk pull) to avoid a per-row query."""

    annual_cost = serializers.SerializerMethodField()
    annual_cost_display = serializers.SerializerMethodField()

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # instance-level so the metaclass doesn't register it as a field
        self._annual_cost_repr = serializers.DecimalField(
            max_digits=12, decimal_places=2, read_only=True
        )

    def get_annual_cost(self, obj):
        value = obj.compute_annual_cost(self.context.get("daily_rate"))
        return self._annual_cost_repr.to_representation(value)

    def get_annual_cost_display(self, obj):
        annual_cost = obj.compute_annual_cost(self.context.get("daily_rate"))
        if annual_cost == 0:
            return ""
        currency = self.get_currency(obj)
        return AppliedControl._stringify_cost(f"{annual_cost:,.2f}", currency)

    def get_custom_fields(self, obj) -> dict:
        values = getattr(obj, "_bulk_custom_field_values", None)
        if values is None:
            return super().get_custom_fields(obj)

        result: dict = {}
        for value in values:
            definition = value.definition
            if definition.field_type == "multi_choice":
                result.setdefault(definition.key, []).append(value.value)
            else:
                result[definition.key] = value.value
        return result

    def to_representation(self, instance):
        # skip Write/Read.to_representation, which query SyncMapping per row
        return self._mask_applied_control_related_fields(
            RequirementAssessmentRelationshipProjectionMixin.to_representation(
                self, instance
            )
        )


class AppliedControlListSerializer(
    AppliedControlRequestProjectionMixin,
    RequirementAssessmentRelationshipProjectionMixin,
    CommitmentSerializerMixin,
    BaseModelSerializer,
):
    """
    Lightweight serializer for the applied controls list view.

    Drops the per-row DB-touching fields from `AppliedControlReadSerializer`
    that the list table does not render:
      - `findings_count` (source="findings.count" → COUNT per row); the related
        findings themselves are served instead, prefetched
      - `ranking_score` (iterates non-prefetched risk_scenarios → 1 query per row)
      - `annual_cost` / `annual_cost_display` / `currency`
        (property hits GlobalSettings per row, called twice)
      - `state`, `evidences`, `objectives`, `security_exceptions`, `path`
        (not displayed on the table)

    Inherits from `BaseModelSerializer` (not `AppliedControlWriteSerializer`)
    to skip the unconditional `SyncMapping` query in Write.to_representation
    that would otherwise also fire per row on the list.
    """

    # Only what the table renders: the full history would be dead weight per row.
    COMMITMENT_FIELD_NAMES = COMMITMENT_LIST_FIELDS

    folder = FieldsRelatedField()
    reference_control = FieldsRelatedField()
    priority = serializers.CharField(source="get_priority_display")
    category = serializers.CharField(source="get_category_display")
    csf_function = serializers.CharField(source="get_csf_function_display")
    effort = serializers.CharField(source="get_effort_display")
    control_impact = serializers.CharField(source="get_control_impact_display")
    cost = serializers.JSONField()
    owner = FieldsRelatedField(many=True)
    filtering_labels = FieldsRelatedField(["id", "folder"], many=True)
    assets = FieldsRelatedField(many=True)
    # The action plan shows which findings a control answers, not how many.
    findings = FieldsRelatedField(many=True)
    is_assigned = serializers.SerializerMethodField()
    linked_models = serializers.SerializerMethodField()

    class Meta:
        model = AppliedControl
        list_serializer_class = (
            RequirementAssessmentRelationshipProjectionListSerializer
        )
        fields = [
            "id",
            "ref_id",
            "name",
            "description",
            "link",
            "status",
            "priority",
            "category",
            "csf_function",
            "control_impact",
            "effort",
            "eta",
            "start_date",
            "expiry_date",
            "progress_field",
            "cost",
            "observation",
            "folder",
            "reference_control",
            "owner",
            "filtering_labels",
            "assets",
            "findings",
            "is_assigned",
            "linked_models",
            "created_at",
            "updated_at",
        ]

    def get_is_assigned(self, obj):
        return self._applied_control_request_projection(obj).is_assigned

    def get_linked_models(self, obj):
        return list(self._applied_control_request_projection(obj).linked_models)


class ActionPlanSerializer(AppliedControlRequestProjectionMixin, BaseModelSerializer):
    folder = FieldsRelatedField()
    reference_control = FieldsRelatedField()
    priority = serializers.CharField(source="get_priority_display")
    category = serializers.CharField(
        source="get_category_display"
    )  # type : get_type_display
    csf_function = serializers.CharField(
        source="get_csf_function_display"
    )  # type : get_type_display
    evidences = FieldsRelatedField(many=True)
    effort = serializers.CharField(source="get_effort_display")
    control_impact = serializers.CharField(source="get_control_impact_display")
    status = serializers.CharField(source="get_status_display")
    cost = serializers.JSONField()
    annual_cost = serializers.DecimalField(
        max_digits=12, decimal_places=2, read_only=True
    )

    ranking_score = serializers.SerializerMethodField()
    owner = FieldsRelatedField(many=True)

    class Meta:
        model = AppliedControl
        fields = "__all__"
        list_serializer_class = AppliedControlRequestProjectionListSerializer


class ComplianceAssessmentActionPlanSerializer(ActionPlanSerializer):
    requirement_assessments = serializers.SerializerMethodField(
        method_name="get_requirement_assessments"
    )
    evidence_attachments = serializers.SerializerMethodField()

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # AppliedControl.get_ranking_score traverses every linked risk
        # scenario.  Risk IAM is outside this compliance-only projection, so
        # exposing the derived value would leak hidden risk levels.
        self.fields.pop("ranking_score", None)

    def get_requirement_assessments(self, obj):
        pk = self.context.get("pk")
        request = self.context.get("request")
        user = getattr(request, "user", None)
        if pk is None or user is None or not getattr(user, "is_authenticated", False):
            return []

        requirement_assessments = getattr(
            obj, "action_plan_requirement_assessments", None
        )
        if requirement_assessments is None:
            visible_ra_ids = RoleAssignment.get_viewable_object_ids(
                user, RequirementAssessment
            )
            requirement_assessments = RequirementAssessment.objects.filter(
                compliance_assessment=pk,
                applied_controls=obj,
                id__in=visible_ra_ids,
            ).select_related("requirement")
        return [
            {
                "str": str(req.requirement.safe_display_str),
                "id": str(req.id),
            }
            for req in requirement_assessments
        ]

    def get_evidence_attachments(self, obj):
        attachments = []
        for evidence in obj.evidences.all():
            filename = evidence.filename()
            if filename:
                attachments.append(
                    {
                        "id": str(evidence.id),
                        "str": str(evidence),
                        "filename": filename,
                    }
                )
        return attachments

    class Meta(ActionPlanSerializer.Meta):
        model = AppliedControl
        fields = [
            "id",
            "ref_id",
            "name",
            "description",
            "folder",
            "status",
            "eta",
            "expiry_date",
            "priority",
            "category",
            "csf_function",
            "effort",
            "control_impact",
            "cost",
            "annual_cost",
            "ranking_score",
            "requirement_assessments",
            "reference_control",
            "evidences",
            "evidence_attachments",
            "owner",
            "created_at",
            "updated_at",
        ]


class RiskAssessmentActionPlanSerializer(ActionPlanSerializer):
    risk_scenarios = serializers.SerializerMethodField(method_name="get_risk_scenarios")

    def get_risk_scenarios(self, obj):
        pk = self.context.get("pk")
        if pk is None:
            return None
        risk_scenarios = (
            scenario
            for scenario in self._applied_control_request_projection(obj).risk_scenarios
            if str(scenario.risk_assessment_id) == str(pk)
        )
        return [
            {
                "str": f"{scenario.ref_id} - {scenario.name}",
                "id": str(scenario.id),
            }
            for scenario in risk_scenarios
        ]

    class Meta(ActionPlanSerializer.Meta):
        model = AppliedControl
        fields = [
            "id",
            "ref_id",
            "name",
            "description",
            "folder",
            "status",
            "eta",
            "expiry_date",
            "priority",
            "category",
            "csf_function",
            "effort",
            "control_impact",
            "cost",
            "annual_cost",
            "ranking_score",
            "risk_scenarios",
            "reference_control",
            "evidences",
            "owner",
            "created_at",
            "updated_at",
        ]


class AppliedControlDuplicateSerializer(BaseModelSerializer):
    duplicate_evidences = serializers.BooleanField(default=False)
    # Resolve target authority in the view so a valid-but-missing UUID and an
    # existing caller-hidden folder share the same denial response.
    folder = serializers.UUIDField()

    class Meta:
        model = AppliedControl
        fields = ["name", "description", "folder", "duplicate_evidences"]


class AppliedControlMergeTargetSerializer(serializers.Serializer):
    type = serializers.ChoiceField(choices=["new", "existing"])
    id = serializers.UUIDField(required=False)
    fields = serializers.DictField(required=False)

    def validate(self, attrs):
        if attrs["type"] == "existing" and not attrs.get("id"):
            raise serializers.ValidationError(
                {"id": "target.id is required when type='existing'"}
            )
        if attrs["type"] == "new" and not attrs.get("fields"):
            raise serializers.ValidationError(
                {"fields": "target.fields is required when type='new'"}
            )
        return attrs


class AppliedControlMergeRequestSerializer(serializers.Serializer):
    """Shape-only validation for POST /applied-controls/merge/. Dedupes
    source_ids, collapses target-in-sources to a survivor merge."""

    MAX_SOURCES = 20

    source_ids = serializers.ListField(
        child=serializers.UUIDField(),
        min_length=1,
        max_length=MAX_SOURCES,
    )
    target = AppliedControlMergeTargetSerializer()
    dry_run = serializers.BooleanField(default=False)

    def validate_source_ids(self, value):
        seen: set[str] = set()
        deduped = []
        for sid in value:
            key = str(sid)
            if key not in seen:
                seen.add(key)
                deduped.append(sid)
        return deduped

    def validate(self, attrs):
        target = attrs["target"]
        if target["type"] == "existing":
            target_id = str(target["id"])
            attrs["source_ids"] = [
                s for s in attrs["source_ids"] if str(s) != target_id
            ]
            if not attrs["source_ids"]:
                raise serializers.ValidationError(
                    "After excluding the target from source_ids, no sources remain."
                )
        return attrs


class AppliedControlImportExportSerializer(BaseModelSerializer):
    reference_control = HashSlugRelatedField(slug_field="pk", read_only=True)
    folder = HashSlugRelatedField(slug_field="pk", read_only=True)
    evidences = HashSlugRelatedField(slug_field="pk", read_only=True, many=True)
    objectives = HashSlugRelatedField(slug_field="pk", read_only=True, many=True)

    class Meta:
        model = AppliedControl
        fields = [
            "folder",
            "ref_id",
            "name",
            "description",
            "priority",
            "reference_control",
            "created_at",
            "updated_at",
            "category",
            "csf_function",
            "status",
            "start_date",
            "eta",
            "expiry_date",
            "link",
            "effort",
            "control_impact",
            "cost",
            "evidences",
            "objectives",
        ]


class PolicyWriteSerializer(AppliedControlWriteSerializer):
    genericcollection = serializers.PrimaryKeyRelatedField(
        source="genericcollection_set",
        many=True,
        required=False,
        queryset=GenericCollection.objects.all(),
    )

    class Meta:
        model = Policy
        fields = "__all__"
        list_serializer_class = (
            RequirementAssessmentRelationshipProjectionListSerializer
        )


class PolicyReadSerializer(AppliedControlReadSerializer):
    path = PathField(read_only=True)
    validation_flows = FieldsRelatedField(
        many=True,
        fields=[
            "id",
            "ref_id",
            "status",
            "request_notes",
            "last_event_notes",
            {"approver": ["id", "email", "first_name", "last_name"]},
        ],
        source="validationflow_set",
    )

    class Meta:
        model = Policy
        fields = "__all__"
        list_serializer_class = (
            RequirementAssessmentRelationshipProjectionListSerializer
        )


class ActorReadSerializer(BaseModelSerializer):
    specific = FieldsRelatedField()
    str = serializers.CharField(source="__str__")

    class Meta:
        model = Actor
        fields = ["id", "str", "type", "specific"]


class TeamWriteSerializer(BaseModelSerializer):
    class Meta:
        model = Team
        fields = [
            "id",
            "name",
            "description",
            "folder",
            "team_email",
            "leader",
            "deputies",
            "members",
        ]


class TeamReadSerializer(BaseModelSerializer):
    folder = FieldsRelatedField()
    leader = FieldsRelatedField()
    deputies = FieldsRelatedField(many=True)
    members = FieldsRelatedField(many=True)

    class Meta:
        model = Team
        fields = [
            "id",
            "name",
            "description",
            "folder",
            "team_email",
            "leader",
            "deputies",
            "members",
        ]


class UserReadSerializer(BaseModelSerializer):
    user_groups = FieldsRelatedField(fields=["builtin", "id"], many=True)
    idp_groups = FieldsRelatedField(many=True)
    has_mfa_enabled = serializers.BooleanField(read_only=True)
    folder = FieldsRelatedField()
    language = serializers.SerializerMethodField()

    def get_language(self, obj):
        # The label, not the code: this feeds the detail view. The edit form reads the
        # code from the write serializer instead.
        code = obj.language_code()
        return dict(settings.LANGUAGES).get(code, code)

    class Meta:
        model = User
        fields = [
            "id",
            "email",
            "first_name",
            "last_name",
            "is_active",
            "date_joined",
            "user_groups",
            "idp_groups",
            "keep_local_login",
            "is_third_party",
            "observation",
            "has_mfa_enabled",
            "expiry_date",
            "is_superuser",
            "is_scim_managed",
            "is_jit_provisioned",
            "folder",
            "language",
        ]


class UserRolesOnFolderSerializer(BaseModelSerializer):
    roles = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = ["id", "email", "first_name", "last_name", "is_active", "roles"]

    def get_roles(self, obj):
        return [
            {"str": str(role)}
            for role in self.context["user_roles_map"].get(obj.id, [])
        ]


class UserWriteSerializer(BaseModelSerializer):
    is_local = serializers.BooleanField(required=False)
    has_mfa_enabled = serializers.BooleanField(read_only=True)
    # Deployment-owned bootstrap flag (CISO_ASSISTANT_SUPERUSER_EMAIL,
    # createsuperuser): the startup sync turns it into admin group membership,
    # so it must never be writable through the API, whoever the requester is.
    # validate() rejects attempted changes instead of letting DRF drop them.
    is_superuser = serializers.BooleanField(read_only=True)
    # Lives in `preferences`, not a column, so it is declared rather than derived.
    language = serializers.CharField(required=False, allow_blank=True, write_only=True)

    class Meta:
        model = User
        fields = [
            "id",
            "language",
            "email",
            "first_name",
            "last_name",
            "is_active",
            "date_joined",
            "user_groups",
            "keep_local_login",
            "is_third_party",
            "is_local",
            "observation",
            "expiry_date",
            "is_superuser",
            "has_mfa_enabled",
        ]

    def validate_email(self, email):
        validate_email(email)
        return email

    def validate_language(self, language):
        from iam.models import is_supported_language

        if language and not is_supported_language(language):
            raise serializers.ValidationError("unsupportedLanguage")
        return language

    @staticmethod
    def _change_usergroup_perm() -> Permission:
        return Permission.objects.get(
            codename="change_usergroup",
            content_type__app_label=UserGroup._meta.app_label,
            content_type__model=UserGroup._meta.model_name,
        )

    def _deny(self, guard: str, errors: dict) -> None:
        """Log the denied privileged user operation as a security event, then
        raise it. Error values are camelCase keys translated by the frontend."""
        request = self.context.get("request")
        requester = getattr(request, "user", None) if request else None
        logger.warning(
            "denied privileged user operation",
            guard=guard,
            errors=errors,
            requester=getattr(requester, "email", None),
            target=getattr(self.instance, "email", None),
        )
        raise PermissionDenied(errors)

    def _enforce_superuser_immutable(self) -> None:
        # The field is read-only, so DRF would silently ignore it; an attempted
        # change must fail loudly instead. Echoing the current value back (full
        # PUT of a previously fetched object) stays valid.
        if "is_superuser" not in self.initial_data:
            return
        requested = self.initial_data.get("is_superuser")
        if requested is None:
            return
        requested = serializers.BooleanField().run_validation(requested)
        current = bool(self.instance.is_superuser) if self.instance else False
        if requested != current:
            self._deny("superuser", {"is_superuser": ["cannotChangeSuperuserStatus"]})

    def _enforce_group_membership_rights(self, attrs: dict) -> None:
        """Group membership grants the roles the group carries, so changing it
        requires change_usergroup on each affected group's folder — change_user
        alone must not let a user manager grant (or strip) the admin group.
        Only the delta is checked, so a full PUT echoing unchanged memberships
        still passes for a plain user manager."""
        if "user_groups" not in attrs:
            return
        request = self.context.get("request")
        if request is None:
            return
        # Not instance.user_groups.all(): the viewset prefetches that relation
        # filtered to the requester's viewable groups, which would hide the
        # memberships this guard exists to protect.
        current = (
            set(UserGroup.objects.filter(user=self.instance).select_related("folder"))
            if self.instance
            else set()
        )
        submitted = set(attrs["user_groups"] or [])
        if current:
            # Memberships in groups the requester cannot see are absent from a
            # full PUT echo; keep them rather than reading the omission as a
            # removal, which would strip them silently or 403 spuriously.
            viewable_ids = {
                str(pk)
                for pk in RoleAssignment.get_viewable_object_ids(
                    request.user, UserGroup
                )
            }
            submitted |= {g for g in current if str(g.id) not in viewable_ids}
            attrs["user_groups"] = list(submitted)
        delta = current.symmetric_difference(submitted)
        if not delta:
            return
        perm = self._change_usergroup_perm()
        for group in delta:
            if not RoleAssignment.is_access_allowed(
                user=request.user, perm=perm, folder=group.folder
            ):
                self._deny(
                    "group_membership",
                    {"user_groups": ["missingPermissionToManageUserGroupMembership"]},
                )

    def _enforce_last_admin_group(self, attrs: dict) -> None:
        """Stripping BI-UG-ADM from the last direct administrator would lock the
        deployment out of administration, so it is blocked for everyone —
        mirroring the delete and deactivation last-admin guards.

        Direct membership only: this edits the DIRECT group list, so the anchor
        it protects is the last *directly*-managed administrator, the one
        SCIM/IdP can never reach and that must always exist. Admins inherited
        via an IdP group are managed by the IdP, not here, so they neither gate
        this check nor count toward it.

        Runs after _enforce_group_membership_rights, which folds memberships
        invisible to the requester back into attrs — those must count as kept,
        not stripped.

        This is the fast fail, running before the lock: it reports a field-level
        error on the common case. It is NOT authoritative — the check is
        check-then-act, so UserViewSet.perform_update re-runs the predicate
        under the admin-group lock, in the same transaction as the write.
        """
        if "user_groups" not in attrs:
            return
        if self.strips_last_admin_group(self.instance, attrs["user_groups"]):
            # Top-level "error" key, not a field-keyed one: same response body
            # this returned from the view, and the same one UserGroupViewSet's
            # remove-members returns for the mirror-image operation.
            self._deny(
                "last_admin_group", {"error": "attemptToRemoveOnlyAdminUserGroup"}
            )

    @staticmethod
    def strips_last_admin_group(instance, submitted_groups) -> bool:
        """Would this membership write leave the deployment with no direct
        administrator? Pure predicate, no raising, so UserViewSet.perform_update
        can re-evaluate it under the BI-UG-ADM lock — the serializer reads it
        before any lock is held, which is only good enough to fail fast."""
        if instance is None:
            return False
        if not UserGroup.objects.filter(user=instance, name="BI-UG-ADM").exists():
            return False
        if User.objects.filter(user_groups__name="BI-UG-ADM").count() > 1:
            return False
        submitted = {str(group.pk) for group in submitted_groups or []}
        return not UserGroup.objects.filter(name="BI-UG-ADM", pk__in=submitted).exists()

    # Lifecycle/auth-surface fields: deactivation (directly, or deferred via
    # expiry_date and the nightly deactivate_expired_users task) and the
    # local-login fallback.
    LIFECYCLE_FIELDS = ("is_active", "keep_local_login", "expiry_date")

    def _enforce_scim_managed_fields(self, attrs: dict) -> None:
        """SCIM is the authoritative write channel for the identity fields of a
        SCIM-managed account: a manual edit is at best drift the next sync
        overwrites, at worst the SSO email re-binding attack. Immutable here for
        everyone, admins included — a legitimate rename arrives through the SCIM
        endpoint itself. `is_active` and `expiry_date` stay admin-only
        break-glass (emergency deactivation must not wait on IdP sync latency);
        `keep_local_login` can never be enabled (a SCIM identity stays SSO-only,
        admin or not) and only an admin can disable a legacy flag. Deleting the
        account (admin-only, see UserViewSet.destroy) remains the escape hatch
        for a decommissioned SCIM integration.
        Local-only fields SCIM has no concept of (user_groups, observation,
        expiry_date, ...) keep their own guards."""
        if self.instance is None or not self.instance.is_scim_managed:
            return
        request = self.context.get("request")
        if request is None:
            return
        if (
            "email" in attrs
            and (attrs["email"] or "").lower() != (self.instance.email or "").lower()
        ):
            self._deny("scim_identity", {"email": ["fieldManagedByScim"]})
        for field in ("first_name", "last_name"):
            if field in attrs and (attrs[field] or "") != (
                getattr(self.instance, field) or ""
            ):
                self._deny("scim_identity", {field: ["fieldManagedByScim"]})
        if attrs.get("keep_local_login") and not self.instance.keep_local_login:
            # A SCIM-owned identity stays SSO-only: no password fallback may be
            # opened on it, not even by an admin — deletion (admin-only, see
            # UserViewSet.destroy) is the decommission escape. Disabling a
            # legacy flag stays admin-only via the lifecycle loop below.
            self._deny(
                "scim_local_login",
                {"keep_local_login": ["scimAccountCannotEnableLocalLogin"]},
            )
        for field in self.LIFECYCLE_FIELDS:
            if (
                field in attrs
                and attrs[field] != getattr(self.instance, field)
                and not request.user.is_admin()
            ):
                self._deny("scim_lifecycle", {field: ["scimAccountFieldRequiresAdmin"]})

    def _require_group_rights_over_instance(
        self, request_user, field_name: str, error_key: str
    ) -> None:
        """Require change_usergroup on the folder of every group the target
        belongs to. DB query, not the visibility-filtered prefetch: memberships
        the requester cannot see must still make the target privileged."""
        groups = list(
            UserGroup.objects.filter(user=self.instance).select_related("folder")
        )
        if not groups:
            return
        perm = self._change_usergroup_perm()
        for group in groups:
            if not RoleAssignment.is_access_allowed(
                user=request_user, perm=perm, folder=group.folder
            ):
                self._deny("group_rights_over_target", {field_name: [error_key]})

    def _enforce_last_active_admin(self, attrs: dict) -> None:
        """Deactivating — or scheduling expiry for — the last active
        directly-managed administrator would lock the deployment out of
        administration, so it is blocked for everyone, mirroring the
        delete/group-removal last-admin guards. Reactivating and clearing an
        expiry stay allowed. deactivate_expired_users carries the same backstop
        for expiries that predate this guard.

        Fast fail only, like _enforce_last_admin_group: the authoritative
        re-check runs under the admin-group lock in
        UserViewSet.perform_update."""
        offending = self.deactivates_last_active_admin(self.instance, attrs)
        if not offending:
            return
        self._deny(
            "last_active_admin",
            {
                field: ["attemptToDeactivateOnlyAdminAccountError"]
                for field in offending
            },
        )

    @staticmethod
    def deactivates_last_active_admin(instance, attrs: dict) -> set:
        """Fields in *attrs* whose write would leave no active direct
        administrator. Pure predicate, mirroring strips_last_admin_group, so the
        view can re-evaluate it under the lock."""
        if instance is None:
            return set()
        offending = set()
        if attrs.get("is_active") is False and instance.is_active:
            offending.add("is_active")
        if (
            "expiry_date" in attrs
            and attrs["expiry_date"] is not None
            and attrs["expiry_date"] != instance.expiry_date
        ):
            offending.add("expiry_date")
        if not offending:
            return set()
        if not UserGroup.objects.filter(user=instance, name="BI-UG-ADM").exists():
            return set()
        if (
            User.objects.filter(user_groups__name="BI-UG-ADM", is_active=True)
            .exclude(pk=instance.pk)
            .exists()
        ):
            return set()
        return offending

    def _enforce_lifecycle_field_rights(self, attrs: dict) -> None:
        """Deactivating an administrator — directly, or deferred via
        expiry_date and the nightly deactivate_expired_users task — or toggling
        their local-login fallback could lock the deployment out of
        administration, so on an admin account these fields require
        change_usergroup on the root folder: the same right that guards admin
        group membership. Non-admin accounts stay freely manageable by user
        managers (routine onboarding/offboarding), deliberately: deactivation
        is a recoverable denial of service, unlike the email re-binding, which
        is a takeover and therefore stays gated on all the target's groups."""
        if self.instance is None:
            return
        changed = {
            field
            for field in self.LIFECYCLE_FIELDS
            if field in attrs and attrs[field] != getattr(self.instance, field)
        }
        if not changed:
            return
        request = self.context.get("request")
        if request is None:
            return
        if not self.instance.is_admin():
            return
        if RoleAssignment.is_access_allowed(
            user=request.user,
            perm=self._change_usergroup_perm(),
            folder=Folder.get_root_folder(),
        ):
            return
        self._deny(
            "admin_lifecycle",
            {
                field: ["adminAccountLifecycleChangeRequiresAdminRights"]
                for field in changed
            },
        )

    @staticmethod
    def _is_sso_only(user) -> bool:
        """No local password path exists for this account, so the IdP assertion
        is the whole identity binding and its email is the only thing tying the
        two together.

        Deliberately not `not user.is_local`: that property also folds in
        `is_active`, so it reads False for a merely *deactivated* plain local
        account — which would make a routine offboarded user's email
        admin-only for no security reason.
        """
        if user.keep_local_login:
            return False
        from global_settings.models import GlobalSettings

        sso_settings = (
            GlobalSettings.objects.filter(name=GlobalSettings.Names.SSO)
            .values_list("value", flat=True)
            .first()
        ) or {}
        return bool(sso_settings.get("is_enabled")) and bool(
            sso_settings.get("force_sso")
        )

    def _enforce_email_change_rights(self, attrs: dict) -> None:
        """The SSO adapter maps logins to accounts by email, so rewriting a
        user's email re-binds their identity: with SSO it hands the account to
        whoever the IdP asserts the new address for, IdP MFA notwithstanding.
        Hence, beyond change_user:
        - a SCIM-managed account is fully immutable on email (see
          _enforce_scim_managed_fields, which runs first);
        - a JIT-provisioned or SSO-only account is admin-only: its authoritative
          email lives in the IdP, but no sync channel exists to repair drift, so
          an admin must be able to (e.g. an IdP-side rename would otherwise
          orphan the account and JIT-provision a duplicate);
        - a user already holding group memberships requires the same
          change_usergroup rights as editing those memberships would.
        """
        if self.instance is None or "email" not in attrs:
            return
        new_email = attrs["email"] or ""
        if new_email.lower() == (self.instance.email or "").lower():
            return
        request = self.context.get("request")
        if request is None:
            return
        idp_bound = (
            self.instance.is_scim_managed
            or self.instance.is_jit_provisioned
            or self._is_sso_only(self.instance)
        )
        if idp_bound and not request.user.is_admin():
            self._deny(
                "idp_bound_email",
                {"email": ["emailChangeOfIdpManagedUserRequiresAdmin"]},
            )
        self._require_group_rights_over_instance(
            request.user, "email", "emailChangeRequiresUserGroupManagementRights"
        )

    def validate(self, attrs):
        attrs = super().validate(attrs)
        self._enforce_superuser_immutable()
        self._enforce_scim_managed_fields(attrs)
        self._enforce_group_membership_rights(attrs)
        self._enforce_last_admin_group(attrs)
        self._enforce_last_active_admin(attrs)
        self._enforce_lifecycle_field_rights(attrs)
        self._enforce_email_change_rights(attrs)
        return attrs

    def to_representation(self, instance):
        # write_only so DRF never looks for a `language` attribute; the edit form
        # still reads its initial value from here.
        data = super().to_representation(instance)
        data["language"] = instance.get_preferences().get("lang")
        # Read-only provenance for the edit form: says which fields the SCIM
        # and admin-account guards will refuse before the user hits a 403.
        data["is_scim_managed"] = instance.is_scim_managed
        data["is_jit_provisioned"] = instance.is_jit_provisioned
        return data

    def create(self, validated_data):
        send_mail = settings.EMAIL_HOST or settings.EMAIL_HOST_RESCUE
        if not RoleAssignment.is_access_allowed(
            user=self.context["request"].user,
            perm=Permission.objects.get(
                codename="add_user",
                content_type__app_label=User._meta.app_label,
                content_type__model=User._meta.model_name,
            ),
            folder=Folder.get_root_folder(),
        ):
            raise PermissionDenied(
                {"error": ["You do not have permission to create users"]}
            )
        try:
            user = User.objects.create_user(**validated_data)
        except Exception as e:
            logger.error(e)
            if (
                User.objects.filter(email=validated_data["email"]).exists()
                and send_mail
            ):
                logger.warning("mailing failed")
                raise serializers.ValidationError(
                    {
                        "warning": [
                            "User created successfully but an error occurred while sending the email"
                        ]
                    }
                )
            else:
                raise serializers.ValidationError(
                    {"error": ["An error occurred while creating the user"]}
                )
        return user

    def update(self, instance: User, validated_data: Any) -> User:
        language = validated_data.pop("language", None)

        user_groups_data = validated_data.get("user_groups")
        if user_groups_data is not None:
            # UserGroup.objects, not instance.user_groups.all(): the latter is the
            # viewset's visibility-filtered prefetch, which would under-report the
            # previous memberships in this audit line.
            initial_groups = set(UserGroup.objects.filter(user=instance))
            new_groups = set(group for group in user_groups_data)

            if initial_groups != new_groups:
                logger.info(
                    "user groups updated",
                    user=instance,
                    initial_user_groups=initial_groups,
                    new_user_groups=new_groups,
                )
                # instance.user_groups.set(user_groups_data)
        updated_instance = super().update(instance, validated_data)

        # After, not before: the change permission is enforced inside super().update(),
        # so writing preferences first would let an unauthorized request through.
        if language:
            preferences = updated_instance.get_preferences()
            preferences["lang"] = language
            updated_instance.preferences = preferences
            updated_instance.save(update_fields=["preferences"])

        return updated_instance


def build_autocomplete_serializer(model_cls, extra_fields=()):
    """Build a lightweight serializer for autocomplete/entity pickers: ``id`` plus
    the given fields, and always a display ``str``. Also carries the common
    label ingredients — ``ref_id``/``name`` (or ``description`` for models
    without a name) and a nested ``folder`` — when the model defines them, so
    lazily searched options render with the same composed labels as eagerly
    fetched ones. Enables server-side search so pickers scale to large
    datasets without loading every row client-side. Used by
    core.views.AutocompleteMixin."""

    def _has_field(name: str) -> bool:
        try:
            model_cls._meta.get_field(name)
            return True
        except FieldDoesNotExist:
            return False

    label_fields = [
        f for f in ("ref_id", "name") if f not in extra_fields and _has_field(f)
    ]
    if (
        "name" not in label_fields
        and "description" not in extra_fields
        and _has_field("description")
    ):
        label_fields.append("description")
    has_folder = "folder" not in extra_fields and _has_field("folder")
    # Hierarchy breadcrumb used by pickers to disambiguate same-named rows.
    has_path = "path" not in extra_fields and hasattr(model_cls, "get_folder_full_path")

    class _AutocompleteSerializer(BaseModelSerializer):
        if has_folder:
            folder = FieldsRelatedField()
        if has_path:
            path = PathField(source="get_folder_full_path", read_only=True)

        class Meta:
            model = model_cls
            fields = [
                "id",
                *label_fields,
                *(["folder"] if has_folder else []),
                *(["path"] if has_path else []),
                *extra_fields,
            ]

        def to_representation(self, instance):
            data = super().to_representation(instance)
            data["str"] = str(instance)
            return data

    return _AutocompleteSerializer


class UserGroupReadSerializer(BaseModelSerializer):
    path = PathField(source="get_folder_full_path", read_only=True)
    name = serializers.CharField(source="__str__")
    folder = FieldsRelatedField()

    class Meta:
        model = UserGroup
        fields = "__all__"


class UserGroupWriteSerializer(BaseModelSerializer):
    class Meta:
        model = UserGroup
        fields = "__all__"


class IdPGroupReadSerializer(BaseModelSerializer):
    user_groups = FieldsRelatedField(many=True)
    folder = FieldsRelatedField()

    class Meta:
        model = IdPGroup
        fields = "__all__"


class IdPGroupWriteSerializer(BaseModelSerializer):
    class Meta:
        model = IdPGroup
        fields = "__all__"
        read_only_fields = ["source"]


class PermissionReadSerializer(BaseModelSerializer):
    content_type = FieldsRelatedField(fields=["id", "app_label", "model"])
    normalized_model = serializers.SerializerMethodField()
    normalized_codename = serializers.SerializerMethodField()

    class Meta:
        model = Permission
        fields = "__all__"

    def get_normalized_model(self, obj):
        model_class = obj.content_type.model_class()
        return (
            model_class.__name__ if model_class else obj.content_type.model.capitalize()
        )

    def get_normalized_codename(self, obj):
        model_class = obj.content_type.model_class()
        model_name = (
            model_class.__name__ if model_class else obj.content_type.model.capitalize()
        )
        return f"{obj.codename.split('_')[0]}{model_name}"


class PermissionWriteSerializer(BaseModelSerializer):
    class Meta:
        model = Permission
        fields = "__all__"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for field in self.fields.values():
            field.read_only = True


class RoleAssignmentReadSerializer(BaseModelSerializer):
    user = FieldsRelatedField()
    user_group = FieldsRelatedField()
    role = FieldsRelatedField()
    perimeter_folders = FieldsRelatedField(many=True)
    folder = FieldsRelatedField()

    class Meta:
        model = RoleAssignment
        fields = "__all__"


class RoleAssignmentWriteSerializer(BaseModelSerializer):
    class Meta:
        model = RoleAssignment
        fields = "__all__"


class FolderWriteSerializer(BaseModelSerializer):
    class Meta:
        read_only_fields = ["content_type"]
        model = Folder
        exclude = [
            "builtin",
            "descendants",
            # The default role is not configurable through this serializer: the
            # root folder carries the baseline reader role, pinned by startup(),
            # and no other folder gets one. A subclass may reopen the field
            # (and inherits the validator below).
            "default_role",
        ]

    def validate_default_role(self, default_role):
        if default_role is None:
            return default_role

        # The default role's audience is coarse (everyone working below), so only
        # read capability may ever be ambient — write capability reaches people
        # through explicit group placement, never through a default role.
        if default_role.permissions.exclude(codename__startswith="view_").exists():
            raise serializers.ValidationError(
                "defaultRoleMustContainOnlyViewPermissions"
            )

        # Enclaves are visitor spaces and receive explicit grants only; a member
        # audience there would contradict their purpose.
        if (
            self.instance is not None
            and self.instance.content_type == Folder.ContentType.ENCLAVE
        ):
            raise serializers.ValidationError("enclaveFolderCannotHaveDefaultRole")

        return default_role

    def update(self, instance, validated_data):
        if (
            instance.content_type == Folder.ContentType.ROOT
            and "create_iam_groups" in validated_data
            and validated_data["create_iam_groups"] != instance.create_iam_groups
        ):
            raise serializers.ValidationError(
                {"create_iam_groups": "globalFolderMustKeepIamGroupsEnabled"}
            )

        create_flag_changed = (
            instance.content_type == Folder.ContentType.DOMAIN
            and "create_iam_groups" in validated_data
            and validated_data["create_iam_groups"] != instance.create_iam_groups
        )
        if create_flag_changed:
            new_value = validated_data["create_iam_groups"]
            if new_value:
                with transaction.atomic():
                    updated_instance = super().update(instance, validated_data)
                    Folder.create_default_ug_and_ra(updated_instance)
                return updated_instance

            auto_groups = UserGroup.objects.filter(folder=instance, builtin=True)
            auto_groups_exist = auto_groups.exists()
            if auto_groups_exist and (
                User.objects.filter(user_groups__in=auto_groups).exists()
                or auto_groups.filter(idp_groups__isnull=False).exists()
            ):
                raise serializers.ValidationError(
                    {"create_iam_groups": "cannotDisableIamGroupsAssignedUsers"}
                )
            with transaction.atomic():
                updated_instance = super().update(instance, validated_data)
                if auto_groups_exist:
                    RoleAssignment.objects.filter(user_group__in=auto_groups).delete()
                    auto_groups.delete()
            return updated_instance

        return super().update(instance, validated_data)

    def validate_name(self, value):
        """
        Check that the folder name does not contain the character "/"
        """
        if "/" in value:
            raise serializers.ValidationError(
                "The name cannot contain '/' for a Folder."
            )
        return value

    def _resolve_parent_folder(self, value):
        """Normalise and authorise a target parent, independent of edition policy.

        Kept out of `validate_parent_folder` so that editions which allow nesting can
        override the policy without losing these rules, and so permission is resolved
        before any policy — a 403 must beat "this needs PRO".
        """
        if not value:
            root = Folder.get_root_folder()
            # Detaching to the root is still an add there. Create is left to `create()`;
            # without this, `parent_folder: null` was the one target needing no rights.
            if self.instance is not None and str(self.instance.parent_folder_id) != str(
                root.id
            ):
                self._check_object_perm(self.instance, "add", folder=root)
            return root
        if self.instance is None:
            # The base class checks this only in `create()`, after field validation —
            # too late for a policy that rejects during `is_valid()`.
            self._check_object_perm(None, "add", folder=value)
        elif self.instance.parent_folder_id and str(value.id) != str(
            self.instance.parent_folder_id
        ):
            self._check_object_perm(self.instance, "add", folder=value)
        return value

    def validate_parent_folder(self, value):
        """Community domains sit directly under the root; nesting is a PRO capability.

        Only *changing* the nesting is gated: an already-nested folder stays editable,
        so downgrading from PRO never strands existing data.
        """
        parent_folder = self._resolve_parent_folder(value)
        if parent_folder == Folder.get_root_folder():
            return parent_folder
        if self.instance is not None and parent_folder == self.instance.parent_folder:
            return parent_folder
        raise serializers.ValidationError("subDomainsRequirePro")


class FolderReadSerializer(BaseModelSerializer):
    path = PathField(read_only=True)
    parent_folder = FieldsRelatedField()
    filtering_labels = FieldsRelatedField(many=True)
    default_role = FieldsRelatedField()

    content_type = serializers.CharField(source="get_content_type_display")

    class Meta:
        model = Folder
        exclude = ["descendants"]


class FolderImportExportSerializer(BaseModelSerializer):
    parent_folder = HashSlugRelatedField(slug_field="pk", read_only=True)

    class Meta:
        model = Folder
        fields = [
            "parent_folder",
            "name",
            "description",
            "content_type",
            "create_iam_groups",
            "created_at",
            "updated_at",
        ]


class RoleReadSerializer(BaseModelSerializer):
    name = serializers.CharField(source="__str__")
    permissions = serializers.SerializerMethodField()
    folder = FieldsRelatedField()

    class Meta:
        model = Role
        fields = "__all__"

    def get_permissions(self, obj):
        return [{"str": perm.codename} for perm in obj.permissions.all()]


class RoleWriteSerializer(BaseModelSerializer):
    class Meta:
        model = Role
        fields = "__all__"

    def validate_permissions(self, permissions):
        # A role already in use as some folder's default role must stay view-only;
        # otherwise editing the role would silently hand write capability to every
        # member audience that references it.
        if (
            self.instance is not None
            and self.instance.default_role_folders.exists()
            and not all(
                permission.codename.startswith("view_") for permission in permissions
            )
        ):
            raise serializers.ValidationError("roleUsedAsDefaultRoleMustStayViewOnly")
        return permissions


# Compliance Assessment


class FrameworkOptionsSerializer(serializers.ModelSerializer):
    """Just enough to render a framework in a picker: the full read serializer
    carries the visibility maps, implementation groups and reference controls."""

    name = serializers.CharField(source="get_name_translated")

    class Meta:
        model = Framework
        fields = ["id", "ref_id", "name"]


class FrameworkReadSerializer(ReferentialSerializer):
    folder = FieldsRelatedField()
    library = FieldsRelatedField(["name", "id", "urn"])
    reference_controls = FieldsRelatedField(many=True)
    is_dynamic = serializers.BooleanField(read_only=True)
    has_update = serializers.BooleanField(read_only=True)
    has_compliance_assessments = serializers.SerializerMethodField()
    is_scale_bound = serializers.SerializerMethodField()
    scores_definition = serializers.SerializerMethodField()
    # The complete per-role visibility map a new CA created from this framework
    # would inherit: DEFAULT_VISIBILITY ⊕ framework.field_visibility. The
    # CA-creation form's editor reads this so its pills always reflect what
    # the backend will actually save.
    effective_field_visibility = serializers.SerializerMethodField()
    # Same map for an audit addressed to a third party: the entity-assessment form
    # reads this so its pills match what that path will save.
    third_party_field_visibility = serializers.SerializerMethodField()

    implementation_groups_definition = serializers.SerializerMethodField()

    def get_implementation_groups_definition(self, obj):
        return obj.get_implementation_groups_definition_translated()

    def get_has_compliance_assessments(self, obj):
        flag = getattr(obj, "has_compliance_assessments_flag", None)
        if flag is not None:
            return flag
        return obj.complianceassessment_set.exists()

    def get_is_scale_bound(self, obj):
        flag = getattr(obj, "scale_bound_flag", None)
        if flag is not None:
            return flag
        return obj.is_scale_bound

    def get_scores_definition(self, obj):
        sd = obj.scores_definition
        if isinstance(sd, dict) and "scale" in sd:
            return sd["scale"]
        return sd

    def get_effective_field_visibility(self, obj):
        from core.utils import build_initial_field_visibility

        return build_initial_field_visibility(obj)

    def get_third_party_field_visibility(self, obj):
        from core.utils import build_third_party_field_visibility

        return build_third_party_field_visibility(obj)

    class Meta:
        model = Framework
        exclude = ["translations"]


class FrameworkWriteSerializer(FrameworkReadSerializer):
    # Override ReferentialSerializer's source-mapped fields so DRF writes
    # to the actual model columns instead of the read-only translation properties.
    name = serializers.CharField(max_length=200, required=False, allow_blank=True)
    description = serializers.CharField(
        required=False, allow_blank=True, allow_null=True
    )
    annotation = serializers.CharField(
        required=False, allow_blank=True, allow_null=True
    )
    # reference_controls is a read-only property on Framework, not a writable DB field.
    reference_controls = serializers.ListField(required=False, read_only=True)
    implementation_groups_definition = serializers.JSONField(
        required=False, allow_null=True
    )

    def create(self, validated_data):
        # Strip any non-model fields that leak through from the read serializer
        validated_data.pop("reference_controls", None)
        return super().create(validated_data)


class FrameworkImportExportSerializer(BaseModelSerializer):
    library = serializers.SlugRelatedField(slug_field="urn", read_only=True)

    class Meta:
        model = Framework
        fields = [
            "urn",
            "ref_id",
            "name",
            "library",
            "min_score",
            "max_score",
            "implementation_groups_definition",
            "outcomes_definition",
            "provider",
            "annotation",
            "translations",
            "locale",
            "default_locale",
            "created_at",
            "updated_at",
        ]


class RequirementNodeReadSerializer(ReferentialSerializer):
    reference_controls = FieldsRelatedField(many=True)
    threats = FieldsRelatedField(many=True)
    display_short = serializers.CharField()
    display_long = serializers.CharField()
    questions = serializers.SerializerMethodField()
    typical_evidence = serializers.CharField(
        source="get_typical_evidence_translated", allow_blank=True, allow_null=True
    )

    def get_questions(self, obj):
        """Reconstruct the old JSON format from Question/QuestionChoice models
        for backward compatibility with the frontend."""
        request = self.context.get("request")
        questionnaire_context = self.context.get("_questionnaire_visibility_context")
        if request is not None and isinstance(
            questionnaire_context, QuestionnaireVisibilityContext
        ):
            questions = questionnaire_context.translated_questions_for(request, obj)
            visibility = (
                questionnaire_context.visible_question_urns,
                questionnaire_context.visible_choice_urns_by_question,
                questionnaire_context.choice_question_urns,
            )
        else:
            questions = obj.get_questions_translated
            visibility = None
        if not questions:
            return None
        # Preserve the established serializer contract for trusted in-process
        # callers (including library/translation tooling). API serializers are
        # given a request by DRF and continue through the exact Question and
        # QuestionChoice IAM projection below.
        if request is None:
            return questions

        visibility = visibility or self.context.get("_questionnaire_visibility")
        if visibility is None:
            visible_question_ids = RoleAssignment.get_viewable_object_ids(
                request.user, Question
            )
            visible_questions = list(
                Question.objects.filter(id__in=visible_question_ids).values_list(
                    "id", "urn", "type"
                )
            )
            question_urn_by_id = {
                question_id: urn for question_id, urn, _type in visible_questions
            }
            visible_question_urns = set(question_urn_by_id.values())
            choice_question_urns = {
                urn
                for _question_id, urn, question_type in visible_questions
                if question_type
                in (Question.Type.UNIQUE_CHOICE, Question.Type.MULTIPLE_CHOICE)
            }
            visible_choice_ids = RoleAssignment.get_viewable_object_ids(
                request.user, QuestionChoice
            )
            visible_choice_urns_by_question: dict[str, set[str]] = {}
            for question_id, choice_urn in QuestionChoice.objects.filter(
                id__in=visible_choice_ids,
                question_id__in=question_urn_by_id,
            ).values_list("question_id", "urn"):
                visible_choice_urns_by_question.setdefault(
                    question_urn_by_id[question_id], set()
                ).add(choice_urn)
            visibility = (
                visible_question_urns,
                visible_choice_urns_by_question,
                choice_question_urns,
            )
            self.context["_questionnaire_visibility"] = visibility

        (
            visible_question_urns,
            visible_choice_urns_by_question,
            choice_question_urns,
        ) = visibility
        return project_questionnaire_payload(
            questions,
            visible_question_urns=visible_question_urns,
            visible_choice_urns_by_question=visible_choice_urns_by_question,
            choice_question_urns=choice_question_urns,
        )

    def to_representation(self, instance):
        data = super().to_representation(instance)
        request = self.context.get("request")
        if request is None:
            return data

        visible_cache = self.context.setdefault(
            "_visible_requirement_node_related_ids", {}
        )
        for field_name, model in (
            ("reference_controls", ReferenceControl),
            ("threats", Threat),
        ):
            values = data.get(field_name)
            if not isinstance(values, list):
                continue
            if model not in visible_cache:
                visible_cache[model] = set(
                    RoleAssignment.get_viewable_object_ids(request.user, model)
                )
            visible_ids = visible_cache[model]
            filtered = []
            for value in values:
                raw_id = value.get("id") if isinstance(value, dict) else value
                try:
                    object_id = UUID(str(raw_id))
                except TypeError, ValueError:
                    continue
                if object_id in visible_ids:
                    filtered.append(value)
            data[field_name] = filtered
        return data

    class Meta:
        model = RequirementNode
        exclude = ["translations"]


class RequirementNodeWriteSerializer(BaseModelSerializer):
    def to_internal_value(self, data):
        if self.instance is not None and "framework" in data:
            try:
                submitted_framework_id = UUID(str(data["framework"]))
            except TypeError, ValueError, AttributeError:
                raise PermissionDenied({"framework": "This field is immutable"})
            if submitted_framework_id != self.instance.framework_id:
                # Reject before the related-field lookup so a public update cannot
                # distinguish an existing foreign Framework UUID from a missing one.
                raise PermissionDenied({"framework": "This field is immutable"})
        return super().to_internal_value(data)

    def validate_framework(self, value):
        self._ensure_immutable("framework", value)
        return value

    def update(self, instance, validated_data):
        # Skip the URN-based "imported objects" guard from BaseModelSerializer
        # because requirement nodes on draft frameworks should be editable.
        self._check_object_perm(instance, "change")
        try:
            with transaction.atomic():
                m2m_field_names = {f.name for f in instance._meta.many_to_many}
                m2m_values = {
                    attr: validated_data.pop(attr)
                    for attr in list(validated_data.keys())
                    if attr in m2m_field_names
                }
                for attr, value in validated_data.items():
                    setattr(instance, attr, value)
                # Only the cross-field override constraints: full_clean() would
                # also re-run clean_fields() over untouched nullable columns and
                # reject them as blank. DRF already validated what was sent.
                instance.clean()
                instance.save()
                for attr, value in m2m_values.items():
                    getattr(instance, attr).set(value)
                return instance
        except DjangoValidationError as e:
            raise serializers.ValidationError(getattr(e, "message_dict", e.messages))
        except Exception:
            logger.error("Failed to update RequirementNode", exc_info=True)
            raise

    class Meta:
        model = RequirementNode
        exclude = ["created_at", "updated_at"]


class EvidenceReadSerializer(
    RequirementAssessmentRelationshipProjectionMixin, BaseModelSerializer
):
    path = PathField(read_only=True)
    attachment = serializers.SerializerMethodField()
    size = serializers.CharField(source="get_size")
    folder = FieldsRelatedField()
    applied_controls = FieldsRelatedField(many=True)
    requirement_assessments = FieldsRelatedField(many=True)
    security_exceptions = FieldsRelatedField(many=True)
    contracts = FieldsRelatedField(many=True)
    task_templates = FieldsRelatedField(many=True)
    filtering_labels = FieldsRelatedField(["id", "folder"], many=True)
    owner = FieldsRelatedField(many=True)
    status = serializers.CharField(source="get_status_display")
    link = serializers.SerializerMethodField()

    def get_attachment(self, obj):
        last_revision = obj.last_revision
        if last_revision and last_revision.attachment:
            return last_revision.attachment.url
        return None

    def get_link(self, obj):
        last_revision = obj.last_revision
        return last_revision.link if last_revision else None

    class Meta:
        model = Evidence
        fields = "__all__"
        list_serializer_class = (
            RequirementAssessmentRelationshipProjectionListSerializer
        )


class EvidenceWriteSerializer(
    RequirementAssessmentRelationshipAuthorityMixin, BaseModelSerializer
):
    applied_controls = serializers.PrimaryKeyRelatedField(
        many=True, queryset=AppliedControl.objects.all(), required=False
    )
    requirement_assessments = GovernedRequirementAssessmentPrimaryKeyRelatedField(
        many=True, queryset=RequirementAssessment.objects.all(), required=False
    )
    findings = serializers.PrimaryKeyRelatedField(
        many=True, required=False, queryset=Finding.objects.all()
    )
    findings_assessments = serializers.PrimaryKeyRelatedField(
        many=True, queryset=FindingsAssessment.objects.all(), required=False
    )
    security_exceptions = serializers.PrimaryKeyRelatedField(
        many=True, queryset=SecurityException.objects.all(), required=False
    )
    timeline_entries = serializers.PrimaryKeyRelatedField(
        many=True, queryset=TimelineEntry.objects.all(), required=False
    )
    contracts = serializers.PrimaryKeyRelatedField(
        many=True, queryset=Contract.objects.all(), required=False
    )
    # Reverse M2M (declared on TaskTemplate): DRF does not pick it up from Meta.
    task_templates = serializers.PrimaryKeyRelatedField(
        many=True, queryset=TaskTemplate.objects.all(), required=False
    )
    genericcollection = serializers.PrimaryKeyRelatedField(
        source="genericcollection_set",
        many=True,
        required=False,
        queryset=GenericCollection.objects.all(),
    )
    owner = serializers.PrimaryKeyRelatedField(
        many=True, queryset=Actor.objects.all(), required=False
    )
    attachment = serializers.FileField(required=False)
    link = serializers.URLField(required=False)
    observation = serializers.CharField(
        required=False, allow_blank=True, allow_null=True, write_only=True
    )

    # A respondent deposits evidence but must not adjudicate it: the status
    # (in_review / approved / rejected / …) is an auditor-side decision.
    RESPONDENT_PROTECTED_FIELDS = {"status"}

    class Meta:
        model = Evidence
        fields = "__all__"
        list_serializer_class = (
            RequirementAssessmentRelationshipProjectionListSerializer
        )

    def create(self, validated_data):
        with transaction.atomic():
            attachment = validated_data.pop("attachment", None)
            link = validated_data.pop("link", None)
            observation = validated_data.pop("observation", None)
            task_templates = validated_data.pop("task_templates", [])

            evidence = super().create(validated_data)

            if task_templates:
                evidence.task_templates.set(task_templates)

            # A revision stands for a deposited artifact. Opening an empty one
            # makes an evidence that holds nothing look populated.
            if attachment or link or observation:
                EvidenceRevision.objects.get_or_create(
                    evidence=evidence,
                    defaults={
                        "link": link,
                        "attachment": attachment,
                        "observation": observation,
                    },
                )

            return evidence

    def update(self, instance, validated_data):
        task_templates = validated_data.pop("task_templates", None)
        with transaction.atomic():
            governed_relationship = "requirement_assessments" in validated_data
            old_folder_id = None if governed_relationship else instance.folder_id
            instance = super().update(instance, validated_data)

            if governed_relationship:
                old_folder_id = self._governed_locked_scalar_snapshot["folder_id"]

            if task_templates is not None:
                instance.task_templates.set(task_templates)

            # Update all EvidenceRevisions' folder if the Evidence's folder changed
            if old_folder_id != instance.folder_id:
                EvidenceRevision.objects.filter(evidence=instance).update(
                    folder=instance.folder
                )

        return instance

    def to_representation(self, instance):
        """Include link and attachment from the latest revision in the response"""
        data = super().to_representation(instance)

        # Add revision fields to the response
        latest_revision = instance.last_revision
        if latest_revision:
            data["link"] = latest_revision.link
            data["attachment"] = (
                latest_revision.attachment.url if latest_revision.attachment else None
            )
        else:
            data["link"] = None
            data["attachment"] = None

        return data


class EvidenceImportExportSerializer(BaseModelSerializer):
    folder = HashSlugRelatedField(slug_field="pk", read_only=True)

    class Meta:
        model = Evidence
        fields = [
            "folder",
            "name",
            "description",
            "created_at",
            "updated_at",
            "status",
            "expiry_date",
        ]


class EvidenceRevisionReadSerializer(BaseModelSerializer):
    attachment = serializers.CharField(source="filename")
    size = serializers.CharField(source="get_size")
    evidence = FieldsRelatedField()
    folder = FieldsRelatedField()
    str = serializers.CharField(source="__str__")
    task_node = FieldsRelatedField()

    class Meta:
        model = EvidenceRevision
        fields = "__all__"


class EvidenceRevisionWriteSerializer(BaseModelSerializer):
    class Meta:
        model = EvidenceRevision
        fields = "__all__"
        read_only_fields = ["version"]

    def validate(self, attrs):
        attrs = super().validate(attrs)
        # The submitted folder is decorative: EvidenceRevision.save() replaces it
        # with the evidence's own. Authorizing the submitted one therefore checks a
        # folder the row never lands in, letting a caller with rights in folder A
        # file a revision against evidence in folder B.
        evidence = attrs.get("evidence") or getattr(self.instance, "evidence", None)
        if evidence is not None:
            self._check_object_perm(attrs, "add", folder=evidence.folder)
            # create() flips the evidence to in_review, which is a write to the
            # parent row and not covered by add_evidencerevision.
            self._check_object_perm(
                attrs, "change", folder=evidence.folder, model=Evidence
            )
        return attrs

    def create(self, validated_data):
        with transaction.atomic():
            evidence = Evidence.objects.select_for_update().get(
                pk=validated_data["evidence"].pk
            )
            max_version = EvidenceRevision.objects.filter(evidence=evidence).aggregate(
                models.Max("version")
            )["version__max"]
            validated_data["version"] = (max_version or 0) + 1
            evidence.status = Evidence.Status.IN_REVIEW
            evidence.save()
            return super().create(validated_data)


class EvidenceRevisionImportExportSerializer(BaseModelSerializer):
    folder = HashSlugRelatedField(slug_field="pk", read_only=True)
    evidence = HashSlugRelatedField(slug_field="pk", read_only=True)
    attachment = serializers.CharField(allow_blank=True)
    size = serializers.CharField(source="get_size", read_only=True)
    attachment_hash = serializers.CharField(read_only=True)

    class Meta:
        model = EvidenceRevision
        fields = [
            "folder",
            "evidence",
            "observation",
            "version",
            "attachment",
            "original_filename",
            "link",
            "created_at",
            "updated_at",
            "size",
            "attachment_hash",
        ]


class AttachmentUploadSerializer(serializers.Serializer):
    attachment = serializers.FileField(required=True)

    class Meta:
        model = Evidence
        fields = ["attachment"]


class OrganisationObjectiveReadSerializer(BaseModelSerializer):
    folder = FieldsRelatedField()
    assets = FieldsRelatedField(many=True)
    issues = FieldsRelatedField(many=True)
    tasks = FieldsRelatedField(many=True)
    metrics = FieldsRelatedField(many=True)
    status = serializers.CharField(source="get_status_display")
    health = serializers.CharField(source="get_health_display")
    assigned_to = FieldsRelatedField(many=True)

    class Meta:
        model = OrganisationObjective
        fields = "__all__"


class OrganisationObjectiveWriteSerializer(BaseModelSerializer):
    applied_controls = serializers.PrimaryKeyRelatedField(
        many=True,
        queryset=AppliedControl.objects.all(),
        required=False,
    )

    class Meta:
        model = OrganisationObjective
        fields = "__all__"

    def create(self, validated_data: Any):
        applied_controls = validated_data.pop("applied_controls", [])
        instance = super().create(validated_data)
        if applied_controls:
            instance.applied_controls.set(applied_controls)
        return instance

    def update(self, instance, validated_data):
        applied_controls = validated_data.pop("applied_controls", None)
        instance = super().update(instance, validated_data)
        if applied_controls is not None:
            instance.applied_controls.set(applied_controls)
        return instance


class OrganisationObjectiveDuplicateSerializer(BaseModelSerializer):
    class Meta:
        model = OrganisationObjective
        fields = ["name", "description", "folder"]


class OrganisationIssueReadSerializer(BaseModelSerializer):
    folder = FieldsRelatedField()
    assets = FieldsRelatedField(many=True)
    category = serializers.CharField(source="get_category_display")
    origin = serializers.CharField(source="get_origin_display")

    class Meta:
        model = OrganisationIssue
        fields = "__all__"


class OrganisationIssueWriteSerializer(BaseModelSerializer):
    objectives = serializers.PrimaryKeyRelatedField(
        many=True,
        queryset=OrganisationObjective.objects.all(),
        required=False,
    )

    class Meta:
        model = OrganisationIssue
        fields = "__all__"

    def validate(self, attrs):
        start_date = attrs.get(
            "start_date",
            getattr(getattr(self, "instance", None), "start_date", None),
        )
        expiration_date = attrs.get(
            "expiration_date",
            getattr(getattr(self, "instance", None), "expiration_date", None),
        )
        if start_date and expiration_date and start_date > expiration_date:
            raise serializers.ValidationError(
                {"expiration_date": "Expiration date must be on or after start date"}
            )
        return super().validate(attrs)

    def create(self, validated_data: Any):
        objectives = validated_data.pop("objectives", [])
        instance = super().create(validated_data)
        if objectives:
            instance.objectives.set(objectives)
        return instance

    def update(self, instance, validated_data):
        objectives = validated_data.pop("objectives", None)
        instance = super().update(instance, validated_data)
        if objectives is not None:
            instance.objectives.set(objectives)
        return instance


class CampaignReadSerializer(BaseModelSerializer):
    folder = FieldsRelatedField()
    compliance_assessments = FieldsRelatedField(many=True)
    perimeters = FieldsRelatedField(many=True)
    entities = FieldsRelatedField(many=True)
    frameworks = FieldsRelatedField(many=True)

    class Meta:
        model = Campaign
        fields = "__all__"


class CampaignWriteSerializer(BaseModelSerializer):
    def validate_selected_implementation_groups(self, value):
        """Launch reads `framework` and `value` off each entry with bare subscripts,
        and the field is free-form JSON: a malformed entry would 500 there."""
        if not value:
            return value
        if not isinstance(value, list) or any(
            not isinstance(entry, dict)
            or "framework" not in entry
            or "value" not in entry
            for entry in value
        ):
            raise serializers.ValidationError(
                "Each entry must be an object carrying `framework` and `value`."
            )
        return value

    class Meta:
        model = Campaign
        fields = "__all__"

    def create(self, validated_data: Any):
        return super().create(validated_data)


class ComplianceAssessmentReadSerializer(AssessmentReadSerializer):
    path = PathField(read_only=True)
    perimeter = FieldsRelatedField(["id", "folder"])
    folder = FieldsRelatedField()
    campaign = FieldsRelatedField()
    # The binder raised from this audit's requirements, so the page can link to it.
    findings_assessments = FieldsRelatedField(many=True)
    framework = FieldsRelatedField(
        [
            "id",
            "urn",
            "min_score",
            "max_score",
            "implementation_groups_definition",
            "outcomes_definition",
            "ref_id",
            "reference_controls",
            "has_update",
        ]
    )
    selected_implementation_groups = serializers.ReadOnlyField(
        source="get_selected_implementation_groups"
    )
    progress = serializers.SerializerMethodField()
    answers_progress = serializers.SerializerMethodField()
    assets = FieldsRelatedField(many=True)
    evidences = FieldsRelatedField(many=True)
    validation_flows = FieldsRelatedField(
        many=True,
        fields=[
            "id",
            "ref_id",
            "status",
            "request_notes",
            "last_event_notes",
            {"approver": ["id", "email", "first_name", "last_name"]},
        ],
        source="validationflow_set",
    )
    entity_assessments = FieldsRelatedField(many=True, source="entityassessment_set")
    requirement_assignments = FieldsRelatedField(["id", "status"], many=True)

    def _request_user(self):
        request = self.context.get("request")
        user = getattr(request, "user", None)
        if user is None or not getattr(user, "is_authenticated", False):
            return None
        return user

    def _visible_ids(self, model) -> set[UUID]:
        """Return a request-scoped generic IAM snapshot for a related model."""
        user = self._request_user()
        if user is None:
            return set()
        cache = self.context.setdefault("_ca_detail_visible_related_ids", {})
        if model not in cache:
            cache[model] = set(RoleAssignment.get_viewable_object_ids(user, model))
        return cache[model]

    @staticmethod
    def _related_uuid(value):
        raw_id = value.get("id") if isinstance(value, dict) else value
        try:
            return UUID(str(raw_id))
        except TypeError, ValueError:
            return None

    def _authorized_progress_projection(self, obj) -> dict | None:
        """Build progress only from rows and answer carriers the caller may read.

        The model properties intentionally describe the complete audit.  A CA
        detail response may also be consumed by an assignment-scoped
        respondent, so delegating to those properties discloses whether hidden
        requirements or answers have moved.  This projector keeps the model as
        the system-of-record while applying generic IAM, the exact full-view
        grant/assignment boundary, RequirementNode IAM, question/choice/answer
        IAM, and field visibility before deriving either percentage.
        """
        user = self._request_user()
        if user is None:
            return None

        cache = self.context.setdefault("_ca_detail_progress_projection", {})
        if obj.id in cache:
            return cache[obj.id]

        from core.utils import get_authorized_compliance_progress_projections

        projection = get_authorized_compliance_progress_projections(user, [obj]).get(
            obj.id
        )
        cache[obj.id] = projection
        return projection

    def get_progress(self, obj):
        projection = self._authorized_progress_projection(obj)
        return projection["progress"] if projection is not None else None

    def get_answers_progress(self, obj):
        projection = self._authorized_progress_projection(obj)
        return projection["answers_progress"] if projection is not None else None

    scores_definition = serializers.SerializerMethodField()

    def get_scores_definition(self, obj):
        sd = obj.scores_definition
        if isinstance(sd, dict) and "scale" in sd:
            return sd["scale"]
        return sd

    field_visibility = serializers.SerializerMethodField()

    def get_field_visibility(self, obj):
        """Return field_visibility with defaults applied.

        If the stored map is empty (e.g. audits created before the field was
        populated at creation time), fall back to the code defaults merged with
        the framework template — the same values a newly created CA would get —
        so the frontend always receives a complete map.
        """
        from core.utils import build_initial_field_visibility

        user = self._request_user()
        if user is None:
            # Serializer use outside an authenticated API request must not
            # reveal this audit's configured role policy or inherit a hidden
            # framework's overrides.
            return build_initial_field_visibility(None)
        fv = obj.field_visibility
        if fv:
            return fv

        if obj.framework_id not in self._visible_ids(Framework):
            return build_initial_field_visibility(None)

        return build_initial_field_visibility(obj.framework)

    # Derived booleans, kept in the API for backwards compatibility. The actual
    # storage is `field_visibility`; clients that want to change these should
    # PATCH `field_visibility` directly.
    scoring_enabled = serializers.BooleanField(read_only=True)
    show_documentation_score = serializers.BooleanField(read_only=True)
    extended_result_enabled = serializers.BooleanField(read_only=True)
    progress_status_enabled = serializers.BooleanField(read_only=True)

    def to_representation(self, instance):
        data = super().to_representation(instance)

        from core.utils import (
            has_full_view_compliance_assessment,
            is_field_visible_to,
        )

        user = self._request_user()
        viewer_role = (
            "auditor"
            if user is not None and has_full_view_compliance_assessment(user, instance)
            else "respondent"
        )
        if not is_field_visible_to(instance, "status", viewer_role):
            data.pop("status", None)
        if not is_field_visible_to(instance, "result", viewer_role):
            # CEL outcomes are a result projection, not an independent path
            # around the assessment's result visibility policy.
            data.pop("computed_outcome", None)
        if not is_field_visible_to(instance, "score", viewer_role):
            for field_name in (
                "min_score",
                "max_score",
                "scores_definition",
                "score_calculation_method",
                "target_score",
                "anchor_na_to_target",
            ):
                data.pop(field_name, None)

        # Top-level related objects are independently governed. Access to the
        # assessment's folder is not transitive authority over an asset,
        # evidence, actor, validation flow, perimeter, campaign, framework, or
        # reference control in another IAM scope.
        for field_name, model in (
            ("assets", Asset),
            ("evidences", Evidence),
            ("authors", Actor),
            ("reviewers", Actor),
        ):
            values = data.get(field_name)
            if not isinstance(values, list):
                continue
            visible_ids = self._visible_ids(model)
            data[field_name] = [
                value for value in values if self._related_uuid(value) in visible_ids
            ]

        validation_flows = data.get("validation_flows")
        if isinstance(validation_flows, list):
            visible_flow_ids = self._visible_ids(ValidationFlow)
            visible_user_ids = self._visible_ids(User)
            filtered_flows = []
            for value in validation_flows:
                if self._related_uuid(value) not in visible_flow_ids:
                    continue
                value = dict(value)
                approver = value.get("approver")
                if (
                    approver is not None
                    and self._related_uuid(approver) not in visible_user_ids
                ):
                    value["approver"] = None
                filtered_flows.append(value)
            data["validation_flows"] = filtered_flows

        for field_name, model in (
            ("folder", Folder),
            ("perimeter", Perimeter),
            ("campaign", Campaign),
        ):
            value = data.get(field_name)
            if value is not None and self._related_uuid(value) not in self._visible_ids(
                model
            ):
                data[field_name] = None
                if field_name == "folder":
                    data["path"] = None

        perimeter = data.get("perimeter")
        if isinstance(perimeter, dict) and perimeter.get("folder") is not None:
            perimeter_folder_id = self._related_uuid(perimeter["folder"])
            if perimeter_folder_id not in self._visible_ids(Folder):
                perimeter["folder"] = None

        framework = data.get("framework")
        if framework is not None:
            if self._related_uuid(framework) not in self._visible_ids(Framework):
                data["framework"] = None
                # These labels are resolved through the hidden Framework and
                # must not survive under a different key.
                data.pop("selected_implementation_groups", None)
            elif isinstance(framework, dict):
                if not is_field_visible_to(instance, "score", viewer_role):
                    framework.pop("min_score", None)
                    framework.pop("max_score", None)
                visible_reference_control_ids = self._visible_ids(ReferenceControl)
                reference_controls = framework.get("reference_controls")
                if isinstance(reference_controls, list):
                    framework["reference_controls"] = [
                        value
                        for value in reference_controls
                        if self._related_uuid(value) in visible_reference_control_ids
                    ]

        return data

    class Meta:
        model = ComplianceAssessment
        fields = "__all__"


class ComplianceAssessmentListSerializer(BaseModelSerializer):
    """Optimized serializer for list views - only includes fields needed by the table."""

    path = PathField(read_only=True)
    authors = FieldsRelatedField(many=True)
    folder = FieldsRelatedField()
    framework = FieldsRelatedField()
    perimeter = FieldsRelatedField()
    progress = serializers.SerializerMethodField()
    entity_assessments = FieldsRelatedField(many=True, source="entityassessment_set")

    def get_progress(self, obj):
        # Fast path: page-scoped counts from optimized_data, computed for
        # every audit of the page (per-mode GROUP BY buckets, plus one shared
        # scalar scan for implementation-groups audits) in
        # ComplianceAssessmentViewSet._get_optimized_object_data.
        optimized_data = self.context.get("optimized_data") or {}
        progress_map = optimized_data.get("progress")
        if progress_map is not None and obj.id in progress_map:
            return progress_map[obj.id]
        total_map = optimized_data.get("total_requirements")
        if total_map is not None and obj.id in total_map:
            total = total_map[obj.id]
            assessed = optimized_data.get("assessed_requirements", {}).get(obj.id, 0)
            return int((assessed / total) * 100) if total else 0
        # No optimized context (serializer used outside the list action): use
        # the same caller-authorized projector. Falling back to ``obj.progress``
        # would expose the complete audit to assignment-scoped respondents.
        request = self.context.get("request")
        user = getattr(request, "user", None)
        from core.utils import get_authorized_compliance_progress_projections

        projection = get_authorized_compliance_progress_projections(user, [obj]).get(
            obj.id
        )
        return projection["progress"] if projection is not None else None

    def to_representation(self, instance):
        data = super().to_representation(instance)
        optimized_data = self.context.get("optimized_data") or {}
        viewer_role = optimized_data.get("viewer_roles", {}).get(instance.id)
        if viewer_role is None:
            request = self.context.get("request")
            user = getattr(request, "user", None)
            if user is None or not getattr(user, "is_authenticated", False):
                viewer_role = "respondent"
            else:
                from core.utils import has_full_view_compliance_assessment

                viewer_role = (
                    "auditor"
                    if has_full_view_compliance_assessment(user, instance)
                    else "respondent"
                )

        from core.utils import is_field_visible_to

        if not is_field_visible_to(instance, "status", viewer_role):
            data.pop("status", None)
        # CEL outcomes are an assessment-result projection. Do not expose them
        # under a separate key when the caller's result axis is hidden.
        if not is_field_visible_to(instance, "result", viewer_role):
            data.pop("computed_outcome", None)
        return data

    class Meta:
        model = ComplianceAssessment
        fields = [
            "id",
            "ref_id",
            "name",
            "description",
            "version",
            "framework",
            "computed_outcome",
            "folder",
            "perimeter",
            "progress",
            "status",
            "is_locked",
            "eta",
            "due_date",
            "created_at",
            "updated_at",
            "path",
            "authors",
            "entity_assessments",
        ]


class ScoreRescaleConfirmationRequired(APIException):
    status_code = 409
    default_code = "score_rescale_confirmation_required"

    def __init__(self, impact: dict):
        self.impact = impact
        super().__init__()
        # Set after init: APIException would turn every number into a string.
        self.detail = {
            "confirm_rescale": ["scoreScaleConfirmRequired"],
            "rescale_impact": impact,
        }


class ComplianceAssessmentWriteSerializer(BaseModelSerializer):
    confirm_rescale = serializers.BooleanField(
        write_only=True, required=False, default=False
    )
    genericcollection = serializers.PrimaryKeyRelatedField(
        source="genericcollection_set",
        many=True,
        required=False,
        queryset=GenericCollection.objects.all(),
    )
    baseline = serializers.PrimaryKeyRelatedField(
        write_only=True,
        queryset=ComplianceAssessment.objects.all(),
        required=False,
        allow_null=True,
    )
    ebios_rm_studies = serializers.PrimaryKeyRelatedField(
        many=True,
        queryset=EbiosRMStudy.objects.all(),
        required=False,
        allow_null=True,
        write_only=True,
    )
    create_applied_controls_from_suggestions = serializers.BooleanField(
        write_only=True, required=False, default=False
    )

    def to_internal_value(self, data):
        if self.instance is not None and "framework" in data:
            try:
                submitted_framework_id = UUID(str(data["framework"]))
            except TypeError, ValueError, AttributeError:
                raise PermissionDenied({"framework": "This field is immutable"})
            if submitted_framework_id != self.instance.framework_id:
                # Reject before the related-field lookup so a public update cannot
                # distinguish an existing foreign Framework UUID from a missing one.
                raise PermissionDenied({"framework": "This field is immutable"})
        return super().to_internal_value(data)

    def validate_framework(self, value):
        self._ensure_immutable("framework", value)
        return value

    def validate(self, attrs):
        # Drop implementation groups that don't exist in the framework.
        if "selected_implementation_groups" in attrs or (
            "framework" in attrs and self.instance
        ):
            framework = attrs.get("framework") or getattr(
                self.instance, "framework", None
            )
            defined = {
                ig.get("ref_id")
                for ig in (
                    getattr(framework, "implementation_groups_definition", None) or []
                )
            }
            selected = attrs.get(
                "selected_implementation_groups",
                getattr(self.instance, "selected_implementation_groups", None),
            )
            selected = selected if isinstance(selected, list) else []
            attrs["selected_implementation_groups"] = [
                g for g in selected if isinstance(g, str) and g in defined
            ]

        if hasattr(self, "instance") and self.instance and self.instance.is_locked:
            # Unlocking may come with other changes in the same save; they still
            # go through the checks below. Otherwise only is_locked may change.
            unlocking = "is_locked" in attrs and attrs["is_locked"] is False
            locked_fields = [field for field in attrs.keys() if field != "is_locked"]
            if not unlocking and locked_fields:
                raise serializers.ValidationError(
                    f"⚠️ Cannot modify the audit attributes when it is locked. Only the 'Locked' field can be modified."
                )

        self._validate_score_scale(attrs, confirm=attrs.pop("confirm_rescale", False))

        target = attrs.get(
            "target_score",
            getattr(self.instance, "target_score", None) if self.instance else None,
        )
        anchor = attrs.get(
            "anchor_na_to_target",
            getattr(self.instance, "anchor_na_to_target", False)
            if self.instance
            else False,
        )
        if anchor and target is None:
            raise serializers.ValidationError(
                {
                    "target_score": "A target score is required when anchoring N/A to target is enabled."
                }
            )
        if target is not None:
            min_s, max_s = getattr(self, "_effective_score_range", None) or (
                attrs.get(
                    "min_score",
                    getattr(self.instance, "min_score", None)
                    if self.instance
                    else None,
                ),
                attrs.get(
                    "max_score",
                    getattr(self.instance, "max_score", None)
                    if self.instance
                    else None,
                ),
            )
            if min_s is not None and max_s is not None:
                if not (min_s <= target <= max_s):
                    raise serializers.ValidationError(
                        {"target_score": "targetScoreOutOfRange"}
                    )

        return super().validate(attrs)

    def _validate_score_scale(self, attrs, confirm=False):
        scale_fields = {
            "score_scale_preset",
            "min_score",
            "max_score",
            "scores_definition",
        }
        instance = self.instance
        # Creation always resolves the scale, so the target is checked against
        # the range the audit will actually get.
        if instance and not scale_fields & attrs.keys():
            return
        framework = attrs.get("framework") or getattr(instance, "framework", None)
        baseline = None if instance else attrs.get("baseline")
        if (
            baseline
            and framework
            and baseline.framework_id == framework.id
            and not scale_fields & attrs.keys()
        ):
            # A copy of an audit keeps its scale by default.
            default = {
                "source": "baseline",
                "score_scale_preset": baseline.score_scale_preset,
                "min_score": baseline.min_score,
                "max_score": baseline.max_score,
                "scores_definition": copy.deepcopy(baseline.scores_definition),
            }
        elif framework:
            # No scale sent: the framework's. The organisation scale is only
            # ever proposed by the form, so non-form clients behave as before.
            default = {
                "source": "framework",
                "score_scale_preset": None,
                "min_score": framework.min_score,
                "max_score": framework.max_score,
                "scores_definition": framework.scores_definition,
            }
        else:
            default = None
        default_range = (
            (default["min_score"], default["max_score"]) if default else None
        )

        preset = attrs.get("score_scale_preset")
        min_s = attrs.get(
            "min_score", None if preset else getattr(instance, "min_score", None)
        )
        max_s = attrs.get(
            "max_score", None if preset else getattr(instance, "max_score", None)
        )
        try:
            preset, min_s, max_s = normalize_score_scale(
                preset, min_s, max_s, attrs.get("scores_definition"), default_range
            )
        except DjangoValidationError as e:
            raise serializers.ValidationError(e.message_dict)
        if preset:
            attrs["min_score"], attrs["max_score"] = min_s, max_s

        resolved = (min_s, max_s) if min_s is not None else default_range
        if min_s is None:
            if default and (
                attrs.get("scores_definition") or default["source"] == "baseline"
            ):
                attrs["min_score"], attrs["max_score"] = default_range
                attrs["score_scale_preset"] = default["score_scale_preset"]
                if not attrs.get("scores_definition"):
                    attrs["scores_definition"] = default["scores_definition"]
            else:
                attrs["score_scale_preset"] = None
                attrs["scores_definition"] = None
        elif (
            "score_scale_preset" not in attrs
            and instance
            and instance.score_scale_preset
        ):
            if SCORE_SCALE_PRESETS.get(instance.score_scale_preset) != resolved:
                attrs["score_scale_preset"] = None

        current = (
            (instance.min_score, instance.max_score) if instance else default_range
        )
        self._effective_score_range = resolved
        if resolved == current:
            return
        if (
            framework
            and framework.is_scale_bound
            and resolved != (framework.min_score, framework.max_score)
        ):
            raise serializers.ValidationError(
                {"score_scale_preset": "scoreScaleBoundToFramework"}
            )
        if instance and None not in (*current, *resolved):
            self._score_rescale = (current, resolved)
            impact = instance.rescale_impact()
            unchanged = attrs.get("target_score", instance.target_score) == (
                instance.target_score
            )
            if unchanged and instance.target_score is not None:
                attrs["target_score"] = rescale_score(
                    instance.target_score, current, resolved, integer=False
                )
                impact["target"] = [instance.target_score, attrs["target_score"]]
            if not confirm and any(impact.values()):
                raise ScoreRescaleConfirmationRequired(
                    {"from": list(current), "to": list(resolved), **impact}
                )

    def create(self, validated_data: Any):
        validated_data.pop("create_applied_controls_from_suggestions", None)
        authors_data = validated_data.get("authors", [])

        # Always merge the caller's partial field_visibility with code defaults
        # + framework template so the new CA is stored as a complete snapshot.
        from core.utils import build_initial_field_visibility

        defaults = build_initial_field_visibility(validated_data.get("framework"))
        provided = validated_data.get("field_visibility") or {}
        validated_data["field_visibility"] = {**defaults, **provided}

        assessment = super().create(validated_data)

        # Send notification to newly assigned authors
        if authors_data:
            self._send_assignment_notifications(
                assessment, [user.id for user in authors_data]
            )

        # Only apply default implementation groups if none were provided by the user
        if (
            assessment.framework.implementation_groups_definition
            and not assessment.selected_implementation_groups
        ):
            default_implementation_groups = []
            for ig in assessment.framework.implementation_groups_definition:
                if ig.get("default_selected", False):
                    default_implementation_groups += [ig["ref_id"]]
            assessment.selected_implementation_groups = default_implementation_groups
            assessment.save()

        return assessment

    def update(self, instance, validated_data):
        # Track old authors, folder, and perimeter before update
        old_author_ids = set(instance.authors.values_list("id", flat=True))
        old_folder_id = instance.folder_id

        # Auto-lock when status changes to deprecated
        old_status = instance.status
        new_status = validated_data.get("status", old_status)
        if old_status != "deprecated" and new_status == "deprecated":
            validated_data["is_locked"] = True

        # If perimeter is being changed, update folder to match the new perimeter's folder
        if "perimeter" in validated_data:
            new_perimeter = validated_data["perimeter"]
            if new_perimeter and new_perimeter.folder:
                validated_data["folder"] = new_perimeter.folder

        # PATCH semantics for field_visibility: merge incoming partial map onto
        # the existing one so a request that only sets a few keys doesn't wipe
        # the rest of the snapshot.
        if "field_visibility" in validated_data:
            existing = instance.field_visibility or {}
            provided = validated_data["field_visibility"] or {}
            validated_data["field_visibility"] = {**existing, **provided}

        old_scoring_enabled = instance.scoring_enabled

        with transaction.atomic():
            # Perform the main update (fields + M2M)
            updated_instance = super().update(instance, validated_data)

            if rescale := getattr(self, "_score_rescale", None):
                updated_instance.rescale_requirement_scores(*rescale)
                # save() snapshotted today's metrics before the scores moved.
                updated_instance.upsert_daily_metrics()

            # For dynamic frameworks, recompute IGs from current answers so the
            # answer-driven calc always wins over any manual override submitted
            # here. Manual (non-dynamic) IGs are preserved inside the helper.
            if updated_instance.framework and updated_instance.framework.is_dynamic():
                from core.utils import update_selected_implementation_groups

                update_selected_implementation_groups(updated_instance)

            # Cascade folder change to requirement assessments
            if old_folder_id != updated_instance.folder_id:
                RequirementAssessment.objects.filter(
                    compliance_assessment=updated_instance
                ).update(folder=updated_instance.folder)

            # Toggle is_scored on all requirement assessments when scoring
            # visibility flips. `is_scored` follows the toggle on EVERY RA so
            # get_global_score goes quiet when scoring is disabled; scores are
            # never touched on question-bearing RAs (they belong to
            # recompute_assessment: a committed score means "questionnaire
            # complete" for the progress cascade) and only pre-filled at the
            # resolved minimum on the others.
            if updated_instance.scoring_enabled != old_scoring_enabled:
                assessable_ras = RequirementAssessment.objects.filter(
                    compliance_assessment=updated_instance,
                    requirement__assessable=True,
                ).exclude(
                    result=RequirementAssessment.Result.NOT_APPLICABLE,
                )
                manual_ras = assessable_ras.exclude(
                    requirement__questions__isnull=False
                )
                if updated_instance.scoring_enabled:
                    # Turn on: set is_scored=True, initialize score to the RA's
                    # resolved minimum (Node override falling back to CA) only
                    # for RAs that don't already have a score. A RN that
                    # overrides min_score above the CA min must not be
                    # initialised below its own range. Question RAs re-enter
                    # the global score only where the recompute committed a
                    # score (complete questionnaires survive an off/on
                    # round-trip).
                    manual_ras.update(is_scored=True)
                    assessable_ras.filter(
                        requirement__questions__isnull=False, score__isnull=False
                    ).update(is_scored=True)
                    ca_min = updated_instance.min_score
                    framework_min = (
                        updated_instance.framework.min_score
                        if updated_instance.framework is not None
                        else None
                    )
                    for ra in manual_ras.filter(score__isnull=True).select_related(
                        "requirement"
                    ):
                        req_min = ra.requirement.min_score
                        if req_min is not None:
                            ra.score = req_min
                        elif ca_min is not None:
                            ra.score = ca_min
                        elif framework_min is not None:
                            ra.score = framework_min
                        else:
                            ra.score = 0
                        ra.save(update_fields=["score"])
                else:
                    # Turn off: only flip is_scored, preserve existing scores
                    assessable_ras.update(is_scored=False)

                # QuerySet.update() bypasses the RA save hooks that normally
                # refresh the audit's daily metrics, so schedule one refresh
                # after the bulk is_scored flip.
                transaction.on_commit(updated_instance.upsert_daily_metrics)

            # Determine newly assigned authors
            new_author_ids = set(updated_instance.authors.values_list("id", flat=True))
            newly_assigned_ids = new_author_ids - old_author_ids

            # Schedule notifications to run **after transaction commits**
            if newly_assigned_ids:
                transaction.on_commit(
                    lambda: self._send_assignment_notifications(
                        updated_instance, list(newly_assigned_ids)
                    )
                )

        return updated_instance

    def _send_assignment_notifications(self, assessment, author_ids):
        """Send assignment notifications to the specified authors"""
        if not author_ids:
            return

        try:
            from core.models import Actor
            from .tasks import send_compliance_assessment_assignment_notification

            assigned_actors = Actor.objects.filter(id__in=author_ids)
            assigned_emails = []
            for actor in assigned_actors:
                assigned_emails.extend(actor.get_emails())

            if assigned_emails:
                send_compliance_assessment_assignment_notification(
                    assessment.id, assigned_emails
                )
        except Exception as e:
            logger.error(
                f"Failed to send ComplianceAssessment assignment notification: {str(e)}"
            )

    class Meta:
        model = ComplianceAssessment
        fields = "__all__"


class ComplianceAssessmentImportExportSerializer(BaseModelSerializer):
    framework = serializers.SlugRelatedField(slug_field="urn", read_only=True)
    evidences = HashSlugRelatedField(slug_field="pk", many=True, read_only=True)

    folder = HashSlugRelatedField(slug_field="pk", read_only=True)
    perimeter = HashSlugRelatedField(slug_field="pk", read_only=True)

    def validate_score_scale_preset(self, value):
        if value and value not in SCORE_SCALE_PRESETS:
            raise serializers.ValidationError("scoreScaleErrorUnknownPreset")
        return value

    class Meta:
        model = ComplianceAssessment
        fields = [
            "ref_id",
            "name",
            "version",
            "description",
            "folder",
            "perimeter",
            "eta",
            "due_date",
            "status",
            "observation",
            "framework",
            "selected_implementation_groups",
            "computed_outcome",
            "min_score",
            "max_score",
            "scores_definition",
            "score_scale_preset",
            "score_calculation_method",
            "target_score",
            "anchor_na_to_target",
            "field_visibility",
            "evidences",
            "created_at",
            "updated_at",
        ]


class RequirementAssessmentReadListSerializer(serializers.ListSerializer):
    """Batch request-scoped IAM projections once for a page/list response."""

    def to_representation(self, data):
        instances = list(data.all() if hasattr(data, "all") else data)
        request = self.context.get("request")
        if request is not None:
            questionnaire_context = self.context.get(
                "_questionnaire_visibility_context"
            )
            if not isinstance(
                questionnaire_context, QuestionnaireVisibilityContext
            ) or not questionnaire_context.covers_requirement_assessments(
                request, instances
            ):
                self.context["_questionnaire_visibility_context"] = (
                    QuestionnaireVisibilityContext.build(
                        request=request,
                        requirement_assessments=instances,
                    )
                )

            from core.utils import get_mapping_inference_visibility_context

            inferences = [
                instance.mapping_inference
                for instance in instances
                if isinstance(instance.mapping_inference, dict)
                and instance.mapping_inference
            ]
            if inferences:
                self.context["_mapping_inference_visibility"] = (
                    get_mapping_inference_visibility_context(request.user, inferences)
                )
        return super().to_representation(instances)


class RequirementAssessmentReadSerializer(BaseModelSerializer):
    class FilteredNodeSerializer(RequirementNodeReadSerializer):
        class Meta:
            model = RequirementNode
            fields = [
                "id",
                "urn",
                "parent_urn",
                "annotation",
                "name",
                "description",
                "typical_evidence",
                "ref_id",
                "associated_reference_controls",
                "associated_threats",
                "parent_requirement",
                "questions",
                "implementation_groups",
                "display_mode",
                "min_score",
                "max_score",
                "scores_definition_ref",
                "weight",
            ]

    name = serializers.CharField(source="__str__")
    description = serializers.CharField(source="get_requirement_description")
    evidences = FieldsRelatedField(many=True)
    # The respondent view lists these as a table, so it needs the promised date and
    # where the commitment stands, not just a name.
    task_templates = FieldsRelatedField(
        ["id", "task_date", "status", "commitment_state", "committed_eta"], many=True
    )
    compliance_assessment = FieldsRelatedField(
        [
            "id",
            "name",
            "is_locked",
            "min_score",
            "max_score",
            "scores_definition",
            "score_calculation_method",
            "progress_status_enabled",
            "extended_result_enabled",
            "field_visibility",
            {"framework": ["implementation_groups_definition", "field_visibility"]},
        ]
    )
    folder = FieldsRelatedField()
    perimeter = FieldsRelatedField(source="compliance_assessment.perimeter")
    assessable = serializers.BooleanField(source="requirement.assessable")
    requirement = FilteredNodeSerializer()
    security_exceptions = FieldsRelatedField(many=True)
    is_locked = serializers.BooleanField()
    applied_controls = FieldsRelatedField(many=True)
    # Reverse FK from Finding: DRF does not pick it up from Meta.
    findings = FieldsRelatedField(many=True)
    answers = serializers.SerializerMethodField()

    # Effective scale after the Node -> CA cascade. Null when the CA has
    # scoring disabled (no scale to expose).
    effective_min_score = serializers.SerializerMethodField()
    effective_max_score = serializers.SerializerMethodField()
    effective_scores_definition = serializers.SerializerMethodField()

    def _resolved(self, obj):
        if not obj.compliance_assessment.scoring_enabled:
            return None
        return obj.get_resolved_scoring()

    def get_effective_min_score(self, obj):
        r = self._resolved(obj)
        return r["min_score"] if r else None

    def get_effective_max_score(self, obj):
        r = self._resolved(obj)
        return r["max_score"] if r else None

    def get_effective_scores_definition(self, obj):
        r = self._resolved(obj)
        return r["scores_definition"] if r else None

    def _ensure_questionnaire_visibility_context(self, obj):
        request = self.context.get("request")
        if request is None:
            return None
        questionnaire_context = self.context.get("_questionnaire_visibility_context")
        if not isinstance(
            questionnaire_context, QuestionnaireVisibilityContext
        ) or not questionnaire_context.covers_requirement_assessments(request, (obj,)):
            questionnaire_context = QuestionnaireVisibilityContext.build(
                request=request,
                requirement_assessments=(obj,),
                requirement_nodes=(obj.requirement,),
            )
            self.context["_questionnaire_visibility_context"] = questionnaire_context
        return questionnaire_context

    def get_answers(self, obj):
        """Reconstruct old JSON format {question_urn: answer_value} from Answer model."""
        request = self.context.get("request")
        if request is None:
            return {}
        questionnaire_context = self._ensure_questionnaire_visibility_context(obj)
        return questionnaire_context.answer_values_for(request, obj)

    def to_representation(self, instance):
        # Build before nested fields are rendered so requirement questions,
        # answers and progress consumers all share the exact same projection.
        self._ensure_questionnaire_visibility_context(instance)
        data = super().to_representation(instance)

        ca = getattr(instance, "compliance_assessment", None)
        if ca is None:
            return data

        viewer_role = self.context.get("viewer_role")
        if viewer_role is None:
            full_view_ids = self.context.get("full_view_compliance_assessment_ids")
            if full_view_ids is not None:
                viewer_role = "auditor" if ca.id in full_view_ids else "respondent"
            elif request := self.context.get("request"):
                from core.utils import has_full_view_compliance_assessment

                viewer_role = (
                    "auditor"
                    if has_full_view_compliance_assessment(request.user, ca)
                    else "respondent"
                )
            else:
                # Serializer use without an authenticated request must not
                # silently gain the authority-bearing auditor projection.
                viewer_role = "respondent"

        # Strip fields the viewer is not allowed to read. Resolve through the
        # cascade (CA overrides → DEFAULT_VISIBILITY → EVERYONE_EDIT) so that
        # default-hidden keys like `score` are stripped even when the CA has
        # an empty/incomplete field_visibility map. Structural fields (id,
        # name, etc.) resolve to EVERYONE_EDIT and are never stripped.
        from core.utils import is_field_visible_to

        request = self.context.get("request")
        # Effective score fields are aliases of the authority-bearing score
        # field on API responses. Preserve the established trusted in-process
        # contract (no request), where callers receive these keys with ``None``
        # when scoring is disabled.
        visibility_aliases = (
            {
                "effective_min_score": "score",
                "effective_max_score": "score",
                "effective_scores_definition": "score",
            }
            if request is not None
            else {}
        )
        for field_name in list(data.keys()):
            policy_field = visibility_aliases.get(field_name, field_name)
            if not is_field_visible_to(ca, policy_field, viewer_role):
                data.pop(field_name, None)

        if not is_field_visible_to(ca, "score", viewer_role):
            requirement_data = data.get("requirement")
            if isinstance(requirement_data, dict):
                for field_name in (
                    "min_score",
                    "max_score",
                    "scores_definition_ref",
                    "weight",
                ):
                    requirement_data.pop(field_name, None)
            assessment_data = data.get("compliance_assessment")
            if isinstance(assessment_data, dict):
                for field_name in (
                    "min_score",
                    "max_score",
                    "scores_definition",
                    "score_calculation_method",
                ):
                    assessment_data.pop(field_name, None)

        if "mapping_inference" in data:
            from core.utils import (
                get_mapping_inference_visibility_context,
                sanitize_mapping_inference_for_viewer,
            )

            mapping_inference = instance.mapping_inference
            mapping_visibility = None
            if (
                request is not None
                and viewer_role == "auditor"
                and isinstance(mapping_inference, dict)
                and mapping_inference
            ):
                mapping_visibility = self.context.get("_mapping_inference_visibility")
                if mapping_visibility is None:
                    mapping_visibility = get_mapping_inference_visibility_context(
                        request.user, [mapping_inference]
                    )
            sanitized_mapping = sanitize_mapping_inference_for_viewer(
                mapping_inference,
                ca,
                viewer_role=viewer_role,
                visibility_context=mapping_visibility,
                target_result=instance.result,
            )
            if sanitized_mapping is None:
                data.pop("mapping_inference", None)
            else:
                data["mapping_inference"] = sanitized_mapping

        if request is not None:
            visible_cache = self.context.setdefault(
                "_visible_requirement_related_ids", {}
            )

            def _related_uuid(value):
                raw_id = value.get("id") if isinstance(value, dict) else value
                try:
                    return UUID(str(raw_id))
                except TypeError, ValueError:
                    return None

            # A view grant on the RequirementAssessment is not transitive to
            # the library node, framework, or perimeter carried by its nested
            # projection.  Mask each relation independently; when the node is
            # hidden, also remove top-level aliases and scales derived from it
            # instead of emitting a plausible partial requirement.
            for model in (RequirementNode, Framework, Perimeter, Folder):
                if model not in visible_cache:
                    visible_cache[model] = set(
                        RoleAssignment.get_viewable_object_ids(request.user, model)
                    )

            if instance.requirement_id not in visible_cache[RequirementNode]:
                data["requirement"] = None
                for field_name in (
                    "name",
                    "description",
                    "assessable",
                    "effective_min_score",
                    "effective_max_score",
                    "effective_scores_definition",
                ):
                    data.pop(field_name, None)

            perimeter_data = data.get("perimeter")
            if (
                perimeter_data is not None
                and _related_uuid(perimeter_data) not in visible_cache[Perimeter]
            ):
                data["perimeter"] = None

            folder_data = data.get("folder")
            if (
                folder_data is not None
                and _related_uuid(folder_data) not in visible_cache[Folder]
            ):
                data["folder"] = None

            assessment_data = data.get("compliance_assessment")
            if isinstance(assessment_data, dict):
                framework_data = assessment_data.get("framework")
                if (
                    framework_data is not None
                    and ca.framework_id not in visible_cache[Framework]
                ):
                    assessment_data["framework"] = None

            for field_name, model in (
                ("applied_controls", AppliedControl),
                ("evidences", Evidence),
                ("security_exceptions", SecurityException),
                ("task_templates", TaskTemplate),
            ):
                values = data.get(field_name)
                if not isinstance(values, list):
                    continue
                if model not in visible_cache:
                    visible_cache[model] = set(
                        RoleAssignment.get_viewable_object_ids(request.user, model)
                    )
                visible_ids = visible_cache[model]
                data[field_name] = [
                    value for value in values if _related_uuid(value) in visible_ids
                ]

            requirement_data = data.get("requirement")
            if isinstance(requirement_data, dict):
                for field_name, model in (
                    ("associated_reference_controls", ReferenceControl),
                    ("associated_threats", Threat),
                ):
                    values = requirement_data.get(field_name)
                    if not isinstance(values, list):
                        continue
                    if model not in visible_cache:
                        visible_cache[model] = set(
                            RoleAssignment.get_viewable_object_ids(request.user, model)
                        )
                    visible_ids = visible_cache[model]
                    requirement_data[field_name] = [
                        value
                        for value in values
                        if isinstance(value, dict)
                        and _related_uuid(value) in visible_ids
                    ]
        else:
            # A serializer invocation without an authenticated request has no
            # generic Folder-IAM proof.  Do not let an explicit viewer-role
            # hint turn the relation into an authority bypass.
            data["folder"] = None

        return data

    class Meta:
        model = RequirementAssessment
        fields = "__all__"
        list_serializer_class = RequirementAssessmentReadListSerializer


def _apply_visible_answer_choice_update(
    answer: Answer,
    desired_choices,
    visible_choice_ids,
    *,
    fail_on_hidden: bool,
) -> None:
    """Replace only the caller-visible portion of an Answer's choices.

    A questionnaire response is projected through QuestionChoice folder IAM, so
    its submitted choices are only a partial view of the persisted relation.
    Applying that partial view with ``set``/``clear`` would silently delete
    hidden selections. Multiple-choice answers therefore use a visible delta;
    unique-choice answers fail closed when any existing selection is hidden,
    because preserving it while accepting another value would violate the
    question's single-choice invariant.
    """
    desired_choices = list(desired_choices)
    desired_ids = {choice.id for choice in desired_choices}

    if (
        fail_on_hidden
        and answer.selected_choices.exclude(id__in=visible_choice_ids).exists()
    ):
        raise PermissionDenied(
            "Existing answer choices are unavailable for this caller."
        )

    if any(choice.question_id != answer.question_id for choice in desired_choices):
        raise serializers.ValidationError(
            {"selected_choices": "A selected choice does not belong to this question."}
        )

    visible_desired_ids = set(
        QuestionChoice.objects.filter(id__in=desired_ids)
        .filter(id__in=visible_choice_ids)
        .values_list("id", flat=True)
    )
    if visible_desired_ids != desired_ids:
        raise PermissionDenied(
            "One or more selected choices are unavailable for this caller."
        )

    current_visible_choices = {
        choice.id: choice
        for choice in answer.selected_choices.filter(id__in=visible_choice_ids)
    }
    desired_by_id = {choice.id: choice for choice in desired_choices}
    remove_choices = [
        choice
        for choice_id, choice in current_visible_choices.items()
        if choice_id not in desired_ids
    ]
    add_choices = [
        choice
        for choice_id, choice in desired_by_id.items()
        if choice_id not in current_visible_choices
    ]
    if remove_choices:
        answer.selected_choices.remove(*remove_choices)
    if add_choices:
        answer.selected_choices.add(*add_choices)


_IMMUTABLE_RELATION_UNAVAILABLE = "The requested relationship is unavailable."
_ANSWER_RELATION_UNAVAILABLE = "One or more answer relationships are unavailable."
_ASSIGNMENT_PARENT_UNAVAILABLE = "The requested assignment parent is unavailable."
_ASSIGNMENT_RELATION_UNAVAILABLE = (
    "One or more assignment relationships are unavailable."
)


def _normalize_related_uuid(value, *, detail: str) -> UUID:
    """Normalize an untrusted relation PK without exposing lookup results."""

    try:
        return UUID(str(value))
    except (TypeError, ValueError, AttributeError) as exc:
        raise PermissionDenied(detail) from exc


def _assert_raw_immutable_relation_ids(instance, data, field_names) -> None:
    """Reject immutable FK changes before DRF performs a related-object query."""

    if instance is None:
        return
    for field_name in field_names:
        if field_name not in data:
            continue
        submitted_id = _normalize_related_uuid(
            data.get(field_name), detail=_IMMUTABLE_RELATION_UNAVAILABLE
        )
        if submitted_id != getattr(instance, f"{field_name}_id", None):
            raise PermissionDenied(_IMMUTABLE_RELATION_UNAVAILABLE)


class ImmutableUpdatePrimaryKeyRelatedField(serializers.PrimaryKeyRelatedField):
    """Resolve an unchanged update FK from the instance, never from client PK."""

    def to_internal_value(self, data):
        instance = getattr(self.root, "instance", None)
        if instance is None:
            return super().to_internal_value(data)
        submitted_id = _normalize_related_uuid(
            data, detail=_IMMUTABLE_RELATION_UNAVAILABLE
        )
        current_id = getattr(instance, f"{self.field_name}_id", None)
        if submitted_id != current_id:
            raise PermissionDenied(_IMMUTABLE_RELATION_UNAVAILABLE)
        return getattr(instance, self.field_name)


class RequirementAssignmentComplianceAssessmentField(
    ImmutableUpdatePrimaryKeyRelatedField
):
    """Resolve a new Assignment parent only inside the caller's CA IAM slice."""

    @staticmethod
    def _add_permission():
        return Permission.objects.get(
            codename="add_requirementassignment",
            content_type__app_label="core",
            content_type__model="requirementassignment",
        )

    def to_internal_value(self, data):
        instance = getattr(self.root, "instance", None)
        if instance is not None:
            return super().to_internal_value(data)

        request = self.context.get("request")
        user = getattr(request, "user", None)
        if not getattr(user, "is_authenticated", False):
            raise PermissionDenied(_ASSIGNMENT_PARENT_UNAVAILABLE)
        assessment_id = _normalize_related_uuid(
            data, detail=_ASSIGNMENT_PARENT_UNAVAILABLE
        )
        try:
            assessment = (
                ComplianceAssessment.objects.select_related("folder")
                .filter(
                    id=assessment_id,
                    id__in=RoleAssignment.get_viewable_object_ids(
                        user, ComplianceAssessment
                    ),
                )
                .first()
            )
            can_add = assessment is not None and RoleAssignment.is_access_allowed(
                user=user,
                perm=self._add_permission(),
                folder=assessment.folder,
            )
        except NotImplementedError, Permission.DoesNotExist:
            can_add = False
        if not can_add:
            raise PermissionDenied(_ASSIGNMENT_PARENT_UNAVAILABLE)
        return assessment


class RequirementAssignmentAuthorityPrimaryKeyRelatedField(
    serializers.PrimaryKeyRelatedField
):
    """Resolve Assignment M2M operands without exposing hidden object UUIDs."""

    def __init__(self, *args, authority_model, **kwargs):
        self.authority_model = authority_model
        super().__init__(*args, **kwargs)

    @staticmethod
    def visible_queryset(*, user, authority_model, object_ids):
        """Mirror the public Actor/RA product projections for assignment writes."""

        bounded_ids = tuple(object_ids)
        if not bounded_ids:
            return authority_model.objects.none()
        if authority_model is Actor:
            from global_settings.models import GlobalSettings

            queryset = (
                Actor.objects.filter(id__in=bounded_ids)
                .filter(id__in=RoleAssignment.get_viewable_object_ids(user, Actor))
                # Machine principals are never valid owner/assignee picker
                # values, even when their underlying User is folder-visible.
                .exclude(user__service_account__isnull=False)
            )
            allow_entities = (
                GlobalSettings.objects.filter(name=GlobalSettings.Names.GENERAL)
                .values_list("value__allow_assignments_to_entities", flat=True)
                .first()
            )
            if not allow_entities:
                queryset = queryset.filter(entity__isnull=True)
            return queryset
        if authority_model is RequirementAssessment:
            from core.utils import get_full_view_compliance_assessment_ids

            visible_framework_ids = RoleAssignment.get_viewable_object_ids(
                user, Framework
            )
            product_visible = models.Q(
                compliance_assessment_id__in=get_full_view_compliance_assessment_ids(
                    user
                )
            ) | models.Q(assignments__actor__in=Actor.get_all_for_user(user))
            return (
                RequirementAssessment.objects.filter(id__in=bounded_ids)
                .filter(
                    id__in=RoleAssignment.get_viewable_object_ids(
                        user, RequirementAssessment
                    ),
                    compliance_assessment_id__in=RoleAssignment.get_viewable_object_ids(
                        user, ComplianceAssessment
                    ),
                    compliance_assessment__framework_id__in=visible_framework_ids,
                    requirement_id__in=RoleAssignment.get_viewable_object_ids(
                        user, RequirementNode
                    ),
                    requirement__framework_id__in=visible_framework_ids,
                    requirement__framework_id=F("compliance_assessment__framework_id"),
                )
                .filter(product_visible)
                .distinct()
            )
        return authority_model.objects.none()

    def to_internal_value(self, data):
        request = self.context.get("request")
        user = getattr(request, "user", None)
        if not getattr(user, "is_authenticated", False):
            raise PermissionDenied(_ASSIGNMENT_RELATION_UNAVAILABLE)
        object_id = _normalize_related_uuid(
            data, detail=_ASSIGNMENT_RELATION_UNAVAILABLE
        )
        try:
            row = self.visible_queryset(
                user=user,
                authority_model=self.authority_model,
                object_ids=(object_id,),
            ).first()
        except NotImplementedError, Permission.DoesNotExist:
            row = None
        if row is None:
            raise PermissionDenied(_ASSIGNMENT_RELATION_UNAVAILABLE)
        return row


class AnswerAuthorityPrimaryKeyRelatedField(serializers.PrimaryKeyRelatedField):
    """Resolve Answer relations only inside the caller's complete IAM slice."""

    def __init__(self, *args, authority_model, immutable_on_update=False, **kwargs):
        self.authority_model = authority_model
        self.immutable_on_update = immutable_on_update
        super().__init__(*args, **kwargs)

    def _quick_form_response(self):
        """Return the quick-form parent named by this Answer write, if any."""

        instance = getattr(self.root, "instance", None)
        if instance is not None and getattr(instance, "response_id", None):
            return instance.response
        initial_data = getattr(self.root, "initial_data", None) or {}
        raw_response_id = initial_data.get("response")
        if not raw_response_id:
            return None
        try:
            response_id = UUID(str(raw_response_id))
        except TypeError, ValueError, AttributeError:
            return None
        return QuickFormResponse.objects.filter(id=response_id).first()

    def _visible_queryset(self, user, object_id):
        response = self._quick_form_response()
        if response is not None:
            if self.authority_model is Question:
                return Question.objects.filter(
                    id=object_id,
                    page__quick_form_id=response.quick_form_id,
                )
            if self.authority_model is QuestionChoice:
                return QuestionChoice.objects.filter(
                    id=object_id,
                    question__page__quick_form_id=response.quick_form_id,
                )

        visible_framework_ids = RoleAssignment.get_viewable_object_ids(user, Framework)
        visible_requirement_node_ids = RoleAssignment.get_viewable_object_ids(
            user, RequirementNode
        )
        visible_question_ids = RoleAssignment.get_viewable_object_ids(user, Question)

        if self.authority_model is RequirementAssessment:
            # Generic folder IAM is only the first visibility gate.  A
            # respondent can read an individual requirement assessment only
            # when they have full-audit visibility or it is linked to one of
            # their direct/team actors (the same product boundary enforced by
            # RequirementAssessmentViewSet).  Resolve the submitted UUID
            # inside that complete slice so an unassigned row cannot become an
            # existence oracle before Answer validation reaches its direct-
            # actor write checks.
            from core.utils import get_full_view_compliance_assessment_ids

            product_visible = models.Q(
                compliance_assessment_id__in=get_full_view_compliance_assessment_ids(
                    user
                )
            ) | models.Q(assignments__actor__in=Actor.get_all_for_user(user))
            return (
                RequirementAssessment.objects.filter(
                    id=object_id,
                    id__in=RoleAssignment.get_viewable_object_ids(
                        user, RequirementAssessment
                    ),
                    compliance_assessment_id__in=RoleAssignment.get_viewable_object_ids(
                        user, ComplianceAssessment
                    ),
                    compliance_assessment__framework_id__in=visible_framework_ids,
                    requirement_id__in=visible_requirement_node_ids,
                    requirement__framework_id__in=visible_framework_ids,
                    requirement__framework_id=F("compliance_assessment__framework_id"),
                )
                .filter(product_visible)
                .distinct()
            )
        if self.authority_model is Question:
            return Question.objects.filter(
                id=object_id,
                id__in=visible_question_ids,
                requirement_node_id__in=visible_requirement_node_ids,
                requirement_node__framework_id__in=visible_framework_ids,
            )
        if self.authority_model is QuestionChoice:
            return QuestionChoice.objects.filter(
                id=object_id,
                id__in=RoleAssignment.get_viewable_object_ids(user, QuestionChoice),
                question_id__in=visible_question_ids,
                question__requirement_node_id__in=visible_requirement_node_ids,
                question__requirement_node__framework_id__in=visible_framework_ids,
            )
        raise PermissionDenied(_ANSWER_RELATION_UNAVAILABLE)

    def to_internal_value(self, data):
        instance = getattr(self.root, "instance", None)
        if instance is not None and self.immutable_on_update:
            submitted_id = _normalize_related_uuid(
                data, detail=_ANSWER_RELATION_UNAVAILABLE
            )
            current_id = getattr(instance, f"{self.field_name}_id", None)
            if submitted_id != current_id:
                raise PermissionDenied(_ANSWER_RELATION_UNAVAILABLE)
            return getattr(instance, self.field_name)

        request = self.context.get("request")
        user = getattr(request, "user", None)
        if not getattr(user, "is_authenticated", False):
            raise PermissionDenied(_ANSWER_RELATION_UNAVAILABLE)
        object_id = _normalize_related_uuid(data, detail=_ANSWER_RELATION_UNAVAILABLE)
        try:
            related = self._visible_queryset(user, object_id).first()
        except (NotImplementedError, Permission.DoesNotExist) as exc:
            raise PermissionDenied(_ANSWER_RELATION_UNAVAILABLE) from exc
        if related is None:
            raise PermissionDenied(_ANSWER_RELATION_UNAVAILABLE)
        return related


class RequirementAssessmentWriteSerializer(BaseModelSerializer):
    compliance_assessment = ImmutableUpdatePrimaryKeyRelatedField(
        queryset=ComplianceAssessment.objects.all()
    )
    folder = ImmutableUpdatePrimaryKeyRelatedField(queryset=Folder.objects.all())
    requirement = serializers.PrimaryKeyRelatedField(read_only=True)
    answers = serializers.JSONField(required=False, write_only=True)
    # Mapping provenance is generated by the controlled mapping service. It is
    # never client-authored or mutable through the public RA endpoint.
    mapping_inference = serializers.JSONField(read_only=True)
    task_templates = serializers.PrimaryKeyRelatedField(
        many=True, required=False, queryset=TaskTemplate.objects.all()
    )
    # Reverse FK from Finding: binding an existing finding to this requirement
    # assessment is done from the assessment's side, like the other pickers.
    findings = serializers.PrimaryKeyRelatedField(
        many=True, required=False, queryset=Finding.objects.all()
    )

    def to_representation(self, instance):
        """Return the same permission-filtered projection as the read API.

        DRF serializes the saved instance with the write serializer after a
        successful mutation. Reusing the read projection prevents that 200
        response from echoing auditor-only fields or raw mapping provenance
        back to a respondent.
        """
        return RequirementAssessmentReadSerializer(
            instance,
            context=self.context,
        ).data

    def to_internal_value(self, data):
        # This must precede field-visibility filtering: silently stripping a
        # hidden immutable parent field would otherwise turn its UUID into an
        # existence/field-policy oracle and make a reparenting attempt appear
        # successful.
        _assert_raw_immutable_relation_ids(
            self.instance, data, ("compliance_assessment", "folder")
        )
        # Strip fields the respondent isn't allowed to write before DRF validates
        # individual field choices — a placeholder value in a disabled select
        # would otherwise trip choice validation. Security enforcement is repeated
        # in validate() since to_internal_value runs before object-level checks.
        request = self.context.get("request")
        if request and self.instance:
            from core.utils import (
                has_full_view_compliance_assessment,
                is_field_editable_by,
            )

            ca = self.instance.compliance_assessment
            viewer_role = (
                "auditor"
                if has_full_view_compliance_assessment(request.user, ca)
                else "respondent"
            )
            # Cascade through DEFAULT_VISIBILITY for both roles. Full-view is
            # read authority, not permission to write fields configured as
            # auditor read-only or hidden.
            data = {
                k: v
                for k, v in data.items()
                if is_field_editable_by(ca, k, viewer_role)
            }

        # A relation the submitting role cannot see must not be writable by it: the
        # form round-trips every field, so a hidden tab would post an empty list.
        if request and self.instance and "task_templates" in data:
            from core.utils import (
                get_respondent_scoped_folder_ids,
                is_field_editable_by,
            )

            ca = self.instance.compliance_assessment
            respondent_folders = get_respondent_scoped_folder_ids(request.user)
            role = (
                "respondent"
                if respondent_folders and ca.folder_id in respondent_folders
                else "auditor"
            )
            if not is_field_editable_by(ca, "task_templates", role):
                data = {k: v for k, v in data.items() if k != "task_templates"}

        # The reviewer's, unconditionally: not routed through field_visibility so it
        # cannot be configured open.
        if request and self.instance and "review_state" in data:
            from core.utils import get_respondent_scoped_folder_ids

            ca = self.instance.compliance_assessment
            respondent_folders = get_respondent_scoped_folder_ids(request.user)
            if respondent_folders and ca.folder_id in respondent_folders:
                data = {k: v for k, v in data.items() if k != "review_state"}

        # On update, treat an empty required-choice value as "unchanged" instead
        # of failing validation. The respondent view (`requirements_list`) strips
        # auditor-only fields like `status` from the read, so the Select-evidence /
        # Select-applied-controls modals — which resubmit the *whole* RA form —
        # send those fields back as "".
        if self.instance is not None:
            data = {
                k: v
                for k, v in data.items()
                if not (
                    v == ""
                    and isinstance(self.fields.get(k), serializers.ChoiceField)
                    and not getattr(self.fields[k], "allow_blank", False)
                )
            }
        return super().to_internal_value(data)

    def validate_answers(self, value):
        if value is not None and not isinstance(value, dict):
            raise serializers.ValidationError(
                "Answers must be a JSON object mapping question URNs to values."
            )
        return value

    def validate_compliance_assessment(self, value):
        self._ensure_immutable("compliance_assessment", value)
        return value

    def validate_folder(self, value):
        self._ensure_immutable("folder", value)
        return value

    def _check_m2m_visibility(self, validated_data: dict) -> None:
        """Defer update-only controlled relations to their bounded delta check.

        The base checker materializes every globally visible related-object ID.
        These fields have a stricter update-time check below that considers only
        current and submitted IDs, so running both is redundant and scales with
        the institution rather than this requirement assessment.
        """
        if self.instance is None:
            return super()._check_m2m_visibility(validated_data)
        controlled_fields = {
            "applied_controls",
            "evidences",
            "security_exceptions",
            "task_templates",
        }
        return super()._check_m2m_visibility(
            {
                field_name: value
                for field_name, value in validated_data.items()
                if field_name not in controlled_fields
            }
        )

    def validate(self, attrs):
        compliance_assessment = self.get_compliance_assessment()

        if compliance_assessment and compliance_assessment.is_locked:
            raise serializers.ValidationError(
                "⚠️ Cannot modify the requirement when the audit is locked."
            )

        if (
            compliance_assessment
            and compliance_assessment.status == Assessment.Status.IN_REVIEW
        ):
            raise serializers.ValidationError(
                "⚠️ Cannot modify the requirement when the audit is in review."
            )

        # Assignment-level and field-level guards for respondent users (auditee or third-party)
        request = self.context.get("request")
        if request and self.instance and compliance_assessment:
            from core.utils import (
                has_full_view_compliance_assessment,
                is_field_editable_by,
            )

            is_full_viewer = has_full_view_compliance_assessment(
                request.user, compliance_assessment
            )
            viewer_role = "auditor" if is_full_viewer else "respondent"
            for name in list(attrs.keys()):
                if not is_field_editable_by(compliance_assessment, name, viewer_role):
                    attrs.pop(name)

            if not is_full_viewer:
                locked_assignment = self.instance.assignments.filter(
                    status__in=["submitted", "closed"]
                ).first()
                if locked_assignment:
                    raise serializers.ValidationError(
                        "Cannot modify: this requirement's assignment has been submitted or closed."
                    )

        # Validate extended_result against result
        if "extended_result" in attrs:
            extended_result = attrs["extended_result"]
        elif self.instance:
            extended_result = self.instance.extended_result
        else:
            extended_result = None

        result = attrs.get("result")
        if result is None and self.instance:
            result = self.instance.result

        if compliance_assessment.extended_result_enabled and extended_result:
            nonconformity_values = [
                RequirementAssessment.ExtendedResult.MAJOR_NONCONFORMITY,
                RequirementAssessment.ExtendedResult.MINOR_NONCONFORMITY,
            ]
            applicable_results_for_nonconformity = [
                RequirementAssessment.Result.NON_COMPLIANT,
                RequirementAssessment.Result.PARTIALLY_COMPLIANT,
            ]

            if extended_result in nonconformity_values:
                if result not in applicable_results_for_nonconformity:
                    raise serializers.ValidationError(
                        {
                            "extended_result": "Major and minor nonconformities are only applicable when result is non-compliant or partially compliant."
                        }
                    )

            if extended_result == RequirementAssessment.ExtendedResult.GOOD_PRACTICE:
                if result != RequirementAssessment.Result.COMPLIANT:
                    raise serializers.ValidationError(
                        {
                            "extended_result": "Good practice is only applicable when result is compliant."
                        }
                    )

        return super().validate(attrs)

    def _validate_against_resolved(self, value):
        """Reject scores that fall outside the RA's resolved scale.

        Rejection (rather than silent clamping) keeps client bugs visible and
        matches the update_requirement endpoint's behavior. Reject on missing
        instance or unresolved bounds so out-of-range values never reach the DB.
        """
        if value is None:
            return value
        if not self.instance:
            raise serializers.ValidationError(
                "Cannot validate score before the requirement assessment is created."
            )
        resolved = self.instance.get_resolved_scoring()
        lo, hi = resolved["min_score"], resolved["max_score"]
        if lo is None or hi is None:
            raise serializers.ValidationError(
                "Scoring is not configured for this audit."
            )
        if value < lo or value > hi:
            raise serializers.ValidationError(f"Score must be between {lo} and {hi}.")
        return value

    def validate_score(self, value):
        return self._validate_against_resolved(value)

    def validate_documentation_score(self, value):
        return self._validate_against_resolved(value)

    def get_compliance_assessment(self):
        if hasattr(self, "instance") and self.instance:
            return self.instance.compliance_assessment
        try:
            compliance_assessment_id = self.context.get("request", {}).data.get(
                "compliance_assessment", {}
            )
            compliance_assessment = ComplianceAssessment.objects.get(
                id=compliance_assessment_id
            )
            return compliance_assessment
        except ComplianceAssessment.DoesNotExist:
            raise serializers.ValidationError(
                "The specified Compliance Assessment does not exist."
            )

    def _pop_visible_relationship_updates(self, instance, validated_data):
        """Extract caller-visible M2M deltas without rewriting hidden rows.

        RequirementAssessment reads independently filter related objects by
        folder IAM. A client can therefore only send back the visible subset;
        applying that subset with ``RelatedManager.set`` would silently unlink
        hidden objects. Reconstructing a full set would also resurrect a hidden
        link removed concurrently by an authorised actor. Return only the
        caller-visible desired IDs and visibility boundary so ``update`` can
        add/remove a bounded delta after scalar fields are saved.
        """
        controlled_fields = {
            "applied_controls",
            "evidences",
            "security_exceptions",
            "task_templates",
        }.intersection(validated_data)
        if not controlled_fields:
            return {}
        request = self.context.get("request")
        if not request or not request.user.is_authenticated:
            raise PermissionDenied(
                "Relationship updates require an authenticated authority context."
            )

        updates = {}
        for field_name in controlled_fields:
            manager = getattr(instance, field_name)
            submitted = list(validated_data[field_name])
            submitted_ids = {related.id for related in submitted}
            current_ids = set(manager.values_list("id", flat=True))
            candidate_ids = current_ids | submitted_ids
            try:
                viewable_ids = RoleAssignment.get_viewable_object_ids(
                    request.user, manager.model
                )
                visible_ids = set(
                    manager.model.objects.filter(id__in=candidate_ids)
                    .filter(id__in=viewable_ids)
                    .values_list("id", flat=True)
                )
            except (NotImplementedError, Permission.DoesNotExist) as exc:
                raise PermissionDenied(
                    "Relationship visibility could not be verified."
                ) from exc

            if not submitted_ids.issubset(visible_ids):
                raise PermissionDenied("Relationship visibility could not be verified.")
            validated_data.pop(field_name)
            updates[field_name] = (visible_ids, submitted_ids)
        return updates

    @staticmethod
    def _apply_visible_relationship_updates(instance, relationship_updates):
        for field_name, (visible_ids, submitted_ids) in relationship_updates.items():
            manager = getattr(instance, field_name)
            current_visible_ids = set(
                manager.filter(id__in=visible_ids).values_list("id", flat=True)
            )
            remove_ids = current_visible_ids - submitted_ids
            add_ids = submitted_ids - current_visible_ids
            if remove_ids:
                manager.remove(*remove_ids)
            if add_ids:
                manager.add(*add_ids)

    def _prepare_locked_answer_updates(self, instance, answers_data):
        """Lock and authorize the complete legacy questionnaire mutation batch.

        The legacy RequirementAssessment endpoint remains a compatibility input
        surface, but it must not be a second authority implementation.  Resolve
        legacy URN values first, then enter the same Answer aggregate boundary as
        the direct Answer endpoint in stable Question order.  No RA or Answer is
        written until every requested child has been locked and authorized.
        """
        request = self.context.get("request")
        if request is None or not getattr(request.user, "is_authenticated", False):
            raise PermissionDenied(
                "Questionnaire updates require an authenticated request."
            )

        user = request.user
        visible_question_ids = RoleAssignment.get_viewable_object_ids(user, Question)
        visible_requirement_node_ids = RoleAssignment.get_viewable_object_ids(
            user, RequirementNode
        )
        visible_framework_ids = RoleAssignment.get_viewable_object_ids(user, Framework)
        visible_choice_ids = RoleAssignment.get_viewable_object_ids(
            user, QuestionChoice
        )
        questions_by_urn = {
            question.urn: question
            for question in Question.objects.filter(
                requirement_node_id=instance.requirement_id,
                requirement_node_id__in=visible_requirement_node_ids,
                requirement_node__framework_id=instance.compliance_assessment.framework_id,
                requirement_node__framework_id__in=visible_framework_ids,
                id__in=visible_question_ids,
                urn__in=answers_data,
            ).order_by("pk")
        }
        unknown_questions = set(answers_data) - set(questions_by_urn)
        if unknown_questions:
            raise serializers.ValidationError(
                {"answers": ("One or more questions are unavailable for this caller.")}
            )

        existing_answer_ids = dict(
            Answer.objects.filter(
                requirement_assessment_id=instance.id,
                question_id__in=[question.id for question in questions_by_urn.values()],
            ).values_list("question_id", "id")
        )
        authority = AnswerWriteSerializer(context=self.context)
        requested_updates = []
        for question in sorted(questions_by_urn.values(), key=lambda row: str(row.id)):
            answer_value = answers_data[question.urn]
            desired_choices = None
            stored_value = answer_value

            if question.type == Question.Type.UNIQUE_CHOICE:
                if answer_value:
                    choice = question.choices.filter(
                        id__in=visible_choice_ids,
                        urn=answer_value,
                    ).first()
                    if choice is None:
                        raise serializers.ValidationError(
                            {
                                "answers": (
                                    "A selected choice is unavailable for this caller."
                                )
                            }
                        )
                    desired_choices = [choice]
                else:
                    desired_choices = []
                stored_value = None
            elif question.type == Question.Type.MULTIPLE_CHOICE:
                if isinstance(answer_value, list) and answer_value:
                    choices = question.choices.filter(
                        id__in=visible_choice_ids,
                        urn__in=answer_value,
                    )
                    found_identifiers = set(choices.values_list("urn", flat=True))
                    if set(answer_value) - found_identifiers:
                        raise serializers.ValidationError(
                            {
                                "answers": (
                                    "One or more selected choices are unavailable for "
                                    "this caller."
                                )
                            }
                        )
                    desired_choices = list(choices)
                else:
                    desired_choices = []
                stored_value = None

            desired_choice_ids = {choice.id for choice in (desired_choices or ())}
            requested_updates.append(
                {
                    "question_id": question.id,
                    "expected_question_urn": question.urn,
                    "expected_question_type": question.type,
                    "answer_id": existing_answer_ids.get(question.id),
                    "desired_choice_ids": desired_choice_ids,
                    "expected_choice_urns_by_id": {
                        choice.id: choice.urn for choice in (desired_choices or ())
                    },
                    "stored_value": stored_value,
                    "has_choice_update": desired_choices is not None,
                }
            )

        scopes = authority._lock_answer_scopes(
            requirement_assessment_id=instance.id,
            operations=requested_updates,
        )
        prepared = []
        locked_requirement_assessment = None
        for requested_update, scope in zip(requested_updates, scopes, strict=True):
            (
                compliance_assessment,
                assignments,
                current_requirement_assessment,
                locked_answer,
                locked_question,
                locked_choices,
                user_actor_ids,
            ) = scope
            authority._assert_locked_answer_authority(
                action="change" if locked_answer is not None else "add",
                compliance_assessment=compliance_assessment,
                assignments=assignments,
                requirement_assessment=current_requirement_assessment,
                answer=locked_answer,
                question=locked_question,
                locked_choices=locked_choices,
                user_actor_ids=user_actor_ids,
                desired_choice_ids=requested_update["desired_choice_ids"],
            )
            if (
                locked_requirement_assessment is not None
                and locked_requirement_assessment.id
                != current_requirement_assessment.id
            ):
                raise PermissionDenied(
                    "The answer parent changed during authorization."
                )
            locked_requirement_assessment = current_requirement_assessment
            locked_choice_by_id = {choice.id: choice for choice in locked_choices}
            prepared.append(
                (
                    locked_question,
                    locked_answer,
                    requested_update["stored_value"],
                    (
                        [
                            locked_choice_by_id[choice_id]
                            for choice_id in sorted(
                                requested_update["desired_choice_ids"], key=str
                            )
                        ]
                        if requested_update["has_choice_update"]
                        else None
                    ),
                )
            )

        return locked_requirement_assessment, prepared, visible_choice_ids

    @staticmethod
    def _apply_locked_answer_updates(
        requirement_assessment,
        prepared_updates,
        visible_choice_ids,
    ):
        for question, answer, stored_value, desired_choices in prepared_updates:
            if answer is None:
                answer = Answer.objects.create(
                    requirement_assessment=requirement_assessment,
                    question=question,
                    folder=requirement_assessment.folder,
                )
            if desired_choices is not None:
                _apply_visible_answer_choice_update(
                    answer,
                    desired_choices,
                    visible_choice_ids,
                    fail_on_hidden=(question.type == Question.Type.UNIQUE_CHOICE),
                )
            answer.value = stored_value
            answer.save(update_fields=["value"])

    def _check_findings_rebind(self, instance, findings):
        """Binding or unbinding a finding edits the finding, not just the assessment.

        Runs inside update()'s transaction: the current, changed and binder rows
        are read under row locks (on PostgreSQL; SQLite has a single writer), so
        a binder locked between validation and the write is still refused and
        a finding bound meanwhile is not silently dropped. `instance.findings`
        is not used here because get_object() prefetched it before the
        transaction.
        """
        current = set(
            Finding.objects.select_for_update().filter(requirement_assessment=instance)
        )
        changed_ids = [f.id for f in current.symmetric_difference(findings)]
        if not changed_ids:
            return
        changed = list(Finding.objects.select_for_update().filter(id__in=changed_ids))
        binder_ids = {
            f.findings_assessment_id for f in changed if f.findings_assessment_id
        }
        # Lock every binder involved, not only the locked ones: an unlocked
        # binder must not get locked between this check and the write.
        locked_binders = {
            binder.id
            for binder in FindingsAssessment.objects.select_for_update().filter(
                id__in=binder_ids
            )
            if binder.is_locked
        }
        for finding in changed:
            if finding.findings_assessment_id in locked_binders:
                raise serializers.ValidationError(
                    {
                        "findings": "⚠️ Cannot bind or unbind a finding whose findings assessment is locked."
                    }
                )
            # A finding belongs to one requirement assessment. Moving it is done
            # from the finding, never as a side effect of editing another assessment.
            if (
                finding.requirement_assessment_id
                and finding.requirement_assessment_id != instance.id
            ):
                raise serializers.ValidationError(
                    {
                        "findings": "⚠️ This finding is already bound to another requirement assessment."
                    }
                )
            self._check_object_perm(finding, "change", model=Finding)

    def update(self, instance, validated_data):
        with transaction.atomic():
            # Handle answers if provided in old JSON format
            answers_data = validated_data.pop("answers", None)

            prepared_answer_updates = []
            visible_choice_ids = None
            if answers_data and isinstance(answers_data, dict):
                (
                    instance,
                    prepared_answer_updates,
                    visible_choice_ids,
                ) = self._prepare_locked_answer_updates(instance, answers_data)

            relationship_updates = self._pop_visible_relationship_updates(
                instance, validated_data
            )
            findings = validated_data.pop("findings", None)
            if findings is not None:
                self._check_findings_rebind(instance, findings)

            # Question-driven score is recompute-owned: drop manual writes
            # unless is_score_overridden pins a value.
            requirement_has_questions = instance.requirement.questions.exists()
            override_after = validated_data.get(
                "is_score_overridden", instance.is_score_overridden
            )
            if (
                ("score" in validated_data or "is_scored" in validated_data)
                and requirement_has_questions
                and not override_after
            ):
                validated_data.pop("score", None)
                validated_data.pop("is_scored", None)

            was_overridden = instance.is_score_overridden
            previous_alignment = instance.respondent_alignment
            instance = super().update(instance, validated_data)
            self._apply_visible_relationship_updates(instance, relationship_updates)

            if findings is not None:
                # bulk=False goes through Finding.save(): updated_at moves and the
                # binder's daily metrics are refreshed, as on any finding edit.
                instance.findings.set(findings, bulk=False)

            # Override turned off: resync score from answers below.
            override_turned_off = (
                requirement_has_questions and was_overridden and not override_after
            )
            score_recomputed = False

            # Override on: is_scored mirrors score presence.
            if override_after and requirement_has_questions:
                new_is_scored = instance.score is not None
                if instance.is_scored != new_is_scored:
                    instance.is_scored = new_is_scored
                    instance.save(update_fields=["is_scored"])

            if prepared_answer_updates:
                self._apply_locked_answer_updates(
                    instance,
                    prepared_answer_updates,
                    visible_choice_ids,
                )
                # Check if any choice has scoring or result logic. For
                # compute_result, mirror `resolve_compute_result`: empty strings,
                # whitespace and unknown values are not actually result-bearing
                # and should not trigger the compute path.
                from core.utils import resolve_compute_result

                choices = QuestionChoice.objects.filter(
                    question__requirement_node=instance.requirement,
                    id__in=visible_choice_ids,
                ).values_list("add_score", "compute_result")

                has_score_or_result = any(
                    add_score is not None or resolve_compute_result(cr) is not None
                    for add_score, cr in choices
                )

                if has_score_or_result:
                    instance.compute_score_and_result()
                    score_recomputed = True

            # Resync score when the override was turned off and nothing else recomputed.
            if override_turned_off and not score_recomputed:
                instance.compute_score_and_result()

            # Auto-map respondent_alignment to result.
            # Skipped when framework questions already drive the result, to avoid
            # the alignment silently overwriting an answer-computed value.
            ALIGNMENT_TO_RESULT = {
                "yes": RequirementAssessment.Result.COMPLIANT,
                "no": RequirementAssessment.Result.NON_COMPLIANT,
                "in_progress": RequirementAssessment.Result.PARTIALLY_COMPLIANT,
                "not_applicable": RequirementAssessment.Result.NOT_APPLICABLE,
            }
            # Only an actual change drives the result. SuperForm round-trips the
            # existing respondent_alignment on every submit, so re-applying it
            # would clobber an auditor-edited result (or zero it out when the
            # respondent never answered). Blank and null mean the same thing.
            if (
                "respondent_alignment" in validated_data
                and "result" not in validated_data
                and not requirement_has_questions
            ):
                new_alignment = validated_data.get("respondent_alignment") or None
                changed = new_alignment != (previous_alignment or None)
                if changed and new_alignment in ALIGNMENT_TO_RESULT:
                    instance.result = ALIGNMENT_TO_RESULT[new_alignment]
                    instance.save(update_fields=["result"])
                elif changed and not new_alignment:
                    # Deselection: reset result and scores so the RA is truly
                    # unassessed (progress() flags an RA as assessed when score
                    # is set, even if result is NOT_ASSESSED).
                    instance.result = RequirementAssessment.Result.NOT_ASSESSED
                    instance.score = None
                    instance.documentation_score = None
                    instance.save(
                        update_fields=["result", "score", "documentation_score"]
                    )

            return instance

    class Meta:
        model = RequirementAssessment
        exclude = ["created_at", "updated_at"]


class QuestionChoiceReadSerializer(BaseModelSerializer):
    folder = FieldsRelatedField()

    class Meta:
        model = QuestionChoice
        fields = "__all__"


class QuestionChoiceWriteSerializer(BaseModelSerializer):
    def to_representation(self, instance):
        return QuestionChoiceReadSerializer(instance, context=self.context).data

    def validate_folder(self, value):
        self._ensure_immutable("folder", value)
        return value

    def validate_question(self, value):
        self._ensure_immutable("question", value)
        return value

    def validate(self, attrs):
        attrs = super().validate(attrs)
        request = self.context.get("request")
        question = attrs.get("question") or (
            self.instance.question if self.instance is not None else None
        )
        if request is not None and question is not None:
            visible_question_ids = RoleAssignment.get_viewable_object_ids(
                request.user, Question
            )
            visible_requirement_node_ids = RoleAssignment.get_viewable_object_ids(
                request.user, RequirementNode
            )
            visible_framework_ids = RoleAssignment.get_viewable_object_ids(
                request.user, Framework
            )
            if not Question.objects.filter(
                id=question.id,
                id__in=visible_question_ids,
                requirement_node_id__in=visible_requirement_node_ids,
                requirement_node__framework_id__in=visible_framework_ids,
            ).exists():
                raise PermissionDenied(
                    {"question": "The parent question is unavailable for this caller."}
                )
        return attrs

    def update(self, instance, validated_data):
        # Skip the URN-based "imported objects" guard from BaseModelSerializer
        # because choices on draft frameworks should be editable.
        self._check_object_perm(instance, "change")
        try:
            return super(BaseModelSerializer, self).update(instance, validated_data)
        except Exception as e:
            logger.error("Failed to update QuestionChoice", error=str(e), exc_info=True)
            raise serializers.ValidationError(
                "Failed to update choice. Please check the input data."
            )

    class Meta:
        model = QuestionChoice
        exclude = ["created_at", "updated_at"]


class QuestionReadListSerializer(serializers.ListSerializer):
    """Build one bounded Question/QuestionChoice projection per response page."""

    def to_representation(self, data):
        questions = list(data.all() if hasattr(data, "all") else data)
        request = self.context.get("request")
        if request is not None:
            self.context["_direct_question_visibility_context"] = (
                DirectQuestionVisibilityContext.build(
                    request=request,
                    questions=questions,
                )
            )
        return super().to_representation(questions)


class QuestionReadSerializer(BaseModelSerializer):
    folder = FieldsRelatedField()
    choices = serializers.SerializerMethodField()
    depends_on = serializers.SerializerMethodField()

    def _visibility_context(self, obj):
        request = self.context.get("request")
        if request is None:
            return None
        visibility_context = self.context.get("_direct_question_visibility_context")
        if not isinstance(
            visibility_context, DirectQuestionVisibilityContext
        ) or not visibility_context.covers_question(request, obj):
            visibility_context = DirectQuestionVisibilityContext.build(
                request=request,
                questions=(obj,),
            )
            self.context["_direct_question_visibility_context"] = visibility_context
        return visibility_context

    def get_choices(self, obj):
        visibility_context = self._visibility_context(obj)
        choices = (
            obj.choices.all()
            if visibility_context is None
            else visibility_context.choices_for(self.context["request"], obj)
        )
        return QuestionChoiceReadSerializer(
            choices,
            many=True,
            context=self.context,
        ).data

    def get_depends_on(self, obj):
        visibility_context = self._visibility_context(obj)
        if visibility_context is None:
            return obj.depends_on
        return visibility_context.dependency_for(self.context["request"], obj)

    class Meta:
        model = Question
        fields = "__all__"
        list_serializer_class = QuestionReadListSerializer


class QuestionWriteSerializer(BaseModelSerializer):
    def to_representation(self, instance):
        return QuestionReadSerializer(instance, context=self.context).data

    def validate_folder(self, value):
        self._ensure_immutable("folder", value)
        return value

    def validate_requirement_node(self, value):
        self._ensure_immutable("requirement_node", value)
        return value

    def validate(self, attrs):
        attrs = super().validate(attrs)
        request = self.context.get("request")
        requirement_node = attrs.get("requirement_node") or (
            self.instance.requirement_node if self.instance is not None else None
        )
        if request is not None and requirement_node is not None:
            if not RequirementNode.objects.filter(
                id=requirement_node.id,
                id__in=RoleAssignment.get_viewable_object_ids(
                    request.user, RequirementNode
                ),
                framework_id__in=RoleAssignment.get_viewable_object_ids(
                    request.user, Framework
                ),
            ).exists():
                raise PermissionDenied(
                    {
                        "requirement_node": (
                            "The parent requirement is unavailable for this caller."
                        )
                    }
                )
        return attrs

    def update(self, instance, validated_data):
        # Skip the URN-based "imported objects" guard from BaseModelSerializer
        # because questions on draft frameworks should be editable.
        self._check_object_perm(instance, "change")
        try:
            return super(BaseModelSerializer, self).update(instance, validated_data)
        except Exception as e:
            logger.error("Failed to update Question", error=str(e), exc_info=True)
            raise serializers.ValidationError(
                "Failed to update question. Please check the input data."
            )

    class Meta:
        model = Question
        exclude = ["created_at", "updated_at"]


class AnswerReadSerializer(BaseModelSerializer):
    folder = FieldsRelatedField()
    selected_choices = serializers.SerializerMethodField()

    def get_selected_choices(self, instance):
        request = self.context.get("request")
        if request is None or not getattr(request.user, "is_authenticated", False):
            return []
        choices = getattr(instance, "questionnaire_visible_choices", None)
        if choices is None:
            if instance.response_id:
                choices = instance.selected_choices.filter(
                    question_id=instance.question_id,
                    question__page__quick_form_id=instance.response.quick_form_id,
                )
                field = FieldsRelatedField()
                return [field.to_representation(choice) for choice in choices]
            visible_question_ids = RoleAssignment.get_viewable_object_ids(
                request.user, Question
            )
            visible_requirement_node_ids = RoleAssignment.get_viewable_object_ids(
                request.user, RequirementNode
            )
            visible_framework_ids = RoleAssignment.get_viewable_object_ids(
                request.user, Framework
            )
            visible_choice_ids = RoleAssignment.get_viewable_object_ids(
                request.user, QuestionChoice
            )
            choices = instance.selected_choices.filter(
                question_id=instance.question_id,
                question_id__in=visible_question_ids,
                question__requirement_node_id__in=visible_requirement_node_ids,
                question__requirement_node__framework_id__in=visible_framework_ids,
                id__in=visible_choice_ids,
            )
        else:
            # A custom Prefetch is an authorization optimization, not evidence
            # that a legacy/corrupt M2M row belongs to this Answer's Question.
            choices = [
                choice
                for choice in choices
                if choice.question_id == instance.question_id
            ]
        field = FieldsRelatedField()
        return [field.to_representation(choice) for choice in choices]

    def to_representation(self, instance):
        data = super().to_representation(instance)
        if instance.question.type in (
            Question.Type.UNIQUE_CHOICE,
            Question.Type.MULTIPLE_CHOICE,
        ):
            # Old rows may still carry choice URNs in ``value``.  Choices cross
            # their own IAM boundary above; the raw compatibility column must
            # never become a second, unfiltered representation.
            data["value"] = None
        return data

    class Meta:
        model = Answer
        fields = "__all__"


class AnswerWriteSerializer(BaseModelSerializer):
    # The RequirementAssessment is the only security-domain authority.  Keeping
    # this read-only also prevents an arbitrary client-supplied Folder UUID from
    # becoming an existence oracle during DRF field resolution.
    folder = serializers.PrimaryKeyRelatedField(read_only=True)
    requirement_assessment = AnswerAuthorityPrimaryKeyRelatedField(
        queryset=RequirementAssessment.objects.all(),
        authority_model=RequirementAssessment,
        immutable_on_update=True,
        required=False,
        allow_null=True,
        # DRF turns each two-column uniqueness constraint into a
        # UniqueTogetherValidator, which otherwise treats both alternative
        # parent fields as required on create.  Supply the absent branch only
        # on create; updates must keep using the persisted immutable parent.
        default=serializers.CreateOnlyDefault(None),
    )
    response = serializers.PrimaryKeyRelatedField(
        queryset=QuickFormResponse.objects.all(),
        required=False,
        allow_null=True,
        default=serializers.CreateOnlyDefault(None),
    )
    question = AnswerAuthorityPrimaryKeyRelatedField(
        queryset=Question.objects.all(),
        authority_model=Question,
        immutable_on_update=True,
    )
    # Accept selected_choices as list of PKs for M2M
    selected_choices = AnswerAuthorityPrimaryKeyRelatedField(
        queryset=QuestionChoice.objects.all(),
        authority_model=QuestionChoice,
        many=True,
        required=False,
    )

    def to_internal_value(self, data):
        request = self.context.get("request")
        if not getattr(getattr(request, "user", None), "is_authenticated", False):
            raise PermissionDenied(_ANSWER_RELATION_UNAVAILABLE)
        return super().to_internal_value(data)

    def to_representation(self, instance):
        # The write queryset may have prefetched the pre-update authorized
        # choice slice to a custom attribute.  Force the response projection to
        # re-read the committed relation instead of echoing that stale list.
        if hasattr(instance, "questionnaire_visible_choices"):
            delattr(instance, "questionnaire_visible_choices")
        return AnswerReadSerializer(instance, context=self.context).data

    def _check_m2m_visibility(self, validated_data: dict) -> None:
        """Choice IAM is checked against this Answer's exact Question below."""
        return super()._check_m2m_visibility(
            {
                field_name: value
                for field_name, value in validated_data.items()
                if field_name
                not in {
                    "selected_choices",
                    "_m2m_choices",
                    "_m2m_expected_choice_urns_by_id",
                }
            }
        )

    @staticmethod
    def _answer_permission(action: str):
        return Permission.objects.get(
            content_type__app_label="core",
            content_type__model="answer",
            codename=f"{action}_answer",
        )

    def _lock_answer_scopes(
        self,
        *,
        requirement_assessment_id,
        operations,
    ):
        """Lock one or more Answer aggregates in one deterministic boundary.

        Unlocked reads only discover the complete parent and security-folder
        identity set.  The locked order is Folder -> Framework -> CA -> ordered
        Assignments -> RequirementNode -> RA -> Questions -> Answers -> Choices
        -> through rows -> direct user Actors -> User.  Locked rows are then
        compared with every locator before authority is evaluated.  No mutation
        returns to an earlier lock class, and new Answer rows derive their folder
        only from the locked RequirementAssessment.
        """
        operations = [
            {
                "question_id": operation["question_id"],
                "expected_question_urn": operation.get("expected_question_urn"),
                "expected_question_type": operation.get("expected_question_type"),
                "answer_id": operation.get("answer_id"),
                "desired_choice_ids": frozenset(
                    operation.get("desired_choice_ids", ())
                ),
                "expected_choice_urns_by_id": (
                    dict(operation["expected_choice_urns_by_id"])
                    if operation.get("expected_choice_urns_by_id") is not None
                    else None
                ),
            }
            for operation in operations
        ]
        operations.sort(key=lambda operation: str(operation["question_id"]))
        question_ids = [operation["question_id"] for operation in operations]
        if not operations or len(set(question_ids)) != len(question_ids):
            raise serializers.ValidationError(
                "Answer lock operations must contain distinct questions."
            )

        requirement_assessment_locator = (
            RequirementAssessment.objects.filter(id=requirement_assessment_id)
            .values(
                "id",
                "compliance_assessment_id",
                "requirement_id",
                "folder_id",
            )
            .first()
        )
        if requirement_assessment_locator is None:
            raise PermissionDenied("The answer parent is unavailable.")
        compliance_assessment_locator = (
            ComplianceAssessment.objects.filter(
                id=requirement_assessment_locator["compliance_assessment_id"]
            )
            .values("id", "framework_id", "folder_id")
            .first()
        )
        requirement_node_locator = (
            RequirementNode.objects.filter(
                id=requirement_assessment_locator["requirement_id"]
            )
            .values("id", "framework_id", "folder_id")
            .first()
        )
        if compliance_assessment_locator is None or requirement_node_locator is None:
            raise PermissionDenied("The answer parent chain is unavailable.")

        question_locators = {
            row["id"]: row
            for row in Question.objects.filter(id__in=question_ids)
            .order_by("pk")
            .values("id", "requirement_node_id", "folder_id", "urn", "type")
        }
        if set(question_locators) != set(question_ids):
            raise PermissionDenied("One or more answer questions are unavailable.")

        answer_locators = list(
            Answer.objects.filter(
                requirement_assessment_id=requirement_assessment_id,
                question_id__in=question_ids,
            )
            .order_by("pk")
            .values("id", "requirement_assessment_id", "question_id", "folder_id")
        )
        answer_ids = [row["id"] for row in answer_locators]
        choice_through = Answer.selected_choices.through
        current_choice_pairs = list(
            choice_through.objects.filter(answer_id__in=answer_ids)
            .order_by("pk")
            .values_list("answer_id", "questionchoice_id")
        )
        all_choice_ids = {choice_id for _answer_id, choice_id in current_choice_pairs}
        all_choice_ids.update(
            choice_id
            for operation in operations
            for choice_id in operation["desired_choice_ids"]
        )
        choice_locators = {
            row["id"]: row
            for row in QuestionChoice.objects.filter(id__in=all_choice_ids)
            .order_by("pk")
            .values("id", "question_id", "folder_id", "urn")
        }
        if set(choice_locators) != all_choice_ids:
            raise PermissionDenied("One or more answer choices are unavailable.")

        assignment_locators = list(
            RequirementAssignment.objects.filter(
                compliance_assessment_id=compliance_assessment_locator["id"],
                requirement_assessments=requirement_assessment_id,
            )
            .order_by("pk")
            .values("id", "compliance_assessment_id")
        )
        assignment_ids = [row["id"] for row in assignment_locators]
        framework_ids = {
            compliance_assessment_locator["framework_id"],
            requirement_node_locator["framework_id"],
        }
        framework_locators = {
            row["id"]: row
            for row in Framework.objects.filter(id__in=framework_ids)
            .order_by("pk")
            .values("id", "folder_id")
        }
        if set(framework_locators) != framework_ids:
            raise PermissionDenied("The answer framework is unavailable.")

        folder_ids = {
            compliance_assessment_locator["folder_id"],
            requirement_node_locator["folder_id"],
            requirement_assessment_locator["folder_id"],
            *(row["folder_id"] for row in framework_locators.values()),
            *(row["folder_id"] for row in question_locators.values()),
            *(row["folder_id"] for row in answer_locators),
            *(row["folder_id"] for row in choice_locators.values()),
        }
        if None in folder_ids:
            raise PermissionDenied("The answer security domain is unavailable.")
        locked_folder_ids = set(
            Folder.objects.select_for_update()
            .filter(id__in=folder_ids)
            .order_by("pk")
            .values_list("id", flat=True)
        )
        if locked_folder_ids != folder_ids:
            raise PermissionDenied("The answer security domain is unavailable.")

        locked_frameworks = list(
            Framework.objects.select_for_update()
            .filter(id__in=framework_ids)
            .order_by("pk")
        )
        if len(locked_frameworks) != len(framework_ids) or any(
            framework.folder_id != framework_locators[framework.id]["folder_id"]
            for framework in locked_frameworks
        ):
            raise PermissionDenied("The answer framework changed during authorization.")

        compliance_assessment = (
            ComplianceAssessment.objects.select_for_update()
            .filter(id=compliance_assessment_locator["id"])
            .order_by("pk")
            .first()
        )
        if compliance_assessment is None or (
            compliance_assessment.framework_id
            != compliance_assessment_locator["framework_id"]
            or compliance_assessment.folder_id
            != compliance_assessment_locator["folder_id"]
        ):
            raise PermissionDenied("The answer audit changed during authorization.")

        assignments = list(
            RequirementAssignment.objects.select_for_update()
            .filter(pk__in=assignment_ids)
            .order_by("pk")
        )
        if [assignment.id for assignment in assignments] != assignment_ids or any(
            assignment.compliance_assessment_id != compliance_assessment_locator["id"]
            for assignment in assignments
        ):
            raise PermissionDenied(
                "The answer assignment boundary changed during authorization."
            )

        requirement_node = (
            RequirementNode.objects.select_for_update()
            .filter(id=requirement_node_locator["id"])
            .order_by("pk")
            .first()
        )
        if requirement_node is None or (
            requirement_node.framework_id != requirement_node_locator["framework_id"]
            or requirement_node.folder_id != requirement_node_locator["folder_id"]
        ):
            raise PermissionDenied(
                "The answer requirement changed during authorization."
            )

        requirement_assessment = (
            RequirementAssessment.objects.select_for_update()
            .filter(id=requirement_assessment_id)
            .order_by("pk")
            .first()
        )
        if requirement_assessment is None or any(
            getattr(requirement_assessment, field_name) != expected
            for field_name, expected in (
                (
                    "compliance_assessment_id",
                    requirement_assessment_locator["compliance_assessment_id"],
                ),
                ("requirement_id", requirement_assessment_locator["requirement_id"]),
                ("folder_id", requirement_assessment_locator["folder_id"]),
            )
        ):
            raise PermissionDenied("The answer parent changed during authorization.")

        locked_questions = list(
            Question.objects.select_for_update()
            .filter(id__in=question_ids)
            .order_by("pk")
        )
        questions_by_id = {question.id: question for question in locked_questions}
        if set(questions_by_id) != set(question_ids) or any(
            question.requirement_node_id
            != question_locators[question.id]["requirement_node_id"]
            or question.folder_id != question_locators[question.id]["folder_id"]
            or question.urn != question_locators[question.id]["urn"]
            or question.type != question_locators[question.id]["type"]
            for question in locked_questions
        ):
            raise PermissionDenied("One or more answer questions are unavailable.")
        if any(
            (
                operation["expected_question_urn"] is not None
                and questions_by_id[operation["question_id"]].urn
                != operation["expected_question_urn"]
            )
            or (
                operation["expected_question_type"] is not None
                and questions_by_id[operation["question_id"]].type
                != operation["expected_question_type"]
            )
            for operation in operations
        ):
            raise PermissionDenied("An answer question changed during authorization.")
        if (
            any(
                question.requirement_node_id != requirement_node.id
                for question in locked_questions
            )
            or requirement_node.framework_id != compliance_assessment.framework_id
        ):
            raise PermissionDenied("The answer parent chain is inconsistent.")

        locked_answers = list(
            Answer.objects.select_for_update()
            .filter(
                requirement_assessment_id=requirement_assessment.id,
                question_id__in=question_ids,
            )
            .order_by("pk")
        )
        answer_locators_by_id = {row["id"]: row for row in answer_locators}
        if {answer.id for answer in locked_answers} != set(
            answer_locators_by_id
        ) or any(
            answer.requirement_assessment_id
            != answer_locators_by_id[answer.id]["requirement_assessment_id"]
            or answer.question_id != answer_locators_by_id[answer.id]["question_id"]
            or answer.folder_id != answer_locators_by_id[answer.id]["folder_id"]
            for answer in locked_answers
        ):
            raise PermissionDenied("The answer parent changed during authorization.")
        answers_by_question_id = {
            answer.question_id: answer for answer in locked_answers
        }
        for operation in operations:
            answer = answers_by_question_id.get(operation["question_id"])
            expected_answer_id = operation["answer_id"]
            if expected_answer_id is None:
                if answer is not None:
                    raise serializers.ValidationError(
                        "An answer already exists for this requirement and question."
                    )
            elif answer is None or answer.id != expected_answer_id:
                raise PermissionDenied(
                    "The answer parent changed during authorization."
                )

        current_choice_ids_by_answer = {}
        for answer_id, choice_id in current_choice_pairs:
            current_choice_ids_by_answer.setdefault(answer_id, set()).add(choice_id)
        locked_choices = list(
            QuestionChoice.objects.select_for_update()
            .filter(id__in=all_choice_ids)
            .order_by("pk")
        )
        choices_by_id = {choice.id: choice for choice in locked_choices}
        if set(choices_by_id) != all_choice_ids or any(
            choice.question_id != choice_locators[choice.id]["question_id"]
            or choice.folder_id != choice_locators[choice.id]["folder_id"]
            or choice.urn != choice_locators[choice.id]["urn"]
            for choice in locked_choices
        ):
            raise PermissionDenied("One or more answer choices are unavailable.")

        operation_choices = {}
        for operation in operations:
            question_id = operation["question_id"]
            answer = answers_by_question_id.get(question_id)
            operation_choice_ids = set(operation["desired_choice_ids"])
            if answer is not None:
                operation_choice_ids.update(
                    current_choice_ids_by_answer.get(answer.id, ())
                )
            choices = [
                choices_by_id[choice_id]
                for choice_id in sorted(operation_choice_ids, key=str)
            ]
            if any(choice.question_id != question_id for choice in choices):
                raise PermissionDenied(
                    "An answer choice does not belong to its question."
                )
            expected_choice_urns = operation["expected_choice_urns_by_id"]
            if expected_choice_urns is not None and (
                set(expected_choice_urns) != set(operation["desired_choice_ids"])
                or any(
                    choices_by_id[choice_id].urn != expected_urn
                    for choice_id, expected_urn in expected_choice_urns.items()
                )
            ):
                raise PermissionDenied("An answer choice changed during authorization.")
            operation_choices[question_id] = choices

        # Through rows are locked only after every aggregate row and choice.
        locked_assignment_link_ids = set(
            RequirementAssignment.requirement_assessments.through.objects.select_for_update()
            .filter(
                requirementassignment_id__in=assignment_ids,
                requirementassessment_id=requirement_assessment.id,
            )
            .order_by("pk")
            .values_list("requirementassignment_id", flat=True)
        )
        current_assignment_link_ids = set(
            RequirementAssignment.requirement_assessments.through.objects.filter(
                requirementassessment_id=requirement_assessment.id,
            ).values_list("requirementassignment_id", flat=True)
        )
        if locked_assignment_link_ids != set(
            assignment_ids
        ) or current_assignment_link_ids != set(assignment_ids):
            raise PermissionDenied(
                "The answer assignment boundary changed during authorization."
            )
        list(
            RequirementAssignment.actor.through.objects.select_for_update()
            .filter(requirementassignment_id__in=assignment_ids)
            .order_by("pk")
            .values_list("pk", flat=True)
        )
        list(
            choice_through.objects.select_for_update()
            .filter(answer_id__in=answer_ids)
            .order_by("pk")
            .values_list("pk", flat=True)
        )
        locked_choice_pairs = set(
            choice_through.objects.filter(answer_id__in=answer_ids).values_list(
                "answer_id", "questionchoice_id"
            )
        )
        if locked_choice_pairs != set(current_choice_pairs):
            raise PermissionDenied("The answer choices changed during authorization.")

        # Team membership is independently mutable and does not participate in
        # this lock protocol.  As with inverse RA writes, only the caller's
        # direct user-backed Actor can confer Answer assignment authority.
        request = self.context.get("request")
        user_actor_ids_before = set()
        user_actor_ids_after = set()
        if request is not None and getattr(request.user, "is_authenticated", False):
            user_actor_ids_before = set(
                Actor.objects.filter(user_id=request.user.id).values_list(
                    "id", flat=True
                )
            )
            linked_actor_ids = set(
                RequirementAssignment.actor.through.objects.filter(
                    requirementassignment_id__in=assignment_ids,
                ).values_list("actor_id", flat=True)
            )
            locked_direct_actors = list(
                Actor.objects.select_for_update()
                .filter(
                    models.Q(id__in=linked_actor_ids)
                    | models.Q(id__in=user_actor_ids_before),
                    user__isnull=False,
                )
                .order_by("pk")
            )
            locked_user = (
                User.objects.select_for_update()
                .filter(id=request.user.id, is_active=True)
                .order_by("pk")
                .first()
            )
            if locked_user is None:
                raise PermissionDenied("The caller is unavailable.")
            user_actor_ids_after = set(
                Actor.objects.filter(user_id=locked_user.id).values_list(
                    "id", flat=True
                )
            )
            if user_actor_ids_after != user_actor_ids_before:
                raise PermissionDenied("The caller's assignment authority changed.")
            if any(
                actor.user_id != locked_user.id
                for actor in locked_direct_actors
                if actor.id in user_actor_ids_after
            ):
                raise PermissionDenied("The caller's assignment authority changed.")

        return [
            (
                compliance_assessment,
                assignments,
                requirement_assessment,
                answers_by_question_id.get(operation["question_id"]),
                questions_by_id[operation["question_id"]],
                operation_choices[operation["question_id"]],
                user_actor_ids_after,
            )
            for operation in operations
        ]

    def _lock_answer_scope(
        self,
        *,
        requirement_assessment_id,
        question_id,
        answer_id=None,
        desired_choice_ids=(),
        expected_choice_urns_by_id=None,
    ):
        """Single-answer wrapper over the shared deterministic batch boundary."""
        return self._lock_answer_scopes(
            requirement_assessment_id=requirement_assessment_id,
            operations=(
                {
                    "question_id": question_id,
                    "answer_id": answer_id,
                    "desired_choice_ids": desired_choice_ids,
                    "expected_choice_urns_by_id": expected_choice_urns_by_id,
                },
            ),
        )[0]

    def _assert_locked_answer_authority(
        self,
        *,
        action: str,
        compliance_assessment,
        assignments,
        requirement_assessment,
        answer,
        question,
        locked_choices,
        user_actor_ids,
        desired_choice_ids=(),
    ) -> None:
        request = self.context.get("request")
        if not getattr(getattr(request, "user", None), "is_authenticated", False):
            raise PermissionDenied(_ANSWER_RELATION_UNAVAILABLE)

        if question.requirement_node_id != requirement_assessment.requirement_id:
            raise PermissionDenied(
                "The answer question does not belong to its assessment."
            )
        if (
            requirement_assessment.requirement.framework_id
            != compliance_assessment.framework_id
        ):
            raise PermissionDenied("The answer assessment framework is inconsistent.")
        if compliance_assessment.is_locked:
            raise serializers.ValidationError(
                "⚠️ Cannot modify the answer when the audit is locked."
            )
        if compliance_assessment.status == ComplianceAssessment.Status.IN_REVIEW:
            raise serializers.ValidationError(
                "⚠️ Cannot modify the answer when the audit is in review."
            )

        user = request.user
        required_views = (
            (ComplianceAssessment, compliance_assessment.id),
            (RequirementAssessment, requirement_assessment.id),
            (RequirementNode, requirement_assessment.requirement_id),
            (Framework, compliance_assessment.framework_id),
            (Question, question.id),
        )
        if answer is not None:
            if answer.folder_id != requirement_assessment.folder_id:
                raise PermissionDenied(
                    "The answer security domain is inconsistent with its assessment."
                )
            required_views += ((Answer, answer.id),)
        for model, object_id in required_views:
            if not model.objects.filter(
                id=object_id,
                id__in=RoleAssignment.get_viewable_object_ids(user, model),
            ).exists():
                raise PermissionDenied(
                    "You do not have permission to access this answer."
                )

        from core.utils import (
            has_full_view_compliance_assessment,
            is_field_editable_by,
        )

        is_full_viewer = has_full_view_compliance_assessment(
            user, compliance_assessment
        )
        viewer_role = "auditor" if is_full_viewer else "respondent"
        if not is_field_editable_by(compliance_assessment, "answers", viewer_role):
            raise PermissionDenied("You do not have permission to update this answer.")

        if not is_full_viewer:
            assignment_ids = [assignment.id for assignment in assignments]
            requirement_links = set(
                RequirementAssignment.requirement_assessments.through.objects.filter(
                    requirementassignment_id__in=assignment_ids,
                    requirementassessment_id=requirement_assessment.id,
                ).values_list("requirementassignment_id", flat=True)
            )
            actor_links = set(
                RequirementAssignment.actor.through.objects.filter(
                    requirementassignment_id__in=requirement_links,
                    actor_id__in=user_actor_ids,
                ).values_list("requirementassignment_id", flat=True)
            )
            user_assignments = [
                assignment for assignment in assignments if assignment.id in actor_links
            ]
            if not user_assignments:
                raise PermissionDenied(
                    "You do not have permission to access this answer."
                )
            if any(
                assignment.status
                in (
                    RequirementAssignment.Status.SUBMITTED,
                    RequirementAssignment.Status.CLOSED,
                )
                for assignment in user_assignments
            ):
                raise serializers.ValidationError(
                    "Cannot modify: this requirement's assignment has been submitted or closed."
                )

        if not RoleAssignment.is_access_allowed(
            user=user,
            perm=self._answer_permission(action),
            # RequirementAssessment owns the Answer security domain.  Never let
            # a legacy/corrupt child folder become a weaker permission root.
            folder=requirement_assessment.folder,
        ):
            raise PermissionDenied(
                f"You do not have permission to {action} this answer."
            )

        desired_choice_ids = set(desired_choice_ids)
        if desired_choice_ids:
            visible_choice_ids = RoleAssignment.get_viewable_object_ids(
                user, QuestionChoice
            )
            authorized_choice_ids = set(
                QuestionChoice.objects.filter(
                    id__in=desired_choice_ids,
                    question_id=question.id,
                )
                .filter(id__in=visible_choice_ids)
                .values_list("id", flat=True)
            )
            if authorized_choice_ids != desired_choice_ids:
                raise PermissionDenied(
                    "One or more selected choices are unavailable for this caller."
                )

    def validate_requirement_assessment(self, value):
        self._ensure_immutable("requirement_assessment", value)
        return value

    def validate_response(self, value):
        self._ensure_immutable("response", value)
        return value

    def validate_question(self, value):
        self._ensure_immutable("question", value)
        return value

    def validate(self, attrs):
        requirement_assessment = attrs.get("requirement_assessment") or (
            self.instance.requirement_assessment if self.instance else None
        )
        question = attrs.get("question") or (
            self.instance.question if self.instance else None
        )
        value = attrs.get("value")
        selected_choices_list = attrs.get("selected_choices")

        response = attrs.get("response") or (
            self.instance.response if self.instance else None
        )

        if not requirement_assessment and not response:
            raise serializers.ValidationError(
                {
                    "requirement_assessment": "Either requirement_assessment or response is required."
                }
            )
        if requirement_assessment and response:
            raise serializers.ValidationError(
                "An answer belongs to a requirement assessment or to a quick form response, not both."
            )

        visible_choice_ids = QuestionChoice.objects.none().values_list("id", flat=True)
        if response:
            # Quick form branch: the question must sit on a page of the
            # response's form, and the response must still be in progress.
            if question and (
                question.page_id is None
                or question.page.quick_form_id != response.quick_form_id
            ):
                raise serializers.ValidationError(
                    {
                        "question": f"Question '{question}' does not belong to quick form response '{response}'."
                    }
                )
            from core.models import QuickFormResponse

            if response.status != QuickFormResponse.Status.DRAFT:
                raise serializers.ValidationError(
                    "Answers can only be modified while the response is in progress."
                )
            # Same rule as the `answers` dict on the response itself: folder-level rights
            # on Answer are not rights over someone else's request.
            request = self.context.get("request")
            if request is not None and not response.is_requester(request.user):
                raise serializers.ValidationError(
                    "Only the requester can change the answers."
                )
            visible_choice_ids = QuestionChoice.objects.filter(
                question__page__quick_form_id=response.quick_form_id,
            ).values_list("id", flat=True)

        if requirement_assessment:
            # 1. Parent/child consistency check
            if (
                question
                and question.requirement_node_id
                != requirement_assessment.requirement_id
            ):
                raise serializers.ValidationError(
                    {
                        "question": f"Question '{question}' does not belong to requirement assessment '{requirement_assessment}'."
                    }
                )

            # 2. Assessment state/locked checks
            compliance_assessment = requirement_assessment.compliance_assessment
            if compliance_assessment.is_locked:
                raise serializers.ValidationError(
                    "⚠️ Cannot modify the answer when the audit is locked."
                )

            from core.models import ComplianceAssessment

            if compliance_assessment.status == ComplianceAssessment.Status.IN_REVIEW:
                raise serializers.ValidationError(
                    "⚠️ Cannot modify the answer when the audit is in review."
                )

            # 3. Assignment, field-policy and product-visibility guards.
            request = self.context.get("request")
            if request:
                from core.utils import (
                    has_full_view_compliance_assessment,
                    is_field_editable_by,
                )

                user = request.user
                if (
                    not ComplianceAssessment.objects.filter(
                        id=compliance_assessment.id,
                        id__in=RoleAssignment.get_viewable_object_ids(
                            user, ComplianceAssessment
                        ),
                    ).exists()
                    or not RequirementAssessment.objects.filter(
                        id=requirement_assessment.id,
                        id__in=RoleAssignment.get_viewable_object_ids(
                            user, RequirementAssessment
                        ),
                    ).exists()
                ):
                    raise PermissionDenied(
                        "You do not have permission to access this answer."
                    )

                is_full_viewer = has_full_view_compliance_assessment(
                    user, compliance_assessment
                )
                viewer_role = "auditor" if is_full_viewer else "respondent"
                if not is_field_editable_by(
                    compliance_assessment, "answers", viewer_role
                ):
                    raise PermissionDenied(
                        "You do not have permission to update this answer."
                    )

                user_actors = Actor.objects.filter(user_id=user.id)
                if (
                    not is_full_viewer
                    and not RequirementAssignment.objects.filter(
                        compliance_assessment=compliance_assessment,
                        requirement_assessments=requirement_assessment,
                        actor__in=user_actors,
                    ).exists()
                ):
                    raise PermissionDenied(
                        "You do not have permission to access this answer."
                    )

                if (
                    question
                    and not Question.objects.filter(
                        id=question.id,
                        id__in=RoleAssignment.get_viewable_object_ids(user, Question),
                    ).exists()
                ):
                    raise PermissionDenied(
                        "You do not have permission to access this answer."
                    )

                visible_choice_ids = RoleAssignment.get_viewable_object_ids(
                    user, QuestionChoice
                )

                if not is_full_viewer:
                    locked_assignment = requirement_assessment.assignments.filter(
                        actor__in=user_actors,
                        status__in=["submitted", "closed"],
                    ).first()
                    if locked_assignment:
                        raise serializers.ValidationError(
                            "Cannot modify: this requirement's assignment has been submitted or closed."
                        )

        if question:
            q_type = question.type

            # Reject sending both value and selected_choices for choice questions
            if (
                q_type in (Question.Type.UNIQUE_CHOICE, Question.Type.MULTIPLE_CHOICE)
                and value is not None
                and selected_choices_list is not None
            ):
                raise serializers.ValidationError(
                    "Cannot send both 'value' and 'selected_choices' for choice questions. "
                    "Use 'selected_choices' (PKs) or 'value' (ref_ids), not both."
                )

            # Reject selected_choices for non-choice question types
            if (
                q_type
                not in (
                    Question.Type.UNIQUE_CHOICE,
                    Question.Type.MULTIPLE_CHOICE,
                )
                and selected_choices_list is not None
            ):
                raise serializers.ValidationError(
                    {
                        "selected_choices": "selected_choices is only valid for choice questions."
                    }
                )

            if q_type == Question.Type.TEXT:
                if value is not None and not isinstance(value, str):
                    raise serializers.ValidationError(
                        {"value": "Text answers must be a string."}
                    )

            elif q_type == Question.Type.NUMBER:
                if value is not None and not isinstance(value, (int, float)):
                    raise serializers.ValidationError(
                        {"value": "Number answers must be numeric."}
                    )

            elif q_type == Question.Type.UNIQUE_CHOICE:
                # Legacy: value is a URN string → resolve to M2M
                if value is not None:
                    if isinstance(value, list):
                        raise serializers.ValidationError(
                            {
                                "value": "Single choice answers must be a string, not a list."
                            }
                        )
                    if value:
                        choice = question.choices.filter(
                            id__in=visible_choice_ids,
                            urn=value,
                        ).first()

                        if not choice:
                            raise serializers.ValidationError(
                                {"value": f"Invalid choice '{value}'."}
                            )
                        attrs["_m2m_choices"] = [choice]
                        attrs["_m2m_expected_choice_urns_by_id"] = {choice.id: value}
                    else:
                        attrs["_m2m_choices"] = []
                        attrs["_m2m_expected_choice_urns_by_id"] = {}
                    attrs["value"] = None

                # Direct M2M PKs: validate all belong to question and at most 1
                if selected_choices_list is not None:
                    if len(selected_choices_list) > 1:
                        raise serializers.ValidationError(
                            {
                                "selected_choices": "Single choice questions accept at most one selection."
                            }
                        )
                    valid_pks = set(
                        question.choices.filter(id__in=visible_choice_ids).values_list(
                            "id", flat=True
                        )
                    )
                    for c in selected_choices_list:
                        if c.id not in valid_pks:
                            raise serializers.ValidationError(
                                {
                                    "selected_choices": f"Choice {c.id} does not belong to this question."
                                }
                            )
                    attrs["_m2m_choices"] = selected_choices_list
                    attrs["_m2m_expected_choice_urns_by_id"] = None
                    attrs["value"] = None

            elif q_type == Question.Type.MULTIPLE_CHOICE:
                # Legacy: value is a list of URN strings → resolve to M2M
                if value is not None:
                    if not isinstance(value, list):
                        raise serializers.ValidationError(
                            {"value": "Multiple choice answers must be a list."}
                        )
                    if value:
                        choices = question.choices.filter(
                            id__in=visible_choice_ids,
                            urn__in=value,
                        )
                        found_identifiers = set(choices.values_list("urn", flat=True))
                        missing = [v for v in value if v not in found_identifiers]

                        if missing:
                            raise serializers.ValidationError(
                                {"value": f"Invalid choices: {missing}"}
                            )
                        attrs["_m2m_choices"] = list(choices)
                        attrs["_m2m_expected_choice_urns_by_id"] = {
                            choice.id: choice.urn for choice in choices
                        }
                    else:
                        attrs["_m2m_choices"] = []
                        attrs["_m2m_expected_choice_urns_by_id"] = {}
                    attrs["value"] = None

                # Direct M2M PKs: validate all belong to question
                if selected_choices_list is not None:
                    valid_pks = set(
                        question.choices.filter(id__in=visible_choice_ids).values_list(
                            "id", flat=True
                        )
                    )
                    for c in selected_choices_list:
                        if c.id not in valid_pks:
                            raise serializers.ValidationError(
                                {
                                    "selected_choices": f"Choice {c.id} does not belong to this question."
                                }
                            )
                    attrs["_m2m_choices"] = selected_choices_list
                    attrs["_m2m_expected_choice_urns_by_id"] = None
                    attrs["value"] = None

            elif q_type == Question.Type.OBJECT_REFERENCE:
                from core.object_references import ReferenceError_, validate_ids

                # The answer's owner, never the question's folder: library questions
                # live in the root folder, so falling back to it would admit every
                # object there — the scope check is the whole point of this branch.
                owner = (
                    self.instance.owner
                    if self.instance
                    else attrs.get("response") or attrs.get("requirement_assessment")
                )
                folder = getattr(owner, "folder", None)
                if folder is None:
                    raise serializers.ValidationError({"value": "unknownAnswerOwner"})
                request = self.context.get("request")
                try:
                    attrs["value"] = validate_ids(
                        question,
                        folder,
                        value or [],
                        user=getattr(request, "user", None),
                    )
                except ReferenceError_ as e:
                    # The code, not the exception text: the response is translatable and
                    # carries nothing the caller did not already send.
                    logger.warning("Rejected object reference", error=e)
                    raise serializers.ValidationError({"value": e.code})
            elif q_type == Question.Type.BOOLEAN:
                if value is not None and not isinstance(value, bool):
                    raise serializers.ValidationError(
                        {"value": "Boolean answers must be true or false."}
                    )
            elif q_type == Question.Type.DATE:
                if value is not None:
                    if not isinstance(value, str):
                        raise serializers.ValidationError(
                            {
                                "value": "Date answers must be a string in YYYY-MM-DD format."
                            }
                        )
                    try:
                        datetime.strptime(value, "%Y-%m-%d")
                    except ValueError:
                        raise serializers.ValidationError(
                            {"value": "Date answers must be in YYYY-MM-DD format."}
                        )

            if "_m2m_choices" in attrs:
                # Keep the authority boundary lazy so update-time delta queries
                # intersect it in SQL instead of materializing every globally
                # visible QuestionChoice ID.
                attrs["_m2m_visible_choice_ids"] = visible_choice_ids

        return super().validate(attrs)

    def create(self, validated_data):
        m2m_choices = validated_data.pop("_m2m_choices", None)
        expected_choice_urns_by_id = validated_data.pop(
            "_m2m_expected_choice_urns_by_id", None
        )
        validated_data.pop("_m2m_visible_choice_ids", None)
        # Remove selected_choices from validated_data since M2M can't be set on create
        validated_data.pop("selected_choices", None)
        requirement_assessment = validated_data.get("requirement_assessment")
        response = validated_data.get("response")
        question = validated_data.get("question")
        if question is None:
            raise serializers.ValidationError({"question": "This field is required."})
        if response is not None:
            validated_data["folder"] = response.folder
            with transaction.atomic():
                instance = super().create(validated_data)
                if m2m_choices is not None:
                    instance.selected_choices.set(m2m_choices)
                    instance.save()
                return instance
        if requirement_assessment is None:
            raise serializers.ValidationError(
                {
                    "requirement_assessment": (
                        "Either requirement_assessment or response is required."
                    )
                }
            )
        desired_choice_ids = {
            choice.id for choice in (m2m_choices if m2m_choices is not None else [])
        }
        with transaction.atomic():
            scope = self._lock_answer_scope(
                requirement_assessment_id=requirement_assessment.id,
                question_id=question.id,
                desired_choice_ids=desired_choice_ids,
                expected_choice_urns_by_id=expected_choice_urns_by_id,
            )
            (
                compliance_assessment,
                assignments,
                locked_requirement_assessment,
                _answer,
                locked_question,
                locked_choices,
                user_actor_ids,
            ) = scope
            self._assert_locked_answer_authority(
                action="add",
                compliance_assessment=compliance_assessment,
                assignments=assignments,
                requirement_assessment=locked_requirement_assessment,
                answer=None,
                question=locked_question,
                locked_choices=locked_choices,
                user_actor_ids=user_actor_ids,
                desired_choice_ids=desired_choice_ids,
            )
            locked_choice_by_id = {choice.id: choice for choice in locked_choices}
            locked_desired_choices = [
                locked_choice_by_id[choice_id]
                for choice_id in sorted(desired_choice_ids, key=str)
            ]
            validated_data["requirement_assessment"] = locked_requirement_assessment
            validated_data["question"] = locked_question
            # The parent owns the security domain. Never trust a second client
            # supplied folder for a child Answer.
            validated_data["folder"] = locked_requirement_assessment.folder
            instance = super().create(validated_data)
            if m2m_choices is not None:
                instance.selected_choices.set(locked_desired_choices)
                # Re-save to trigger IG update for dynamic frameworks
                instance.save()
            return instance

    def update(self, instance, validated_data):
        m2m_choices = validated_data.pop("_m2m_choices", None)
        expected_choice_urns_by_id = validated_data.pop(
            "_m2m_expected_choice_urns_by_id", None
        )
        validated_data.pop("_m2m_visible_choice_ids", None)
        validated_data.pop("selected_choices", None)
        if instance.response_id:
            with transaction.atomic():
                instance = super().update(instance, validated_data)
                if m2m_choices is not None:
                    instance.selected_choices.set(m2m_choices)
                    instance.save()
                return instance
        desired_choice_ids = {
            choice.id for choice in (m2m_choices if m2m_choices is not None else [])
        }
        with transaction.atomic():
            scope = self._lock_answer_scope(
                requirement_assessment_id=instance.requirement_assessment_id,
                question_id=instance.question_id,
                answer_id=instance.id,
                desired_choice_ids=desired_choice_ids,
                expected_choice_urns_by_id=expected_choice_urns_by_id,
            )
            (
                compliance_assessment,
                assignments,
                locked_requirement_assessment,
                locked_answer,
                locked_question,
                locked_choices,
                user_actor_ids,
            ) = scope
            self.instance = locked_answer
            self._assert_locked_answer_authority(
                action="change",
                compliance_assessment=compliance_assessment,
                assignments=assignments,
                requirement_assessment=locked_requirement_assessment,
                answer=locked_answer,
                question=locked_question,
                locked_choices=locked_choices,
                user_actor_ids=user_actor_ids,
                desired_choice_ids=desired_choice_ids,
            )
            locked_choice_by_id = {choice.id: choice for choice in locked_choices}
            locked_desired_choices = [
                locked_choice_by_id[choice_id]
                for choice_id in sorted(desired_choice_ids, key=str)
            ]
            instance = super().update(locked_answer, validated_data)
            if m2m_choices is not None:
                _apply_visible_answer_choice_update(
                    instance,
                    locked_desired_choices,
                    RoleAssignment.get_viewable_object_ids(
                        self.context["request"].user, QuestionChoice
                    ),
                    fail_on_hidden=(
                        instance.question.type == Question.Type.UNIQUE_CHOICE
                    ),
                )
                # Re-save to trigger IG update for dynamic frameworks
                instance.save()
            return instance

    def delete(self, instance):
        if instance.response_id:
            return super().delete(instance)
        with transaction.atomic():
            scope = self._lock_answer_scope(
                requirement_assessment_id=instance.requirement_assessment_id,
                question_id=instance.question_id,
                answer_id=instance.id,
            )
            (
                compliance_assessment,
                assignments,
                locked_requirement_assessment,
                locked_answer,
                locked_question,
                locked_choices,
                user_actor_ids,
            ) = scope
            self.instance = locked_answer
            self._assert_locked_answer_authority(
                action="delete",
                compliance_assessment=compliance_assessment,
                assignments=assignments,
                requirement_assessment=locked_requirement_assessment,
                answer=locked_answer,
                question=locked_question,
                locked_choices=locked_choices,
                user_actor_ids=user_actor_ids,
            )
            return super().delete(locked_answer)

    class Meta:
        model = Answer
        exclude = ["created_at", "updated_at"]


class RequirementMappingSetReadSerializer(BaseModelSerializer):
    # library = FieldsRelatedField(["name", "id"])
    folder = FieldsRelatedField()
    source_framework = serializers.SerializerMethodField()
    target_framework = serializers.SerializerMethodField()
    urn = serializers.SerializerMethodField()
    frameworks_available = serializers.SerializerMethodField()

    class Meta:
        model = StoredLibrary
        fields = [
            "source_framework",
            "target_framework",
            "folder",
            "id",
            "name",
            "description",
            "ref_id",
            "urn",
            "provider",
            "builtin",
            "locale",
            "default_locale",
            "translations",
            "frameworks_available",
        ]

    def _resolve_framework_name(self, urn):
        """Resolve a framework name without widening an API projection.

        Trusted in-process callers historically use this serializer without a
        request and expect names from the stored framework library even when
        the framework has not been imported. DRF always supplies a request;
        that path resolves only an exact-IAM-visible imported Framework.
        """

        request = self.context.get("request")
        if request is None:
            library = StoredLibrary.objects.filter(
                content__framework__urn=urn,
                content__framework__isnull=False,
                content__requirement_mapping_set__isnull=True,
                content__requirement_mapping_sets__isnull=True,
            ).first()
            if library is None:
                return None
            framework = library.content.get("framework") or {}
            return framework.get("name", urn)
        framework = Framework.objects.filter(
            urn=urn,
            id__in=RoleAssignment.get_viewable_object_ids(request.user, Framework),
        ).first()
        if framework is None:
            return None
        return framework.get_name_translated or framework.name or urn

    def _framework_info(self, urn):
        if not urn:
            return {"str": urn, "urn": urn}
        # On list requests the viewset pre-populates `framework_map` (O(1) lookup).
        framework_map = (self.context.get("optimized_data") or {}).get("framework_map")
        if framework_map is not None:
            name = framework_map.get(urn)
        else:
            # Retrieve path: cache per-instance so the duplicate calls from
            # get_frameworks_available don't re-issue the DB lookup.
            cache = self.__dict__.setdefault("_framework_name_cache", {})
            if urn not in cache:
                cache[urn] = self._resolve_framework_name(urn)
            name = cache[urn]
        return {"str": name or urn, "urn": urn}

    def get_source_framework(self, obj):
        mapping_set = obj.content.get(
            "requirement_mapping_sets", [obj.content.get("requirement_mapping_set", {})]
        )[0]
        return self._framework_info(mapping_set.get("source_framework_urn", ""))

    def get_target_framework(self, obj):
        mapping_set = obj.content.get(
            "requirement_mapping_sets", [obj.content.get("requirement_mapping_set", {})]
        )[0]
        return self._framework_info(mapping_set.get("target_framework_urn", ""))

    def get_urn(self, obj):
        rms = obj.content.get(
            "requirement_mapping_sets", [obj.content.get("requirement_mapping_set", {})]
        )
        return rms[0].get("urn") if rms else None

    def get_frameworks_available(self, obj):
        source = self.get_source_framework(obj)
        target = self.get_target_framework(obj)
        # When framework is not found, str equals urn
        return source["str"] != source["urn"] and target["str"] != target["urn"]


class RequirementAssessmentImportExportSerializer(BaseModelSerializer):
    requirement = serializers.SlugRelatedField(slug_field="urn", read_only=True)

    folder = HashSlugRelatedField(slug_field="pk", read_only=True)
    compliance_assessment = HashSlugRelatedField(slug_field="pk", read_only=True)
    evidences = HashSlugRelatedField(slug_field="pk", read_only=True, many=True)
    applied_controls = HashSlugRelatedField(slug_field="pk", read_only=True, many=True)

    class Meta:
        model = RequirementAssessment
        fields = [
            "created_at",
            "updated_at",
            "eta",
            "due_date",
            "folder",
            "status",
            "result",
            "extended_result",
            "score",
            "is_scored",
            "is_score_overridden",
            "documentation_score",
            "target_score",
            "respondent_alignment",
            "review_state",
            "observation",
            "compliance_assessment",
            "requirement",
            "selected",
            "mapping_inference",
            "evidences",
            "applied_controls",
        ]


class RequirementAssignmentEventSerializer(BaseModelSerializer):
    event_actor = FieldsRelatedField(["id", "email", "first_name", "last_name"])

    class Meta:
        model = RequirementAssignmentEvent
        fields = ["id", "event_type", "event_actor", "event_notes", "created_at"]


class AnswerImportExportSerializer(BaseModelSerializer):
    folder = HashSlugRelatedField(slug_field="pk", read_only=True)
    requirement_assessment = HashSlugRelatedField(slug_field="pk", read_only=True)
    response = HashSlugRelatedField(slug_field="pk", read_only=True)
    question = serializers.SlugRelatedField(slug_field="urn", read_only=True)
    selected_choices_urns = serializers.SerializerMethodField()

    def get_selected_choices_urns(self, obj):
        return list(obj.selected_choices.values_list("urn", flat=True))

    class Meta:
        model = Answer
        fields = [
            "created_at",
            "updated_at",
            "folder",
            "requirement_assessment",
            "response",
            "question",
            "value",
            "selected_choices_urns",
        ]


class QuickFormImportExportSerializer(BaseModelSerializer):
    library = serializers.SlugRelatedField(slug_field="urn", read_only=True)

    class Meta:
        model = QuickForm
        fields = [
            "urn",
            "ref_id",
            "name",
            "library",
            "outcomes_definition",
            "scores_definition",
        ]


class QuickFormResponseImportExportSerializer(BaseModelSerializer):
    quick_form = serializers.SlugRelatedField(slug_field="urn", read_only=True)
    folder = HashSlugRelatedField(slug_field="pk", read_only=True)

    class Meta:
        model = QuickFormResponse
        fields = [
            "name",
            "description",
            "folder",
            "quick_form",
            "status",
            "eta",
            "due_date",
            "computed_outcome",
            "score",
            "started_at",
            "submitted_at",
            "observation",
            "created_at",
            "updated_at",
        ]


class FindingsAssessmentImportExportSerializer(BaseModelSerializer):
    folder = HashSlugRelatedField(slug_field="pk", read_only=True)
    perimeter = HashSlugRelatedField(slug_field="pk", read_only=True)
    evidences = HashSlugRelatedField(slug_field="pk", read_only=True, many=True)
    compliance_assessment = HashSlugRelatedField(slug_field="pk", read_only=True)

    class Meta:
        model = FindingsAssessment
        fields = [
            "ref_id",
            "name",
            "description",
            "version",
            "status",
            "eta",
            "due_date",
            "reported_at",
            "observation",
            "category",
            "is_locked",
            "folder",
            "perimeter",
            "evidences",
            "compliance_assessment",
            "created_at",
            "updated_at",
        ]


class FindingImportExportSerializer(BaseModelSerializer):
    folder = HashSlugRelatedField(slug_field="pk", read_only=True)
    findings_assessment = HashSlugRelatedField(slug_field="pk", read_only=True)
    asset = HashSlugRelatedField(slug_field="pk", read_only=True)
    requirement_node = serializers.SlugRelatedField(slug_field="urn", read_only=True)
    threats = HashSlugRelatedField(slug_field="pk", read_only=True, many=True)
    vulnerabilities = HashSlugRelatedField(slug_field="pk", read_only=True, many=True)
    reference_controls = HashSlugRelatedField(
        slug_field="pk", read_only=True, many=True
    )
    applied_controls = HashSlugRelatedField(slug_field="pk", read_only=True, many=True)
    evidences = HashSlugRelatedField(slug_field="pk", read_only=True, many=True)

    class Meta:
        model = Finding
        fields = [
            "ref_id",
            "name",
            "description",
            "severity",
            "status",
            "priority",
            "observation",
            "eta",
            "due_date",
            "folder",
            "findings_assessment",
            "asset",
            "requirement_node",
            "threats",
            "vulnerabilities",
            "reference_controls",
            "applied_controls",
            "evidences",
            "created_at",
            "updated_at",
        ]


class RiskAcceptanceImportExportSerializer(BaseModelSerializer):
    folder = HashSlugRelatedField(slug_field="pk", read_only=True)
    risk_scenarios = HashSlugRelatedField(slug_field="pk", read_only=True, many=True)

    class Meta:
        model = RiskAcceptance
        fields = [
            "name",
            "description",
            "state",
            "expiry_date",
            "accepted_at",
            "rejected_at",
            "revoked_at",
            "justification",
            "folder",
            "risk_scenarios",
            "created_at",
            "updated_at",
        ]


class SecurityExceptionImportExportSerializer(BaseModelSerializer):
    folder = HashSlugRelatedField(slug_field="pk", read_only=True)
    assets = HashSlugRelatedField(slug_field="pk", read_only=True, many=True)
    applied_controls = HashSlugRelatedField(slug_field="pk", read_only=True, many=True)
    vulnerabilities = HashSlugRelatedField(slug_field="pk", read_only=True, many=True)
    risk_scenarios = HashSlugRelatedField(slug_field="pk", read_only=True, many=True)
    requirement_assessments = HashSlugRelatedField(
        slug_field="pk", read_only=True, many=True
    )

    class Meta:
        model = SecurityException
        fields = [
            "ref_id",
            "name",
            "description",
            "severity",
            "status",
            "expiration_date",
            "observation",
            "link",
            "folder",
            "assets",
            "applied_controls",
            "vulnerabilities",
            "risk_scenarios",
            "requirement_assessments",
            "created_at",
            "updated_at",
        ]


class IncidentImportExportSerializer(BaseModelSerializer):
    folder = HashSlugRelatedField(slug_field="pk", read_only=True)
    threats = HashSlugRelatedField(slug_field="pk", read_only=True, many=True)
    assets = HashSlugRelatedField(slug_field="pk", read_only=True, many=True)
    entities = HashSlugRelatedField(slug_field="pk", read_only=True, many=True)

    class Meta:
        model = Incident
        fields = [
            "ref_id",
            "name",
            "description",
            "status",
            "severity",
            "reported_at",
            "detection",
            "link",
            "occurred_at",
            "resolved_at",
            "resolution",
            "is_bcp_activated",
            "folder",
            "threats",
            "assets",
            "entities",
            "created_at",
            "updated_at",
        ]


class CampaignImportExportSerializer(BaseModelSerializer):
    folder = HashSlugRelatedField(slug_field="pk", read_only=True)
    frameworks = serializers.SlugRelatedField(
        slug_field="urn", read_only=True, many=True
    )
    perimeters = HashSlugRelatedField(slug_field="pk", read_only=True, many=True)
    entities = HashSlugRelatedField(slug_field="pk", read_only=True, many=True)

    class Meta:
        model = Campaign
        fields = [
            "name",
            "description",
            "kind",
            "status",
            "start_date",
            "eta",
            "due_date",
            "selected_implementation_groups",
            "folder",
            "frameworks",
            "perimeters",
            "entities",
            "created_at",
            "updated_at",
        ]


class TaskTemplateImportExportSerializer(BaseModelSerializer):
    folder = HashSlugRelatedField(slug_field="pk", read_only=True)
    evidences = HashSlugRelatedField(slug_field="pk", read_only=True, many=True)
    assets = HashSlugRelatedField(slug_field="pk", read_only=True, many=True)
    applied_controls = HashSlugRelatedField(slug_field="pk", read_only=True, many=True)
    compliance_assessments = HashSlugRelatedField(
        slug_field="pk", read_only=True, many=True
    )
    requirement_assessments = HashSlugRelatedField(
        slug_field="pk", read_only=True, many=True
    )
    risk_assessments = HashSlugRelatedField(slug_field="pk", read_only=True, many=True)
    findings_assessment = HashSlugRelatedField(
        slug_field="pk", read_only=True, many=True
    )

    class Meta:
        model = TaskTemplate
        fields = [
            "ref_id",
            "name",
            "description",
            "task_date",
            "is_recurrent",
            "schedule",
            "enabled",
            "link",
            "folder",
            "evidences",
            "assets",
            "applied_controls",
            "compliance_assessments",
            "requirement_assessments",
            "risk_assessments",
            "findings_assessment",
            "created_at",
            "updated_at",
        ]


class TaskNodeImportExportSerializer(BaseModelSerializer):
    folder = HashSlugRelatedField(slug_field="pk", read_only=True)
    task_template = HashSlugRelatedField(slug_field="pk", read_only=True)
    evidences = HashSlugRelatedField(slug_field="pk", read_only=True, many=True)

    class Meta:
        model = TaskNode
        fields = [
            "due_date",
            "scheduled_date",
            "status",
            "observation",
            "to_delete",
            "folder",
            "task_template",
            "evidences",
            "created_at",
            "updated_at",
        ]


class RequirementAssignmentReadSerializer(BaseModelSerializer):
    folder = FieldsRelatedField()
    compliance_assessment = FieldsRelatedField()
    actor = FieldsRelatedField(many=True)
    requirement_assessments = FieldsRelatedField(["id", "review_state"], many=True)
    events = RequirementAssignmentEventSerializer(many=True, read_only=True)

    class Meta:
        model = RequirementAssignment
        fields = "__all__"


class RequirementAssignmentWriteSerializer(BaseModelSerializer):
    compliance_assessment = RequirementAssignmentComplianceAssessmentField(
        queryset=ComplianceAssessment.objects.all()
    )
    # Assignment security follows its ComplianceAssessment. Accept a matching
    # legacy client value below, but never persist a client-selected Folder as
    # an independent authority root.
    folder = serializers.PrimaryKeyRelatedField(read_only=True)
    actor = RequirementAssignmentAuthorityPrimaryKeyRelatedField(
        queryset=Actor.objects.all(),
        authority_model=Actor,
        many=True,
        allow_empty=False,
    )
    requirement_assessments = RequirementAssignmentAuthorityPrimaryKeyRelatedField(
        queryset=RequirementAssessment.objects.all(),
        authority_model=RequirementAssessment,
        many=True,
        required=False,
    )

    def to_internal_value(self, data):
        _assert_raw_immutable_relation_ids(
            self.instance, data, ("compliance_assessment", "folder")
        )
        attrs = super().to_internal_value(data)
        if self.instance is None:
            assessment = attrs.get("compliance_assessment")
            if assessment is None:
                raise PermissionDenied(_ASSIGNMENT_PARENT_UNAVAILABLE)
            if "folder" in data:
                submitted_folder_id = _normalize_related_uuid(
                    data.get("folder"), detail=_ASSIGNMENT_PARENT_UNAVAILABLE
                )
                if submitted_folder_id != assessment.folder_id:
                    raise PermissionDenied(_ASSIGNMENT_PARENT_UNAVAILABLE)
            self._assignment_parent_snapshot = (
                assessment.id,
                assessment.folder_id,
            )
        return attrs

    class Meta:
        model = RequirementAssignment
        fields = "__all__"
        read_only_fields = ["status"]

    def validate_compliance_assessment(self, value):
        self._ensure_immutable("compliance_assessment", value)
        return value

    def validate_folder(self, value):
        self._ensure_immutable("folder", value)
        return value

    @staticmethod
    def _assert_requirement_assessments_belong_to_assessment(
        *, user, compliance_assessment, requirement_assessments
    ) -> None:
        rows = tuple(requirement_assessments)
        if not rows:
            return
        if any(
            row.compliance_assessment_id != compliance_assessment.id for row in rows
        ):
            raise PermissionDenied(_ASSIGNMENT_RELATION_UNAVAILABLE)

    @staticmethod
    def _assert_relation_visibility(*, user, model, object_ids) -> None:
        requested_ids = set(object_ids)
        if not requested_ids:
            return
        try:
            visible_ids = set(
                RequirementAssignmentAuthorityPrimaryKeyRelatedField.visible_queryset(
                    user=user,
                    authority_model=model,
                    object_ids=requested_ids,
                ).values_list("id", flat=True)
            )
        except NotImplementedError, Permission.DoesNotExist:
            visible_ids = set()
        if visible_ids != requested_ids:
            raise PermissionDenied(_ASSIGNMENT_RELATION_UNAVAILABLE)

    def create(self, validated_data):
        """Bind and reprove the Assignment parent under a deterministic lock."""

        request = self.context.get("request")
        user = getattr(request, "user", None)
        snapshot = getattr(self, "_assignment_parent_snapshot", None)
        if not getattr(user, "is_authenticated", False) or snapshot is None:
            raise PermissionDenied(_ASSIGNMENT_PARENT_UNAVAILABLE)
        assessment_id, folder_id = snapshot

        with transaction.atomic():
            locked_folder = (
                Folder.objects.select_for_update().filter(id=folder_id).first()
            )
            locked_assessment = (
                ComplianceAssessment.objects.select_for_update(of=("self",))
                .filter(id=assessment_id, folder_id=folder_id)
                .first()
            )
            try:
                assessment_is_visible = (
                    locked_assessment is not None
                    and ComplianceAssessment.objects.filter(
                        id=locked_assessment.id,
                        id__in=RoleAssignment.get_viewable_object_ids(
                            user, ComplianceAssessment
                        ),
                    ).exists()
                )
                can_add = (
                    locked_folder is not None
                    and assessment_is_visible
                    and RoleAssignment.is_access_allowed(
                        user=user,
                        perm=(
                            RequirementAssignmentComplianceAssessmentField._add_permission()
                        ),
                        folder=locked_folder,
                    )
                )
            except NotImplementedError, Permission.DoesNotExist:
                can_add = False
            if not can_add:
                raise PermissionDenied(_ASSIGNMENT_PARENT_UNAVAILABLE)

            requested_actors = tuple(validated_data.get("actor", ()))
            requested_assessments = tuple(
                validated_data.get("requirement_assessments", ())
            )
            actor_ids = {actor.id for actor in requested_actors}
            requirement_assessment_ids = {row.id for row in requested_assessments}
            locked_requirement_assessments = list(
                RequirementAssessment.objects.select_for_update()
                .filter(id__in=requirement_assessment_ids)
                .order_by("pk")
            )
            locked_actors = list(
                Actor.objects.select_for_update()
                .filter(id__in=actor_ids)
                .order_by("pk")
            )
            if {
                row.id for row in locked_requirement_assessments
            } != requirement_assessment_ids or {
                actor.id for actor in locked_actors
            } != actor_ids:
                raise PermissionDenied(_ASSIGNMENT_RELATION_UNAVAILABLE)
            self._assert_relation_visibility(
                user=user,
                model=RequirementAssessment,
                object_ids=requirement_assessment_ids,
            )
            self._assert_relation_visibility(
                user=user,
                model=Actor,
                object_ids=actor_ids,
            )
            self._assert_requirement_assessments_belong_to_assessment(
                user=user,
                compliance_assessment=locked_assessment,
                requirement_assessments=locked_requirement_assessments,
            )
            if RequirementAssignment.objects.filter(
                compliance_assessment=locked_assessment,
                requirement_assessments__in=locked_requirement_assessments,
            ).exists():
                raise serializers.ValidationError(
                    {
                        "requirement_assessments": "Some requirement assessments are already assigned to another assignment."
                    }
                )

            locked_data = dict(validated_data)
            locked_data["compliance_assessment"] = locked_assessment
            locked_data["folder"] = locked_folder
            locked_data["actor"] = locked_actors
            locked_data["requirement_assessments"] = locked_requirement_assessments
            return super().create(locked_data)

    def validate(self, attrs):
        """
        Validate that requirement assessments belong to the specified compliance assessment
        and are not already assigned to another assignment.
        """
        compliance_assessment = attrs.get(
            "compliance_assessment",
            getattr(self.instance, "compliance_assessment", None),
        )
        requirement_assessments = attrs.get("requirement_assessments", [])

        if compliance_assessment and requirement_assessments:
            request = self.context.get("request")
            user = getattr(request, "user", None)
            if not getattr(user, "is_authenticated", False):
                raise PermissionDenied(_ASSIGNMENT_RELATION_UNAVAILABLE)
            self._assert_requirement_assessments_belong_to_assessment(
                user=user,
                compliance_assessment=compliance_assessment,
                requirement_assessments=requirement_assessments,
            )

            # Check that requirement assessments are not already assigned to another assignment
            existing_assignment_ids = (
                RequirementAssignment.objects.filter(
                    compliance_assessment=compliance_assessment,
                    requirement_assessments__in=requirement_assessments,
                )
                .exclude(id=self.instance.id if self.instance else None)
                .values_list("id", flat=True)
                .distinct()
            )

            if existing_assignment_ids:
                raise serializers.ValidationError(
                    {
                        "requirement_assessments": "Some requirement assessments are already assigned to another assignment."
                    }
                )

        return super().validate(attrs)


class RequirementMappingSetWriteSerializer(RequirementMappingSetReadSerializer):
    pass


class ComputeMappingSerializer(serializers.Serializer):
    mapping_set = serializers.PrimaryKeyRelatedField(
        queryset=RequirementMappingSet.objects.all()
    )
    source_assessment = serializers.PrimaryKeyRelatedField(
        queryset=ComplianceAssessment.objects.all()
    )


class FilteringLabelReadSerializer(BaseModelSerializer):
    path = PathField(read_only=True)
    folder = FieldsRelatedField()

    class Meta:
        model = FilteringLabel
        fields = "__all__"


class FilteringLabelWriteSerializer(BaseModelSerializer):
    class Meta:
        model = FilteringLabel
        exclude = ["folder"]


class LibraryFilteringLabelReadSerializer(BaseModelSerializer):
    path = PathField(read_only=True)
    folder = FieldsRelatedField()

    class Meta:
        model = LibraryFilteringLabel
        fields = "__all__"


class LibraryFilteringLabelWriteSerializer(BaseModelSerializer):
    class Meta:
        model = LibraryFilteringLabel
        exclude = ["folder"]


class SecurityExceptionWriteSerializer(
    RequirementAssessmentRelationshipAuthorityMixin,
    CustomFieldsSerializerMixin,
    BaseModelSerializer,
):
    genericcollection = serializers.PrimaryKeyRelatedField(
        source="genericcollection_set",
        many=True,
        required=False,
        queryset=GenericCollection.objects.all(),
    )
    requirement_assessments = GovernedRequirementAssessmentPrimaryKeyRelatedField(
        many=True, queryset=RequirementAssessment.objects.all(), required=False
    )
    applied_controls = serializers.PrimaryKeyRelatedField(
        many=True, queryset=AppliedControl.objects.all(), required=False
    )
    assets = serializers.PrimaryKeyRelatedField(
        many=True, queryset=Asset.objects.all(), required=False
    )
    evidences = serializers.PrimaryKeyRelatedField(
        many=True, queryset=Evidence.objects.all(), required=False
    )

    def create(self, validated_data):
        with transaction.atomic():
            owner_data = validated_data.get("owners", [])
            security_exception = super().create(validated_data)

            # Notify newly assigned owners
            if owner_data:
                self._send_assignment_notifications(
                    security_exception, [actor.id for actor in owner_data]
                )

            return security_exception

    def update(self, instance, validated_data):
        with transaction.atomic():
            governed_relationship = "requirement_assessments" in validated_data
            if governed_relationship:
                old_owner_ids = None
                old_status = None
            else:
                old_owner_ids = set(instance.owners.values_list("id", flat=True))
                old_status = instance.status

            updated_instance = super().update(instance, validated_data)

            if governed_relationship:
                old_status = self._governed_locked_scalar_snapshot["status"]
            else:
                new_owner_ids = set(
                    updated_instance.owners.values_list("id", flat=True)
                )
                newly_assigned_ids = new_owner_ids - old_owner_ids
                if newly_assigned_ids:
                    self._send_assignment_notifications(
                        updated_instance, list(newly_assigned_ids)
                    )

            # Notify owners and approver on status change
            if updated_instance.status != old_status:
                self._send_status_notification(updated_instance)

            return updated_instance

    def _send_assignment_notifications(self, security_exception, owner_ids):
        """Send assignment notifications to the specified owners"""
        if not owner_ids:
            return

        try:
            from core.models import Actor
            from .tasks import send_security_exception_assignment_notification

            assigned_actors = Actor.objects.filter(id__in=owner_ids)
            assigned_emails = []
            for actor in assigned_actors:
                assigned_emails.extend(actor.get_emails())

            # Dedupe (several actors can resolve to the same email) and defer until
            # the transaction commits, so a rollback doesn't send spurious emails.
            unique_emails = list(dict.fromkeys(filter(None, assigned_emails)))
            if unique_emails:
                exception_id = security_exception.id

                def enqueue_assignment_notification():
                    try:
                        send_security_exception_assignment_notification(
                            exception_id, unique_emails
                        )
                    except Exception as exc:
                        logger.error(
                            "Failed to queue SecurityException assignment notification",
                            error_type=type(exc).__name__,
                        )

                transaction.on_commit(enqueue_assignment_notification)
        except Exception as e:
            logger.error(
                f"Failed to send SecurityException assignment notification: {str(e)}"
            )

    def _send_status_notification(self, security_exception):
        """Notify owners when the status changes"""
        try:
            from .tasks import send_security_exception_status_notification

            recipient_emails = []
            for owner in security_exception.owners.all():
                recipient_emails.extend(owner.get_emails())

            if not recipient_emails:
                return

            request = self.context.get("request")
            actor_name = "System"
            if request and getattr(request, "user", None):
                user = request.user
                actor_name = (
                    f"{user.first_name} {user.last_name}".strip()
                    if (user.first_name or user.last_name)
                    else user.email
                )

            exception_id = security_exception.id
            new_status = security_exception.get_status_display()

            def enqueue_status_notification():
                try:
                    send_security_exception_status_notification(
                        exception_id, new_status, actor_name, recipient_emails
                    )
                except Exception as exc:
                    logger.error(
                        "Failed to queue SecurityException status notification",
                        error_type=type(exc).__name__,
                    )

            transaction.on_commit(enqueue_status_notification)
        except Exception as e:
            logger.error(
                f"Failed to send SecurityException status notification: {str(e)}"
            )

    class Meta:
        model = SecurityException
        fields = "__all__"
        list_serializer_class = (
            RequirementAssessmentRelationshipProjectionListSerializer
        )
        # Deprecated: approval is handled through validation flows. The field is
        # kept read-only so existing values remain visible without new writes.
        read_only_fields = ["approver"]


class ProducedFromMixin(serializers.Serializer):
    """`produced_from` on any read serializer whose model can be created by automation.

    One indexed query against `ProducedObjectLink`, so adding it to another model costs
    a mixin and nothing else. Answers "where did this record come from?" — the half of
    provenance that a register needs and a forward-only link cannot give.
    """

    produced_from = serializers.SerializerMethodField()

    def get_produced_from(self, obj) -> list[dict]:
        from core.models import ProducedObjectLink

        return [
            link.describe(link.source_object)
            for link in ProducedObjectLink.produced_by(obj)
            if link.source_object is not None
        ]


class SecurityExceptionReadSerializer(
    ProducedFromMixin,
    RequirementAssessmentRelationshipProjectionMixin,
    CustomFieldsSerializerMixin,
    BaseModelSerializer,
):
    # Two bases declare FLAGGED_FIELDS and the MRO picks a winner silently. Stating it
    # here means a future change to the base order cannot quietly drop custom-field
    # flagging on this serializer.
    FLAGGED_FIELDS = CustomFieldsSerializerMixin.FLAGGED_FIELDS
    path = PathField(read_only=True)
    folder = FieldsRelatedField()
    owners = FieldsRelatedField(many=True)
    approver = FieldsRelatedField()
    severity = serializers.CharField(source="get_severity_display")
    associated_objects_count = serializers.SerializerMethodField()
    assets = FieldsRelatedField(many=True)
    evidences = FieldsRelatedField(many=True)
    requirement_assessments = FieldsRelatedField(many=True)
    validation_flows = FieldsRelatedField(
        many=True,
        fields=[
            "id",
            "ref_id",
            "status",
            "request_notes",
            "last_event_notes",
            {"approver": ["id", "email", "first_name", "last_name"]},
        ],
        source="validationflow_set",
    )

    def get_associated_objects_count(self, obj):
        """Count only caller-projectable requirement-assessment links."""
        projected_ra_count = len(self._projected_requirement_assessment_ids(obj))
        try:
            # Uses prefetch cache when available (no extra queries)
            return (
                len(obj.assets.all())
                + len(obj.applied_controls.all())
                + len(obj.vulnerabilities.all())
                + len(obj.risk_scenarios.all())
                + projected_ra_count
                + len(obj.evidences.all())
            )
        except Exception:
            # Fallback: perform DB counts
            return (
                obj.assets.count()
                + obj.applied_controls.count()
                + obj.vulnerabilities.count()
                + obj.risk_scenarios.count()
                + projected_ra_count
                + obj.evidences.count()
            )

    class Meta:
        model = SecurityException
        fields = "__all__"
        list_serializer_class = (
            RequirementAssessmentRelationshipProjectionListSerializer
        )


class FindingsAssessmentWriteSerializer(BaseModelSerializer):
    genericcollection = serializers.PrimaryKeyRelatedField(
        source="genericcollection_set",
        many=True,
        required=False,
        queryset=GenericCollection.objects.all(),
    )

    def validate(self, attrs):
        if hasattr(self, "instance") and self.instance and self.instance.is_locked:
            # If we're unlocking (setting is_locked to False), allow the operation
            if "is_locked" in attrs and attrs["is_locked"] is False:
                return super().validate(attrs)

            # Otherwise, only allow modifying the is_locked field
            locked_fields = [field for field in attrs.keys() if field != "is_locked"]
            if locked_fields:
                raise serializers.ValidationError(
                    f"⚠️ Cannot modify the findings assessment attributes when it is locked. Only the 'Locked' field can be modified."
                )
        return super().validate(attrs)

    def update(self, instance, validated_data):
        # Track old folder before update
        old_folder_id = instance.folder_id
        # Check if status is changing to deprecated
        old_status = instance.status
        new_status = validated_data.get("status", old_status)

        # Auto-lock when status changes to deprecated
        if old_status != "deprecated" and new_status == "deprecated":
            validated_data["is_locked"] = True

        # If perimeter is being changed, update folder to match the new perimeter's folder
        if "perimeter" in validated_data:
            new_perimeter = validated_data["perimeter"]
            if new_perimeter and new_perimeter.folder:
                validated_data["folder"] = new_perimeter.folder

        with transaction.atomic():
            updated_instance = super().update(instance, validated_data)

            # Cascade folder change to findings
            if old_folder_id != updated_instance.folder_id:
                Finding.objects.filter(findings_assessment=updated_instance).update(
                    folder=updated_instance.folder
                )

        return updated_instance

    class Meta:
        model = FindingsAssessment
        exclude = ["created_at", "updated_at"]


class FindingsAssessmentReadSerializer(AssessmentReadSerializer):
    path = PathField(read_only=True)
    folder = FieldsRelatedField()
    # The audit this binder captures findings for — the way back.
    compliance_assessment = FieldsRelatedField()
    findings_count = serializers.IntegerField(source="findings.count")
    treatment_progress = serializers.IntegerField(read_only=True, default=0)
    evidences = FieldsRelatedField(many=True)
    filtering_labels = FieldsRelatedField(["id", "folder"], many=True)
    validation_flows = FieldsRelatedField(
        many=True,
        fields=[
            "id",
            "ref_id",
            "status",
            "request_notes",
            "last_event_notes",
            {"approver": ["id", "email", "first_name", "last_name"]},
        ],
        source="validationflow_set",
    )

    class Meta:
        model = FindingsAssessment
        fields = "__all__"


class FindingWriteSerializer(BaseModelSerializer):
    requirement_assessment = GovernedRequirementAssessmentPrimaryKeyRelatedField(
        queryset=RequirementAssessment.objects.all(),
        required=False,
        allow_null=True,
        policy_field="findings",
    )
    # Reverse M2M (declared on TaskTemplate): DRF does not pick it up from Meta.
    task_templates = serializers.PrimaryKeyRelatedField(
        many=True, required=False, queryset=TaskTemplate.objects.all()
    )

    def to_internal_value(self, data):
        """Derive the catalog node before DRF resolves a client-supplied one.

        A bound finding's node is owned by its RequirementAssessment.  Dropping
        an echoed/mismatched node UUID here avoids turning that redundant input
        into a visibility oracle; unbound findings retain the upstream ability
        to select a standalone requirement node.
        """

        self._derive_requirement_node = False
        relation_submitted = "requirement_assessment" in data
        submitted_relation = data.get("requirement_assessment")
        current_relation_id = getattr(
            getattr(self, "instance", None), "requirement_assessment_id", None
        )
        if (relation_submitted and submitted_relation not in (None, "")) or (
            not relation_submitted
            and current_relation_id is not None
            and "requirement_node" in data
        ):
            data = data.copy()
            data.pop("requirement_node", None)
            self._derive_requirement_node = True
        return super().to_internal_value(data)

    def validate(self, attrs):
        current_assessment = getattr(self.instance, "findings_assessment", None)
        if current_assessment and current_assessment.is_locked:
            raise serializers.ValidationError(
                "⚠️ Cannot modify the finding when the findings assessment is locked."
            )
        target_assessment = attrs.get("findings_assessment")
        if target_assessment and target_assessment.is_locked:
            raise serializers.ValidationError(
                {
                    "findings_assessment": "⚠️ Cannot attach the finding to a locked findings assessment."
                }
            )
        # Same rule as the findings-binder endpoint, for direct API writes.
        target_requirement_assessment = attrs.get("requirement_assessment")
        if target_requirement_assessment and target_requirement_assessment.is_locked:
            raise serializers.ValidationError(
                {
                    "requirement_assessment": "⚠️ Cannot bind a finding to a requirement of a locked audit."
                }
            )

        relation_submitted = "requirement_assessment" in attrs
        current_requirement_assessment = getattr(
            self.instance, "requirement_assessment", None
        )
        effective_requirement_assessment = (
            attrs["requirement_assessment"]
            if relation_submitted
            else current_requirement_assessment
        )
        if relation_submitted or getattr(self, "_derive_requirement_node", False):
            affected_rows = {
                row.id: row
                for row in (
                    current_requirement_assessment,
                    effective_requirement_assessment,
                )
                if row is not None
            }
            request = self.context.get("request")
            assert_requirement_assessment_rows_editable(
                user=getattr(request, "user", None),
                rows=affected_rows.values(),
                policy_field="findings",
            )
            if effective_requirement_assessment is not None:
                attrs["requirement_node"] = effective_requirement_assessment.requirement

        return super().validate(attrs)

    class Meta:
        model = Finding
        exclude = ["created_at", "updated_at"]

    def create(self, validated_data):
        findings_assessment = validated_data.get("findings_assessment")
        if findings_assessment:
            validated_data["folder"] = findings_assessment.folder
        elif not validated_data.get("folder"):
            raise serializers.ValidationError(
                {
                    "folder": "A domain is required for a finding without a findings assessment."
                }
            )
        task_templates = validated_data.pop("task_templates", [])

        finding = super().create(validated_data)
        if task_templates:
            finding.task_templates.set(task_templates)

        return finding

    def update(self, instance, validated_data):
        task_templates = validated_data.pop("task_templates", None)
        reparented = "findings_assessment" in validated_data
        findings_assessment = (
            validated_data["findings_assessment"]
            if reparented
            else instance.findings_assessment
        )
        previous_assessment = instance.findings_assessment

        if findings_assessment:
            # A bound finding lives in its assessment's folder: moving it means
            # detaching it, or moving the assessment.
            if (
                not reparented
                and "folder" in validated_data
                and validated_data["folder"] != instance.folder
            ):
                raise serializers.ValidationError(
                    {
                        "folder": "Detach the finding from its findings assessment to move it to another domain."
                    }
                )
            if findings_assessment.folder != instance.folder:
                self._check_object_perm(
                    instance, "add", folder=findings_assessment.folder
                )
            validated_data["folder"] = findings_assessment.folder

        updated_instance = super().update(instance, validated_data)

        if task_templates is not None:
            updated_instance.task_templates.set(task_templates)

        if previous_assessment and previous_assessment != findings_assessment:
            previous_assessment.upsert_daily_metrics()

        return updated_instance


class FindingReadListSerializer(serializers.ListSerializer):
    """Prime singular RequirementAssessment projections once for a finding page."""

    def to_representation(self, data):
        instances = list(data.all() if hasattr(data, "all") else data)
        if "requirement_assessment" in self.child.fields:
            self.child._prime_requirement_assessment_projection(instances)
        return super().to_representation(instances)


class FindingReadSerializer(FindingWriteSerializer):
    path = PathField(read_only=True)
    owner = FieldsRelatedField(many=True)
    findings_assessment = FieldsRelatedField(["id", "name", "is_locked"])
    # No standalone page exists for requirement nodes: omit "id" so the
    # generic detail view renders plain text instead of a dead link.
    requirement_node = FieldsRelatedField(["ref_id", "name"])
    # This one does have a page — it is the way back to what raised the finding.
    # Resolve it only after the audit assignment and field-visibility projection;
    # a generic Finding folder grant is not transitive to its linked audit row.
    requirement_assessment = serializers.SerializerMethodField()
    asset = FieldsRelatedField()
    threats = FieldsRelatedField(many=True)
    vulnerabilities = FieldsRelatedField(many=True)
    reference_controls = FieldsRelatedField(many=True)
    applied_controls = FieldsRelatedField(["id", "status"], many=True)
    filtering_labels = FieldsRelatedField(many=True)
    evidences = FieldsRelatedField(many=True)
    task_templates = FieldsRelatedField(many=True)
    perimeter = FieldsRelatedField(
        source="findings_assessment.perimeter",
        fields=["id", "name", "folder"],
        allow_null=True,
    )
    folder = FieldsRelatedField()
    severity = serializers.CharField(source="get_severity_display")
    priority = serializers.CharField(source="get_priority_display")

    class Meta:
        model = Finding
        fields = "__all__"
        list_serializer_class = FindingReadListSerializer

    def _requirement_assessment_projection_key(self, row_id):
        request = self.context.get("request")
        user = getattr(request, "user", None) if request is not None else None
        return getattr(user, "pk", None), row_id

    def _prime_requirement_assessment_projection(self, instances) -> None:
        request = self.context.get("request")
        user = getattr(request, "user", None) if request is not None else None
        if not getattr(user, "is_authenticated", False):
            return
        row_ids = {
            instance.requirement_assessment_id
            for instance in instances
            if instance.requirement_assessment_id is not None
        }
        if not row_ids:
            return
        visible = visible_requirement_assessment_rows(
            user=user,
            ra_ids=row_ids,
            policy_field="findings",
        )
        cache = self.context.setdefault("_finding_ra_projection_cache", {})
        for row_id in row_ids:
            cache[self._requirement_assessment_projection_key(row_id)] = visible.get(
                row_id
            )

    def get_requirement_assessment(self, instance):
        row_id = instance.requirement_assessment_id
        if row_id is None:
            return None
        request = self.context.get("request")
        user = getattr(request, "user", None) if request is not None else None
        if not getattr(user, "is_authenticated", False):
            return None

        cache = self.context.setdefault("_finding_ra_projection_cache", {})
        key = self._requirement_assessment_projection_key(row_id)
        if key not in cache:
            visible = visible_requirement_assessment_rows(
                user=user,
                ra_ids=(row_id,),
                policy_field="findings",
            )
            cache[key] = visible.get(row_id)
        row = cache[key]
        if row is None:
            return None
        return {"str": str(row), "id": row.id}


class CommitmentReadSerializer(BaseModelSerializer):
    """The cross-model register: every promise, whoever it is about."""

    folder = FieldsRelatedField()
    committed_by = FieldsRelatedField()
    target = serializers.SerializerMethodField()
    target_type = serializers.SerializerMethodField()
    is_breached = serializers.BooleanField(read_only=True)

    def get_target(self, obj):
        target = obj.target
        if target is None:
            return None
        return {"id": str(target.id), "str": str(target)}

    def get_target_type(self, obj):
        return obj.content_type.model

    class Meta:
        model = Commitment
        exclude = ["content_type", "object_id"]


class PresetReadSerializer(BaseModelSerializer):
    folder = FieldsRelatedField()
    is_user_authored = serializers.SerializerMethodField()
    scaffolded_objects = serializers.SerializerMethodField()

    class Meta:
        model = Preset
        fields = [
            "id",
            "name",
            "description",
            "urn",
            "ref_id",
            "version",
            "provider",
            "translations",
            "profile",
            "feature_flags",
            "dependencies",
            "folder",
            "is_user_authored",
            "scaffolded_objects",
            "created_at",
            "updated_at",
        ]

    def get_is_user_authored(self, obj) -> bool:
        return obj.urn is None

    def get_scaffolded_objects(self, obj):
        items = obj.scaffolded_objects or []
        if not items:
            return []
        from collections import Counter

        counts = Counter(item.get("type") for item in items if item.get("type"))
        return [{"type": t, "count": c} for t, c in counts.items()]


class PresetWriteSerializer(BaseModelSerializer):
    class Meta:
        model = Preset
        fields = [
            "name",
            "description",
            "folder",
            "translations",
            "profile",
            "feature_flags",
            "dependencies",
            "scaffolded_objects",
            "steps",
        ]


class PresetJourneyStepReadSerializer(BaseModelSerializer):
    title = serializers.CharField(source="get_title_translated")
    description = serializers.CharField(
        source="get_description_translated", allow_blank=True
    )

    class Meta:
        model = PresetJourneyStep
        exclude = ["translations"]


class PresetJourneyStepWriteSerializer(BaseModelSerializer):
    class Meta:
        model = PresetJourneyStep
        fields = ["status", "notes", "target_ref"]

    def update(self, instance, validated_data):
        if "status" in validated_data:
            new_status = validated_data["status"]
            if new_status in (
                PresetJourneyStep.Status.DONE,
                PresetJourneyStep.Status.SKIPPED,
            ):
                validated_data["completed_at"] = timezone.now()
                validated_data["completed_by"] = self.context["request"].user
            elif new_status == PresetJourneyStep.Status.NOT_STARTED:
                validated_data["completed_at"] = None
                validated_data["completed_by"] = None

        with transaction.atomic():
            journey = instance.journey
            update_fields = ["updated_at"]
            # Sync target_ref change to parent journey's object_refs
            if "target_ref" in validated_data:
                new_ref = validated_data["target_ref"]
                object_refs = dict(journey.object_refs or {})
                if new_ref:
                    object_refs[instance.key] = new_ref
                else:
                    object_refs.pop(instance.key, None)
                journey.object_refs = object_refs
                update_fields.append("object_refs")
            # Bump journey.updated_at on every step edit so the catalog's
            # "recently active" list surfaces it.
            journey.save(update_fields=update_fields)

            return super().update(instance, validated_data)


class PresetJourneyReadSerializer(BaseModelSerializer):
    steps = PresetJourneyStepReadSerializer(many=True, read_only=True)
    folder = FieldsRelatedField()
    preset = FieldsRelatedField(["id", "name", "urn", "version"])
    applied_by = FieldsRelatedField(["id", "email"])
    latest_version = serializers.SerializerMethodField()

    class Meta:
        model = PresetJourney
        fields = "__all__"

    def get_latest_version(self, obj):
        if not obj.preset:
            return obj.applied_version
        if obj.preset.urn:
            # The Preset row can lag behind a newer stored library; `upgrade`
            # upserts from it, so the badge must look at the same source.
            # Cached on the shared root context so a list costs one query per
            # distinct URN rather than one per journey.
            cache = self.context.setdefault("_stored_versions", {})
            if obj.preset.urn not in cache:
                cache[obj.preset.urn] = (
                    StoredLibrary.objects.filter(urn=obj.preset.urn)
                    .order_by("-version")
                    .values_list("version", flat=True)
                    .first()
                )
            stored_version = cache[obj.preset.urn]
            if stored_version:
                return max(stored_version, obj.preset.version)
        return obj.preset.version


class PresetJourneyWriteSerializer(BaseModelSerializer):
    class Meta:
        model = PresetJourney
        fields = ["name", "description"]


class QuickStartSerializer(serializers.Serializer):
    folder = serializers.UUIDField(required=False)
    audit_name = serializers.CharField()
    framework = serializers.CharField()
    create_risk_assessment = serializers.BooleanField()
    risk_assessment_name = serializers.CharField(required=False)
    risk_matrix = serializers.CharField(required=False)

    def save(self, **kwargs):
        return self.create(self.validated_data)

    def create(self, validated_data):
        folder = Folder.objects.filter(
            content_type=Folder.ContentType.DOMAIN,
            name="Starter",
        ).first()
        if not folder:
            folder_data = {
                "content_type": Folder.ContentType.DOMAIN,
                "name": "Starter",
                "create_iam_groups": True,
            }
            folder_serializer = FolderWriteSerializer(
                data=folder_data, context=self.context
            )
            if not folder_serializer.is_valid(raise_exception=True):
                return None
            folder = folder_serializer.save()
            Folder.create_default_ug_and_ra(folder)

        perimeter_data = {
            "folder": folder.id,
            "name": "Starter",
        }
        perimeter = Perimeter.objects.filter(**perimeter_data).first()
        if not perimeter:
            perimeter_serializer = PerimeterWriteSerializer(
                data=perimeter_data, context=self.context
            )
            if not perimeter_serializer.is_valid(raise_exception=True):
                return None
            perimeter = perimeter_serializer.save()

        framework_lib_urn = validated_data["framework"]
        if not LoadedLibrary.objects.filter(urn=framework_lib_urn).exists():
            framework_stored_lib = StoredLibrary.objects.get(urn=framework_lib_urn)
            try:
                framework_stored_lib.load()
            except Exception as e:
                logger.error(e)
                raise serializers.ValidationError(
                    {"error": "Could not load the selected framework library"}
                )
        framework_lib = LoadedLibrary.objects.get(urn=framework_lib_urn)
        framework = Framework.objects.get(library=framework_lib)
        compliance_assessment_data = {
            "folder": folder.id,
            "perimeter": perimeter.id,
            "framework": framework.id,
            "name": validated_data["audit_name"],
        }
        compliance_asssessment_serializer = ComplianceAssessmentWriteSerializer(
            data=compliance_assessment_data, context=self.context
        )
        if not compliance_asssessment_serializer.is_valid(raise_exception=True):
            return None
        audit = compliance_asssessment_serializer.save()
        audit.create_requirement_assessments()

        created_objects = {
            "folder": FolderReadSerializer(folder).data,
            "perimeter": PerimeterReadSerializer(perimeter).data,
            "complianceassessment": ComplianceAssessmentReadSerializer(audit).data,
        }

        if not validated_data["create_risk_assessment"]:
            return created_objects

        matrix_lib_urn = validated_data["risk_matrix"]
        if not LoadedLibrary.objects.filter(urn=matrix_lib_urn).exists():
            matrix_stored_lib = StoredLibrary.objects.get(urn=matrix_lib_urn)
            try:
                matrix_stored_lib.load()
            except Exception as e:
                logger.error(e)
                raise serializers.ValidationError(
                    {"error": "Could not load the selected risk matrix library"}
                )
        matrix_lib = LoadedLibrary.objects.get(urn=matrix_lib_urn)
        matrix = RiskMatrix.objects.get(library=matrix_lib)

        risk_assessment_data = {
            "folder": folder.id,
            "perimeter": perimeter.id,
            "risk_matrix": matrix.id,
            "name": validated_data["risk_assessment_name"],
        }
        risk_asssessment_serializer = RiskAssessmentWriteSerializer(
            data=risk_assessment_data, context=self.context
        )
        if not risk_asssessment_serializer.is_valid(raise_exception=True):
            return created_objects
        risk_assessment = risk_asssessment_serializer.save()
        created_objects["riskassessment"] = RiskAssessmentReadSerializer(
            risk_assessment
        ).data

        return created_objects


class TimelineEntryWriteSerializer(BaseModelSerializer):
    class Meta:
        model = TimelineEntry
        exclude = ["created_at", "updated_at"]


class TimelineEntryReadSerializer(TimelineEntryWriteSerializer):
    path = PathField(read_only=True)
    str = serializers.CharField(source="__str__", read_only=True)
    author = FieldsRelatedField()
    folder = FieldsRelatedField()
    incident = FieldsRelatedField()
    evidences = FieldsRelatedField(many=True)

    class Meta:
        model = TimelineEntry
        exclude = []


class CommentWriteSerializer(BaseModelSerializer):
    PARENT_FIELDS = Comment.PARENT_FIELDS

    def validate(self, data):
        data = super().validate(data)
        if self.instance is None:
            parent_count = sum(1 for f in self.PARENT_FIELDS if data.get(f) is not None)
            if parent_count != 1:
                raise serializers.ValidationError(
                    f"Exactly one parent ({', '.join(self.PARENT_FIELDS)}) must be set."
                )
        else:
            for field_name in self.PARENT_FIELDS:
                if field_name in data:
                    self._ensure_immutable(field_name, data[field_name])
        return data

    def create(self, validated_data):
        # Resolve folder from the parent object so the RBAC check in
        # BaseModelSerializer.create() uses the correct folder instead
        # of falling back to root (which auditees cannot access).
        for field_name in self.PARENT_FIELDS:
            parent_obj = validated_data.get(field_name)
            if parent_obj is not None:
                validated_data["folder"] = parent_obj.folder
                break
        return super().create(validated_data)

    class Meta:
        model = Comment
        exclude = ["created_at", "updated_at", "is_tainted", "author", "folder"]


class CommentReadSerializer(CommentWriteSerializer):
    str = serializers.CharField(source="__str__", read_only=True)
    author = FieldsRelatedField(["id", "email", "first_name", "last_name"])
    folder = FieldsRelatedField()
    requirement_assessment = FieldsRelatedField()
    risk_scenario = FieldsRelatedField()
    applied_control = FieldsRelatedField()
    finding = FieldsRelatedField()

    class Meta:
        model = Comment
        fields = "__all__"


class IncidentWriteSerializer(BaseModelSerializer):
    class Meta:
        model = Incident
        exclude = ["created_at", "updated_at"]

    def validate(self, attrs):
        # Merge with existing instance values for partial updates
        occurred_at = attrs.get(
            "occurred_at", getattr(self.instance, "occurred_at", None)
        )
        reported_at = attrs.get(
            "reported_at", getattr(self.instance, "reported_at", None)
        )
        resolved_at = attrs.get(
            "resolved_at", getattr(self.instance, "resolved_at", None)
        )

        if occurred_at and reported_at and reported_at < occurred_at:
            raise serializers.ValidationError(
                {"reported_at": "Reported date cannot be before occurrence date."}
            )
        if resolved_at and occurred_at and resolved_at < occurred_at:
            raise serializers.ValidationError(
                {"resolved_at": "Resolution date cannot be before occurrence date."}
            )
        if resolved_at and reported_at and resolved_at < reported_at:
            raise serializers.ValidationError(
                {"resolved_at": "Resolution date cannot be before reported date."}
            )

        return super().validate(attrs)

    def update(self, instance, validated_data):
        old_folder_id = instance.folder_id
        with transaction.atomic():
            updated_instance = super().update(instance, validated_data)
            if old_folder_id != updated_instance.folder_id:
                TimelineEntry.objects.filter(incident=updated_instance).update(
                    folder=updated_instance.folder
                )
        return updated_instance


class IncidentReadSerializer(IncidentWriteSerializer):
    path = PathField(read_only=True)
    threats = FieldsRelatedField(many=True)
    owners = FieldsRelatedField(many=True)
    assets = FieldsRelatedField(many=True)
    qualifications = FieldsRelatedField(many=True)
    entities = FieldsRelatedField(many=True)
    applied_controls = FieldsRelatedField(many=True)
    task_templates = FieldsRelatedField(many=True)
    risk_scenarios = FieldsRelatedField(many=True)
    severity = serializers.CharField(source="get_severity_display", read_only=True)
    status = serializers.CharField(source="get_status_display", read_only=True)
    detection = serializers.CharField(source="get_detection_display", read_only=True)
    folder = FieldsRelatedField()
    filtering_labels = FieldsRelatedField(many=True)

    class Meta:
        model = Incident
        fields = "__all__"

    def get_timeline_entries(self, obj):
        """Returns a serialized list of timeline entries related to the incident."""
        return TimelineEntryReadSerializer(obj.timeline_entries.all(), many=True).data


class TaskTemplateReadSerializer(
    RequirementAssessmentRelationshipProjectionMixin,
    CommitmentSerializerMixin,
    BaseModelSerializer,
):
    path = PathField(read_only=True)
    folder = FieldsRelatedField()
    incidents = FieldsRelatedField(many=True)
    evidences = FieldsRelatedField(many=True)
    assets = FieldsRelatedField(many=True)
    applied_controls = FieldsRelatedField(many=True)
    compliance_assessments = FieldsRelatedField(many=True)
    requirement_assessments = FieldsRelatedField(many=True)
    risk_assessments = FieldsRelatedField(many=True)
    assigned_to = FieldsRelatedField(many=True)
    findings_assessment = FieldsRelatedField(many=True)
    findings = FieldsRelatedField(many=True)
    filtering_labels = FieldsRelatedField(["id", "folder"], many=True)

    next_occurrence = serializers.ReadOnlyField(source="get_next_occurrence")
    last_occurrence_status = serializers.ReadOnlyField(
        source="get_last_occurrence_status"
    )
    next_occurrence_status = serializers.ReadOnlyField(
        source="get_next_occurrence_status"
    )

    # Expose task_node fields directly
    status = serializers.SerializerMethodField()
    observation = serializers.SerializerMethodField()

    class Meta:
        model = TaskTemplate
        # The schedule is exposed so the UI can render the cadence in words; it is
        # not shown raw anywhere, detailViewFields decides what the table renders.
        fields = "__all__"
        list_serializer_class = (
            RequirementAssessmentRelationshipProjectionListSerializer
        )

    def get_task_node(self, obj):
        """
        Helper to fetch the related TaskNode for non-recurrent templates.
        Cached on the instance since both get_status and get_observation call this.
        """
        if not hasattr(obj, "_cached_task_node"):
            obj._cached_task_node = (
                None
                if obj.is_recurrent
                else TaskNode.objects.filter(task_template=obj)
                .order_by("due_date")
                .first()
            )
        return obj._cached_task_node

    # Resolved in the list/retrieve queryset; None there is a real answer, so it
    # cannot double as "not annotated".
    _NOT_ANNOTATED = object()

    def get_status(self, obj):
        annotated = getattr(obj, "one_time_status", self._NOT_ANNOTATED)
        if annotated is not self._NOT_ANNOTATED:
            return None if obj.is_recurrent else annotated
        task_node = self.get_task_node(obj)
        return task_node.status if task_node else None

    def get_observation(self, obj):
        annotated = getattr(obj, "one_time_observation", self._NOT_ANNOTATED)
        if annotated is not self._NOT_ANNOTATED:
            # A null observation on an existing node is not the same answer as no
            # node at all. TaskNode.status is non-nullable, so its annotation being
            # None is what tells the two apart.
            no_occurrence = getattr(obj, "one_time_status", None) is None
            if obj.is_recurrent or no_occurrence:
                return ""
            return annotated
        task_node = self.get_task_node(obj)
        return task_node.observation if task_node else ""


class TaskTemplateWriteSerializer(
    RequirementAssessmentRelationshipAuthorityMixin,
    CommitmentSerializerMixin,
    BaseModelSerializer,
):
    requirement_assessments = GovernedRequirementAssessmentPrimaryKeyRelatedField(
        many=True,
        required=False,
        queryset=RequirementAssessment.objects.all(),
    )
    status = serializers.CharField(required=False)
    observation = serializers.CharField(
        required=False, allow_blank=True, allow_null=True
    )
    objectives = serializers.PrimaryKeyRelatedField(
        queryset=OrganisationObjective.objects.all(),
        many=True,
        required=False,
    )
    incidents = serializers.PrimaryKeyRelatedField(
        many=True, required=False, queryset=Incident.objects.all()
    )

    class Meta:
        model = TaskTemplate
        fields = "__all__"
        list_serializer_class = (
            RequirementAssessmentRelationshipProjectionListSerializer
        )

    def to_representation(self, instance):
        data = super().to_representation(instance)
        if not instance.is_recurrent:
            task_node = (
                TaskNode.objects.filter(task_template=instance)
                .order_by("due_date")
                .first()
            )
            if task_node:
                data["status"] = task_node.status
                data["observation"] = task_node.observation
            else:
                data["status"] = None
                data["observation"] = ""
        return data

    def validate(self, attrs):
        return self.validate_commitment(super().validate(attrs))

    def create(self, validated_data):
        commitment_data = dict(validated_data)
        self.pop_commitment(validated_data)
        assigned_to_data = validated_data.get("assigned_to", [])
        incidents = validated_data.pop("incidents", [])
        tasknode_data = self._extract_tasknode_fields(validated_data)
        with transaction.atomic():
            instance = super().create(validated_data)
            self._sync_task_node(instance, tasknode_data, False, instance.is_recurrent)
            if incidents:
                instance.incidents.set(incidents)

        # Send notification to newly assigned users
        if assigned_to_data:
            self._send_assignment_notifications(
                instance, [actor.id for actor in assigned_to_data]
            )

        # A recurrent template is a definition, not one promise; the mixin drops the
        # fields for it on update, but on create there is no instance to check yet.
        if not instance.is_recurrent:
            self.apply_commitment(instance, commitment_data)

        return instance

    def update(self, instance, validated_data):
        governed_relationship = "requirement_assessments" in validated_data
        # A governed delta is relation-only and the authority mixin takes the
        # target lock. Avoid basing notification or folder side effects on an
        # unlocked pre-authority snapshot in that path.
        old_assigned_ids = (
            None
            if governed_relationship
            else set(instance.assigned_to.values_list("id", flat=True))
        )
        commitment_data = dict(validated_data)
        self.pop_commitment(validated_data)

        # Track old folder before update
        old_folder_id = None if governed_relationship else instance.folder_id

        was_recurrent = None if governed_relationship else instance.is_recurrent
        tasknode_data = self._extract_tasknode_fields(validated_data)
        incidents = validated_data.pop("incidents", None)

        with transaction.atomic():
            instance = super().update(instance, validated_data)
            if governed_relationship:
                old_folder_id = self._governed_locked_scalar_snapshot["folder_id"]
                was_recurrent = self._governed_locked_scalar_snapshot["is_recurrent"]
            now_recurrent = instance.is_recurrent
            if not governed_relationship:
                self._sync_task_node(
                    instance, tasknode_data, was_recurrent, now_recurrent
                )
            if incidents is not None:
                instance.incidents.set(incidents)

            # Update all TaskNodes' folder if the TaskTemplate's folder changed
            if old_folder_id != instance.folder_id:
                TaskNode.objects.filter(task_template=instance).update(
                    folder=instance.folder
                )
                # A commitment is only ever as visible as the object it is about.
                instance.commitments.update(folder=instance.folder)

            # Inside the block: the template and its promise move together.
            self.apply_commitment(instance, commitment_data)

        # Get new assigned users after update
        if old_assigned_ids is not None:
            new_assigned_ids = set(instance.assigned_to.values_list("id", flat=True))

            # Send notifications only to newly assigned users
            newly_assigned_ids = new_assigned_ids - old_assigned_ids
            if newly_assigned_ids:
                self._send_assignment_notifications(instance, list(newly_assigned_ids))

        return instance

    def _send_assignment_notifications(self, task_template, actor_ids):
        """Send assignment notifications to the specified actors"""
        if not actor_ids:
            return

        try:
            from core.models import Actor
            from .tasks import send_task_template_assignment_notification

            assigned_actors = Actor.objects.filter(id__in=actor_ids)
            assigned_emails = []
            for actor in assigned_actors:
                assigned_emails.extend(actor.get_emails())

            if assigned_emails:
                send_task_template_assignment_notification(
                    task_template.id, assigned_emails
                )
        except Exception as e:
            logger.error(
                f"Failed to send TaskTemplate assignment notification: {str(e)}"
            )

    def _extract_tasknode_fields(self, validated_data):
        """
        Separate the TaskNode-specific fields from validated_data.
        """
        return {
            "status": validated_data.pop("status", None),
            "observation": validated_data.pop("observation", None),
        }

    def _sync_task_node(
        self, task_template, tasknode_data, was_recurrent, now_recurrent
    ):
        """
        Synchronize or create the TaskNode linked to a non-recurrent TaskTemplate.
        """
        if now_recurrent:
            return  # Only sync for non-recurrent templates

        task_nodes = TaskNode.objects.filter(task_template=task_template)
        if was_recurrent:
            # Was recurrent, now non-recurrent: must clean
            task_nodes.delete()
            task_node = TaskNode.objects.create(
                task_template=task_template,
                due_date=task_template.task_date,
                scheduled_date=task_template.task_date,
                folder=task_template.folder,
            )
        else:
            # Was already non-recurrent: reuse if possible
            if task_nodes.count() == 1:
                task_node = task_nodes.first()
            else:
                task_nodes.delete()
                task_node = TaskNode.objects.create(
                    task_template=task_template,
                    due_date=task_template.task_date,
                    scheduled_date=task_template.task_date,
                    folder=task_template.folder,
                )

        task_node.to_delete = False
        task_node.due_date = task_template.task_date
        task_node.scheduled_date = task_template.task_date
        if tasknode_data.get("status") is not None:
            task_node.status = tasknode_data["status"]
        if tasknode_data.get("observation") is not None:
            task_node.observation = tasknode_data["observation"]
        task_node.save()


class TaskNodeReadSerializer(BaseModelSerializer):
    path = PathField(read_only=True)
    task_template = FieldsRelatedField(["folder", "id", "description"])
    folder = FieldsRelatedField()
    name = serializers.SerializerMethodField()
    assigned_to = FieldsRelatedField(many=True)
    evidences = FieldsRelatedField(["folder", "id"], many=True)
    is_recurrent = serializers.BooleanField(source="task_template.is_recurrent")
    # These read off the template. The model exposes them as properties returning
    # `.all()`, and DRF calls `.all()` again on whatever it gets — on a QuerySet that
    # clones and discards the prefetched rows, costing a query per node per field.
    # Naming the manager instead lets the second `.all()` hit the prefetch cache.
    expected_evidence = FieldsRelatedField(
        ["folder", "id"], many=True, source="task_template.evidences"
    )
    evidence_reviewed = serializers.SerializerMethodField()
    evidence_revisions_map = serializers.SerializerMethodField()
    applied_controls = FieldsRelatedField(
        ["folder", "id"], many=True, source="task_template.applied_controls"
    )
    compliance_assessments = FieldsRelatedField(
        ["folder", "id"], many=True, source="task_template.compliance_assessments"
    )
    assets = FieldsRelatedField(
        ["folder", "id"], many=True, source="task_template.assets"
    )
    risk_assessments = FieldsRelatedField(
        ["folder", "id"], many=True, source="task_template.risk_assessments"
    )
    findings_assessment = FieldsRelatedField(
        ["folder", "id"], many=True, source="task_template.findings_assessment"
    )

    def get_name(self, obj):
        return obj.task_template.name if obj.task_template else ""

    def get_evidence_reviewed(self, obj):
        """Which expected evidences this occurrence has a file for.

        Read from the occurrence's own revisions, the same source as
        get_evidence_revisions_map below. The evidence's *latest* revision is
        the wrong question: expected_evidence is the template's list, shared by
        every occurrence, so February filing v2 used to un-tick January, and a
        revision filed by anything other than an occurrence (a workflow
        collecting the file, say) used to un-tick whoever had answered.
        """
        expected = {evidence.id for evidence in obj.expected_evidence}
        reviewed = []
        # An occurrence may hold several revisions of one evidence; the tick is
        # per evidence, so report each at most once.
        for revision in obj.evidence_revisions.all():
            if (
                revision.evidence_id in expected
                and revision.evidence_id not in reviewed
            ):
                reviewed.append(revision.evidence_id)
        return reviewed

    def get_evidence_revisions_map(self, obj):
        """Returns a mapping of evidence ID to revision ID for this task node"""
        expected = {evidence.id for evidence in obj.expected_evidence}
        evidence_revisions = {}
        # Walking the node's own revisions costs one prefetched list; querying per
        # expected evidence cost a query each. setdefault keeps the first match, as
        # the per-evidence .first() did.
        for revision in obj.evidence_revisions.all():
            if revision.evidence_id in expected:
                evidence_revisions.setdefault(
                    str(revision.evidence_id), str(revision.id)
                )
        return evidence_revisions

    class Meta:
        model = TaskNode
        exclude = ["to_delete"]


class TaskNodeWriteSerializer(BaseModelSerializer):
    class Meta:
        model = TaskNode
        exclude = ["task_template", "evidences", "scheduled_date"]

    def validate_due_date(self, value):
        if self.instance and value:
            exists = (
                TaskNode.objects.filter(
                    task_template=self.instance.task_template,
                    due_date=value,
                )
                .exclude(pk=self.instance.pk)
                .exists()
            )
            if exists:
                raise serializers.ValidationError("taskNodeDuplicateDueDate")
        return value


class TerminologyReadSerializer(BaseModelSerializer):
    field_path = serializers.CharField(source="get_field_path_display", read_only=True)
    translated_name = serializers.CharField(source="get_name_translated")

    class Meta:
        model = Terminology
        exclude = ["folder"]


class TerminologyWriteSerializer(BaseModelSerializer):
    # Built-in terminologies are seeded at startup; users may only toggle their
    # visibility, not rename or otherwise modify them.
    BUILTIN_EDITABLE_FIELDS = {"is_visible"}
    builtin = serializers.BooleanField(read_only=True)

    class Meta:
        model = Terminology
        exclude = ["folder"]


class ClassificationLevelReadSerializer(BaseModelSerializer):
    object_classification = FieldsRelatedField()
    label = serializers.ReadOnlyField()

    class Meta:
        model = ClassificationLevel
        exclude = ["folder"]


class ClassificationLevelWriteSerializer(BaseModelSerializer):
    # Same as terminologies: built-in levels can only be shown/hidden.
    BUILTIN_EDITABLE_FIELDS = {"is_visible"}
    builtin = serializers.BooleanField(read_only=True)

    class Meta:
        model = ClassificationLevel
        exclude = ["folder"]


class ObjectClassificationReadSerializer(BaseModelSerializer):
    folder = FieldsRelatedField()
    levels = ClassificationLevelReadSerializer(many=True, read_only=True)

    class Meta:
        model = ObjectClassification
        fields = "__all__"


class ObjectClassificationWriteSerializer(BaseModelSerializer):
    # Built-in classifications (e.g. TLP) can only be shown/hidden.
    BUILTIN_EDITABLE_FIELDS = {"is_visible"}
    builtin = serializers.BooleanField(read_only=True)

    class Meta:
        model = ObjectClassification
        exclude = ["folder"]


class ValidationFlowWriteSerializer(BaseModelSerializer):
    ALLOWED_STATUS_TRANSITIONS = {
        ValidationFlow.Status.SUBMITTED: {
            ValidationFlow.Status.ACCEPTED,
            ValidationFlow.Status.REJECTED,
            ValidationFlow.Status.CHANGE_REQUESTED,
            ValidationFlow.Status.DROPPED,
        },
        ValidationFlow.Status.ACCEPTED: {ValidationFlow.Status.REVOKED},
        ValidationFlow.Status.CHANGE_REQUESTED: {
            ValidationFlow.Status.SUBMITTED,
            ValidationFlow.Status.DROPPED,
        },
    }

    ref_id = serializers.CharField(required=False, allow_blank=True, allow_null=True)
    event_notes = serializers.CharField(
        required=False, allow_blank=True, allow_null=True, write_only=True
    )

    def validate_status(self, value):
        if self.instance is None and value != ValidationFlow.Status.SUBMITTED:
            raise serializers.ValidationError("validationMustStartAsSubmitted")
        return value

    def create(self, validated_data: dict) -> ValidationFlow:
        """
        Override create to automatically set the requester to the current user
        and create initial submission event.
        """
        from core.models import FlowEvent

        request_user = self.context["request"].user
        validated_data["requester"] = request_user

        # Extract event_notes (if provided) or use request_notes for initial event
        event_notes = validated_data.pop("event_notes", None)
        if not event_notes:
            event_notes = validated_data.get("request_notes", None)

        # Create the validation flow
        instance = super().create(validated_data)

        # Create initial submission event
        FlowEvent.objects.create(
            validation_flow=instance,
            event_type=instance.status,
            event_actor=request_user,
            event_notes=event_notes,
            folder=instance.folder,
        )

        # Send notification to approver (best-effort only, don't break creation)
        try:
            from core.tasks import send_validation_flow_created_notification

            send_validation_flow_created_notification(instance)
        except Exception as e:
            logger.error(
                "Failed to send validation flow creation notification",
                validation_flow_id=instance.id,
                ref_id=instance.ref_id,
            )

        return instance

    def update(self, instance: ValidationFlow, validated_data: dict) -> ValidationFlow:
        """
        Override update to ensure proper permissions for status transitions:
        - Approver can modify status when status is 'submitted' or 'accepted'
        - Requester can modify status when status is 'change_requested'
        - Creates FlowEvent for each status transition
        """
        from core.models import FlowEvent

        request_user = self.context["request"].user
        old_folder_id = instance.folder_id

        # Check if status is being modified
        if "status" in validated_data:
            new_status = validated_data["status"]

            # Extract event notes from validated_data (passed from actions)
            event_notes = validated_data.pop("event_notes", None)

            with transaction.atomic():
                # Re-read under lock: concurrent requests must not both validate the same starting status
                instance = ValidationFlow.objects.select_for_update().get(
                    pk=instance.pk
                )
                current_status = instance.status

                # Define who can modify based on current status
                if current_status in ["submitted", "accepted"]:
                    # For submitted status: approver can do any action, requester can only drop
                    if current_status == "submitted" and new_status == "dropped":
                        # Allow requester to drop their own request
                        if (
                            instance.requester != request_user
                            and instance.approver != request_user
                        ):
                            raise PermissionDenied(
                                {"error": "validationOnlyRequesterOrApproverCanDrop"}
                            )
                    else:
                        # Only approver can change status from submitted or accepted (for other actions)
                        if instance.approver != request_user:
                            raise PermissionDenied(
                                {"error": "validationOnlyApproverCanModify"}
                            )
                elif current_status == "change_requested":
                    # Only requester can change status from change_requested
                    if instance.requester != request_user:
                        raise PermissionDenied(
                            {"error": "validationOnlyRequesterCanAct"}
                        )
                else:
                    # Terminal states (rejected, revoked, dropped, expired) cannot be modified
                    raise PermissionDenied({"error": "validationInTerminalState"})

                if (
                    new_status != current_status
                    and new_status
                    not in self.ALLOWED_STATUS_TRANSITIONS.get(current_status, set())
                ):
                    raise serializers.ValidationError(
                        {
                            "status": "validationStatusTransitionNotAllowed",
                            # Context for API consumers and the frontend message
                            "from_status": current_status,
                            "to_status": new_status,
                        }
                    )

                # Update the instance
                updated_instance = super().update(instance, validated_data)

                # Create FlowEvent after successful status transition
                FlowEvent.objects.create(
                    validation_flow=updated_instance,
                    event_type=updated_instance.status,
                    event_actor=request_user,
                    event_notes=event_notes,
                    folder=updated_instance.folder,
                )

                # Auto-lock/unlock associated objects based on status transitions
                self._manage_associated_objects_lock(
                    updated_instance, current_status, new_status
                )

                # Cascade folder changes to events if needed
                if old_folder_id != updated_instance.folder_id:
                    FlowEvent.objects.filter(validation_flow=updated_instance).update(
                        folder=updated_instance.folder
                    )

            # Notify the other party about the status change (after commit)
            def _send_update_notification():
                try:
                    from core.tasks import send_validation_flow_updated_notification

                    actor_name = (
                        f"{request_user.first_name} {request_user.last_name}".strip()
                        or request_user.email
                    )

                    # Approver acted → notify requester
                    if (
                        request_user == updated_instance.approver
                        and updated_instance.requester
                        and updated_instance.requester.email
                    ):
                        send_validation_flow_updated_notification(
                            updated_instance.id,
                            updated_instance.requester.email,
                            updated_instance.get_status_display(),
                            actor_name,
                            event_notes,
                        )
                    # Requester acted → notify approver
                    elif (
                        request_user == updated_instance.requester
                        and updated_instance.approver
                        and updated_instance.approver.email
                    ):
                        send_validation_flow_updated_notification(
                            updated_instance.id,
                            updated_instance.approver.email,
                            updated_instance.get_status_display(),
                            actor_name,
                            event_notes,
                        )
                except Exception as e:
                    logger.error(
                        "Failed to send validation flow update notification",
                        validation_flow_id=updated_instance.id,
                        error=str(e),
                    )

            transaction.on_commit(_send_update_notification)

            return updated_instance

        with transaction.atomic():
            updated_instance = super().update(instance, validated_data)

            if old_folder_id != updated_instance.folder_id:
                FlowEvent.objects.filter(validation_flow=updated_instance).update(
                    folder=updated_instance.folder
                )

        return updated_instance

    def _manage_associated_objects_lock(
        self, validation_flow, old_status: str, new_status: str
    ):
        """
        Automatically lock/unlock associated objects based on validation status.
        - Lock when status becomes 'accepted'
        """
        # Only act on specific transitions
        should_lock = new_status == "accepted"
        # should_unlock = old_status == "accepted" and new_status == "revoked"
        #
        # if not (should_lock or should_unlock):
        #     return

        if not should_lock:
            return
        lock_value = should_lock

        # Get all assessment model fields
        assessment_fields = [
            "compliance_assessments",
            "risk_assessments",
            "business_impact_analysis",
            "findings_assessments",
        ]

        for field_name in assessment_fields:
            related_manager = getattr(validation_flow, field_name)
            if related_manager.exists():
                related_manager.update(is_locked=lock_value)
                logger.info(
                    f"{'Locked' if lock_value else 'Unlocked'} {related_manager.count()} "
                    f"{field_name} for validation flow {validation_flow.ref_id}"
                )

    class Meta:
        model = ValidationFlow
        fields = "__all__"
        read_only_fields = ["requester"]


class FlowEventSerializer(BaseModelSerializer):
    event_actor = FieldsRelatedField(["id", "email", "first_name", "last_name"])

    class Meta:
        model = FlowEvent
        fields = ["id", "event_type", "event_actor", "event_notes", "created_at"]


class ValidationFlowReadSerializer(BaseModelSerializer):
    str = serializers.CharField(source="__str__", read_only=True)
    path = PathField(read_only=True)
    folder = FieldsRelatedField()
    compliance_assessments = FieldsRelatedField(
        many=True,
        fields=[
            "id",
            "status",
            "updated_at",
            {"perimeter": ["id", {"folder": ["id"]}]},
        ],
    )
    risk_assessments = FieldsRelatedField(
        many=True,
        fields=[
            "id",
            "status",
            "updated_at",
            {"perimeter": ["id", {"folder": ["id"]}]},
        ],
    )
    business_impact_analysis = FieldsRelatedField(
        many=True,
        fields=[
            "id",
            "status",
            "updated_at",
            {"perimeter": ["id", {"folder": ["id"]}]},
        ],
    )
    crq_studies = FieldsRelatedField(many=True)
    ebios_studies = FieldsRelatedField(many=True)
    entity_assessments = FieldsRelatedField(
        many=True,
        fields=[
            "id",
            "status",
            "updated_at",
            {"perimeter": ["id", {"folder": ["id"]}]},
        ],
    )
    findings_assessments = FieldsRelatedField(
        many=True,
        fields=[
            "id",
            "status",
            "updated_at",
            {"perimeter": ["id", {"folder": ["id"]}]},
        ],
    )
    evidences = FieldsRelatedField(many=True)
    security_exceptions = FieldsRelatedField(many=True)
    policies = FieldsRelatedField(many=True)
    processings = FieldsRelatedField(many=True)
    accreditations = FieldsRelatedField(many=True)
    contracts = FieldsRelatedField(many=True)
    filtering_labels = FieldsRelatedField(many=True)
    requester = FieldsRelatedField(["id", "email", "first_name", "last_name"])
    approver = FieldsRelatedField(["id", "email", "first_name", "last_name"])
    linked_models = serializers.SerializerMethodField()
    events = FlowEventSerializer(many=True, read_only=True)

    class Meta:
        model = ValidationFlow
        fields = "__all__"

    def get_linked_models(self, obj):
        linked = []
        field_map = [
            ("compliance_assessments", "has_compliance_assessments"),
            ("risk_assessments", "has_risk_assessments"),
            ("business_impact_analysis", "has_business_impact_analysis"),
            ("crq_studies", "has_crq_studies"),
            ("ebios_studies", "has_ebios_studies"),
            ("entity_assessments", "has_entity_assessments"),
            ("findings_assessments", "has_findings_assessments"),
            ("evidences", "has_evidences"),
            ("security_exceptions", "has_security_exceptions"),
            ("policies", "has_policies"),
            ("processings", "has_processings"),
            ("accreditations", "has_accreditations"),
            ("contracts", "has_contracts"),
        ]
        prefetched = getattr(obj, "_prefetched_objects_cache", {})
        for field_name, flag_name in field_map:
            annotated_value = getattr(obj, flag_name, None)
            if annotated_value is not None:
                has_items = annotated_value
            elif field_name in prefetched:
                has_items = bool(prefetched[field_name])
            else:
                manager = getattr(obj, field_name, None)
                has_items = bool(manager and manager.exists())
            if has_items:
                linked.append(field_name)
        return linked


class ComplianceAssessmentEvidenceSerializer(BaseModelSerializer):
    """Serializer for evidences in the context of compliance assessments"""

    folder = FieldsRelatedField()
    status = serializers.CharField(source="get_status_display")
    owner = FieldsRelatedField(many=True)
    size = serializers.CharField(source="get_size")
    last_update = serializers.DateTimeField(source="updated_at")
    requirement_assessments = serializers.SerializerMethodField()

    def get_requirement_assessments(self, obj):
        pk = self.context.get("pk")
        if pk is None:
            return {"direct_links": [], "indirect_links": []}

        # Get requirement assessments for this compliance assessment
        requirement_assessments = RequirementAssessment.objects.filter(
            compliance_assessment=pk
        ).prefetch_related("applied_controls")

        direct_links = []
        indirect_links = []

        # Direct links - evidence is directly linked to requirement assessment
        for req_assessment in requirement_assessments:
            if obj in req_assessment.evidences.all():
                direct_links.append(
                    {
                        "requirement_assessment_id": str(req_assessment.id),
                        "requirement_assessment_name": str(
                            req_assessment.requirement.safe_display_str
                        ),
                    }
                )

        # Indirect links - evidence is linked through applied controls
        for req_assessment in requirement_assessments:
            for applied_control in req_assessment.applied_controls.all():
                if obj in applied_control.evidences.all():
                    indirect_links.append(
                        {
                            "requirement_assessment_id": str(req_assessment.id),
                            "requirement_assessment_name": str(
                                req_assessment.requirement.safe_display_str
                            ),
                            "applied_control_id": str(applied_control.id),
                            "applied_control_name": applied_control.name,
                        }
                    )

        # Return a simplified format similar to action-plan
        all_links = []

        # Add direct links
        for link in direct_links:
            all_links.append(
                {
                    "str": link["requirement_assessment_name"],
                    "id": link["requirement_assessment_id"],
                }
            )

        # Add indirect links
        for link in indirect_links:
            all_links.append(
                {
                    "str": f"{link['requirement_assessment_name']} (via {link['applied_control_name'][:15]}...)",
                    "id": link["requirement_assessment_id"],
                }
            )

        return all_links

    class Meta:
        model = Evidence
        fields = [
            "id",
            "name",
            "status",
            "last_update",
            "expiry_date",
            "owner",
            "folder",
            "size",
            "requirement_assessments",
        ]


# ---------------------------------------------------------------------------
# Quick forms
# ---------------------------------------------------------------------------


class QuickFormReadSerializer(BaseModelSerializer):
    folder = FieldsRelatedField()
    library = FieldsRelatedField(["id", "urn", "name"])
    pages_count = serializers.SerializerMethodField()
    responses_count = serializers.SerializerMethodField()
    is_deletable = serializers.SerializerMethodField()

    def get_pages_count(self, obj):
        return obj.pages.count()

    def get_responses_count(self, obj):
        return obj.responses.count()

    def get_is_deletable(self, obj):
        return obj.is_deletable()

    class Meta:
        model = QuickForm
        fields = "__all__"


class QuickFormWriteSerializer(BaseModelSerializer):
    class Meta:
        model = QuickForm
        exclude = ["created_at", "updated_at"]


class QuickFormPageReadSerializer(BaseModelSerializer):
    folder = FieldsRelatedField()
    quick_form = FieldsRelatedField()
    questions = serializers.SerializerMethodField()

    def get_questions(self, obj):
        return obj.get_questions_translated() or {}

    class Meta:
        model = QuickFormPage
        fields = "__all__"


class QuickFormPageWriteSerializer(BaseModelSerializer):
    class Meta:
        model = QuickFormPage
        exclude = ["created_at", "updated_at"]


def _reject_entity_actors(actors):
    """Third-party respondents are out of scope for quick forms: only user
    and team actors may be picked."""
    for actor in actors or []:
        if actor.entity_id is not None:
            raise serializers.ValidationError(
                f"Entity actor '{actor}' cannot be picked on a quick form response."
            )
    return actors


class QuickFormPublicationWriteSerializer(BaseModelSerializer):
    class Meta:
        model = QuickFormPublication
        exclude = ["created_at", "updated_at"]

    def validate_default_reviewers(self, value):
        return _reject_entity_actors(value)


class QuickFormPublicationReadSerializer(BaseModelSerializer):
    folder = FieldsRelatedField()
    submission_folder = FieldsRelatedField()
    quick_form = FieldsRelatedField(["id", "name", "urn"])
    audience_groups = FieldsRelatedField(many=True)
    default_reviewers = FieldsRelatedField(many=True)
    responses_count = serializers.SerializerMethodField()

    def get_responses_count(self, obj) -> int:
        return obj.responses.count()

    class Meta:
        model = QuickFormPublication
        fields = "__all__"


class QuickFormResponseReadSerializer(BaseModelSerializer):
    folder = FieldsRelatedField()
    quick_form = FieldsRelatedField(["id", "name", "urn"])
    respondents = FieldsRelatedField(many=True)
    reviewers = FieldsRelatedField(many=True)
    assignee = FieldsRelatedField()
    publication = FieldsRelatedField()
    cloned_from = FieldsRelatedField(["id", "ref_id"])
    progress = serializers.SerializerMethodField()
    is_deletable = serializers.SerializerMethodField()
    awaiting_conversion = serializers.BooleanField(read_only=True)

    def get_is_deletable(self, obj) -> bool:
        # Answered per caller: a closed request is administrator-only.
        request = self.context.get("request")
        return obj.is_deletable(getattr(request, "user", None))

    def get_progress(self, obj):
        """Cheap list-view progress: answered vs seeded questions, ignoring
        page visibility and depends_on. The `content` endpoint carries the
        exact figures."""
        total = Question.objects.filter(page__quick_form_id=obj.quick_form_id).count()
        answered = (
            obj.answers.filter(
                ~Answer.empty_value_q() | Q(selected_choices__isnull=False)
            )
            .distinct()
            .count()
        )
        return {"answered_count": answered, "total_count": total}

    class Meta:
        model = QuickFormResponse
        fields = "__all__"


class QuickFormResponseWriteSerializer(BaseModelSerializer):
    answers = serializers.JSONField(required=False, write_only=True)
    start_now = serializers.BooleanField(required=False, write_only=True, default=False)

    class Meta:
        model = QuickFormResponse
        exclude = ["created_at", "updated_at"]
        read_only_fields = [
            "status",
            "computed_outcome",
            "score",
            "started_at",
            "submitted_at",
        ]

    def validate_respondents(self, value):
        return _reject_entity_actors(value)

    def validate_reviewers(self, value):
        return _reject_entity_actors(value)

    def validate_answers(self, value):
        if value is not None and not isinstance(value, dict):
            raise serializers.ValidationError("answers must be an object keyed by URN")
        return value

    def validate(self, attrs):
        attrs = super().validate(attrs)
        if (
            self.instance
            and attrs.get("answers")
            and self.instance.status != QuickFormResponse.Status.DRAFT
        ):
            raise serializers.ValidationError(
                {
                    "answers": "Answers can only be modified while the response is in progress."
                }
            )
        # The content of a request belongs to whoever is asking. A reviewer with change
        # rights on the domain sends it back with a note; they do not answer it for you.
        if self.instance and attrs.get("answers") is not None:
            request = self.context.get("request")
            if request is not None and not self.instance.is_requester(request.user):
                raise serializers.ValidationError(
                    {"answers": "Only the requester can change the answers."}
                )
        if self.instance and "quick_form" in attrs:
            if attrs["quick_form"] != self.instance.quick_form:
                raise serializers.ValidationError(
                    {
                        "quick_form": "The form of an existing response cannot be changed."
                    }
                )
        return attrs

    def _apply_answers(self, instance, answers_data):
        from core.utils import apply_answers_dict

        questions_by_urn = {
            q.urn: q
            for q in Question.objects.filter(
                page__quick_form_id=instance.quick_form_id
            ).prefetch_related("choices")
        }
        apply_answers_dict(
            "response",
            instance,
            questions_by_urn,
            answers_data,
            user=getattr(self.context.get("request"), "user", None),
        )
        instance.refresh_title_from_answers()

    def create(self, validated_data):
        from core.tasks import send_quick_form_started_notification

        answers_data = validated_data.pop("answers", None)
        start_now = validated_data.pop("start_now", False)
        request = self.context.get("request")
        with transaction.atomic():
            if not validated_data.get("reviewers") and request is not None:
                # Someone has to hear about the submission: default the
                # reviewers to the creator when none were picked.
                creator_actor = Actor.objects.filter(user=request.user).first()
                if creator_actor is not None:
                    validated_data["reviewers"] = [creator_actor]
            instance = super().create(validated_data)
            instance.seed_answers()
            if answers_data:
                self._apply_answers(instance, answers_data)
            if start_now:
                instance.started_at = timezone.now()
                instance.save(update_fields=["started_at"])
                transaction.on_commit(
                    lambda pk=instance.pk: send_quick_form_started_notification(pk)
                )
        return instance

    def update(self, instance, validated_data):
        answers_data = validated_data.pop("answers", None)
        validated_data.pop("start_now", None)
        with transaction.atomic():
            instance = super().update(instance, validated_data)
            if answers_data:
                self._apply_answers(instance, answers_data)
        return instance
