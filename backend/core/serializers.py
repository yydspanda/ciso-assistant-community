import importlib
from collections import defaultdict
from typing import Any
from uuid import UUID

import structlog
from django.db import DatabaseError, models, transaction
from django.db.models.fields.related import ManyToManyRel
from datetime import datetime

from django.db.models import F
from django.utils import timezone

from django.conf import settings
from core.models import *
from core.assignment_access import (
    AssignmentAnswerValidationError,
    ComplianceAssessmentRelocationError,
    assert_assignment_folder_owner,
    assert_assignment_recompute_scope_complete,
    build_assignment_answer_context,
    get_bound_assignment_scope,
    relocate_compliance_assessment_tree,
    validate_assignment_answers,
)
from core.questionnaire import (
    QuestionnaireAnswerError,
    is_question_dependency_valid_strict,
    is_question_visible_strict,
    normalize_question_answer,
)
from core.reserved_iam import (
    MANAGED_TPRM_RESPONDENT_IAM_ERROR,
    ManagedTprmRespondentIamError,
    assert_tprm_membership_change_allowed,
    assert_tprm_role_assignment_write_allowed,
    assert_tprm_user_group_write_allowed,
    lock_and_assert_no_tprm_idp_group_inheritance,
)
from core.relation_locking import (
    lock_assessment_relation_targets,
    lock_owner_folder_write_scope,
    lock_questionnaire_owner_graph,
    lock_rows_in_global_model_order,
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
from global_settings.utils import ff_is_enabled
from iam.models import *
from django.contrib.auth.models import Permission

from rest_framework import serializers
from rest_framework.exceptions import PermissionDenied
from django.core.exceptions import (
    FieldDoesNotExist,
    ValidationError as DjangoValidationError,
)

from integrations.models import (
    IntegrationConfiguration,
    IntegrationProvider,
    SyncMapping,
)

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

    def validate_folder(self, folder: Folder | None) -> Folder | None:
        """Enforce permission when an object is moved to a different folder."""
        # A few write contracts use an explicit null as a redacted full-form
        # placeholder and resolve it under the model's locked update. Let the
        # model serializer decide whether null is valid instead of dereferencing
        # it in this generic permission hook.
        if folder is None:
            return None
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
        self._check_object_perm(instance, "change")
        if hasattr(instance, "urn") and getattr(instance, "urn"):
            raise PermissionDenied({"urn": "Imported objects cannot be modified"})
        try:
            object_updated = super().update(instance, validated_data)
            return object_updated
        except DatabaseError:
            # Preserve SQLSTATE for the view boundary, which converts
            # retryable lock conflicts into a fixed 409 response.
            raise
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

    def _filter_writable_related_representation(self, data):
        """Mask related IDs in write responses using independent model IAM.

        DRF returns ``WriteSerializer.data`` after create/update, bypassing the
        list/retrieve projection filter in the view layer.  Callers that expose
        writable relationship fields can use this helper so a successful write
        does not echo UUIDs that the same caller cannot independently read.
        """

        request = self.context.get("request")
        user = getattr(request, "user", None)
        if user is None or not getattr(user, "is_authenticated", False):
            return data
        allowed_by_model = {}
        for field_name, field in self.fields.items():
            if field_name not in data:
                continue
            relation = getattr(field, "child_relation", field)
            queryset = getattr(relation, "queryset", None)
            model = getattr(queryset, "model", None)
            if model is None:
                source_name = field.source or field_name
                if source_name != "*":
                    try:
                        model_field = self.Meta.model._meta.get_field(source_name)
                    except FieldDoesNotExist:
                        model_field = None
                    if model_field is not None and model_field.is_relation:
                        model = model_field.related_model
            if model is None:
                continue
            if model not in allowed_by_model:
                try:
                    allowed_by_model[model] = {
                        str(value)
                        for value in RoleAssignment.get_viewable_object_ids(user, model)
                    }
                except (NotImplementedError, Permission.DoesNotExist):
                    allowed_by_model[model] = set()
            allowed_ids = allowed_by_model[model]
            value = data[field_name]
            if isinstance(value, list):
                raw_ids = {
                    str(item.get("id") if isinstance(item, dict) else item)
                    for item in value
                }
                if not raw_ids.issubset(allowed_ids):
                    # A partial list is not a safe full-form value. Omit the
                    # field entirely so response-driven PUT clients preserve
                    # the relationship instead of replacing it with a subset.
                    data.pop(field_name, None)
            elif value is not None:
                raw_id = value.get("id") if isinstance(value, dict) else value
                if str(raw_id) not in allowed_ids:
                    data.pop(field_name, None)
        return data

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
        exclude = ["is_published"]


class VulnerabilityWriteSerializer(BaseModelSerializer):
    findings = serializers.PrimaryKeyRelatedField(
        many=True, required=False, queryset=Finding.objects.all()
    )

    class Meta:
        model = Vulnerability
        exclude = ["created_at", "updated_at", "is_published"]


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


def _visible_sync_mapping_projection(instance, context) -> list[dict[str, Any]]:
    """Project integration state only through both mapping and config IAM.

    SyncMapping uses a generic foreign key, so the local UUID alone is not an
    object identity.  The content type, local UUID, independently visible
    mapping, independently visible configuration, and owner folder must all
    agree before remote identifiers or provider/error details can be returned.
    """

    request = context.get("request")
    user = getattr(request, "user", None)
    if user is None or not getattr(user, "is_authenticated", False):
        return []

    try:
        visible_config_ids = RoleAssignment.get_viewable_object_ids(
            user, IntegrationConfiguration
        )
        visible_provider_ids = RoleAssignment.get_viewable_object_ids(
            user, IntegrationProvider
        )
        visible_mapping_ids = RoleAssignment.get_viewable_object_ids(user, SyncMapping)
    except (NotImplementedError, Permission.DoesNotExist):
        return []

    from django.contrib.contenttypes.models import ContentType

    content_type = ContentType.objects.get_for_model(type(instance))
    mappings = (
        SyncMapping.objects.filter(
            id__in=visible_mapping_ids,
            configuration_id__in=visible_config_ids,
            configuration__provider_id__in=visible_provider_ids,
            content_type=content_type,
            local_object_id=instance.id,
            folder_id=instance.folder_id,
            configuration__folder_id=instance.folder_id,
            configuration__is_active=True,
            configuration__provider__is_active=True,
        )
        .select_related("configuration__provider")
        .only(
            "id",
            "remote_id",
            "sync_status",
            "last_synced_at",
            "last_sync_direction",
            "error_message",
            "configuration__folder_id",
            "configuration__is_active",
            "configuration__provider_id",
            "configuration__provider__name",
            "configuration__provider__folder_id",
            "configuration__provider__is_active",
        )
        .order_by("id")
    )
    coherent_provider_folder_ids = {
        instance.folder_id,
        *Folder.objects.filter(descendants__id=instance.folder_id).values_list(
            "id", flat=True
        ),
    }
    return [
        {
            "id": mapping.id,
            "remote_id": mapping.remote_id,
            "sync_status": mapping.sync_status,
            "last_synced_at": mapping.last_synced_at,
            "last_sync_direction": mapping.last_sync_direction,
            "error_message": mapping.error_message,
            "provider": mapping.configuration.provider.name,
        }
        for mapping in mappings
        if mapping.configuration.provider.folder_id in coherent_provider_folder_ids
    ]


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
        sync_mappings = _visible_sync_mapping_projection(instance, self.context)
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

    class Meta:
        model = AppliedControl
        fields = ["id", "name", "ref_id", "folder"]

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
        exclude = ["created_at", "updated_at", "is_published"]


class AssetClassWriteSerializer(BaseModelSerializer):
    # Built-ins are re-seeded at every startup: they are hidable, not editable.
    BUILTIN_EDITABLE_FIELDS = {"is_visible"}

    class Meta:
        model = AssetClass
        exclude = ["created_at", "updated_at", "folder", "is_published"]

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


class AppliedControlWriteSerializer(CustomFieldsSerializerMixin, BaseModelSerializer):
    findings = serializers.PrimaryKeyRelatedField(
        many=True, required=False, queryset=Finding.objects.all()
    )
    requirement_assessments = serializers.PrimaryKeyRelatedField(
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

    def create(self, validated_data: Any):
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

        return applied_control

    def update(self, instance, validated_data):
        # Track old owners before update
        old_owner_ids = set(instance.owner.values_list("id", flat=True))

        findings = validated_data.pop("findings", None)
        task_templates = validated_data.pop("task_templates", None)
        incidents = validated_data.pop("incidents", None)

        updated_instance = super().update(instance, validated_data)

        if findings is not None:
            updated_instance.findings.set(findings)
        if task_templates is not None:
            updated_instance.task_templates.set(task_templates)
        if incidents is not None:
            updated_instance.incidents.set(incidents)

        # Get new owners after update
        new_owner_ids = set(updated_instance.owner.values_list("id", flat=True))

        # Send notifications only to newly assigned owners
        newly_assigned_ids = new_owner_ids - old_owner_ids
        if newly_assigned_ids:
            self._send_assignment_notifications(
                updated_instance, list(newly_assigned_ids)
            )

        return updated_instance

    def to_representation(self, instance):
        ret = super().to_representation(instance)
        ret = self._filter_writable_related_representation(ret)
        sync_mappings = _visible_sync_mapping_projection(instance, self.context)
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

            if assigned_emails:
                control_id = applied_control.id
                emails = tuple(assigned_emails)
                transaction.on_commit(
                    lambda: send_applied_control_assignment_notification(
                        control_id, list(emails)
                    )
                )
        except Exception as e:
            logger.error(
                f"Failed to send AppliedControl assignment notification: {str(e)}"
            )

    class Meta:
        model = AppliedControl
        fields = "__all__"


class AppliedControlReadSerializer(AppliedControlWriteSerializer):
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

    ranking_score = serializers.IntegerField(source="get_ranking_score")
    owner = FieldsRelatedField(many=True)
    security_exceptions = FieldsRelatedField(many=True)
    state = serializers.SerializerMethodField()
    findings_count = serializers.IntegerField(source="findings.count")
    is_assigned = serializers.BooleanField(read_only=True)
    linked_models = serializers.SerializerMethodField()

    def get_linked_models(self, obj):
        from core.views import APPLIED_CONTROL_LINKED_FIELD_NAMES

        return [
            name
            for name in APPLIED_CONTROL_LINKED_FIELD_NAMES
            if getattr(obj, f"has_{name}", False)
        ]

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

    def to_representation(self, instance):
        # skip Write/Read.to_representation, which query SyncMapping per row
        return BaseModelSerializer.to_representation(self, instance)


class AppliedControlListSerializer(BaseModelSerializer):
    """
    Lightweight serializer for the applied controls list view.

    Drops the per-row DB-touching fields from `AppliedControlReadSerializer`
    that the list table does not render:
      - `findings_count` (source="findings.count" → COUNT per row)
      - `ranking_score` (iterates non-prefetched risk_scenarios → 1 query per row)
      - `annual_cost` / `annual_cost_display` / `currency`
        (property hits GlobalSettings per row, called twice)
      - `state`, `evidences`, `objectives`, `security_exceptions`, `path`
        (not displayed on the table)

    Inherits from `BaseModelSerializer` (not `AppliedControlWriteSerializer`)
    to skip the unconditional `SyncMapping` query in Write.to_representation
    that would otherwise also fire per row on the list.
    """

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
    is_assigned = serializers.SerializerMethodField()
    linked_models = serializers.SerializerMethodField()

    class Meta:
        model = AppliedControl
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
            "is_assigned",
            "linked_models",
            "created_at",
            "updated_at",
        ]

    def get_is_assigned(self, obj):
        # `owner` is prefetched on the list path; `.all()` hits the prefetch
        # cache, while `.exists()` (the model @property) bypasses it.
        return bool(obj.owner.all())

    def get_linked_models(self, obj):
        from core.views import APPLIED_CONTROL_LINKED_FIELD_NAMES

        return [
            name
            for name in APPLIED_CONTROL_LINKED_FIELD_NAMES
            if getattr(obj, f"has_{name}", False)
        ]


class ActionPlanSerializer(BaseModelSerializer):
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

    ranking_score = serializers.IntegerField(source="get_ranking_score")
    owner = FieldsRelatedField(many=True)

    class Meta:
        model = AppliedControl
        fields = "__all__"


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

    class Meta:
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
            RiskScenario.objects.filter(risk_assessment=pk)
            .filter(Q(applied_controls=obj) | Q(existing_applied_controls=obj))
            .distinct()
        )
        return [
            {
                "str": str(req.ref_id + " - " + req.name),
                "id": str(req.id),
            }
            for req in risk_scenarios
        ]

    class Meta:
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
            "folder",
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


def _managed_tprm_iam_permission_denied(exc):
    raise PermissionDenied({"error": MANAGED_TPRM_RESPONDENT_IAM_ERROR}) from exc


def _lock_user_groups(groups):
    """Return fresh, locked group rows after the folder-tree mutex is held."""

    group_ids = {group.id for group in groups}
    locked_groups = list(
        UserGroup.objects.select_for_update(of=("self",))
        .select_related("folder")
        .filter(id__in=group_ids)
        .order_by("id")
    )
    if {group.id for group in locked_groups} != group_ids:
        raise PermissionDenied("One or more user groups are unavailable; retry.")
    return locked_groups


def _lock_optional_user_group(group):
    if group is None:
        return None
    return _lock_user_groups((group,))[0]


class UserWriteSerializer(BaseModelSerializer):
    is_local = serializers.BooleanField(required=False)
    has_mfa_enabled = serializers.BooleanField(read_only=True)

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

    @transaction.atomic
    def create(self, validated_data):
        # The TPRM exact-replacement path takes this same mutex before it owns
        # enclave membership.  Holding it through the generic write closes the
        # otherwise possible validate-then-replace race.
        Folder._lock_folder_tree()
        proposed_groups = _lock_user_groups(validated_data.get("user_groups", []))
        try:
            assert_tprm_membership_change_allowed(
                current_groups=(), proposed_groups=proposed_groups
            )
        except ManagedTprmRespondentIamError as exc:
            _managed_tprm_iam_permission_denied(exc)
        if "user_groups" in validated_data:
            validated_data["user_groups"] = proposed_groups

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

    @transaction.atomic
    def update(self, instance: User, validated_data: Any) -> User:
        Folder._lock_folder_tree()
        locked_instance = User.objects.select_for_update(of=("self",)).get(
            id=instance.id
        )
        user_groups_data = validated_data.get("user_groups")
        if user_groups_data is not None:
            initial_groups = _lock_user_groups(locked_instance.user_groups.all())
            new_groups = _lock_user_groups(user_groups_data)
            try:
                assert_tprm_membership_change_allowed(
                    current_groups=initial_groups,
                    proposed_groups=new_groups,
                )
            except ManagedTprmRespondentIamError as exc:
                _managed_tprm_iam_permission_denied(exc)

            if {group.id for group in initial_groups} != {
                group.id for group in new_groups
            }:
                logger.info(
                    "user groups updated",
                    user=locked_instance,
                    initial_user_groups=initial_groups,
                    new_user_groups=new_groups,
                )
            validated_data["user_groups"] = new_groups
        return super().update(locked_instance, validated_data)

    @transaction.atomic
    def delete(self, instance: User) -> None:
        Folder._lock_folder_tree()
        # A historical IdP mapping can make this user's membership part of a
        # TPRM respondent grant.  Lock and validate that full inheritance graph
        # before deleting the User, otherwise CASCADE would silently erase the
        # membership row and make damaged authority appear repaired.
        idp_group_ids = tuple(
            IdPGroup.objects.filter(users__id=instance.id)
            .order_by("id")
            .values_list("id", flat=True)
        )
        try:
            lock_and_assert_no_tprm_idp_group_inheritance(
                idp_group_ids=idp_group_ids
            )
        except ManagedTprmRespondentIamError as exc:
            _managed_tprm_iam_permission_denied(exc)
        locked_instance = User.objects.select_for_update(of=("self",)).get(
            id=instance.id
        )
        if set(locked_instance.idp_groups.values_list("id", flat=True)) != set(
            idp_group_ids
        ):
            _managed_tprm_iam_permission_denied(ManagedTprmRespondentIamError())
        current_groups = _lock_user_groups(locked_instance.user_groups.all())
        try:
            assert_tprm_membership_change_allowed(
                current_groups=current_groups, proposed_groups=()
            )
        except ManagedTprmRespondentIamError as exc:
            _managed_tprm_iam_permission_denied(exc)
        return super().delete(locked_instance)


def build_autocomplete_serializer(model_cls, extra_fields=()):
    """Build a lightweight serializer for autocomplete/entity pickers: ``id`` plus
    the given fields, and always a display ``str``. Enables server-side search so
    pickers scale to large datasets without loading every row client-side. Used by
    core.views.AutocompleteMixin."""

    class _AutocompleteSerializer(BaseModelSerializer):
        class Meta:
            model = model_cls
            fields = ["id", *extra_fields]

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

    @staticmethod
    def _assert_write_allowed(*, current_group=None, proposed_folder=None):
        try:
            assert_tprm_user_group_write_allowed(
                current_group=current_group,
                proposed_folder=proposed_folder,
            )
        except ManagedTprmRespondentIamError as exc:
            _managed_tprm_iam_permission_denied(exc)

    @transaction.atomic
    def create(self, validated_data):
        Folder._lock_folder_tree()
        self._assert_write_allowed(proposed_folder=validated_data.get("folder"))
        return super().create(validated_data)

    @transaction.atomic
    def update(self, instance, validated_data):
        Folder._lock_folder_tree()
        locked_instance = (
            UserGroup.objects.select_for_update(of=("self",))
            .select_related("folder")
            .get(id=instance.id)
        )
        proposed_folder = validated_data.get("folder", locked_instance.folder)
        self._assert_write_allowed(
            current_group=locked_instance,
            proposed_folder=proposed_folder,
        )
        return super().update(locked_instance, validated_data)

    @transaction.atomic
    def delete(self, instance):
        Folder._lock_folder_tree()
        # Treat the group as a proposed mapping scope so the complete
        # UserGroup -> RoleAssignment/perimeter -> IdP graph is locked even
        # when the group itself lives in an ordinary domain.  Deleting a
        # damaged group must not CASCADE away the evidence or its mapping.
        try:
            lock_and_assert_no_tprm_idp_group_inheritance(
                proposed_user_group_ids=(instance.id,)
            )
        except ManagedTprmRespondentIamError as exc:
            _managed_tprm_iam_permission_denied(exc)
        locked_instance = (
            UserGroup.objects.select_for_update(of=("self",))
            .select_related("folder")
            .get(id=instance.id)
        )
        self._assert_write_allowed(current_group=locked_instance)
        return super().delete(locked_instance)


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

    @staticmethod
    def _assert_mapping_change_allowed(*, current_groups, proposed_groups):
        try:
            assert_tprm_membership_change_allowed(
                current_groups=current_groups,
                proposed_groups=proposed_groups,
            )
        except ManagedTprmRespondentIamError as exc:
            _managed_tprm_iam_permission_denied(exc)

    @staticmethod
    def _lock_complete_mapping_scope(*, idp_group_ids=(), proposed_groups=()):
        try:
            lock_and_assert_no_tprm_idp_group_inheritance(
                idp_group_ids=idp_group_ids,
                proposed_user_group_ids=(group.id for group in proposed_groups),
            )
        except ManagedTprmRespondentIamError as exc:
            _managed_tprm_iam_permission_denied(exc)

    @transaction.atomic
    def create(self, validated_data):
        Folder._lock_folder_tree()
        proposed_groups = validated_data.get("user_groups", [])
        self._lock_complete_mapping_scope(proposed_groups=proposed_groups)
        proposed_groups = _lock_user_groups(proposed_groups)
        self._assert_mapping_change_allowed(
            current_groups=(), proposed_groups=proposed_groups
        )
        if "user_groups" in validated_data:
            validated_data["user_groups"] = proposed_groups
        return super().create(validated_data)

    @transaction.atomic
    def update(self, instance, validated_data):
        Folder._lock_folder_tree()
        locked_instance = IdPGroup.objects.select_for_update(of=("self",)).get(
            id=instance.id
        )
        self._lock_complete_mapping_scope(
            idp_group_ids=(locked_instance.id,),
            proposed_groups=validated_data.get("user_groups", ()),
        )
        if "user_groups" in validated_data:
            current_groups = _lock_user_groups(locked_instance.user_groups.all())
            proposed_groups = _lock_user_groups(validated_data["user_groups"])
            self._assert_mapping_change_allowed(
                current_groups=current_groups,
                proposed_groups=proposed_groups,
            )
            validated_data["user_groups"] = proposed_groups
        return super().update(locked_instance, validated_data)

    @transaction.atomic
    def delete(self, instance):
        Folder._lock_folder_tree()
        locked_instance = IdPGroup.objects.select_for_update(of=("self",)).get(
            id=instance.id
        )
        self._lock_complete_mapping_scope(idp_group_ids=(locked_instance.id,))
        current_groups = _lock_user_groups(locked_instance.user_groups.all())
        self._assert_mapping_change_allowed(
            current_groups=current_groups, proposed_groups=()
        )
        return super().delete(locked_instance)


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
    class Meta:
        model = RoleAssignment
        fields = "__all__"


class RoleAssignmentWriteSerializer(BaseModelSerializer):
    class Meta:
        model = RoleAssignment
        fields = "__all__"

    @staticmethod
    def _assert_write_allowed(*, folder, role, user_group, perimeter_folders):
        try:
            assert_tprm_role_assignment_write_allowed(
                folder=folder,
                role=role,
                user_group=user_group,
                perimeter_folders=perimeter_folders,
            )
        except ManagedTprmRespondentIamError as exc:
            _managed_tprm_iam_permission_denied(exc)

    @classmethod
    def _assert_instance_allowed(cls, instance):
        cls._assert_write_allowed(
            folder=instance.folder,
            role=instance.role,
            user_group=instance.user_group,
            perimeter_folders=instance.perimeter_folders.all(),
        )

    @transaction.atomic
    def create(self, validated_data):
        Folder._lock_folder_tree()
        user_group = _lock_optional_user_group(validated_data.get("user_group"))
        self._assert_write_allowed(
            folder=validated_data.get("folder"),
            role=validated_data.get("role"),
            user_group=user_group,
            perimeter_folders=validated_data.get("perimeter_folders", ()),
        )
        if "user_group" in validated_data:
            validated_data["user_group"] = user_group
        return super().create(validated_data)

    @transaction.atomic
    def update(self, instance, validated_data):
        Folder._lock_folder_tree()
        locked_instance = (
            RoleAssignment.objects.select_for_update(of=("self",))
            .select_related("folder", "role", "user_group", "user_group__folder")
            .get(id=instance.id)
        )
        self._assert_instance_allowed(locked_instance)
        user_group = _lock_optional_user_group(
            validated_data.get("user_group", locked_instance.user_group)
        )
        self._assert_write_allowed(
            folder=validated_data.get("folder", locked_instance.folder),
            role=validated_data.get("role", locked_instance.role),
            user_group=user_group,
            perimeter_folders=validated_data.get(
                "perimeter_folders", locked_instance.perimeter_folders.all()
            ),
        )
        if "user_group" in validated_data:
            validated_data["user_group"] = user_group
        return super().update(locked_instance, validated_data)

    @transaction.atomic
    def delete(self, instance):
        Folder._lock_folder_tree()
        locked_instance = (
            RoleAssignment.objects.select_for_update(of=("self",))
            .select_related("folder", "role", "user_group", "user_group__folder")
            .get(id=instance.id)
        )
        self._assert_instance_allowed(locked_instance)
        return super().delete(locked_instance)


class FolderWriteSerializer(BaseModelSerializer):
    class Meta:
        model = Folder
        exclude = [
            "builtin",
            "content_type",
            "descendants",
        ]

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

    def validate_parent_folder(self, value):
        """
        If parent_folder is empty or None, default to the root folder.
        On update, check add permission on the target parent folder.
        """
        if not value:
            return Folder.get_root_folder()
        if (
            self.instance is not None
            and self.instance.parent_folder_id
            and str(value.id) != str(self.instance.parent_folder_id)
        ):
            self._check_object_perm(self.instance, "add", folder=value)
        return value


class FolderReadSerializer(BaseModelSerializer):
    path = PathField(read_only=True)
    parent_folder = FieldsRelatedField()
    filtering_labels = FieldsRelatedField(many=True)

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


# Compliance Assessment


_REQUIREMENT_NODE_SCORE_METADATA_FIELDS = (
    "min_score",
    "max_score",
    "scores_definition_ref",
    "target_score",
    "weight",
)


def _assignment_score_is_visible(context, *, user, scope=None) -> bool | None:
    """Resolve score visibility from the exact assignment assessment policy.

    ``None`` means this is an ordinary, non-assignment serializer context.  An
    assignment marker that cannot be authenticated fails closed.  The policy
    cache is deliberately separate from generic IAM caches: assignment
    authority must never become a reusable object visibility grant.
    """

    if context.get("requirement_assignment_scope") is None:
        return None
    if scope is None:
        scope = get_bound_assignment_scope(context, user=user)
    if scope is None:
        return False

    cache = context.setdefault("_assignment_score_visibility", {})
    cache_key = (
        scope.user_id,
        scope.assignment_id,
        scope.compliance_assessment_id,
        scope.viewer_role,
    )
    cached = cache.get(cache_key)
    if isinstance(cached, bool):
        return cached

    policy = (
        ComplianceAssessment.objects.filter(
            id=scope.compliance_assessment_id,
            framework_id=scope.framework_id,
        )
        .values("field_visibility", "framework__field_visibility")
        .first()
    )
    if policy is None:
        cache[cache_key] = False
        return False

    from core.utils import resolve_visibility_from_overrides

    overrides = policy["field_visibility"] or policy["framework__field_visibility"]
    pair = resolve_visibility_from_overrides(overrides, "score")
    visible = pair.get(scope.viewer_role, "edit") != "hidden"
    cache[cache_key] = visible
    return visible


def _generic_visible_object_ids(context, user, model):
    """Return one user-bound generic IAM snapshot for a model."""

    cache = context.setdefault("_generic_iam_visible_ids", {})
    cache_key = (user.id, model)
    visible_ids = cache.get(cache_key)
    if visible_ids is None:
        visible_ids = frozenset(RoleAssignment.get_viewable_object_ids(user, model))
        cache[cache_key] = visible_ids
    return visible_ids


def _generic_answer_projection_ids(context, user):
    """Cache generic answer-carrier IAM without assignment delegation."""

    cache = context.setdefault("_generic_answer_projection_visibility", {})
    visibility = cache.get(user.id)
    if visibility is None:
        visibility = (
            _generic_visible_object_ids(context, user, Answer),
            _generic_visible_object_ids(context, user, Question),
            _generic_visible_object_ids(context, user, QuestionChoice),
        )
        cache[user.id] = visibility
    return visibility


def _assignment_question_projection_snapshots(
    context,
    *,
    user,
    scope,
    requirement_assessments,
):
    """Hydrate exact question/choice carriers for an assignment row batch."""

    if not scope.is_bound_to_user(user):
        return {}
    rows = [
        row
        for row in requirement_assessments
        if scope.allows_requirement_assessment(row)
    ]
    if not rows:
        return {}

    (
        _generic_answer_ids,
        generic_question_ids,
        generic_choice_ids,
    ) = _generic_answer_projection_ids(context, user)
    scoped_question_ids_by_row = {
        row.id: scope.question_ids_for_requirement_assessment(row.id) for row in rows
    }
    scoped_question_ids = frozenset().union(*scoped_question_ids_by_row.values())
    scoped_choice_ids = scope.choice_ids_for_questions(scoped_question_ids)
    projected_choice_ids = set(generic_choice_ids) | set(scoped_choice_ids)
    questions = list(
        Question.objects.filter(
            id__in=set(generic_question_ids) | set(scoped_question_ids),
            requirement_node_id__in={row.requirement_id for row in rows},
        )
        .annotate(
            _has_configured_choices=models.Exists(
                QuestionChoice.objects.filter(question_id=models.OuterRef("pk"))
            )
        )
        .prefetch_related(
            models.Prefetch(
                "choices",
                queryset=QuestionChoice.objects.filter(id__in=projected_choice_ids),
            )
        )
    )
    questions_by_node: dict[UUID, list] = {}
    for question in questions:
        questions_by_node.setdefault(question.requirement_node_id, []).append(question)

    question_ids = {question.id for question in questions}
    choice_rows = QuestionChoice.objects.filter(
        id__in=projected_choice_ids,
        question_id__in=question_ids,
    ).values_list("id", "question_id", "urn")
    choice_ids_by_question: dict[UUID, set[UUID]] = {}
    choice_urns_by_question: dict[UUID, set[str]] = {}
    for choice_id, question_id, choice_urn in choice_rows:
        is_bound_choice = (question_id, choice_id) in scope.choice_bindings
        if choice_id in generic_choice_ids or is_bound_choice:
            choice_ids_by_question.setdefault(question_id, set()).add(choice_id)
            if choice_urn:
                choice_urns_by_question.setdefault(question_id, set()).add(choice_urn)

    snapshots = {}
    for row in rows:
        allowed_question_ids = set(generic_question_ids) | set(
            scoped_question_ids_by_row[row.id]
        )
        row_questions = [
            question
            for question in questions_by_node.get(row.requirement_id, ())
            if question.id in allowed_question_ids
        ]
        snapshots[row.id] = (
            row_questions,
            {
                question.id: frozenset(choice_ids_by_question.get(question.id, ()))
                for question in row_questions
            },
            {
                question.id: frozenset(choice_urns_by_question.get(question.id, ()))
                for question in row_questions
            },
        )
    return snapshots


class FrameworkReadSerializer(ReferentialSerializer):
    folder = FieldsRelatedField()
    library = FieldsRelatedField(["name", "id", "urn"])
    reference_controls = FieldsRelatedField(many=True)
    is_dynamic = serializers.BooleanField(read_only=True)
    has_update = serializers.BooleanField(read_only=True)
    has_compliance_assessments = serializers.SerializerMethodField()
    scores_definition = serializers.SerializerMethodField()
    # The complete per-role visibility map a new CA created from this framework
    # would inherit: DEFAULT_VISIBILITY ⊕ framework.field_visibility. The
    # CA-creation form's editor reads this so its pills always reflect what
    # the backend will actually save.
    effective_field_visibility = serializers.SerializerMethodField()

    implementation_groups_definition = serializers.SerializerMethodField()

    def get_implementation_groups_definition(self, obj):
        return obj.get_implementation_groups_definition_translated()

    def get_has_compliance_assessments(self, obj):
        return obj.complianceassessment_set.exists()

    def get_scores_definition(self, obj):
        sd = obj.scores_definition
        if isinstance(sd, dict) and "scale" in sd:
            return sd["scale"]
        return sd

    def get_effective_field_visibility(self, obj):
        from core.utils import build_initial_field_visibility

        return build_initial_field_visibility(obj)

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

    def _generic_questionnaire_visibility(self, user, requirement_node_id):
        """Return generic-IAM questionnaire visibility for one exact node."""

        cache_by_user = self.context.setdefault("_generic_questionnaire_visibility", {})
        visibility_by_node = cache_by_user.get(user.id)
        if visibility_by_node is None:
            visible_question_ids = _generic_visible_object_ids(
                self.context, user, Question
            )
            question_rows = list(
                Question.objects.filter(id__in=visible_question_ids).values_list(
                    "id", "requirement_node_id", "urn"
                )
            )
            question_by_id = {
                question_id: (node_id, question_urn)
                for question_id, node_id, question_urn in question_rows
            }
            visible_choice_ids = _generic_visible_object_ids(
                self.context, user, QuestionChoice
            )
            choice_rows = QuestionChoice.objects.filter(
                id__in=visible_choice_ids,
                question_id__in=question_by_id,
            ).values_list("question_id", "urn")

            mutable_by_node: dict[UUID, tuple[set[str], dict[str, set[str]]]] = {}
            for _question_id, node_id, question_urn in question_rows:
                question_urns, _choice_urns = mutable_by_node.setdefault(
                    node_id, (set(), {})
                )
                question_urns.add(question_urn)
            for question_id, choice_urn in choice_rows:
                node_id, question_urn = question_by_id[question_id]
                _question_urns, choice_urns = mutable_by_node.setdefault(
                    node_id, (set(), {})
                )
                choice_urns.setdefault(question_urn, set()).add(choice_urn)

            visibility_by_node = {
                node_id: (
                    frozenset(question_urns),
                    {
                        question_urn: frozenset(choice_urns)
                        for question_urn, choice_urns in choices_by_question.items()
                    },
                )
                for node_id, (
                    question_urns,
                    choices_by_question,
                ) in mutable_by_node.items()
            }
            cache_by_user[user.id] = visibility_by_node
        return visibility_by_node.get(requirement_node_id, (frozenset(), {}))

    def _delegated_questionnaire_visibility(
        self, user, requirement_node_id, assignment_scope
    ):
        """Return assignment-delegated visibility without widening generic IAM."""

        if not assignment_scope.is_bound_to_user(user):
            return frozenset(), {}
        cache = self.context.setdefault("_assignment_questionnaire_visibility", {})
        cache_key = (
            assignment_scope.user_id,
            assignment_scope.assignment_id,
            assignment_scope.compliance_assessment_id,
        )
        visibility_by_node = cache.get(cache_key)
        if visibility_by_node is None:
            expected_node_by_question_id: dict[UUID, UUID] = {}
            for row_id, question_id in assignment_scope.question_bindings:
                node_id = assignment_scope.node_id_for(row_id)
                if node_id is not None:
                    expected_node_by_question_id[question_id] = node_id

            question_rows = list(
                Question.objects.filter(
                    id__in=expected_node_by_question_id,
                    requirement_node_id__in=(
                        assignment_scope.structural_requirement_node_ids
                    ),
                ).values_list("id", "requirement_node_id", "urn")
            )
            question_by_id = {
                question_id: (node_id, question_urn)
                for question_id, node_id, question_urn in question_rows
                if expected_node_by_question_id.get(question_id) == node_id
            }
            delegated_choice_ids = assignment_scope.choice_ids_for_questions(
                frozenset(question_by_id)
            )
            choice_rows = QuestionChoice.objects.filter(
                id__in=delegated_choice_ids,
                question_id__in=question_by_id,
            ).values_list("id", "question_id", "urn")

            mutable_by_node: dict[UUID, tuple[set[str], dict[str, set[str]]]] = {}
            for question_id, (node_id, question_urn) in question_by_id.items():
                question_urns, _choice_urns = mutable_by_node.setdefault(
                    node_id, (set(), {})
                )
                question_urns.add(question_urn)
            for choice_id, question_id, choice_urn in choice_rows:
                if (question_id, choice_id) not in assignment_scope.choice_bindings:
                    continue
                node_id, question_urn = question_by_id[question_id]
                _question_urns, choice_urns = mutable_by_node.setdefault(
                    node_id, (set(), {})
                )
                choice_urns.setdefault(question_urn, set()).add(choice_urn)

            visibility_by_node = {
                node_id: (
                    frozenset(question_urns),
                    {
                        question_urn: frozenset(choice_urns)
                        for question_urn, choice_urns in choices_by_question.items()
                    },
                )
                for node_id, (
                    question_urns,
                    choices_by_question,
                ) in mutable_by_node.items()
            }
            cache[cache_key] = visibility_by_node
        return visibility_by_node.get(requirement_node_id, (frozenset(), {}))

    def get_questions(self, obj):
        """Reconstruct the old JSON format from Question/QuestionChoice models
        for backward compatibility with the frontend."""
        questions = obj.get_questions_translated
        request = self.context.get("request")
        if not questions:
            return None
        # Preserve the established serializer contract for trusted in-process
        # callers (including library/translation tooling). API serializers are
        # given a request by DRF and continue through the exact Question and
        # QuestionChoice IAM projection below.
        if request is None:
            return questions

        assignment_scope = get_bound_assignment_scope(
            self.context,
            user=request.user,
            requirement_node=obj,
        )
        generic_question_urns, generic_choice_urns = (
            self._generic_questionnaire_visibility(request.user, obj.id)
        )
        delegated_question_urns, delegated_choice_urns = (
            self._delegated_questionnaire_visibility(
                request.user, obj.id, assignment_scope
            )
            if assignment_scope is not None
            else (frozenset(), {})
        )
        visible_question_urns = set(generic_question_urns) | set(
            delegated_question_urns
        )
        visible_choice_urns_by_question = {
            question_urn: set(choice_urns)
            for question_urn, choice_urns in generic_choice_urns.items()
        }
        for question_urn, choice_urns in delegated_choice_urns.items():
            visible_choice_urns_by_question.setdefault(question_urn, set()).update(
                choice_urns
            )

        assignment_score_visible = _assignment_score_is_visible(
            self.context,
            user=request.user,
            scope=assignment_scope,
        )
        assignment_context = (
            self.context.get("requirement_assignment_scope") is not None
        )
        filtered = {}
        for question_urn, question_data in questions.items():
            if question_urn not in visible_question_urns:
                continue
            question_data = dict(question_data)
            depends_on = question_data.get("depends_on")
            if isinstance(depends_on, dict):
                dependency_urn = depends_on.get("question")
                if dependency_urn not in visible_question_urns:
                    continue
                depends_on = dict(depends_on)
                dependency_choices = visible_choice_urns_by_question.get(
                    dependency_urn, set()
                )
                if isinstance(depends_on.get("answers"), list):
                    dependency_question = questions.get(dependency_urn)
                    dependency_has_choices = (
                        isinstance(dependency_question, dict)
                        and isinstance(dependency_question.get("choices"), list)
                        and bool(dependency_question["choices"])
                    )
                    # Preserve the established generic projection.  In an
                    # assignment, scalar parent answers remain valid strict
                    # dependency values, while choice parents are intersected
                    # with the exact authorized choice projection.
                    if not assignment_context or dependency_has_choices:
                        depends_on["answers"] = [
                            answer
                            for answer in depends_on["answers"]
                            if answer in dependency_choices
                        ]
                question_data["depends_on"] = depends_on
            if isinstance(question_data.get("choices"), list):
                visible_choice_urns = visible_choice_urns_by_question.get(
                    question_urn, set()
                )
                visible_choices = [
                    dict(choice)
                    for choice in question_data["choices"]
                    if choice.get("urn") in visible_choice_urns
                ]
                if assignment_score_visible is False:
                    for choice in visible_choices:
                        choice.pop("add_score", None)
                        choice.pop("compute_result", None)
                question_data["choices"] = visible_choices
                if not visible_choices:
                    question_data.pop("choices")
            if assignment_score_visible is False:
                question_data.pop("weight", None)
            filtered[question_urn] = question_data

        if assignment_context:
            if assignment_scope is None:
                return None
            strict_questions = {
                question_urn: {"urn": question_urn, **question_data}
                for question_urn, question_data in filtered.items()
            }
            filtered = {
                question_urn: question_data
                for question_urn, question_data in filtered.items()
                if is_question_dependency_valid_strict(
                    strict_questions[question_urn],
                    strict_questions,
                )
            }
        return filtered or None

    def to_representation(self, instance):
        data = super().to_representation(instance)
        request = self.context.get("request")
        if request is None:
            return data

        assignment_scope = get_bound_assignment_scope(
            self.context,
            user=request.user,
            requirement_node=instance,
        )
        if (
            _assignment_score_is_visible(
                self.context,
                user=request.user,
                scope=assignment_scope,
            )
            is False
        ):
            for field_name in _REQUIREMENT_NODE_SCORE_METADATA_FIELDS:
                data.pop(field_name, None)
        if assignment_scope is not None and assignment_scope.framework_id not in set(
            RoleAssignment.get_viewable_object_ids(request.user, Framework)
        ):
            # The assignment delegates node/question content, not the complete
            # framework object or its authority-bearing configuration.
            data["framework"] = None
        if assignment_scope is not None and instance.folder_id not in set(
            RoleAssignment.get_viewable_object_ids(request.user, Folder)
        ):
            data["folder"] = None

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
    def to_representation(self, instance):
        return self._filter_writable_related_representation(
            super().to_representation(instance)
        )

    def _preserve_hidden_governance_links(
        self,
        instance,
        validated_data,
        expected_relation_ids,
    ) -> None:
        request = self.context.get("request")
        if request is None:
            return
        for field_name, model in (
            ("reference_controls", ReferenceControl),
            ("threats", Threat),
        ):
            requested_items = validated_data.get(field_name)
            if not isinstance(requested_items, list):
                continue
            requested_ids = [item.id for item in requested_items]
            field = instance._meta.get_field(field_name)
            source_name = field.m2m_field_name()
            target_name = field.m2m_reverse_field_name()
            through = field.remote_field.through
            through_filter = {f"{source_name}_id": instance.id}
            discovered_current_ids = set(
                through.objects.filter(**through_filter).values_list(
                    f"{target_name}_id", flat=True
                )
            )
            target_ids = discovered_current_ids | set(requested_ids)
            locked_targets = {
                item.id: item
                for item in model.objects.select_for_update(of=("self",))
                .filter(id__in=target_ids)
                .order_by("id")
            }
            if set(locked_targets) != target_ids:
                raise PermissionDenied(
                    {field_name: "One or more governance links are unavailable."}
                )
            locked_current_ids = set(
                through.objects.select_for_update()
                .filter(**through_filter)
                .order_by("pk")
                .values_list(f"{target_name}_id", flat=True)
            )
            if (
                locked_current_ids != discovered_current_ids
                or locked_current_ids != expected_relation_ids[field_name]
            ):
                raise PermissionDenied(
                    {field_name: "The governance links changed concurrently; retry."}
                )
            visible_ids = set(
                RoleAssignment.get_viewable_object_ids(request.user, model)
            )
            if (set(requested_ids) - locked_current_ids) - visible_ids:
                raise PermissionDenied(
                    {field_name: "One or more governance links are unavailable."}
                )
            protected_ids = locked_current_ids - visible_ids
            validated_data[field_name] = [
                *requested_items,
                *(
                    locked_targets[item_id]
                    for item_id in sorted(protected_ids - set(requested_ids), key=str)
                ),
            ]

    def create(self, validated_data):
        with transaction.atomic():
            Folder._lock_folder_tree()
            targets_by_model = defaultdict(set)
            requested_framework = validated_data.get("framework")
            requested_folder = validated_data.get("folder")
            if requested_framework is None:
                raise serializers.ValidationError(
                    {"framework": "This field is required."}
                )
            expected_framework_folder_id = requested_framework.folder_id
            targets_by_model[Framework].add(requested_framework.id)
            targets_by_model[Folder].add(expected_framework_folder_id)
            if requested_folder is not None:
                targets_by_model[Folder].add(requested_folder.id)
            for field_name, model in (
                ("reference_controls", ReferenceControl),
                ("threats", Threat),
            ):
                requested_items = validated_data.get(field_name)
                if isinstance(requested_items, list):
                    targets_by_model[model].update(item.id for item in requested_items)

            locked_by_model = lock_rows_in_global_model_order(targets_by_model)
            request = self.context.get("request")
            if requested_framework is not None:
                requested_framework = locked_by_model[Framework][requested_framework.id]
                if requested_framework.folder_id != expected_framework_folder_id:
                    raise PermissionDenied(
                        {"framework": "The framework owner changed; retry."}
                    )
                if request is not None and requested_framework.id not in set(
                    RoleAssignment.get_viewable_object_ids(request.user, Framework)
                ):
                    raise PermissionDenied(
                        {"framework": "The target framework is unavailable."}
                    )
                validated_data["framework"] = requested_framework
            if (
                requested_folder is not None
                and requested_folder.id != requested_framework.folder_id
            ):
                raise PermissionDenied(
                    {"folder": "The requirement must use its framework folder."}
                )
            validated_data["folder"] = locked_by_model[Folder][
                requested_framework.folder_id
            ]
            for field_name, model in (
                ("reference_controls", ReferenceControl),
                ("threats", Threat),
            ):
                requested_items = validated_data.get(field_name)
                if not isinstance(requested_items, list):
                    continue
                requested_ids = {item.id for item in requested_items}
                if request is not None and requested_ids - set(
                    RoleAssignment.get_viewable_object_ids(request.user, model)
                ):
                    raise PermissionDenied(
                        {field_name: "One or more governance links are unavailable."}
                    )
                validated_data[field_name] = [
                    locked_by_model[model][item.id] for item in requested_items
                ]
            return super().create(validated_data)

    def update(self, instance, validated_data):
        # Skip the URN-based "imported objects" guard from BaseModelSerializer
        # because requirement nodes on draft frameworks should be editable.
        expected_current_folder_id = instance.folder_id
        expected_framework_id = instance.framework_id
        relation_fields = ("reference_controls", "threats")
        expected_relation_ids = {
            field_name: {item.id for item in getattr(instance, field_name).all()}
            for field_name in relation_fields
            if field_name in validated_data
        }
        try:
            with transaction.atomic():
                Folder._lock_folder_tree()
                observed = RequirementNode.objects.only(
                    "id", "framework_id", "folder_id"
                ).get(pk=instance.pk)
                if (
                    observed.framework_id != expected_framework_id
                    or observed.folder_id != expected_current_folder_id
                ):
                    raise PermissionDenied(
                        "The requirement owner changed concurrently; retry."
                    )
                requested_framework = validated_data.get("framework")
                if (
                    "framework" in validated_data
                    and getattr(requested_framework, "id", None)
                    != observed.framework_id
                ):
                    raise PermissionDenied({"framework": "This field is immutable."})
                locked_framework = None
                if observed.framework_id is not None:
                    locked_framework = Framework.objects.select_for_update(
                        of=("self",)
                    ).get(id=observed.framework_id)
                instance = RequirementNode.objects.select_for_update(of=("self",)).get(
                    pk=instance.pk, framework_id=observed.framework_id
                )
                if (
                    instance.folder_id != expected_current_folder_id
                    or instance.framework_id != expected_framework_id
                ):
                    raise PermissionDenied(
                        "The requirement owner changed concurrently; retry."
                    )
                request = self.context.get("request")
                if locked_framework is not None:
                    if request is not None and locked_framework.id not in set(
                        RoleAssignment.get_viewable_object_ids(request.user, Framework)
                    ):
                        raise PermissionDenied(
                            {"framework": "The current framework is unavailable."}
                        )
                    instance.framework = locked_framework
                    if "framework" in validated_data:
                        validated_data["framework"] = locked_framework
                else:
                    raise PermissionDenied(
                        {"framework": "The current framework is unavailable."}
                    )
                if instance.folder_id != locked_framework.folder_id:
                    raise PermissionDenied(
                        "The requirement owner chain is inconsistent."
                    )
                requested_folder = validated_data.get("folder", instance.folder)
                if getattr(requested_folder, "id", None) != locked_framework.folder_id:
                    raise PermissionDenied(
                        {"folder": "The requirement must use its framework folder."}
                    )
                folder_ids = {
                    folder_id
                    for folder_id in (
                        instance.folder_id,
                        getattr(requested_folder, "id", None),
                    )
                    if folder_id is not None
                }
                locked_folders = {
                    folder.id: folder
                    for folder in Folder.objects.select_for_update(of=("self",))
                    .filter(id__in=folder_ids)
                    .order_by("id")
                }
                if set(locked_folders) != folder_ids:
                    raise PermissionDenied(
                        {"folder": "The requirement folder is unavailable."}
                    )
                if instance.folder_id is not None:
                    instance.folder = locked_folders[instance.folder_id]
                self._check_object_perm(instance, "change")
                if getattr(requested_folder, "id", None) is not None:
                    requested_folder = locked_folders[requested_folder.id]
                    if requested_folder.id != instance.folder_id:
                        if (
                            Question.objects.filter(
                                requirement_node_id=instance.id
                            ).exists()
                            or RequirementAssessment.objects.filter(
                                requirement_id=instance.id
                            ).exists()
                        ):
                            raise serializers.ValidationError(
                                {
                                    "folder": (
                                        "A requirement with questionnaire or "
                                        "assessment children cannot change folder."
                                    )
                                }
                            )
                        self._check_object_perm(
                            instance,
                            "add",
                            folder=requested_folder,
                        )
                    if "folder" in validated_data:
                        validated_data["folder"] = requested_folder
                self.instance = instance
                validated_data = self.validate(dict(validated_data))
                self._preserve_hidden_governance_links(
                    instance,
                    validated_data,
                    expected_relation_ids,
                )
                m2m_field_names = {f.name for f in instance._meta.many_to_many}
                m2m_values = {
                    attr: validated_data.pop(attr)
                    for attr in list(validated_data.keys())
                    if attr in m2m_field_names
                }
                for attr, value in validated_data.items():
                    setattr(instance, attr, value)
                # Trigger RequirementNode.clean() for override constraints. M2M
                # fields aren't yet attached at this point; exclude them.
                instance.full_clean(exclude=list(m2m_field_names))
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


class EvidenceReadSerializer(BaseModelSerializer):
    path = PathField(read_only=True)
    attachment = serializers.SerializerMethodField()
    size = serializers.CharField(source="get_size")
    folder = FieldsRelatedField()
    applied_controls = FieldsRelatedField(many=True)
    requirement_assessments = FieldsRelatedField(many=True)
    security_exceptions = FieldsRelatedField(many=True)
    contracts = FieldsRelatedField(many=True)
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


class EvidenceWriteSerializer(BaseModelSerializer):
    applied_controls = serializers.PrimaryKeyRelatedField(
        many=True, queryset=AppliedControl.objects.all(), required=False
    )
    requirement_assessments = serializers.PrimaryKeyRelatedField(
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

    # A respondent deposits evidence but must not adjudicate it: the status
    # (in_review / approved / rejected / …) is an auditor-side decision.
    RESPONDENT_PROTECTED_FIELDS = {"status"}

    class Meta:
        model = Evidence
        exclude = ["is_published"]

    def create(self, validated_data):
        attachment = validated_data.pop("attachment", None)
        link = validated_data.pop("link", None)

        evidence = super().create(validated_data)

        EvidenceRevision.objects.get_or_create(
            evidence=evidence, defaults={"link": link, "attachment": attachment}
        )

        return evidence

    def update(self, instance, validated_data):
        # Track old folder before update
        old_folder_id = instance.folder_id

        # Handle properly owner field cleaning
        with transaction.atomic():
            instance = super().update(instance, validated_data)

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

        return self._filter_writable_related_representation(data)


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

    def create(self, validated_data):
        evidence = validated_data["evidence"]
        max_version = EvidenceRevision.objects.filter(evidence=evidence).aggregate(
            models.Max("version")
        )["version__max"]
        validated_data["version"] = (max_version or 0) + 1
        # Update evidence status to in_review when a new revision is submitted
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
    frameworks = FieldsRelatedField(many=True)
    status = serializers.CharField(source="get_status_display")
    framework = FieldsRelatedField(
        [
            "id",
            "min_score",
            "max_score",
            "implementation_groups_definition",
            "ref_id",
            "reference_controls",
        ]
    )

    class Meta:
        model = Campaign
        fields = "__all__"


class CampaignWriteSerializer(BaseModelSerializer):
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

        provenance_fields = (
            "baseline_source_assessment_id_snapshot",
            "baseline_snapshot_sha256",
            "baseline_copied_by_id_snapshot",
            "baseline_copied_at",
        )
        source_id = self._related_uuid(
            data.get("baseline_source_assessment_id_snapshot")
        )
        if (
            viewer_role != "auditor"
            or source_id is None
            or source_id not in self._visible_ids(ComplianceAssessment)
        ):
            for field_name in provenance_fields:
                data.pop(field_name, None)
        else:
            actor_id = self._related_uuid(data.get("baseline_copied_by_id_snapshot"))
            if actor_id is None or actor_id not in self._visible_ids(User):
                data.pop("baseline_copied_by_id_snapshot", None)

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
        request = self.context.get("request")
        user = getattr(request, "user", None)
        visible_ids = {}

        def visible(model):
            if user is None or not getattr(user, "is_authenticated", False):
                return set()
            if model not in visible_ids:
                visible_ids[model] = set(
                    RoleAssignment.get_viewable_object_ids(user, model)
                )
            return visible_ids[model]

        def related_id(value):
            raw_id = value.get("id") if isinstance(value, dict) else value
            try:
                return UUID(str(raw_id))
            except (TypeError, ValueError):
                return None

        folder_ids = visible(Folder)
        if related_id(data.get("folder")) not in folder_ids:
            data["folder"] = None
            data["path"] = None
        elif isinstance(data.get("path"), list):
            data["path"] = [
                value for value in data["path"] if related_id(value) in folder_ids
            ]
        if related_id(data.get("framework")) not in visible(Framework):
            data["framework"] = None
        if related_id(data.get("perimeter")) not in visible(Perimeter):
            data["perimeter"] = None
        elif isinstance(data.get("perimeter"), dict):
            perimeter_folder = data["perimeter"].get("folder")
            if (
                perimeter_folder is not None
                and related_id(perimeter_folder) not in folder_ids
            ):
                data["perimeter"]["folder"] = None
        if isinstance(data.get("authors"), list):
            visible_actor_ids = visible(Actor)
            data["authors"] = [
                value
                for value in data["authors"]
                if related_id(value) in visible_actor_ids
            ]

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
        ]


class ComplianceAssessmentWriteSerializer(BaseModelSerializer):
    GOVERNED_M2M_RELATIONS = (
        ("assets", "assets", Asset),
        ("evidences", "evidences", Evidence),
        ("authors", "authors", Actor),
        ("reviewers", "reviewers", Actor),
        ("genericcollection", "genericcollection_set", GenericCollection),
        ("ebios_rm_studies", "ebios_rm_studies", EbiosRMStudy),
    )

    folder = serializers.PrimaryKeyRelatedField(
        queryset=Folder.objects.all(),
        required=False,
        allow_null=True,
    )
    framework = serializers.PrimaryKeyRelatedField(
        queryset=Framework.objects.all(),
        required=False,
        allow_null=True,
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
    computed_outcome = serializers.JSONField(read_only=True)
    baseline_source_assessment_id_snapshot = serializers.UUIDField(read_only=True)
    baseline_snapshot_sha256 = serializers.CharField(read_only=True)
    baseline_copied_by_id_snapshot = serializers.UUIDField(read_only=True)
    baseline_copied_at = serializers.DateTimeField(read_only=True)

    def to_representation(self, instance):
        """Use the independently authorized detail projection after writes."""

        return ComplianceAssessmentReadSerializer(
            instance,
            context=self.context,
        ).data

    def _preserve_hidden_m2m_links(self, instance, validated_data) -> None:
        """Lock CA relations and retain current targets hidden from the caller."""

        request = self.context.get("request")
        if request is None:
            return
        relation_specs = []
        target_ids_by_model = {}
        for input_name, source_name, model in self.GOVERNED_M2M_RELATIONS:
            requested_items = validated_data.get(source_name)
            if not isinstance(requested_items, list):
                continue
            requested_ids = {item.id for item in requested_items}
            try:
                relation = instance._meta.get_field(source_name)
            except FieldDoesNotExist:
                relation = next(
                    (
                        candidate
                        for candidate in instance._meta.get_fields()
                        if isinstance(candidate, ManyToManyRel)
                        and candidate.get_accessor_name() == source_name
                    ),
                    None,
                )
                if relation is None:
                    raise PermissionDenied(
                        {input_name: "The relationship is unavailable."}
                    )
            if isinstance(relation, ManyToManyRel):
                forward_field = relation.field
                instance_name = forward_field.m2m_reverse_field_name()
                related_name = forward_field.m2m_field_name()
            elif isinstance(relation, models.ManyToManyField):
                forward_field = relation
                instance_name = forward_field.m2m_field_name()
                related_name = forward_field.m2m_reverse_field_name()
            else:
                raise PermissionDenied({input_name: "The relationship is unavailable."})
            through = forward_field.remote_field.through
            through_filter = {f"{instance_name}_id": instance.id}
            current_ids = set(
                through.objects.filter(**through_filter).values_list(
                    f"{related_name}_id", flat=True
                )
            )
            target_ids = current_ids | requested_ids
            target_ids_by_model.setdefault(model, set()).update(target_ids)
            relation_specs.append(
                (
                    input_name,
                    source_name,
                    model,
                    requested_items,
                    requested_ids,
                    current_ids,
                    through,
                    through_filter,
                    related_name,
                )
            )

        locked_by_model = lock_rows_in_global_model_order(target_ids_by_model)
        for (
            input_name,
            source_name,
            model,
            requested_items,
            requested_ids,
            current_ids,
            through,
            through_filter,
            related_name,
        ) in relation_specs:
            locked_targets = locked_by_model[model]
            locked_current_ids = set(
                through.objects.select_for_update()
                .filter(**through_filter)
                .order_by("pk")
                .values_list(f"{related_name}_id", flat=True)
            )
            if locked_current_ids != current_ids:
                raise PermissionDenied(
                    {input_name: "The relationship changed concurrently; retry."}
                )

            try:
                visible_ids = set(
                    RoleAssignment.get_viewable_object_ids(request.user, model)
                )
            except (NotImplementedError, Permission.DoesNotExist):
                visible_ids = set()
            if (requested_ids - locked_current_ids) - visible_ids:
                raise PermissionDenied(
                    {input_name: "One or more related objects are unavailable."}
                )
            protected_ids = locked_current_ids - visible_ids
            validated_data[source_name] = [
                *requested_items,
                *(
                    locked_targets[item_id]
                    for item_id in sorted(protected_ids - requested_ids, key=str)
                ),
            ]

    def _lock_and_authorize_create_m2m_links(self, user) -> None:
        """Re-resolve every submitted CA relationship under the create lock."""

        relation_specs = []
        target_ids_by_model = {}
        for input_name, source_name, model in self.GOVERNED_M2M_RELATIONS:
            requested_items = self.validated_data.get(source_name)
            if not isinstance(requested_items, list):
                continue
            requested_ids = {item.id for item in requested_items}
            target_ids_by_model.setdefault(model, set()).update(requested_ids)
            relation_specs.append(
                (input_name, source_name, model, requested_items, requested_ids)
            )

        locked_by_model = lock_rows_in_global_model_order(target_ids_by_model)
        for (
            input_name,
            source_name,
            model,
            requested_items,
            requested_ids,
        ) in relation_specs:
            locked_targets = locked_by_model[model]
            try:
                visible_ids = set(RoleAssignment.get_viewable_object_ids(user, model))
            except (NotImplementedError, Permission.DoesNotExist):
                visible_ids = set()
            if requested_ids - visible_ids:
                raise PermissionDenied(
                    {input_name: "One or more related objects are unavailable."}
                )
            self.validated_data[source_name] = [
                locked_targets[item.id] for item in requested_items
            ]

    def _preserve_hidden_owner_links(self, instance, validated_data) -> None:
        """Lock nullable owner FKs and protect values hidden by detail IAM."""

        request = self.context.get("request")
        if request is None:
            return
        owner_specs = []
        target_ids_by_model = {}
        for field_name, model in (
            ("perimeter", Perimeter),
            ("campaign", Campaign),
        ):
            current_id = getattr(instance, f"{field_name}_id")
            was_submitted = field_name in validated_data
            requested = (
                validated_data[field_name]
                if was_submitted
                else getattr(instance, field_name)
            )
            requested_id = getattr(requested, "id", None)
            target_ids = {value for value in (current_id, requested_id) if value}
            target_ids_by_model.setdefault(model, set()).update(target_ids)
            owner_specs.append(
                (
                    field_name,
                    model,
                    current_id,
                    requested_id,
                    was_submitted,
                )
            )

        locked_by_model = lock_rows_in_global_model_order(target_ids_by_model)
        for (
            field_name,
            model,
            current_id,
            requested_id,
            was_submitted,
        ) in owner_specs:
            locked_targets = locked_by_model[model]
            if current_id is not None:
                setattr(instance, field_name, locked_targets[current_id])
            if not was_submitted:
                continue

            visible_ids = set(
                RoleAssignment.get_viewable_object_ids(request.user, model)
            )
            if current_id is not None and current_id not in visible_ids:
                if requested_id not in (None, current_id):
                    raise PermissionDenied(
                        {
                            field_name: (
                                "The current related owner object is unavailable."
                            )
                        }
                    )
                validated_data[field_name] = locked_targets[current_id]
                continue
            if requested_id is not None and requested_id != current_id:
                if requested_id not in visible_ids:
                    raise PermissionDenied(
                        {field_name: "The related owner object is unavailable."}
                    )
                target_folder = Folder.get_folder(locked_targets[requested_id])
                if target_folder is not None:
                    self._check_object_perm(
                        instance,
                        "add",
                        folder=target_folder,
                    )

            # Never carry the pre-lock serializer instance into the save.  A
            # visible owner may have moved folders while this request waited;
            # all subsequent folder derivation must use the locked row that was
            # re-authorized above.
            if requested_id is not None:
                validated_data[field_name] = locked_targets[requested_id]

    def validate(self, attrs):
        if self.instance is None and attrs.get("framework") is None:
            raise serializers.ValidationError({"framework": "This field is required."})
        if self.instance is None and "folder" in attrs and attrs["folder"] is None:
            raise serializers.ValidationError({"folder": "This field may not be null."})
        if hasattr(self, "instance") and self.instance and self.instance.is_locked:
            # If we're unlocking (setting is_locked to False), allow the operation
            if "is_locked" in attrs and attrs["is_locked"] is False:
                return super().validate(attrs)

            # Otherwise, only allow modifying the is_locked field
            locked_fields = [field for field in attrs.keys() if field != "is_locked"]
            if locked_fields:
                raise serializers.ValidationError(
                    f"⚠️ Cannot modify the audit attributes when it is locked. Only the 'Locked' field can be modified."
                )

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
            min_s = attrs.get(
                "min_score",
                getattr(self.instance, "min_score", None) if self.instance else None,
            )
            max_s = attrs.get(
                "max_score",
                getattr(self.instance, "max_score", None) if self.instance else None,
            )
            if min_s is not None and max_s is not None:
                if not (min_s <= target <= max_s):
                    raise serializers.ValidationError(
                        {
                            "target_score": f"Target score must be between {min_s} and {max_s}."
                        }
                    )

        return super().validate(attrs)

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
        with transaction.atomic():
            # Folder.save() takes this root-row mutex before changing hierarchy
            # or hierarchy-derived closure rows.  Take it first so every IAM
            # decision below observes one stable folder tree.
            Folder._lock_folder_tree()

            # Framework identity owns the generated RequirementAssessment tree.
            # It is immutable after creation; a filtered detail form may send
            # null when the current framework is independently hidden, which is
            # treated as omission rather than detaching/corrupting that tree.
            # Observe the owner first, then take Framework -> CA locks.  Clone
            # creation uses the same order, so an ordinary audit PATCH cannot
            # deadlock a same-framework baseline clone by taking CA -> Framework.
            expected_framework_id = instance.framework_id
            observed_framework_id = (
                ComplianceAssessment.objects.filter(pk=instance.pk)
                .values_list("framework_id", flat=True)
                .get()
            )
            if observed_framework_id != expected_framework_id:
                raise PermissionDenied(
                    {"framework": "The audit's framework changed concurrently."}
                )
            requested_framework = validated_data.get("framework")
            framework_ids = {
                framework_id
                for framework_id in (
                    observed_framework_id,
                    getattr(requested_framework, "id", None),
                )
                if framework_id is not None
            }
            locked_frameworks = {
                framework.id: framework
                for framework in Framework.objects.select_for_update(of=("self",))
                .filter(id__in=framework_ids)
                .order_by("id")
            }
            if set(locked_frameworks) != framework_ids:
                raise PermissionDenied({"framework": "The framework is unavailable."})

            # Validation happens before ``serializer.save()`` in DRF. Re-read
            # and revalidate the authority-bearing audit after waiting so a
            # concurrent lock/status/folder/IAM change cannot be overwritten by
            # stale serializer state (including the generic batch endpoint).
            instance = ComplianceAssessment.objects.select_for_update(of=("self",)).get(
                pk=instance.pk
            )
            if instance.framework_id != observed_framework_id:
                raise PermissionDenied(
                    {"framework": "The audit's framework changed concurrently."}
                )
            instance.framework = locked_frameworks[instance.framework_id]
            self.instance = instance
            requested_framework = validated_data.get("framework", instance.framework)

            if "framework" in validated_data:
                if requested_framework is None:
                    request = self.context.get("request")
                    visible_ids = (
                        set(
                            RoleAssignment.get_viewable_object_ids(
                                request.user, Framework
                            )
                        )
                        if request is not None
                        else {instance.framework_id}
                    )
                    if instance.framework_id in visible_ids:
                        raise serializers.ValidationError(
                            {"framework": "This field may not be null."}
                        )
                    validated_data["framework"] = locked_frameworks[
                        instance.framework_id
                    ]
                elif requested_framework.id != instance.framework_id:
                    raise PermissionDenied(
                        {"framework": "An audit's framework is immutable."}
                    )
                else:
                    validated_data["framework"] = locked_frameworks[
                        instance.framework_id
                    ]

            if "folder" in validated_data and validated_data["folder"] is None:
                request = self.context.get("request")
                visible_folder_ids = (
                    set(RoleAssignment.get_viewable_object_ids(request.user, Folder))
                    if request is not None
                    else {instance.folder_id}
                )
                if instance.folder_id in visible_folder_ids:
                    raise serializers.ValidationError(
                        {"folder": "This field may not be null."}
                    )
                validated_data["folder"] = instance.folder
            self._preserve_hidden_owner_links(instance, validated_data)

            # Current and final owners are locked above.  Lock every folder
            # that can own or authorize the audit, then rebind stale serializer
            # objects to those rows before repeating change/add IAM checks.
            final_perimeter = validated_data.get("perimeter", instance.perimeter)
            final_campaign = validated_data.get("campaign", instance.campaign)
            requested_folder = validated_data.get("folder", instance.folder)
            folder_ids = {
                folder_id
                for folder_id in (
                    instance.folder_id,
                    getattr(requested_folder, "id", None),
                    getattr(final_perimeter, "folder_id", None),
                    getattr(final_campaign, "folder_id", None),
                )
                if folder_id is not None
            }
            locked_folders = {
                folder.id: folder
                for folder in Folder.objects.select_for_update(of=("self",))
                .filter(id__in=folder_ids)
                .order_by("id")
            }
            if set(locked_folders) != folder_ids:
                raise PermissionDenied(
                    {"folder": "One or more owner folders are unavailable."}
                )
            if instance.folder_id is not None:
                instance.folder = locked_folders[instance.folder_id]
            if getattr(requested_folder, "id", None) is not None:
                requested_folder = locked_folders[requested_folder.id]
                if "folder" in validated_data:
                    validated_data["folder"] = requested_folder
            for owner in (final_perimeter, final_campaign):
                if owner is not None and owner.folder_id is not None:
                    owner.folder = locked_folders[owner.folder_id]

            validated_data = self.validate(dict(validated_data))

            old_author_ids = set(instance.authors.values_list("id", flat=True))
            old_folder_id = instance.folder_id
            old_status = instance.status
            old_scoring_enabled = instance.scoring_enabled

            # Auto-lock when status changes to deprecated.
            new_status = validated_data.get("status", old_status)
            if old_status != "deprecated" and new_status == "deprecated":
                validated_data["is_locked"] = True

            # A perimeter owns the audit folder. Bind the derived destination
            # inside the locked update and repeat target-folder IAM here because
            # the ordinary field validator ran before this transaction.
            final_perimeter = validated_data.get("perimeter", instance.perimeter)
            if final_perimeter and final_perimeter.folder:
                supplied_folder = validated_data.get("folder")
                if (
                    supplied_folder is not None
                    and supplied_folder.id != final_perimeter.folder_id
                ):
                    raise serializers.ValidationError(
                        {
                            "folder": (
                                "The audit folder must match its perimeter folder."
                            )
                        }
                    )
                validated_data["folder"] = final_perimeter.folder
            requested_folder = validated_data.get("folder", instance.folder)
            if (
                getattr(requested_folder, "id", None) is not None
                and requested_folder.id != instance.folder_id
            ):
                self._check_object_perm(instance, "add", folder=requested_folder)

            # PATCH semantics for field_visibility: merge incoming partial map
            # onto the locked snapshot so concurrent changes are not lost.
            if "field_visibility" in validated_data:
                existing = instance.field_visibility or {}
                provided = validated_data["field_visibility"] or {}
                validated_data["field_visibility"] = {**existing, **provided}

            self._preserve_hidden_m2m_links(instance, validated_data)

            # Perform the main update (fields + M2M)
            updated_instance = super().update(instance, validated_data)

            # For dynamic frameworks, recompute IGs from current answers so the
            # answer-driven calc always wins over any manual override submitted
            # here. Manual (non-dynamic) IGs are preserved inside the helper.
            if updated_instance.framework and updated_instance.framework.is_dynamic():
                from core.utils import update_selected_implementation_groups

                update_selected_implementation_groups(updated_instance)

            # Relocate the complete owned tree or fail closed. This also
            # synchronizes assignments, events, terminal mail records and
            # answers while refusing to cross an in-flight delivery intent.
            if old_folder_id != updated_instance.folder_id:
                try:
                    relocate_compliance_assessment_tree(
                        updated_instance,
                        source_folder_id=old_folder_id,
                    )
                except ComplianceAssessmentRelocationError as exc:
                    raise serializers.ValidationError({"folder": str(exc)}) from exc

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

    folder = HashSlugRelatedField(slug_field="pk", read_only=True)
    perimeter = HashSlugRelatedField(slug_field="pk", read_only=True)

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
            "score_calculation_method",
            "target_score",
            "anchor_na_to_target",
            "field_visibility",
            "created_at",
            "updated_at",
        ]
        read_only_fields = ["computed_outcome"]


class RequirementAssessmentReadListSerializer(serializers.ListSerializer):
    """Batch mapping-provenance IAM once for a page/list response."""

    def to_representation(self, data):
        instances = list(data.all() if hasattr(data, "all") else data)
        request = self.context.get("request")
        if request is not None and instances:
            from core.utils import get_mapping_inference_visibility_context

            assignment_scope = get_bound_assignment_scope(
                self.context,
                user=request.user,
            )
            scoped_question_ids: set[UUID] = set()
            if assignment_scope is not None:
                for instance in instances:
                    if assignment_scope.allows_requirement_assessment(instance):
                        scoped_question_ids.update(
                            assignment_scope.question_ids_for_requirement_assessment(
                                instance.id
                            )
                        )
            scoped_choice_ids = (
                assignment_scope.choice_ids_for_questions(scoped_question_ids)
                if assignment_scope is not None
                else frozenset()
            )

            (
                generic_answer_ids,
                generic_question_ids,
                generic_choice_ids,
            ) = _generic_answer_projection_ids(self.context, request.user)
            visible_question_ids = set(generic_question_ids) | scoped_question_ids
            visible_choice_ids = set(generic_choice_ids) | set(scoped_choice_ids)

            if assignment_scope is not None:
                snapshots = _assignment_question_projection_snapshots(
                    self.context,
                    user=request.user,
                    scope=assignment_scope,
                    requirement_assessments=instances,
                )
                for instance in instances:
                    (
                        instance._assignment_projection_questions,
                        instance._assignment_projection_choice_ids,
                        instance._assignment_projection_choice_urns,
                    ) = snapshots.get(instance.id, ([], {}, {}))

            projected_selected_choices = (
                QuestionChoice.objects.all()
                if assignment_scope is not None
                else QuestionChoice.objects.filter(id__in=visible_choice_ids)
            )
            models.prefetch_related_objects(
                instances,
                models.Prefetch(
                    "answers",
                    queryset=Answer.objects.filter(
                        id__in=generic_answer_ids,
                        question_id__in=visible_question_ids,
                    )
                    .select_related("question")
                    .prefetch_related(
                        models.Prefetch(
                            "selected_choices",
                            queryset=projected_selected_choices,
                        )
                    ),
                    to_attr="_permission_filtered_answers",
                ),
            )

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
        parent_requirement = serializers.SerializerMethodField()

        @staticmethod
        def _parent_projection(parent):
            return {
                "str": parent.display_long,
                "urn": parent.urn,
                "id": parent.id,
                "ref_id": parent.ref_id,
                "name": parent.name,
                "description": parent.description,
            }

        def get_parent_requirement(self, obj):
            """Project an assignment parent without the model's global fallback."""

            if self.context.get("requirement_assignment_scope") is None:
                # Preserve the established generic API behavior.  The model
                # property may resolve by globally unique URN in this path,
                # after ordinary RequirementNode IAM has admitted the object.
                return obj.parent_requirement

            request = self.context.get("request")
            if request is None:
                return None
            assignment_scope = get_bound_assignment_scope(
                self.context,
                user=request.user,
                requirement_node=obj,
            )
            if assignment_scope is None or not obj.parent_urn:
                return None

            cache = self.context.setdefault(
                "_assignment_parent_requirement_projection", {}
            )
            cache_key = (
                assignment_scope.user_id,
                assignment_scope.assignment_id,
                obj.id,
                obj.parent_urn,
            )
            if cache_key in cache:
                projection = cache[cache_key]
                return dict(projection) if projection is not None else None

            parent = getattr(obj, "_parent_requirement_obj", None)
            if not (
                parent is not None
                and parent.id != obj.id
                and parent.urn == obj.parent_urn
                and assignment_scope.allows_requirement_node(parent)
            ):
                # The assignment view normally supplies the exact structural
                # parent in ``_parent_requirement_obj``.  This bounded fallback
                # is safe for other assignment serializer callers and cannot
                # cross the captured framework or structural-node set.
                parent = (
                    RequirementNode.objects.filter(
                        id__in=(assignment_scope.structural_requirement_node_ids),
                        framework_id=assignment_scope.framework_id,
                        urn=obj.parent_urn,
                    )
                    .exclude(id=obj.id)
                    .only(
                        "id",
                        "urn",
                        "ref_id",
                        "name",
                        "description",
                        "translations",
                        "framework_id",
                    )
                    .first()
                )

            projection = self._parent_projection(parent) if parent is not None else None
            cache[cache_key] = projection
            return dict(projection) if projection is not None else None

        class Meta:
            model = RequirementNode
            fields = [
                "id",
                "urn",
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

    @staticmethod
    def _strict_assignment_answers(
        *,
        questions,
        answers,
        choice_ids_by_question,
        answer_folder_id,
    ):
        allowed_choice_ids = set().union(*choice_ids_by_question.values())
        (
            _selected_choice_ids,
            answers_by_urn,
            questions_by_urn,
            _has_answer,
        ) = build_assignment_answer_context(
            questions=questions,
            answers=answers,
            allowed_choice_ids=allowed_choice_ids,
            answer_folder_id=answer_folder_id,
        )

        return {
            question_urn: answers_by_urn[question_urn]
            for question_urn, question in questions_by_urn.items()
            if question_urn in answers_by_urn
            and is_question_visible_strict(
                question,
                answers_by_urn,
                questions_by_urn,
            )
        }

    def get_answers(self, obj):
        """Reconstruct old JSON format {question_urn: answer_value} from Answer model."""
        from core.utils import build_answers_dict

        assignment_context = (
            self.context.get("requirement_assignment_scope") is not None
        )
        prefetched_answers = getattr(obj, "_permission_filtered_answers", None)
        if not assignment_context and prefetched_answers is not None:
            return build_answers_dict(prefetched_answers)

        request = self.context.get("request")
        if request is None:
            return {}
        assignment_scope = get_bound_assignment_scope(
            self.context,
            user=request.user,
            requirement_assessment=obj,
        )
        if assignment_context and assignment_scope is None:
            return {}
        scoped_question_ids = (
            assignment_scope.question_ids_for_requirement_assessment(obj.id)
            if assignment_scope is not None
            else frozenset()
        )
        scoped_choice_ids = (
            assignment_scope.choice_ids_for_questions(scoped_question_ids)
            if assignment_scope is not None
            else frozenset()
        )
        (
            visible_answer_ids,
            generic_question_ids,
            generic_choice_ids,
        ) = _generic_answer_projection_ids(self.context, request.user)
        visible_question_ids = set(generic_question_ids) | set(scoped_question_ids)
        visible_choice_ids = set(generic_choice_ids) | set(scoped_choice_ids)
        if prefetched_answers is None:
            projected_selected_choices = (
                QuestionChoice.objects.all()
                if assignment_scope is not None
                else QuestionChoice.objects.filter(id__in=visible_choice_ids)
            )
            answers = list(
                obj.answers.filter(
                    id__in=visible_answer_ids,
                    question_id__in=visible_question_ids,
                )
                .select_related("question")
                .prefetch_related(
                    models.Prefetch(
                        "selected_choices",
                        queryset=projected_selected_choices,
                    )
                )
            )
        else:
            answers = prefetched_answers

        if not assignment_context:
            return build_answers_dict(answers)

        questions = getattr(obj, "_assignment_projection_questions", None)
        choice_ids_by_question = getattr(obj, "_assignment_projection_choice_ids", None)
        choice_urns_by_question = getattr(
            obj, "_assignment_projection_choice_urns", None
        )
        if (
            questions is None
            or choice_ids_by_question is None
            or choice_urns_by_question is None
        ):
            snapshots = _assignment_question_projection_snapshots(
                self.context,
                user=request.user,
                scope=assignment_scope,
                requirement_assessments=[obj],
            )
            (
                questions,
                choice_ids_by_question,
                choice_urns_by_question,
            ) = snapshots.get(obj.id, ([], {}, {}))
        return self._strict_assignment_answers(
            questions=questions,
            answers=answers,
            choice_ids_by_question=choice_ids_by_question,
            answer_folder_id=obj.folder_id,
        )

    def to_representation(self, instance):
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
                "target_score": "score",
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
                for field_name in _REQUIREMENT_NODE_SCORE_METADATA_FIELDS:
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

            mapping_visibility = None
            if request is not None and viewer_role == "auditor":
                mapping_visibility = self.context.get("_mapping_inference_visibility")
                if mapping_visibility is None:
                    mapping_visibility = get_mapping_inference_visibility_context(
                        request.user, [instance.mapping_inference]
                    )
            sanitized_mapping = sanitize_mapping_inference_for_viewer(
                instance.mapping_inference,
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

            # An authenticated assignment scope delegates only this exact node;
            # it never delegates the framework or unrelated library content.
            assignment_scope = get_bound_assignment_scope(
                self.context,
                user=request.user,
                requirement_assessment=instance,
            )
            delegated_node_visible = assignment_scope is not None

            if (
                instance.requirement_id not in visible_cache[RequirementNode]
                and not delegated_node_visible
            ):
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


class RequirementAssessmentWriteSerializer(BaseModelSerializer):
    requirement = serializers.PrimaryKeyRelatedField(read_only=True)
    answers = serializers.JSONField(required=False, write_only=True)
    # Mapping provenance is generated by the controlled mapping service. It is
    # never client-authored or mutable through the public RA endpoint.
    mapping_inference = serializers.JSONField(read_only=True)

    def validate_compliance_assessment(self, value):
        """Keep the authority-bearing audit owner immutable after creation."""

        self._ensure_immutable("compliance_assessment", value)
        return value

    def validate_folder(self, value):
        """Keep an existing requirement assessment in its audit enclave."""

        self._ensure_immutable("folder", value)
        return value

    def to_representation(self, instance):
        """Return the same permission-filtered projection as the read API.

        DRF serializes the saved instance with the write serializer after a
        successful mutation.  Reusing the read projection prevents that 200
        response from echoing auditor-only fields or raw mapping provenance
        back to a respondent.
        """
        return RequirementAssessmentReadSerializer(
            instance,
            context=self.context,
        ).data

    def to_internal_value(self, data):
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
        request = self.context.get("request")
        raw_scope = self.context.get("requirement_assignment_scope")
        if value is not None and raw_scope is not None:
            if request is None or self.instance is None:
                raise PermissionDenied(
                    "Assignment-scoped answers require an authenticated update."
                )
            scope = get_bound_assignment_scope(
                self.context,
                user=request.user,
                requirement_assessment=self.instance,
                mutable=True,
            )
            if scope is None:
                raise PermissionDenied(
                    "The assignment questionnaire scope is unavailable."
                )
            try:
                self._normalized_assignment_answers = validate_assignment_answers(
                    scope=scope,
                    user=request.user,
                    requirement_assessment=self.instance,
                    answers_data=value,
                )
            except AssignmentAnswerValidationError as exc:
                raise serializers.ValidationError(str(exc)) from exc
        return value

    def validate(self, attrs):
        compliance_assessment = self.get_compliance_assessment()
        folder = attrs.get("folder", getattr(self.instance, "folder", None))
        if folder is None and self.instance is None:
            folder = compliance_assessment.folder
            attrs["folder"] = folder
        if folder is None or folder.id != compliance_assessment.folder_id:
            raise serializers.ValidationError(
                {
                    "folder": "The requirement assessment folder must match the compliance assessment folder."
                }
            )

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
            compliance_assessment_id = self.initial_data.get("compliance_assessment")
            compliance_assessment = ComplianceAssessment.objects.get(
                id=compliance_assessment_id
            )
            return compliance_assessment
        except ComplianceAssessment.DoesNotExist:
            raise serializers.ValidationError(
                "The specified Compliance Assessment does not exist."
            )

    def update(self, instance, validated_data):
        with transaction.atomic():
            # Handle answers if provided in old JSON format
            answers_data = validated_data.pop("answers", None)

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
            override_turned_off = (
                requirement_has_questions and was_overridden and not override_after
            )
            assignment_scope_for_recompute = None
            if self.context.get("requirement_assignment_scope") is not None and (
                bool(answers_data) or override_turned_off
            ):
                request = self.context.get("request")
                if request is None:
                    raise PermissionDenied(
                        "Questionnaire updates require an authenticated request."
                    )
                assignment_scope_for_recompute = get_bound_assignment_scope(
                    self.context,
                    user=request.user,
                    requirement_assessment=instance,
                    mutable=True,
                )
                if assignment_scope_for_recompute is None:
                    raise PermissionDenied(
                        "The assignment questionnaire scope is unavailable."
                    )
                assert_assignment_recompute_scope_complete(
                    scope=assignment_scope_for_recompute,
                    user=request.user,
                    requirement_assessment=instance,
                )

            instance = super().update(instance, validated_data)

            # Override turned off: resync score from answers below.
            score_recomputed = False

            # Override on: is_scored mirrors score presence.
            if override_after and requirement_has_questions:
                new_is_scored = instance.score is not None
                if instance.is_scored != new_is_scored:
                    instance.is_scored = new_is_scored
                    instance.save(update_fields=["is_scored"])

            if answers_data and isinstance(answers_data, dict):
                # Convert incoming answers dict to Answer model updates
                from core.models import Answer, Question

                request = self.context.get("request")
                if request is None:
                    raise PermissionDenied(
                        "Questionnaire updates require an authenticated request."
                    )
                assignment_scope = get_bound_assignment_scope(
                    self.context,
                    user=request.user,
                    requirement_assessment=instance,
                    mutable=True,
                )
                if assignment_scope_for_recompute is not None:
                    assignment_scope = assignment_scope_for_recompute
                if (
                    self.context.get("requirement_assignment_scope") is not None
                    and assignment_scope is None
                ):
                    raise PermissionDenied(
                        "The assignment questionnaire scope is unavailable."
                    )
                scoped_question_ids = (
                    assignment_scope.question_ids_for_requirement_assessment(
                        instance.id
                    )
                    if assignment_scope is not None
                    else frozenset()
                )
                scoped_choice_ids = (
                    assignment_scope.choice_ids_for_questions(scoped_question_ids)
                    if assignment_scope is not None
                    else frozenset()
                )
                visible_question_ids = set(
                    RoleAssignment.get_viewable_object_ids(request.user, Question)
                ) | set(scoped_question_ids)
                visible_choice_ids = set(
                    RoleAssignment.get_viewable_object_ids(request.user, QuestionChoice)
                ) | set(scoped_choice_ids)
                visible_answer_ids = RoleAssignment.get_viewable_object_ids(
                    request.user, Answer
                )

                questions_by_urn = {
                    q.urn: q
                    for q in Question.objects.filter(
                        requirement_node=instance.requirement,
                        id__in=visible_question_ids,
                    ).prefetch_related("choices")
                }
                unknown_questions = set(answers_data) - set(questions_by_urn)
                if unknown_questions:
                    raise serializers.ValidationError(
                        {
                            "answers": (
                                "One or more questions are unavailable for this caller."
                            )
                        }
                    )
                normalized_answers = getattr(
                    self, "_normalized_assignment_answers", None
                )
                if normalized_answers is None:
                    normalized_answers = {}
                    for question_urn, raw_value in answers_data.items():
                        try:
                            normalized_answers[question_urn] = (
                                normalize_question_answer(
                                    questions_by_urn[question_urn],
                                    raw_value,
                                    allowed_choice_ids=visible_choice_ids,
                                )
                            )
                        except QuestionnaireAnswerError as exc:
                            raise serializers.ValidationError(
                                {"answers": str(exc)}
                            ) from exc
                existing_answers = {
                    answer.question_id: answer
                    for answer in Answer.objects.filter(
                        requirement_assessment=instance,
                        question__urn__in=answers_data,
                    )
                }
                if any(
                    answer.id not in visible_answer_ids
                    for answer in existing_answers.values()
                ):
                    raise PermissionDenied(
                        "One or more answers are unavailable for this caller."
                    )
                add_answer_permission = Permission.objects.get(
                    content_type__app_label="core",
                    content_type__model="answer",
                    codename="add_answer",
                )
                change_answer_permission = Permission.objects.get(
                    content_type__app_label="core",
                    content_type__model="answer",
                    codename="change_answer",
                )
                expected_choice_ids_by_answer = self.context.get(
                    "expected_answer_choice_ids", {}
                )
                for q_urn in answers_data:
                    question = questions_by_urn.get(q_urn)
                    normalized_answer = normalized_answers[q_urn]
                    answer = existing_answers.get(question.id)
                    required_permission = (
                        change_answer_permission
                        if answer is not None
                        else add_answer_permission
                    )
                    if not RoleAssignment.is_access_allowed(
                        user=request.user,
                        perm=required_permission,
                        folder=answer.folder if answer is not None else instance.folder,
                    ):
                        raise PermissionDenied(
                            "You do not have permission to update this answer."
                        )
                    if answer is None:
                        answer = Answer.objects.create(
                            requirement_assessment=instance,
                            question=question,
                            folder=instance.folder,
                        )

                    current_choice_ids = set(
                        answer.selected_choices.values_list("id", flat=True)
                    )
                    expected_choice_ids = expected_choice_ids_by_answer.get(answer.id)
                    if expected_choice_ids is not None and current_choice_ids != set(
                        expected_choice_ids
                    ):
                        raise PermissionDenied(
                            "The answer's selected choices changed concurrently; retry."
                        )

                    if question.type in (
                        Question.Type.UNIQUE_CHOICE,
                        Question.Type.MULTIPLE_CHOICE,
                    ):
                        requested_choice_ids = {
                            choice.id for choice in normalized_answer.choices
                        }
                        hidden_current_ids = current_choice_ids - set(
                            visible_choice_ids
                        )
                        current_visible_ids = current_choice_ids & set(
                            visible_choice_ids
                        )
                        if (
                            hidden_current_ids
                            and question.type == Question.Type.UNIQUE_CHOICE
                            and requested_choice_ids != current_visible_ids
                        ):
                            raise PermissionDenied(
                                "A hidden existing choice prevents replacing this unique-choice answer."
                            )
                        final_choice_ids = requested_choice_ids | hidden_current_ids
                        locked_choices = list(
                            QuestionChoice.objects.filter(
                                id__in=final_choice_ids,
                                question_id=question.id,
                            ).order_by("id")
                        )
                        if {choice.id for choice in locked_choices} != final_choice_ids:
                            raise PermissionDenied(
                                "One or more selected choices are unavailable."
                            )
                        answer.selected_choices.set(locked_choices)
                        answer.value = None
                        answer.save(update_fields=["value"])
                    else:
                        if current_choice_ids:
                            raise PermissionDenied(
                                "A non-choice answer contains inconsistent selected choices."
                            )
                        answer.selected_choices.clear()
                        answer.value = normalized_answer.value
                        answer.save(update_fields=["value"])

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
            # Skip auto-map when the auditor explicitly sets result in the same
            # request: SuperForm round-trips the existing respondent_alignment
            # on every submit, and we must not clobber an auditor-edited result
            # (or zero it to NOT_ASSESSED if the respondent never answered).
            if (
                "respondent_alignment" in validated_data
                and "result" not in validated_data
                and not requirement_has_questions
            ):
                new_alignment = validated_data.get("respondent_alignment")
                if new_alignment and new_alignment in ALIGNMENT_TO_RESULT:
                    instance.result = ALIGNMENT_TO_RESULT[new_alignment]
                    instance.save(update_fields=["result"])
                elif not new_alignment:
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

    def to_representation(self, instance):
        data = super().to_representation(instance)
        request = self.context.get("request")
        user = getattr(request, "user", None)
        if (
            _assignment_score_is_visible(
                self.context,
                user=user,
            )
            is False
        ):
            data.pop("add_score", None)
            data.pop("compute_result", None)
        return data

    class Meta:
        model = QuestionChoice
        fields = "__all__"


class QuestionChoiceWriteSerializer(BaseModelSerializer):
    def to_representation(self, instance):
        return self._filter_writable_related_representation(
            super().to_representation(instance)
        )

    def update(self, instance, validated_data):
        # Skip the URN-based "imported objects" guard from BaseModelSerializer
        # because choices on draft frameworks should be editable.
        with transaction.atomic():
            Folder._lock_folder_tree()
            observed = QuestionChoice.objects.only("id", "question_id").get(
                id=instance.id
            )
            requested_question = validated_data.get("question")
            question_ids = {observed.question_id}
            if requested_question is not None:
                question_ids.add(requested_question.id)
            graph = lock_questionnaire_owner_graph(
                user=getattr(self.context.get("request"), "user", None),
                question_ids=question_ids,
                choice_ids={instance.id},
            )
            nodes_by_id = graph["nodes"]
            questions_by_id = graph["questions"]
            locked_choice = graph["choices"][instance.id]
            if locked_choice.question_id != observed.question_id:
                raise serializers.ValidationError(
                    {"question": "The choice owner changed concurrently."}
                )

            target_question = questions_by_id[
                requested_question.id
                if requested_question is not None
                else locked_choice.question_id
            ]
            source_question = questions_by_id[locked_choice.question_id]
            if locked_choice.folder_id != source_question.folder_id or any(
                question.folder_id
                != nodes_by_id[question.requirement_node_id].folder_id
                for question in (source_question, target_question)
            ):
                raise PermissionDenied(
                    {"folder": "The choice owner folder is inconsistent."}
                )
            request = self.context.get("request")
            if request:
                visible_question_ids = set(
                    RoleAssignment.get_viewable_object_ids(request.user, Question)
                )
                visible_node_ids = set(
                    RoleAssignment.get_viewable_object_ids(
                        request.user, RequirementNode
                    )
                )
                if (
                    source_question.id not in visible_question_ids
                    or target_question.id not in visible_question_ids
                    or source_question.requirement_node_id not in visible_node_ids
                    or target_question.requirement_node_id not in visible_node_ids
                ):
                    raise PermissionDenied(
                        {"question": "The source or target question is unavailable."}
                    )
            if target_question.id != locked_choice.question_id:
                if (
                    source_question.given_answers.exists()
                    or target_question.given_answers.exists()
                    or locked_choice.choice_answers.exists()
                ):
                    raise serializers.ValidationError(
                        {
                            "question": "A choice used by an assessment cannot change question."
                        }
                    )
                self._check_object_perm(
                    locked_choice,
                    "delete",
                    folder=source_question.folder,
                )
                self._check_object_perm(
                    locked_choice,
                    "add",
                    folder=target_question.folder,
                )
            self._check_object_perm(
                locked_choice,
                "change",
                folder=source_question.folder,
            )
            # A choice is owned by its Question's IAM scope.  Ignore a stale or
            # malicious independent folder value and bind both owner fields to
            # the rows locked above.
            validated_data["question"] = target_question
            validated_data["folder"] = target_question.folder
            self.instance = locked_choice
            try:
                return super(BaseModelSerializer, self).update(
                    locked_choice, validated_data
                )
            except (PermissionDenied, serializers.ValidationError):
                raise
            except Exception as exc:
                logger.error(
                    "Failed to update QuestionChoice",
                    error=str(exc),
                    exc_info=True,
                )
                raise serializers.ValidationError(
                    "Failed to update choice. Please check the input data."
                ) from exc

    class Meta:
        model = QuestionChoice
        exclude = ["created_at", "updated_at"]
        read_only_fields = ["folder"]


class QuestionReadSerializer(BaseModelSerializer):
    folder = FieldsRelatedField()
    choices = QuestionChoiceReadSerializer(many=True, read_only=True)

    def to_representation(self, instance):
        data = super().to_representation(instance)
        request = self.context.get("request")
        user = getattr(request, "user", None)
        if user is None or not getattr(user, "is_authenticated", False):
            data["choices"] = []
            return data

        visible_choice_ids = set(
            _generic_visible_object_ids(self.context, user, QuestionChoice)
        )
        assignment_scope = get_bound_assignment_scope(
            self.context,
            user=user,
            requirement_node=instance.requirement_node,
        )
        if (
            assignment_scope is not None
            and instance.id
            in assignment_scope.question_ids_for_requirement_node(
                instance.requirement_node_id
            )
        ):
            visible_choice_ids.update(
                assignment_scope.choice_ids_for_questions(frozenset({instance.id}))
            )

        filtered_choices = []
        for choice in data.get("choices") or []:
            raw_id = choice.get("id") if isinstance(choice, dict) else choice
            try:
                choice_id = UUID(str(raw_id))
            except (TypeError, ValueError):
                continue
            if choice_id in visible_choice_ids:
                filtered_choices.append(choice)
        data["choices"] = filtered_choices
        return data

    class Meta:
        model = Question
        fields = "__all__"


class QuestionWriteSerializer(BaseModelSerializer):
    def to_representation(self, instance):
        return self._filter_writable_related_representation(
            super().to_representation(instance)
        )

    def update(self, instance, validated_data):
        # Skip the URN-based "imported objects" guard from BaseModelSerializer
        # because questions on draft frameworks should be editable.
        with transaction.atomic():
            Folder._lock_folder_tree()
            observed = Question.objects.only("id", "requirement_node_id").get(
                id=instance.id
            )
            requested_node = validated_data.get("requirement_node")
            node_ids = {observed.requirement_node_id}
            if requested_node is not None:
                node_ids.add(requested_node.id)
            graph = lock_questionnaire_owner_graph(
                user=getattr(self.context.get("request"), "user", None),
                requirement_node_ids=node_ids,
                question_ids={instance.id},
            )
            nodes_by_id = graph["nodes"]
            locked_question = graph["questions"][instance.id]
            if locked_question.requirement_node_id != observed.requirement_node_id:
                raise serializers.ValidationError(
                    {"requirement_node": "The question owner changed concurrently."}
                )

            target_node = nodes_by_id[
                requested_node.id
                if requested_node is not None
                else locked_question.requirement_node_id
            ]
            source_node = nodes_by_id[locked_question.requirement_node_id]
            if locked_question.folder_id != source_node.folder_id:
                raise PermissionDenied(
                    {"folder": "The question owner folder is inconsistent."}
                )
            request = self.context.get("request")
            if request:
                visible_node_ids = set(
                    RoleAssignment.get_viewable_object_ids(
                        request.user, RequirementNode
                    )
                )
                if (
                    source_node.id not in visible_node_ids
                    or target_node.id not in visible_node_ids
                ):
                    raise PermissionDenied(
                        {
                            "requirement_node": (
                                "The source or target requirement is unavailable."
                            )
                        }
                    )
            if target_node.id != locked_question.requirement_node_id:
                has_choices = QuestionChoice.objects.filter(
                    question=locked_question
                ).exists()
                crosses_folder = source_node.folder_id != target_node.folder_id
                if (
                    locked_question.given_answers.exists()
                    or QuestionChoice.objects.filter(
                        question=locked_question,
                        choice_answers__isnull=False,
                    ).exists()
                    or (crosses_folder and has_choices)
                ):
                    raise serializers.ValidationError(
                        {
                            "requirement_node": (
                                "A used question, or a question with choices "
                                "crossing folders, cannot change requirement."
                            )
                        }
                    )
                self._check_object_perm(
                    locked_question,
                    "delete",
                    folder=source_node.folder,
                )
                self._check_object_perm(
                    locked_question,
                    "add",
                    folder=target_node.folder,
                )
            self._check_object_perm(
                locked_question,
                "change",
                folder=source_node.folder,
            )
            # A Question cannot carry an IAM folder independent of its owning
            # RequirementNode.
            validated_data["requirement_node"] = target_node
            validated_data["folder"] = target_node.folder
            self.instance = locked_question
            try:
                return super(BaseModelSerializer, self).update(
                    locked_question, validated_data
                )
            except (PermissionDenied, serializers.ValidationError):
                raise
            except Exception as exc:
                logger.error("Failed to update Question", error=str(exc), exc_info=True)
                raise serializers.ValidationError(
                    "Failed to update question. Please check the input data."
                ) from exc

    class Meta:
        model = Question
        exclude = ["created_at", "updated_at"]
        read_only_fields = ["folder"]


class AnswerReadSerializer(BaseModelSerializer):
    folder = FieldsRelatedField()
    selected_choices = FieldsRelatedField(many=True)

    def to_representation(self, instance):
        data = super().to_representation(instance)
        selected_choices = data.pop("selected_choices", [])
        data = self._filter_writable_related_representation(data)
        request = self.context.get("request")
        if request is None:
            data["selected_choices"] = []
            return data
        visible_choice_ids = set(
            RoleAssignment.get_viewable_object_ids(request.user, QuestionChoice)
        )
        visible_choices = []
        for choice in selected_choices:
            raw_id = choice.get("id") if isinstance(choice, dict) else choice
            try:
                choice_id = UUID(str(raw_id))
            except (TypeError, ValueError):
                continue
            if choice_id in visible_choice_ids:
                visible_choices.append(choice)
        data["selected_choices"] = visible_choices
        return data

    class Meta:
        model = Answer
        fields = "__all__"


class AnswerWriteSerializer(BaseModelSerializer):
    # Accept selected_choices as list of PKs for M2M
    selected_choices = serializers.PrimaryKeyRelatedField(
        queryset=QuestionChoice.objects.all(), many=True, required=False
    )

    def to_representation(self, instance):
        return AnswerReadSerializer(instance, context=self.context).data

    def validate(self, attrs):
        requirement_assessment = attrs.get("requirement_assessment") or (
            self.instance.requirement_assessment if self.instance else None
        )
        question = attrs.get("question") or (
            self.instance.question if self.instance else None
        )
        value_supplied = "value" in attrs
        value = attrs.get("value")
        selected_choices_list = attrs.get("selected_choices")

        if self.instance is not None:
            immutable_fields = {
                "requirement_assessment": "requirement_assessment_id",
                "question": "question_id",
                "folder": "folder_id",
            }
            changed_immutable_fields = [
                field_name
                for field_name, id_field in immutable_fields.items()
                if field_name in attrs
                and getattr(attrs[field_name], "id", None)
                != getattr(self.instance, id_field)
            ]
            if changed_immutable_fields:
                raise serializers.ValidationError(
                    {
                        field_name: "This answer ownership field is immutable."
                        for field_name in changed_immutable_fields
                    }
                )

        if not requirement_assessment:
            raise serializers.ValidationError(
                {"requirement_assessment": "This field is required."}
            )
        if self.instance is None:
            answer_folder = attrs.get("folder")
            if answer_folder is None:
                attrs["folder"] = requirement_assessment.folder
            elif (
                answer_folder is not None
                and answer_folder.id != requirement_assessment.folder_id
            ):
                raise serializers.ValidationError(
                    {"folder": "An answer must use its requirement assessment folder."}
                )

        # 1. Parent/child consistency check
        if (
            question
            and question.requirement_node_id != requirement_assessment.requirement_id
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

        # 3. Assignment-level locking for respondent users
        request = self.context.get("request")
        visible_choice_ids = QuestionChoice.objects.none().values_list("id", flat=True)
        if request and requirement_assessment:
            from core.utils import has_full_view_compliance_assessment

            user = request.user
            if (
                compliance_assessment.id
                not in RoleAssignment.get_viewable_object_ids(
                    user, ComplianceAssessment
                )
                or requirement_assessment.id
                not in RoleAssignment.get_viewable_object_ids(
                    user, RequirementAssessment
                )
            ):
                raise PermissionDenied(
                    "You do not have permission to access this answer."
                )

            is_full_viewer = has_full_view_compliance_assessment(
                user, compliance_assessment
            )
            if not is_full_viewer:
                raise PermissionDenied(
                    "Respondent answers must use an exact requirement-assignment endpoint."
                )

            if question and question.id not in RoleAssignment.get_viewable_object_ids(
                user, Question
            ):
                raise PermissionDenied(
                    "You do not have permission to access this answer."
                )

            visible_choice_ids = RoleAssignment.get_viewable_object_ids(
                user, QuestionChoice
            )
            if selected_choices_list is not None and any(
                choice.id not in visible_choice_ids for choice in selected_choices_list
            ):
                raise PermissionDenied(
                    "You do not have permission to access this answer."
                )

        if question:
            q_type = question.type

            # Reject sending both value and selected_choices for choice questions
            if (
                q_type in (Question.Type.UNIQUE_CHOICE, Question.Type.MULTIPLE_CHOICE)
                and value_supplied
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

            # Keep both direct wire forms (legacy value and selected-choice PKs)
            # on the same deterministic normalizer used by RA bulk answers.
            try:
                normalized_answer = None
                if value_supplied:
                    normalized_answer = normalize_question_answer(
                        question,
                        value,
                        allowed_choice_ids=visible_choice_ids,
                    )
                if selected_choices_list is not None:
                    if any(
                        choice.question_id != question.id
                        for choice in selected_choices_list
                    ):
                        raise QuestionnaireAnswerError(
                            "Selected choices must belong to the target question."
                        )
                    if any(
                        not isinstance(choice.urn, str) or not choice.urn
                        for choice in selected_choices_list
                    ):
                        raise QuestionnaireAnswerError(
                            "Selected choices must have a stable non-empty URN."
                        )
                    if q_type == Question.Type.UNIQUE_CHOICE:
                        if not selected_choices_list:
                            selected_wire_value = None
                        elif len(selected_choices_list) == 1:
                            selected_wire_value = selected_choices_list[0].urn
                        else:
                            selected_wire_value = [
                                choice.urn for choice in selected_choices_list
                            ]
                    else:
                        selected_wire_value = [
                            choice.urn for choice in selected_choices_list
                        ]
                    normalized_answer = normalize_question_answer(
                        question,
                        selected_wire_value,
                        allowed_choice_ids=visible_choice_ids,
                    )
            except QuestionnaireAnswerError as exc:
                raise serializers.ValidationError({"value": str(exc)}) from exc

            if normalized_answer is not None and q_type in (
                Question.Type.UNIQUE_CHOICE,
                Question.Type.MULTIPLE_CHOICE,
            ):
                attrs["_m2m_choices"] = list(normalized_answer.choices)
                attrs["value"] = None
            elif normalized_answer is not None:
                attrs["value"] = normalized_answer.value
                attrs["_m2m_choices"] = []

        return super().validate(attrs)

    def create(self, validated_data):
        m2m_choices = validated_data.pop("_m2m_choices", None)
        # Remove selected_choices from validated_data since M2M can't be set on create
        validated_data.pop("selected_choices", None)
        instance = super().create(validated_data)
        if m2m_choices is not None:
            instance.selected_choices.set(m2m_choices)
            # Re-save to trigger IG update for dynamic frameworks
            instance.save()
        return instance

    def update(self, instance, validated_data):
        m2m_choices = validated_data.pop("_m2m_choices", None)
        validated_data.pop("selected_choices", None)
        instance = super().update(instance, validated_data)
        if m2m_choices is not None:
            instance.selected_choices.set(m2m_choices)
            # Re-save to trigger IG update for dynamic frameworks
            instance.save()
        return instance

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
            "is_published",
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
            "score",
            "is_scored",
            "is_score_overridden",
            "observation",
            "compliance_assessment",
            "requirement",
            "selected",
            "mapping_inference",
            "evidences",
            "applied_controls",
        ]


class RequirementAssignmentEventSerializer(BaseModelSerializer):
    # A named maker/checker is part of the assignment workflow record and is
    # intentionally visible to participants who may read the event itself.
    event_actor = FieldsRelatedField(["id", "email", "first_name", "last_name"])

    class Meta:
        model = RequirementAssignmentEvent
        fields = ["id", "event_type", "event_actor", "event_notes", "created_at"]


class AnswerImportExportSerializer(BaseModelSerializer):
    folder = HashSlugRelatedField(slug_field="pk", read_only=True)
    requirement_assessment = HashSlugRelatedField(slug_field="pk", read_only=True)
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
            "question",
            "value",
            "selected_choices_urns",
        ]


class FindingsAssessmentImportExportSerializer(BaseModelSerializer):
    folder = HashSlugRelatedField(slug_field="pk", read_only=True)
    perimeter = HashSlugRelatedField(slug_field="pk", read_only=True)
    evidences = HashSlugRelatedField(slug_field="pk", read_only=True, many=True)

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

    class Meta:
        model = Campaign
        fields = [
            "name",
            "description",
            "status",
            "start_date",
            "eta",
            "due_date",
            "selected_implementation_groups",
            "folder",
            "frameworks",
            "perimeters",
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
    requirement_assessments = FieldsRelatedField(many=True)
    events = RequirementAssignmentEventSerializer(many=True, read_only=True)

    @staticmethod
    def _related_id(value):
        raw_id = value.get("id") if isinstance(value, dict) else value
        try:
            return UUID(str(raw_id))
        except (TypeError, ValueError):
            return None

    def to_representation(self, instance):
        assert_assignment_folder_owner(instance)
        if any(
            event.folder_id != instance.folder_id for event in instance.events.all()
        ):
            raise PermissionDenied(
                "The requirement assignment contains an inconsistent workflow event."
            )
        data = super().to_representation(instance)
        request = self.context.get("request")
        user = getattr(request, "user", None)
        if user is None or not getattr(user, "is_authenticated", False):
            data["folder"] = None
            data["compliance_assessment"] = None
            data["actor"] = []
            data["requirement_assessments"] = []
            data["events"] = []
            return data

        for field_name, model, many in (
            ("folder", Folder, False),
            ("compliance_assessment", ComplianceAssessment, False),
            ("actor", Actor, True),
            ("requirement_assessments", RequirementAssessment, True),
        ):
            allowed_ids = set(RoleAssignment.get_viewable_object_ids(user, model))
            if many:
                values = data.get(field_name)
                if isinstance(values, list):
                    data[field_name] = [
                        value
                        for value in values
                        if self._related_id(value) in allowed_ids
                    ]
            elif self._related_id(data.get(field_name)) not in allowed_ids:
                data[field_name] = None
        return data

    class Meta:
        model = RequirementAssignment
        fields = "__all__"


class RequirementAssignmentWriteSerializer(BaseModelSerializer):
    def to_representation(self, instance):
        return RequirementAssignmentReadSerializer(
            instance,
            context=self.context,
        ).data

    class Meta:
        model = RequirementAssignment
        fields = "__all__"
        read_only_fields = ["status"]

    def validate(self, attrs):
        """
        Validate that requirement assessments belong to the specified compliance assessment
        and are not already assigned to another assignment.
        """
        compliance_assessment = attrs.get(
            "compliance_assessment",
            getattr(self.instance, "compliance_assessment", None),
        )
        requirement_assessments = attrs.get("requirement_assessments")
        folder = attrs.get("folder", getattr(self.instance, "folder", None))

        if self.instance is not None and "compliance_assessment" in attrs:
            self._ensure_immutable(
                "compliance_assessment",
                attrs["compliance_assessment"],
            )
        if self.instance is not None and "folder" in attrs:
            self._ensure_immutable("folder", attrs["folder"])

        if compliance_assessment is not None:
            if folder is None and self.instance is None:
                folder = compliance_assessment.folder
                attrs["folder"] = folder
            if folder is None or folder.id != compliance_assessment.folder_id:
                raise serializers.ValidationError(
                    {
                        "folder": "The assignment folder must match the compliance assessment folder."
                    }
                )

        if compliance_assessment and requirement_assessments is not None:
            # Check that all requirement assessments belong to the compliance assessment
            for ra in requirement_assessments:
                if ra.compliance_assessment_id != compliance_assessment.id:
                    raise serializers.ValidationError(
                        {
                            "requirement_assessments": f"Requirement assessment '{ra}' does not belong to the specified compliance assessment."
                        }
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
        exclude = ["folder", "is_published"]


class LibraryFilteringLabelReadSerializer(BaseModelSerializer):
    path = PathField(read_only=True)
    folder = FieldsRelatedField()

    class Meta:
        model = LibraryFilteringLabel
        fields = "__all__"


class LibraryFilteringLabelWriteSerializer(BaseModelSerializer):
    class Meta:
        model = LibraryFilteringLabel
        exclude = ["folder", "is_published"]


class SecurityExceptionWriteSerializer(
    CustomFieldsSerializerMixin, BaseModelSerializer
):
    genericcollection = serializers.PrimaryKeyRelatedField(
        source="genericcollection_set",
        many=True,
        required=False,
        queryset=GenericCollection.objects.all(),
    )
    requirement_assessments = serializers.PrimaryKeyRelatedField(
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

    def to_representation(self, instance):
        data = super().to_representation(instance)
        return self._filter_writable_related_representation(data)

    def create(self, validated_data):
        owner_data = validated_data.get("owners", [])
        security_exception = super().create(validated_data)

        # Notify newly assigned owners
        if owner_data:
            self._send_assignment_notifications(
                security_exception, [actor.id for actor in owner_data]
            )

        return security_exception

    def update(self, instance, validated_data):
        old_owner_ids = set(instance.owners.values_list("id", flat=True))
        old_status = instance.status

        updated_instance = super().update(instance, validated_data)

        new_owner_ids = set(updated_instance.owners.values_list("id", flat=True))

        # Notify only newly assigned owners
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
                transaction.on_commit(
                    lambda: send_security_exception_assignment_notification(
                        exception_id, unique_emails
                    )
                )
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
            transaction.on_commit(
                lambda: send_security_exception_status_notification(
                    exception_id, new_status, actor_name, recipient_emails
                )
            )
        except Exception as e:
            logger.error(
                f"Failed to send SecurityException status notification: {str(e)}"
            )

    class Meta:
        model = SecurityException
        fields = "__all__"
        # Deprecated: approval is handled through validation flows. The field is
        # kept read-only so existing values remain visible without new writes.
        read_only_fields = ["approver"]


class SecurityExceptionReadSerializer(CustomFieldsSerializerMixin, BaseModelSerializer):
    path = PathField(read_only=True)
    folder = FieldsRelatedField()
    owners = FieldsRelatedField(many=True)
    approver = FieldsRelatedField()
    severity = serializers.CharField(source="get_severity_display")
    associated_objects_count = serializers.SerializerMethodField()
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

    def get_associated_objects_count(self, obj):
        """Prefer annotated or prefetched counts to avoid extra DB queries."""
        annotated = getattr(obj, "associated_objects_count", None)
        if annotated is not None:
            return annotated
        try:
            # Uses prefetch cache when available (no extra queries)
            return (
                len(obj.assets.all())
                + len(obj.applied_controls.all())
                + len(obj.vulnerabilities.all())
                + len(obj.risk_scenarios.all())
                + len(obj.requirement_assessments.all())
                + len(obj.evidences.all())
            )
        except Exception:
            # Fallback: perform DB counts
            return (
                obj.assets.count()
                + obj.applied_controls.count()
                + obj.vulnerabilities.count()
                + obj.risk_scenarios.count()
                + obj.requirement_assessments.count()
                + obj.evidences.count()
            )

    class Meta:
        model = SecurityException
        fields = "__all__"


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
    def validate(self, attrs):
        if (
            hasattr(self, "instance")
            and self.instance
            and self.instance.findings_assessment.is_locked
        ):
            raise serializers.ValidationError(
                "⚠️ Cannot modify the finding when the findings assessment is locked."
            )
        return super().validate(attrs)

    class Meta:
        model = Finding
        exclude = ["created_at", "updated_at", "folder"]

    def create(self, validated_data):
        findings_assessment = validated_data.get("findings_assessment")
        if not findings_assessment:
            raise serializers.ValidationError({"findings_assessment": "mandatory"})
        validated_data["folder"] = findings_assessment.folder

        return super().create(validated_data)


class FindingReadSerializer(FindingWriteSerializer):
    path = PathField(read_only=True)
    owner = FieldsRelatedField(many=True)
    findings_assessment = FieldsRelatedField(["id", "name", "is_locked"])
    # No standalone page exists for requirement nodes: omit "id" so the
    # generic detail view renders plain text instead of a dead link.
    requirement_node = FieldsRelatedField(["ref_id", "name"])
    asset = FieldsRelatedField()
    threats = FieldsRelatedField(many=True)
    vulnerabilities = FieldsRelatedField(many=True)
    reference_controls = FieldsRelatedField(many=True)
    applied_controls = FieldsRelatedField(many=True)
    filtering_labels = FieldsRelatedField(many=True)
    evidences = FieldsRelatedField(many=True)
    perimeter = FieldsRelatedField(
        source="findings_assessment.perimeter", fields=["id", "name", "folder"]
    )
    folder = FieldsRelatedField()
    severity = serializers.CharField(source="get_severity_display")
    priority = serializers.CharField(source="get_priority_display")

    class Meta:
        model = Finding
        fields = "__all__"


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
                    "Exactly one parent (requirement_assessment, risk_scenario, "
                    "applied_control, or finding) must be set."
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


class TaskTemplateReadSerializer(BaseModelSerializer):
    path = PathField(read_only=True)
    folder = FieldsRelatedField()
    incidents = FieldsRelatedField(many=True)
    evidences = FieldsRelatedField(many=True)
    assets = FieldsRelatedField(many=True)
    applied_controls = FieldsRelatedField(many=True)
    compliance_assessments = FieldsRelatedField(many=True)
    risk_assessments = FieldsRelatedField(many=True)
    assigned_to = FieldsRelatedField(many=True)
    findings_assessment = FieldsRelatedField(many=True)
    findings = FieldsRelatedField(many=True)
    filtering_labels = FieldsRelatedField(["id", "folder"], many=True)

    next_occurrence = serializers.SerializerMethodField()
    last_occurrence_status = serializers.SerializerMethodField()
    next_occurrence_status = serializers.SerializerMethodField()

    # Expose task_node fields directly
    status = serializers.SerializerMethodField()
    observation = serializers.SerializerMethodField()

    class Meta:
        model = TaskTemplate
        exclude = ["schedule"]

    def _get_visible_task_nodes(self, obj):
        cache = getattr(self, "_visible_task_nodes_by_template", None)
        if cache is None:
            cache = {}
            self._visible_task_nodes_by_template = cache
        if obj.id in cache:
            return cache[obj.id]

        request = self.context.get("request")
        user = getattr(request, "user", None)
        if user is None or not getattr(user, "is_authenticated", False):
            cache[obj.id] = []
            return cache[obj.id]

        if not hasattr(self, "_visible_task_node_ids"):
            try:
                self._visible_task_node_ids = set(
                    RoleAssignment.get_viewable_object_ids(user, TaskNode)
                )
            except (NotImplementedError, Permission.DoesNotExist):
                # These fields are TaskNode-owned.  Unsupported or incomplete
                # IAM resolution must not fall back to an unscoped query.
                self._visible_task_node_ids = set()

        cache[obj.id] = list(
            TaskNode.objects.filter(
                task_template=obj,
                id__in=self._visible_task_node_ids,
            ).order_by("due_date", "id")
        )
        return cache[obj.id]

    def get_task_node(self, obj):
        """Return only a TaskNode independently visible to this caller."""
        if obj.is_recurrent:
            return None
        return next(iter(self._get_visible_task_nodes(obj)), None)

    def get_next_occurrence(self, obj):
        if self.context.get("authorized_task_node_summary"):
            return getattr(obj, "next_occurrence", None)
        nodes = self._get_visible_task_nodes(obj)
        if not obj.is_recurrent:
            node = next((item for item in nodes if item.due_date is not None), None)
            return node.due_date if node else None
        today = timezone.localdate()
        node = next(
            (
                item
                for item in nodes
                if item.due_date is not None and item.due_date >= today
            ),
            None,
        )
        return node.due_date if node else None

    def get_last_occurrence_status(self, obj):
        if not obj.is_recurrent:
            return None
        if self.context.get("authorized_task_node_summary"):
            return getattr(obj, "last_occurrence_status", None)
        today = timezone.localdate()
        past_nodes = [
            node
            for node in self._get_visible_task_nodes(obj)
            if node.due_date is not None and node.due_date < today
        ]
        return past_nodes[-1].status if past_nodes else None

    def get_next_occurrence_status(self, obj):
        if self.context.get("authorized_task_node_summary"):
            return getattr(obj, "next_occurrence_status", None)
        nodes = self._get_visible_task_nodes(obj)
        if not obj.is_recurrent:
            node = next(iter(nodes), None)
            return node.status if node else None
        today = timezone.localdate()
        node = next(
            (
                item
                for item in nodes
                if item.due_date is not None and item.due_date >= today
            ),
            None,
        )
        return node.status if node else None

    def get_status(self, obj):
        task_node = self.get_task_node(obj)
        return task_node.status if task_node else None

    def get_observation(self, obj):
        task_node = self.get_task_node(obj)
        return task_node.observation if task_node else ""


class TaskTemplateWriteSerializer(BaseModelSerializer):
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

    def to_representation(self, instance):
        data = super().to_representation(instance)
        if not instance.is_recurrent:
            # The view injects a node only after proving independent TaskNode
            # visibility.  Never query here: doing so would read hidden state
            # before a later projection had a chance to mask it.
            task_node = self.context.get("task_node")
            if task_node is not None and task_node.task_template_id == instance.id:
                data["status"] = task_node.status
                data["observation"] = task_node.observation
            else:
                data["status"] = None
                data["observation"] = ""
        return data

    def create(self, validated_data):
        assigned_to_data = validated_data.get("assigned_to", [])
        incidents = validated_data.pop("incidents", [])
        self.tasknode_data = self._extract_tasknode_fields(validated_data)
        with transaction.atomic():
            instance = super().create(validated_data)
            if incidents:
                instance.incidents.set(incidents)

        # Send notification to newly assigned users
        if assigned_to_data:
            self._send_assignment_notifications(
                instance, [actor.id for actor in assigned_to_data]
            )

        return instance

    def update(self, instance, validated_data):
        # Track old assigned users before update
        old_assigned_ids = set(instance.assigned_to.values_list("id", flat=True))

        self.tasknode_data = self._extract_tasknode_fields(validated_data)
        incidents = validated_data.pop("incidents", None)

        with transaction.atomic():
            instance = super().update(instance, validated_data)
            if incidents is not None:
                instance.incidents.set(incidents)

        # Get new assigned users after update
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
                task_template_id = task_template.id
                transaction.on_commit(
                    lambda: send_task_template_assignment_notification(
                        task_template_id, assigned_emails
                    )
                )
        except Exception as e:
            logger.error(
                f"Failed to send TaskTemplate assignment notification: {str(e)}"
            )

    def _extract_tasknode_fields(self, validated_data):
        """
        Separate TaskNode-specific fields without mutating any TaskNode rows.

        The owning view consumes ``tasknode_data`` inside its root/template/node
        lock hierarchy and performs the exact permission-checked diff.
        """
        tasknode_data = {}
        for field_name in ("status", "observation"):
            if field_name not in validated_data:
                continue
            value = validated_data.pop(field_name)
            if value is not None:
                tasknode_data[field_name] = value
        return tasknode_data


class TaskNodeReadSerializer(BaseModelSerializer):
    path = PathField(read_only=True)
    task_template = FieldsRelatedField(["folder", "id", "description"])
    folder = FieldsRelatedField()
    name = serializers.SerializerMethodField()
    assigned_to = FieldsRelatedField(many=True)
    evidences = FieldsRelatedField(["folder", "id"], many=True)
    is_recurrent = serializers.BooleanField(source="task_template.is_recurrent")
    expected_evidence = FieldsRelatedField(["folder", "id"], many=True)
    evidence_reviewed = serializers.SerializerMethodField()
    evidence_revisions_map = serializers.SerializerMethodField()
    applied_controls = FieldsRelatedField(["folder", "id"], many=True)
    compliance_assessments = FieldsRelatedField(["folder", "id"], many=True)
    assets = FieldsRelatedField(["folder", "id"], many=True)
    risk_assessments = FieldsRelatedField(["folder", "id"], many=True)
    findings_assessment = FieldsRelatedField(["folder", "id"], many=True)

    def get_name(self, obj):
        return obj.task_template.name if obj.task_template else ""

    def get_evidence_reviewed(self, obj):
        evidence_reviewed = []
        for evidence in obj.expected_evidence:
            last_revision = evidence.last_revision
            if last_revision and last_revision.task_node == obj:
                evidence_reviewed.append(evidence.id)
        return evidence_reviewed

    def get_evidence_revisions_map(self, obj):
        """Returns a mapping of evidence ID to revision ID for this task node"""
        from core.models import EvidenceRevision

        evidence_revisions = {}
        for evidence in obj.expected_evidence:
            # Find revisions for this evidence that belong to this task node
            revision = EvidenceRevision.objects.filter(
                evidence=evidence, task_node=obj
            ).first()
            if revision:
                evidence_revisions[str(evidence.id)] = str(revision.id)
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
        exclude = ["folder", "is_published"]


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
        exclude = ["folder", "is_published"]


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
        exclude = ["folder", "is_published"]


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

    def _lock_owner_write_authority(self, instance, validated_data):
        """Rebind folder authority after the shared root mutex is held."""

        locked_instance, current_folder, destination_folder = (
            lock_owner_folder_write_scope(
                model=ValidationFlow,
                instance=instance,
                validated_data=validated_data,
            )
        )
        if locked_instance is None:
            self._check_object_perm(
                validated_data,
                "add",
                folder=destination_folder,
            )
        else:
            self._check_object_perm(locked_instance, "change")
            if destination_folder.pk != current_folder.pk:
                self._check_object_perm(
                    locked_instance,
                    "add",
                    folder=destination_folder,
                )
        return locked_instance, current_folder

    @transaction.atomic
    def create(self, validated_data: dict) -> ValidationFlow:
        """
        Override create to automatically set the requester to the current user
        and create initial submission event.
        """
        from core.models import FlowEvent

        request_user = self.context["request"].user
        Folder._lock_folder_tree()
        self._lock_owner_write_authority(None, validated_data)
        lock_assessment_relation_targets(validated_data, user=request_user)
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

        # Check if status is being modified
        if "status" in validated_data:
            new_status = validated_data["status"]

            # Extract event notes from validated_data (passed from actions)
            event_notes = validated_data.pop("event_notes", None)

            with transaction.atomic():
                Folder._lock_folder_tree()
                instance, current_folder = self._lock_owner_write_authority(
                    instance,
                    validated_data,
                )
                old_folder_id = current_folder.pk
                lock_assessment_relation_targets(
                    validated_data,
                    user=request_user,
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
            Folder._lock_folder_tree()
            locked_instance, current_folder = self._lock_owner_write_authority(
                instance,
                validated_data,
            )
            old_folder_id = current_folder.pk
            lock_assessment_relation_targets(
                validated_data,
                user=request_user,
            )
            updated_instance = super().update(locked_instance, validated_data)

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
